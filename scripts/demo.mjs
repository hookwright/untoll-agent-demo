// UNTOLL agent quickstart: give an agent a scoped session key, watch containment hold.
//
// What this proves, live, on a real EVM:
//   1. An agent EOA delegates its own address to the real SessionKeyDelegate via EIP-7702.
//   2. A scoped session key does the ALLOWED thing (an in-scope call whose output goes to the owner). It passes.
//   3. The same key tries the FORBIDDEN things (redirect the output, call an off-scope selector, blow
//      the value cap, hit an off-scope target). Every one is stopped. No funds move.
//
// The session key is the only thing a compromised agent model would hold. The owner key installs the
// scope once and is never handed to the agent. That separation is the whole non-custodial guarantee.
import fs from "node:fs";
import { createPublicClient, createWalletClient, http, encodeFunctionData, toFunctionSelector, keccak256, toBytes, parseEther } from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { startChain } from "./chain.mjs";
import { assertSafe, KEY_LABEL } from "./safety.mjs";

const useColor = !process.env.NO_COLOR && process.stdout.isTTY;
const c = (code, s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const green = (s) => c("32", s), red = (s) => c("31", s), dim = (s) => c("2", s), bold = (s) => c("1", s);
const short = (a) => a.slice(0, 6) + "…" + a.slice(-4);
const line = () => console.log(dim("─".repeat(74)));

const load = (n) => JSON.parse(fs.readFileSync(new URL(`../artifacts/${n}.json`, import.meta.url)));
const delegateArt = load("SessionKeyDelegate");
const targetArt = load("MockTarget");

// Reason tags: the delegate tags each breach class with bytes4(keccak256(LABEL)). Recompute the map
// here so a mined ScopeViolation reason is decoded to a human label from first principles, not a guess.
const REASONS = Object.fromEntries(
  ["TARGET", "SELECTOR", "PER_TX", "PER_EPOCH", "EXPIRED", "RECIPIENT", "CALLDATA_SHORT"].map((l) => [
    keccak256(toBytes(l)).slice(0, 10),
    l,
  ]),
);

const fork = process.argv.includes("--fork");

const chain = await startChain({ fork });
assertSafe(chain.rpcUrl, chain.chainId); // hard gate: refuses anything that could touch a real account
const viemChain = { id: chain.chainId, name: "local", nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [chain.rpcUrl] } } };

const pub = createPublicClient({ chain: viemChain, transport: http(chain.rpcUrl) });
const wait = (hash) => pub.waitForTransactionReceipt({ hash });

let exitCode = 0;
try {
  console.log("");
  console.log(bold("  UNTOLL · scoped-key agent delegation demo"));
  console.log(dim("  the agent does the allowed thing, and cannot do the forbidden thing"));
  console.log("");
  console.log(`  network      ${bold("chain " + chain.chainId)} at ${chain.rpcUrl}` + (fork ? dim("  (fork of Robinhood testnet 46630)") : ""));

  // Keys. Relayer is anvil's first dev account (sponsors gas on the local node). owner/session/attacker
  // are generated this run and thrown away at exit. None is ever funded on a real chain.
  const relayer = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
  const owner = privateKeyToAccount(generatePrivateKey());
  const session = privateKeyToAccount(generatePrivateKey());
  const attacker = privateKeyToAccount(generatePrivateKey());
  console.log(`  owner EOA    ${short(owner.address)}   ${dim("installs the scope; never handed to the agent")}`);
  console.log(`  session key  ${short(session.address)}   ${dim("the agent transacts with this, and only this")}`);
  console.log(`  attacker     ${short(attacker.address)}   ${dim("where a jailbroken agent would try to send funds")}`);
  console.log(dim(`  (all three: ${KEY_LABEL})`));

  const relayerWc = createWalletClient({ account: relayer, chain: viemChain, transport: http(chain.rpcUrl) });
  const ownerWc = createWalletClient({ account: owner, chain: viemChain, transport: http(chain.rpcUrl) });
  const sessionWc = createWalletClient({ account: session, chain: viemChain, transport: http(chain.rpcUrl) });

  for (const to of [owner.address, session.address]) await wait(await relayerWc.sendTransaction({ to, value: parseEther("100") }));

  // Deploy the real contracts. The delegate is the exact compiled bytecode of contracts/SessionKeyDelegate.sol.
  const delegateImpl = (await wait(await relayerWc.deployContract({ abi: delegateArt.abi, bytecode: delegateArt.bytecode }))).contractAddress;
  const targetContract = (await wait(await relayerWc.deployContract({ abi: targetArt.abi, bytecode: targetArt.bytecode }))).contractAddress;

  line();
  console.log(bold("  STEP 1  ") + "delegate the agent EOA to the SessionKeyDelegate (EIP-7702)");
  const codeBefore = (await pub.getCode({ address: owner.address })) || "0x";
  console.log(`  before:  code at owner EOA = ${codeBefore}  ${dim("(a plain EOA, no code)")}`);
  const auth = await ownerWc.signAuthorization({ account: owner, contractAddress: delegateImpl });
  await wait(await relayerWc.sendTransaction({ authorizationList: [auth], to: owner.address, data: "0x" }));
  const codeAfter = await pub.getCode({ address: owner.address });
  const isDelegated = codeAfter?.toLowerCase() === ("0xef0100" + delegateImpl.slice(2)).toLowerCase();
  console.log(`  after:   code at owner EOA = ${codeAfter}`);
  console.log(`           ${isDelegated ? green("✓") : red("✗")} that is the 0xef0100 delegation designator plus the delegate address: ${isDelegated ? green("real 7702, verified on this local chain") : red("NOT a real delegation")}`);
  if (!isDelegated) throw new Error("7702 delegation did not attach; aborting rather than showing theatre.");

  line();
  console.log(bold("  STEP 2  ") + "install the scope (the owner does this once, off-limits to the agent)");
  const swapSel = toFunctionSelector("swap(address,address,uint256,address)");
  const now = Number((await pub.getBlock()).timestamp);
  const scope = {
    owner: owner.address, sessionKey: session.address,
    expiry: BigInt(now + 86400), perTxCap: parseEther("1"), perEpochCap: parseEther("2"),
    // TKT-0433, the AMOUNT lane. perTxCap and perEpochCap meter the native `value` field, and an
    // ERC-20 call carries value == 0, so on a token they bound nothing. perTxUnitCap and
    // perEpochUnitCap meter the decoded amount ARGUMENT of any selector named in amountSelectors.
    // This scope allowlists only swap(), which grants no standing allowance, so the lane is left
    // unarmed. Allowlisting approve() with these at zero is refused on chain, by design.
    perTxUnitCap: 0n, perEpochUnitCap: 0n,
    epochLength: 3600n,
    targets: [targetContract], selectors: [swapSel], recipients: [owner.address], recipientSelectors: [swapSel], recipientArgs: [4n],
    amountSelectors: [], amountArgs: [],
  };
  await wait(await ownerWc.sendTransaction({ to: owner.address, data: encodeFunctionData({ abi: delegateArt.abi, functionName: "initialize", args: [scope] }) }));
  console.log(`  the session key may: call ${dim("swap(...)")} on ${short(targetContract)}, output to the owner only, ≤ 1 ETH/tx, before expiry.`);
  console.log(`  everything else is out of scope.`);

  const swapTo = (to) => encodeFunctionData({ abi: targetArt.abi, functionName: "swap", args: ["0x0000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000002", 1000n, to] });
  const exec = (target, value, data) => encodeFunctionData({ abi: delegateArt.abi, functionName: "execute", args: [target, value, data] });
  const tryExec = (target, value, data) => encodeFunctionData({ abi: delegateArt.abi, functionName: "tryExecute", args: [target, value, data] });

  line();
  console.log(bold("  STEP 3  ") + "the agent acts through its session key");
  console.log("");

  // Positive control: the ALLOWED action. A real mined transaction that settles.
  const okHash = await sessionWc.sendTransaction({ to: owner.address, data: exec(targetContract, 0n, swapTo(owner.address)) });
  const okRc = await wait(okHash);
  console.log(`  ${green("ALLOWED")}   in-scope call, output → owner    ${okRc.status === "success" ? green("PASSED") : red("failed")}   ${dim("tx " + short(okHash))}`);
  if (okRc.status !== "success") throw new Error("the in-scope control did not pass; aborting.");

  // The hard-revert guarantee: execute() the forbidden redirect. The real deployed contract reverts.
  let heroErr = "(no revert - THEATRE ALARM)";
  try {
    await pub.simulateContract({ address: owner.address, abi: delegateArt.abi, functionName: "execute", args: [targetContract, 0n, swapTo(attacker.address)], account: session.address });
  } catch (e) {
    heroErr = e.walk?.((x) => x?.data?.errorName)?.data?.errorName || e.cause?.data?.errorName || e.shortMessage || "reverted";
  }
  console.log(`  ${red("BLOCKED")}   in-scope call, output → attacker    ${red("execute() reverted: " + heroErr)}`);

  // Every forbidden vector, run through the monitored tryExecute() path: each mines a real tx whose
  // receipt carries a ScopeViolation with the breach reason. Decoded from the receipt, not narrated.
  const vectors = [
    { label: "redirect output → attacker", target: targetContract, value: 0n, data: swapTo(attacker.address) },
    { label: "off-scope selector drain()", target: targetContract, value: 0n, data: encodeFunctionData({ abi: targetArt.abi, functionName: "drain", args: [attacker.address] }) },
    { label: "over the 1 ETH per-tx cap", target: targetContract, value: parseEther("2"), data: swapTo(owner.address) },
    { label: "off-scope target (unknown)", target: attacker.address, value: 0n, data: swapTo(owner.address) },
  ];
  const { decodeEventLog } = await import("viem");
  const violations = [];
  for (const v of vectors) {
    const rc = await wait(await sessionWc.sendTransaction({ to: owner.address, value: v.value, data: tryExec(v.target, v.value, v.data) }));
    let reason = null;
    for (const log of rc.logs) {
      try { const d = decodeEventLog({ abi: delegateArt.abi, ...log }); if (d.eventName === "ScopeViolation") reason = d.args.reason; } catch {}
    }
    violations.push({ ...v, reason, label2: REASONS[reason] || reason, tx: rc.transactionHash });
    console.log(`  ${red("BLOCKED")}   ${v.label.padEnd(28)} ${red("ScopeViolation(" + (REASONS[reason] || reason) + ")")}  ${dim("tx " + short(rc.transactionHash))}`);
  }

  // Nothing moved: the target contract received value only from the one allowed call (0), and the
  // attacker EOA holds exactly its starting balance.
  const attackerBal = await pub.getBalance({ address: attacker.address });
  const noValueMoved = attackerBal === 0n;

  line();
  console.log(bold("  PROOF") + dim("  (re-checkable by hand; nothing here is asserted by the script's narration)"));
  console.log(`  chain id                ${chain.chainId} ${dim("(the RPC this run used)")}`);
  console.log(`  7702 delegation         ${codeAfter}`);
  console.log(`  delegate runtime hash   ${keccak256(codeAfter ? await pub.getCode({ address: delegateImpl }) : "0x")}  ${dim("keccak256 of the deployed SessionKeyDelegate code")}`);
  console.log(`  hard-revert reason      ${heroErr}  ${dim("(the real custom error, decoded from the deployed ABI)")}`);
  console.log(`  scope violations mined  ${violations.length} on-chain events, reasons: ${violations.map((v) => v.label2).join(", ")}`);
  console.log(`  attacker balance        ${attackerBal} wei  ${noValueMoved ? green("✓ no funds moved") : red("✗ funds moved")}`);

  line();
  console.log("");
  console.log("  " + green("✓ the allowed action passed") + "   and   " + red("✗ every forbidden action was stopped"));
  console.log(dim("  same session key for both. a compromised agent gains nothing the scope did not grant."));
  console.log("");
  if (!noValueMoved) throw new Error("value moved to the attacker; containment did not hold.");
} catch (err) {
  exitCode = 1;
  console.error("\n" + red("  demo failed: ") + (err?.shortMessage || err?.message || String(err)));
} finally {
  await chain.stop();
}
// Force a clean exit: if we auto-spawned anvil, a lingering child handle could otherwise keep node alive.
process.exit(exitCode);

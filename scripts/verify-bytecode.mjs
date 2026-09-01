// Prove the contract this demo deploys is the one it claims to deploy.
//
// WHY THIS SCRIPT WAS REWRITTEN. The previous version recompiled the repo's own contracts/*.sol and
// compared the result to the repo's own artifacts/*.json. Both halves came from the same tree, and
// `npm run build:contracts` writes the artifact FROM the source, so the check was circular and could
// not fail. It printed MATCH and exited 0 while this repo shipped a delegate with a known
// standing-allowance hole. A verification that cannot go red is worse than none, because a green tick
// launders a false claim into evidence.
//
// The fix is an anchor the build pipeline cannot write. EXPECTED.json carries hashes a human reviewed
// and committed. Nothing in `build:contracts`, `demo`, or this script ever writes it. Swap the source
// and rebuild the artifacts, and leg SOURCE goes red immediately, because the pin did not move.
//
// FOUR LEGS, all must pass, and a missing pin is a failure rather than a skip:
//   SOURCE    sha256(contracts/X.sol)            == EXPECTED.source_sha256
//   ARTIFACT  keccak(executable creation code)   == EXPECTED.creation_exec_keccak
//   COMPILE   artifact executable code           == fresh forge compile of contracts/X.sol
//   RUNTIME   keccak(executable deployed code)   == EXPECTED.runtime_exec_keccak
//
// COMPILE is the old leg. It is kept, because it still proves the artifact was not hand-edited, but it
// can no longer pass alone. RUNTIME is the strongest: it hashes the code that actually executes, as
// deployed from the shipped artifact, which is the same number the demo prints as its proof.
//
// STATED LIMIT, so nobody over-reads this. The pin lives in this repo, so an author who edits both the
// source and EXPECTED.json in one commit still passes. This control is not built against that. It is
// built against SILENT DRIFT, where a stale or wrong contract rides in while every automated check
// stays green. Moving the pin is a small, isolated, reviewable diff a human has to make on purpose.
//
// Run `npm run pin:print` to see the measured values. It prints and never writes: re-pinning is a
// human act by design, and no flag automates it.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import { createPublicClient, createWalletClient, http, keccak256 } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { startChain } from "./chain.mjs";
import { assertSafe } from "./safety.mjs";

const root = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const NAMES = ["SessionKeyDelegate", "MockTarget"];
const PRINT = process.argv.includes("--print");

const green = (s) => `\x1b[32m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;

// Strip the trailing CBOR metadata blob: its last 2 bytes are the blob length; remove blob plus those
// 2. Solidity encodes the source file PATH in that trailer, so the same code compiled at src/X.sol and
// at contracts/X.sol differs only there. The executable code is what actually runs.
function stripMeta(hex) {
  hex = hex.toLowerCase().replace(/^0x/, "");
  if (hex.length < 4) return hex;
  const len = parseInt(hex.slice(-4), 16);
  const cut = (len + 2) * 2;
  return cut < hex.length ? hex.slice(0, hex.length - cut) : hex;
}

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const hex0x = (h) => (h.startsWith("0x") ? h : "0x" + h);

// ---------------------------------------------------------------------------
// Load the pin. Fail closed: no pin, no verification. A missing anchor is exactly
// the state this script exists to refuse, so it must never degrade into a skip.
// ---------------------------------------------------------------------------
function loadPin() {
  const path = `${root}/EXPECTED.json`;
  if (!fs.existsSync(path)) {
    console.error(red("FAIL") + "  EXPECTED.json is missing. There is no anchor to verify against.");
    console.error(dim("      A recompile of this repo's own source against this repo's own artifact proves nothing."));
    console.error(dim("      Run `npm run pin:print`, review every value by hand, then commit EXPECTED.json."));
    process.exit(2);
  }
  let pin;
  try {
    pin = JSON.parse(fs.readFileSync(path, "utf8"));
  } catch (e) {
    console.error(red("FAIL") + `  EXPECTED.json is present but unparseable: ${e.message}`);
    process.exit(2);
  }
  for (const n of NAMES) {
    const c = pin.contracts?.[n];
    if (!c?.source_sha256 || !c?.creation_exec_keccak || !c?.runtime_exec_keccak) {
      console.error(red("FAIL") + `  EXPECTED.json carries no complete pin for ${n}.`);
      process.exit(2);
    }
  }
  return pin;
}

// ---------------------------------------------------------------------------
// Measure. Everything below is read off disk or off a chain, never asserted.
// ---------------------------------------------------------------------------
function measureOffline() {
  try {
    execFileSync("forge", ["build"], { cwd: root, stdio: "ignore", shell: process.platform === "win32" });
  } catch {
    console.error("forge not found. Install Foundry to verify: curl -L https://foundry.paradigm.xyz | bash && foundryup");
    process.exit(2);
  }
  const out = {};
  for (const n of NAMES) {
    const src = fs.readFileSync(`${root}/contracts/${n}.sol`);
    const shipped = JSON.parse(fs.readFileSync(`${root}/artifacts/${n}.json`)).bytecode;
    const fresh = JSON.parse(fs.readFileSync(`${root}/out/${n}.sol/${n}.json`)).bytecode.object;
    out[n] = {
      source_sha256: sha256(src),
      creation_exec_keccak: keccak256(hex0x(stripMeta(shipped))),
      shipped_exec: stripMeta(shipped),
      fresh_exec: stripMeta(fresh),
    };
  }
  return out;
}

// Deploy the SHIPPED artifacts on a throwaway local chain and hash the code that actually lands. This
// is the leg the build pipeline cannot reach: it is a property of executing bytes, not of files.
async function measureRuntime() {
  const chain = await startChain({});
  try {
    assertSafe(chain.rpcUrl, chain.chainId); // the same hard gate the demo uses: local endpoints only
    const viemChain = {
      id: chain.chainId,
      name: "local",
      nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
      rpcUrls: { default: { http: [chain.rpcUrl] } },
    };
    const pub = createPublicClient({ chain: viemChain, transport: http(chain.rpcUrl) });
    // anvil's first well-known dev key. Throwaway, local only, never funded on any real network.
    const deployer = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const wc = createWalletClient({ account: deployer, chain: viemChain, transport: http(chain.rpcUrl) });
    const out = {};
    for (const n of NAMES) {
      const art = JSON.parse(fs.readFileSync(`${root}/artifacts/${n}.json`));
      const hash = await wc.deployContract({ abi: art.abi, bytecode: art.bytecode });
      const { contractAddress } = await pub.waitForTransactionReceipt({ hash });
      const code = await pub.getCode({ address: contractAddress });
      if (!code || code === "0x") throw new Error(`${n} deployed with no runtime code`);
      out[n] = { runtime_exec_keccak: keccak256(hex0x(stripMeta(code))) };
    }
    return out;
  } finally {
    await chain.stop();
  }
}

// ---------------------------------------------------------------------------
const offline = measureOffline();
const runtime = await measureRuntime();

if (PRINT) {
  const block = {
    _comment:
      "Human-reviewed anchor. Nothing in the build writes this file. Review every value before committing a change to it.",
    upstream: { note: "the canonical source these contracts are a byte copy of", repo: "FILL IN", commit: "FILL IN" },
    reviewed: { by: "FILL IN", at: new Date().toISOString().slice(0, 10) },
    contracts: Object.fromEntries(
      NAMES.map((n) => [
        n,
        {
          source_sha256: offline[n].source_sha256,
          creation_exec_keccak: offline[n].creation_exec_keccak,
          runtime_exec_keccak: runtime[n].runtime_exec_keccak,
        },
      ]),
    ),
  };
  console.log("");
  console.log(dim("  Measured now. Review each value, then paste into EXPECTED.json. This command writes nothing."));
  console.log("");
  console.log(JSON.stringify(block, null, 2));
  process.exit(0);
}

const pin = loadPin();
let ok = true;
const row = (pass, leg, name, detail) => {
  ok = ok && pass;
  console.log(`${pass ? green("PASS") : red("FAIL")}  ${leg.padEnd(8)}  ${name.padEnd(19)}  ${detail}`);
};

console.log("");
for (const n of NAMES) {
  const m = offline[n];
  const r = runtime[n];
  const p = pin.contracts[n];

  const srcOk = m.source_sha256 === p.source_sha256;
  row(srcOk, "SOURCE", n, srcOk
    ? dim(`sha256 ${m.source_sha256.slice(0, 16)} matches the reviewed pin`)
    : red(`sha256 ${m.source_sha256.slice(0, 16)} but the pin says ${p.source_sha256.slice(0, 16)}`));

  const artOk = m.creation_exec_keccak === p.creation_exec_keccak;
  row(artOk, "ARTIFACT", n, artOk
    ? dim(`creation code ${m.creation_exec_keccak.slice(0, 18)} matches the reviewed pin`)
    : red(`creation code ${m.creation_exec_keccak.slice(0, 18)} but the pin says ${p.creation_exec_keccak.slice(0, 18)}`));

  const cmpOk = m.shipped_exec === m.fresh_exec;
  row(cmpOk, "COMPILE", n, cmpOk
    ? dim(`shipped artifact is the compile of contracts/${n}.sol`)
    : red(`shipped artifact is NOT the compile of contracts/${n}.sol`));

  const runOk = r.runtime_exec_keccak === p.runtime_exec_keccak;
  row(runOk, "RUNTIME", n, runOk
    ? dim(`deployed code ${r.runtime_exec_keccak.slice(0, 18)} matches the reviewed pin`)
    : red(`deployed code ${r.runtime_exec_keccak.slice(0, 18)} but the pin says ${p.runtime_exec_keccak.slice(0, 18)}`));
}

console.log("");
if (ok) {
  console.log(green("  Verified against the reviewed pin in EXPECTED.json, including the code deployed on chain."));
  if (pin.upstream?.commit) {
    console.log(dim(`  Source is a byte copy of ${pin.upstream.repo ?? "upstream"} at ${pin.upstream.commit}.`));
  }
} else {
  console.log(red("  MISMATCH. This build is not the reviewed one. Do not trust it, and do not publish it."));
  console.log(dim("  If the change was intended, review the new values with `npm run pin:print` and edit EXPECTED.json by hand."));
}
process.exit(ok ? 0 : 1);

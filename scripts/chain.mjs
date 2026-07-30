// Chain lifecycle: connect to a node you already have running, or start a local anvil in Prague mode
// (the hardfork that carries EIP-7702). The demo needs a 7702-capable EVM; anvil --hardfork prague is
// the guaranteed one. Nothing here touches a public network.
import { spawn, spawnSync } from "node:child_process";
import { createPublicClient, http } from "viem";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function reachable(rpcUrl) {
  try {
    const id = await createPublicClient({ transport: http(rpcUrl) }).getChainId();
    return id;
  } catch {
    return null;
  }
}

// Returns { rpcUrl, chainId, stop() }. If RPC env is set (you brought your own node or a fork), we use
// it. Otherwise we spawn anvil --hardfork prague and manage its lifecycle.
export async function startChain({ fork } = {}) {
  const envRpc = process.env.RPC;
  if (envRpc) {
    const chainId = await reachable(envRpc);
    if (!chainId) throw new Error(`RPC=${envRpc} is set but not reachable. Start the node, or unset RPC to auto-launch anvil.`);
    return { rpcUrl: envRpc, chainId, stop: async () => {} };
  }

  const port = 8545;
  const rpcUrl = `http://127.0.0.1:${port}`;
  const already = await reachable(rpcUrl);
  if (already) return { rpcUrl, chainId: already, stop: async () => {} };

  const args = ["--hardfork", "prague", "--port", String(port), "--silent"];
  if (fork) args.push("--fork-url", "https://rpc.testnet.chain.robinhood.com");

  // Spawn anvil.exe directly (no shell) so there is no cmd wrapper to orphan when we stop it. Fall back
  // to a shell only if the direct spawn cannot resolve anvil on this machine.
  let child;
  const trySpawn = (useShell) => spawn("anvil", args, { stdio: ["ignore", "ignore", "pipe"], shell: useShell });
  try {
    child = trySpawn(false);
    await new Promise((res, rej) => { child.once("spawn", res); child.once("error", rej); });
  } catch {
    try {
      child = trySpawn(true);
      await new Promise((res, rej) => { child.once("spawn", res); child.once("error", rej); });
    } catch {
      throw new Error(anvilMissingMessage(fork));
    }
  }
  let stderr = "";
  child.stderr?.on("data", (d) => (stderr += d.toString()));

  // Kill the whole tree so no anvil is left behind, even if a shell wrapper was used.
  const stop = async () => {
    try {
      if (process.platform === "win32" && child.pid) spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
      else child.kill("SIGTERM");
    } catch {}
  };

  for (let i = 0; i < 40; i++) {
    if (child.exitCode !== null) throw new Error(anvilMissingMessage(fork) + (stderr ? `\n\nanvil said:\n${stderr}` : ""));
    const chainId = await reachable(rpcUrl);
    if (chainId) return { rpcUrl, chainId, stop };
    await sleep(250);
  }
  await stop();
  throw new Error(`anvil did not become reachable on ${rpcUrl} within 10s.` + (stderr ? `\n\nanvil said:\n${stderr}` : ""));
}

function anvilMissingMessage(fork) {
  return [
    "Could not start anvil. This demo needs a 7702-capable local node.",
    "",
    "Install Foundry (one line):  curl -L https://foundry.paradigm.xyz | bash  &&  foundryup",
    "",
    "Or, in another terminal, start one yourself and re-run:",
    fork
      ? "  anvil --hardfork prague --fork-url https://rpc.testnet.chain.robinhood.com"
      : "  anvil --hardfork prague",
    "",
    "Already have a node? Point the demo at it:  RPC=http://127.0.0.1:8545 npm run demo",
  ].join("\n");
}

// The safety gate. This demo runs against a local chain with throwaway keys and moves no real value.
// The gate below is what makes that a guarantee instead of a promise: it refuses to run anywhere it
// could touch a real account. If you are reviewing this repo, this is the file to read first.

// Chain ids the demo is allowed to send transactions to. 31337 is anvil's default. 46630 is the
// Robinhood testnet, permitted ONLY through a local anvil --fork (see the localhost rule below), so a
// fork run still executes on your own machine and broadcasts nothing to the public chain.
const ALLOWED_CHAIN_IDS = new Set([31337, 46630]);

// The demo only ever sends transactions to a node on your own machine. A fork of a public testnet is
// still a localhost endpoint. A direct public RPC is refused: deploying our contracts to a public
// chain is a separate, operator-gated step, never something this quickstart does on your behalf.
function isLocalEndpoint(rpcUrl) {
  try {
    const h = new URL(rpcUrl).hostname;
    return h === "127.0.0.1" || h === "localhost" || h === "0.0.0.0" || h === "[::1]";
  } catch {
    return false;
  }
}

// Enforced before any key is generated or any transaction is signed. Throws to stop the run cold.
export function assertSafe(rpcUrl, chainId) {
  if (process.env.PRIVATE_KEY || process.env.MNEMONIC || process.env.SEED) {
    throw new Error(
      "This demo never uses a key you supply. Unset PRIVATE_KEY / MNEMONIC / SEED and re-run. " +
        "Every key here is generated fresh at runtime and thrown away when the process exits.",
    );
  }
  if (!isLocalEndpoint(rpcUrl)) {
    throw new Error(
      `Refusing to send transactions to a non-local endpoint (${rpcUrl}). This demo only drives a ` +
        "node on your own machine. To run against Robinhood testnet state, use a local fork: " +
        "`anvil --hardfork prague --fork-url https://rpc.testnet.chain.robinhood.com` then `npm run demo:fork`.",
    );
  }
  if (!ALLOWED_CHAIN_IDS.has(chainId)) {
    throw new Error(
      `Chain id ${chainId} is not on the allowlist ${[...ALLOWED_CHAIN_IDS].join(", ")}. ` +
        "The demo refuses to run against an unrecognized chain so it can never act on a live network.",
    );
  }
}

export const KEY_LABEL = "THROWAWAY, generated this run, never funded, safe to see in your terminal";

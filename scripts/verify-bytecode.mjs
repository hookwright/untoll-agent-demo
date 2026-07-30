// Prove the artifact the demo deploys is the real compiled output of contracts/SessionKeyDelegate.sol.
// Recompiles from source with forge and compares the executable bytecode.
//
// Solidity appends a CBOR metadata trailer that encodes the source file PATH, so a byte-for-byte match
// is not expected across two repos: the same code compiled at src/X.sol and contracts/X.sol differs
// only in that trailer. We strip the trailer and compare the executable code, which is what actually
// runs. A MATCH means the demo deploys the real contract logic, not a stand-in. Requires Foundry.
import { execFileSync } from "node:child_process";
import fs from "node:fs";

const root = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");

// Strip the trailing CBOR metadata blob: its last 2 bytes are the blob length; remove blob + those 2 bytes.
function stripMeta(hex) {
  hex = hex.toLowerCase().replace(/^0x/, "");
  if (hex.length < 4) return hex;
  const len = parseInt(hex.slice(-4), 16);
  const cut = (len + 2) * 2;
  return cut < hex.length ? hex.slice(0, hex.length - cut) : hex;
}

try {
  execFileSync("forge", ["build"], { cwd: root, stdio: "ignore", shell: process.platform === "win32" });
} catch {
  console.error("forge not found. Install Foundry to verify: curl -L https://foundry.paradigm.xyz | bash && foundryup");
  process.exit(2);
}

let ok = true;
for (const name of ["SessionKeyDelegate", "MockTarget"]) {
  const shipped = stripMeta(JSON.parse(fs.readFileSync(`${root}/artifacts/${name}.json`)).bytecode);
  const fresh = stripMeta(JSON.parse(fs.readFileSync(`${root}/out/${name}.sol/${name}.json`)).bytecode.object);
  const match = shipped === fresh;
  ok = ok && match;
  console.log(`${match ? "MATCH   " : "MISMATCH"}  ${name}  (executable code: shipped artifact vs fresh compile of contracts/${name}.sol)`);
}
console.log(ok ? "\nThe demo deploys the real contract code, verified from source." : "\nMISMATCH: the shipped artifact does not match the source. Do not trust this build.");
process.exit(ok ? 0 : 1);

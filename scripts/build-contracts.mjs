// Optional: recompile the shipped Solidity source into artifacts/ using forge. The demo does not need
// this (it ships precompiled artifacts), but running it lets you prove those artifacts came from the
// source in contracts/. Requires Foundry.
import { execFileSync } from "node:child_process";
import fs from "node:fs";

const root = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");

try {
  execFileSync("forge", ["build"], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
} catch {
  console.error("\nforge not found or build failed. Install Foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup");
  process.exit(1);
}

for (const name of ["SessionKeyDelegate", "MockTarget"]) {
  const j = JSON.parse(fs.readFileSync(`${root}/out/${name}.sol/${name}.json`));
  fs.writeFileSync(`${root}/artifacts/${name}.json`, JSON.stringify({ abi: j.abi, bytecode: j.bytecode.object }));
  console.log(`rebuilt artifacts/${name}.json from contracts/${name}.sol`);
}

# UNTOLL agent quickstart

Give an autonomous agent a scoped session key. Watch it do the allowed thing, and watch it get stopped
from doing the forbidden thing. One command, real contracts, no funds, no wallet to connect.

This is the containment core of the UNTOLL agent lane: an agent transacts with a key whose authority is
confined by contract bytecode, not by a signature its model could be talked into producing. When the
model is jailbroken, the drain hits the delegate and reverts. This demo makes that literal in your
terminal.

## What you will see

A green line and a red line, from the same session key:

```
  ALLOWED   in-scope call, output → owner    PASSED   tx 0xe68f…2e47
  BLOCKED   in-scope call, output → attacker    execute() reverted: RecipientNotAllowed
  BLOCKED   redirect output → attacker   ScopeViolation(RECIPIENT)  tx 0xed8f…c5a2
  BLOCKED   off-scope selector drain()   ScopeViolation(SELECTOR)  tx 0xeba2…9a79
  BLOCKED   over the 1 ETH per-tx cap    ScopeViolation(PER_TX)  tx 0x46ee…e543
  BLOCKED   off-scope target (unknown)   ScopeViolation(TARGET)  tx 0x1a88…5eac

  ✓ the allowed action passed   and   ✗ every forbidden action was stopped
```

The allowed in-scope call sends its output to the owner and passes. The identical call pointed at an
attacker reverts, changing nothing else. That one difference, a single address 100 bytes into the
calldata, is what a coarse wallet allowlist cannot catch and this delegate does.

## Prerequisites

- Node 18 or newer.
- Foundry (for the local chain). Install: `curl -L https://foundry.paradigm.xyz | bash && foundryup`.
  Already have a node running? Point the demo at it with `RPC=http://127.0.0.1:8545` and Foundry is
  optional.

## Run it

```
npm install
npm run demo
```

That is the whole path. The demo starts a local chain in Prague mode (the hardfork that carries
EIP-7702), generates three throwaway keys, deploys the real `SessionKeyDelegate`, delegates an agent
EOA to it, installs a scope, and runs the allowed action and five forbidden ones. It exits in a few
seconds and cleans up the chain it started.

Optional:

- `npm run demo:fork` runs the same demo on a local fork of Robinhood testnet (chain 46630), so the
  chain id and state are the real testnet's while execution stays on your machine.
- `npm run verify:bytecode` recompiles the contract from `contracts/` and confirms the executable code
  the demo deploys is the real thing, not a stand-in.

## What just happened

```
  owner EOA ──EIP-7702──▶ runs SessionKeyDelegate's code at its own address
      │
      │ installs a scope once (targets, selectors, caps, expiry, recipient policy)
      ▼
  session key ──execute()──▶ delegate checks scope ──▶ in-scope: forwards, out-of-scope: reverts
```

- The **owner key** installs the scope and is never handed to the agent.
- The **session key** is the only thing the agent transacts with. Even fully compromised, it can do
  only what the scope granted.
- `execute()` hard-reverts on any breach, so a drain moves no funds. `tryExecute()` does the same check
  but records the attempt as a `ScopeViolation` event instead of reverting, which is what the demo reads
  out of each mined receipt.

Every claim the demo prints is backed by an on-chain artifact you can re-check: the live chain id, the
`0xef0100…` delegation designator in the owner EOA's code, the real revert reason decoded from the
deployed ABI, and a mined `ScopeViolation` per blocked vector. Nothing is a hardcoded log line.

## Make it yours

- The scope lives in `scripts/demo.mjs` under `STEP 2`. Change the target, the selectors, the caps, or
  the recipient policy and re-run to see the boundary move.
- The action the agent takes is one `swap(...)` call. Drop in your own target contract and selector to
  scope a real agent action for your hackathon build.
- `contracts/SessionKeyDelegate.sol` is the full delegate. Its scope model (target and selector
  allowlists, per-tx and per-epoch value caps, hard expiry, and a per-selector recipient policy) is the
  surface you integrate against.

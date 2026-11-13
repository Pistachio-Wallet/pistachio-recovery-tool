# Pistachio recovery tool (Layer 2 of sovereign exit)

> ⚠️ **Unaudited prototype. Do not use it with significant funds.**
> This tool has not had a security audit. The only live sweep so far ran on a testnet (Base Sepolia).
> It moves native tokens only (ERC-20 tokens are not swept yet) and finds ZeroDev Kernel v3.0 smart
> accounts only. Test with a small amount first, and never paste a key into a hosted copy you have not verified.

Standalone, offline-capable static page: paste your Pistachio backup (raw private
key OR 24-word recovery phrase) → recompute the smart-account address your funds
live at → scan native balances across all supported EVM chains → sweep to an
address you choose via a public ERC-4337 bundler, self-paid gas. **Zero
Pistachio/Portal infra.**

The codec (`src/main.js`) mirrors Mobile `utils/Backup/recoveryPhrase.ts`
byte-for-byte, so the address it derives is the exact one the app promised.

## Build & run
    npm install
    npm run build            # esbuild → src/bundle.js
    (cd src && python3 -m http.server 8899)   # open http://localhost:8899

## Status (2026-08-02, updated)
- ✅ Derive + 12-chain balance scan: VERIFIED in-browser. Addresses match the
  Node core (02-recover.mjs) and the Mobile app.
- ✅ Sweep logic: reuses the path proven on Base Sepolia (sovereign-exit-spike
  §B). Needs a bundler URL + a funded account for a live in-browser run.

## TODO
- Inline bundle.js into a single self-contained recovery.html (true offline / IPFS-pinnable).
- Bundler hosting decision (embed a public bundler default vs user-provided; a public tool can't ship a Pimlico key).
- Live sweep test with real funds on one chain.
- Publish: GitHub Pages + IPFS pin; link from the app's "Pistachio recovery tool" copy.

## Update (later 2026-08-02)
- ✅ Full mainnet chain set now mirrors the app (18 chains incl. Robinhood, MegaETH, Monad,
  HyperEVM, Plume, Ink). RPCs are viem public defaults / chains' own public endpoints — no keyed
  or Pistachio infra ("lasts beyond us").
- ✅ Single self-contained `recovery.html` built (base64-inlined bundle, UTF-8-safe loader —
  a raw inline broke on a sequence in the 1MB bundle; base64 sidesteps it). Verified in-browser:
  derive + 18-chain scan work; one dead RPC (Plume) degrades to "unreachable" without blocking.

## Scope / generality
- Derivation is **Kernel v3.0** (ZeroDev, ECDSA owner, index 0) — the config Pistachio uses. So it
  recovers ANY Kernel v3.0 smart account owned by the given key, not only Pistachio. It does NOT
  cover Safe or other AA account types (different address derivation).
- The 24-word input uses Pistachio's scheme: the words ARE the raw key (mnemonicToEntropy). This is
  NOT a standard BIP-39 HD seed — a MetaMask-style seed derives keys via BIP-32 (m/44'/60'/…), which
  this does not do. Supporting standard seeds = add a BIP-32 HD-derivation mode.
- The private-key path is fully general (any EOA → its Kernel smart account).

## Update — universal modes (2026-08-02)
- ✅ Standard BIP-39 HD seed mode (MetaMask/Ledger): words → BIP-32 m/44'/60'/0'/0/0 → key.
  Verified against the canonical `abandon…about` vector (EOA 0x9858EfFD…Eda94) in-browser.
- ✅ Three input modes: private key (auto) / Pistachio phrase / standard seed (radio).
- ✅ Scans BOTH the owner EOA and the Kernel smart account across all chains, in two sections.
  (Live test found real dust on the test EOA across opBNB/Celo/Monad/Robinhood.)
- ✅ Sweep is per-account: EOA = plain signed tx (no bundler); Kernel = 4337 userOp (bundler).

## Not yet: Safe + other smart-account types
The tool covers EOAs (any key/seed) and Kernel v3.0. It does NOT yet derive Safe or other AA
account addresses. The blocker is real: a smart account's address depends on its deploy config
(factory version, singleton, owners, threshold, salt) — not derivable from the owner key alone for
most types. Plan: (a) derive the DEFAULT address per supported type (e.g. Safe v1.4.1 1-of-1,
canonical factory, saltNonce 0) and scan it, clearly caveated; (b) a manual-address field so a user
can paste any smart-account address to scan; (c) type-specific sweep (Safe execTransaction, etc.).

## Update — no-bundler sweep (2026-08-02)
The Kernel smart-account sweep no longer needs any bundler service. The tool hand-builds the
userOp and the **owner EOA submits it straight to the public EntryPoint v0.7 singleton**
(`0x0000000071727De22E5E9d8BAf0edAc6f37da032`, immutable + identical on every chain) via
`handleOps`, acting as its own bundler and reimbursing itself as `beneficiary`. The smart
account's own balance prefunds the op (self-paid gas) and the op deploys the account on first use.
Zero third-party infra — nothing to expire after us. Requirement surfaced in the UI: the owner
wallet needs a little native gas on the chain to front the `handleOps` tx (reimbursed from the
account). Dropped deps from the bundle: `permissionless`/pimlico (bundle 1.4MB → 1.35MB).
Verified in-browser (build/sign/pack/handleOps-encode proven in Node vs the real EntryPoint ABI);
a live funded smart-account sweep still needs a real funded Kernel account to confirm on-chain.

## Update — offline model + custom RPCs + verifiable download (2026-08-02)
Clarified what "offline" actually means and made the trust model honest:
- **The file is self-contained, not the network calls.** Deriving your address is pure math and
  works fully offline. Reading balances and broadcasting a sweep inherently need a live RPC — you
  cannot do them air-gapped. The old "disconnect before you paste" warning was self-contradictory
  and is gone.
- **Key never leaves the page.** It is used only to sign locally; the tool goes online only to read
  balances and broadcast. That's the real reason to prefer a verified download over a hosted page.
- **Custom RPC endpoints (Advanced).** Per-chain override: `chain url` per line (name or id).
  Chains without an override use their public default. Point these at your own node so recovery
  outlives any single provider. Verified in-browser (a bad Base override → Base "unreachable",
  the other 16 chains scan fine).

## Download & verify (the secure path — like a validator key ceremony)
Don't trust a hosted link with a real key. Instead:
1. Download `recovery.html` and `recovery.html.sha256` from the official GitHub release.
2. Verify the bytes: `shasum -a 256 -c recovery.html.sha256` → must print `recovery.html: OK`.
3. Open the saved file locally (double-click, or on an air-gapped machine for the derive step).

`npm run bundle` produces both `recovery.html` and its `.sha256`. Hosted mirrors (GitHub Pages,
IPFS pin) are convenience only; the verified download is what real recoveries should use.

## Live proof — no-bundler sweep on-chain (2026-08-03)
The smart-account sweep path was proven end-to-end on Base Sepolia using this repo's own
`sweep()` (no test doubles): a funded Kernel account was deployed AND swept in a single userOp
submitted by the owner EOA straight to the public EntryPoint v0.7 — **no bundler service**.
- Swept 0.00499216 ETH; smart account 0.005 → 0; destination received 0.00499216.
- `handleOps` tx `0xdbc4207f96c63a13ad2667ae75cc72934679da60c8f5d5e8b47ef093207988a6`
  (Base Sepolia, block 45002407, status success); `UserOperationEvent.success = true`;
  zero stranded EntryPoint deposit.

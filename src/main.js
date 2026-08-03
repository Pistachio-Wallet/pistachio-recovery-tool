// Pistachio recovery tool — standalone, offline-capable.
// Paste your backup (private key OR 24-word recovery phrase); it recomputes the
// smart-account address your funds live at, scans balances across chains, and
// sweeps to an address you choose. Zero Pistachio/Portal infra.
//
// The codec mirrors the Pistachio app (utils/Backup/recoveryPhrase.ts) exactly,
// so the address this derives is the same one the app showed you.

import {
    entropyToMnemonic,
    mnemonicToEntropy,
    mnemonicToSeedSync,
    validateMnemonic,
} from "@scure/bip39"
import { wordlist } from "@scure/bip39/wordlists/english"
import { HDKey } from "@scure/bip32"
import {
    http,
    createPublicClient,
    createWalletClient,
    defineChain,
    bytesToHex,
    hexToBytes,
    formatEther,
    isAddress,
    getAddress,
    zeroAddress,
    parseEventLogs,
} from "viem"
import { publicActionsL2 } from "viem/op-stack"
import { privateKeyToAccount } from "viem/accounts"
import {
    mainnet,
    optimism,
    polygon,
    arbitrum,
    base,
    plumeMainnet,
    mantle,
    scroll,
    opBNB,
    ink,
    bsc,
    hyperliquid,
    celo,
    linea,
    monad,
} from "viem/chains"

// Not (yet) exported by viem — mirrors the app's utils/viem/chains.ts, using the
// chains' own public RPC endpoints (default publics that outlast Pistachio).
const megaeth = defineChain({
    id: 4326,
    name: "MegaETH",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: ["https://mainnet.megaeth.com/rpc"] } },
})
const robinhood = defineChain({
    id: 4663,
    name: "Robinhood Chain",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: ["https://rpc.mainnet.chain.robinhood.com"] } },
})
import {
    entryPoint07Address,
    entryPoint07Abi,
    toPackedUserOperation,
} from "viem/account-abstraction"
import { getUserOperationHash } from "viem/account-abstraction"
import { createKernelAccount } from "@zerodev/sdk"
import { KERNEL_V3_0, getEntryPoint } from "@zerodev/sdk/constants"
import { signerToEcdsaValidator, getKernelAddressFromECDSA } from "@zerodev/ecdsa-validator"

// ---- codec (byte-for-byte mirror of the app) --------------------------------
const HEX_64 = /^[0-9a-f]{64}$/
const SECP256K1_ORDER = BigInt(
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
)

function normalizePrivateKey(raw) {
    const hex = String(raw).trim().toLowerCase().replace(/^0x/, "")
    if (!HEX_64.test(hex)) throw new Error("Expected a 32-byte hex private key")
    const scalar = BigInt(`0x${hex}`)
    if (scalar < 1n || scalar >= SECP256K1_ORDER)
        throw new Error("Private key is outside the valid secp256k1 range")
    return `0x${hex}`
}

function normalizePhrase(phrase) {
    return String(phrase).trim().replace(/\s+/g, " ").toLowerCase()
}

// PISTACHIO phrase: the 24 words ARE the raw private key (mnemonicToEntropy).
// NOT a standard HD seed — the words encode the key directly.
function pistachioPhraseToPrivateKey(phrase) {
    const p = normalizePhrase(phrase)
    if (p.split(" ").length !== 24)
        throw new Error("A Pistachio recovery phrase is 24 words")
    if (!validateMnemonic(p, wordlist))
        throw new Error("Invalid recovery phrase — check the words and their order")
    return normalizePrivateKey(bytesToHex(mnemonicToEntropy(p, wordlist)))
}

// BIP-32 HD key at an explicit derivation path, honoring an optional BIP-39
// passphrase (the "25th word"). Used for standard (MetaMask/Ledger) seeds.
function hdKeyAtPath(phrase, path, passphrase = "") {
    const seed = mnemonicToSeedSync(phrase, passphrase || "")
    const node = HDKey.fromMasterSeed(seed).derive(path)
    return normalizePrivateKey(bytesToHex(node.privateKey))
}

// STANDARD BIP-39 seed (MetaMask, Ledger, …): the words seed BIP-32 HD
// derivation at the Ethereum path m/44'/60'/0'/0/<index>. Supports 12–24 words.
export function standardSeedToPrivateKey(phrase, addressIndex = 0, passphrase = "") {
    const p = normalizePhrase(phrase)
    if (![12, 15, 18, 21, 24].includes(p.split(" ").length))
        throw new Error("A seed phrase is 12, 15, 18, 21, or 24 words")
    if (!validateMnemonic(p, wordlist))
        throw new Error("Invalid seed phrase — check the words and their order")
    return hdKeyAtPath(p, `m/44'/60'/0'/0/${addressIndex}`, passphrase)
}

// phraseMode: "pistachio" (default) or "standard". Ignored for a raw key.
// A backup with ANY whitespace (space, tab, newline) is treated as a phrase.
export function inputToPrivateKey(input, phraseMode = "pistachio") {
    const trimmed = String(input).trim()
    if (!trimmed) throw new Error("Enter your private key or recovery phrase")
    if (!/\s/.test(trimmed)) return normalizePrivateKey(trimmed)
    return phraseMode === "standard"
        ? standardSeedToPrivateKey(trimmed)
        : pistachioPhraseToPrivateKey(trimmed)
}

// For display only — never leaves the page.
export { normalizePrivateKey }

// ---- chains (the smart-account address is identical on every EVM chain) -----
// Mirrors the app's mainnet chain set. RPCs come from viem's built-in public
// defaults (or the chain's own public endpoint) — no keyed/Pistachio infra, so
// the tool keeps working after we're gone.
export const CHAINS = [
    mainnet, optimism, polygon, arbitrum, base, plumeMainnet, mantle, scroll,
    opBNB, ink, bsc, hyperliquid, celo, linea, monad,
    megaeth, robinhood,
]

// OP-stack L2s in our set (they charge a separate L1 data fee). Used to reserve a
// buffer if the L1 gas oracle can't be read, so an oracle blip can't underfund a tx.
const OP_STACK = new Set([10, 8453, 204, 57073]) // optimism, base, opBNB, ink

// Parse the "custom RPC" textarea into a { [chainId]: url } map. Each non-empty
// line is `<chainId or chain name> <url>` (separated by whitespace, `=`, or a
// comma). Unknown chains are ignored; the name match is case-insensitive.
export function parseRpcOverrides(text) {
    const out = {}
    if (!text) return out
    for (const raw of String(text).split("\n")) {
        const line = raw.trim()
        if (!line) continue
        const m = line.match(/^(.+?)[\s=,]+(https?:\/\/\S+)$/i)
        if (!m) continue
        const [, keyRaw, url] = m
        const key = keyRaw.trim().toLowerCase()
        const norm = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, "")
        const k = norm(key)
        // Exact by id or normalized name first; otherwise a UNIQUE name-prefix
        // (so "linea" matches "Linea Mainnet", but an ambiguous "polygon" still
        // resolves to the exact "Polygon" rather than "Polygon zkEVM").
        let chain =
            CHAINS.find((c) => String(c.id) === key || norm(c.name) === k)
        if (!chain) {
            const pref = CHAINS.filter((c) => norm(c.name).startsWith(k))
            if (pref.length === 1) chain = pref[0]
        }
        if (chain) out[chain.id] = url
    }
    return out
}

const ep = getEntryPoint("0.7")

// Checksum (EIP-55) an address for display, so a user can eyeball the sweep
// destination before an irreversible send. Passes through non-addresses unchanged.
export function checksumAddress(a) {
    return isAddress(a) ? getAddress(a) : a
}

// A public client used only to satisfy the derivation API. For EntryPoint v0.7 the
// Kernel init-code hash is computed locally, so this client never makes a network
// call during address derivation (verified: derivation works with an unreachable
// RPC). Kernel discovery is therefore fully offline and never depends on any RPC.
const derivationClient = createPublicClient({ chain: base, transport: http() })

// The Kernel v3.0 smart-account address for an owner key (counterfactual, same on
// every EVM chain), computed OFFLINE via CREATE2 — no RPC, no Base dependency.
async function kernelAddress(privateKey) {
    return getKernelAddressFromECDSA({
        publicClient: derivationClient,
        eoaAddress: privateKeyToAccount(privateKey).address,
        index: 0n,
        entryPoint: ep,
        kernelVersion: KERNEL_V3_0,
    })
}

// Kept for tests/back-compat: owner EOA + its Kernel address for one key.
export async function deriveAddresses(privateKey) {
    return {
        eoa: privateKeyToAccount(privateKey).address,
        smartAccount: await kernelAddress(privateKey),
    }
}

const HD_ACCOUNTS = 5 // scan account indices 0..4 on each standard path

// Turn a backup into the FULL set of candidate accounts to scan. Each candidate
// carries its own key (held only in this closure) so it can be swept individually.
//
// Why a set, not one account:
//  - A 24-word phrase is ambiguous — it can be a Pistachio phrase (the words ARE
//    the key) OR a standard BIP-39 seed. Guessing wrong derives a real-but-empty
//    account and reads as "funds gone", so we derive BOTH interpretations.
//  - Standard wallets keep funds across several accounts. MetaMask varies the
//    address index (m/44'/60'/0'/0/i); Ledger Live varies the hardened account
//    (m/44'/60'/i'/0/0). We enumerate both paths for accounts 0..4.
// `phraseMode` only decides which candidates are marked `primary` (always shown);
// every candidate is scanned regardless, so a wrong mode can never hide funds.
export async function deriveCandidates(input, phraseMode = "pistachio", passphrase = "") {
    const trimmed = String(input).trim()
    if (!trimmed) throw new Error("Enter your private key or recovery phrase")

    const out = []
    const seen = new Set()
    const addEoa = (key, label, hint, primary = false) => {
        const address = privateKeyToAccount(key).address
        const id = `eoa:${address.toLowerCase()}`
        if (seen.has(id)) return
        seen.add(id)
        out.push({ key, address, kind: "eoa", label, hint, primary })
    }
    const addKernel = async (key, label, hint, primary = false) => {
        const address = await kernelAddress(key)
        const id = `smart:${address.toLowerCase()}`
        if (seen.has(id)) return
        seen.add(id)
        out.push({ key, address, kind: "smart", label, hint, primary })
    }

    // Raw private key: an owner EOA and its Kernel smart account. (Any whitespace
    // means "phrase"; a bare key has none.)
    if (!/\s/.test(trimmed)) {
        const key = normalizePrivateKey(trimmed)
        addEoa(key, "Owner wallet (EOA)", "Plain wallets keep funds here", true)
        await addKernel(key, "Smart account (Kernel)", "Pistachio / ZeroDev accounts keep funds here", true)
        return out
    }

    const p = normalizePhrase(trimmed)
    const words = p.split(" ").length
    if (![12, 15, 18, 21, 24].includes(words))
        throw new Error("A recovery phrase is 12, 15, 18, 21, or 24 words")
    if (!validateMnemonic(p, wordlist))
        throw new Error("Invalid recovery phrase — check the words and their order")

    // Pistachio interpretation (24 words only — the words ARE the key; a BIP-39
    // passphrase does not apply). If the entropy isn't a valid secp256k1 scalar
    // this phrase can't be a Pistachio backup, so skip it rather than aborting.
    if (words === 24) {
        try {
            const pk = normalizePrivateKey(bytesToHex(mnemonicToEntropy(p, wordlist)))
            const pistachioPrimary = phraseMode !== "standard"
            addEoa(pk, "Pistachio phrase · owner (EOA)", "If this is a Pistachio backup", pistachioPrimary)
            await addKernel(pk, "Pistachio phrase · smart account (Kernel)", "Where Pistachio funds live", pistachioPrimary)
        } catch {
            // entropy out of scalar range — not a Pistachio key; standard only
        }
    }

    // Standard BIP-39 HD interpretation (MetaMask + Ledger paths, accounts 0..4),
    // honoring the optional BIP-39 passphrase. i=0 on both paths is the same key
    // (deduped). EVERY enumerated account also gets its Kernel candidate — a smart
    // account can be owned by any HD-path EOA, and offline derivation is cheap, so
    // we don't want a Kernel on account N > 0 to go unscanned.
    const stdPrimary = phraseMode === "standard" || words !== 24
    for (let i = 0; i < HD_ACCOUNTS; i++) {
        for (const [label, path] of [
            [`Standard seed · account ${i}`, `m/44'/60'/0'/0/${i}`],
            [`Ledger · account ${i}`, `m/44'/60'/${i}'/0/0`],
        ]) {
            const key = hdKeyAtPath(p, path, passphrase)
            addEoa(key, label, path, stdPrimary && path === "m/44'/60'/0'/0/0")
            await addKernel(key, `${label} · Kernel`, "Smart account owned by this path", false)
        }
    }
    return out
}

// A per-chain RPC override map { [chainId]: url }. The chains' own public RPCs
// are the default, but any public endpoint eventually rate-limits or dies — an
// override lets a user point at their own node (or any live endpoint), which is
// what actually keeps this working after every default provider. http(undefined)
// falls back to the chain's built-in default, so an absent override is harmless.
function rpc(chain, rpcOverrides = {}) {
    // Fail fast: a dead endpoint shouldn't stall the whole scan behind the default
    // multi-retry/long-timeout behavior. One quick retry, short timeout.
    return http(rpcOverrides[chain.id], { timeout: 8_000, retryCount: 1 })
}

// Scan native balance of one address across all chains, in parallel. Never
// throws — an unreachable RPC just reports as null so one dead chain can't hide
// the others.
export async function scanBalances(address, rpcOverrides = {}) {
    return Promise.all(
        CHAINS.map(async (chain) => {
            try {
                const client = createPublicClient({ chain, transport: rpc(chain, rpcOverrides) })
                const wei = await client.getBalance({ address })
                return {
                    chainId: chain.id,
                    name: chain.name,
                    symbol: chain.nativeCurrency.symbol,
                    wei,
                    formatted: formatEther(wei),
                    ok: true,
                }
            } catch {
                return { chainId: chain.id, name: chain.name, ok: false }
            }
        }),
    )
}

// Scan many candidate addresses across all chains at once. One client per chain
// (not per address) so a dead/slow RPC costs a single timeout for the whole scan
// instead of one per candidate. Returns a Map address -> per-chain balance rows.
export async function scanCandidates(addresses, rpcOverrides = {}) {
    const result = new Map(addresses.map((a) => [a, []]))
    await Promise.all(
        CHAINS.map(async (chain) => {
            let wei
            try {
                const client = createPublicClient({ chain, transport: rpc(chain, rpcOverrides) })
                // If the user supplied a custom RPC for this chain, verify it really
                // serves this chain id before trusting its balances — otherwise a
                // wrong-network endpoint would mislabel balances (and a bogus Sweep).
                if (rpcOverrides[chain.id]) {
                    const cid = await client.getChainId()
                    if (cid !== chain.id)
                        throw new Error(`Custom RPC for ${chain.name} reports chain ${cid}`)
                }
                wei = await Promise.all(
                    addresses.map((a) =>
                        client.getBalance({ address: a }).then(
                            (w) => ({ ok: true, w }),
                            () => ({ ok: false }),
                        ),
                    ),
                )
            } catch {
                wei = addresses.map(() => ({ ok: false }))
            }
            addresses.forEach((a, i) => {
                const b = wei[i]
                result.get(a).push(
                    b.ok
                        ? {
                              chainId: chain.id,
                              name: chain.name,
                              symbol: chain.nativeCurrency.symbol,
                              wei: b.w,
                              formatted: formatEther(b.w),
                              ok: true,
                          }
                        : { chainId: chain.id, name: chain.name, ok: false },
                )
            })
        }),
    )
    return result
}

// Read one address's native balance on one chain, formatted in ether. Used to show
// the residual after a sweep (a charged-but-reverted op / gas buffer changes state).
export async function readBalance(address, chain, rpcOverrides = {}) {
    const client = createPublicClient({ chain, transport: rpc(chain, rpcOverrides) })
    return formatEther(await client.getBalance({ address }))
}

// Sweep native balance of the OWNER EOA (standard-seed / EOA wallets) to
// `destination` — a plain transaction the EOA signs itself. No bundler needed.
export async function sweepEoa({ privateKey, chain, destination, rpcOverrides = {} }) {
    if (!isAddress(destination)) throw new Error("Enter a valid destination address")
    const account = privateKeyToAccount(privateKey)
    const publicClient = createPublicClient({ chain, transport: rpc(chain, rpcOverrides) })
    const walletClient = createWalletClient({ account, chain, transport: rpc(chain, rpcOverrides) })
    const balance = await publicClient.getBalance({ address: account.address })

    // Fees: EIP-1559 where supported, LEGACY (type-0, gasPrice) otherwise. Detect
    // which from the chain's own latest block — `estimateFeesPerGas()` can RESOLVE
    // (not throw) on a legacy chain, so a try/catch isn't enough; a block with no
    // baseFeePerGas is pre-1559 and must be signed as a legacy (gasPrice) tx.
    let feePerGas, feeFields
    const latest = await publicClient.getBlock()
    if (latest.baseFeePerGas == null) {
        const gp = await publicClient.getGasPrice()
        feePerGas = gp
        feeFields = { gasPrice: gp }
    } else {
        const e = await publicClient.estimateFeesPerGas()
        feePerGas = e.maxFeePerGas
        feeFields = { maxFeePerGas: e.maxFeePerGas, maxPriorityFeePerGas: e.maxPriorityFeePerGas }
    }

    // Destination-aware gas. A plain EOA transfer is 21k, but a contract receiver
    // whose logic scales with the amount can need far more — estimate with the REAL
    // (near-full) value, not dust, using a state override so the simulation has
    // headroom to "send" it, then add margin. Fall back to a contract-aware default.
    const destCode = await publicClient.getCode({ address: destination })
    const destIsContract = !!destCode && destCode.length > 2
    let gas
    try {
        gas =
            ((await publicClient.estimateGas({
                account,
                to: destination,
                value: balance,
                stateOverride: [{ address: account.address, balance: balance * 2n }],
            })) *
                12n) /
            10n
    } catch {
        gas = destIsContract ? 300_000n : 21_000n
    }
    const l2Cost = gas * feePerGas
    // On OP-stack L2s the sender ALSO pays an L1 data fee not in l2Cost. Estimate it
    // via the L1 gas oracle; if the oracle can't be read on a KNOWN OP-stack chain,
    // reserve a buffer rather than 0 (an oracle blip must not underfund the tx).
    let l1Fee = 0n
    try {
        const l2 = publicClient.extend(publicActionsL2())
        l1Fee = await l2.estimateL1Fee({ account, to: destination, value: balance })
    } catch {
        // Oracle unavailable on a known OP-stack chain: reserve a buffer with an
        // absolute floor (0.0001 native) so the reserve doesn't collapse when the
        // L2 gas price is tiny — the L1 fee is independent of the L2 gas price.
        if (OP_STACK.has(chain.id)) {
            const FLOOR = 100_000_000_000_000n // 0.0001 native
            const coupled = l2Cost * 4n
            l1Fee = coupled > FLOOR ? coupled : FLOOR
        }
    }
    const reserve = l2Cost + (l1Fee > 0n ? (l1Fee * 3n) / 2n : 0n)
    if (balance <= reserve)
        throw new Error("EOA balance is too low to cover the transfer gas on this chain")
    const value = balance - reserve
    const hash = await walletClient.sendTransaction({ to: destination, value, gas, ...feeFields })
    const receipt = await publicClient.waitForTransactionReceipt({ hash })
    return { swept: formatEther(value), txHash: hash, success: receipt.status === "success" }
}

// Sweep the smart account's native balance with NO bundler service. We hand-build
// the userOp and the owner EOA submits it straight to the public EntryPoint v0.7
// singleton (`handleOps`), acting as its own bundler and reimbursing itself as the
// `beneficiary`. The smart account's own balance prefunds the op (self-paid gas),
// and the op deploys the account on its first use. Zero third-party infra — the
// EntryPoint is immutable and identical on every chain, so this keeps working
// after every bundler service and after us.
//
// One requirement: because the owner EOA fronts the L1 gas to send `handleOps`
// (then gets reimbursed from the account), it needs a small amount of native gas
// on this chain. Fund the owner address shown above with a little gas first.
export async function sweep({ privateKey, chain, destination, rpcOverrides = {} }) {
    if (!isAddress(destination)) throw new Error("Enter a valid destination address")
    const publicClient = createPublicClient({ chain, transport: rpc(chain, rpcOverrides) })
    const signer = privateKeyToAccount(privateKey)
    const walletClient = createWalletClient({ account: signer, chain, transport: rpc(chain, rpcOverrides) })
    const ecdsaValidator = await signerToEcdsaValidator(publicClient, {
        entryPoint: ep, kernelVersion: KERNEL_V3_0, signer,
    })
    const account = await createKernelAccount(publicClient, {
        entryPoint: ep, kernelVersion: KERNEL_V3_0,
        plugins: { sudo: ecdsaValidator }, index: 0n,
    })

    // Refuse chains where the Kernel factory isn't deployed. There the SDK
    // reconstructs a zero/incorrect sender (e.g. Polygon zkEVM), which would build
    // a userOp for the wrong account. The offline derivation is the real address.
    const expected = await kernelAddress(privateKey)
    if (account.address === zeroAddress || account.address.toLowerCase() !== expected.toLowerCase())
        throw new Error(
            `Kernel accounts aren't supported on ${chain.name} (missing factory deployment) — funds here can't be swept with this tool.`,
        )

    // Fees: EIP-1559 where supported, legacy gasPrice otherwise.
    let maxFeePerGas, maxPriorityFeePerGas
    try {
        const est = await publicClient.estimateFeesPerGas()
        maxFeePerGas = est.maxFeePerGas
        maxPriorityFeePerGas = est.maxPriorityFeePerGas
    } catch {
        const gp = await publicClient.getGasPrice()
        maxFeePerGas = gp
        maxPriorityFeePerGas = gp
    }

    // Gas limits (no bundler to estimate for us). Call gas is destination-aware: a
    // contract-wallet receiver needs far more than an EOA, and a fixed low limit
    // would revert the transfer while still deploying + charging gas. First use
    // must also pay to deploy the account, so verification gets extra headroom.
    const destCode = await publicClient.getCode({ address: destination })
    const callGasLimit = destCode && destCode.length > 2 ? 500_000n : 120_000n
    const code = await publicClient.getCode({ address: account.address })
    const deployed = !!code && code.length > 2
    const verificationGasLimit = deployed ? 200_000n : 800_000n
    const preVerificationGas = 200_000n
    const maxGasCost =
        (callGasLimit + verificationGasLimit + preVerificationGas) * maxFeePerGas

    // Prefund can come from native balance OR an existing EntryPoint deposit;
    // account for the deposit so a deposit-funded / near-zero-native account isn't
    // wrongly rejected.
    let priorDeposit = 0n
    try {
        priorDeposit = await publicClient.readContract({
            address: entryPoint07Address, abi: entryPoint07Abi,
            functionName: "balanceOf", args: [account.address],
        })
    } catch {
        // treat as 0
    }
    const balance = await publicClient.getBalance({ address: account.address })
    const needNative = maxGasCost > priorDeposit ? maxGasCost - priorDeposit : 0n
    if (balance <= needNative)
        throw new Error(
            `Smart-account balance ${formatEther(balance)} is too low to cover the self-submitted sweep gas on this chain`,
        )
    const value = balance - needNative

    // The owner EOA must be able to front the handleOps tx gas.
    const eoaBalance = await publicClient.getBalance({ address: signer.address })
    if (eoaBalance <= maxGasCost)
        throw new Error(
            `The owner wallet ${signer.address} needs a little native gas on this chain to submit the sweep (send it some ${chain.nativeCurrency.symbol}, then retry — it is reimbursed from the account)`,
        )

    const nonce = await account.getNonce()
    const { factory, factoryData } = await account.getFactoryArgs()
    const callData = await account.encodeCalls([{ to: destination, value, data: "0x" }])
    const op = {
        sender: account.address,
        nonce,
        ...(deployed ? {} : { factory, factoryData }),
        callData,
        callGasLimit,
        verificationGasLimit,
        preVerificationGas,
        maxFeePerGas,
        maxPriorityFeePerGas,
    }
    const stub = await account.getStubSignature({ ...op, signature: "0x" })
    const signature = await account.signUserOperation({ ...op, signature: stub })
    const packed = toPackedUserOperation({ ...op, signature })

    const hash = await walletClient.writeContract({
        address: entryPoint07Address,
        abi: entryPoint07Abi,
        functionName: "handleOps",
        args: [[packed], signer.address],
    })
    const receipt = await publicClient.waitForTransactionReceipt({ hash })
    // receipt.status only reflects the OUTER handleOps tx. A userOp can pass
    // validation yet REVERT in execution while handleOps still succeeds — so
    // authenticate the outcome from the EntryPoint's UserOperationEvent, matched by
    // sender AND nonce (not sender alone), and require it to be present AND
    // successful. Missing / mismatched / unrelated evidence is NOT success.
    let opFound = false
    let opSuccess = false
    try {
        const events = parseEventLogs({
            abi: entryPoint07Abi,
            logs: receipt.logs,
            eventName: "UserOperationEvent",
        })
        const mine = events.find(
            (e) =>
                e.args.sender?.toLowerCase() === account.address.toLowerCase() &&
                e.args.nonce === nonce,
        )
        if (mine) {
            opFound = true
            opSuccess = mine.args.success === true
        }
    } catch {
        // couldn't parse logs — leave unfound (treated as unverified below)
    }
    const success = receipt.status === "success" && opFound && opSuccess
    const note =
        receipt.status === "success" && !opFound
            ? "Could not find this operation's on-chain event — verify the transaction before assuming funds moved."
            : undefined

    // Residual gas over-reservation is refunded to the account's EntryPoint DEPOSIT
    // (recoverable via withdrawTo). Report it; a failed read is reported as unknown
    // (null), never silently zero.
    let strandedDeposit = null
    try {
        strandedDeposit = formatEther(
            await publicClient.readContract({
                address: entryPoint07Address,
                abi: entryPoint07Abi,
                functionName: "balanceOf",
                args: [account.address],
            }),
        )
    } catch {
        // leave null = unknown
    }
    return { swept: formatEther(value), txHash: hash, success, opSuccess, note, strandedDeposit }
}

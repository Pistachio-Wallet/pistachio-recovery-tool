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
    validateMnemonic,
} from "@scure/bip39"
import { wordlist } from "@scure/bip39/wordlists/english"
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
    parseEventLogs,
} from "viem"
import { publicActionsL2 } from "viem/op-stack"
import { privateKeyToAccount, mnemonicToAccount } from "viem/accounts"
import {
    mainnet,
    optimism,
    polygon,
    arbitrum,
    base,
    plume,
    mantle,
    scroll,
    opBNB,
    polygonZkEvm,
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
import { createKernelAccount } from "@zerodev/sdk"
import { KERNEL_V3_0, getEntryPoint } from "@zerodev/sdk/constants"
import { signerToEcdsaValidator } from "@zerodev/ecdsa-validator"

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

// STANDARD BIP-39 seed (MetaMask, Ledger, …): the words seed BIP-32 HD
// derivation at the Ethereum path m/44'/60'/0'/0/<index>. Supports 12–24 words.
export function standardSeedToPrivateKey(phrase, addressIndex = 0) {
    const p = normalizePhrase(phrase)
    if (![12, 15, 18, 21, 24].includes(p.split(" ").length))
        throw new Error("A seed phrase is 12, 15, 18, 21, or 24 words")
    if (!validateMnemonic(p, wordlist))
        throw new Error("Invalid seed phrase — check the words and their order")
    const hd = mnemonicToAccount(p, { addressIndex })
    return normalizePrivateKey(bytesToHex(hd.getHdKey().privateKey))
}

// phraseMode: "pistachio" (default) or "standard". Ignored for a raw key.
export function inputToPrivateKey(input, phraseMode = "pistachio") {
    const trimmed = String(input).trim()
    if (!trimmed) throw new Error("Enter your private key or recovery phrase")
    if (!trimmed.includes(" ")) return normalizePrivateKey(trimmed)
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
    mainnet, optimism, polygon, arbitrum, base, plume, mantle, scroll,
    opBNB, polygonZkEvm, ink, bsc, hyperliquid, celo, linea, monad,
    megaeth, robinhood,
]

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

// The Kernel v3.0 smart-account address for an owner key (counterfactual, same on
// every EVM chain). Any chain works for derivation.
async function kernelAddress(privateKey) {
    const client = createPublicClient({ chain: base, transport: http() })
    const signer = privateKeyToAccount(privateKey)
    const ecdsaValidator = await signerToEcdsaValidator(client, {
        entryPoint: ep, kernelVersion: KERNEL_V3_0, signer,
    })
    const account = await createKernelAccount(client, {
        entryPoint: ep, kernelVersion: KERNEL_V3_0,
        plugins: { sudo: ecdsaValidator }, index: 0n,
    })
    return account.address
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
export async function deriveCandidates(input, phraseMode = "pistachio") {
    const trimmed = String(input).trim()
    if (!trimmed) throw new Error("Enter your private key or recovery phrase")

    const out = []
    const addEoa = (key, label, hint, primary = false) =>
        out.push({ key, address: privateKeyToAccount(key).address, kind: "eoa", label, hint, primary })
    const addKernel = async (key, label, hint, primary = false) =>
        out.push({ key, address: await kernelAddress(key), kind: "smart", label, hint, primary })

    // Raw private key: an owner EOA and its Kernel smart account.
    if (!trimmed.includes(" ")) {
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

    // Pistachio interpretation (24 words only — the words ARE the key). If the
    // entropy isn't a valid secp256k1 scalar this phrase simply can't be a
    // Pistachio backup, so skip it rather than aborting the standard derivation.
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

    // Standard BIP-39 HD interpretation (MetaMask + Ledger paths, accounts 0..4).
    const stdPrimary = phraseMode === "standard" || words !== 24
    const seen = new Set(out.map((c) => `${c.kind}:${c.address.toLowerCase()}`))
    for (let i = 0; i < HD_ACCOUNTS; i++) {
        const mm = mnemonicToAccount(p, { addressIndex: i }) // m/44'/60'/0'/0/i
        const lg = mnemonicToAccount(p, { accountIndex: i }) // m/44'/60'/i'/0/0
        const push = (acct, label, hint, primary) => {
            const key = normalizePrivateKey(bytesToHex(acct.getHdKey().privateKey))
            const id = `eoa:${privateKeyToAccount(key).address.toLowerCase()}`
            if (seen.has(id)) return // i=0 MetaMask and Ledger paths coincide
            seen.add(id)
            addEoa(key, label, hint, primary)
        }
        push(mm, `Standard seed · account ${i}`, `m/44'/60'/0'/0/${i}`, stdPrimary && i === 0)
        push(lg, `Ledger · account ${i}`, `m/44'/60'/${i}'/0/0`, false)
    }
    return out
}

// A per-chain RPC override map { [chainId]: url }. The chains' own public RPCs
// are the default, but any public endpoint eventually rate-limits or dies — an
// override lets a user point at their own node (or any live endpoint), which is
// what actually keeps this working after every default provider. http(undefined)
// falls back to the chain's built-in default, so an absent override is harmless.
function rpc(chain, rpcOverrides = {}) {
    return http(rpcOverrides[chain.id])
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

// Sweep native balance of the OWNER EOA (standard-seed / EOA wallets) to
// `destination` — a plain transaction the EOA signs itself. No bundler needed.
export async function sweepEoa({ privateKey, chain, destination, rpcOverrides = {} }) {
    if (!isAddress(destination)) throw new Error("Enter a valid destination address")
    const account = privateKeyToAccount(privateKey)
    const publicClient = createPublicClient({ chain, transport: rpc(chain, rpcOverrides) })
    const walletClient = createWalletClient({ account, chain, transport: rpc(chain, rpcOverrides) })
    const balance = await publicClient.getBalance({ address: account.address })

    // Fees: EIP-1559 where supported, legacy gasPrice otherwise.
    let maxFeePerGas, maxPriorityFeePerGas
    try {
        const e = await publicClient.estimateFeesPerGas()
        maxFeePerGas = e.maxFeePerGas
        maxPriorityFeePerGas = e.maxPriorityFeePerGas
    } catch {
        maxFeePerGas = maxPriorityFeePerGas = await publicClient.getGasPrice()
    }

    const gas = 21_000n
    const l2Cost = gas * maxFeePerGas
    // On OP-stack L2s (Optimism/Base/opBNB/Ink) the sender ALSO pays an L1 data
    // fee that isn't in l2Cost. Estimate it via the L1 gas oracle; on non-OP
    // chains the call throws and we treat it as 0. Reserve it (with variance
    // headroom) so the sweep doesn't fail for insufficient funds on those chains.
    let l1Fee = 0n
    try {
        const l2 = publicClient.extend(publicActionsL2())
        l1Fee = await l2.estimateL1Fee({ account, to: destination, value: 1n })
    } catch {
        // not an OP-stack chain / no L1 oracle — no separate L1 fee
    }
    const reserve = l2Cost + (l1Fee > 0n ? (l1Fee * 3n) / 2n : 0n)
    if (balance <= reserve)
        throw new Error("EOA balance is too low to cover the transfer gas on this chain")
    const value = balance - reserve
    const hash = await walletClient.sendTransaction({
        to: destination,
        value,
        gas,
        maxFeePerGas,
        maxPriorityFeePerGas,
    })
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

    // Gas limits: generous fixed values (no bundler to estimate for us). First use
    // must also pay to deploy the account, so verification gets extra headroom.
    const code = await publicClient.getCode({ address: account.address })
    const deployed = !!code && code.length > 2
    const callGasLimit = 120_000n
    const verificationGasLimit = deployed ? 200_000n : 800_000n
    const preVerificationGas = 200_000n
    const maxGasCost =
        (callGasLimit + verificationGasLimit + preVerificationGas) * maxFeePerGas

    const balance = await publicClient.getBalance({ address: account.address })
    if (balance <= maxGasCost)
        throw new Error(
            `Smart-account balance ${formatEther(balance)} is too low to cover the self-submitted sweep gas on this chain`,
        )
    const value = balance - maxGasCost

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
    // validation yet REVERT in execution (e.g. callGasLimit too low for a contract
    // destination) while handleOps still succeeds — so decode the EntryPoint's
    // UserOperationEvent and require its `success` flag before claiming the sweep
    // landed. If the event can't be found, fall back to the outer status.
    let opSuccess
    try {
        const events = parseEventLogs({
            abi: entryPoint07Abi,
            logs: receipt.logs,
            eventName: "UserOperationEvent",
        })
        const mine = events.find(
            (e) => e.args.sender?.toLowerCase() === account.address.toLowerCase(),
        )
        if (mine) opSuccess = mine.args.success
    } catch {
        // couldn't parse — leave opSuccess undefined and use the outer status
    }
    const success = receipt.status === "success" && opSuccess !== false

    // The fixed gas limits over-reserve; the unused remainder is refunded to the
    // account's EntryPoint DEPOSIT (not the destination). Report it so the user
    // knows funds remain and can reclaim them via EntryPoint.withdrawTo.
    let stranded = "0"
    try {
        const dep = await publicClient.readContract({
            address: entryPoint07Address,
            abi: entryPoint07Abi,
            functionName: "balanceOf",
            args: [account.address],
        })
        stranded = formatEther(dep)
    } catch {
        // best-effort — leave "0" if the read fails
    }
    return { swept: formatEther(value), txHash: hash, success, opSuccess, strandedDeposit: stranded }
}

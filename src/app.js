import {
    deriveCandidates,
    scanCandidates,
    sweep,
    sweepEoa,
    readBalance,
    parseRpcOverrides,
    checksumAddress,
    CHAINS,
} from "./main.js"

const $ = (id) => document.getElementById(id)
const show = (el) => el.classList.remove("hidden")
const hide = (el) => el.classList.add("hidden")
const isAddr = (s) => /^0x[0-9a-fA-F]{40}$/.test(s)

// Build DOM nodes with textContent — never innerHTML of dynamic values. This page
// holds a private key, so a single XSS foothold (e.g. a hostile RPC response) would
// be fatal; keeping all dynamic data as text neutralizes that class of bug.
function el(tag, className, text) {
    const e = document.createElement(tag)
    if (className) e.className = className
    if (text != null) e.textContent = text
    return e
}

// Candidate accounts (each carries its own key) live only in this closure while
// the page is open. The input textarea is wiped as soon as they're derived.
let candidates = []
let rpcOverrides = {}

function setStatus(msg, kind = "") {
    const s = $("status")
    s.textContent = msg
    s.className = kind
}

function phraseMode() {
    const m = document.querySelector('input[name="mode"]:checked')
    return m ? m.value : "pistachio"
}

function trim(v) {
    const n = Number(v)
    return n === 0 ? "0" : n < 0.0001 ? "<0.0001" : n.toFixed(6).replace(/0+$/, "")
}

async function onRecover() {
    setStatus("Recovering…")
    hide($("results"))
    $("accounts").innerHTML = ""
    try {
        rpcOverrides = parseRpcOverrides($("rpcOverrides").value)
        candidates = await deriveCandidates(
            $("backup").value,
            phraseMode(),
            $("passphrase") ? $("passphrase").value : "",
        )
        // Keys are now captured in `candidates`; wipe the plaintext DOM copies (the
        // seed AND the passphrase) so a later script foothold can't read them back.
        $("backup").value = ""
        if ($("passphrase")) $("passphrase").value = ""
        show($("results"))
        setStatus(`Scanning ${candidates.length} derived account(s) across chains…`)
        const balances = await scanCandidates(
            candidates.map((c) => c.address),
            rpcOverrides,
        )
        renderCandidates(balances)
    } catch (e) {
        setStatus(e.message || String(e), "err")
    }
}

function renderCandidates(balancesMap) {
    const empties = []
    for (const c of candidates) {
        const rows = balancesMap.get(c.address) || []
        const funded = rows.some((b) => b.ok && b.wei > 0n)
        if (c.primary || funded) renderCard(c, rows)
        else empties.push(c)
    }
    if (empties.length) renderEmptySummary(empties)

    // Count unreachable chains across EVERY candidate (a per-address RPC failure on
    // a later candidate must not be hidden behind the first candidate's success).
    const unreachableChains = new Set()
    for (const c of candidates)
        for (const b of balancesMap.get(c.address) || [])
            if (!b.ok) unreachableChains.add(b.chainId)
    if (unreachableChains.size > 0)
        setStatus(
            `Scan incomplete — ${unreachableChains.size} chain(s) unreachable. Retry, or add a custom RPC under Advanced, before assuming a chain is empty.`,
            "warn",
        )
    else setStatus("Recovered. Any funds found are shown below.", "ok")
}

function renderCard(c, rows) {
    const card = el("div", "acct")
    const head = el("div", "acct-head")
    head.append(el("div", "k", c.label), el("div", "hint", c.hint))
    const table = document.createElement("table")
    table.innerHTML =
        '<thead><tr><th>Chain</th><th class="num">Native balance</th><th></th></tr></thead><tbody></tbody>'
    card.append(head, el("div", "v" + (c.kind === "smart" ? " big" : ""), c.address), table)
    const tbody = table.querySelector("tbody")
    $("accounts").appendChild(card)

    for (const b of rows) {
        const tr = document.createElement("tr")
        const bal = el(
            "td",
            "num" + (b.ok ? "" : " unreach"),
            b.ok ? `${trim(b.formatted)} ${b.symbol}` : "unreachable",
        )
        const act = el("td")
        if (b.ok && b.wei > 0n) {
            const btn = el("button", "sweep-btn", "Sweep")
            btn.onclick = () => openSweep(c, b)
            act.appendChild(btn)
        }
        tr.append(el("td", null, b.name), bal, act)
        tbody.appendChild(tr)
    }
}

// Empty, non-primary derivations (extra HD indices / the unlikely interpretation)
// are collapsed so completeness is visible without burying the funded accounts.
function renderEmptySummary(empties) {
    const d = document.createElement("details")
    d.className = "acct empties"
    const sum = document.createElement("summary")
    sum.textContent = `Also checked ${empties.length} more derivation path(s) — no funds found`
    d.appendChild(sum)
    for (const c of empties) {
        const row = el("div", "empty-row")
        row.append(el("span", "empty-label", c.label), el("span", "empty-addr", c.address))
        d.appendChild(row)
    }
    $("accounts").appendChild(d)
}

let sweepCtx = null
let pendingConfirm = false

function openSweep(candidate, balance) {
    sweepCtx = { candidate, chain: CHAINS.find((c) => c.id === balance.chainId), balance, reviewedDestination: null }
    pendingConfirm = false
    $("sweepChainName").textContent = balance.name
    $("destination").value = ""
    $("sweepResult").textContent = ""
    hide($("sweepConfirm"))
    $("doSweep").textContent = "Review sweep"
    // Smart-account sweeps self-submit to the EntryPoint, so the owner wallet needs
    // a little gas on this chain (reimbursed). EOA sweeps are a plain self-paid tx.
    $("gasNote").className = candidate.kind === "smart" ? "note" : "hidden"
    show($("sweepModal"))
}

async function onDoSweep() {
    const destination = $("destination").value.trim()
    const result = $("sweepResult")
    if (!isAddr(destination)) {
        result.textContent = "Enter a valid 0x destination address."
        result.className = "err"
        return
    }
    // Step 1: echo chain, amount, and checksummed destination for a second look
    // before the irreversible send (guards fat-fingers / clipboard hijacking).
    // Re-review whenever the address changed since it was last reviewed, so the
    // broadcast can never target an address the confirmation didn't show.
    if (!pendingConfirm || sweepCtx.reviewedDestination !== destination) {
        const { chain, balance } = sweepCtx
        $("sweepConfirm").textContent = `Send up to ${trim(balance.formatted)} ${chain.nativeCurrency.symbol} on ${chain.name} to ${checksumAddress(destination)} — this is irreversible.`
        show($("sweepConfirm"))
        $("doSweep").textContent = "Confirm & send"
        pendingConfirm = true
        sweepCtx.reviewedDestination = destination
        return
    }
    // Step 2: send to the EXACT reviewed destination (not a fresh read).
    const dest = sweepCtx.reviewedDestination
    result.className = ""
    result.textContent = "Sweeping…"
    $("doSweep").disabled = true
    try {
        const { candidate, chain } = sweepCtx
        const r =
            candidate.kind === "smart"
                ? await sweep({ privateKey: candidate.key, chain, destination: dest, rpcOverrides })
                : await sweepEoa({ privateKey: candidate.key, chain, destination: dest, rpcOverrides })
        const sym = chain.nativeCurrency.symbol
        result.textContent = r.success
            ? `Swept ${r.swept} ${sym}. tx: `
            : `Submitted but the transfer did not succeed (it may need more gas for a contract destination). tx: `
        result.appendChild(el("code", null, r.txHash || ""))
        if (r.note) result.appendChild(el("div", "modenote", r.note))
        if (r.success && r.strandedDeposit && Number(r.strandedDeposit) > 0)
            result.appendChild(
                el(
                    "div",
                    "modenote",
                    `Note: ${trim(r.strandedDeposit)} ${sym} remains in the account's EntryPoint deposit (gas buffer, recoverable via withdrawTo).`,
                ),
            )
        result.className = r.success ? "ok" : "err"
        // Show the account's residual balance afterward — a charged-but-reverted op
        // or the gas buffer leaves state the original scan no longer reflects.
        try {
            const residual = await readBalance(sweepCtx.candidate.address, chain, rpcOverrides)
            result.appendChild(el("div", "modenote", `Account balance now: ${trim(residual)} ${sym}.`))
        } catch {
            // best-effort — skip if the read fails
        }
        hide($("sweepConfirm"))
        $("doSweep").textContent = "Review sweep"
        pendingConfirm = false
    } catch (e) {
        result.textContent = e.message || String(e)
        result.className = "err"
    } finally {
        $("doSweep").disabled = false
    }
}

// Show the page's own SHA-256 so a user can compare it to the published release
// checksum without leaving the page. Works when served over http(s); when opened
// as a local file, fetch is blocked, so point at the offline verify step instead.
async function showSelfHash() {
    const out = $("selfHash")
    if (!out) return
    try {
        const buf = await (await fetch(location.href)).arrayBuffer()
        const digest = await crypto.subtle.digest("SHA-256", buf)
        const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("")
        out.textContent = `This page's SHA-256: ${hex} — compare it to the checksum on the official release.`
    } catch {
        out.textContent =
            "To verify integrity, check the downloaded file: shasum -a 256 -c recovery.html.sha256"
    }
}

$("recover").onclick = onRecover
$("doSweep").onclick = onDoSweep
$("closeSweep").onclick = () => hide($("sweepModal"))
showSelfHash()

// Inline src/index.html + src/bundle.js into one self-contained recovery.html.
// The bundle is base64-embedded and decoded UTF-8-safely at load time, so the
// file has zero external requests and works offline / from IPFS / from a USB stick.
import { readFileSync, writeFileSync } from "node:fs"
import { createHash } from "node:crypto"

const html = readFileSync("src/index.html", "utf8")
const bundle = readFileSync("src/bundle.js", "utf8")
const b64 = Buffer.from(bundle, "utf8").toString("base64")

const loader = `<script>
(function(){
  var b64 = "${b64}";
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  var code = new TextDecoder("utf-8").decode(bytes);
  var s = document.createElement("script");
  s.textContent = code;
  document.body.appendChild(s);
})();
</script>`

const out = html.replace('<script src="./bundle.js"></script>', loader)
writeFileSync("recovery.html", out)

// Publish a SHA-256 checksum so a downloader can verify the exact bytes before
// trusting the file with a key: `shasum -a 256 -c recovery.html.sha256`.
const digest = createHash("sha256").update(out).digest("hex")
writeFileSync("recovery.html.sha256", `${digest}  recovery.html\n`)
console.log("recovery.html:", (out.length / 1024).toFixed(0) + "kb")
console.log("sha256:", digest)

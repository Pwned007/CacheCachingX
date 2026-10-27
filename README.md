# WCD-Hunter

**By Syed Sadam Hussain Shah** — [LinkedIn](https://qa.linkedin.com/in/syed-sadam-h-950a62336)

A Web Cache Deception (WCD) scanner with **two-session verification** — it doesn't just spot a
suspicious cache header, it proves the leak by priming the cache as an authenticated victim and
then reading it back with a completely unauthenticated attacker session.

## What it is

Most WCD checks stop at "the response looked cacheable." WCD-Hunter instead runs the full
two-actor scenario:

1. **Baseline** — fetch the real endpoint once as the victim (authenticated) and once as the
   attacker (unauthenticated) to establish whether the endpoint is actually private. If an
   anonymous user already sees the same content, there's nothing to leak and the target is
   correctly skipped — this is the main false-positive guard.
2. **Prime** — the victim session requests a crafted "cacheable-looking" variant of the private
   URL (e.g. appending `.css`).
3. **Steal** — the attacker session (no cookies) requests the *same* crafted URL.
4. **Prove it** — compares cache headers, HTTP status, and content similarity across all three
   responses. A finding only fires when the cache actually served the victim's private content
   to the attacker — not from a single suspicious header.

## Techniques

| Technique | Example |
|---|---|
| Extension appending | `/profile` → `/profile.css` |
| Fake path segment | `/profile` → `/profile/x.css` |
| Path traversal + extension | `/profile` → `/profile/..%2Fx.css` |
| Delimiter confusion (11 variants) | `;` `%3B` `%23` `%3F` `%00` `%0A` `%09` `%7C` `\` `%5C` `//` |
| Double-extension | `/profile` → `/profile.php.css` |
| Backslash confusion | `/profile` → `/profile\.css` |

Tested against **19 cacheable extensions** by default (`.css .js .png .jpg .svg .woff .pdf .xml`
…), or `--quick` for a fast 4-extension pass.

## Cache providers detected

Cloudflare, Varnish, Fastly, Akamai, AWS CloudFront, Nginx, Squid, Azure CDN — identified by
fingerprinting provider-specific headers (`cf-cache-status`, `x-varnish`, `x-amz-cf-id`, etc.),
with a generic `x-cache`/`Age` fallback for anything else.

## Built-in sensitive-content detection

Every response is scanned for 15 categories so a confirmed finding's **severity** reflects what
was actually exposed: emails, JWTs, Bearer tokens, API keys, AWS/GitHub/Slack/Google key formats,
credit card numbers, SSNs, CSRF tokens, session IDs, PEM private key blocks, internal IP ranges,
and username/password JSON fields.

## Installation

```bash
git clone https://github.com/Pwned007/wcd-hunter.git
cd wcd-hunter
pip install -r requirements.txt
```

Requires Python 3.8+.

## Usage

```bash
# Single URL with the victim's authenticated session cookies
python wcd_hunter.py -u https://target.com/account -c "session=abc123"

# Multiple targets from a file (one URL per line, '#' for comments)
python wcd_hunter.py -l urls.txt -c "auth=xyz"

# Through Burp
python wcd_hunter.py -u https://target.com/account -c "session=abc" --proxy http://127.0.0.1:8080

# Self-signed / no cert validation
python wcd_hunter.py -u https://target.com/account -c "session=abc" --no-ssl-verify

# Quick mode (4 extensions instead of 19)
python wcd_hunter.py -u https://target.com/account -c "session=abc" --quick

# Custom extensions
python wcd_hunter.py -u https://target.com/account -c "session=abc" --extensions .css,.js,.txt

# Tune concurrency / rate / timeout
python wcd_hunter.py -l urls.txt -c "sid=..." --threads 10 --delay 0.3 --timeout 15

# HTML + JSON reports
python wcd_hunter.py -u https://target.com/account -c "session=abc" --html --json-out

# Harvest cached private content + write curl/Python PoCs for confirmed findings
python wcd_hunter.py -u https://target.com/account -c "session=abc" --exploit

# Full workflow
python wcd_hunter.py -l targets.txt \
    -c "session=<victim-cookie>" \
    --proxy http://127.0.0.1:8080 --no-ssl-verify \
    --threads 8 --delay 0.3 \
    --html --json-out --exploit \
    --output-dir ./wcd_results
```

| Flag | Meaning |
|---|---|
| `-u / --url` | single target URL |
| `-l / --url-list` | file of target URLs, one per line |
| `-c / --cookies` | **victim's** authenticated session cookies (`"name=val; name2=val2"`) |
| `--attacker-cookies` | attacker session cookies — default is none (unauthenticated) |
| `-H / --headers` | extra headers, newline-separated `"Key: Val"` |
| `-x / --proxy` | HTTP proxy, e.g. `http://127.0.0.1:8080` |
| `--extensions` | comma-separated extensions to test (default: all 19) |
| `--quick` | fast mode: `.css .js .png .ico` only |
| `--threads N` | concurrent threads (default 5) |
| `--delay SECONDS` | pause between requests (default 0.2) |
| `--timeout SECONDS` | request timeout (default 15) |
| `--no-ssl-verify` | disable TLS verification |
| `--html` / `--json-out` | write a report (JSON auto-saves if any findings) |
| `--exploit` | harvest the cached private content live + write curl/Python PoC scripts |
| `--output-dir` | output directory (default `./wcd_hunter_output`) |
| `-v / --verbose` | show every payload tested, not just hits |

**Remember:** `-c/--cookies` is the **victim's** authenticated session; the attacker session is
unauthenticated by default. If the attacker has different (e.g. lower-privilege) cookies, set
`--attacker-cookies` explicitly. Output goes to `./wcd_hunter_output/` by default; exploit
artifacts land in `./wcd_hunter_output/exploit/`.

## Exploitation module (`--exploit`)

For every confirmed finding it produces four files under `<output-dir>/exploit/`:
- `*_evidence.html` — the actual stolen page content, harvested live
- `*.json` — cache status, headers, sensitive-pattern matches
- `*.sh` — a 2-curl PoC (prime as victim, steal as attacker)
- `*.py` — the same PoC as a standalone Python script

## Legal

Authorized penetration testing only. `--exploit` actively harvests and saves the target's real
private content as proof-of-impact — only run it against systems you have explicit written
permission to test, and handle the harvested evidence like any other client-sensitive data.

## License

MIT — see [LICENSE](LICENSE). Contributions and issues welcome.

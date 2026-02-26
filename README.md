# PathBreaker

A professional path and header fuzzing extension for Burp Suite.

PathBreaker adds a dedicated **PathBreaker** tab to Burp Suite with two fuzzing engines:

| Tab | What it does |
|-----|-------------|
| **Path Fuzzer** | Replaces or appends the URL path with entries from a wordlist and records each HTTP response |
| **Header Fuzzer** | Injects different header values (or full header:value pairs) into a request to discover access-control bypasses and other header-based vulnerabilities |

---

## Installation

### Pre-built JAR (recommended)

1. Download `dist/PathBreaker.jar` from this repository.
2. In Burp Suite go to **Extensions → Installed → Add**.
3. Set **Extension type** to **Java**, select `PathBreaker.jar`, and click **Next**.
4. The **PathBreaker** tab will appear in the Burp Suite tab bar.

### Build from source

Requirements: **Java 11+** and **Apache Maven 3.6+**.

```bash
git clone https://github.com/YOUR_USERNAME/PathBreaker.git
cd PathBreaker
mvn clean package
# Output: dist/PathBreaker.jar
```

---

## Usage

### Path Fuzzer

| Field | Description |
|-------|-------------|
| **URL** | Full target URL, e.g. `https://example.com/` |
| **Method** | HTTP method for every request (default: GET) |
| **Mode** | *Replace Path* – each wordlist entry becomes the full path; *Append to Path* – entries are appended after the existing path |
| **Extra Headers** | Additional headers added to every request (one per line) |
| **Wordlist** | Built-in list of ~150 common paths, or select your own file |
| **Threads** | Parallel workers (1–50, default 10) |
| **Delay (ms)** | Per-request delay to throttle scanning |
| **Filter Codes** | Comma-separated status codes to keep, e.g. `200,301,302`. Empty = show all |

Results are colour-coded: **green** = 2xx, **yellow** = 3xx, **red** = 5xx.  
Right-click any row to **Copy URL**. Click **Export CSV** to save results.

### Header Fuzzer

| Field | Description |
|-------|-------------|
| **URL** | Full target URL |
| **Fuzz Mode** | *Single Header* – fuzz one header's value; *Header Pairs* – inject full `Name: Value` pairs from the wordlist |
| **Header Name** | Header to fuzz in *Single Header* mode (e.g. `X-Forwarded-For`) |
| **Wordlist** | Built-in list of security-bypass header:value pairs, or your own file |
| **Base Headers** | Static headers added to every request |
| **Body** | Request body (for POST/PUT) |

### Context-menu integration

Right-click any request in **Proxy History**, **Repeater**, or any other Burp tool and select:

* **Send to PathBreaker – Path Fuzzer**
* **Send to PathBreaker – Header Fuzzer**

This pre-populates the target URL from the selected request.

---

## Built-in Wordlists

| File | Contents |
|------|----------|
| `wordlists/paths.txt` | ~150 common web paths: admin panels, CMS paths, API endpoints, config files, backup files, debug paths |
| `wordlists/header-pairs.txt` | ~60 security-bypass header:value pairs covering IP spoofing, Host header injection, URL override, cache poisoning, and authorization bypass |

Custom wordlists can be loaded via the **File** radio button in either panel.

---

## License

MIT

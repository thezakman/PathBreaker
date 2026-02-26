<div align="center">
  <img src="src/main/resources/pathbreaker/PathBreaker.png" alt="PathBreaker Logo" width="512"/>

  # PathBreaker v1.3
  **A professional path and header fuzzing extension for Burp Suite**

  [![Java](https://img.shields.io/badge/Java-17-orange?logo=openjdk)](https://www.java.com/)
  [![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Extension-FF6633)](https://portswigger.net/burp)
  [![Gradle](https://img.shields.io/badge/Gradle-8.14.2-02303A?logo=gradle)](https://gradle.org/)
</div>

---

## Overview

PathBreaker is a Burp Suite extension built for penetration testers who need to efficiently discover hidden endpoints and test HTTP header injection vulnerabilities. It combines a powerful fuzzing engine with an intuitive UI, supporting multiple injection modes, programmatic path generation, and real-time result analysis.

---

## Features

- **Path Fuzzing** — Four injection modes: `tail`, `prefix`, `mid:N`, and `replace`
- **Header Fuzzing** — Inject and permute custom HTTP headers using the built-in dictionary or importing custom wordlists via "Load File..."
- **Programmatic Variations** — Auto-generates protocol-level path anomalies (encoding tricks, slash variants, traversal prefixes, etc.)
- **Built-in Wordlist** — 212+ curated path traversal and access-control bypass payloads
- **Custom Payloads** — Import your own wordlist from a file
- **Header Dictionary** — Manage headers with per-entry enable/disable toggles, plus "Clear All" for quick resets
- **Multi-threaded Engine** — Configurable thread pool (1–50 threads)
- **Real-time Results** — Live progress tracking with color-coded status codes
- **Result Filtering** — Filter by status codes, "Only Hits", "Hide Errors"
- **Request/Response Viewer** — Inspect raw request and response side-by-side
- **Editable Notes** — Annotate any result row directly in the table
- **Context Menu Integration** — Right-click "Send to PathBreaker" from Proxy, Repeater, and message editors

---

## Installation

### Prerequisites

- [Burp Suite](https://portswigger.net/burp) (Professional or Community Edition)
- Java 17+

### Build from Source

```bash
git clone https://github.com/thezakman/PathBreaker.git
cd PathBreaker
./gradlew shadowJar
```

The compiled JAR will be at:

```
build/libs/PathBreaker-all.jar
```

### Load in Burp Suite

1. Open Burp Suite
2. Go to **Settings → Extensions → Installed**
3. Click **Add**
4. Set **Extension Type** to `Java`
5. Select `PathBreaker-all.jar`
6. Click **Next** — PathBreaker will appear as a new tab

---

## Usage

### Basic Workflow

1. In Burp Suite, right-click any request in **Proxy**, **Repeater**, or a message editor
2. Select **Send to PathBreaker**
3. Configure your fuzzing session in the extension tabs
4. Click **▶ Start** and monitor results in real-time

### Tabs

| Tab | Description |
|-----|-------------|
| **Fuzzer** | Main interface — configure and run fuzzing sessions |
| **Headers** | Manage the header dictionary (add, remove, toggle, load from file, clear) |
| **Payloads** | View or import custom payload wordlists |
| **About** | Project information and usage tips |

### Injection Modes

| Mode | Behavior |
|------|----------|
| `tail` | Appends payload after the base path: `/base/payload` |
| `prefix` | Prepends payload before the base path: `/payload/base` |
| `mid:N` | Inserts payload at segment N of the path |
| `replace` | Replaces the entire path with the payload |

### Fuzz Targets

| Target | Description |
|--------|-------------|
| `Paths` | Fuzz URL paths only |
| `Headers` | Fuzz HTTP headers only |
| `Both` | Fuzz paths and headers simultaneously |

### Status Code Colors

| Color | Meaning |
|-------|---------|
| Green | 2xx — Success |
| Cyan | 3xx — Redirect |
| Red | 403 — Forbidden |
| Orange | 404 — Not Found |
| Yellow | Other codes |

---

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| Inject Mode | `tail` | How payloads are injected into the path |
| Fuzz Target | `Paths` | What to fuzz (paths, headers, or both) |
| Threads | `10` | Number of concurrent fuzzing threads |
| Permute Headers | `true` | Generate all header combinations |
| Only Hits | `false` | Show only interesting results (2xx/3xx) |
| Hide Errors | `false` | Hide connection error entries |
| Programmatic | `true` | Include auto-generated path variations |
| Status Filter | _(empty)_ | Comma-separated codes to include in results |

---

## Project Structure

```
PathBreaker/
├── src/
│   └── main/
│       ├── java/pathbreaker/
│       │   ├── PathBreakerExtension.java   # Extension entry point
│       │   ├── PathBreakerTab.java         # Main UI (tabs, table, editors)
│       │   ├── PathBreakerContextMenu.java # Right-click context menu
│       │   ├── FuzzEngine.java             # Core fuzzing logic & wordlist
│       │   ├── FuzzConfig.java             # Configuration model
│       │   └── FuzzResult.java             # Result data model
│       └── resources/pathbreaker/
│           └── PathBreaker.png             # Extension icon
├── build.gradle
├── settings.gradle
├── gradlew / gradlew.bat
└── README.md
```

---

## Technical Details

- **Language:** Java 17
- **API:** [Burp Montoya API](https://portswigger.net/burp/documentation/desktop/extensions/creating) 2023.12.1
- **Build:** Gradle + Shadow JAR plugin (fat JAR)
- **Concurrency:** `ThreadPoolExecutor` with graceful `shutdownNow()` support
- **Thread Safety:** `AtomicBoolean` / `AtomicInteger` for state; `SwingUtilities.invokeLater` for UI updates
- **Memory & I/O:** Highly optimized engine — `FuzzResult` relies on native Burp `HttpRequestResponse` binary references to prevent JVM RAM exhaustion. Smart disk I/O logic only writes "Interesting" responses to temp files, preserving SSD health.
- **CPU & UI Throttling:** Baseline payload orchestration executes asynchronously; parsed HTTP structures are separated from the main hot-loop. The UI thread dynamically throttles scroll events based on `JScrollbar` position to prevent EDT freezes.
- **Architecture:** MVC-style separation — UI (`PathBreakerTab`), engine (`FuzzEngine`), models (`FuzzConfig`, `FuzzResult`)

---

## Author

Made by [@thezakman](https://github.com/thezakman)

---

## Disclaimer

PathBreaker is intended for **authorized security testing only**. Do not use this tool against systems you do not have explicit permission to test. The author assumes no liability for misuse.

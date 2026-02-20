# Dependency Guardian

**Supply chain security that detects malicious behavior, not just known vulnerabilities.**

Tools like Snyk, Dependabot, and npm audit check packages against a database of known CVEs. If an attacker compromises a legitimate package and injects credential-stealing code, those tools see nothing — the CVE doesn't exist yet. The 2.5-to-12-hour window between a package being compromised and being removed from the registry is the kill zone, and database scanners are blind during all of it. Dependency Guardian takes a different approach: it analyzes what the code actually *does*. Shell execution on install, outbound network calls, credential file reads, environment variable exfiltration, code obfuscation, time-gated payloads — these are behavioral signals that malware can't hide, regardless of whether it's been reported yet. The 2025 attack wave proved this isn't theoretical: the [Shai-Hulud worm](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) compromised 500+ packages in 24 hours, the [S1ngularity campaign](https://www.wiz.io/blog/s1ngularity-supply-chain-attack) harvested 2,349 credentials from 1,079 developer systems, and the [Chalk/Debug attack](https://www.wiz.io/blog/widespread-npm-supply-chain-attack-breaking-down-impact-scope-across-debug-chalk) injected malicious code into 18 packages with 2.6 billion combined weekly downloads. None were in any CVE database when they hit.

---

## Free to Use

**200 scans/month. Public and private repos. No credit card.**

Get your API key at [westbayberry.com/dashboard](https://westbayberry.com/dashboard) and start scanning in under 2 minutes.

---

## Quick Start

### GitHub Action

Add this to `.github/workflows/dependency-guardian.yml`:

```yaml
name: Dependency Guardian
on: [pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  scan-deps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: WestBayBerry/dependency-guardian-action@v1
        with:
          api_key: ${{ secrets.DG_API_KEY }}
          mode: "block"
```

Add your API key as a repository secret (`DG_API_KEY`). Every pull request that changes dependencies will be scanned automatically.

### CLI (any CI system)

```bash
npx @westbayberry/dg
```

Works in GitLab CI, Jenkins, Bitbucket Pipelines, CircleCI — anywhere you can run Node.js.

---

## How It Works

```
Developer opens a Pull Request
         |
         v
+----------------------------+
|  GitHub Action (this repo)  |  Open-source client
|  Extracts lockfile diff     |  You can audit exactly what
|  Sends package names +      |  data leaves your CI
|  versions to API            |
+-------------+--------------+
              |
              |  HTTPS (encrypted)
              v
+----------------------------+
|  Detection API              |  Closed-source engine
|                             |
|  Downloads npm tarball      |
|  Runs 26 detectors          |
|  Correlates cross-detector  |
|  signals (53 amplifiers)    |
|  Scores risk 0-100          |
+-------------+--------------+
              |
              v
+----------------------------+
|  PR Comment + Check Status  |  Block, warn, or pass
|  Per-package risk scores    |
|  Evidence + safe version    |
|  recommendations            |
+----------------------------+
```

The detection engine looks for behavioral signals that malicious packages can't avoid producing:

- **Network calls during install** — a color library shouldn't be making HTTP requests when you `npm install`
- **Credential file reads** — accessing `~/.ssh/id_rsa`, `~/.npmrc`, or `~/.aws/credentials` is not normal package behavior
- **Environment variable exfiltration** — reading `NPM_TOKEN`, `GITHUB_TOKEN`, or `AWS_SECRET_ACCESS_KEY` and sending them somewhere
- **Code obfuscation** — eval chains, hex-encoded strings, invisible unicode characters, string reconstruction from char codes
- **Time-gated execution** — `setTimeout` with an epoch comparison that activates a payload days after installation
- **Self-propagation** — running `npm publish` or writing to other packages in `node_modules`
- **Version diff anomalies** — a patch bump that suddenly adds shell execution and network calls

Individual signals are noisy. The correlator is what makes it work: when a package has a new maintainer AND suddenly adds network calls AND obfuscates the code AND reads CI tokens, that combination fires multiple amplifier rules that virtually eliminate false positives while catching sophisticated multi-vector attacks.

---

## Benchmark

Validated against 8,356 known-malicious packages and 3,000 clean packages from the top of npm:

| Metric | Value |
|--------|-------|
| Malicious packages tested | 8,356 |
| Clean packages tested | 3,000 |
| Precision | 99.95% |
| Recall | 99.44% |
| **F1 Score** | **99.70%** |
| False positives | 4 out of 3,000 |
| False negatives | 47 out of 8,356 |

Malicious package sources: [DataDog Malicious Software Packages Dataset](https://github.com/DataDog/malicious-software-packages-dataset), [OSSF Malicious Packages](https://github.com/ossf/malicious-packages), [GitHub Advisory Database](https://github.com/advisories).

### Real-World Attack Coverage

These are the major supply chain attacks of 2025. Each row shows which detectors fire on a reconstructed replica of the attack:

| Attack | What Happened | Detectors That Fire |
|--------|---------------|---------------------|
| **Shai-Hulud** (Sep–Nov 2025) | First self-replicating npm worm. 500+ packages in 24 hours. Stole npm tokens, exfiltrated via GitHub API, used Bun runtime to evade Node.js sandboxes. | `install_script` `child_process` `network_exfil` `ci_secret_access` `token_theft` `bun_runtime_evasion` `worm_behavior` + correlator amplifiers |
| **S1ngularity** (Aug 2025) | Compromised Nx build tool packages. Harvested 2,349 credentials from 1,079 developer systems. | `install_script` `child_process` `ci_secret_access` `token_theft` `behavior_drift` + correlator amplifiers |
| **Chalk/Debug** (Sep 2025) | Phished maintainer credentials. Injected credential-stealing code into 18 packages with 2.6B combined weekly downloads. | `maintainer_change` `network_exfil` `behavior_drift` `diff_risk` + correlator amplifiers |

---

## The 26 Detectors

| # | Detector | What It Catches |
|---|----------|-----------------|
| 1 | **Install Script** | Download-and-execute patterns in npm lifecycle scripts (preinstall, postinstall) |
| 2 | **Child Process** | Shell command execution via exec, spawn, execFile, and third-party shell libraries (execa, cross-spawn, shelljs) |
| 3 | **Network Exfiltration** | Outbound connections via 30+ libraries — HTTP, WebSocket, gRPC, DNS tunneling |
| 4 | **Obfuscation** | eval chains, hex encoding, invisible unicode, string reconstruction, encrypted payloads |
| 5 | **Diff Risk** | Behavioral changes between package versions — new scripts added, new dangerous API calls |
| 6 | **Fresh Publish** | Versions published within a configurable time window (default: 48 hours) |
| 7 | **Maintainer Change** | Ownership changes, email domain shifts, rapid publish timing after account takeover |
| 8 | **Sensitive Path** | String references to `.ssh`, `.aws`, `/etc/shadow`, Kubernetes configs, keychains |
| 9 | **Binary Addon** | Native binaries (`.node`, `.so`, `.dll`, `.exe`) with ELF/PE/Mach-O magic-byte verification |
| 10 | **Filesystem Persistence** | Writes to crontab, systemd, `.bashrc`, SSH `authorized_keys`, Windows registry, LaunchAgents |
| 11 | **CI Secret Access** | Reads of `NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, and 20+ named CI/CD tokens |
| 12 | **Suspicious API** | Use of `vm`, `worker_threads`, `inspector`, `process.binding`, native FFI bindings |
| 13 | **GitHub Reputation** | Ghost repositories, low stars, archived/dormant repos, fake popularity, borrowed repo URLs |
| 14 | **Source-Registry Mismatch** | Compares npm tarball against GitHub source tree to detect trojaned packages |
| 15 | **Purpose Mismatch** | A CSS library that spawns shells. A date utility that opens network sockets. |
| 16 | **Typosquat** | String similarity to popular npm packages (`lodash` vs `lodahs`, `express` vs `expresss`) |
| 17 | **Behavior Drift** | Time-gated execution — `setTimeout` with epoch comparison near `exec`/`fetch` calls |
| 18 | **Token Theft** | File reads targeting `~/.npmrc`, `.ssh/id_rsa`, `.git-credentials`, browser credential stores |
| 19 | **Worm Behavior** | Self-propagation via `npm publish`, `node_modules` writes, auth token extraction |
| 20 | **Preinstall Timing** | Meaningful code execution in `preinstall` — the most dangerous lifecycle hook |
| 21 | **Legitimate API Exfiltration** | Data exfiltrated via trusted SDKs (GitHub API, AWS SDK, Slack) to blend into normal traffic |
| 22 | **Bun Runtime Evasion** | Bun-specific APIs (`Bun.spawn`, `Bun.write`, `Bun.file`) used to bypass Node.js-focused scanners |
| 23 | **Dependency Confusion** | Private package namespace squatting — high version numbers, low downloads, internal naming patterns |
| 24 | **Browser Phishing** | Cookie theft, form injection, clipboard hijacking, `navigator.sendBeacon` exfiltration |
| 25 | **Empty Package** | Stub packages with no meaningful code — namespace squatting and confusion attack indicators |
| 26 | **Cross-Detector Correlator** | 53 amplifier rules that combine signals across detectors into high-confidence verdicts |

---

## Configuration

| Input | Description | Default |
|-------|-------------|---------|
| `api_key` | Dependency Guardian API key (`dg_live_xxx`). **Required.** | — |
| `github_token` | GitHub token for PR comments and file access | `${{ github.token }}` |
| `mode` | `block` (fail PR on threshold), `warn` (comments only), `off` (logging only) | `warn` |
| `block_threshold` | Risk score (0–100) to fail the check | `70` |
| `warn_threshold` | Risk score (0–100) to show warnings | `60` |
| `noteworthy_threshold` | Risk score (0–100) for informational reporting | `25` |
| `allowlist` | Comma-separated package names to skip | — |
| `max_packages` | Maximum changed packages to analyze per PR | `200` |
| `include_dev` | Whether to apply blocking logic to devDependencies | `false` |
| `fresh_publish_hours` | Hours threshold for flagging recently published versions | `48` |
| `young_repo_days` | Days threshold for flagging young GitHub repositories | `30` |
| `low_stars_threshold` | Star count below which GitHub repos are flagged | `5` |

### Full example with all options

```yaml
- uses: WestBayBerry/dependency-guardian-action@v1
  with:
    api_key: ${{ secrets.DG_API_KEY }}
    github_token: ${{ secrets.GITHUB_TOKEN }}
    mode: "block"
    block_threshold: "70"
    warn_threshold: "60"
    noteworthy_threshold: "25"
    allowlist: "lodash,express"
    max_packages: "200"
    include_dev: "false"
    fresh_publish_hours: "48"
    young_repo_days: "30"
    low_stars_threshold: "5"
```

---

## Why Closed-Core

The detection engine is proprietary. This GitHub Action and the [CLI](https://www.npmjs.com/package/@westbayberry/dg) are open source.

The open-source client means you can audit exactly what data leaves your CI environment. It sends package names and versions to the detection API. It does not send your source code, your environment variables, or anything else.

The detection engine is closed because detection logic that's public is detection logic that attackers can test against. The same reason antivirus signatures aren't published. We'd rather have attackers guess than iterate.


---

## Known Limitations

- **npm only** — Analyzes `package-lock.json` and `package.json`. Yarn and pnpm lockfile parsing is not yet implemented.
- **Static analysis only** — Pattern matching on source code. No dynamic execution or runtime sandboxing.
- **50 MB tarball cap** — Packages with tarballs larger than 50 MB are skipped.
- **15 MB scan budget** — Only the first 15 MB of JS/TS content per package is analyzed.

---

## Links

- [Get an API key](https://westbayberry.com/dashboard)
- [WestBayBerry](https://westbayberry.com)
- [Report a bug](https://github.com/WestBayBerry/dependency-guardian-action/issues)

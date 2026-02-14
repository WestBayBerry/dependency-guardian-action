import * as core from "@actions/core";
import * as github from "@actions/github";
import { Config, PackageScanResult, ScanResult } from "./types";

/* ── Formatting helpers ─────────────────────────────────────────── */

function sevLabel(severity: number): string {
  switch (severity) {
    case 5: return "CRITICAL";
    case 4: return "HIGH";
    case 3: return "MEDIUM";
    case 2: return "LOW";
    default: return "INFO";
  }
}

function diffPrefix(severity: number): string {
  return severity >= 3 ? "-" : "+";
}

function scoreColor(
  score: number,
  blockThreshold: number,
  warnThreshold: number
): string {
  if (score >= blockThreshold) return "critical";
  if (score >= warnThreshold) return "orange";
  return "yellow";
}

function scoreBadgeUrl(
  score: number,
  color: string,
  style: string
): string {
  return `https://img.shields.io/badge/-${score}-${color}?style=${style}`;
}

function statusKbd(
  score: number,
  mode: string,
  blockThreshold: number
): string {
  return mode === "block" && score >= blockThreshold
    ? "<kbd>BLOCK</kbd>"
    : "<kbd>WARN</kbd>";
}

/* ── Block-candidate check (shared by header badge + enforcement) ─ */

const UNCONDITIONAL_BLOCK_IDS = [
  "exfil_tripwire",
  "install_download_exec",
  "persistence_exfil",
  "secret_theft",
  "ghost_package_risk",
  "trojan_package",
  "disposable_attack",
  "root_script_risk",
  "binary_smuggler",
  // Phase 2.1 amplifiers
  "legitimate_exfil_theft",
  "bun_evasion_attack",
  "worm_propagation",
  "preinstall_attack",
  "confusion_attack",
  "token_exfil_via_api",
  "install_shell_exec",
  // Phase 5 amplifiers
  "shell_exfil",
  "obfuscated_exec",
  "obfuscated_install",
  "typosquat_network",
  "shell_token_exfil",
  // Phase 6 amplifiers
  "confusion_ghost",
  "ghost_stub",
  "binary_ghost",
  "isolated_high_severity",
  // Phase 7 amplifiers
  "binary_stub",
  "confusion_stub",
  "install_secret_buildup",
  "worm_self_update_install",
];

function isBlockCandidate(
  p: PackageScanResult,
  config: Config
): boolean {
  if (config.allowlist.includes(p.pkg.name)) return false;

  const hasMaliciousInstallScript = p.detectorResults.some(
    (r) =>
      r.id === "install_script" &&
      r.evidence.some((e) =>
        /Matches: (curl|wget|bash|powershell|sh -c|node -e|node -r)/i.test(e)
      )
  );

  const hasNewInstallScript = p.detectorResults.some(
    (r) =>
      r.id === "diff_risk" &&
      r.evidence.some((e) =>
        /New (preinstall|install|postinstall|prepare) script added/i.test(e)
      )
  );

  const hasTrigger = p.detectorResults.some((r) =>
    UNCONDITIONAL_BLOCK_IDS.includes(r.id)
  );

  if (hasMaliciousInstallScript || hasNewInstallScript || hasTrigger)
    return true;

  if (p.pkg.isDev && !config.includeDev) return false;
  return p.score >= config.blockThreshold;
}

export async function report(
  scanResult: ScanResult,
  config: Config
): Promise<void> {
  core.info(`Scanned ${scanResult.totalScanned} package(s)`);

  if (scanResult.skipped.length > 0) {
    const preview = scanResult.skipped.slice(0, 5).join(", ");
    const more =
      scanResult.skipped.length > 5
        ? ` and ${scanResult.skipped.length - 5} more`
        : "";
    core.warning(
      `Skipped ${scanResult.skipped.length} package(s) due to max_packages cap: ${preview}${more}`
    );
  }

  const flagged = scanResult.packages.filter(
    (p) =>
      p.score >= config.warnThreshold ||
      p.detectorResults.some((r) => r.critical === true)
  );

  const noteworthy = scanResult.packages.filter(
    (p) =>
      p.score >= config.noteworthyThreshold &&
      !flagged.includes(p)
  );

  // Log details for each flagged package
  for (const pkg of flagged) {
    core.startGroup(
      `${pkg.pkg.name}@${pkg.pkg.newVersion} score=${pkg.score} reasons=[${pkg.reasons.join(", ")}]`
    );
    for (const r of pkg.detectorResults) {
      const msg = `[${r.id}] ${r.title} (severity=${r.severity}, confidence=${r.confidence})`;
      if (r.severity >= 4) {
        core.error(msg);
      } else if (r.severity >= 3) {
        core.warning(msg);
      } else {
        core.info(msg);
      }
      for (const e of r.evidence) {
        core.info(`  - ${e}`);
      }
    }
    core.endGroup();
  }

  // Log noteworthy packages (informational only)
  for (const pkg of noteworthy) {
    core.startGroup(
      `~ ${pkg.pkg.name}@${pkg.pkg.newVersion} score=${pkg.score} (noteworthy)`
    );
    for (const r of pkg.detectorResults) {
      core.info(`[${r.id}] ${r.title} (severity=${r.severity}, confidence=${r.confidence})`);
    }
    core.endGroup();
  }

  // GitHub Step Summary — header badge
  const blockedForBadge =
    config.mode === "block"
      ? flagged.filter((p) => isBlockCandidate(p, config))
      : [];
  const summaryStatus =
    blockedForBadge.length > 0
      ? `${blockedForBadge.length}_Blocked`
      : flagged.length > 0
        ? `${flagged.length}_Flagged`
        : "Clean";
  const summaryColor =
    blockedForBadge.length > 0
      ? "critical"
      : flagged.length > 0
        ? "orange"
        : "success";
  const summaryBadge = `![Dependency Guardian](https://img.shields.io/badge/Dependency_Guardian-${summaryStatus}-${summaryColor}?style=for-the-badge)`;

  const summary = core.summary.addRaw(summaryBadge + "\n\n", true);

  if (flagged.length === 0 && noteworthy.length === 0) {
    summary.addRaw(
      `No suspicious dependency changes detected. Scanned ${scanResult.totalScanned} package(s).`,
      true
    );
  } else if (flagged.length > 0) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rows: any[][] = [
      [
        { data: "Status", header: true },
        { data: "Package", header: true },
        { data: "Version", header: true },
        { data: "Score", header: true },
        { data: "Findings", header: true },
      ],
    ];

    for (const pkg of flagged) {
      const versionChange = pkg.pkg.oldVersion
        ? `${pkg.pkg.oldVersion} → ${pkg.pkg.newVersion}`
        : `(new) ${pkg.pkg.newVersion}`;

      const topFindings = pkg.reasons.slice(0, 3).join("; ");
      const type = pkg.pkg.isDev ? "dev" : "prod";
      const color = scoreColor(
        pkg.score,
        config.blockThreshold,
        config.warnThreshold
      );
      const badge = `<img src="${scoreBadgeUrl(pkg.score, color, "flat-square")}" alt="${pkg.score}">`;
      const status = statusKbd(pkg.score, config.mode, config.blockThreshold);
      const pkgCell = `<b>${pkg.pkg.name}</b><br><sub>${type}</sub>`;

      rows.push([status, pkgCell, versionChange, badge, topFindings]);
    }

    summary.addTable(rows);
  }

  if (noteworthy.length > 0) {
    const nRows = noteworthy
      .map((pkg) => {
        const color = scoreColor(
          pkg.score,
          config.blockThreshold,
          config.warnThreshold
        );
        const badge = `<img src="${scoreBadgeUrl(pkg.score, color, "flat-square")}" alt="${pkg.score}">`;
        return `| **${pkg.pkg.name}@${pkg.pkg.newVersion}** | ${badge} | ${pkg.reasons[0] ?? "N/A"} |`;
      })
      .join("\n");
    const noteworthyTable = [
      "| Package | Score | Finding |",
      "|:--------|:------|:--------|",
      nRows,
    ].join("\n");
    summary.addRaw(
      `\n<details><summary>Packages of Interest (${noteworthy.length})</summary>\n\n${noteworthyTable}\n</details>\n`,
      true
    );
  }

  await summary.write();

  // PR Comment
  await postPrComment(scanResult, flagged, noteworthy, config);

  // Policy enforcement
  if (config.mode === "off") return;

  if (config.mode === "block") {
    const blocked = flagged.filter((p) => isBlockCandidate(p, config));

    if (blocked.length > 0) {
      const names = blocked
        .map((p) => `${p.pkg.name}@${p.pkg.newVersion} (score=${p.score})`)
        .join(", ");
      core.setFailed(
        `Dependency Guardian: blocked ${blocked.length} package(s) due to high risk: ${names}`
      );
    }
  }
}

const COMMENT_MARKER = "<!-- dependency-guardian-report -->";

async function postPrComment(
  scanResult: ScanResult,
  flagged: PackageScanResult[],
  noteworthy: PackageScanResult[],
  config: Config
): Promise<void> {
  const ctx = github.context;
  const prNumber = ctx.payload.pull_request?.number;
  if (!prNumber) return;

  try {
    const octokit = github.getOctokit(config.githubToken);

    // Header badge
    const blockedPkgs =
      config.mode === "block"
        ? flagged.filter((p) => isBlockCandidate(p, config))
        : [];
    const headerStatus =
      blockedPkgs.length > 0
        ? `${blockedPkgs.length}_Blocked`
        : flagged.length > 0
          ? `${flagged.length}_Flagged`
          : "Clean";
    const headerColor =
      blockedPkgs.length > 0
        ? "critical"
        : flagged.length > 0
          ? "orange"
          : "success";
    const headerBadge = `![Dependency Guardian](https://img.shields.io/badge/Dependency_Guardian-${headerStatus}-${headerColor}?style=for-the-badge)`;

    // Noteworthy section (table format)
    const noteworthySection =
      noteworthy.length > 0
        ? (() => {
            const nRows = noteworthy
              .map((pkg) => {
                const color = scoreColor(
                  pkg.score,
                  config.blockThreshold,
                  config.warnThreshold
                );
                const badge = `![${pkg.score}](${scoreBadgeUrl(pkg.score, color, "flat-square")})`;
                return `| **${pkg.pkg.name}@${pkg.pkg.newVersion}** | ${badge} | ${pkg.reasons[0] ?? "N/A"} |`;
              })
              .join("\n");
            const tbl = [
              "| Package | Score | Finding |",
              "|:--------|:------|:--------|",
              nRows,
            ].join("\n");
            return `\n\n<details><summary>Packages of Interest (${noteworthy.length})</summary>\n\n${tbl}\n</details>`;
          })()
        : "";

    let body: string;
    if (flagged.length === 0) {
      body = `${COMMENT_MARKER}\n${headerBadge}\n\nNo suspicious dependency changes detected. Scanned ${scanResult.totalScanned} package(s).${noteworthySection}`;
    } else {
      // Main table with badges + kbd status
      const rows = flagged.map((pkg) => {
        const version = pkg.pkg.oldVersion
          ? `\`${pkg.pkg.oldVersion}\` → \`${pkg.pkg.newVersion}\``
          : `(new) \`${pkg.pkg.newVersion}\``;
        const type = pkg.pkg.isDev ? "dev" : "prod";
        const color = scoreColor(
          pkg.score,
          config.blockThreshold,
          config.warnThreshold
        );
        const badge = `![${pkg.score}](${scoreBadgeUrl(pkg.score, color, "flat-square")})`;
        const status = statusKbd(pkg.score, config.mode, config.blockThreshold);
        const findings = pkg.reasons.slice(0, 3).join("; ");
        return `| ${status} | **${pkg.pkg.name}**<br><sub>${type}</sub> | ${version} | ${badge} | ${findings} |`;
      });

      const table = [
        "| Status | Package | Version | Score | Findings |",
        "|:-------|:--------|:--------|:------|:---------|",
        ...rows,
      ].join("\n");

      // Detail sections with diff code blocks
      const details = flagged
        .map((pkg) => {
          const findingLines = pkg.detectorResults
            .map((r) => {
              const prefix = diffPrefix(r.severity);
              const label = sevLabel(r.severity);
              const evidenceLines = r.evidence
                .slice(0, 5)
                .map((e) => `${prefix}   ${e}`)
                .join("\n");
              return `${prefix} [${label}] ${r.id} — ${r.title} (sev ${r.severity})${evidenceLines ? "\n" + evidenceLines : ""}`;
            })
            .join("\n");
          const findingsBlock = "```diff\n" + findingLines + "\n```";
          const rec = pkg.recommendation
            ? `\n\n> **Recommendation:** ${pkg.recommendation}`
            : "";
          const color = scoreColor(
            pkg.score,
            config.blockThreshold,
            config.warnThreshold
          );
          const badge = `<img src="${scoreBadgeUrl(pkg.score, color, "flat-square")}" alt="Score: ${pkg.score}">`;
          const status = statusKbd(
            pkg.score,
            config.mode,
            config.blockThreshold
          );
          return `<details>\n<summary>${status} <b>${pkg.pkg.name}@${pkg.pkg.newVersion}</b> — ${badge}</summary>\n\n${findingsBlock}${rec}\n</details>`;
        })
        .join("\n\n");

      body = `${COMMENT_MARKER}\n${headerBadge}\n\n${table}\n\n${details}${noteworthySection}\n\n---\n<sub>Scanned ${scanResult.totalScanned} package(s) | mode: ${config.mode}</sub>`;
    }

    // Find existing comment to update
    const comments = await octokit.rest.issues.listComments({
      ...ctx.repo,
      issue_number: prNumber,
      per_page: 50,
    });

    const existing = comments.data.find(
      (c) => c.body?.includes(COMMENT_MARKER)
    );

    if (existing) {
      await octokit.rest.issues.updateComment({
        ...ctx.repo,
        comment_id: existing.id,
        body,
      });
    } else {
      await octokit.rest.issues.createComment({
        ...ctx.repo,
        issue_number: prNumber,
        body,
      });
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    core.warning(`Failed to post PR comment: ${msg}`);
  }
}

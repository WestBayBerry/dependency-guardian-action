import { DetectorFinding } from "./types";

const SEVERITY_POINTS: Record<number, number> = {
  5: 30,
  4: 22,
  3: 14,
  2: 8,
  1: 3,
};

const NEW_PACKAGE_BONUS = 15;

// IDs that represent cross-detector amplifiers (not base detectors)
export const AMPLIFIER_IDS = new Set([
  "exfil_tripwire",
  "install_download_exec",
  "malicious_newcomer",
  "install_shell_exec",
  "maintainer_risk",
  "fresh_risk",
  "persistence_exfil",
  "secret_theft",
  "ghost_package_risk",
  "suspicious_api_combo",
  "disposable_attack",
  "disguised_exfiltration",
  "trojan_package",
  "binary_smuggler",
  "delayed_payload",
  // Phase 2.1 amplifiers
  "legitimate_exfil_theft",
  "bun_evasion_attack",
  "worm_propagation",
  "preinstall_attack",
  "confusion_attack",
  "token_exfil_via_api",
  // Phase 5 amplifiers
  "shell_exfil",
  "obfuscated_exec",
  "obfuscated_install",
  "typosquat_network",
  "shell_token_exfil",
  // Audit amplifiers
  "obfuscated_network",
  "wasm_smuggler",
  "heavy_obfuscation",
  "confusion_ghost",
  "ghost_stub",
  "binary_ghost",
  "isolated_high_severity",
  // Phase 7 amplifiers
  "binary_stub",
  "install_binary",
  "network_exec",
  // Phase 8 amplifiers
  "confusion_stub",
  "install_secret_buildup",
  "worm_self_update_install",
]);

export interface ScoreResult {
  score: number;
  reasons: string[];
}

export const REPUTABLE_THRESHOLD = 100_000;

export function computePackageScore(
  findings: DetectorFinding[],
  isNewPackage: boolean,
  weeklyDownloads?: number | null
): ScoreResult {
  if (findings.length === 0) {
    return { score: 0, reasons: [] };
  }

  const isReputable =
    typeof weeklyDownloads === "number" &&
    weeklyDownloads >= REPUTABLE_THRESHOLD;

  const contributions: { title: string; points: number }[] = [];

  // Base findings (individual detectors)
  const baseFindings = findings.filter((f) => !AMPLIFIER_IDS.has(f.id));
  // Amplifier findings (cross-detector correlations)
  const amplifierFindings = findings.filter((f) => AMPLIFIER_IDS.has(f.id));

  for (const f of baseFindings) {
    const base = SEVERITY_POINTS[f.severity] ?? 0;
    const points = base * f.confidence;
    contributions.push({ title: f.title, points });
  }

  let raw = contributions.reduce((sum, c) => sum + c.points, 0);

  // New package bonus — only for non-reputable new additions.
  // Reputable packages (>100k downloads) are well-established and don't need
  // the unknown-package penalty that catches fresh malware uploads.
  if (isNewPackage && !isReputable && baseFindings.length > 0) {
    raw += NEW_PACKAGE_BONUS;
  }

  // Amplifiers add fixed bonuses (already severity*confidence scored)
  for (const f of amplifierFindings) {
    const base = SEVERITY_POINTS[f.severity] ?? 0;
    const points = base * f.confidence;
    contributions.push({ title: f.title, points });
    raw += points;
  }

  // Critical finding floor: confirmed-malicious signals bypass numeric dilution.
  // For reputable packages (new or update), only cross-detector amplifier
  // critical findings trigger the floor — base detector critical flags
  // (e.g. worm_behavior on build tools, obfuscation on minified code)
  // can be false positives on popular packages.
  const hasCritical = isReputable
    ? amplifierFindings.some((f) => f.critical === true)
    : findings.some((f) => f.critical === true);
  if (hasCritical) {
    raw = Math.max(raw, 100);
  }

  // Reputable packages (>100k weekly downloads) legitimately use network,
  // crypto, fs, etc. Without a critical finding from the correlator,
  // cap the score to avoid false positives on expected capabilities.
  // Critical amplifier findings (actual attack patterns) override these caps.
  if (isReputable && !hasCritical) {
    // Reputable packages (>100k downloads) without critical amplifier findings
    // are well-established. Cap at 55 regardless of new vs. update.
    // scan-all mode marks everything as "new" which inflated scores to WARN (65);
    // a package with millions of weekly downloads is not meaningfully "new".
    raw = Math.min(raw, 55);
  }

  const score = Math.min(100, Math.round(raw));

  const reasons = contributions
    .sort((a, b) => b.points - a.points)
    .map((c) => c.title);

  return { score, reasons };
}

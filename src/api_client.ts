import * as core from "@actions/core";
import * as github from "@actions/github";
import { Config, PackageChange, PackageScanResult, ScanResult, DetectorFinding } from "./types";
import { report } from "./reporting";
import {
  getPrFiles,
  getBaseFileContent,
  getHeadFileContent,
  resolveToken,
} from "./github/pr_files";
import { parseLockfile } from "./lockfile/parse_package_lock";
import { diffLockfiles } from "./lockfile/diff";
import { diffPackageJsons } from "./lockfile/parse_package_json";

const API_BASE = "https://api.westbayberry.com";

interface APIResponse {
  score: number;
  action: "block" | "warn" | "pass";
  packages: {
    name: string;
    version: string;
    score: number;
    findings: DetectorFinding[];
    reasons: string[];
    recommendation?: string;
    cached: boolean;
  }[];
  safeVersions: Record<string, string>;
}

export async function runAPIMode(apiKey: string): Promise<void> {
  try {
    const config = parseConfig();
    core.info("Dependency Guardian running (API mode)");
    core.info(
      `mode=${config.mode} block_threshold=${config.blockThreshold} warn_threshold=${config.warnThreshold}`
    );

    if (config.mode === "off") {
      core.info("Mode is off — skipping analysis.");
      return;
    }

    // PR file discovery (stays local — needs GitHub context)
    const prInfo = await getPrFiles(config.githubToken);
    if (!prInfo.isPullRequest) {
      core.info("Not a pull request event — skipping dependency analysis.");
      return;
    }

    core.info(
      `PR #${prInfo.prNumber}: ${prInfo.dependencyFilesChanged.length} dependency file(s) changed`
    );

    if (prInfo.dependencyFilesChanged.length === 0) {
      core.info("No dependency files changed in this PR.");
      return;
    }

    // Extract changed packages (lockfile parsing stays local)
    const changes = await extractChanges(config, prInfo.baseSha);
    if (changes.length === 0) {
      core.info("No package changes detected (or all are allowlisted).");
      return;
    }

    const filtered = changes.filter(
      (c) => !config.allowlist.includes(c.name)
    );
    if (filtered.length === 0) {
      core.info("All changed packages are allowlisted.");
      return;
    }

    core.info(`Sending ${filtered.length} package(s) to Detection API...`);

    // Call the Detection API
    const ctx = github.context;
    const apiPayload = {
      packages: filtered.map((c) => ({
        name: c.name,
        version: c.newVersion,
        previousVersion: c.oldVersion,
        isNew: c.oldVersion === null,
      })),
      config: {
        blockThreshold: config.blockThreshold,
        warnThreshold: config.warnThreshold,
        githubToken: config.githubToken,
      },
      repoMeta: {
        owner: ctx.repo.owner,
        repo: ctx.repo.repo,
        prNumber: prInfo.prNumber,
      },
    };

    const response = await fetch(`${API_BASE}/v1/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
        "User-Agent": "dependency-guardian-action/1.0",
      },
      body: JSON.stringify(apiPayload),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`API returned ${response.status}: ${errorBody}`);
    }

    const apiResult = (await response.json()) as APIResponse;
    core.info(
      `API returned: score=${apiResult.score} action=${apiResult.action} packages=${apiResult.packages.length}`
    );

    // Convert API response to ScanResult for the reporting module
    const packageResults: PackageScanResult[] = apiResult.packages.map((pkg) => {
      const change = filtered.find((c) => c.name === pkg.name) ?? {
        name: pkg.name,
        oldVersion: null,
        newVersion: pkg.version,
        isDirect: false,
        isDev: false,
      };
      return {
        pkg: change,
        detectorResults: pkg.findings,
        score: pkg.score,
        reasons: pkg.reasons,
        recommendation: pkg.recommendation,
      };
    });

    const scanResult: ScanResult = {
      packages: packageResults,
      maxScore: apiResult.score,
      totalScanned: packageResults.length,
      skipped: [],
    };

    // Use existing reporting module (PR comment, step summary, enforcement)
    await report(scanResult, config);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    core.setFailed(`Dependency Guardian (API mode) failed: ${msg}`);
  }
}

function parseConfig(): Config {
  const token = resolveToken();
  const mode = (core.getInput("mode") || "warn") as Config["mode"];
  if (!["block", "warn", "off"].includes(mode)) {
    throw new Error(`Invalid mode: ${mode}. Must be block, warn, or off.`);
  }

  return {
    githubToken: token,
    blockThreshold: Number(core.getInput("block_threshold") || "70"),
    warnThreshold: Number(core.getInput("warn_threshold") || "60"),
    noteworthyThreshold: Number(core.getInput("noteworthy_threshold") || "25"),
    mode,
    allowlist: (core.getInput("allowlist") || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    maxPackages: Number(core.getInput("max_packages") || "200"),
    includeDev: core.getBooleanInput("include_dev") || false,
    freshPublishHours: Number(core.getInput("fresh_publish_hours") || "48"),
    youngRepoDays: Number(core.getInput("young_repo_days") || "30"),
    lowStarsThreshold: Number(core.getInput("low_stars_threshold") || "5"),
  };
}

async function extractChanges(
  config: Config,
  baseSha: string
): Promise<PackageChange[]> {
  const headLockfile = getHeadFileContent("package-lock.json");
  if (headLockfile) {
    core.info("Found package-lock.json — using lockfile diff");
    const baseLockfile = baseSha
      ? getBaseFileContent(baseSha, "package-lock.json")
      : null;

    try {
      const headParsed = parseLockfile(headLockfile);
      const baseParsed = baseLockfile ? parseLockfile(baseLockfile) : null;

      const directDeps = getDirectDeps();
      const result = diffLockfiles(
        baseParsed,
        headParsed,
        config.maxPackages,
        directDeps
      );

      if (result.skipped.length > 0) {
        const preview = result.skipped.slice(0, 5).join(", ");
        core.warning(
          `Skipped ${result.skipped.length} package(s) due to max_packages cap: ${preview}`
        );
      }

      return result.changes;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      core.warning(`Failed to parse lockfile: ${msg} — falling back to package.json diff`);
    }
  }

  const headPkgJson = getHeadFileContent("package.json");
  if (headPkgJson) {
    core.info("Falling back to package.json diff");
    const basePkgJson = baseSha
      ? getBaseFileContent(baseSha, "package.json")
      : null;

    try {
      const result = diffPackageJsons(basePkgJson, headPkgJson, config.maxPackages);
      return result.changes;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      core.warning(`Failed to parse package.json: ${msg}`);
    }
  }

  return [];
}

function getDirectDeps(): Set<string> {
  try {
    const fs = require("fs");
    const content = fs.readFileSync("package.json", "utf-8");
    const pkg = JSON.parse(content);
    return new Set([
      ...Object.keys(pkg.dependencies ?? {}),
      ...Object.keys(pkg.devDependencies ?? {}),
    ]);
  } catch {
    return new Set();
  }
}

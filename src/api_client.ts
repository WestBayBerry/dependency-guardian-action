import * as core from "@actions/core";
import * as github from "@actions/github";
import { Config, PackageChange, PackageScanResult, ScanResult, DetectorFinding } from "./types";
import { report } from "./reporting";
import {
  getPrFiles,
  PrFileInfo,
  getBaseFileContent,
  getHeadFileContent,
  resolveToken,
} from "./github/pr_files";
import { parseLockfile } from "./lockfile/parse_package_lock";
import { diffLockfiles } from "./lockfile/diff";
import { diffPackageJsons } from "./lockfile/parse_package_json";
import { parseRequirements, diffRequirements } from "./lockfile/parse_requirements";
import { parsePipfileLock, diffPipfileLocks } from "./lockfile/parse_pipfile_lock";
import { parsePoetryLock, diffPoetryLocks } from "./lockfile/parse_poetry_lock";

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
      `PR #${prInfo.prNumber}: ${prInfo.dependencyFilesChanged.length} dependency file(s) changed` +
      ` (${prInfo.npmFilesChanged.length} npm, ${prInfo.pypiFilesChanged.length} pypi)`
    );

    if (prInfo.dependencyFilesChanged.length === 0) {
      core.info("No dependency files changed in this PR.");
      return;
    }

    // Extract changed packages (lockfile parsing stays local)
    const { npmChanges, pypiChanges } = await extractChanges(config, prInfo);
    const allChanges = [...npmChanges, ...pypiChanges];
    if (allChanges.length === 0) {
      core.info("No package changes detected.");
      return;
    }

    const npmFiltered = npmChanges.filter(
      (c) => !config.allowlist.includes(c.name)
    );
    const pypiFiltered = pypiChanges.filter(
      (c) => !config.allowlist.includes(c.name)
    );
    const allFiltered = [...npmFiltered, ...pypiFiltered];

    if (allFiltered.length === 0) {
      core.info("All changed packages are allowlisted.");
      return;
    }

    core.info(
      `Sending ${npmFiltered.length} npm + ${pypiFiltered.length} pypi package(s) to Detection API...`
    );

    // Call the Detection API (npm and pypi in parallel)
    const ctx = github.context;
    const repoMeta = {
      owner: ctx.repo.owner,
      repo: ctx.repo.repo,
      prNumber: prInfo.prNumber,
    };
    const apiConfig = {
      blockThreshold: config.blockThreshold,
      warnThreshold: config.warnThreshold,
      githubToken: config.githubToken,
    };
    const headers = {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
      "User-Agent": "dependency-guardian-action/1.0",
    };

    const [npmResponse, pypiResponse] = await Promise.all([
      npmFiltered.length > 0
        ? fetch(`${API_BASE}/v1/analyze`, {
            method: "POST",
            headers,
            body: JSON.stringify({
              packages: npmFiltered.map((c) => ({
                name: c.name,
                version: c.newVersion,
                previousVersion: c.oldVersion,
                isNew: c.oldVersion === null,
              })),
              config: apiConfig,
              repoMeta,
            }),
          })
        : null,
      pypiFiltered.length > 0
        ? fetch(`${API_BASE}/v1/pypi/analyze`, {
            method: "POST",
            headers,
            body: JSON.stringify({
              packages: pypiFiltered.map((c) => ({
                name: c.name,
                version: c.newVersion || "latest",
                previousVersion: c.oldVersion,
                isNew: c.oldVersion === null,
              })),
              config: apiConfig,
              repoMeta,
            }),
          })
        : null,
    ]);

    // Parse responses
    const npmResult = npmResponse ? await parseApiResponse(npmResponse) : null;
    const pypiResult = pypiResponse ? await parseApiResponse(pypiResponse) : null;

    const mergedApiPackages = [
      ...(npmResult?.packages ?? []),
      ...(pypiResult?.packages ?? []),
    ];
    const mergedScore = Math.max(npmResult?.score ?? 0, pypiResult?.score ?? 0);
    const mergedAction = mergedScore >= config.blockThreshold ? "block"
      : mergedScore >= config.warnThreshold ? "warn" : "pass";

    core.info(
      `API returned: score=${mergedScore} action=${mergedAction} packages=${mergedApiPackages.length}`
    );

    // Convert API response to ScanResult for the reporting module
    const packageResults: PackageScanResult[] = mergedApiPackages.map((pkg) => {
      const change = allFiltered.find((c) => c.name === pkg.name) ?? {
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
      maxScore: mergedScore,
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

async function parseApiResponse(response: Response): Promise<APIResponse> {
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`API returned ${response.status}: ${errorBody}`);
  }
  return (await response.json()) as APIResponse;
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
  prInfo: PrFileInfo
): Promise<{ npmChanges: PackageChange[]; pypiChanges: PackageChange[] }> {
  // --- npm extraction (existing logic) ---
  let npmChanges: PackageChange[] = [];
  if (prInfo.npmFilesChanged.length > 0) {
    npmChanges = extractNpmChanges(config);
  }

  // --- Python extraction ---
  let pypiChanges: PackageChange[] = [];
  if (prInfo.pypiFilesChanged.length > 0) {
    pypiChanges = extractPythonChanges(config, prInfo);
  }

  return { npmChanges, pypiChanges };
}

function extractNpmChanges(config: Config): PackageChange[] {
  const headLockfile = getHeadFileContent("package-lock.json");
  if (headLockfile) {
    core.info("Found package-lock.json — using lockfile diff");
    const baseLockfile = config.githubToken
      ? getBaseFileContent(getBranchBaseSha(), "package-lock.json")
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
    const basePkgJson = getBaseFileContent(getBranchBaseSha(), "package.json");

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

function extractPythonChanges(config: Config, prInfo: PrFileInfo): PackageChange[] {
  const allChanges: PackageChange[] = [];
  const baseSha = prInfo.baseSha;

  for (const pyFile of prInfo.pypiFilesChanged) {
    const basename = pyFile.split("/").pop() ?? "";
    const headContent = getHeadFileContent(pyFile);
    if (!headContent) continue;
    const baseContent = baseSha ? getBaseFileContent(baseSha, pyFile) : null;

    let changes: PackageChange[] = [];

    try {
      if (basename === "Pipfile.lock") {
        const head = parsePipfileLock(headContent);
        const base = baseContent ? parsePipfileLock(baseContent) : null;
        changes = diffPipfileLocks(base, head, config.maxPackages).changes;
      } else if (basename === "poetry.lock") {
        const head = parsePoetryLock(headContent);
        const base = baseContent ? parsePoetryLock(baseContent) : null;
        changes = diffPoetryLocks(base, head, config.maxPackages).changes;
      } else if (/requirements.*\.txt$/.test(basename)) {
        const head = parseRequirements(headContent);
        const base = baseContent ? parseRequirements(baseContent) : null;
        changes = diffRequirements(base, head, config.maxPackages).changes;
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      core.warning(`Failed to parse ${pyFile}: ${msg}`);
      continue;
    }

    for (const c of changes) {
      if (!allChanges.some((existing) => existing.name === c.name)) {
        allChanges.push(c);
      }
    }
  }

  return allChanges;
}

function getBranchBaseSha(): string {
  try {
    const ctx = github.context;
    return ctx.payload.pull_request?.base?.sha ?? "";
  } catch {
    return "";
  }
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

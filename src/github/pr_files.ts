import * as core from "@actions/core";
import * as github from "@actions/github";
import { execSync } from "child_process";
import * as fs from "fs";

const DEPENDENCY_FILES = [
  "package.json",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
];

export interface PrFileInfo {
  isPullRequest: boolean;
  dependencyFilesChanged: string[];
  prNumber: number;
  baseSha: string;
  headSha: string;
}

export async function getPrFiles(token: string): Promise<PrFileInfo> {
  const ctx = github.context;

  if (
    ctx.eventName !== "pull_request" &&
    ctx.eventName !== "pull_request_target"
  ) {
    return {
      isPullRequest: false,
      dependencyFilesChanged: [],
      prNumber: 0,
      baseSha: "",
      headSha: "",
    };
  }

  const prNumber = ctx.payload.pull_request?.number;
  if (!prNumber) {
    return {
      isPullRequest: false,
      dependencyFilesChanged: [],
      prNumber: 0,
      baseSha: "",
      headSha: "",
    };
  }

  const baseSha: string = ctx.payload.pull_request?.base?.sha ?? "";
  const headSha: string = ctx.payload.pull_request?.head?.sha ?? "";

  const octokit = github.getOctokit(token);
  const files = await octokit.paginate(octokit.rest.pulls.listFiles, {
    ...ctx.repo,
    pull_number: prNumber,
    per_page: 100,
  });

  const depFiles = files
    .map((f) => f.filename)
    .filter((f) =>
      DEPENDENCY_FILES.some((df) => f === df || f.endsWith("/" + df))
    );

  return {
    isPullRequest: true,
    dependencyFilesChanged: depFiles,
    prNumber,
    baseSha,
    headSha,
  };
}

export function getBaseFileContent(
  baseSha: string,
  filePath: string
): string | null {
  try {
    execSync(`git fetch origin ${baseSha} --depth=1`, {
      stdio: "pipe",
      timeout: 30000,
    });
  } catch {
    core.warning(`Failed to fetch base ref ${baseSha}`);
    return null;
  }

  try {
    const content = execSync(`git show ${baseSha}:${filePath}`, {
      encoding: "utf-8",
      maxBuffer: 50 * 1024 * 1024,
      timeout: 30000,
    });
    return content;
  } catch {
    return null;
  }
}

export function getHeadFileContent(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
}

export function resolveToken(): string {
  const inputToken = core.getInput("github_token");
  if (inputToken) return inputToken;

  const envToken = process.env.GITHUB_TOKEN;
  if (envToken) return envToken;

  throw new Error(
    "No GitHub token found. Provide github_token input or set GITHUB_TOKEN env var."
  );
}

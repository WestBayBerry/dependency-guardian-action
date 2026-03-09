import { PackageChange } from "../types";

export interface PoetryLockEntry {
  name: string;
  version: string;
  isDev: boolean;
  category?: string;
}

export interface ParsedPoetryLock {
  packages: Map<string, PoetryLockEntry>;
}

/**
 * Parse a poetry.lock file (TOML format) into package entries.
 * Uses a simple regex-based parser since poetry.lock has a predictable structure:
 *
 * [[package]]
 * name = "package-name"
 * version = "1.2.3"
 * category = "main" | "dev"
 *
 * We don't need a full TOML parser — just extract package blocks.
 */
export function parsePoetryLock(content: string): ParsedPoetryLock {
  const packages = new Map<string, PoetryLockEntry>();

  // Split into [[package]] blocks
  const blocks = content.split(/^\[\[package\]\]\s*$/m);

  for (const block of blocks) {
    const nameMatch = block.match(/^name\s*=\s*"([^"]+)"/m);
    const versionMatch = block.match(/^version\s*=\s*"([^"]+)"/m);

    if (!nameMatch || !versionMatch) continue;

    const name = normalizePyName(nameMatch[1]);
    const version = versionMatch[1];

    // Check category (poetry 1.x uses "category", poetry 2.x uses groups)
    const categoryMatch = block.match(/^category\s*=\s*"([^"]+)"/m);
    const category = categoryMatch?.[1] ?? "main";
    const isDev = category === "dev";

    if (!packages.has(name)) {
      packages.set(name, { name, version, isDev, category });
    }
  }

  return { packages };
}

export function diffPoetryLocks(
  base: ParsedPoetryLock | null,
  head: ParsedPoetryLock,
  maxPackages: number
): { changes: PackageChange[]; skipped: string[] } {
  const changes: PackageChange[] = [];

  for (const [name, headEntry] of head.packages) {
    const baseEntry = base?.packages.get(name);

    if (!baseEntry) {
      changes.push({
        name,
        oldVersion: null,
        newVersion: headEntry.version,
        isDirect: true,
        isDev: headEntry.isDev,
      });
    } else if (baseEntry.version !== headEntry.version) {
      changes.push({
        name,
        oldVersion: baseEntry.version,
        newVersion: headEntry.version,
        isDirect: true,
        isDev: headEntry.isDev,
      });
    }
  }

  changes.sort((a, b) => a.name.localeCompare(b.name));

  if (changes.length <= maxPackages) {
    return { changes, skipped: [] };
  }

  return {
    changes: changes.slice(0, maxPackages),
    skipped: changes.slice(maxPackages).map((c) => c.name),
  };
}

function normalizePyName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

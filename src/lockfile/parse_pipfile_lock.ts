import { PackageChange } from "../types";

export interface PipfileLockEntry {
  name: string;
  version: string;
  isDev: boolean;
}

export interface ParsedPipfileLock {
  packages: Map<string, PipfileLockEntry>;
}

/**
 * Parse a Pipfile.lock (JSON format) into package entries.
 * Pipfile.lock has two sections: "default" (production) and "develop" (dev).
 * Each entry is keyed by package name with a "version" field like "==1.2.3".
 */
export function parsePipfileLock(content: string): ParsedPipfileLock {
  const packages = new Map<string, PipfileLockEntry>();
  const json = JSON.parse(content);

  parsePipfileSection(json.default, false, packages);
  parsePipfileSection(json.develop, true, packages);

  return { packages };
}

function parsePipfileSection(
  section: unknown,
  isDev: boolean,
  packages: Map<string, PipfileLockEntry>
): void {
  if (!section || typeof section !== "object") return;

  for (const [rawName, entry] of Object.entries(section as Record<string, unknown>)) {
    if (!entry || typeof entry !== "object") continue;
    const entryObj = entry as Record<string, unknown>;
    const rawVersion = entryObj.version;
    if (typeof rawVersion !== "string") continue;

    const name = normalizePyName(rawName);
    // Strip leading "==" from version
    const version = rawVersion.replace(/^==/, "");

    if (!packages.has(name)) {
      packages.set(name, { name, version, isDev });
    }
  }
}

export function diffPipfileLocks(
  base: ParsedPipfileLock | null,
  head: ParsedPipfileLock,
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

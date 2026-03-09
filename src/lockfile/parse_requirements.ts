import { PackageChange } from "../types";

export interface RequirementsEntry {
  name: string;
  version: string;
  extras?: string[];
}

export interface ParsedRequirements {
  packages: Map<string, RequirementsEntry>;
}

/**
 * Parse a requirements.txt file into package entries.
 * Handles: name==version, name>=version, name~=version, name!=version,
 * extras like name[extra1,extra2]==version, comments (#), -r includes (ignored),
 * environment markers (;), and line continuations (\).
 */
export function parseRequirements(content: string): ParsedRequirements {
  const packages = new Map<string, RequirementsEntry>();

  // Join line continuations
  const joined = content.replace(/\\\n/g, "");
  const lines = joined.split("\n");

  for (const rawLine of lines) {
    const line = rawLine.trim();

    // Skip empty lines, comments, options, and -r/-c references
    if (!line || line.startsWith("#") || line.startsWith("-") || line.startsWith("--")) {
      continue;
    }

    // Strip environment markers (everything after ;)
    const withoutMarker = line.split(";")[0].trim();
    if (!withoutMarker) continue;

    // Parse package name, extras, and version specifier
    const match = withoutMarker.match(
      /^([a-zA-Z0-9][-a-zA-Z0-9_.]*(?:\[[^\]]*\])?)(?:\s*(==|>=|<=|~=|!=|>|<|===)\s*([^\s,;]+))?/
    );
    if (!match) continue;

    const nameWithExtras = match[1];
    const version = match[3] || "";

    // Extract extras: name[extra1,extra2] -> name, [extra1, extra2]
    const extrasMatch = nameWithExtras.match(/^([a-zA-Z0-9][-a-zA-Z0-9_.]*)(?:\[([^\]]*)\])?$/);
    if (!extrasMatch) continue;

    const name = normalizePyName(extrasMatch[1]);
    const extras = extrasMatch[2]
      ? extrasMatch[2].split(",").map((e) => e.trim()).filter(Boolean)
      : undefined;

    if (!packages.has(name)) {
      packages.set(name, { name, version, extras });
    }
  }

  return { packages };
}

/**
 * Diff two requirements.txt files to find added/changed packages.
 */
export function diffRequirements(
  base: ParsedRequirements | null,
  head: ParsedRequirements,
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
        isDev: false,
      });
    } else if (baseEntry.version !== headEntry.version) {
      changes.push({
        name,
        oldVersion: baseEntry.version,
        newVersion: headEntry.version,
        isDirect: true,
        isDev: false,
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

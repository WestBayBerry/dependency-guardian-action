import { PackageChange } from "../types";
import { ParsedLockfile } from "./parse_package_lock";

export interface DiffResult {
  changes: PackageChange[];
  skipped: string[];
}

export function diffLockfiles(
  base: ParsedLockfile | null,
  head: ParsedLockfile,
  maxPackages: number,
  directDeps?: Set<string>
): DiffResult {
  const allChanges: PackageChange[] = [];

  for (const [name, headEntry] of head.packages) {
    const baseEntry = base?.packages.get(name);

    if (!baseEntry) {
      allChanges.push({
        name,
        oldVersion: null,
        newVersion: headEntry.version,
        isDirect: directDeps?.has(name) ?? false,
        isDev: headEntry.dev ?? false,
      });
    } else if (baseEntry.version !== headEntry.version) {
      allChanges.push({
        name,
        oldVersion: baseEntry.version,
        newVersion: headEntry.version,
        isDirect: directDeps?.has(name) ?? false,
        isDev: headEntry.dev ?? false,
      });
    }
  }

  allChanges.sort((a, b) => {
    if (a.isDirect !== b.isDirect) return a.isDirect ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  if (allChanges.length <= maxPackages) {
    return { changes: allChanges, skipped: [] };
  }

  const changes = allChanges.slice(0, maxPackages);
  const skipped = allChanges.slice(maxPackages).map((c) => c.name);
  return { changes, skipped };
}

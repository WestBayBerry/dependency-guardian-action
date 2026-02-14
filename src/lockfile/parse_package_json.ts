import { PackageChange } from "../types";

export interface PackageJsonDiffResult {
  changes: PackageChange[];
}

export function diffPackageJsons(
  baseContent: string | null,
  headContent: string,
  maxPackages: number
): PackageJsonDiffResult {
  const head = JSON.parse(headContent);
  const headDeps: Record<string, string> = {
    ...head.dependencies,
    ...head.devDependencies,
  };

  let baseDeps: Record<string, string> = {};
  if (baseContent) {
    const base = JSON.parse(baseContent);
    baseDeps = { ...base.dependencies, ...base.devDependencies };
  }

  const changes: PackageChange[] = [];

  for (const [name, version] of Object.entries(headDeps)) {
    if (changes.length >= maxPackages) break;

    const baseVersion = baseDeps[name];
    const isDev = !!(head.devDependencies && head.devDependencies[name]);

    if (!baseVersion) {
      changes.push({
        name,
        oldVersion: null,
        newVersion: version,
        isDirect: true,
        isDev,
      });
    } else if (baseVersion !== version) {
      changes.push({
        name,
        oldVersion: baseVersion,
        newVersion: version,
        isDirect: true,
        isDev,
      });
    }
  }

  return { changes };
}

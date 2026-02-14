export interface LockfileEntry {
  version: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
}

export interface ParsedLockfile {
  lockfileVersion: number;
  packages: Map<string, LockfileEntry>;
}

export function parseLockfile(content: string): ParsedLockfile {
  const json = JSON.parse(content);
  const lockfileVersion: number = json.lockfileVersion ?? 1;
  const packages = new Map<string, LockfileEntry>();

  if (lockfileVersion >= 2 && json.packages) {
    for (const [path, entry] of Object.entries(json.packages)) {
      if (path === "") continue;
      const name = extractPackageName(path);
      if (name) {
        const e = entry as Record<string, unknown>;
        packages.set(name, {
          version: (e.version as string) ?? "",
          resolved: e.resolved as string | undefined,
          integrity: e.integrity as string | undefined,
          dev: e.dev as boolean | undefined,
        });
      }
    }
  } else if (json.dependencies) {
    parseLegacyDeps(json.dependencies, packages);
  }

  return { lockfileVersion, packages };
}

function extractPackageName(nodePath: string): string | null {
  const prefix = "node_modules/";
  const lastIdx = nodePath.lastIndexOf(prefix);
  if (lastIdx === -1) return null;
  const name = nodePath.slice(lastIdx + prefix.length);
  return name || null;
}

function parseLegacyDeps(
  deps: Record<string, unknown>,
  packages: Map<string, LockfileEntry>,
  parentPrefix = ""
): void {
  for (const [name, value] of Object.entries(deps)) {
    const fullName = parentPrefix ? `${parentPrefix}/${name}` : name;
    const entry = value as Record<string, unknown>;
    packages.set(fullName, {
      version: (entry.version as string) ?? "",
      resolved: entry.resolved as string | undefined,
      integrity: entry.integrity as string | undefined,
      dev: entry.dev as boolean | undefined,
    });
    if (entry.dependencies) {
      parseLegacyDeps(
        entry.dependencies as Record<string, unknown>,
        packages
      );
    }
  }
}

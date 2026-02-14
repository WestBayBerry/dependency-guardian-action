export interface Config {
  githubToken: string;
  blockThreshold: number;
  warnThreshold: number;
  noteworthyThreshold: number;
  mode: "block" | "warn" | "off";
  allowlist: string[];
  maxPackages: number;
  includeDev: boolean;
  freshPublishHours: number;
  youngRepoDays: number;
  lowStarsThreshold: number;
}

export interface PackageChange {
  name: string;
  oldVersion: string | null;
  newVersion: string;
  isDirect: boolean;
  isDev: boolean;
}

export interface PackageScanResult {
  pkg: PackageChange;
  detectorResults: DetectorFinding[];
  score: number;
  reasons: string[];
  recommendation?: string;
}

export interface ScanResult {
  packages: PackageScanResult[];
  maxScore: number;
  totalScanned: number;
  skipped: string[];
}

export interface DetectorSignal {
  kind: string;
  value?: string | number | boolean;
}

export interface DetectorFinding {
  id: string;
  severity: 1 | 2 | 3 | 4 | 5;
  confidence: number;
  title: string;
  evidence: string[];
  critical?: boolean;
  signals?: DetectorSignal[];
}

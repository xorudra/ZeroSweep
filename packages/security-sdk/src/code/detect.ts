import type {
  DetectedLanguage, LanguageDetectionResult, RepositoryFileClass, SourceFileEntry,
} from "./types";

/**
 * Language / framework / build-system detection (Prompt 12 §15–§17) and
 * repository file classification (§84/§87/§88). Everything here works
 * from file LISTINGS and manifest CONTENTS as data — detection reads
 * metadata only and never executes anything it finds (§14).
 */

const LANGUAGE_BY_EXTENSION: Record<string, string> = {
  ts: "TypeScript", tsx: "TypeScript", js: "JavaScript", jsx: "JavaScript", mjs: "JavaScript", cjs: "JavaScript",
  py: "Python", java: "Java", rb: "Ruby", go: "Go", rs: "Rust", php: "PHP",
  c: "C", h: "C", cpp: "C++", cc: "C++", cxx: "C++", hpp: "C++", cs: "C#",
  sh: "Shell", bash: "Shell", kt: "Kotlin", kts: "Kotlin", swift: "Swift",
  scala: "Scala", pl: "Perl", lua: "Lua", ex: "Elixir", exs: "Elixir", erl: "Erlang",
  clj: "Clojure", hs: "Haskell", ml: "OCaml", vue: "Vue", svelte: "Svelte",
};

function extensionOf(path: string): string {
  const base = path.split("/").pop() ?? "";
  const dot = base.lastIndexOf(".");
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : "";
}

export function detectLanguages(files: SourceFileEntry[]): LanguageDetectionResult {
  const counts = new Map<string, number>();
  let total = 0;
  for (const file of files) {
    const cls = classifyRepositoryFile(file.path);
    if (cls !== "SOURCE" && cls !== "TEST") continue;
    const language = LANGUAGE_BY_EXTENSION[extensionOf(file.path)];
    if (!language) continue;
    counts.set(language, (counts.get(language) ?? 0) + 1);
    total += 1;
  }
  const languages: DetectedLanguage[] = [...counts.entries()]
    .map(([language, fileCount]) => ({ language, fileCount, percentage: total > 0 ? fileCount / total : 0 }))
    .sort((a, b) => b.fileCount - a.fileCount || a.language.localeCompare(b.language));
  return {
    languages,
    primaryLanguage: languages[0]?.language,
    frameworks: [],
    buildSystems: [],
  };
}

const BUILD_SYSTEM_MARKERS: { file: string; system: string }[] = [
  { file: "package.json", system: "npm" },
  { file: "pnpm-lock.yaml", system: "pnpm" },
  { file: "yarn.lock", system: "yarn" },
  { file: "pom.xml", system: "maven" },
  { file: "build.gradle", system: "gradle" },
  { file: "build.gradle.kts", system: "gradle" },
  { file: "Gemfile", system: "bundler" },
  { file: "Gemfile.lock", system: "bundler" },
  { file: "go.mod", system: "go-modules" },
  { file: "Cargo.toml", system: "cargo" },
  { file: "requirements.txt", system: "pip" },
  { file: "Pipfile", system: "pipenv" },
  { file: "poetry.lock", system: "poetry" },
  { file: "pyproject.toml", system: "python-packaging" },
  { file: "composer.json", system: "composer" },
  { file: "mix.exs", system: "mix" },
];

export function detectBuildSystems(files: SourceFileEntry[]): string[] {
  const names = new Set(files.map((f) => f.path.split("/").pop() ?? ""));
  return [...new Set(BUILD_SYSTEM_MARKERS.filter((m) => names.has(m.file)).map((m) => m.system))].sort();
}

/**
 * Framework detection from manifest CONTENTS (dependency names are data,
 * §16). Manifest contents are the repository's own declarations — read
 * as text, never installed or executed (§57).
 */
const FRAMEWORK_SIGNATURES: { framework: string; manifestHints: string[] }[] = [
  { framework: "Express", manifestHints: ["\"express\""] },
  { framework: "React", manifestHints: ["\"react\""] },
  { framework: "Angular", manifestHints: ["\"@angular/core\""] },
  { framework: "Vue", manifestHints: ["\"vue\""] },
  { framework: "Next.js", manifestHints: ["\"next\""] },
  { framework: "Django", manifestHints: ["django"] },
  { framework: "Flask", manifestHints: ["flask"] },
  { framework: "FastAPI", manifestHints: ["fastapi"] },
  { framework: "Rails", manifestHints: ["rails"] },
  { framework: "Spring", manifestHints: ["spring-boot", "springframework"] },
  { framework: "Laravel", manifestHints: ["laravel/framework"] },
  { framework: "ASP.NET", manifestHints: ["Microsoft.AspNetCore"] },
];

export function detectFrameworks(manifestContents: Record<string, string>): string[] {
  const corpus = Object.values(manifestContents).join("\n").toLowerCase();
  return FRAMEWORK_SIGNATURES.filter((s) => s.manifestHints.some((h) => corpus.includes(h.toLowerCase()))).map((s) => s.framework).sort();
}

/** Full detection pass (§15–§17) over a snapshot listing + manifests. */
export function detectRepository(files: SourceFileEntry[], manifestContents: Record<string, string> = {}): LanguageDetectionResult {
  const base = detectLanguages(files);
  return {
    ...base,
    frameworks: detectFrameworks(manifestContents),
    buildSystems: detectBuildSystems(files),
  };
}

const MANIFEST_FILES = new Set([
  "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
  "requirements.txt", "pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml",
  "pom.xml", "build.gradle", "build.gradle.kts", "gemfile", "gemfile.lock",
  "go.mod", "go.sum", "cargo.toml", "cargo.lock", "composer.json", "composer.lock",
]);

const BINARY_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "ico", "pdf", "zip", "jar", "war", "class",
  "so", "dll", "exe", "bin", "woff", "woff2", "ttf", "eot", "mp4", "mp3",
]);

/**
 * Classify one repository file (§84/§87/§88). Order matters: manifests
 * and vendored trees win over generic source classification so generated
 * and third-party code is never mistaken for first-party source.
 */
export function classifyRepositoryFile(path: string): RepositoryFileClass {
  const lower = path.toLowerCase();
  const base = lower.split("/").pop() ?? "";
  if (MANIFEST_FILES.has(base)) return "DEPENDENCY_MANIFEST";
  if (/(^|\/)(node_modules|vendor|third_party|bower_components)\//.test(lower)) return "VENDORED";
  if (/(^|\/)(dist|build|out|target|\.next|coverage)\//.test(lower)) return "BUILD_OUTPUT";
  if (/\.min\.(js|css)$/.test(lower) || /(^|\/)generated\//.test(lower) || /\.generated\./.test(lower) || base.endsWith(".pb.go") || base.endsWith("_pb2.py")) return "GENERATED";
  if (BINARY_EXTENSIONS.has(extensionOf(lower))) return "BINARY";
  if (/(^|\/)(test|tests|__tests__|spec|__mocks__)(\/|$)/.test(lower) || /\.(test|spec)\.[a-z]+$/.test(lower) || base.startsWith("test_") || base.endsWith("_test.go")) return "TEST";
  if (/\.(md|rst|txt|adoc)$/.test(lower) && !MANIFEST_FILES.has(base)) return "DOCUMENTATION";
  if (/\.(json|ya?ml|toml|ini|cfg|conf|properties|xml)$/.test(lower) || base.startsWith(".") || /(^|\/)config\//.test(lower)) return "CONFIGURATION";
  if (LANGUAGE_BY_EXTENSION[extensionOf(lower)]) return "SOURCE";
  return "UNKNOWN";
}

/** True for files whose findings default to lower priority (§87). */
export function isGeneratedOrVendored(path: string): boolean {
  const cls = classifyRepositoryFile(path);
  return cls === "GENERATED" || cls === "VENDORED" || cls === "BUILD_OUTPUT";
}

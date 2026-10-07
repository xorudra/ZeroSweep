import { createHash } from "node:crypto";

/**
 * Wordlist management (Prompt 6 §10–§13). Wordlists are GOVERNED PLATFORM
 * DATA: administrators register them in controlled storage, adapters refer
 * to them by registered ID only, and users can never supply a filesystem
 * path (§11 — "/etc/passwd" as a wordlist location is rejected by shape
 * before any lookup happens). The lists bundled here are deliberately
 * SMALL starter lists so the pipeline is testable offline; production
 * deployments register full lists (SecLists-scale) as admin wordlists
 * whose entries live in controlled storage, never in application code.
 */

export const WORDLIST_CATEGORIES = [
  "COMMON_DIRECTORIES", "COMMON_FILES", "API_ROUTES", "TECHNOLOGY_SPECIFIC", "PARAMETER_NAMES",
] as const;
export type WordlistCategory = (typeof WORDLIST_CATEGORIES)[number];

export const WORDLIST_PROFILES = ["SMALL", "STANDARD", "COMPREHENSIVE"] as const;
export type WordlistProfile = (typeof WORDLIST_PROFILES)[number];

export interface WordlistRecord {
  id: string;
  name: string;
  description: string;
  category: WordlistCategory;
  /** Controlled-storage reference (relative, e.g. "builtin/common-dirs-small.txt").
   *  NEVER an absolute or user-supplied filesystem path (§11). */
  storageLocation: string;
  checksum: string;
  entryCount: number;
  sizeBytes: number;
  enabled: boolean;
  /** Discovery profile this list serves (category lists may serve several). */
  profiles: WordlistProfile[];
  /** Technology hint for TECHNOLOGY_SPECIFIC lists (§13) — a hint, never a fact. */
  technology?: string;
  /** Bundled starter entries; admin-registered lists keep entries in
   *  controlled storage, so this stays undefined for them. */
  entries?: string[];
}

export class WordlistError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WordlistError";
  }
}

const WORDLIST_ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

/** §11: a wordlist identifier is a slug, never a path. Anything containing
 *  a separator, a dot segment or an absolute marker is rejected outright. */
export function assertWordlistId(id: unknown): string {
  if (typeof id !== "string" || !WORDLIST_ID_RE.test(id) || id.includes("..")) {
    throw new WordlistError(`invalid wordlist id ${JSON.stringify(String(id)).slice(0, 64)}: wordlists are referenced by registered id, never by filesystem path`);
  }
  return id;
}

/** Registration-time validation of a controlled-storage reference. */
export function assertStorageLocation(location: unknown): string {
  if (
    typeof location !== "string" || location.length === 0 || location.length > 200 ||
    location.startsWith("/") || location.startsWith("\\") || location.includes("..") || location.includes("\\") || /^[a-zA-Z]:/.test(location)
  ) {
    throw new WordlistError("wordlist storageLocation must be a relative controlled-storage reference (no absolute paths, no traversal)");
  }
  return location;
}

export function wordlistChecksum(entries: readonly string[]): string {
  return createHash("sha256").update(entries.join("\n")).digest("hex");
}

function bundled(
  id: string, name: string, description: string, category: WordlistCategory,
  profiles: WordlistProfile[], entries: string[], technology?: string,
): WordlistRecord {
  const sorted = [...new Set(entries.map((e) => e.trim()).filter(Boolean))];
  return {
    id, name, description, category,
    storageLocation: `builtin/${id}.txt`,
    checksum: wordlistChecksum(sorted),
    entryCount: sorted.length,
    sizeBytes: Buffer.byteLength(sorted.join("\n")),
    enabled: true,
    profiles,
    ...(technology ? { technology } : {}),
    entries: sorted,
  };
}

const DIRECTORIES_SMALL = [
  "admin", "login", "dashboard", "api", "assets", "static", "uploads", "images",
  "css", "js", "fonts", "docs", "help", "about", "contact", "search",
  "account", "profile", "settings", "config", "backup", "tmp", "test", "dev",
];
const DIRECTORIES_STANDARD_EXTRA = [
  "administrator", "wp-admin", "wp-content", "wp-includes", "wp-login.php", "xmlrpc.php",
  "management", "console", "portal", "panel", "cpanel", "webmail", "mail", "ftp",
  "private", "internal", "hidden", "old", "new", "beta", "staging", "prod",
  "v1", "v2", "rest", "graphql", "swagger", "openapi", "actuator", "metrics",
  "health", "status", "info", "debug", "logs", "data", "files", "media", "download", "export",
];
const DIRECTORIES_COMPREHENSIVE_EXTRA = [
  "wp-json", "wp-cron.php", ".git", ".env", "server-status", "phpinfo.php", "elmah.axd",
  "trace.axd", "web.config", "crossdomain.xml", "clientaccesspolicy.xml", "sitemap.xml",
  "robots.txt", "security.txt", ".well-known", "api-docs", "redoc", "graphiql", "playground",
  "vendor", "node_modules", "dist", "build", "src", "app", "core", "includes", "modules",
  "themes", "plugins", "cache", "temp", "archive", "backups", "db", "database", "sql",
  "install", "setup", "upgrade", "update", "register", "signup", "forgot-password", "reset",
  "oauth", "auth", "sso", "saml", "callback", "webhook", "hooks", "cron", "jobs",
];
const COMMON_FILES = [
  "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt", "favicon.ico",
  "manifest.json", "site.webmanifest", "humans.txt", "ads.txt", "index.html", "index.php",
  "crossdomain.xml", "clientaccesspolicy.xml", "README.md", "CHANGELOG.md", "composer.json",
  "package.json", "web.config", "phpinfo.php", "server-status", "health", "ready",
];
const API_ROUTES = [
  "api", "api/v1", "api/v2", "api/users", "api/user", "api/auth", "api/login", "api/logout",
  "api/search", "api/products", "api/items", "api/orders", "api/admin", "api/config",
  "api/health", "api/status", "api/docs", "api/openapi.json", "api/swagger.json",
  "graphql", "rest", "v1", "v2", "oauth/token", "oauth/authorize",
];
const PARAMETER_NAMES = [
  "id", "page", "lang", "search", "q", "query", "category", "sort", "order", "limit",
  "offset", "filter", "type", "name", "email", "user", "username", "file", "path",
  "url", "redirect", "next", "return", "callback", "ref", "source", "format", "view",
  "mode", "action", "tab", "section", "date", "year", "month", "day", "tag", "author",
];
const WORDPRESS_ROUTES = [
  "wp-admin", "wp-login.php", "wp-content", "wp-includes", "wp-json", "wp-json/wp/v2",
  "wp-json/wp/v2/users", "wp-json/wp/v2/posts", "xmlrpc.php", "wp-cron.php", "wp-config.php",
  "wp-content/uploads", "wp-content/plugins", "wp-content/themes", "readme.html", "license.txt",
];

/** The bundled starter registry. Sizes are intentionally tiny next to real
 *  assessment lists — they prove the machinery, not the coverage. */
export const BUNDLED_WORDLISTS: WordlistRecord[] = [
  bundled("common-directories-small", "Common directories (small)", "Fast baseline directory vocabulary for the SMALL profile.", "COMMON_DIRECTORIES", ["SMALL"], DIRECTORIES_SMALL),
  bundled("common-directories-standard", "Common directories (standard)", "Standard directory vocabulary: small list plus common application routes.", "COMMON_DIRECTORIES", ["STANDARD"], [...DIRECTORIES_SMALL, ...DIRECTORIES_STANDARD_EXTRA]),
  bundled("common-directories-comprehensive", "Common directories (comprehensive)", "Comprehensive directory vocabulary — larger assessments only, never auto-selected (§12).", "COMMON_DIRECTORIES", ["COMPREHENSIVE"], [...DIRECTORIES_SMALL, ...DIRECTORIES_STANDARD_EXTRA, ...DIRECTORIES_COMPREHENSIVE_EXTRA]),
  bundled("common-files", "Common files", "Well-known public files worth inventorying (robots.txt, sitemaps, manifests — §22).", "COMMON_FILES", ["SMALL", "STANDARD", "COMPREHENSIVE"], COMMON_FILES),
  bundled("api-routes", "API routes", "Common API route vocabulary (§13: added when an API surface is detected).", "API_ROUTES", ["STANDARD", "COMPREHENSIVE"], API_ROUTES),
  bundled("parameter-names", "Parameter names", "Common parameter names for controlled parameter discovery (§29).", "PARAMETER_NAMES", ["SMALL", "STANDARD", "COMPREHENSIVE"], PARAMETER_NAMES),
  bundled("wordpress-routes", "WordPress routes", "WordPress-oriented route vocabulary (§13 technology hint).", "TECHNOLOGY_SPECIFIC", ["STANDARD", "COMPREHENSIVE"], WORDPRESS_ROUTES, "wordpress"),
];

/** In-container location a plan may reference for a registered wordlist.
 *  Derived ONLY from the validated storage reference — user input never
 *  reaches this string (§11). */
export const WORDLIST_CONTAINER_DIR = "/wordlists";
export function wordlistContainerPath(record: WordlistRecord): string {
  return `${WORDLIST_CONTAINER_DIR}/${assertStorageLocation(record.storageLocation)}`;
}

export class WordlistManager {
  private readonly byId = new Map<string, WordlistRecord>();

  constructor(records: readonly WordlistRecord[] = BUNDLED_WORDLISTS) {
    for (const r of records) this.register(r);
  }

  /** Register an administrator-managed wordlist (§10). Metadata is
   *  validated; duplicate ids are refused; path-shaped ids/locations are
   *  refused (§11). */
  register(record: WordlistRecord): WordlistRecord {
    assertWordlistId(record.id);
    assertStorageLocation(record.storageLocation);
    if (this.byId.has(record.id)) throw new WordlistError(`wordlist ${record.id} is already registered`);
    if (!WORDLIST_CATEGORIES.includes(record.category)) throw new WordlistError(`unknown wordlist category ${String(record.category)}`);
    const entries = record.entries ? [...new Set(record.entries.map((e) => e.trim()).filter(Boolean))] : undefined;
    const stored: WordlistRecord = {
      ...record,
      ...(entries ? { entries, entryCount: entries.length, checksum: wordlistChecksum(entries), sizeBytes: Buffer.byteLength(entries.join("\n")) } : {}),
    };
    this.byId.set(stored.id, stored);
    return stored;
  }

  list(category?: WordlistCategory): WordlistRecord[] {
    const all = [...this.byId.values()].filter((r) => r.enabled);
    return category ? all.filter((r) => r.category === category) : all;
  }

  /** Resolve by REGISTERED ID ONLY (§11). Unknown ids throw — callers must
   *  never fall back to treating the value as a path. */
  resolve(id: string): WordlistRecord {
    assertWordlistId(id);
    const record = this.byId.get(id);
    if (!record || !record.enabled) throw new WordlistError(`wordlist ${id} is not registered (or is disabled)`);
    return record;
  }

  entries(id: string): string[] {
    const record = this.resolve(id);
    if (!record.entries) {
      throw new WordlistError(`wordlist ${id} entries live in controlled storage (${record.storageLocation}) and are mounted into the tool container at execution time`);
    }
    return record.entries;
  }

  /** The registered list serving a profile for a category (§12). When no
   *  list serves the requested level, selection falls DOWNWARD
   *  (COMPREHENSIVE → STANDARD → SMALL) — never upward into a bigger list
   *  than the profile asked for. Among candidates, the most specific list
   *  (the one stretching least beyond the requested level) wins. */
  forProfile(category: WordlistCategory, profile: WordlistProfile): WordlistRecord {
    const rank: Record<WordlistProfile, number> = { SMALL: 0, STANDARD: 1, COMPREHENSIVE: 2 };
    const levels: WordlistProfile[] = ["SMALL", "STANDARD", "COMPREHENSIVE"].slice(0, rank[profile] + 1).reverse() as WordlistProfile[];
    for (const level of levels) {
      const serving = this.list(category)
        .filter((r) => r.profiles.includes(level))
        .sort((a, b) => (Math.max(...a.profiles.map((p) => rank[p])) - Math.max(...b.profiles.map((p) => rank[p]))) || (a.entryCount - b.entryCount));
      if (serving.length > 0) return serving[0]!;
    }
    throw new WordlistError(`no registered wordlist for category ${category} at profile ${profile}`);
  }

  /** Technology-aware additions (§13): detection is a HINT — matching
   *  technology-specific lists are offered, never silently trusted. */
  forTechnologies(technologies: readonly string[]): WordlistRecord[] {
    const hints = new Set(technologies.map((t) => t.toLowerCase()));
    return this.list("TECHNOLOGY_SPECIFIC").filter((r) => r.technology && hints.has(r.technology.toLowerCase()));
  }

  /** Resolve everything a content-discovery plan may use: one primary list
   *  for the category/profile plus technology-specific additions. */
  resolveForDiscovery(input: { category: WordlistCategory; profile: WordlistProfile; technologies?: readonly string[] }): { primary: WordlistRecord; additional: WordlistRecord[] } {
    const primary = this.forProfile(input.category, input.profile);
    const additional = input.technologies && input.technologies.length > 0
      ? this.forTechnologies(input.technologies).filter((r) => r.id !== primary.id)
      : [];
    return { primary, additional };
  }
}

/** Default shared manager over the bundled registry. */
export const defaultWordlistManager = new WordlistManager();

import { describe, expect, it } from "vitest";
import {
  BUNDLED_WORDLISTS, WordlistError, WordlistManager, assertWordlistId, wordlistChecksum, wordlistContainerPath,
} from "./wordlists";

describe("WordlistManager (§10–§13)", () => {
  const mgr = new WordlistManager();

  it("bundled registry covers every category with consistent checksums", () => {
    const categories = new Set(BUNDLED_WORDLISTS.map((w) => w.category));
    expect(categories).toEqual(new Set(["COMMON_DIRECTORIES", "COMMON_FILES", "API_ROUTES", "TECHNOLOGY_SPECIFIC", "PARAMETER_NAMES"]));
    for (const w of BUNDLED_WORDLISTS) {
      expect(w.checksum).toBe(wordlistChecksum(w.entries!));
      expect(w.entryCount).toBe(w.entries!.length);
      expect(w.storageLocation).toMatch(/^builtin\//);
      expect(wordlistContainerPath(w)).toBe(`/wordlists/${w.storageLocation}`);
    }
  });

  it("profiles pick the right-sized list and never auto-select COMPREHENSIVE (§12)", () => {
    const small = mgr.forProfile("COMMON_DIRECTORIES", "SMALL");
    const standard = mgr.forProfile("COMMON_DIRECTORIES", "STANDARD");
    const comprehensive = mgr.forProfile("COMMON_DIRECTORIES", "COMPREHENSIVE");
    expect(small.id).toBe("common-directories-small");
    expect(standard.id).toBe("common-directories-standard");
    expect(comprehensive.id).toBe("common-directories-comprehensive");
    expect(small.entryCount).toBeLessThan(standard.entryCount);
    expect(standard.entryCount).toBeLessThan(comprehensive.entryCount);
  });

  it("falls downward only — a list is never bigger than the profile asked (§12)", () => {
    // Prompt 9 §14 added the governed API_ROUTES_SMALL list, so the API
    // category now serves SMALL exactly; the downward-only rule is
    // proven on a category with no serving list at all: refusal beats a
    // silent upgrade.
    expect(mgr.forProfile("API_ROUTES", "SMALL").id).toBe("api-routes-small");
    const noSmall = new WordlistManager(BUNDLED_WORDLISTS.filter((w) => w.id === "api-routes"));
    expect(() => noSmall.forProfile("API_ROUTES", "SMALL")).toThrow(WordlistError);
    // With only the SMALL directories list registered, a STANDARD request
    // falls DOWN to it rather than inventing a bigger list.
    const smallOnly = new WordlistManager(BUNDLED_WORDLISTS.filter((w) => w.id === "common-directories-small"));
    expect(smallOnly.forProfile("COMMON_DIRECTORIES", "STANDARD").id).toBe("common-directories-small");
    expect(smallOnly.forProfile("COMMON_DIRECTORIES", "COMPREHENSIVE").id).toBe("common-directories-small");
  });

  it("technology hints add technology-specific vocabulary (§13)", () => {
    const { primary, additional } = mgr.resolveForDiscovery({ category: "COMMON_DIRECTORIES", profile: "STANDARD", technologies: ["WordPress", "nginx"] });
    expect(primary.id).toBe("common-directories-standard");
    expect(additional.map((w) => w.id)).toEqual(["wordpress-routes"]);
    const none = mgr.resolveForDiscovery({ category: "COMMON_DIRECTORIES", profile: "STANDARD", technologies: ["nginx"] });
    expect(none.additional).toEqual([]);
  });

  it("path injection is refused by shape — ids are slugs, never paths (§11)", () => {
    for (const evil of ["/etc/passwd", "../secret", "..\\windows", "a/b", "C:\\lists\\x", "", "/wordlists/x"]) {
      expect(() => assertWordlistId(evil)).toThrow(WordlistError);
      expect(() => mgr.resolve(evil)).toThrow(WordlistError);
    }
    expect(() => mgr.resolve("not-registered")).toThrow(/not registered/);
  });

  it("administrator registration validates metadata and rejects duplicates (§10/§11)", () => {
    const m = new WordlistManager([]);
    const rec = m.register({
      id: "corp-dirs", name: "Corp directories", description: "admin list", category: "COMMON_DIRECTORIES",
      storageLocation: "corp/dirs.txt", checksum: "", entryCount: 0, sizeBytes: 0, enabled: true, profiles: ["STANDARD"],
    });
    expect(rec.id).toBe("corp-dirs");
    expect(() => m.register(rec)).toThrow(/already registered/);
    expect(() => m.register({ ...rec, id: "corp-2", storageLocation: "/etc/passwd" })).toThrow(WordlistError);
    // Admin entries live in controlled storage — the manager refuses to
    // pretend it can serve them from code.
    expect(() => m.entries("corp-dirs")).toThrow(/controlled storage/);
  });
});

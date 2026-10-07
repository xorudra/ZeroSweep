/**
 * Prompt 18 — binary identification + header parsing (§5/§12–§15).
 *
 * Format identification uses MAGIC BYTES ONLY — the declared filename
 * or extension is never trusted (§102: a file named report.pdf that
 * contains an ELF is an ELF). Parsers are pure functions over bytes:
 * they NEVER execute, load or map the artifact as code, and they fail
 * SAFELY on malformed input (§103) — truncated headers, lying counts
 * and out-of-range offsets produce a malformed report, never a throw
 * and never an unbounded read. All counts are capped by the budget.
 */
import { sanitizeMobileText } from "../mobile/sanitize";

export interface BinarySectionRaw {
  name: string;
  type?: string;
  offset: number;
  size: number;
  virtualAddress: string;
  permissions: string; // subset of R/W/X
  entropy?: number;
}

export interface BinaryHeaderReport {
  format: "ELF" | "PE" | "MACH_O" | "UNKNOWN";
  kind: "EXECUTABLE" | "SHARED_LIBRARY" | "OBJECT" | "CORE" | "UNKNOWN";
  architecture?: string;
  bitness?: 32 | 64;
  endianness?: "LE" | "BE";
  platform?: string;
  entryPoint?: string;
  stripped: "STRIPPED" | "NOT_STRIPPED" | "UNKNOWN";
  hasDebugInfo: boolean;
  debugPaths: string[];
  compilerHints: string[];
  sections: BinarySectionRaw[];
  dynamicLibraries: string[];
  importedSymbols: { library: string | null; symbol: string }[];
  exportedSymbols: string[];
  symbolNames: string[];
  hasStackCanary: boolean;
  fortifySymbols: boolean;
  /** Raw hardening signals — normalized in hardening.ts. */
  signals: Record<string, string>;
  malformed: boolean;
  errors: string[];
}

function hex(n: number | bigint): string {
  return `0x${n.toString(16)}`;
}

function sectionEntropy(bytes: Buffer, offset: number, size: number): number {
  const len = Math.min(size, 65536);
  if (len <= 0 || offset < 0 || offset >= bytes.length) return 0;
  const counts = new Array(256).fill(0);
  const end = Math.min(bytes.length, offset + len);
  for (let i = offset; i < end; i++) counts[bytes[i]!]!++;
  let entropy = 0;
  const total = end - offset;
  for (const c of counts) {
    if (c === 0) continue;
    const p = c / total;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

function emptyReport(format: BinaryHeaderReport["format"]): BinaryHeaderReport {
  return {
    format, kind: "UNKNOWN", stripped: "UNKNOWN", hasDebugInfo: false,
    debugPaths: [], compilerHints: [], sections: [], dynamicLibraries: [],
    importedSymbols: [], exportedSymbols: [], symbolNames: [],
    hasStackCanary: false, fortifySymbols: false, signals: {},
    malformed: false, errors: [],
  };
}

/** §5: magic-byte identification. Extensions are NEVER consulted. */
export function detectBinaryFormat(bytes: Buffer): "ELF" | "PE" | "MACH_O" | "UNKNOWN" {
  if (bytes.length >= 4 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) return "ELF";
  if (bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a) return "PE"; // MZ
  if (bytes.length >= 4) {
    const le = bytes.readUInt32LE(0);
    const be = bytes.readUInt32BE(0);
    if (le === 0xfeedface || le === 0xfeedfacf || be === 0xfeedface || be === 0xfeedfacf) return "MACH_O";
    if (le === 0xcafebabe || be === 0xcafebabe) return "MACH_O"; // fat
  }
  return "UNKNOWN";
}

// ── ELF ─────────────────────────────────────────────────────────────

const ELF_MACHINES: Record<number, string> = {
  3: "x86", 8: "MIPS", 20: "PPC", 21: "PPC64", 40: "ARM", 42: "SPARC",
  50: "IA-64", 62: "x86-64", 75: "VAX", 88: "LoongArch", 164: "Qualcomm DSP6",
  183: "AArch64", 188: "TilePro", 243: "RISC-V",
};

function parseElf(bytes: Buffer): BinaryHeaderReport {
  const report = emptyReport("ELF");
  try {
    if (bytes.length < 64) { report.malformed = true; report.errors.push("ELF header truncated"); return report; }
    const cls = bytes[4]!;
    const data = bytes[5]!;
    const is64 = cls === 2;
    const le = data !== 2;
    report.bitness = is64 ? 64 : 32;
    report.endianness = le ? "LE" : "BE";
    report.platform = "Linux/ELF";
    const u16 = (o: number) => (le ? bytes.readUInt16LE(o) : bytes.readUInt16BE(o));
    const u32 = (o: number) => (le ? bytes.readUInt32LE(o) : bytes.readUInt32BE(o));
    const u64 = (o: number) => (le ? Number(bytes.readBigUInt64LE(o)) : Number(bytes.readBigUInt64BE(o)));
    if (bytes.length < (is64 ? 64 : 52)) { report.malformed = true; report.errors.push("ELF header truncated for its class"); return report; }
    const eType = u16(16);
    report.kind = eType === 1 ? "OBJECT" : eType === 2 ? "EXECUTABLE" : eType === 3 ? "SHARED_LIBRARY" : eType === 4 ? "CORE" : "UNKNOWN";
    // An ET_DYN with an interpreter is a PIE executable; without one
    // it is a shared library.
    report.architecture = ELF_MACHINES[u16(18)] ?? `machine-${u16(18)}`;
    report.entryPoint = hex(is64 ? u64(24) : u32(24));
    const phoff = is64 ? u64(32) : u32(32);
    const shoff = is64 ? u64(40) : u32(36);
    const phentsize = u16(is64 ? 54 : 42);
    const phnum = Math.min(u16(is64 ? 56 : 44), 256);
    const shentsize = u16(is64 ? 58 : 46);
    const shnum = Math.min(u16(is64 ? 60 : 48), 1024);
    const shstrndx = u16(is64 ? 62 : 50);

    // Program headers: interpreter, GNU_STACK (NX), GNU_RELRO.
    let hasInterp = false;
    const dynamicEntries: { type: number; value: number }[] = [];
    for (let i = 0; i < phnum; i++) {
      const off = phoff + i * phentsize;
      if (off + phentsize > bytes.length || phentsize < (is64 ? 56 : 32)) break;
      const pType = u32(off);
      const pFlags = is64 ? u32(off + 4) : u32(off + 24);
      if (pType === 3) hasInterp = true;
      if (pType === 0x6474e551) report.signals.gnuStack = (pFlags & 1) !== 0 ? "EXECUTABLE" : "NON_EXECUTABLE";
      if (pType === 0x6474e552) report.signals.gnuRelro = "PRESENT";
      if (pType === 2) {
        const pOff = is64 ? u64(off + 8) : u32(off + 4);
        const filesz = is64 ? u64(off + 32) : u32(off + 16);
        const count = Math.min(Math.floor(filesz / (is64 ? 16 : 8)), 4096);
        for (let d = 0; d < count; d++) {
          const doff = pOff + d * (is64 ? 16 : 8);
          if (doff + (is64 ? 16 : 8) > bytes.length) break;
          dynamicEntries.push({ type: is64 ? Number(bytes.readBigInt64LE(doff)) : bytes.readInt32LE(doff), value: is64 ? u64(doff + 8) : u32(doff + 4) });
        }
      }
    }
    if (report.kind === "SHARED_LIBRARY" && hasInterp) report.kind = "EXECUTABLE";
    report.signals.pieType = eType === 3 ? "DYN" : eType === 2 ? "EXEC" : "OTHER";
    if (dynamicEntries.some((d) => d.type === 24)) report.signals.bindNow = "PRESENT"; // DT_BIND_NOW

    // Section headers + names.
    interface Shdr { nameIdx: number; type: number; flags: number; addr: number; offset: number; size: number; link: number; entsize: number }
    const shdrs: Shdr[] = [];
    for (let i = 0; i < shnum; i++) {
      const off = shoff + i * shentsize;
      if (off + shentsize > bytes.length || shentsize < (is64 ? 64 : 40)) break;
      shdrs.push({
        nameIdx: u32(off), type: u32(off + 4),
        flags: is64 ? u64(off + 8) : u32(off + 8),
        addr: is64 ? u64(off + 16) : u32(off + 12),
        offset: is64 ? u64(off + 24) : u32(off + 16),
        size: is64 ? u64(off + 32) : u32(off + 20),
        link: u32(off + (is64 ? 40 : 24)),
        entsize: is64 ? u64(off + 56) : u32(off + 36),
      });
    }
    const strtabBytes = (sh: Shdr | undefined): Buffer | null => {
      if (!sh || sh.offset + sh.size > bytes.length || sh.size > 16 * 1024 * 1024) return null;
      return bytes.subarray(sh.offset, sh.offset + sh.size);
    };
    const readStr = (tab: Buffer | null, idx: number): string => {
      if (!tab || idx >= tab.length) return "";
      const end = tab.indexOf(0, idx);
      return tab.subarray(idx, end === -1 ? tab.length : end).toString("latin1");
    };
    const shstr = strtabBytes(shdrs[shstrndx]);
    const dynamicStrtab = strtabBytes(shdrs.find((s) => s.type === 3 && readStr(shstr, s.nameIdx) === ".dynstr") ?? shdrs[dynamicEntries.length ? 0 : -1]);
    // DT_STRTAB virtual address → file offset via PT_LOAD is overkill
    // for fixture-grade parsing; prefer the .dynstr section.
    for (const d of dynamicEntries) {
      if (d.type === 1 /* DT_NEEDED */ && dynamicStrtab) {
        const name = sanitizeMobileText(readStr(dynamicStrtab, d.value), 256);
        if (name) report.dynamicLibraries.push(name);
      }
    }
    const sectionNames: string[] = [];
    for (const sh of shdrs) {
      const name = sanitizeMobileText(readStr(shstr, sh.nameIdx), 128) || `section-${sectionNames.length}`;
      sectionNames.push(name);
      const perms = `${(sh.flags & 4) !== 0 || sh.type === 1 ? "R" : ""}${(sh.flags & 1) !== 0 ? "W" : ""}${(sh.flags & 2) !== 0 ? "X" : ""}` || "-";
      report.sections.push({
        name, type: `SHT-${sh.type}`, offset: sh.offset, size: sh.size,
        virtualAddress: hex(sh.addr), permissions: perms,
        ...(sh.size > 0 && sh.type !== 8 ? { entropy: sectionEntropy(bytes, sh.offset, sh.size) } : {}),
      });
      if (/^\.debug_|^\.zdebug_/.test(name)) report.hasDebugInfo = true;
      if (name === ".comment") {
        const raw = bytes.subarray(sh.offset, Math.min(bytes.length, sh.offset + Math.min(sh.size, 4096))).toString("latin1");
        for (const hint of raw.split("\0")) {
          const clean = sanitizeMobileText(hint, 200);
          if (clean) report.compilerHints.push(clean);
        }
      }
    }
    // Symbol tables: SYMTAB (stripped signal) + DYNSYM (imports/exports).
    let hasSymtab = false;
    for (let i = 0; i < shdrs.length; i++) {
      const sh = shdrs[i]!;
      if (sh.type !== 2 && sh.type !== 11) continue;
      if (sh.type === 2) hasSymtab = true;
      const strSh = shdrs[sh.link];
      const tab = strtabBytes(strSh);
      const entsize = sh.entsize || (is64 ? 24 : 16);
      const count = Math.min(Math.floor(sh.size / entsize), 100000);
      for (let sIdx = 1; sIdx < count; sIdx++) {
        const off = sh.offset + sIdx * entsize;
        if (off + entsize > bytes.length) break;
        const nameIdx = u32(off);
        const name = sanitizeMobileText(readStr(tab, nameIdx), 256);
        if (!name) continue;
        const shndx = u16(off + (is64 ? 6 : 14));
        if (sh.type === 2 && report.symbolNames.length < 100000) report.symbolNames.push(name);
        if (sh.type === 11) {
          if (shndx === 0) report.importedSymbols.push({ library: null, symbol: name });
          else if (report.exportedSymbols.length < 100000) report.exportedSymbols.push(name);
        }
        if (name === "__stack_chk_fail" || name === "__stack_chk_guard") report.hasStackCanary = true;
        if (/_chk(@|$)/.test(name)) report.fortifySymbols = true;
      }
    }
    report.stripped = hasSymtab ? "NOT_STRIPPED" : "STRIPPED";
    if (report.signals.gnuStack === undefined) report.signals.gnuStack = "ABSENT";
    if (report.signals.gnuRelro === undefined) report.signals.gnuRelro = "ABSENT";
  } catch {
    report.malformed = true;
    report.errors.push("ELF parser failed safely on malformed input");
  }
  return report;
}

// ── PE ──────────────────────────────────────────────────────────────

const PE_MACHINES: Record<number, string> = {
  0x14c: "x86", 0x8664: "x86-64", 0x1c0: "ARM", 0xaa64: "ARM64", 0x200: "IA-64",
};

function parsePe(bytes: Buffer): BinaryHeaderReport {
  const report = emptyReport("PE");
  report.platform = "Windows/PE";
  try {
    if (bytes.length < 64) { report.malformed = true; report.errors.push("PE DOS header truncated"); return report; }
    const peOff = bytes.readUInt32LE(0x3c);
    if (peOff + 24 > bytes.length || bytes.toString("latin1", peOff, peOff + 4) !== "PE\0\0") {
      report.malformed = true; report.errors.push("PE signature missing at e_lfanew"); return report;
    }
    const machine = bytes.readUInt16LE(peOff + 4);
    const numSections = Math.min(bytes.readUInt16LE(peOff + 6), 96);
    const optSize = bytes.readUInt16LE(peOff + 20);
    const characteristics = bytes.readUInt16LE(peOff + 22);
    report.kind = (characteristics & 0x2000) !== 0 ? "SHARED_LIBRARY" : "EXECUTABLE";
    report.architecture = PE_MACHINES[machine] ?? `machine-0x${machine.toString(16)}`;
    const optOff = peOff + 24;
    if (optOff + optSize > bytes.length || optSize < 96) { report.malformed = true; report.errors.push("PE optional header truncated"); return report; }
    const magic = bytes.readUInt16LE(optOff);
    const is64 = magic === 0x20b;
    report.bitness = is64 ? 64 : 32;
    report.endianness = "LE";
    report.entryPoint = hex(bytes.readUInt32LE(optOff + 16));
    const dllChars = bytes.readUInt16LE(optOff + 70);
    report.signals.aslr = (dllChars & 0x40) !== 0 ? "ENABLED" : "DISABLED"; // DYNAMIC_BASE
    report.signals.nx = (dllChars & 0x100) !== 0 ? "ENABLED" : "DISABLED"; // NX_COMPAT
    report.signals.cfg = (dllChars & 0x4000) !== 0 ? "ENABLED" : "DISABLED"; // GUARD_CF
    report.signals.safeSeh = (dllChars & 0x400) !== 0 ? "NOT_APPLICABLE" : "PRESENT_CHECK"; // NO_SEH flag
    report.signals.highEntropyVa = (dllChars & 0x20) !== 0 ? "ENABLED" : "DISABLED";
    const dirBase = optOff + (is64 ? 112 : 96);
    const dir = (idx: number): { rva: number; size: number } => {
      const o = dirBase + idx * 8;
      return o + 8 <= bytes.length ? { rva: bytes.readUInt32LE(o), size: bytes.readUInt32LE(o + 4) } : { rva: 0, size: 0 };
    };
    const security = dir(4);
    report.signals.codeSigning = security.size > 0 ? "PRESENT" : "ABSENT";
    if (dir(6).size > 0) report.hasDebugInfo = true;
    // Sections + RVA→offset map.
    const secOff = optOff + optSize;
    interface PSec { name: string; vsize: number; vaddr: number; rawSize: number; rawPtr: number; chars: number }
    const secs: PSec[] = [];
    for (let i = 0; i < numSections; i++) {
      const o = secOff + i * 40;
      if (o + 40 > bytes.length) break;
      const name = sanitizeMobileText(bytes.toString("latin1", o, o + 8).replace(/\0.*$/s, ""), 64) || `section-${i}`;
      const chars = bytes.readUInt32LE(o + 36);
      const perms = `${(chars & 0x40000000) !== 0 ? "R" : ""}${(chars & 0x80000000) !== 0 ? "W" : ""}${(chars & 0x20000000) !== 0 ? "X" : ""}` || "-";
      const psec = { name, vsize: bytes.readUInt32LE(o + 8), vaddr: bytes.readUInt32LE(o + 12), rawSize: bytes.readUInt32LE(o + 16), rawPtr: bytes.readUInt32LE(o + 20), chars };
      secs.push(psec);
      report.sections.push({
        name, type: "PE_SECTION", offset: psec.rawPtr, size: psec.rawSize,
        virtualAddress: hex(psec.vaddr), permissions: perms,
        ...(psec.rawSize > 0 ? { entropy: sectionEntropy(bytes, psec.rawPtr, psec.rawSize) } : {}),
      });
      if (name === ".debug") report.hasDebugInfo = true;
    }
    const rvaToOff = (rva: number): number => {
      for (const s of secs) {
        const span = Math.max(s.vsize, s.rawSize);
        if (rva >= s.vaddr && rva < s.vaddr + span) return s.rawPtr + (rva - s.vaddr);
      }
      return -1;
    };
    const cstr = (off: number, cap = 512): string => {
      if (off < 0 || off >= bytes.length) return "";
      const end = bytes.indexOf(0, off);
      return sanitizeMobileText(bytes.toString("latin1", off, Math.min(end === -1 ? off + cap : end, off + cap)), 256);
    };
    // Imports (bounded): directory of IMAGE_IMPORT_DESCRIPTOR (20 bytes).
    const imp = dir(1);
    if (imp.rva) {
      let off = rvaToOff(imp.rva);
      for (let d = 0; d < 512 && off >= 0 && off + 20 <= bytes.length; d++, off += 20) {
        const oft = bytes.readUInt32LE(off);
        const nameRva = bytes.readUInt32LE(off + 12);
        const ft = bytes.readUInt32LE(off + 16);
        if (oft === 0 && nameRva === 0 && ft === 0) break;
        const library = cstr(rvaToOff(nameRva)) || "unknown.dll";
        if (!report.dynamicLibraries.includes(library)) report.dynamicLibraries.push(library);
        let thunkOff = rvaToOff(oft !== 0 ? oft : ft);
        const step = is64 ? 8 : 4;
        for (let t = 0; t < 4096 && thunkOff >= 0 && thunkOff + step <= bytes.length; t++, thunkOff += step) {
          const val = is64 ? Number(bytes.readBigUInt64LE(thunkOff)) : bytes.readUInt32LE(thunkOff);
          if (val === 0) break;
          if ((is64 ? val >= 0x8000000000000000 : (val & 0x80000000) !== 0)) {
            report.importedSymbols.push({ library, symbol: `ordinal-${val & 0xffff}` });
          } else {
            const sym = cstr(rvaToOff(val) + 2);
            if (sym) report.importedSymbols.push({ library, symbol: sym });
          }
        }
      }
    }
    // Exports (bounded): names from the export directory.
    const exp = dir(0);
    if (exp.rva) {
      const off = rvaToOff(exp.rva);
      if (off >= 0 && off + 40 <= bytes.length) {
        const nNames = Math.min(bytes.readUInt32LE(off + 24), 100000);
        const namesRva = bytes.readUInt32LE(off + 32);
        const namesOff = rvaToOff(namesRva);
        for (let i = 0; i < nNames && namesOff >= 0 && namesOff + i * 4 + 4 <= bytes.length; i++) {
          const sym = cstr(rvaToOff(bytes.readUInt32LE(namesOff + i * 4)));
          if (sym) report.exportedSymbols.push(sym);
        }
      }
    }
    report.stripped = report.hasDebugInfo ? "NOT_STRIPPED" : "UNKNOWN";
  } catch {
    report.malformed = true;
    report.errors.push("PE parser failed safely on malformed input");
  }
  return report;
}

// ── Mach-O ──────────────────────────────────────────────────────────

const MACHO_CPUS: Record<number, string> = {
  7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000c: "ARM64", 18: "PPC", 0x01000012: "PPC64",
};

function parseMachOAt(bytes: Buffer, base: number, report: BinaryHeaderReport): void {
  const magic = bytes.readUInt32LE(base);
  const swapped = magic === 0xcefaedfe || magic === 0xcffaedfe;
  const is64 = magic === 0xfeedfacf || magic === 0xcffaedfe;
  const u32 = (o: number) => (swapped ? bytes.readUInt32BE(base + o) : bytes.readUInt32LE(base + o));
  report.bitness = is64 ? 64 : 32;
  report.endianness = swapped ? "BE" : "LE";
  report.platform = "macOS/Mach-O";
  report.architecture = MACHO_CPUS[u32(4)] ?? `cpu-${u32(4)}`;
  const filetype = u32(12);
  report.kind = filetype === 1 ? "OBJECT" : filetype === 6 ? "SHARED_LIBRARY" : filetype === 2 ? "EXECUTABLE" : "UNKNOWN";
  const ncmds = Math.min(u32(16), 512);
  const flags = u32(24);
  report.signals.pie = (flags & 0x200000) !== 0 ? "ENABLED" : "DISABLED"; // MH_PIE
  let off = base + (is64 ? 32 : 28);
  let hasSymtab = false;
  for (let c = 0; c < ncmds; c++) {
    if (off + 8 > bytes.length) { report.malformed = true; report.errors.push("Mach-O load command truncated"); return; }
    const cmd = swapped ? bytes.readUInt32BE(off) : bytes.readUInt32LE(off);
    const cmdsize = swapped ? bytes.readUInt32BE(off + 4) : bytes.readUInt32LE(off + 4);
    if (cmdsize < 8 || off + cmdsize > bytes.length) { report.malformed = true; report.errors.push("Mach-O load command size invalid"); return; }
    const ru32 = (o: number) => (swapped ? bytes.readUInt32BE(off + o) : bytes.readUInt32LE(off + o));
    if (cmd === 0x19 || cmd === 0x1) { // LC_SEGMENT_64 / LC_SEGMENT
      const segname = sanitizeMobileText(bytes.toString("latin1", off + 8, off + 24).replace(/\0.*$/s, ""), 32);
      const nsects = Math.min(ru32(is64 ? 64 : 56), 512);
      report.signals.stackExec = (ru32(is64 ? 56 : 48) & 0x1) !== 0 ? "EXECUTABLE" : "NON_EXECUTABLE"; // initprot VM_PROT_EXECUTE bit approximation
      for (let s = 0; s < nsects; s++) {
        const so = off + (is64 ? 72 : 56) + s * (is64 ? 80 : 68);
        if (so + (is64 ? 80 : 68) > bytes.length) break;
        const sect = sanitizeMobileText(bytes.toString("latin1", so, so + 16).replace(/\0.*$/s, ""), 32);
        const size = is64 ? Number(bytes.readBigUInt64LE(so + 40)) : bytes.readUInt32LE(so + 36);
        const offsetS = bytes.readUInt32LE(so + (is64 ? 48 : 40));
        report.sections.push({
          name: `${segname}.${sect}`, type: "MACHO_SECTION", offset: offsetS, size,
          virtualAddress: hex(is64 ? Number(bytes.readBigUInt64LE(so + 32)) : bytes.readUInt32LE(so + 32)),
          permissions: "R",
          ...(size > 0 ? { entropy: sectionEntropy(bytes, base + offsetS, size) } : {}),
        });
      }
    } else if (cmd === 0x2) { // LC_SYMTAB
      const nsyms = ru32(12);
      if (nsyms > 0) hasSymtab = true;
    } else if (cmd === 0xc || cmd === 0x8000001c || cmd === 0x1f) { // LC_LOAD_DYLIB / REEXPORT / WEAK
      const nameOff = ru32(8);
      const name = sanitizeMobileText(bytes.toString("latin1", off + nameOff, Math.min(off + cmdsize, off + nameOff + 256)).replace(/\0.*$/s, ""), 256);
      if (name) report.dynamicLibraries.push(name);
    } else if (cmd === 0x21) { // LC_ENCRYPTION_INFO(_64): encrypted = FairPlay, not a vuln
      report.signals.encryptionInfo = "PRESENT";
    }
    off += cmdsize;
  }
  report.stripped = hasSymtab ? "NOT_STRIPPED" : "STRIPPED";
  report.hasDebugInfo = report.sections.some((s) => s.name.includes("__debug"));
}

function parseMachO(bytes: Buffer): BinaryHeaderReport {
  const report = emptyReport("MACH_O");
  try {
    if (bytes.length < 4) { report.malformed = true; report.errors.push("Mach-O header truncated"); return report; }
    const magicBE = bytes.readUInt32BE(0);
    if (magicBE === 0xcafebabe && bytes.length >= 8) {
      // Fat binary: parse the first architecture slice.
      const nfat = bytes.readUInt32BE(4);
      if (nfat < 1 || bytes.length < 8 + 20) { report.malformed = true; report.errors.push("Mach-O fat header truncated"); return report; }
      const sliceOff = bytes.readUInt32BE(8 + 8);
      if (sliceOff + 4 > bytes.length) { report.malformed = true; report.errors.push("Mach-O fat slice out of range"); return report; }
      report.signals.fatBinary = `${nfat} architectures`;
      const slice = bytes.subarray(sliceOff);
      const inner = emptyReport("MACH_O");
      parseMachOAt(slice, 0, inner);
      Object.assign(report, inner, { format: "MACH_O" as const, signals: { ...inner.signals, fatBinary: `${nfat} architectures` } });
      return report;
    }
    parseMachOAt(bytes, 0, report);
  } catch {
    report.malformed = true;
    report.errors.push("Mach-O parser failed safely on malformed input");
  }
  return report;
}

/** §12: full header parse by content. UNKNOWN never guesses (§5). */
export function parseBinaryHeaders(bytes: Buffer): BinaryHeaderReport {
  const format = detectBinaryFormat(bytes);
  switch (format) {
    case "ELF": return parseElf(bytes);
    case "PE": return parsePe(bytes);
    case "MACH_O": return parseMachO(bytes);
    default: {
      const r = emptyReport("UNKNOWN");
      r.errors.push("No recognized magic bytes — format UNKNOWN, never guessed (§5)");
      return r;
    }
  }
}

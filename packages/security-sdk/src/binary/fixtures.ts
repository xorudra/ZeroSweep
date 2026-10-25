/**
 * Prompt 18 — synthetic binary fixtures (§97–§104).
 *
 * Every fixture is SYNTHETIC and SAFE: hand-assembled header bytes,
 * no real malware, no real firmware, no real credentials. The ELF
 * fixture embeds a shell-snippet STRING as inert rodata (the §100
 * no-execution proof): if anything ever executed the artifact, a
 * marker would be created — the pipeline never executes artifacts,
 * and the tests assert the marker does not exist and only analyzer
 * tools were invoked.
 */
import { sha1Of, sha256Of } from "./intake";

/** Synthetic FAKE credential (matches the AWS key-id shape so the
 *  P12 detectors fire): exists ONLY to prove fingerprint-only
 *  persistence — it must appear in NO persisted record. */
export const FAKE_BINARY_TOKEN = "AKIAFAKEBINARYFIXTUR";
export const EXECUTION_MARKER_PATH = "/tmp/ZEROSWEEP_BINARY_EXECUTED_MARKER";
export const FIXTURE_EMBEDDED_URL = "https://example.invalid/api";

// ── ELF builder ─────────────────────────────────────────────────────

interface ElfOpts {
  hardened: boolean;
  withSymtab?: boolean;
}

function buildElf(opts: ElfOpts): Buffer {
  const hardened = opts.hardened;
  const parts: Buffer[] = [];
  const dynstr = Buffer.from("\0libc.so.6\0libssl.so.3\0libz.so.1.2.11\0__stack_chk_fail\0__memcpy_chk\0MD5_Init\0gets\0strcpy\0main\0", "latin1");
  const strtab = Buffer.from("\0fixture_main\0helper_check\0process_request\0", "latin1");
  const interp = Buffer.from("/lib64/ld-linux-x86-64.so.2\0", "latin1");
  const rodata = Buffer.from(
    `fixture-binary\0${FAKE_BINARY_TOKEN}\0${FIXTURE_EMBEDDED_URL}\0/var/lib/fixture/config.db\0Error: failed to open fixture\0#!/bin/sh\ntouch ${EXECUTION_MARKER_PATH}\n\0`,
    "latin1",
  );
  const text = Buffer.alloc(64, 0x90);
  text.writeUInt8(0xc3, 0); // ret — inert fixture bytes
  const comment = Buffer.from("GCC: (Fixture) 13.2.0\0clang version 17.0.0 (fixture)\0", "latin1");

  // .dynamic entries (16 bytes each): NEEDED x3 (strtab offsets 1, 11, 22), BIND_NOW (hardened), NULL.
  const dynEntries: [number, number][] = [[1, 1], [1, 11], [1, 23]];
  if (hardened) dynEntries.push([24, 0]);
  dynEntries.push([0, 0]);
  const dynamic = Buffer.alloc(dynEntries.length * 16);
  dynEntries.forEach(([tag, val], i) => {
    dynamic.writeBigInt64LE(BigInt(tag), i * 16);
    dynamic.writeBigUInt64LE(BigInt(val), i * 16 + 8);
  });

  // .dynsym entries (24 bytes): null, canary?, fortify?, MD5_Init, gets, strcpy, main (defined, shndx=1).
  const dynsymNames = ["", ...(hardened ? ["__stack_chk_fail", "__memcpy_chk"] : []), "MD5_Init", "gets", "strcpy", "main"];
  const nameOff = (name: string) => dynstr.indexOf(`\0${name}\0`) + 1;
  const dynsym = Buffer.alloc(dynsymNames.length * 24);
  dynsymNames.forEach((name, i) => {
    if (i === 0) return;
    dynsym.writeUInt32LE(nameOff(name), i * 24);
    dynsym.writeUInt8(0x12, i * 24 + 4); // GLOBAL FUNC
    dynsym.writeUInt16LE(name === "main" ? 1 : 0, i * 24 + 6); // undefined = import
  });

  // .symtab entries (24 bytes): null + 3 defined functions.
  const symNames = ["", "fixture_main", "helper_check", "process_request"];
  const symNameOff = (name: string) => strtab.indexOf(`\0${name}\0`) + 1;
  const symtab = Buffer.alloc(symNames.length * 24);
  symNames.forEach((name, i) => {
    if (i === 0) return;
    symtab.writeUInt32LE(symNameOff(name), i * 24);
    symtab.writeUInt8(0x12, i * 24 + 4);
    symtab.writeUInt16LE(1, i * 24 + 6);
  });

  const sectionContents: { name: string; type: number; flags: number; content: Buffer; link?: number; entsize?: number }[] = [
    { name: "", type: 0, flags: 0, content: Buffer.alloc(0) },
    ...(hardened ? [{ name: ".interp", type: 1, flags: 4, content: interp }] : []),
    { name: ".text", type: 1, flags: hardened ? 6 : 7, content: text }, // AX hardened; AWX unhardened
    { name: ".rodata", type: 1, flags: 2, content: rodata },
    { name: ".dynamic", type: 6, flags: 3, content: dynamic, link: 0, entsize: 16 },
    { name: ".dynstr", type: 3, flags: 2, content: dynstr },
    { name: ".dynsym", type: 11, flags: 2, content: dynsym, link: 0, entsize: 24 },
    ...(opts.withSymtab !== false ? [{ name: ".symtab", type: 2, flags: 0, content: symtab, link: 0, entsize: 24 }, { name: ".strtab", type: 3, flags: 0, content: strtab }] : []),
    ...(hardened ? [{ name: ".debug_info", type: 1, flags: 0, content: Buffer.from("fixture-debug\0", "latin1") }] : []),
    { name: ".comment", type: 1, flags: 0x30, content: comment },
  ];
  // Wire section links: .dynamic→.dynstr idx, .dynsym→.dynstr idx, .symtab→.strtab idx.
  const idxOf = (n: string) => sectionContents.findIndex((s) => s.name === n);
  for (const s of sectionContents) {
    if (s.name === ".dynamic" || s.name === ".dynsym") s.link = idxOf(".dynstr");
    if (s.name === ".symtab") s.link = idxOf(".strtab");
  }
  const shstrtab = Buffer.from("\0" + sectionContents.map((s) => s.name).filter(Boolean).join("\0") + "\0.shstrtab\0", "latin1");
  sectionContents.push({ name: ".shstrtab", type: 3, flags: 0, content: shstrtab });
  const shstrOff = (name: string) => shstrtab.indexOf(`\0${name}\0`) + 1;

  // Program headers.
  const phdrs: { type: number; flags: number; offset: number; filesz?: number }[] = [
    { type: 1, flags: 5, offset: 0 }, // PT_LOAD R+X
    ...(hardened ? [{ type: 3, flags: 4, offset: 0 }] : []), // PT_INTERP
    { type: 2, flags: 6, offset: 0 }, // PT_DYNAMIC (offset patched below)
    { type: 0x6474e551, flags: hardened ? 6 : 7, offset: 0 }, // GNU_STACK RW / RWX
    ...(hardened ? [{ type: 0x6474e552, flags: 4, offset: 0 }] : []), // GNU_RELRO
  ];

  const ehsize = 64, phentsize = 56, shentsize = 64;
  const phoff = ehsize;
  let cursor = phoff + phdrs.length * phentsize;
  const sectionOffsets: number[] = [];
  for (const s of sectionContents) {
    if (s.content.length === 0) { sectionOffsets.push(0); continue; }
    if (cursor % 8 !== 0) cursor += 8 - (cursor % 8);
    sectionOffsets.push(cursor);
    cursor += s.content.length;
  }
  const shoff = cursor;
  const total = shoff + sectionContents.length * shentsize;
  const buf = Buffer.alloc(total);
  // ELF header.
  buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  buf.writeUInt16LE(hardened ? 3 : 2, 16); // ET_DYN (PIE) / ET_EXEC
  buf.writeUInt16LE(62, 18); // x86-64
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(0x1040n, 24);
  buf.writeBigUInt64LE(BigInt(phoff), 32);
  buf.writeBigUInt64LE(BigInt(shoff), 40);
  buf.writeUInt16LE(ehsize, 52);
  buf.writeUInt16LE(phentsize, 54);
  buf.writeUInt16LE(phdrs.length, 56);
  buf.writeUInt16LE(shentsize, 58);
  buf.writeUInt16LE(sectionContents.length, 60);
  buf.writeUInt16LE(sectionContents.length - 1, 62); // shstrndx
  // Program headers.
  phdrs.forEach((ph, i) => {
    const o = phoff + i * phentsize;
    const dynIdx = sectionContents.findIndex((s) => s.name === ".dynamic");
    const offset = ph.type === 2 ? sectionOffsets[dynIdx]! : ph.offset;
    const filesz = ph.type === 2 ? sectionContents[dynIdx]!.content.length : ph.type === 1 ? total : 0;
    buf.writeUInt32LE(ph.type, o);
    buf.writeUInt32LE(ph.flags, o + 4);
    buf.writeBigUInt64LE(BigInt(offset), o + 8);
    buf.writeBigUInt64LE(BigInt(ph.type === 1 ? 0 : offset), o + 16);
    buf.writeBigUInt64LE(BigInt(filesz), o + 32);
    buf.writeBigUInt64LE(BigInt(filesz), o + 40);
  });
  // Sections content + headers.
  sectionContents.forEach((s, i) => {
    if (s.content.length > 0) buf.set(s.content, sectionOffsets[i]!);
    const o = shoff + i * shentsize;
    buf.writeUInt32LE(s.name ? shstrOff(s.name) : 0, o);
    buf.writeUInt32LE(s.type, o + 4);
    buf.writeBigUInt64LE(BigInt(s.flags), o + 8);
    buf.writeBigUInt64LE(BigInt(sectionOffsets[i]!), o + 16);
    buf.writeBigUInt64LE(BigInt(sectionOffsets[i]!), o + 24);
    buf.writeBigUInt64LE(BigInt(s.content.length), o + 32);
    buf.writeUInt32LE(s.link ?? 0, o + 40);
    buf.writeBigUInt64LE(BigInt(s.entsize ?? 0), o + 56);
  });
  void parts;
  return buf;
}

export const FIXTURE_ELF_HARDENED = buildElf({ hardened: true });
export const FIXTURE_ELF_UNHARDENED = buildElf({ hardened: false });
export const FIXTURE_ELF_STRIPPED = buildElf({ hardened: true, withSymtab: false });
export const FIXTURE_ELF_TRUNCATED = FIXTURE_ELF_HARDENED.subarray(0, 16);
export const FIXTURE_ELF_SHA256 = sha256Of(FIXTURE_ELF_HARDENED);
export const FIXTURE_ELF_UNHARDENED_SHA256 = sha256Of(FIXTURE_ELF_UNHARDENED);
export const FIXTURE_ELF_SHA1 = sha1Of(FIXTURE_ELF_HARDENED);

// ── PE builder (PE32+, x86-64) ─────────────────────────────────────

function buildPe(hardened: boolean): Buffer {
  const total = 0x600;
  const buf = Buffer.alloc(total);
  buf.write("MZ", 0, "latin1");
  buf.writeUInt32LE(64, 0x3c);
  buf.write("PE\0\0", 64, "latin1");
  buf.writeUInt16LE(0x8664, 68); // machine
  buf.writeUInt16LE(2, 70); // sections
  buf.writeUInt16LE(240, 84); // opt size
  buf.writeUInt16LE(0x0022, 86); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
  const opt = 88;
  buf.writeUInt16LE(0x20b, opt); // PE32+
  buf.writeUInt32LE(0x1000, opt + 16); // entry RVA
  buf.writeUInt16LE(hardened ? 0x4160 : 0x0000, opt + 70); // HIGH_ENTROPY|DYNAMIC_BASE|NX|GUARD_CF
  const dirs = opt + 112;
  // import dir (idx 1) → RVA 0x2000 size 40; debug (6) + security (4) hardened.
  buf.writeUInt32LE(0x2000, dirs + 8); buf.writeUInt32LE(40, dirs + 12);
  if (hardened) {
    buf.writeUInt32LE(0x3000, dirs + 4 * 8); buf.writeUInt32LE(0x1a0, dirs + 4 * 8 + 4); // security
    buf.writeUInt32LE(0x2100, dirs + 6 * 8); buf.writeUInt32LE(28, dirs + 6 * 8 + 4); // debug
  }
  const sec = opt + 240;
  const writeSec = (i: number, name: string, vsize: number, vaddr: number, rawSize: number, rawPtr: number, chars: number) => {
    const o = sec + i * 40;
    buf.write(name, o, "latin1");
    buf.writeUInt32LE(vsize, o + 8); buf.writeUInt32LE(vaddr, o + 12);
    buf.writeUInt32LE(rawSize, o + 16); buf.writeUInt32LE(rawPtr, o + 20);
    buf.writeUInt32LE(chars, o + 36);
  };
  writeSec(0, ".text", 0x200, 0x1000, 0x200, 0x200, hardened ? 0x60000020 : 0xe0000020); // RX / RWX
  writeSec(1, ".rdata", 0x200, 0x2000, 0x200, 0x400, 0x40000040);
  // Import descriptors at file offset 0x400 (RVA 0x2000).
  const imp = 0x400;
  buf.writeUInt32LE(0x2040, imp); // OFT RVA → file 0x440
  buf.writeUInt32LE(0x2060, imp + 12); // Name RVA → file 0x460 "KERNEL32.dll"
  buf.writeUInt32LE(0x2040, imp + 16); // FT
  buf.write("KERNEL32.dll\0", imp + 0x60, "latin1");
  // Thunks (8 bytes): thunk0 → hint/name RVA 0x2080 → file 0x480
  buf.writeBigUInt64LE(0x2080n, imp + 0x40);
  buf.writeUInt16LE(0, imp + 0x80);
  buf.write("CreateFileW\0", imp + 0x82, "latin1");
  buf.write("FixturePE\0", 0x200, "latin1");
  buf.write(FAKE_BINARY_TOKEN + "\0", 0x220, "latin1");
  return buf;
}

export const FIXTURE_PE_HARDENED = buildPe(true);
export const FIXTURE_PE_UNHARDENED = buildPe(false);
export const FIXTURE_PE_SHA256 = sha256Of(FIXTURE_PE_HARDENED);

// ── Mach-O builder (64-bit, ARM64) ─────────────────────────────────

function buildMachO(hardened: boolean): Buffer {
  const segCmdSize = 72 + 80;
  const symtabSize = 24;
  const dylibName = Buffer.from("/usr/lib/libSystem.B.dylib\0", "latin1");
  const dylibCmdSize = 24 + Math.ceil(dylibName.length / 8) * 8;
  const sizeofcmds = segCmdSize + symtabSize + dylibCmdSize;
  const textOff = 32 + sizeofcmds;
  const buf = Buffer.alloc(textOff + 32);
  buf.set([0xcf, 0xfa, 0xed, 0xfe], 0); // MH_MAGIC_64 LE
  buf.writeUInt32LE(0x0100000c, 4); // ARM64
  buf.writeUInt32LE(3, 8); // cpusubtype
  buf.writeUInt32LE(2, 12); // MH_EXECUTE
  buf.writeUInt32LE(3, 16); // ncmds
  buf.writeUInt32LE(sizeofcmds, 20);
  buf.writeUInt32LE(hardened ? 0x200000 : 0, 24); // MH_PIE
  let o = 32;
  buf.writeUInt32LE(0x19, o); buf.writeUInt32LE(segCmdSize, o + 4); // LC_SEGMENT_64
  buf.write("__TEXT", o + 8, "latin1");
  buf.writeBigUInt64LE(0x100000000n, o + 24);
  buf.writeBigUInt64LE(0x4000n, o + 32);
  buf.writeBigUInt64LE(0n, o + 40);
  buf.writeBigUInt64LE(BigInt(textOff + 32), o + 48);
  buf.writeUInt32LE(7, o + 56); buf.writeUInt32LE(5, o + 60); // maxprot RWX? initprot RX
  buf.writeUInt32LE(1, o + 64); // nsects
  const so = o + 72;
  buf.write("__text", so, "latin1");
  buf.write("__TEXT", so + 16, "latin1");
  buf.writeBigUInt64LE(0x100003f50n, so + 32);
  buf.writeBigUInt64LE(32n, so + 40);
  buf.writeUInt32LE(textOff, so + 48);
  o += segCmdSize;
  buf.writeUInt32LE(0x2, o); buf.writeUInt32LE(symtabSize, o + 4); // LC_SYMTAB
  buf.writeUInt32LE(0, o + 8); buf.writeUInt32LE(3, o + 12); // nsyms 3
  o += symtabSize;
  buf.writeUInt32LE(0xc, o); buf.writeUInt32LE(dylibCmdSize, o + 4); // LC_LOAD_DYLIB
  buf.writeUInt32LE(24, o + 8); // name offset
  buf.set(dylibName, o + 24);
  buf.write("fixture-macho\0", textOff, "latin1");
  return buf;
}

export const FIXTURE_MACHO_HARDENED = buildMachO(true);
export const FIXTURE_MACHO_UNHARDENED = buildMachO(false);
export const FIXTURE_MACHO_SHA256 = sha256Of(FIXTURE_MACHO_HARDENED);

/** §103: malformed fixtures — bad PE offset, lying Mach-O cmdsize. */
export const FIXTURE_PE_MALFORMED = (() => { const b = Buffer.from(FIXTURE_PE_HARDENED); b.writeUInt32LE(0x7fff0000, 0x3c); return b; })();
export const FIXTURE_MACHO_MALFORMED = (() => { const b = Buffer.from(FIXTURE_MACHO_HARDENED); b.writeUInt32LE(0xfffffff0, 36); return b; })();

/** §102: an ELF named report.pdf — identity is content, not name. */
export const FIXTURE_SPOOFED_NAME = "report.pdf";

// ── Recorded tool outputs ───────────────────────────────────────────

export const CHECKSEC_HARDENED_JSON = JSON.stringify({
  "/fixture/app-hardened": {
    relro: "Full RELRO", canary: "Canary found", nx: "NX enabled", pie: "PIE enabled",
    rpath: "No RUNPATH", runpath: "No RUNPATH", symbols: "Symbols", fortify_source: "Yes",
    fortified: "3", "fortify-able": "4",
  },
});

export const CHECKSEC_UNHARDENED_JSON = JSON.stringify({
  "/fixture/app-unhardened": {
    relro: "No RELRO", canary: "No canary found", nx: "NX disabled", pie: "No PIE",
    rpath: "No RUNPATH", runpath: "No RUNPATH", symbols: "Symbols", fortify_source: "No",
    fortified: "0", "fortify-able": "4",
  },
});

export const GHIDRA_BINARY_REPORT_JSON = JSON.stringify({
  program: { name: "app-hardened", format: "ELF", architecture: "x86-64", entryPoint: "0x1040" },
  sections: [{ name: ".text", type: "SHT-1", offset: 4096, size: 512, virtualAddress: "0x1000", permissions: "RX", entropy: 6.1 }],
  functions: [
    { name: "main", address: "0x1040", size: 48, callingConvention: "__stdcall", confidence: 0.95, fingerprint: "fn:main:9f2c" },
    { name: "process_request", address: "0x1150", size: 120, confidence: 0.9, fingerprint: "fn:process_request:77ab", referencesRiskyApi: ["strcpy"] },
    { name: "helper_check", address: "0x1200", size: 32, confidence: 0.85, fingerprint: "fn:helper_check:10cd" },
  ],
  imports: [
    { library: "libc.so.6", symbol: "strcpy", address: "0x4010" },
    { library: "libcrypto.so.3", symbol: "MD5_Init", address: "0x4020" },
    { library: "libc.so.6", symbol: "__stack_chk_fail", address: "0x4030" },
  ],
  exports: [{ symbol: "main", address: "0x1040", type: "FUNCTION" }],
  symbols: [{ name: "main", type: "FUNCTION", binding: "GLOBAL", address: "0x1040" }],
  libraries: [{ name: "zlib", version: "1.2.11" }, { name: "libssl.so.3" }],
  hardening: { NX: "ENABLED", PIE: "ENABLED", RELRO: "ENABLED" },
});

export const RADARE2_REPORT_JSON = JSON.stringify([
  { op: "METADATA", data: { format: "ELF", arch: "x86", bits: 64, stripped: false, canary: true, nx: true, pie: true, relro: "full" } },
  { op: "SECTIONS", data: [{ name: ".text", p_offset: 4096, vsize: 512, vaddr: 4096, perm: "r-x" }] },
  { op: "IMPORTS", data: [{ name: "strcpy", libname: "libc.so.6", plt: 16400 }, { name: "MD5_Init", libname: "libcrypto.so.3", plt: 16416 }] },
  { op: "EXPORTS", data: [{ name: "main", vaddr: 4160 }] },
  { op: "FUNCTIONS", data: [{ name: "main", offset: 4160, size: 48 }, { name: "process_request", offset: 4432, size: 120 }] },
  { op: "SYMBOLS", data: [{ name: "main", type: "FUNC", bind: "GLOBAL" }] },
]);

/** A second-build Ghidra report for diff fixtures: PIE lost, helper
 *  removed, new function added. */
export const GHIDRA_BINARY_REPORT_V2_JSON = JSON.stringify({
  program: { name: "app-hardened", format: "ELF", architecture: "x86-64", entryPoint: "0x1040" },
  sections: [{ name: ".text", type: "SHT-1", offset: 4096, size: 640, virtualAddress: "0x1000", permissions: "RX", entropy: 6.4 }],
  functions: [
    { name: "main", address: "0x1040", size: 48, callingConvention: "__stdcall", confidence: 0.95, fingerprint: "fn:main:9f2c" },
    { name: "process_request", address: "0x1150", size: 132, confidence: 0.9, fingerprint: "fn:process_request:99ff", referencesRiskyApi: ["strcpy"] },
    { name: "new_feature", address: "0x1300", size: 64, confidence: 0.8, fingerprint: "fn:new_feature:aa01" },
  ],
  imports: [{ library: "libc.so.6", symbol: "strcpy", address: "0x4010" }],
  exports: [{ symbol: "main", address: "0x1040", type: "FUNCTION" }],
  symbols: [{ name: "main", type: "FUNCTION", binding: "GLOBAL", address: "0x1040" }],
  libraries: [{ name: "zlib", version: "1.2.11" }, { name: "libssl.so.3" }, { name: "libcurl", version: "7.68.0" }],
  hardening: { NX: "ENABLED", PIE: "DISABLED", RELRO: "PARTIAL" },
});

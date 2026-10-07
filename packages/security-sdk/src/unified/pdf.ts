/**
 * Minimal deterministic PDF 1.4 writer (Prompt 20 §60).
 *
 * The platform generates its own PDFs in-repo — no external rendering
 * service, no headless browser. Core-font (Helvetica) text layout with
 * a cover-friendly first page, page numbers and the report watermark
 * on every page. Output is byte-deterministic for a given input (no
 * timestamps are embedded beyond the caller-provided document ones),
 * which keeps snapshot checksums meaningful.
 */

export interface PdfDocumentInput {
  title: string;
  creator: string;
  lines: string[];
  footer: string;
}

const PAGE_WIDTH = 595; // A4 pt
const PAGE_HEIGHT = 842;
const MARGIN = 54;
const FONT_SIZE = 10.5;
const LEADING = 15;
const LINES_PER_PAGE = Math.floor((PAGE_HEIGHT - MARGIN * 2 - 20) / LEADING);
const MAX_CHARS = 92; // ~ fits A4 at 10.5pt Helvetica within margins

function pdfEscape(text: string): string {
  return text
    // PDF literal strings are byte-oriented: fold non-ASCII to '?' so
    // offsets stay exact. (HTML/JSON exports carry full Unicode.)
    .replace(/[^\x20-\x7E]/g, "?")
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}

export function wrapLine(line: string): string[] {
  if (line.length <= MAX_CHARS) return [line];
  const out: string[] = [];
  let rest = line;
  while (rest.length > MAX_CHARS) {
    let cut = rest.lastIndexOf(" ", MAX_CHARS);
    if (cut < 20) cut = MAX_CHARS;
    out.push(rest.slice(0, cut));
    rest = "  " + rest.slice(cut).trimStart();
  }
  if (rest) out.push(rest);
  return out;
}

export function renderPdf(input: PdfDocumentInput): Buffer {
  const wrapped = input.lines.flatMap(wrapLine);
  const pages: string[][] = [];
  for (let i = 0; i < wrapped.length; i += LINES_PER_PAGE) pages.push(wrapped.slice(i, i + LINES_PER_PAGE));
  if (pages.length === 0) pages.push(["(empty report)"]);

  const objects: string[] = [];
  const fontObj = 3;
  objects[1] = `<< /Type /Catalog /Pages 2 0 R >>`;
  const pageObjIds = pages.map((_, i) => 4 + i * 2);
  objects[2] = `<< /Type /Pages /Kids [${pageObjIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${pages.length} >>`;
  objects[fontObj] = `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>`;

  pages.forEach((pageLines, i) => {
    const pageId = pageObjIds[i]!;
    const contentId = pageId + 1;
    const content: string[] = ["BT", `/F1 ${FONT_SIZE} Tf`, `${LEADING} TL`, `${MARGIN} ${PAGE_HEIGHT - MARGIN} Td`];
    for (const line of pageLines) {
      content.push(`(${pdfEscape(line)}) Tj`, "T*");
    }
    content.push("ET");
    // footer: watermark + page number
    content.push("BT", `/F1 8 Tf`, `12 TL`, `${MARGIN} 30 Td`, `(${pdfEscape(`${input.footer} · Page ${i + 1} of ${pages.length}`)}) Tj`, "ET");
    const stream = content.join("\n");
    objects[pageId] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] /Resources << /Font << /F1 ${fontObj} 0 R >> >> /Contents ${contentId} 0 R >>`;
    objects[contentId] = `<< /Length ${Buffer.byteLength(stream, "utf8")} >>\nstream\n${stream}\nendstream`;
  });

  const infoId = 4 + pages.length * 2;
  objects[infoId] = `<< /Title (${pdfEscape(input.title)}) /Creator (${pdfEscape(input.creator)}) /Producer (DSRclone ReportingEngine) >>`;

  let pdf = "%PDF-1.4\n";
  const offsets: number[] = [0];
  const maxId = infoId;
  for (let id = 1; id <= maxId; id++) {
    offsets[id] = Buffer.byteLength(pdf, "utf8");
    pdf += `${id} 0 obj\n${objects[id] ?? ""}\nendobj\n`;
  }
  const xrefPos = Buffer.byteLength(pdf, "utf8");
  pdf += `xref\n0 ${maxId + 1}\n0000000000 65535 f \n`;
  for (let id = 1; id <= maxId; id++) {
    pdf += `${String(offsets[id]).padStart(10, "0")} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${maxId + 1} /Root 1 0 R /Info ${infoId} 0 R >>\nstartxref\n${xrefPos}\n%%EOF\n`;
  void PAGE_WIDTH;
  return Buffer.from(pdf, "utf8");
}

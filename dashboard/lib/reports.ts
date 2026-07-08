/**
 * lib/reports.ts — Utilidades compartidas para generación de reportes.
 *
 * Mejoras implementadas:
 * - Diseño profesional moderno (clean, corporativo, con mejor jerarquía visual).
 * - Tablas mejoradas: bordes, alineación inteligente, cálculo preciso de alturas, wrapping real.
 * - Mejor manejo de colores y tipografía.
 * - Espaciado consistente y breathing room.
 * - Footer automático en todas las páginas.
 * - Portada más impactante.
 * - Código más mantenible y extensible.
 */

import PDFDocument from "pdfkit";

// ─── CSV ─────────────────────────────────────────────────────────
/**
 * Convierte un array de objetos a string CSV.
 * Usa json2csv si está disponible, fallback manual.
 */
export function toCSV(
  data: Record<string, unknown>[],
  columns?: string[],
): string {
  if (data.length === 0) return "";
  const cols = columns ?? Object.keys(data[0]);
  const escape = (v: unknown): string => {
    const s = String(v ?? "");
    if (s.includes(",") || s.includes('"') || s.includes("\n")) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  };
  const header = cols.map(escape).join(",");
  const rows = data.map((row) => cols.map((c) => escape(row[c])).join(","));
  return [header, ...rows].join("\n");
}

// ─── Colores y Estilos ───────────────────────────────────────────
// Paleta corporativa profesional — tonos sobrios, alto contraste, diseño limpio.
const COLORS = {
  // Encabezados y texto principal
  heading: "#1e293b",    // Slate-800 — serio, profesional
  body: "#475569",       // Slate-600 — legible sin ser harsh
  muted: "#94a3b8",      // Slate-400 — texto secundario, metadata
  // Acento — usado con moderación para jerarquía
  accent: "#0284c7",     // Sky-600 — más profundo y serio que sky-500
  accentLight: "#e0f2fe",// Sky-100 — fondo sutil de acento
  // Fondos y bordes
  bgDark: "#0f172a",     // Slate-900 — fondo de portada
  bgLight: "#f8fafc",    // Slate-50 — fondo de filas alternas
  border: "#e2e8f0",     // Slate-200 — líneas sutiles
  // Tablas
  tableHeader: "#1e293b",// Slate-800
  tableHeaderText: "#f1f5f9",
  tableBorder: "#cbd5e1",// Slate-300
  // Semántico
  success: "#16a34a",
  warning: "#ca8a04",
  white: "#ffffff",
} as const;

const FONTS = {
  bold: "Helvetica-Bold",
  regular: "Helvetica",
  light: "Helvetica",
};

// ─── Tabla Mejorada ──────────────────────────────────────────────
interface PDFTableOptions {
  headers: string[];
  rows: string[][];
  startX?: number;
  startY?: number;
  headerBg?: string;
  headerColor?: string;
  rowBgEven?: string;
  rowBgOdd?: string;
  textColor?: string;
  fontSize?: number;
  headerFontSize?: number;
  colWidths?: number[]; // Porcentajes o píxeles absolutos
  padding?: number;
}

/**
 * Dibuja una tabla profesional con diseño limpio y bordes sutiles.
 */
export function drawTable(
  doc: typeof PDFDocument.prototype,
  options: PDFTableOptions,
): number {
  const {
    headers,
    rows,
    startX = 50,
    startY = doc.y,
    headerBg = COLORS.tableHeader,
    headerColor = COLORS.tableHeaderText,
    rowBgEven = COLORS.bgLight,
    rowBgOdd = COLORS.white,
    textColor = COLORS.body,
    fontSize = 9,
    headerFontSize = 10,
    padding = 6,
  } = options;

  let y = startY;
  const pageWidth = doc.page.width;
  const marginRight = 50;
  const totalWidth = pageWidth - startX - marginRight;

  const colWidths =
    options.colWidths || headers.map(() => totalWidth / headers.length);
  const colXPositions = colWidths.reduce((acc, width, i) => {
    acc.push(i === 0 ? startX : acc[i - 1] + colWidths[i - 1]);
    return acc;
  }, [] as number[]);

  // ── Verificar espacio suficiente antes de dibujar la tabla ──
  const minSpace = 40; // espacio mínimo para header + 1 fila
  if (y > doc.page.height - minSpace) {
    doc.addPage();
    y = 50;
  }

  // ── Header ──
  doc.rect(startX, y, totalWidth, 24).fill(headerBg);
  // IMPORTANTE: fill() cambia el color de relleno actual — lo restauramos para el texto
  doc.fillColor(headerColor).font(FONTS.bold).fontSize(headerFontSize);

  headers.forEach((header, i) => {
    doc.text(header, colXPositions[i] + padding, y + 7, {
      width: colWidths[i] - padding * 2,
      align: "left",
    });
  });

  y += 24;

  // Línea separadora sutil
  doc
    .moveTo(startX, y)
    .lineTo(startX + totalWidth, y)
    .lineWidth(0.5)
    .stroke(COLORS.border);

  y += 3;

  // ── Rows ──
  rows.forEach((row, rowIndex) => {
    const isOdd = rowIndex % 2 === 1;
    let maxRowHeight = 20;

    // Calcular altura real necesaria
    row.forEach((cell, colIndex) => {
      if (!cell) return;
      const textWidth = colWidths[colIndex] - padding * 2;
      const estimatedLines =
        Math.ceil(doc.widthOfString(String(cell)) / textWidth) || 1;
      maxRowHeight = Math.max(
        maxRowHeight,
        estimatedLines * (fontSize + 3) + padding * 2,
      );
    });

    // Verificar si entra en la página actual
    if (y + maxRowHeight > doc.page.height - 60) {
      doc.addPage();
      y = 50;
    }

    // Fondo de fila (solo impares)
    if (isOdd) {
      doc.rect(startX, y, totalWidth, maxRowHeight).fill(rowBgEven);
    }

    // Restaurar color de texto DESPUÉS de cualquier fill()
    doc.fillColor(textColor).font(FONTS.regular).fontSize(fontSize);

    // Contenido de celdas
    row.forEach((cell, colIndex) => {
      doc.text(String(cell ?? ""), colXPositions[colIndex] + padding, y + padding, {
        width: colWidths[colIndex] - padding * 2,
        align: "left",
        lineBreak: true,
      });
    });

    // Línea horizontal entre filas (sutil)
    if (rowIndex < rows.length - 1) {
      doc
        .moveTo(startX, y + maxRowHeight)
        .lineTo(startX + totalWidth, y + maxRowHeight)
        .lineWidth(0.3)
        .stroke(COLORS.border);
    }

    y += maxRowHeight;
  });

  doc.y = y + 8;
  return y;
}

// ─── Generación Principal de PDF ─────────────────────────────────
/**
 * Genera un PDF de reporte completo y profesional.
 * @param timeoutMs — tiempo máximo en ms (default 20s). Si se excede, la promesa
 *   rechaza con un error de timeout sin cancelar PDFKit internamente, pero el
 *   request HTTP responde rápido en lugar de quedar colgado.
 */
export async function generatePDF(
  title: string,
  sections: Array<{
    heading: string;
    content?: string;
    table?: { headers: string[]; rows: string[][]; colWidths?: number[] };
  }>,
  timeoutMs = 20000,
): Promise<Uint8Array> {
  const pdfPromise = new Promise<Uint8Array>((resolve, reject) => {
    const doc = new PDFDocument({
      size: "A4",
      margin: 50,
      info: {
        Title: title,
        Author: "WAF-ML Engine",
        Subject: "Reporte de Seguridad",
        Keywords: "waf, ml, seguridad, lgbm, mlp",
      },
    });

    const chunks: Buffer[] = [];
    doc.on("data", (chunk) => chunks.push(chunk));
    doc.on("end", () => resolve(new Uint8Array(Buffer.concat(chunks))));
    doc.on("error", reject);

    // ── Portada (fondo oscuro, diseño limpio) ──
    // Barra decorativa superior
    doc.rect(0, 0, doc.page.width, 6).fill(COLORS.accent);

    const pageCenter = doc.page.width / 2;

    // Título principal
    doc
      .fontSize(36)
      .font(FONTS.bold)
      .fillColor(COLORS.bgDark)
      .text("WAF-ML ENGINE", pageCenter, 140, { align: "center" });

    // Línea decorativa
    doc
      .moveTo(pageCenter - 40, 185)
      .lineTo(pageCenter + 40, 185)
      .lineWidth(3)
      .stroke(COLORS.accent);

    // Subtítulo
    doc
      .fontSize(15)
      .font(FONTS.regular)
      .fillColor(COLORS.muted)
      .text("Hybrid Web Application Firewall • LGBM + MLP Ensemble", {
        align: "center",
      });
    doc.moveDown(4);

    // Título del reporte (caja con fondo)
    const reportTitleY = doc.y;
    const reportTitleBoxH = 50;
    doc
      .rect(70, reportTitleY, doc.page.width - 140, reportTitleBoxH)
      .fill(COLORS.bgDark);
    doc
      .fontSize(20)
      .font(FONTS.bold)
      .fillColor(COLORS.white)
      .text(title, 70, reportTitleY + 14, {
        align: "center",
        width: doc.page.width - 140,
      });

    doc.moveDown(5);

    // Metadata
    const metaY = doc.y;
    doc
      .fontSize(10)
      .font(FONTS.regular)
      .fillColor(COLORS.muted)
      .text(
        `Generado el ${new Date().toLocaleDateString("es-PE")} a las ${new Date().toLocaleTimeString("es-PE")}`,
        { align: "center" },
      );
    doc.text("USAT — Universidad Católica Santo Toribio de Mogrovejo", {
      align: "center",
    });
    doc.text(`Perú • ${new Date().getFullYear()}`, { align: "center" });

    // Barra decorativa inferior
    doc.rect(0, doc.page.height - 6, doc.page.width, 6).fill(COLORS.accent);

    doc.addPage();

    // ── Contenido ──
    let prevSectionHadTable = false;
    for (const section of sections) {
      // Salto de página automático entre secciones consecutivas con tabla
      if (section.table && prevSectionHadTable) {
        doc.addPage();
      }
      prevSectionHadTable = !!section.table;

      // Heading sin color — solo peso bold para jerarquía limpia
      doc
        .fontSize(16)
        .font(FONTS.bold)
        .fillColor(COLORS.heading)
        .text(section.heading);
      doc.moveDown(0.3);

      // Línea decorativa sutil bajo heading
      const headingEndY = doc.y;
      doc
        .moveTo(50, headingEndY)
        .lineTo(doc.page.width - 50, headingEndY)
        .lineWidth(1.5)
        .stroke(COLORS.accent);
      doc.moveDown(0.7);

      // Contenido textual
      if (section.content) {
        doc
          .fontSize(10.5)
          .font(FONTS.regular)
          .fillColor(COLORS.body)
          .text(section.content, {
            align: "justify",
            lineGap: 3,
            paragraphGap: 4,
          });
        doc.moveDown(0.8);
      }

      // Tabla
      if (section.table) {
        drawTable(doc, {
          headers: section.table.headers,
          rows: section.table.rows,
          colWidths: section.table.colWidths,
          startY: doc.y,
          padding: 7,
        });
        doc.moveDown(1.2);
      }
    }

    // Footer en todas las páginas
    const range = doc.bufferedPageRange();
    // Después de todo el contenido, agregamos footer a cada página
    for (let i = range.start; i < range.start + range.count; i++) {
      doc.switchToPage(i);
      // Línea separadora del footer
      doc
        .moveTo(50, doc.page.height - 42)
        .lineTo(doc.page.width - 50, doc.page.height - 42)
        .lineWidth(0.5)
        .stroke(COLORS.border);
      // Texto del footer (usando fontSize + fillColor antes de cada text())
      doc.fontSize(7.5).font(FONTS.regular).fillColor(COLORS.muted);
      doc.text(
        `WAF-ML Engine • Reporte de Seguridad • Página ${i + 1} de ${range.count}`,
        50,
        doc.page.height - 35,
        { align: "center", width: doc.page.width - 100 },
      );
      doc.text(
        `Generado: ${new Date().toLocaleString("es-PE")} • USAT Perú`,
        50,
        doc.page.height - 25,
        { align: "center", width: doc.page.width - 100 },
      );
    }

    doc.end();
  });

  // ── Timeout guard: si el PDF tarda más de timeoutMs, responde con error ──
  const timeoutPromise = new Promise<never>((_, reject) =>
    setTimeout(
      () => reject(new Error(`PDF generation timed out after ${timeoutMs}ms`)),
      timeoutMs,
    ),
  );

  return Promise.race([pdfPromise, timeoutPromise]);
}

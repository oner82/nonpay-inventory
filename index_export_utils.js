(() => {
  const encoder = new TextEncoder();
  const escapeXml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[char]));
  const zipPart = (value) => typeof value === "string" ? encoder.encode(value) : value;
  const zipConcat = (parts) => {
    const chunks = parts.map(zipPart);
    const output = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
    let offset = 0;
    chunks.forEach((chunk) => {
      output.set(chunk, offset);
      offset += chunk.length;
    });
    return output;
  };
  const zipU16 = (value) => new Uint8Array([value & 255, (value >>> 8) & 255]);
  const zipU32 = (value) => new Uint8Array([value & 255, (value >>> 8) & 255, (value >>> 16) & 255, (value >>> 24) & 255]);
  const crcTable = Array.from({ length: 256 }, (_, index) => {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    return value >>> 0;
  });
  const crc32 = (bytes) => {
    let crc = 0xffffffff;
    bytes.forEach((byte) => {
      crc = crcTable[(crc ^ byte) & 255] ^ (crc >>> 8);
    });
    return (crc ^ 0xffffffff) >>> 0;
  };
  const zipFiles = (files) => {
    const locals = [];
    const centrals = [];
    let offset = 0;
    files.forEach((file) => {
      const name = encoder.encode(file.name);
      const data = zipPart(file.content);
      const crc = crc32(data);
      const local = zipConcat([
        zipU32(0x04034b50), zipU16(20), zipU16(0), zipU16(0), zipU16(0), zipU16(0),
        zipU32(crc), zipU32(data.length), zipU32(data.length), zipU16(name.length), zipU16(0),
        name, data
      ]);
      const central = zipConcat([
        zipU32(0x02014b50), zipU16(20), zipU16(20), zipU16(0), zipU16(0), zipU16(0), zipU16(0),
        zipU32(crc), zipU32(data.length), zipU32(data.length), zipU16(name.length), zipU16(0), zipU16(0),
        zipU16(0), zipU16(0), zipU32(0), zipU32(offset), name
      ]);
      locals.push(local);
      centrals.push(central);
      offset += local.length;
    });
    const centralSize = centrals.reduce((sum, item) => sum + item.length, 0);
    const end = zipConcat([
      zipU32(0x06054b50), zipU16(0), zipU16(0), zipU16(files.length), zipU16(files.length),
      zipU32(centralSize), zipU32(offset), zipU16(0)
    ]);
    return zipConcat([...locals, ...centrals, end]);
  };
  const xlsxColumnName = (index) => {
    let name = "";
    for (let value = index + 1; value > 0; value = Math.floor((value - 1) / 26)) {
      name = String.fromCharCode(65 + ((value - 1) % 26)) + name;
    }
    return name;
  };
  const xlsxCell = (value, rowIndex, columnIndex) => {
    const ref = `${xlsxColumnName(columnIndex)}${rowIndex}`;
    const style = rowIndex === 1 ? 1 : (typeof value === "number" && Number.isFinite(value) ? 3 : 2);
    if (typeof value === "number" && Number.isFinite(value)) return `<c r="${ref}" s="${style}"><v>${value}</v></c>`;
    return `<c r="${ref}" s="${style}" t="inlineStr"><is><t xml:space="preserve">${escapeXml(value)}</t></is></c>`;
  };
  const xlsxTextWidth = (value) => String(value ?? "").split(/\r?\n/).reduce((max, line) => {
    const width = Array.from(line).reduce((sum, char) => sum + (char.charCodeAt(0) > 255 ? 2 : 1), 0);
    return Math.max(max, width);
  }, 0);
  const xlsxColumnWidth = (header, values) => {
    const headerText = String(header ?? "");
    const maxText = Math.max(xlsxTextWidth(headerText), ...values.map(xlsxTextWidth));
    const keywordMax = /메모|사용제품|제품명|랜딩표시/.test(headerText) ? 60 : 42;
    const keywordMin = /날짜|사용일|입고일|입력시각|수정시각/.test(headerText) ? 13 : 9;
    return Math.min(keywordMax, Math.max(keywordMin, maxText + 3));
  };
  const xlsxCols = (headers, rows) => {
    const cols = headers.map((header, index) => {
      const width = xlsxColumnWidth(header, rows.map((row) => row[index]));
      return `<col min="${index + 1}" max="${index + 1}" width="${width}" customWidth="1"/>`;
    }).join("");
    return cols ? `<cols>${cols}</cols>` : "";
  };
  const xlsxNumericReportColumns = (headers, rows) => headers
    .map((header, index) => ({ header: String(header ?? ""), index }))
    .filter((column) =>
      /수량|입고|사용|재고|현재고|기준재고|누적/.test(column.header) &&
      rows.some((row) => typeof row[column.index] === "number" && Number.isFinite(row[column.index]))
    );
  const xlsxDataBars = (headers, rows) => {
    if (!rows.length) return "";
    return xlsxNumericReportColumns(headers, rows).map((column, index) => {
      const name = xlsxColumnName(column.index);
      return `<conditionalFormatting sqref="${name}2:${name}${rows.length + 1}"><cfRule type="dataBar" priority="${index + 1}"><dataBar><cfvo type="min"/><cfvo type="max"/><color rgb="FF5B8DEF"/></dataBar></cfRule></conditionalFormatting>`;
    }).join("");
  };
  const xlsxSheetName = (name) => String(name || "Report").replace(/[\[\]:*?/\\]/g, " ").slice(0, 31) || "Report";
  const xlsxGeneratedAt = () => {
    try {
      return new Date().toLocaleString("ko-KR");
    } catch (_error) {
      return new Date().toISOString();
    }
  };
  const xlsxSumColumn = (rows, index) => rows.reduce((sum, row) => {
    const value = row[index];
    return sum + (typeof value === "number" && Number.isFinite(value) ? value : 0);
  }, 0);
  const xlsxSummaryGroupIndex = (headers) => {
    const preferred = ["제품군", "분류", "구분", "업체명", "과", "수술", "원장코드"];
    const labels = headers.map((header) => String(header ?? ""));
    for (const label of preferred) {
      const index = labels.findIndex((header) => header === label);
      if (index >= 0) return index;
    }
    return labels.findIndex((header) => /제품군|분류|구분|업체|과|수술|원장/.test(header));
  };
  const xlsxSummaryMetricColumn = (numericColumns) => {
    const preferred = [/수량/, /기간사용/, /기간입고/, /사용/, /입고/, /현재고/];
    for (const pattern of preferred) {
      const column = numericColumns.find((item) => pattern.test(item.header));
      if (column) return column;
    }
    return numericColumns[0] || null;
  };
  const xlsxGroupedSummaryRows = (headers, rows, groupIndex, metricColumn) => {
    if (groupIndex < 0 || !metricColumn) return [];
    const grouped = new Map();
    rows.forEach((row) => {
      const group = String(row[groupIndex] || "미분류");
      const value = row[metricColumn.index];
      grouped.set(group, (grouped.get(group) || 0) + (typeof value === "number" && Number.isFinite(value) ? value : 0));
    });
    return Array.from(grouped.entries())
      .sort((left, right) => right[1] - left[1])
      .slice(0, 12)
      .map(([group, total]) => [group, total]);
  };
  const xlsxSummarySheet = (headers, rows) => {
    const numericColumns = xlsxNumericReportColumns(headers, rows);
    if (!rows.length || !numericColumns.length) return null;
    const metricColumn = xlsxSummaryMetricColumn(numericColumns);
    const groupIndex = xlsxSummaryGroupIndex(headers);
    const summaryRows = [
      ["보고서 요약", "값"],
      ["생성일시", xlsxGeneratedAt()],
      ["상세 행수", rows.length],
      ["", ""],
      ["수량/재고 합계", "합계"],
      ...numericColumns.map((column) => [column.header, xlsxSumColumn(rows, column.index)])
    ];
    const groupedRows = xlsxGroupedSummaryRows(headers, rows, groupIndex, metricColumn);
    if (groupedRows.length) {
      summaryRows.push(["", ""]);
      summaryRows.push([`${headers[groupIndex]}별 ${metricColumn.header} 상위`, metricColumn.header]);
      summaryRows.push(...groupedRows);
    }
    return {
      name: "요약",
      headers: summaryRows[0],
      rows: summaryRows.slice(1)
    };
  };
  const xlsxStyles = () => `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Calibri"/></font></fonts>
  <fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF24507A"/><bgColor indexed="64"/></patternFill></fill></fills>
  <borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style="thin"><color rgb="FFD9E2EC"/></left><right style="thin"><color rgb="FFD9E2EC"/></right><top style="thin"><color rgb="FFD9E2EC"/></top><bottom style="thin"><color rgb="FFD9E2EC"/></bottom><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="4"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment horizontal="right" vertical="top"/></xf></cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
  <dxfs count="0"/><tableStyles count="0" defaultTableStyle="TableStyleMedium2" defaultPivotStyle="PivotStyleLight16"/>
</styleSheet>`;
  const xlsxWorksheet = (headers, rows, options = {}) => {
    const allRows = [headers, ...rows];
    const lastCell = `${xlsxColumnName(Math.max(headers.length - 1, 0))}${Math.max(allRows.length, 1)}`;
    const filterRef = headers.length ? `A1:${lastCell}` : "A1:A1";
    const sheetRows = allRows.map((row, rowIndex) =>
      `<row r="${rowIndex + 1}">${row.map((value, columnIndex) => xlsxCell(value, rowIndex + 1, columnIndex)).join("")}</row>`
    ).join("");
    const filters = options.filter === false ? "" : `<autoFilter ref="${filterRef}"/>`;
    const bars = options.dataBars === false ? "" : xlsxDataBars(headers, rows);
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="A1:${lastCell}"/><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="18"/>${xlsxCols(headers, rows)}<sheetData>${sheetRows}</sheetData>${filters}${bars}<pageMargins left="0.35" right="0.35" top="0.6" bottom="0.6" header="0.3" footer="0.3"/></worksheet>`;
  };
  const xlsxWorkbookSheets = (headers, rows) => {
    const summary = xlsxSummarySheet(headers, rows);
    const detail = { name: summary ? "상세" : "Report", headers, rows };
    return summary ? [summary, detail] : [detail];
  };
  const xlsxWorkbook = (headers, rows) => {
    const sheets = xlsxWorkbookSheets(headers, rows);
    const sheetOverrides = sheets.map((_, index) =>
      `<Override PartName="/xl/worksheets/sheet${index + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`
    ).join("");
    const sheetEntries = sheets.map((sheet, index) =>
      `<sheet name="${escapeXml(xlsxSheetName(sheet.name))}" sheetId="${index + 1}" r:id="rId${index + 1}"/>`
    ).join("");
    const sheetRelationships = sheets.map((_, index) =>
      `<Relationship Id="rId${index + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${index + 1}.xml"/>`
    ).join("");
    const worksheetFiles = sheets.map((sheet, index) => ({
      name: `xl/worksheets/sheet${index + 1}.xml`,
      content: xlsxWorksheet(sheet.headers, sheet.rows, { filter: index !== 0 || sheets.length === 1 })
    }));
    return zipFiles([
      { name: "[Content_Types].xml", content: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>${sheetOverrides}</Types>` },
      { name: "_rels/.rels", content: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>` },
      { name: "xl/workbook.xml", content: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>${sheetEntries}</sheets></workbook>` },
      { name: "xl/_rels/workbook.xml.rels", content: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${sheetRelationships}<Relationship Id="rId${sheets.length + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>` },
      { name: "xl/styles.xml", content: xlsxStyles() },
      ...worksheetFiles
    ]);
  };
  const downloadExcel = (filename, headers, rows) => {
    const blob = new Blob([xlsxWorkbook(headers, rows)], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename.replace(/\.(xls|csv)$/i, ".xlsx");
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();
    setTimeout(() => {
      URL.revokeObjectURL(url);
      link.remove();
    }, 0);
  };

  window.ORInventoryExportUtils = {
    zipFiles,
    xlsxWorkbook,
    downloadExcel
  };
})();

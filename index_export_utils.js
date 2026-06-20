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
    if (typeof value === "number" && Number.isFinite(value)) return `<c r="${ref}"><v>${value}</v></c>`;
    return `<c r="${ref}" t="inlineStr"><is><t>${escapeXml(value)}</t></is></c>`;
  };
  const xlsxWorkbook = (headers, rows) => {
    const allRows = [headers, ...rows];
    const sheetRows = allRows.map((row, rowIndex) =>
      `<row r="${rowIndex + 1}">${row.map((value, columnIndex) => xlsxCell(value, rowIndex + 1, columnIndex)).join("")}</row>`
    ).join("");
    const worksheet = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>${sheetRows}</sheetData></worksheet>`;
    return zipFiles([
      { name: "[Content_Types].xml", content: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>` },
      { name: "_rels/.rels", content: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>` },
      { name: "xl/workbook.xml", content: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Report" sheetId="1" r:id="rId1"/></sheets></workbook>` },
      { name: "xl/_rels/workbook.xml.rels", content: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>` },
      { name: "xl/worksheets/sheet1.xml", content: worksheet }
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

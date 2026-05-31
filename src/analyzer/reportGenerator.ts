import { Section, Symbol } from '../disassembler/types.js';
import { ScanResult } from './signatures.js';
import { ExtractedString } from './strings.js';
import { EntropyBlock } from './entropy.js';
import { PEParser } from '../parser/pe.js';

export interface ReportData {
  fileName: string;
  fileSize: number;
  architecture: string;
  entryPoint: number;
  sections: Section[];
  symbols: Symbol[];
  signatures: ScanResult[];
  entropy: {
    overall: number;
    highEntropyBlocks: EntropyBlock[];
  };
  strings: ExtractedString[];
  binaryData?: Uint8Array;
}

export class ReportGenerator {
  public static generateJSON(data: ReportData): string {
    const reportObj: any = { ...data };
    delete reportObj.binaryData;

    if (
      data.binaryData &&
      data.binaryData.length > 64 &&
      data.binaryData[0] === 0x4d &&
      data.binaryData[1] === 0x5a
    ) {
      try {
        const peParser = new PEParser(data.binaryData.buffer as ArrayBuffer);
        const pe = peParser.parse();
        if (pe.resources) {
          reportObj.peResources = {
            manifests: pe.resources.manifests,
            stringsCount: Object.keys(pe.resources.strings).length,
            iconsCount: pe.resources.icons.length,
            allResources: pe.resources.all.map((r) => ({
              typeName: r.typeName,
              name: r.name,
              language: r.language,
              size: r.size,
              offset: r.offset,
            })),
          };
        }
      } catch {
        // Ignore parsing errors
      }
    }

    return JSON.stringify(reportObj, null, 2);
  }

  public static generateMarkdown(data: ReportData): string {
    const formatSize = (bytes: number) => {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    let md = `# Binary Analysis Report: ${data.fileName}\n\n`;

    // Metadata Table
    md += `## 📋 File Metadata\n\n`;
    md += `| Parameter | Value |\n`;
    md += `|---|---|\n`;
    md += `| **File Name** | ${data.fileName} |\n`;
    md += `| **Size** | ${formatSize(data.fileSize)} (${data.fileSize} bytes) |\n`;
    md += `| **Architecture** | ${data.architecture.toUpperCase()} |\n`;
    md += `| **Entry Point** | 0x${data.entryPoint.toString(16).toUpperCase()} |\n`;
    md += `| **Overall Entropy** | ${data.entropy.overall.toFixed(4)} |\n\n`;

    // Sections Table
    md += `## 📦 Sections\n\n`;
    if (data.sections && data.sections.length > 0) {
      md += `| Name | Virtual Address | Virtual Size | File Offset | File Size | Entropy | Flags |\n`;
      md += `|---|---|---|---|---|---|---|\n`;
      for (const sec of data.sections) {
        const flagsStr = [
          sec.flags.read ? 'R' : '-',
          sec.flags.write ? 'W' : '-',
          sec.flags.execute ? 'X' : '-',
        ].join('');
        const entropyVal =
          sec.entropy !== undefined ? sec.entropy.toFixed(4) : 'N/A';
        md += `| \`${sec.name}\` | 0x${sec.virtualAddress.toString(16).toUpperCase()} | ${formatSize(sec.virtualSize)} | 0x${sec.fileOffset.toString(16).toUpperCase()} | ${formatSize(sec.fileSize)} | ${entropyVal} | \`${flagsStr}\` |\n`;
      }
    } else {
      md += `No sections found.\n`;
    }
    md += `\n`;

    // Symbols List
    md += `## 🏷️ Symbols\n\n`;
    const funcSyms = data.symbols.filter((s) => s.type === 'function');
    const otherSyms = data.symbols.filter((s) => s.type !== 'function');
    md += `Total Symbols: ${data.symbols.length} (Functions: ${funcSyms.length}, Other: ${otherSyms.length})\n\n`;
    if (data.symbols.length > 0) {
      md += `| Name | Address | Type | Binding | Size |\n`;
      md += `|---|---|---|---|---|\n`;
      const displayedSymbols = data.symbols.slice(0, 50);
      for (const sym of displayedSymbols) {
        const sizeStr = sym.size !== undefined ? sym.size.toString() : 'N/A';
        md += `| \`${sym.name}\` | 0x${sym.address.toString(16).toUpperCase()} | \`${sym.type}\` | \`${sym.binding}\` | ${sizeStr} |\n`;
      }
      if (data.symbols.length > 50) {
        md += `| ... | ... | ... | ... | ... |\n`;
        md += `\n*Showing top 50 symbols. Check JSON report for full list.*\n`;
      }
    } else {
      md += `No symbols found.\n`;
    }
    md += `\n`;

    // Signature Matches
    md += `## 🛡️ Signature Scan Results\n\n`;
    if (data.signatures && data.signatures.length > 0) {
      md += `| Rule Name | Category | Matches (Offsets) |\n`;
      md += `|---|---|---|\n`;
      for (const sig of data.signatures) {
        const matchesStr = sig.matches
          .map(
            (m) => `0x${m.offset.toString(16).toUpperCase()} (${m.patternType})`
          )
          .join(', ');
        md += `| **${sig.ruleName}** | \`${sig.category}\` | ${matchesStr} |\n`;
      }
    } else {
      md += `No signatures matched.\n`;
    }
    md += `\n`;

    // Entropy Blocks
    md += `## 📈 High Entropy Blocks\n\n`;
    if (
      data.entropy.highEntropyBlocks &&
      data.entropy.highEntropyBlocks.length > 0
    ) {
      md += `| Start Offset | End Offset | Length | Entropy |\n`;
      md += `|---|---|---|---|\n`;
      for (const block of data.entropy.highEntropyBlocks) {
        md += `| 0x${block.start.toString(16).toUpperCase()} | 0x${block.end.toString(16).toUpperCase()} | ${block.length} B | ${block.entropy.toFixed(4)} |\n`;
      }
    } else {
      md += `No high entropy blocks detected (entropy >= 7.2).\n`;
    }
    md += `\n`;

    // Extracted Strings
    md += `## 💬 Extracted Strings (Top 100)\n\n`;
    if (data.strings && data.strings.length > 0) {
      md += `| Offset | Address | Encoding | Tags | String Value |\n`;
      md += `|---|---|---|---|---|\n`;
      const displayedStrings = data.strings.slice(0, 100);
      for (const str of displayedStrings) {
        const tagsStr =
          str.tags.length > 0
            ? str.tags.map((t) => `\`${t}\``).join(', ')
            : '-';
        const escapedValue = str.value
          .replace(/\|/g, '\\|')
          .replace(/\n/g, '\\n')
          .replace(/\r/g, '\\r');
        md += `| 0x${str.offset.toString(16).toUpperCase()} | 0x${str.virtualAddress.toString(16).toUpperCase()} | \`${str.encoding}\` | ${tagsStr} | \`${escapedValue}\` |\n`;
      }
      if (data.strings.length > 100) {
        md += `| ... | ... | ... | ... | ... |\n`;
        md += `\n*Showing top 100 strings. Check JSON report for full list.*\n`;
      }
    } else {
      md += `No strings extracted.\n`;
    }
    md += `\n`;

    // PE Resources section if it exists
    if (
      data.binaryData &&
      data.binaryData.length > 64 &&
      data.binaryData[0] === 0x4d &&
      data.binaryData[1] === 0x5a
    ) {
      try {
        const peParser = new PEParser(data.binaryData.buffer as ArrayBuffer);
        const pe = peParser.parse();
        if (pe.resources && pe.resources.all && pe.resources.all.length > 0) {
          const r = pe.resources;
          md += `## 📦 PE Resource (.rsrc) Section\n\n`;

          md += `### All Resources\n\n`;
          md += `| Type Name | Name/ID | Lang ID | Size | Offset |\n`;
          md += `|---|---|---|---|---|\n`;
          for (const res of r.all) {
            md += `| \`${res.typeName}\` | ${res.name} | ${res.language} | ${res.size} B | 0x${res.offset.toString(16).toUpperCase()} |\n`;
          }
          md += `\n`;

          if (r.manifests && r.manifests.length > 0) {
            md += `### Manifests\n\n`;
            for (const m of r.manifests) {
              md += `\`\`\`xml\n${m}\n\`\`\`\n\n`;
            }
          }

          const stringKeys = Object.keys(r.strings);
          if (stringKeys.length > 0) {
            md += `### Parsed String Table Resources\n\n`;
            md += `| ID | String Value |\n`;
            md += `|---|---|\n`;
            for (const k of stringKeys) {
              md += `| ${k} | \`${r.strings[Number(k)]}\` |\n`;
            }
            md += `\n`;
          }

          if (r.icons && r.icons.length > 0) {
            md += `### Icons & Group Icons\n\n`;
            md += `| Type | Size | File Offset |\n`;
            md += `|---|---|---|\n`;
            for (const i of r.icons) {
              md += `| ${i.type} | ${i.size} B | 0x${i.offset.toString(16).toUpperCase()} |\n`;
            }
            md += `\n`;
          }
        }
      } catch {
        // Ignore PE parsing errors
      }
    }

    return md;
  }

  public static generateHTML(data: ReportData): string {
    const formatSize = (bytes: number) => {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    const overallEntropy = data.entropy.overall.toFixed(4);
    const sectionsRows = data.sections && data.sections.length > 0
      ? data.sections.map(sec => {
          const flagsStr = [
            sec.flags.read ? 'R' : '-',
            sec.flags.write ? 'W' : '-',
            sec.flags.execute ? 'X' : '-',
          ].join('');
          const entropyVal = sec.entropy !== undefined ? sec.entropy.toFixed(4) : 'N/A';
          return `
            <tr>
              <td><code>${sec.name}</code></td>
              <td>0x${sec.virtualAddress.toString(16).toUpperCase()}</td>
              <td>${formatSize(sec.virtualSize)}</td>
              <td>0x${sec.fileOffset.toString(16).toUpperCase()}</td>
              <td>${formatSize(sec.fileSize)}</td>
              <td>${entropyVal}</td>
              <td><code>${flagsStr}</code></td>
            </tr>
          `;
        }).join('')
      : `<tr><td colspan="7" class="no-data">No sections found.</td></tr>`;

    const funcSyms = data.symbols.filter((s) => s.type === 'function');
    const otherSyms = data.symbols.filter((s) => s.type !== 'function');
    const displayedSymbols = data.symbols.slice(0, 50);
    const symbolsRows = data.symbols.length > 0
      ? displayedSymbols.map(sym => {
          const sizeStr = sym.size !== undefined ? sym.size.toString() : 'N/A';
          return `
            <tr>
              <td><code>${sym.name}</code></td>
              <td>0x${sym.address.toString(16).toUpperCase()}</td>
              <td><code>${sym.type}</code></td>
              <td><code>${sym.binding}</code></td>
              <td>${sizeStr}</td>
            </tr>
          `;
        }).join('') + (data.symbols.length > 50 ? `<tr><td colspan="5" class="truncated-row">... showing top 50 symbols. Check JSON report for full list. ...</td></tr>` : '')
      : `<tr><td colspan="5" class="no-data">No symbols found.</td></tr>`;

    const signaturesRows = data.signatures && data.signatures.length > 0
      ? data.signatures.map(sig => {
          const matchesStr = sig.matches
            .map(m => `0x${m.offset.toString(16).toUpperCase()} (${m.patternType})`)
            .join(', ');
          return `
            <tr>
              <td><strong>${sig.ruleName}</strong></td>
              <td><code>${sig.category}</code></td>
              <td>${matchesStr}</td>
            </tr>
          `;
        }).join('')
      : `<tr><td colspan="3" class="no-data">No signatures matched.</td></tr>`;

    const entropyRows = data.entropy.highEntropyBlocks && data.entropy.highEntropyBlocks.length > 0
      ? data.entropy.highEntropyBlocks.map(block => `
          <tr>
            <td>0x${block.start.toString(16).toUpperCase()}</td>
            <td>0x${block.end.toString(16).toUpperCase()}</td>
            <td>${block.length} B</td>
            <td>${block.entropy.toFixed(4)}</td>
          </tr>
        `).join('')
      : `<tr><td colspan="4" class="no-data">No high entropy blocks detected (entropy &gt;= 7.2).</td></tr>`;

    const displayedStrings = data.strings.slice(0, 100);
    const stringsRows = data.strings && data.strings.length > 0
      ? displayedStrings.map(str => {
          const tagsStr = str.tags.length > 0
            ? str.tags.map(t => `<span class="tag">${t}</span>`).join(' ')
            : '-';
          const escapedValue = str.value
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
          return `
            <tr>
              <td>0x${str.offset.toString(16).toUpperCase()}</td>
              <td>0x${str.virtualAddress.toString(16).toUpperCase()}</td>
              <td><code>${str.encoding}</code></td>
              <td>${tagsStr}</td>
              <td class="string-val"><code>${escapedValue}</code></td>
            </tr>
          `;
        }).join('') + (data.strings.length > 100 ? `<tr><td colspan="5" class="truncated-row">... showing top 100 strings. Check JSON report for full list. ...</td></tr>` : '')
      : `<tr><td colspan="5" class="no-data">No strings extracted.</td></tr>`;

    // PE Resources HTML block if it exists
    let peResourcesHTML = '';
    if (
      data.binaryData &&
      data.binaryData.length > 64 &&
      data.binaryData[0] === 0x4d &&
      data.binaryData[1] === 0x5a
    ) {
      try {
        const peParser = new PEParser(data.binaryData.buffer as ArrayBuffer);
        const pe = peParser.parse();
        if (pe.resources && pe.resources.all && pe.resources.all.length > 0) {
          const r = pe.resources;
          const resourceRows = r.all.map(res => `
            <tr>
              <td><code>${res.typeName}</code></td>
              <td>${res.name}</td>
              <td>${res.language}</td>
              <td>${res.size} B</td>
              <td>0x${res.offset.toString(16).toUpperCase()}</td>
            </tr>
          `).join('');

          let manifestBlock = '';
          if (r.manifests && r.manifests.length > 0) {
            manifestBlock = `
              <h3>Manifests</h3>
              ${r.manifests.map(m => `
                <pre class="manifest-code"><code>${m.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code></pre>
              `).join('')}
            `;
          }

          let stringTableBlock = '';
          const stringKeys = Object.keys(r.strings);
          if (stringKeys.length > 0) {
            stringTableBlock = `
              <h3>Parsed String Table Resources</h3>
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>String Value</th>
                  </tr>
                </thead>
                <tbody>
                  ${stringKeys.map(k => `
                    <tr>
                      <td>${k}</td>
                      <td><code>${r.strings[Number(k)].replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code></td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            `;
          }

          let iconsBlock = '';
          if (r.icons && r.icons.length > 0) {
            iconsBlock = `
              <h3>Icons & Group Icons</h3>
              <table>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Size</th>
                    <th>File Offset</th>
                  </tr>
                </thead>
                <tbody>
                  ${r.icons.map(i => `
                    <tr>
                      <td>${i.type}</td>
                      <td>${i.size} B</td>
                      <td>0x${i.offset.toString(16).toUpperCase()}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            `;
          }

          peResourcesHTML = `
            <section class="page-break-before">
              <h2>📦 PE Resource (.rsrc) Section</h2>
              <table>
                <thead>
                  <tr>
                    <th>Type Name</th>
                    <th>Name/ID</th>
                    <th>Lang ID</th>
                    <th>Size</th>
                    <th>Offset</th>
                  </tr>
                </thead>
                <tbody>
                  ${resourceRows}
                </tbody>
              </table>
              ${manifestBlock}
              ${stringTableBlock}
              ${iconsBlock}
            </section>
          `;
        }
      } catch {
        // Ignore PE parsing errors
      }
    }

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Binary Analysis Report - ${data.fileName}</title>
  <style>
    :root {
      --primary-color: #2b6cb0;
      --secondary-color: #2d3748;
      --text-color: #2d3748;
      --bg-color: #f7fafc;
      --card-bg: #ffffff;
      --border-color: #e2e8f0;
      --accent-color: #dd6b20;
    }
    
    body {
      font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
      color: var(--text-color);
      background-color: var(--bg-color);
      line-height: 1.6;
      margin: 0;
      padding: 2rem;
    }

    .report-container {
      max-width: 900px;
      margin: 0 auto;
      background: var(--card-bg);
      border-radius: 8px;
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -1px rgba(0,0,0,0.06);
      padding: 3rem;
    }

    header {
      border-bottom: 3px solid var(--primary-color);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
      position: relative;
    }

    .header-title {
      font-size: 2.2rem;
      color: var(--secondary-color);
      margin: 0;
    }

    .header-subtitle {
      font-size: 1rem;
      color: #718096;
      margin: 0.5rem 0 0 0;
    }

    h2 {
      font-size: 1.5rem;
      color: var(--secondary-color);
      border-bottom: 2px solid var(--border-color);
      padding-bottom: 0.5rem;
      margin-top: 2rem;
    }

    h3 {
      font-size: 1.2rem;
      color: var(--secondary-color);
      margin-top: 1.5rem;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin: 1.2rem 0;
    }

    th, td {
      border: 1px solid var(--border-color);
      padding: 0.75rem 1rem;
      text-align: left;
    }

    th {
      background-color: #edf2f7;
      color: #4a5568;
      font-weight: 600;
    }

    tr:nth-child(even) {
      background-color: #f7fafc;
    }

    code {
      font-family: SFMono-Regular, Consolas, monospace;
      background-color: #edf2f7;
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      font-size: 0.85em;
    }

    .tag {
      display: inline-block;
      background-color: #feebc8;
      color: #c05621;
      padding: 0.1rem 0.4rem;
      border-radius: 4px;
      font-size: 0.75em;
      font-weight: 600;
      margin-right: 0.2rem;
    }

    .string-val {
      max-width: 300px;
      word-break: break-all;
    }

    .no-data, .truncated-row {
      text-align: center;
      color: #a0aec0;
      font-style: italic;
    }

    .manifest-code {
      background: #2d3748;
      color: #f7fafc;
      padding: 1rem;
      border-radius: 6px;
      overflow-x: auto;
      font-size: 0.9em;
    }

    @media print {
      body {
        background-color: #fff;
        padding: 0;
      }
      .report-container {
        box-shadow: none;
        padding: 0;
        max-width: 100%;
      }
      .page-break-before {
        page-break-before: always;
      }
      thead {
        display: table-header-group;
      }
      tr {
        page-break-inside: avoid;
      }
      .no-print {
        display: none !important;
      }
    }
  </style>
</head>
<body>
  <div class="report-container">
    <div style="display: flex; justify-content: flex-end; margin-bottom: 1rem;" class="no-print">
      <button onclick="window.print()" style="padding: 0.5rem 1rem; font-size: 1rem; cursor: pointer; background: var(--primary-color); color: #fff; border: none; border-radius: 4px; font-weight: bold;">Print / Save as PDF</button>
    </div>
    <header>
      <h1 class="header-title">Binary Analysis Report</h1>
      <p class="header-subtitle">Generated automatically for ${data.fileName}</p>
    </header>

    <section>
      <h2>📋 File Metadata</h2>
      <table>
        <tbody>
          <tr>
            <td><strong>File Name</strong></td>
            <td>${data.fileName}</td>
          </tr>
          <tr>
            <td><strong>Size</strong></td>
            <td>${formatSize(data.fileSize)} (${data.fileSize} bytes)</td>
          </tr>
          <tr>
            <td><strong>Architecture</strong></td>
            <td>${data.architecture.toUpperCase()}</td>
          </tr>
          <tr>
            <td><strong>Entry Point</strong></td>
            <td>0x${data.entryPoint.toString(16).toUpperCase()}</td>
          </tr>
          <tr>
            <td><strong>Overall Entropy</strong></td>
            <td>${overallEntropy}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <section>
      <h2>📦 Sections</h2>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Virtual Address</th>
            <th>Virtual Size</th>
            <th>File Offset</th>
            <th>File Size</th>
            <th>Entropy</th>
            <th>Flags</th>
          </tr>
        </thead>
        <tbody>
          ${sectionsRows}
        </tbody>
      </table>
    </section>

    <section class="page-break-before">
      <h2>🏷️ Symbols</h2>
      <p>Total Symbols: ${data.symbols.length} (Functions: ${funcSyms.length}, Other: ${otherSyms.length})</p>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Address</th>
            <th>Type</th>
            <th>Binding</th>
            <th>Size</th>
          </tr>
        </thead>
        <tbody>
          ${symbolsRows}
        </tbody>
      </table>
    </section>

    <section>
      <h2>🛡️ Signature Scan Results</h2>
      <table>
        <thead>
          <tr>
            <th>Rule Name</th>
            <th>Category</th>
            <th>Matches (Offsets)</th>
          </tr>
        </thead>
        <tbody>
          ${signaturesRows}
        </tbody>
      </table>
    </section>

    <section>
      <h2>📈 High Entropy Blocks</h2>
      <table>
        <thead>
          <tr>
            <th>Start Offset</th>
            <th>End Offset</th>
            <th>Length</th>
            <th>Entropy</th>
          </tr>
        </thead>
        <tbody>
          ${entropyRows}
        </tbody>
      </table>
    </section>

    <section class="page-break-before">
      <h2>💬 Extracted Strings (Top 100)</h2>
      <table>
        <thead>
          <tr>
            <th>Offset</th>
            <th>Address</th>
            <th>Encoding</th>
            <th>Tags</th>
            <th>String Value</th>
          </tr>
        </thead>
        <tbody>
          ${stringsRows}
        </tbody>
      </table>
    </section>

    ${peResourcesHTML}
  </div>
</body>
</html>`;
  }

  public static generatePlaintext(data: ReportData): string {
    const formatSize = (bytes: number) => {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    let text = `================================================================================\n`;
    text += `BINARY ANALYSIS REPORT: ${data.fileName}\n`;
    text += `================================================================================\n\n`;

    // Metadata
    text += `[ FILE METADATA ]\n`;
    text += `--------------------------------------------------------------------------------\n`;
    text += `File Name:         ${data.fileName}\n`;
    text += `Size:              ${formatSize(data.fileSize)} (${data.fileSize} bytes)\n`;
    text += `Architecture:      ${data.architecture.toUpperCase()}\n`;
    text += `Entry Point:       0x${data.entryPoint.toString(16).toUpperCase()}\n`;
    text += `Overall Entropy:   ${data.entropy.overall.toFixed(4)}\n\n`;

    // Sections
    text += `[ SECTIONS ]\n`;
    text += `--------------------------------------------------------------------------------\n`;
    if (data.sections && data.sections.length > 0) {
      text += `Name       Virtual Addr   Virtual Size   File Offset    File Size      Entropy  Flags\n`;
      text += `--------------------------------------------------------------------------------\n`;
      for (const sec of data.sections) {
        const flagsStr = [
          sec.flags.read ? 'R' : '-',
          sec.flags.write ? 'W' : '-',
          sec.flags.execute ? 'X' : '-',
        ].join('');
        const entropyVal = sec.entropy !== undefined ? sec.entropy.toFixed(4) : 'N/A';
        const namePad = sec.name.slice(0, 10).padEnd(10);
        const vAddrPad = `0x${sec.virtualAddress.toString(16).toUpperCase()}`.padEnd(14);
        const vSizePad = formatSize(sec.virtualSize).padEnd(14);
        const fOffPad = `0x${sec.fileOffset.toString(16).toUpperCase()}`.padEnd(14);
        const fSizePad = formatSize(sec.fileSize).padEnd(14);
        const entropyPad = entropyVal.padEnd(8);
        text += `${namePad} ${vAddrPad} ${vSizePad} ${fOffPad} ${fSizePad} ${entropyPad} ${flagsStr}\n`;
      }
    } else {
      text += `No sections found.\n`;
    }
    text += `\n`;

    // Symbols
    text += `[ SYMBOLS (Top 50) ]\n`;
    text += `--------------------------------------------------------------------------------\n`;
    const funcSyms = data.symbols.filter((s) => s.type === 'function');
    const otherSyms = data.symbols.filter((s) => s.type !== 'function');
    text += `Total Symbols: ${data.symbols.length} (Functions: ${funcSyms.length}, Other: ${otherSyms.length})\n\n`;
    if (data.symbols.length > 0) {
      text += `Name                           Address        Type           Binding        Size\n`;
      text += `--------------------------------------------------------------------------------\n`;
      const displayedSymbols = data.symbols.slice(0, 50);
      for (const sym of displayedSymbols) {
        const sizeStr = sym.size !== undefined ? sym.size.toString() : 'N/A';
        const namePad = (sym.name.length > 29 ? sym.name.slice(0, 26) + '...' : sym.name).padEnd(30);
        const addrPad = `0x${sym.address.toString(16).toUpperCase()}`.padEnd(14);
        const typePad = sym.type.padEnd(14);
        const bindPad = sym.binding.padEnd(14);
        text += `${namePad} ${addrPad} ${typePad} ${bindPad} ${sizeStr}\n`;
      }
      if (data.symbols.length > 50) {
        text += `... showing top 50 symbols. Check JSON report for full list.\n`;
      }
    } else {
      text += `No symbols found.\n`;
    }
    text += `\n`;

    // Signatures
    text += `[ SIGNATURE SCAN RESULTS ]\n`;
    text += `--------------------------------------------------------------------------------\n`;
    if (data.signatures && data.signatures.length > 0) {
      for (const sig of data.signatures) {
        const matchesStr = sig.matches
          .map((m) => `0x${m.offset.toString(16).toUpperCase()} (${m.patternType})`)
          .join(', ');
        text += `Rule Name: ${sig.ruleName}\n`;
        text += `Category:  ${sig.category}\n`;
        text += `Matches:   ${matchesStr}\n`;
        text += `--------------------------------------------------------------------------------\n`;
      }
    } else {
      text += `No signatures matched.\n\n`;
    }

    // High Entropy Blocks
    text += `[ HIGH ENTROPY BLOCKS ]\n`;
    text += `--------------------------------------------------------------------------------\n`;
    if (data.entropy.highEntropyBlocks && data.entropy.highEntropyBlocks.length > 0) {
      text += `Start Offset   End Offset     Length         Entropy\n`;
      text += `--------------------------------------------------------------------------------\n`;
      for (const block of data.entropy.highEntropyBlocks) {
        const startPad = `0x${block.start.toString(16).toUpperCase()}`.padEnd(14);
        const endPad = `0x${block.end.toString(16).toUpperCase()}`.padEnd(14);
        const lenPad = `${block.length} B`.padEnd(14);
        text += `${startPad} ${endPad} ${lenPad} ${block.entropy.toFixed(4)}\n`;
      }
    } else {
      text += `No high entropy blocks detected.\n`;
    }
    text += `\n`;

    // Strings
    text += `[ STRINGS (Top 100) ]\n`;
    text += `--------------------------------------------------------------------------------\n`;
    if (data.strings && data.strings.length > 0) {
      text += `Offset     Address    Encoding   Tags                 Value\n`;
      text += `--------------------------------------------------------------------------------\n`;
      const displayedStrings = data.strings.slice(0, 100);
      for (const str of displayedStrings) {
        const tagsStr = str.tags.length > 0 ? str.tags.join(', ') : '-';
        const offPad = `0x${str.offset.toString(16).toUpperCase()}`.padEnd(10);
        const addrPad = `0x${str.virtualAddress.toString(16).toUpperCase()}`.padEnd(10);
        const encPad = str.encoding.padEnd(10);
        const tagsPad = (tagsStr.length > 19 ? tagsStr.slice(0, 16) + '...' : tagsStr).padEnd(20);
        const valStr = str.value.replace(/\n/g, '\\n').replace(/\r/g, '\\r');
        text += `${offPad} ${addrPad} ${encPad} ${tagsPad} ${valStr}\n`;
      }
      if (data.strings.length > 100) {
        text += `... showing top 100 strings. Check JSON report for full list.\n`;
      }
    } else {
      text += `No strings extracted.\n`;
    }
    text += `\n`;

    // PE Resources section if it exists
    if (
      data.binaryData &&
      data.binaryData.length > 64 &&
      data.binaryData[0] === 0x4d &&
      data.binaryData[1] === 0x5a
    ) {
      try {
        const peParser = new PEParser(data.binaryData.buffer as ArrayBuffer);
        const pe = peParser.parse();
        if (pe.resources && pe.resources.all && pe.resources.all.length > 0) {
          const r = pe.resources;
          text += `[ PE RESOURCES (.rsrc) ]\n`;
          text += `--------------------------------------------------------------------------------\n`;
          text += `Type Name            Name/ID              Lang ID    Size       Offset\n`;
          text += `--------------------------------------------------------------------------------\n`;
          for (const res of r.all) {
            const typePad = res.typeName.padEnd(20);
            const namePad = String(res.name).padEnd(20);
            const langPad = String(res.language).padEnd(10);
            const sizePad = `${res.size} B`.padEnd(10);
            const offPad = `0x${res.offset.toString(16).toUpperCase()}`;
            text += `${typePad} ${namePad} ${langPad} ${sizePad} ${offPad}\n`;
          }
          text += `\n`;

          if (r.manifests && r.manifests.length > 0) {
            text += `[ PE MANIFESTS ]\n`;
            for (const m of r.manifests) {
              text += `--------------------------------------------------------------------------------\n`;
              text += `${m}\n`;
            }
            text += `\n`;
          }

          const stringKeys = Object.keys(r.strings);
          if (stringKeys.length > 0) {
            text += `[ PE STRING TABLES ]\n`;
            text += `--------------------------------------------------------------------------------\n`;
            for (const k of stringKeys) {
              text += `ID ${k}: ${r.strings[Number(k)]}\n`;
            }
            text += `\n`;
          }

          if (r.icons && r.icons.length > 0) {
            text += `[ PE ICONS & GROUP ICONS ]\n`;
            text += `--------------------------------------------------------------------------------\n`;
            text += `Type                 Size       File Offset\n`;
            text += `--------------------------------------------------------------------------------\n`;
            for (const i of r.icons) {
              const typePad = String(i.type).padEnd(20);
              const sizePad = `${i.size} B`.padEnd(10);
              const offPad = `0x${i.offset.toString(16).toUpperCase()}`;
              text += `${typePad} ${sizePad} ${offPad}\n`;
            }
            text += `\n`;
          }
        }
      } catch {
        // Ignore PE parsing errors
      }
    }

    return text;
  }
}

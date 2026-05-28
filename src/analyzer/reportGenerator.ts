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

    if (data.binaryData && data.binaryData.length > 64 && data.binaryData[0] === 0x4d && data.binaryData[1] === 0x5a) {
      try {
        const peParser = new PEParser(data.binaryData.buffer);
        const pe = peParser.parse();
        if (pe.resources) {
          reportObj.peResources = {
            manifests: pe.resources.manifests,
            stringsCount: Object.keys(pe.resources.strings).length,
            iconsCount: pe.resources.icons.length,
            allResources: pe.resources.all.map(r => ({
              typeName: r.typeName,
              name: r.name,
              language: r.language,
              size: r.size,
              offset: r.offset
            }))
          };
        }
      } catch (e) {
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
          sec.flags.execute ? 'X' : '-'
        ].join('');
        const entropyVal = sec.entropy !== undefined ? sec.entropy.toFixed(4) : 'N/A';
        md += `| \`${sec.name}\` | 0x${sec.virtualAddress.toString(16).toUpperCase()} | ${formatSize(sec.virtualSize)} | 0x${sec.fileOffset.toString(16).toUpperCase()} | ${formatSize(sec.fileSize)} | ${entropyVal} | \`${flagsStr}\` |\n`;
      }
    } else {
      md += `No sections found.\n`;
    }
    md += `\n`;

    // Symbols List
    md += `## 🏷️ Symbols\n\n`;
    const funcSyms = data.symbols.filter(s => s.type === 'function');
    const otherSyms = data.symbols.filter(s => s.type !== 'function');
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
        const matchesStr = sig.matches.map(m => `0x${m.offset.toString(16).toUpperCase()} (${m.patternType})`).join(', ');
        md += `| **${sig.ruleName}** | \`${sig.category}\` | ${matchesStr} |\n`;
      }
    } else {
      md += `No signatures matched.\n`;
    }
    md += `\n`;

    // Entropy Blocks
    md += `## 📈 High Entropy Blocks\n\n`;
    if (data.entropy.highEntropyBlocks && data.entropy.highEntropyBlocks.length > 0) {
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
        const tagsStr = str.tags.length > 0 ? str.tags.map(t => `\`${t}\``).join(', ') : '-';
        const escapedValue = str.value.replace(/\|/g, '\\|').replace(/\n/g, '\\n').replace(/\r/g, '\\r');
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
    if (data.binaryData && data.binaryData.length > 64 && data.binaryData[0] === 0x4d && data.binaryData[1] === 0x5a) {
      try {
        const peParser = new PEParser(data.binaryData.buffer);
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
      } catch (e) {
        // Ignore PE parsing errors
      }
    }

    return md;
  }
}

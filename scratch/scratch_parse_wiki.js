import fs from 'fs';

const htmlPath = 'C:\\Users\\NaThA\\.gemini\\antigravity-cli\\brain\\56b9719a-1144-4a2f-af93-ce8b331253d4\\.system_generated\\steps\\27\\content.md';
const html = fs.readFileSync(htmlPath, 'utf8');

// Find all tables
const tableRegex = /<table[^>]*class="wikitable[^"]*"[^>]*>([\s\S]*?)<\/table>/g;
const opcodes = [];

let match;
while ((match = tableRegex.exec(html)) !== null) {
  const tableContent = match[1];
  const trRegex = /<tr[^>]*>([\s\S]*?)<\/tr>/g;
  let trMatch;
  
  // Skip header row
  trRegex.exec(tableContent);
  
  while ((trMatch = trRegex.exec(tableContent)) !== null) {
    const trContent = trMatch[1];
    const tdRegex = /<td[^>]*>([\s\S]*?)<\/td>/g;
    const cols = [];
    let tdMatch;
    while ((tdMatch = tdRegex.exec(trContent)) !== null) {
      cols.push(tdMatch[1].replace(/<[^>]*>/g, '').trim());
    }
    
    if (cols.length >= 3) {
      opcodes.push({
        op: cols[0],
        inst: cols[1],
        desc: cols[2],
        type: cols[3] || ''
      });
    }
  }
}

fs.writeFileSync('opcodes.json', JSON.stringify(opcodes, null, 2));
console.log(`Extracted ${opcodes.length} opcodes`);

const fs = require('fs');
const content = fs.readFileSync('src/disassembler/router.ts', 'utf8');
const lines = content.split('\n');

let openBraces = 0;
let inString = false;
let stringChar = '';

for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  let lineBracesOpen = 0;
  let lineBracesClose = 0;
  
  for (let j = 0; j < line.length; j++) {
    const char = line[j];
    
    // Simple comment check
    if (!inString && char === '/' && line[j+1] === '/') {
      break; // Ignore rest of line
    }
    
    if ((char === '"' || char === "'" || char === '`') && line[j-1] !== '\\') {
      if (!inString) {
        inString = true;
        stringChar = char;
      } else if (char === stringChar) {
        inString = false;
      }
    }
    
    if (!inString) {
      if (char === '{') {
        openBraces++;
        lineBracesOpen++;
      } else if (char === '}') {
        openBraces--;
        lineBracesClose++;
      }
    }
  }
  
  // print line brace count if it changed
  console.log(`${i+1}: bracesOpen=${lineBracesOpen}, bracesClose=${lineBracesClose}, totalOpen=${openBraces} | ${line.trim().substring(0, 40)}`);
}

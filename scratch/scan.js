const fs = require('fs');
const path = require('path');

function scanDir(dir) {
  fs.readdirSync(dir).forEach(file => {
    const full = path.join(dir, file);
    if (fs.statSync(full).isDirectory()) {
      if (file !== 'node_modules' && file !== '.git' && file !== 'dist') {
        scanDir(full);
      }
    } else if (file.endsWith('.ts') || file.endsWith('.js')) {
      const content = fs.readFileSync(full, 'utf8');
      
      // Look for relative import/export paths in quotes
      // Find all matches for strings starting with ./ or ../ inside quotes
      // e.g. './foo' or "../foo"
      const regex = /['"](\.\.?\/[^'"]+)['"]/g;
      let match;
      while ((match = regex.exec(content)) !== null) {
        const importPath = match[1];
        if (!importPath.endsWith('.js') && !importPath.endsWith('.css') && !importPath.endsWith('.html') && !importPath.endsWith('.json') && !importPath.endsWith('.wasm')) {
          // Find line number
          const offset = match.index;
          const linesBefore = content.substring(0, offset).split('\n');
          const lineNum = linesBefore.length;
          const lineContent = content.split('\n')[lineNum - 1];
          console.log(JSON.stringify({
            file: full.replace(/\\/g, '/'),
            line: lineNum,
            importPath: importPath,
            content: lineContent.trim()
          }));
        }
      }
    }
  });
}

scanDir('src');
scanDir('tests');

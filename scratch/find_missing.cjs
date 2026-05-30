const fs = require('fs');
const path = require('path');

// Recursive file finder
function getFiles(dir) {
  let results = [];
  const list = fs.readdirSync(dir);
  list.forEach((file) => {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat && stat.isDirectory()) {
      if (file !== 'node_modules' && file !== '.git' && file !== 'dist') {
        results = results.concat(getFiles(fullPath));
      }
    } else {
      if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.tsx') || file.endsWith('.jsx')) {
        results.push(fullPath);
      }
    }
  });
  return results;
}

const files = getFiles('src');

files.forEach(file => {
  const content = fs.readFileSync(file, 'utf8');
  
  // Find all import and export statements
  // Specifically we want:
  // import ... from "..."
  // export ... from "..."
  // import "..."
  // import(...)
  
  const regexes = [
    /import\s+[\s\S]*?\s+from\s+['"`](\.\.?\/[^'"`]+)['"`]/g,
    /export\s+[\s\S]*?\s+from\s+['"`](\.\.?\/[^'"`]+)['"`]/g,
    /import\s+['"`](\.\.?\/[^'"`]+)['"`]/g,
    /import\(\s*['"`](\.\.?\/[^'"`]+)['"`]\s*\)/g
  ];

  regexes.forEach(regex => {
    let match;
    while ((match = regex.exec(content)) !== null) {
      const importPath = match[1];
      if (!importPath.endsWith('.js') && !importPath.endsWith('.css') && !importPath.endsWith('.html') && !importPath.endsWith('.json') && !importPath.endsWith('.wasm')) {
        console.log(`MISSING EXTENSION: File: ${file}, Import: ${importPath}`);
      }
    }
  });
});
console.log("Done checking.");

const fs = require('fs');
const path = require('path');

function processDir(dir) {
  fs.readdirSync(dir).forEach(file => {
    const full = path.join(dir, file);
    if (fs.statSync(full).isDirectory()) {
      if (file !== 'node_modules' && file !== '.git' && file !== 'dist') {
        processDir(full);
      }
    } else if (file.endsWith('.ts') || file.endsWith('.js')) {
      let content = fs.readFileSync(full, 'utf8');
      let changed = false;

      // Regex matches: 'import ... from './path'' or 'export ... from './path'' or dynamic 'import('./path')'
      // We look for any relative path starting with ./ or ../ inside quotes that doesn't end with a known extension.
      const regex = /(['"])(\.\.?\/[^'"]+)(['"])/g;
      
      const newContent = content.replace(regex, (match, q1, importPath, q2) => {
        if (!importPath.endsWith('.js') && 
            !importPath.endsWith('.css') && 
            !importPath.endsWith('.html') && 
            !importPath.endsWith('.json') && 
            !importPath.endsWith('.wasm')) {
          changed = true;
          console.log(`Fixing import in ${full}: ${importPath} -> ${importPath}.js`);
          return `${q1}${importPath}.js${q2}`;
        }
        return match;
      });

      if (changed) {
        fs.writeFileSync(full, newContent, 'utf8');
      }
    }
  });
}

processDir('src');
processDir('tests');
console.log('Fixing complete.');

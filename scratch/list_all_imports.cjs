const fs = require('fs');
const path = require('path');

function scanDir(dir) {
  fs.readdirSync(dir).forEach((file) => {
    const full = path.join(dir, file);
    if (fs.statSync(full).isDirectory()) {
      if (file !== 'node_modules' && file !== '.git' && file !== 'dist') {
        scanDir(full);
      }
    } else if (file.endsWith('.ts') || file.endsWith('.js')) {
      const content = fs.readFileSync(full, 'utf8');

      // Look for any string starting with ./ or ../ inside quotes
      const regex = /['"](\.\.?\/[^'"]+)['"]/g;
      let match;
      while ((match = regex.exec(content)) !== null) {
        const importPath = match[1];
        console.log(`${full}: ${importPath}`);
      }
    }
  });
}

scanDir('src');

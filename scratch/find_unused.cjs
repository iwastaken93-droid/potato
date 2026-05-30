const fs = require('fs');
const path = require('path');

const srcDir = path.resolve(__dirname, '../src');

// Find all TS/JS files in src (excluding node_modules, etc)
function getAllFiles(dir, files = []) {
  const list = fs.readdirSync(dir);
  for (const file of list) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      if (file !== 'node_modules' && file !== 'coverage') {
        getAllFiles(fullPath, files);
      }
    } else {
      if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.css') || file.endsWith('.html')) {
        files.push(fullPath);
      }
    }
  }
  return files;
}

const allFiles = getAllFiles(srcDir);

// Dependency map: file -> list of imported files
const deps = {};
// Initialize deps
for (const file of allFiles) {
  deps[file] = [];
}

// Parse imports
for (const file of allFiles) {
  if (!file.endsWith('.ts') && !file.endsWith('.js')) continue;
  const content = fs.readFileSync(file, 'utf8');
  // Match import statements
  // import ... from '...' or import '...' or export ... from '...'
  const regex = /(?:import|export)\s+(?:[\w\s{},*]*\s+from\s+)?['"](\.\.?\/[^'"]+)['"]/g;
  let match;
  while ((match = regex.exec(content)) !== null) {
    let importPath = match[1];
    // Resolve importPath relative to file
    let resolved = path.resolve(path.dirname(file), importPath);
    // Try adding extension if it doesn't match a file directly
    let fileCandidates = [
      resolved,
      resolved + '.ts',
      resolved + '.js',
      resolved.replace(/\.js$/, '.ts'), // since rule says imports must use .js but files are actually .ts
      resolved.replace(/\.js$/, ''),
    ];
    let found = false;
    for (const cand of fileCandidates) {
      if (fs.existsSync(cand) && !fs.statSync(cand).isDirectory()) {
        deps[file].push(cand);
        found = true;
        break;
      }
    }
    if (!found) {
      // Maybe it is a directory index or similar, or just not found
    }
  }
}

// Let's also check if any workers are referenced by string URL, etc.
// Look for binaryProcessor.worker.ts or .js references
for (const file of allFiles) {
  const content = fs.readFileSync(file, 'utf8');
  if (content.includes('binaryProcessor.worker')) {
    const workerPath = path.resolve(srcDir, 'analyzer/binaryProcessor.worker.ts');
    if (fs.existsSync(workerPath)) {
      deps[file].push(workerPath);
    }
  }
}

// Traverse starting from src/main.ts and src/index.html
const entryPoints = [
  path.resolve(srcDir, 'index.html'),
  path.resolve(srcDir, 'main.ts')
];
const visited = new Set();

function traverse(file) {
  if (visited.has(file)) return;
  visited.add(file);
  const imports = deps[file] || [];
  for (const imp of imports) {
    traverse(imp);
  }
}

// We should also check styles.css, since it's referenced in index.html
const stylesCss = path.resolve(srcDir, 'styles.css');
if (fs.existsSync(stylesCss)) {
  visited.add(stylesCss);
}

for (const entry of entryPoints) {
  traverse(entry);
}

console.log('--- Reachable files in src ---');
console.log(`Total reachable: ${visited.size}`);

console.log('\n--- Unreachable files in src (Dead Code/Unused Assets) ---');
let unreachableCount = 0;
for (const file of allFiles) {
  if (!visited.has(file)) {
    console.log(path.relative(srcDir, file));
    unreachableCount++;
  }
}
console.log(`Total unreachable: ${unreachableCount}`);

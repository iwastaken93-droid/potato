import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

// 1. Get modified files list from git status
const gitStatus = execSync('git status --porcelain', { encoding: 'utf-8' });
const lines = gitStatus.split('\n');
const modifiedFiles = [];
const untrackedFiles = [];

for (const line of lines) {
  if (!line.trim()) continue;
  const status = line.substring(0, 2);
  const file = line.substring(3).trim();
  if (file.startsWith('src/') || file.startsWith('tests/')) {
    if (status.includes('M') || status.includes('A')) {
      modifiedFiles.push(file);
    } else if (status.includes('??')) {
      untrackedFiles.push(file);
    }
  }
}

console.log('Modified Files:', modifiedFiles);
console.log('Untracked Files:', untrackedFiles);

// Regex to capture imports:
// Matches import ... from '...' or import '...'
// Also dynamic import('...')
const importRegex = /(?:import\s+[\s\S]*?\s+from\s+['"]([^'"]+)['"])|(?:import\s*\(?\s*['"]([^'"]+)['"]\)?)/g;

function checkImportPath(importPath, filePath) {
  // We only care about relative imports (starting with ./ or ../)
  if (importPath.startsWith('.') || importPath.startsWith('/')) {
    if (!importPath.endsWith('.js') && !importPath.endsWith('.json') && !importPath.endsWith('.wasm')) {
      console.log(`INVALID IMPORT in ${filePath}: "${importPath}"`);
      return false;
    }
  }
  return true;
}

// Check newly added/modified imports
console.log('\n--- Scanning Git Diff for new/modified imports ---');
for (const file of modifiedFiles) {
  try {
    const diff = execSync(`git diff HEAD -- "${file}"`, { encoding: 'utf-8' });
    const diffLines = diff.split('\n');
    for (const dl of diffLines) {
      if (dl.startsWith('+') && !dl.startsWith('+++')) {
        // scan this line for import
        let match;
        // reset regex state
        importRegex.lastIndex = 0;
        while ((match = importRegex.exec(dl)) !== null) {
          const imp = match[1] || match[2];
          if (imp) {
            checkImportPath(imp, file);
          }
        }
      }
    }
  } catch (err) {
    console.error(`Error diffing ${file}:`, err.message);
  }
}

console.log('\n--- Scanning Untracked Files ---');
for (const file of untrackedFiles) {
  if (fs.statSync(file).isDirectory()) continue;
  try {
    const content = fs.readFileSync(file, 'utf-8');
    let match;
    // reset regex state
    importRegex.lastIndex = 0;
    while ((match = importRegex.exec(content)) !== null) {
      const imp = match[1] || match[2];
      if (imp) {
        checkImportPath(imp, file);
      }
    }
  } catch (err) {
    console.error(`Error reading untracked ${file}:`, err.message);
  }
}

import { execSync } from 'child_process';
import fs from 'fs';

try {
  // Get git status to find untracked files
  const gitStatus = execSync('git status --porcelain', { encoding: 'utf-8' });
  const lines = gitStatus.split('\n');
  const untrackedFiles = [];
  for (const line of lines) {
    if (line.startsWith('?? ')) {
      const file = line.substring(3).trim();
      if ((file.startsWith('src/') || file.startsWith('tests/')) && !fs.statSync(file).isDirectory()) {
        untrackedFiles.push(file);
      }
    }
  }

  console.log('Untracked files to check:', untrackedFiles);

  // We want to extract import paths from relative imports.
  // Match relative import paths: starting with ./ or ../ or a file path containing no node_modules.
  // Note: standard ESM relative imports start with .
  const importRegex = /(?:import\s+[\s\S]*?\s+from\s+['"]([^'"]+)['"])|(?:import\s*\(?\s*['"]([^'"]+)['"]\)?)/g;

  function checkImport(imp, file, context) {
    if (imp.startsWith('.')) {
      if (!imp.endsWith('.js') && !imp.endsWith('.json') && !imp.endsWith('.wasm')) {
        console.log(`INVALID: File "${file}" has relative import "${imp}" (missing .js extension) in: "${context}"`);
      }
    }
  }

  // 1. Get git diff of modified files (all at once)
  console.log('\n--- Scanning git diff of modified files ---');
  const diff = execSync('git diff HEAD -- src/ tests/', { encoding: 'utf-8' });
  const diffLines = diff.split('\n');
  let currentFile = '';
  for (const line of diffLines) {
    if (line.startsWith('diff --git ')) {
      const parts = line.split(' ');
      // parts[3] is b/path/to/file
      currentFile = parts[3].substring(2);
    } else if (line.startsWith('+') && !line.startsWith('+++')) {
      const addedText = line.substring(1);
      importRegex.lastIndex = 0;
      let match;
      while ((match = importRegex.exec(addedText)) !== null) {
        const imp = match[1] || match[2];
        if (imp) {
          checkImport(imp, currentFile, addedText.trim());
        }
      }
    }
  }

  // 2. Scan untracked files completely
  console.log('\n--- Scanning untracked files ---');
  for (const file of untrackedFiles) {
    const content = fs.readFileSync(file, 'utf-8');
    const contentLines = content.split('\n');
    for (const line of contentLines) {
      importRegex.lastIndex = 0;
      let match;
      while ((match = importRegex.exec(line)) !== null) {
        const imp = match[1] || match[2];
        if (imp) {
          checkImport(imp, file, line.trim());
        }
      }
    }
  }

} catch (err) {
  console.error(err);
}

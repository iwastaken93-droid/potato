import fs from 'node:fs';
import path from 'node:path';

const devlogPath = path.resolve('DEVLOG.md');

if (!fs.existsSync(devlogPath)) {
  console.error('DEVLOG.md not found');
  process.exit(1);
}

const content = fs.readFileSync(devlogPath, 'utf8');
const lines = content.split(/\r?\n/);

console.log(`Read DEVLOG.md with ${lines.length} lines.`);

// Let's parse by sections.
// A section starts with a heading like `## Session <N>` or `# <Title>`
// We want to detect duplicate Session headings, and merge their contents, and deduplicate list items inside them.

const sections = [];
let currentSection = { heading: null, lines: [], level: 0 };

for (const line of lines) {
  const headingMatch = line.match(/^(#{1,6})\s+(.*)$/);
  if (headingMatch) {
    if (currentSection.lines.length > 0 || currentSection.heading !== null) {
      sections.push(currentSection);
    }
    currentSection = {
      heading: line,
      level: headingMatch[1].length,
      title: headingMatch[2].trim(),
      lines: []
    };
  } else {
    currentSection.lines.push(line);
  }
}
if (currentSection.lines.length > 0 || currentSection.heading !== null) {
  sections.push(currentSection);
}

console.log(`Found ${sections.length} total sections/headings.`);

// Merge duplicate sections that have the same heading
const mergedSections = [];
const headingMap = new Map();

for (const sec of sections) {
  if (sec.heading) {
    const key = sec.heading.toLowerCase().trim();
    if (headingMap.has(key)) {
      console.log(`Duplicate section heading found: "${sec.heading}". Merging...`);
      const existingSec = headingMap.get(key);
      // Append lines
      existingSec.lines.push(...sec.lines);
    } else {
      headingMap.set(key, sec);
      mergedSections.push(sec);
    }
  } else {
    // Lead-in/frontmatter section without a heading (should be first)
    mergedSections.push(sec);
  }
}

// Now, for each section, let's deduplicate its lines.
// We should be careful: we only want to deduplicate bullet points (- item) or tasks, and keep empty lines or structural tables if possible.
// Actually, let's deduplicate:
// 1. Duplicate consecutive empty lines (reduce to single empty line).
// 2. Duplicate bullet points / markdown list items (- / *) within the same section.
// 3. Keep other lines.

for (const sec of mergedSections) {
  const newLines = [];
  const seenBullets = new Set();
  let lastLineWasEmpty = false;

  for (let i = 0; i < sec.lines.length; i++) {
    const line = sec.lines[i];
    const trimmed = line.trim();

    if (trimmed === '') {
      if (!lastLineWasEmpty) {
        newLines.push(line);
        lastLineWasEmpty = true;
      }
      continue;
    }
    lastLineWasEmpty = false;

    // Check if it is a list item/bullet point
    const bulletMatch = trimmed.match(/^[-*+]\s+(.*)$/);
    if (bulletMatch) {
      const bulletContent = bulletMatch[1].toLowerCase().trim();
      if (seenBullets.has(bulletContent)) {
        console.log(`Removing duplicate list item in "${sec.title}": "${trimmed}"`);
        continue; // skip duplicate bullet
      }
      seenBullets.add(bulletContent);
    }

    // Also deduplicate table rows if they are exactly identical
    if (trimmed.startsWith('|') && trimmed.endsWith('|')) {
      const tableRowContent = trimmed.toLowerCase().replace(/\s+/g, '');
      // If we already saw this identical table row in this section, skip it (unless it is a header divider like |---|---|)
      if (tableRowContent.includes('-') && !tableRowContent.replace(/\||-/g, '')) {
        // it's a divider line, keep it
      } else {
        if (seenBullets.has(tableRowContent)) {
          console.log(`Removing duplicate table row in "${sec.title}": "${trimmed}"`);
          continue;
        }
        seenBullets.add(tableRowContent);
      }
    }

    newLines.push(line);
  }
  sec.lines = newLines;
}

// Reconstruct the file content
const outputLines = [];
for (const sec of mergedSections) {
  if (sec.heading) {
    outputLines.push(sec.heading);
  }
  outputLines.push(...sec.lines);
}

// Ensure the file ends with a single newline
let finalContent = outputLines.join('\n');
if (!finalContent.endsWith('\n')) {
  finalContent += '\n';
}

fs.writeFileSync(devlogPath, finalContent, 'utf8');
console.log('DEVLOG.md verified, cleaned, and written.');

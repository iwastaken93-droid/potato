# 💻 Developer Setup & Engineering Guidelines

This document outlines the local setup, tooling configuration, testing standards, and development scripts for extending and maintaining DISSECT.

---

## 📋 Prerequisites

DISSECT is built using modern TypeScript (ESNext target) and utilizes `bun` as its primary package manager.

- **Runtime & Package Manager**: `bun` (mandatory rule).

---

## 🚀 Running Commands

Inside the project root directory, run these scripts to execute operations:

### 📦 Package Installation

Bootstrap development libraries and project modules:

```bash
bun install
```

### 🏃 Running Locally (Development)

Launches Vite's local dev server at `http://localhost:5173`. Modifying components or styles triggers Hot Module Replacement (HMR) instantly.

```bash
bun run dev
```

### 🧪 Executing Unit Tests

DISSECT uses **Vitest** for running unit test suites. Run tests with:

```bash
bun run test
```

The test suite validates parser correctness, CPU emulator execution (registers, flags, virtual memory paging), decompiler AST mapping, and UI utility components.

### 🏗️ Compiling a Production Build

Bundles the code, styles, and template files into the production-ready static assets directory `dist/`:

```bash
bun run build
```

---

## 🛠️ Code Styling & Quality Assurance

To ensure codebase cleanliness and standard formatting across files, DISSECT includes:

### Prettier Styling Formatting

Prettier rules are specified in [.prettierrc](file:///home/myname/projects/potato/.prettierrc) to govern tab sizing, bracket spacing, and quote preferences:

- **Tab Width**: 2 spaces
- **Quotes**: Single quotes
- **Trailing Commas**: ES5 compliance

### ESLint Rules

Linting logic is declared in [eslint.config.js](file:///home/myname/projects/potato/eslint.config.js) leveraging TypeScript recommended practices.

### TypeScript Compilation Constraints

Configure configurations in [tsconfig.json](file:///home/myname/projects/potato/tsconfig.json):

- **Module Resolution**: `node16` / `nodenext` configuration is enforced, which mandates that all relative imports must include standard `.js` file extensions.
- **Bitness/Bignum Compatibility**: Requires the target version to support native JavaScript ESNext/ES2020 features (specifically `BigInt` operations).
- **Strict Checks**: `noImplicitAny: true` and `strict: true` settings are turned on to prevent type bypasses.

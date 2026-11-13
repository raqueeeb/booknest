// Every backend route is served under /api. A call that omits the prefix still
// passes authentication and then matches no controller, which the server reports
// as a generic 500 — so the mistake looks like a server fault rather than a
// wrong URL. Six calls were wrong this way, including the password change.
//
// Run with: npm run check:api-paths
import fs from 'node:fs';
import path from 'node:path';

const SRC = path.join(import.meta.dirname, '..', 'src');
const CALL = /API\.(get|post|put|delete|patch)\(\s*(["'`])([^"'`]*)/g;

const problems = [];
(function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) { walk(full); continue; }
    if (!/\.(jsx?|tsx?)$/.test(entry.name)) continue;
    const text = fs.readFileSync(full, 'utf8');
    text.split(/\r?\n/).forEach((line, i) => {
      for (const m of line.matchAll(CALL)) {
        const url = m[3];
        if (!url.startsWith('/')) continue; // absolute URL or a variable: not ours to judge
        if (!url.startsWith('/api/')) {
          problems.push(`${path.relative(SRC, full).split(path.sep).join('/')}:${i + 1}  ${m[1].toUpperCase()} ${url}`);
        }
      }
    });
  }
})(SRC);

if (problems.length) {
  console.error('API calls missing the /api prefix:');
  for (const p of problems) console.error('  - ' + p);
  process.exit(1);
}
console.log('check-api-paths: every API call uses the /api prefix');

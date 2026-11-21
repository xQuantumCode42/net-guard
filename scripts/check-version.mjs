import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const root = new URL('../', import.meta.url);
const expected = '1.0.0';
for (const name of ['apps/desktop/package.json', 'apps/desktop/package-lock.json', 'apps/desktop/src-tauri/tauri.conf.json']) {
  const value = JSON.parse(readFileSync(new URL(name, root), 'utf8'));
  if (value.version !== expected) throw new Error(`Version mismatch: ${name}`);
}
const cargo = readFileSync(new URL('Cargo.toml', root), 'utf8');
if (!cargo.includes(`version = "${expected}"`)) throw new Error('Rust workspace version mismatch');
console.log(`Verified ${expected} in ${fileURLToPath(root)}; no version changed.`);

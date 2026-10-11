// Executes every cookbook snippet meant for Node. Pass = exit 0 for each.
import { readdirSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';

const snippetsDir = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'snippets');
const failures = [];
for (const dir of ['node', 'wasm']) {
  for (const file of readdirSync(join(snippetsDir, dir)).sort()) {
    if (!file.endsWith('.js')) continue;
    const path = join(snippetsDir, dir, file);
    const result = spawnSync(process.execPath, [path], { encoding: 'utf8' });
    if (result.status !== 0) {
      failures.push(`${dir}/${file} (exit ${result.status})\n${result.stderr}`);
    }
  }
}
if (failures.length) {
  console.error(`FAILED ${failures.length} snippet(s):\n${failures.join('\n---\n')}`);
  process.exit(1);
}
console.log('All snippets passed.');
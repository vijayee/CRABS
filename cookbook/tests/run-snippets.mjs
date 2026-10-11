// Executes every cookbook snippet meant for Node. Pass = exit 0 for each.
// C snippets are excluded here deliberately — they run via cookbook/tests/run-c.sh.
import { readdirSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';

const snippetsDir = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'snippets');
const failures = [];
let executed = 0;
for (const dir of ['node', 'wasm']) {
  for (const file of readdirSync(join(snippetsDir, dir)).sort()) {
    if (!file.endsWith('.js')) continue;
    executed += 1;
    const path = join(snippetsDir, dir, file);
    const result = spawnSync(process.execPath, [path], { encoding: 'utf8' });
    if (result.status !== 0) {
      const cause = result.status === null && result.signal
        ? `killed by ${result.signal}`
        : `exit ${result.status}`;
      failures.push(`${dir}/${file} (${cause})\n${result.stderr}${result.stdout}`);
    }
  }
}
if (executed === 0) {
  console.error('No snippets found under any of the scanned directories — harness is not covering anything.');
  process.exit(1);
}
if (failures.length) {
  console.error(`FAILED ${failures.length} snippet(s):\n${failures.join('\n---\n')}`);
  process.exit(1);
}
console.log(`All ${executed} snippet(s) passed.`);
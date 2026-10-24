import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const workspace = dirname(dirname(fileURLToPath(import.meta.url)));
const temporaryRoot = resolve(tmpdir());
const dataRoot = mkdtempSync(join(temporaryRoot, 'rustsign-tests-'));

try {
  const result = spawnSync(
    'cargo',
    [
      'test',
      '--package',
      'rustsign',
      '--lib',
      '--tests',
      ...process.argv.slice(2),
      '--',
      '--test-threads=1',
    ],
    {
      cwd: workspace,
      stdio: 'inherit',
      env: { ...process.env, RUSTSIGN_DATA_DIR: dataRoot },
    },
  );
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
} finally {
  if (dirname(resolve(dataRoot)) !== temporaryRoot) {
    throw new Error('Test data root is outside the temporary directory.');
  }
  rmSync(dataRoot, { recursive: true, force: true });
}

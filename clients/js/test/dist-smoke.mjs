// Loads the BUILT package (not the TypeScript sources the suite runs) and identifies one request through it: the
// entry points resolve, the Node adapter is there, and the compiled client applies spec v2 (Remote-Kind).
//
//   node test/dist-smoke.mjs [dist directory]      (default: ./dist)
//
// Run by the CI workflow client-js after `npm run build` and by scripts/check.sh against a build in a throwaway
// directory. Until 2026-11-22 this check lived inline in the workflow only, so check.sh never ran it and a request
// without Remote-Kind reached the CI first.

import path from 'node:path';
import { pathToFileURL } from 'node:url';

const dist = path.resolve(process.argv[2] ?? 'dist');
const load = (file) => import(pathToFileURL(path.join(dist, file)).href);

const gate = await load('index.js');
const node = await load('node.js');
const g = await gate.createGate({ mode: 'header' });
const id = await g.identify({
  headers: [
    ['Remote-User', 'anna'],
    ['Remote-Auth', 'session'],
    ['Remote-Kind', 'user'],
  ],
});
if (id.user !== 'anna' || !id.isSession() || id.accountKind !== 'user' || typeof node.gateMiddleware !== 'function') {
  console.error('the built package does not identify the request as expected');
  process.exit(1);
}
let refused = false;
try {
  await g.identify({ headers: [['Remote-User', 'anna']] });
} catch (err) {
  refused = err instanceof gate.GateError && err.code === 'header';
}
if (!refused) {
  console.error('the built package accepts a request without Remote-Kind (spec v2)');
  process.exit(1);
}
console.log(`dist loads and identifies (${dist})`);

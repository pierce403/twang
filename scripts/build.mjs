import { cp, mkdir, rm, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const dist = path.join(root, 'dist');
await access(path.join(root, 'app/transport.mjs'));
await rm(dist, {recursive:true, force:true});
await mkdir(dist, {recursive:true});
await cp(path.join(root, 'public'), dist, {recursive:true});
await cp(path.join(root, 'app'), path.join(dist, 'app'), {recursive:true});
console.log('Built Twang diagnostic interface in dist/.');

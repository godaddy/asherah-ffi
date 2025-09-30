/*
 Interoperability test between published asherah (npm) and local asherah-node (napi-rs)

 Usage:
   # Install published asherah and link local asherah-node
   npm run setup-local   # from repo root: cd interop && npm run setup-local
   npm run interop
*/
const path = require('path');
const fs = require('fs');

// Load published asherah from npm
let oldAsherah;
try { oldAsherah = require('asherah'); }
catch (e) { console.error('Please `npm install asherah` in interop/ first.'); process.exit(1); }

// Load local asherah-node addon
let newAsherah;
const npmLoader = path.resolve(__dirname, '..', 'asherah-node', 'npm', 'index.js');
if (fs.existsSync(npmLoader)) {
  newAsherah = require(npmLoader);
} else {
  // fallback to dev build
  const dev = path.resolve(__dirname, '..', 'target', 'debug', process.platform === 'win32' ? 'asherah_node.node' : 'asherah_node.node');
  try { newAsherah = require(dev); } catch (e) {
    console.error('Could not find local asherah-node build. Run `npm run setup-local` from interop/.');
    process.exit(1);
  }
}

// Ensure both use same static master key
if (!process.env.STATIC_MASTER_KEY_HEX) {
  process.env.STATIC_MASTER_KEY_HEX = '11'.repeat(32); // 32-byte key (hex)
}

const cfgNew = {
  serviceName: 'svc',
  productId: 'prod',
  metastore: 'memory',
  kms: 'static',
  enableSessionCaching: false,
};
const cfgOld = {
  ServiceName: 'svc',
  ProductID: 'prod',
  Metastore: 'memory',
  KMS: 'static',
  EnableSessionCaching: false,
};

function assert(cond, msg) { if (!cond) { throw new Error(msg || 'assertion failed'); } }

function toHex(buf) { return Buffer.from(buf).toString('hex'); }

function main() {
  console.log('Setting up old (npm) asherah...');
  oldAsherah.setup(cfgOld);
  console.log('Setting up new (local) asherah-node...');
  newAsherah.setup(cfgNew);
  const pid = 'p1';

  // old encrypt -> new decrypt
  let drrOld = oldAsherah.encrypt(pid, Buffer.from('hello-old'));
  assert(typeof drrOld === 'string' && drrOld.includes('"Key"'), 'old encrypt returned invalid DRR');
  // Normalize old DRR to Rust-expected JSON (convert base64 strings -> byte arrays)
  try {
    const obj = JSON.parse(drrOld);
    if (obj.Key && typeof obj.Key.Key === 'string') {
      obj.Key.Key = Array.from(Buffer.from(obj.Key.Key, 'base64'));
    }
    if (typeof obj.Data === 'string') {
      obj.Data = Array.from(Buffer.from(obj.Data, 'base64'));
    }
    drrOld = JSON.stringify(obj);
  } catch (e) { /* ignore, will fail below if incompatible */ }
  const outNew = newAsherah.decrypt(pid, drrOld);
  assert(Buffer.isBuffer(outNew) && outNew.toString() === 'hello-old', 'new decrypt did not match');
  console.log('old->new OK');

  // new encrypt -> old decrypt
  let drrNew = newAsherah.encrypt(pid, Buffer.from('hello-new'));
  assert(typeof drrNew === 'string' && drrNew.includes('"Key"'), 'new encrypt returned invalid DRR');
  // Normalize new DRR to old-expected JSON (convert byte arrays -> base64 strings)
  try {
    const obj = JSON.parse(drrNew);
    if (obj.Key && Array.isArray(obj.Key.Key)) {
      obj.Key.Key = Buffer.from(obj.Key.Key).toString('base64');
    }
    if (Array.isArray(obj.Data)) {
      obj.Data = Buffer.from(obj.Data).toString('base64');
    }
    drrNew = JSON.stringify(obj);
  } catch (e) { /* ignore */ }
  const outOld = oldAsherah.decrypt(pid, drrNew);
  assert(Buffer.isBuffer(outOld) && outOld.toString() === 'hello-new', 'old decrypt did not match');
  console.log('new->old OK');

  oldAsherah.shutdown();
  newAsherah.shutdown();
  console.log('Interop success');
}

main();

#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Find all built .node files
const nodeFiles = fs.readdirSync('.')
  .filter(f => f.startsWith('index.') && f.endsWith('.node'));

if (nodeFiles.length === 0) {
  console.error('No .node files found! Run the build script first.');
  process.exit(1);
}

console.log('Found binaries:', nodeFiles);

// Create platform-specific directories and copy binaries
const platformMap = {
  'index.darwin-arm64.node': 'darwin-arm64',
  'index.darwin-x64.node': 'darwin-x64',
  'index.linux-x64-gnu.node': 'linux-x64-gnu',
  'index.linux-arm64-gnu.node': 'linux-arm64-gnu',
  'index.win32-x64-msvc.node': 'win32-x64-msvc'
};

for (const file of nodeFiles) {
  const platform = platformMap[file];
  if (!platform) {
    console.warn(`Unknown platform for ${file}, skipping`);
    continue;
  }

  const dir = path.join('npm', platform);
  fs.mkdirSync(dir, { recursive: true });
  
  const targetName = `index.${platform}.node`;
  const target = path.join(dir, targetName);
  
  fs.copyFileSync(file, target);
  console.log(`✓ Copied ${file} to ${target}`);
}

console.log('\n✓ Universal package structure created!');
console.log('Now run: npm pack');

const fs = require('fs');

const lockContent = fs.readFileSync('package-lock.json', 'utf8');
const lockData = JSON.parse(lockContent);

console.log('Checking for main lodash package...');

// 1. Check root dependencies (packages[""].dependencies)
const rootPkg = lockData.packages[''] || {};
const rootDeps = rootPkg.dependencies || {};
console.log('Root dependencies:', rootDeps);
if (rootDeps.lodash) {
  console.log('✅ Found lodash in root dependencies: ' + rootDeps.lodash);
}

// 2. Check packages section
const packages = lockData.packages || {};
let found = false;
for (const [pkgName, pkgInfo] of Object.entries(packages)) {
  if (pkgName === 'lodash' || pkgName === 'node_modules/lodash') {
    console.log('✅ Found lodash in packages: ' + pkgInfo.version);
    found = true;
  }
}

if (!found && !rootDeps.lodash) {
  console.log('❌ lodash not found anywhere.');
}
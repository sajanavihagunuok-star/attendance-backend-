const fs = require('fs');
console.log('cwd:', process.cwd());
console.log('exists routes:', fs.existsSync('./routes'));
try {
  console.log('routes listing:', fs.readdirSync('./routes'));
} catch (e) {
  console.error('readdirSync error:', e.message);
}
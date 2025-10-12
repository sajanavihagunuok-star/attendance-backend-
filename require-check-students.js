try {
  console.log('node cwd:', process.cwd());
  console.log('require.resolve students:', require.resolve('./routes/students'));
} catch (e) {
  console.error('resolve error:', e && e.message);
}
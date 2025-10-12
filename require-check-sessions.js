try {
  console.log('cwd:', process.cwd());
  console.log('require.resolve sessions:', require.resolve('./routes/sessions'));
} catch (e) {
  console.error('resolve error:', e && e.message);
  console.error(e && e.stack);
}
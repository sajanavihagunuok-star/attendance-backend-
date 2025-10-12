try {
  console.log('require.resolve:', require.resolve('./routes/me'));
} catch (e) {
  console.error('resolve error:', e && e.message);
  console.error(e && e.stack);
}
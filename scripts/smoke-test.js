// scripts/smoke-test.js
const base = process.env.BASE_URL;
if (!base) {
  console.error('BASE_URL not set');
  process.exit(2);
}

async function check(path) {
  const url = `${base.replace(/\/$/, '')}${path}`;
  console.log('Checking', url);
  const res = await fetch(url, { method: 'GET' });
  const text = await res.text();
  if (!res.ok) {
    console.error(`FAIL ${url} -> ${res.status} ${res.statusText}`);
    console.error('Body:', text);
    process.exit(1);
  }
  console.log(`OK ${url} -> ${res.status}`);
  return text;
}

(async () => {
  try {
    await check('/ping');
    await check('/sessions?limit=1');
    console.log('Smoke tests passed');
    process.exit(0);
  } catch (err) {
    console.error('Smoke test error:', err && err.stack ? err.stack : err);
    process.exit(1);
  }
})();
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Supabase env vars missing: SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

/**
 * callWithRetry - wrapper for supabase calls with timeout and retry
 * - fn: async function that receives an AbortSignal and should perform supabase operation
 * - opts: { retries, baseDelayMs, timeoutMs }
 */
async function callWithRetry(fn, opts = {}) {
  const retries = Number(opts.retries ?? 3);
  const baseDelayMs = Number(opts.baseDelayMs ?? 200);
  const timeoutMs = Number(opts.timeoutMs ?? 7000);

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  let attempt = 0;
  while (true) {
    attempt += 1;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const result = await fn({ signal: controller.signal, timeoutMs });
      clearTimeout(timer);
      return result;
    } catch (err) {
      clearTimeout(timer);
      const isAbort = err && (err.name === 'AbortError' || String(err.message || '').toLowerCase().includes('aborted') || err.code === 'ETIMEDOUT');
      const isTransient = isAbort || /timeout|ECONNRESET|ENOTFOUND|EAI_AGAIN|ETIMEDOUT|503|502/.test(String(err.message || ''));
      if (attempt > retries || !isTransient) {
        err.attempt = attempt;
        throw err;
      }
      const jitter = Math.floor(Math.random() * 100);
      const delay = Math.min(5000, baseDelayMs * Math.pow(2, attempt - 1) + jitter);
      await sleep(delay);
    }
  }
}

module.exports = {
  supabase,
  callWithRetry,
};

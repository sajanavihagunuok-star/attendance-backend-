const express = require('express');
const router = express.Router();
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Supabase env vars missing: SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  global: { headers: { 'x-from-server': 'true' } }
});

const isUuid = (s) => {
  if (!s || typeof s !== 'string') return false;
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(s);
};

router.get('/', async (req, res) => {
  try {
    const qid = req.query.id;
    if (qid) {
      if (!isUuid(qid)) return res.status(400).json({ error: 'invalid id format' });
      const { data, error } = await supabase
        .from('sessions')
        .select('id,title,course_id,lecturer_id,start_time,end_time,capacity,created_at')
        .eq('id', qid)
        .limit(1)
        .maybeSingle();
      if (error) {
        console.error('supabase session by query id error', error);
        return res.status(500).json({ error: error.message || 'supabase error' });
      }
      if (!data) return res.status(404).json({ error: 'not found' });
      return res.json({ ok: true, session: data });
    }

    const limit = parseInt(req.query.limit, 10) || 500;
    const { data, error } = await supabase
      .from('sessions')
      .select('id,title,course_id,lecturer_id,start_time,end_time,capacity,created_at')
      .order('start_time', { ascending: false })
      .limit(limit);

    if (error) {
      console.error('supabase sessions list error', error);
      return res.status(500).json({ error: error.message || 'supabase error' });
    }

    res.json({ ok: true, sessions: data || [] });
  } catch (err) {
    console.error('sessions GET error', err);
    res.status(500).json({ error: err.message || 'internal error' });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const id = req.params.id;
    if (!isUuid(id)) return res.status(400).json({ error: 'invalid id format' });

    const { data, error } = await supabase
      .from('sessions')
      .select('id,title,course_id,lecturer_id,start_time,end_time,capacity,created_at')
      .eq('id', id)
      .limit(1)
      .maybeSingle();

    if (error) {
      console.error('supabase session by id error', error);
      return res.status(500).json({ error: error.message || 'supabase error' });
    }

    if (!data) return res.status(404).json({ error: 'not found' });

    res.json({ ok: true, session: data });
  } catch (err) {
    console.error('sessions/:id error', err);
    res.status(500).json({ error: err.message || 'internal error' });
  }
});

module.exports = router;

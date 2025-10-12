// get_supabase_token.mjs
import { createClient } from '@supabase/supabase-js'
const SUPABASE_URL = process.env.SUPABASE_URL
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY
if (!SUPABASE_URL || !SUPABASE_ANON_KEY) { console.error('Missing SUPABASE_URL or SUPABASE_ANON_KEY'); process.exit(1) }
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { persistSession: false } })
async function run() {
  const email = "sajana.vihagun.uok@gmail.com"
  const password = "TestPass#1234"
  const { data, error } = await supabase.auth.signInWithPassword({ email, password })
  if (error) { console.error('signIn error', error); process.exit(1) }
  if (!data || !data.session) { console.error('No session received', data); process.exit(1) }
  console.log(data.session.access_token)
}
run()

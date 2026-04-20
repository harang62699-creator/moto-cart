import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-workers'

type Bindings = {
  DB: D1Database
}

const app = new Hono<{ Bindings: Bindings }>()

app.use('/api/*', cors())
app.use('/static/*', serveStatic({ root: './' }))

// ────────────────────────────────────────────────
// 유틸: 비밀번호 해시 (Web Crypto)
// ────────────────────────────────────────────────
async function hashPassword(password: string): Promise<string> {
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode('moto-cert-salt'), iterations: 100000, hash: 'SHA-256' },
    key, 256
  )
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('')
}

const JWT_SECRET = 'moto-cert-jwt-secret-2025'

function toBase64url(str: string): string {
  const enc = new TextEncoder()
  const bytes = enc.encode(str)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

function fromBase64url(b64: string): string {
  const binary = atob(b64.replace(/-/g, '+').replace(/_/g, '/'))
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return new TextDecoder().decode(bytes)
}

function arrayBufferToBase64url(data: ArrayBuffer): string {
  let binary = ''
  for (const b of new Uint8Array(data)) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

async function signJWT(payload: Record<string, unknown>): Promise<string> {
  const header = toBase64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const body = toBase64url(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + 86400 * 7 }))
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', enc.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${header}.${body}`))
  return `${header}.${body}.${arrayBufferToBase64url(sig)}`
}

async function verifyJWT(token: string): Promise<Record<string, unknown> | null> {
  try {
    const [header, body, sig] = token.split('.')
    const enc = new TextEncoder()
    const key = await crypto.subtle.importKey('raw', enc.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'])
    const sigBytes = Uint8Array.from(atob(sig.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(`${header}.${body}`))
    if (!valid) return null
    const payload = JSON.parse(fromBase64url(body))
    if (payload.exp < Math.floor(Date.now() / 1000)) return null
    return payload
  } catch { return null }
}

async function authMiddleware(c: any, next: () => Promise<void>) {
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  if (!token) return c.json({ error: 'Unauthorized' }, 401)
  const payload = await verifyJWT(token)
  if (!payload) return c.json({ error: 'Invalid token' }, 401)
  c.set('user', payload)
  await next()
}

// ── API Routes ──────────────────────────────────
app.post('/api/auth/register', async (c) => {
  const { username, password, company_name, representative, business_number, phone } = await c.req.json()
  if (!username || !password || !company_name || !representative || !business_number)
    return c.json({ error: '필수 항목을 모두 입력해주세요.' }, 400)
  if (!/^[a-zA-Z0-9_]{4,20}$/.test(username))
    return c.json({ error: '아이디는 영문·숫자·밑줄 4~20자로 입력해주세요.' }, 400)
  const hash = await hashPassword(password)
  try {
    const result = await c.env.DB.prepare(
      'INSERT INTO users (username, password_hash, company_name, representative, business_number, phone) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(username, hash, company_name, representative, business_number, phone || '').run()
    const user = await c.env.DB.prepare('SELECT id, username, company_name, representative FROM users WHERE id = ?').bind(result.meta.last_row_id).first()
    const token = await signJWT({ id: user!.id, username: user!.username, company_name: user!.company_name })
    return c.json({ ok: true, token, user })
  } catch (e: any) {
    if (e.message?.includes('UNIQUE')) return c.json({ error: '이미 사용중인 아이디입니다.' }, 409)
    return c.json({ error: '서버 오류: ' + e.message }, 500)
  }
})

app.post('/api/auth/login', async (c) => {
  const { username, password } = await c.req.json()
  if (!username || !password) return c.json({ error: '아이디와 비밀번호를 입력해주세요.' }, 400)
  const hash = await hashPassword(password)
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE username = ? AND password_hash = ?').bind(username, hash).first()
  if (!user) return c.json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' }, 401)
  const token = await signJWT({ id: user.id, username: user.username, company_name: user.company_name })
  return c.json({ ok: true, token, user: { id: user.id, username: user.username, company_name: user.company_name, representative: user.representative } })
})

app.post('/api/auth/logout', async (c) => c.json({ ok: true }))

app.get('/api/auth/me', authMiddleware, async (c) => {
  const payload = c.get('user') as any
  const user = await c.env.DB.prepare('SELECT id, username, company_name, representative, business_number, phone FROM users WHERE id = ?').bind(payload.id).first()
  if (!user) return c.json({ error: 'Not found' }, 404)
  return c.json({ user })
})

app.get('/api/applications', authMiddleware, async (c) => {
  const payload = c.get('user') as any
  const list = await c.env.DB.prepare(
    `SELECT a.*,
      (SELECT COUNT(*) FROM form_data WHERE application_id = a.id AND completed = 1) as completed_forms,
      (SELECT COUNT(*) FROM form_data WHERE application_id = a.id) as total_forms
     FROM applications a WHERE a.user_id = ? ORDER BY a.updated_at DESC`
  ).bind(payload.id).all()
  return c.json({ applications: list.results })
})

app.post('/api/applications', authMiddleware, async (c) => {
  const payload = c.get('user') as any
  try {
    const { cert_type, title, brand, model, model_year, prev_cert_number, change_item, change_reason } = await c.req.json()
    if (!cert_type || !title) return c.json({ error: '신청 제목과 인증 유형은 필수입니다.' }, 400)
    const result = await c.env.DB.prepare(
      'INSERT INTO applications (user_id, cert_type, title, brand, model, model_year, prev_cert_number, change_item, change_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(payload.id, cert_type, title, brand || '', model || '', model_year || '', prev_cert_number || '', change_item || '', change_reason || '').run()
    const app_id = result.meta.last_row_id
    const formTypes = ['summary','gasoline','detail_plan','emission_noise','obd_config','emission_test','evap_test','obd_operation','noise_test','confirmation']
    await c.env.DB.batch(formTypes.map(ft => c.env.DB.prepare('INSERT INTO form_data (application_id, form_type) VALUES (?, ?)').bind(app_id, ft)))
    const created = await c.env.DB.prepare('SELECT * FROM applications WHERE id = ?').bind(app_id).first()
    return c.json({ ok: true, application: created }, 201)
  } catch (e: any) {
    return c.json({ error: '신청서 생성 실패: ' + e.message }, 500)
  }
})

app.get('/api/applications/:id', authMiddleware, async (c) => {
  const payload = c.get('user') as any
  const id = c.req.param('id')
  const appl = await c.env.DB.prepare('SELECT * FROM applications WHERE id = ? AND user_id = ?').bind(id, payload.id).first()
  if (!appl) return c.json({ error: 'Not found' }, 404)
  const forms = await c.env.DB.prepare('SELECT * FROM form_data WHERE application_id = ?').bind(id).all()
  return c.json({ application: appl, forms: forms.results })
})

app.put('/api/applications/:id', authMiddleware, async (c) => {
  const payload = c.get('user') as any
  const id = c.req.param('id')
  const appl = await c.env.DB.prepare('SELECT * FROM applications WHERE id = ? AND user_id = ?').bind(id, payload.id).first()
  if (!appl) return c.json({ error: 'Not found' }, 404)
  const { title, brand, model, model_year, status } = await c.req.json()
  await c.env.DB.prepare('UPDATE applications SET title=?, brand=?, model=?, model_year=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?')
    .bind(title || appl.title, brand || appl.brand, model || appl.model, model_year || appl.model_year, status || appl.status, id).run()
  return c.json({ ok: true })
})

app.delete('/api/applications/:id', authMiddleware, async (c) => {
  const payload = c.get('user') as any
  const id = c.req.param('id')
  const appl = await c.env.DB.prepare('SELECT * FROM applications WHERE id = ? AND user_id = ?').bind(id, payload.id).first()
  if (!appl) return c.json({ error: 'Not found' }, 404)
  await c.env.DB.prepare('DELETE FROM form_data WHERE application_id = ?').bind(id).run()
  await c.env.DB.prepare('DELETE FROM applications WHERE id = ?').bind(id).run()
  return c.json({ ok: true })
})

app.get('/api/applications/:id/forms/:type', authMiddleware, async (c) => {
  const payload = c.get('user') as any
  const { id, type } = c.req.param()
  const appl = await c.env.DB.prepare('SELECT * FROM applications WHERE id = ? AND user_id = ?').bind(id, payload.id).first()
  if (!appl) return c.json({ error: 'Not found' }, 404)
  const form = await c.env.DB.prepare('SELECT * FROM form_data WHERE application_id = ? AND form_type = ?').bind(id, type).first()
  return c.json({ form })
})

app.put('/api/applications/:id/forms/:type', authMiddleware, async (c) => {
  const payload = c.get('user') as any
  const { id, type } = c.req.param()
  const appl = await c.env.DB.prepare('SELECT * FROM applications WHERE id = ? AND user_id = ?').bind(id, payload.id).first()
  if (!appl) return c.json({ error: 'Not found' }, 404)
  const { data, completed } = await c.req.json()
  await c.env.DB.prepare('UPDATE form_data SET data=?, completed=?, updated_at=CURRENT_TIMESTAMP WHERE application_id=? AND form_type=?')
    .bind(JSON.stringify(data), completed ? 1 : 0, id, type).run()
  const completedCount = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM form_data WHERE application_id=? AND completed=1').bind(id).first() as any
  const totalCount = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM form_data WHERE application_id=?').bind(id).first() as any
  const newStatus = completedCount.cnt === totalCount.cnt ? 'completed' : completedCount.cnt > 0 ? 'in_progress' : 'draft'
  await c.env.DB.prepare('UPDATE applications SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(newStatus, id).run()
  return c.json({ ok: true })
})

// ── HTML ────────────────────────────────────────
const HTML = `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Motocert — 수입이륜차 인증신청 지원</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Pretendard:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.0/css/all.min.css" rel="stylesheet">
<style>
/* ── 디자인 토큰 ───────────────────────────── */
:root {
  --c-bg:       #0f1117;
  --c-surface:  #16191f;
  --c-surface2: #1e2229;
  --c-border:   rgba(255,255,255,.08);
  --c-border2:  rgba(255,255,255,.14);
  --c-text:     #f0f2f5;
  --c-text2:    #8b93a4;
  --c-text3:    #5a6272;
  --c-accent:   #4f8ef7;
  --c-accent2:  #6c5ce7;
  --c-success:  #00c896;
  --c-warn:     #f5a623;
  --c-danger:   #ff5f6d;
  --grad-hero:  linear-gradient(135deg,#1a2342 0%,#0f1117 60%);
  --grad-card:  linear-gradient(145deg,#1e2430,#161a22);
  --grad-accent:linear-gradient(135deg,#4f8ef7,#6c5ce7);
  --grad-green: linear-gradient(135deg,#00c896,#00b4d8);
  --shadow-sm:  0 2px 8px rgba(0,0,0,.35);
  --shadow-md:  0 8px 24px rgba(0,0,0,.45);
  --shadow-lg:  0 20px 60px rgba(0,0,0,.6);
  --r-sm: 10px;
  --r-md: 14px;
  --r-lg: 20px;
  --r-xl: 28px;
  --transition: .2s cubic-bezier(.4,0,.2,1);
}
*,*::before,*::after { box-sizing:border-box; margin:0; padding:0; }
html { scroll-behavior:smooth; }
body {
  font-family:'Pretendard','Malgun Gothic',sans-serif;
  background:var(--c-bg);
  color:var(--c-text);
  min-height:100vh;
  display:flex;
  flex-direction:column;
  -webkit-font-smoothing:antialiased;
}
/* 헤더 제외 페이지 영역 확장 */
#page-dashboard.active,
#page-application.active,
#page-form.active {
  flex:1;
}

/* ── 스크롤바 ───────────────────────────────── */
::-webkit-scrollbar { width:6px; height:6px; }
::-webkit-scrollbar-track { background:var(--c-surface); }
::-webkit-scrollbar-thumb { background:var(--c-border2); border-radius:3px; }
::-webkit-scrollbar-thumb:hover { background:var(--c-text3); }

/* ── 페이지 전환 ────────────────────────────── */
.page { display:none; animation:fadeIn .25s ease; }
.page.active { display:block; }
@keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }

/* ── 공통 컴포넌트 ──────────────────────────── */
.glass {
  background:rgba(255,255,255,.03);
  backdrop-filter:blur(20px);
  -webkit-backdrop-filter:blur(20px);
  border:1px solid var(--c-border);
}
.card {
  background:var(--grad-card);
  border:1px solid var(--c-border);
  border-radius:var(--r-lg);
  box-shadow:var(--shadow-sm);
  transition:all var(--transition);
}
.card:hover { border-color:var(--c-border2); box-shadow:var(--shadow-md); }

/* ── 버튼 ───────────────────────────────────── */
.btn {
  display:inline-flex; align-items:center; justify-content:center; gap:7px;
  border:none; cursor:pointer; font-family:inherit;
  font-weight:600; font-size:.875rem;
  padding:10px 20px; border-radius:var(--r-sm);
  transition:all var(--transition);
  white-space:nowrap;
}
.btn:disabled { opacity:.5; cursor:not-allowed; }
.btn-primary {
  background:var(--grad-accent);
  color:#fff;
  box-shadow:0 4px 15px rgba(79,142,247,.35);
}
.btn-primary:hover:not(:disabled) { transform:translateY(-1px); box-shadow:0 6px 20px rgba(79,142,247,.5); }
.btn-primary:active:not(:disabled) { transform:translateY(0); }
.btn-ghost {
  background:rgba(255,255,255,.05);
  color:var(--c-text2);
  border:1px solid var(--c-border);
}
.btn-ghost:hover:not(:disabled) { background:rgba(255,255,255,.09); color:var(--c-text); border-color:var(--c-border2); }
.btn-danger {
  background:rgba(255,95,109,.12);
  color:var(--c-danger);
  border:1px solid rgba(255,95,109,.25);
}
.btn-danger:hover:not(:disabled) { background:rgba(255,95,109,.2); }
.btn-success {
  background:rgba(0,200,150,.12);
  color:var(--c-success);
  border:1px solid rgba(0,200,150,.3);
}
.btn-success:hover:not(:disabled) { background:rgba(0,200,150,.22); }
.btn-sm { padding:7px 14px; font-size:.8rem; border-radius:8px; }
.btn-lg { padding:13px 28px; font-size:1rem; border-radius:var(--r-md); }
.btn-icon { width:36px; height:36px; padding:0; border-radius:9px; }

/* ── 인풋 ───────────────────────────────────── */
.input {
  width:100%;
  background:rgba(255,255,255,.04);
  border:1px solid var(--c-border);
  border-radius:var(--r-sm);
  color:var(--c-text);
  font-family:inherit;
  font-size:.9rem;
  padding:11px 14px;
  transition:all var(--transition);
  outline:none;
}
.input::placeholder { color:var(--c-text3); }
.input:focus { border-color:var(--c-accent); background:rgba(79,142,247,.06); box-shadow:0 0 0 3px rgba(79,142,247,.12); }
.input:disabled { opacity:.5; cursor:not-allowed; }
select.input { appearance:none; cursor:pointer; }
textarea.input { resize:vertical; min-height:80px; line-height:1.6; }
.label {
  display:block; font-size:.8rem; font-weight:600;
  color:var(--c-text2); margin-bottom:6px; letter-spacing:.02em;
}
.field-wrap { display:flex; flex-direction:column; gap:0; }
.field-note { font-size:.73rem; color:var(--c-text3); margin-top:5px; }

/* ── 배지 ───────────────────────────────────── */
.badge {
  display:inline-flex; align-items:center; gap:4px;
  font-size:.72rem; font-weight:700; padding:3px 10px;
  border-radius:999px; letter-spacing:.02em;
}
.badge-blue  { background:rgba(79,142,247,.15); color:#7eb3ff; border:1px solid rgba(79,142,247,.25); }
.badge-violet{ background:rgba(108,92,231,.15); color:#a78bfa; border:1px solid rgba(108,92,231,.25); }
.badge-green { background:rgba(0,200,150,.13); color:#34d399; border:1px solid rgba(0,200,150,.25); }
.badge-yellow{ background:rgba(245,166,35,.13); color:#fbbf24; border:1px solid rgba(245,166,35,.25); }
.badge-gray  { background:rgba(255,255,255,.06); color:var(--c-text2); border:1px solid var(--c-border); }

/* ── 프로그레스 바 ──────────────────────────── */
.progress-track { background:rgba(255,255,255,.07); border-radius:999px; overflow:hidden; }
.progress-fill { border-radius:999px; transition:width .6s cubic-bezier(.4,0,.2,1); }

/* ── 모달 ───────────────────────────────────── */
.modal-backdrop {
  position:fixed; inset:0; z-index:200;
  background:rgba(0,0,0,.7);
  backdrop-filter:blur(6px);
  display:flex; align-items:center; justify-content:center; padding:20px;
  animation:fadeBackdrop .2s ease;
}
.modal-backdrop.hidden { display:none; }
@keyframes fadeBackdrop { from{opacity:0} to{opacity:1} }
.modal {
  background:var(--c-surface);
  border:1px solid var(--c-border2);
  border-radius:var(--r-xl);
  box-shadow:var(--shadow-lg);
  width:100%; max-width:500px;
  animation:slideModal .25s cubic-bezier(.34,1.56,.64,1);
}
@keyframes slideModal { from{opacity:0;transform:scale(.94)translateY(12px)} to{opacity:1;transform:scale(1)translateY(0)} }
.modal-header { padding:28px 28px 0; display:flex; align-items:center; justify-content:space-between; }
.modal-body { padding:24px 28px; display:flex; flex-direction:column; gap:18px; }
.modal-footer { padding:0 28px 28px; display:flex; justify-content:flex-end; gap:10px; }

/* ── 토스트 ─────────────────────────────────── */
.toast-stack { position:fixed; bottom:28px; right:28px; z-index:300; display:flex; flex-direction:column; gap:10px; }
.toast {
  display:flex; align-items:center; gap:10px;
  background:var(--c-surface2);
  border:1px solid var(--c-border2);
  border-radius:var(--r-md);
  box-shadow:var(--shadow-md);
  padding:14px 18px; font-size:.875rem; font-weight:500;
  animation:toastIn .3s cubic-bezier(.34,1.56,.64,1);
  max-width:340px;
}
.toast.out { animation:toastOut .25s ease forwards; }
@keyframes toastIn  { from{opacity:0;transform:translateY(16px)scale(.95)} to{opacity:1;transform:translateY(0)scale(1)} }
@keyframes toastOut { to{opacity:0;transform:translateY(8px)scale(.95)} }
.toast-icon { width:20px; height:20px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:.7rem; flex-shrink:0; }
.toast-success .toast-icon { background:rgba(0,200,150,.2); color:var(--c-success); }
.toast-error   .toast-icon { background:rgba(255,95,109,.2); color:var(--c-danger); }
.toast-info    .toast-icon { background:rgba(79,142,247,.2); color:var(--c-accent); }

/* ── 스피너 ─────────────────────────────────── */
.spinner {
  width:16px; height:16px; border-radius:50%;
  border:2px solid rgba(255,255,255,.2);
  border-top-color:#fff;
  animation:spin .6s linear infinite;
  flex-shrink:0;
}
@keyframes spin { to{transform:rotate(360deg)} }

/* ── 헤더 ───────────────────────────────────── */
#app-header {
  position:sticky; top:0; z-index:100;
  height:60px;
  background:rgba(15,17,23,.85);
  backdrop-filter:blur(20px);
  -webkit-backdrop-filter:blur(20px);
  border-bottom:1px solid var(--c-border);
  display:flex; align-items:center;
}
.header-inner {
  max-width:1200px; width:100%; margin:0 auto;
  padding:0 24px;
  display:flex; align-items:center; justify-content:space-between;
  gap:16px;
}
.logo { display:flex; align-items:center; gap:10px; text-decoration:none; }
.logo-icon {
  width:34px; height:34px; border-radius:9px;
  background:var(--grad-accent);
  display:flex; align-items:center; justify-content:center;
  font-size:15px; color:#fff;
  box-shadow:0 4px 12px rgba(79,142,247,.4);
}
.logo-text { font-size:.95rem; font-weight:800; color:var(--c-text); letter-spacing:-.02em; }
.logo-sub { font-size:.7rem; color:var(--c-text3); font-weight:500; }

/* ── 로그인 페이지 ──────────────────────────── */
#page-auth {
  min-height:calc(100vh - 60px);
  display:none; align-items:center; justify-content:center;
  padding:24px;
  background:var(--grad-hero);
  position:relative; overflow:hidden;
}
#page-auth.active { display:flex; }
#page-auth::before {
  content:'';
  position:absolute; inset:0;
  background:
    radial-gradient(ellipse 60% 50% at 20% 40%, rgba(79,142,247,.08) 0%, transparent 70%),
    radial-gradient(ellipse 50% 40% at 80% 60%, rgba(108,92,231,.07) 0%, transparent 70%);
  pointer-events:none;
}
.auth-wrap { position:relative; z-index:1; width:100%; max-width:420px; }
.auth-hero { text-align:center; margin-bottom:32px; }
.auth-logo-big {
  width:64px; height:64px; border-radius:18px;
  background:var(--grad-accent);
  display:flex; align-items:center; justify-content:center;
  font-size:26px; color:#fff; margin:0 auto 18px;
  box-shadow:0 8px 30px rgba(79,142,247,.45);
}
.auth-title { font-size:1.6rem; font-weight:800; letter-spacing:-.03em; margin-bottom:6px; }
.auth-desc { font-size:.875rem; color:var(--c-text2); line-height:1.6; }
.auth-card {
  background:rgba(22,25,31,.9);
  border:1px solid var(--c-border2);
  border-radius:var(--r-xl);
  box-shadow:var(--shadow-lg);
  overflow:hidden;
}
.auth-tabs {
  display:flex;
  border-bottom:1px solid var(--c-border);
}
.auth-tab {
  flex:1; padding:16px; font-size:.875rem; font-weight:600;
  background:none; border:none; cursor:pointer; color:var(--c-text3);
  transition:all var(--transition); position:relative;
  font-family:inherit;
}
.auth-tab.active { color:var(--c-accent); }
.auth-tab.active::after {
  content:''; position:absolute; bottom:-1px; left:0; right:0; height:2px;
  background:var(--grad-accent); border-radius:2px 2px 0 0;
}
.auth-form { padding:28px; display:flex; flex-direction:column; gap:16px; }
.auth-error {
  background:rgba(255,95,109,.1); border:1px solid rgba(255,95,109,.25);
  border-radius:var(--r-sm); padding:11px 14px;
  font-size:.82rem; color:#ff8a92; display:none;
  animation:fadeIn .2s ease;
}

/* ── 대시보드 ───────────────────────────────── */
#page-dashboard { max-width:1200px; width:100%; margin:0 auto; padding:36px 24px; }
.dash-header {
  display:flex; align-items:center; justify-content:space-between;
  flex-wrap:wrap; gap:12px; margin-bottom:32px;
}
.dash-title { font-size:1.4rem; font-weight:800; letter-spacing:-.03em; }
.dash-sub { font-size:.85rem; color:var(--c-text2); margin-top:4px; }
.stats-grid {
  display:grid; grid-template-columns:repeat(4,1fr); gap:14px;
  margin-bottom:28px;
}
@media(max-width:640px) { .stats-grid { grid-template-columns:repeat(2,1fr); } }
.stat-card {
  background:var(--grad-card);
  border:1px solid var(--c-border); border-radius:var(--r-lg);
  padding:20px 22px; position:relative; overflow:hidden;
  transition:all var(--transition);
}
.stat-card:hover { border-color:var(--c-border2); transform:translateY(-2px); }
.stat-card::before {
  content:''; position:absolute; top:-30px; right:-20px;
  width:80px; height:80px; border-radius:50%;
  opacity:.07;
}
.stat-card.total::before  { background:var(--c-text); }
.stat-card.prog::before   { background:var(--c-warn); }
.stat-card.done::before   { background:var(--c-success); }
.stat-card.draft::before  { background:var(--c-text3); }
.stat-num { font-size:2rem; font-weight:800; letter-spacing:-.04em; line-height:1; }
.stat-num.total  { color:var(--c-text); }
.stat-num.prog   { color:var(--c-warn); }
.stat-num.done   { color:var(--c-success); }
.stat-num.draft  { color:var(--c-text3); }
.stat-label { font-size:.78rem; color:var(--c-text2); font-weight:600; margin-top:6px; letter-spacing:.02em; }
.stat-icon {
  position:absolute; top:18px; right:18px;
  width:32px; height:32px; border-radius:8px;
  display:flex; align-items:center; justify-content:center; font-size:13px;
}
.stat-card.total .stat-icon { background:rgba(255,255,255,.06); color:var(--c-text2); }
.stat-card.prog  .stat-icon { background:rgba(245,166,35,.1); color:var(--c-warn); }
.stat-card.done  .stat-icon { background:rgba(0,200,150,.1); color:var(--c-success); }
.stat-card.draft .stat-icon { background:rgba(255,255,255,.04); color:var(--c-text3); }

/* 신청서 목록 */
.app-item {
  background:var(--grad-card);
  border:1px solid var(--c-border);
  border-radius:var(--r-lg);
  padding:20px 22px;
  display:flex; align-items:center; gap:18px;
  transition:all var(--transition); cursor:default;
}
.app-item:hover { border-color:var(--c-border2); box-shadow:var(--shadow-sm); transform:translateX(2px); }
.app-item-icon {
  width:46px; height:46px; border-radius:var(--r-sm); flex-shrink:0;
  background:rgba(79,142,247,.1); border:1px solid rgba(79,142,247,.2);
  display:flex; align-items:center; justify-content:center;
  font-size:18px; color:var(--c-accent);
}
.app-item-body { flex:1; min-width:0; }
.app-item-title {
  font-size:.95rem; font-weight:700; color:var(--c-text);
  white-space:nowrap; overflow:hidden; text-overflow:ellipsis; margin-bottom:6px;
}
.app-item-meta { font-size:.78rem; color:var(--c-text3); margin-bottom:10px; }
.app-item-actions { display:flex; align-items:center; gap:8px; flex-shrink:0; }

/* 빈 상태 */
.empty-state { text-align:center; padding:80px 20px; }
.empty-icon {
  width:72px; height:72px; border-radius:var(--r-lg);
  background:rgba(255,255,255,.04); border:1px solid var(--c-border);
  display:flex; align-items:center; justify-content:center;
  font-size:28px; color:var(--c-text3); margin:0 auto 20px;
}
.empty-title { font-size:1.05rem; font-weight:700; margin-bottom:8px; }
.empty-desc  { font-size:.875rem; color:var(--c-text2); line-height:1.7; margin-bottom:24px; }

/* ── 신청서 상세 ─────────────────────────────── */
#page-application { max-width:1200px; width:100%; margin:0 auto; padding:36px 24px; }
.breadcrumb {
  display:flex; align-items:center; gap:8px;
  font-size:.82rem; color:var(--c-text3); margin-bottom:24px; flex-wrap:wrap;
}
.breadcrumb a, .breadcrumb button {
  background:none; border:none; cursor:pointer; font-family:inherit; font-size:inherit;
  color:var(--c-accent); text-decoration:none; padding:0; font-weight:500;
  transition:opacity var(--transition);
}
.breadcrumb a:hover, .breadcrumb button:hover { opacity:.7; }
.breadcrumb-sep { color:var(--c-text3); font-size:.7rem; }
.appl-hero {
  background:var(--grad-card);
  border:1px solid var(--c-border); border-radius:var(--r-xl);
  padding:28px 32px; margin-bottom:28px;
  display:flex; align-items:flex-start; justify-content:space-between; gap:24px; flex-wrap:wrap;
}
.appl-hero-left { flex:1; min-width:0; }
.appl-hero-badges { display:flex; align-items:center; gap:8px; margin-bottom:12px; flex-wrap:wrap; }
.appl-hero-title { font-size:1.3rem; font-weight:800; letter-spacing:-.03em; margin-bottom:6px; }
.appl-hero-meta  { font-size:.85rem; color:var(--c-text2); }
.appl-hero-right { flex-shrink:0; text-align:right; }
.appl-pct { font-size:2.4rem; font-weight:800; letter-spacing:-.04em; color:var(--c-accent); line-height:1; }
.appl-pct-label { font-size:.78rem; color:var(--c-text3); margin-bottom:8px; }
.forms-section-title { font-size:.9rem; font-weight:700; color:var(--c-text2); margin-bottom:16px; letter-spacing:.03em; text-transform:uppercase; }
.forms-grid {
  display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:14px;
  margin-bottom:28px;
}
.form-card {
  background:var(--grad-card);
  border:1px solid var(--c-border); border-radius:var(--r-lg);
  padding:18px 20px; cursor:pointer;
  display:flex; align-items:center; gap:14px;
  transition:all var(--transition); position:relative; overflow:hidden;
}
.form-card::before {
  content:''; position:absolute; left:0; top:0; bottom:0; width:3px;
  background:transparent; border-radius:0 3px 3px 0; transition:background var(--transition);
}
.form-card:hover { border-color:var(--c-border2); box-shadow:var(--shadow-sm); transform:translateY(-2px); }
.form-card:hover::before { background:var(--c-accent); }
.form-card.done { border-color:rgba(0,200,150,.3); background:rgba(0,200,150,.04); }
.form-card.done::before { background:var(--c-success); }
.form-card-icon {
  width:42px; height:42px; border-radius:10px; flex-shrink:0;
  display:flex; align-items:center; justify-content:center; font-size:16px;
}
.form-card-body { flex:1; min-width:0; }
.form-card-num  { font-size:.72rem; color:var(--c-text3); font-weight:600; margin-bottom:4px; letter-spacing:.02em; }
.form-card-name { font-size:.875rem; font-weight:700; color:var(--c-text); line-height:1.4; }
.form-card-chevron { color:var(--c-text3); font-size:.75rem; flex-shrink:0; transition:transform var(--transition); }
.form-card:hover .form-card-chevron { transform:translateX(3px); color:var(--c-accent); }

/* ── 서류 폼 페이지 ──────────────────────────── */
#page-form { max-width:860px; width:100%; margin:0 auto; padding:36px 24px; }
.form-page-header {
  background:var(--grad-card);
  border:1px solid var(--c-border); border-radius:var(--r-xl);
  padding:24px 28px; margin-bottom:24px;
  display:flex; align-items:center; justify-content:space-between; gap:16px; flex-wrap:wrap;
}
.form-page-title { font-size:1.1rem; font-weight:800; letter-spacing:-.02em; margin-bottom:4px; }
.form-page-sub   { font-size:.8rem; color:var(--c-text2); }
.form-page-actions { display:flex; gap:8px; flex-shrink:0; }
.form-section {
  background:var(--grad-card);
  border:1px solid var(--c-border); border-radius:var(--r-lg);
  padding:24px 26px; margin-bottom:16px;
}
.form-section-title {
  font-size:.82rem; font-weight:700; color:var(--c-accent);
  letter-spacing:.06em; text-transform:uppercase;
  margin-bottom:18px; padding-bottom:12px;
  border-bottom:1px solid var(--c-border);
  display:flex; align-items:center; gap:7px;
}
.form-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(220px,1fr)); gap:16px; }
.form-grid-full { display:grid; gap:16px; }
.complete-card {
  background:var(--grad-card);
  border:1px solid var(--c-border); border-radius:var(--r-lg);
  padding:20px 24px; display:flex; align-items:center; gap:14px;
  cursor:pointer; transition:all var(--transition);
}
.complete-card:hover { border-color:rgba(0,200,150,.4); }
.complete-card.checked { border-color:rgba(0,200,150,.5); background:rgba(0,200,150,.04); }
.complete-checkbox {
  width:22px; height:22px; border-radius:6px; flex-shrink:0;
  accent-color:var(--c-success); cursor:pointer;
}
.complete-label-title { font-weight:700; font-size:.9rem; margin-bottom:2px; }
.complete-label-sub   { font-size:.78rem; color:var(--c-text2); }

/* ── 반응형 ─────────────────────────────────── */
@media(max-width:768px) {
  #page-dashboard, #page-application, #page-form { padding:20px 16px; }
  .appl-hero { padding:20px; }
  .forms-grid { grid-template-columns:1fr; }
  .stats-grid { grid-template-columns:repeat(2,1fr); }
  .modal { border-radius:var(--r-lg); }
  .form-page-header { padding:18px 20px; }
  .form-section { padding:18px 20px; }
}
@media print {
  .no-print { display:none !important; }
  body { background:#fff !important; color:#000 !important; }
  .card, .form-section { background:#fff !important; border:1px solid #ddd !important; box-shadow:none !important; }
  .input { border:1px solid #ccc !important; background:#fff !important; color:#000 !important; }
  .label { color:#333 !important; }
}

/* ── 구분선 ─────────────────────────────────── */
.divider { height:1px; background:var(--c-border); margin:4px 0; }

/* 오버플로우 숨김 헬퍼 */
.truncate { white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
</style>
</head>
<body>

<!-- ═══════════════════════════════════════════════
     헤더
════════════════════════════════════════════════ -->
<header id="app-header" class="no-print">
  <div class="header-inner">
    <div class="logo">
      <div class="logo-icon"><i class="fas fa-motorcycle"></i></div>
      <div>
        <div class="logo-text">MotoCart</div>
        <div class="logo-sub">수입이륜차 인증신청 지원</div>
      </div>
    </div>
    <div id="header-user" style="display:flex;align-items:center;gap:10px;"></div>
  </div>
</header>

<!-- 토스트 컨테이너 -->
<div id="toast-stack" class="toast-stack no-print"></div>

<!-- ═══════════════════════════════════════════════
     PAGE: 로그인/회원가입
════════════════════════════════════════════════ -->
<div id="page-auth" class="page active">
  <div class="auth-wrap">
    <div class="auth-hero">
      <div class="auth-logo-big"><i class="fas fa-motorcycle"></i></div>
      <div class="auth-title">인증신청 지원 시스템</div>
      <div class="auth-desc">수입이륜차 배출가스·소음 인증<br>서류 작성을 효율적으로</div>
    </div>
    <div class="auth-card">
      <div class="auth-tabs">
        <button class="auth-tab active" id="tab-login" onclick="showAuthTab('login')">로그인</button>
        <button class="auth-tab" id="tab-register" onclick="showAuthTab('register')">회원가입</button>
      </div>

      <!-- 로그인 폼 -->
      <div id="login-form" class="auth-form">
        <div class="field-wrap">
          <label class="label"><i class="fas fa-user" style="margin-right:5px;opacity:.6;"></i>아이디</label>
          <input id="login-username" class="input" type="text" placeholder="아이디를 입력하세요" autocomplete="username"
            onkeydown="if(event.key==='Enter')document.getElementById('login-password').focus()">
        </div>
        <div class="field-wrap">
          <label class="label"><i class="fas fa-lock" style="margin-right:5px;opacity:.6;"></i>비밀번호</label>
          <input id="login-password" class="input" type="password" placeholder="비밀번호를 입력하세요" autocomplete="current-password"
            onkeydown="if(event.key==='Enter')doLogin()">
        </div>
        <div id="login-error" class="auth-error"></div>
        <button id="login-btn" class="btn btn-primary btn-lg" onclick="doLogin()" style="width:100%;margin-top:4px;">
          <i class="fas fa-sign-in-alt"></i>로그인
        </button>
      </div>

      <!-- 회원가입 폼 -->
      <div id="register-form" class="auth-form" style="display:none;">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">
          <div class="field-wrap" style="grid-column:1/-1;">
            <label class="label">아이디 <span style="color:var(--c-danger);">*</span></label>
            <input id="reg-username" class="input" type="text" placeholder="영문·숫자·밑줄 4~20자" autocomplete="username">
            <span class="field-note">영문, 숫자, 밑줄(_)만 가능</span>
          </div>
          <div class="field-wrap">
            <label class="label">비밀번호 <span style="color:var(--c-danger);">*</span></label>
            <input id="reg-password" class="input" type="password" placeholder="8자 이상" autocomplete="new-password">
          </div>
          <div class="field-wrap">
            <label class="label">비밀번호 확인 <span style="color:var(--c-danger);">*</span></label>
            <input id="reg-password2" class="input" type="password" placeholder="재입력" autocomplete="new-password">
          </div>
          <div class="field-wrap" style="grid-column:1/-1;">
            <label class="label">회사명 <span style="color:var(--c-danger);">*</span></label>
            <input id="reg-company" class="input" type="text" placeholder="(주)○○모터스">
          </div>
          <div class="field-wrap">
            <label class="label">대표자명 <span style="color:var(--c-danger);">*</span></label>
            <input id="reg-rep" class="input" type="text" placeholder="홍길동">
          </div>
          <div class="field-wrap">
            <label class="label">사업자등록번호 <span style="color:var(--c-danger);">*</span></label>
            <input id="reg-bizno" class="input" type="text" placeholder="000-00-00000">
          </div>
          <div class="field-wrap" style="grid-column:1/-1;">
            <label class="label">연락처</label>
            <input id="reg-phone" class="input" type="text" placeholder="02-0000-0000">
          </div>
        </div>
        <div id="register-error" class="auth-error"></div>
        <button id="register-btn" class="btn btn-primary btn-lg" onclick="doRegister()" style="width:100%;margin-top:4px;">
          <i class="fas fa-user-plus"></i>회원가입
        </button>
      </div>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════
     PAGE: 대시보드
════════════════════════════════════════════════ -->
<div id="page-dashboard" class="page">
  <div class="dash-header">
    <div>
      <div class="dash-title">인증신청 목록</div>
      <div id="dash-subtitle" class="dash-sub"></div>
    </div>
    <button class="btn btn-primary" onclick="showNewAppModal()">
      <i class="fas fa-plus"></i>새 신청서 작성
    </button>
  </div>

  <!-- 통계 카드 -->
  <div class="stats-grid">
    <div class="stat-card total">
      <div class="stat-icon"><i class="fas fa-layer-group"></i></div>
      <div id="stat-total" class="stat-num total">0</div>
      <div class="stat-label">전체 신청서</div>
    </div>
    <div class="stat-card prog">
      <div class="stat-icon"><i class="fas fa-pen-nib"></i></div>
      <div id="stat-inprogress" class="stat-num prog">0</div>
      <div class="stat-label">작성중</div>
    </div>
    <div class="stat-card done">
      <div class="stat-icon"><i class="fas fa-check-circle"></i></div>
      <div id="stat-completed" class="stat-num done">0</div>
      <div class="stat-label">완료</div>
    </div>
    <div class="stat-card draft">
      <div class="stat-icon"><i class="fas fa-save"></i></div>
      <div id="stat-draft" class="stat-num draft">0</div>
      <div class="stat-label">임시저장</div>
    </div>
  </div>

  <!-- 목록 -->
  <div id="app-list" style="display:flex;flex-direction:column;gap:12px;"></div>
  <div id="app-empty" class="empty-state" style="display:none;">
    <div class="empty-icon"><i class="fas fa-file-signature"></i></div>
    <div class="empty-title">아직 신청서가 없습니다</div>
    <div class="empty-desc">새 신청서를 작성하여<br>인증 절차를 시작해보세요.</div>
    <button class="btn btn-primary btn-lg" onclick="showNewAppModal()">
      <i class="fas fa-plus"></i>첫 신청서 작성하기
    </button>
  </div>
</div>

<!-- ═══════════════════════════════════════════════
     PAGE: 신청서 상세
════════════════════════════════════════════════ -->
<div id="page-application" class="page">
  <nav class="breadcrumb no-print">
    <button onclick="showDashboard()"><i class="fas fa-home"></i> 목록</button>
    <span class="breadcrumb-sep"><i class="fas fa-chevron-right" style="font-size:.65rem;"></i></span>
    <span id="appl-breadcrumb" style="color:var(--c-text2);"></span>
  </nav>

  <!-- 신청서 헤더 카드 -->
  <div class="appl-hero">
    <div class="appl-hero-left">
      <div class="appl-hero-badges">
        <span id="appl-cert-badge" class="badge badge-blue"></span>
        <span id="appl-status-badge" class="badge badge-gray"></span>
      </div>
      <div class="appl-hero-title" id="appl-title"></div>
      <div class="appl-hero-meta" id="appl-meta"></div>
    </div>
    <div class="appl-hero-right">
      <div class="appl-pct-label">전체 진행률</div>
      <div class="appl-pct" id="appl-progress-pct">0%</div>
      <div class="progress-track" style="width:140px;height:6px;margin-top:10px;">
        <div id="appl-progress-bar" class="progress-fill" style="height:6px;background:var(--grad-accent);width:0%;"></div>
      </div>
    </div>
  </div>

  <div class="forms-section-title">제출 서류 목록</div>
  <div id="forms-grid" class="forms-grid"></div>
</div>

<!-- ═══════════════════════════════════════════════
     PAGE: 서류 입력 폼
════════════════════════════════════════════════ -->
<div id="page-form" class="page">
  <nav class="breadcrumb no-print">
    <button onclick="showDashboard()"><i class="fas fa-home"></i> 목록</button>
    <span class="breadcrumb-sep"><i class="fas fa-chevron-right" style="font-size:.65rem;"></i></span>
    <button id="form-appl-link"></button>
    <span class="breadcrumb-sep"><i class="fas fa-chevron-right" style="font-size:.65rem;"></i></span>
    <span id="form-breadcrumb" style="color:var(--c-text2);"></span>
  </nav>

  <div class="form-page-header no-print">
    <div>
      <div class="form-page-title" id="form-title"></div>
      <div class="form-page-sub" id="form-subtitle"></div>
    </div>
    <div class="form-page-actions">
      <button id="save-btn" class="btn btn-success" onclick="saveForm()">
        <i class="fas fa-save"></i>저장
      </button>
      <button class="btn btn-ghost" onclick="window.print()">
        <i class="fas fa-print"></i>인쇄
      </button>
    </div>
  </div>

  <div id="form-content"></div>

  <!-- 완료 체크 -->
  <div class="complete-card no-print" id="complete-card" onclick="toggleComplete()">
    <input type="checkbox" id="form-completed-chk" class="complete-checkbox" onclick="event.stopPropagation();updateCompleteCard();">
    <div>
      <div class="complete-label-title">이 서류 작성을 완료했습니다</div>
      <div class="complete-label-sub">체크하면 진행률에 반영됩니다</div>
    </div>
    <i class="fas fa-check-circle" style="margin-left:auto;font-size:1.2rem;color:var(--c-success);opacity:0;transition:opacity .2s;" id="complete-check-icon"></i>
  </div>
</div>

<!-- ═══════════════════════════════════════════════
     MODAL: 새 신청서
════════════════════════════════════════════════ -->
<div id="modal-new-app" class="modal-backdrop hidden no-print">
  <div class="modal" onclick="event.stopPropagation()">
    <div class="modal-header">
      <div style="font-size:1.05rem;font-weight:800;letter-spacing:-.02em;">
        <i class="fas fa-file-plus" style="color:var(--c-accent);margin-right:8px;"></i>새 인증신청서 작성
      </div>
      <button class="btn btn-ghost btn-icon btn-sm" onclick="closeNewAppModal()"><i class="fas fa-times"></i></button>
    </div>
    <div class="modal-body">
      <div class="field-wrap">
        <label class="label">신청 제목 <span style="color:var(--c-danger);">*</span></label>
        <input id="new-title" class="input" type="text" placeholder="예) 2025년 Honda CB125R 기본인증">
      </div>
      <div class="field-wrap">
        <label class="label">인증 유형 <span style="color:var(--c-danger);">*</span></label>
        <select id="new-cert-type" class="input" onchange="onNewCertTypeChange()">
          <option value="basic">기본인증 — 신규 수입이륜차</option>
          <option value="change">변경인증 — 인증사항 중요 변경</option>
          <option value="report">변경보고 — 경미한 사항 변경</option>
        </select>
      </div>
      <div id="new-prev-cert-wrap" class="field-wrap" style="display:none;">
        <label class="label">기존 인증번호 <span style="color:var(--c-danger);">*</span></label>
        <input id="new-prev-cert" class="input" type="text" placeholder="기존 인증번호 입력">
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;">
        <div class="field-wrap">
          <label class="label">브랜드</label>
          <input id="new-brand" class="input" type="text" placeholder="Honda">
        </div>
        <div class="field-wrap">
          <label class="label">차종명</label>
          <input id="new-model" class="input" type="text" placeholder="CB125R">
        </div>
        <div class="field-wrap">
          <label class="label">연식</label>
          <input id="new-year" class="input" type="text" placeholder="2025">
        </div>
      </div>
      <div id="modal-error" class="auth-error"></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="closeNewAppModal()">취소</button>
      <button id="create-btn" class="btn btn-primary" onclick="createApplication()">
        <i class="fas fa-check"></i>신청서 생성
      </button>
    </div>
  </div>
</div>

<script>
// ================================================================
// 상태
// ================================================================
let currentUser = null, currentApplications = [], currentApplication = null;
let currentForms = [], currentFormType = null, currentApplicationId = null;

const FORM_META = [
  { type:'summary',        title:'인증신청 요약서',              icon:'fa-file-alt',       color:'#4f8ef7', bg:'rgba(79,142,247,.12)'   },
  { type:'gasoline',       title:'휘발유차 인증신청 주요내용',   icon:'fa-gas-pump',       color:'#f97316', bg:'rgba(249,115,22,.12)'   },
  { type:'detail_plan',    title:'인증에 필요한 세부 계획 서류', icon:'fa-clipboard-list', color:'#a855f7', bg:'rgba(168,85,247,.12)'   },
  { type:'emission_noise', title:'배출가스·소음 저감 서류',      icon:'fa-wind',           color:'#06b6d4', bg:'rgba(6,182,212,.12)'    },
  { type:'obd_config',     title:'OBD 구성에 관한 서류',         icon:'fa-microchip',      color:'#6366f1', bg:'rgba(99,102,241,.12)'   },
  { type:'emission_test',  title:'배출가스 시험보고서',          icon:'fa-flask',          color:'#22c55e', bg:'rgba(34,197,94,.12)'    },
  { type:'evap_test',      title:'증발가스 시험내용 보고서',     icon:'fa-vials',          color:'#eab308', bg:'rgba(234,179,8,.12)'    },
  { type:'obd_operation',  title:'OBD 작동 확인시험 보고서',    icon:'fa-cogs',           color:'#ef4444', bg:'rgba(239,68,68,.12)'    },
  { type:'noise_test',     title:'자동차소음 시험내용 보고서',   icon:'fa-volume-up',      color:'#ec4899', bg:'rgba(236,72,153,.12)'   },
  { type:'confirmation',   title:'확인서',                       icon:'fa-stamp',          color:'#64748b', bg:'rgba(100,116,139,.12)'  },
];
const CERT_LABEL   = { basic:'기본인증', change:'변경인증', report:'변경보고' };
const STATUS_LABEL = { draft:'임시저장', in_progress:'작성중', completed:'완료' };
const STATUS_BADGE = { draft:'badge-gray', in_progress:'badge-yellow', completed:'badge-green' };

// ================================================================
// 토큰
// ================================================================
const getToken   = () => localStorage.getItem('auth_token');
const setToken   = t  => localStorage.setItem('auth_token', t);
const clearToken = () => localStorage.removeItem('auth_token');

async function api(path, opts = {}) {
  const token = getToken();
  const headers = { 'Content-Type':'application/json', ...(opts.headers||{}) };
  if (token) headers['Authorization'] = 'Bearer ' + token;
  return fetch(path, { ...opts, headers });
}

// ================================================================
// 초기화
// ================================================================
async function init() {
  if (!getToken()) { showPage('page-auth'); return; }
  try {
    const res = await api('/api/auth/me');
    if (res.ok) { currentUser = (await res.json()).user; showDashboard(); }
    else { clearToken(); showPage('page-auth'); }
  } catch { showPage('page-auth'); }
}

// ================================================================
// 페이지
// ================================================================
function showPage(id) {
  document.querySelectorAll('.page').forEach(p => { p.style.display='none'; p.classList.remove('active'); });
  const el = document.getElementById(id);
  el.style.display = 'block'; el.classList.add('active');
  window.scrollTo({ top:0, behavior:'smooth' });
}

function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// ================================================================
// 헤더
// ================================================================
function updateHeader() {
  const el = document.getElementById('header-user');
  if (!currentUser) { el.innerHTML = ''; return; }
  el.innerHTML = \`
    <div style="text-align:right;line-height:1.3;">
      <div style="font-size:.85rem;font-weight:700;color:var(--c-text);">\${esc(currentUser.company_name)}</div>
      <div style="font-size:.72rem;color:var(--c-text3);">@\${esc(currentUser.username)}</div>
    </div>
    <div style="width:1px;height:24px;background:var(--c-border);"></div>
    <button class="btn btn-ghost btn-sm" onclick="doLogout()">
      <i class="fas fa-sign-out-alt"></i>로그아웃
    </button>
  \`;
}

// ================================================================
// 인증
// ================================================================
function showAuthTab(tab) {
  const isLogin = tab === 'login';
  document.getElementById('login-form').style.display    = isLogin ? 'flex' : 'none';
  document.getElementById('register-form').style.display = isLogin ? 'none' : 'flex';
  document.getElementById('tab-login').className    = 'auth-tab' + (isLogin ? ' active' : '');
  document.getElementById('tab-register').className = 'auth-tab' + (!isLogin ? ' active' : '');
}

function showFieldError(id, msg) {
  const el = document.getElementById(id);
  el.textContent = msg; el.style.display = 'block';
}
function hideFieldError(id) { document.getElementById(id).style.display = 'none'; }

async function doLogin() {
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  hideFieldError('login-error');
  if (!username || !password) { showFieldError('login-error','아이디와 비밀번호를 입력하세요.'); return; }
  const btn = document.getElementById('login-btn');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>로그인 중...';
  try {
    const res  = await fetch('/api/auth/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username,password}) });
    const data = await res.json();
    if (!res.ok) { showFieldError('login-error', data.error||'로그인 실패'); return; }
    setToken(data.token); currentUser = data.user; showDashboard();
  } catch { showFieldError('login-error','네트워크 오류가 발생했습니다.'); }
  finally { btn.disabled=false; btn.innerHTML='<i class="fas fa-sign-in-alt"></i>로그인'; }
}

async function doRegister() {
  const username=document.getElementById('reg-username').value.trim(),
        password=document.getElementById('reg-password').value,
        pw2     =document.getElementById('reg-password2').value,
        company =document.getElementById('reg-company').value.trim(),
        rep     =document.getElementById('reg-rep').value.trim(),
        bizno   =document.getElementById('reg-bizno').value.trim(),
        phone   =document.getElementById('reg-phone').value.trim();
  hideFieldError('register-error');
  if (!username||!password||!company||!rep||!bizno) { showFieldError('register-error','필수 항목을 모두 입력해주세요.'); return; }
  if (!/^[a-zA-Z0-9_]{4,20}$/.test(username)) { showFieldError('register-error','아이디는 영문·숫자·밑줄 4~20자로 입력해주세요.'); return; }
  if (password.length < 8) { showFieldError('register-error','비밀번호는 8자 이상이어야 합니다.'); return; }
  if (password !== pw2)    { showFieldError('register-error','비밀번호가 일치하지 않습니다.'); return; }
  const btn = document.getElementById('register-btn');
  btn.disabled = true; btn.innerHTML = '<div class="spinner"></div>가입 중...';
  try {
    const res  = await fetch('/api/auth/register', { method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username,password,company_name:company,representative:rep,business_number:bizno,phone}) });
    const data = await res.json();
    if (!res.ok) { showFieldError('register-error', data.error||'회원가입 실패'); return; }
    setToken(data.token); currentUser = data.user;
    showToast('회원가입이 완료되었습니다. 환영합니다!','success'); showDashboard();
  } catch { showFieldError('register-error','네트워크 오류가 발생했습니다.'); }
  finally { btn.disabled=false; btn.innerHTML='<i class="fas fa-user-plus"></i>회원가입'; }
}

async function doLogout() {
  clearToken(); currentUser=null; currentApplications=[];
  showPage('page-auth'); updateHeader();
}

// ================================================================
// 대시보드
// ================================================================
async function showDashboard() {
  updateHeader(); showPage('page-dashboard');
  document.getElementById('dash-subtitle').textContent = currentUser
    ? currentUser.company_name + '  ·  @' + currentUser.username : '';
  await loadApplications();
}

async function loadApplications() {
  try {
    const res = await api('/api/applications');
    if (!res.ok) { if(res.status===401){clearToken();showPage('page-auth');} return; }
    currentApplications = (await res.json()).applications || [];
    renderAppList();
  } catch { showToast('목록을 불러오지 못했습니다.','error'); }
}

function renderAppList() {
  const total = currentApplications.length;
  const prog  = currentApplications.filter(a=>a.status==='in_progress').length;
  const done  = currentApplications.filter(a=>a.status==='completed').length;
  const draft = currentApplications.filter(a=>a.status==='draft').length;
  document.getElementById('stat-total').textContent      = total;
  document.getElementById('stat-inprogress').textContent = prog;
  document.getElementById('stat-completed').textContent  = done;
  document.getElementById('stat-draft').textContent      = draft;
  const listEl  = document.getElementById('app-list');
  const emptyEl = document.getElementById('app-empty');
  if (!total) { listEl.innerHTML=''; emptyEl.style.display='block'; return; }
  emptyEl.style.display = 'none';
  listEl.innerHTML = currentApplications.map(a => {
    const done_f  = a.completed_forms || 0;
    const total_f = a.total_forms || 10;
    const pct     = Math.round(done_f/total_f*100);
    const date    = new Date(a.updated_at).toLocaleDateString('ko-KR',{month:'short',day:'numeric'});
    const metaStr = [a.brand,a.model,a.model_year?a.model_year+'년식':''].filter(Boolean).join(' ');
    const certBadge = { basic:'badge-blue', change:'badge-violet', report:'badge-yellow' }[a.cert_type] || 'badge-gray';
    return \`
      <div class="app-item">
        <div class="app-item-icon"><i class="fas fa-file-alt"></i></div>
        <div class="app-item-body">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap;">
            <span class="badge \${certBadge}">\${CERT_LABEL[a.cert_type]||a.cert_type}</span>
            <span class="badge \${STATUS_BADGE[a.status]||'badge-gray'}">\${STATUS_LABEL[a.status]||a.status}</span>
          </div>
          <div class="app-item-title">\${esc(a.title)}</div>
          <div class="app-item-meta">\${esc(metaStr)} &nbsp;·&nbsp; \${date} 수정</div>
          <div style="display:flex;align-items:center;gap:10px;">
            <div class="progress-track" style="flex:1;height:4px;">
              <div class="progress-fill" style="height:4px;background:var(--grad-accent);width:\${pct}%;"></div>
            </div>
            <span style="font-size:.75rem;color:var(--c-text3);flex-shrink:0;">\${done_f}/\${total_f}</span>
          </div>
        </div>
        <div class="app-item-actions">
          <button class="btn btn-primary btn-sm" onclick="openApplication(\${a.id})">
            <i class="fas fa-edit"></i>작성
          </button>
          <button class="btn btn-danger btn-sm btn-icon" onclick="deleteApplication(event,\${a.id})" title="삭제">
            <i class="fas fa-trash-alt"></i>
          </button>
        </div>
      </div>
    \`;
  }).join('');
}

// ================================================================
// 신청서 상세
// ================================================================
async function openApplication(id) {
  try {
    const res = await api('/api/applications/'+id);
    if (!res.ok) { showToast('불러오기 실패','error'); return; }
    const data = await res.json();
    currentApplication = data.application; currentForms = data.forms; currentApplicationId = id;
    renderApplicationPage(); showPage('page-application');
  } catch { showToast('네트워크 오류','error'); }
}

function renderApplicationPage() {
  const a = currentApplication;
  document.getElementById('appl-breadcrumb').textContent = a.title;
  const certBadge  = { basic:'badge-blue', change:'badge-violet', report:'badge-yellow' }[a.cert_type]||'badge-gray';
  document.getElementById('appl-cert-badge').className   = 'badge ' + certBadge;
  document.getElementById('appl-cert-badge').textContent = CERT_LABEL[a.cert_type]||a.cert_type;
  const sb = document.getElementById('appl-status-badge');
  sb.className   = 'badge ' + (STATUS_BADGE[a.status]||'badge-gray');
  sb.textContent = STATUS_LABEL[a.status]||a.status;
  document.getElementById('appl-title').textContent = a.title;
  document.getElementById('appl-meta').textContent  = [a.brand,a.model,a.model_year?a.model_year+'년식':''].filter(Boolean).join(' · ');
  const done  = currentForms.filter(f=>f.completed).length;
  const total = currentForms.length;
  const pct   = total ? Math.round(done/total*100) : 0;
  document.getElementById('appl-progress-pct').textContent = pct + '%';
  document.getElementById('appl-progress-bar').style.width = pct + '%';
  document.getElementById('forms-grid').innerHTML = FORM_META.map((m,i) => {
    const fd    = currentForms.find(f=>f.form_type===m.type);
    const isDone = !!fd?.completed;
    return \`
      <div class="form-card \${isDone?'done':''}" onclick="openForm('\${m.type}')">
        <div class="form-card-icon" style="background:\${isDone?'rgba(0,200,150,.12)':m.bg};color:\${isDone?'var(--c-success)':m.color};">
          <i class="fas \${m.icon}"></i>
        </div>
        <div class="form-card-body">
          <div class="form-card-num">
            서류 \${i+1}
            &nbsp;
            \${isDone
              ? '<span class="badge badge-green" style="font-size:.65rem;padding:2px 7px;"><i class="fas fa-check" style="margin-right:2px;"></i>완료</span>'
              : '<span class="badge badge-gray" style="font-size:.65rem;padding:2px 7px;">미완료</span>'
            }
          </div>
          <div class="form-card-name">\${m.title}</div>
        </div>
        <i class="fas fa-chevron-right form-card-chevron"></i>
      </div>
    \`;
  }).join('');
}

// ================================================================
// 서류 폼
// ================================================================
async function openForm(formType) {
  currentFormType = formType;
  const meta   = FORM_META.find(m=>m.type===formType);
  const fd     = currentForms.find(f=>f.form_type===formType);
  let saved = {};
  try { saved = JSON.parse(fd?.data||'{}'); } catch {}
  const link = document.getElementById('form-appl-link');
  link.textContent = currentApplication.title;
  link.onclick = () => openApplication(currentApplicationId);
  document.getElementById('form-breadcrumb').textContent = meta.title;
  document.getElementById('form-title').textContent      = meta.title;
  document.getElementById('form-subtitle').textContent   = CERT_LABEL[currentApplication.cert_type]+' · '+currentApplication.title;
  const chk = document.getElementById('form-completed-chk');
  chk.checked = !!fd?.completed;
  updateCompleteCard();
  document.getElementById('form-content').innerHTML = buildFormHTML(formType, saved);
  showPage('page-form');
}

function toggleComplete() {
  const chk = document.getElementById('form-completed-chk');
  chk.checked = !chk.checked;
  updateCompleteCard();
}
function updateCompleteCard() {
  const chk  = document.getElementById('form-completed-chk');
  const card = document.getElementById('complete-card');
  const icon = document.getElementById('complete-check-icon');
  if (chk.checked) { card.classList.add('checked'); icon.style.opacity='1'; }
  else { card.classList.remove('checked'); icon.style.opacity='0'; }
}

async function saveForm() {
  const data = {};
  document.querySelectorAll('#form-content [data-field]').forEach(el => {
    data[el.dataset.field] = el.type==='checkbox' ? String(el.checked) : el.value;
  });
  const completed = document.getElementById('form-completed-chk').checked;
  const btn = document.getElementById('save-btn');
  btn.disabled = true; btn.innerHTML = '<div class="spinner"></div>저장 중...';
  try {
    const res = await api('/api/applications/'+currentApplicationId+'/forms/'+currentFormType,
      { method:'PUT', body:JSON.stringify({data,completed}) });
    if (res.ok) {
      showToast('저장되었습니다.','success');
      const idx = currentForms.findIndex(f=>f.form_type===currentFormType);
      if (idx>=0) { currentForms[idx].data=JSON.stringify(data); currentForms[idx].completed=completed?1:0; }
    } else { showToast('저장 실패','error'); }
  } catch { showToast('네트워크 오류','error'); }
  finally { btn.disabled=false; btn.innerHTML='<i class="fas fa-save"></i>저장'; }
}

// ================================================================
// 신청서 생성/삭제
// ================================================================
function showNewAppModal() {
  ['new-title','new-brand','new-model','new-year'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('new-cert-type').value = 'basic';
  document.getElementById('modal-error').style.display = 'none';
  document.getElementById('create-btn').disabled = false;
  document.getElementById('create-btn').innerHTML = '<i class="fas fa-check"></i>신청서 생성';
  onNewCertTypeChange();
  document.getElementById('modal-new-app').classList.remove('hidden');
  setTimeout(()=>document.getElementById('new-title').focus(),150);
}
function closeNewAppModal() { document.getElementById('modal-new-app').classList.add('hidden'); }
function onNewCertTypeChange() {
  const v = document.getElementById('new-cert-type').value;
  document.getElementById('new-prev-cert-wrap').style.display = v==='basic' ? 'none' : 'flex';
}
document.getElementById('modal-new-app').addEventListener('click', function(e){ if(e.target===this)closeNewAppModal(); });

async function createApplication() {
  const title    = document.getElementById('new-title').value.trim();
  const cert_type= document.getElementById('new-cert-type').value;
  const brand    = document.getElementById('new-brand').value.trim();
  const model    = document.getElementById('new-model').value.trim();
  const model_year= document.getElementById('new-year').value.trim();
  const prev_cert= document.getElementById('new-prev-cert')?.value.trim()||'';
  const errEl    = document.getElementById('modal-error');
  errEl.style.display = 'none';
  if (!title) { errEl.textContent='신청 제목을 입력하세요.'; errEl.style.display='block'; document.getElementById('new-title').focus(); return; }
  if ((cert_type==='change'||cert_type==='report')&&!prev_cert) {
    errEl.textContent='기존 인증번호를 입력하세요.'; errEl.style.display='block'; return; }
  const btn = document.getElementById('create-btn');
  btn.disabled=true; btn.innerHTML='<div class="spinner"></div>생성 중...';
  try {
    const res  = await api('/api/applications',{method:'POST',body:JSON.stringify({title,cert_type,brand,model,model_year,prev_cert_number:prev_cert})});
    const data = await res.json();
    if (!res.ok) { errEl.textContent=data.error||'생성 실패'; errEl.style.display='block'; return; }
    closeNewAppModal();
    showToast('신청서가 생성되었습니다.','success');
    await openApplication(data.application.id);
  } catch { errEl.textContent='네트워크 오류가 발생했습니다.'; errEl.style.display='block'; }
  finally { btn.disabled=false; btn.innerHTML='<i class="fas fa-check"></i>신청서 생성'; }
}

async function deleteApplication(e, id) {
  e.stopPropagation();
  if (!confirm('신청서를 삭제하면 모든 서류 데이터도 함께 삭제됩니다.\\n계속하시겠습니까?')) return;
  const res = await api('/api/applications/'+id,{method:'DELETE'});
  if (res.ok) { showToast('삭제되었습니다.','info'); await loadApplications(); }
  else showToast('삭제 실패','error');
}

// ================================================================
// 폼 HTML 빌더
// ================================================================
function buildFormHTML(formType, saved) {
  const v   = (k,def='') => saved[k]!==undefined ? saved[k] : def;
  const E   = esc;
  const fld = (label, key, type='text', ph='', note='') => \`
    <div class="field-wrap">
      <label class="label">\${label}</label>
      <input type="\${type}" data-field="\${key}" value="\${E(v(key))}" placeholder="\${ph}" class="input">
      \${note?'<span class="field-note">'+note+'</span>':''}
    </div>\`;
  const ta  = (label, key, ph='', rows=3) => \`
    <div class="field-wrap">
      <label class="label">\${label}</label>
      <textarea data-field="\${key}" rows="\${rows}" placeholder="\${ph}" class="input">\${E(v(key))}</textarea>
    </div>\`;
  const sel = (label, key, opts) => \`
    <div class="field-wrap">
      <label class="label">\${label}</label>
      <select data-field="\${key}" class="input">
        \${opts.map(([val,txt])=>\`<option value="\${val}" \${v(key)===val?'selected':''}>\${txt}</option>\`).join('')}
      </select>
    </div>\`;
  const sec = (title, icon, fields, full=false) => \`
    <div class="form-section">
      <div class="form-section-title"><i class="fas \${icon}"></i>\${title}</div>
      <div class="\${full?'form-grid-full':'form-grid'}">\${fields}</div>
    </div>\`;

  if (formType==='summary') return (
    sec('신청인 정보','fa-building',
      fld('신청인 (회사명)','company','text','(주)○○모터스')+fld('대표자','rep','text','홍길동')+
      fld('사업자등록번호','bizno','text','000-00-00000')+fld('주소','address','text','서울시...')+
      fld('연락처','phone','text','02-0000-0000')+fld('담당자','manager','text','담당자명'))+
    sec('차량 개요','fa-motorcycle',
      fld('제작사 (브랜드)','brand','text','Honda')+fld('차종명','model','text','CB125R')+
      fld('원산지','origin','text','일본')+fld('연식','model_year','text','2025')+
      sel('연료 종류','fuel',[['gasoline','휘발유'],['electric','전기'],['lpg','LPG']])+
      sel('변속기','trans',[['manual','수동'],['auto','자동'],['cvt','CVT']])+
      fld('차대번호(VIN)','vin','text',''))+
    sec('배출가스 기준','fa-smog',
      fld('적용 배출가스 기준','emission_std','text','EURO 5')+fld('OBD 단계','obd_stage','text','OBD-II')+
      fld('대표 차종 여부','is_rep','text','해당/비해당')+fld('보증기간 (km)','warranty_km','number','30000')+
      fld('보증기간 (년)','warranty_year','number','5'))+
    sec('소음 기준','fa-volume-up',
      fld('적용 소음 기준','noise_std','text','ECE R41')+fld('가속소음 (dB(A))','accel_noise','number','')+
      fld('배기소음 (dB(A))','exhaust_noise','number',''))
  );

  if (formType==='gasoline') return (
    sec('기본 차량 정보','fa-car',
      fld('제작사명','maker')+fld('차종명','model')+fld('배기량 (cc)','displacement','number')+
      fld('연료 공급 방식','fuel_supply','text','전자제어 분사')+fld('냉각 방식','cooling','text','수냉/공냉')+
      fld('기통수','cylinders','number','1'))+
    sec('적용 인증 기준','fa-certificate',
      sel('배출가스 기준','emission_std',[['EURO5','EURO 5'],['EURO6','EURO 6'],['EURO4','EURO 4']])+
      fld('OBD 단계','obd_stage','text','OBD-II')+fld('증발가스 기준','evap_std')+fld('인증 적용 대상','cert_target'))+
    sec('대표 차종','fa-layer-group',
      fld('대표 차종 여부','is_rep')+fld('대표 차종명','rep_model')+fld('포함 차종 수','family_count','number','1'))+
    sec('보증 기간','fa-shield-alt',
      fld('보증기간 (km)','warranty_km','number')+fld('보증기간 (년)','warranty_year','number')+
      fld('자가 진단 교환 주기','obd_interval'))+
    sec('배출가스 시험 결과 (WMTC)','fa-flask',
      fld('CO 측정값 (g/km)','co_result','number')+fld('NOx 측정값 (g/km)','nox_result','number')+
      fld('HC 측정값 (g/km)','hc_result','number')+fld('NMHC 측정값 (g/km)','nmhc_result','number')+
      fld('CO 기준값','co_std','number')+fld('NOx 기준값','nox_std','number'))
  );

  if (formType==='detail_plan') return (
    sec('차량 기본 사양','fa-info-circle',
      fld('제작사','maker')+fld('차종명','model')+fld('연식','model_year')+
      fld('차량 총중량 (kg)','gvw','number')+fld('공차중량 (kg)','curb_weight','number')+
      fld('전장 (mm)','length','number')+fld('전폭 (mm)','width','number')+
      fld('전고 (mm)','height','number')+fld('축간거리 (mm)','wheelbase','number'))+
    sec('엔진 사양','fa-cog',
      fld('배기량 (cc)','displacement','number')+fld('최고출력 (kW)','max_power','number')+
      fld('최대토크 (N·m)','max_torque','number')+fld('보어 × 스트로크 (mm)','bore_stroke')+
      fld('압축비','compression')+fld('연료탱크 용량 (L)','fuel_tank','number'))+
    sec('촉매 장치','fa-filter',
      fld('촉매 종류','catalyst_type','text','3원 촉매')+fld('귀금속 성분 (Pt)','cat_pt','number')+
      fld('귀금속 성분 (Pd)','cat_pd','number')+fld('귀금속 성분 (Rh)','cat_rh','number')+
      fld('촉매 위치','cat_location'))+
    sec('배출가스 개발 목표','fa-bullseye',
      fld('CO 목표 (g/km)','target_co','number')+fld('NOx 목표 (g/km)','target_nox','number')+
      fld('THC 목표 (g/km)','target_thc','number')+fld('NMHC 목표 (g/km)','target_nmhc','number')+
      fld('PM 목표 (g/km)','target_pm','number'))
  );

  if (formType==='emission_noise') return (
    sec('소음기','fa-volume-mute',
      fld('소음기 종류','muffler_type')+fld('소음기 재질','muffler_material')+
      fld('소음기 외경 (mm)','muffler_od','number')+fld('소음기 길이 (mm)','muffler_length','number'))+
    sec('소음기 구조 설명','fa-align-left',ta('소음기 구조 및 작동 방식','muffler_desc','소음기 구조 설명',3),true)+
    sec('촉매 변환장치','fa-filter',
      fld('촉매 형식','cat_type')+fld('촉매 용량 (L)','cat_volume','number')+
      fld('셀 밀도 (cpsi)','cat_cpsi','number')+fld('귀금속 함량 (g/ft³)','cat_pgm','number'))+
    sec('배출가스 저감 기술','fa-leaf',ta('주요 저감 기술 설명','emission_tech','엔진 제어, 연료분사, 촉매 등',4),true)+
    sec('소음 측정 결과 요약','fa-chart-bar',
      fld('가속소음 측정값 (dB(A))','accel_noise_meas','number')+fld('가속소음 기준값 (dB(A))','accel_noise_std','number')+
      fld('배기소음 측정값 (dB(A))','exhaust_noise_meas','number')+fld('배기소음 기준값 (dB(A))','exhaust_noise_std','number'))
  );

  if (formType==='obd_config') return (
    sec('OBD 시스템 개요','fa-microchip',
      fld('OBD 시스템 제조사','obd_maker')+fld('ECU 제조사','ecu_maker')+fld('OBD 적용 단계','obd_stage','text','OBD-II'))+
    sec('OBD 개요 설명','fa-align-left',ta('OBD 시스템 전반적인 구성 설명','obd_overview','OBD 시스템 설명',3),true)+
    sec('모니터링 항목','fa-list-check',
      fld('크랭크 포지션 센서 (CPS)','mon_cps','text','해당/비해당')+fld('T-MAP 센서','mon_tmap','text','해당/비해당')+
      fld('스로틀 포지션 센서 (TPS)','mon_tps','text','해당/비해당')+fld('수온 센서 (WTS)','mon_wts','text','해당/비해당')+
      fld('O₂ 센서','mon_o2','text','해당/비해당')+fld('연료 인젝터','mon_injector','text','해당/비해당')+
      fld('점화 코일','mon_ignition','text','해당/비해당')+fld('촉매 (CAT)','mon_catalyst','text','해당/비해당')+
      fld('실화 모니터','mon_misfire','text','해당/비해당')+fld('연료 계통','mon_fuel_sys','text','해당/비해당'))+
    sec('고장 표시 장치','fa-exclamation-triangle',
      fld('MIL 위치','mil_location')+fld('OBD 커넥터 위치','obd_connector'))+
    sec('DTC 처리 방식','fa-align-left',ta('고장코드 발생 조건 및 소거 방법','dtc_handling','DTC 처리 방식 설명',3),true)
  );

  if (formType==='emission_test') return (
    sec('시험 일반 정보','fa-clipboard',
      fld('시험기관','test_lab')+fld('시험일','test_date','date')+
      fld('시험 모드','test_mode','text','WMTC')+fld('시험 담당자','tester'))+
    sec('차량 정보','fa-motorcycle',
      fld('차종명','model')+fld('연식','model_year')+fld('차대번호','vin')+
      fld('공차중량 (kg)','curb_weight','number')+fld('시험 중량 (kg)','test_weight','number')+
      fld('주행거리 (km)','mileage','number'))+
    sec('시험 조건','fa-thermometer-half',
      fld('실내 온도 (°C)','room_temp','number')+fld('대기압 (kPa)','atm_pressure','number')+
      fld('습도 (%)','humidity','number')+fld('연료 종류','fuel_type','text','무연 휘발유'))+
    sec('배출가스 측정 결과 (g/km)','fa-chart-line',
      fld('HC 측정값','hc_result','number')+fld('HC 기준값','hc_limit','number')+
      fld('CO 측정값','co_result','number')+fld('CO 기준값','co_limit','number')+
      fld('NOx 측정값','nox_result','number')+fld('NOx 기준값','nox_limit','number')+
      fld('NMHC 측정값','nmhc_result','number')+fld('NMHC 기준값','nmhc_limit','number')+
      fld('CO₂ (g/km)','co2_result','number')+fld('연비 (km/L)','fuel_economy','number'))
  );

  if (formType==='evap_test') return (
    sec('시험 일반 정보','fa-clipboard',
      fld('시험기관','test_lab')+fld('시험일','test_date','date')+fld('시험 담당자','tester'))+
    sec('차량 및 연료','fa-gas-pump',
      fld('차종명','model')+fld('차대번호','vin')+
      fld('연료탱크 용량 (L)','fuel_tank','number')+fld('카니스터 용량 (g)','canister_cap','number'))+
    sec('시험 결과','fa-vials',
      fld('고온 침지 측정값 (g)','hot_soak_result','number')+fld('고온 침지 기준값 (g)','hot_soak_limit','number')+
      fld('주간 증발 측정값 (g)','diurnal_result','number')+fld('주간 증발 기준값 (g)','diurnal_limit','number')+
      fld('합산 측정값 (g)','total_result','number')+fld('합산 기준값 (g)','total_limit','number'))
  );

  if (formType==='obd_operation') return (
    sec('시험 일반 정보','fa-clipboard',
      fld('시험기관','test_lab')+fld('시험일','test_date','date')+fld('시험 담당자','tester'))+
    sec('차량 정보','fa-motorcycle',
      fld('차종명','model')+fld('차대번호','vin')+fld('공차중량 (kg)','curb_weight','number')+
      fld('연료 종류','fuel_type')+fld('변속기 종류','trans_type'))+
    sec('배출가스 제어 장치','fa-sliders-h',
      fld('촉매 종류','catalyst_type')+fld('ECU 제조사','ecu_maker')+
      fld('O₂ 센서 종류','o2_type')+fld('EGR 장치','egr','text','해당/비해당')+
      fld('2차 공기 공급','secondary_air','text','해당/비해당')+fld('퍼지 밸브','purge_valve'))+
    sec('OBD 작동 확인 시험 결과','fa-chart-bar',
      fld('CO 측정값 (g/km)','co_meas','number')+fld('CO 고장 허용값','co_fault','number')+
      fld('NOx 측정값 (g/km)','nox_meas','number')+fld('NOx 고장 허용값','nox_fault','number')+
      fld('HC 측정값 (g/km)','hc_meas','number')+fld('HC 고장 허용값','hc_fault','number'))
  );

  if (formType==='noise_test') return (
    sec('시험 일반 정보','fa-clipboard',
      fld('시험기관','test_lab')+fld('시험일','test_date','date')+
      fld('적용 법규','regulation','text','ECE R41')+fld('시험 담당자','tester'))+
    sec('시험 환경','fa-cloud-sun',
      fld('시험장 표면','surface','text','ISO 10844 아스팔트')+fld('배경소음 (dB(A))','bg_noise','number')+
      fld('온도 (°C)','temp','number')+fld('풍속 (m/s)','wind','number'))+
    sec('차량 정보','fa-motorcycle',
      fld('차종명','model')+fld('차대번호','vin')+fld('공차중량 (kg)','curb_weight','number')+
      fld('최고출력 (kW)','max_power','number')+fld('변속기 종류','trans_type')+fld('타이어 규격','tire_spec'))+
    sec('가속소음 시험 결과','fa-volume-up',
      fld('1차 좌 (dB(A))','accel_l1','number')+fld('1차 우 (dB(A))','accel_r1','number')+
      fld('2차 좌 (dB(A))','accel_l2','number')+fld('2차 우 (dB(A))','accel_r2','number')+
      fld('평균 측정값 (dB(A))','accel_avg','number')+fld('기준값 (dB(A))','accel_limit','number'))+
    sec('배기소음 시험 결과','fa-volume-down',
      fld('배기소음 측정값 (dB(A))','exhaust_meas','number')+fld('배기소음 기준값 (dB(A))','exhaust_limit','number')+
      fld('측정 장비 (소음계)','noise_meter'))
  );

  if (formType==='confirmation') return (
    sec('확인서 정보','fa-file-signature',
      fld('신청인 (회사명)','company')+fld('대표자','rep')+
      fld('작성일','confirm_date','date')+fld('차종명','model')+fld('인증 유형','cert_type_text'))+
    \`<div class="form-section">
      <div class="form-section-title"><i class="fas fa-check-double"></i>보증 내용 확인</div>
      <div class="form-grid-full">
        \${[
          ['chk_warranty','「대기환경보전법」 제48조에 따른 배출가스 보증 의무를 이행하겠습니다.'],
          ['chk_doc',     '제출된 서류는 모두 사실임을 확인합니다.'],
          ['chk_translate','외국어 서류의 경우 번역본을 함께 제출합니다.'],
          ['chk_change',  '인증사항 변경 시 즉시 변경인증 또는 변경보고를 하겠습니다.'],
          ['chk_recall',  '결함이 발견될 경우 시정조치(리콜) 의무를 이행하겠습니다.'],
        ].map(([key,text])=>\`
          <label style="display:flex;align-items:flex-start;gap:12px;padding:14px 16px;border:1px solid var(--c-border);border-radius:var(--r-sm);cursor:pointer;transition:all var(--transition);"
            onmouseover="this.style.borderColor='var(--c-border2)';this.style.background='rgba(255,255,255,.02)'"
            onmouseout="this.style.borderColor='var(--c-border)';this.style.background='transparent'">
            <input type="checkbox" data-field="\${key}" \${v(key)==='true'?'checked':''}
              onchange="this.value=this.checked"
              style="margin-top:2px;width:17px;height:17px;accent-color:var(--c-accent);flex-shrink:0;cursor:pointer;">
            <span style="font-size:.875rem;color:var(--c-text2);line-height:1.6;">\${text}</span>
          </label>\`).join('')}
      </div>
    </div>\`+
    sec('서명','fa-pen',fld('대표자 서명 (타이핑)','signature','text','성명 입력'))
  );

  return '<div class="form-section" style="text-align:center;color:var(--c-text3);padding:40px;">준비 중입니다.</div>';
}

// ================================================================
// 토스트
// ================================================================
function showToast(msg, type='info') {
  const icons = { success:'fa-check', error:'fa-exclamation', info:'fa-info' };
  const stack = document.getElementById('toast-stack');
  const t = document.createElement('div');
  t.className = 'toast toast-'+type;
  t.innerHTML = \`<div class="toast-icon"><i class="fas \${icons[type]||'fa-info'}"></i></div><span>\${esc(msg)}</span>\`;
  stack.appendChild(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(()=>t.remove(), 300); }, 3000);
}

// ================================================================
// 초기 실행
// ================================================================
document.addEventListener('DOMContentLoaded', init);
</script>
</body>
</html>`;

app.get('/', (c) => c.html(HTML))
app.get('*', (c) => c.html(HTML))

export default app

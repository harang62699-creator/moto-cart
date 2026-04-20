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

// ────────────────────────────────────────────────
// 유틸: 간단 JWT (HMAC-SHA256, 유니코드 안전)
// ────────────────────────────────────────────────
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

// ────────────────────────────────────────────────
// 미들웨어: 인증 체크
// ────────────────────────────────────────────────
async function authMiddleware(c: any, next: () => Promise<void>) {
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  if (!token) return c.json({ error: 'Unauthorized' }, 401)
  const payload = await verifyJWT(token)
  if (!payload) return c.json({ error: 'Invalid token' }, 401)
  c.set('user', payload)
  await next()
}

// ────────────────────────────────────────────────
// API: 인증
// ────────────────────────────────────────────────
app.post('/api/auth/register', async (c) => {
  const { username, password, company_name, representative, business_number, phone } = await c.req.json()
  if (!username || !password || !company_name || !representative || !business_number) {
    return c.json({ error: '필수 항목을 모두 입력해주세요.' }, 400)
  }
  if (!/^[a-zA-Z0-9_]{4,20}$/.test(username)) {
    return c.json({ error: '아이디는 영문·숫자·밑줄 4~20자로 입력해주세요.' }, 400)
  }
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

app.post('/api/auth/logout', async (c) => {
  return c.json({ ok: true })
})

app.get('/api/auth/me', authMiddleware, async (c) => {
  const payload = c.get('user') as any
  const user = await c.env.DB.prepare('SELECT id, username, company_name, representative, business_number, phone FROM users WHERE id = ?').bind(payload.id).first()
  if (!user) return c.json({ error: 'Not found' }, 404)
  return c.json({ user })
})

// ────────────────────────────────────────────────
// API: 신청서 CRUD
// ────────────────────────────────────────────────
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
    const stmts = formTypes.map(ft =>
      c.env.DB.prepare('INSERT INTO form_data (application_id, form_type) VALUES (?, ?)').bind(app_id, ft)
    )
    await c.env.DB.batch(stmts)
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
  await c.env.DB.prepare(
    'UPDATE applications SET title=?, brand=?, model=?, model_year=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?'
  ).bind(title || appl.title, brand || appl.brand, model || appl.model, model_year || appl.model_year, status || appl.status, id).run()
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

// ────────────────────────────────────────────────
// API: 서류 폼
// ────────────────────────────────────────────────
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
  await c.env.DB.prepare(
    'UPDATE form_data SET data=?, completed=?, updated_at=CURRENT_TIMESTAMP WHERE application_id=? AND form_type=?'
  ).bind(JSON.stringify(data), completed ? 1 : 0, id, type).run()
  const completedCount = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM form_data WHERE application_id=? AND completed=1').bind(id).first() as any
  const totalCount = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM form_data WHERE application_id=?').bind(id).first() as any
  if (completedCount.cnt === totalCount.cnt) {
    await c.env.DB.prepare('UPDATE applications SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?').bind('completed', id).run()
  } else if (completedCount.cnt > 0) {
    await c.env.DB.prepare('UPDATE applications SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?').bind('in_progress', id).run()
  }
  return c.json({ ok: true })
})

// ────────────────────────────────────────────────
// HTML (SPA)
// ────────────────────────────────────────────────
const HTML = `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>수입이륜차 배출가스·소음 인증신청 지원 시스템</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
<style>
  :root { font-family: 'Malgun Gothic', 'Apple SD Gothic Neo', sans-serif; }
  .page { display: none; }
  .page.active { display: block; }
  .form-section { background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:24px; margin-bottom:16px; box-shadow:0 1px 3px rgba(0,0,0,.06); }
  .field-label { display:block; font-size:.85rem; font-weight:600; color:#374151; margin-bottom:4px; }
  .field-input { width:100%; border:1px solid #d1d5db; border-radius:8px; padding:8px 12px; font-size:.9rem; box-sizing:border-box; transition:border-color .2s; }
  .field-input:focus { outline:none; border-color:#3b82f6; box-shadow:0 0 0 3px rgba(59,130,246,.15); }
  .field-input:disabled { background:#f9fafb; color:#6b7280; }
  .btn-primary { background:#2563eb; color:#fff; border:none; border-radius:8px; padding:9px 20px; font-weight:600; font-size:.9rem; cursor:pointer; transition:background .2s; }
  .btn-primary:hover { background:#1d4ed8; }
  .btn-primary:disabled { background:#93c5fd; cursor:not-allowed; }
  .btn-secondary { background:#f3f4f6; color:#374151; border:none; border-radius:8px; padding:9px 20px; font-weight:500; font-size:.9rem; cursor:pointer; transition:background .2s; }
  .btn-secondary:hover { background:#e5e7eb; }
  .btn-danger { background:#ef4444; color:#fff; border:none; border-radius:8px; padding:8px 14px; font-weight:600; font-size:.85rem; cursor:pointer; transition:background .2s; }
  .btn-danger:hover { background:#dc2626; }
  .btn-success { background:#16a34a; color:#fff; border:none; border-radius:8px; padding:9px 20px; font-weight:600; font-size:.9rem; cursor:pointer; transition:background .2s; }
  .btn-success:hover { background:#15803d; }
  .badge-draft { background:#f3f4f6; color:#6b7280; font-size:.75rem; font-weight:600; padding:3px 10px; border-radius:999px; }
  .badge-in_progress { background:#fef3c7; color:#d97706; font-size:.75rem; font-weight:600; padding:3px 10px; border-radius:999px; }
  .badge-completed { background:#dcfce7; color:#16a34a; font-size:.75rem; font-weight:600; padding:3px 10px; border-radius:999px; }
  .form-card { background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:18px; cursor:pointer; transition:all .2s; }
  .form-card:hover { box-shadow:0 4px 12px rgba(0,0,0,.1); border-color:#3b82f6; }
  .form-card.done { border-color:#86efac; background:#f0fdf4; }
  .modal-overlay { position:fixed; inset:0; background:rgba(0,0,0,.5); display:flex; align-items:center; justify-content:center; z-index:50; }
  .modal-overlay.hidden { display:none; }
  .modal-box { background:#fff; border-radius:16px; box-shadow:0 20px 60px rgba(0,0,0,.2); padding:32px; width:100%; max-width:480px; margin:16px; }
  .toast-msg { position:fixed; bottom:24px; right:24px; background:#1f2937; color:#fff; padding:12px 20px; border-radius:12px; box-shadow:0 4px 12px rgba(0,0,0,.3); z-index:100; font-size:.9rem; animation:slideUp .3s ease; }
  .toast-msg.error { background:#dc2626; }
  .toast-msg.success { background:#16a34a; }
  @keyframes slideUp { from { transform:translateY(20px); opacity:0; } to { transform:translateY(0); opacity:1; } }
  .progress-bar { transition:width .5s ease; }
  .spinner { display:inline-block; width:16px; height:16px; border:2px solid rgba(255,255,255,.3); border-top-color:#fff; border-radius:50%; animation:spin .6s linear infinite; margin-right:6px; }
  @keyframes spin { to { transform:rotate(360deg); } }
  @media print { .no-print { display:none !important; } }
  select.field-input { appearance:auto; }
  textarea.field-input { resize:vertical; }
</style>
</head>
<body style="background:#f8fafc; min-height:100vh;">

<!-- ── 헤더 ────────────────────────────────────────── -->
<header style="background:#fff; border-bottom:1px solid #e5e7eb; box-shadow:0 1px 4px rgba(0,0,0,.06);" class="no-print" id="main-header">
  <div style="max-width:1200px; margin:0 auto; padding:0 20px; height:60px; display:flex; align-items:center; justify-content:space-between;">
    <div style="display:flex; align-items:center; gap:12px;">
      <div style="width:40px; height:40px; background:#2563eb; border-radius:10px; display:flex; align-items:center; justify-content:center;">
        <i class="fas fa-motorcycle" style="color:#fff; font-size:18px;"></i>
      </div>
      <div>
        <div style="font-size:1rem; font-weight:700; color:#1e3a5f;">수입이륜차 인증신청 지원 시스템</div>
        <div style="font-size:.75rem; color:#6b7280;">배출가스·소음 인증 전용</div>
      </div>
    </div>
    <div id="header-user" style="display:flex; align-items:center; gap:12px;"></div>
  </div>
</header>

<!-- ── 로그인/회원가입 ──────────────────────────────── -->
<div id="page-auth" class="page active" style="min-height:calc(100vh - 60px); display:flex; align-items:center; justify-content:center; padding:24px;">
  <div style="width:100%; max-width:420px;">
    <div style="text-align:center; margin-bottom:32px;">
      <div style="width:64px; height:64px; background:#2563eb; border-radius:16px; display:flex; align-items:center; justify-content:center; margin:0 auto 16px;">
        <i class="fas fa-motorcycle" style="color:#fff; font-size:28px;"></i>
      </div>
      <h2 style="font-size:1.5rem; font-weight:700; color:#1f2937; margin:0 0 6px;">수입이륜차 인증신청</h2>
      <p style="color:#6b7280; font-size:.9rem; margin:0;">배출가스·소음 인증신청 지원 시스템</p>
    </div>

    <!-- 탭 -->
    <div style="display:flex; gap:4px; margin-bottom:20px; background:#f3f4f6; padding:4px; border-radius:12px;">
      <button onclick="showAuthTab('login')" id="auth-tab-login"
        style="flex:1; padding:10px; font-size:.9rem; font-weight:600; border:none; border-radius:9px; cursor:pointer; background:#fff; color:#2563eb; box-shadow:0 1px 3px rgba(0,0,0,.1);">
        로그인
      </button>
      <button onclick="showAuthTab('register')" id="auth-tab-register"
        style="flex:1; padding:10px; font-size:.9rem; font-weight:500; border:none; border-radius:9px; cursor:pointer; background:transparent; color:#6b7280;">
        회원가입
      </button>
    </div>

    <!-- 로그인 폼 -->
    <div id="login-form" style="background:#fff; border-radius:16px; box-shadow:0 4px 20px rgba(0,0,0,.08); padding:28px;">
      <div style="margin-bottom:16px;">
        <label class="field-label"><i class="fas fa-user" style="color:#9ca3af; margin-right:6px;"></i>아이디</label>
        <input id="login-username" type="text" class="field-input" placeholder="아이디 입력" autocomplete="username"
          onkeydown="if(event.key==='Enter')document.getElementById('login-password').focus()">
      </div>
      <div style="margin-bottom:20px;">
        <label class="field-label"><i class="fas fa-lock" style="color:#9ca3af; margin-right:6px;"></i>비밀번호</label>
        <input id="login-password" type="password" class="field-input" placeholder="비밀번호 입력" autocomplete="current-password"
          onkeydown="if(event.key==='Enter')doLogin()">
      </div>
      <button onclick="doLogin()" id="login-btn" class="btn-primary" style="width:100%; padding:12px; font-size:1rem;">
        <i class="fas fa-sign-in-alt" style="margin-right:8px;"></i>로그인
      </button>
      <div id="login-error" style="display:none; color:#dc2626; font-size:.85rem; margin-top:12px; padding:10px 14px; background:#fef2f2; border-radius:8px; border:1px solid #fecaca;"></div>
    </div>

    <!-- 회원가입 폼 -->
    <div id="register-form" style="display:none; background:#fff; border-radius:16px; box-shadow:0 4px 20px rgba(0,0,0,.08); padding:28px;">
      <div style="display:grid; gap:14px;">
        <div>
          <label class="field-label">아이디 <span style="color:#ef4444;">*</span></label>
          <input id="reg-username" type="text" class="field-input" placeholder="영문·숫자·밑줄 4~20자" autocomplete="username">
          <p style="font-size:.75rem; color:#9ca3af; margin:4px 0 0;">영문, 숫자, 밑줄(_)만 사용 가능</p>
        </div>
        <div>
          <label class="field-label">비밀번호 <span style="color:#ef4444;">*</span></label>
          <input id="reg-password" type="password" class="field-input" placeholder="8자 이상" autocomplete="new-password">
        </div>
        <div>
          <label class="field-label">비밀번호 확인 <span style="color:#ef4444;">*</span></label>
          <input id="reg-password2" type="password" class="field-input" placeholder="비밀번호 재입력" autocomplete="new-password">
        </div>
        <div>
          <label class="field-label">회사명 <span style="color:#ef4444;">*</span></label>
          <input id="reg-company" type="text" class="field-input" placeholder="(주)○○모터스">
        </div>
        <div>
          <label class="field-label">대표자명 <span style="color:#ef4444;">*</span></label>
          <input id="reg-rep" type="text" class="field-input" placeholder="홍길동">
        </div>
        <div>
          <label class="field-label">사업자등록번호 <span style="color:#ef4444;">*</span></label>
          <input id="reg-bizno" type="text" class="field-input" placeholder="000-00-00000">
        </div>
        <div>
          <label class="field-label">연락처</label>
          <input id="reg-phone" type="text" class="field-input" placeholder="02-0000-0000">
        </div>
      </div>
      <button onclick="doRegister()" id="register-btn" class="btn-primary" style="width:100%; padding:12px; font-size:1rem; margin-top:20px;">
        <i class="fas fa-user-plus" style="margin-right:8px;"></i>회원가입
      </button>
      <div id="register-error" style="display:none; color:#dc2626; font-size:.85rem; margin-top:12px; padding:10px 14px; background:#fef2f2; border-radius:8px; border:1px solid #fecaca;"></div>
    </div>
  </div>
</div>

<!-- ── 대시보드 ──────────────────────────────────────── -->
<div id="page-dashboard" class="page" style="max-width:1200px; margin:0 auto; padding:28px 20px;">
  <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:24px; flex-wrap:wrap; gap:12px;">
    <div>
      <h2 style="font-size:1.3rem; font-weight:700; color:#1f2937; margin:0 0 4px;">인증신청 목록</h2>
      <p id="dash-subtitle" style="font-size:.9rem; color:#6b7280; margin:0;"></p>
    </div>
    <button onclick="showNewAppModal()" class="btn-primary">
      <i class="fas fa-plus" style="margin-right:8px;"></i>새 신청서 작성
    </button>
  </div>

  <!-- 요약 카드 -->
  <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:24px;">
    <div style="background:#fff; border-radius:12px; border:1px solid #e5e7eb; padding:18px; text-align:center;">
      <div id="stat-total" style="font-size:1.8rem; font-weight:700; color:#1f2937;">0</div>
      <div style="font-size:.8rem; color:#6b7280; margin-top:4px;">전체</div>
    </div>
    <div style="background:#fff; border-radius:12px; border:1px solid #e5e7eb; padding:18px; text-align:center;">
      <div id="stat-inprogress" style="font-size:1.8rem; font-weight:700; color:#d97706;">0</div>
      <div style="font-size:.8rem; color:#6b7280; margin-top:4px;">작성중</div>
    </div>
    <div style="background:#fff; border-radius:12px; border:1px solid #e5e7eb; padding:18px; text-align:center;">
      <div id="stat-completed" style="font-size:1.8rem; font-weight:700; color:#16a34a;">0</div>
      <div style="font-size:.8rem; color:#6b7280; margin-top:4px;">완료</div>
    </div>
    <div style="background:#fff; border-radius:12px; border:1px solid #e5e7eb; padding:18px; text-align:center;">
      <div id="stat-draft" style="font-size:1.8rem; font-weight:700; color:#9ca3af;">0</div>
      <div style="font-size:.8rem; color:#6b7280; margin-top:4px;">임시저장</div>
    </div>
  </div>

  <!-- 신청서 목록 -->
  <div id="app-list" style="display:flex; flex-direction:column; gap:12px;"></div>
  <div id="app-empty" style="display:none; text-align:center; padding:60px 20px;">
    <i class="fas fa-file-alt" style="font-size:3rem; color:#d1d5db; margin-bottom:16px; display:block;"></i>
    <p style="color:#6b7280; margin-bottom:16px;">아직 작성된 신청서가 없습니다.</p>
    <button onclick="showNewAppModal()" class="btn-primary">첫 신청서 작성하기</button>
  </div>
</div>

<!-- ── 신청서 상세 ────────────────────────────────────── -->
<div id="page-application" class="page" style="max-width:1200px; margin:0 auto; padding:28px 20px;">
  <!-- 브레드크럼 -->
  <div class="no-print" style="display:flex; align-items:center; gap:8px; font-size:.9rem; color:#6b7280; margin-bottom:20px;">
    <button onclick="showDashboard()" style="background:none; border:none; cursor:pointer; color:#2563eb; font-size:.9rem;">
      <i class="fas fa-home" style="margin-right:4px;"></i>목록
    </button>
    <span>›</span>
    <span id="appl-breadcrumb" style="color:#1f2937; font-weight:500;"></span>
  </div>

  <!-- 신청서 헤더 -->
  <div class="form-section" style="margin-bottom:20px;">
    <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:16px; flex-wrap:wrap;">
      <div style="flex:1; min-width:0;">
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px; flex-wrap:wrap;">
          <span id="appl-cert-badge" style="font-size:.75rem; font-weight:700; padding:3px 12px; border-radius:999px; background:#dbeafe; color:#1d4ed8;"></span>
          <span id="appl-status-badge" class="badge-draft"></span>
        </div>
        <h3 id="appl-title" style="font-size:1.2rem; font-weight:700; color:#1f2937; margin:0 0 6px;"></h3>
        <p id="appl-meta" style="font-size:.9rem; color:#6b7280; margin:0;"></p>
      </div>
      <div style="text-align:right; flex-shrink:0;">
        <div style="font-size:.85rem; color:#6b7280; margin-bottom:4px;">전체 진행률</div>
        <div id="appl-progress-pct" style="font-size:1.8rem; font-weight:700; color:#2563eb;">0%</div>
        <div style="width:120px; background:#e5e7eb; border-radius:999px; height:6px; margin-top:6px;">
          <div id="appl-progress-bar" class="progress-bar" style="background:#2563eb; height:6px; border-radius:999px; width:0%;"></div>
        </div>
      </div>
    </div>
  </div>

  <h4 style="font-size:1rem; font-weight:700; color:#374151; margin:0 0 14px;">제출 서류 작성 현황</h4>
  <div id="forms-grid" style="display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr)); gap:14px; margin-bottom:24px;"></div>
</div>

<!-- ── 서류 입력 폼 ──────────────────────────────────── -->
<div id="page-form" class="page" style="max-width:900px; margin:0 auto; padding:28px 20px;">
  <!-- 브레드크럼 -->
  <div class="no-print" style="display:flex; align-items:center; gap:8px; font-size:.9rem; color:#6b7280; margin-bottom:20px;">
    <button onclick="showDashboard()" style="background:none; border:none; cursor:pointer; color:#2563eb;">
      <i class="fas fa-home" style="margin-right:4px;"></i>목록
    </button>
    <span>›</span>
    <button id="form-appl-link" style="background:none; border:none; cursor:pointer; color:#2563eb; font-size:.9rem;"></button>
    <span>›</span>
    <span id="form-breadcrumb" style="color:#1f2937; font-weight:500;"></span>
  </div>

  <div class="form-section no-print" style="margin-bottom:20px;">
    <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px;">
      <div>
        <h3 id="form-title" style="font-size:1.1rem; font-weight:700; color:#1f2937; margin:0 0 4px;"></h3>
        <p id="form-subtitle" style="font-size:.85rem; color:#6b7280; margin:0;"></p>
      </div>
      <div style="display:flex; gap:8px;">
        <button onclick="saveForm()" id="save-btn" class="btn-success">
          <i class="fas fa-save" style="margin-right:6px;"></i>저장
        </button>
        <button onclick="window.print()" class="btn-secondary no-print">
          <i class="fas fa-print" style="margin-right:6px;"></i>인쇄
        </button>
      </div>
    </div>
  </div>

  <div id="form-content"></div>

  <!-- 완료 체크 -->
  <div class="form-section no-print" style="margin-top:16px;">
    <label style="display:flex; align-items:center; gap:12px; cursor:pointer;">
      <input type="checkbox" id="form-completed-chk" style="width:20px; height:20px; accent-color:#16a34a; cursor:pointer;">
      <div>
        <div style="font-weight:600; color:#1f2937;">이 서류 작성을 완료했습니다</div>
        <div style="font-size:.8rem; color:#6b7280; margin-top:2px;">체크하면 진행률에 반영됩니다</div>
      </div>
    </label>
  </div>
</div>

<!-- ── 새 신청서 모달 ─────────────────────────────────── -->
<div id="modal-new-app" class="modal-overlay hidden no-print">
  <div class="modal-box">
    <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:20px;">
      <h3 style="font-size:1.1rem; font-weight:700; color:#1f2937; margin:0;">
        <i class="fas fa-file-plus" style="color:#2563eb; margin-right:8px;"></i>새 인증신청서 작성
      </h3>
      <button onclick="closeNewAppModal()" style="background:none; border:none; cursor:pointer; color:#9ca3af; font-size:1.2rem;">
        <i class="fas fa-times"></i>
      </button>
    </div>

    <div style="display:grid; gap:16px;">
      <div>
        <label class="field-label">신청 제목 <span style="color:#ef4444;">*</span></label>
        <input id="new-title" type="text" class="field-input" placeholder="예) 2025년 Honda CB125R 기본인증">
      </div>
      <div>
        <label class="field-label">인증 유형 <span style="color:#ef4444;">*</span></label>
        <select id="new-cert-type" class="field-input" onchange="onNewCertTypeChange()">
          <option value="basic">기본인증 (신규 수입이륜차)</option>
          <option value="change">변경인증 (인증사항 중요 변경)</option>
          <option value="report">변경보고 (경미한 사항 변경)</option>
        </select>
      </div>
      <div id="new-prev-cert-wrap" style="display:none;">
        <label class="field-label">기존 인증번호 <span style="color:#ef4444;">*</span></label>
        <input id="new-prev-cert" type="text" class="field-input" placeholder="기존 인증번호 입력">
      </div>
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
        <div>
          <label class="field-label">제조사 브랜드</label>
          <input id="new-brand" type="text" class="field-input" placeholder="Honda, Yamaha 등">
        </div>
        <div>
          <label class="field-label">차종명</label>
          <input id="new-model" type="text" class="field-input" placeholder="CB125R 등">
        </div>
      </div>
      <div>
        <label class="field-label">연식</label>
        <input id="new-year" type="text" class="field-input" placeholder="2025">
      </div>
    </div>

    <div id="modal-error" style="display:none; color:#dc2626; font-size:.85rem; margin-top:12px; padding:10px 14px; background:#fef2f2; border-radius:8px; border:1px solid #fecaca;"></div>

    <div style="display:flex; justify-content:flex-end; gap:10px; margin-top:24px;">
      <button onclick="closeNewAppModal()" class="btn-secondary">취소</button>
      <button onclick="createApplication()" id="create-btn" class="btn-primary">
        <i class="fas fa-check" style="margin-right:6px;"></i>생성
      </button>
    </div>
  </div>
</div>

<script>
// ================================================================
// 전역 상태
// ================================================================
let currentUser = null;
let currentApplications = [];
let currentApplication = null;
let currentForms = [];
let currentFormType = null;
let currentApplicationId = null;

const FORM_META = [
  { type: 'summary',        title: '인증신청 요약서',                icon: 'fa-file-alt',       color: '#3b82f6' },
  { type: 'gasoline',       title: '휘발유차 인증신청 주요내용',     icon: 'fa-gas-pump',       color: '#f97316' },
  { type: 'detail_plan',    title: '인증에 필요한 세부 계획 서류',   icon: 'fa-clipboard-list', color: '#8b5cf6' },
  { type: 'emission_noise', title: '배출가스·소음 저감 서류',        icon: 'fa-wind',           color: '#14b8a6' },
  { type: 'obd_config',     title: 'OBD 구성에 관한 서류',           icon: 'fa-microchip',      color: '#6366f1' },
  { type: 'emission_test',  title: '배출가스 시험보고서',            icon: 'fa-flask',          color: '#22c55e' },
  { type: 'evap_test',      title: '증발가스 시험내용 보고서',       icon: 'fa-vials',          color: '#eab308' },
  { type: 'obd_operation',  title: 'OBD 작동 확인시험 보고서',      icon: 'fa-cogs',           color: '#ef4444' },
  { type: 'noise_test',     title: '자동차소음 시험내용 보고서',     icon: 'fa-volume-up',      color: '#ec4899' },
  { type: 'confirmation',   title: '확인서',                         icon: 'fa-stamp',          color: '#6b7280' },
];

const CERT_TYPE_LABEL = { basic: '기본인증', change: '변경인증', report: '변경보고' };
const STATUS_LABEL    = { draft: '임시저장', in_progress: '작성중', completed: '완료' };

// ================================================================
// 토큰 관리
// ================================================================
function getToken()    { return localStorage.getItem('auth_token'); }
function setToken(t)   { localStorage.setItem('auth_token', t); }
function clearToken()  { localStorage.removeItem('auth_token'); }

async function api(path, options = {}) {
  const token = getToken();
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (token) headers['Authorization'] = 'Bearer ' + token;
  const res = await fetch(path, { ...options, headers });
  return res;
}

// ================================================================
// 초기화
// ================================================================
async function init() {
  const token = getToken();
  if (!token) { showPage('page-auth'); return; }
  try {
    const res = await api('/api/auth/me');
    if (res.ok) {
      const { user } = await res.json();
      currentUser = user;
      showDashboard();
    } else {
      clearToken();
      showPage('page-auth');
    }
  } catch {
    showPage('page-auth');
  }
}

// ================================================================
// 페이지 전환
// ================================================================
function showPage(id) {
  document.querySelectorAll('.page').forEach(p => {
    p.style.display = 'none';
    p.classList.remove('active');
  });
  const el = document.getElementById(id);
  el.style.display = 'block';
  el.classList.add('active');
  window.scrollTo(0, 0);
}

function updateHeader() {
  const el = document.getElementById('header-user');
  if (!currentUser) { el.innerHTML = ''; return; }
  el.innerHTML = \`
    <div style="text-align:right; display:none;" class="sm-block">
      <div style="font-size:.9rem; font-weight:600; color:#1f2937;">\${escHtml(currentUser.company_name)}</div>
      <div style="font-size:.78rem; color:#6b7280;"><i class="fas fa-user" style="margin-right:4px;"></i>\${escHtml(currentUser.username)}</div>
    </div>
    <button onclick="doLogout()" class="btn-secondary" style="font-size:.85rem;">
      <i class="fas fa-sign-out-alt" style="margin-right:6px;"></i>로그아웃
    </button>
  \`;
}

function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ================================================================
// 인증
// ================================================================
function showAuthTab(tab) {
  const isLogin = tab === 'login';
  document.getElementById('login-form').style.display = isLogin ? 'block' : 'none';
  document.getElementById('register-form').style.display = isLogin ? 'none' : 'block';
  const loginBtn = document.getElementById('auth-tab-login');
  const regBtn = document.getElementById('auth-tab-register');
  loginBtn.style.background = isLogin ? '#fff' : 'transparent';
  loginBtn.style.color = isLogin ? '#2563eb' : '#6b7280';
  loginBtn.style.fontWeight = isLogin ? '600' : '500';
  loginBtn.style.boxShadow = isLogin ? '0 1px 3px rgba(0,0,0,.1)' : 'none';
  regBtn.style.background = !isLogin ? '#fff' : 'transparent';
  regBtn.style.color = !isLogin ? '#2563eb' : '#6b7280';
  regBtn.style.fontWeight = !isLogin ? '600' : '500';
  regBtn.style.boxShadow = !isLogin ? '0 1px 3px rgba(0,0,0,.1)' : 'none';
}

function showAuthError(id, msg) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.style.display = 'block';
}
function hideAuthError(id) {
  document.getElementById(id).style.display = 'none';
}

async function doLogin() {
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  hideAuthError('login-error');
  if (!username || !password) { showAuthError('login-error', '아이디와 비밀번호를 입력하세요.'); return; }
  const btn = document.getElementById('login-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>로그인 중...';
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (!res.ok) { showAuthError('login-error', data.error || '로그인 실패'); return; }
    setToken(data.token);
    currentUser = data.user;
    showDashboard();
  } catch (e) {
    showAuthError('login-error', '네트워크 오류가 발생했습니다.');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-sign-in-alt" style="margin-right:8px;"></i>로그인';
  }
}

async function doRegister() {
  const username      = document.getElementById('reg-username').value.trim();
  const password      = document.getElementById('reg-password').value;
  const password2     = document.getElementById('reg-password2').value;
  const company_name  = document.getElementById('reg-company').value.trim();
  const representative= document.getElementById('reg-rep').value.trim();
  const business_number = document.getElementById('reg-bizno').value.trim();
  const phone         = document.getElementById('reg-phone').value.trim();
  hideAuthError('register-error');
  if (!username || !password || !company_name || !representative || !business_number) {
    showAuthError('register-error', '필수 항목을 모두 입력해주세요.'); return;
  }
  if (!/^[a-zA-Z0-9_]{4,20}$/.test(username)) {
    showAuthError('register-error', '아이디는 영문·숫자·밑줄 4~20자로 입력해주세요.'); return;
  }
  if (password.length < 8) { showAuthError('register-error', '비밀번호는 8자 이상이어야 합니다.'); return; }
  if (password !== password2) { showAuthError('register-error', '비밀번호가 일치하지 않습니다.'); return; }
  const btn = document.getElementById('register-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>가입 중...';
  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, company_name, representative, business_number, phone })
    });
    const data = await res.json();
    if (!res.ok) { showAuthError('register-error', data.error || '회원가입 실패'); return; }
    setToken(data.token);
    currentUser = data.user;
    showToast('회원가입이 완료되었습니다.', 'success');
    showDashboard();
  } catch (e) {
    showAuthError('register-error', '네트워크 오류가 발생했습니다.');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-user-plus" style="margin-right:8px;"></i>회원가입';
  }
}

async function doLogout() {
  clearToken();
  currentUser = null;
  currentApplications = [];
  showPage('page-auth');
  updateHeader();
}

// ================================================================
// 대시보드
// ================================================================
async function showDashboard() {
  updateHeader();
  showPage('page-dashboard');
  document.getElementById('dash-subtitle').textContent =
    currentUser ? currentUser.company_name + '  @' + currentUser.username : '';
  await loadApplications();
}

async function loadApplications() {
  try {
    const res = await api('/api/applications');
    if (!res.ok) {
      if (res.status === 401) { clearToken(); showPage('page-auth'); return; }
      showToast('목록 로드 실패', 'error'); return;
    }
    const data = await res.json();
    currentApplications = data.applications || [];
    renderApplicationList();
  } catch {
    showToast('네트워크 오류', 'error');
  }
}

function renderApplicationList() {
  const list   = document.getElementById('app-list');
  const empty  = document.getElementById('app-empty');
  const total  = currentApplications.length;
  const inprog = currentApplications.filter(a => a.status === 'in_progress').length;
  const compl  = currentApplications.filter(a => a.status === 'completed').length;
  const draft  = currentApplications.filter(a => a.status === 'draft').length;
  document.getElementById('stat-total').textContent     = total;
  document.getElementById('stat-inprogress').textContent = inprog;
  document.getElementById('stat-completed').textContent  = compl;
  document.getElementById('stat-draft').textContent      = draft;

  if (total === 0) {
    list.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';
  list.innerHTML = currentApplications.map(a => {
    const total_f = a.total_forms || 10;
    const done_f  = a.completed_forms || 0;
    const pct     = Math.round(done_f / total_f * 100);
    const updDate = new Date(a.updated_at).toLocaleDateString('ko-KR');
    const metaStr = [a.brand, a.model, a.model_year ? a.model_year + '년식' : ''].filter(Boolean).join(' ');
    return \`
      <div style="background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:18px 20px; display:flex; align-items:center; gap:16px; transition:box-shadow .2s;"
           onmouseover="this.style.boxShadow='0 4px 12px rgba(0,0,0,.1)'" onmouseout="this.style.boxShadow='none'">
        <div style="flex:1; min-width:0;">
          <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px; flex-wrap:wrap;">
            <span style="font-size:.75rem; font-weight:700; padding:2px 10px; border-radius:999px; background:#dbeafe; color:#1d4ed8;">\${CERT_TYPE_LABEL[a.cert_type] || a.cert_type}</span>
            <span class="badge-\${a.status}">\${STATUS_LABEL[a.status] || a.status}</span>
          </div>
          <h4 style="font-weight:600; color:#1f2937; margin:0 0 4px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">\${escHtml(a.title)}</h4>
          <p style="font-size:.8rem; color:#6b7280; margin:0 0 8px;">\${escHtml(metaStr)} · \${updDate}</p>
          <div style="display:flex; align-items:center; gap:8px;">
            <div style="flex:1; background:#e5e7eb; border-radius:999px; height:5px;">
              <div style="background:#2563eb; height:5px; border-radius:999px; width:\${pct}%; transition:width .5s;"></div>
            </div>
            <span style="font-size:.8rem; color:#6b7280; flex-shrink:0;">\${done_f}/\${total_f} 서류</span>
          </div>
        </div>
        <div style="display:flex; gap:8px; flex-shrink:0;">
          <button onclick="openApplication(\${a.id})" class="btn-primary" style="font-size:.85rem;">
            <i class="fas fa-edit" style="margin-right:4px;"></i>작성하기
          </button>
          <button onclick="deleteApplication(event, \${a.id})" class="btn-danger">
            <i class="fas fa-trash"></i>
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
    const res = await api('/api/applications/' + id);
    if (!res.ok) { showToast('신청서 로드 실패', 'error'); return; }
    const data = await res.json();
    currentApplication   = data.application;
    currentForms         = data.forms;
    currentApplicationId = id;
    renderApplicationPage();
    showPage('page-application');
  } catch {
    showToast('네트워크 오류', 'error');
  }
}

function renderApplicationPage() {
  const a = currentApplication;
  document.getElementById('appl-breadcrumb').textContent = a.title;
  document.getElementById('appl-cert-badge').textContent = CERT_TYPE_LABEL[a.cert_type] || a.cert_type;
  const sb = document.getElementById('appl-status-badge');
  sb.className = 'badge-' + a.status;
  sb.textContent = STATUS_LABEL[a.status] || a.status;
  document.getElementById('appl-title').textContent = a.title;
  const meta = [a.brand, a.model, a.model_year ? a.model_year + '년식' : ''].filter(Boolean).join(' · ');
  document.getElementById('appl-meta').textContent = meta;
  const done  = currentForms.filter(f => f.completed).length;
  const total = currentForms.length;
  const pct   = total ? Math.round(done / total * 100) : 0;
  document.getElementById('appl-progress-pct').textContent = pct + '%';
  document.getElementById('appl-progress-bar').style.width = pct + '%';

  const grid = document.getElementById('forms-grid');
  grid.innerHTML = FORM_META.map((meta, idx) => {
    const formData = currentForms.find(f => f.form_type === meta.type);
    const isDone   = !!formData?.completed;
    const bgColor  = isDone ? '#f0fdf4' : '#fff';
    const borderColor = isDone ? '#86efac' : '#e5e7eb';
    const iconBg  = isDone ? '#dcfce7' : '#f3f4f6';
    const iconColor = isDone ? '#16a34a' : meta.color;
    return \`
      <div class="form-card \${isDone ? 'done' : ''}" onclick="openForm('\${meta.type}')"
           style="background:\${bgColor}; border-color:\${borderColor};">
        <div style="display:flex; align-items:flex-start; gap:14px;">
          <div style="width:42px; height:42px; border-radius:10px; background:\${iconBg}; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
            <i class="fas \${meta.icon}" style="color:\${iconColor}; font-size:16px;"></i>
          </div>
          <div style="flex:1; min-width:0;">
            <div style="display:flex; align-items:center; gap:6px; margin-bottom:4px; flex-wrap:wrap;">
              <span style="font-size:.75rem; color:#9ca3af; font-weight:500;">서류 \${idx + 1}</span>
              \${isDone
                ? '<span style="font-size:.72rem; background:#dcfce7; color:#16a34a; padding:2px 8px; border-radius:999px; font-weight:600;"><i class="fas fa-check" style="margin-right:3px;"></i>완료</span>'
                : '<span style="font-size:.72rem; background:#f3f4f6; color:#6b7280; padding:2px 8px; border-radius:999px;">미완료</span>'
              }
            </div>
            <h5 style="font-weight:600; color:#1f2937; font-size:.9rem; line-height:1.4; margin:0;">\${meta.title}</h5>
          </div>
          <i class="fas fa-chevron-right" style="color:#d1d5db; font-size:.8rem; flex-shrink:0; margin-top:4px;"></i>
        </div>
      </div>
    \`;
  }).join('');
}

// ================================================================
// 서류 폼
// ================================================================
async function openForm(formType) {
  currentFormType = formType;
  const meta     = FORM_META.find(m => m.type === formType);
  const formData = currentForms.find(f => f.form_type === formType);
  let savedData  = {};
  try { savedData = JSON.parse(formData?.data || '{}'); } catch {}

  const applLink = document.getElementById('form-appl-link');
  applLink.textContent = currentApplication.title;
  applLink.onclick = () => openApplication(currentApplicationId);
  document.getElementById('form-breadcrumb').textContent = meta.title;
  document.getElementById('form-title').textContent      = meta.title;
  document.getElementById('form-subtitle').textContent   =
    CERT_TYPE_LABEL[currentApplication.cert_type] + ' · ' + currentApplication.title;
  document.getElementById('form-completed-chk').checked = !!formData?.completed;
  document.getElementById('form-content').innerHTML = buildFormHTML(formType, savedData);
  showPage('page-form');
}

async function saveForm() {
  const data      = collectFormData();
  const completed = document.getElementById('form-completed-chk').checked;
  const btn       = document.getElementById('save-btn');
  btn.disabled    = true;
  btn.innerHTML   = '<span class="spinner"></span>저장 중...';
  try {
    const res = await api('/api/applications/' + currentApplicationId + '/forms/' + currentFormType, {
      method: 'PUT',
      body: JSON.stringify({ data, completed })
    });
    if (res.ok) {
      showToast('저장되었습니다.', 'success');
      const idx = currentForms.findIndex(f => f.form_type === currentFormType);
      if (idx >= 0) {
        currentForms[idx].data      = JSON.stringify(data);
        currentForms[idx].completed = completed ? 1 : 0;
      }
    } else {
      showToast('저장 실패', 'error');
    }
  } catch {
    showToast('네트워크 오류', 'error');
  } finally {
    btn.disabled  = false;
    btn.innerHTML = '<i class="fas fa-save" style="margin-right:6px;"></i>저장';
  }
}

// ================================================================
// 신청서 생성/삭제
// ================================================================
function showNewAppModal() {
  document.getElementById('modal-new-app').classList.remove('hidden');
  document.getElementById('new-title').value      = '';
  document.getElementById('new-brand').value      = '';
  document.getElementById('new-model').value      = '';
  document.getElementById('new-year').value       = '';
  document.getElementById('new-cert-type').value  = 'basic';
  document.getElementById('modal-error').style.display = 'none';
  const btn = document.getElementById('create-btn');
  btn.disabled  = false;
  btn.innerHTML = '<i class="fas fa-check" style="margin-right:6px;"></i>생성';
  onNewCertTypeChange();
  setTimeout(() => document.getElementById('new-title').focus(), 100);
}

function closeNewAppModal() {
  document.getElementById('modal-new-app').classList.add('hidden');
}

function onNewCertTypeChange() {
  const v = document.getElementById('new-cert-type').value;
  document.getElementById('new-prev-cert-wrap').style.display = v === 'basic' ? 'none' : 'block';
}

async function createApplication() {
  const title    = document.getElementById('new-title').value.trim();
  const cert_type = document.getElementById('new-cert-type').value;
  const brand    = document.getElementById('new-brand').value.trim();
  const model    = document.getElementById('new-model').value.trim();
  const model_year = document.getElementById('new-year').value.trim();
  const prev_cert_number = document.getElementById('new-prev-cert')?.value.trim() || '';
  const errEl = document.getElementById('modal-error');
  errEl.style.display = 'none';

  if (!title) {
    errEl.textContent = '신청 제목을 입력하세요.';
    errEl.style.display = 'block';
    document.getElementById('new-title').focus();
    return;
  }
  if ((cert_type === 'change' || cert_type === 'report') && !prev_cert_number) {
    errEl.textContent = '기존 인증번호를 입력하세요.';
    errEl.style.display = 'block';
    return;
  }

  const btn = document.getElementById('create-btn');
  btn.disabled  = true;
  btn.innerHTML = '<span class="spinner"></span>생성 중...';

  try {
    const res = await api('/api/applications', {
      method: 'POST',
      body: JSON.stringify({ title, cert_type, brand, model, model_year, prev_cert_number })
    });
    const data = await res.json();
    if (!res.ok) {
      errEl.textContent = data.error || '신청서 생성에 실패했습니다.';
      errEl.style.display = 'block';
      btn.disabled  = false;
      btn.innerHTML = '<i class="fas fa-check" style="margin-right:6px;"></i>생성';
      return;
    }
    closeNewAppModal();
    showToast('신청서가 생성되었습니다.', 'success');
    await openApplication(data.application.id);
  } catch (e) {
    errEl.textContent = '네트워크 오류가 발생했습니다.';
    errEl.style.display = 'block';
    btn.disabled  = false;
    btn.innerHTML = '<i class="fas fa-check" style="margin-right:6px;"></i>생성';
  }
}

async function deleteApplication(e, id) {
  e.stopPropagation();
  if (!confirm('이 신청서를 삭제하시겠습니까?\\n\\n삭제하면 모든 서류 데이터도 함께 삭제됩니다.')) return;
  try {
    const res = await api('/api/applications/' + id, { method: 'DELETE' });
    if (res.ok) {
      showToast('삭제되었습니다.', 'success');
      await loadApplications();
    } else {
      showToast('삭제 실패', 'error');
    }
  } catch {
    showToast('네트워크 오류', 'error');
  }
}

// ================================================================
// 폼 데이터 수집
// ================================================================
function collectFormData() {
  const data = {};
  document.querySelectorAll('#form-content [data-field]').forEach(el => {
    if (el.type === 'checkbox') {
      data[el.dataset.field] = el.checked ? 'true' : 'false';
    } else {
      data[el.dataset.field] = el.value;
    }
  });
  return data;
}

// ================================================================
// 폼 HTML 빌더
// ================================================================
function buildFormHTML(formType, saved) {
  const v   = (k, def='') => saved[k] !== undefined ? saved[k] : def;
  const esc = (s) => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  const field = (label, key, type='text', placeholder='', note='') => \`
    <div>
      <label class="field-label">\${label}</label>
      <input type="\${type}" data-field="\${key}" value="\${esc(v(key))}" placeholder="\${placeholder}" class="field-input">
      \${note ? '<p style="font-size:.75rem;color:#9ca3af;margin:4px 0 0;">' + note + '</p>' : ''}
    </div>
  \`;
  const textarea = (label, key, placeholder='', rows=3) => \`
    <div>
      <label class="field-label">\${label}</label>
      <textarea data-field="\${key}" rows="\${rows}" placeholder="\${placeholder}" class="field-input">\${esc(v(key))}</textarea>
    </div>
  \`;
  const select = (label, key, options) => \`
    <div>
      <label class="field-label">\${label}</label>
      <select data-field="\${key}" class="field-input">
        \${options.map(([val, txt]) => \`<option value="\${val}" \${v(key) === val ? 'selected' : ''}>\${txt}</option>\`).join('')}
      </select>
    </div>
  \`;
  const section = (title, fields) => \`
    <div class="form-section">
      <h4 style="font-size:1rem; font-weight:700; color:#1d4ed8; margin:0 0 16px; padding-bottom:10px; border-bottom:1px solid #dbeafe;">\${title}</h4>
      <div style="display:grid; grid-template-columns:repeat(auto-fill,minmax(240px,1fr)); gap:16px;">\${fields}</div>
    </div>
  \`;
  const sectionFull = (title, fields) => \`
    <div class="form-section">
      <h4 style="font-size:1rem; font-weight:700; color:#1d4ed8; margin:0 0 16px; padding-bottom:10px; border-bottom:1px solid #dbeafe;">\${title}</h4>
      <div style="display:grid; gap:16px;">\${fields}</div>
    </div>
  \`;

  if (formType === 'summary') {
    return section('신청인 정보',
        field('신청인 (회사명)', 'company', 'text', '(주)○○모터스') +
        field('대표자', 'rep', 'text', '홍길동') +
        field('사업자등록번호', 'bizno', 'text', '000-00-00000') +
        field('주소', 'address', 'text', '서울시...') +
        field('연락처', 'phone', 'text', '02-0000-0000') +
        field('담당자', 'manager', 'text', '담당자명')) +
      section('차량 개요',
        field('제작사 (브랜드)', 'brand', 'text', 'Honda') +
        field('차종명', 'model', 'text', 'CB125R') +
        field('원산지', 'origin', 'text', '일본') +
        field('연식', 'model_year', 'text', '2025') +
        select('연료 종류', 'fuel', [['gasoline','휘발유'],['electric','전기'],['lpg','LPG']]) +
        select('변속기', 'trans', [['manual','수동'],['auto','자동'],['cvt','CVT']]) +
        field('차대번호(VIN)', 'vin', 'text', '')) +
      section('배출가스 기준',
        field('적용 배출가스 기준', 'emission_std', 'text', 'EURO 5') +
        field('OBD 단계', 'obd_stage', 'text', 'OBD-II') +
        field('대표 차종 여부', 'is_rep', 'text', '해당/비해당') +
        field('보증기간 (km)', 'warranty_km', 'number', '30000') +
        field('보증기간 (년)', 'warranty_year', 'number', '5')) +
      section('소음 기준',
        field('적용 소음 기준', 'noise_std', 'text', 'ECE R41') +
        field('가속소음 (dB(A))', 'accel_noise', 'number', '') +
        field('배기소음 (dB(A))', 'exhaust_noise', 'number', ''));
  }

  if (formType === 'gasoline') {
    return section('기본 차량 정보',
        field('제작사명', 'maker', 'text', '') +
        field('차종명', 'model', 'text', '') +
        field('배기량 (cc)', 'displacement', 'number', '') +
        field('연료 공급 방식', 'fuel_supply', 'text', '전자제어 분사') +
        field('냉각 방식', 'cooling', 'text', '수냉/공냉') +
        field('기통수', 'cylinders', 'number', '1')) +
      section('적용 인증 기준',
        select('배출가스 기준', 'emission_std', [['EURO5','EURO 5'],['EURO6','EURO 6'],['EURO4','EURO 4']]) +
        field('OBD 단계', 'obd_stage', 'text', 'OBD-II') +
        field('증발가스 기준', 'evap_std', 'text', '') +
        field('인증 적용 대상', 'cert_target', 'text', '')) +
      section('대표 차종',
        field('대표 차종 여부', 'is_rep', 'text', '') +
        field('대표 차종명', 'rep_model', 'text', '') +
        field('포함 차종 수', 'family_count', 'number', '1')) +
      section('보증 기간',
        field('보증기간 (km)', 'warranty_km', 'number', '') +
        field('보증기간 (년)', 'warranty_year', 'number', '') +
        field('자가 진단 교환 주기', 'obd_interval', 'text', '')) +
      section('배출가스 시험 결과 (WMTC)',
        field('CO 측정값 (g/km)', 'co_result', 'number', '') +
        field('NOx 측정값 (g/km)', 'nox_result', 'number', '') +
        field('HC 측정값 (g/km)', 'hc_result', 'number', '') +
        field('NMHC 측정값 (g/km)', 'nmhc_result', 'number', '') +
        field('CO 기준값', 'co_std', 'number', '') +
        field('NOx 기준값', 'nox_std', 'number', ''));
  }

  if (formType === 'detail_plan') {
    return section('차량 기본 사양',
        field('제작사', 'maker', 'text', '') + field('차종명', 'model', 'text', '') +
        field('연식', 'model_year', 'text', '') + field('차량 총중량 (kg)', 'gvw', 'number', '') +
        field('공차중량 (kg)', 'curb_weight', 'number', '') + field('전장 (mm)', 'length', 'number', '') +
        field('전폭 (mm)', 'width', 'number', '') + field('전고 (mm)', 'height', 'number', '') +
        field('축간거리 (mm)', 'wheelbase', 'number', '')) +
      section('엔진 사양',
        field('배기량 (cc)', 'displacement', 'number', '') + field('최고출력 (kW)', 'max_power', 'number', '') +
        field('최대토크 (N·m)', 'max_torque', 'number', '') + field('보어 × 스트로크 (mm)', 'bore_stroke', 'text', '') +
        field('압축비', 'compression', 'text', '') + field('연료탱크 용량 (L)', 'fuel_tank', 'number', '')) +
      section('촉매 장치',
        field('촉매 종류', 'catalyst_type', 'text', '3원 촉매') +
        field('귀금속 성분 (Pt)', 'cat_pt', 'number', '') + field('귀금속 성분 (Pd)', 'cat_pd', 'number', '') +
        field('귀금속 성분 (Rh)', 'cat_rh', 'number', '') + field('촉매 위치', 'cat_location', 'text', '')) +
      section('배출가스 개발 목표',
        field('CO 목표 (g/km)', 'target_co', 'number', '') + field('NOx 목표 (g/km)', 'target_nox', 'number', '') +
        field('THC 목표 (g/km)', 'target_thc', 'number', '') + field('NMHC 목표 (g/km)', 'target_nmhc', 'number', '') +
        field('PM 목표 (g/km)', 'target_pm', 'number', ''));
  }

  if (formType === 'emission_noise') {
    return sectionFull('소음 저감 장치 – 소음기',
        field('소음기 종류', 'muffler_type', 'text', '') + field('소음기 재질', 'muffler_material', 'text', '') +
        field('소음기 외경 (mm)', 'muffler_od', 'number', '') + field('소음기 길이 (mm)', 'muffler_length', 'number', '') +
        textarea('소음기 구조 설명', 'muffler_desc', '소음기 구조 및 작동 방식 설명')) +
      section('촉매 변환장치',
        field('촉매 형식', 'cat_type', 'text', '') + field('촉매 용량 (L)', 'cat_volume', 'number', '') +
        field('셀 밀도 (cpsi)', 'cat_cpsi', 'number', '') + field('귀금속 함량 (g/ft³)', 'cat_pgm', 'number', '')) +
      sectionFull('배출가스 저감 기술', textarea('주요 저감 기술 설명', 'emission_tech', '엔진 제어, 연료분사, 촉매 등 기술 설명', 4)) +
      section('소음 측정 결과 요약',
        field('가속소음 측정값 (dB(A))', 'accel_noise_meas', 'number', '') +
        field('가속소음 기준값 (dB(A))', 'accel_noise_std', 'number', '') +
        field('배기소음 측정값 (dB(A))', 'exhaust_noise_meas', 'number', '') +
        field('배기소음 기준값 (dB(A))', 'exhaust_noise_std', 'number', ''));
  }

  if (formType === 'obd_config') {
    return sectionFull('OBD 시스템 개요',
        field('OBD 시스템 제조사', 'obd_maker', 'text', '') + field('ECU 제조사', 'ecu_maker', 'text', '') +
        field('OBD 적용 단계', 'obd_stage', 'text', 'OBD-II') +
        textarea('OBD 시스템 개요 설명', 'obd_overview', 'OBD 시스템 전반적인 구성 설명', 3)) +
      section('모니터링 항목',
        field('크랭크 포지션 센서 (CPS)', 'mon_cps', 'text', '해당/비해당') +
        field('T-MAP 센서', 'mon_tmap', 'text', '해당/비해당') +
        field('스로틀 포지션 센서 (TPS)', 'mon_tps', 'text', '해당/비해당') +
        field('수온 센서 (WTS)', 'mon_wts', 'text', '해당/비해당') +
        field('O₂ 센서', 'mon_o2', 'text', '해당/비해당') +
        field('연료 인젝터', 'mon_injector', 'text', '해당/비해당') +
        field('점화 코일', 'mon_ignition', 'text', '해당/비해당') +
        field('촉매 (CAT)', 'mon_catalyst', 'text', '해당/비해당') +
        field('실화 모니터', 'mon_misfire', 'text', '해당/비해당') +
        field('연료 계통', 'mon_fuel_sys', 'text', '해당/비해당')) +
      sectionFull('고장 표시 장치',
        field('고장 표시 램프 (MIL) 위치', 'mil_location', 'text', '') +
        textarea('고장코드 (DTC) 처리 방식', 'dtc_handling', 'DTC 발생 조건 및 소거 방법') +
        field('OBD 커넥터 위치', 'obd_connector', 'text', ''));
  }

  if (formType === 'emission_test') {
    return section('시험 일반 정보',
        field('시험기관', 'test_lab', 'text', '') + field('시험일', 'test_date', 'date', '') +
        field('시험 모드', 'test_mode', 'text', 'WMTC') + field('시험 담당자', 'tester', 'text', '')) +
      section('차량 정보',
        field('차종명', 'model', 'text', '') + field('연식', 'model_year', 'text', '') +
        field('차대번호', 'vin', 'text', '') + field('공차중량 (kg)', 'curb_weight', 'number', '') +
        field('시험 중량 (kg)', 'test_weight', 'number', '') + field('주행거리 (km)', 'mileage', 'number', '')) +
      section('시험 조건',
        field('실내 온도 (°C)', 'room_temp', 'number', '') + field('대기압 (kPa)', 'atm_pressure', 'number', '') +
        field('습도 (%)', 'humidity', 'number', '') + field('연료 종류', 'fuel_type', 'text', '무연 휘발유')) +
      section('배출가스 측정 결과 (g/km)',
        field('HC 측정값', 'hc_result', 'number', '') + field('HC 기준값', 'hc_limit', 'number', '') +
        field('CO 측정값', 'co_result', 'number', '') + field('CO 기준값', 'co_limit', 'number', '') +
        field('NOx 측정값', 'nox_result', 'number', '') + field('NOx 기준값', 'nox_limit', 'number', '') +
        field('NMHC 측정값', 'nmhc_result', 'number', '') + field('NMHC 기준값', 'nmhc_limit', 'number', '') +
        field('CO₂ (g/km)', 'co2_result', 'number', '') + field('연비 (km/L)', 'fuel_economy', 'number', ''));
  }

  if (formType === 'evap_test') {
    return section('시험 일반 정보',
        field('시험기관', 'test_lab', 'text', '') + field('시험일', 'test_date', 'date', '') +
        field('시험 담당자', 'tester', 'text', '')) +
      section('차량 및 연료',
        field('차종명', 'model', 'text', '') + field('차대번호', 'vin', 'text', '') +
        field('연료탱크 용량 (L)', 'fuel_tank', 'number', '') + field('카니스터 용량 (g)', 'canister_cap', 'number', '')) +
      section('시험 결과',
        field('고온 침지 측정값 (g)', 'hot_soak_result', 'number', '') +
        field('고온 침지 기준값 (g)', 'hot_soak_limit', 'number', '') +
        field('주간 증발 측정값 (g)', 'diurnal_result', 'number', '') +
        field('주간 증발 기준값 (g)', 'diurnal_limit', 'number', '') +
        field('합산 측정값 (g)', 'total_result', 'number', '') +
        field('합산 기준값 (g)', 'total_limit', 'number', ''));
  }

  if (formType === 'obd_operation') {
    return section('시험 일반 정보',
        field('시험기관', 'test_lab', 'text', '') + field('시험일', 'test_date', 'date', '') +
        field('시험 담당자', 'tester', 'text', '')) +
      section('차량 정보',
        field('차종명', 'model', 'text', '') + field('차대번호', 'vin', 'text', '') +
        field('공차중량 (kg)', 'curb_weight', 'number', '') + field('연료 종류', 'fuel_type', 'text', '') +
        field('변속기 종류', 'trans_type', 'text', '')) +
      section('배출가스 제어 장치',
        field('촉매 종류', 'catalyst_type', 'text', '') + field('ECU 제조사', 'ecu_maker', 'text', '') +
        field('O₂ 센서 종류', 'o2_type', 'text', '') + field('EGR 장치', 'egr', 'text', '해당/비해당') +
        field('2차 공기 공급', 'secondary_air', 'text', '해당/비해당') + field('퍼지 밸브', 'purge_valve', 'text', '')) +
      section('OBD 작동 확인 시험 결과',
        field('CO 측정값 (g/km)', 'co_meas', 'number', '') + field('CO 고장 허용값 (g/km)', 'co_fault', 'number', '') +
        field('NOx 측정값 (g/km)', 'nox_meas', 'number', '') + field('NOx 고장 허용값 (g/km)', 'nox_fault', 'number', '') +
        field('HC 측정값 (g/km)', 'hc_meas', 'number', '') + field('HC 고장 허용값 (g/km)', 'hc_fault', 'number', ''));
  }

  if (formType === 'noise_test') {
    return section('시험 일반 정보',
        field('시험기관', 'test_lab', 'text', '') + field('시험일', 'test_date', 'date', '') +
        field('적용 법규', 'regulation', 'text', 'ECE R41') + field('시험 담당자', 'tester', 'text', '')) +
      section('시험 환경',
        field('시험장 표면', 'surface', 'text', 'ISO 10844 아스팔트') + field('배경소음 (dB(A))', 'bg_noise', 'number', '') +
        field('온도 (°C)', 'temp', 'number', '') + field('풍속 (m/s)', 'wind', 'number', '')) +
      section('차량 정보',
        field('차종명', 'model', 'text', '') + field('차대번호', 'vin', 'text', '') +
        field('공차중량 (kg)', 'curb_weight', 'number', '') + field('최고출력 (kW)', 'max_power', 'number', '') +
        field('변속기 종류', 'trans_type', 'text', '') + field('타이어 규격', 'tire_spec', 'text', '')) +
      section('가속소음 시험 결과',
        field('1차 측정값 좌 (dB(A))', 'accel_l1', 'number', '') + field('1차 측정값 우 (dB(A))', 'accel_r1', 'number', '') +
        field('2차 측정값 좌 (dB(A))', 'accel_l2', 'number', '') + field('2차 측정값 우 (dB(A))', 'accel_r2', 'number', '') +
        field('평균 측정값 (dB(A))', 'accel_avg', 'number', '') + field('기준값 (dB(A))', 'accel_limit', 'number', '')) +
      section('배기소음 시험 결과',
        field('배기소음 측정값 (dB(A))', 'exhaust_meas', 'number', '') +
        field('배기소음 기준값 (dB(A))', 'exhaust_limit', 'number', '') +
        field('측정 장비 (소음계)', 'noise_meter', 'text', ''));
  }

  if (formType === 'confirmation') {
    return section('확인서 정보',
        field('신청인 (회사명)', 'company', 'text', '') + field('대표자', 'rep', 'text', '') +
        field('작성일', 'confirm_date', 'date', '') + field('차종명', 'model', 'text', '') +
        field('인증 유형', 'cert_type_text', 'text', '')) +
      \`<div class="form-section">
        <h4 style="font-size:1rem; font-weight:700; color:#1d4ed8; margin:0 0 16px; padding-bottom:10px; border-bottom:1px solid #dbeafe;">보증 내용 확인</h4>
        <div style="display:grid; gap:10px;">
          \${[
            ['chk_warranty', '「대기환경보전법」 제48조에 따른 배출가스 보증 의무를 이행하겠습니다.'],
            ['chk_doc',      '제출된 서류는 모두 사실임을 확인합니다.'],
            ['chk_translate','외국어 서류의 경우 번역본을 함께 제출합니다.'],
            ['chk_change',   '인증사항 변경 시 즉시 변경인증 또는 변경보고를 하겠습니다.'],
            ['chk_recall',   '결함이 발견될 경우 시정조치(리콜) 의무를 이행하겠습니다.'],
          ].map(([key, text]) => \`
            <label style="display:flex; align-items:flex-start; gap:10px; cursor:pointer; padding:12px; border:1px solid #e5e7eb; border-radius:8px; transition:background .15s;"
                   onmouseover="this.style.background='#f9fafb'" onmouseout="this.style.background='transparent'">
              <input type="checkbox" data-field="\${key}" \${v(key) === 'true' ? 'checked' : ''}
                     onchange="this.value=this.checked" style="margin-top:2px; width:16px; height:16px; accent-color:#2563eb; cursor:pointer; flex-shrink:0;">
              <span style="font-size:.9rem; color:#374151;">\${text}</span>
            </label>
          \`).join('')}
        </div>
      </div>\` +
      section('서명', field('대표자 서명 (타이핑)', 'signature', 'text', '성명 입력'));
  }

  return '<div class="form-section" style="color:#6b7280; text-align:center; padding:40px;">해당 서류 양식을 준비 중입니다.</div>';
}

// ================================================================
// 토스트
// ================================================================
function showToast(msg, type = 'default') {
  const existing = document.querySelector('.toast-msg');
  if (existing) existing.remove();
  const t = document.createElement('div');
  t.className = 'toast-msg' + (type !== 'default' ? ' ' + type : '');
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

// ================================================================
// 모달 외부 클릭 닫기
// ================================================================
document.getElementById('modal-new-app').addEventListener('click', function(e) {
  if (e.target === this) closeNewAppModal();
});

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

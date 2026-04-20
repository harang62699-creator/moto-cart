import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-workers'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'

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

// 유니코드를 포함한 문자열을 base64url로 인코딩
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
  const token = getCookie(c, 'auth_token') || c.req.header('Authorization')?.replace('Bearer ', '')
  if (!token) return c.json({ error: 'Unauthorized' }, 401)
  const payload = await verifyJWT(token)
  if (!payload) return c.json({ error: 'Invalid token' }, 401)
  c.set('user', payload)
  await next()
}

// ────────────────────────────────────────────────
// API: 인증 (회원가입 / 로그인 / 로그아웃 / 내정보)
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
    setCookie(c, 'auth_token', token, { httpOnly: true, maxAge: 86400 * 7, path: '/' })
    return c.json({ ok: true, user })
  } catch (e: any) {
    if (e.message?.includes('UNIQUE')) return c.json({ error: '이미 사용중인 아이디입니다.' }, 409)
    return c.json({ error: '서버 오류' }, 500)
  }
})

app.post('/api/auth/login', async (c) => {
  const { username, password } = await c.req.json()
  const hash = await hashPassword(password)
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE username = ? AND password_hash = ?').bind(username, hash).first()
  if (!user) return c.json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' }, 401)
  const token = await signJWT({ id: user.id, username: user.username, company_name: user.company_name })
  setCookie(c, 'auth_token', token, { httpOnly: true, maxAge: 86400 * 7, path: '/' })
  return c.json({ ok: true, user: { id: user.id, username: user.username, company_name: user.company_name, representative: user.representative } })
})

app.post('/api/auth/logout', async (c) => {
  deleteCookie(c, 'auth_token', { path: '/' })
  return c.json({ ok: true })
})

app.get('/api/auth/me', authMiddleware, async (c) => {
  const payload = c.get('user') as any
  const user = await c.env.DB.prepare('SELECT id, username, company_name, representative, business_number, phone FROM users WHERE id = ?').bind(payload.id).first()
  if (!user) return c.json({ error: 'Not found' }, 404)
  return c.json({ user })
})

// ────────────────────────────────────────────────
// API: 신청서 (CRUD)
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
  const { cert_type, title, brand, model, model_year, prev_cert_number, change_item, change_reason } = await c.req.json()
  if (!cert_type || !title) return c.json({ error: '필수 항목 누락' }, 400)
  const result = await c.env.DB.prepare(
    'INSERT INTO applications (user_id, cert_type, title, brand, model, model_year, prev_cert_number, change_item, change_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(payload.id, cert_type, title, brand || '', model || '', model_year || '', prev_cert_number || '', change_item || '', change_reason || '').run()
  const app_id = result.meta.last_row_id
  // 10개 서류 폼 레코드 생성
  const formTypes = ['summary','gasoline','detail_plan','emission_noise','obd_config','emission_test','evap_test','obd_operation','noise_test','confirmation']
  const stmts = formTypes.map(ft =>
    c.env.DB.prepare('INSERT INTO form_data (application_id, form_type) VALUES (?, ?)').bind(app_id, ft)
  )
  await c.env.DB.batch(stmts)
  const created = await c.env.DB.prepare('SELECT * FROM applications WHERE id = ?').bind(app_id).first()
  return c.json({ ok: true, application: created }, 201)
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
  await c.env.DB.prepare('DELETE FROM applications WHERE id = ?').bind(id).run()
  return c.json({ ok: true })
})

// ────────────────────────────────────────────────
// API: 서류 폼 데이터 (저장/조회)
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
  // 모든 폼 완료 시 신청서 상태 업데이트
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
// HTML 반환 (SPA - 모든 경로)
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
  .tab-btn { @apply px-4 py-2 text-sm font-medium rounded-t-lg border-b-2 transition-colors; }
  .tab-btn.active { @apply border-blue-600 text-blue-600 bg-blue-50; }
  .tab-btn:not(.active) { @apply border-transparent text-gray-500 hover:text-gray-700; }
  .form-section { @apply bg-white border border-gray-200 rounded-xl p-6 mb-4 shadow-sm; }
  .field-label { @apply block text-sm font-semibold text-gray-700 mb-1; }
  .field-input { @apply w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400; }
  .field-input:disabled { @apply bg-gray-50 text-gray-500; }
  .btn-primary { @apply bg-blue-600 hover:bg-blue-700 text-white font-semibold px-5 py-2 rounded-lg transition-colors; }
  .btn-secondary { @apply bg-gray-100 hover:bg-gray-200 text-gray-700 font-medium px-5 py-2 rounded-lg transition-colors; }
  .btn-danger { @apply bg-red-500 hover:bg-red-600 text-white font-semibold px-4 py-2 rounded-lg transition-colors; }
  .btn-success { @apply bg-green-600 hover:bg-green-700 text-white font-semibold px-5 py-2 rounded-lg transition-colors; }
  .status-draft { @apply bg-gray-100 text-gray-600 text-xs font-medium px-2 py-1 rounded-full; }
  .status-in_progress { @apply bg-yellow-100 text-yellow-700 text-xs font-medium px-2 py-1 rounded-full; }
  .status-completed { @apply bg-green-100 text-green-700 text-xs font-medium px-2 py-1 rounded-full; }
  .form-card { @apply bg-white border border-gray-200 rounded-xl p-5 hover:shadow-md transition-shadow cursor-pointer; }
  .form-card.done { @apply border-green-400 bg-green-50; }
  .progress-bar { transition: width 0.5s ease; }
  .modal-overlay { @apply fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50; }
  .modal-box { @apply bg-white rounded-2xl shadow-2xl p-8 w-full max-w-lg mx-4; }
  .sub-tab-btn { @apply px-3 py-1.5 text-xs font-medium rounded-full transition-colors; }
  .sub-tab-btn.active { @apply bg-blue-600 text-white; }
  .sub-tab-btn:not(.active) { @apply bg-gray-100 text-gray-600 hover:bg-gray-200; }
  .toast { @apply fixed bottom-6 right-6 bg-gray-800 text-white px-5 py-3 rounded-xl shadow-lg z-50 text-sm; }
  @media print { .no-print { display: none !important; } }
</style>
</head>
<body class="bg-gray-50 min-h-screen">

<!-- ── 헤더 ────────────────────────────────── -->
<header class="bg-white border-b border-gray-200 shadow-sm no-print" id="main-header">
  <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
    <div class="flex items-center gap-3">
      <div class="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center">
        <i class="fas fa-motorcycle text-white text-lg"></i>
      </div>
      <div>
        <h1 class="text-base font-bold text-gray-800">수입이륜차 인증신청 지원 시스템</h1>
        <p class="text-xs text-gray-500">배출가스·소음 인증 전용</p>
      </div>
    </div>
    <div id="header-user" class="flex items-center gap-3">
      <!-- 로그인 후 표시 -->
    </div>
  </div>
</header>

<!-- ── 페이지: 로그인/회원가입 ─────────────── -->
<div id="page-auth" class="page active min-h-screen flex items-center justify-center p-4">
  <div class="w-full max-w-md">
    <div class="text-center mb-8">
      <div class="w-16 h-16 bg-blue-600 rounded-2xl flex items-center justify-center mx-auto mb-4">
        <i class="fas fa-motorcycle text-white text-3xl"></i>
      </div>
      <h2 class="text-2xl font-bold text-gray-800">수입이륜차 인증신청</h2>
      <p class="text-gray-500 text-sm mt-1">배출가스·소음 인증신청 지원 시스템</p>
    </div>

    <!-- 탭 -->
    <div class="flex gap-2 mb-6 bg-gray-100 p-1 rounded-xl">
      <button onclick="showAuthTab('login')" id="auth-tab-login" class="flex-1 py-2 text-sm font-medium rounded-lg bg-white shadow text-blue-600">로그인</button>
      <button onclick="showAuthTab('register')" id="auth-tab-register" class="flex-1 py-2 text-sm font-medium rounded-lg text-gray-500">회원가입</button>
    </div>

    <!-- 로그인 폼 -->
    <div id="login-form" class="bg-white rounded-2xl shadow-lg p-6">
      <div class="mb-4">
        <label class="field-label"><i class="fas fa-user mr-1 text-gray-400"></i>아이디</label>
        <input id="login-username" type="text" class="field-input" placeholder="아이디 입력" autocomplete="username">
      </div>
      <div class="mb-6">
        <label class="field-label"><i class="fas fa-lock mr-1 text-gray-400"></i>비밀번호</label>
        <input id="login-password" type="password" class="field-input" placeholder="비밀번호 입력" autocomplete="current-password">
      </div>
      <button onclick="doLogin()" class="btn-primary w-full py-3">
        <i class="fas fa-sign-in-alt mr-2"></i>로그인
      </button>
      <p id="login-error" class="text-red-500 text-sm mt-3 hidden"></p>
    </div>

    <!-- 회원가입 폼 -->
    <div id="register-form" class="bg-white rounded-2xl shadow-lg p-6 hidden">
      <div class="grid grid-cols-1 gap-4">
        <div>
          <label class="field-label">아이디 <span class="text-red-500">*</span></label>
          <input id="reg-username" type="text" class="field-input" placeholder="영문·숫자·밑줄 4~20자" autocomplete="username">
          <p class="text-xs text-gray-400 mt-1">영문, 숫자, 밑줄(_)만 사용 가능 (4~20자)</p>
        </div>
        <div>
          <label class="field-label">비밀번호 <span class="text-red-500">*</span></label>
          <input id="reg-password" type="password" class="field-input" placeholder="8자 이상" autocomplete="new-password">
        </div>
        <div>
          <label class="field-label">비밀번호 확인 <span class="text-red-500">*</span></label>
          <input id="reg-password2" type="password" class="field-input" placeholder="비밀번호 재입력" autocomplete="new-password">
        </div>
        <div>
          <label class="field-label">회사명 <span class="text-red-500">*</span></label>
          <input id="reg-company" type="text" class="field-input" placeholder="(주)○○모터스">
        </div>
        <div>
          <label class="field-label">대표자명 <span class="text-red-500">*</span></label>
          <input id="reg-rep" type="text" class="field-input" placeholder="홍길동">
        </div>
        <div>
          <label class="field-label">사업자등록번호 <span class="text-red-500">*</span></label>
          <input id="reg-bizno" type="text" class="field-input" placeholder="000-00-00000">
        </div>
        <div>
          <label class="field-label">연락처</label>
          <input id="reg-phone" type="text" class="field-input" placeholder="02-0000-0000">
        </div>
      </div>
      <button onclick="doRegister()" class="btn-primary w-full py-3 mt-5">
        <i class="fas fa-user-plus mr-2"></i>회원가입
      </button>
      <p id="register-error" class="text-red-500 text-sm mt-3 hidden"></p>
    </div>
  </div>
</div>

<!-- ── 페이지: 대시보드 ───────────────────── -->
<div id="page-dashboard" class="page max-w-7xl mx-auto px-4 py-6">
  <!-- 상단 -->
  <div class="flex items-center justify-between mb-6">
    <div>
      <h2 class="text-xl font-bold text-gray-800">인증신청 목록</h2>
      <p id="dash-subtitle" class="text-sm text-gray-500 mt-1"></p>
    </div>
    <button onclick="showNewAppModal()" class="btn-primary">
      <i class="fas fa-plus mr-2"></i>새 신청서 작성
    </button>
  </div>

  <!-- 요약 카드 -->
  <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
    <div class="bg-white rounded-xl border border-gray-200 p-4 text-center">
      <div class="text-2xl font-bold text-gray-800" id="stat-total">0</div>
      <div class="text-xs text-gray-500 mt-1">전체</div>
    </div>
    <div class="bg-white rounded-xl border border-gray-200 p-4 text-center">
      <div class="text-2xl font-bold text-yellow-600" id="stat-inprogress">0</div>
      <div class="text-xs text-gray-500 mt-1">작성중</div>
    </div>
    <div class="bg-white rounded-xl border border-gray-200 p-4 text-center">
      <div class="text-2xl font-bold text-green-600" id="stat-completed">0</div>
      <div class="text-xs text-gray-500 mt-1">완료</div>
    </div>
    <div class="bg-white rounded-xl border border-gray-200 p-4 text-center">
      <div class="text-2xl font-bold text-gray-400" id="stat-draft">0</div>
      <div class="text-xs text-gray-500 mt-1">임시저장</div>
    </div>
  </div>

  <!-- 신청서 목록 -->
  <div id="app-list" class="space-y-3">
    <!-- JS로 생성 -->
  </div>
  <div id="app-empty" class="hidden text-center py-16">
    <i class="fas fa-file-alt text-5xl text-gray-300 mb-4"></i>
    <p class="text-gray-500">아직 작성된 신청서가 없습니다.</p>
    <button onclick="showNewAppModal()" class="btn-primary mt-4">첫 신청서 작성하기</button>
  </div>
</div>

<!-- ── 페이지: 신청서 상세/서류 작성 ─────── -->
<div id="page-application" class="page max-w-7xl mx-auto px-4 py-6">
  <!-- 브레드크럼 -->
  <div class="flex items-center gap-2 text-sm text-gray-500 mb-4 no-print">
    <button onclick="showDashboard()" class="hover:text-blue-600">
      <i class="fas fa-home mr-1"></i>목록
    </button>
    <span>›</span>
    <span id="appl-breadcrumb" class="text-gray-800 font-medium"></span>
  </div>

  <!-- 신청서 헤더 -->
  <div class="bg-white rounded-xl border border-gray-200 p-6 mb-5 shadow-sm">
    <div class="flex items-start justify-between">
      <div>
        <div class="flex items-center gap-3 mb-2">
          <span id="appl-cert-badge" class="text-xs font-bold px-3 py-1 rounded-full bg-blue-100 text-blue-700"></span>
          <span id="appl-status-badge" class="status-draft"></span>
        </div>
        <h3 id="appl-title" class="text-lg font-bold text-gray-800"></h3>
        <p id="appl-meta" class="text-sm text-gray-500 mt-1"></p>
      </div>
      <div class="text-right">
        <div class="text-sm text-gray-500 mb-1">전체 진행률</div>
        <div class="text-2xl font-bold text-blue-600" id="appl-progress-pct">0%</div>
        <div class="w-32 bg-gray-200 rounded-full h-2 mt-1">
          <div id="appl-progress-bar" class="bg-blue-600 h-2 rounded-full progress-bar" style="width:0%"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- 서류 목록 -->
  <h4 class="text-base font-bold text-gray-700 mb-3">제출 서류 작성 현황</h4>
  <div id="forms-grid" class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
    <!-- JS로 생성 -->
  </div>
</div>

<!-- ── 페이지: 서류 입력 폼 ──────────────── -->
<div id="page-form" class="page max-w-5xl mx-auto px-4 py-6">
  <!-- 헤더 -->
  <div class="flex items-center gap-2 text-sm text-gray-500 mb-4 no-print">
    <button onclick="showDashboard()" class="hover:text-blue-600"><i class="fas fa-home mr-1"></i>목록</button>
    <span>›</span>
    <button id="form-appl-link" class="hover:text-blue-600"></button>
    <span>›</span>
    <span id="form-breadcrumb" class="text-gray-800 font-medium"></span>
  </div>

  <div class="bg-white rounded-xl border border-gray-200 p-6 mb-5 shadow-sm">
    <div class="flex items-center justify-between">
      <div>
        <h3 id="form-title" class="text-lg font-bold text-gray-800"></h3>
        <p id="form-subtitle" class="text-sm text-gray-500 mt-1"></p>
      </div>
      <div class="flex gap-2">
        <button onclick="saveForm()" class="btn-success"><i class="fas fa-save mr-2"></i>저장</button>
        <button onclick="printForm()" class="btn-secondary no-print"><i class="fas fa-print mr-2"></i>인쇄</button>
      </div>
    </div>
  </div>

  <!-- 폼 내용 (동적 생성) -->
  <div id="form-content"></div>

  <!-- 완료 체크 -->
  <div class="bg-white rounded-xl border border-gray-200 p-5 mt-4 shadow-sm no-print">
    <label class="flex items-center gap-3 cursor-pointer">
      <input type="checkbox" id="form-completed-chk" class="w-5 h-5 accent-green-600">
      <span class="font-medium text-gray-700">이 서류 작성을 완료했습니다 (체크리스트에 반영됩니다)</span>
    </label>
  </div>
</div>

<!-- ── 모달: 새 신청서 만들기 ─────────────── -->
<div id="modal-new-app" class="modal-overlay hidden no-print">
  <div class="modal-box">
    <h3 class="text-lg font-bold text-gray-800 mb-5"><i class="fas fa-file-plus mr-2 text-blue-600"></i>새 인증신청서 작성</h3>
    <div class="space-y-4">
      <div>
        <label class="field-label">신청 제목 <span class="text-red-500">*</span></label>
        <input id="new-title" type="text" class="field-input" placeholder="예) 2025년 ABC 125cc 기본인증">
      </div>
      <div>
        <label class="field-label">인증 유형 <span class="text-red-500">*</span></label>
        <select id="new-cert-type" class="field-input" onchange="onNewCertTypeChange()">
          <option value="basic">기본인증 (신규 수입이륜차)</option>
          <option value="change">변경인증 (인증사항 중요 변경)</option>
          <option value="report">변경보고 (경미한 사항 변경)</option>
        </select>
      </div>
      <div id="new-prev-cert-wrap" class="hidden">
        <label class="field-label">기존 인증번호 <span class="text-red-500">*</span></label>
        <input id="new-prev-cert" type="text" class="field-input" placeholder="기존 인증번호 입력">
      </div>
      <div class="grid grid-cols-2 gap-3">
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
    <div class="flex justify-end gap-3 mt-6">
      <button onclick="closeNewAppModal()" class="btn-secondary">취소</button>
      <button onclick="createApplication()" class="btn-primary"><i class="fas fa-check mr-2"></i>생성</button>
    </div>
  </div>
</div>

<!-- ── 토스트 ──────────────────────────────── -->
<div id="toast" class="toast hidden"></div>

<script>
// ================================================================
// 상태
// ================================================================
let currentUser = null;
let currentApplications = [];
let currentApplication = null;
let currentForms = [];
let currentFormType = null;
let currentApplicationId = null;

const FORM_META = [
  { type: 'summary',        title: '인증신청 요약서',              icon: 'fa-file-alt',        color: 'blue' },
  { type: 'gasoline',       title: '휘발유차 인증신청 주요내용',   icon: 'fa-gas-pump',        color: 'orange' },
  { type: 'detail_plan',    title: '인증에 필요한 세부 계획 서류', icon: 'fa-clipboard-list',  color: 'purple' },
  { type: 'emission_noise', title: '배출가스·소음 저감 서류',      icon: 'fa-wind',            color: 'teal' },
  { type: 'obd_config',     title: 'OBD 구성에 관한 서류',         icon: 'fa-microchip',       color: 'indigo' },
  { type: 'emission_test',  title: '배출가스 시험보고서',          icon: 'fa-flask',           color: 'green' },
  { type: 'evap_test',      title: '증발가스 시험내용 보고서',     icon: 'fa-vials',           color: 'yellow' },
  { type: 'obd_operation',  title: 'OBD 작동 확인시험 보고서',    icon: 'fa-cogs',            color: 'red' },
  { type: 'noise_test',     title: '자동차소음 시험내용 보고서',   icon: 'fa-volume-up',       color: 'pink' },
  { type: 'confirmation',   title: '확인서',                       icon: 'fa-stamp',           color: 'gray' },
];

const CERT_TYPE_LABEL = { basic: '기본인증', change: '변경인증', report: '변경보고' };
const STATUS_LABEL = { draft: '임시저장', in_progress: '작성중', completed: '완료' };

// ================================================================
// 초기화
// ================================================================
async function init() {
  try {
    const res = await fetch('/api/auth/me');
    if (res.ok) {
      const { user } = await res.json();
      currentUser = user;
      showDashboard();
    } else {
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
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

function updateHeader() {
  const el = document.getElementById('header-user');
  if (!currentUser) {
    el.innerHTML = '';
    return;
  }
  el.innerHTML = \`
    <div class="text-right hidden sm:block">
      <div class="text-sm font-semibold text-gray-800">\${currentUser.company_name}</div>
      <div class="text-xs text-gray-500"><i class="fas fa-user mr-1"></i>\${currentUser.username}</div>
    </div>
    <button onclick="doLogout()" class="btn-secondary text-sm">
      <i class="fas fa-sign-out-alt mr-1"></i>로그아웃
    </button>
  \`;
}

// ================================================================
// 인증
// ================================================================
function showAuthTab(tab) {
  document.getElementById('login-form').classList.toggle('hidden', tab !== 'login');
  document.getElementById('register-form').classList.toggle('hidden', tab !== 'register');
  document.getElementById('auth-tab-login').className = 'flex-1 py-2 text-sm font-medium rounded-lg ' + (tab === 'login' ? 'bg-white shadow text-blue-600' : 'text-gray-500');
  document.getElementById('auth-tab-register').className = 'flex-1 py-2 text-sm font-medium rounded-lg ' + (tab === 'register' ? 'bg-white shadow text-blue-600' : 'text-gray-500');
}

async function doLogin() {
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const err = document.getElementById('login-error');
  err.classList.add('hidden');
  if (!username || !password) { err.textContent = '아이디와 비밀번호를 입력하세요.'; err.classList.remove('hidden'); return; }
  const res = await fetch('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) });
  const data = await res.json();
  if (!res.ok) { err.textContent = data.error; err.classList.remove('hidden'); return; }
  currentUser = data.user;
  showDashboard();
}

async function doRegister() {
  const username = document.getElementById('reg-username').value.trim();
  const password = document.getElementById('reg-password').value;
  const password2 = document.getElementById('reg-password2').value;
  const company_name = document.getElementById('reg-company').value.trim();
  const representative = document.getElementById('reg-rep').value.trim();
  const business_number = document.getElementById('reg-bizno').value.trim();
  const phone = document.getElementById('reg-phone').value.trim();
  const err = document.getElementById('register-error');
  err.classList.add('hidden');
  if (!username || !password || !company_name || !representative || !business_number) {
    err.textContent = '필수 항목을 모두 입력해주세요.'; err.classList.remove('hidden'); return;
  }
  if (!/^[a-zA-Z0-9_]{4,20}$/.test(username)) {
    err.textContent = '아이디는 영문·숫자·밑줄 4~20자로 입력해주세요.'; err.classList.remove('hidden'); return;
  }
  if (password.length < 8) { err.textContent = '비밀번호는 8자 이상이어야 합니다.'; err.classList.remove('hidden'); return; }
  if (password !== password2) { err.textContent = '비밀번호가 일치하지 않습니다.'; err.classList.remove('hidden'); return; }
  const res = await fetch('/api/auth/register', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, company_name, representative, business_number, phone })
  });
  const data = await res.json();
  if (!res.ok) { err.textContent = data.error; err.classList.remove('hidden'); return; }
  currentUser = data.user;
  showToast('회원가입이 완료되었습니다.');
  showDashboard();
}

async function doLogout() {
  await fetch('/api/auth/logout', { method: 'POST' });
  currentUser = null;
  showPage('page-auth');
  updateHeader();
}

// ================================================================
// 대시보드
// ================================================================
async function showDashboard() {
  updateHeader();
  showPage('page-dashboard');
  document.getElementById('dash-subtitle').textContent = currentUser ? currentUser.company_name + ' · @' + currentUser.username : '';
  await loadApplications();
}

async function loadApplications() {
  const res = await fetch('/api/applications');
  const data = await res.json();
  currentApplications = data.applications || [];
  renderApplicationList();
}

function renderApplicationList() {
  const list = document.getElementById('app-list');
  const empty = document.getElementById('app-empty');
  let total = currentApplications.length;
  let inprogress = currentApplications.filter(a => a.status === 'in_progress').length;
  let completed = currentApplications.filter(a => a.status === 'completed').length;
  let draft = currentApplications.filter(a => a.status === 'draft').length;
  document.getElementById('stat-total').textContent = total;
  document.getElementById('stat-inprogress').textContent = inprogress;
  document.getElementById('stat-completed').textContent = completed;
  document.getElementById('stat-draft').textContent = draft;
  if (total === 0) { list.innerHTML = ''; empty.classList.remove('hidden'); return; }
  empty.classList.add('hidden');
  list.innerHTML = currentApplications.map(a => {
    const total_f = a.total_forms || 10;
    const done_f = a.completed_forms || 0;
    const pct = Math.round(done_f / total_f * 100);
    return \`
      <div class="bg-white border border-gray-200 rounded-xl p-5 hover:shadow-md transition-shadow flex items-center justify-between gap-4">
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 mb-1">
            <span class="text-xs font-bold px-2 py-0.5 rounded-full bg-blue-100 text-blue-700">\${CERT_TYPE_LABEL[a.cert_type] || a.cert_type}</span>
            <span class="status-\${a.status}">\${STATUS_LABEL[a.status] || a.status}</span>
          </div>
          <h4 class="font-semibold text-gray-800 truncate">\${a.title}</h4>
          <p class="text-xs text-gray-500 mt-0.5">\${a.brand || ''} \${a.model || ''} \${a.model_year ? a.model_year + '년식' : ''} · \${new Date(a.updated_at).toLocaleDateString('ko-KR')}</p>
          <div class="flex items-center gap-2 mt-2">
            <div class="flex-1 bg-gray-200 rounded-full h-1.5">
              <div class="bg-blue-500 h-1.5 rounded-full" style="width:\${pct}%"></div>
            </div>
            <span class="text-xs text-gray-500 shrink-0">\${done_f}/\${total_f} 서류</span>
          </div>
        </div>
        <div class="flex gap-2 shrink-0">
          <button onclick="openApplication(\${a.id})" class="btn-primary text-sm">
            <i class="fas fa-edit mr-1"></i>작성하기
          </button>
          <button onclick="deleteApplication(\${a.id})" class="btn-danger text-sm">
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
  const res = await fetch('/api/applications/' + id);
  const data = await res.json();
  currentApplication = data.application;
  currentForms = data.forms;
  currentApplicationId = id;
  renderApplicationPage();
  showPage('page-application');
}

function renderApplicationPage() {
  const a = currentApplication;
  document.getElementById('appl-breadcrumb').textContent = a.title;
  document.getElementById('appl-cert-badge').textContent = CERT_TYPE_LABEL[a.cert_type] || a.cert_type;
  const sb = document.getElementById('appl-status-badge');
  sb.className = 'status-' + a.status;
  sb.textContent = STATUS_LABEL[a.status] || a.status;
  document.getElementById('appl-title').textContent = a.title;
  document.getElementById('appl-meta').textContent = [a.brand, a.model, a.model_year ? a.model_year + '년식' : ''].filter(Boolean).join(' · ');
  const done = currentForms.filter(f => f.completed).length;
  const total = currentForms.length;
  const pct = total ? Math.round(done / total * 100) : 0;
  document.getElementById('appl-progress-pct').textContent = pct + '%';
  document.getElementById('appl-progress-bar').style.width = pct + '%';

  const grid = document.getElementById('forms-grid');
  grid.innerHTML = FORM_META.map((meta, idx) => {
    const formData = currentForms.find(f => f.form_type === meta.type);
    const done = formData?.completed;
    return \`
      <div class="form-card \${done ? 'done' : ''}" onclick="openForm('\${meta.type}')">
        <div class="flex items-start gap-4">
          <div class="w-10 h-10 rounded-xl flex items-center justify-center shrink-0 \${done ? 'bg-green-100' : 'bg-' + meta.color + '-100'}">
            <i class="fas \${meta.icon} \${done ? 'text-green-600' : 'text-' + meta.color + '-600'}"></i>
          </div>
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 mb-1">
              <span class="text-xs text-gray-400 font-medium">서류 \${idx + 1}</span>
              \${done ? '<span class="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full font-medium"><i class="fas fa-check mr-1"></i>완료</span>' : '<span class="text-xs bg-gray-100 text-gray-500 px-2 py-0.5 rounded-full">미완료</span>'}
            </div>
            <h5 class="font-semibold text-gray-800 text-sm leading-tight">\${meta.title}</h5>
          </div>
          <i class="fas fa-chevron-right text-gray-300 text-sm mt-2"></i>
        </div>
      </div>
    \`;
  }).join('');
}

// ================================================================
// 서류 폼 열기/저장
// ================================================================
async function openForm(formType) {
  currentFormType = formType;
  const meta = FORM_META.find(m => m.type === formType);
  const formData = currentForms.find(f => f.form_type === formType);
  let savedData = {};
  try { savedData = JSON.parse(formData?.data || '{}'); } catch {}

  document.getElementById('form-appl-link').textContent = currentApplication.title;
  document.getElementById('form-appl-link').onclick = () => { openApplication(currentApplicationId); };
  document.getElementById('form-breadcrumb').textContent = meta.title;
  document.getElementById('form-title').textContent = meta.title;
  document.getElementById('form-subtitle').textContent = CERT_TYPE_LABEL[currentApplication.cert_type] + ' · ' + currentApplication.title;
  document.getElementById('form-completed-chk').checked = !!formData?.completed;

  const content = document.getElementById('form-content');
  content.innerHTML = buildFormHTML(formType, savedData);
  showPage('page-form');
}

async function saveForm() {
  const data = collectFormData(currentFormType);
  const completed = document.getElementById('form-completed-chk').checked;
  const res = await fetch('/api/applications/' + currentApplicationId + '/forms/' + currentFormType, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data, completed })
  });
  if (res.ok) {
    showToast('저장되었습니다.');
    // 현재 폼 데이터 갱신
    const idx = currentForms.findIndex(f => f.form_type === currentFormType);
    if (idx >= 0) { currentForms[idx].data = JSON.stringify(data); currentForms[idx].completed = completed ? 1 : 0; }
  } else {
    showToast('저장 실패');
  }
}

function printForm() {
  window.print();
}

// ================================================================
// 신청서 생성/삭제
// ================================================================
function showNewAppModal() {
  document.getElementById('modal-new-app').classList.remove('hidden');
  document.getElementById('new-title').value = '';
  document.getElementById('new-brand').value = '';
  document.getElementById('new-model').value = '';
  document.getElementById('new-year').value = '';
  document.getElementById('new-cert-type').value = 'basic';
  onNewCertTypeChange();
}

function closeNewAppModal() {
  document.getElementById('modal-new-app').classList.add('hidden');
}

function onNewCertTypeChange() {
  const v = document.getElementById('new-cert-type').value;
  document.getElementById('new-prev-cert-wrap').classList.toggle('hidden', v === 'basic');
}

async function createApplication() {
  const title = document.getElementById('new-title').value.trim();
  const cert_type = document.getElementById('new-cert-type').value;
  const brand = document.getElementById('new-brand').value.trim();
  const model = document.getElementById('new-model').value.trim();
  const model_year = document.getElementById('new-year').value.trim();
  const prev_cert_number = document.getElementById('new-prev-cert')?.value.trim() || '';
  if (!title) { showToast('신청 제목을 입력하세요.'); return; }
  if ((cert_type === 'change' || cert_type === 'report') && !prev_cert_number) {
    showToast('기존 인증번호를 입력하세요.'); return;
  }
  const res = await fetch('/api/applications', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title, cert_type, brand, model, model_year, prev_cert_number })
  });
  if (res.ok) {
    const { application } = await res.json();
    closeNewAppModal();
    showToast('신청서가 생성되었습니다.');
    await openApplication(application.id);
  } else {
    showToast('생성 실패');
  }
}

async function deleteApplication(id) {
  if (!confirm('이 신청서를 삭제하시겠습니까?')) return;
  const res = await fetch('/api/applications/' + id, { method: 'DELETE' });
  if (res.ok) { showToast('삭제되었습니다.'); await loadApplications(); }
}

// ================================================================
// 폼 데이터 수집 (각 서류 공통)
// ================================================================
function collectFormData(formType) {
  const data = {};
  document.querySelectorAll('#form-content [data-field]').forEach(el => {
    data[el.dataset.field] = el.value;
  });
  return data;
}

// ================================================================
// 폼 HTML 빌더 (서류별)
// ================================================================
function buildFormHTML(formType, saved) {
  const v = (k, def='') => saved[k] !== undefined ? saved[k] : def;
  const field = (label, key, type='text', placeholder='', note='') => \`
    <div>
      <label class="field-label">\${label}</label>
      <input type="\${type}" data-field="\${key}" value="\${v(key)}" placeholder="\${placeholder}" class="field-input">
      \${note ? '<p class="text-xs text-gray-400 mt-1">' + note + '</p>' : ''}
    </div>
  \`;
  const textarea = (label, key, placeholder='', rows=3) => \`
    <div>
      <label class="field-label">\${label}</label>
      <textarea data-field="\${key}" rows="\${rows}" placeholder="\${placeholder}" class="field-input">\${v(key)}</textarea>
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
      <h4 class="text-base font-bold text-blue-700 mb-4 border-b border-blue-100 pb-2">\${title}</h4>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">\${fields}</div>
    </div>
  \`;

  if (formType === 'summary') {
    return section('신청인 정보', field('신청인 (회사명)', 'company', 'text', '(주)○○모터스') + field('대표자', 'rep', 'text', '홍길동') + field('사업자등록번호', 'bizno', 'text', '000-00-00000') + field('주소', 'address', 'text', '서울시...') + field('연락처', 'phone', 'text', '02-0000-0000') + field('담당자', 'manager', 'text', '담당자명')) +
      section('차량 개요', field('제작사 (브랜드)', 'brand', 'text', 'Honda') + field('차종명', 'model', 'text', 'CB125R') + field('원산지', 'origin', 'text', '일본') + field('연식', 'model_year', 'text', '2025') + select('연료 종류', 'fuel', [['gasoline','휘발유'],['electric','전기'],['lpg','LPG']]) + select('변속기', 'trans', [['manual','수동'],['auto','자동'],['cvt','CVT']]) + field('차대번호(VIN)', 'vin', 'text', '')) +
      section('배출가스 기준', field('적용 배출가스 기준', 'emission_std', 'text', 'EURO 5') + field('OBD 단계', 'obd_stage', 'text', 'OBD-II') + field('대표 차종 여부', 'is_rep', 'text', '해당/비해당') + field('보증기간 (km)', 'warranty_km', 'number', '30000') + field('보증기간 (년)', 'warranty_year', 'number', '5')) +
      section('소음 기준', field('적용 소음 기준', 'noise_std', 'text', 'ECE R41') + field('가속소음 (dB(A))', 'accel_noise', 'number', '') + field('배기소음 (dB(A))', 'exhaust_noise', 'number', ''));
  }

  if (formType === 'gasoline') {
    return section('기본 차량 정보', field('제작사명', 'maker', 'text', '') + field('차종명', 'model', 'text', '') + field('배기량 (cc)', 'displacement', 'number', '') + field('연료 공급 방식', 'fuel_supply', 'text', '전자제어 분사') + field('냉각 방식', 'cooling', 'text', '수냉/공냉') + field('기통수', 'cylinders', 'number', '1')) +
      section('적용 인증 기준', select('배출가스 기준', 'emission_std', [['EURO5','EURO 5'],['EURO6','EURO 6'],['EURO4','EURO 4']]) + field('OBD 단계', 'obd_stage', 'text', 'OBD-II') + field('증발가스 기준', 'evap_std', 'text', '') + field('인증 적용 대상', 'cert_target', 'text', '')) +
      section('대표 차종', field('대표 차종 여부', 'is_rep', 'text', '') + field('대표 차종명', 'rep_model', 'text', '') + field('포함 차종 수', 'family_count', 'number', '1')) +
      section('보증 기간', field('보증기간 (km)', 'warranty_km', 'number', '') + field('보증기간 (년)', 'warranty_year', 'number', '') + field('자가 진단 교환 주기', 'obd_interval', 'text', '')) +
      section('배출가스 시험 결과 (WMTC)', field('CO 측정값 (g/km)', 'co_result', 'number', '') + field('NOx 측정값 (g/km)', 'nox_result', 'number', '') + field('HC 측정값 (g/km)', 'hc_result', 'number', '') + field('NMHC 측정값 (g/km)', 'nmhc_result', 'number', '') + field('CO 기준값', 'co_std', 'number', '') + field('NOx 기준값', 'nox_std', 'number', '')) +
      section('OBD 진단 항목', field('O₂ 센서 모니터링', 'obd_o2', 'text', '해당/비해당') + field('촉매 모니터링', 'obd_cat', 'text', '해당/비해당') + field('연료계통 모니터링', 'obd_fuel', 'text', '해당/비해당') + field('실화 모니터링', 'obd_misfire', 'text', '해당/비해당'));
  }

  if (formType === 'detail_plan') {
    return section('차량 기본 사양', field('제작사', 'maker', 'text', '') + field('차종명', 'model', 'text', '') + field('연식', 'model_year', 'text', '') + field('차량 총중량 (kg)', 'gvw', 'number', '') + field('공차중량 (kg)', 'curb_weight', 'number', '') + field('전장 (mm)', 'length', 'number', '') + field('전폭 (mm)', 'width', 'number', '') + field('전고 (mm)', 'height', 'number', '') + field('축간거리 (mm)', 'wheelbase', 'number', '')) +
      section('엔진 사양', field('배기량 (cc)', 'displacement', 'number', '') + field('최고출력 (kW)', 'max_power', 'number', '') + field('최대토크 (N·m)', 'max_torque', 'number', '') + field('보어 × 스트로크 (mm)', 'bore_stroke', 'text', '') + field('압축비', 'compression', 'text', '') + field('연료탱크 용량 (L)', 'fuel_tank', 'number', '')) +
      section('촉매 장치', field('촉매 종류', 'catalyst_type', 'text', '3원 촉매') + field('귀금속 성분 (Pt)', 'cat_pt', 'number', '') + field('귀금속 성분 (Pd)', 'cat_pd', 'number', '') + field('귀금속 성분 (Rh)', 'cat_rh', 'number', '') + field('촉매 위치', 'cat_location', 'text', '')) +
      section('배출가스 개발 목표', field('CO 목표 (g/km)', 'target_co', 'number', '') + field('NOx 목표 (g/km)', 'target_nox', 'number', '') + field('THC 목표 (g/km)', 'target_thc', 'number', '') + field('NMHC 목표 (g/km)', 'target_nmhc', 'number', '') + field('PM 목표 (g/km)', 'target_pm', 'number', '')) +
      section('타이어 사양', field('전륜 타이어 규격', 'front_tire', 'text', '') + field('후륜 타이어 규격', 'rear_tire', 'text', '') + field('전륜 타이어 압력 (kPa)', 'front_pressure', 'number', '') + field('후륜 타이어 압력 (kPa)', 'rear_pressure', 'number', ''));
  }

  if (formType === 'emission_noise') {
    return section('소음 저감 장치 – 소음기', field('소음기 종류', 'muffler_type', 'text', '') + field('소음기 재질', 'muffler_material', 'text', '') + field('소음기 외경 (mm)', 'muffler_od', 'number', '') + field('소음기 길이 (mm)', 'muffler_length', 'number', '') + textarea('소음기 구조 설명', 'muffler_desc', '소음기 구조 및 작동 방식 설명')) +
      section('촉매 변환장치', field('촉매 형식', 'cat_type', 'text', '') + field('촉매 용량 (L)', 'cat_volume', 'number', '') + field('셀 밀도 (cpsi)', 'cat_cpsi', 'number', '') + field('귀금속 함량 (g/ft³)', 'cat_pgm', 'number', '')) +
      section('2차 공기 공급 장치', field('2차 공기 공급 여부', 'secondary_air', 'text', '해당/비해당') + field('공급 방식', 'secondary_air_method', 'text', '')) +
      section('배출가스 저감 기술', textarea('주요 저감 기술 설명', 'emission_tech', '엔진 제어, 연료분사, 촉매 등 기술 설명', 4)) +
      section('소음 측정 결과 요약', field('가속소음 측정값 (dB(A))', 'accel_noise_meas', 'number', '') + field('가속소음 기준값 (dB(A))', 'accel_noise_std', 'number', '') + field('배기소음 측정값 (dB(A))', 'exhaust_noise_meas', 'number', '') + field('배기소음 기준값 (dB(A))', 'exhaust_noise_std', 'number', ''));
  }

  if (formType === 'obd_config') {
    return section('OBD 시스템 개요', field('OBD 시스템 제조사', 'obd_maker', 'text', '') + field('ECU 제조사', 'ecu_maker', 'text', '') + field('OBD 적용 단계', 'obd_stage', 'text', 'OBD-II') + textarea('OBD 시스템 개요 설명', 'obd_overview', 'OBD 시스템 전반적인 구성 설명', 3)) +
      section('모니터링 항목', field('크랭크 포지션 센서 (CPS)', 'mon_cps', 'text', '해당/비해당') + field('T-MAP 센서', 'mon_tmap', 'text', '해당/비해당') + field('스로틀 포지션 센서 (TPS)', 'mon_tps', 'text', '해당/비해당') + field('수온 센서 (WTS)', 'mon_wts', 'text', '해당/비해당') + field('O₂ 센서', 'mon_o2', 'text', '해당/비해당') + field('연료 인젝터', 'mon_injector', 'text', '해당/비해당') + field('점화 코일', 'mon_ignition', 'text', '해당/비해당') + field('촉매 (CAT)', 'mon_catalyst', 'text', '해당/비해당') + field('실화 모니터', 'mon_misfire', 'text', '해당/비해당') + field('연료 계통', 'mon_fuel_sys', 'text', '해당/비해당')) +
      section('고장 표시 장치', field('고장 표시 램프 (MIL) 위치', 'mil_location', 'text', '') + textarea('고장코드 (DTC) 처리 방식', 'dtc_handling', 'DTC 발생 조건 및 소거 방법') + field('OBD 커넥터 위치', 'obd_connector', 'text', '')) +
      section('기술 정보', textarea('모니터링 방법 설명', 'mon_method', '각 센서/액추에이터 모니터링 원리') + textarea('고장 판정 기준', 'fault_criteria', '각 항목별 고장 판정 기준값'));
  }

  if (formType === 'emission_test') {
    return section('시험 일반 정보', field('시험기관', 'test_lab', 'text', '') + field('시험일', 'test_date', 'date', '') + field('시험 모드', 'test_mode', 'text', 'WMTC') + field('시험 담당자', 'tester', 'text', '')) +
      section('차량 정보', field('차종명', 'model', 'text', '') + field('연식', 'model_year', 'text', '') + field('차대번호', 'vin', 'text', '') + field('공차중량 (kg)', 'curb_weight', 'number', '') + field('시험 중량 (kg)', 'test_weight', 'number', '') + field('주행거리 (km)', 'mileage', 'number', '')) +
      section('시험 조건', field('실내 온도 (°C)', 'room_temp', 'number', '') + field('대기압 (kPa)', 'atm_pressure', 'number', '') + field('습도 (%)', 'humidity', 'number', '') + field('연료 종류', 'fuel_type', 'text', '무연 휘발유')) +
      section('배출가스 측정 결과 (g/km)', field('HC 측정값', 'hc_result', 'number', '') + field('HC 기준값', 'hc_limit', 'number', '') + field('CO 측정값', 'co_result', 'number', '') + field('CO 기준값', 'co_limit', 'number', '') + field('NOx 측정값', 'nox_result', 'number', '') + field('NOx 기준값', 'nox_limit', 'number', '') + field('NMHC 측정값', 'nmhc_result', 'number', '') + field('NMHC 기준값', 'nmhc_limit', 'number', '') + field('CO₂ (g/km)', 'co2_result', 'number', '') + field('연비 (km/L)', 'fuel_economy', 'number', '')) +
      section('측정 장비', field('가스 분석기 제조사/모델', 'analyzer', 'text', '') + field('섀시 다이나모 제조사/모델', 'dyno', 'text', '') + field('CVS 용량 (m³/min)', 'cvs_cap', 'number', ''));
  }

  if (formType === 'evap_test') {
    return section('시험 일반 정보', field('시험기관', 'test_lab', 'text', '') + field('시험일', 'test_date', 'date', '') + field('시험 담당자', 'tester', 'text', '')) +
      section('차량 및 연료', field('차종명', 'model', 'text', '') + field('차대번호', 'vin', 'text', '') + field('연료탱크 용량 (L)', 'fuel_tank', 'number', '') + field('카니스터 용량 (g)', 'canister_cap', 'number', '')) +
      section('시험 챔버', field('챔버 용량 (m³)', 'chamber_vol', 'number', '') + field('챔버 온도 범위 (°C)', 'chamber_temp_range', 'text', '') + field('측정 장비 (FID)', 'fid_model', 'text', '')) +
      section('시험 결과', field('고온 침지 측정값 (g)', 'hot_soak_result', 'number', '') + field('고온 침지 기준값 (g)', 'hot_soak_limit', 'number', '') + field('주간 증발 측정값 (g)', 'diurnal_result', 'number', '') + field('주간 증발 기준값 (g)', 'diurnal_limit', 'number', '') + field('합산 측정값 (g)', 'total_result', 'number', '') + field('합산 기준값 (g)', 'total_limit', 'number', ''));
  }

  if (formType === 'obd_operation') {
    return section('시험 일반 정보', field('시험기관', 'test_lab', 'text', '') + field('시험일', 'test_date', 'date', '') + field('시험 담당자', 'tester', 'text', '')) +
      section('차량 정보', field('차종명', 'model', 'text', '') + field('차대번호', 'vin', 'text', '') + field('공차중량 (kg)', 'curb_weight', 'number', '') + field('연료 종류', 'fuel_type', 'text', '') + field('변속기 종류', 'trans_type', 'text', '')) +
      section('배출가스 제어 장치', field('촉매 종류', 'catalyst_type', 'text', '') + field('2차 공기 공급', 'secondary_air', 'text', '해당/비해당') + field('EGR 장치', 'egr', 'text', '해당/비해당') + field('ECU 제조사', 'ecu_maker', 'text', '') + field('O₂ 센서 종류', 'o2_type', 'text', '') + field('퍼지 밸브', 'purge_valve', 'text', '')) +
      section('OBD 작동 확인 시험 결과', field('CO 측정값 (g/km)', 'co_meas', 'number', '') + field('CO 고장 허용값 (g/km)', 'co_fault', 'number', '') + field('NOx 측정값 (g/km)', 'nox_meas', 'number', '') + field('NOx 고장 허용값 (g/km)', 'nox_fault', 'number', '') + field('HC 측정값 (g/km)', 'hc_meas', 'number', '') + field('HC 고장 허용값 (g/km)', 'hc_fault', 'number', ''));
  }

  if (formType === 'noise_test') {
    return section('시험 일반 정보', field('시험기관', 'test_lab', 'text', '') + field('시험일', 'test_date', 'date', '') + field('적용 법규', 'regulation', 'text', 'ECE R41') + field('시험 담당자', 'tester', 'text', '')) +
      section('시험 환경', field('시험장 표면', 'surface', 'text', 'ISO 10844 아스팔트') + field('배경소음 (dB(A))', 'bg_noise', 'number', '') + field('온도 (°C)', 'temp', 'number', '') + field('풍속 (m/s)', 'wind', 'number', '')) +
      section('차량 정보', field('차종명', 'model', 'text', '') + field('차대번호', 'vin', 'text', '') + field('공차중량 (kg)', 'curb_weight', 'number', '') + field('최고출력 (kW)', 'max_power', 'number', '') + field('변속기 종류', 'trans_type', 'text', '') + field('타이어 규격', 'tire_spec', 'text', '')) +
      section('가속소음 시험 결과', field('1차 측정값 좌 (dB(A))', 'accel_l1', 'number', '') + field('1차 측정값 우 (dB(A))', 'accel_r1', 'number', '') + field('2차 측정값 좌 (dB(A))', 'accel_l2', 'number', '') + field('2차 측정값 우 (dB(A))', 'accel_r2', 'number', '') + field('평균 측정값 (dB(A))', 'accel_avg', 'number', '') + field('기준값 (dB(A))', 'accel_limit', 'number', '')) +
      section('배기소음 시험 결과', field('배기소음 측정값 (dB(A))', 'exhaust_meas', 'number', '') + field('배기소음 기준값 (dB(A))', 'exhaust_limit', 'number', '') + field('측정 장비 (소음계)', 'noise_meter', 'text', ''));
  }

  if (formType === 'confirmation') {
    return section('확인서 정보', field('신청인 (회사명)', 'company', 'text', '') + field('대표자', 'rep', 'text', '') + field('작성일', 'confirm_date', 'date', '') + field('차종명', 'model', 'text', '') + field('인증 유형', 'cert_type_text', 'text', '')) +
      section('보증 내용 확인', \`
        <div class="md:col-span-2 space-y-3">
          \${[
            ['chk_warranty', '「대기환경보전법」 제48조에 따른 배출가스 보증 의무를 이행하겠습니다.'],
            ['chk_doc', '제출된 서류는 모두 사실임을 확인합니다.'],
            ['chk_translate', '외국어 서류의 경우 번역본을 함께 제출합니다.'],
            ['chk_change', '인증사항 변경 시 즉시 변경인증 또는 변경보고를 하겠습니다.'],
            ['chk_recall', '결함이 발견될 경우 시정조치(리콜) 의무를 이행하겠습니다.'],
          ].map(([key, text]) => \`
            <label class="flex items-start gap-3 cursor-pointer p-3 border border-gray-200 rounded-lg hover:bg-gray-50">
              <input type="checkbox" data-field="\${key}" \${v(key) === 'true' ? 'checked' : ''} onchange="this.value=this.checked" class="mt-0.5 w-4 h-4 accent-blue-600">
              <span class="text-sm text-gray-700">\${text}</span>
            </label>
          \`).join('')}
        </div>
      \`) +
      section('서명', field('대표자 서명 (타이핑)', 'signature', 'text', '성명 입력'));
  }

  return '<div class="form-section text-gray-500">해당 서류 양식을 준비 중입니다.</div>';
}

// ================================================================
// 토스트
// ================================================================
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  setTimeout(() => t.classList.add('hidden'), 3000);
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

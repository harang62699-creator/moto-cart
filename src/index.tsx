import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-workers'

type Bindings = {
  DB: D1Database
}

const app = new Hono<{ Bindings: Bindings }>()

// ── 서버사이드 LL: detail_plan 폼 HTML 템플릿 리터럴에서 사용 (ko 기본값) ──
// const HTML = `...${LL('dp_s1')}...` 평가 시 호출됨
const _SERVER_LL_DICT: Record<string,string> = {
  dp_s1:'1.  인증소개', dp_s2:'2.  기밀요청', dp_s3:'3.  자동차 제원',
  dp_s4:'4.  측정장비', dp_s5:'5.  시험정보', dp_s6:'6.  공차중량 측정',
  dp_s7:'7.  배출가스 시험', dp_s8:'8.  소음 시험', dp_s9:'9.  증발가스 시험',
  dp_s10:'10. 배출가스 보증', dp_s11:'11. 내구성', dp_s12:'12. 교정정보',
  dp_s13:'13. 기타',
  dp_1_1_lbl:'1.1. 인증대상 자동차 개발배경 및 특성',
  dp_1_2_lbl:'1.2. 인증대상 자동차 제원 요약',
  dp_5_1_lbl:'5.1. 배출가스 시험 정보',
  dp_5_2_lbl:'5.2. 내구성 시험 정보',
  dp_5_3_lbl:'5.3. 소음 시험 정보',
  dp_5_4_lbl:'5.4. 증발가스 시험 정보',
  dp_7_1_lbl:'7.1. 배출가스 시험 결과',
  dp_7_2_lbl:'7.2. 배출가스 시험 성적서',
};
function LL(key: string): string {
  return _SERVER_LL_DICT[key] ?? key;
}
// BL은 buildFormHTML 전용 헬퍼 — const HTML 백틱 평가 시 서버사이드에서 호출되므로 LL과 동일하게 정의
function BL(key: string): string {
  return _SERVER_LL_DICT[key] ?? key;
}

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

// 비밀번호 변경
app.post('/api/auth/change-password', authMiddleware, async (c) => {
  const payload = c.get('user') as any
  const { current_password, new_password } = await c.req.json()
  if (!current_password || !new_password) return c.json({ error: '현재 비밀번호와 새 비밀번호를 입력해주세요.' }, 400)
  if (new_password.length < 4) return c.json({ error: '새 비밀번호는 4자 이상이어야 합니다.' }, 400)
  const currentHash = await hashPassword(current_password)
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ? AND password_hash = ?').bind(payload.id, currentHash).first()
  if (!user) return c.json({ error: '현재 비밀번호가 올바르지 않습니다.' }, 401)
  const newHash = await hashPassword(new_password)
  await c.env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(newHash, payload.id).run()
  return c.json({ ok: true, message: '비밀번호가 변경되었습니다.' })
})

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
    const { cert_type, title, importer, cert_year, displacement, family_code, lang, prev_cert_number, change_item, change_reason } = await c.req.json()
    if (!cert_type || !title) return c.json({ error: '신청 제목과 인증 유형은 필수입니다.' }, 400)
    const result = await c.env.DB.prepare(
      'INSERT INTO applications (user_id, cert_type, title, importer, cert_year, displacement, family_code, lang, prev_cert_number, change_item, change_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(payload.id, cert_type, title, importer || '', cert_year || '', displacement || '', family_code || '', lang || 'ko', prev_cert_number || '', change_item || '', change_reason || '').run()
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
  const { title, importer, cert_year, displacement, family_code, lang, status } = await c.req.json()
  await c.env.DB.prepare('UPDATE applications SET title=?, importer=?, cert_year=?, displacement=?, family_code=?, lang=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?')
    .bind(title || appl.title, importer ?? appl.importer, cert_year ?? appl.cert_year, displacement ?? appl.displacement, family_code ?? appl.family_code, lang ?? appl.lang, status || appl.status, id).run()
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

// ================================================================
// 진위여부 QR 검증 API
// ================================================================

const QR_SECRET = 'moto-cert-qr-secret-2025'

async function signQR(payload: Record<string, unknown>): Promise<string> {
  const data = JSON.stringify(payload)
  const enc  = new TextEncoder()
  const key  = await crypto.subtle.importKey(
    'raw', enc.encode(QR_SECRET),
    { name:'HMAC', hash:'SHA-256' }, false, ['sign']
  )
  const sig    = await crypto.subtle.sign('HMAC', key, enc.encode(data))
  const sigB64 = arrayBufferToBase64url(sig)
  return toBase64url(data) + '.' + sigB64
}

async function verifyQR(token: string): Promise<Record<string, unknown> | null> {
  const parts = token.split('.')
  if (parts.length !== 2) return null
  const [dataB64, sigB64] = parts
  try {
    const data = fromBase64url(dataB64)
    const enc  = new TextEncoder()
    const key  = await crypto.subtle.importKey(
      'raw', enc.encode(QR_SECRET),
      { name:'HMAC', hash:'SHA-256' }, false, ['verify']
    )
    const sigBytes = Uint8Array.from(
      atob(sigB64.replace(/-/g,'+').replace(/_/g,'/')),
      ch => ch.charCodeAt(0)
    )
    const ok = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(data))
    if (!ok) return null
    return JSON.parse(data)
  } catch { return null }
}

// QR 토큰 발급 API
app.post('/api/qr/issue', authMiddleware, async (c) => {
  const payload = c.get('user') as any
  const { application_id, form_type, form_title } = await c.req.json()
  const appl = await c.env.DB.prepare('SELECT * FROM applications WHERE id=? AND user_id=?')
    .bind(application_id, payload.id).first() as any
  if (!appl) return c.json({ error: 'Not found' }, 404)
  const issuedAt = new Date().toISOString()
  const token = await signQR({
    app_id    : application_id,
    form_type,
    title     : appl.title,
    company   : payload.company_name || '',
    form_title,
    issued_at : issuedAt,
    issuer    : payload.username
  })
  return c.json({ ok: true, token, issued_at: issuedAt })
})

// QR 검증 공개 API
app.get('/api/verify/:token', async (c) => {
  const token   = c.req.param('token')
  const payload = await verifyQR(token)
  if (!payload) return c.json({ valid: false, reason: '위조되거나 손상된 토큰입니다.' })
  const appl = await c.env.DB.prepare('SELECT * FROM applications WHERE id=?')
    .bind(payload.app_id).first() as any
  if (!appl) return c.json({ valid: false, reason: '삭제된 신청서입니다.' })
  const form = await c.env.DB.prepare('SELECT * FROM form_data WHERE application_id=? AND form_type=?')
    .bind(payload.app_id, payload.form_type).first() as any
  if (!form) return c.json({ valid: false, reason: '폼 데이터를 찾을 수 없습니다.' })
  return c.json({
    valid     : true,
    app_id    : payload.app_id,
    form_type : payload.form_type,
    form_title: payload.form_title,
    title     : payload.title,
    company   : payload.company,
    issued_at : payload.issued_at,
    issuer    : payload.issuer,
    completed : !!form.completed
  })
})

// 검증 웹 페이지 (/verify?t=TOKEN)
app.get('/verify', (c) => {
  const token = c.req.query('t') || ''
  return c.html(`<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>서류 진위 확인 — Motocert</title>
<link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.0/css/all.min.css" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Malgun Gothic','Apple SD Gothic Neo',sans-serif;background:#0a0d14;color:#e8ecf4;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px;gap:16px}
  .card{background:#13172060;backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,.12);border-radius:20px;padding:40px 36px;max-width:520px;width:100%;text-align:center;box-shadow:0 16px 64px rgba(0,0,0,.5)}
  .logo{display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:32px}
  .logo-icon{width:40px;height:40px;background:linear-gradient(135deg,#3b5bdb,#6c5ce7);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18pt;color:#fff}
  .logo-text{font-size:16pt;font-weight:800;color:#e8ecf4;letter-spacing:-.03em}
  .logo-sub{font-size:8pt;color:#6b7280;margin-top:2px;letter-spacing:.04em}
  /* 상태 공통 */
  .status-icon{font-size:52pt;margin-bottom:16px;line-height:1}
  .status-valid .status-icon{color:#10b981}
  .status-invalid .status-icon{color:#ef4444}
  .status-loading .status-icon{color:#6b7280;animation:spin 1.2s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  h2{font-size:18pt;font-weight:800;margin-bottom:8px;letter-spacing:-.02em}
  .status-valid h2{color:#10b981}
  .status-invalid h2{color:#ef4444}
  .reason{font-size:10pt;color:#9ca3af;margin-bottom:4px;line-height:1.6}
  /* 정보 박스 */
  .info-box{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:18px 20px;text-align:left;margin-top:20px}
  .info-row{display:flex;justify-content:space-between;align-items:flex-start;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.06);font-size:9pt;gap:10px}
  .info-row:last-child{border-bottom:none;padding-bottom:0}
  .info-label{color:#9ca3af;min-width:72px;flex-shrink:0;font-size:8.5pt}
  .info-value{color:#e8ecf4;font-weight:700;text-align:right;word-break:break-all}
  /* 뱃지 */
  .badge-ok{display:inline-flex;align-items:center;gap:4px;background:rgba(16,185,129,.15);color:#10b981;border:1px solid rgba(16,185,129,.3);padding:3px 12px;border-radius:20px;font-size:8pt;font-weight:700}
  .badge-ng{display:inline-flex;align-items:center;gap:4px;background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3);padding:3px 12px;border-radius:20px;font-size:8pt;font-weight:700}
  /* 성공 배너 */
  .valid-banner{background:linear-gradient(135deg,rgba(16,185,129,.12),rgba(16,185,129,.04));border:1px solid rgba(16,185,129,.25);border-radius:12px;padding:14px 18px;margin-top:16px;display:flex;align-items:center;gap:12px;text-align:left}
  .valid-banner-icon{font-size:20pt;color:#10b981;flex-shrink:0}
  .valid-banner-text{font-size:9pt;color:#6ee7b7;line-height:1.6}
  /* 하단 */
  .footer{font-size:7.5pt;color:#4b5563;line-height:1.7;text-align:center}
  .footer a{color:#3b5bdb;text-decoration:none}
  /* 검증 코드 표시 */
  .code-box{margin-top:16px;background:rgba(59,91,219,.08);border:1px solid rgba(59,91,219,.2);border-radius:8px;padding:10px 14px;font-size:7pt;color:#7c9ef5;word-break:break-all;line-height:1.6;text-align:left}
  .code-box-label{font-weight:700;color:#3b5bdb;margin-bottom:4px;font-size:7.5pt}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon"><i class="fas fa-certificate"></i></div>
    <div>
      <div class="logo-text">Motocert</div>
      <div class="logo-sub">수입이륜차 인증신청 시스템</div>
    </div>
  </div>
  <div id="status-wrap" class="status-loading">
    <div class="status-icon"><i class="fas fa-circle-notch"></i></div>
    <h2>확인 중...</h2>
    <div class="reason">서류 진위 여부를 검증하고 있습니다.<br>잠시만 기다려 주세요.</div>
  </div>
</div>
<div class="footer">
  본 QR코드는 Motocert 수입이륜차 인증신청 시스템에서 발급되었습니다.<br>
  위조·변조가 의심될 경우 담당 기관에 문의하시기 바랍니다.
</div>
<script>
(async () => {
  const token = ${JSON.stringify(token)};
  const wrap  = document.getElementById('status-wrap');
  if (!token) {
    wrap.className='status-invalid';
    wrap.innerHTML='<div class="status-icon"><i class="fas fa-ban"></i></div><h2>유효하지 않은 주소</h2><div class="reason">QR코드 또는 URL이 올바르지 않습니다.<br>원본 문서의 QR코드를 다시 스캔해 주세요.</div>';
    return;
  }
  try {
    const res  = await fetch('/api/verify/'+encodeURIComponent(token));
    const d    = await res.json();
    if (d.valid) {
      const dt = d.issued_at ? new Date(d.issued_at).toLocaleString('ko-KR') : '-';
      const shortToken = token.length > 40 ? token.substring(0,40)+'...' : token;
      wrap.className='status-valid';
      wrap.innerHTML=\`
        <div class="status-icon"><i class="fas fa-shield-halved"></i></div>
        <h2>진위 확인됨 ✓</h2>
        <div class="reason">Motocert 시스템에서 정식 발급된 문서입니다.</div>
        <div class="valid-banner">
          <div class="valid-banner-icon"><i class="fas fa-check-circle"></i></div>
          <div class="valid-banner-text">본 서류는 위변조되지 않은 <strong>정식 인증 서류</strong>입니다.<br>발급 정보가 시스템 데이터베이스와 일치합니다.</div>
        </div>
        <div class="info-box">
          <div class="info-row"><span class="info-label">서류명</span><span class="info-value">\${d.form_title||'-'}</span></div>
          <div class="info-row"><span class="info-label">신청서명</span><span class="info-value">\${d.title||'-'}</span></div>
          <div class="info-row"><span class="info-label">발급 기관</span><span class="info-value">\${d.company||d.issuer||'-'}</span></div>
          <div class="info-row"><span class="info-label">발급 일시</span><span class="info-value">\${dt}</span></div>
          <div class="info-row"><span class="info-label">작성 상태</span><span class="info-value">\${d.completed?'<span class="badge-ok"><i class="fas fa-check"></i>작성 완료</span>':'<span class="badge-ng"><i class="fas fa-clock"></i>작성 중</span>'}</span></div>
        </div>
        <div class="code-box"><div class="code-box-label"><i class="fas fa-key"></i> 진위확인 코드 (일부)</div>\${shortToken}</div>
      \`;
    } else {
      wrap.className='status-invalid';
      wrap.innerHTML=\`
        <div class="status-icon"><i class="fas fa-triangle-exclamation"></i></div>
        <h2>진위 확인 실패</h2>
        <div class="reason">\${d.reason||'확인할 수 없는 문서입니다.'}<br><br>서류가 위조·변조되었거나 발급 기관이 다를 수 있습니다.</div>
      \`;
    }
  } catch {
    wrap.className='status-invalid';
    wrap.innerHTML='<div class="status-icon"><i class="fas fa-wifi"></i></div><h2>연결 오류</h2><div class="reason">네트워크 오류가 발생했습니다.<br>잠시 후 다시 시도해 주세요.</div>';
  }
})();
</script>
</body>
</html>`)
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
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
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
/* 헤더 제외 페이지 영역 - 전체 너비 차지 + 중앙 정렬 래퍼 역할 */
#page-dashboard.active,
#page-application.active,
#page-form.active {
  display:block;
  width:100%;
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
/* auto-grow textarea: 한 줄로 시작, 내용 증가 시 자동 확장 */
textarea.auto-grow {
  resize:none !important;
  overflow:hidden !important;
  min-height:0 !important;
  line-height:1.5;
  padding-top:4px;
  padding-bottom:4px;
  box-sizing:border-box;
  display:block;
  width:100%;
  white-space:pre-wrap;
  word-break:break-word;
  /* cf-item-inp 스타일 유지 */
  font-family:inherit;
  font-size:inherit;
  color:inherit;
  background:transparent;
}
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
#page-dashboard { max-width:1200px; width:100%; padding:36px 24px; margin:0 auto; }
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
#page-application { max-width:1200px; width:100%; padding:36px 24px; margin:0 auto; }
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
.forms-section-title {
  font-size:10pt; font-weight:800; color:var(--c-accent);
  padding:6px 0 10px; margin-bottom:6px;
  border-bottom:2px solid var(--c-border2);
  letter-spacing:.02em;
}
/* ── 제출 서류 목록 테이블 (gasoline 스타일) ── */
.forms-grid {
  width:100%; border-collapse:collapse;
  display:table;
  margin-bottom:24px;
  border:1px solid var(--c-border2);
  border-radius:var(--r-lg); overflow:hidden;
}
.forms-grid-head {
  display:table-row;
  background:rgba(79,142,247,.10);
}
.forms-grid-head > div {
  display:table-cell;
  font-size:10pt; font-weight:700; color:var(--c-text2);
  padding:10px 14px; border-bottom:1px solid var(--c-border2);
  border-right:1px solid var(--c-border);
}
.forms-grid-head > div:last-child { border-right:none; }
.forms-grid-body { display:table-row-group; }

/* ── 신청서 하단 액션 바 ────────────────────── */
.appl-action-bar {
  display:flex; align-items:center; justify-content:space-between;
  flex-wrap:wrap; gap:12px;
  background:rgba(255,255,255,.03);
  border:1px solid var(--c-border);
  border-radius:var(--r-lg);
  padding:20px 24px;
  margin-top:8px;
}
.appl-action-bar-left { display:flex; align-items:center; gap:10px; }
.appl-action-bar-right { display:flex; align-items:center; gap:10px; }
/* ── form-card : 테이블 행 스타일 ── */
.form-card {
  display:table-row;
  cursor:pointer;
  transition:background var(--transition);
}
.form-card:hover { background:rgba(79,142,247,.05) !important; }
.form-card.done  { background:rgba(0,200,150,.04) !important; }

/* 각 셀 */
.form-card > .fc-cell {
  display:table-cell;
  vertical-align:middle;
  padding:11px 14px;
  border-bottom:1px solid var(--c-border);
  border-right:1px solid var(--c-border);
  font-size:10pt;
}
.form-card > .fc-cell:last-child { border-right:none; }
.form-card:last-child > .fc-cell { border-bottom:none; }

/* 번호 셀 */
.fc-num {
  width:48px; text-align:center;
  font-weight:700; color:var(--c-text3);
  background:rgba(79,142,247,.04);
}
.form-card.done .fc-num { background:rgba(0,200,150,.06); }

/* 아이콘+서류명 셀 */
.fc-main {
  display:table-cell !important;
}
.fc-main-inner {
  display:flex; align-items:center; gap:12px;
}
.form-card-icon {
  width:36px; height:36px; border-radius:8px; flex-shrink:0;
  display:flex; align-items:center; justify-content:center; font-size:15px;
}
.form-card-name { font-size:10pt; font-weight:700; color:var(--c-text); }

/* 상태 셀 */
.fc-status { width:90px; text-align:center; }

/* 열기 버튼 셀 */
.fc-action { width:44px; text-align:center; }
.form-card-chevron { color:var(--c-text3); font-size:10pt; transition:transform var(--transition); }
.form-card:hover .form-card-chevron { transform:translateX(3px); color:var(--c-accent); }

/* ── 서류 폼 페이지 ──────────────────────────── */
#page-form { max-width:860px; width:100%; padding:36px 24px; margin:0 auto; }
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

/* ── 휘발유차 인증신청 주요내용 스타일 ─────── */
.gasoline-sec-title {
  font-size:.88rem; font-weight:800; color:var(--c-accent);
  padding:14px 20px; border-bottom:1px solid var(--c-border2);
  background:rgba(79,142,247,.05);
  display:flex; align-items:center; gap:7px; letter-spacing:.02em;
}
.gasoline-subsec {
  font-size:.82rem; font-weight:700; color:var(--c-text2);
  padding:10px 4px 4px; margin-top:8px;
  border-bottom:1px solid var(--c-border); margin-bottom:10px;
}
.gasoline-check-row {
  display:flex; align-items:center; gap:10px;
  padding:6px 8px; border-radius:var(--r-sm);
  cursor:pointer; transition:background var(--transition);
  font-size:.875rem; color:var(--c-text);
}
.gasoline-check-row:hover { background:rgba(255,255,255,.04); }
.gasoline-check-row input[type="checkbox"] { width:16px; height:16px; flex-shrink:0; accent-color:var(--c-accent); }

/* ── 인증신청 요약서 (구 클래스 유지 - 혹시 다른 곳 참조 방지용 stub) ──── */
/* (구 summary 인쇄 CSS 제거됨) */

/* ── 서류 폼 하단 액션 바 ──────────────────── */
.form-action-bar {
  display:flex; align-items:center; justify-content:space-between;
  flex-wrap:wrap; gap:12px;
  background:rgba(255,255,255,.03);
  border:1px solid var(--c-border);
  border-radius:var(--r-lg);
  padding:18px 24px;
  margin-top:16px;
}
.form-action-bar-left  { display:flex; align-items:center; gap:10px; }
.form-action-bar-right { display:flex; align-items:center; gap:10px; }

/* ── QR 진위확인 블록 ── */
.qr-footer {
  margin-top:16px;
  border:2px solid #3b5bdb;
  border-radius:8px;
  padding:10px 14px;
  display:flex;
  align-items:center;
  gap:14px;
  background:linear-gradient(135deg,#eef2ff 0%,#f7f9fc 100%);
  page-break-inside:avoid;
  position:relative;
}
.qr-footer::before {
  content:'■ 진위여부 확인';
  position:absolute;
  top:-10px; left:12px;
  background:#3b5bdb;
  color:#fff;
  font-size:7pt; font-weight:700;
  padding:1px 8px; border-radius:4px;
  letter-spacing:.04em;
}
.qr-footer-left { flex-shrink:0; display:flex; flex-direction:column; align-items:center; gap:4px; }
.qr-footer-qr { flex-shrink:0; }
.qr-footer-qr canvas, .qr-footer-qr img { display:block; border:1px solid #c8d4ea; border-radius:4px; }
.qr-footer-code-label {
  font-size:6pt; color:#3b5bdb; font-weight:700;
  text-align:center; letter-spacing:.05em;
}
.qr-footer-short-code {
  font-size:7pt; color:#1a2342; font-weight:800;
  text-align:center; letter-spacing:.12em;
  font-family:monospace;
  margin-top:2px;
  background:#eef2ff; border:1px solid #c8d4ea;
  border-radius:3px; padding:1px 4px;
  -webkit-print-color-adjust:exact; print-color-adjust:exact;
}
.qr-footer-info { flex:1; min-width:0; }
.qr-footer-title {
  font-size:8pt; font-weight:800; color:#1a2342;
  margin-bottom:5px; letter-spacing:.02em;
  padding-bottom:4px; border-bottom:1px dashed #c8d4ea;
}
.qr-footer-rows { font-size:7pt; color:#555; line-height:1.9; }
.qr-footer-rows span { color:#1a2342; font-weight:700; }
.qr-footer-url { display:none; }
.qr-footer-url span { display:none; }
.qr-footer-badge {
  display:inline-block; font-size:7pt; font-weight:700;
  padding:1px 8px; border-radius:20px; margin-left:4px;
}
.qr-footer-badge.ok  { background:#d1fae5; color:#065f46; }
.qr-footer-badge.ng  { background:#fee2e2; color:#991b1b; }
.qr-footer-pending { color:#888; font-size:7pt; margin-top:8px; font-style:italic; padding:8px 0; }
.qr-footer-pending i { margin-right:4px; }
@media print {
  /* 로딩/에러 메시지는 인쇄에서 숨김 */
  .qr-footer-pending { display:none !important; }
}
/* 화면에서만 숨기고 인쇄에서만 보이는 요소 */
.no-screen { display:none; }
@media screen {
  .qr-footer { max-width:640px; }
}
@media print {
  #qr-footer-wrap {
    display:block !important;
    visibility:visible !important;
    opacity:1 !important;
  }
  .qr-footer {
    display:flex !important;
    border:2px solid #3b5bdb !important;
    background:linear-gradient(135deg,#eef2ff 0%,#f7f9fc 100%) !important;
    -webkit-print-color-adjust:exact !important; print-color-adjust:exact !important;
    page-break-inside:avoid !important;
    margin-top:10px !important;
    padding:6px 10px !important;
    gap:10px !important;
    visibility:visible !important;
  }
  .qr-footer::before {
    background:#3b5bdb !important;
    color:#fff !important;
    -webkit-print-color-adjust:exact !important; print-color-adjust:exact !important;
  }
  .qr-footer-left {
    display:flex !important; flex-direction:column !important;
    align-items:center !important; flex-shrink:0 !important;
  }
  .qr-footer-info { display:block !important; flex:1 !important; }
  .qr-footer-title { font-size:7pt !important; display:block !important; }
  .qr-footer-rows  { font-size:6.5pt !important; display:block !important; }
  .qr-footer-url   { display:none !important; }
  .qr-footer-short-code {
    font-size:7pt !important; font-weight:800 !important;
    background:#eef2ff !important; border:1px solid #c8d4ea !important;
    -webkit-print-color-adjust:exact !important; print-color-adjust:exact !important;
    display:block !important; visibility:visible !important;
  }
  .qr-print-code-bar { display:none !important; }
}

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
  #page-dashboard, #page-application, #page-form { padding:20px 16px; margin:0 auto; }
  .appl-hero { padding:20px; }
  .fc-main { min-width:0; }
  .form-card-name { font-size:9pt; }
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
  /* auto-grow textarea 인쇄 시 높이 고정 해제 */
  textarea.auto-grow {
    border:1px solid #ccc !important; background:#fff !important; color:#000 !important;
    height:auto !important; overflow:visible !important; resize:none !important;
    white-space:pre-wrap !important; word-break:break-word !important;
    page-break-inside:avoid;
  }
  /* cf-item-inp auto-grow 인쇄 시 */
  textarea.cf-item-inp.auto-grow {
    border:none !important; border-bottom:1px solid #888 !important;
    background:transparent !important; color:#000 !important;
    height:auto !important; overflow:visible !important;
    white-space:pre-wrap !important; word-break:break-word !important;
    font-size:10pt !important;
  }
  /* cf-warranty-subject-inp auto-grow 인쇄 시 */
  textarea.cf-warranty-subject-inp.auto-grow {
    border:none !important; border-bottom:1px solid #888 !important;
    background:transparent !important; color:#000 !important;
    height:auto !important; overflow:visible !important;
    white-space:pre-wrap !important; word-break:break-word !important;
    font-size:10pt !important;
  }
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
      <div id="dash-title" class="dash-title">인증신청 목록</div>
      <div id="dash-subtitle" class="dash-sub"></div>
    </div>
    <button id="btn-new-appl" class="btn btn-primary" onclick="showNewAppModal()">
      <i class="fas fa-plus"></i>새 신청서 작성
    </button>
  </div>

  <!-- 통계 카드 -->
  <div class="stats-grid">
    <div class="stat-card total">
      <div class="stat-icon"><i class="fas fa-layer-group"></i></div>
      <div id="stat-total" class="stat-num total">0</div>
      <div id="stat-total-lbl" class="stat-label">전체 신청서</div>
    </div>
    <div class="stat-card prog">
      <div class="stat-icon"><i class="fas fa-pen-nib"></i></div>
      <div id="stat-inprogress" class="stat-num prog">0</div>
      <div id="stat-prog-lbl" class="stat-label">작성중</div>
    </div>
    <div class="stat-card done">
      <div class="stat-icon"><i class="fas fa-check-circle"></i></div>
      <div id="stat-completed" class="stat-num done">0</div>
      <div id="stat-done-lbl" class="stat-label">완료</div>
    </div>
    <div class="stat-card draft">
      <div class="stat-icon"><i class="fas fa-save"></i></div>
      <div id="stat-draft" class="stat-num draft">0</div>
      <div id="stat-draft-lbl" class="stat-label">임시저장</div>
    </div>
  </div>

  <!-- 목록 -->
  <div id="app-list" style="display:flex;flex-direction:column;gap:12px;"></div>
  <div id="app-empty" class="empty-state" style="display:none;">
    <div class="empty-icon"><i class="fas fa-file-signature"></i></div>
    <div id="empty-title" class="empty-title">아직 신청서가 없습니다</div>
    <div id="empty-desc" class="empty-desc">새 신청서를 작성하여<br>인증 절차를 시작해보세요.</div>
    <button id="btn-first-appl" class="btn btn-primary btn-lg" onclick="showNewAppModal()">
      <i class="fas fa-plus"></i>첫 신청서 작성하기
    </button>
  </div>
</div>

<!-- ═══════════════════════════════════════════════
     PAGE: 신청서 상세
════════════════════════════════════════════════ -->
<div id="page-application" class="page">
  <nav class="breadcrumb no-print">
    <button id="btn-breadcrumb-home-appl" onclick="showDashboard()"><i class="fas fa-home"></i> 목록</button>
    <span class="breadcrumb-sep"><i class="fas fa-chevron-right" style="font-size:10pt;"></i></span>
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
      <!-- 서류 언어 변경 -->
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px;">
        <span style="font-size:8pt;color:var(--c-text3);white-space:nowrap;">서류 언어</span>
        <select id="appl-lang-sel" class="input" style="font-size:8.5pt;padding:2px 6px;height:auto;width:auto;"
          onchange="onApplLangChange(this.value)">
          <option value="ko">🇰🇷 한국어</option>
          <option value="en">🇺🇸 English</option>
          <option value="ja">🇯🇵 日本語</option>
          <option value="zh">🇨🇳 中文</option>
        </select>
      </div>
      <div id="appl-pct-label-el" class="appl-pct-label">전체 진행률</div>
      <div class="appl-pct" id="appl-progress-pct">0%</div>
      <div class="progress-track" style="width:140px;height:6px;margin-top:10px;">
        <div id="appl-progress-bar" class="progress-fill" style="height:6px;background:var(--grad-accent);width:0%;"></div>
      </div>
    </div>
  </div>

  <div id="forms-section-title-el" class="forms-section-title">□ 제출 서류 목록</div>
  <div id="forms-grid" class="forms-grid">
    <!-- 헤더행 -->
    <div class="forms-grid-head">
      <div style="width:48px;text-align:center;">번호</div>
      <div>서류명</div>
      <div style="width:90px;text-align:center;">상태</div>
      <div style="width:44px;text-align:center;"></div>
    </div>
    <div class="forms-grid-body" id="forms-grid-body"></div>
  </div>

  <!-- 하단 액션 바 -->
  <div class="appl-action-bar no-print">
    <div class="appl-action-bar-left">
      <button id="btn-back-list" class="btn btn-ghost" onclick="showDashboard()">
        <i class="fas fa-arrow-left"></i>목록으로
      </button>
    </div>
    <div class="appl-action-bar-right">
      <button id="btn-print" class="btn btn-ghost" onclick="printApplicationSummary()">
        <i class="fas fa-print"></i>인쇄
      </button>
      <button id="btn-save-all" class="btn btn-success" onclick="saveAllForms()">
        <i class="fas fa-save"></i>모두 저장
      </button>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════
     PAGE: 서류 입력 폼
════════════════════════════════════════════════ -->
<div id="page-form" class="page">
  <nav class="breadcrumb no-print">
    <button id="btn-breadcrumb-home-form" onclick="showDashboard()"><i class="fas fa-home"></i> 목록</button>
    <span class="breadcrumb-sep"><i class="fas fa-chevron-right" style="font-size:10pt;"></i></span>
    <button id="form-appl-link"></button>
    <span class="breadcrumb-sep"><i class="fas fa-chevron-right" style="font-size:10pt;"></i></span>
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
      <button class="btn btn-ghost" onclick="printWithQR()">
        <i class="fas fa-print"></i>인쇄
      </button>
      <button id="btn-toc-print" class="btn btn-ghost" onclick="printDetailPlanToc()" style="display:none;">
        <i class="fas fa-list-ol"></i>목차인쇄
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
    <i class="fas fa-check-circle" style="margin-left:auto;font-size:10pt;color:var(--c-success);opacity:0;transition:opacity .2s;" id="complete-check-icon"></i>
  </div>

  <!-- 하단 액션 바 -->
  <div class="form-action-bar no-print">
    <div class="form-action-bar-left">
      <button class="btn btn-ghost" onclick="goBackToApplication()">
        <i class="fas fa-arrow-left"></i>목록
      </button>
    </div>
    <div class="form-action-bar-right">
      <button class="btn btn-ghost" onclick="printWithQR()">
        <i class="fas fa-print"></i>인쇄
      </button>
      <button class="btn btn-success" onclick="saveForm()">
        <i class="fas fa-save"></i>저장
      </button>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════
     MODAL: 새 신청서
════════════════════════════════════════════════ -->
<div id="modal-new-app" class="modal-backdrop hidden no-print">
  <div class="modal" onclick="event.stopPropagation()">
    <div class="modal-header">
      <div style="font-size:10pt;font-weight:800;letter-spacing:-.02em;">
        <i class="fas fa-file-plus" style="color:var(--c-accent);margin-right:8px;"></i>새 인증신청서 작성
      </div>
      <button class="btn btn-ghost btn-icon btn-sm" onclick="closeNewAppModal()"><i class="fas fa-times"></i></button>
    </div>
    <div class="modal-body">
      <div class="field-wrap">
        <label class="label">신청 제목 <span style="color:var(--c-danger);">*</span></label>
        <input id="new-title" class="input" type="text" placeholder="예) 2025년 Honda CB125R 기본인증">
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div class="field-wrap">
          <label class="label">인증 유형 <span style="color:var(--c-danger);">*</span></label>
          <select id="new-cert-type" class="input" onchange="onNewCertTypeChange()">
            <option value="basic">기본인증 — 신규 수입이륜차</option>
            <option value="change">변경인증 — 인증사항 중요 변경</option>
            <option value="report">변경보고 — 경미한 사항 변경</option>
          </select>
        </div>
        <div class="field-wrap">
          <label class="label">서류 언어</label>
          <select id="new-lang" class="input" onchange="onNewLangChange()">
            <option value="ko">🇰🇷 한국어</option>
            <option value="en">🇺🇸 English</option>
            <option value="ja">🇯🇵 日本語</option>
            <option value="zh">🇨🇳 中文</option>
          </select>
        </div>
      </div>
      <div id="new-prev-cert-wrap" class="field-wrap" style="display:none;">
        <label class="label">기존 인증번호 <span style="color:var(--c-danger);">*</span></label>
        <input id="new-prev-cert" class="input" type="text" placeholder="기존 인증번호 입력">
      </div>
      <div style="display:grid;grid-template-columns:2fr 1fr 1fr 2.5fr;gap:12px;">
        <div class="field-wrap">
          <label class="label">수입사</label>
          <input id="new-importer" class="input" type="text" placeholder="Honda Korea">
        </div>
        <div class="field-wrap">
          <label class="label">인증연도</label>
          <input id="new-cert-year" class="input" type="text" placeholder="2025">
        </div>
        <div class="field-wrap">
          <label class="label">배기량</label>
          <input id="new-displacement" class="input" type="text" placeholder="125cc">
        </div>
        <div class="field-wrap">
          <label class="label">동일차종기호 <span style="font-size:.75rem;color:var(--c-text3);font-weight:400;">(17자리)</span></label>
          <input id="new-family-code" class="input" type="text" placeholder="예) ABCDE12345FGHIJ67" maxlength="17">
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
// 이미지 첨부 시스템 (detail_plan 지정 섹션 전용)
// ================================================================
(function() {
  // ── CSS ──────────────────────────────────────────────────────────
  var _css = document.createElement('style');
  _css.textContent = [
    '.img-att-btn{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;',
    'margin-left:5px;background:#2563eb;color:#fff;border:none;border-radius:5px;',
    'font-size:8.5pt;cursor:pointer;vertical-align:middle;flex-shrink:0;}',
    '.img-att-btn:hover{background:#1d4ed8;}',
    '.img-att-btn.has-img{background:#16a34a;}',
    '.img-att-btn.has-img:hover{background:#15803d;}',
    '.img-att-thumbs{display:flex;flex-wrap:wrap;gap:5px;margin-top:4px;}',
    '.img-att-thumbs img{width:52px;height:52px;object-fit:cover;border-radius:4px;',
    'border:1px solid #b0c4de;cursor:pointer;}',
    '#_img_att_ov{display:none;position:fixed;inset:0;z-index:9999;',
    'background:rgba(0,0,0,.55);align-items:center;justify-content:center;}',
    '@media print{.img-att-btn{display:none!important;}',
    '.img-att-thumbs{display:flex!important;}}'
  ].join('');
  document.head.appendChild(_css);

  // ── 모달 ─────────────────────────────────────────────────────────
  var ov = document.createElement('div'); ov.id = '_img_att_ov';
  ov.innerHTML =
    '<div style="background:#fff;border-radius:12px;padding:22px 26px;width:460px;max-width:94vw;' +
    'box-shadow:0 8px 40px rgba(0,0,0,.35);max-height:85vh;overflow-y:auto;">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">' +
        '<span id="_iat_lbl" style="font-size:12pt;font-weight:700;color:#1e3a5f;">' +
          '<i class="fas fa-image" style="color:#2563eb;margin-right:6px;"></i>이미지 첨부' +
        '</span>' +
        '<button id="_iat_x" style="background:none;border:none;font-size:20px;cursor:pointer;color:#666;">&times;</button>' +
      '</div>' +
      '<div id="_iat_drop" style="border:2px dashed #b0c4de;border-radius:8px;padding:20px;' +
      'text-align:center;cursor:pointer;background:#f7faff;margin-bottom:12px;">' +
        '<input type="file" id="_iat_fi" accept="image/*" multiple style="display:none;">' +
        '<i class="fas fa-cloud-upload-alt" style="font-size:22px;color:#7a9cc0;display:block;margin-bottom:6px;"></i>' +
        '<span style="color:#7a9cc0;font-size:9pt;">클릭하거나 이미지를 드래그하세요</span>' +
      '</div>' +
      '<div id="_iat_list" style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px;"></div>' +
      '<div style="display:flex;gap:8px;justify-content:flex-end;">' +
        '<button id="_iat_cancel" style="padding:7px 18px;border:1px solid #ccc;border-radius:6px;' +
        'background:#fff;cursor:pointer;font-size:9pt;">취소</button>' +
        '<button id="_iat_ok" style="padding:7px 18px;background:#2563eb;color:#fff;' +
        'border:none;border-radius:6px;cursor:pointer;font-size:9pt;font-weight:600;">확인</button>' +
      '</div>' +
    '</div>';
  document.body.appendChild(ov);

  // ── 상태 ─────────────────────────────────────────────────────────
  var _curHid = null, _curThumb = null, _curBtn = null, _imgs = [];

  function _renderList() {
    var list = document.getElementById('_iat_list');
    list.innerHTML = '';
    _imgs.forEach(function(src, idx) {
      var wrap = document.createElement('div');
      wrap.style.cssText = 'position:relative;width:88px;height:88px;';
      var img = document.createElement('img');
      img.src = src;
      img.style.cssText = 'width:100%;height:100%;object-fit:cover;border-radius:6px;border:1px solid #ccc;';
      var del = document.createElement('button');
      del.textContent = '\xd7';
      del.style.cssText = 'position:absolute;top:-6px;right:-6px;width:18px;height:18px;' +
        'background:#ef4444;color:#fff;border:none;border-radius:50%;font-size:11px;cursor:pointer;' +
        'display:flex;align-items:center;justify-content:center;line-height:1;';
      del.onclick = function(e) { e.stopPropagation(); _imgs.splice(idx, 1); _renderList(); };
      wrap.appendChild(img); wrap.appendChild(del);
      list.appendChild(wrap);
    });
  }

  function _renderThumbs() {
    if (!_curThumb) return;
    _curThumb.innerHTML = '';
    _imgs.forEach(function(src) {
      var img = document.createElement('img');
      img.src = src; img.title = '클릭하여 크게 보기';
      img.onclick = function() { window.open(src, '_blank'); };
      _curThumb.appendChild(img);
    });
  }

  function _syncState() {
    if (_curHid) _curHid.value = JSON.stringify(_imgs);
    if (_curBtn) {
      _curBtn.classList.toggle('has-img', _imgs.length > 0);
      _curBtn.innerHTML = '<i class="fas fa-paperclip"></i> ' +
        (_imgs.length > 0 ? '사진 ' + _imgs.length + '장' : '사진 첨부');
    }
  }

  function _addFiles(files) {
    Array.from(files).forEach(function(f) {
      if (!f.type.startsWith('image/')) return;
      var fr = new FileReader();
      fr.onload = function(e) { _imgs.push(e.target.result); _renderList(); };
      fr.readAsDataURL(f);
    });
  }

  function _open(hidId, thumbId, btnEl, label) {
    _curHid   = document.getElementById(hidId);
    _curThumb = document.getElementById(thumbId);
    _curBtn   = btnEl;
    try { _imgs = JSON.parse((_curHid && _curHid.value) || '[]'); } catch(e) { _imgs = []; }
    document.getElementById('_iat_lbl').innerHTML =
      '<i class="fas fa-image" style="color:#2563eb;margin-right:6px;"></i>' + (label || '이미지 첨부');
    _renderList();
    ov.style.display = 'flex';
  }

  function _close(apply) {
    if (apply) { _renderThumbs(); _syncState(); }
    ov.style.display = 'none';
  }

  // 이벤트
  document.getElementById('_iat_x').onclick      = function() { _close(false); };
  document.getElementById('_iat_cancel').onclick  = function() { _close(false); };
  document.getElementById('_iat_ok').onclick      = function() { _close(true); };
  ov.addEventListener('click', function(e) { if (e.target === ov) _close(false); });
  var _drop = document.getElementById('_iat_drop');
  var _fi   = document.getElementById('_iat_fi');
  _drop.onclick = function() { _fi.click(); };
  _fi.onchange  = function() { _addFiles(_fi.files); _fi.value = ''; };
  _drop.addEventListener('dragover',  function(e) { e.preventDefault(); _drop.style.borderColor='#2563eb'; });
  _drop.addEventListener('dragleave', function()  { _drop.style.borderColor='#b0c4de'; });
  _drop.addEventListener('drop', function(e) {
    e.preventDefault(); _drop.style.borderColor='#b0c4de';
    _addFiles(e.dataTransfer.files);
  });

  // ── 공개 API ─────────────────────────────────────────────────────
  window._imgAtt = {
    open: _open,
    // 저장된 이미지 복원 (폼 로드 시 호출)
    restore: function(hidId, thumbId) {
      var hid = document.getElementById(hidId);
      var th  = document.getElementById(thumbId);
      if (!hid || !th) return;
      var imgs = [];
      try { imgs = JSON.parse(hid.value || '[]'); } catch(e) {}
      th.innerHTML = '';
      imgs.forEach(function(src) {
        var img = document.createElement('img');
        img.src = src; img.title = '클릭하여 크게 보기';
        img.onclick = function() { window.open(src, '_blank'); };
        th.appendChild(img);
      });
      // 버튼 상태 갱신
      var btn = document.getElementById(hidId + '_btn');
      if (btn) {
        btn.classList.toggle('has-img', imgs.length > 0);
        btn.innerHTML = '<i class="fas fa-paperclip"></i> ' +
          (imgs.length > 0 ? '사진 ' + imgs.length + '장' : '사진 첨부');
      }
    }
  };
})();

// ================================================================
// 상태
// ================================================================
let currentUser = null, currentApplications = [], currentApplication = null;
let currentForms = [], currentFormType = null, currentApplicationId = null;
let currentLang = 'ko'; // 'ko' | 'en' | 'ja' | 'zh'

const FORM_META = [
  { type:'summary',        titleKey:'form_summary',        icon:'fa-file-alt',       color:'#4f8ef7', bg:'rgba(79,142,247,.12)'   },
  { type:'gasoline',       titleKey:'form_gasoline',       icon:'fa-gas-pump',       color:'#f97316', bg:'rgba(249,115,22,.12)'   },
  { type:'detail_plan',    titleKey:'form_detail_plan',    icon:'fa-clipboard-list', color:'#a855f7', bg:'rgba(168,85,247,.12)'   },
  { type:'emission_noise', titleKey:'form_emission_noise', icon:'fa-wind',           color:'#06b6d4', bg:'rgba(6,182,212,.12)'    },
  { type:'obd_config',     titleKey:'form_obd_config',     icon:'fa-microchip',      color:'#6366f1', bg:'rgba(99,102,241,.12)'   },
  { type:'emission_test',  titleKey:'form_emission_test',  icon:'fa-flask',          color:'#22c55e', bg:'rgba(34,197,94,.12)'    },
  { type:'evap_test',      titleKey:'form_evap_test',      icon:'fa-vials',          color:'#eab308', bg:'rgba(234,179,8,.12)'    },
  { type:'obd_operation',  titleKey:'form_obd_operation',  icon:'fa-cogs',           color:'#ef4444', bg:'rgba(239,68,68,.12)'    },
  { type:'noise_test',     titleKey:'form_noise_test',     icon:'fa-volume-up',      color:'#ec4899', bg:'rgba(236,72,153,.12)'   },
  { type:'confirmation',   titleKey:'form_confirmation',   icon:'fa-stamp',          color:'#64748b', bg:'rgba(100,116,139,.12)'  },
];
// ================================================================
// 다국어 사전 (LANG_DICT)
// ================================================================
const LANG_DICT = {
  ko: {
    // 공통 헤더 필드
    importer:'수입사', cert_year:'인증연도', displacement:'배기량', family_code:'동일차종기호',
    appl_div:'구분', appl_no:'인증번호', cert_date:'인증일자', representative:'대표자',
    address:'주소', phone:'전화번호', model_name:'차종명', engine_no:'엔진번호',
    // summary
    summary_title:'인증신청 요약서',
    sv_title:'배출가스 및 소음 인증신청 요약',
    sv_th_div:'구분', sv_th_item:'항 목', sv_th_content:'내 용',
    sv_maker:'제작사(제작국)', sv_vehicle_name:'시험자동차 명칭(형식)', sv_vehicle_name_simple:'자동차 명칭',
    sv_fuel:'사용연료', sv_std:'적용 기준', sv_emission:'배출가스', sv_noise_simple:'소음',
    sv_foreign_std:'외국 기준', sv_foreign_std_note:'(유럽 또는 미국 기준)',
    sv_evap_rep_title:'증발가스 대표차 여부 및', sv_obd_rep_title:'OBD 대표차 여부 및',
    sv_vehicle_name_lbl:'자동차 명칭', sv_type_lbl:'형식', sv_rep_vehicle_lbl:'대표차량',
    sv_warranty:'보증 기간', sv_self_test:'자체시험실시 내역', sv_key_tech:'대표 기술',
    unit_year:'년', fuel_gasoline:'휘발유', fuel_diesel:'경유',
    // gasoline
    gasoline_title:'휘발유차 인증신청 주요내용',
    maker:'제작사', engine_type:'엔진형식', fuel:'연료',
    max_power:'최고출력(ps/rpm)', max_torque:'최대토크(N·m/rpm)',
    transmission:'변속기', drive_type:'구동방식', fuel_tank:'연료탱크용량(L)',
    curb_weight:'공차중량(kg)', wheelbase:'축간거리(mm)',
    // gasoline 섹션 라벨
    g_app_overview:'인증신청 개요', g_app_type:'인증신청 유형',
    g_appl_date:'신청일자', g_maker:'제작사', g_vehicle_form:'차종(형식)',
    g_vehicle_fuel:'연료', g_power_cc:'출력/배기량', g_std_emission:'기준(배출가스)',
    g_cert_no:'인증번호', g_note:'비고',
    g_cert_content:'인증 내용', g_applicable:'해당', g_evap:'증발가스',
    g_warranty:'보증', g_detail:'세부 내역', g_tech:'기술적 특징',
    g_self_result:'자체시험 결과', g_emission_colon:'배출가스:', g_noise_colon:'소음:',
    g_hc:'HC', g_co_full:'CO(g/km)', g_hc_exhaust:'HC 배기(g/km)', g_nox_full:'NOx(g/km)', g_hc_evap:'HC 증발(g/Test)',
    g_accel_noise:'가속주행소음(dB(A))', g_exhaust_noise:'배기소음(dB(A))', g_horn_noise:'경적소음(dB(A))',
    g_allowable_std:'허용기준', g_test_result:'시험결과', g_compliance_rate:'적합여부',
    g_monitor_device:'모니터링 장치', g_fault_cond:'결함 조건', g_wmtc_result:'WMTC 결과',
    g_mil_lamp:'오작동표시등<br>점등여부', g_fault_std:'고장 기준', g_monitor_pass:'감시장치<br>적부판정',
    g_catalyst:'촉매장치', g_catalyst_dpf:'촉매장치(DPF)',
    g_spec_result:'기술 사양 및 시험결과',
    g_blowby:'블로바이 제어', g_obd_std_name:'OBD 기준명', g_monitor_item:'모니터 항목',
    g_tested:'시험여부', g_test_car_name:'시험차 명칭', g_test_facility:'시험 시설',
    g_test_car_basis:'시험차 선정 근거', g_evap_test:'증발가스 시험',
    g_warranty_df:'보증 및 악화계수', g_df_applied:'악화계수 적용',
    g_durability:'내구성 시험', g_ki_test:'KI 시험', g_noise_test:'소음시험',
    // detail_plan
    detail_plan_title:'인증에 필요한 세부 계획 서류',
    vehicle_type:'차종', model_year:'연식', color:'색상',
    test_org:'시험기관', test_date:'시험일자', test_result:'시험결과',
    // emission_noise
    emission_noise_title:'배출가스·소음 저감 서류',
    emission_std:'배출가스 기준', noise_std:'소음 기준',
    catalyst:'촉매장치', muffler:'소음기', air_filter:'공기청정기',
    // emission_noise 세부 라벨
    en_main_title:'배출가스 소음 저감장치 자료',
    en_muffler:'1. 소음기(머플러)',
    en_muffler_comp_title:'1.1 머플러 구성 내역',
    en_muffler_diagram_title:'1.2 머플러 도면',
    en_muffler_spec_title:'1.3 머플러 사양',
    en_1_3_1:'구조 및 소음저감 원리', en_1_3_2:'흐름도', en_1_3_3:'제작사',
    en_1_3_4:'내외부 재질', en_1_3_5:'치수 도면',
    en_cat_spec_title:'1.4 촉매장치 사양',
    en_1_4_1:'촉매 제작사', en_1_4_2:'촉매 재질', en_1_4_3:'촉매 성능 및 치수',
    en_1_4_4:'치수 도면', en_1_4_5:'원리 또는 효과', en_1_4_6:'부착 위치',
    img_hint:'이미지를 드래그하거나 클릭하여 업로드',
    // obd_config
    obd_config_title:'OBD 구성에 관한 서류',
    obd_system:'OBD시스템 유형', ecu_maker:'ECU 제조사', ecu_model:'ECU 모델',
    sensor_o2:'O2 센서', sensor_map:'MAP 센서', sensor_tps:'TPS 센서',
    dtc_code:'고장코드(DTC)', mil:'MIL 경고등', readiness:'준비완료 모니터',
    // obd_config 세부 라벨 (th_*)
    th_div:'구분', th_item:'항목', th_content:'내용', th_fuel:'연료',
    // emission_test
    emission_test_title:'배출가스 시험보고서',
    co:'CO(g/km)', hc:'HC(g/km)', nox:'NOx(g/km)', co2:'CO₂(g/km)',
    test_mode:'시험모드', fuel_consumption:'연료소비율(km/L)',
    // evap_test
    evap_test_title:'증발가스 시험내용 보고서',
    evap_std:'증발가스 기준', canister:'캐니스터 용량', tank_vol:'연료탱크 용량',
    // obd_operation
    obd_operation_title:'OBD 작동 확인시험 보고서',
    fault_insert:'결함 삽입 방법', mil_check:'MIL 점등 확인', dtc_check:'DTC 저장 확인',
    freeze_frame:'Freeze Frame 확인',
    // noise_test
    noise_test_title:'자동차소음 시험내용 보고서',
    nt_main_title:'자동차소음 시험내용 보고서', nt_sec1:'1. 시험관련 규정',
    drive_noise:'주행소음(dB(A))', stationary_noise:'정지소음(dB(A))', horn_noise:'경음기 소음',
    // confirmation
    confirmation_title:'확인서', cf_title:'확인서',
    confirm_content:'확인 내용', confirm_date:'확인일자', confirm_sign:'서명',
    // emission_test 본문
    em_main_title:'배출가스 시험내용 보고서(WMTC 모드)',
    em_test_div:'시험구분', em_test_no:'시험번호', em_driver:'운전자',
    em_operator:'장비작동자', em_inspector:'검사책임자',
    em_dynamo:'다이나모 메타', em_analyzer:'분석 장치', em_cooling_fan:'냉각팬',
    // evap_test 본문
    ev_main_title:'증발가스 시험내용 보고서',
    ev_diurnal_test:'주간증발손실시험', ev_hot_soak:'고온소오크시험',
    // obd_operation 본문
    oo_main_title:'배출가스자기진단장치 작동 확인시험내용 보고서',
    oo_sec_general:'□ 시험 일반 내용', oo_sec_vehicle:'□ 시험자동차 제원', oo_sec_result:'□ 시 험 결 과',
    // placeholder
    ph_importer:'수입사명', ph_cert_year:'예) 2025', ph_displacement:'예) 125cc', ph_family_code:'기호 입력',
    attach_note:'첨부파일 안내',
    attach_hint:'파일을 드래그하거나 클릭하여 업로드',
    cf_maker_confirm:'이 차량이 환경인증 기준에 적합함을 확인합니다.',
    g_std_noise:'기준(소음)',
    g_cert_appl:'인증 신청 유형',
    g_vehicle_evap_rep:'증발가스 대표차 여부',
    g_vehicle:'차종',
    g_std_13g2:'2013년 휘발유 배출가스 기준(2)',
    g_std_13g1:'2013년 휘발유 배출가스 기준(1)',
    g_std_16g:'2016년 휘발유 배출가스 기준',
    g_std_20g:'2020년 휘발유 배출가스 기준',
    g_std_14d:'2014년 경유 배출가스 기준',
    g_obd_g1:'휘발유 OBD 기준 1',
    g_obd_g2:'휘발유 OBD 기준 2',
    g_obd_g3:'휘발유 OBD 기준 3',
    g_obd_g4:'휘발유 EURO6 OBD 기준',
    g_obd_d1:'경유 OBD 기준 1',
    g_obd_d2:'경유 EURO6 OBD 기준',
    g_rep_label:'대표차명',
    g_evap_rep:'증발가스 대표차',
    g_evap_same:'증발가스 동일차종',
    g_evap_col:'증발가스 구분',
    g_warr_10_192:'보증기간 : 10년 / 19만2천km',
    g_warr_10_240:'보증기간 : 10년 / 24만km',
    g_warr_15_240:'보증기간 : 15년 / 24만km',
    g_warr_2_20:'보증기간 : 02년 / 2만km',
    g_warr_2_35:'보증기간 : 02년 / 3.5만km',
    g_warr_d10_160:'보증기간 : 10년 / 16만km',
    g_o2sensor:'O2 센서',
    g_chk_evap_rep:'□ 증발가스 대표차 여부',
    g_chk_blowby:'□ 블로바이 제어장치 부착 여부',
    g_obd2_diag:'OBD2 자기진단 기준',
    g_obd2_suffix:'이륜자동차 기준',
    g_chk_obd_rep:'□ OBD 대표차 여부',
    g_chk_obd_std:'□ OBD 적용기준',
    g_chk_obd_fault:'□ 고장기준 해당 여부',
    g_chk_obd_monitor:'□ 모니터 항목 해당 여부',
    g_chk_facility:'□ 자체시험시설 보유 여부',
    g_chk_em_basis:'□ 배출가스 적용기준',
    g_chk_noise_basis:'□ 소음 적용기준',
    g_chk_obd_basis:'□ OBD 적용기준',
    ev_cert_name:'인증차명',
    ev_test_name:'시험차명',
    ev_test_date:'시험일시',
    ev_same_type:'동일차종',
    ev_test_no:'시험번호',
    ev_vin:'차대번호',
    ev_eng_no:'엔진번호',
    ev_odo:'적산거리',
    ev_chamber_spec:'측정실(밀폐실) 규격',
    ev_height:'높이',
    ev_width:'폭',
    ev_length:'길이',
    ev_vol:'순내부체적',
    ev_temp_method:'측정실 온도 조정방법',
    ev_fuel_heater:'연료가열장치',
    ev_chamber_model:'측정실 모델',
    ev_analyzer:'분석장비',
    ev_hc_fix:'HC 고정 방법',
    ev_model_label:'모델',
    ev_charcoal_trap:'활성탄 채집트랙',
    ev_trap_spec:'용기규격 및 재질',
    ev_trap_aux:'보조채집장치의 규격 및 재질',
    ev_trap_weight_before:'채집용기 무게',
    ev_trap_weight_after:'시험후 무게',
    ev_trap_net_weight:'손무게',
    ev_col_div:'구분',
    ev_initial_phase:'초기단계(밀폐실)',
    ev_final_phase:'최종단계(밀폐실)',
    ev_result:'결과 g',
    ev_temp:'온도 ℃',
    ev_pressure:'압력 mmHg',
    ev_conc:'농도 ppm',
    ev_test_result_label:'시험결과',
    ev_df:'열화계수',
    ev_final_result:'최종결과(g/Test)',
    ev_std_val:'기준(g/Test)',
    ev_test_results:'시험결과표',
    ev_test_div:'시험구분',
    em_cert_name:'인증차 명칭(형식)',
    em_mfg_date:'제작일',
    em_trans_type:'변속기 형식',
    em_curb_weight:'공차중량(kg)',
    em_maker:'제작사',
    em_gvw:'최대적재중량(kg)',
    em_inertia:'관성중량등급(kg)',
    em_tank_loc:'연료탱크용량 및 위치',
    em_road_load:'도로 부하력',
    em_coastdown:'코스트다운 시간',
    em_catalyst_yn:'촉매부착 여부',
    em_eng_no:'엔진번호',
    em_eng_type:'엔진형식',
    em_max_power:'최고출력(ps/rpm)',
    em_total_cc:'총배기량(cc)',
    em_cyl:'실린더 수',
    em_idle:'공회전 속도(rpm)',
    em_cooling:'냉각 방식',
    em_cycle:'연소 사이클',
    em_test_fuel:'시험연료',
    em_col_name:'장치명',
    em_col_type:'형식',
    em_col_model:'모델명',
    em_col_approval:'형식승인번호',
    em_col_location:'설치장소',
    em_col_item:'측정항목',
    em_mass:'배출질량(g/test)',
    em_pressure:'대기압(kPa)',
    em_wet_temp:'습구온도(℃)',
    em_dry_temp:'건구온도(℃)',
    em_rh:'상대습도(%)',
    em_abs_hum:'비교습도 H₂Og/kg Air',
    em_emission_vol:'배출가스량',
    em_drive_dist:'주행거리(km)',
    oo_test_date:'시험일자',
    oo_gen_spec:'일반제원',
    oo_car_name:'자동차 명칭',
    oo_form:'형식',
    oo_car_type:'차종',
    oo_trans_type:'변속기 형식',
    oo_gvw_kg:'최대적재중량(kg)',
    oo_engine:'엔진',
    oo_emission_ctrl:'배출가스 제어장치',
    oo_catalyst_type:'촉매장치 형식',
    oo_secondary_air:'이차공기 공급장치',
    oo_egr:'EGR 장치',
    oo_ecu_type:'ECU 형식',
    oo_o2_type:'O2 센서 형식',
    oo_purge_type:'퍼지 밸브 형식',
    oo_monitor_target:'시험대상 감시장치',
    oo_verdict:'결과판정',
    oo_cvs75:'CVS-75 모드 결과(g/km)',
    oo_fault_std:'오작동 판기준(g/km)',
    oo_device_name:'장치명',
    oo_fault_cond2:'오작동<br>재현조건',
    oo_eng_spec_title:'2. 엔 진 제 원',
    nt_sec3:'3. 시험자동차 제원',
    nt_sec4:'4. 시험조건',
    nt_sec5:'5. 시험장비',
    nt_sec6:'6. 시험결과 (가속주행소음)',
    nt_sec6_1:'6.1. ECE 가속주행소음 측정결과',
    nt_sec6_2:'6.2. KSAISO 362 가속주행소음 측정결과',
    nt_sec7:'7. 배기소음 측정결과',
    nt_sec8:'8. 경적소음 측정결과',
    nt_col_form:'형식',
    nt_col_serial:'기기번호',
    nt_col_cal_date:'검·교정일',
    nt_car_name:'차 명',
    nt_maker_country:'제작사(국)',
    nt_car_type:'차종',
    nt_vin:'차대번호',
    nt_form:'형식',
    nt_eng_no:'엔진번호',
    nt_eng_type:'엔진형식',
    nt_max_power:'최고출력(PS/rpm, kW/rpm)',
    nt_chassis_type:'차대형식',
    nt_max_torque:'최대토크(N·m/rpm)',
    nt_displacement:'배기량(cc)',
    nt_rpm_34:'엔진회전수(Pmax 3/4, rpm)',
    nt_model_year:'차령연식',
    nt_rpm_12:'엔진회전수(Pmax 1/2, rpm)',
    nt_trans_type:'변속기종류 및 단수',
    nt_eng_pos:'엔진 위치',
    nt_gear_ratio:'변속비(또는 기어비)',
    nt_axle_count:'축수',
    nt_decel_ratio:'감속비',
    nt_drive_axle:'구동축수',
    nt_drive_shaft:'구동륜타이어동하중반경(m)',
    nt_axle_ratio:'축비',
    nt_curb_weight:'공차중량(kg)',
    nt_gvw:'총 중량(kg)',
    nt_test_weight:'시험중량(kg)',
    nt_pmr:'중량대 출력비(PMR, kW/t)',
    nt_veh_length:'자동차의 길이(m)',
    nt_kp:'부분출력계수(kp)',
    nt_muffler_info:'소음기형태 및 부착위치·수량',
    nt_tire_pressure:'타이어규격 및 트레이드깊이',
    nt_tire_pres_kpa:'타이어 공기압력(kPa)',
    nt_auto_down:'자동저단변속장치 작동여부',
    nt_horn_type:'경음기형식 및 수량',
    nt_etc:'기타',
    nt_place:'장소',
    nt_weather:'날씨',
    nt_wind_dir:'풍향',
    nt_wind_speed:'풍속',
    nt_humidity:'대기습도',
    nt_atm_pressure:'대기압력',
    nt_air_temp:'대기온도',
    nt_sound_meter:'소음계',
    nt_calibrator:'교정기',
    nt_speedometer:'차속계',
    nt_rpm_meter:'엔진속도측정기',
    nt_weather_eq:'기상관측장비(풍속,온도)',
    nt_track:'기록계',
    nt_test_weight_kg:'시험중량(Tested Vehicle weight, kg)',
    nt_load_kg:'적재중량(Vehicle load, kg)',
    nt_gear_1:'선택기어(Gear selected, i)',
    nt_gear_2:'선택기어(Gear selected, i+1)',
    nt_a_urban:'목표 가속도(a_urban, m/s²)',
    nt_a_wotref:'기준 가속도(a_wot,ref, m/s²)',
    nt_a_wot:'측정 가속도(a_wot,test, m/s²)',
    nt_kp_col:'부분출력계수(kp)',
    nt_k_weight:'가중계수(k)',
    nt_gear_used:'사용변속기어',
    nt_accel_test:'가속주행시험',
    nt_const_test:'정속주행시험',
    nt_v_aa:'초기 속도(V_AA)',
    nt_v_pp:'중간 속도(V_PP)',
    nt_v_bb:'탈출 속도(V_BB)',
    nt_n_bb:'탈출 엔진회전수(N_BB)',
    nt_accel_start:'가속 시작위치',
    nt_accel_val:'가속도(a_wot)',
    nt_trial_1:'1회',
    nt_trial_2:'2회',
    nt_trial_3:'3회',
    nt_trial_4:'4회',
    nt_avg:'평균',
    nt_test_result:'시험결과(dB(A))',
    nt_final_result:'최종결과(dB(A))',
    nt_std_val:'기준값(dB(A))',
    nt_bg_noise_a:'암소음(dB(A))',
    nt_exhaust_noise_val:'배기소음(dB(A))',
    nt_score_a:'성적(dB(A))',
    nt_std_a:'기준치(dB(A))',
    nt_measured:'측정치',
    nt_corrected:'보정치',
    nt_meas_count:'측정회수',
    nt_horn_form:'경음기 형식',
    nt_horn_count:'경음기 수',
    nt_bg_noise_c:'암소음(dB(C))',
    nt_horn_noise_val:'경적소음(dB(C))',
    nt_score_c:'성적(dB(C))',
    nt_std_c:'기준치(dB(C))',
    nt_tester:'시험자',
    nt_verifier:'확인자',
    nt_raw_data_note:'원시데이터 첨부',
    nt_col_item:'항목',
    ph_maker:'제작사명', ph_model_name:'차종명 입력', ph_appl_no:'인증번호 입력',
    g_obd_g5:'이륜자동차 OBD 기준',
    nt_col_content:'내용',

    saving:'저장 중',
    save_all_ok_prefix:'전체 ', save_all_ok_suffix:'개 서류가 저장되었습니다.',
    save_partial_ok:'개 저장 완료', save_partial_fail:'개 실패',
    save_error:'저장 중 오류가 발생했습니다.',
    // 제출서류 목록 다국어
    forms_section_title:'□ 제출 서류 목록',
    appl_pct_label:'전체 진행률',
    form_col_no:'번호', form_col_name:'서류명', form_col_status:'상태',
    form_status_done:'완료', form_status_todo:'미완료',
    btn_back_list:'목록으로', btn_print:'인쇄', btn_save_all:'모두 저장',
    // 서류 타입 이름
    form_summary:'인증신청 요약서',
    form_gasoline:'휘발유차 인증신청 주요내용',
    form_detail_plan:'인증에 필요한 세부 계획 서류',
    form_emission_noise:'배출가스·소음 저감 서류',
    form_obd_config:'배출가스자기진단장치(OBD) 구성에 관한 서류',
    form_emission_test:'배출가스 시험보고서',
    form_evap_test:'증발가스 시험내용 보고서',
    form_obd_operation:'OBD 작동 확인시험 보고서',
    form_noise_test:'자동차소음 시험내용 보고서',
    form_confirmation:'확인서',
    // 대시보드 & 목록 다국어
    cert_basic:'기본인증', cert_change:'변경인증', cert_report:'변경보고',
    status_draft:'임시저장', status_inprogress:'작성중', status_completed:'완료',
    dash_title:'인증신청 목록',
    stat_total_lbl:'전체 신청서', stat_prog_lbl:'작성중', stat_done_lbl:'완료', stat_draft_lbl:'임시저장',
    btn_new_appl:'새 신청서 작성', btn_first_appl:'첫 신청서 작성하기',
    btn_write:'작성', btn_delete:'삭제',
    empty_title:'아직 신청서가 없습니다',
    empty_desc:'새 신청서를 작성하여<br>인증 절차를 시작해보세요.',
    meta_modified:'수정',
    // ── detail_plan 전용 라벨 ──
    dp_h_importer:'수입사', dp_h_certyear:'인증연도', dp_h_disp:'배기량', dp_h_famcode:'동일차종기호',
    dp_doc_tag:'[별지 제4호 서식]',
    dp_doc_title:'인증에 필요한 세부 계획에 관한 서류',
    dp_s1:'1.  인증소개', dp_s2:'2.  기밀 사항', dp_s3:'3.  인증시험 연료',
    dp_s4:'4.  시험설비 및 배출가스·소음 측정장비',
    dp_s5:'5.  시험절차', dp_s6:'6.  정비 및 보증',
    dp_s7:'7.  배출가스 표지판(LABEL)', dp_s8:'8.  배출가스 제어기술',
    dp_s9:'9.  증발가스 및 블로바이가스', dp_s10:'10. 동일차종(원동기)',
    dp_s11:'11. 시험차량', dp_s12:'12. 교정정보 및 사후 확정정보 제출협약', dp_s13:'13. 기타',
    dp_1_1_lbl:'1.1. 인증대상 자동차 개발배경 및 특성',
    dp_1_2_lbl:'1.2. 배출가스, 소음관련 신기술',
    dp_1_3_lbl:'1.3. 개발 목표 (수입차의 경우 외국인증성적 등으로 갈음)',
    dp_1_4_lbl:'1.4. 인증대상자동차 제원',
    dp_2_1_lbl:'2.1. 기밀에 대한 요청',
    dp_3_lbl:'3.1. 인증시험 연료',
    dp_5_1_lbl:'5.1. 배출가스 시험', dp_5_2_lbl:'5.2. 주행거리 축적', dp_5_3_lbl:'5.3. 소음시험',
    dp_6_1_lbl:'6.1. 시험차량의 정비계획(정기 정비/비 정기 정비)',
    dp_6_2_lbl:'6.2. 차량 구입자에 대한 추천 정비', dp_6_3_lbl:'6.3. 보증에 관한 설명',
    dp_7_1_lbl:'7.1. 견본(SAMPLE)', dp_7_2_lbl:'7.2. 부착위치 등',
    dp_8_1_lbl:'8.1.  연료시스템', dp_8_2_lbl:'8.2.  흡·배기장치',
    dp_img_hint:'이미지 클릭 또는 드래그',
    dp_img_hint2:'구성도 이미지 클릭 또는 드래그',
    dp_diagram_attach:'구성도 첨부:',
    dp_toc_num:'번 호', dp_toc_item:'항 목',
    dp_toc_writeno:'작성 번호', dp_toc_order:'순 서', dp_toc_see_below:'아래 목차 참조',
    dp_toc_title:'목 차',
    dp_print_title:'목차 - 인증에 필요한 세부 계획에 관한 서류',
    dp_toc_1:'인증 소개', dp_toc_1_1:'인증대상 자동차 개발배경 및 특성',
    dp_toc_1_2:'배출가스, 소음관련 신기술', dp_toc_1_3:'개발 목표',
    dp_toc_1_4:'인증대상자동차 제원', dp_toc_2:'기밀 사항', dp_toc_2_1:'기밀에 대한 요청',
    dp_toc_3:'인증시험 연료', dp_toc_4:'시험설비 및 배출가스·소음 측정장비',
    dp_toc_5:'시험절차', dp_toc_5_1:'배출가스 시험', dp_toc_5_2:'주행거리 축적',
    dp_toc_5_3:'소음시험', dp_toc_6:'정비 및 보증',
    dp_toc_6_1:'시험차량의 정비계획(정기 정비/비 정기 정비)',
    dp_toc_6_2:'차량 구입자에 대한 추천 정비', dp_toc_6_3:'보증에 관한 설명',
    dp_toc_7:'배출가스 표지판(LABEL)', dp_toc_7_1:'견본(SAMPLE)', dp_toc_7_2:'부착위치 등',
    dp_toc_8:'배출가스 제어기술', dp_toc_8_1:'연료시스템', dp_toc_8_2:'흡·배기장치',
    dp_toc_8_3:'크랭크케이스 제어장치', dp_toc_8_4:'엔진', dp_toc_8_5:'변속기',
    dp_toc_8_6:'촉매 전환 시스템', dp_toc_8_7:'배출가스 재 순환 장치(EGR)',
    dp_toc_8_8:'전자제어 장치', dp_toc_8_9:'기타 배출가스 제어장치',
    dp_toc_8_10:'감지변수 대 제어변수', dp_toc_8_11:'부품목록',
    dp_toc_8_12:'선택적 촉매장치 성능 및 원리 등 설명',
    dp_toc_8_13:'선택적 촉매장치(SCR)용 요소수 용액 성분 분석 결과',
    dp_toc_8_14:'전기자동차 제어장치',
    dp_toc_9:'증발가스 및 블로바이가스', dp_toc_9_1:'증발가스 제어장치 설명',
    dp_toc_9_2:'제어장치 구성도 등', dp_toc_10:'동일차종(원동기)', dp_toc_10_1:'동일차종 설명',
    dp_toc_11:'시험차량', dp_toc_11_1:'시험차량 선정',
    dp_toc_11_2:'내구성 시험차량 선정근거', dp_toc_11_3:'배출가스 시험차량 선정근거',
    dp_toc_11_4:'소음 시험차량 선정 근거',
    dp_toc_12:'교정정보 및 사후 확정정보 제출협약', dp_toc_13:'기타',
  },
  en: {
    importer:'Importer', cert_year:'Cert. Year', displacement:'Displacement', family_code:'Family Code',
    appl_div:'Type', appl_no:'Cert. No.', cert_date:'Cert. Date', representative:'Representative',
    address:'Address', phone:'Phone', model_name:'Model Name', engine_no:'Engine No.',
    summary_title:'Certification Application Summary',
    sv_title:'Emission & Noise Certification Application Summary',
    sv_th_div:'No.', sv_th_item:'Item', sv_th_content:'Content',
    sv_maker:'Manufacturer (Country)', sv_vehicle_name:'Test Vehicle Name (Type)', sv_vehicle_name_simple:'Vehicle Name',
    sv_fuel:'Fuel Type', sv_std:'Applicable Standard', sv_emission:'Emission', sv_noise_simple:'Noise',
    sv_foreign_std:'Foreign Standard', sv_foreign_std_note:'(Europe or USA Standard)',
    sv_evap_rep_title:'Evap. Representative Vehicle &', sv_obd_rep_title:'OBD Representative Vehicle &',
    sv_vehicle_name_lbl:'Vehicle Name', sv_type_lbl:'Type', sv_rep_vehicle_lbl:'Rep. Vehicle',
    sv_warranty:'Warranty Period', sv_self_test:'In-house Test Records', sv_key_tech:'Key Technology',
    unit_year:'yr', fuel_gasoline:'Gasoline', fuel_diesel:'Diesel',
    gasoline_title:'Gasoline Vehicle Certification Key Information',
    maker:'Manufacturer', engine_type:'Engine Type', fuel:'Fuel',
    max_power:'Max Power(ps/rpm)', max_torque:'Max Torque(N·m/rpm)',
    transmission:'Transmission', drive_type:'Drive Type', fuel_tank:'Fuel Tank(L)',
    curb_weight:'Curb Weight(kg)', wheelbase:'Wheelbase(mm)',
    g_app_overview:'Application Overview', g_app_type:'Application Type',
    g_appl_date:'Application Date', g_maker:'Manufacturer', g_vehicle_form:'Vehicle Type(Form)',
    g_vehicle_fuel:'Fuel', g_power_cc:'Power/Displacement', g_std_emission:'Emission Standard',
    g_cert_no:'Cert. No.', g_note:'Remarks',
    g_cert_content:'Certification Content', g_applicable:'Applicable', g_evap:'Evap.',
    g_warranty:'Warranty', g_detail:'Details', g_tech:'Technical Features',
    g_self_result:'Self-Test Results', g_emission_colon:'Emission:', g_noise_colon:'Noise:',
    g_hc:'HC', g_co_full:'CO(g/km)', g_hc_exhaust:'HC Exhaust(g/km)', g_nox_full:'NOx(g/km)', g_hc_evap:'HC Evap.(g/Test)',
    g_accel_noise:'Accel. Noise(dB(A))', g_exhaust_noise:'Exhaust Noise(dB(A))', g_horn_noise:'Horn Noise(dB(A))',
    g_allowable_std:'Allowable Std.', g_test_result:'Test Result', g_compliance_rate:'Compliance',
    g_monitor_device:'Monitor Device', g_fault_cond:'Fault Condition', g_wmtc_result:'WMTC Result',
    g_mil_lamp:'MIL Lamp<br>(On/Off)', g_fault_std:'Fault Standard', g_monitor_pass:'Device<br>Compliance',
    g_catalyst:'Catalyst', g_catalyst_dpf:'Catalyst(DPF)',
    g_spec_result:'Technical Spec. & Test Results',
    g_blowby:'Blow-by Control', g_obd_std_name:'OBD Standard Name', g_monitor_item:'Monitor Item',
    g_tested:'Tested', g_test_car_name:'Test Car Name', g_test_facility:'Test Facility',
    g_test_car_basis:'Test Car Selection Basis', g_evap_test:'Evap. Test',
    g_warranty_df:'Warranty & Deterioration Factor', g_df_applied:'DF Applied',
    g_durability:'Durability Test', g_ki_test:'KI Test', g_noise_test:'Noise Test',
    detail_plan_title:'Detailed Plan Documents',
    vehicle_type:'Vehicle Type', model_year:'Model Year', color:'Color',
    test_org:'Test Organization', test_date:'Test Date', test_result:'Test Result',
    emission_noise_title:'Emission & Noise Reduction Documents',
    emission_std:'Emission Standard', noise_std:'Noise Standard',
    catalyst:'Catalyst', muffler:'Muffler', air_filter:'Air Filter',
    en_main_title:'Emission & Noise Reduction Device Data',
    en_muffler:'1. Muffler',
    en_muffler_comp_title:'1.1 Muffler Composition',
    en_muffler_diagram_title:'1.2 Muffler Diagram',
    en_muffler_spec_title:'1.3 Muffler Specifications',
    en_1_3_1:'Structure & Noise Reduction Principle', en_1_3_2:'Flow Diagram', en_1_3_3:'Manufacturer',
    en_1_3_4:'Inner/Outer Material', en_1_3_5:'Dimensional Drawing',
    en_cat_spec_title:'1.4 Catalyst Specifications',
    en_1_4_1:'Catalyst Manufacturer', en_1_4_2:'Catalyst Material', en_1_4_3:'Catalyst Performance & Dimensions',
    en_1_4_4:'Dimensional Drawing', en_1_4_5:'Principle or Effect', en_1_4_6:'Mounting Position',
    img_hint:'Drag or click to upload image',
    obd_config_title:'OBD Configuration Documents',
    obd_system:'OBD System Type', ecu_maker:'ECU Manufacturer', ecu_model:'ECU Model',
    sensor_o2:'O2 Sensor', sensor_map:'MAP Sensor', sensor_tps:'TPS Sensor',
    dtc_code:'DTC Code', mil:'MIL Warning Light', readiness:'Readiness Monitor',
    th_div:'No.', th_item:'Item', th_content:'Content', th_fuel:'Fuel',
    emission_test_title:'Emission Test Report',
    co:'CO(g/km)', hc:'HC(g/km)', nox:'NOx(g/km)', co2:'CO₂(g/km)',
    test_mode:'Test Mode', fuel_consumption:'Fuel Economy(km/L)',
    evap_test_title:'Evaporative Emission Test Report',
    evap_std:'Evap. Standard', canister:'Canister Capacity', tank_vol:'Fuel Tank Volume',
    obd_operation_title:'OBD Operation Verification Test Report',
    fault_insert:'Fault Insertion Method', mil_check:'MIL Activation Check', dtc_check:'DTC Storage Check',
    freeze_frame:'Freeze Frame Check',
    noise_test_title:'Vehicle Noise Test Report',
    nt_main_title:'Vehicle Noise Test Report', nt_sec1:'1. Test Regulations',
    drive_noise:'Drive-by Noise(dB(A))', stationary_noise:'Stationary Noise(dB(A))', horn_noise:'Horn Noise',
    confirmation_title:'Confirmation Letter', cf_title:'Confirmation Letter',
    confirm_content:'Confirmation Content', confirm_date:'Date', confirm_sign:'Signature',
    // emission_test
    em_main_title:'Emission Test Report (WMTC Mode)',
    em_test_div:'Test Type', em_test_no:'Test No.', em_driver:'Driver',
    em_operator:'Equipment Operator', em_inspector:'Inspection Manager',
    em_dynamo:'Dynamometer', em_analyzer:'Analyzer', em_cooling_fan:'Cooling Fan',
    // evap_test
    ev_main_title:'Evaporative Emission Test Report',
    ev_diurnal_test:'Diurnal Emission Test', ev_hot_soak:'Hot Soak Test',
    // obd_operation
    oo_main_title:'OBD Operation Verification Test Report',
    oo_sec_general:'□ General Test Information', oo_sec_vehicle:'□ Test Vehicle Specifications', oo_sec_result:'□ Test Results',
    ph_importer:'Importer name', ph_cert_year:'e.g. 2025', ph_displacement:'e.g. 125cc', ph_family_code:'Family code',
    attach_note:'Attachment Notes',
    attach_hint:'Drag or click to upload',
    cf_maker_confirm:'We confirm that this vehicle meets environmental certification standards.',
    g_std_noise:'Noise Standard',
    g_cert_appl:'Cert. Application Type',
    g_vehicle_evap_rep:'Evap. Rep. Vehicle',
    g_vehicle:'Vehicle Type',
    g_std_13g2:'2013 Gasoline Emission Std.(2)',
    g_std_13g1:'2013 Gasoline Emission Std.(1)',
    g_std_16g:'2016 Gasoline Emission Std.',
    g_std_20g:'2020 Gasoline Emission Std.',
    g_std_14d:'2014 Diesel Emission Std.',
    g_obd_g1:'Gasoline OBD Std.1',
    g_obd_g2:'Gasoline OBD Std.2',
    g_obd_g3:'Gasoline OBD Std.3',
    g_obd_g4:'Gasoline EURO6 OBD Std.',
    g_obd_d1:'Diesel OBD Std.1',
    g_obd_d2:'Diesel EURO6 OBD Std.',
    g_rep_label:'Rep. Vehicle Name',
    g_evap_rep:'Evap. Rep. Vehicle',
    g_evap_same:'Evap. Same Type',
    g_evap_col:'Evap. Category',
    g_warr_10_192:'Warranty: 10yr / 192,000km',
    g_warr_10_240:'Warranty: 10yr / 240,000km',
    g_warr_15_240:'Warranty: 15yr / 240,000km',
    g_warr_2_20:'Warranty: 2yr / 20,000km',
    g_warr_2_35:'Warranty: 2yr / 35,000km',
    g_warr_d10_160:'Warranty: 10yr / 160,000km',
    g_o2sensor:'O2 Sensor',
    g_chk_evap_rep:'□ Evap. Rep. Vehicle',
    g_chk_blowby:'□ Blow-by Control Device',
    g_obd2_diag:'OBD2 Self-diagnosis Std.',
    g_obd2_suffix:'Two-Wheeler Std.',
    g_chk_obd_rep:'□ OBD Rep. Vehicle',
    g_chk_obd_std:'□ OBD Applicable Std.',
    g_chk_obd_fault:'□ Fault Standard Applicable',
    g_chk_obd_monitor:'□ Monitor Item Applicable',
    g_chk_facility:'□ In-house Test Facility',
    g_chk_em_basis:'□ Emission Applicable Std.',
    g_chk_noise_basis:'□ Noise Applicable Std.',
    g_chk_obd_basis:'□ OBD Applicable Std.',
    ev_cert_name:'Certified Vehicle',
    ev_test_name:'Test Vehicle',
    ev_test_date:'Test Date/Time',
    ev_same_type:'Same Type',
    ev_test_no:'Test No.',
    ev_vin:'VIN',
    ev_eng_no:'Engine No.',
    ev_odo:'Odometer Reading',
    ev_chamber_spec:'Test Chamber(Sealed) Spec.',
    ev_height:'Height',
    ev_width:'Width',
    ev_length:'Length',
    ev_vol:'Net Internal Volume',
    ev_temp_method:'Chamber Temp. Control Method',
    ev_fuel_heater:'Fuel Heating Device',
    ev_chamber_model:'Chamber Model',
    ev_analyzer:'Analysis Equipment',
    ev_hc_fix:'HC Fixing Method',
    ev_model_label:'Model',
    ev_charcoal_trap:'Charcoal Trap',
    ev_trap_spec:'Container Spec. & Material',
    ev_trap_aux:'Aux. Device Spec. & Material',
    ev_trap_weight_before:'Container Weight',
    ev_trap_weight_after:'Post-Test Weight',
    ev_trap_net_weight:'Net Weight',
    ev_col_div:'Category',
    ev_initial_phase:'Initial Phase(Chamber)',
    ev_final_phase:'Final Phase(Chamber)',
    ev_result:'Result g',
    ev_temp:'Temp. ℃',
    ev_pressure:'Pressure mmHg',
    ev_conc:'Conc. ppm',
    ev_test_result_label:'Test Result',
    ev_df:'Deterioration Factor',
    ev_final_result:'Final Result(g/Test)',
    ev_std_val:'Standard(g/Test)',
    ev_test_results:'Test Results Table',
    ev_test_div:'Test Type',
    em_cert_name:'Certified Vehicle Name(Type)',
    em_mfg_date:'Manufacture Date',
    em_trans_type:'Transmission Type',
    em_curb_weight:'Curb Weight(kg)',
    em_maker:'Manufacturer',
    em_gvw:'GVW(kg)',
    em_inertia:'Inertia Weight Class(kg)',
    em_tank_loc:'Fuel Tank Vol. & Location',
    em_road_load:'Road Load Force',
    em_coastdown:'Coastdown Time',
    em_catalyst_yn:'Catalyst Installed',
    em_eng_no:'Engine No.',
    em_eng_type:'Engine Type',
    em_max_power:'Max Power(ps/rpm)',
    em_total_cc:'Total Displacement(cc)',
    em_cyl:'No. of Cylinders',
    em_idle:'Idle Speed(rpm)',
    em_cooling:'Cooling Method',
    em_cycle:'Combustion Cycle',
    em_test_fuel:'Test Fuel',
    em_col_name:'Device Name',
    em_col_type:'Type',
    em_col_model:'Model Name',
    em_col_approval:'Type Approval No.',
    em_col_location:'Installation Location',
    em_col_item:'Measurement Item',
    em_mass:'Emission Mass(g/test)',
    em_pressure:'Atm. Pressure(kPa)',
    em_wet_temp:'Wet Bulb Temp.(℃)',
    em_dry_temp:'Dry Bulb Temp.(℃)',
    em_rh:'Relative Humidity(%)',
    em_abs_hum:'Specific Humidity H₂Og/kg Air',
    em_emission_vol:'Emission Volume',
    em_drive_dist:'Drive Distance(km)',
    oo_test_date:'Test Date',
    oo_gen_spec:'General Specs.',
    oo_car_name:'Vehicle Name',
    oo_form:'Type',
    oo_car_type:'Vehicle Type',
    oo_trans_type:'Transmission Type',
    oo_gvw_kg:'GVW(kg)',
    oo_engine:'Engine',
    oo_emission_ctrl:'Emission Control Device',
    oo_catalyst_type:'Catalyst Type',
    oo_secondary_air:'Secondary Air Supply',
    oo_egr:'EGR Device',
    oo_ecu_type:'ECU Type',
    oo_o2_type:'O2 Sensor Type',
    oo_purge_type:'Purge Valve Type',
    oo_monitor_target:'Test Target Monitor',
    oo_verdict:'Verdict',
    oo_cvs75:'CVS-75 Mode Result(g/km)',
    oo_fault_std:'Malfunction Criterion(g/km)',
    oo_device_name:'Device Name',
    oo_fault_cond2:'Malfunction<br>Condition',
    oo_eng_spec_title:'2. Engine Specifications',
    nt_sec3:'3. Vehicle Specifications',
    nt_sec4:'4. Test Conditions',
    nt_sec5:'5. Test Equipment',
    nt_sec6:'6. Test Results (Accel. Noise)',
    nt_sec6_1:'6.1. ECE Accel. Noise Results',
    nt_sec6_2:'6.2. KSAISO 362 Accel. Noise Results',
    nt_sec7:'7. Exhaust Noise Results',
    nt_sec8:'8. Horn Noise Results',
    nt_col_form:'Type',
    nt_col_serial:'Device No.',
    nt_col_cal_date:'Insp./Cal. Date',
    nt_car_name:'Vehicle Name',
    nt_maker_country:'Manufacturer(Country)',
    nt_car_type:'Vehicle Type',
    nt_vin:'VIN',
    nt_form:'Type',
    nt_eng_no:'Engine No.',
    nt_eng_type:'Engine Type',
    nt_max_power:'Max Power(PS/rpm, kW/rpm)',
    nt_chassis_type:'Body Type',
    nt_max_torque:'Max Torque(N·m/rpm)',
    nt_displacement:'Displacement(cc)',
    nt_rpm_34:'Engine Speed(Pmax 3/4, rpm)',
    nt_model_year:'Vehicle Age/Year',
    nt_rpm_12:'Engine Speed(Pmax 1/2, rpm)',
    nt_trans_type:'Trans. Type & Stages',
    nt_eng_pos:'Engine Position',
    nt_gear_ratio:'Gear Ratio (or Trans. Ratio)',
    nt_axle_count:'No. of Axles',
    nt_decel_ratio:'Decel Ratio',
    nt_drive_axle:'No. of Drive Axles',
    nt_drive_shaft:'Dynamic Tire Radius(m)',
    nt_axle_ratio:'Axle Ratio',
    nt_curb_weight:'Curb Weight(kg)',
    nt_gvw:'Gross Weight(kg)',
    nt_test_weight:'Test Weight(kg)',
    nt_pmr:'PMR(kW/t)',
    nt_veh_length:'Vehicle Length(m)',
    nt_kp:'Partial Power Factor(kp)',
    nt_muffler_info:'Muffler Type, Position & Qty',
    nt_tire_pressure:'Tire Spec & Tread Depth',
    nt_tire_pres_kpa:'Tire Pressure(kPa)',
    nt_auto_down:'Auto-Downshift Operation',
    nt_horn_type:'Horn Type & Qty',
    nt_etc:'Other',
    nt_place:'Location',
    nt_weather:'Weather',
    nt_wind_dir:'Wind Direction',
    nt_wind_speed:'Wind Speed',
    nt_humidity:'Atm. Humidity',
    nt_atm_pressure:'Atm. Pressure',
    nt_air_temp:'Atm. Temperature',
    nt_sound_meter:'Sound Level Meter',
    nt_calibrator:'Calibrator',
    nt_speedometer:'Vehicle Speed Meter',
    nt_rpm_meter:'Engine Speed Meter',
    nt_weather_eq:'Meteorological Equip.(Wind/Temp)',
    nt_track:'Data Recorder',
    nt_test_weight_kg:'Test Weight(Tested Vehicle weight, kg)',
    nt_load_kg:'Vehicle Load(kg)',
    nt_gear_1:'Gear selected(i)',
    nt_gear_2:'Gear selected(i+1)',
    nt_a_urban:'Target Accel.(a_urban, m/s²)',
    nt_a_wotref:'Reference Accel.(a_wot,ref, m/s²)',
    nt_a_wot:'Measured Accel.(a_wot,test, m/s²)',
    nt_kp_col:'부분출력계수(kp)',
    nt_k_weight:'Weighting Factor(k)',
    nt_gear_used:'Gear Used',
    nt_accel_test:'Acceleration Test',
    nt_const_test:'Constant Speed Test',
    nt_v_aa:'Initial Speed(V_AA)',
    nt_v_pp:'Mid Speed(V_PP)',
    nt_v_bb:'Exit Speed(V_BB)',
    nt_n_bb:'Exit Engine RPM(N_BB)',
    nt_accel_start:'Accel. Start Position',
    nt_accel_val:'Acceleration(a_wot)',
    nt_trial_1:'1st',
    nt_trial_2:'2nd',
    nt_trial_3:'3rd',
    nt_trial_4:'4th',
    nt_avg:'Average',
    nt_test_result:'Test Result(dB(A))',
    nt_final_result:'Final Result(dB(A))',
    nt_std_val:'Standard Value(dB(A))',
    nt_bg_noise_a:'Background Noise(dB(A))',
    nt_exhaust_noise_val:'Exhaust Noise(dB(A))',
    nt_score_a:'Result(dB(A))',
    nt_std_a:'Standard(dB(A))',
    nt_measured:'Measured',
    nt_corrected:'Corrected',
    nt_meas_count:'Measurement No.',
    nt_horn_form:'Horn Type',
    nt_horn_count:'Horn Count',
    nt_bg_noise_c:'Background Noise(dB(C))',
    nt_horn_noise_val:'Horn Noise(dB(C))',
    nt_score_c:'Result(dB(C))',
    nt_std_c:'Standard(dB(C))',
    nt_tester:'Tester',
    nt_verifier:'Verifier',
    nt_raw_data_note:'Raw Data Attached',
    nt_col_item:'Item',
    ph_maker:'Manufacturer', ph_model_name:'Model name', ph_appl_no:'Cert. number',
    g_obd_g5:'Motorcycle OBD Std',
    nt_col_content:'Content',

    saving:'Saving',
    save_all_ok_prefix:'All ', save_all_ok_suffix:' documents saved.',
    save_partial_ok:' saved', save_partial_fail:' failed',
    save_error:'An error occurred while saving.',
    // 제출서류 목록 다국어
    forms_section_title:'□ Document Checklist',
    appl_pct_label:'Overall Progress',
    form_col_no:'No.', form_col_name:'Document', form_col_status:'Status',
    form_status_done:'Done', form_status_todo:'Pending',
    btn_back_list:'Back to List', btn_print:'Print', btn_save_all:'Save All',
    // 서류 타입 이름
    form_summary:'Certification Application Summary',
    form_gasoline:'Gasoline Vehicle Certification Details',
    form_detail_plan:'Detailed Plan for Certification',
    form_emission_noise:'Emission & Noise Reduction Documents',
    form_obd_config:'OBD System Configuration Documents',
    form_emission_test:'Emission Test Report',
    form_evap_test:'Evaporative Emission Test Report',
    form_obd_operation:'OBD Operation Verification Report',
    form_noise_test:'Vehicle Noise Test Report',
    form_confirmation:'Confirmation Letter',
    // 대시보드 & 목록 다국어
    cert_basic:'Basic', cert_change:'Change', cert_report:'Report',
    status_draft:'Draft', status_inprogress:'In Progress', status_completed:'Completed',
    dash_title:'Application List',
    stat_total_lbl:'Total', stat_prog_lbl:'In Progress', stat_done_lbl:'Completed', stat_draft_lbl:'Draft',
    btn_new_appl:'New Application', btn_first_appl:'Create First Application',
    btn_write:'Edit', btn_delete:'Delete',
    empty_title:'No applications yet',
    empty_desc:'Create a new application to<br>start the certification process.',
    meta_modified:'Modified',
    // ── detail_plan labels ──
    dp_h_importer:'Importer', dp_h_certyear:'Cert. Year', dp_h_disp:'Displacement', dp_h_famcode:'Family Code',
    dp_doc_tag:'[Annex Form No.4]',
    dp_doc_title:'Detailed Plan Documents for Certification',
    dp_s1:'1.  Certification Introduction', dp_s2:'2.  Confidential Matters', dp_s3:'3.  Certification Test Fuel',
    dp_s4:'4.  Test Facilities & Emission/Noise Equipment',
    dp_s5:'5.  Test Procedures', dp_s6:'6.  Maintenance & Warranty',
    dp_s7:'7.  Emission Label', dp_s8:'8.  Emission Control Technology',
    dp_s9:'9.  Evaporative & Blow-by Gas', dp_s10:'10. Same Vehicle Type (Engine)',
    dp_s11:'11. Test Vehicles', dp_s12:'12. Calibration & Post-confirmation Agreement', dp_s13:'13. Others',
    dp_1_1_lbl:'1.1. Development Background & Features of Certified Vehicle',
    dp_1_2_lbl:'1.2. New Emission/Noise Technology',
    dp_1_3_lbl:'1.3. Development Goals (For imports: foreign cert. results acceptable)',
    dp_1_4_lbl:'1.4. Vehicle Specifications',
    dp_2_1_lbl:'2.1. Request for Confidentiality',
    dp_3_lbl:'3.1. Certification Test Fuel',
    dp_5_1_lbl:'5.1. Emission Test', dp_5_2_lbl:'5.2. Mileage Accumulation', dp_5_3_lbl:'5.3. Noise Test',
    dp_6_1_lbl:'6.1. Test Vehicle Maintenance Plan',
    dp_6_2_lbl:'6.2. Recommended Maintenance for Buyers', dp_6_3_lbl:'6.3. Warranty Description',
    dp_7_1_lbl:'7.1. Sample', dp_7_2_lbl:'7.2. Label Location',
    dp_8_1_lbl:'8.1.  Fuel System', dp_8_2_lbl:'8.2.  Intake/Exhaust System',
    dp_img_hint:'Click or drag image',
    dp_img_hint2:'Diagram image: click or drag',
    dp_diagram_attach:'Attach Diagram:',
    dp_toc_num:'No.', dp_toc_item:'Item',
    dp_toc_writeno:'Doc. No.', dp_toc_order:'Order', dp_toc_see_below:'See table of contents below',
    dp_toc_title:'Table of Contents',
    dp_print_title:'TOC - Detailed Plan Documents for Certification',
    dp_toc_1:'Certification Introduction', dp_toc_1_1:'Development Background & Features',
    dp_toc_1_2:'New Emission/Noise Technology', dp_toc_1_3:'Development Goals',
    dp_toc_1_4:'Vehicle Specifications', dp_toc_2:'Confidential Matters', dp_toc_2_1:'Request for Confidentiality',
    dp_toc_3:'Certification Test Fuel', dp_toc_4:'Test Facilities & Emission/Noise Equipment',
    dp_toc_5:'Test Procedures', dp_toc_5_1:'Emission Test', dp_toc_5_2:'Mileage Accumulation',
    dp_toc_5_3:'Noise Test', dp_toc_6:'Maintenance & Warranty',
    dp_toc_6_1:'Test Vehicle Maintenance Plan',
    dp_toc_6_2:'Recommended Maintenance for Buyers', dp_toc_6_3:'Warranty Description',
    dp_toc_7:'Emission Label', dp_toc_7_1:'Sample', dp_toc_7_2:'Label Location',
    dp_toc_8:'Emission Control Technology', dp_toc_8_1:'Fuel System', dp_toc_8_2:'Intake/Exhaust System',
    dp_toc_8_3:'Crankcase Control', dp_toc_8_4:'Engine', dp_toc_8_5:'Transmission',
    dp_toc_8_6:'Catalytic Conversion System', dp_toc_8_7:'EGR System',
    dp_toc_8_8:'Electronic Control', dp_toc_8_9:'Other Emission Control Devices',
    dp_toc_8_10:'Sensing vs. Control Variables', dp_toc_8_11:'Parts List',
    dp_toc_8_12:'SCR Performance & Principles',
    dp_toc_8_13:'SCR AdBlue Solution Analysis Results',
    dp_toc_8_14:'EV Control System',
    dp_toc_9:'Evaporative & Blow-by Gas', dp_toc_9_1:'Evaporative Control Description',
    dp_toc_9_2:'Control System Diagram', dp_toc_10:'Same Vehicle Type (Engine)', dp_toc_10_1:'Same Type Description',
    dp_toc_11:'Test Vehicles', dp_toc_11_1:'Test Vehicle Selection',
    dp_toc_11_2:'Durability Test Vehicle Selection Basis', dp_toc_11_3:'Emission Test Vehicle Selection Basis',
    dp_toc_11_4:'Noise Test Vehicle Selection Basis',
    dp_toc_12:'Calibration & Post-confirmation Agreement', dp_toc_13:'Others',
  },
  ja: {
    importer:'輸入会社', cert_year:'認証年度', displacement:'排気量', family_code:'同一車種記号',
    appl_div:'区分', appl_no:'認証番号', cert_date:'認証日', representative:'代表者',
    address:'住所', phone:'電話番号', model_name:'車種名', engine_no:'エンジン番号',
    summary_title:'認証申請概要書',
    sv_title:'排出ガス及び騒音 認証申請概要',
    sv_th_div:'区分', sv_th_item:'項目', sv_th_content:'内容',
    sv_maker:'製造社(製造国)', sv_vehicle_name:'試験自動車名称(形式)', sv_vehicle_name_simple:'自動車名称',
    sv_fuel:'使用燃料', sv_std:'適用基準', sv_emission:'排出ガス', sv_noise_simple:'騒音',
    sv_foreign_std:'外国基準', sv_foreign_std_note:'(欧州または米国基準)',
    sv_evap_rep_title:'蒸発ガス代表車有無及び', sv_obd_rep_title:'OBD代表車有無及び',
    sv_vehicle_name_lbl:'自動車名称', sv_type_lbl:'形式', sv_rep_vehicle_lbl:'代表車両',
    sv_warranty:'保証期間', sv_self_test:'自社試験実施内訳', sv_key_tech:'代表技術',
    unit_year:'年', fuel_gasoline:'ガソリン', fuel_diesel:'軽油',
    gasoline_title:'ガソリン車認証申請主要内容',
    maker:'製造社', engine_type:'エンジン形式', fuel:'燃料',
    max_power:'最高出力(ps/rpm)', max_torque:'最大トルク(N·m/rpm)',
    transmission:'変速機', drive_type:'駆動方式', fuel_tank:'燃料タンク容量(L)',
    curb_weight:'車両重量(kg)', wheelbase:'軸距(mm)',
    g_app_overview:'認証申請概要', g_app_type:'認証申請タイプ',
    g_appl_date:'申請日', g_maker:'製造社', g_vehicle_form:'車種(形式)',
    g_vehicle_fuel:'燃料', g_power_cc:'出力/排気量', g_std_emission:'排出ガス基準',
    g_cert_no:'認証番号', g_note:'備考',
    g_cert_content:'認証内容', g_applicable:'該当', g_evap:'蒸発ガス',
    g_warranty:'保証', g_detail:'詳細', g_tech:'技術的特徴',
    g_self_result:'自社試験結果', g_emission_colon:'排出ガス:', g_noise_colon:'騒音:',
    g_hc:'HC', g_co_full:'CO(g/km)', g_hc_exhaust:'HC排気(g/km)', g_nox_full:'NOx(g/km)', g_hc_evap:'HC蒸発(g/Test)',
    g_accel_noise:'加速走行騒音(dB(A))', g_exhaust_noise:'排気騒音(dB(A))', g_horn_noise:'警音器騒音(dB(A))',
    g_allowable_std:'許容基準', g_test_result:'試験結果', g_compliance_rate:'適合可否',
    g_monitor_device:'モニタリング装置', g_fault_cond:'故障条件', g_wmtc_result:'WMTC結果',
    g_mil_lamp:'誤作動表示灯<br>点灯有無', g_fault_std:'故障基準', g_monitor_pass:'監視装置<br>適否判定',
    g_catalyst:'触媒装置', g_catalyst_dpf:'触媒装置(DPF)',
    g_spec_result:'技術仕様及び試験結果',
    g_blowby:'ブローバイ制御', g_obd_std_name:'OBD基準名', g_monitor_item:'モニター項目',
    g_tested:'試験有無', g_test_car_name:'試験車名称', g_test_facility:'試験施設',
    g_test_car_basis:'試験車選定根拠', g_evap_test:'蒸発ガス試験',
    g_warranty_df:'保証及び劣化係数', g_df_applied:'劣化係数適用',
    g_durability:'耐久試験', g_ki_test:'KI試験', g_noise_test:'騒音試験',
    detail_plan_title:'認証に必要な詳細計画書類',
    vehicle_type:'車種', model_year:'年式', color:'色',
    test_org:'試験機関', test_date:'試験日', test_result:'試験結果',
    emission_noise_title:'排出ガス・騒音低減書類',
    emission_std:'排出ガス基準', noise_std:'騒音基準',
    catalyst:'触媒装置', muffler:'消音器', air_filter:'エアフィルター',
    en_main_title:'排出ガス・騒音低減装置資料',
    en_muffler:'1. 消音器（マフラー）',
    en_muffler_comp_title:'1.1 マフラー構成内訳',
    en_muffler_diagram_title:'1.2 マフラー図面',
    en_muffler_spec_title:'1.3 マフラー仕様',
    en_1_3_1:'構造及び騒音低減原理', en_1_3_2:'フロー図', en_1_3_3:'製造社',
    en_1_3_4:'内外部材質', en_1_3_5:'寸法図面',
    en_cat_spec_title:'1.4 触媒装置仕様',
    en_1_4_1:'触媒製造社', en_1_4_2:'触媒材質', en_1_4_3:'触媒性能及び寸法',
    en_1_4_4:'寸法図面', en_1_4_5:'原理または効果', en_1_4_6:'取付位置',
    img_hint:'画像をドラッグまたはクリックしてアップロード',
    obd_config_title:'OBD構成に関する書類',
    obd_system:'OBDシステムタイプ', ecu_maker:'ECUメーカー', ecu_model:'ECUモデル',
    sensor_o2:'O2センサー', sensor_map:'MAPセンサー', sensor_tps:'TPSセンサー',
    dtc_code:'故障コード(DTC)', mil:'MIL警告灯', readiness:'レディネスモニター',
    th_div:'区分', th_item:'項目', th_content:'内容', th_fuel:'燃料',
    emission_test_title:'排出ガス試験報告書',
    co:'CO(g/km)', hc:'HC(g/km)', nox:'NOx(g/km)', co2:'CO₂(g/km)',
    test_mode:'試験モード', fuel_consumption:'燃費(km/L)',
    evap_test_title:'蒸発ガス試験内容報告書',
    evap_std:'蒸発ガス基準', canister:'キャニスター容量', tank_vol:'燃料タンク容量',
    obd_operation_title:'OBD作動確認試験報告書',
    fault_insert:'故障挿入方法', mil_check:'MIL点灯確認', dtc_check:'DTC保存確認',
    freeze_frame:'フリーズフレーム確認',
    noise_test_title:'自動車騒音試験内容報告書',
    nt_main_title:'自動車騒音試験内容報告書', nt_sec1:'1. 試験関連規定',
    drive_noise:'走行騒音(dB(A))', stationary_noise:'定置騒音(dB(A))', horn_noise:'警音器騒音',
    confirmation_title:'確認書', cf_title:'確認書',
    confirm_content:'確認内容', confirm_date:'確認日', confirm_sign:'署名',
    // emission_test
    em_main_title:'排出ガス試験内容報告書(WMTCモード)',
    em_test_div:'試験区分', em_test_no:'試験番号', em_driver:'運転者',
    em_operator:'装備操作者', em_inspector:'検査責任者',
    em_dynamo:'ダイナモメーター', em_analyzer:'分析装置', em_cooling_fan:'冷却ファン',
    // evap_test
    ev_main_title:'蒸発ガス試験内容報告書',
    ev_diurnal_test:'昼間蒸発損失試験', ev_hot_soak:'ホットソーク試験',
    // obd_operation
    oo_main_title:'排出ガス自己診断装置作動確認試験内容報告書',
    oo_sec_general:'□ 試験一般内容', oo_sec_vehicle:'□ 試験自動車諸元', oo_sec_result:'□ 試 験 結 果',
    ph_importer:'輸入会社名', ph_cert_year:'例) 2025', ph_displacement:'例) 125cc', ph_family_code:'記号入力',
    attach_note:'添付ファイル案内',
    attach_hint:'ドラッグまたはクリックでアップロード',
    cf_maker_confirm:'この車両が環境認証基準に適合することを確認します。',
    g_std_noise:'騒音基準',
    g_cert_appl:'認証申請タイプ',
    g_vehicle_evap_rep:'蒸発ガス代表車',
    g_vehicle:'車種',
    g_std_13g2:'2013年ガソリン排出ガス基準(2)',
    g_std_13g1:'2013年ガソリン排出ガス基準(1)',
    g_std_16g:'2016年ガソリン排出ガス基準',
    g_std_20g:'2020年ガソリン排出ガス基準',
    g_std_14d:'2014年ディーゼル排出ガス基準',
    g_obd_g1:'ガソリンOBD基準1',
    g_obd_g2:'ガソリンOBD基準2',
    g_obd_g3:'ガソリンOBD基準3',
    g_obd_g4:'ガソリンEURO6 OBD基準',
    g_obd_d1:'ディーゼルOBD基準1',
    g_obd_d2:'ディーゼルEURO6 OBD基準',
    g_rep_label:'代表車名',
    g_evap_rep:'蒸発ガス代表車',
    g_evap_same:'蒸発ガス同一車種',
    g_evap_col:'蒸発ガス区分',
    g_warr_10_192:'保証期間：10年/19万2千km',
    g_warr_10_240:'保証期間：10年/24万km',
    g_warr_15_240:'保証期間：15年/24万km',
    g_warr_2_20:'保証期間：2年/2万km',
    g_warr_2_35:'保証期間：2年/3.5万km',
    g_warr_d10_160:'保証期間：10年/16万km',
    g_o2sensor:'O2センサ',
    g_chk_evap_rep:'□ 蒸発ガス代表車',
    g_chk_blowby:'□ ブローバイ制御装置',
    g_obd2_diag:'OBD2自己診断基準',
    g_obd2_suffix:'二輪自動車基準',
    g_chk_obd_rep:'□ OBD代表車',
    g_chk_obd_std:'□ OBD適用基準',
    g_chk_obd_fault:'□ 故障基準該当',
    g_chk_obd_monitor:'□ モニター項目該当',
    g_chk_facility:'□ 自社試験施設保有',
    g_chk_em_basis:'□ 排出ガス適用基準',
    g_chk_noise_basis:'□ 騒音適用基準',
    g_chk_obd_basis:'□ OBD適用基準',
    ev_cert_name:'認証車名',
    ev_test_name:'試験車名',
    ev_test_date:'試験日時',
    ev_same_type:'同一車種',
    ev_test_no:'試験番号',
    ev_vin:'車台番号',
    ev_eng_no:'エンジン番号',
    ev_odo:'積算距離',
    ev_chamber_spec:'測定室(密閉室)規格',
    ev_height:'高さ',
    ev_width:'幅',
    ev_length:'長さ',
    ev_vol:'正味内部容積',
    ev_temp_method:'測定室温度調整方法',
    ev_fuel_heater:'燃料加熱装置',
    ev_chamber_model:'測定室モデル',
    ev_analyzer:'分析設備',
    ev_hc_fix:'HC固定方法',
    ev_model_label:'モデル',
    ev_charcoal_trap:'活性炭採集トラック',
    ev_trap_spec:'容器規格および材質',
    ev_trap_aux:'補助採集装置の規格および材質',
    ev_trap_weight_before:'採集容器重量',
    ev_trap_weight_after:'試験後重量',
    ev_trap_net_weight:'正味重量',
    ev_col_div:'区分',
    ev_initial_phase:'初期段階(密閉室)',
    ev_final_phase:'最終段階(密閉室)',
    ev_result:'結果 g',
    ev_temp:'温度 ℃',
    ev_pressure:'圧力 mmHg',
    ev_conc:'濃度 ppm',
    ev_test_result_label:'試験結果',
    ev_df:'劣化係数',
    ev_final_result:'最終結果(g/Test)',
    ev_std_val:'基準(g/Test)',
    ev_test_results:'試験結果表',
    ev_test_div:'試験区分',
    em_cert_name:'認証車名称(形式)',
    em_mfg_date:'製造日',
    em_trans_type:'変速機形式',
    em_curb_weight:'空車重量(kg)',
    em_maker:'製造社',
    em_gvw:'最大積載重量(kg)',
    em_inertia:'慣性重量等級(kg)',
    em_tank_loc:'燃料タンク容量及び位置',
    em_road_load:'道路負荷力',
    em_coastdown:'コーストダウン時間',
    em_catalyst_yn:'触媒装着有無',
    em_eng_no:'エンジン番号',
    em_eng_type:'エンジン形式',
    em_max_power:'最高出力(ps/rpm)',
    em_total_cc:'総排気量(cc)',
    em_cyl:'シリンダ数',
    em_idle:'アイドル回転数(rpm)',
    em_cooling:'冷却方式',
    em_cycle:'燃焼サイクル',
    em_test_fuel:'試験燃料',
    em_col_name:'装置名',
    em_col_type:'形式',
    em_col_model:'モデル名',
    em_col_approval:'型式承認番号',
    em_col_location:'設置場所',
    em_col_item:'測定項目',
    em_mass:'排出質量(g/test)',
    em_pressure:'大気圧(kPa)',
    em_wet_temp:'湿球温度(℃)',
    em_dry_temp:'乾球温度(℃)',
    em_rh:'相対湿度(%)',
    em_abs_hum:'比較湿度 H₂Og/kg Air',
    em_emission_vol:'排出ガス量',
    em_drive_dist:'走行距離(km)',
    oo_test_date:'試験日',
    oo_gen_spec:'一般諸元',
    oo_car_name:'自動車名称',
    oo_form:'形式',
    oo_car_type:'車種',
    oo_trans_type:'変速機形式',
    oo_gvw_kg:'最大積載重量(kg)',
    oo_engine:'エンジン',
    oo_emission_ctrl:'排出ガス制御装置',
    oo_catalyst_type:'触媒装置形式',
    oo_secondary_air:'二次空気供給装置',
    oo_egr:'EGR装置',
    oo_ecu_type:'ECU形式',
    oo_o2_type:'O2センサ形式',
    oo_purge_type:'パージバルブ形式',
    oo_monitor_target:'試験対象監視装置',
    oo_verdict:'結果判定',
    oo_cvs75:'CVS-75モード結果(g/km)',
    oo_fault_std:'誤作動判定基準(g/km)',
    oo_device_name:'装置名',
    oo_fault_cond2:'誤作動<br>再現条件',
    oo_eng_spec_title:'2. エンジン諸元',
    nt_sec3:'3. 試験自動車諸元',
    nt_sec4:'4. 試験条件',
    nt_sec5:'5. 試験装置',
    nt_sec6:'6. 試験結果（加速走行騒音）',
    nt_sec6_1:'6.1. ECE 加速走行騒音測定結果',
    nt_sec6_2:'6.2. KSAISO 362 加速走行騒音測定結果',
    nt_sec7:'7. 排気騒音測定結果',
    nt_sec8:'8. 警笛騒音測定結果',
    nt_col_form:'形式',
    nt_col_serial:'機器番号',
    nt_col_cal_date:'検・校正日',
    nt_car_name:'自動車名称',
    nt_maker_country:'製造社(国)',
    nt_car_type:'車種',
    nt_vin:'車台番号',
    nt_form:'形式',
    nt_eng_no:'エンジン番号',
    nt_eng_type:'エンジン形式',
    nt_max_power:'最高出力(ps/rpm)',
    nt_chassis_type:'車体形式',
    nt_max_torque:'最大トルク(N·m/rpm)',
    nt_displacement:'排気量(cc)',
    nt_rpm_34:'3,4速等価変速比',
    nt_model_year:'年式',
    nt_rpm_12:'1,2速等価変速比',
    nt_trans_type:'変速機形式',
    nt_eng_pos:'エンジン位置',
    nt_gear_ratio:'ギア比',
    nt_axle_count:'車軸数',
    nt_decel_ratio:'減速比',
    nt_drive_axle:'駆動車軸',
    nt_drive_shaft:'駆動軸',
    nt_axle_ratio:'車軸比',
    nt_curb_weight:'空車重量(kg)',
    nt_gvw:'最大積載重量(kg)',
    nt_test_weight:'試験重量(kg)',
    nt_pmr:'PMR(kW/t)',
    nt_veh_length:'車両全長(mm)',
    nt_kp:'kP値',
    nt_muffler_info:'消音器情報',
    nt_tire_pressure:'タイヤ空気圧(kPa)',
    nt_auto_down:'自動変速機シフトダウン回転数(rpm)',
    nt_horn_type:'警笛形式',
    nt_etc:'その他',
    nt_place:'場所',
    nt_weather:'天気',
    nt_wind_dir:'風向',
    nt_wind_speed:'風速',
    nt_humidity:'大気湿度',
    nt_atm_pressure:'大気圧力',
    nt_air_temp:'大気温度',
    nt_sound_meter:'騒音計',
    nt_calibrator:'校正器',
    nt_speedometer:'車速計',
    nt_rpm_meter:'エンジン回転数計',
    nt_weather_eq:'気象観測装置(風速,温度)',
    nt_track:'記録計',
    nt_test_weight_kg:'試験重量(Tested Vehicle weight, kg)',
    nt_load_kg:'積載重量(Vehicle load, kg)',
    nt_gear_1:'選択ギア(Gear selected, i)',
    nt_gear_2:'選択ギア(Gear selected, i+1)',
    nt_a_urban:'目標加速度(a_urban, m/s²)',
    nt_a_wotref:'基準加速度(a_wot,ref, m/s²)',
    nt_a_wot:'測定加速度(a_wot,test, m/s²)',
    nt_kp_col:'部分出力係数(kp)',
    nt_k_weight:'重み係数(k)',
    nt_gear_used:'使用変速ギア',
    nt_accel_test:'加速走行試験',
    nt_const_test:'定速走行試験',
    nt_v_aa:'初期速度(V_AA)',
    nt_v_pp:'中間速度(V_PP)',
    nt_v_bb:'出口速度(V_BB)',
    nt_n_bb:'出口エンジン回転数(N_BB)',
    nt_accel_start:'加速開始位置',
    nt_accel_val:'加速度(a_wot)',
    nt_trial_1:'1回',
    nt_trial_2:'2回',
    nt_trial_3:'3回',
    nt_trial_4:'4回',
    nt_avg:'平均',
    nt_test_result:'試験結果(dB(A))',
    nt_final_result:'最終結果(dB(A))',
    nt_std_val:'基準値(dB(A))',
    nt_bg_noise_a:'暗騒音(dB(A))',
    nt_exhaust_noise_val:'排気騒音(dB(A))',
    nt_score_a:'成績(dB(A))',
    nt_std_a:'基準値(dB(A))',
    nt_measured:'測定値',
    nt_corrected:'補正値',
    nt_meas_count:'測定回数',
    nt_horn_form:'警笛形式',
    nt_horn_count:'警笛数',
    nt_bg_noise_c:'暗騒音(dB(C))',
    nt_horn_noise_val:'警笛騒音(dB(C))',
    nt_score_c:'成績(dB(C))',
    nt_std_c:'基準値(dB(C))',
    nt_tester:'試験者',
    nt_verifier:'確認者',
    nt_raw_data_note:'生データ添付',
    nt_col_item:'項目',
    ph_maker:'製造社名', ph_model_name:'車種名入力', ph_appl_no:'認証番号入力',
    g_obd_g5:'二輪車OBD基準',
    nt_col_content:'内容',

    saving:'保存中',
    save_all_ok_prefix:'全', save_all_ok_suffix:'件の書類が保存されました。',
    save_partial_ok:'件保存完了', save_partial_fail:'件失敗',
    save_error:'保存中にエラーが発生しました。',
    // 제출서류 목록 다국어
    forms_section_title:'□ 提出書類一覧',
    appl_pct_label:'全体進捗率',
    form_col_no:'番号', form_col_name:'書類名', form_col_status:'状態',
    form_status_done:'完了', form_status_todo:'未完了',
    btn_back_list:'一覧へ', btn_print:'印刷', btn_save_all:'すべて保存',
    // 서류 타입 이름
    form_summary:'認証申請概要書',
    form_gasoline:'ガソリン車認証申請主要内容',
    form_detail_plan:'認証に必要な詳細計画書類',
    form_emission_noise:'排出ガス・騒音低減書類',
    form_obd_config:'OBDシステム構成書類',
    form_emission_test:'排出ガス試験報告書',
    form_evap_test:'蒸発ガス試験内容報告書',
    form_obd_operation:'OBD作動確認試験報告書',
    form_noise_test:'自動車騒音試験内容報告書',
    form_confirmation:'確認書',
    // 대시보드 & 목록 다국어
    cert_basic:'基本認証', cert_change:'変更認証', cert_report:'変更報告',
    status_draft:'下書き', status_inprogress:'作成中', status_completed:'完了',
    dash_title:'認証申請一覧',
    stat_total_lbl:'全申請書', stat_prog_lbl:'作成中', stat_done_lbl:'完了', stat_draft_lbl:'下書き',
    btn_new_appl:'新規申請書作成', btn_first_appl:'最初の申請書を作成',
    btn_write:'編集', btn_delete:'削除',
    empty_title:'申請書がありません',
    empty_desc:'新しい申請書を作成して<br>認証手続きを開始してください。',
    meta_modified:'更新',
    // ── detail_plan ラベル ──
    dp_h_importer:'輸入会社', dp_h_certyear:'認証年度', dp_h_disp:'排気量', dp_h_famcode:'同一車種記号',
    dp_doc_tag:'[別紙第4号様式]',
    dp_doc_title:'認証に必要な詳細計画に関する書類',
    dp_s1:'1.  認証概要', dp_s2:'2.  機密事項', dp_s3:'3.  認証試験燃料',
    dp_s4:'4.  試験設備及び排気ガス・騒音測定設備',
    dp_s5:'5.  試験手順', dp_s6:'6.  整備及び保証',
    dp_s7:'7.  排気ガスラベル', dp_s8:'8.  排気ガス制御技術',
    dp_s9:'9.  蒸発ガス及びブローバイガス', dp_s10:'10. 同一車種（原動機）',
    dp_s11:'11. 試験車両', dp_s12:'12. 校正情報及び事後確定情報提出協約', dp_s13:'13. その他',
    dp_1_1_lbl:'1.1. 認証対象自動車の開発背景及び特性',
    dp_1_2_lbl:'1.2. 排気ガス・騒音関連新技術',
    dp_1_3_lbl:'1.3. 開発目標（輸入車の場合は外国認証成績等で代替）',
    dp_1_4_lbl:'1.4. 認証対象自動車諸元',
    dp_2_1_lbl:'2.1. 機密に関する要請',
    dp_3_lbl:'3.1. 認証試験燃料',
    dp_5_1_lbl:'5.1. 排気ガス試験', dp_5_2_lbl:'5.2. 走行距離蓄積', dp_5_3_lbl:'5.3. 騒音試験',
    dp_6_1_lbl:'6.1. 試験車両の整備計画',
    dp_6_2_lbl:'6.2. 車両購入者への推奨整備', dp_6_3_lbl:'6.3. 保証に関する説明',
    dp_7_1_lbl:'7.1. サンプル', dp_7_2_lbl:'7.2. 貼付位置等',
    dp_8_1_lbl:'8.1.  燃料システム', dp_8_2_lbl:'8.2.  吸排気装置',
    dp_img_hint:'画像クリックまたはドラッグ',
    dp_img_hint2:'構成図画像クリックまたはドラッグ',
    dp_diagram_attach:'構成図添付:',
    dp_toc_num:'番号', dp_toc_item:'項目',
    dp_toc_writeno:'作成番号', dp_toc_order:'順序', dp_toc_see_below:'下記目次参照',
    dp_toc_title:'目 次',
    dp_print_title:'目次 - 認証に必要な詳細計画に関する書類',
    dp_toc_1:'認証概要', dp_toc_1_1:'開発背景及び特性',
    dp_toc_1_2:'排気ガス・騒音関連新技術', dp_toc_1_3:'開発目標',
    dp_toc_1_4:'認証対象自動車諸元', dp_toc_2:'機密事項', dp_toc_2_1:'機密に関する要請',
    dp_toc_3:'認証試験燃料', dp_toc_4:'試験設備及び排気ガス・騒音測定設備',
    dp_toc_5:'試験手順', dp_toc_5_1:'排気ガス試験', dp_toc_5_2:'走行距離蓄積',
    dp_toc_5_3:'騒音試験', dp_toc_6:'整備及び保証',
    dp_toc_6_1:'試験車両の整備計画',
    dp_toc_6_2:'車両購入者への推奨整備', dp_toc_6_3:'保証に関する説明',
    dp_toc_7:'排気ガスラベル', dp_toc_7_1:'サンプル', dp_toc_7_2:'貼付位置等',
    dp_toc_8:'排気ガス制御技術', dp_toc_8_1:'燃料システム', dp_toc_8_2:'吸排気装置',
    dp_toc_8_3:'クランクケース制御装置', dp_toc_8_4:'エンジン', dp_toc_8_5:'変速機',
    dp_toc_8_6:'触媒変換システム', dp_toc_8_7:'EGR装置',
    dp_toc_8_8:'電子制御装置', dp_toc_8_9:'その他排気ガス制御装置',
    dp_toc_8_10:'感知変数対制御変数', dp_toc_8_11:'部品リスト',
    dp_toc_8_12:'SCR性能及び原理等説明',
    dp_toc_8_13:'SCR用尿素水溶液成分分析結果',
    dp_toc_8_14:'電気自動車制御装置',
    dp_toc_9:'蒸発ガス及びブローバイガス', dp_toc_9_1:'蒸発ガス制御装置説明',
    dp_toc_9_2:'制御装置構成図等', dp_toc_10:'同一車種（原動機）', dp_toc_10_1:'同一車種説明',
    dp_toc_11:'試験車両', dp_toc_11_1:'試験車両選定',
    dp_toc_11_2:'耐久性試験車両選定根拠', dp_toc_11_3:'排気ガス試験車両選定根拠',
    dp_toc_11_4:'騒音試験車両選定根拠',
    dp_toc_12:'校正情報及び事後確定情報提出協約', dp_toc_13:'その他',
  },
  zh: {
    importer:'进口商', cert_year:'认证年度', displacement:'排量', family_code:'同一车型代号',
    appl_div:'类别', appl_no:'认证编号', cert_date:'认证日期', representative:'代表人',
    address:'地址', phone:'电话', model_name:'车型名称', engine_no:'发动机编号',
    summary_title:'认证申请概要书',
    sv_title:'排放及噪声 认证申请概要',
    sv_th_div:'序号', sv_th_item:'项目', sv_th_content:'内容',
    sv_maker:'制造商（制造国）', sv_vehicle_name:'试验车辆名称（型式）', sv_vehicle_name_simple:'车辆名称',
    sv_fuel:'使用燃料', sv_std:'适用标准', sv_emission:'排放', sv_noise_simple:'噪声',
    sv_foreign_std:'外国标准', sv_foreign_std_note:'（欧洲或美国标准）',
    sv_evap_rep_title:'蒸发排放代表车辆及', sv_obd_rep_title:'OBD代表车辆及',
    sv_vehicle_name_lbl:'车辆名称', sv_type_lbl:'型式', sv_rep_vehicle_lbl:'代表车辆',
    sv_warranty:'保修期', sv_self_test:'自检实施内容', sv_key_tech:'核心技术',
    unit_year:'年', fuel_gasoline:'汽油', fuel_diesel:'柴油',
    gasoline_title:'汽油车认证申请主要内容',
    maker:'制造商', engine_type:'发动机型式', fuel:'燃料',
    max_power:'最大功率(ps/rpm)', max_torque:'最大扭矩(N·m/rpm)',
    transmission:'变速器', drive_type:'驱动方式', fuel_tank:'油箱容量(L)',
    curb_weight:'整备质量(kg)', wheelbase:'轴距(mm)',
    g_app_overview:'认证申请概述', g_app_type:'认证申请类型',
    g_appl_date:'申请日期', g_maker:'制造商', g_vehicle_form:'车种（型式）',
    g_vehicle_fuel:'燃料', g_power_cc:'功率/排量', g_std_emission:'排放标准',
    g_cert_no:'认证编号', g_note:'备注',
    g_cert_content:'认证内容', g_applicable:'适用', g_evap:'蒸发排放',
    g_warranty:'保修', g_detail:'详细内容', g_tech:'技术特征',
    g_self_result:'自检结果', g_emission_colon:'排放:', g_noise_colon:'噪声:',
    g_hc:'HC', g_co_full:'CO(g/km)', g_hc_exhaust:'HC排气(g/km)', g_nox_full:'NOx(g/km)', g_hc_evap:'HC蒸发(g/Test)',
    g_accel_noise:'加速行驶噪声(dB(A))', g_exhaust_noise:'排气噪声(dB(A))', g_horn_noise:'喇叭噪声(dB(A))',
    g_allowable_std:'允许标准', g_test_result:'试验结果', g_compliance_rate:'合规与否',
    g_monitor_device:'监控装置', g_fault_cond:'故障条件', g_wmtc_result:'WMTC结果',
    g_mil_lamp:'误动作指示灯<br>点亮与否', g_fault_std:'故障标准', g_monitor_pass:'监视装置<br>适否判定',
    g_catalyst:'催化装置', g_catalyst_dpf:'催化装置(DPF)',
    g_spec_result:'技术规格及试验结果',
    g_blowby:'曲轴箱通风控制', g_obd_std_name:'OBD标准名称', g_monitor_item:'监控项目',
    g_tested:'试验与否', g_test_car_name:'试验车名称', g_test_facility:'试验设施',
    g_test_car_basis:'试验车选定依据', g_evap_test:'蒸发排放试验',
    g_warranty_df:'保修及劣化系数', g_df_applied:'劣化系数适用',
    g_durability:'耐久试验', g_ki_test:'KI试验', g_noise_test:'噪声试验',
    detail_plan_title:'认证所需详细计划文件',
    vehicle_type:'车种', model_year:'年款', color:'颜色',
    test_org:'检测机构', test_date:'检测日期', test_result:'检测结果',
    emission_noise_title:'排放及噪音减排文件',
    emission_std:'排放标准', noise_std:'噪音标准',
    catalyst:'催化装置', muffler:'消音器', air_filter:'空气滤清器',
    en_main_title:'排放及噪声减排装置资料',
    en_muffler:'1. 消音器（排气管）',
    en_muffler_comp_title:'1.1 消音器构成内容',
    en_muffler_diagram_title:'1.2 消音器图纸',
    en_muffler_spec_title:'1.3 消音器规格',
    en_1_3_1:'结构及降噪原理', en_1_3_2:'流程图', en_1_3_3:'制造商',
    en_1_3_4:'内外部材质', en_1_3_5:'尺寸图纸',
    en_cat_spec_title:'1.4 催化装置规格',
    en_1_4_1:'催化制造商', en_1_4_2:'催化材质', en_1_4_3:'催化性能及尺寸',
    en_1_4_4:'尺寸图纸', en_1_4_5:'原理或效果', en_1_4_6:'安装位置',
    img_hint:'拖拽或点击上传图片',
    obd_config_title:'OBD配置相关文件',
    obd_system:'OBD系统类型', ecu_maker:'ECU制造商', ecu_model:'ECU型号',
    sensor_o2:'O2传感器', sensor_map:'MAP传感器', sensor_tps:'TPS传感器',
    dtc_code:'故障码(DTC)', mil:'MIL警告灯', readiness:'就绪监测器',
    th_div:'序号', th_item:'项目', th_content:'内容', th_fuel:'燃料',
    emission_test_title:'排放气体试验报告书',
    co:'CO(g/km)', hc:'HC(g/km)', nox:'NOx(g/km)', co2:'CO₂(g/km)',
    test_mode:'试验模式', fuel_consumption:'油耗(km/L)',
    evap_test_title:'蒸发排放试验内容报告书',
    evap_std:'蒸发排放标准', canister:'碳罐容量', tank_vol:'油箱容量',
    obd_operation_title:'OBD运行确认试验报告书',
    fault_insert:'故障插入方法', mil_check:'MIL点亮确认', dtc_check:'DTC存储确认',
    freeze_frame:'冻结帧确认',
    noise_test_title:'汽车噪声试验内容报告书',
    nt_main_title:'汽车噪声试验内容报告书', nt_sec1:'1. 试验相关规定',
    drive_noise:'行驶噪声(dB(A))', stationary_noise:'怠速噪声(dB(A))', horn_noise:'喇叭噪声',
    confirmation_title:'确认书', cf_title:'确认书',
    confirm_content:'确认内容', confirm_date:'确认日期', confirm_sign:'签名',
    // emission_test
    em_main_title:'排放气体试验内容报告书(WMTC模式)',
    em_test_div:'试验区分', em_test_no:'试验编号', em_driver:'驾驶员',
    em_operator:'设备操作员', em_inspector:'检验负责人',
    em_dynamo:'测功机', em_analyzer:'分析装置', em_cooling_fan:'冷却风扇',
    // evap_test
    ev_main_title:'蒸发排放试验内容报告书',
    ev_diurnal_test:'日间蒸发损失试验', ev_hot_soak:'热浸泡试验',
    // obd_operation
    oo_main_title:'排放自诊断装置运行确认试验内容报告书',
    oo_sec_general:'□ 试验一般内容', oo_sec_vehicle:'□ 试验车辆规格', oo_sec_result:'□ 试 验 结 果',
    ph_importer:'进口商名称', ph_cert_year:'例) 2025', ph_displacement:'例) 125cc', ph_family_code:'代号输入',
    attach_note:'附件说明',
    attach_hint:'拖拽或点击上传',
    cf_maker_confirm:'我们确认该车辆符合环境认证标准。',
    g_std_noise:'噪声标准',
    g_cert_appl:'认证申请类型',
    g_vehicle_evap_rep:'蒸发排放代表车',
    g_vehicle:'车型',
    g_std_13g2:'2013年汽油排放标准(2)',
    g_std_13g1:'2013年汽油排放标准(1)',
    g_std_16g:'2016年汽油排放标准',
    g_std_20g:'2020年汽油排放标准',
    g_std_14d:'2014年柴油排放标准',
    g_obd_g1:'汽油OBD标准1',
    g_obd_g2:'汽油OBD标准2',
    g_obd_g3:'汽油OBD标准3',
    g_obd_g4:'汽油EURO6 OBD标准',
    g_obd_d1:'柴油OBD标准1',
    g_obd_d2:'柴油EURO6 OBD标准',
    g_rep_label:'代表车名',
    g_evap_rep:'蒸发排放代表车',
    g_evap_same:'蒸发排放同型车',
    g_evap_col:'蒸发排放分类',
    g_warr_10_192:'保修期：10年/19.2万km',
    g_warr_10_240:'保修期：10年/24万km',
    g_warr_15_240:'保修期：15年/24万km',
    g_warr_2_20:'保修期：2年/2万km',
    g_warr_2_35:'保修期：2年/3.5万km',
    g_warr_d10_160:'保修期：10年/16万km',
    g_o2sensor:'O2传感器',
    g_chk_evap_rep:'□ 蒸发排放代表车',
    g_chk_blowby:'□ 曲轴通风控制装置',
    g_obd2_diag:'OBD2自诊断标准',
    g_obd2_suffix:'二轮车标准',
    g_chk_obd_rep:'□ OBD代表车',
    g_chk_obd_std:'□ OBD适用标准',
    g_chk_obd_fault:'□ 故障标准适用',
    g_chk_obd_monitor:'□ 监控项目适用',
    g_chk_facility:'□ 自有试验设施',
    g_chk_em_basis:'□ 排放适用标准',
    g_chk_noise_basis:'□ 噪声适用标准',
    g_chk_obd_basis:'□ OBD适用标准',
    ev_cert_name:'认证车名',
    ev_test_name:'试验车名',
    ev_test_date:'试验日时',
    ev_same_type:'同型车',
    ev_test_no:'试验编号',
    ev_vin:'车架号',
    ev_eng_no:'发动机编号',
    ev_odo:'积算里程',
    ev_chamber_spec:'测定室(密封室)规格',
    ev_height:'高度',
    ev_width:'宽度',
    ev_length:'长度',
    ev_vol:'净内部容积',
    ev_temp_method:'测定室温度调节方法',
    ev_fuel_heater:'燃油加热装置',
    ev_chamber_model:'测定室型号',
    ev_analyzer:'分析设备',
    ev_hc_fix:'HC固定方法',
    ev_model_label:'型号',
    ev_charcoal_trap:'活性炭吸附管',
    ev_trap_spec:'容器规格及材质',
    ev_trap_aux:'辅助采集装置规格及材质',
    ev_trap_weight_before:'采集容器重量',
    ev_trap_weight_after:'试验后重量',
    ev_trap_net_weight:'净重量',
    ev_col_div:'类别',
    ev_initial_phase:'初始阶段(密封室)',
    ev_final_phase:'最终阶段(密封室)',
    ev_result:'结果 g',
    ev_temp:'温度 ℃',
    ev_pressure:'压力 mmHg',
    ev_conc:'浓度 ppm',
    ev_test_result_label:'试验结果',
    ev_df:'劣化系数',
    ev_final_result:'最终结果(g/Test)',
    ev_std_val:'标准(g/Test)',
    ev_test_results:'试验结果表',
    ev_test_div:'试验类型',
    em_cert_name:'认证车名称(型式)',
    em_mfg_date:'制造日期',
    em_trans_type:'变速器型式',
    em_curb_weight:'整备质量(kg)',
    em_maker:'制造商',
    em_gvw:'最大总质量(kg)',
    em_inertia:'惯性质量等级(kg)',
    em_tank_loc:'油箱容量及位置',
    em_road_load:'道路负荷力',
    em_coastdown:'滑行时间',
    em_catalyst_yn:'催化器安装与否',
    em_eng_no:'发动机编号',
    em_eng_type:'发动机型式',
    em_max_power:'最大功率(ps/rpm)',
    em_total_cc:'总排量(cc)',
    em_cyl:'气缸数',
    em_idle:'怠速转速(rpm)',
    em_cooling:'冷却方式',
    em_cycle:'燃烧循环',
    em_test_fuel:'试验燃料',
    em_col_name:'装置名称',
    em_col_type:'型式',
    em_col_model:'型号名称',
    em_col_approval:'型式批准号',
    em_col_location:'安装地点',
    em_col_item:'测量项目',
    em_mass:'排放质量(g/test)',
    em_pressure:'大气压(kPa)',
    em_wet_temp:'湿球温度(℃)',
    em_dry_temp:'干球温度(℃)',
    em_rh:'相对湿度(%)',
    em_abs_hum:'比較湿度 H₂Og/kg Air',
    em_emission_vol:'排放量',
    em_drive_dist:'行驶距离(km)',
    oo_test_date:'试验日期',
    oo_gen_spec:'一般规格',
    oo_car_name:'车辆名称',
    oo_form:'型式',
    oo_car_type:'车型',
    oo_trans_type:'变速器型式',
    oo_gvw_kg:'最大总质量(kg)',
    oo_engine:'发动机',
    oo_emission_ctrl:'排放控制装置',
    oo_catalyst_type:'催化装置型式',
    oo_secondary_air:'二次空气供应装置',
    oo_egr:'EGR装置',
    oo_ecu_type:'ECU型式',
    oo_o2_type:'O2传感器型式',
    oo_purge_type:'净化阀型式',
    oo_monitor_target:'试验对象监视装置',
    oo_verdict:'结果判定',
    oo_cvs75:'CVS-75模式结果(g/km)',
    oo_fault_std:'误动作判定基准(g/km)',
    oo_device_name:'装置名称',
    oo_fault_cond2:'误动作<br>再现条件',
    oo_eng_spec_title:'2. 发动机规格',
    nt_sec3:'3. 试验车辆规格',
    nt_sec4:'4. 试验条件',
    nt_sec5:'5. 试验设备',
    nt_sec6:'6. 试验结果（加速行驶噪声）',
    nt_sec6_1:'6.1. ECE 加速行驶噪声测量结果',
    nt_sec6_2:'6.2. KSAISO 362 加速行驶噪声测量结果',
    nt_sec7:'7. 排气噪声测量结果',
    nt_sec8:'8. 喇叭噪声测量结果',
    nt_col_form:'型式',
    nt_col_serial:'设备编号',
    nt_col_cal_date:'检·校准日',
    nt_car_name:'车辆名称',
    nt_maker_country:'制造商(国)',
    nt_car_type:'车型',
    nt_vin:'车架号',
    nt_form:'型式',
    nt_eng_no:'发动机编号',
    nt_eng_type:'发动机型式',
    nt_max_power:'最大功率(ps/rpm)',
    nt_chassis_type:'车身型式',
    nt_max_torque:'最大扭矩(N·m/rpm)',
    nt_displacement:'排量(cc)',
    nt_rpm_34:'3,4挡等效变速比',
    nt_model_year:'年款',
    nt_rpm_12:'1,2挡等效变速比',
    nt_trans_type:'变速器型式',
    nt_eng_pos:'发动机位置',
    nt_gear_ratio:'传动比',
    nt_axle_count:'车轴数',
    nt_decel_ratio:'减速比',
    nt_drive_axle:'驱动车轴',
    nt_drive_shaft:'驱动轴',
    nt_axle_ratio:'桥速比',
    nt_curb_weight:'整备质量(kg)',
    nt_gvw:'最大总质量(kg)',
    nt_test_weight:'试验质量(kg)',
    nt_pmr:'PMR(kW/t)',
    nt_veh_length:'车辆全长(mm)',
    nt_kp:'kP值',
    nt_muffler_info:'消声器信息',
    nt_tire_pressure:'轮胎气压(kPa)',
    nt_auto_down:'自动变速器降档转速(rpm)',
    nt_horn_type:'喇叭型式',
    nt_etc:'其他',
    nt_place:'地点',
    nt_weather:'天气',
    nt_wind_dir:'风向',
    nt_wind_speed:'风速',
    nt_humidity:'大气湿度',
    nt_atm_pressure:'大气压力',
    nt_air_temp:'大气温度',
    nt_sound_meter:'声级计',
    nt_calibrator:'校准器',
    nt_speedometer:'车速计',
    nt_rpm_meter:'发动机转速计',
    nt_weather_eq:'气象观测设备(风速,温度)',
    nt_track:'记录仪',
    nt_test_weight_kg:'试验质量(Tested Vehicle weight, kg)',
    nt_load_kg:'装载质量(Vehicle load, kg)',
    nt_gear_1:'选择挡位(Gear selected, i)',
    nt_gear_2:'选择挡位(Gear selected, i+1)',
    nt_a_urban:'目标加速度(a_urban, m/s²)',
    nt_a_wotref:'基准加速度(a_wot,ref, m/s²)',
    nt_a_wot:'测定加速度(a_wot,test, m/s²)',
    nt_kp_col:'部分功率系数(kp)',
    nt_k_weight:'加权系数(k)',
    nt_gear_used:'使用传动挡',
    nt_accel_test:'加速行驶试验',
    nt_const_test:'匀速行驶试验',
    nt_v_aa:'初始速度(V_AA)',
    nt_v_pp:'中间速度(V_PP)',
    nt_v_bb:'出口速度(V_BB)',
    nt_n_bb:'出口发动机转速(N_BB)',
    nt_accel_start:'加速起始位置',
    nt_accel_val:'加速度(a_wot)',
    nt_trial_1:'第1次',
    nt_trial_2:'第2次',
    nt_trial_3:'第3次',
    nt_trial_4:'第4次',
    nt_avg:'平均',
    nt_test_result:'试验结果(dB(A))',
    nt_final_result:'最终结果(dB(A))',
    nt_std_val:'标准值(dB(A))',
    nt_bg_noise_a:'本底噪声(dB(A))',
    nt_exhaust_noise_val:'排气噪声(dB(A))',
    nt_score_a:'成绩(dB(A))',
    nt_std_a:'标准值(dB(A))',
    nt_measured:'测量值',
    nt_corrected:'修正值',
    nt_meas_count:'测定次数',
    nt_horn_form:'喇叭型式',
    nt_horn_count:'喇叭数',
    nt_bg_noise_c:'本底噪声(dB(C))',
    nt_horn_noise_val:'喇叭噪声(dB(C))',
    nt_score_c:'成绩(dB(C))',
    nt_std_c:'标准值(dB(C))',
    nt_tester:'试验人员',
    nt_verifier:'确认人员',
    nt_raw_data_note:'原始数据附件',
    nt_col_item:'项目',
    ph_maker:'制造商名称', ph_model_name:'车型名称', ph_appl_no:'认证编号输入',

    saving:'保存中',
    save_all_ok_prefix:'共 ', save_all_ok_suffix:' 份文件已保存。',
    save_partial_ok:' 份已保存', save_partial_fail:' 份失败',
    save_error:'保存时发生错误。',
    // 제출서류 목록 다국어
    forms_section_title:'□ 提交文件清单',
    appl_pct_label:'整体进度',
    form_col_no:'编号', form_col_name:'文件名称', form_col_status:'状态',
    form_status_done:'已完成', form_status_todo:'未完成',
    btn_back_list:'返回列表', btn_print:'打印', btn_save_all:'全部保存',
    // 서류 타입 이름
    form_summary:'认证申请概要书',
    form_gasoline:'汽油车认证申请主要内容',
    form_detail_plan:'认证所需详细计划文件',
    form_emission_noise:'排放与噪声减少文件',
    form_obd_config:'OBD系统配置文件',
    form_emission_test:'排放试验报告书',
    form_evap_test:'蒸发排放试验报告书',
    form_obd_operation:'OBD运行确认试验报告书',
    form_noise_test:'汽车噪声试验报告书',
    form_confirmation:'确认书',
    // 대시보드 & 목록 다국어
    cert_basic:'基本认证', cert_change:'变更认证', cert_report:'变更报告',
    status_draft:'草稿', status_inprogress:'进行中', status_completed:'已完成',
    dash_title:'认证申请列表',
    stat_total_lbl:'全部申请', stat_prog_lbl:'进行中', stat_done_lbl:'已完成', stat_draft_lbl:'草稿',
    btn_new_appl:'新建申请', btn_first_appl:'创建第一份申请',
    btn_write:'编辑', btn_delete:'删除',
    empty_title:'暂无申请书',
    empty_desc:'创建新申请书以<br>开始认证流程。',
    meta_modified:'修改',
    // ── detail_plan 标签 ──
    dp_h_importer:'进口商', dp_h_certyear:'认证年度', dp_h_disp:'排气量', dp_h_famcode:'同一车种符号',
    dp_doc_tag:'[附件第4号样式]',
    dp_doc_title:'认证所需详细计划书类',
    dp_s1:'1.  认证介绍', dp_s2:'2.  保密事项', dp_s3:'3.  认证试验燃料',
    dp_s4:'4.  试验设施及排放气体·噪音测量设备',
    dp_s5:'5.  试验程序', dp_s6:'6.  维修及保修',
    dp_s7:'7.  排放标签', dp_s8:'8.  排放控制技术',
    dp_s9:'9.  蒸发气体及窜气', dp_s10:'10. 同一车种（发动机）',
    dp_s11:'11. 试验车辆', dp_s12:'12. 校准信息及事后确定信息提交协议', dp_s13:'13. 其他',
    dp_1_1_lbl:'1.1. 认证对象车辆开发背景及特性',
    dp_1_2_lbl:'1.2. 排放·噪音新技术',
    dp_1_3_lbl:'1.3. 开发目标（进口车可用外国认证成绩代替）',
    dp_1_4_lbl:'1.4. 认证对象车辆规格',
    dp_2_1_lbl:'2.1. 保密申请',
    dp_3_lbl:'3.1. 认证试验燃料',
    dp_5_1_lbl:'5.1. 排放测试', dp_5_2_lbl:'5.2. 里程积累', dp_5_3_lbl:'5.3. 噪音测试',
    dp_6_1_lbl:'6.1. 试验车辆维修计划',
    dp_6_2_lbl:'6.2. 对购车者的推荐维修', dp_6_3_lbl:'6.3. 保修说明',
    dp_7_1_lbl:'7.1. 样本', dp_7_2_lbl:'7.2. 粘贴位置等',
    dp_8_1_lbl:'8.1.  燃料系统', dp_8_2_lbl:'8.2.  进排气装置',
    dp_img_hint:'点击或拖拽图片',
    dp_img_hint2:'结构图图片点击或拖拽',
    dp_diagram_attach:'附结构图:',
    dp_toc_num:'编号', dp_toc_item:'项目',
    dp_toc_writeno:'文件编号', dp_toc_order:'顺序', dp_toc_see_below:'见下方目录',
    dp_toc_title:'目 录',
    dp_print_title:'目录 - 认证所需详细计划书类',
    dp_toc_1:'认证介绍', dp_toc_1_1:'开发背景及特性',
    dp_toc_1_2:'排放·噪音新技术', dp_toc_1_3:'开发目标',
    dp_toc_1_4:'车辆规格', dp_toc_2:'保密事项', dp_toc_2_1:'保密申请',
    dp_toc_3:'认证试验燃料', dp_toc_4:'试验设施及排放气体·噪音测量设备',
    dp_toc_5:'试验程序', dp_toc_5_1:'排放测试', dp_toc_5_2:'里程积累',
    dp_toc_5_3:'噪音测试', dp_toc_6:'维修及保修',
    dp_toc_6_1:'试验车辆维修计划',
    dp_toc_6_2:'对购车者的推荐维修', dp_toc_6_3:'保修说明',
    dp_toc_7:'排放标签', dp_toc_7_1:'样本', dp_toc_7_2:'粘贴位置等',
    dp_toc_8:'排放控制技术', dp_toc_8_1:'燃料系统', dp_toc_8_2:'进排气装置',
    dp_toc_8_3:'曲轴箱控制装置', dp_toc_8_4:'发动机', dp_toc_8_5:'变速器',
    dp_toc_8_6:'催化转换系统', dp_toc_8_7:'EGR装置',
    dp_toc_8_8:'电子控制装置', dp_toc_8_9:'其他排放控制装置',
    dp_toc_8_10:'传感变量对控制变量', dp_toc_8_11:'零件清单',
    dp_toc_8_12:'SCR性能及原理说明',
    dp_toc_8_13:'SCR用尿素溶液成分分析结果',
    dp_toc_8_14:'电动汽车控制装置',
    dp_toc_9:'蒸发气体及窜气', dp_toc_9_1:'蒸发控制装置说明',
    dp_toc_9_2:'控制装置结构图等', dp_toc_10:'同一车种（发动机）', dp_toc_10_1:'同一车种说明',
    dp_toc_11:'试验车辆', dp_toc_11_1:'试验车辆选定',
    dp_toc_11_2:'耐久性试验车辆选定依据', dp_toc_11_3:'排放试验车辆选定依据',
    dp_toc_11_4:'噪音试验车辆选定依据',
    dp_toc_12:'校准信息及事后确定信息提交协议', dp_toc_13:'其他',
  },
};
// LANG_DICT 헬퍼: 현재 언어로 라벨 반환 (fallback: ko)
function LL(key) {
  return (LANG_DICT[currentLang]||LANG_DICT.ko)[key] || (LANG_DICT.ko[key] || key);
}
function PH(key) {
  const phKey = 'ph_'+key;
  return (LANG_DICT[currentLang]||LANG_DICT.ko)[phKey] || (LANG_DICT.ko[phKey] || '');
}


// FORM_META에서 현재 언어 기준 title 반환
function getFormTitle(m) { return LL(m.titleKey) || m.titleKey; }
// CERT_LABEL / STATUS_LABEL 은 현재 언어에 따라 동적으로 반환
function CERT_LABEL_FN()   { return { basic:LL('cert_basic'), change:LL('cert_change'), report:LL('cert_report') }; }
function STATUS_LABEL_FN() { return { draft:LL('status_draft'), in_progress:LL('status_inprogress'), completed:LL('status_completed') }; }
// 하위 호환: CERT_LABEL[x] → getCertLabel(x)
function getCertLabel(type)   { return CERT_LABEL_FN()[type]   || type; }
function getStatusLabel(type) { return STATUS_LABEL_FN()[type] || type; }
// 배지 클래스는 언어 무관
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
      <div style="font-size:10pt;font-weight:700;color:var(--c-text);">\${esc(currentUser.company_name)}</div>
      <div style="font-size:10pt;color:var(--c-text3);">@\${esc(currentUser.username)}</div>
    </div>
    <div style="width:1px;height:24px;background:var(--c-border);"></div>
    <button class="btn btn-ghost btn-sm" onclick="showChangePwModal()" title="비밀번호 변경">
      <i class="fas fa-key"></i>
    </button>
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
  // ── 대시보드 UI 텍스트 갱신 (언어 전환 대응) ──
  const setT = (id,v) => { const el=document.getElementById(id); if(el) el.textContent=v; };
  const setH = (id,v) => { const el=document.getElementById(id); if(el) el.innerHTML=v; };
  setT('dash-title',       LL('dash_title'));
  setT('stat-total-lbl',   LL('stat_total_lbl'));
  setT('stat-prog-lbl',    LL('stat_prog_lbl'));
  setT('stat-done-lbl',    LL('stat_done_lbl'));
  setT('stat-draft-lbl',   LL('stat_draft_lbl'));
  setT('empty-title',      LL('empty_title'));
  setH('empty-desc',       LL('empty_desc'));
  const btnNew   = document.getElementById('btn-new-appl');
  if (btnNew)   btnNew.innerHTML   = '<i class="fas fa-plus"></i>' + LL('btn_new_appl');
  const btnFirst = document.getElementById('btn-first-appl');
  if (btnFirst) btnFirst.innerHTML = '<i class="fas fa-plus"></i>' + LL('btn_first_appl');

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
  // 신청서별 언어에 맞게 라벨을 반환하는 헬퍼
  const localeMap = { ko:'ko-KR', en:'en-US', ja:'ja-JP', zh:'zh-CN' };
  const certLabelFor   = (lang,type) => (LANG_DICT[lang]||LANG_DICT.ko)['cert_'+type]   || (LANG_DICT.ko['cert_'+type]||type);
  const statusLabelFor = (lang,st)   => { const k={draft:'status_draft',in_progress:'status_inprogress',completed:'status_completed'}[st]||st; return (LANG_DICT[lang]||LANG_DICT.ko)[k]||(LANG_DICT.ko[k]||st); };
  const modifiedFor    = (lang)      => (LANG_DICT[lang]||LANG_DICT.ko)['meta_modified'] || (LANG_DICT.ko['meta_modified']||'수정');
  listEl.innerHTML = currentApplications.map(a => {
    const lang    = (a.lang && ['ko','en','ja','zh'].includes(a.lang)) ? a.lang : 'ko';
    const locale  = localeMap[lang] || 'ko-KR';
    const done_f  = a.completed_forms || 0;
    const total_f = a.total_forms || 10;
    const pct     = Math.round(done_f/total_f*100);
    const date    = new Date(a.updated_at).toLocaleDateString(locale,{month:'short',day:'numeric'});
    const yearSfx = lang==='ko' ? '년' : lang==='ja' ? '年' : '';
    const metaStr = [a.importer,a.cert_year?(a.cert_year+yearSfx):'',a.displacement?(a.displacement+'cc'):''].filter(Boolean).join(' ');
    const certBadge = { basic:'badge-blue', change:'badge-violet', report:'badge-yellow' }[a.cert_type] || 'badge-gray';
    return \`
      <div class="app-item">
        <div class="app-item-icon"><i class="fas fa-file-alt"></i></div>
        <div class="app-item-body">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap;">
            <span class="badge \${certBadge}">\${certLabelFor(lang,a.cert_type)}</span>
            <span class="badge \${STATUS_BADGE[a.status]||'badge-gray'}">\${statusLabelFor(lang,a.status)}</span>
          </div>
          <div class="app-item-title">\${esc(a.title)}</div>
          <div class="app-item-meta">\${esc(metaStr)} &nbsp;·&nbsp; \${date} \${modifiedFor(lang)}</div>
          <div style="display:flex;align-items:center;gap:10px;">
            <div class="progress-track" style="flex:1;height:4px;">
              <div class="progress-fill" style="height:4px;background:var(--grad-accent);width:\${pct}%;"></div>
            </div>
            <span style="font-size:10pt;color:var(--c-text3);flex-shrink:0;">\${done_f}/\${total_f}</span>
          </div>
        </div>
        <div class="app-item-actions">
          <button class="btn btn-primary btn-sm" onclick="openApplication(\${a.id})">
            <i class="fas fa-edit"></i>\${(LANG_DICT[lang]||LANG_DICT.ko)['btn_write']||LL('btn_write')}
          </button>
          <button class="btn btn-danger btn-sm btn-icon" onclick="deleteApplication(event,\${a.id})" title="\${(LANG_DICT[lang]||LANG_DICT.ko)['btn_delete']||LL('btn_delete')}">
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
    // 저장된 언어 복원
    if (data.application.lang && ['ko','en','ja','zh'].includes(data.application.lang)) {
      currentLang = data.application.lang;
    } else {
      currentLang = 'ko';
    }
    renderApplicationPage(); showPage('page-application');
  } catch { showToast('네트워크 오류','error'); }
}

function renderApplicationPage() {
  const a = currentApplication;
  // ── 언어 헬퍼를 맨 먼저 설정 ──
  const lang = (a?.lang && ['ko','en','ja','zh'].includes(a.lang)) ? a.lang : 'ko';
  const ld = LANG_DICT[lang] || LANG_DICT.ko;
  const lt = k => ld[k] || (LANG_DICT.ko[k] || k);
  // ── breadcrumb 홈 버튼 ──
  const btnHomeAppl = document.getElementById('btn-breadcrumb-home-appl');
  if (btnHomeAppl) btnHomeAppl.innerHTML = '<i class="fas fa-home"></i> ' + lt('dash_title');
  document.getElementById('appl-breadcrumb').textContent = a.title;
  // ── 배지: 인증 구분 / 상태 ──
  const certBadge  = { basic:'badge-blue', change:'badge-violet', report:'badge-yellow' }[a.cert_type]||'badge-gray';
  document.getElementById('appl-cert-badge').className   = 'badge ' + certBadge;
  document.getElementById('appl-cert-badge').textContent = lt('cert_'+a.cert_type) || getCertLabel(a.cert_type);
  const sb = document.getElementById('appl-status-badge');
  sb.className   = 'badge ' + (STATUS_BADGE[a.status]||'badge-gray');
  const statusKey = {draft:'status_draft',in_progress:'status_inprogress',completed:'status_completed'}[a.status]||a.status;
  sb.textContent = lt(statusKey) || getStatusLabel(a.status);
  // ── 제목 / 메타 ──
  document.getElementById('appl-title').textContent = a.title;
  const langSel = document.getElementById('appl-lang-sel');
  if (langSel) langSel.value = lang;
  const yearSfx = lang==='ko'?'년':lang==='ja'?'年':'';
  document.getElementById('appl-meta').textContent  = [a.importer,a.cert_year?a.cert_year+yearSfx:'',a.displacement?a.displacement+'cc':''].filter(Boolean).join(' · ');
  const done  = currentForms.filter(f=>f.completed).length;
  const total = currentForms.length;
  const pct   = total ? Math.round(done/total*100) : 0;
  document.getElementById('appl-progress-pct').textContent = pct + '%';
  document.getElementById('appl-progress-bar').style.width = pct + '%';
  const formsGrid = document.getElementById('forms-grid');
  formsGrid.innerHTML = \`
    <div class="forms-grid-head">
      <div style="width:48px;text-align:center;">\${lt('form_col_no')}</div>
      <div>\${lt('form_col_name')}</div>
      <div style="width:90px;text-align:center;">\${lt('form_col_status')}</div>
      <div style="width:44px;text-align:center;"></div>
    </div>
    <div class="forms-grid-body">\${FORM_META.map((m,i) => {
      const fd    = currentForms.find(f=>f.form_type===m.type);
      const isDone = !!fd?.completed;
      const title  = lt(m.titleKey);
      return \`
        <div class="form-card \${isDone?'done':''}" onclick="openForm('\${m.type}')">
          <div class="fc-cell fc-num">\${i+1}</div>
          <div class="fc-cell fc-main">
            <div class="fc-main-inner">
              <div class="form-card-icon" style="background:\${isDone?'rgba(0,200,150,.12)':m.bg};color:\${isDone?'var(--c-success)':m.color};">
                <i class="fas \${m.icon}"></i>
              </div>
              <span class="form-card-name">\${title}</span>
            </div>
          </div>
          <div class="fc-cell fc-status">
            \${isDone
              ? \`<span class="badge badge-green" style="font-size:9pt;"><i class="fas fa-check" style="margin-right:2px;"></i>\${lt('form_status_done')}</span>\`
              : \`<span class="badge badge-gray" style="font-size:9pt;">\${lt('form_status_todo')}</span>\`
            }
          </div>
          <div class="fc-cell fc-action"><i class="fas fa-chevron-right form-card-chevron"></i></div>
        </div>
      \`;
    }).join('')}</div>
  \`;
  // 신청서 상세 페이지 UI 텍스트도 언어에 맞게 갱신
  const setT2 = (id,v) => { const el=document.getElementById(id); if(el) el.textContent=v; };
  const setH2 = (id,v) => { const el=document.getElementById(id); if(el) el.innerHTML=v; };
  setT2('forms-section-title-el', lt('forms_section_title'));
  setT2('appl-pct-label-el',      lt('appl_pct_label'));
  const btnBack = document.getElementById('btn-back-list');
  if (btnBack) btnBack.innerHTML = '<i class="fas fa-arrow-left"></i>' + lt('btn_back_list');
  const btnPrint = document.getElementById('btn-print');
  if (btnPrint) btnPrint.innerHTML = '<i class="fas fa-print"></i>' + lt('btn_print');
  const btnSaveAll = document.getElementById('btn-save-all');
  if (btnSaveAll) btnSaveAll.innerHTML = '<i class="fas fa-save"></i>' + lt('btn_save_all');
}

// ================================================================
// 서류 폼
// ================================================================
// 서류 폼 → 신청서 상세로 돌아가기
function goBackToApplication() {
  if (currentApplicationId) {
    openApplication(currentApplicationId);
  } else {
    showDashboard();
  }
}

async function openForm(formType) {
  currentFormType = formType;
  const meta   = FORM_META.find(m=>m.type===formType);
  const fd     = currentForms.find(f=>f.form_type===formType);
  let saved = {};
  try { saved = JSON.parse(fd?.data||'{}'); } catch {}
  const _fLang = (currentApplication?.lang && ['ko','en','ja','zh'].includes(currentApplication.lang)) ? currentApplication.lang : 'ko';
  const _fLd   = LANG_DICT[_fLang] || LANG_DICT.ko;
  const _fLt   = k => _fLd[k] || (LANG_DICT.ko[k] || k);
  const btnHomeForm = document.getElementById('btn-breadcrumb-home-form');
  if (btnHomeForm) btnHomeForm.innerHTML = '<i class="fas fa-home"></i> ' + _fLt('dash_title');
  const link = document.getElementById('form-appl-link');
  link.textContent = currentApplication.title;
  link.onclick = () => openApplication(currentApplicationId);
  const formTitle = getFormTitle(meta);
  document.getElementById('form-breadcrumb').textContent = formTitle;
  document.getElementById('form-title').textContent      = formTitle;
  document.getElementById('form-subtitle').textContent   = _fLt('cert_'+currentApplication.cert_type)+' · '+currentApplication.title;
  const chk = document.getElementById('form-completed-chk');
  chk.checked = !!fd?.completed;
  updateCompleteCard();
  document.getElementById('form-content').innerHTML = buildFormHTML(formType, saved);
  showPage('page-form');
  // auto-grow 초기화 (input[type=text] → textarea 자동 교체)
  setTimeout(() => initAutoGrow(document.getElementById('form-content')), 50);
  // QR 코드 비동기 생성 (폼 렌더 직후)
  setTimeout(() => generateFormQR(formType, formTitle), 100);
  // obd_operation 첨부파일 기능 초기화
  if (formType === 'obd_operation') setTimeout(() => initObdAttach(), 150);
  // noise_test 첨부파일 기능 초기화
  if (formType === 'noise_test') setTimeout(() => initNoiseAttach(), 150);
  // emission_test 첨부파일 기능 초기화
  if (formType === 'emission_test') setTimeout(() => initEmissionAttach(), 150);
  // evap_test 첨부파일 기능 초기화
  if (formType === 'evap_test') setTimeout(() => initEvapAttach(), 150);
  // emission_noise 복합 입력 필드 초기화
  if (formType === 'emission_noise') setTimeout(() => initEnFields(), 150);
  // obd_config 이미지 드롭존 초기화
  if (formType === 'obd_config') setTimeout(() => initObdImgDrops(), 150);
  // detail_plan 이미지 첨부 복원 (저장된 이미지 썸네일 재표시)
  // detail_plan 이미지 드롭존 복원 (dp-drop 방식)
  if (formType === 'detail_plan') setTimeout(() => {
    if (typeof window.dpRestoreAll === 'function') window.dpRestoreAll();
  }, 200);
  // 목차인쇄 버튼: detail_plan 폼에서만 표시
  const tocBtn = document.getElementById('btn-toc-print');
  if (tocBtn) tocBtn.style.display = (formType === 'detail_plan') ? '' : 'none';
}

// ── Auto-grow: input[type=text] → textarea 동적 교체 ──────────────
function initAutoGrow(container) {
  if (!container) return;

  // 소형 고정 너비 입력 제외 판별 (px 단위 80px 미만 고정폭만 제외)
  function isSmallFixed(inp) {
    const w = inp.style.width || '';
    if (!w) return false;
    if (w.includes('%') || w.includes('calc') || w.includes('em') || w.includes('rem')) return false;
    const wVal = parseInt(w);
    return wVal > 0 && wVal < 80;
  }

  // input → textarea 교체 공통 함수
  function replaceWithTextarea(inp) {
    if (isSmallFixed(inp)) return;
    const ta = document.createElement('textarea');
    // data-field 복사
    if (inp.dataset.field) ta.dataset.field = inp.dataset.field;
    // 클래스 복사 + auto-grow 추가
    ta.className = inp.className + ' auto-grow';
    ta.placeholder = inp.placeholder || '';
    ta.value = inp.value || '';
    // 스타일 복사
    const inpStyle = inp.getAttribute('style') || '';
    ta.setAttribute('style', inpStyle);
    ta.rows = 1;
    // 높이 자동 조정
    function adjustHeight() {
      ta.style.height = 'auto';
      ta.style.height = ta.scrollHeight + 'px';
    }
    ta.addEventListener('input', adjustHeight);
    ta.addEventListener('change', adjustHeight);
    setTimeout(adjustHeight, 0);
    inp.parentNode.replaceChild(ta, inp);
  }

  // 1) data-field 있는 일반 input[type=text] (g-inp, sv-inp 등)
  // ev-inp, em-inp는 표 구조 유지를 위해 textarea 교체 제외
  container.querySelectorAll('input[type="text"][data-field]:not(.ev-inp):not(.em-inp)').forEach(replaceWithTextarea);

  // 2) cf-item-inp (확인서 항목 입력)
  container.querySelectorAll('input[type="text"].cf-item-inp').forEach(replaceWithTextarea);

  // 3) cf-warranty-subject-inp (보증내용 주어)
  container.querySelectorAll('input[type="text"].cf-warranty-subject-inp').forEach(replaceWithTextarea);

  // 4) cf-header-inp 삭제: en-inp 공유 클래스로 통일 (en-inp는 헤더 싨청용 단일행 input이므로 replaceWithTextarea 불필요)

  // 5) cf-sign-inp 제외 (서명란 - 너무 작아 자동 확장 불필요)

  // 6) 기존 textarea[data-field] (rows 고정된 것)도 auto-grow 적용
  container.querySelectorAll('textarea[data-field], textarea.cf-item-inp, textarea.cf-warranty-subject-inp').forEach(ta => {
    if (ta.classList.contains('auto-grow')) return;
    ta.classList.add('auto-grow');
    ta.style.resize = 'none';
    ta.style.overflow = 'hidden';
    function adjustHeight() {
      ta.style.height = 'auto';
      ta.style.height = ta.scrollHeight + 'px';
    }
    ta.addEventListener('input', adjustHeight);
    ta.addEventListener('change', adjustHeight);
    setTimeout(adjustHeight, 0);
  });
}

// ── QR 코드 생성 및 하단 블록 렌더 ──────────────────────────────
// QR 블록 HTML 생성 헬퍼
function buildQRBlockHTML(qrDivId, formTitle, dt, verifyUrl, pageLabel, shortCode) {
  return \`<div class="qr-footer">
  <div class="qr-footer-left">
    <div class="qr-footer-qr" id="\${qrDivId}"></div>
    <div class="qr-footer-code-label">진위여부코드</div>
    <div class="qr-footer-short-code">\${shortCode||'-'}</div>
  </div>
  <div class="qr-footer-info">
    <div class="qr-footer-title"><i class="fas fa-qrcode"></i>&nbsp;진위여부 확인\${pageLabel ? ' — '+pageLabel : ''}</div>
    <div class="qr-footer-rows">
      서류명 &nbsp;&nbsp;: <span>\${formTitle}</span><br>
      신청서 &nbsp;&nbsp;: <span>\${currentApplication?.title||'-'}</span><br>
      발급일시 &nbsp;: <span>\${dt}</span><br>
      발급기관 &nbsp;: <span>\${currentUser?.company_name||currentUser?.username||'-'}</span><br>
      진위여부코드: <span style="font-family:monospace;font-size:8pt;letter-spacing:.1em;font-weight:800;">\${shortCode||'-'}</span>
    </div>
  </div>
</div>\`;
}

function printWithQR() {
  const wrap = document.getElementById('qr-footer-wrap');

  // 아직 로딩 중이거나 에러 상태면 잠시 기다린 후 인쇄
  if (wrap && wrap.querySelector('.qr-footer-pending')) {
    const formType = currentFormType;
    const meta = FORM_META.find(m=>m.type===formType);
    if (meta) {
      generateFormQR(formType, getFormTitle(meta)).then(() => {
        setTimeout(() => window.print(), 300);
      });
      return;
    }
  }
  window.print();
}

// ── 목차인쇄 (detail_plan 전용) ──────────────────────────────────────────
function printDetailPlanToc() {
  var imp  = ((document.querySelector('[data-field="dp_importer"]')  || {}).value  || (currentApplication && currentApplication.importer    || '')).replace(/</g,'&lt;');
  var cy   = ((document.querySelector('[data-field="dp_cert_year"]') || {}).value  || (currentApplication && currentApplication.cert_year   || '')).replace(/</g,'&lt;');
  var dsp  = ((document.querySelector('[data-field="dp_disp"]')      || {}).value  || (currentApplication && currentApplication.displacement || '')).replace(/</g,'&lt;');
  var fam  = ((document.querySelector('[data-field="dp_fam_code"]')  || {}).value  || (currentApplication && currentApplication.family_code  || '')).replace(/</g,'&lt;');

  var toc = [
    ['1.',    LL('dp_toc_1')],
    ['1.1.',  LL('dp_toc_1_1')],
    ['1.2.',  LL('dp_toc_1_2')],
    ['1.3.',  LL('dp_toc_1_3')],
    ['1.4.',  LL('dp_toc_1_4')],
    ['2.',    LL('dp_toc_2')],
    ['2.1.',  LL('dp_toc_2_1')],
    ['3.',    LL('dp_toc_3')],
    ['4.',    LL('dp_toc_4')],
    ['5.',    LL('dp_toc_5')],
    ['5.1.',  LL('dp_toc_5_1')],
    ['5.2.',  LL('dp_toc_5_2')],
    ['5.3.',  LL('dp_toc_5_3')],
    ['6.',    LL('dp_toc_6')],
    ['6.1.',  LL('dp_toc_6_1')],
    ['6.2.',  LL('dp_toc_6_2')],
    ['6.3.',  LL('dp_toc_6_3')],
    ['7.',    LL('dp_toc_7')],
    ['7.1.',  LL('dp_toc_7_1')],
    ['7.2.',  LL('dp_toc_7_2')],
    ['8.',    LL('dp_toc_8')],
    ['8.1.',  LL('dp_toc_8_1')],
    ['8.2.',  LL('dp_toc_8_2')],
    ['8.3.',  LL('dp_toc_8_3')],
    ['8.4.',  LL('dp_toc_8_4')],
    ['8.5.',  LL('dp_toc_8_5')],
    ['8.6.',  LL('dp_toc_8_6')],
    ['8.7.',  LL('dp_toc_8_7')],
    ['8.8.',  LL('dp_toc_8_8')],
    ['8.9.',  LL('dp_toc_8_9')],
    ['8.10.', LL('dp_toc_8_10')],
    ['8.11',  LL('dp_toc_8_11')],
    ['8.12',  LL('dp_toc_8_12')],
    ['8.13',  LL('dp_toc_8_13')],
    ['8.14',  LL('dp_toc_8_14')],
    ['9.',    LL('dp_toc_9')],
    ['9.1.',  LL('dp_toc_9_1')],
    ['9.2.',  LL('dp_toc_9_2')],
    ['10.',   LL('dp_toc_10')],
    ['10.1.', LL('dp_toc_10_1')],
    ['11.',   LL('dp_toc_11')],
    ['11.1.', LL('dp_toc_11_1')],
    ['11.2.', LL('dp_toc_11_2')],
    ['11.3.', LL('dp_toc_11_3')],
    ['11.4.', LL('dp_toc_11_4')],
    ['12.',   LL('dp_toc_12')],
    ['13.',   LL('dp_toc_13')]
  ];

  var rows = '';
  for (var i = 0; i < toc.length; i++) {
    var no = toc[i][0], title = toc[i][1];
    var isMajor = /^\d+\.$/.test(no.trim());
    var ind = isMajor ? '' : 'padding-left:1.8em;';
    var wt  = isMajor ? 'font-weight:700;' : 'font-weight:400;';
    var bg  = (i % 2 === 0) ? '' : 'background:#f6f9ff;';
    rows += '<tr>'
          + '<td style="padding:3px 8px;border:1px solid #bbb;' + ind + wt + bg + '">' + no + '</td>'
          + '<td style="padding:3px 8px;border:1px solid #bbb;' + ind + wt + bg + '">' + title + '</td>'
          + '</tr>';
  }

  var html = '<!DOCTYPE html>'
    + '<html lang="ko"><head><meta charset="UTF-8">'
    + '<title>'+LL('dp_print_title')+'</title>'
    + '<style>'
    + '@page{size:A4;margin:18mm 20mm 18mm 20mm;}'
    + 'body{font-family:"맑은 고딕","Malgun Gothic",sans-serif;font-size:10pt;color:#111;margin:0;padding:0;}'
    + 'table{width:100%;border-collapse:collapse;margin-bottom:10px;}'
    + 'th{background:#dbe8f8;border:1px solid #aac;padding:4px 8px;font-size:9pt;font-weight:600;text-align:center;}'
    + 'td{border:1px solid #aac;padding:4px 8px;font-size:9pt;text-align:center;}'
    + '.tag{font-size:9pt;color:#555;margin-bottom:2px;}'
    + '.main-title{font-size:14pt;font-weight:800;text-align:center;margin:8px 0 14px;}'
    + '.sec-title{font-size:10pt;font-weight:700;margin:0 0 6px;}'
    + '@media print{body{-webkit-print-color-adjust:exact;print-color-adjust:exact;}}'
    + '</style></head><body>'
    + '<table><thead><tr><th>'+LL('dp_h_importer')+'</th><th>'+LL('dp_h_certyear')+'</th><th>'+LL('dp_h_disp')+'</th><th>'+LL('dp_h_famcode')+'</th></tr></thead>'
    + '<tbody><tr>'
    + '<td>' + (imp||'&nbsp;') + '</td>'
    + '<td>' + (cy ||'&nbsp;') + '</td>'
    + '<td>' + (dsp||'&nbsp;') + '</td>'
    + '<td>' + (fam||'&nbsp;') + '</td>'
    + '</tr></tbody></table>'
    + '<div class="tag">'+LL('dp_doc_tag')+'</div>'
    + '<div class="main-title">'+LL('dp_doc_title')+'</div>'
    + '<table><colgroup><col style="width:18%;"><col style="width:82%;"></colgroup>'
    + '<thead><tr>'
    + '<th style="background:#dbe8f8;border:1px solid #aac;padding:4px 8px;font-size:9pt;">'+LL('dp_toc_num')+'</th>'
    + '<th style="background:#dbe8f8;border:1px solid #aac;padding:4px 8px;font-size:9pt;">'+LL('dp_toc_item')+'</th>'
    + '</tr></thead>'
    + '<tbody>' + rows + '</tbody></table>'
    + '<script>window.onload=function(){window.print();};<' + '/script>'
    + '</body></html>';

  var w = window.open('', '_blank', 'width=800,height=900');
  if (!w) { alert('팝업이 차단되었습니다. 팝업 허용 후 다시 시도하세요.'); return; }
  w.document.open();
  w.document.write(html);
  w.document.close();
}

async function generateFormQR(formType, formTitle) {
  // qr-footer-wrap div 수집 (단일)
  const allWraps = [];
  const mainWrap = document.getElementById('qr-footer-wrap');
  if (mainWrap) allWraps.push({ el: mainWrap, pageLabel: '' });

  if (allWraps.length === 0) return;

  // 로딩 표시
  allWraps.forEach(({el}) => {
    el.innerHTML = '<div class="qr-footer-pending"><i class="fas fa-spinner fa-spin"></i> 진위확인 코드 생성 중...</div>';
  });

  // 1) 서버에서 서명된 토큰 발급
  let token = null, issuedAt = null;
  try {
    const res = await api('/api/qr/issue', {
      method:'POST',
      body: JSON.stringify({
        application_id: currentApplicationId,
        form_type     : formType,
        form_title    : formTitle
      })
    });
    if (res.ok) {
      const d  = await res.json();
      token    = d.token;
      issuedAt = d.issued_at;
    }
  } catch {}

  if (!token) {
    allWraps.forEach(({el}) => {
      el.innerHTML = '<div class="qr-footer-pending">⚠ QR 코드를 생성하려면 로그인 상태를 확인하세요.</div>';
    });
    return;
  }

  // 2) 검증 URL
  const verifyUrl = window.location.origin + '/verify?t=' + encodeURIComponent(token);
  const dt = issuedAt ? new Date(issuedAt).toLocaleString('ko-KR') : '-';

  // 3) 각 wrap에 QR 블록 렌더링
  // 토큰 앞 8자리를 진위여부코드로 사용
  const shortCode = token ? token.replace(/[^A-Za-z0-9]/g,'').slice(0,8).toUpperCase() : '';
  allWraps.forEach(({el, pageLabel}, idx) => {
    const qrDivId = 'qr-canvas-' + formType + (idx > 0 ? '-p' + idx : '');
    el.innerHTML = buildQRBlockHTML(qrDivId, formTitle, dt, verifyUrl, pageLabel, shortCode);
    // 4) QRCode.js로 QR 이미지 생성
    try {
      new QRCode(document.getElementById(qrDivId), {
        text      : verifyUrl,
        width     : 80,
        height    : 80,
        colorDark : '#1a2342',
        colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.M
      });
    } catch (e) {
      const qrEl = document.getElementById(qrDivId);
      if (qrEl) qrEl.innerHTML = '<div style="font-size:7pt;color:#888;">QR생성실패</div>';
    }
  });
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
// 신청서 상세 – 모두 저장 / 인쇄
// ================================================================
async function saveAllForms() {
  const btn = document.getElementById('btn-save-all');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>' + LL('saving') + '...';
  let successCount = 0;
  let failCount = 0;
  try {
    for (const form of currentForms) {
      try {
        let data = {};
        try { data = JSON.parse(form.data || '{}'); } catch {}
        const res = await api(
          '/api/applications/' + currentApplicationId + '/forms/' + form.form_type,
          { method: 'PUT', body: JSON.stringify({ data, completed: !!form.completed }) }
        );
        if (res.ok) successCount++;
        else failCount++;
      } catch { failCount++; }
    }
    if (failCount === 0) {
      showToast(\`\${LL('save_all_ok_prefix')}\${successCount}\${LL('save_all_ok_suffix')}\`, 'success');
    } else {
      showToast(\`\${successCount}\${LL('save_partial_ok')}, \${failCount}\${LL('save_partial_fail')}\`, 'error');
    }
    // 최신 데이터 다시 로드
    await openApplication(currentApplicationId);
  } catch {
    showToast(LL('save_error'), 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-save"></i>' + LL('btn_save_all');
  }
}

function printApplicationSummary() {
  window.print();
}

// ================================================================
// 신청서 생성/삭제
// ================================================================
function showNewAppModal() {
  ['new-title','new-importer','new-cert-year','new-displacement','new-family-code'].forEach(id=>{
    const el=document.getElementById(id); if(el)el.value='';
  });
  document.getElementById('new-cert-type').value = 'basic';
  document.getElementById('new-lang').value = currentLang || 'ko';
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
function onNewLangChange() {
  currentLang = document.getElementById('new-lang').value;
}

// 신청서 상세 페이지에서 언어 변경 → DB 저장 + 폼 재렌더
async function onApplLangChange(newLang) {
  if (!currentApplicationId || !['ko','en','ja','zh'].includes(newLang)) return;
  currentLang = newLang;
  if (currentApplication) currentApplication.lang = newLang;
  try {
    const token = localStorage.getItem('auth_token');
    await fetch('/api/applications/' + currentApplicationId, {
      method:'PUT',
      headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
      body: JSON.stringify({
        title: currentApplication.title,
        importer: currentApplication.importer,
        cert_year: currentApplication.cert_year,
        displacement: currentApplication.displacement,
        family_code: currentApplication.family_code,
        lang: newLang,
        status: currentApplication.status
      })
    });
  } catch(e) { console.warn('lang save failed', e); }
  // 현재 열려있는 폼이 있으면 재렌더
  if (currentFormType) {
    const fd = currentForms.find(f=>f.form_type===currentFormType);
    let saved = {};
    try { saved = JSON.parse(fd?.data||'{}'); } catch {}
    document.getElementById('form-content').innerHTML = buildFormHTML(currentFormType, saved);
    setTimeout(() => initAutoGrow(document.getElementById('form-content')), 50);
    setTimeout(() => generateFormQR(currentFormType, getFormTitle(FORM_META.find(m=>m.type===currentFormType))), 100);
    if (currentFormType==='emission_noise') setTimeout(()=>initEnFields(),150);
    if (currentFormType==='obd_config') setTimeout(()=>initObdImgDrops(),150);
    if (currentFormType==='detail_plan') setTimeout(()=>{ if(typeof window.dpRestoreAll==='function') window.dpRestoreAll(); },200);
  }
}
document.getElementById('modal-new-app').addEventListener('click', function(e){ if(e.target===this)closeNewAppModal(); });

async function createApplication() {
  const title       = document.getElementById('new-title').value.trim();
  const cert_type   = document.getElementById('new-cert-type').value;
  const lang        = document.getElementById('new-lang').value;
  const importer    = document.getElementById('new-importer').value.trim();
  const cert_year   = document.getElementById('new-cert-year').value.trim();
  const displacement= document.getElementById('new-displacement').value.trim();
  const family_code = document.getElementById('new-family-code').value.trim();
  const prev_cert   = document.getElementById('new-prev-cert')?.value.trim()||'';
  const errEl       = document.getElementById('modal-error');
  errEl.style.display = 'none';
  if (!title) { errEl.textContent='신청 제목을 입력하세요.'; errEl.style.display='block'; document.getElementById('new-title').focus(); return; }
  if ((cert_type==='change'||cert_type==='report')&&!prev_cert) {
    errEl.textContent='기존 인증번호를 입력하세요.'; errEl.style.display='block'; return; }
  const btn = document.getElementById('create-btn');
  btn.disabled=true; btn.innerHTML='<div class="spinner"></div>생성 중...';
  try {
    const res  = await api('/api/applications',{method:'POST',body:JSON.stringify({
      title, cert_type, lang, importer, cert_year, displacement, family_code, prev_cert_number:prev_cert
    })});
    const data = await res.json();
    if (!res.ok) { errEl.textContent=data.error||'생성 실패'; errEl.style.display='block'; return; }
    // 선택한 언어를 전역 상태에 반영
    currentLang = lang;
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
  // ── 신청서에 저장된 lang 기준으로 언어 헬퍼 설정 (currentLang 상태에 무관하게 일관성 보장) ──
  const _bLang = (currentApplication?.lang && ['ko','en','ja','zh'].includes(currentApplication.lang))
    ? currentApplication.lang : 'ko';
  const _bLd = LANG_DICT[_bLang] || LANG_DICT.ko;
  // buildFormHTML 전용 번역 헬퍼 (전역 LL 대신 사용)
  const BL = k => _bLd[k] || (LANG_DICT.ko[k] || k);
  // cert_type → 구분 기본값: 저장값이 없으면 현재 신청서의 cert_type을 해당 언어 라벨로 자동 채움
  const _certDefault = BL('cert_'+(currentApplication?.cert_type||'')) || getCertLabel(currentApplication?.cert_type) || '';
  const v   = (k,def='') => {
    // ── 신청서 메타 자동채움 우선 적용 (저장값이 빈 문자열이어도 메타값 사용) ──
    // detail_plan 헤더 4개 필드
    if (k==='dp_importer')  { const mv=currentApplication?.importer;    if(mv) return mv; }
    if (k==='dp_cert_year') { const mv=currentApplication?.cert_year;   if(mv) return mv; }
    if (k==='dp_disp')      { const mv=currentApplication?.displacement; if(mv) return mv; }
    if (k==='dp_fam_code')  { const mv=currentApplication?.family_code;  if(mv) return mv; }
    // 나머지 폼 공통 메타 필드도 동일하게 우선 적용
    if (k==='importer')     { const mv=currentApplication?.importer;    if(mv) return mv; }
    if (k==='cert_year')    { const mv=currentApplication?.cert_year;   if(mv) return mv; }
    if (k==='displacement') { const mv=currentApplication?.displacement; if(mv) return mv; }
    if (k==='family_code')  { const mv=currentApplication?.family_code;  if(mv) return mv; }
    if (/^(en|em|ev|nt)_importer$/.test(k))  { const mv=currentApplication?.importer;    if(mv) return mv; }
    if (/^(en|em|ev|nt)_cert_year$/.test(k)) { const mv=currentApplication?.cert_year;   if(mv) return mv; }
    if (/^(en|em|ev)_disp$/.test(k))         { const mv=currentApplication?.displacement; if(mv) return mv; }
    if (/^(en|em|ev|nt)_fam_code$/.test(k))  { const mv=currentApplication?.family_code;  if(mv) return mv; }
    if (k==='obd_header_importer') { const mv=currentApplication?.importer;    if(mv) return mv; }
    if (k==='obd_header_year')     { const mv=currentApplication?.cert_year;   if(mv) return mv; }
    if (k==='obd_header_cc')       { const mv=currentApplication?.displacement; if(mv) return mv; }
    if (k==='obd_header_code')     { const mv=currentApplication?.family_code;  if(mv) return mv; }
    if (k==='displacement_cc')     { const mv=currentApplication?.displacement; if(mv) return mv; }
    if (k==='oo_importer')  { const mv=currentApplication?.importer;    if(mv) return mv; }
    if (k==='oo_cert_year') { const mv=currentApplication?.cert_year;   if(mv) return mv; }
    if (k==='oo_disp')      { const mv=currentApplication?.displacement; if(mv) return mv; }
    if (k==='oo_fam_code')  { const mv=currentApplication?.family_code;  if(mv) return mv; }
    // ── 저장값 반환 (위 메타 우선 처리 후) ──
    if (saved[k]!==undefined) return saved[k];
    if (k==='appl_div') return _certDefault;
    return def;
  };
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

  if (formType==='summary') return \`
<style>
/* ══════════ summary 전용 스타일 ══════════ */
.en-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
  background:#fff;
  color:#111;
  border-radius:8px;
}
.en-doc-tag { font-size:8.5pt; font-weight:700; color:#444; margin:10px 0 4px; }
.en-main-title {
  font-size:13pt; font-weight:900; text-align:center;
  margin:4px 0 14px; letter-spacing:.03em; color:#111;
}
.en-tbl {
  width:100%; border-collapse:collapse;
  font-size:8.5pt; margin-bottom:0;
}
.en-tbl th, .en-tbl td {
  border:1px solid #888;
  padding:3px 5px;
  vertical-align:middle;
  color:#111;
}
.en-sec-th {
  background:#d6e4f7;
  font-weight:700; text-align:left;
  padding:4px 6px; font-size:8.5pt; color:#111;
}
.en-sub-th {
  background:#eef3fa;
  font-weight:700; text-align:left;
  padding:3px 6px; font-size:8.5pt; color:#111;
}
.en-th {
  background:#eef3fa;
  font-weight:600; text-align:center;
  font-size:8pt; color:#111;
}
.en-lbl {
  background:#f5f8ff;
  font-weight:600; color:#111;
  vertical-align:middle;
}
/* ── 복합 입력 필드 (텍스트 + 이미지) ── */
.en-field {
  display:flex; flex-direction:column; gap:4px;
  padding:3px 4px; box-sizing:border-box; width:100%;
}
.en-field-text {
  width:100%; font-size:8.5pt; font-family:inherit;
  border:none; background:transparent; padding:2px 0;
  box-sizing:border-box; resize:vertical; color:#111;
  min-height:36px; line-height:1.5;
}
.en-field-text::placeholder { color:#aaa; }
.en-field-text:focus { outline:none; border-bottom:1px dashed #4e90d8; }
/* 이미지 드롭존 */
.en-drop {
  border:1.5px dashed #b0c4de;
  border-radius:5px;
  background:#f8faff;
  padding:6px 8px;
  cursor:pointer;
  transition:border-color .15s, background .15s;
  position:relative;
  min-height:36px;
}
.en-drop:hover { border-color:#4e90d8; background:#eef3fa; }
.en-drop.drag-over { border-color:#2563eb; background:#dbeafe; }
.en-drop-hint {
  color:#aaa; font-size:7.5pt; text-align:center;
  pointer-events:none; user-select:none;
  display:flex; align-items:center; justify-content:center; gap:4px;
}
.en-drop input[type=file] { display:none; }
/* 이미지 미리보기 목록 */
.en-img-list {
  display:flex; flex-wrap:wrap; gap:6px; margin-top:4px;
}
.en-img-item {
  position:relative; display:inline-block;
}
.en-img-item img {
  max-width:140px; max-height:100px;
  border:1px solid #ccc; border-radius:3px;
  display:block; object-fit:contain; background:#fff;
}
.en-img-item-del {
  position:absolute; top:-6px; right:-6px;
  width:16px; height:16px; border-radius:50%;
  background:#ef4444; color:#fff; font-size:10px;
  display:flex; align-items:center; justify-content:center;
  cursor:pointer; line-height:1; border:none;
  box-shadow:0 1px 3px rgba(0,0,0,.3);
}
.en-img-item-del:hover { background:#dc2626; }
/* 헤더 셀의 텍스트 입력 (수입사 등 단순 1행 셀) */
.en-inp {
  border:none; background:transparent;
  width:100%; font-size:8.5pt;
  font-family:inherit; padding:0 2px;
  box-sizing:border-box; color:#111;
}
.en-inp::placeholder { color:#aaa; }
.en-inp:focus { outline:none; border-bottom:1px solid #4e90d8; }
@media print {
  /* ── 전체 래퍼 ── */
  .en-wrap { background:#fff !important; color:#000 !important; border-radius:0 !important; }

  /* ── 테이블 셀: 내용에 맞춰 높이 자동 확장, 잘림 방지 ── */
  .en-tbl { table-layout:fixed !important; width:100% !important; }
  .en-tbl th, .en-tbl td {
    border:1px solid #333 !important; color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important; overflow-wrap:break-word !important;
  }

  /* ── en-field: 인쇄 시 flex 유지, 높이 자동 ── */
  .en-field { height:auto !important; overflow:visible !important; display:flex !important; flex-direction:column !important; }

  /* ── textarea: 내용 전체 표시, 스크롤 없이 ── */
  textarea.en-field-text {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; min-height:0 !important; max-height:none !important;
    overflow:visible !important; resize:none !important;
    white-space:pre-wrap !important; word-break:break-word !important;
    overflow-wrap:break-word !important;
    display:block !important; box-sizing:border-box !important;
    -webkit-appearance:none !important; appearance:none !important;
    padding:2px 0 !important;
  }

  /* ── 단순 1행 input ── */
  .en-inp {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important;
  }

  /* ── hidden input 완전 숨김 ── */
  input[type=hidden] { display:none !important; }

  /* ── 이미지 드롭존: 테두리/배경 제거, 힌트/삭제버튼 숨김 ── */
  .en-drop {
    border:none !important; background:transparent !important;
    padding:0 !important; min-height:unset !important;
    height:auto !important; overflow:visible !important;
  }
  .en-drop-hint { display:none !important; }
  .en-img-item-del { display:none !important; }
  .en-img-list { gap:4px !important; margin-top:2px !important; }
  .en-img-item img {
    max-width:100% !important; max-height:none !important;
    page-break-inside:avoid;
  }
  /* 이미지가 없는 빈 en-drop은 공간 차지 안 함 */
  .en-drop:not(:has(img)) { display:none !important; }

  /* ── 섹션 헤더 배경색 유지 ── */
  .en-sec-th { background:#d6e4f7 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-sub-th { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-th     { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-lbl    { background:#f5f8ff !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }

  /* ── 페이지 분리 방지 (행 단위) ── */
  .en-tbl tr { page-break-inside:avoid; }
}

.sv-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
}
/* ── 제목 ── */
.sv-title {
  text-align:center;
  font-size:14pt; font-weight:800;
  letter-spacing:.05em;
  padding:14px 10px;
  border:1px solid #888; border-top:none;
}

/* ── 본문 테이블 ── */
.sv-tbl {
  width:100%; border-collapse:collapse;
  border:1px solid #888; border-top:none;
  table-layout:fixed;
}
.sv-tbl th, .sv-tbl td {
  border:1px solid #888;
  vertical-align:middle;
  padding:0;
}
.sv-tbl thead th {
  background:#d8e0f0; font-weight:700;
  text-align:center; font-size:10pt;
  padding:6px 4px;
}
/* 구분열: 11.3%, 항목열: 31.5%, 내용열: 나머지 */
.sv-col-num   { width:11%; }
.sv-col-label { width:31%; }
.sv-col-val   { }

.sv-num {
  text-align:center; font-size:10pt; font-weight:600;
  padding:8px 4px;
  background:#f5f8ff; color:#111;
}
.sv-lbl {
  font-size:10pt; font-weight:500;
  padding:8px 10px; line-height:1.4;
  word-break:keep-all;
  background:#f5f8ff; color:#111;
}
.sv-val {
  padding:5px 10px;
}
.sv-val .sv-inp {
  width:100%; background:transparent;
  border:none; border-bottom:1px solid #ccc;
  color:#111; font-size:10pt;
  padding:4px 2px; outline:none;
}
.sv-val .sv-inp:focus { border-bottom-color:#4e90d8; }
.sv-val .sv-sel {
  width:100%; background:transparent;
  border:1px solid #ccc;
  color:#111; font-size:10pt;
  padding:3px 4px; outline:none;
  border-radius:3px;
}
.sv-val .sv-sel:focus { border-color:#4e90d8; }
.sv-val .sv-ta {
  width:100%; background:transparent;
  border:1px solid #ccc;
  color:#111; font-size:10pt;
  padding:4px 6px; outline:none; resize:vertical;
  border-radius:3px; min-height:52px;
}
.sv-val .sv-ta:focus { border-color:#4e90d8; }

/* 4번 적용기준 구분선 */
.sv-sub-row {
  display:flex; align-items:center; gap:8px;
  padding:5px 10px;
}
.sv-sub-row + .sv-sub-row {
  border-top:1px solid #e0e0e0;
}
.sv-sub-lbl {
  font-size:10pt; color:#555;
  width:56px; flex-shrink:0; font-weight:500;
}

/* 6·7번 대표차량 인라인 레이아웃 (PDF 동일) */
.sv-rep-inline {
  display:flex; align-items:center;
  gap:0; padding:6px 10px;
  flex-wrap:wrap; gap:4px 16px;
}
.sv-rep-item {
  display:flex; align-items:center; gap:4px;
  white-space:nowrap;
}
.sv-rep-item-lbl { font-size:10pt; color:#111; white-space:nowrap; }
.sv-rep-item-inp {
  background:transparent;
  border:none; border-bottom:1px solid #ccc;
  color:#111; font-size:10pt;
  padding:2px 2px; outline:none; min-width:80px;
}
.sv-rep-item-inp:focus { border-bottom-color:#4e90d8; }

/* 8번 보증기간 인라인 */
.sv-warranty-row {
  display:flex; align-items:center; gap:6px;
  padding:5px 10px;
}

@media screen {
  .sv-tbl thead th  { background:#d8e0f0; color:#111; border-color:#888; }
  .sv-tbl th, .sv-tbl td { border-color:#888; }
}

@media print {
  /* ── 전역 페이지 설정 ── */
  @page { size:A4 portrait; margin:18mm 15mm; }
  .no-print  { display:none !important; }
  body       { background:#fff !important; color:#000 !important; }
  -webkit-print-color-adjust: exact;
  print-color-adjust: exact;

  /* ── sv-wrap 전체 ── */
  .sv-wrap {
    font-family:'맑은 고딕','Malgun Gothic','MS Gothic',sans-serif;
    font-size:9pt; color:#000;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }

            /* ── 제목 ── */
  .sv-title {
    font-size:14pt !important; font-weight:900 !important;
    color:#000 !important; background:#fff !important;
    border:1px solid #555 !important; border-top:none !important;
    padding:10px 8px !important; text-align:center !important;
    letter-spacing:.08em !important;
  }

  /* ── 본문 테이블 전체 ── */
  .sv-tbl {
    border:1px solid #555 !important; border-top:none !important;
    border-collapse:collapse !important; width:100% !important;
    table-layout:fixed !important;
  }
  .sv-tbl th, .sv-tbl td {
    border:1px solid #555 !important;
    font-size:9pt !important;
  }
  /* 헤더행 */
  .sv-tbl thead th {
    background:#c8d4ea !important; color:#000 !important;
    font-size:9pt !important; font-weight:700 !important;
    padding:5px 4px !important; text-align:center !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }

  /* 구분 번호 셀 */
  .sv-num {
    text-align:center !important;
    font-size:9pt !important; font-weight:600 !important;
    color:#000 !important;
    background:#f0f3f8 !important;
    padding:7px 2px !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }
  /* 항목 레이블 셀 */
  .sv-lbl {
    font-size:9pt !important; font-weight:500 !important;
    color:#000 !important;
    background:#f0f3f8 !important;
    padding:6px 8px !important; line-height:1.5 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }
  /* 내용 셀 */
  .sv-val { padding:4px 8px !important; }

  /* 내용 셀 내 입력 요소 → 텍스트만 표시 */
  .sv-val .sv-inp,
  .sv-rep-item-inp {
    font-size:9pt !important; color:#000 !important;
    background:transparent !important;
    border:none !important; border-bottom:none !important;
    padding:0 !important; outline:none !important;
    width:auto !important; font-family:inherit !important;
    -webkit-appearance:none; appearance:none;
  }
  .sv-val .sv-sel {
    font-size:9pt !important; color:#000 !important;
    background:transparent !important;
    border:none !important; padding:0 !important;
    -webkit-appearance:none; appearance:none;
    font-family:inherit !important;
  }
  .sv-val .sv-ta {
    font-size:9pt !important; color:#000 !important;
    background:transparent !important; border:none !important;
    padding:0 !important; resize:none !important;
    min-height:auto !important; font-family:inherit !important;
    white-space:pre-wrap; word-break:break-all;
  }

  /* 4번 배출가스/소음 구분 */
  .sv-sub-row { padding:4px 8px !important; }
  .sv-sub-lbl { font-size:9pt !important; color:#000 !important; width:52px !important; }

  /* 6·7번 대표차량 인라인 */
  .sv-rep-inline { padding:4px 8px !important; gap:4px 20px !important; }
  .sv-rep-item-lbl { font-size:9pt !important; color:#000 !important; }

  /* 8번 보증기간 */
  .sv-warranty-row { padding:4px 8px !important; }
  .sv-warranty-row span { font-size:9pt !important; color:#000 !important; }
}
</style>

<div class="en-wrap">
  <!-- ① 상단 헤더 (emission_noise와 동일 구조) -->
  <table class="en-tbl" style="margin-bottom:12px; table-layout:fixed;">
    <colgroup><col style="width:35%;"><col style="width:12%;"><col style="width:13%;"><col style="width:40%;"></colgroup>
    <thead>
      <tr>
        <th class="en-th">\${BL('importer')}</th>
        <th class="en-th">\${BL('cert_year')}</th>
        <th class="en-th">\${BL('displacement')}</th>
        <th class="en-th">\${BL('family_code')}</th>
      </tr>
    </thead>
    <tbody>
      <tr style="height:26px;">
        <td><input data-field="importer"     class="en-inp" type="text" placeholder="\${BL('ph_importer')}"     value="\${E(v('importer'))}"></td>
        <td><input data-field="cert_year"    class="en-inp" type="text" placeholder="\${BL('ph_cert_year')}"   value="\${E(v('cert_year'))}"></td>
        <td><input data-field="displacement" class="en-inp" type="text" placeholder="\${BL('ph_displacement')}" value="\${E(v('displacement'))}"></td>
        <td><input data-field="family_code"  class="en-inp" type="text" placeholder="\${BL('ph_family_code')}"  value="\${E(v('family_code'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- ② 제목 (emission_noise와 동일 구조: doc-tag + main-title) -->
  <div class="en-main-title">\${BL('sv_title')}</div>

  <!-- ③ 본문 테이블 -->
  <table class="sv-tbl">
    <colgroup>
      <col class="sv-col-num">
      <col class="sv-col-label">
      <col class="sv-col-val">
    </colgroup>
    <thead>
      <tr>
        <th>\${BL('sv_th_div')}</th>
        <th>\${BL('sv_th_item')}</th>
        <th>\${BL('sv_th_content')}</th>
      </tr>
    </thead>
    <tbody>

      <!-- 1. 제작사(제작국) -->
      <tr>
        <td class="sv-num">1</td>
        <td class="sv-lbl">\${BL('sv_maker')}</td>
        <td class="sv-val">
          <input data-field="maker" class="sv-inp" type="text"
            placeholder="예) PIAGGIO C.S.P.A(이태리)"
            value="\${E(v('maker'))}">
        </td>
      </tr>

      <!-- 2. 시험자동차 명칭(형식) -->
      <tr>
        <td class="sv-num">2</td>
        <td class="sv-lbl">\${BL('sv_vehicle_name')}</td>
        <td class="sv-val">
          <input data-field="vehicle_name" class="sv-inp" type="text"
            placeholder="예) RSV4 1000 RR"
            value="\${E(v('vehicle_name'))}">
        </td>
      </tr>

      <!-- 3. 사용연료 -->
      <tr>
        <td class="sv-num">3</td>
        <td class="sv-lbl">\${BL('sv_fuel')}</td>
        <td class="sv-val">
          <input data-field="fuel" class="sv-inp" type="text"
            placeholder="예) 휘발유, 경유, LPG"
            value="\${E(v('fuel'))}">
        </td>
      </tr>

      <!-- 4. 적용 기준 : 배출가스 / 소음 2행 분리 -->
      <tr>
        <td class="sv-num" rowspan="2">4</td>
        <td class="sv-lbl" rowspan="2">\${BL('sv_std')}</td>
        <td style="padding:0; border-bottom:1px solid #ccc;">
          <div class="sv-sub-row">
            <span class="sv-sub-lbl">\${BL('sv_emission')}</span>
            <input data-field="emission_std" class="sv-inp" type="text"
              placeholder="예) EURO 5"
              value="\${E(v('emission_std'))}" style="flex:1;min-width:0;">
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding:0;">
          <div class="sv-sub-row">
            <span class="sv-sub-lbl">\${BL('sv_noise_simple')}</span>
            <input data-field="noise_std" class="sv-inp" type="text"
              placeholder="예) ECE R41-04"
              value="\${E(v('noise_std'))}" style="flex:1;min-width:0;">
          </div>
        </td>
      </tr>

      <!-- 5. 외국 기준 (유럽 또는 미국 기준) -->
      <tr>
        <td class="sv-num">5</td>
        <td class="sv-lbl">
          \${BL('sv_foreign_std')}<br>
          <span style="font-weight:400; font-size:.88em; opacity:.75;">\${BL('sv_foreign_std_note')}</span>
        </td>
        <td class="sv-val">
          <input data-field="foreign_std" class="sv-inp" type="text"
            placeholder="예) EURO 5"
            value="\${E(v('foreign_std'))}">
        </td>
      </tr>

      <!-- 6. 증발가스 대표차 여부 및 자동차 명칭/형식 (2행 분리) -->
      <tr>
        <td class="sv-num" rowspan="3">6</td>
        <td class="sv-lbl" rowspan="3">\${BL('sv_evap_rep_title')}<br>\${BL('sv_vehicle_name_simple')}</td>
        <td style="padding:0; border-bottom:1px solid #ccc;">
          <div class="sv-sub-row">
            <span class="sv-sub-lbl" style="width:64px;">\${BL('sv_rep_vehicle_lbl')}</span>
            <input data-field="evap_is_rep" class="sv-inp" type="text"
              placeholder="대표/비대표"
              value="\${E(v('evap_is_rep'))}" style="flex:1;min-width:0;">
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding:0; border-bottom:1px solid #ccc;">
          <div class="sv-sub-row">
            <span class="sv-sub-lbl" style="width:64px;">\${BL('sv_vehicle_name_lbl')}</span>
            <input data-field="evap_rep_name" class="sv-inp" type="text"
              placeholder="예) RSV4 1000 RR"
              value="\${E(v('evap_rep_name'))}" style="flex:1;min-width:0;">
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding:0;">
          <div class="sv-sub-row">
            <span class="sv-sub-lbl" style="width:64px;">\${BL('sv_type_lbl')}</span>
            <input data-field="evap_rep_type" class="sv-inp" type="text"
              placeholder="예) ABC-123"
              value="\${E(v('evap_rep_type'))}" style="flex:1;min-width:0;">
          </div>
        </td>
      </tr>

      <!-- 7. OBD 대표차 여부 및 자동차 명칭/형식 (2행 분리) -->
      <tr>
        <td class="sv-num" rowspan="3">7</td>
        <td class="sv-lbl" rowspan="3">\${BL('sv_obd_rep_title')}<br>\${BL('sv_vehicle_name_simple')}</td>
        <td style="padding:0; border-bottom:1px solid #ccc;">
          <div class="sv-sub-row">
            <span class="sv-sub-lbl" style="width:64px;">\${BL('sv_rep_vehicle_lbl')}</span>
            <input data-field="obd_is_rep" class="sv-inp" type="text"
              placeholder="대표/비대표"
              value="\${E(v('obd_is_rep'))}" style="flex:1;min-width:0;">
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding:0; border-bottom:1px solid #ccc;">
          <div class="sv-sub-row">
            <span class="sv-sub-lbl" style="width:64px;">\${BL('sv_vehicle_name_lbl')}</span>
            <input data-field="obd_rep_name" class="sv-inp" type="text"
              placeholder="예) RSV4 1000 RR"
              value="\${E(v('obd_rep_name'))}" style="flex:1;min-width:0;">
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding:0;">
          <div class="sv-sub-row">
            <span class="sv-sub-lbl" style="width:64px;">\${BL('sv_type_lbl')}</span>
            <input data-field="obd_rep_type" class="sv-inp" type="text"
              placeholder="예) ABC-123"
              value="\${E(v('obd_rep_type'))}" style="flex:1;min-width:0;">
          </div>
        </td>
      </tr>

      <!-- 8. 보증 기간 -->
      <tr>
        <td class="sv-num">8</td>
        <td class="sv-lbl">\${BL('sv_warranty')}</td>
        <td style="padding:0;">
          <div class="sv-warranty-row">
            <input data-field="warranty_year" class="sv-rep-item-inp" type="text"
              placeholder="년" value="\${E(v('warranty_year'))}" style="width:50px;text-align:right;">
            <span style="font-size:10pt;">\${BL('unit_year')}</span>
            <span style="font-size:10pt;">&nbsp;/&nbsp;</span>
            <input data-field="warranty_km" class="sv-rep-item-inp" type="text"
              placeholder="km" value="\${E(v('warranty_km'))}" style="width:90px;text-align:right;">
            <span style="font-size:10pt;">km</span>
          </div>
        </td>
      </tr>

      <!-- 9. 자체시험실시 내역 -->
      <tr>
        <td class="sv-num">9</td>
        <td class="sv-lbl">\${BL('sv_self_test')}</td>
        <td class="sv-val">
          <input data-field="self_test" class="sv-inp" type="text"
            placeholder="예) OBD, 소음, 증발가스"
            value="\${E(v('self_test'))}">
        </td>
      </tr>

      <!-- 10. 대표 기술 -->
      <tr>
        <td class="sv-num">10</td>
        <td class="sv-lbl">\${BL('sv_key_tech')}</td>
        <td class="sv-val">
          <textarea data-field="key_tech" class="sv-ta" rows="3"
            placeholder="예) 산소센서, 삼원촉매, OBD, ECU, Idle control, 전자식 연료주입">\${E(v('key_tech'))}</textarea>
        </td>
      </tr>

    </tbody>
  </table>
</div>
<div id="qr-footer-wrap" style="margin-top:12px;"></div>
\`;

  if (formType==='gasoline') return \`
<style>
/* ══════════ gasoline 전용 스타일 (emission_noise 동일 구조) ══════════ */
.en-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
  background:#fff;
  color:#111;
  border-radius:8px;
}
.en-doc-tag { font-size:8.5pt; font-weight:700; color:#444; margin:10px 0 4px; }
.en-main-title {
  font-size:13pt; font-weight:900; text-align:center;
  margin:4px 0 14px; letter-spacing:.03em; color:#111;
}
.en-tbl {
  width:100%; border-collapse:collapse;
  font-size:8.5pt; margin-bottom:0;
}
.en-tbl th, .en-tbl td {
  border:1px solid #888;
  padding:3px 5px;
  vertical-align:middle;
  color:#111;
}
.en-sec-th {
  background:#d6e4f7;
  font-weight:700; text-align:left;
  padding:4px 6px; font-size:8.5pt; color:#111;
}
.en-sub-th {
  background:#eef3fa;
  font-weight:700; text-align:left;
  padding:3px 6px; font-size:8.5pt; color:#111;
}
.en-th {
  background:#eef3fa;
  font-weight:600; text-align:center;
  font-size:8pt; color:#111;
}
.en-lbl {
  background:#f5f8ff;
  font-weight:600; color:#111;
  vertical-align:middle;
}
/* ── 복합 입력 필드 ── */
.en-field {
  display:flex; flex-direction:column; gap:4px;
  padding:3px 4px; box-sizing:border-box; width:100%;
}
.en-field-text {
  width:100%; font-size:8.5pt; font-family:inherit;
  border:none; background:transparent; padding:2px 0;
  box-sizing:border-box; resize:vertical; color:#111;
  min-height:36px; line-height:1.5;
}
.en-field-text::placeholder { color:#aaa; }
.en-field-text:focus { outline:none; border-bottom:1px dashed #4e90d8; }
/* 이미지 드롭존 */
.en-drop {
  border:1.5px dashed #b0c4de;
  border-radius:5px;
  background:#f8faff;
  padding:6px 8px;
  cursor:pointer;
  transition:border-color .15s, background .15s;
  position:relative;
  min-height:36px;
}
.en-drop:hover { border-color:#4e90d8; background:#eef3fa; }
.en-drop.drag-over { border-color:#2563eb; background:#dbeafe; }
.en-drop-hint {
  color:#aaa; font-size:7.5pt; text-align:center;
  pointer-events:none; user-select:none;
  display:flex; align-items:center; justify-content:center; gap:4px;
}
.en-drop input[type=file] { display:none; }
.en-img-list {
  display:flex; flex-wrap:wrap; gap:6px; margin-top:4px;
}
.en-img-item {
  position:relative; display:inline-block;
}
.en-img-item img {
  max-width:140px; max-height:100px;
  border:1px solid #ccc; border-radius:3px;
  display:block; object-fit:contain; background:#fff;
}
.en-img-item-del {
  position:absolute; top:-6px; right:-6px;
  width:16px; height:16px; border-radius:50%;
  background:#ef4444; color:#fff; font-size:10px;
  display:flex; align-items:center; justify-content:center;
  cursor:pointer; line-height:1; border:none;
  box-shadow:0 1px 3px rgba(0,0,0,.3);
}
.en-img-item-del:hover { background:#dc2626; }
/* 헤더 셀 단순 1행 input */
.en-inp {
  border:none; background:transparent;
  width:100%; font-size:8.5pt;
  font-family:inherit; padding:0 2px;
  box-sizing:border-box; color:#111;
}
.en-inp::placeholder { color:#aaa; }
.en-inp:focus { outline:none; border-bottom:1px solid #4e90d8; }
/* 체크박스 행 */
.g-chk-row {
  display:flex; align-items:center; gap:6px;
  padding:3px 6px; font-size:8.5pt;
}
.g-chk-row input[type=checkbox] { margin:0; cursor:pointer; }
.g-chk-inp {
  border:none; border-bottom:1px solid #ccc; background:transparent;
  font-size:8.5pt; font-family:inherit; width:120px; padding:0 2px;
}
.g-chk-inp:focus { outline:none; border-bottom-color:#4e90d8; }
@media print {
  .en-wrap { background:#fff !important; color:#000 !important; border-radius:0 !important; }
  .en-tbl { table-layout:fixed !important; width:100% !important; }
  .en-tbl th, .en-tbl td {
    border:1px solid #333 !important; color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important; overflow-wrap:break-word !important;
  }
  .en-field { height:auto !important; overflow:visible !important; display:flex !important; flex-direction:column !important; }
  textarea.en-field-text {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; min-height:0 !important; max-height:none !important;
    overflow:visible !important; resize:none !important;
    white-space:pre-wrap !important; word-break:break-word !important;
    overflow-wrap:break-word !important;
    display:block !important; box-sizing:border-box !important;
    -webkit-appearance:none !important; appearance:none !important;
    padding:2px 0 !important;
  }
  .en-inp {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important;
  }
  input[type=hidden] { display:none !important; }
  .en-drop {
    border:none !important; background:transparent !important;
    padding:0 !important; min-height:unset !important;
    height:auto !important; overflow:visible !important;
  }
  .en-drop-hint { display:none !important; }
  .en-img-item-del { display:none !important; }
  .en-img-list { gap:4px !important; margin-top:2px !important; }
  .en-img-item img {
    max-width:100% !important; max-height:none !important;
    page-break-inside:avoid;
  }
  .en-drop:not(:has(img)) { display:none !important; }
  .en-sec-th { background:#d6e4f7 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-sub-th { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-th     { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-lbl    { background:#f5f8ff !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-tbl tr { page-break-inside:avoid; }
}
</style>

<div class="en-wrap">

  <!-- ── 상단 헤더 (수입사/인증연도/배기량/동일차종기호) ── -->
  <table class="en-tbl" style="margin-bottom:12px; table-layout:fixed;">
    <colgroup>
      <col style="width:35%;"><col style="width:12%;"><col style="width:13%;"><col style="width:40%;">
    </colgroup>
    <thead>
      <tr>
        <th class="en-th">\${BL('importer')}</th>
        <th class="en-th">\${BL('cert_year')}</th>
        <th class="en-th">\${BL('displacement')}</th>
        <th class="en-th">\${BL('family_code')}</th>
      </tr>
    </thead>
    <tbody>
      <tr style="height:26px;">
        <td><input data-field="g_importer"  class="en-inp" type="text" placeholder="\${BL('ph_importer')}"    value="\${E(v('g_importer'))}"></td>
        <td><input data-field="g_cert_year" class="en-inp" type="text" placeholder="\${BL('ph_cert_year')}"   value="\${E(v('g_cert_year'))}"></td>
        <td><input data-field="g_disp"      class="en-inp" type="text" placeholder="\${BL('ph_displacement')}" value="\${E(v('g_disp'))}"></td>
        <td><input data-field="g_fam_code"  class="en-inp" type="text" placeholder="\${BL('ph_family_code')}" value="\${E(v('g_fam_code'))}"></td>
      </tr>
    </tbody>
  </table>

  <div class="en-doc-tag">[별지 제2호 서식]</div>
  <div class="en-main-title">휘발유차 인증신청 주요내용</div>

  <!-- ══════════════════════════════════════════════════════════════ -->
  <!-- 1. 신청 개요                                                   -->
  <!-- ══════════════════════════════════════════════════════════════ -->
  <table class="en-tbl" style="table-layout:fixed; width:100%; margin-bottom:10px;">
    <colgroup>
      <col style="width:8%;">
      <col style="width:10%;">
      <col style="width:12%;">
      <col style="width:14%;">
      <col style="width:10%;">
      <col style="width:14%;">
      <col style="width:16%;">
      <col style="width:10%;">
      <col style="width:6%;">
    </colgroup>
    <thead>
      <tr>
        <th class="en-sec-th" colspan="9">1. 신청 개요</th>
      </tr>
      <tr>
        <th class="en-th">구분</th>
        <th class="en-th">신청일</th>
        <th class="en-th">제작사</th>
        <th class="en-th">차명<br>(형식)</th>
        <th class="en-th">차종<br>(사용연료)</th>
        <th class="en-th">출력(ps/rpm)<br>(배기량 cc)</th>
        <th class="en-th">적용기준</th>
        <th class="en-th">인증번호</th>
        <th class="en-th">비고</th>
      </tr>
    </thead>
    <tbody>
      <tr style="height:48px;">
        <td><input class="en-inp" data-field="g_overview_div"      type="text" value="\${E(v('g_overview_div'))}"></td>
        <td><input class="en-inp" data-field="g_apply_date"        type="text" placeholder="YYYY-MM-DD" value="\${E(v('g_apply_date'))}"></td>
        <td><input class="en-inp" data-field="g_maker"             type="text" value="\${E(v('g_maker'))}"></td>
        <td><input class="en-inp" data-field="g_model_name"        type="text" value="\${E(v('g_model_name'))}"></td>
        <td><input class="en-inp" data-field="g_vehicle_type"      type="text" value="\${E(v('g_vehicle_type'))}"></td>
        <td><input class="en-inp" data-field="g_output_disp"       type="text" value="\${E(v('g_output_disp'))}"></td>
        <td style="padding:2px 4px; font-size:8pt; line-height:1.6;">
          배출 : <input class="en-inp" data-field="g_std_emission" type="text" value="\${E(v('g_std_emission'))}" style="width:80%;"><br>
          소음 : <input class="en-inp" data-field="g_std_noise"    type="text" value="\${E(v('g_std_noise'))}"    style="width:80%;">
        </td>
        <td><input class="en-inp" data-field="g_cert_no"           type="text" value="\${E(v('g_cert_no'))}"></td>
        <td><input class="en-inp" data-field="g_note"              type="text" value="\${E(v('g_note'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════════════ -->
  <!-- 2. 신청 유형                                                   -->
  <!-- ══════════════════════════════════════════════════════════════ -->
  <table class="en-tbl" style="table-layout:fixed; width:100%; margin-bottom:10px;">
    <colgroup><col style="width:100%;"></colgroup>
    <tbody>
      <tr><th class="en-sec-th">2. 신청 유형</th></tr>

      <!-- 2.1 EURO-5 기준 적용 -->
      <tr>
        <td style="padding:4px 8px;">
          <div class="g-chk-row">
            
            <span>2.1. EURO–5 기준 적용 휘발유 이륜자동차 인증신청, 대표차종 :</span>
            <input class="g-chk-inp" data-field="g_euro5_rep" type="text" value="\${E(v('g_euro5_rep'))}">
          </div>
        </td>
      </tr>

      <!-- 2.2 OBD/증발가스 대표 차종 -->
      <tr>
        <td style="padding:4px 8px;">
          <div class="g-chk-row">
            <span>2.2. OBD 대표 차종 :</span>
            <input class="g-chk-inp" data-field="g_obd_rep" type="text" value="\${E(v('g_obd_rep'))}" style="width:100px;">
            <span style="margin-left:12px;">증발가스 대표 차종 :</span>
            <input class="g-chk-inp" data-field="g_evap_rep" type="text" value="\${E(v('g_evap_rep'))}" style="width:100px;">
          </div>
        </td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════════════ -->
  <!-- 신청 유형 상세 테이블 (구분/인증서 기재 내용/해당여부)         -->
  <!-- ══════════════════════════════════════════════════════════════ -->
  <table class="en-tbl" style="table-layout:fixed; width:100%; margin-bottom:10px;">
    <colgroup>
      <col style="width:10%;">
      <col style="width:12%;">
      <col style="width:60%;">
      <col style="width:18%;">
    </colgroup>
    <thead>
      <tr>
        <th class="en-th">구분</th>
        <th class="en-th">연료</th>
        <th class="en-th">인증서 기재 내용</th>
        <th class="en-th">해당여부</th>
      </tr>
    </thead>
    <tbody>
      <!-- ── 배출기준 ── -->
      <tr>
        <td class="en-lbl" rowspan="5" style="text-align:center; font-weight:700;">배출기준</td>
        <td class="en-lbl" rowspan="4" style="text-align:center;">휘발유</td>
        <td>* 13년 휘발유 기준2의 나</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_em1" type="text" placeholder="해당/미해당" value="\${E(v('g_app_em1'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>* 13년 휘발유 기준1의 나</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_em2" type="text" placeholder="해당/미해당" value="\${E(v('g_app_em2'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>* 16년 휘발유 기준</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_em3" type="text" placeholder="해당/미해당" value="\${E(v('g_app_em3'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>* 20년 1월 이륜자동차(130km/h 이하) 기준</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_em4" type="text" placeholder="해당/미해당" value="\${E(v('g_app_em4'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td class="en-lbl" style="text-align:center;">경유</td>
        <td>* 14년 9월 경유 소형승용 기준</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_em5" type="text" placeholder="해당/미해당" value="\${E(v('g_app_em5'))}" style="width:100%;">
        </td>
      </tr>

      <!-- ── OBD 2 ── -->
      <tr>
        <td class="en-lbl" rowspan="7" style="text-align:center; font-weight:700;">OBD 2</td>
        <td class="en-lbl" rowspan="5" style="text-align:center;">휘발유</td>
        <td>* OBD2 휘발유 기준 적용 대표(IUPR 1st 기준)</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_obd1" type="text" placeholder="해당/미해당" value="\${E(v('g_app_obd1'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td style="padding:3px 5px;">
          * OBD2 휘발유 기준 적용 동일(IUPR 1st 기준), 대표차종 :
          <input class="g-chk-inp" data-field="g_obd_std2_rep" type="text" value="\${E(v('g_obd_std2_rep'))}" style="width:90px;">
        </td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_obd2" type="text" placeholder="해당/미해당" value="\${E(v('g_app_obd2'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>* OBD2 휘발유 EURO6 기준 적용 대표(IUPR 2nd 기준)</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_obd3" type="text" placeholder="해당/미해당" value="\${E(v('g_app_obd3'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td style="padding:3px 5px;">
          * OBD2 휘발유 EURO6 기준 적용 동일(IUPR 2nd 기준), 대표차종 :
          <input class="g-chk-inp" data-field="g_obd_std4_rep" type="text" value="\${E(v('g_obd_std4_rep'))}" style="width:90px;">
        </td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_obd4" type="text" placeholder="해당/미해당" value="\${E(v('g_app_obd4'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>* OBD2 휘발유 EURO5 이륜자동차 기준 적용 대표(OBD Stage 2)</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_obd5" type="text" placeholder="해당/미해당" value="\${E(v('g_app_obd5'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td class="en-lbl" rowspan="2" style="text-align:center;">경유</td>
        <td>* OBD2 경유 (다)기준 적용 대표 (IUPR 2nd 기준)</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_obd6" type="text" placeholder="해당/미해당" value="\${E(v('g_app_obd6'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td style="padding:3px 5px;">
          * OBD2 경유 (다)기준 적용 동일(IUPR 2nd 기준), 대표차종 :
          <input class="g-chk-inp" data-field="g_obd_std7_rep" type="text" value="\${E(v('g_obd_std7_rep'))}" style="width:90px;">
        </td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_obd7" type="text" placeholder="해당/미해당" value="\${E(v('g_app_obd7'))}" style="width:100%;">
        </td>
      </tr>

      <!-- ── 증발가스 ── -->
      <tr>
        <td class="en-lbl" rowspan="2" style="text-align:center; font-weight:700;">증발가스</td>
        <td class="en-lbl" rowspan="2" style="text-align:center;"> </td>
        <td>* 증발가스 대표</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_evap1" type="text" placeholder="해당/미해당" value="\${E(v('g_app_evap1'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td style="padding:3px 5px;">
          * 증발가스 동일, 대표차종 :
          <input class="g-chk-inp" data-field="g_evap_std2_rep" type="text" value="\${E(v('g_evap_std2_rep'))}" style="width:120px;">
        </td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_evap2" type="text" placeholder="해당/미해당" value="\${E(v('g_app_evap2'))}" style="width:100%;">
        </td>
      </tr>

      <!-- ── 보증기간 ── -->
      <tr>
        <td class="en-lbl" rowspan="6" style="text-align:center; font-weight:700;">보증기간</td>
        <td class="en-lbl" rowspan="5" style="text-align:center;">휘발유</td>
        <td>* 보증기간 : 10년 / 19만2천km</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_war1" type="text" placeholder="해당/미해당" value="\${E(v('g_app_war1'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>* 보증기간 : 10년 / 24만km</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_war2" type="text" placeholder="해당/미해당" value="\${E(v('g_app_war2'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>* 보증기간 : 15년 / 24만km</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_war3" type="text" placeholder="해당/미해당" value="\${E(v('g_app_war3'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>* 보증기간 : 02년 / 3.5만km</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_war4" type="text" placeholder="해당/미해당" value="\${E(v('g_app_war4'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>* 보증기간 : 02년 / 2만km</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_war5" type="text" placeholder="해당/미해당" value="\${E(v('g_app_war5'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td class="en-lbl" style="text-align:center;">경유</td>
        <td>* 보증기간 : 10년 / 16만km</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_war6" type="text" placeholder="해당/미해당" value="\${E(v('g_app_war6'))}" style="width:100%;">
        </td>
      </tr>

    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════════════ -->
  <!-- 3. 상세내역                                                    -->
  <!-- ══════════════════════════════════════════════════════════════ -->
  <table class="en-tbl" style="table-layout:fixed; width:100%; margin-bottom:10px;">
    <colgroup>
      <col style="width:4%;">
      <col style="width:18%;">
      <col style="width:78%;">
    </colgroup>
    <thead>
      <tr><th class="en-sec-th" colspan="3">3. 상세내역</th></tr>
    </thead>
    <tbody>

      <!-- 3.1 적용기술 -->
      <tr>
        <td class="en-lbl" style="text-align:center; font-weight:700;">1</td>
        <td class="en-sub-th">3.1. 적용기술</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_tech_applied" rows="3" placeholder="적용된 배출가스·소음 저감 기술을 기재하세요">\${E(v('g_tech_applied'))}</textarea>
            <input type="hidden" data-field="g_tech_applied_imgs" value="\${E(v('g_tech_applied_imgs'))}">
            <div class="en-drop" data-field-img="g_tech_applied"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.2 자체시험결과 -->
      <tr>
        <td class="en-lbl" style="text-align:center; font-weight:700;" rowspan="2">2</td>
        <td class="en-sub-th">3.2.1. 배출</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_self_test_emission" rows="2" placeholder="배출가스 자체시험 결과">\${E(v('g_self_test_emission'))}</textarea>
          </div>
        </td>
      </tr>
      <tr>
        <td class="en-sub-th">3.2.2. 소음</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_self_test_noise" rows="2" placeholder="소음 자체시험 결과">\${E(v('g_self_test_noise'))}</textarea>
          </div>
        </td>
      </tr>

    </tbody>
  </table>

  <!-- 3.2 자체시험결과 상세 테이블 -->
  <table class="en-tbl" style="table-layout:fixed; width:100%; margin-bottom:10px; font-size:8pt;">
    <colgroup>
      <col style="width:12%;">
      <col style="width:9%;">
      <col style="width:9%;">
      <col style="width:9%;">
      <col style="width:9%;">
      <col style="width:9%;">
      <col style="width:9%;">
      <col style="width:9%;">
      <col style="width:9%;">
      <col style="width:10%;">
    </colgroup>
    <thead>
      <tr>
        <th class="en-th" rowspan="2">구분</th>
        <th class="en-th" rowspan="2">CO<br>(g/km)</th>
        <th class="en-th" rowspan="2">NOx<br>(g/km)</th>
        <th class="en-th" colspan="3">탄화수소</th>
        <th class="en-th" rowspan="2">CO₂<br>(g/km)</th>
        <th class="en-th" rowspan="2">가속주행<br>dB(A)</th>
        <th class="en-th" rowspan="2">가속주행<br>dB(A)</th>
        <th class="en-th" rowspan="2">가속주행<br>dB(C)</th>
      </tr>
      <tr>
        <th class="en-th">THC<br>(g/km)</th>
        <th class="en-th">NMHC<br>(g/km)</th>
        <th class="en-th">증발가스<br>(g/Test)</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td class="en-lbl">허용기준</td>
        <td><input class="en-inp" data-field="g_lim_co"   type="text" value="\${E(v('g_lim_co'))}"></td>
        <td><input class="en-inp" data-field="g_lim_nox"  type="text" value="\${E(v('g_lim_nox'))}"></td>
        <td><input class="en-inp" data-field="g_lim_thc"  type="text" value="\${E(v('g_lim_thc'))}"></td>
        <td><input class="en-inp" data-field="g_lim_nmhc" type="text" value="\${E(v('g_lim_nmhc'))}"></td>
        <td><input class="en-inp" data-field="g_lim_evap" type="text" value="\${E(v('g_lim_evap'))}"></td>
        <td><input class="en-inp" data-field="g_lim_co2"  type="text" value="\${E(v('g_lim_co2'))}"></td>
        <td><input class="en-inp" data-field="g_lim_nA"   type="text" value="\${E(v('g_lim_nA'))}"></td>
        <td><input class="en-inp" data-field="g_lim_nA2"  type="text" value="\${E(v('g_lim_nA2'))}"></td>
        <td><input class="en-inp" data-field="g_lim_nC"   type="text" value="\${E(v('g_lim_nC'))}"></td>
      </tr>
      <tr>
        <td class="en-lbl">시험결과</td>
        <td><input class="en-inp" data-field="g_res_co"   type="text" value="\${E(v('g_res_co'))}"></td>
        <td><input class="en-inp" data-field="g_res_nox"  type="text" value="\${E(v('g_res_nox'))}"></td>
        <td><input class="en-inp" data-field="g_res_thc"  type="text" value="\${E(v('g_res_thc'))}"></td>
        <td><input class="en-inp" data-field="g_res_nmhc" type="text" value="\${E(v('g_res_nmhc'))}"></td>
        <td><input class="en-inp" data-field="g_res_evap" type="text" value="\${E(v('g_res_evap'))}"></td>
        <td><input class="en-inp" data-field="g_res_co2"  type="text" value="\${E(v('g_res_co2'))}"></td>
        <td><input class="en-inp" data-field="g_res_nA"   type="text" value="\${E(v('g_res_nA'))}"></td>
        <td><input class="en-inp" data-field="g_res_nA2"  type="text" value="\${E(v('g_res_nA2'))}"></td>
        <td><input class="en-inp" data-field="g_res_nC"   type="text" value="\${E(v('g_res_nC'))}"></td>
      </tr>
      <tr>
        <td class="en-lbl">기준만족도(%)</td>
        <td><input class="en-inp" data-field="g_sat_co"   type="text" value="\${E(v('g_sat_co'))}"></td>
        <td><input class="en-inp" data-field="g_sat_nox"  type="text" value="\${E(v('g_sat_nox'))}"></td>
        <td><input class="en-inp" data-field="g_sat_thc"  type="text" value="\${E(v('g_sat_thc'))}"></td>
        <td><input class="en-inp" data-field="g_sat_nmhc" type="text" value="\${E(v('g_sat_nmhc'))}"></td>
        <td><input class="en-inp" data-field="g_sat_evap" type="text" value="\${E(v('g_sat_evap'))}"></td>
        <td><input class="en-inp" data-field="g_sat_co2"  type="text" value="\${E(v('g_sat_co2'))}"></td>
        <td><input class="en-inp" data-field="g_sat_nA"   type="text" value="\${E(v('g_sat_nA'))}"></td>
        <td><input class="en-inp" data-field="g_sat_nA2"  type="text" value="\${E(v('g_sat_nA2'))}"></td>
        <td><input class="en-inp" data-field="g_sat_nC"   type="text" value="\${E(v('g_sat_nC'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- OBD 시험대상 감시장치 테이블 -->
  <table class="en-tbl" style="table-layout:fixed; width:100%; margin-bottom:10px; font-size:8pt;">
    <colgroup>
      <col style="width:10%;">
      <col style="width:18%;">
      <col style="width:8%;">
      <col style="width:8%;">
      <col style="width:8%;">
      <col style="width:10%;">
      <col style="width:8%;">
      <col style="width:8%;">
      <col style="width:8%;">
      <col style="width:14%;">
    </colgroup>
    <thead>
      <tr>
        <th class="en-th" colspan="2">시험대상 감시장치</th>
        <th class="en-th" colspan="4">시험 결과</th>
        <th class="en-th" colspan="4">결과 판정</th>
      </tr>
      <tr>
        <th class="en-th">장치 명</th>
        <th class="en-th">오작동 재현 조건</th>
        <th class="en-th">WMTC 모드<br>CO(g/km)</th>
        <th class="en-th">NOx<br>(g/km)</th>
        <th class="en-th">HC<br>(g/km)</th>
        <th class="en-th">표시등<br>점등여부</th>
        <th class="en-th">판단기준<br>CO(g/km)</th>
        <th class="en-th">NOx<br>(g/km)</th>
        <th class="en-th">HC<br>(g/km)</th>
        <th class="en-th">감시장치<br>적부판정</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td class="en-lbl">촉매</td>
        <td><input class="en-inp" data-field="g_obd_cond1" type="text" placeholder="실화" value="\${E(v('g_obd_cond1'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r1_co" type="text" value="\${E(v('g_obd_r1_co'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r1_nox" type="text" value="\${E(v('g_obd_r1_nox'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r1_hc"  type="text" value="\${E(v('g_obd_r1_hc'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r1_led" type="text" placeholder="유/무" value="\${E(v('g_obd_r1_led'))}"></td>
        <td><input class="en-inp" data-field="g_obd_c1_co"  type="text" value="\${E(v('g_obd_c1_co'))}"></td>
        <td><input class="en-inp" data-field="g_obd_c1_nox" type="text" value="\${E(v('g_obd_c1_nox'))}"></td>
        <td><input class="en-inp" data-field="g_obd_c1_hc"  type="text" value="\${E(v('g_obd_c1_hc'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r1_judg" type="text" placeholder="적합/부적합" value="\${E(v('g_obd_r1_judg'))}"></td>
      </tr>
      <tr>
        <td class="en-lbl">O₂센서</td>
        <td><input class="en-inp" data-field="g_obd_cond2" type="text" placeholder="열화" value="\${E(v('g_obd_cond2'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r2_co" type="text" value="\${E(v('g_obd_r2_co'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r2_nox" type="text" value="\${E(v('g_obd_r2_nox'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r2_hc"  type="text" value="\${E(v('g_obd_r2_hc'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r2_led" type="text" placeholder="유/무" value="\${E(v('g_obd_r2_led'))}"></td>
        <td><input class="en-inp" data-field="g_obd_c2_co"  type="text" value="\${E(v('g_obd_c2_co'))}"></td>
        <td><input class="en-inp" data-field="g_obd_c2_nox" type="text" value="\${E(v('g_obd_c2_nox'))}"></td>
        <td><input class="en-inp" data-field="g_obd_c2_hc"  type="text" value="\${E(v('g_obd_c2_hc'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r2_judg" type="text" placeholder="적합/부적합" value="\${E(v('g_obd_r2_judg'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════════════ -->
  <!-- 3.3 항목별 제원 및 시험결과                                   -->
  <!-- ══════════════════════════════════════════════════════════════ -->
  <table class="en-tbl" style="table-layout:fixed; width:100%; margin-bottom:10px;">
    <colgroup>
      <col style="width:4%;">
      <col style="width:20%;">
      <col style="width:76%;">
    </colgroup>
    <thead>
      <tr><th class="en-sub-th" colspan="3">3.3. 항목별 제원 및 시험결과 등</th></tr>
      <tr>
        <th class="en-th">구분</th>
        <th class="en-th">항 목</th>
        <th class="en-th">내 용</th>
      </tr>
    </thead>
    <tbody>
      <!-- 1. 촉매, DPF 등 후처리장치 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">1</td>
        <td class="en-lbl">촉매, DPF 등 후처리장치</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_catalyst" rows="2" placeholder="후처리장치 상세 내용">\${E(v('g_catalyst'))}</textarea>
            <input type="hidden" data-field="g_catalyst_imgs" value="\${E(v('g_catalyst_imgs'))}">
            <div class="en-drop" data-field-img="g_catalyst"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 2. 증발가스 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">2</td>
        <td class="en-lbl">증발가스</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_evap_content" rows="3" placeholder="증발가스 대표/동일 여부 및 관련 내용">\${E(v('g_evap_content'))}</textarea>
            <input type="hidden" data-field="g_evap_content_imgs" value="\${E(v('g_evap_content_imgs'))}">
            <div class="en-drop" data-field-img="g_evap_content"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3. 블로바이가스 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">3</td>
        <td class="en-lbl">블로바이가스</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_blowby_detail" rows="2" placeholder="블로바이가스 제어장치 내용">\${E(v('g_blowby_detail'))}</textarea>
            <input type="hidden" data-field="g_blowby_detail_imgs" value="\${E(v('g_blowby_detail_imgs'))}">
            <div class="en-drop" data-field-img="g_blowby_detail"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 4. 배출가스자기진단장치(OBD2) -->
      <tr>
        <td class="en-lbl" style="text-align:center; vertical-align:top; padding-top:8px;">4</td>
        <td class="en-lbl" style="vertical-align:top; padding-top:8px;">배출가스자기진단장치<br>(OBD2)</td>
        <td style="padding:4px 6px;">
          <!-- OBD2 대표/동일 여부 -->
          <div class="en-field" style="margin-bottom:6px;">
            <textarea class="en-field-text" data-field="g_obd_rep_detail" rows="2" placeholder="OBD2 대표/동일 여부 및 관련 내용">\${E(v('g_obd_rep_detail'))}</textarea>
            <input type="hidden" data-field="g_obd_rep_detail_imgs" value="\${E(v('g_obd_rep_detail_imgs'))}">
            <div class="en-drop" data-field-img="g_obd_rep_detail"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>

          <!-- OBD 기준 테이블 -->
          <table class="en-tbl" style="margin:6px 0; font-size:8pt;">
            <thead>
              <tr>
                <th class="en-th" style="width:70%;">OBD 기준명</th>
                <th class="en-th" style="width:30%;">해당 여부</th>
              </tr>
            </thead>
            <tbody>
              <tr><td>휘발유 2006년 OBD 기준</td>
                  <td><input class="en-inp" data-field="g_obd_std1" type="text" placeholder="해당/미해당" value="\${E(v('g_obd_std1'))}"></td></tr>
              <tr><td>휘발유 2013년 OBD IUPR 1st 기준</td>
                  <td><input class="en-inp" data-field="g_obd_std2" type="text" placeholder="해당/미해당" value="\${E(v('g_obd_std2'))}"></td></tr>
              <tr><td>휘발유 2013년 OBD IUPR 2nd(2016년 1월) 기준</td>
                  <td><input class="en-inp" data-field="g_obd_std3" type="text" placeholder="해당/미해당" value="\${E(v('g_obd_std3'))}"></td></tr>
              <tr><td>휘발유 EURO6 OBD IUPR 2nd 기준</td>
                  <td><input class="en-inp" data-field="g_obd_std4" type="text" placeholder="해당/미해당" value="\${E(v('g_obd_std4'))}"></td></tr>
              <tr><td>휘발유 EURO5 OBD 이륜자동차 기준(OBD Stage 2)</td>
                  <td><input class="en-inp" data-field="g_obd_std5" type="text" placeholder="해당/미해당" value="\${E(v('g_obd_std5'))}"></td></tr>
              <tr><td>경유 2006년 OBD 기준</td>
                  <td><input class="en-inp" data-field="g_obd_std6" type="text" placeholder="해당/미해당" value="\${E(v('g_obd_std6'))}"></td></tr>
              <tr><td>경유 2012년 OBD IUPR 1st 기준</td>
                  <td><input class="en-inp" data-field="g_obd_std7" type="text" placeholder="해당/미해당" value="\${E(v('g_obd_std7'))}"></td></tr>
              <tr><td>경유 2014년 9월 OBD IUPR 2nd 기준</td>
                  <td><input class="en-inp" data-field="g_obd_std8" type="text" placeholder="해당/미해당" value="\${E(v('g_obd_std8'))}"></td></tr>
            </tbody>
          </table>

          <!-- OBD2 오작동 판정기준 -->
          <div class="en-field" style="margin-bottom:6px;">
            <textarea class="en-field-text" data-field="g_obd_mal_detail" rows="2" placeholder="OBD2 오작동 판정기준 관련 내용">\${E(v('g_obd_mal_detail'))}</textarea>
            <input type="hidden" data-field="g_obd_mal_detail_imgs" value="\${E(v('g_obd_mal_detail_imgs'))}">
            <div class="en-drop" data-field-img="g_obd_mal_detail"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>

          <!-- OBD2 감시항목별 시험여부 -->
          <table class="en-tbl" style="margin:6px 0; font-size:8pt;">
            <thead>
              <tr>
                <th class="en-th" style="width:40%;">감시항목</th>
                <th class="en-th" style="width:30%;">시험여부</th>
                <th class="en-th" style="width:30%;">시험차명</th>
              </tr>
            </thead>
            <tbody>
              <tr><td>산소센서</td>
                  <td><input class="en-inp" data-field="g_mon_o2_yn"  type="text" value="\${E(v('g_mon_o2_yn'))}"></td>
                  <td><input class="en-inp" data-field="g_mon_o2_car" type="text" value="\${E(v('g_mon_o2_car'))}"></td></tr>
              <tr><td>배기가스 재순환계통</td>
                  <td><input class="en-inp" data-field="g_mon_egr_yn"  type="text" value="\${E(v('g_mon_egr_yn'))}"></td>
                  <td><input class="en-inp" data-field="g_mon_egr_car" type="text" value="\${E(v('g_mon_egr_car'))}"></td></tr>
              <tr><td>가변밸브타이밍계통</td>
                  <td><input class="en-inp" data-field="g_mon_vvt_yn"  type="text" value="\${E(v('g_mon_vvt_yn'))}"></td>
                  <td><input class="en-inp" data-field="g_mon_vvt_car" type="text" value="\${E(v('g_mon_vvt_car'))}"></td></tr>
              <tr><td>연료계통</td>
                  <td><input class="en-inp" data-field="g_mon_fuel_yn"  type="text" value="\${E(v('g_mon_fuel_yn'))}"></td>
                  <td><input class="en-inp" data-field="g_mon_fuel_car" type="text" value="\${E(v('g_mon_fuel_car'))}"></td></tr>
              <tr><td>실화</td>
                  <td><input class="en-inp" data-field="g_mon_mis_yn"  type="text" value="\${E(v('g_mon_mis_yn'))}"></td>
                  <td><input class="en-inp" data-field="g_mon_mis_car" type="text" value="\${E(v('g_mon_mis_car'))}"></td></tr>
              <tr><td>2차 공기계통</td>
                  <td><input class="en-inp" data-field="g_mon_air_yn"  type="text" value="\${E(v('g_mon_air_yn'))}"></td>
                  <td><input class="en-inp" data-field="g_mon_air_car" type="text" value="\${E(v('g_mon_air_car'))}"></td></tr>
              <tr><td>촉매</td>
                  <td><input class="en-inp" data-field="g_mon_cat_yn"  type="text" value="\${E(v('g_mon_cat_yn'))}"></td>
                  <td><input class="en-inp" data-field="g_mon_cat_car" type="text" value="\${E(v('g_mon_cat_car'))}"></td></tr>
            </tbody>
          </table>

          <!-- IUPR 적용내역 -->
          <table class="en-tbl" style="margin:6px 0; font-size:8pt;">
            <thead>
              <tr>
                <th class="en-th" style="width:30%;">감시항목</th>
                <th class="en-th" style="width:20%;">적용여부</th>
                <th class="en-th" style="width:25%;">측정결과</th>
                <th class="en-th" style="width:25%;">시험차명</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><input class="en-inp" data-field="g_iupr_item1" type="text" value="\${E(v('g_iupr_item1'))}"></td>
                <td><input class="en-inp" data-field="g_iupr_yn1"   type="text" value="\${E(v('g_iupr_yn1'))}"></td>
                <td><input class="en-inp" data-field="g_iupr_res1"  type="text" value="\${E(v('g_iupr_res1'))}"></td>
                <td><input class="en-inp" data-field="g_iupr_car1"  type="text" value="\${E(v('g_iupr_car1'))}"></td>
              </tr>
              <tr>
                <td><input class="en-inp" data-field="g_iupr_item2" type="text" value="\${E(v('g_iupr_item2'))}"></td>
                <td><input class="en-inp" data-field="g_iupr_yn2"   type="text" value="\${E(v('g_iupr_yn2'))}"></td>
                <td><input class="en-inp" data-field="g_iupr_res2"  type="text" value="\${E(v('g_iupr_res2'))}"></td>
                <td><input class="en-inp" data-field="g_iupr_car2"  type="text" value="\${E(v('g_iupr_car2'))}"></td>
              </tr>
            </tbody>
          </table>
        </td>
      </tr>

      <!-- 5. 시험시설 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">5</td>
        <td class="en-lbl">시험시설</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_test_facility" rows="2" placeholder="자체시험을 실시한 시설에 대한 시설확인 내역">\${E(v('g_test_facility'))}</textarea>
            <input type="hidden" data-field="g_test_facility_imgs" value="\${E(v('g_test_facility_imgs'))}">
            <div class="en-drop" data-field-img="g_test_facility"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 6. 시험차 선정근거 -->
      <tr>
        <td class="en-lbl" style="text-align:center; vertical-align:top; padding-top:8px;">6</td>
        <td class="en-lbl" style="vertical-align:top; padding-top:8px;">시험차 선정근거</td>
        <td style="padding:4px 6px; font-size:8.5pt; line-height:1.7;">
          <div>시험자동차 선정근거</div>
          <div>- 배출가스 시험차량 : 「제작자동차 인증 및 검사방법과 절차 등에 관한 규정」 제11조(배출가스시험자동차의 선정)에 따라 시험차량 선정</div>
          <div>- 소음 시험차량 : 「제작자동차 인증 및 검사방법과 절차 등에 관한 규정」 제12조(소음인증시험자동차의 선정)에 따라 시험차량 선정</div>
          <div>- OBD 시험차량 : 「제작자동차 인증 및 검사방법과 절차 등에 관한 규정」 제23조(OBD인증시험자동차의 선정)에 따라 시험차량 선정</div>
          <div style="margin-top:4px;">
            <input class="en-inp" data-field="g_vehicle_sel_note" type="text" placeholder="추가 사항 기재" value="\${E(v('g_vehicle_sel_note'))}" style="width:100%;">
          </div>
        </td>
      </tr>

      <!-- 7. 배출가스 시험 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">7</td>
        <td class="en-lbl">배출가스 시험</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_em_test_detail" rows="3" placeholder="배출가스 시험모드, 시험 회수, 자체시험 성적서 제출 내역 등">\${E(v('g_em_test_detail'))}</textarea>
            <input type="hidden" data-field="g_em_test_imgs" value="\${E(v('g_em_test_imgs'))}">
            <div class="en-drop" data-field-img="g_em_test"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 8. 증발가스 시험 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">8</td>
        <td class="en-lbl">증발가스 시험</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_evap_test_detail" rows="3" placeholder="증발가스 자체시험 성적서 제출 내역 등">\${E(v('g_evap_test_detail'))}</textarea>
            <input type="hidden" data-field="g_evap_test_imgs" value="\${E(v('g_evap_test_imgs'))}">
            <div class="en-drop" data-field-img="g_evap_test"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 9. 보증기간 및 열화계수 -->
      <tr>
        <td class="en-lbl" style="text-align:center; vertical-align:top; padding-top:8px;">9</td>
        <td class="en-lbl" style="vertical-align:top; padding-top:8px;">보증기간 및 열화계수</td>
        <td style="padding:4px 6px;">
          <!-- 보증기간 및 열화계수 적용 내역 -->
          <div class="en-field" style="margin-bottom:6px;">
            <textarea class="en-field-text" data-field="g_warranty_detail" rows="2" placeholder="보증기간 및 열화계수 적용 내역">\${E(v('g_warranty_detail'))}</textarea>
            <input type="hidden" data-field="g_warranty_detail_imgs" value="\${E(v('g_warranty_detail_imgs'))}">
            <div class="en-drop" data-field-img="g_warranty_detail"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
          <div style="padding:2px 6px; font-size:8.5pt;">
            보증기간(km) : <input class="g-chk-inp" data-field="g_warranty_km" type="text" value="\${E(v('g_warranty_km'))}" style="width:120px;">
          </div>
          <table class="en-tbl" style="margin:6px 0; font-size:8pt;">
            <thead>
              <tr>
                <th class="en-th" style="width:50%;">항목</th>
                <th class="en-th" style="width:50%;">적용 열화계수</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>일산화탄소(CO)</td>
                <td><input class="en-inp" data-field="g_deter_co" type="text" value="\${E(v('g_deter_co'))}"></td>
              </tr>
              <tr>
                <td>배기관 탄화수소</td>
                <td><input class="en-inp" data-field="g_deter_hc" type="text" value="\${E(v('g_deter_hc'))}"></td>
              </tr>
              <tr>
                <td>질소산화물</td>
                <td><input class="en-inp" data-field="g_deter_nox" type="text" value="\${E(v('g_deter_nox'))}"></td>
              </tr>
              <tr>
                <td>증발 탄화수소</td>
                <td><input class="en-inp" data-field="g_deter_evap" type="text" value="\${E(v('g_deter_evap'))}"></td>
              </tr>
            </tbody>
          </table>
        </td>
      </tr>

      <!-- 10. 내구 시험 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">10</td>
        <td class="en-lbl">내구 시험</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_endurance" rows="3" placeholder="내구 시험 내용을 기재하세요">\${E(v('g_endurance'))}</textarea>
            <input type="hidden" data-field="g_endurance_imgs" value="\${E(v('g_endurance_imgs'))}">
            <div class="en-drop" data-field-img="g_endurance"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 11. 주기적재생지수(ki) 시험 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">11</td>
        <td class="en-lbl">주기적재생지수<br>(ki) 시험</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_ki_test" rows="3" placeholder="주기적재생지수(ki) 시험 내용">\${E(v('g_ki_test'))}</textarea>
            <input type="hidden" data-field="g_ki_test_imgs" value="\${E(v('g_ki_test_imgs'))}">
            <div class="en-drop" data-field-img="g_ki_test"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 12. 소음시험 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">12</td>
        <td class="en-lbl">소음시험</td>
        <td style="padding:4px 6px; font-size:8.5pt;">
          <div class="g-chk-row">
            
            <span>소음시험 성적서 제출 내역</span>
          </div>
          <div class="g-chk-row">
            
            <span>소음 시험방법</span>
          </div>
          <div style="padding:2px 8px; font-size:8.5pt; line-height:2.0;">
            - 가속주행소음 : <input class="g-chk-inp" data-field="g_noise_accel" type="text" value="\${E(v('g_noise_accel'))}" style="width:200px;"><br>
            - 배기소음 : <input class="g-chk-inp" data-field="g_noise_exhaust" type="text" value="\${E(v('g_noise_exhaust'))}" style="width:200px;"><br>
            - 경적소음 : <input class="g-chk-inp" data-field="g_noise_horn" type="text" value="\${E(v('g_noise_horn'))}" style="width:200px;">
          </div>
        </td>
      </tr>

      <!-- 13. 동일차종 구성 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">13</td>
        <td class="en-lbl">동일차종 구성</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_same_type" rows="3" placeholder="동일차종 구성 내용을 기재하세요">\${E(v('g_same_type'))}</textarea>
            <input type="hidden" data-field="g_same_type_imgs" value="\${E(v('g_same_type_imgs'))}">
            <div class="en-drop" data-field-img="g_same_type"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

    </tbody>
  </table>

</div>
<div id="qr-footer-wrap" style="margin-top:12px;"></div>
\`;



if (formType==='detail_plan') return \`
<style>
/* ══════ detail_plan 전용 스타일 (emission_noise 동일 틀) ══════ */
.dp-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
  background:#fff;
  color:#111;
  border-radius:8px;
}
.dp-doc-tag { font-size:8.5pt; font-weight:700; color:#444; margin:10px 0 4px; }
.dp-main-title {
  font-size:13pt; font-weight:900; text-align:center;
  margin:4px 0 14px; letter-spacing:.03em; color:#111;
}
.dp-tbl {
  width:100%; border-collapse:collapse;
  font-size:8.5pt; margin-bottom:0;
}
.dp-tbl th, .dp-tbl td {
  border:1px solid #888;
  padding:3px 5px;
  vertical-align:middle;
  color:#111;
}
.dp-sec-th {
  background:#d6e4f7;
  font-weight:700; text-align:left;
  padding:4px 6px; font-size:8.5pt; color:#111;
}
.dp-sub-th {
  background:#eef3fa;
  font-weight:700; text-align:left;
  padding:3px 6px; font-size:8.5pt; color:#111;
}
.dp-th {
  background:#eef3fa;
  font-weight:600; text-align:center;
  font-size:8pt; color:#111;
}
.dp-lbl {
  background:#f5f8ff;
  font-weight:600; color:#111;
  vertical-align:middle;
}
.dp-field {
  display:flex; flex-direction:column; gap:4px;
  padding:3px 4px; box-sizing:border-box; width:100%;
}
.dp-field-text {
  width:100%; font-size:8.5pt; font-family:inherit;
  border:none; background:transparent; padding:2px 0;
  box-sizing:border-box; resize:vertical; color:#111;
  min-height:36px; line-height:1.5;
}
.dp-field-text::placeholder { color:#aaa; }
.dp-field-text:focus { outline:none; border-bottom:1px dashed #4e90d8; }
.dp-inp {
  border:none; background:transparent;
  width:100%; font-size:8.5pt;
  font-family:inherit; padding:0 2px;
  box-sizing:border-box; color:#111;
}
.dp-inp::placeholder { color:#aaa; }
.dp-inp:focus { outline:none; border-bottom:1px solid #4e90d8; }
/* 이미지 드롭존 (emission_noise 동일) */
.dp-drop {
  border:1.5px dashed #b0c4de;
  border-radius:5px;
  background:#f8faff;
  padding:6px 8px;
  cursor:pointer;
  transition:border-color .15s, background .15s;
  position:relative;
  min-height:36px;
}
.dp-drop:hover { border-color:#4e90d8; background:#eef3fa; }
.dp-drop.drag-over { border-color:#2563eb; background:#dbeafe; }
.dp-drop-hint {
  color:#aaa; font-size:7.5pt; text-align:center;
  pointer-events:none; user-select:none;
  display:flex; align-items:center; justify-content:center; gap:4px;
}
.dp-drop input[type=file] { display:none; }
.dp-img-list { display:flex; flex-wrap:wrap; gap:6px; margin-top:4px; }
.dp-img-item { position:relative; display:inline-block; }
.dp-img-item img {
  max-width:140px; max-height:100px;
  border:1px solid #ccc; border-radius:3px;
  display:block; object-fit:contain; background:#fff;
}
.dp-img-item-del {
  position:absolute; top:-6px; right:-6px;
  width:16px; height:16px; border-radius:50%;
  background:#ef4444; color:#fff; font-size:10px;
  display:flex; align-items:center; justify-content:center;
  cursor:pointer; line-height:1; border:none;
  box-shadow:0 1px 3px rgba(0,0,0,.3);
}
.dp-img-item-del:hover { background:#dc2626; }
@media print {
  .dp-wrap { background:#fff !important; color:#000 !important; border-radius:0 !important; }
  .dp-tbl { table-layout:fixed !important; width:100% !important; }
  .dp-tbl th, .dp-tbl td {
    border:1px solid #333 !important; color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important; overflow-wrap:break-word !important;
  }
  .dp-field { height:auto !important; overflow:visible !important; display:flex !important; flex-direction:column !important; }
  textarea.dp-field-text {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; min-height:0 !important; max-height:none !important;
    overflow:visible !important; resize:none !important;
    white-space:pre-wrap !important; word-break:break-word !important;
    overflow-wrap:break-word !important;
    display:block !important; box-sizing:border-box !important;
    -webkit-appearance:none !important; appearance:none !important;
    padding:2px 0 !important;
  }
  .dp-inp {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important;
  }
  input[type=hidden] { display:none !important; }
  .dp-drop {
    border:none !important; background:transparent !important;
    padding:0 !important; min-height:unset !important;
    height:auto !important; overflow:visible !important;
  }
  .dp-drop-hint { display:none !important; }
  .dp-img-item-del { display:none !important; }
  .dp-img-list { gap:4px !important; margin-top:2px !important; }
  .dp-img-item img { max-width:100% !important; max-height:none !important; page-break-inside:avoid; }
  .dp-drop:not(:has(img)) { display:none !important; }
  .dp-sec-th { background:#d6e4f7 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .dp-sub-th { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .dp-th     { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .dp-lbl    { background:#f5f8ff !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .dp-tbl tr { page-break-inside:avoid; }
  .img-att-btn { display:none !important; }
  .img-att-thumbs { display:flex !important; }
}
</style>

<div class="dp-wrap">

<!-- ── 상단 헤더 ── -->
<table class="dp-tbl" style="margin-bottom:12px; table-layout:fixed;">
  <colgroup>
    <col style="width:25%;"><col style="width:25%;"><col style="width:25%;"><col style="width:25%;">
  </colgroup>
  <thead>
    <tr>
      <th class="dp-th">\${BL('dp_h_importer')}</th>
      <th class="dp-th">\${BL('dp_h_certyear')}</th>
      <th class="dp-th">\${BL('dp_h_disp')}</th>
      <th class="dp-th">\${BL('dp_h_famcode')}</th>
    </tr>
  </thead>
  <tbody>
    <tr style="height:26px;">
      <td><input data-field="dp_importer"  class="dp-inp" type="text" placeholder="\${BL('dp_h_importer')}" value="\${E(v('dp_importer'))}"></td>
      <td><input data-field="dp_cert_year" class="dp-inp" type="text" placeholder="예) 2025" value="\${E(v('dp_cert_year'))}"></td>
      <td><input data-field="dp_disp"      class="dp-inp" type="text" placeholder="예) 125cc" value="\${E(v('dp_disp'))}"></td>
      <td><input data-field="dp_fam_code"  class="dp-inp" type="text" placeholder="\${BL('dp_h_famcode')}" value="\${E(v('dp_fam_code'))}"></td>
    </tr>
  </tbody>
</table>

<div class="dp-doc-tag">\${BL('dp_doc_tag')}</div>
<div class="dp-main-title">\${BL('dp_doc_title')}</div>

<!-- ══ 1. 인증소개 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:28%;"><col style="width:72%;"></colgroup>
  <tbody>
    <tr><th class="dp-sec-th" colspan="2">${BL('dp_s1')}</th></tr>

    <!-- 1.1 개발배경 및 특성 -->
    <tr>
      <td class="dp-lbl">${BL('dp_1_1_lbl')}</td>
      <td>
        <div class="dp-field">
          <textarea class="dp-field-text" data-field="dp_1_1" rows="4" placeholder="개발배경 및 특성을 기재하세요">\${E(v('dp_1_1'))}</textarea>
          <input type="hidden" id="dp_1_1_imgs" data-field="dp_1_1_imgs" value="\${E(v('dp_1_1_imgs'))}">
          <div class="dp-drop" id="dp_1_1_drop" onclick="document.getElementById('dp_1_1_fi').click();" ondragover="event.preventDefault();this.classList.add('drag-over');" ondragleave="this.classList.remove('drag-over');" ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('dp_1_1_imgs','dp_1_1_drop',event.dataTransfer.files);">
            <input type="file" id="dp_1_1_fi" accept="image/*" multiple onchange="dpAddFiles('dp_1_1_imgs','dp_1_1_drop',this.files);this.value='';">
            <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
            <div class="dp-img-list" id="dp_1_1_imgs_list"></div>
          </div>
        </div>
      </td>
    </tr>

    <!-- 1.2 신기술 -->
    <tr>
      <td class="dp-lbl">${BL('dp_1_2_lbl')}</td>
      <td>
        <div class="dp-field">
          <textarea class="dp-field-text" data-field="dp_1_2" rows="4" placeholder="신기술 내용을 기재하세요">\${E(v('dp_1_2'))}</textarea>
          <input type="hidden" id="dp_1_2_imgs" data-field="dp_1_2_imgs" value="\${E(v('dp_1_2_imgs'))}">
          <div class="dp-drop" id="dp_1_2_drop" onclick="document.getElementById('dp_1_2_fi').click();" ondragover="event.preventDefault();this.classList.add('drag-over');" ondragleave="this.classList.remove('drag-over');" ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('dp_1_2_imgs','dp_1_2_drop',event.dataTransfer.files);">
            <input type="file" id="dp_1_2_fi" accept="image/*" multiple onchange="dpAddFiles('dp_1_2_imgs','dp_1_2_drop',this.files);this.value='';">
            <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
            <div class="dp-img-list" id="dp_1_2_imgs_list"></div>
          </div>
        </div>
      </td>
    </tr>

    <!-- 1.3 개발 목표 -->
    <tr><td class="dp-sub-th" colspan="2">1.3. 개발 목표 (수입차의 경우 외국인증성적 등으로 갈음)</td></tr>
  </tbody>
</table>
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup>
    <col style="width:12%;"><col style="width:11%;"><col style="width:11%;"><col style="width:11%;"><col style="width:11%;"><col style="width:11%;"><col style="width:11%;"><col style="width:11%;"><col style="width:11%;">
  </colgroup>
  <thead>
    <tr>
      <th class="dp-th">구분</th>
      <th class="dp-th">CO<br>(g/km)</th>
      <th class="dp-th">NOx<br>(g/km)</th>
      <th class="dp-th">MHHC<br>(g/km)</th>
      <th class="dp-th">증발가스<br>(g/test)</th>
      <th class="dp-th">PM<br>(g/km)</th>
      <th class="dp-th">포름알데히드<br>(g/km)</th>
      <th class="dp-th">매연<br>(%/kWh)</th>
      <th class="dp-th">Cold CO<br>(g/km)</th>
    </tr>
  </thead>
  <tbody>
    \${['허용기준','개발 목표치','현행기준 만족도(%)'].map((row,ri)=>\`
    <tr>
      <td class="dp-lbl">\${row}</td>
      \${['co','nox','mhhc','evap','pm','form','smoke','cold_co'].map(col=>\`<td><input class="dp-inp" data-field="dp_1_3_\${ri}_\${col}" type="text" value="\${E(v(\`dp_1_3_\${ri}_\${col}\`))}"></td>\`).join('')}
    </tr>\`).join('')}
  </tbody>
</table>

<!-- ══ 1.4 인증대상자동차 제원 ══ -->
<!-- ── Page 1: 자동차 제원 + 치수 (3col: 20/20/60) ── -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:20%;"><col style="width:20%;"><col style="width:60%;"></colgroup>
  <tbody>
    <tr><th class="dp-sub-th" colspan="3">1.4.&nbsp;인증대상자동차 제원</th></tr>
    <tr><td class="dp-lbl" colspan="2">차명</td><td><input class="dp-inp" data-field="dp_1_4_carname" type="text" value="\${E(v('dp_1_4_carname'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">자동차 형식</td><td><input class="dp-inp" data-field="dp_1_4_type" type="text" value="\${E(v('dp_1_4_type'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="13">자동차 제원</td><td class="dp-lbl">제작사</td><td><input class="dp-inp" data-field="dp_1_4_maker" type="text" value="\${E(v('dp_1_4_maker'))}"></td></tr>
    <tr><td class="dp-lbl">승차인원</td><td><input class="dp-inp" data-field="dp_1_4_passenger" type="text" value="\${E(v('dp_1_4_passenger'))}"></td></tr>
    <tr><td class="dp-lbl">모델년도</td><td><input class="dp-inp" data-field="dp_1_4_modelyear" type="text" value="\${E(v('dp_1_4_modelyear'))}"></td></tr>
    <tr><td class="dp-lbl">제원관리번호</td><td><input class="dp-inp" data-field="dp_1_4_specno" type="text" value="\${E(v('dp_1_4_specno'))}"></td></tr>
    <tr><td class="dp-lbl">구동형태</td><td><input class="dp-inp" data-field="dp_1_4_drive" type="text" value="\${E(v('dp_1_4_drive'))}"></td></tr>
    <tr><td class="dp-lbl">차종</td><td><input class="dp-inp" data-field="dp_1_4_cartype" type="text" value="\${E(v('dp_1_4_cartype'))}"></td></tr>
    <tr><td class="dp-lbl">용도</td><td><input class="dp-inp" data-field="dp_1_4_purpose" type="text" value="\${E(v('dp_1_4_purpose'))}"></td></tr>
    <tr><td class="dp-lbl">변속기 종류</td><td><input class="dp-inp" data-field="dp_1_4_trans" type="text" value="\${E(v('dp_1_4_trans'))}"></td></tr>
    <tr><td class="dp-lbl">차체형상</td><td><input class="dp-inp" data-field="dp_1_4_body" type="text" value="\${E(v('dp_1_4_body'))}"></td></tr>
    <tr><td class="dp-lbl">공차중량(kg)</td><td><input class="dp-inp" data-field="dp_1_4_curb" type="text" value="\${E(v('dp_1_4_curb'))}"></td></tr>
    <tr><td class="dp-lbl">차량 총 중량(kg)</td><td><input class="dp-inp" data-field="dp_1_4_gvw" type="text" value="\${E(v('dp_1_4_gvw'))}"></td></tr>
    <tr><td class="dp-lbl">등가관성 중량(kg)</td><td><input class="dp-inp" data-field="dp_1_4_inertia" type="text" value="\${E(v('dp_1_4_inertia'))}"></td></tr>
    <tr><td class="dp-lbl">실제 다이나모 마력(hp)</td><td><input class="dp-inp" data-field="dp_1_4_dyno" type="text" value="\${E(v('dp_1_4_dyno'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="3">치수</td><td class="dp-lbl">전장(mm)</td><td><input class="dp-inp" data-field="dp_1_4_len" type="text" value="\${E(v('dp_1_4_len'))}"></td></tr>
    <tr><td class="dp-lbl">전폭(mm)</td><td><input class="dp-inp" data-field="dp_1_4_width" type="text" value="\${E(v('dp_1_4_width'))}"></td></tr>
    <tr><td class="dp-lbl">전고(mm)</td><td><input class="dp-inp" data-field="dp_1_4_height" type="text" value="\${E(v('dp_1_4_height'))}"></td></tr>
  </tbody>
</table>

<!-- ── Page 2: 원동기(rowspan=21) + 연료장치(rowspan=6) (4col: 20/20/20/40) ── -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:20%;"><col style="width:20%;"><col style="width:20%;"><col style="width:40%;"></colgroup>
  <tbody>
    <tr><td class="dp-lbl" rowspan="21">원동기</td><td class="dp-lbl" colspan="2">제작회사</td><td><input class="dp-inp" data-field="dp_1_4_eng_maker" type="text" value="\${E(v('dp_1_4_eng_maker'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">연소방식</td><td><input class="dp-inp" data-field="dp_1_4_eng_comb" type="text" value="\${E(v('dp_1_4_eng_comb'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">원동기 형식</td><td><input class="dp-inp" data-field="dp_1_4_eng_type" type="text" value="\${E(v('dp_1_4_eng_type'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">배기량(cc)</td><td><input class="dp-inp" data-field="dp_1_4_eng_disp" type="text" value="\${E(v('dp_1_4_eng_disp'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">원동기부착위치</td><td><input class="dp-inp" data-field="dp_1_4_eng_pos" type="text" value="\${E(v('dp_1_4_eng_pos'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">사용연료</td><td><input class="dp-inp" data-field="dp_1_4_eng_fuel" type="text" value="\${E(v('dp_1_4_eng_fuel'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">실린더 수</td><td><input class="dp-inp" data-field="dp_1_4_eng_cyl" type="text" value="\${E(v('dp_1_4_eng_cyl'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">실린더 배열</td><td><input class="dp-inp" data-field="dp_1_4_eng_cylarr" type="text" value="\${E(v('dp_1_4_eng_cylarr'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">연소실 형식</td><td><input class="dp-inp" data-field="dp_1_4_eng_chamber" type="text" value="\${E(v('dp_1_4_eng_chamber'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">최대출력(ps/rpm)</td><td><input class="dp-inp" data-field="dp_1_4_eng_maxpow" type="text" value="\${E(v('dp_1_4_eng_maxpow'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">최대토크(kg-m/rpm)</td><td><input class="dp-inp" data-field="dp_1_4_eng_maxtq" type="text" value="\${E(v('dp_1_4_eng_maxtq'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">보어*스트로크(mm)</td><td><input class="dp-inp" data-field="dp_1_4_eng_bore" type="text" value="\${E(v('dp_1_4_eng_bore'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">공회전속도(rpm)</td><td><input class="dp-inp" data-field="dp_1_4_eng_idle" type="text" value="\${E(v('dp_1_4_eng_idle'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">냉각방식</td><td><input class="dp-inp" data-field="dp_1_4_eng_cool" type="text" value="\${E(v('dp_1_4_eng_cool'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">공기흡입방식</td><td><input class="dp-inp" data-field="dp_1_4_eng_intake" type="text" value="\${E(v('dp_1_4_eng_intake'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">흡기매니폴드</td><td class="dp-lbl">포트크기</td><td><input class="dp-inp" data-field="dp_1_4_inm_size" type="text" value="\${E(v('dp_1_4_inm_size'))}"></td></tr>
    <tr><td class="dp-lbl">포트형상</td><td><input class="dp-inp" data-field="dp_1_4_inm_shape" type="text" value="\${E(v('dp_1_4_inm_shape'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">배기매니폴드</td><td class="dp-lbl">포트크기(mm)</td><td><input class="dp-inp" data-field="dp_1_4_exm_size" type="text" value="\${E(v('dp_1_4_exm_size'))}"></td></tr>
    <tr><td class="dp-lbl">포트형상</td><td><input class="dp-inp" data-field="dp_1_4_exm_shape" type="text" value="\${E(v('dp_1_4_exm_shape'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">압축비</td><td><input class="dp-inp" data-field="dp_1_4_compress" type="text" value="\${E(v('dp_1_4_compress'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">점화시기(Degree)</td><td><input class="dp-inp" data-field="dp_1_4_ign_timing" type="text" value="\${E(v('dp_1_4_ign_timing'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="6">연료장치</td><td class="dp-lbl" colspan="2">연료공급방식</td><td><input class="dp-inp" data-field="dp_1_4_fuel_supply" type="text" value="\${E(v('dp_1_4_fuel_supply'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="3">연료탱크</td><td class="dp-lbl">용량(ℓ)</td><td><input class="dp-inp" data-field="dp_1_4_tank_vol" type="text" value="\${E(v('dp_1_4_tank_vol'))}"></td></tr>
    <tr><td class="dp-lbl">위치</td><td><input class="dp-inp" data-field="dp_1_4_tank_pos" type="text" value="\${E(v('dp_1_4_tank_pos'))}"></td></tr>
    <tr><td class="dp-lbl">재질</td><td><input class="dp-inp" data-field="dp_1_4_tank_mat" type="text" value="\${E(v('dp_1_4_tank_mat'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">제어공기<br>청정기</td><td class="dp-lbl">형식</td><td><input class="dp-inp" data-field="dp_1_4_air_type" type="text" value="\${E(v('dp_1_4_air_type'))}"></td></tr>
    <tr><td class="dp-lbl">수</td><td><input class="dp-inp" data-field="dp_1_4_filter_cnt" type="text" value="\${E(v('dp_1_4_filter_cnt'))}"></td></tr>
  </tbody>
</table>

<!-- ── Page 3: 동력전달장치 + 전기자동차 + 타이어 (5col: 15/15/15/15/40) ── -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:15%;"><col style="width:15%;"><col style="width:15%;"><col style="width:15%;"><col style="width:40%;"></colgroup>
  <tbody>
    <tr><td class="dp-lbl" rowspan="16">동력전달장치</td><td class="dp-lbl" rowspan="2">클러치</td><td class="dp-lbl" colspan="2">형식</td><td><input class="dp-inp" data-field="dp_1_4_clutch_type" type="text" value="\${E(v('dp_1_4_clutch_type'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">조작방식</td><td><input class="dp-inp" data-field="dp_1_4_clutch_op" type="text" value="\${E(v('dp_1_4_clutch_op'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="11">변속기</td><td class="dp-lbl" rowspan="2">형식</td><td class="dp-lbl">전진</td><td><input class="dp-inp" data-field="dp_1_4_trans_fwd" type="text" value="\${E(v('dp_1_4_trans_fwd'))}"></td></tr>
    <tr><td class="dp-lbl">후진</td><td><input class="dp-inp" data-field="dp_1_4_trans_rev" type="text" value="\${E(v('dp_1_4_trans_rev'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">조작방식</td><td><input class="dp-inp" data-field="dp_1_4_trans_op" type="text" value="\${E(v('dp_1_4_trans_op'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="8">변속비</td><td class="dp-lbl">1단</td><td><input class="dp-inp" data-field="dp_1_4_gear_1" type="text" value="\${E(v('dp_1_4_gear_1'))}"></td></tr>
    <tr><td class="dp-lbl">2단</td><td><input class="dp-inp" data-field="dp_1_4_gear_2" type="text" value="\${E(v('dp_1_4_gear_2'))}"></td></tr>
    <tr><td class="dp-lbl">3단</td><td><input class="dp-inp" data-field="dp_1_4_gear_3" type="text" value="\${E(v('dp_1_4_gear_3'))}"></td></tr>
    <tr><td class="dp-lbl">4단</td><td><input class="dp-inp" data-field="dp_1_4_gear_4" type="text" value="\${E(v('dp_1_4_gear_4'))}"></td></tr>
    <tr><td class="dp-lbl">5단</td><td><input class="dp-inp" data-field="dp_1_4_gear_5" type="text" value="\${E(v('dp_1_4_gear_5'))}"></td></tr>
    <tr><td class="dp-lbl">6단</td><td><input class="dp-inp" data-field="dp_1_4_gear_6" type="text" value="\${E(v('dp_1_4_gear_6'))}"></td></tr>
    <tr><td class="dp-lbl">7단</td><td><input class="dp-inp" data-field="dp_1_4_gear_7" type="text" value="\${E(v('dp_1_4_gear_7'))}"></td></tr>
    <tr><td class="dp-lbl">후진</td><td><input class="dp-inp" data-field="dp_1_4_gear_8" type="text" value="\${E(v('dp_1_4_gear_8'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">감속비</td><td class="dp-lbl" colspan="2">제1 감속비</td><td><input class="dp-inp" data-field="dp_1_4_red1" type="text" value="\${E(v('dp_1_4_red1'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">제2 감속비</td><td><input class="dp-inp" data-field="dp_1_4_red2" type="text" value="\${E(v('dp_1_4_red2'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="3">N/V 비</td><td><input class="dp-inp" data-field="dp_1_4_nv" type="text" value="\${E(v('dp_1_4_nv'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="4">전기자동차 관련 제원</td><td class="dp-lbl" colspan="3">전동기 형식</td><td><input class="dp-inp" data-field="dp_1_4_ev_motor" type="text" value="\${E(v('dp_1_4_ev_motor'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="3">축전지 정격전압 및 용량</td><td><input class="dp-inp" data-field="dp_1_4_ev_batt" type="text" value="\${E(v('dp_1_4_ev_batt'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="3">전동기 최대출력</td><td><input class="dp-inp" data-field="dp_1_4_ev_pow" type="text" value="\${E(v('dp_1_4_ev_pow'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="3">1회충전 주행거리</td><td><input class="dp-inp" data-field="dp_1_4_ev_range" type="text" value="\${E(v('dp_1_4_ev_range'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="6">타이어</td><td class="dp-lbl" colspan="3">타이어 제조회사</td><td><input class="dp-inp" data-field="dp_1_4_tire_maker" type="text" value="\${E(v('dp_1_4_tire_maker'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="3">타이어 구조</td><td><input class="dp-inp" data-field="dp_1_4_tire_struct" type="text" value="\${E(v('dp_1_4_tire_struct'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">타이어 크기</td><td class="dp-lbl" colspan="2">전</td><td><input class="dp-inp" data-field="dp_1_4_tire_fsize" type="text" value="\${E(v('dp_1_4_tire_fsize'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">후</td><td><input class="dp-inp" data-field="dp_1_4_tire_rsize" type="text" value="\${E(v('dp_1_4_tire_rsize'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">타이어<br>공기압</td><td class="dp-lbl" colspan="2">전</td><td><input class="dp-inp" data-field="dp_1_4_tire_fpres" type="text" value="\${E(v('dp_1_4_tire_fpres'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">후</td><td><input class="dp-inp" data-field="dp_1_4_tire_rpres" type="text" value="\${E(v('dp_1_4_tire_rpres'))}"></td></tr>
  </tbody>
</table>

<!-- ── Page 4: 촉매/배출가스/캐니스터/소음기/경보장치 (4col: 20/20/20/40) ── -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:20%;"><col style="width:20%;"><col style="width:20%;"><col style="width:40%;"></colgroup>
  <tbody>
    <tr><td class="dp-lbl" rowspan="5">촉매</td><td class="dp-lbl" colspan="2">종류</td><td><input class="dp-inp" data-field="dp_1_4_cat_type" type="text" value="\${E(v('dp_1_4_cat_type'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">귀금속 성분</td><td><input class="dp-inp" data-field="dp_1_4_cat_pm" type="text" value="\${E(v('dp_1_4_cat_pm'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">귀금속량(g)</td><td><input class="dp-inp" data-field="dp_1_4_cat_pmg" type="text" value="\${E(v('dp_1_4_cat_pmg'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">용량(㎤)</td><td><input class="dp-inp" data-field="dp_1_4_cat_vol" type="text" value="\${E(v('dp_1_4_cat_vol'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">귀금속 물질비(Pt:Pd:Rh)</td><td><input class="dp-inp" data-field="dp_1_4_cat_ratio" type="text" value="\${E(v('dp_1_4_cat_ratio'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="3">배출가스 시험에<br>관한 사항</td><td class="dp-lbl" colspan="2">실 도로 부하력(hp)</td><td><input class="dp-inp" data-field="dp_1_4_roadload" type="text" value="\${E(v('dp_1_4_roadload'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">도로흡력력계수</td><td><input class="dp-inp" data-field="dp_1_4_roadcoef" type="text" value="\${E(v('dp_1_4_roadcoef'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">코스트다운 시간(sec)</td><td><input class="dp-inp" data-field="dp_1_4_coastdown" type="text" value="\${E(v('dp_1_4_coastdown'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="4">캐니스터</td><td class="dp-lbl" colspan="2">캐니스터의 흡수 용량</td><td><input class="dp-inp" data-field="dp_1_4_can_cap" type="text" value="\${E(v('dp_1_4_can_cap'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">캐니스터의 크기(cc)</td><td><input class="dp-inp" data-field="dp_1_4_can_size" type="text" value="\${E(v('dp_1_4_can_size'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">캐니스터의 매체</td><td><input class="dp-inp" data-field="dp_1_4_can_media" type="text" value="\${E(v('dp_1_4_can_media'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">40%연료시 탱크의 최대 증발가스 용량</td><td><input class="dp-inp" data-field="dp_1_4_can_evap" type="text" value="\${E(v('dp_1_4_can_evap'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="4">소음기</td><td class="dp-lbl" rowspan="2">주 소음기</td><td class="dp-lbl">재질</td><td><input class="dp-inp" data-field="dp_1_4_muf_main_mat" type="text" value="\${E(v('dp_1_4_muf_main_mat'))}"></td></tr>
    <tr><td class="dp-lbl">용량(L)</td><td><input class="dp-inp" data-field="dp_1_4_muf_main_vol" type="text" value="\${E(v('dp_1_4_muf_main_vol'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">보조 소음기</td><td class="dp-lbl">재질</td><td><input class="dp-inp" data-field="dp_1_4_muf_sub_mat" type="text" value="\${E(v('dp_1_4_muf_sub_mat'))}"></td></tr>
    <tr><td class="dp-lbl">용량(L)</td><td><input class="dp-inp" data-field="dp_1_4_muf_sub_vol" type="text" value="\${E(v('dp_1_4_muf_sub_vol'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">경보장치</td><td class="dp-lbl" rowspan="2">경음기</td><td class="dp-lbl">형식</td><td><input class="dp-inp" data-field="dp_1_4_horn_type" type="text" value="\${E(v('dp_1_4_horn_type'))}"></td></tr>
    <tr><td class="dp-lbl">성능(dB(C))</td><td><input class="dp-inp" data-field="dp_1_4_horn_db" type="text" value="\${E(v('dp_1_4_horn_db'))}"></td></tr>
  </tbody>
</table>

<!-- ══ 2. 기밀사항 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:100%;"></colgroup>
  <tbody>
    <tr><th class="dp-sec-th">${BL('dp_s2')}</th></tr>
    <tr><td class="dp-sub-th">2.1. 기밀에 대한 요청</td></tr>
    <tr><td>
      <div class="dp-field">
        <textarea class="dp-field-text" data-field="dp_2_1" rows="3" placeholder="기밀 요청 내용을 기재하세요">\${E(v('dp_2_1'))}</textarea>
      </div>
    </td></tr>
  </tbody>
</table>

<!-- ══ 3. 인증시험 연료 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:18%;"><col style="width:27%;"><col style="width:27%;"><col style="width:28%;"></colgroup>
  <thead>
    <tr><th class="dp-sec-th" colspan="4">${BL('dp_s3')}</th></tr>
    <tr>
      <th class="dp-th">구분</th>
      <th class="dp-th">항목</th>
      <th class="dp-th">시험용연료</th>
      <th class="dp-th">주행거리 축적용 연료</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="dp-lbl" rowspan="10">휘발유</td>
      <td class="dp-lbl">옥탄가(리서치법)</td>
      <td><input class="dp-inp" data-field="dp_f_gas_oct_test" type="text" value="\${E(v('dp_f_gas_oct_test'))}"></td>
      <td><input class="dp-inp" data-field="dp_f_gas_oct_acc" type="text" value="\${E(v('dp_f_gas_oct_acc'))}"></td>
    </tr>
    \${[
      ['방향족화합물함량(부피%)','dp_f_gas_arom'],
      ['벤젠함량(부피%)','dp_f_gas_benz'],
      ['산소함량(무게%)','dp_f_gas_oxy'],
      ['납함량(g/ℓ)','dp_f_gas_pb'],
      ['인함량(g/ℓ)','dp_f_gas_p'],
      ['올레핀함량(부피%)','dp_f_gas_olef'],
      ['증기압(kPa)','dp_f_gas_vp'],
      ['90%유출온도(℃)','dp_f_gas_90t'],
      ['황함량(무게%)','dp_f_gas_s'],
    ].map(([item,fld])=>\`<tr>
      <td class="dp-lbl">\${item}</td>
      <td><input class="dp-inp" data-field="\${fld}_test" type="text" value="\${E(v('\${fld}_test'))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_acc" type="text" value="\${E(v('\${fld}_acc'))}"></td>
    </tr>\`).join('')}
    <tr>
      <td class="dp-lbl" rowspan="5">경유</td>
      <td class="dp-lbl">10% 잔류탄소량(%)</td>
      <td><input class="dp-inp" data-field="dp_f_die_rc_test" type="text" value="\${E(v('dp_f_die_rc_test'))}"></td>
      <td><input class="dp-inp" data-field="dp_f_die_rc_acc" type="text" value="\${E(v('dp_f_die_rc_acc'))}"></td>
    </tr>
    \${[
      ['황함량(무게%)','dp_f_die_s'],
      ['세탄지수','dp_f_die_ci'],
      ['90%유출온도(℃)','dp_f_die_90t'],
      ['방향족화합물함량(부피%)','dp_f_die_arom'],
    ].map(([item,fld])=>\`<tr>
      <td class="dp-lbl">\${item}</td>
      <td><input class="dp-inp" data-field="\${fld}_test" type="text" value="\${E(v('\${fld}_test'))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_acc" type="text" value="\${E(v('\${fld}_acc'))}"></td>
    </tr>\`).join('')}
    <tr>
      <td class="dp-lbl" rowspan="2">LPG</td>
      <td class="dp-lbl">10% 잔류탄소량(%)</td>
      <td><input class="dp-inp" data-field="dp_f_lpg_rc_test" type="text" value="\${E(v('dp_f_lpg_rc_test'))}"></td>
      <td><input class="dp-inp" data-field="dp_f_lpg_rc_acc" type="text" value="\${E(v('dp_f_lpg_rc_acc'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">황함량(무게%)</td>
      <td><input class="dp-inp" data-field="dp_f_lpg_s_test" type="text" value="\${E(v('dp_f_lpg_s_test'))}"></td>
      <td><input class="dp-inp" data-field="dp_f_lpg_s_acc" type="text" value="\${E(v('dp_f_lpg_s_acc'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">연료구입처</td>
      <td colspan="2"><input class="dp-inp" data-field="dp_f_source" type="text" value="\${E(v('dp_f_source'))}"></td>
    </tr>
  </tbody>
</table>

<!-- ══ 4. 시험설비 및 배출가스·소음 측정장비 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:22%;"><col style="width:13%;"><col style="width:13%;"><col style="width:13%;"><col style="width:16%;"><col style="width:13%;"><col style="width:10%;"></colgroup>
  <thead>
    <tr><th class="dp-sec-th" colspan="7">${BL('dp_s4')}</th></tr>
    <tr><th class="dp-sub-th" colspan="7">4.1. 배출가스 측정장비</th></tr>
    <tr>
      <th class="dp-th">설비, 장비명</th>
      <th class="dp-th">제작사</th>
      <th class="dp-th">모델명</th>
      <th class="dp-th">형식승인번호</th>
      <th class="dp-th">형식승인일자</th>
      <th class="dp-th">실험실명</th>
      <th class="dp-th">최종정도검사일</th>
    </tr>
  </thead>
  <tbody>
    \${[0,1,2,3,4].map(i=>\`<tr>
      <td><input class="dp-inp" data-field="dp_4_1_name_\${i}" type="text" value="\${E(v(\`dp_4_1_name_\${i}\`))}"></td>
      <td><input class="dp-inp" data-field="dp_4_1_maker_\${i}" type="text" value="\${E(v(\`dp_4_1_maker_\${i}\`))}"></td>
      <td><input class="dp-inp" data-field="dp_4_1_model_\${i}" type="text" value="\${E(v(\`dp_4_1_model_\${i}\`))}"></td>
      <td><input class="dp-inp" data-field="dp_4_1_appno_\${i}" type="text" value="\${E(v(\`dp_4_1_appno_\${i}\`))}"></td>
      <td><input class="dp-inp" data-field="dp_4_1_appdt_\${i}" type="text" value="\${E(v(\`dp_4_1_appdt_\${i}\`))}"></td>
      <td><input class="dp-inp" data-field="dp_4_1_lab_\${i}" type="text" value="\${E(v(\`dp_4_1_lab_\${i}\`))}"></td>
      <td><input class="dp-inp" data-field="dp_4_1_calib_\${i}" type="text" value="\${E(v(\`dp_4_1_calib_\${i}\`))}"></td>
    </tr>\`).join('')}
    <tr><th class="dp-sub-th" colspan="7">4.2. 소음 측정장비</th></tr>
    <tr>
      <th class="dp-th">설비, 장비명</th>
      <th class="dp-th">제작사</th>
      <th class="dp-th">모델명</th>
      <th class="dp-th">형식승인번호</th>
      <th class="dp-th">형식승인일자</th>
      <th class="dp-th">실험실명</th>
      <th class="dp-th">최종정도검사일</th>
    </tr>
    \${[0,1,2].map(i=>\`<tr>
      <td><input class="dp-inp" data-field="dp_4_2_name_\${i}" type="text" value="\${E(v(\`dp_4_2_name_\${i}\`))}"></td>
      <td><input class="dp-inp" data-field="dp_4_2_maker_\${i}" type="text" value="\${E(v(\`dp_4_2_maker_\${i}\`))}"></td>
      <td><input class="dp-inp" data-field="dp_4_2_model_\${i}" type="text" value="\${E(v(\`dp_4_2_model_\${i}\`))}"></td>
      <td><input class="dp-inp" data-field="dp_4_2_appno_\${i}" type="text" value="\${E(v(\`dp_4_2_appno_\${i}\`))}"></td>
      <td><input class="dp-inp" data-field="dp_4_2_appdt_\${i}" type="text" value="\${E(v(\`dp_4_2_appdt_\${i}\`))}"></td>
      <td><input class="dp-inp" data-field="dp_4_2_lab_\${i}" type="text" value="\${E(v(\`dp_4_2_lab_\${i}\`))}"></td>
      <td><input class="dp-inp" data-field="dp_4_2_calib_\${i}" type="text" value="\${E(v(\`dp_4_2_calib_\${i}\`))}"></td>
    </tr>\`).join('')}
  </tbody>
</table>

<!-- ══ 5. 시험절차 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:28%;"><col style="width:72%;"></colgroup>
  <tbody>
    <tr><th class="dp-sec-th" colspan="2">${BL('dp_s5')}</th></tr>
    <tr><th class="dp-sub-th" colspan="2">${BL('dp_5_1_lbl')}</th></tr>
    <tr><td class="dp-lbl">5.1.1. 시험장소</td><td><input class="dp-inp" data-field="dp_5_1_1" type="text" value="\${E(v('dp_5_1_1'))}"></td></tr>
    <tr><td class="dp-lbl">5.1.2. 시험절차</td><td><input class="dp-inp" data-field="dp_5_1_2" type="text" value="\${E(v('dp_5_1_2'))}"></td></tr>
    <tr><th class="dp-sub-th" colspan="2">${BL('dp_5_2_lbl')}</th></tr>
    <tr><td class="dp-lbl">5.2.1. 내구성시험 주행여부</td><td><input class="dp-inp" data-field="dp_5_2_1" type="text" value="\${E(v('dp_5_2_1'))}"></td></tr>
    <tr><td class="dp-lbl">5.2.2. 길들이기 주행여부</td><td><input class="dp-inp" data-field="dp_5_2_2" type="text" value="\${E(v('dp_5_2_2'))}"></td></tr>
    <tr><td class="dp-lbl">5.2.3. 주행예정 기간</td><td><input class="dp-inp" data-field="dp_5_2_3" type="text" value="\${E(v('dp_5_2_3'))}"></td></tr>
    <tr><td class="dp-lbl">5.2.4. 주행장소</td><td><input class="dp-inp" data-field="dp_5_2_4" type="text" value="\${E(v('dp_5_2_4'))}"></td></tr>
    <tr><td class="dp-lbl">5.2.5. 주행절차</td><td><input class="dp-inp" data-field="dp_5_2_5" type="text" value="\${E(v('dp_5_2_5'))}"></td></tr>
    <tr><th class="dp-sub-th" colspan="2">${BL('dp_5_3_lbl')}</th></tr>
    <tr><td class="dp-lbl">5.3.1. 시험장소</td><td><input class="dp-inp" data-field="dp_5_3_1" type="text" value="\${E(v('dp_5_3_1'))}"></td></tr>
    <tr><td class="dp-lbl">5.3.2. 시험절차</td><td><input class="dp-inp" data-field="dp_5_3_2" type="text" value="\${E(v('dp_5_3_2'))}"></td></tr>
    <tr><th class="dp-sub-th" colspan="2">${BL('dp_5_4_lbl')}</th></tr>
    <tr><td class="dp-lbl">5.4.1. 시험장소</td><td><input class="dp-inp" data-field="dp_5_4_1" type="text" value="\${E(v('dp_5_4_1'))}"></td></tr>
    <tr><td class="dp-lbl">5.4.2. 시험절차</td><td><input class="dp-inp" data-field="dp_5_4_2" type="text" value="\${E(v('dp_5_4_2'))}"></td></tr>
  </tbody>
</table>

<!-- ══ 6. 정비 및 보증 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:12%;"><col style="width:18%;"><col style="width:10%;"><col style="width:10%;"><col style="width:10%;"><col style="width:10%;"><col style="width:10%;"><col style="width:20%;"></colgroup>
  <tbody>
    <tr><th class="dp-sec-th" colspan="8">${BL('dp_s6')}</th></tr>
    <tr><th class="dp-sub-th" colspan="8">6.1.&#8194;시험차량의 정비계획</th></tr>
    <tr><th class="dp-sub-th" colspan="8">6.1.1.&#8202;정기정비</th></tr>
    <tr>
      <th class="dp-th">구분</th><th class="dp-th">항목</th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_1_1_km_0" type="text" value="\${E(v('dp_6_1_1_km_0'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_1_1_km_1" type="text" value="\${E(v('dp_6_1_1_km_1'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_1_1_km_2" type="text" value="\${E(v('dp_6_1_1_km_2'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_1_1_km_3" type="text" value="\${E(v('dp_6_1_1_km_3'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_1_1_km_4" type="text" value="\${E(v('dp_6_1_1_km_4'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th">비고</th>
    </tr>
    <tr>
      <td class="dp-lbl">엔진</td><td><input class="dp-inp" data-field="dp_6_1_1_0_item" type="text" value="\${E(v('dp_6_1_1_0_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_0_0" type="text" value="\${E(v('dp_6_1_1_0_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_0_1" type="text" value="\${E(v('dp_6_1_1_0_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_0_2" type="text" value="\${E(v('dp_6_1_1_0_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_0_3" type="text" value="\${E(v('dp_6_1_1_0_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_0_4" type="text" value="\${E(v('dp_6_1_1_0_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_0_note" type="text" value="\${E(v('dp_6_1_1_0_note'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">점화장치</td><td><input class="dp-inp" data-field="dp_6_1_1_1_item" type="text" value="\${E(v('dp_6_1_1_1_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_1_0" type="text" value="\${E(v('dp_6_1_1_1_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_1_1" type="text" value="\${E(v('dp_6_1_1_1_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_1_2" type="text" value="\${E(v('dp_6_1_1_1_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_1_3" type="text" value="\${E(v('dp_6_1_1_1_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_1_4" type="text" value="\${E(v('dp_6_1_1_1_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_1_note" type="text" value="\${E(v('dp_6_1_1_1_note'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">샤시</td><td><input class="dp-inp" data-field="dp_6_1_1_2_item" type="text" value="\${E(v('dp_6_1_1_2_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_2_0" type="text" value="\${E(v('dp_6_1_1_2_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_2_1" type="text" value="\${E(v('dp_6_1_1_2_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_2_2" type="text" value="\${E(v('dp_6_1_1_2_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_2_3" type="text" value="\${E(v('dp_6_1_1_2_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_2_4" type="text" value="\${E(v('dp_6_1_1_2_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_2_note" type="text" value="\${E(v('dp_6_1_1_2_note'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">기타</td><td><input class="dp-inp" data-field="dp_6_1_1_3_item" type="text" value="\${E(v('dp_6_1_1_3_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_3_0" type="text" value="\${E(v('dp_6_1_1_3_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_3_1" type="text" value="\${E(v('dp_6_1_1_3_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_3_2" type="text" value="\${E(v('dp_6_1_1_3_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_3_3" type="text" value="\${E(v('dp_6_1_1_3_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_3_4" type="text" value="\${E(v('dp_6_1_1_3_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_3_note" type="text" value="\${E(v('dp_6_1_1_3_note'))}"></td>
    </tr>
    <tr><th class="dp-sub-th" colspan="8">6.1.2.&#8202;비정기정비</th></tr>
    <tr>
      <td class="dp-lbl" colspan="2">A.&nbsp;엔진 :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_1_2_0" rows="2" placeholder="엔진 내용">\${E(v('dp_6_1_2_0'))}</textarea></div></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">B.&nbsp;점화장치 :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_1_2_1" rows="2" placeholder="점화장치 내용">\${E(v('dp_6_1_2_1'))}</textarea></div></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">C.&nbsp;샤시 :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_1_2_2" rows="2" placeholder="샤시 내용">\${E(v('dp_6_1_2_2'))}</textarea></div></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">D.&nbsp;기타 :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_1_2_3" rows="2" placeholder="기타 내용">\${E(v('dp_6_1_2_3'))}</textarea></div></td>
    </tr>
    <tr><th class="dp-sub-th" colspan="8">6.2.&#8194;차량구입자에 대한 추천정비</th></tr>
    <tr>
      <th class="dp-th">구분</th><th class="dp-th">항목</th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_2_km_0" type="text" value="\${E(v('dp_6_2_km_0'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_2_km_1" type="text" value="\${E(v('dp_6_2_km_1'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_2_km_2" type="text" value="\${E(v('dp_6_2_km_2'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_2_km_3" type="text" value="\${E(v('dp_6_2_km_3'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_2_km_4" type="text" value="\${E(v('dp_6_2_km_4'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th">비고</th>
    </tr>
    <tr>
      <td class="dp-lbl">엔진</td><td><input class="dp-inp" data-field="dp_6_2_0_item" type="text" value="\${E(v('dp_6_2_0_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_0_0" type="text" value="\${E(v('dp_6_2_0_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_0_1" type="text" value="\${E(v('dp_6_2_0_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_0_2" type="text" value="\${E(v('dp_6_2_0_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_0_3" type="text" value="\${E(v('dp_6_2_0_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_0_4" type="text" value="\${E(v('dp_6_2_0_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_0_note" type="text" value="\${E(v('dp_6_2_0_note'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">점화장치</td><td><input class="dp-inp" data-field="dp_6_2_1_item" type="text" value="\${E(v('dp_6_2_1_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_1_0" type="text" value="\${E(v('dp_6_2_1_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_1_1" type="text" value="\${E(v('dp_6_2_1_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_1_2" type="text" value="\${E(v('dp_6_2_1_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_1_3" type="text" value="\${E(v('dp_6_2_1_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_1_4" type="text" value="\${E(v('dp_6_2_1_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_1_note" type="text" value="\${E(v('dp_6_2_1_note'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">샤시</td><td><input class="dp-inp" data-field="dp_6_2_2_item" type="text" value="\${E(v('dp_6_2_2_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_2_0" type="text" value="\${E(v('dp_6_2_2_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_2_1" type="text" value="\${E(v('dp_6_2_2_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_2_2" type="text" value="\${E(v('dp_6_2_2_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_2_3" type="text" value="\${E(v('dp_6_2_2_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_2_4" type="text" value="\${E(v('dp_6_2_2_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_2_note" type="text" value="\${E(v('dp_6_2_2_note'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">기타</td><td><input class="dp-inp" data-field="dp_6_2_3_item" type="text" value="\${E(v('dp_6_2_3_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_3_0" type="text" value="\${E(v('dp_6_2_3_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_3_1" type="text" value="\${E(v('dp_6_2_3_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_3_2" type="text" value="\${E(v('dp_6_2_3_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_3_3" type="text" value="\${E(v('dp_6_2_3_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_3_4" type="text" value="\${E(v('dp_6_2_3_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_3_note" type="text" value="\${E(v('dp_6_2_3_note'))}"></td>
    </tr>
    <tr><th class="dp-sub-th" colspan="8">6.3.&#8194;보증에 관한 설명</th></tr>
    <tr>
      <td class="dp-lbl" colspan="2">6.3.1.&#8202;보증내용 :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_3_0" rows="2" placeholder="보증내용">\${E(v('dp_6_3_0'))}</textarea></div></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">6.3.2.&#8202;보증기간 :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_3_1" rows="2" placeholder="보증기간">\${E(v('dp_6_3_1'))}</textarea></div></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">6.3.3.&#8202;보증에서 제외되는 사항 :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_3_2" rows="2" placeholder="보증에서 제외되는 사항">\${E(v('dp_6_3_2'))}</textarea></div></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">6.3.4.&#8202;차량소유자의 의무 :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_3_3" rows="2" placeholder="차량소유자의 의무">\${E(v('dp_6_3_3'))}</textarea></div></td>
    </tr>
  </tbody>
</table>

<!-- ══ 7. 배출가스 표지판 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:28%;"><col style="width:72%;"></colgroup>
  <tbody>
    <tr><th class="dp-sec-th" colspan="2">${BL('dp_s7')}</th></tr>
    <tr>
      <td class="dp-lbl">${BL('dp_7_1_lbl')}</td>
      <td>
        <div class="dp-field">
          <textarea class="dp-field-text" data-field="dp_7_1" rows="3" placeholder="표지판 견본 설명">\${E(v('dp_7_1'))}</textarea>
          <input type="hidden" id="dp_7_1_imgs" data-field="dp_7_1_imgs" value="\${E(v('dp_7_1_imgs'))}">
          <div class="dp-drop" id="dp_7_1_drop" onclick="document.getElementById('dp_7_1_fi').click();" ondragover="event.preventDefault();this.classList.add('drag-over');" ondragleave="this.classList.remove('drag-over');" ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('dp_7_1_imgs','dp_7_1_drop',event.dataTransfer.files);">
            <input type="file" id="dp_7_1_fi" accept="image/*" multiple onchange="dpAddFiles('dp_7_1_imgs','dp_7_1_drop',this.files);this.value='';">
            <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
            <div class="dp-img-list" id="dp_7_1_imgs_list"></div>
          </div>
        </div>
      </td>
    </tr>
    <tr>
      <td class="dp-lbl">${BL('dp_7_2_lbl')}</td>
      <td>
        <div class="dp-field">
          <textarea class="dp-field-text" data-field="dp_7_2" rows="3" placeholder="부착위치 등 기재">\${E(v('dp_7_2'))}</textarea>
          <input type="hidden" id="dp_7_2_imgs" data-field="dp_7_2_imgs" value="\${E(v('dp_7_2_imgs'))}">
          <div class="dp-drop" id="dp_7_2_drop" onclick="document.getElementById('dp_7_2_fi').click();" ondragover="event.preventDefault();this.classList.add('drag-over');" ondragleave="this.classList.remove('drag-over');" ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('dp_7_2_imgs','dp_7_2_drop',event.dataTransfer.files);">
            <input type="file" id="dp_7_2_fi" accept="image/*" multiple onchange="dpAddFiles('dp_7_2_imgs','dp_7_2_drop',this.files);this.value='';">
            <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
            <div class="dp-img-list" id="dp_7_2_imgs_list"></div>
          </div>
        </div>
      </td>
    </tr>
  </tbody>
</table>

<!-- ══ 8. 배출가스 제어기술 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup>
    <col style="width:13%;"><col style="width:14%;"><col style="width:28%;"><col style="width:27%;"><col style="width:18%;">
  </colgroup>
  <tbody>
    <tr><th class="dp-sec-th" colspan="5">${BL('dp_s8')}</th></tr>
    \${[
      ['8.1. 연료장치','dp_8_1',['연료공급계','연료제어계','연료분사계']],
      ['8.2. 흡배기장치','dp_8_2',['흡기장치','배기장치']],
      ['8.3. 점화장치','dp_8_3',['점화장치']],
      ['8.4. 크랭크케이스제어장치','dp_8_4',['크랭크케이스제어장치']],
      ['8.5. 엔진','dp_8_5',['엔진']],
      ['8.6. 촉매전환기','dp_8_6',['촉매형식','촉매물질 구성','체적','촉매무게']],
      ['8.7. 배출가스 재순환장치(EGR)','dp_8_7',['배출가스재순환장치']],
      ['8.8. 전자제어장치','dp_8_8',['장치/제원/입출력신호','엔진토크 산출방법과 적합성 자료']],
      ['8.9. 기타 배출가스 제어장치','dp_8_9',['기타 장치']],
    ].map(([sec,pfx,rows])=>\`
    <tr><th class="dp-sub-th" colspan="5">\${sec}</th></tr>
    <tr>
      <th class="dp-th">항목</th><th class="dp-th">세부항목</th>
      <th class="dp-th">구조/업체/크기/용량 등</th>
      <th class="dp-th">제어기술/제어원리</th>
      <th class="dp-th">배출가스 저감효과</th>
    </tr>
    \${rows.map((row,ri)=>\`<tr>
      <td class="dp-lbl">\${row}</td><td><input class="dp-inp" data-field="\${pfx}_\${ri}_sub" type="text" value="\${E(v(\`\${pfx}_\${ri}_sub\`))}"></td>
      <td><input class="dp-inp" data-field="\${pfx}_\${ri}_struct" type="text" value="\${E(v(\`\${pfx}_\${ri}_struct\`))}"></td>
      <td><input class="dp-inp" data-field="\${pfx}_\${ri}_ctrl" type="text" value="\${E(v(\`\${pfx}_\${ri}_ctrl\`))}"></td>
      <td><input class="dp-inp" data-field="\${pfx}_\${ri}_eff" type="text" value="\${E(v(\`\${pfx}_\${ri}_eff\`))}"></td>
    </tr>\`).join('')}
    <tr>
      <td colspan="5">
        <div class="dp-field" style="flex-direction:row;align-items:flex-start;gap:6px;">
          <span style="font-size:7.5pt;color:#666;white-space:nowrap;padding-top:6px;">\${sec.replace(/^[\d.]+\s*/,'')} 구성도 첨부:</span>
          <div style="flex:1;">
            <input type="hidden" id="\${pfx}_diagram_imgs" data-field="\${pfx}_diagram_imgs" value="\${E(v(\`\${pfx}_diagram_imgs\`))}">
            <div class="dp-drop" id="\${pfx}_diagram_drop" onclick="document.getElementById('\${pfx}_diagram_fi').click();" ondragover="event.preventDefault();this.classList.add('drag-over');" ondragleave="this.classList.remove('drag-over');" ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('\${pfx}_diagram_imgs','\${pfx}_diagram_drop',event.dataTransfer.files);">
              <input type="file" id="\${pfx}_diagram_fi" accept="image/*" multiple onchange="dpAddFiles('\${pfx}_diagram_imgs','\${pfx}_diagram_drop',this.files);this.value='';">
              <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
              <div class="dp-img-list" id="\${pfx}_diagram_imgs_list"></div>
            </div>
          </div>
        </div>
      </td>
    </tr>\`).join('')}
  </tbody>
</table>

<!-- ══ 8.10. 감지변수 대 제어변수 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup>
    <col style="width:22%;"><col style="width:13%;"><col style="width:13%;"><col style="width:26%;"><col style="width:26%;">
  </colgroup>
  <tbody>
    <tr><th class="dp-sub-th" colspan="5">8.10. 감지변수 대 제어변수</th></tr>
    <tr>
      <th class="dp-th">감지변수</th>
      <th class="dp-th">연료(공연비)</th>
      <th class="dp-th">점화시기</th>
      <th class="dp-th">캐니스터 퍼지 / 공회전수 / 배출가스재순환</th>
      <th class="dp-th">비고</th>
    </tr>
    \${['배출가스 중 산소농도','흡입공기 유량','흡입공기 온도','냉각수 온도','스로틀 위치','대기압','흡기부압','크랭크샤프트 위치','캠 샤프트 위치','배터리 전압','차량 속도','원동기 회전수','변속기 기어','정지 및 중립','브레이크 적용','에어컨 가동','원동기 녹킹'].map((row,ri)=>\`<tr>
      <td class="dp-lbl">\${row}</td>
      <td><input class="dp-inp" data-field="dp_8_10_fuel_\${ri}" type="text" value="\${E(v(\`dp_8_10_fuel_\${ri}\`))}"></td>
      <td><input class="dp-inp" data-field="dp_8_10_ign_\${ri}" type="text" value="\${E(v(\`dp_8_10_ign_\${ri}\`))}"></td>
      <td><input class="dp-inp" data-field="dp_8_10_etc_\${ri}" type="text" value="\${E(v(\`dp_8_10_etc_\${ri}\`))}"></td>
      <td><input class="dp-inp" data-field="dp_8_10_note_\${ri}" type="text" value="\${E(v(\`dp_8_10_note_\${ri}\`))}"></td>
    </tr>\`).join('')}
  </tbody>
</table>

<!-- ══ 8.11. 부품목록 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup>
    <col style="width:20%;"><col style="width:18%;"><col style="width:15%;">
    <col style="width:17%;"><col style="width:14%;"><col style="width:16%;">
  </colgroup>
  <tbody>
    <tr><th class="dp-sub-th" colspan="6">8.11. 부품목록</th></tr>
    <tr>
      <th class="dp-th" rowspan="2">항목</th>
      <th class="dp-th" rowspan="2">세부항목</th>
      <th class="dp-th" rowspan="2">부품번호</th>
      <th class="dp-th" colspan="2">제조사</th>
      <th class="dp-th" rowspan="2">비고</th>
    </tr>
    <tr>
      <th class="dp-th">제조업체명</th>
      <th class="dp-th">제조국</th>
    </tr>
    \${['점화장치','연료공급장치','배출가스 전환장치','배출가스 재순환장치','연료증발가스 방지장치','브로바이가스 환원장치','2차공기 분사장치'].map((item,ii)=>\`<tr>
      <td class="dp-lbl">\${item}</td>
      <td><input class="dp-inp" data-field="dp_8_11_\${ii}_sub" type="text" value="\${E(v(\`dp_8_11_\${ii}_sub\`))}"></td>
      <td><input class="dp-inp" data-field="dp_8_11_\${ii}_partno" type="text" value="\${E(v(\`dp_8_11_\${ii}_partno\`))}"></td>
      <td><input class="dp-inp" data-field="dp_8_11_\${ii}_maker" type="text" value="\${E(v(\`dp_8_11_\${ii}_maker\`))}"></td>
      <td><input class="dp-inp" data-field="dp_8_11_\${ii}_country" type="text" value="\${E(v(\`dp_8_11_\${ii}_country\`))}"></td>
      <td><input class="dp-inp" data-field="dp_8_11_\${ii}_note" type="text" value="\${E(v(\`dp_8_11_\${ii}_note\`))}"></td>
    </tr>\`).join('')}
  </tbody>
</table>

<!-- ══ 8.12. SCR ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup>
    <col style="width:13%;"><col style="width:14%;"><col style="width:28%;"><col style="width:27%;"><col style="width:18%;">
  </colgroup>
  <tbody>
    <tr><th class="dp-sub-th" colspan="5">8.12. 선택적촉매장치(SCR) 성능 및 원리 등 설명</th></tr>
    <tr>
      <th class="dp-th">항목</th><th class="dp-th">세부항목</th>
      <th class="dp-th">구조/업체/크기/용량 등</th>
      <th class="dp-th">제어기술/제어원리</th>
      <th class="dp-th">배출가스 저감효과</th>
    </tr>
    \${['공급계','제어계','분사계','충전경고 시스템'].map((row,ri)=>\`<tr>
      <td class="dp-lbl">\${row}</td><td><input class="dp-inp" data-field="dp_8_12_\${ri}_sub" type="text" value="\${E(v(\`dp_8_12_\${ri}_sub\`))}"></td>
      <td><input class="dp-inp" data-field="dp_8_12_\${ri}_struct" type="text" value="\${E(v(\`dp_8_12_\${ri}_struct\`))}"></td>
      <td><input class="dp-inp" data-field="dp_8_12_\${ri}_ctrl" type="text" value="\${E(v(\`dp_8_12_\${ri}_ctrl\`))}"></td>
      <td><input class="dp-inp" data-field="dp_8_12_\${ri}_eff" type="text" value="\${E(v(\`dp_8_12_\${ri}_eff\`))}"></td>
    </tr>\`).join('')}
  </tbody>
</table>

<!-- ══ 8.13. SCR 요소수용액 성분분석 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:20%;"><col style="width:16%;"><col style="width:16%;"><col style="width:16%;"><col style="width:16%;"><col style="width:16%;"></colgroup>
  <tbody>
    <tr><th class="dp-sub-th" colspan="6">8.13. 선택적촉매장치(SCR)용 요소수용액 성분분석 결과</th></tr>
    <tr>
      <th class="dp-th">항목</th><th class="dp-th">분석결과</th>
      <th class="dp-th">분석기관</th><th class="dp-th">분석방법</th>
      <th class="dp-th">분석년월일</th><th class="dp-th">증빙번호</th>
    </tr>
    \${[0,1,2].map(i=>\`<tr>
      <td><input class="dp-inp" data-field="dp_8_13_\${i}_item" type="text" value="\${E(v(\`dp_8_13_\${i}_item\`))}"></td>
      <td><input class="dp-inp" data-field="dp_8_13_\${i}_result" type="text" value="\${E(v(\`dp_8_13_\${i}_result\`))}"></td>
      <td><input class="dp-inp" data-field="dp_8_13_\${i}_org" type="text" value="\${E(v(\`dp_8_13_\${i}_org\`))}"></td>
      <td><input class="dp-inp" data-field="dp_8_13_\${i}_method" type="text" value="\${E(v(\`dp_8_13_\${i}_method\`))}"></td>
      <td><input class="dp-inp" data-field="dp_8_13_\${i}_date" type="text" value="\${E(v(\`dp_8_13_\${i}_date\`))}"></td>
      <td><input class="dp-inp" data-field="dp_8_13_\${i}_evno" type="text" value="\${E(v(\`dp_8_13_\${i}_evno\`))}"></td>
    </tr>\`).join('')}
  </tbody>
</table>

<!-- ══ 8.14. 전기자동차 제어장치 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:35%;"><col style="width:65%;"></colgroup>
  <tbody>
    <tr><th class="dp-sub-th" colspan="2">8.14. 전기자동차 제어장치</th></tr>
    <tr><td class="dp-lbl">8.14.1. 전동기 및 전동기 제어장치</td><td>
      <div class="dp-field"><textarea class="dp-field-text" data-field="dp_8_14_1" rows="2" placeholder="전동기 및 전동기 제어장치 설명">\${E(v('dp_8_14_1'))}</textarea></div>
      <input type="hidden" id="dp_8_14_1_imgs" data-field="dp_8_14_1_imgs" value="\${E(v('dp_8_14_1_imgs'))}">
      <div class="dp-drop" id="dp_8_14_1_drop"
        onclick="document.getElementById('dp_8_14_1_fi').click();"
        ondragover="event.preventDefault();this.classList.add('drag-over');"
        ondragleave="this.classList.remove('drag-over');"
        ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('dp_8_14_1_imgs','dp_8_14_1_drop',event.dataTransfer.files);">
        <input type="file" id="dp_8_14_1_fi" accept="image/*" multiple onchange="dpAddFiles('dp_8_14_1_imgs','dp_8_14_1_drop',this.files);this.value='';">
        <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
        <div class="dp-img-list" id="dp_8_14_1_imgs_list"></div>
      </div>
    </td></tr>
    <tr><td class="dp-lbl">8.14.2. 축전지 및 축전지 제어장치</td><td>
      <div class="dp-field"><textarea class="dp-field-text" data-field="dp_8_14_2" rows="2" placeholder="축전지 및 축전지 제어장치 설명">\${E(v('dp_8_14_2'))}</textarea></div>
      <input type="hidden" id="dp_8_14_2_imgs" data-field="dp_8_14_2_imgs" value="\${E(v('dp_8_14_2_imgs'))}">
      <div class="dp-drop" id="dp_8_14_2_drop"
        onclick="document.getElementById('dp_8_14_2_fi').click();"
        ondragover="event.preventDefault();this.classList.add('drag-over');"
        ondragleave="this.classList.remove('drag-over');"
        ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('dp_8_14_2_imgs','dp_8_14_2_drop',event.dataTransfer.files);">
        <input type="file" id="dp_8_14_2_fi" accept="image/*" multiple onchange="dpAddFiles('dp_8_14_2_imgs','dp_8_14_2_drop',this.files);this.value='';">
        <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
        <div class="dp-img-list" id="dp_8_14_2_imgs_list"></div>
      </div>
    </td></tr>
  </tbody>
</table>

<!-- ══ 9. 증발가스 및 브로바이 가스 ══ -->
<!-- Table 1: 9.1 저장장치 3컬럼 -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup>
    <col style="width:25%;"><col style="width:25%;"><col style="width:50%;">
  </colgroup>
  <tbody>
    <tr><th class="dp-sec-th" colspan="3">${BL('dp_s9')}</th></tr>
    <tr><th class="dp-sub-th" colspan="3">9.1. 증발가스 제어장치 설명</th></tr>
    <tr>
      <th class="dp-th">저장 장치</th>
      <th class="dp-th">흡수용량(C)</th>
      <th class="dp-th">크기(㎤)/매체</th>
    </tr>
    \${['캐니스터','에어클리너','크랭크케이스','기타'].map((dev,di)=>\`<tr>
      <td class="dp-lbl">\${dev}</td>
      <td><input class="dp-inp" data-field="dp_9_1_\${di}_cap" type="text" value="\${E(v(\`dp_9_1_\${di}_cap\`))}"></td>
      <td><input class="dp-inp" data-field="dp_9_1_\${di}_size" type="text" value="\${E(v(\`dp_9_1_\${di}_size\`))}"></td>
    </tr>\`).join('')}
  </tbody>
</table>
<!-- Table 2: 부품리스트 5컬럼 -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup>
    <col style="width:18%;"><col style="width:16%;"><col style="width:22%;">
    <col style="width:26%;"><col style="width:18%;">
  </colgroup>
  <tbody>
    <tr><th class="dp-sub-th" colspan="5">증발가스 제어장치 부품리스트(보조배출가스 제어장치 포함)</th></tr>
    <tr>
      <th class="dp-th">증발가스Code</th>
      <th class="dp-th">공칭탱크<br>용량(L)</th>
      <th class="dp-th">40%연료시 탱크의<br>최대 증발가스 용량</th>
      <th class="dp-th">기화기/연료분사장치의<br>reservoir의 최대용량</th>
      <th class="dp-th">적용차명</th>
    </tr>
    \${[0,1,2].map(i=>\`<tr>
      <td><input class="dp-inp" data-field="dp_9_1_list_\${i}_code" type="text" value="\${E(v(\`dp_9_1_list_\${i}_code\`))}"></td>
      <td><input class="dp-inp" data-field="dp_9_1_list_\${i}_vol" type="text" value="\${E(v(\`dp_9_1_list_\${i}_vol\`))}"></td>
      <td><input class="dp-inp" data-field="dp_9_1_list_\${i}_evap" type="text" value="\${E(v(\`dp_9_1_list_\${i}_evap\`))}"></td>
      <td><input class="dp-inp" data-field="dp_9_1_list_\${i}_res" type="text" value="\${E(v(\`dp_9_1_list_\${i}_res\`))}"></td>
      <td><input class="dp-inp" data-field="dp_9_1_list_\${i}_car" type="text" value="\${E(v(\`dp_9_1_list_\${i}_car\`))}"></td>
    </tr>\`).join('')}
  </tbody>
</table>
<!-- Table 3: 9.2 제어장치 구성도 -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:100%;"></colgroup>
  <tbody>
    <tr>
      <td class="dp-lbl" style="padding-top:6px;">
        <strong>9.2. 제어장치 구성도</strong>
      </td>
    </tr>
    <tr>
      <td>
        <div class="dp-field">
          <textarea class="dp-field-text" data-field="dp_9_2" rows="3" placeholder="제어장치 구성도 설명">\${E(v('dp_9_2'))}</textarea>
          <input type="hidden" id="dp_9_2_imgs" data-field="dp_9_2_imgs" value="\${E(v('dp_9_2_imgs'))}">
          <div class="dp-drop" id="dp_9_2_drop"
            onclick="document.getElementById('dp_9_2_fi').click();"
            ondragover="event.preventDefault();this.classList.add('drag-over');"
            ondragleave="this.classList.remove('drag-over');"
            ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('dp_9_2_imgs','dp_9_2_drop',event.dataTransfer.files);">
            <input type="file" id="dp_9_2_fi" accept="image/*" multiple onchange="dpAddFiles('dp_9_2_imgs','dp_9_2_drop',this.files);this.value='';">
            <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint2')}</div>
            <div class="dp-img-list" id="dp_9_2_imgs_list"></div>
          </div>
        </div>
      </td>
    </tr>
  </tbody>
</table>

<!-- ══ 10. 동일차종(원동기) ══ -->
<!-- ── 10.1 배출가스 및 소음 동일차종(원동기) 설명 (5컬럼) ── -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup>
    <col style="width:18%;"><col style="width:13%;"><col style="width:22%;">
    <col style="width:23.5%;"><col style="width:23.5%;">
  </colgroup>
  <tbody>
    <tr><th class="dp-sec-th" colspan="5">${BL('dp_s10')}</th></tr>
    <tr><th class="dp-sub-th" colspan="5">10.1. 배출가스 및 소음 동일차종(원동기) 설명</th></tr>
    <tr>
      <th class="dp-th" colspan="3">구 분</th>
      <th class="dp-th">기본 차종</th>
      <th class="dp-th">배출가스 및 소음<br>동일차종</th>
    </tr>
    <!-- 단순 1행 항목들 -->
    \${[
      ['차명','dp_10_1_carname'],['자동차 형식','dp_10_1_type'],['차체형상','dp_10_1_body'],
      ['승차인원','dp_10_1_passenger'],['사용연료','dp_10_1_fuel'],['배기량(cc)','dp_10_1_disp'],
      ['연소방식','dp_10_1_comb'],['실린더 수','dp_10_1_cyl'],['최대출력(ps/rpm)','dp_10_1_maxpow'],
      ['최대토크(kg-m/rpm)','dp_10_1_maxtq'],['보어*스트로크(mm)','dp_10_1_bore'],['압축비','dp_10_1_compress'],
      ['실린더 보어 중심간의 거리(mm)','dp_10_1_cyl_dist'],['실린더 블록 형상','dp_10_1_block'],
      ['실린더 배열','dp_10_1_cylarr'],['실린더 헤드 방식','dp_10_1_head'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl" colspan="3">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_base" type="text" value="\${E(v(\`\${fld}_base\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_same" type="text" value="\${E(v(\`\${fld}_same\`))}"></td>
    </tr>\`).join('')}
    <!-- 흡기 매니폴드 rowspan=2 -->
    <tr>
      <td class="dp-lbl" colspan="2" rowspan="2">흡기 매니폴드</td>
      <td class="dp-lbl">흡입포트크기</td>
      <td><input class="dp-inp" data-field="dp_10_1_inport_base" type="text" value="\${E(v('dp_10_1_inport_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_inport_same" type="text" value="\${E(v('dp_10_1_inport_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">흡입포트 형상</td>
      <td><input class="dp-inp" data-field="dp_10_1_inshape_base" type="text" value="\${E(v('dp_10_1_inshape_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_inshape_same" type="text" value="\${E(v('dp_10_1_inshape_same'))}"></td>
    </tr>
    <!-- 배기 매니폴드 rowspan=2 -->
    <tr>
      <td class="dp-lbl" colspan="2" rowspan="2">배기 매니폴드</td>
      <td class="dp-lbl">배기포트크기</td>
      <td><input class="dp-inp" data-field="dp_10_1_export_base" type="text" value="\${E(v('dp_10_1_export_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_export_same" type="text" value="\${E(v('dp_10_1_export_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">배기포트 형상</td>
      <td><input class="dp-inp" data-field="dp_10_1_exshape_base" type="text" value="\${E(v('dp_10_1_exshape_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_exshape_same" type="text" value="\${E(v('dp_10_1_exshape_same'))}"></td>
    </tr>
    <!-- 흡배기폐기시 rowspan=4 -->
    <tr>
      <td class="dp-lbl" rowspan="4">흡배기폐기시</td>
      <td class="dp-lbl" rowspan="2">흡입<br>밸브</td>
      <td class="dp-lbl">열기</td>
      <td><input class="dp-inp" data-field="dp_10_1_in_open_base" type="text" value="\${E(v('dp_10_1_in_open_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_in_open_same" type="text" value="\${E(v('dp_10_1_in_open_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">닫기</td>
      <td><input class="dp-inp" data-field="dp_10_1_in_close_base" type="text" value="\${E(v('dp_10_1_in_close_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_in_close_same" type="text" value="\${E(v('dp_10_1_in_close_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl" rowspan="2">배기<br>밸브</td>
      <td class="dp-lbl">열기</td>
      <td><input class="dp-inp" data-field="dp_10_1_ex_open_base" type="text" value="\${E(v('dp_10_1_ex_open_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_ex_open_same" type="text" value="\${E(v('dp_10_1_ex_open_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">닫기</td>
      <td><input class="dp-inp" data-field="dp_10_1_ex_close_base" type="text" value="\${E(v('dp_10_1_ex_close_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_ex_close_same" type="text" value="\${E(v('dp_10_1_ex_close_same'))}"></td>
    </tr>
    <!-- 기통별 밸브수 rowspan=2 -->
    <tr>
      <td class="dp-lbl" colspan="2" rowspan="2">기통별 밸브수</td>
      <td class="dp-lbl">흡기</td>
      <td><input class="dp-inp" data-field="dp_10_1_valve_in_base" type="text" value="\${E(v('dp_10_1_valve_in_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_valve_in_same" type="text" value="\${E(v('dp_10_1_valve_in_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">배기</td>
      <td><input class="dp-inp" data-field="dp_10_1_valve_ex_base" type="text" value="\${E(v('dp_10_1_valve_ex_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_valve_ex_same" type="text" value="\${E(v('dp_10_1_valve_ex_same'))}"></td>
    </tr>
    <!-- 밸브크기 rowspan=2 -->
    <tr>
      <td class="dp-lbl" colspan="2" rowspan="2">밸브크기</td>
      <td class="dp-lbl">흡기</td>
      <td><input class="dp-inp" data-field="dp_10_1_vsize_in_base" type="text" value="\${E(v('dp_10_1_vsize_in_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_vsize_in_same" type="text" value="\${E(v('dp_10_1_vsize_in_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">배기</td>
      <td><input class="dp-inp" data-field="dp_10_1_vsize_ex_base" type="text" value="\${E(v('dp_10_1_vsize_ex_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_vsize_ex_same" type="text" value="\${E(v('dp_10_1_vsize_ex_same'))}"></td>
    </tr>
    <!-- 공기 흡입 방식 -->
    <tr>
      <td class="dp-lbl" colspan="3">공기 흡입 방식</td>
      <td><input class="dp-inp" data-field="dp_10_1_airtype_base" type="text" value="\${E(v('dp_10_1_airtype_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_airtype_same" type="text" value="\${E(v('dp_10_1_airtype_same'))}"></td>
    </tr>
    <!-- 촉매 rowspan=5 (Page2 이어짐) -->
    <tr>
      <td class="dp-lbl" colspan="2" rowspan="5">촉매</td>
      <td class="dp-lbl">종류</td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_type_base" type="text" value="\${E(v('dp_10_1_cat_type_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_type_same" type="text" value="\${E(v('dp_10_1_cat_type_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">귀금속 성분</td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_pm_base" type="text" value="\${E(v('dp_10_1_cat_pm_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_pm_same" type="text" value="\${E(v('dp_10_1_cat_pm_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">귀금속량(g)</td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_pmg_base" type="text" value="\${E(v('dp_10_1_cat_pmg_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_pmg_same" type="text" value="\${E(v('dp_10_1_cat_pmg_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">용량(㎤)</td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_vol_base" type="text" value="\${E(v('dp_10_1_cat_vol_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_vol_same" type="text" value="\${E(v('dp_10_1_cat_vol_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">귀금속물질비(Pt:Pd:Rh)</td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_ratio_base" type="text" value="\${E(v('dp_10_1_cat_ratio_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_ratio_same" type="text" value="\${E(v('dp_10_1_cat_ratio_same'))}"></td>
    </tr>
    <!-- 단순 1행 항목들 (Page2 나머지) -->
    \${[
      ['크랭크 축 중심선에서 캠축 중심선까지의 거리(mm)','dp_10_1_crank_cam'],
      ['크랭크 축 중심선에서 실린더 블록 헤드 면 상부까지의 거리(mm)','dp_10_1_crank_head'],
      ['TDC 상태에서 연소실 표면적 체적비율','dp_10_1_tdc'],
      ['연료 공급 방식','dp_10_1_fuel_supply'],
      ['분사 시기 제어범위','dp_10_1_inj_range'],
      ['캠축타이밍','dp_10_1_cam_timing'],
      ['등가관성 중량','dp_10_1_inertia'],
      ['도로부하마력','dp_10_1_roadload'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl" colspan="3">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_base" type="text" value="\${E(v(\`\${fld}_base\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_same" type="text" value="\${E(v(\`\${fld}_same\`))}"></td>
    </tr>\`).join('')}
  </tbody>
</table>

<!-- ══ 10.2. 증발가스 동일차종 ══ -->
<!-- ── 10.2 증발가스 동일차종 설명 (4컬럼, 캐니스터 설계특성 rowspan=5) ── -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup>
    <col style="width:18%;"><col style="width:22%;"><col style="width:30%;"><col style="width:30%;">
  </colgroup>
  <tbody>
    <tr><th class="dp-sub-th" colspan="4">10.2. 증발가스 동일차종 설명</th></tr>
    <tr>
      <th class="dp-th" colspan="2">구 분</th>
      <th class="dp-th">기본 차종</th>
      <th class="dp-th">증발가스 동일차종</th>
    </tr>
    <!-- 단순 1행 항목들 -->
    \${[
      ['배출가스 인증번호','dp_10_2_certno'],['자동차 명칭','dp_10_2_carname'],
      ['자동차 형식','dp_10_2_type'],['원동기 형식','dp_10_2_eng'],
      ['차종','dp_10_2_cartype'],['사용연료','dp_10_2_fuel'],
      ['증발가스 저장형식','dp_10_2_evap_type'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl" colspan="2">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_base" type="text" value="\${E(v(\`\${fld}_base\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_same" type="text" value="\${E(v(\`\${fld}_same\`))}"></td>
    </tr>\`).join('')}
    <!-- 캐니스터 설계 특성 rowspan=5 -->
    <tr>
      <td class="dp-lbl" rowspan="5">캐니스터<br>설계 특성</td>
      <td class="dp-lbl">증발가스 흡수용량</td>
      <td><input class="dp-inp" data-field="dp_10_2_evap_cap_base" type="text" value="\${E(v('dp_10_2_evap_cap_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_2_evap_cap_same" type="text" value="\${E(v('dp_10_2_evap_cap_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">캐니스터 개수 및 연결방법</td>
      <td><input class="dp-inp" data-field="dp_10_2_can_cnt_base" type="text" value="\${E(v('dp_10_2_can_cnt_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_2_can_cnt_same" type="text" value="\${E(v('dp_10_2_can_cnt_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">캐니스터 형상</td>
      <td><input class="dp-inp" data-field="dp_10_2_can_shape_base" type="text" value="\${E(v('dp_10_2_can_shape_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_2_can_shape_same" type="text" value="\${E(v('dp_10_2_can_shape_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">캐니스터 구조</td>
      <td><input class="dp-inp" data-field="dp_10_2_can_struct_base" type="text" value="\${E(v('dp_10_2_can_struct_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_2_can_struct_same" type="text" value="\${E(v('dp_10_2_can_struct_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">캐니스터 재질</td>
      <td><input class="dp-inp" data-field="dp_10_2_can_mat_base" type="text" value="\${E(v('dp_10_2_can_mat_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_2_can_mat_same" type="text" value="\${E(v('dp_10_2_can_mat_same'))}"></td>
    </tr>
    <!-- 연료시스템 / 주유관 밀폐구조 (별도 행) -->
    <tr>
      <td class="dp-lbl" colspan="2">연료시스템</td>
      <td><input class="dp-inp" data-field="dp_10_2_fuel_sys_base" type="text" value="\${E(v('dp_10_2_fuel_sys_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_2_fuel_sys_same" type="text" value="\${E(v('dp_10_2_fuel_sys_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">주유관 밀폐구조</td>
      <td><input class="dp-inp" data-field="dp_10_2_fuel_seal_base" type="text" value="\${E(v('dp_10_2_fuel_seal_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_2_fuel_seal_same" type="text" value="\${E(v('dp_10_2_fuel_seal_same'))}"></td>
    </tr>
    <!-- 나머지 항목 -->
    \${[
      ['증발가스 제어시스템','dp_10_2_ctrl'],['퍼지제어 시스템','dp_10_2_purge'],
      ['증발가스 호스 재질','dp_10_2_hose_mat'],['연료탱크 재질','dp_10_2_tank_mat'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl" colspan="2">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_base" type="text" value="\${E(v(\`\${fld}_base\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_same" type="text" value="\${E(v(\`\${fld}_same\`))}"></td>
    </tr>\`).join('')}
  </tbody>
</table>

<!-- ══ 10.3. 배출가스자기진단장치 동일차종 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:35%;"><col style="width:32.5%;"><col style="width:32.5%;"></colgroup>
  <tbody>
    <tr><th class="dp-sub-th" colspan="3">10.3. 배출가스자기진단장치 동일차종 설명</th></tr>
    <tr>
      <th class="dp-th">구 분</th>
      <th class="dp-th">기본 차종</th>
      <th class="dp-th">배출가스자기진단장치 동일차종</th>
    </tr>
    \${[
      ['배출가스 인증번호','dp_10_3_certno'],['자동차 명칭','dp_10_3_carname'],
      ['자동차 형식','dp_10_3_type'],['원동기 형식','dp_10_3_eng'],
      ['차종','dp_10_3_cartype'],['사용연료','dp_10_3_fuel'],
      ['배출가스 자가진단 장치의 작동법','dp_10_3_obd_op'],['배출가스 허용기준','dp_10_3_std'],
      ['연소싸이클','dp_10_3_cycle'],['연료공급방식','dp_10_3_fuel_supply'],
      ['촉매전환장치 형태','dp_10_3_cat'],['입자상물질 포집장치 형태','dp_10_3_dpf'],
      ['2차 공기 분사 유무','dp_10_3_air2'],['배출가스 재순환장치 유무','dp_10_3_egr'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_base" type="text" value="\${E(v('\${fld}_base'))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_same" type="text" value="\${E(v('\${fld}_same'))}"></td>
    </tr>\`).join('')}
  </tbody>
</table>

<!-- ══ 11. 시험차량 ══ -->
<!-- ── 11.1 시험차량 선정 (4컬럼, 배출가스제어장치 rowspan=2) ── -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup>
    <col style="width:20%;"><col style="width:15%;"><col style="width:32.5%;"><col style="width:32.5%;">
  </colgroup>
  <tbody>
    <tr><th class="dp-sec-th" colspan="4">${BL('dp_s11')}</th></tr>
    <tr><th class="dp-sub-th" colspan="4">11.1. 시험차량 선정</th></tr>
    <tr>
      <th class="dp-th" colspan="2">구 분</th>
      <th class="dp-th">내구성 시험차량</th>
      <th class="dp-th">배출가스시험차량</th>
    </tr>
    <!-- 단순 1행 항목들 -->
    \${[
      ['차대번호(엔진번호)','dp_11_1_vin'],['배기량(cc)','dp_11_1_disp'],
      ['엔진코드','dp_11_1_eng_code'],['증발가스 코드','dp_11_1_evap_code'],
      ['촉매코드','dp_11_1_cat_code'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl" colspan="2">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_dur" type="text" value="\${E(v(\`\${fld}_dur\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_em" type="text" value="\${E(v(\`\${fld}_em\`))}"></td>
    </tr>\`).join('')}
    <!-- 배출가스 제어장치 rowspan=2 -->
    <tr>
      <td class="dp-lbl" rowspan="2">배출가스<br>제어장치</td>
      <td class="dp-lbl">배출가스</td>
      <td><input class="dp-inp" data-field="dp_11_1_ctrl_em_dur" type="text" value="\${E(v('dp_11_1_ctrl_em_dur'))}"></td>
      <td><input class="dp-inp" data-field="dp_11_1_ctrl_em_em" type="text" value="\${E(v('dp_11_1_ctrl_em_em'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">증발가스</td>
      <td><input class="dp-inp" data-field="dp_11_1_ctrl_evap_dur" type="text" value="\${E(v('dp_11_1_ctrl_evap_dur'))}"></td>
      <td><input class="dp-inp" data-field="dp_11_1_ctrl_evap_em" type="text" value="\${E(v('dp_11_1_ctrl_evap_em'))}"></td>
    </tr>
    <!-- 나머지 단순 항목들 -->
    \${[
      ['모델명','dp_11_1_model'],['변속기 형태','dp_11_1_trans'],
      ['변속 절차','dp_11_1_trans_proc'],['등가관성 중량(kg)','dp_11_1_inertia'],
      ['종 감속기','dp_11_1_final_red'],['N/V 비, RRM/KPH','dp_11_1_nv'],
      ['타이어','dp_11_1_tire'],
      ['비고','dp_11_1_note'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl" colspan="2">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_dur" type="text" value="\${E(v(\`\${fld}_dur\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_em" type="text" value="\${E(v(\`\${fld}_em\`))}"></td>
    </tr>\`).join('')}
  </tbody>
</table>

<!-- ── 11.2 내구성 시험차량 선정 ── -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup>
    <col style="width:34%;"><col style="width:33%;"><col style="width:33%;">
  </colgroup>
  <tbody>
    <tr><th class="dp-sub-th" colspan="3">11.2. 내구성 시험차량 선정</th></tr>
    <tr>
      <th class="dp-th">구 분</th>
      <th class="dp-th">자동차 형식 1</th>
      <th class="dp-th">자동차 형식 2</th>
    </tr>
    \${[
      ['자동차 형식','dp_11_2_type'],['변속기','dp_11_2_trans'],
      ['원동기 형식','dp_11_2_eng'],['배기량','dp_11_2_disp'],
      ['공차중량','dp_11_2_weight'],['등가관성중량','dp_11_2_inertia'],
      ['도로부하마력','dp_11_2_roadload'],['연료탱크용량','dp_11_2_tankVol'],
      ['종 감속비(제1감속비)','dp_11_2_finalRed'],['판매대수','dp_11_2_sales'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_1" type="text" value="\${E(v(\`\${fld}_1\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_2" type="text" value="\${E(v(\`\${fld}_2\`))}"></td>
    </tr>\`).join('')}
  </tbody>
</table>

<!-- ── 11.3 배출가스 시험차량 선정 ── -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup>
    <col style="width:40%;"><col style="width:30%;"><col style="width:30%;">
  </colgroup>
  <tbody>
    <tr><th class="dp-sub-th" colspan="3">11.3. 배출가스 시험차량 선정</th></tr>
    <!-- A. 차대 동력계 -->
    <tr>
      <td class="dp-lbl" colspan="3" style="font-weight:600; background:#f5f5f5;">
        A. 차대 동력계를 사용하는 경우 :
      </td>
    </tr>
    <tr>
      <th class="dp-th">항 목</th>
      <td><input class="dp-inp" data-field="dp_11_3_a_hdr1" type="text" placeholder="자동차 형식" value="\${E(v('dp_11_3_a_hdr1'))}"></td>
      <td><input class="dp-inp" data-field="dp_11_3_a_hdr2" type="text" placeholder="자동차 형식" value="\${E(v('dp_11_3_a_hdr2'))}"></td>
    </tr>
    \${[
      ['자동차 형식','dp_11_3_a_type'],
      ['동일차종 중 등가관성중량이 가장 큰 것','dp_11_3_a_0'],
      ['상기 조건 내에서 도로 부하력이 가장 큰 것','dp_11_3_a_1'],
      ['상기 조건 내에서 배기량이 가장 큰 것','dp_11_3_a_2'],
      ['상기 조건 내에서 가장 높은 최종기어비를 갖는 변속기','dp_11_3_a_3'],
      ['상기 조건 내에서 연료탱크 용량이 가장 큰 것','dp_11_3_a_4'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_1" type="text" value="\${E(v(\`\${fld}_1\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_2" type="text" value="\${E(v(\`\${fld}_2\`))}"></td>
    </tr>\`).join('')}
    <!-- B. 원동기 동력계 -->
    <tr>
      <td class="dp-lbl" colspan="3" style="font-weight:600; background:#f5f5f5;">
        B. 원동기동력계를 사용하는 경우 :
      </td>
    </tr>
    <tr>
      <th class="dp-th">항 목</th>
      <td><input class="dp-inp" data-field="dp_11_3_b_hdr1" type="text" placeholder="자동차 형식" value="\${E(v('dp_11_3_b_hdr1'))}"></td>
      <td><input class="dp-inp" data-field="dp_11_3_b_hdr2" type="text" placeholder="자동차 형식" value="\${E(v('dp_11_3_b_hdr2'))}"></td>
    </tr>
    \${[
      ['최고 토오크 시 속도에서 행정당 연료배분율이 가장 큰 원동기','dp_11_3_b_0'],
      ['최고 속도 시 행정당 연료배분율이 가장 큰 원동기','dp_11_3_b_1'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_1" type="text" value="\${E(v(\`\${fld}_1\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_2" type="text" value="\${E(v(\`\${fld}_2\`))}"></td>
    </tr>\`).join('')}
  </tbody>
</table>

<!-- ── 11.4 소음 시험차량 선정 ── -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup>
    <col style="width:40%;"><col style="width:30%;"><col style="width:30%;">
  </colgroup>
  <tbody>
    <tr><th class="dp-sub-th" colspan="3">11.4. 소음 시험차량 선정</th></tr>
    <tr>
      <th class="dp-th">항 목</th>
      <td><input class="dp-inp" data-field="dp_11_4_hdr1" type="text" placeholder="자동차 형식" value="\${E(v('dp_11_4_hdr1'))}"></td>
      <td><input class="dp-inp" data-field="dp_11_4_hdr2" type="text" placeholder="자동차 형식" value="\${E(v('dp_11_4_hdr2'))}"></td>
    </tr>
    \${[
      ['공차중량이 가장 무거운 자동차','dp_11_4_0'],
      ['배기량이 가장 큰 자동차','dp_11_4_1'],
      ['최종기어비율(오버드라이브를 포함한다)이 가장 높은 변속기를 장착한 자동차','dp_11_4_2'],
      ['차축비가 가장 높은 자동차','dp_11_4_3'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_1" type="text" value="\${E(v(\`\${fld}_1\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_2" type="text" value="\${E(v(\`\${fld}_2\`))}"></td>
    </tr>\`).join('')}
  </tbody>
</table>

<!-- ══ 12. 교정정보 및 사후확정정보 제출협약 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:100%;"></colgroup>
  <tbody>
    <tr><th class="dp-sec-th">${BL('dp_s12')}</th></tr>
    <tr><td style="font-size:7.5pt;color:#555;padding:4px 6px;">
      내구성 시험을 실시하는 경우로서 인증신청 당시까지 세부개발계획이 확정되지 않는 등 불가피한 사유로 최초 제출하는 신청서류에 기재할 수 없는 사항이 있는 경우 그 사유를 명시하고, 내구성시험 최종보고서 제출 시 확정된 사항을 일괄적으로 제출할 수 있다.
    </td></tr>
    <tr><td>
      <div class="dp-field"><textarea class="dp-field-text" data-field="dp_12" rows="4" placeholder="불가피한 사유 명시">\${E(v('dp_12'))}</textarea></div>
    </td></tr>
  </tbody>
</table>

<!-- ══ 13. 기타 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:100%;"></colgroup>
  <tbody>
    <tr><th class="dp-sec-th">${BL('dp_s13')}</th></tr>
    <tr><td>
      <div class="dp-field">
        <textarea class="dp-field-text" data-field="dp_13" rows="3" placeholder="기타 사항">\${E(v('dp_13'))}</textarea>
        <input type="hidden" id="dp_13_imgs" data-field="dp_13_imgs" value="\${E(v('dp_13_imgs'))}">
        <div class="dp-drop" id="dp_13_drop" onclick="document.getElementById('dp_13_fi').click();" ondragover="event.preventDefault();this.classList.add('drag-over');" ondragleave="this.classList.remove('drag-over');" ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('dp_13_imgs','dp_13_drop',event.dataTransfer.files);">
          <input type="file" id="dp_13_fi" accept="image/*" multiple onchange="dpAddFiles('dp_13_imgs','dp_13_drop',this.files);this.value='';">
          <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
          <div class="dp-img-list" id="dp_13_imgs_list"></div>
        </div>
      </div>
    </td></tr>
  </tbody>
</table>

<div id="qr-footer-wrap" style="margin-top:12px;"></div>
</div>



\`;


  if (formType==='emission_noise') return \`
<style>
/* ══════ emission_noise 전용 스타일 ══════ */
.en-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
  background:#fff;
  color:#111;
  border-radius:8px;
}
.en-doc-tag { font-size:8.5pt; font-weight:700; color:#444; margin:10px 0 4px; }
.en-main-title {
  font-size:13pt; font-weight:900; text-align:center;
  margin:4px 0 14px; letter-spacing:.03em; color:#111;
}
.en-tbl {
  width:100%; border-collapse:collapse;
  font-size:8.5pt; margin-bottom:0;
}
.en-tbl th, .en-tbl td {
  border:1px solid #888;
  padding:3px 5px;
  vertical-align:middle;
  color:#111;
}
.en-sec-th {
  background:#d6e4f7;
  font-weight:700; text-align:left;
  padding:4px 6px; font-size:8.5pt; color:#111;
}
.en-sub-th {
  background:#eef3fa;
  font-weight:700; text-align:left;
  padding:3px 6px; font-size:8.5pt; color:#111;
}
.en-th {
  background:#eef3fa;
  font-weight:600; text-align:center;
  font-size:8pt; color:#111;
}
.en-lbl {
  background:#f5f8ff;
  font-weight:600; color:#111;
  vertical-align:middle;
}
/* ── 복합 입력 필드 (텍스트 + 이미지) ── */
.en-field {
  display:flex; flex-direction:column; gap:4px;
  padding:3px 4px; box-sizing:border-box; width:100%;
}
.en-field-text {
  width:100%; font-size:8.5pt; font-family:inherit;
  border:none; background:transparent; padding:2px 0;
  box-sizing:border-box; resize:vertical; color:#111;
  min-height:36px; line-height:1.5;
}
.en-field-text::placeholder { color:#aaa; }
.en-field-text:focus { outline:none; border-bottom:1px dashed #4e90d8; }
/* 이미지 드롭존 */
.en-drop {
  border:1.5px dashed #b0c4de;
  border-radius:5px;
  background:#f8faff;
  padding:6px 8px;
  cursor:pointer;
  transition:border-color .15s, background .15s;
  position:relative;
  min-height:36px;
}
.en-drop:hover { border-color:#4e90d8; background:#eef3fa; }
.en-drop.drag-over { border-color:#2563eb; background:#dbeafe; }
.en-drop-hint {
  color:#aaa; font-size:7.5pt; text-align:center;
  pointer-events:none; user-select:none;
  display:flex; align-items:center; justify-content:center; gap:4px;
}
.en-drop input[type=file] { display:none; }
/* 이미지 미리보기 목록 */
.en-img-list {
  display:flex; flex-wrap:wrap; gap:6px; margin-top:4px;
}
.en-img-item {
  position:relative; display:inline-block;
}
.en-img-item img {
  max-width:140px; max-height:100px;
  border:1px solid #ccc; border-radius:3px;
  display:block; object-fit:contain; background:#fff;
}
.en-img-item-del {
  position:absolute; top:-6px; right:-6px;
  width:16px; height:16px; border-radius:50%;
  background:#ef4444; color:#fff; font-size:10px;
  display:flex; align-items:center; justify-content:center;
  cursor:pointer; line-height:1; border:none;
  box-shadow:0 1px 3px rgba(0,0,0,.3);
}
.en-img-item-del:hover { background:#dc2626; }
/* 헤더 셀의 텍스트 입력 (수입사 등 단순 1행 셀) */
.en-inp {
  border:none; background:transparent;
  width:100%; font-size:8.5pt;
  font-family:inherit; padding:0 2px;
  box-sizing:border-box; color:#111;
}
.en-inp::placeholder { color:#aaa; }
.en-inp:focus { outline:none; border-bottom:1px solid #4e90d8; }
@media print {
  /* ── 전체 래퍼 ── */
  .en-wrap { background:#fff !important; color:#000 !important; border-radius:0 !important; }

  /* ── 테이블 셀: 내용에 맞춰 높이 자동 확장, 잘림 방지 ── */
  .en-tbl { table-layout:fixed !important; width:100% !important; }
  .en-tbl th, .en-tbl td {
    border:1px solid #333 !important; color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important; overflow-wrap:break-word !important;
  }

  /* ── en-field: 인쇄 시 flex 유지, 높이 자동 ── */
  .en-field { height:auto !important; overflow:visible !important; display:flex !important; flex-direction:column !important; }

  /* ── textarea: 내용 전체 표시, 스크롤 없이 ── */
  textarea.en-field-text {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; min-height:0 !important; max-height:none !important;
    overflow:visible !important; resize:none !important;
    white-space:pre-wrap !important; word-break:break-word !important;
    overflow-wrap:break-word !important;
    display:block !important; box-sizing:border-box !important;
    -webkit-appearance:none !important; appearance:none !important;
    padding:2px 0 !important;
  }

  /* ── 단순 1행 input ── */
  .en-inp {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important;
  }

  /* ── hidden input 완전 숨김 ── */
  input[type=hidden] { display:none !important; }

  /* ── 이미지 드롭존: 테두리/배경 제거, 힌트/삭제버튼 숨김 ── */
  .en-drop {
    border:none !important; background:transparent !important;
    padding:0 !important; min-height:unset !important;
    height:auto !important; overflow:visible !important;
  }
  .en-drop-hint { display:none !important; }
  .en-img-item-del { display:none !important; }
  .en-img-list { gap:4px !important; margin-top:2px !important; }
  .en-img-item img {
    max-width:100% !important; max-height:none !important;
    page-break-inside:avoid;
  }
  /* 이미지가 없는 빈 en-drop은 공간 차지 안 함 */
  .en-drop:not(:has(img)) { display:none !important; }

  /* ── 섹션 헤더 배경색 유지 ── */
  .en-sec-th { background:#d6e4f7 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-sub-th { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-th     { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-lbl    { background:#f5f8ff !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }

  /* ── 페이지 분리 방지 (행 단위) ── */
  .en-tbl tr { page-break-inside:avoid; }
}
</style>

<div class="en-wrap">

  <!-- ── 상단 헤더 (수입사/인증연도/배기량/동일차종기호) ── -->
  <table class="en-tbl" style="margin-bottom:12px; table-layout:fixed;">
    <colgroup>
      <col style="width:35%;"><col style="width:12%;"><col style="width:13%;"><col style="width:40%;">
    </colgroup>
    <thead>
      <tr>
        <th class="en-th">\${BL('importer')}</th>
        <th class="en-th">\${BL('cert_year')}</th>
        <th class="en-th">\${BL('displacement')}</th>
        <th class="en-th">\${BL('family_code')}</th>
      </tr>
    </thead>
    <tbody>
      <tr style="height:26px;">
        <td><input data-field="en_importer"  class="en-inp" type="text" placeholder="\${BL('ph_importer')}" value="\${E(v('en_importer'))}"></td>
        <td><input data-field="en_cert_year" class="en-inp" type="text" placeholder="\${BL('ph_cert_year')}" value="\${E(v('en_cert_year'))}"></td>
        <td><input data-field="en_disp"      class="en-inp" type="text" placeholder="\${BL('ph_displacement')}" value="\${E(v('en_disp'))}"></td>
        <td><input data-field="en_fam_code"  class="en-inp" type="text" placeholder="\${BL('ph_family_code')}" value="\${E(v('en_fam_code'))}"></td>
      </tr>
    </tbody>
  </table>

  <div class="en-doc-tag">[별지 제5호 서식]</div>
  <div class="en-main-title">\${BL('en_main_title')}</div>

  <!-- ══════════════════════════════════════════════════════ -->
  <!-- 1. 머플러                                              -->
  <!-- ══════════════════════════════════════════════════════ -->
  <table class="en-tbl" style="table-layout:fixed; width:100%;">
    <colgroup><col style="width:22%;"><col style="width:78%;"></colgroup>
    <tbody>
      <tr><th class="en-sec-th" colspan="2">\${BL('en_muffler')}</th></tr>

      <!-- 1.1 머플러 구성 내역 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_muffler_comp_title')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_muffler_comp" rows="3" placeholder="머플러 구성 내역을 기재하세요">\${E(v('en_muffler_comp'))}</textarea>
            <input type="hidden" data-field="en_muffler_comp_imgs" value="\${E(v('en_muffler_comp_imgs'))}"><div class="en-drop" data-field-img="en_muffler_comp"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.2 머플러 내부 구조도 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_muffler_diagram_title')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_muffler_diagram" rows="2" placeholder="내부 구조 설명">\${E(v('en_muffler_diagram'))}</textarea>
            <input type="hidden" data-field="en_muffler_diagram_imgs" value="\${E(v('en_muffler_diagram_imgs'))}"><div class="en-drop" data-field-img="en_muffler_diagram"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.3 소음기 상세제원 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_muffler_spec_title')}</td></tr>

      <!-- 1.3.1 구조 및 소음저감 원리 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_3_1')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_muffler_principle" rows="3" placeholder="구조 및 소음저감 원리를 기재하세요">\${E(v('en_muffler_principle'))}</textarea>
            <input type="hidden" data-field="en_muffler_principle_imgs" value="\${E(v('en_muffler_principle_imgs'))}"><div class="en-drop" data-field-img="en_muffler_principle"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.3.2 소음기내의 배출가스 흐름도 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_3_2')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_muffler_flow" rows="2" placeholder="흐름도 설명">\${E(v('en_muffler_flow'))}</textarea>
            <input type="hidden" data-field="en_muffler_flow_imgs" value="\${E(v('en_muffler_flow_imgs'))}"><div class="en-drop" data-field-img="en_muffler_flow"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.3.3 소음기 제작사 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_3_3')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_muffler_maker" rows="2" placeholder="제작사명">\${E(v('en_muffler_maker'))}</textarea>
            <input type="hidden" data-field="en_muffler_maker_imgs" value="\${E(v('en_muffler_maker_imgs'))}"><div class="en-drop" data-field-img="en_muffler_maker"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.3.4 소음기 내부/외부 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_3_4')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <div style="display:flex; gap:8px; align-items:flex-start; flex-wrap:wrap;">
              <label style="font-size:8pt; white-space:nowrap; margin-top:4px;">내부 :</label>
              <textarea class="en-field-text" data-field="en_muffler_inside" rows="2" placeholder="내부 재질/사양" style="flex:1; min-width:80px;">\${E(v('en_muffler_inside'))}</textarea>
              <label style="font-size:8pt; white-space:nowrap; margin-top:4px;">외부 :</label>
              <textarea class="en-field-text" data-field="en_muffler_outside" rows="2" placeholder="외부 재질/사양" style="flex:1; min-width:80px;">\${E(v('en_muffler_outside'))}</textarea>
            </div>
            <input type="hidden" data-field="en_muffler_inout_imgs" value="\${E(v('en_muffler_inout_imgs'))}"><div class="en-drop" data-field-img="en_muffler_inout"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.3.5 소음기 치수 도면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_3_5')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_muffler_dim" rows="2" placeholder="치수 도면 설명">\${E(v('en_muffler_dim'))}</textarea>
            <input type="hidden" data-field="en_muffler_dim_imgs" value="\${E(v('en_muffler_dim_imgs'))}"><div class="en-drop" data-field-img="en_muffler_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.4 촉매 상세제원 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_cat_spec_title')}</td></tr>

      <!-- 1.4.1 촉매 제작사 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_4_1')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cat_maker" rows="2" placeholder="제작사명">\${E(v('en_cat_maker'))}</textarea>
            <input type="hidden" data-field="en_cat_maker_imgs" value="\${E(v('en_cat_maker_imgs'))}"><div class="en-drop" data-field-img="en_cat_maker"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.4.2 촉매 재질 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_4_2')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cat_material" rows="2" placeholder="촉매 재질">\${E(v('en_cat_material'))}</textarea>
            <input type="hidden" data-field="en_cat_material_imgs" value="\${E(v('en_cat_material_imgs'))}"><div class="en-drop" data-field-img="en_cat_material"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.4.3 촉매 성능 및 치수 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_4_3')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cat_spec" rows="2" placeholder="촉매 성능 및 치수">\${E(v('en_cat_spec'))}</textarea>
            <input type="hidden" data-field="en_cat_spec_imgs" value="\${E(v('en_cat_spec_imgs'))}"><div class="en-drop" data-field-img="en_cat_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.4.4 촉매 치수 도면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_4_4')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cat_dim" rows="2" placeholder="치수 도면 설명">\${E(v('en_cat_dim'))}</textarea>
            <input type="hidden" data-field="en_cat_dim_imgs" value="\${E(v('en_cat_dim_imgs'))}"><div class="en-drop" data-field-img="en_cat_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.4.5 촉매 원리 또는 효과 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_4_5')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cat_principle" rows="3" placeholder="촉매 원리 또는 효과를 기재하세요">\${E(v('en_cat_principle'))}</textarea>
            <input type="hidden" data-field="en_cat_principle_imgs" value="\${E(v('en_cat_principle_imgs'))}"><div class="en-drop" data-field-img="en_cat_principle"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.4.6 촉매 부착위치 도면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_4_6')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cat_pos" rows="2" placeholder="부착위치 설명">\${E(v('en_cat_pos'))}</textarea>
            <input type="hidden" data-field="en_cat_pos_imgs" value="\${E(v('en_cat_pos_imgs'))}"><div class="en-drop" data-field-img="en_cat_pos"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.5 센서 상세제원 -->
      <tr><td class="en-sub-th" colspan="2">1.5. 센서 상세제원</td></tr>

      <!-- 1.5.1 센서 제작사 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">1.5.1. 센서 제작사</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_sensor_maker" rows="2" placeholder="제작사명">\${E(v('en_sensor_maker'))}</textarea>
            <input type="hidden" data-field="en_sensor_maker_imgs" value="\${E(v('en_sensor_maker_imgs'))}"><div class="en-drop" data-field-img="en_sensor_maker"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.5.2 센서 재질 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">1.5.2. 센서 재질</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_sensor_material" rows="2" placeholder="센서 재질">\${E(v('en_sensor_material'))}</textarea>
            <input type="hidden" data-field="en_sensor_material_imgs" value="\${E(v('en_sensor_material_imgs'))}"><div class="en-drop" data-field-img="en_sensor_material"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.5.3 센서 치수 도면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">1.5.3. 센서 치수 도면</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_sensor_dim" rows="2" placeholder="치수 도면 설명">\${E(v('en_sensor_dim'))}</textarea>
            <input type="hidden" data-field="en_sensor_dim_imgs" value="\${E(v('en_sensor_dim_imgs'))}"><div class="en-drop" data-field-img="en_sensor_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.6 머플러 도면 -->
      <tr><td class="en-sub-th" colspan="2">1.6. 머플러 도면</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_muffler_drawing" rows="2" placeholder="머플러 도면 설명">\${E(v('en_muffler_drawing'))}</textarea>
            <input type="hidden" data-field="en_muffler_drawing_imgs" value="\${E(v('en_muffler_drawing_imgs'))}"><div class="en-drop" data-field-img="en_muffler_drawing"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.7 머플러 사진 -->
      <tr><td class="en-sub-th" colspan="2">1.7. 머플러 사진</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_muffler_photo" rows="2" placeholder="머플러 사진 설명">\${E(v('en_muffler_photo'))}</textarea>
            <input type="hidden" data-field="en_muffler_photo_imgs" value="\${E(v('en_muffler_photo_imgs'))}"><div class="en-drop" data-field-img="en_muffler_photo"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════ -->
  <!-- 2. 밸브 장치(Valve Train)                              -->
  <!-- ══════════════════════════════════════════════════════ -->
  <table class="en-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup><col style="width:22%;"><col style="width:78%;"></colgroup>
    <tbody>
      <tr><th class="en-sec-th" colspan="2">2. 밸브 장치(Valve Train)</th></tr>

      <!-- 2.1 밸브 기구의 관성력 -->
      <tr><td class="en-sub-th" colspan="2">2.1. 밸브 기구의 관성력</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_valve_inertia" rows="3" placeholder="밸브 기구의 관성력에 관한 내용을 기재하세요">\${E(v('en_valve_inertia'))}</textarea>
            <input type="hidden" data-field="en_valve_inertia_imgs" value="\${E(v('en_valve_inertia_imgs'))}"><div class="en-drop" data-field-img="en_valve_inertia"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 2.2 밸브 스프링의 Surging 현상 대응기술 -->
      <tr><td class="en-sub-th" colspan="2">2.2. 밸브 스프링의 Surging 현상 대응기술</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_valve_surging" rows="3" placeholder="Surging 현상 대응기술을 기재하세요">\${E(v('en_valve_surging'))}</textarea>
            <input type="hidden" data-field="en_valve_surging_imgs" value="\${E(v('en_valve_surging_imgs'))}"><div class="en-drop" data-field-img="en_valve_surging"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 2.3 캠프로파일 및 제원 -->
      <tr><td class="en-sub-th" colspan="2">2.3. 캠프로파일 및 제원</td></tr>

      <!-- 2.3.1 밸브 제원 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">2.3.1. 밸브 제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_valve_spec" rows="2" placeholder="밸브 제원을 기재하세요">\${E(v('en_valve_spec'))}</textarea>
            <input type="hidden" data-field="en_valve_spec_imgs" value="\${E(v('en_valve_spec_imgs'))}"><div class="en-drop" data-field-img="en_valve_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 2.3.2 Cam 제원 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">2.3.2. Cam 제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cam_spec" rows="2" placeholder="Cam 제원을 기재하세요">\${E(v('en_cam_spec'))}</textarea>
            <input type="hidden" data-field="en_cam_spec_imgs" value="\${E(v('en_cam_spec_imgs'))}"><div class="en-drop" data-field-img="en_cam_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 2.3.3 Cam 치수 도면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">2.3.3. Cam 치수 도면</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cam_dim" rows="2" placeholder="Cam 치수 도면 설명">\${E(v('en_cam_dim'))}</textarea>
            <input type="hidden" data-field="en_cam_dim_imgs" value="\${E(v('en_cam_dim_imgs'))}"><div class="en-drop" data-field-img="en_cam_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 2.4 Valve 기구의 재질 -->
      <tr><td class="en-sub-th" colspan="2">2.4. Valve 기구의 재질 등에 관한 내용</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_valve_material" rows="3" placeholder="Valve 기구의 재질 등에 관한 내용을 기재하세요">\${E(v('en_valve_material'))}</textarea>
            <input type="hidden" data-field="en_valve_material_imgs" value="\${E(v('en_valve_material_imgs'))}"><div class="en-drop" data-field-img="en_valve_material"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 2.5 밸브 간극 -->
      <tr><td class="en-sub-th" colspan="2">2.5. 밸브 간극</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_valve_clearance" rows="2" placeholder="밸브 간극 수치 또는 설명">\${E(v('en_valve_clearance'))}</textarea>
            <input type="hidden" data-field="en_valve_clearance_imgs" value="\${E(v('en_valve_clearance_imgs'))}"><div class="en-drop" data-field-img="en_valve_clearance"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════ -->
  <!-- 3. 점화장치                                            -->
  <!-- ══════════════════════════════════════════════════════ -->
  <table class="en-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup><col style="width:22%;"><col style="width:78%;"></colgroup>
    <tbody>
      <tr><th class="en-sec-th" colspan="2">3. 점화장치</th></tr>

      <!-- 3.1 점화장치 구성도 -->
      <tr><td class="en-sub-th" colspan="2">3.1. 점화장치 구성도</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ign_diagram" rows="2" placeholder="점화장치 구성 설명">\${E(v('en_ign_diagram'))}</textarea>
            <input type="hidden" data-field="en_ign_diagram_imgs" value="\${E(v('en_ign_diagram_imgs'))}"><div class="en-drop" data-field-img="en_ign_diagram"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.2 점화장치 제어특성 -->
      <tr><td class="en-sub-th" colspan="2">3.2. 점화장치 제어특성</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ign_control" rows="3" placeholder="점화장치 제어특성을 기재하세요">\${E(v('en_ign_control'))}</textarea>
            <input type="hidden" data-field="en_ign_control_imgs" value="\${E(v('en_ign_control_imgs'))}"><div class="en-drop" data-field-img="en_ign_control"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.3 점화장치 상세제원 -->
      <tr><td class="en-sub-th" colspan="2">3.3. 점화장치 상세제원</td></tr>

      <!-- 3.3.1 제너레이터 -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">3.3.1. 제너레이터</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">3.3.1.1. 제너레이터 상세제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_gen_spec" rows="2" placeholder="제너레이터 상세제원">\${E(v('en_gen_spec'))}</textarea>
            <input type="hidden" data-field="en_gen_spec_imgs" value="\${E(v('en_gen_spec_imgs'))}"><div class="en-drop" data-field-img="en_gen_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">3.3.1.2. 제너레이터 형상 및 치수제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_gen_dim" rows="2" placeholder="형상 및 치수 설명">\${E(v('en_gen_dim'))}</textarea>
            <input type="hidden" data-field="en_gen_dim_imgs" value="\${E(v('en_gen_dim_imgs'))}"><div class="en-drop" data-field-img="en_gen_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.3.2 CDI UNIT -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">3.3.2. CDI UNIT</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">3.3.2.1. CDI UNIT 상세제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cdi_spec" rows="2" placeholder="CDI UNIT 상세제원">\${E(v('en_cdi_spec'))}</textarea>
            <input type="hidden" data-field="en_cdi_spec_imgs" value="\${E(v('en_cdi_spec_imgs'))}"><div class="en-drop" data-field-img="en_cdi_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">3.3.2.2. CDI UNIT 형상 및 치수제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cdi_dim" rows="2" placeholder="형상 및 치수 설명">\${E(v('en_cdi_dim'))}</textarea>
            <input type="hidden" data-field="en_cdi_dim_imgs" value="\${E(v('en_cdi_dim_imgs'))}"><div class="en-drop" data-field-img="en_cdi_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.3.3 점화코일 -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">3.3.3. 점화코일</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">3.3.3.1. 점화코일 상세제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_coil_spec" rows="2" placeholder="점화코일 상세제원">\${E(v('en_coil_spec'))}</textarea>
            <input type="hidden" data-field="en_coil_spec_imgs" value="\${E(v('en_coil_spec_imgs'))}"><div class="en-drop" data-field-img="en_coil_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">3.3.3.2. 점화코일 형상 및 치수제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_coil_dim" rows="2" placeholder="형상 및 치수 설명">\${E(v('en_coil_dim'))}</textarea>
            <input type="hidden" data-field="en_coil_dim_imgs" value="\${E(v('en_coil_dim_imgs'))}"><div class="en-drop" data-field-img="en_coil_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.3.4 점화플러그 -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">3.3.4. 점화플러그</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">3.3.4.1. 점화플러그 상세제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_plug_spec" rows="2" placeholder="점화플러그 상세제원">\${E(v('en_plug_spec'))}</textarea>
            <input type="hidden" data-field="en_plug_spec_imgs" value="\${E(v('en_plug_spec_imgs'))}"><div class="en-drop" data-field-img="en_plug_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">3.3.4.2. 점화플러그 형상 및 치수제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_plug_dim" rows="2" placeholder="형상 및 치수 설명">\${E(v('en_plug_dim'))}</textarea>
            <input type="hidden" data-field="en_plug_dim_imgs" value="\${E(v('en_plug_dim_imgs'))}"><div class="en-drop" data-field-img="en_plug_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.3.5 ECU -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">3.3.5. ECU 상세제원</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">3.3.5.1. ECU 상세제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ecu_spec" rows="2" placeholder="ECU 상세제원">\${E(v('en_ecu_spec'))}</textarea>
            <input type="hidden" data-field="en_ecu_spec_imgs" value="\${E(v('en_ecu_spec_imgs'))}"><div class="en-drop" data-field-img="en_ecu_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">3.3.5.2. ECU 형상 및 치수제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ecu_dim" rows="2" placeholder="형상 및 치수 설명">\${E(v('en_ecu_dim'))}</textarea>
            <input type="hidden" data-field="en_ecu_dim_imgs" value="\${E(v('en_ecu_dim_imgs'))}"><div class="en-drop" data-field-img="en_ecu_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.4 점화장치 사진 -->
      <tr><td class="en-sub-th" colspan="2">3.4. 점화장치 사진</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ign_photo" rows="2" placeholder="점화장치 사진 설명">\${E(v('en_ign_photo'))}</textarea>
            <input type="hidden" data-field="en_ign_photo_imgs" value="\${E(v('en_ign_photo_imgs'))}"><div class="en-drop" data-field-img="en_ign_photo"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════ -->
  <!-- 4. 연료장치                                            -->
  <!-- ══════════════════════════════════════════════════════ -->
  <table class="en-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup><col style="width:22%;"><col style="width:78%;"></colgroup>
    <tbody>
      <tr><th class="en-sec-th" colspan="2">4. 연료장치</th></tr>

      <!-- 4.1 연료장치 구성 및 제어방식 -->
      <tr><td class="en-sub-th" colspan="2">4.1. 연료장치 구성 및 제어방식</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_fuel_sys" rows="3" placeholder="연료장치 구성 및 제어방식을 기재하세요">\${E(v('en_fuel_sys'))}</textarea>
            <input type="hidden" data-field="en_fuel_sys_imgs" value="\${E(v('en_fuel_sys_imgs'))}"><div class="en-drop" data-field-img="en_fuel_sys"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 4.2 연료장치 도면 및 치수 -->
      <tr><td class="en-sub-th" colspan="2">4.2. 연료장치 도면 및 치수</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_fuel_drawing" rows="2" placeholder="도면 및 치수 설명">\${E(v('en_fuel_drawing'))}</textarea>
            <input type="hidden" data-field="en_fuel_drawing_imgs" value="\${E(v('en_fuel_drawing_imgs'))}"><div class="en-drop" data-field-img="en_fuel_drawing"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 4.3 연료장치 상세제원 -->
      <tr><td class="en-sub-th" colspan="2">4.3. 연료장치 상세제원</td></tr>

      <!-- 4.3.1 연료탱크 -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">4.3.1. 연료탱크</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">4.3.1.1. 연료탱크 상세제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_tank_spec" rows="2" placeholder="연료탱크 상세제원">\${E(v('en_tank_spec'))}</textarea>
            <input type="hidden" data-field="en_tank_spec_imgs" value="\${E(v('en_tank_spec_imgs'))}"><div class="en-drop" data-field-img="en_tank_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">4.3.1.2. 연료탱크 위치</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_tank_pos" rows="2" placeholder="위치 설명">\${E(v('en_tank_pos'))}</textarea>
            <input type="hidden" data-field="en_tank_pos_imgs" value="\${E(v('en_tank_pos_imgs'))}"><div class="en-drop" data-field-img="en_tank_pos"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">4.3.1.3. 연료탱크 형상</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_tank_shape" rows="2" placeholder="형상 설명">\${E(v('en_tank_shape'))}</textarea>
            <input type="hidden" data-field="en_tank_shape_imgs" value="\${E(v('en_tank_shape_imgs'))}"><div class="en-drop" data-field-img="en_tank_shape"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 4.3.2 스로틀바디 -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">4.3.2. 스로틀바디</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">4.3.2.1. 스로틀바디 상세제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_throttle_spec" rows="2" placeholder="스로틀바디 상세제원">\${E(v('en_throttle_spec'))}</textarea>
            <input type="hidden" data-field="en_throttle_spec_imgs" value="\${E(v('en_throttle_spec_imgs'))}"><div class="en-drop" data-field-img="en_throttle_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">4.3.2.2. 스로틀바디 형상 및 치수제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_throttle_dim" rows="2" placeholder="형상 및 치수 설명">\${E(v('en_throttle_dim'))}</textarea>
            <input type="hidden" data-field="en_throttle_dim_imgs" value="\${E(v('en_throttle_dim_imgs'))}"><div class="en-drop" data-field-img="en_throttle_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 4.3.3 연료인젝터 -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">4.3.3. 연료인젝터</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">4.3.3.1. 연료인젝터 상세제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_injector_spec" rows="2" placeholder="연료인젝터 상세제원">\${E(v('en_injector_spec'))}</textarea>
            <input type="hidden" data-field="en_injector_spec_imgs" value="\${E(v('en_injector_spec_imgs'))}"><div class="en-drop" data-field-img="en_injector_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">4.3.3.2. 연료인젝터 형상 및 치수제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_injector_dim" rows="2" placeholder="형상 및 치수 설명">\${E(v('en_injector_dim'))}</textarea>
            <input type="hidden" data-field="en_injector_dim_imgs" value="\${E(v('en_injector_dim_imgs'))}"><div class="en-drop" data-field-img="en_injector_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 4.3.4 연료펌프 -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">4.3.4. 연료펌프</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">4.3.4.1. 연료펌프 상세제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_pump_spec" rows="2" placeholder="연료펌프 상세제원">\${E(v('en_pump_spec'))}</textarea>
            <input type="hidden" data-field="en_pump_spec_imgs" value="\${E(v('en_pump_spec_imgs'))}"><div class="en-drop" data-field-img="en_pump_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">4.3.4.2. 연료펌프 형상 및 치수제원</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_pump_dim" rows="2" placeholder="형상 및 치수 설명">\${E(v('en_pump_dim'))}</textarea>
            <input type="hidden" data-field="en_pump_dim_imgs" value="\${E(v('en_pump_dim_imgs'))}"><div class="en-drop" data-field-img="en_pump_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 4.4 연료장치 사진 -->
      <tr><td class="en-sub-th" colspan="2">4.4. 연료장치 사진</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_fuel_photo" rows="2" placeholder="연료장치 사진 설명">\${E(v('en_fuel_photo'))}</textarea>
            <input type="hidden" data-field="en_fuel_photo_imgs" value="\${E(v('en_fuel_photo_imgs'))}"><div class="en-drop" data-field-img="en_fuel_photo"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════ -->
  <!-- 5. 흡배기장치                                          -->
  <!-- ══════════════════════════════════════════════════════ -->
  <table class="en-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup><col style="width:22%;"><col style="width:78%;"></colgroup>
    <tbody>
      <tr><th class="en-sec-th" colspan="2">5. 흡배기장치</th></tr>

      <!-- 5.1 흡기계통 -->
      <tr><td class="en-sub-th" colspan="2">5.1. 흡기계통</td></tr>

      <!-- 5.1.1 흡기다기관 구성도 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">5.1.1. 흡기다기관 구성도</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_intake_diagram" rows="2" placeholder="흡기다기관 구성 설명">\${E(v('en_intake_diagram'))}</textarea>
            <input type="hidden" data-field="en_intake_diagram_imgs" value="\${E(v('en_intake_diagram_imgs'))}"><div class="en-drop" data-field-img="en_intake_diagram"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 5.1.2 흡기메니폴드 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">5.1.2. 흡기메니폴드</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_intake_manifold" rows="2" placeholder="흡기메니폴드 제원 또는 설명">\${E(v('en_intake_manifold'))}</textarea>
            <input type="hidden" data-field="en_intake_manifold_imgs" value="\${E(v('en_intake_manifold_imgs'))}"><div class="en-drop" data-field-img="en_intake_manifold"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 5.1.3 에어필터 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">5.1.3. 에어필터</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_air_filter" rows="2" placeholder="에어필터 제원 또는 설명">\${E(v('en_air_filter'))}</textarea>
            <input type="hidden" data-field="en_air_filter_imgs" value="\${E(v('en_air_filter_imgs'))}"><div class="en-drop" data-field-img="en_air_filter"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 5.2 배기계통 -->
      <tr><td class="en-sub-th" colspan="2">5.2. 배기계통</td></tr>

      <!-- 5.2.1 배기다기관 구성도 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">5.2.1. 배기다기관 구성도</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_exhaust_diagram" rows="2" placeholder="배기다기관 구성 설명">\${E(v('en_exhaust_diagram'))}</textarea>
            <input type="hidden" data-field="en_exhaust_diagram_imgs" value="\${E(v('en_exhaust_diagram_imgs'))}"><div class="en-drop" data-field-img="en_exhaust_diagram"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 5.2.2 배기메니폴드 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">5.2.2. 배기메니폴드</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_exhaust_manifold" rows="2" placeholder="배기메니폴드 제원 또는 설명">\${E(v('en_exhaust_manifold'))}</textarea>
            <input type="hidden" data-field="en_exhaust_manifold_imgs" value="\${E(v('en_exhaust_manifold_imgs'))}"><div class="en-drop" data-field-img="en_exhaust_manifold"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════ -->
  <!-- 6. 차량외관 및 치수                                    -->
  <!-- ══════════════════════════════════════════════════════ -->
  <table class="en-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup><col style="width:22%;"><col style="width:78%;"></colgroup>
    <tbody>
      <tr><th class="en-sec-th" colspan="2">6. 차량외관 및 치수</th></tr>

      <!-- 6.1 차량사진 -->
      <tr><td class="en-sub-th" colspan="2">6.1. 차량사진</td></tr>

      <!-- 6.1.1 차량 전면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">6.1.1. 차량 전면</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_veh_front" rows="2" placeholder="차량 전면 설명">\${E(v('en_veh_front'))}</textarea>
            <input type="hidden" data-field="en_veh_front_imgs" value="\${E(v('en_veh_front_imgs'))}"><div class="en-drop" data-field-img="en_veh_front"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 6.1.2 차량 후면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">6.1.2. 차량 후면</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_veh_rear" rows="2" placeholder="차량 후면 설명">\${E(v('en_veh_rear'))}</textarea>
            <input type="hidden" data-field="en_veh_rear_imgs" value="\${E(v('en_veh_rear_imgs'))}"><div class="en-drop" data-field-img="en_veh_rear"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 6.1.3 차량 측면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">6.1.3. 차량 측면</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_veh_side" rows="2" placeholder="차량 측면 설명">\${E(v('en_veh_side'))}</textarea>
            <input type="hidden" data-field="en_veh_side_imgs" value="\${E(v('en_veh_side_imgs'))}"><div class="en-drop" data-field-img="en_veh_side"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 6.1.4 차량 상면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">6.1.4. 차량 상면</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_veh_top" rows="2" placeholder="차량 상면 설명">\${E(v('en_veh_top'))}</textarea>
            <input type="hidden" data-field="en_veh_top_imgs" value="\${E(v('en_veh_top_imgs'))}"><div class="en-drop" data-field-img="en_veh_top"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 6.2 외형도 -->
      <tr><td class="en-sub-th" colspan="2">6.2. 외형도</td></tr>

      <!-- 6.2.1 외형 측면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">6.2.1. 외형 측면</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ext_side" rows="2" placeholder="외형 측면 설명">\${E(v('en_ext_side'))}</textarea>
            <input type="hidden" data-field="en_ext_side_imgs" value="\${E(v('en_ext_side_imgs'))}"><div class="en-drop" data-field-img="en_ext_side"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 6.2.2 외형 상면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">6.2.2. 외형 상면</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ext_top" rows="2" placeholder="외형 상면 설명">\${E(v('en_ext_top'))}</textarea>
            <input type="hidden" data-field="en_ext_top_imgs" value="\${E(v('en_ext_top_imgs'))}"><div class="en-drop" data-field-img="en_ext_top"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 6.2.3 외형 뒷면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">6.2.3. 외형 뒷면</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ext_rear" rows="2" placeholder="외형 뒷면 설명">\${E(v('en_ext_rear'))}</textarea>
            <input type="hidden" data-field="en_ext_rear_imgs" value="\${E(v('en_ext_rear_imgs'))}"><div class="en-drop" data-field-img="en_ext_rear"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════ -->
  <!-- 7. 기타                                                -->
  <!-- ══════════════════════════════════════════════════════ -->
  <table class="en-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup><col style="width:22%;"><col style="width:78%;"></colgroup>
    <tbody>
      <tr><th class="en-sec-th" colspan="2">7. 기타</th></tr>

      <!-- 7.1 그 외 배출가스 및 소음 저감기술 -->
      <tr><td class="en-sub-th" colspan="2">7.1. 그 외 배출가스 및 소음 저감기술</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_other_tech" rows="4" placeholder="그 외 배출가스 및 소음 저감기술을 기재하세요">\${E(v('en_other_tech'))}</textarea>
            <input type="hidden" data-field="en_other_tech_imgs" value="\${E(v('en_other_tech_imgs'))}"><div class="en-drop" data-field-img="en_other_tech"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
    </tbody>
  </table>

  <div id="qr-footer-wrap" style="margin-top:12px;"></div>
</div>
\`;

  if (formType==='obd_config') return \`
<style>
/* ══════ obd_config 전용 스타일 ══════ */
.en-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
  background:#fff;
  color:#111;
  border-radius:8px;
}
.en-doc-tag { font-size:8.5pt; font-weight:700; color:#444; margin:10px 0 4px; }
.en-main-title {
  font-size:13pt; font-weight:900; text-align:center;
  margin:4px 0 14px; letter-spacing:.03em; color:#111;
}
.en-tbl {
  width:100%; border-collapse:collapse;
  font-size:8.5pt; margin-bottom:0;
}
.en-tbl th, .en-tbl td {
  border:1px solid #888;
  padding:3px 5px;
  vertical-align:middle;
  color:#111;
}
.en-sec-th {
  background:#d6e4f7;
  font-weight:700; text-align:left;
  padding:4px 6px; font-size:8.5pt; color:#111;
}
.en-sub-th {
  background:#eef3fa;
  font-weight:700; text-align:left;
  padding:3px 6px; font-size:8.5pt; color:#111;
}
.en-th {
  background:#eef3fa;
  font-weight:600; text-align:center;
  font-size:8pt; color:#111;
}
.en-lbl {
  background:#f5f8ff;
  font-weight:600; color:#111;
  vertical-align:middle;
}
/* ── 복합 입력 필드 (텍스트 + 이미지) ── */
.en-field {
  display:flex; flex-direction:column; gap:4px;
  padding:3px 4px; box-sizing:border-box; width:100%;
}
.en-field-text {
  width:100%; font-size:8.5pt; font-family:inherit;
  border:none; background:transparent; padding:2px 0;
  box-sizing:border-box; resize:vertical; color:#111;
  min-height:36px; line-height:1.5;
}
.en-field-text::placeholder { color:#aaa; }
.en-field-text:focus { outline:none; border-bottom:1px dashed #4e90d8; }
/* 이미지 드롭존 */
.en-drop {
  border:1.5px dashed #b0c4de;
  border-radius:5px;
  background:#f8faff;
  padding:6px 8px;
  cursor:pointer;
  transition:border-color .15s, background .15s;
  position:relative;
  min-height:36px;
}
.en-drop:hover { border-color:#4e90d8; background:#eef3fa; }
.en-drop.drag-over { border-color:#2563eb; background:#dbeafe; }
.en-drop-hint {
  color:#aaa; font-size:7.5pt; text-align:center;
  pointer-events:none; user-select:none;
  display:flex; align-items:center; justify-content:center; gap:4px;
}
.en-drop input[type=file] { display:none; }
/* 이미지 미리보기 목록 */
.en-img-list {
  display:flex; flex-wrap:wrap; gap:6px; margin-top:4px;
}
.en-img-item {
  position:relative; display:inline-block;
}
.en-img-item img {
  max-width:140px; max-height:100px;
  border:1px solid #ccc; border-radius:3px;
  display:block; object-fit:contain; background:#fff;
}
.en-img-item-del {
  position:absolute; top:-6px; right:-6px;
  width:16px; height:16px; border-radius:50%;
  background:#ef4444; color:#fff; font-size:10px;
  display:flex; align-items:center; justify-content:center;
  cursor:pointer; line-height:1; border:none;
  box-shadow:0 1px 3px rgba(0,0,0,.3);
}
.en-img-item-del:hover { background:#dc2626; }
/* 헤더 셀의 텍스트 입력 (수입사 등 단순 1행 셀) */
.en-inp {
  border:none; background:transparent;
  width:100%; font-size:8.5pt;
  font-family:inherit; padding:0 2px;
  box-sizing:border-box; color:#111;
}
.en-inp::placeholder { color:#aaa; }
.en-inp:focus { outline:none; border-bottom:1px solid #4e90d8; }
@media print {
  /* ── 전체 래퍼 ── */
  .en-wrap { background:#fff !important; color:#000 !important; border-radius:0 !important; }

  /* ── 테이블 셀: 내용에 맞춰 높이 자동 확장, 잘림 방지 ── */
  .en-tbl { table-layout:fixed !important; width:100% !important; }
  .en-tbl th, .en-tbl td {
    border:1px solid #333 !important; color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important; overflow-wrap:break-word !important;
  }

  /* ── en-field: 인쇄 시 flex 유지, 높이 자동 ── */
  .en-field { height:auto !important; overflow:visible !important; display:flex !important; flex-direction:column !important; }

  /* ── textarea: 내용 전체 표시, 스크롤 없이 ── */
  textarea.en-field-text {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; min-height:0 !important; max-height:none !important;
    overflow:visible !important; resize:none !important;
    white-space:pre-wrap !important; word-break:break-word !important;
    overflow-wrap:break-word !important;
    display:block !important; box-sizing:border-box !important;
    -webkit-appearance:none !important; appearance:none !important;
    padding:2px 0 !important;
  }

  /* ── 단순 1행 input ── */
  .en-inp {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important;
  }

  /* ── hidden input 완전 숨김 ── */
  input[type=hidden] { display:none !important; }

  /* ── 이미지 드롭존: 테두리/배경 제거, 힌트/삭제버튼 숨김 ── */
  .en-drop {
    border:none !important; background:transparent !important;
    padding:0 !important; min-height:unset !important;
    height:auto !important; overflow:visible !important;
  }
  .en-drop-hint { display:none !important; }
  .en-img-item-del { display:none !important; }
  .en-img-list { gap:4px !important; margin-top:2px !important; }
  .en-img-item img {
    max-width:100% !important; max-height:none !important;
    page-break-inside:avoid;
  }
  /* 이미지가 없는 빈 en-drop은 공간 차지 안 함 */
  .en-drop:not(:has(img)) { display:none !important; }

  /* ── 섹션 헤더 배경색 유지 ── */
  .en-sec-th { background:#d6e4f7 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-sub-th { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-th     { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-lbl    { background:#f5f8ff !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }

  /* ── 페이지 분리 방지 (행 단위) ── */
  .en-tbl tr { page-break-inside:avoid; }
}

.obd-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
  background:#fff;
  color:#111;
  border-radius:8px;
}
.obd-doc-tag { font-size:8.5pt; font-weight:700; color:#444; margin:10px 0 4px; }
.obd-main-title {
  font-size:13pt; font-weight:900; text-align:center;
  margin:4px 0 14px; letter-spacing:.03em; color:#111;
}
.obd-tbl {
  width:100%; border-collapse:collapse;
  font-size:8.5pt; margin-bottom:0;
}
.obd-tbl th, .obd-tbl td {
  border:1px solid #888;
  padding:3px 5px;
  vertical-align:middle;
  color:#111;
}
.obd-sec-th {
  background:#d6e4f7;
  font-weight:700; text-align:left;
  padding:4px 6px; font-size:8.5pt; color:#111;
}
.obd-sub-th {
  background:#eef3fa;
  font-weight:700; text-align:left;
  padding:3px 6px; font-size:8.5pt; color:#111;
}
.obd-th {
  background:#eef3fa;
  font-weight:600; text-align:center;
  font-size:8pt; color:#111;
}
.obd-lbl {
  background:#f5f8ff;
  font-weight:600; color:#111;
  vertical-align:middle;
}
.obd-lbl2 {
  background:#f5f8ff;
  font-weight:600; color:#111;
  vertical-align:top;
  padding:4px 6px;
}
.obd-field {
  display:flex; flex-direction:column; gap:4px;
  padding:3px 4px; box-sizing:border-box; width:100%;
}
.obd-field-text {
  width:100%; font-size:8.5pt; font-family:inherit;
  border:none; background:transparent; padding:2px 0;
  box-sizing:border-box; resize:vertical; color:#111;
  min-height:28px; line-height:1.5;
}
.obd-field-text::placeholder { color:#aaa; }
.obd-field-text:focus { outline:none; border-bottom:1px dashed #4e90d8; }
/* 이미지 드롭존 */
.obd-drop {
  border:1.5px dashed #b0c4de;
  border-radius:5px;
  background:#f8faff;
  padding:6px 8px;
  cursor:pointer;
  transition:border-color .15s, background .15s;
  position:relative;
  min-height:36px;
}
.obd-drop:hover { border-color:#4e90d8; background:#eef3fa; }
.obd-drop.drag-over { border-color:#2563eb; background:#dbeafe; }
.obd-drop-hint {
  color:#aaa; font-size:7.5pt; text-align:center;
  pointer-events:none; user-select:none;
  display:flex; align-items:center; justify-content:center; gap:4px;
}
.obd-drop input[type=file] { display:none; }
.obd-img-list {
  display:flex; flex-wrap:wrap; gap:6px; margin-top:4px;
}
.obd-img-item {
  position:relative; display:inline-block;
}
.obd-img-item img {
  max-width:140px; max-height:100px;
  border:1px solid #ccc; border-radius:3px;
  display:block; object-fit:contain; background:#fff;
}
.obd-img-item-del {
  position:absolute; top:-6px; right:-6px;
  width:16px; height:16px; border-radius:50%;
  background:#ef4444; color:#fff; font-size:10px;
  display:flex; align-items:center; justify-content:center;
  cursor:pointer; line-height:1; border:none;
  box-shadow:0 1px 3px rgba(0,0,0,.3);
}
.obd-check-row { display:flex; align-items:center; gap:6px; flex-wrap:wrap; }
.obd-check-row label { display:flex; align-items:center; gap:3px; font-size:8.5pt; cursor:pointer; }
.obd-check-row input[type=checkbox] { width:13px; height:13px; cursor:pointer; }
.obd-section-label {
  font-weight:700; color:#1e3a5f; font-size:8.5pt;
  padding:4px 6px 2px; background:#e8f0fb;
  border-left:3px solid #4e90d8; margin:8px 0 2px;
}
.obd-note-text {
  font-size:8pt; color:#555;
  padding:3px 4px;
  border:none; background:transparent;
  width:100%; box-sizing:border-box;
  resize:vertical; min-height:24px; font-family:inherit;
}
.obd-note-text:focus { outline:none; border-bottom:1px dashed #999; }
</style>

<div class="obd-wrap">

<!-- ══ 헤더 식별 정보 (맨 위) ══ -->
<table class="obd-tbl" style="margin-bottom:8px;">
  <colgroup><col style="width:35%"><col style="width:12%"><col style="width:13%"><col style="width:40%"></colgroup>
  <tr>
    <th class="obd-th">\${BL('importer')}</th>
    <th class="obd-th">\${BL('cert_year')}</th>
    <th class="obd-th">\${BL('displacement')}</th>
    <th class="obd-th">\${BL('family_code')}</th>
  </tr>
  <tr>
    <td><input class="obd-field-text" type="text" readonly style="background:#f5f8ff;pointer-events:none;cursor:default;" value="\${E(v('importer'))}"></td>
    <td><input class="obd-field-text" type="text" readonly style="background:#f5f8ff;pointer-events:none;cursor:default;" value="\${E(v('cert_year'))}"></td>
    <td><input class="obd-field-text" type="text" readonly style="background:#f5f8ff;pointer-events:none;cursor:default;" value="\${E(v('displacement'))}"></td>
    <td><input class="obd-field-text" type="text" readonly style="background:#f5f8ff;pointer-events:none;cursor:default;" value="\${E(v('family_code'))}"></td>
  </tr>
</table>

<div class="obd-doc-tag">[별지 제9호 서식]</div>
<div class="obd-main-title">배출가스자기진단장치(OBD) 구성에 관한 서류</div>

<!-- ══════════════════════════════════════════════════
     1. OBD 종합정보에 관한 서류
══════════════════════════════════════════════════ -->
<div class="obd-section-label">1. 배출가스자기진단장치(OBD) 종합정보에 관한 서류</div>

<!-- 1.1 부품 목록 -->
<div style="font-size:8pt; font-weight:600; padding:4px 2px 2px; color:#333;">
  1.1. 센서·액츄에이터 등의 부품들과 같이 배출가스 자기진단장치에 의해 감시되는 자동차 배출가스 관련 부품 목록 및 기능적인 특성을 설명하는 자료
</div>
<table class="obd-tbl">
  <colgroup><col style="width:14%"><col style="width:38%"><col style="width:48%"></colgroup>
  <tr>
    <th class="obd-th">\${BL('th_div')}</th>
    <th class="obd-th">자동차 배출가스 관련 부품</th>
    <th class="obd-th">기능적인 작동 특성</th>
  </tr>
  <!-- 센서 -->
  <tr>
    <td class="obd-lbl" rowspan="5" style="text-align:center; font-weight:700;">센서</td>
    <td class="obd-lbl" style="font-weight:400;">크랭크 포지션 센서(CPS)</td>
    <td><textarea class="obd-field-text" data-field="obd_cps_char" placeholder="기능적인 작동 특성 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">온도 공기압 센서(T-MAP)</td>
    <td><textarea class="obd-field-text" data-field="obd_tmap_char" placeholder="기능적인 작동 특성 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">스로틀 포지션 센서(TPS)</td>
    <td><textarea class="obd-field-text" data-field="obd_tps_char" placeholder="기능적인 작동 특성 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">엔진 온도 센서(WPS)</td>
    <td><textarea class="obd-field-text" data-field="obd_wps_char" placeholder="기능적인 작동 특성 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">산소 센서(O₂)</td>
    <td><textarea class="obd-field-text" data-field="obd_o2_char" placeholder="기능적인 작동 특성 입력"></textarea></td>
  </tr>
  <!-- 액츄에이터 -->
  <tr>
    <td class="obd-lbl" rowspan="4" style="text-align:center; font-weight:700;">액츄에이터</td>
    <td class="obd-lbl" style="font-weight:400;">연료분사장치(인젝터)</td>
    <td><textarea class="obd-field-text" data-field="obd_injector_char" placeholder="기능적인 작동 특성 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">점화코일</td>
    <td><textarea class="obd-field-text" data-field="obd_coil_char" placeholder="기능적인 작동 특성 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">O₂ 센서 히터</td>
    <td><textarea class="obd-field-text" data-field="obd_o2heater_char" placeholder="기능적인 작동 특성 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">와이어 액츄에이터에 의한 스로틀</td>
    <td><textarea class="obd-field-text" data-field="obd_throttle_char" placeholder="기능적인 작동 특성 입력"></textarea></td>
  </tr>
  <!-- 기타 -->
  <tr>
    <td class="obd-lbl" rowspan="2" style="text-align:center; font-weight:700;">\${BL('nt_etc')}</td>
    <td class="obd-lbl" style="font-weight:400;">라디에이터 팬 릴레이</td>
    <td><textarea class="obd-field-text" data-field="obd_fanrelay_char" placeholder="기능적인 작동 특성 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">연료 펌프 릴레이</td>
    <td><textarea class="obd-field-text" data-field="obd_pumprelay_char" placeholder="기능적인 작동 특성 입력"></textarea></td>
  </tr>
</table>

<!-- 1.2 오작동표시등 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">
  1.2. 오작동을 알려주는 오작동표시등에 관한 설명자료
</div>
<table class="obd-tbl">
  <tr>
    <td class="obd-lbl" style="width:8%; text-align:center; white-space:nowrap;">1.2.1.</td>
    <td><textarea class="obd-field-text" data-field="obd_1_2_1" placeholder="이륜자동차에 결함코드가 확인되면 계기판에 엔진 체크등이 점등됨.">이륜자동차에 결함코드가 확인되면 계기판에 엔진 체크등이 점등됨.</textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap; vertical-align:top; padding-top:6px;">1.2.2.</td>
    <td>
      <div style="font-size:8pt; padding:2px 0; color:#333; margin-bottom:4px;">오작동 표시등의 형태 및 위치 : 형태 및 위치를 알 수 있는 도면 또는 사진</div>
      <div class="obd-drop" id="obd-drop-1_2_2" onclick="document.getElementById('obd-file-1_2_2').click()">
        <div class="obd-drop-hint"><i class="fas fa-image"></i> 클릭하여 도면/사진 첨부</div>
        <input type="file" id="obd-file-1_2_2" accept="image/*" multiple data-drop-id="obd-drop-1_2_2">
        <input type="hidden" data-field="obd_1_2_2_img" value="\${E(v('obd_1_2_2_img'))}">
      </div>
      <div class="obd-img-list" id="obd-imgs-1_2_2"></div>
    </td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; vertical-align:top; padding-top:6px; white-space:nowrap;">1.2.3.</td>
    <td>
      <div style="font-size:8pt; padding:2px 0 4px; color:#333; font-weight:600;">제어, 자동표시기, 인디케이터 위치 및 식별 기호</div>
      <table class="obd-tbl" style="margin-bottom:4px;">
        <tr>
          <td class="obd-lbl" style="width:32%; white-space:nowrap;">1.2.3.1. 왼쪽 핸들 스위치의 제어 및 기호 도면</td>
          <td>
            <div class="obd-drop" id="obd-drop-1_2_3_1" onclick="document.getElementById('obd-file-1_2_3_1').click()">
              <div class="obd-drop-hint"><i class="fas fa-image"></i> 클릭하여 도면/사진 첨부</div>
              <input type="file" id="obd-file-1_2_3_1" accept="image/*" multiple data-drop-id="obd-drop-1_2_3_1">
              <input type="hidden" data-field="obd_1_2_3_1_img" value="\${E(v('obd_1_2_3_1_img'))}">
            </div>
            <div class="obd-img-list" id="obd-imgs-1_2_3_1"></div>
          </td>
        </tr>
        <tr>
          <td class="obd-lbl" style="white-space:nowrap;">1.2.3.2. 오른쪽 핸들 스위치의 제어 및 기호 도면</td>
          <td>
            <div class="obd-drop" id="obd-drop-1_2_3_2" onclick="document.getElementById('obd-file-1_2_3_2').click()">
              <div class="obd-drop-hint"><i class="fas fa-image"></i> 클릭하여 도면/사진 첨부</div>
              <input type="file" id="obd-file-1_2_3_2" accept="image/*" multiple data-drop-id="obd-drop-1_2_3_2">
              <input type="hidden" data-field="obd_1_2_3_2_img" value="\${E(v('obd_1_2_3_2_img'))}">
            </div>
            <div class="obd-img-list" id="obd-imgs-1_2_3_2"></div>
          </td>
        </tr>
        <tr>
          <td class="obd-lbl" style="white-space:nowrap;">1.2.3.3. 키박스 도면</td>
          <td>
            <div class="obd-drop" id="obd-drop-1_2_3_3" onclick="document.getElementById('obd-file-1_2_3_3').click()">
              <div class="obd-drop-hint"><i class="fas fa-image"></i> 클릭하여 도면/사진 첨부</div>
              <input type="file" id="obd-file-1_2_3_3" accept="image/*" multiple data-drop-id="obd-drop-1_2_3_3">
              <input type="hidden" data-field="obd_1_2_3_3_img" value="\${E(v('obd_1_2_3_3_img'))}">
            </div>
            <div class="obd-img-list" id="obd-imgs-1_2_3_3"></div>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>

<!-- 1.3 무단변경 금지 문구 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">
  1.3. 무단변경 및 배기가스제어컴퓨터의 수정을 금지하는 문구
</div>
<table class="obd-tbl">
  <tr>
    <td>
      <textarea class="obd-field-text" data-field="obd_1_3" placeholder="무단변경 및 배기가스제어컴퓨터의 수정을 금지하는 문구 입력" style="min-height:40px;"></textarea>
    </td>
  </tr>
</table>

<!-- 1.4 감시장치 기술적 설명 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">
  1.4. 감시장치의 기술적인 설명자료(일반적인 작동원리)
</div>
<table class="obd-tbl">
  <colgroup><col style="width:5%"><col style="width:55%"><col style="width:40%"></colgroup>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap;">1.4.2.</td>
    <td class="obd-lbl">촉매 감시장치</td>
    <td><textarea class="obd-field-text" data-field="obd_1_4_2" placeholder="내용 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap;">1.4.3.</td>
    <td class="obd-lbl">매연여과장치 감시장치</td>
    <td><textarea class="obd-field-text" data-field="obd_1_4_3" placeholder="내용 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap;">1.4.4.</td>
    <td class="obd-lbl">전자분사시스템 감시장치</td>
    <td><textarea class="obd-field-text" data-field="obd_1_4_4" placeholder="내용 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap;">1.4.5.</td>
    <td class="obd-lbl">배출가스자기진단장치에 의해 감시되는 부품들</td>
    <td><textarea class="obd-field-text" data-field="obd_1_4_5" placeholder="내용 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap;">1.4.6.</td>
    <td class="obd-lbl">오작동표시등 점등을 위한 기준(운전 싸이클의 횟수 및 통계적인 방법)</td>
    <td><textarea class="obd-field-text" data-field="obd_1_4_6" placeholder="내용 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap;">1.4.7.</td>
    <td class="obd-lbl">모든 배출가스자기진단장치 출력코드 목록과 사용된 양식(각각의 설명 포함)</td>
    <td><textarea class="obd-field-text" data-field="obd_1_4_7" placeholder="내용 입력"></textarea></td>
  </tr>
</table>

<!-- 1.5 기타 추가정보 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">
  1.5. 기타 추가정보
</div>
<table class="obd-tbl">
  <colgroup><col style="width:70%"><col style="width:30%"></colgroup>
  <tr>
    <th class="obd-th">시험 요구 사항 작동 기준(Ⅰ)형</th>
    <th class="obd-th">적합 여부</th>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400; font-size:8pt; line-height:1.6;">
      오작동 재현을 위한 부품 또는 오작동 모터사이클을 위한 전자 장비를 장착한 차량을 시험할 때, 오작동 판단 기준 이하에서 오작동 경고등이 점등되며 배출가스 자기진단장치는 적합한 것으로 판정됨
    </td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_1_5_1_pass"> 적합</label>
        <label><input type="checkbox" data-field="obd_1_5_1_fail"> 부적합</label>
      </div>
    </td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400; font-size:8pt; line-height:1.6;">
      배출가스 관련 부품 또는 배출가스와 관련되고 엔진 제어장치에 연결된 파워트레인 관련 부품의 전기적인 연속성을 감시하여야 함
    </td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_1_5_2_pass"> 적합</label>
        <label><input type="checkbox" data-field="obd_1_5_2_fail"> 부적합</label>
      </div>
    </td>
  </tr>
</table>

<!-- 1.5.1 ~ 1.5.3 -->
<table class="obd-tbl" style="margin-top:2px;">
  <tr>
    <td class="obd-lbl" style="width:5%; text-align:center; white-space:nowrap; vertical-align:top; padding-top:6px;">1.5.1.</td>
    <td class="obd-lbl" style="width:55%; vertical-align:top; padding-top:6px;">오작동 확인시험을 위한 준비싸이클의 형식과 회수에 대한 설명</td>
    <td><textarea class="obd-field-text" data-field="obd_1_5_1_desc" placeholder="내용 입력" style="min-height:36px;"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap; vertical-align:top; padding-top:6px;">1.5.2.</td>
    <td class="obd-lbl" style="vertical-align:top; padding-top:6px;">배출가스자기진단장치에 의해 감시되는 부품에 대한 확인시험을 위한 시험싸이클의 형식에 관한 설명</td>
    <td><textarea class="obd-field-text" data-field="obd_1_5_2_desc" placeholder="내용 입력" style="min-height:36px;"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap; vertical-align:top; padding-top:6px;">1.5.3.</td>
    <td class="obd-lbl" style="vertical-align:top; padding-top:6px;">배출가스자기진단장치에 의해 감시되는 구성부품들에 대한 2차 감시변수들의 목록, 오작동 확인 및 오작동표시등 점등을 위한 방법을 포함한 포괄적인 설명자료</td>
    <td><textarea class="obd-field-text" data-field="obd_1_5_3_desc" placeholder="내용 입력" style="min-height:36px;"></textarea></td>
  </tr>
</table>

<!-- 1.6 자체시험결과 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">
  1.6. 자체시험결과 및 기술적 설명자료
</div>
<div style="font-size:8pt; font-weight:600; padding:2px 2px 2px; color:#333;">1.6.1. 시험결과</div>
<table class="obd-tbl">
  <colgroup><col style="width:34%"><col style="width:33%"><col style="width:33%"></colgroup>
  <tr>
    <th class="obd-th">부품 점검</th>
    <th class="obd-th">MI 활성화 시기</th>
    <th class="obd-th">메모리에 저장된 오류코드 수정</th>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_part1" placeholder="부품 점검 내용"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_mi1" placeholder="MI 활성화 시기"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_err1" placeholder="오류코드 수정"></textarea></td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_part2" placeholder="부품 점검 내용"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_mi2" placeholder="MI 활성화 시기"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_err2" placeholder="오류코드 수정"></textarea></td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_part3" placeholder="부품 점검 내용"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_mi3" placeholder="MI 활성화 시기"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_err3" placeholder="오류코드 수정"></textarea></td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_part4" placeholder="부품 점검 내용"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_mi4" placeholder="MI 활성화 시기"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_err4" placeholder="오류코드 수정"></textarea></td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_part5" placeholder="부품 점검 내용"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_mi5" placeholder="MI 활성화 시기"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_err5" placeholder="오류코드 수정"></textarea></td>
  </tr>
</table>

<!-- 1.6.2 OBD 감시부품 테스트 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">1.6.2. OBD 감시부품의 테스트 및 진단</div>
<table class="obd-tbl">
  <colgroup><col style="width:24%"><col style="width:18%"><col style="width:12%"><col style="width:12%"><col style="width:18%"><col style="width:16%"></colgroup>
  <tr>
    <th class="obd-th">\${BL('th_item')}</th>
    <th class="obd-th">부품/하네스</th>
    <th class="obd-th">스위치</th>
    <th class="obd-th">시동</th>
    <th class="obd-th">규격</th>
    <th class="obd-th">오작동표시등 점등</th>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_item1" placeholder="항목"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_part1" placeholder="부품/하네스"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_sw1" placeholder="스위치"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_start1" placeholder="시동"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_spec1" placeholder="규격"></textarea></td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_1_6_2_mi1_y"> 유</label>
        <label><input type="checkbox" data-field="obd_1_6_2_mi1_n"> 무</label>
      </div>
    </td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_item2" placeholder="항목"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_part2" placeholder="부품/하네스"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_sw2" placeholder="스위치"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_start2" placeholder="시동"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_spec2" placeholder="규격"></textarea></td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_1_6_2_mi2_y"> 유</label>
        <label><input type="checkbox" data-field="obd_1_6_2_mi2_n"> 무</label>
      </div>
    </td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_item3" placeholder="항목"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_part3" placeholder="부품/하네스"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_sw3" placeholder="스위치"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_start3" placeholder="시동"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_spec3" placeholder="규격"></textarea></td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_1_6_2_mi3_y"> 유</label>
        <label><input type="checkbox" data-field="obd_1_6_2_mi3_n"> 무</label>
      </div>
    </td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_item4" placeholder="항목"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_part4" placeholder="부품/하네스"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_sw4" placeholder="스위치"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_start4" placeholder="시동"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_spec4" placeholder="규격"></textarea></td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_1_6_2_mi4_y"> 유</label>
        <label><input type="checkbox" data-field="obd_1_6_2_mi4_n"> 무</label>
      </div>
    </td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_item5" placeholder="항목"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_part5" placeholder="부품/하네스"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_sw5" placeholder="스위치"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_start5" placeholder="시동"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_spec5" placeholder="규격"></textarea></td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_1_6_2_mi5_y"> 유</label>
        <label><input type="checkbox" data-field="obd_1_6_2_mi5_n"> 무</label>
      </div>
    </td>
  </tr>
</table>

<!-- ══════════════════════════════════════════════════
     2. 동일차종 설명에 관한 서류
══════════════════════════════════════════════════ -->
<div class="obd-section-label" style="margin-top:12px;">2. 동일차종 설명에 관한 서류</div>
<div style="font-size:8pt; font-weight:600; padding:2px 2px 2px; color:#333;">2.1. 자동차 제원(자기진단동일차종 중 대표차종)</div>

<!-- 1. 일반 제원 -->
<div style="font-size:8pt; font-weight:600; padding:4px 2px 1px; color:#555;">1. 일반 제원</div>
<table class="obd-tbl">
  <colgroup><col style="width:14%"><col style="width:14%"><col style="width:14%"><col style="width:14%"><col style="width:14%"><col style="width:30%"></colgroup>
  <tr>
    <th class="obd-th">차명</th>
    <th class="obd-th">형식</th>
    <th class="obd-th">차종</th>
    <th class="obd-th">\${BL('sv_fuel')}</th>
    <th class="obd-th">\${BL('oo_trans_type')}</th>
    <th class="obd-th">총중량(공차중량, kg)</th>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_2_1_1_name" placeholder="차명"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_1_type" placeholder="형식"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_1_kind" placeholder="차종"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_1_fuel" placeholder="사용연료"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_1_trans" placeholder="변속기 종류"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_1_weight" placeholder="총중량(공차중량, kg)"></textarea></td>
  </tr>
</table>

<!-- 2. 엔진 제원 -->
<div style="font-size:8pt; font-weight:600; padding:4px 2px 1px; color:#555;">2. 엔진 제원</div>
<table class="obd-tbl">
  <colgroup><col><col><col><col><col><col></colgroup>
  <tr>
    <th class="obd-th">형식</th>
    <th class="obd-th">최고출력(ps/rpm)</th>
    <th class="obd-th">배기량(cc)</th>
    <th class="obd-th">연소형식</th>
    <th class="obd-th">연소사이클</th>
    <th class="obd-th">연료 공급형태</th>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_2_1_2_etype" placeholder="엔진형식"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_2_power" placeholder="최고출력"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_2_cc" placeholder="배기량(cc)"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_2_comb" placeholder="연소형식"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_2_cycle" placeholder="연소사이클"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_2_supply" placeholder="연료 공급형태"></textarea></td>
  </tr>
</table>

<!-- 3. 배출가스 제어장치 및 OBD 제원 -->
<div style="font-size:8pt; font-weight:600; padding:4px 2px 1px; color:#555;">3. 배출가스 제어장치 및 배출가스 자기진단장치 제원</div>
<table class="obd-tbl">
  <colgroup><col style="width:34%"><col style="width:22%"><col style="width:22%"><col style="width:22%"></colgroup>
  <tr>
    <th class="obd-th">촉매전환기 형식 (제작사)</th>
    <th class="obd-th">2차 공기 분사</th>
    <th class="obd-th" colspan="2">배출가스 재순환 장치</th>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_2_1_3_cat" placeholder="촉매전환기 형식 및 제작사"></textarea></td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_2_1_3_air_y"> 유</label>
        <label><input type="checkbox" data-field="obd_2_1_3_air_n"> 무</label>
      </div>
    </td>
    <td colspan="2">
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_2_1_3_egr_y"> 유</label>
        <label><input type="checkbox" data-field="obd_2_1_3_egr_n"> 무</label>
      </div>
    </td>
  </tr>
  <tr>
    <th class="obd-th">전자제어장치 형식 (제작사)</th>
    <th class="obd-th">산소센서 형식 (제작사)</th>
    <th class="obd-th" colspan="2">퍼지 제어밸브 형식 (제작사)</th>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_2_1_3_ecu" placeholder="전자제어장치 형식 및 제작사"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_3_o2s" placeholder="산소센서 형식 및 제작사"></textarea></td>
    <td colspan="2"><textarea class="obd-field-text" data-field="obd_2_1_3_purge" placeholder="퍼지 제어밸브 형식 및 제작사"></textarea></td>
  </tr>
</table>

<!-- 2.2 자기진단동일차종 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">2.2. 자기진단동일차종</div>
<table class="obd-tbl">
  <colgroup><col><col><col><col><col><col></colgroup>
  <tr>
    <th class="obd-th">차명(형식)</th>
    <th class="obd-th">엔진형식</th>
    <th class="obd-th">배기량(cc)</th>
    <th class="obd-th">최대출력</th>
    <th class="obd-th">변속기(단)</th>
    <th class="obd-th">총중량(공차중량, kg)</th>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_2_2_name1" placeholder="차명(형식)"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_2_etype1" placeholder="엔진형식"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_2_cc1" placeholder="배기량(cc)"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_2_power1" placeholder="최대출력"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_2_trans1" placeholder="변속기(단)"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_2_weight1" placeholder="총중량(공차중량)"></textarea></td>
  </tr>
</table>

<!-- 2.3 OBD 동일차종 설명 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">2.3. 배출가스자기진단장치 동일차종 설명</div>
<table class="obd-tbl">
  <colgroup><col style="width:22%"><col style="width:28%"><col style="width:50%"></colgroup>
  <tr>
    <th class="obd-th" colspan="2">\${BL('th_item')}</th>
    <th class="obd-th">배출가스자기진단장치 동일차종</th>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">차명(동일차명)</td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_name" placeholder="차명(동일차명)"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" rowspan="2">엔진</td>
    <td class="obd-lbl">연소과정<br><small style="font-weight:400;">(불꽃점화, 압축착화, 2행정, 4행정 등)</small></td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_combustion" placeholder="예) 불꽃점화, 4행정"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">연료공급 방법<br><small style="font-weight:400;">(기화기식, 연료분사식 등)</small></td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_fuel_supply" placeholder="예) 연료분사식(EFI)"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" rowspan="4">\${BL('sv_emission')}<br>제어장치</td>
    <td class="obd-lbl">촉매전환기의 형식<br><small style="font-weight:400;">(산화촉매, 삼원촉매, 가열식촉매 등)</small></td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_cat_type" placeholder="예) 삼원촉매"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">매연여과장치의 형식</td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_dpf" placeholder="해당없음 또는 형식 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">2차공기 분사의 유무</td>
    <td>
      <div class="obd-check-row">
        <label><input type="checkbox" data-field="obd_2_3_air2_y"> 유</label>
        <label><input type="checkbox" data-field="obd_2_3_air2_n"> 무</label>
      </div>
    </td>
  </tr>
  <tr>
    <td class="obd-lbl">배출가스 재순환장치의 유무</td>
    <td>
      <div class="obd-check-row">
        <label><input type="checkbox" data-field="obd_2_3_egr_y"> 유</label>
        <label><input type="checkbox" data-field="obd_2_3_egr_n"> 무</label>
      </div>
    </td>
  </tr>
  <tr>
    <td class="obd-lbl" rowspan="3">\${BL('sv_emission')}<br>자기진단장치의<br>구성 및 기능</td>
    <td class="obd-lbl">배출가스 자기진단장치의 작동방법</td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_obd_method" placeholder="작동방법 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">감시장치의 오작동 확인 방법</td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_obd_check" placeholder="오작동 확인 방법 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">오작동 표시방법</td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_obd_display" placeholder="오작동 표시방법 입력"></textarea></td>
  </tr>
</table>

<!-- ══════════════════════════════════════════════════
     3. 시험차량 선정에 관한 서류
══════════════════════════════════════════════════ -->
<div class="obd-section-label" style="margin-top:12px;">3. 시험차량 선정에 관한 서류</div>
<div style="font-size:8pt; font-weight:600; padding:2px 2px 2px; color:#333;">3.1. 배출가스자기진단장치 시험차량 선정근거</div>
<table class="obd-tbl">
  <colgroup><col style="width:25%"><col style="width:25%"><col style="width:50%"></colgroup>
  <tr>
    <th class="obd-th" colspan="2">\${BL('th_item')}</th>
    <th class="obd-th">배출가스자기진단장치 시험차량</th>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">모델명</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_model" placeholder="모델명"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">차대번호(엔진번호)</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_vin" placeholder="차대번호(엔진번호)"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">\${BL('nt_displacement')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_cc" placeholder="배기량(cc)"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">\${BL('nt_eng_type')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_etype" placeholder="엔진형식"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">변속기 형태</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_trans_type" placeholder="변속기 형태"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">변속절차</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_trans_proc" placeholder="변속절차"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">등가관성중량(kg)</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_inertia" placeholder="등가관성중량(kg)"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">종감속기</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_final_drive" placeholder="종감속기"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">N/V비, rpm/kph</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_nv" placeholder="N/V비, rpm/kph"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" rowspan="2">타이어</td>
    <td class="obd-lbl">전</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_tire_f" placeholder="전 타이어 규격"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">후</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_tire_r" placeholder="후 타이어 규격"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" rowspan="5">\${BL('sv_emission')}<br>제어장치</td>
    <td class="obd-lbl">촉매 전환기의 형식<br><small style="font-weight:400;">(산화촉매, 삼원촉매, 가열식 촉매 등)</small></td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_cat" placeholder="촉매 전환기의 형식"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">매연 여과장치의 형식</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_dpf" placeholder="해당없음 또는 형식 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">2차공기 분사의 유무</td>
    <td>
      <div class="obd-check-row">
        <label><input type="checkbox" data-field="obd_3_1_air2_y"> 유</label>
        <label><input type="checkbox" data-field="obd_3_1_air2_n"> 무</label>
      </div>
    </td>
  </tr>
  <tr>
    <td class="obd-lbl">배출가스 재 순환 장치의 유무</td>
    <td>
      <div class="obd-check-row">
        <label><input type="checkbox" data-field="obd_3_1_egr_y"> 유</label>
        <label><input type="checkbox" data-field="obd_3_1_egr_n"> 무</label>
      </div>
    </td>
  </tr>
  <tr>
    <td class="obd-lbl">증발가스 제어장치</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_evap" placeholder="증발가스 제어장치"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" rowspan="4">배출가스자기진단장치의<br>구성 및 기능</td>
    <td class="obd-lbl">배출가스 자기진단장치 작동방법</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_obd_method" placeholder="작동방법 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">감시장치의 오작동 확인방법</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_obd_check" placeholder="오작동 확인방법 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">오작동 표시 방법</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_obd_display" placeholder="오작동 표시방법 입력"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">\${BL('g_monitor_item')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_monitor" placeholder="감시항목 입력" style="min-height:40px;"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">\${BL('g_note')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_note" placeholder="비고" style="min-height:36px;"></textarea></td>
  </tr>
</table>

<!-- OBD TEST 사진 첨부 -->
<div style="font-size:8pt; font-weight:600; padding:8px 2px 4px; color:#333;">
  OBD TEST 사진 및 스캐너 사진 첨부 : 차량사진, 차대번호 사진, 엔진번호 사진 포함
</div>
<table class="obd-tbl">
  <tr>
    <th class="obd-th" style="width:33%;">차량 사진</th>
    <th class="obd-th" style="width:33%;">차대번호 사진</th>
    <th class="obd-th" style="width:34%;">엔진번호 사진</th>
  </tr>
  <tr>
    <td>
      <div class="obd-drop" id="obd-drop-car" onclick="document.getElementById('obd-file-car').click()">
        <div class="obd-drop-hint"><i class="fas fa-image"></i> 차량 사진 첨부</div>
        <input type="file" id="obd-file-car" accept="image/*" multiple data-drop-id="obd-drop-car">
        <input type="hidden" data-field="obd_car_img" value="\${E(v('obd_car_img'))}">
      </div>
      <div class="obd-img-list" id="obd-imgs-car"></div>
    </td>
    <td>
      <div class="obd-drop" id="obd-drop-vin" onclick="document.getElementById('obd-file-vin').click()">
        <div class="obd-drop-hint"><i class="fas fa-image"></i> 차대번호 사진 첨부</div>
        <input type="file" id="obd-file-vin" accept="image/*" multiple data-drop-id="obd-drop-vin">
        <input type="hidden" data-field="obd_vin_img" value="\${E(v('obd_vin_img'))}">
      </div>
      <div class="obd-img-list" id="obd-imgs-vin"></div>
    </td>
    <td>
      <div class="obd-drop" id="obd-drop-eng" onclick="document.getElementById('obd-file-eng').click()">
        <div class="obd-drop-hint"><i class="fas fa-image"></i> 엔진번호 사진 첨부</div>
        <input type="file" id="obd-file-eng" accept="image/*" multiple data-drop-id="obd-drop-eng">
        <input type="hidden" data-field="obd_eng_img" value="\${E(v('obd_eng_img'))}">
      </div>
      <div class="obd-img-list" id="obd-imgs-eng"></div>
    </td>
  </tr>
  <tr>
    <th class="obd-th" colspan="3">OBD 스캐너 사진</th>
  </tr>
  <tr>
    <td colspan="3">
      <div class="obd-drop" id="obd-drop-scanner" onclick="document.getElementById('obd-file-scanner').click()">
        <div class="obd-drop-hint"><i class="fas fa-image"></i> OBD 스캐너 사진 첨부 (복수 첨부 가능)</div>
        <input type="file" id="obd-file-scanner" accept="image/*" multiple data-drop-id="obd-drop-scanner">
        <input type="hidden" data-field="obd_scanner_img" value="\${E(v('obd_scanner_img'))}">
      </div>
      <div class="obd-img-list" id="obd-imgs-scanner"></div>
    </td>
  </tr>
</table>

<div id="qr-footer-wrap" style="margin-top:12px;"></div>
</div>
\`;


  if (formType==='emission_test') return \`
<style>
/* ══════ emission_test 전용 스타일 ══════ */
.en-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
  background:#fff;
  color:#111;
  border-radius:8px;
}
.en-doc-tag { font-size:8.5pt; font-weight:700; color:#444; margin:10px 0 4px; }
.en-main-title {
  font-size:13pt; font-weight:900; text-align:center;
  margin:4px 0 14px; letter-spacing:.03em; color:#111;
}
.en-tbl {
  width:100%; border-collapse:collapse;
  font-size:8.5pt; margin-bottom:0;
}
.en-tbl th, .en-tbl td {
  border:1px solid #888;
  padding:3px 5px;
  vertical-align:middle;
  color:#111;
}
.en-sec-th {
  background:#d6e4f7;
  font-weight:700; text-align:left;
  padding:4px 6px; font-size:8.5pt; color:#111;
}
.en-sub-th {
  background:#eef3fa;
  font-weight:700; text-align:left;
  padding:3px 6px; font-size:8.5pt; color:#111;
}
.en-th {
  background:#eef3fa;
  font-weight:600; text-align:center;
  font-size:8pt; color:#111;
}
.en-lbl {
  background:#f5f8ff;
  font-weight:600; color:#111;
  vertical-align:middle;
}
/* ── 복합 입력 필드 (텍스트 + 이미지) ── */
.en-field {
  display:flex; flex-direction:column; gap:4px;
  padding:3px 4px; box-sizing:border-box; width:100%;
}
.en-field-text {
  width:100%; font-size:8.5pt; font-family:inherit;
  border:none; background:transparent; padding:2px 0;
  box-sizing:border-box; resize:vertical; color:#111;
  min-height:36px; line-height:1.5;
}
.en-field-text::placeholder { color:#aaa; }
.en-field-text:focus { outline:none; border-bottom:1px dashed #4e90d8; }
/* 이미지 드롭존 */
.en-drop {
  border:1.5px dashed #b0c4de;
  border-radius:5px;
  background:#f8faff;
  padding:6px 8px;
  cursor:pointer;
  transition:border-color .15s, background .15s;
  position:relative;
  min-height:36px;
}
.en-drop:hover { border-color:#4e90d8; background:#eef3fa; }
.en-drop.drag-over { border-color:#2563eb; background:#dbeafe; }
.en-drop-hint {
  color:#aaa; font-size:7.5pt; text-align:center;
  pointer-events:none; user-select:none;
  display:flex; align-items:center; justify-content:center; gap:4px;
}
.en-drop input[type=file] { display:none; }
/* 이미지 미리보기 목록 */
.en-img-list {
  display:flex; flex-wrap:wrap; gap:6px; margin-top:4px;
}
.en-img-item {
  position:relative; display:inline-block;
}
.en-img-item img {
  max-width:140px; max-height:100px;
  border:1px solid #ccc; border-radius:3px;
  display:block; object-fit:contain; background:#fff;
}
.en-img-item-del {
  position:absolute; top:-6px; right:-6px;
  width:16px; height:16px; border-radius:50%;
  background:#ef4444; color:#fff; font-size:10px;
  display:flex; align-items:center; justify-content:center;
  cursor:pointer; line-height:1; border:none;
  box-shadow:0 1px 3px rgba(0,0,0,.3);
}
.en-img-item-del:hover { background:#dc2626; }
/* 헤더 셀의 텍스트 입력 (수입사 등 단순 1행 셀) */
.en-inp {
  border:none; background:transparent;
  width:100%; font-size:8.5pt;
  font-family:inherit; padding:0 2px;
  box-sizing:border-box; color:#111;
}
.en-inp::placeholder { color:#aaa; }
.en-inp:focus { outline:none; border-bottom:1px solid #4e90d8; }
@media print {
  /* ── 전체 래퍼 ── */
  .en-wrap { background:#fff !important; color:#000 !important; border-radius:0 !important; }

  /* ── 테이블 셀: 내용에 맞춰 높이 자동 확장, 잘림 방지 ── */
  .en-tbl { table-layout:fixed !important; width:100% !important; }
  .en-tbl th, .en-tbl td {
    border:1px solid #333 !important; color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important; overflow-wrap:break-word !important;
  }

  /* ── en-field: 인쇄 시 flex 유지, 높이 자동 ── */
  .en-field { height:auto !important; overflow:visible !important; display:flex !important; flex-direction:column !important; }

  /* ── textarea: 내용 전체 표시, 스크롤 없이 ── */
  textarea.en-field-text {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; min-height:0 !important; max-height:none !important;
    overflow:visible !important; resize:none !important;
    white-space:pre-wrap !important; word-break:break-word !important;
    overflow-wrap:break-word !important;
    display:block !important; box-sizing:border-box !important;
    -webkit-appearance:none !important; appearance:none !important;
    padding:2px 0 !important;
  }

  /* ── 단순 1행 input ── */
  .en-inp {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important;
  }

  /* ── hidden input 완전 숨김 ── */
  input[type=hidden] { display:none !important; }

  /* ── 이미지 드롭존: 테두리/배경 제거, 힌트/삭제버튼 숨김 ── */
  .en-drop {
    border:none !important; background:transparent !important;
    padding:0 !important; min-height:unset !important;
    height:auto !important; overflow:visible !important;
  }
  .en-drop-hint { display:none !important; }
  .en-img-item-del { display:none !important; }
  .en-img-list { gap:4px !important; margin-top:2px !important; }
  .en-img-item img {
    max-width:100% !important; max-height:none !important;
    page-break-inside:avoid;
  }
  /* 이미지가 없는 빈 en-drop은 공간 차지 안 함 */
  .en-drop:not(:has(img)) { display:none !important; }

  /* ── 섹션 헤더 배경색 유지 ── */
  .en-sec-th { background:#d6e4f7 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-sub-th { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-th     { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-lbl    { background:#f5f8ff !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }

  /* ── 페이지 분리 방지 (행 단위) ── */
  .en-tbl tr { page-break-inside:avoid; }
}

.em-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
  background:#fff;
  color:#111;
  border-radius:8px;
}
.em-doc-tag  { font-size:8.5pt; font-weight:700; color:#444; margin:10px 0 4px; }
.em-main-title {
  font-size:13pt; font-weight:900; text-align:center;
  margin:4px 0 14px; letter-spacing:.03em; color:#111;
}
.em-tbl {
  width:100%; border-collapse:collapse;
  font-size:8.5pt; margin-bottom:0;
}
.em-tbl th, .em-tbl td {
  border:1px solid #888;
  padding:3px 5px;
  vertical-align:middle;
  color:#111;
}
.em-sec-th {
  background:#d6e4f7;
  font-weight:700;
  text-align:left;
  padding:3px 6px;
  font-size:8.5pt;
  color:#111;
}
.em-th {
  background:#eef3fa;
  font-weight:600;
  white-space:nowrap;
  font-size:8pt;
  color:#111;
}
.em-inp {
  border:none;
  background:transparent;
  width:100%;
  font-size:8.5pt;
  font-family:inherit;
  padding:0 2px;
  box-sizing:border-box;
  color:#111;
}
.em-inp::placeholder { color:#aaa; }
.em-inp:focus { outline:none; border-bottom:1px solid #4e90d8; }
.em-chk { display:flex; align-items:center; gap:3px; font-size:8.5pt; color:#111; }
/* 첨부 섹션 (증발가스와 동일 패턴) */
.em-attach-section { margin-top:14px; }
.em-attach-title { font-size:9pt; font-weight:700; margin-bottom:6px; color:#222; }
.em-attach-note { font-size:8pt; color:#666; margin-bottom:8px; }
.em-attach-drop {
  border:2px dashed #bbb; border-radius:8px;
  padding:16px; text-align:center; cursor:pointer;
  transition:border-color .2s, background .2s;
  display:flex; flex-direction:column; align-items:center; gap:4px;
  color:#555; background:#fafafa;
}
.em-attach-drop:hover { border-color:#4e90d8; background:rgba(79,142,247,.04); }
.em-attach-drop input[type=file] { display:none; }
.em-attach-list { margin-top:8px; display:flex; flex-direction:column; gap:4px; }
.em-attach-item {
  display:flex; align-items:center; gap:8px;
  padding:4px 8px; border-radius:4px;
  background:#f0f4fa; font-size:8.5pt;
}
.em-attach-item-name { flex:1; color:#111; word-break:break-all; }
.em-attach-item-size { color:#666; white-space:nowrap; font-size:8pt; }
.em-attach-item-del { color:#ef4444; cursor:pointer; padding:1px 5px; border-radius:3px; font-size:10pt; line-height:1; }
.em-attach-item-del:hover { background:rgba(239,68,68,.12); }
/* 첨부문서: 인쇄 미리보기 기능 제거됨 (업로드/다운로드 전용) */

@media print {
  .em-wrap {
    background:#fff !important;
    color:#000 !important;
    border-radius:0 !important;
  }
  .em-tbl th, .em-tbl td {
    border:1px solid #333 !important;
    color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }
  .em-inp {
    border:none !important;
    background:transparent !important;
    height:auto !important;
    overflow:visible !important;
    font-size:8.5pt !important;
    font-family:'맑은 고딕','Malgun Gothic',sans-serif !important;
    padding:0 2px !important;
    color:#000 !important;
  }
  .em-sec-th {
    background:#d6e4f7 !important;
    color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }
  .em-th {
    background:#eef3fa !important;
    color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }
  .em-chk { color:#000 !important; }
  /* 첨부문서 영역 인쇄 시 완전 숨김 */
  .em-attach-section { display:none !important; }
}
</style>

<div class="em-wrap">

  <!-- ── 최상단 헤더 (수입사/인증연도/배기량/동일차종기호) ── -->
  <!-- PDF 실측: 4등분 25.2%/24.7%/24.8%/25.2% -->
  <table class="em-tbl" style="margin-bottom:12px; table-layout:fixed;">
    <colgroup>
      <col style="width:35%;"><col style="width:12%;"><col style="width:13%;"><col style="width:40%;">
    </colgroup>
    <thead>
      <tr>
        <th class="em-th">\${BL('importer')}</th>
        <th class="em-th">\${BL('cert_year')}</th>
        <th class="em-th">\${BL('displacement')}</th>
        <th class="em-th">\${BL('family_code')}</th>
      </tr>
    </thead>
    <tbody>
      <tr style="height:26px;">
        <td><input data-field="em_importer"  class="em-inp" type="text" placeholder="\${BL('ph_importer')}" value="\${E(v('em_importer'))}"></td>
        <td><input data-field="em_cert_year" class="em-inp" type="text" placeholder="\${BL('ph_cert_year')}" value="\${E(v('em_cert_year'))}"></td>
        <td><input data-field="em_disp"      class="em-inp" type="text" placeholder="\${BL('ph_displacement')}" value="\${E(v('em_disp'))}"></td>
        <td><input data-field="em_fam_code"  class="em-inp" type="text" placeholder="\${BL('ph_family_code')}" value="\${E(v('em_fam_code'))}"></td>
      </tr>
    </tbody>
  </table>

  <div class="em-doc-tag">[별지 제18의2호 서식]</div>
  <div class="em-main-title">\${BL('em_main_title')}</div>

  <!-- ══════════════════════════════════════════ -->
  <!-- 1. 일반 사항                               -->
  <!-- ══════════════════════════════════════════ -->
  <!-- PDF 실측: y=181~196 섹션헤더              -->
  <!-- y=196~210: 3열 [33.5%|31.5%|35.1%]       -->
  <!-- y=210~225: 시험구분 10셀 복합              -->
  <!-- y=225~240: 시험번호/운전자/장비작동자/검사책임자 8셀 -->
  <table class="em-tbl">
    <tbody>
      <tr>
        <th class="em-sec-th" colspan="8">1. 일반 사항</th>
      </tr>
      <!-- 인증차명 / 시험차명 / 시험일시 (3열) -->
      <tr>
        <td class="em-th" colspan="3" style="width:33.5%;">\${BL('em_cert_name')}(\${BL('ev_same_type')}) :
          <input data-field="em_cert_model" class="em-inp" type="text" value="\${E(v('em_cert_model'))}">
        </td>
        <td class="em-th" colspan="2" style="width:31.5%;">\${BL('ev_test_name')} :
          <input data-field="em_test_model" class="em-inp" type="text" value="\${E(v('em_test_model'))}">
        </td>
        <td class="em-th" colspan="3" style="width:35.0%;">\${BL('ev_test_date')} :
          <input data-field="em_test_date" class="em-inp" type="text" placeholder="YYYY-MM-DD" value="\${E(v('em_test_date'))}">
        </td>
      </tr>
      <!-- 시험구분 -->
      <tr>
        <td class="em-th" colspan="1">\${BL('em_test_div')}</td>
        <td colspan="2" style="text-align:center;">
          <label class="em-chk"><input type="checkbox" data-field="em_type_dur" \${v('em_type_dur')?'checked':''}>&nbsp;내구주행시험</label>
        </td>
        <td colspan="2" style="text-align:center;">
          <label class="em-chk"><input type="checkbox" data-field="em_type_emis" \${v('em_type_emis')?'checked':''}>&nbsp;배출가스 시험</label>
        </td>
        <td colspan="2" style="text-align:center;">
          <label class="em-chk"><input type="checkbox" data-field="em_type_insp" \${v('em_type_insp')?'checked':''}>&nbsp;정기검사</label>
        </td>
        <td colspan="1" style="text-align:center;">
          <label class="em-chk"><input type="checkbox" data-field="em_type_etc" \${v('em_type_etc')?'checked':''}>&nbsp;기타</label>
        </td>
      </tr>
      <!-- 시험번호 / 운전자 / 장비작동자 / 검사책임자 -->
      <tr>
        <td class="em-th" colspan="1">\${BL('em_test_no')}</td>
        <td colspan="1"><input data-field="em_test_no"   class="em-inp" type="text" value="\${E(v('em_test_no'))}"></td>
        <td class="em-th" colspan="1">\${BL('em_driver')}</td>
        <td colspan="1"><input data-field="em_driver"    class="em-inp" type="text" value="\${E(v('em_driver'))}"></td>
        <td class="em-th" colspan="1">\${BL('em_operator')}</td>
        <td colspan="1"><input data-field="em_operator"  class="em-inp" type="text" value="\${E(v('em_operator'))}"></td>
        <td class="em-th" colspan="1">\${BL('em_inspector')}</td>
        <td colspan="1"><input data-field="em_inspector" class="em-inp" type="text" value="\${E(v('em_inspector'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════ -->
  <!-- 2. 시험자동차 제원                         -->
  <!-- PDF 실측 y=254~298                         -->
  <!-- y=254~269: [27.8%|14.5%|23.3%|18.2%|16.2%] (5셀) -->
  <!-- y=269~284: 좌측 22.3%는 rowspan, 나머지 3열  -->
  <!-- y=284~298: 우측 42.3%/23.3%/34.4%          -->
  <!-- ══════════════════════════════════════════ -->
  <table class="em-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <tbody>
      <tr>
        <th class="em-sec-th" colspan="5">2. 시험자동차 제원</th>
      </tr>
      <!-- 행1: 차대번호/제작일/변속기형식/적산거리/공차중량 -->
      <!-- PDF: 27.8%|14.5%|23.3%|18.2%|16.2% -->
      <tr>
        <td style="width:27.8%;">
          <span class="em-th">\${BL('ev_vin')}:</span>
          <input data-field="em_vin"        class="em-inp" type="text" value="\${E(v('em_vin'))}">
        </td>
        <td style="width:14.5%;">
          <span class="em-th">\${BL('em_mfg_date')}:</span>
          <input data-field="em_mfg_date"   class="em-inp" type="text" value="\${E(v('em_mfg_date'))}">
        </td>
        <td style="width:23.3%;">
          <span class="em-th">\${BL('em_trans_type')}:</span>
          <input data-field="em_trans"      class="em-inp" type="text" value="\${E(v('em_trans'))}">
        </td>
        <td style="width:18.2%;">
          <span class="em-th">\${BL('ev_odo')}:</span>
          <input data-field="em_mileage"    class="em-inp" type="text" placeholder="km" value="\${E(v('em_mileage'))}">
        </td>
        <td style="width:16.2%;">
          <span class="em-th">\${BL('em_curb_weight')}:</span>
          <input data-field="em_curb_wt"    class="em-inp" type="text" placeholder="kg" value="\${E(v('em_curb_wt'))}">
        </td>
      </tr>
      <!-- 행2: 제작사(rowspan=1)/차량총중량/관성중량등급/연료탱크 용량 및 위치 -->
      <!-- PDF y=269: 22.3% | 20.0% | 23.3% | 34.4% -->
      <tr>
        <td style="width:27.8%;">
          <span class="em-th">\${BL('em_maker')}:</span>
          <input data-field="em_maker"      class="em-inp" type="text" value="\${E(v('em_maker'))}">
        </td>
        <td style="width:14.5%;">
          <span class="em-th">\${BL('em_gvw')}:</span>
          <input data-field="em_gvw"        class="em-inp" type="text" placeholder="kg" value="\${E(v('em_gvw'))}">
        </td>
        <td style="width:23.3%;">
          <span class="em-th">\${BL('em_inertia')}:</span>
          <input data-field="em_inertia"    class="em-inp" type="text" value="\${E(v('em_inertia'))}">
        </td>
        <td colspan="2" style="width:34.4%;">
          <span class="em-th">\${BL('em_tank_loc')}:</span>
          <input data-field="em_tank"       class="em-inp" type="text" value="\${E(v('em_tank'))}">
        </td>
      </tr>
      <!-- 행3: 도로부하력/코스트다운시간/촉매부착여부 -->
      <!-- PDF y=284: 42.3% | 23.3% | 34.4% (내부수직선 259.8, 373.7) -->
      <tr>
        <td colspan="2" style="width:42.3%;">
          <span class="em-th">\${BL('em_road_load')}:</span>
          <input data-field="em_road_load"  class="em-inp" type="text" value="\${E(v('em_road_load'))}">
        </td>
        <td style="width:23.3%;">
          <span class="em-th">\${BL('em_coastdown')}:</span>
          <input data-field="em_coastdown"  class="em-inp" type="text" value="\${E(v('em_coastdown'))}">
        </td>
        <td colspan="2" style="width:34.4%;">
          <span class="em-th">\${BL('em_catalyst_yn')}:</span>
          <input data-field="em_catalyst"   class="em-inp" type="text" value="\${E(v('em_catalyst'))}">
        </td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════ -->
  <!-- 3. 시험차 엔진제원                         -->
  <!-- PDF 실측 y=312~342                         -->
  <!-- 5열: 18.2%|22.0%|16.3%|26.8%|16.6%        -->
  <!-- 행1: 엔진번호/엔진방식/최고출력/총배기량/실린더수 -->
  <!-- 행2: 공회전/냉각방식/연소사이클/시험연료    -->
  <!-- ══════════════════════════════════════════ -->
  <table class="em-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:18.2%;"><col style="width:22.0%;"><col style="width:16.3%;"><col style="width:26.8%;"><col style="width:16.6%;">
    </colgroup>
    <tbody>
      <tr>
        <th class="em-sec-th" colspan="5">3. 시험차 엔진제원</th>
      </tr>
      <tr>
        <td><span class="em-th">\${BL('em_eng_no')}:</span><input data-field="em_eng_no"    class="em-inp" type="text" value="\${E(v('em_eng_no'))}"></td>
        <td><span class="em-th">\${BL('em_eng_type')}:</span><input data-field="em_eng_type"  class="em-inp" type="text" value="\${E(v('em_eng_type'))}"></td>
        <td><span class="em-th">\${BL('em_max_power')}:</span><input data-field="em_max_pow"   class="em-inp" type="text" value="\${E(v('em_max_pow'))}"></td>
        <td><span class="em-th">\${BL('em_total_cc')}:</span><input data-field="em_total_cc"  class="em-inp" type="text" placeholder="cc" value="\${E(v('em_total_cc'))}"></td>
        <td><span class="em-th">\${BL('em_cyl')}:</span><input data-field="em_cyl"       class="em-inp" type="text" value="\${E(v('em_cyl'))}"></td>
      </tr>
      <tr>
        <td><span class="em-th">\${BL('em_idle')}:</span><input data-field="em_idle"       class="em-inp" type="text" placeholder="rpm" value="\${E(v('em_idle'))}"></td>
        <td><span class="em-th">\${BL('em_cooling')}:</span><input data-field="em_cooling"   class="em-inp" type="text" value="\${E(v('em_cooling'))}"></td>
        <td><span class="em-th">\${BL('em_cycle')}:</span><input data-field="em_cycle"    class="em-inp" type="text" value="\${E(v('em_cycle'))}"></td>
        <td colspan="2"><span class="em-th">\${BL('em_test_fuel')}:</span><input data-field="em_fuel"     class="em-inp" type="text" value="\${E(v('em_fuel'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════ -->
  <!-- 4. 시험장비                                -->
  <!-- PDF 실측 y=356~430 (명칭행 포함)           -->
  <!-- y=357~430: 6열 18.2%|11.2%|17.3%|16.9%|16.9%|19.4% -->
  <!-- 헤더: 명칭|형식|제작사|모델|형식승인일자|설치장소 -->
  <!-- 데이터: 다이나모메타/분석장치/CVS장치/냉각팬 -->
  <!-- ══════════════════════════════════════════ -->
  <table class="em-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:18.2%;"><col style="width:11.2%;"><col style="width:17.3%;"><col style="width:16.9%;"><col style="width:16.9%;"><col style="width:19.4%;">
    </colgroup>
    <tbody>
      <tr>
        <th class="em-sec-th" colspan="6">4. 시험장비</th>
      </tr>
      <tr>
        <th class="em-th" style="text-align:center;">\${BL('em_col_name')}</th>
        <th class="em-th" style="text-align:center;">\${BL('em_col_type')}</th>
        <th class="em-th" style="text-align:center;">\${BL('g_maker')}</th>
        <th class="em-th" style="text-align:center;">\${BL('em_col_model')}</th>
        <th class="em-th" style="text-align:center;">\${BL('em_col_approval')}</th>
        <th class="em-th" style="text-align:center;">\${BL('em_col_location')}</th>
      </tr>
      <tr>
        <td class="em-th">\${BL('em_dynamo')}</td>
        <td><input data-field="em_dyn_form"   class="em-inp" type="text" value="\${E(v('em_dyn_form'))}"></td>
        <td><input data-field="em_dyn_maker"  class="em-inp" type="text" value="\${E(v('em_dyn_maker'))}"></td>
        <td><input data-field="em_dyn_model"  class="em-inp" type="text" value="\${E(v('em_dyn_model'))}"></td>
        <td><input data-field="em_dyn_appr"   class="em-inp" type="text" value="\${E(v('em_dyn_appr'))}"></td>
        <td><input data-field="em_dyn_loc"    class="em-inp" type="text" value="\${E(v('em_dyn_loc'))}"></td>
      </tr>
      <tr>
        <td class="em-th">\${BL('em_analyzer')}</td>
        <td><input data-field="em_ana_form"   class="em-inp" type="text" value="\${E(v('em_ana_form'))}"></td>
        <td><input data-field="em_ana_maker"  class="em-inp" type="text" value="\${E(v('em_ana_maker'))}"></td>
        <td><input data-field="em_ana_model"  class="em-inp" type="text" value="\${E(v('em_ana_model'))}"></td>
        <td><input data-field="em_ana_appr"   class="em-inp" type="text" value="\${E(v('em_ana_appr'))}"></td>
        <td><input data-field="em_ana_loc"    class="em-inp" type="text" value="\${E(v('em_ana_loc'))}"></td>
      </tr>
      <tr>
        <td class="em-th">CVS 장치</td>
        <td><input data-field="em_cvs_form"   class="em-inp" type="text" value="\${E(v('em_cvs_form'))}"></td>
        <td><input data-field="em_cvs_maker"  class="em-inp" type="text" value="\${E(v('em_cvs_maker'))}"></td>
        <td><input data-field="em_cvs_model"  class="em-inp" type="text" value="\${E(v('em_cvs_model'))}"></td>
        <td><input data-field="em_cvs_appr"   class="em-inp" type="text" value="\${E(v('em_cvs_appr'))}"></td>
        <td><input data-field="em_cvs_loc"    class="em-inp" type="text" value="\${E(v('em_cvs_loc'))}"></td>
      </tr>
      <tr>
        <td class="em-th">\${BL('em_cooling_fan')}</td>
        <td><input data-field="em_fan_form"   class="em-inp" type="text" value="\${E(v('em_fan_form'))}"></td>
        <td><input data-field="em_fan_maker"  class="em-inp" type="text" value="\${E(v('em_fan_maker'))}"></td>
        <td><input data-field="em_fan_model"  class="em-inp" type="text" value="\${E(v('em_fan_model'))}"></td>
        <td><input data-field="em_fan_appr"   class="em-inp" type="text" value="\${E(v('em_fan_appr'))}"></td>
        <td><input data-field="em_fan_loc"    class="em-inp" type="text" value="\${E(v('em_fan_loc'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════ -->
  <!-- 5. CVS 운전시험상태                        -->
  <!-- PDF 실측 y=430~564                         -->
  <!-- y=430~563 (냉각팬 이후): 5열               -->
  <!-- 구분 | 1BAG | 2BAG | 3BAG 헤더             -->
  <!-- 18.2% | 28.6% | 16.9% | 16.9% | 19.4%    -->
  <!-- 단, 첫 열은 "5.CVS 운전시험상태" 라벨+구분  -->
  <!-- ══════════════════════════════════════════ -->
  <!-- CVS: "구분" 칸을 위 4.시험장비의 "명칭+형식" 두 열 너비(18.2+11.2=29.4%)로 확장 -->
  <!-- 세로선 정렬: 29.4% | 17.3% | 16.9% | 16.9% | 19.4% (합계≈99.9%) -->
  <table class="em-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:29.4%;"><col style="width:17.3%;"><col style="width:16.9%;"><col style="width:16.9%;"><col style="width:19.4%;">
    </colgroup>
    <tbody>
      <tr>
        <th class="em-sec-th" colspan="5">5. CVS 운전시험상태</th>
      </tr>
      <tr>
        <th class="em-th" style="text-align:center;">\${BL('ev_col_div')}</th>
        <th class="em-th" style="text-align:center;">1BAG</th>
        <th class="em-th" style="text-align:center;">2BAG</th>
        <th class="em-th" style="text-align:center;">3BAG</th>
        <th class="em-th" style="text-align:center;">\${BL('g_note')}</th>
      </tr>
      <tr>
        <td class="em-th">\${BL('em_pressure')} mmHg</td>
        <td><input data-field="em_cvs_press1" class="em-inp" type="text" value="\${E(v('em_cvs_press1'))}"></td>
        <td><input data-field="em_cvs_press2" class="em-inp" type="text" value="\${E(v('em_cvs_press2'))}"></td>
        <td><input data-field="em_cvs_press3" class="em-inp" type="text" value="\${E(v('em_cvs_press3'))}"></td>
        <td><input data-field="em_cvs_press_note" class="em-inp" type="text" value="\${E(v('em_cvs_press_note'))}"></td>
      </tr>
      <tr>
        <td class="em-th">\${BL('em_wet_temp')}</td>
        <td><input data-field="em_cvs_wet1"   class="em-inp" type="text" value="\${E(v('em_cvs_wet1'))}"></td>
        <td><input data-field="em_cvs_wet2"   class="em-inp" type="text" value="\${E(v('em_cvs_wet2'))}"></td>
        <td><input data-field="em_cvs_wet3"   class="em-inp" type="text" value="\${E(v('em_cvs_wet3'))}"></td>
        <td><input data-field="em_cvs_wet_note" class="em-inp" type="text" value="\${E(v('em_cvs_wet_note'))}"></td>
      </tr>
      <tr>
        <td class="em-th">\${BL('em_dry_temp')}</td>
        <td><input data-field="em_cvs_dry1"   class="em-inp" type="text" value="\${E(v('em_cvs_dry1'))}"></td>
        <td><input data-field="em_cvs_dry2"   class="em-inp" type="text" value="\${E(v('em_cvs_dry2'))}"></td>
        <td><input data-field="em_cvs_dry3"   class="em-inp" type="text" value="\${E(v('em_cvs_dry3'))}"></td>
        <td><input data-field="em_cvs_dry_note" class="em-inp" type="text" value="\${E(v('em_cvs_dry_note'))}"></td>
      </tr>
      <tr>
        <td class="em-th">\${BL('em_rh')}</td>
        <td><input data-field="em_cvs_rh1"    class="em-inp" type="text" value="\${E(v('em_cvs_rh1'))}"></td>
        <td><input data-field="em_cvs_rh2"    class="em-inp" type="text" value="\${E(v('em_cvs_rh2'))}"></td>
        <td><input data-field="em_cvs_rh3"    class="em-inp" type="text" value="\${E(v('em_cvs_rh3'))}"></td>
        <td><input data-field="em_cvs_rh_note" class="em-inp" type="text" value="\${E(v('em_cvs_rh_note'))}"></td>
      </tr>
      <tr>
        <td class="em-th">\${BL('em_abs_hum')}</td>
        <td><input data-field="em_cvs_ha1"    class="em-inp" type="text" value="\${E(v('em_cvs_ha1'))}"></td>
        <td><input data-field="em_cvs_ha2"    class="em-inp" type="text" value="\${E(v('em_cvs_ha2'))}"></td>
        <td><input data-field="em_cvs_ha3"    class="em-inp" type="text" value="\${E(v('em_cvs_ha3'))}"></td>
        <td><input data-field="em_cvs_ha_note" class="em-inp" type="text" value="\${E(v('em_cvs_ha_note'))}"></td>
      </tr>
      <tr>
        <td class="em-th">\${BL('em_emission_vol')} ㎥</td>
        <td><input data-field="em_cvs_vol1"   class="em-inp" type="text" value="\${E(v('em_cvs_vol1'))}"></td>
        <td><input data-field="em_cvs_vol2"   class="em-inp" type="text" value="\${E(v('em_cvs_vol2'))}"></td>
        <td><input data-field="em_cvs_vol3"   class="em-inp" type="text" value="\${E(v('em_cvs_vol3'))}"></td>
        <td><input data-field="em_cvs_vol_note" class="em-inp" type="text" value="\${E(v('em_cvs_vol_note'))}"></td>
      </tr>
      <tr>
        <td class="em-th">DF</td>
        <td><input data-field="em_cvs_df1"    class="em-inp" type="text" value="\${E(v('em_cvs_df1'))}"></td>
        <td><input data-field="em_cvs_df2"    class="em-inp" type="text" value="\${E(v('em_cvs_df2'))}"></td>
        <td><input data-field="em_cvs_df3"    class="em-inp" type="text" value="\${E(v('em_cvs_df3'))}"></td>
        <td><input data-field="em_cvs_df_note" class="em-inp" type="text" value="\${E(v('em_cvs_df_note'))}"></td>
      </tr>
      <tr>
        <td class="em-th">\${BL('em_drive_dist')}</td>
        <td><input data-field="em_cvs_dist1"  class="em-inp" type="text" value="\${E(v('em_cvs_dist1'))}"></td>
        <td><input data-field="em_cvs_dist2"  class="em-inp" type="text" value="\${E(v('em_cvs_dist2'))}"></td>
        <td><input data-field="em_cvs_dist3"  class="em-inp" type="text" value="\${E(v('em_cvs_dist3'))}"></td>
        <td><input data-field="em_cvs_dist_note" class="em-inp" type="text" value="\${E(v('em_cvs_dist_note'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════ -->
  <!-- 6. 시험결과                                        -->
  <!-- PDF 실측 y=577~755                                 -->
  <!-- ── 상단헤더: 항목|PHASE1|PHASE2|PHASE3            -->
  <!--    4열: 11.8%|29.3%|29.2%|29.7%                  -->
  <!-- ── 중단헤더: 항목|배출질량×2|배출질량×2|배출질량×2 -->
  <!--    7열: 11.8%|14.6%|14.6%|14.6%|14.6%|14.6%|15.1% -->
  <!-- ── 데이터: HC/CO/NOx/CO2/연비                      -->
  <!-- ── 하단: 종합결과표                                 -->
  <!-- ══════════════════════════════════════════════════ -->
  <table class="em-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:11.8%;"><!-- 항목 -->
      <col style="width:14.6%;"><!-- PHASE1 배출질량 -->
      <col style="width:14.6%;"><!-- PHASE1 g/km -->
      <col style="width:14.6%;"><!-- PHASE2 배출질량 -->
      <col style="width:14.6%;"><!-- PHASE2 g/km -->
      <col style="width:14.6%;"><!-- PHASE3 배출질량 -->
      <col style="width:15.1%;"><!-- PHASE3 g/km -->
    </colgroup>
    <thead>
      <tr>
        <th class="em-sec-th" colspan="7">6. 시험결과</th>
      </tr>
      <!-- 복합 헤더 1행: PHASE 1/2/3 -->
      <tr>
        <th class="em-th" rowspan="2" style="text-align:center; vertical-align:middle;">\${BL('em_col_item')}</th>
        <th class="em-th" colspan="2" style="text-align:center;">PHASE 1</th>
        <th class="em-th" colspan="2" style="text-align:center;">PHASE 2</th>
        <th class="em-th" colspan="2" style="text-align:center;">PHASE 3</th>
      </tr>
      <!-- 복합 헤더 2행: 배출질량/g/km -->
      <tr>
        <th class="em-th" style="text-align:center; font-size:7.5pt;">\${BL('em_mass')}</th>
        <th class="em-th" style="text-align:center;">g/km</th>
        <th class="em-th" style="text-align:center; font-size:7.5pt;">\${BL('em_mass')}</th>
        <th class="em-th" style="text-align:center;">g/km</th>
        <th class="em-th" style="text-align:center; font-size:7.5pt;">\${BL('em_mass')}</th>
        <th class="em-th" style="text-align:center;">g/km</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td class="em-th" style="text-align:center;">HC</td>
        <td><input data-field="em_hc_p1_mass" class="em-inp" type="text" value="\${E(v('em_hc_p1_mass'))}"></td>
        <td><input data-field="em_hc_p1_gkm"  class="em-inp" type="text" value="\${E(v('em_hc_p1_gkm'))}"></td>
        <td><input data-field="em_hc_p2_mass" class="em-inp" type="text" value="\${E(v('em_hc_p2_mass'))}"></td>
        <td><input data-field="em_hc_p2_gkm"  class="em-inp" type="text" value="\${E(v('em_hc_p2_gkm'))}"></td>
        <td><input data-field="em_hc_p3_mass" class="em-inp" type="text" value="\${E(v('em_hc_p3_mass'))}"></td>
        <td><input data-field="em_hc_p3_gkm"  class="em-inp" type="text" value="\${E(v('em_hc_p3_gkm'))}"></td>
      </tr>
      <tr>
        <td class="em-th" style="text-align:center;">CO</td>
        <td><input data-field="em_co_p1_mass" class="em-inp" type="text" value="\${E(v('em_co_p1_mass'))}"></td>
        <td><input data-field="em_co_p1_gkm"  class="em-inp" type="text" value="\${E(v('em_co_p1_gkm'))}"></td>
        <td><input data-field="em_co_p2_mass" class="em-inp" type="text" value="\${E(v('em_co_p2_mass'))}"></td>
        <td><input data-field="em_co_p2_gkm"  class="em-inp" type="text" value="\${E(v('em_co_p2_gkm'))}"></td>
        <td><input data-field="em_co_p3_mass" class="em-inp" type="text" value="\${E(v('em_co_p3_mass'))}"></td>
        <td><input data-field="em_co_p3_gkm"  class="em-inp" type="text" value="\${E(v('em_co_p3_gkm'))}"></td>
      </tr>
      <tr>
        <td class="em-th" style="text-align:center;">NOx</td>
        <td><input data-field="em_nox_p1_mass" class="em-inp" type="text" value="\${E(v('em_nox_p1_mass'))}"></td>
        <td><input data-field="em_nox_p1_gkm"  class="em-inp" type="text" value="\${E(v('em_nox_p1_gkm'))}"></td>
        <td><input data-field="em_nox_p2_mass" class="em-inp" type="text" value="\${E(v('em_nox_p2_mass'))}"></td>
        <td><input data-field="em_nox_p2_gkm"  class="em-inp" type="text" value="\${E(v('em_nox_p2_gkm'))}"></td>
        <td><input data-field="em_nox_p3_mass" class="em-inp" type="text" value="\${E(v('em_nox_p3_mass'))}"></td>
        <td><input data-field="em_nox_p3_gkm"  class="em-inp" type="text" value="\${E(v('em_nox_p3_gkm'))}"></td>
      </tr>
      <tr>
        <td class="em-th" style="text-align:center;">CO₂</td>
        <td><input data-field="em_co2_p1_mass" class="em-inp" type="text" value="\${E(v('em_co2_p1_mass'))}"></td>
        <td><input data-field="em_co2_p1_gkm"  class="em-inp" type="text" value="\${E(v('em_co2_p1_gkm'))}"></td>
        <td><input data-field="em_co2_p2_mass" class="em-inp" type="text" value="\${E(v('em_co2_p2_mass'))}"></td>
        <td><input data-field="em_co2_p2_gkm"  class="em-inp" type="text" value="\${E(v('em_co2_p2_gkm'))}"></td>
        <td><input data-field="em_co2_p3_mass" class="em-inp" type="text" value="\${E(v('em_co2_p3_mass'))}"></td>
        <td><input data-field="em_co2_p3_gkm"  class="em-inp" type="text" value="\${E(v('em_co2_p3_gkm'))}"></td>
      </tr>
      <tr>
        <td class="em-th" style="text-align:center; font-size:7.5pt;">연비<br>(km/ℓ)</td>
        <td colspan="2"><input data-field="em_fe_p1"  class="em-inp" type="text" value="\${E(v('em_fe_p1'))}"></td>
        <td colspan="2"><input data-field="em_fe_p2"  class="em-inp" type="text" value="\${E(v('em_fe_p2'))}"></td>
        <td colspan="2"><input data-field="em_fe_p3"  class="em-inp" type="text" value="\${E(v('em_fe_p3'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════════ -->
  <!-- 6. 시험결과 - 종합 결과표                                  -->
  <!-- PDF 실측 y=672~755                                        -->
  <!-- y=673~687: 항목|CO|NOx|HC(배기관/NMHC/증발가스)|PM|CO2|연비 -->
  <!-- 7열: 11.8%|10.5%|11.8%|33.3%|6.4%|11.2%|15.1%           -->
  <!--   ↑ HC열은 내부적으로 배기관가스/NMHC/증발가스 3분할       -->
  <!-- y=687~755: 데이터 행 (시험결과/열화계수/최종결과/기준치)   -->
  <!-- ══════════════════════════════════════════════════════════ -->
  <table class="em-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:11.8%;"><!-- 항목 -->
      <col style="width:10.5%;"><!-- CO -->
      <col style="width:11.8%;"><!-- NOx -->
      <col style="width:14.1%;"><!-- HC 배기관 -->
      <col style="width:9.8%; "><!-- NMHC -->
      <col style="width:9.4%; "><!-- 증발가스 -->
      <col style="width:6.4%; "><!-- PM -->
      <col style="width:11.2%;"><!-- CO2 -->
      <col style="width:15.0%;"><!-- 연비 -->
    </colgroup>
    <thead>
      <tr>
        <th class="em-th" rowspan="2" style="text-align:center; vertical-align:middle;">항&nbsp;목</th>
        <th class="em-th" rowspan="2" style="text-align:center; vertical-align:middle;">CO</th>
        <th class="em-th" rowspan="2" style="text-align:center; vertical-align:middle;">NOx</th>
        <th class="em-th" colspan="3" style="text-align:center;">HC</th>
        <th class="em-th" rowspan="2" style="text-align:center; vertical-align:middle;">PM</th>
        <th class="em-th" rowspan="2" style="text-align:center; vertical-align:middle;">CO₂</th>
        <th class="em-th" rowspan="2" style="text-align:center; vertical-align:middle; font-size:7.5pt;">연 비<br>(km/ℓ)</th>
      </tr>
      <tr>
        <th class="em-th" style="text-align:center; font-size:7.5pt;">배기관<br>가스</th>
        <th class="em-th" style="text-align:center;">NMHC</th>
        <th class="em-th" style="text-align:center; font-size:7.5pt;">증발가스<br>(g/test)</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td class="em-th" style="font-size:7.5pt;">\${BL('g_test_result')}<br>(g/km)</td>
        <td><input data-field="em_r_co"       class="em-inp" type="text" value="\${E(v('em_r_co'))}"></td>
        <td><input data-field="em_r_nox"      class="em-inp" type="text" value="\${E(v('em_r_nox'))}"></td>
        <td><input data-field="em_r_hc"       class="em-inp" type="text" value="\${E(v('em_r_hc'))}"></td>
        <td><input data-field="em_r_nmhc"     class="em-inp" type="text" value="\${E(v('em_r_nmhc'))}"></td>
        <td><input data-field="em_r_evap"     class="em-inp" type="text" value="\${E(v('em_r_evap'))}"></td>
        <td><input data-field="em_r_pm"       class="em-inp" type="text" value="\${E(v('em_r_pm'))}"></td>
        <td><input data-field="em_r_co2"      class="em-inp" type="text" value="\${E(v('em_r_co2'))}"></td>
        <td><input data-field="em_r_fe"       class="em-inp" type="text" value="\${E(v('em_r_fe'))}"></td>
      </tr>
      <tr>
        <td class="em-th" style="font-size:7.5pt;">열화계수<br>(DF)</td>
        <td><input data-field="em_df_co"      class="em-inp" type="text" value="\${E(v('em_df_co'))}"></td>
        <td><input data-field="em_df_nox"     class="em-inp" type="text" value="\${E(v('em_df_nox'))}"></td>
        <td><input data-field="em_df_hc"      class="em-inp" type="text" value="\${E(v('em_df_hc'))}"></td>
        <td><input data-field="em_df_nmhc"    class="em-inp" type="text" value="\${E(v('em_df_nmhc'))}"></td>
        <td><input data-field="em_df_evap"    class="em-inp" type="text" value="\${E(v('em_df_evap'))}"></td>
        <td><input data-field="em_df_pm"      class="em-inp" type="text" value="\${E(v('em_df_pm'))}"></td>
        <td><input data-field="em_df_co2"     class="em-inp" type="text" value="\${E(v('em_df_co2'))}"></td>
        <td><input data-field="em_df_fe"      class="em-inp" type="text" value="\${E(v('em_df_fe'))}"></td>
      </tr>
      <tr>
        <td class="em-th" style="text-align:center;">\${BL('ev_final_result')}</td>
        <td><input data-field="em_fin_co"     class="em-inp" type="text" value="\${E(v('em_fin_co'))}"></td>
        <td><input data-field="em_fin_nox"    class="em-inp" type="text" value="\${E(v('em_fin_nox'))}"></td>
        <td><input data-field="em_fin_hc"     class="em-inp" type="text" value="\${E(v('em_fin_hc'))}"></td>
        <td><input data-field="em_fin_nmhc"   class="em-inp" type="text" value="\${E(v('em_fin_nmhc'))}"></td>
        <td><input data-field="em_fin_evap"   class="em-inp" type="text" value="\${E(v('em_fin_evap'))}"></td>
        <td><input data-field="em_fin_pm"     class="em-inp" type="text" value="\${E(v('em_fin_pm'))}"></td>
        <td><input data-field="em_fin_co2"    class="em-inp" type="text" value="\${E(v('em_fin_co2'))}"></td>
        <td><input data-field="em_fin_fe"     class="em-inp" type="text" value="\${E(v('em_fin_fe'))}"></td>
      </tr>
      <tr>
        <td class="em-th" style="text-align:center;">기&nbsp;준&nbsp;치</td>
        <td><input data-field="em_lim_co"     class="em-inp" type="text" value="\${E(v('em_lim_co'))}"></td>
        <td><input data-field="em_lim_nox"    class="em-inp" type="text" value="\${E(v('em_lim_nox'))}"></td>
        <td><input data-field="em_lim_hc"     class="em-inp" type="text" value="\${E(v('em_lim_hc'))}"></td>
        <td><input data-field="em_lim_nmhc"   class="em-inp" type="text" value="\${E(v('em_lim_nmhc'))}"></td>
        <td><input data-field="em_lim_evap"   class="em-inp" type="text" value="\${E(v('em_lim_evap'))}"></td>
        <td><input data-field="em_lim_pm"     class="em-inp" type="text" value="\${E(v('em_lim_pm'))}"></td>
        <td><input data-field="em_lim_co2"    class="em-inp" type="text" value="\${E(v('em_lim_co2'))}"></td>
        <td><input data-field="em_lim_fe"     class="em-inp" type="text" value="\${E(v('em_lim_fe'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- ── 첨부문서: 자체 배출가스 시험 성적서 / RAW DATA ── -->
  <div class="em-attach-section no-print" id="em-attach-raw-section">
    <div class="em-attach-title"><i class="fas fa-paperclip"></i> 첨부문서 (자체시험성적서 / RAW DATA)</div>
    <div class="em-attach-note">이미지(JPG, PNG) 또는 PDF 파일을 업로드하세요. 첨부파일은 인쇄 시 출력되지 않습니다.</div>
    <div class="em-attach-drop" id="em-drop-raw">
      <i class="fas fa-cloud-upload-alt" style="font-size:20pt;margin-bottom:6px;display:block;"></i>
      클릭하거나 파일을 드래그하여 업로드
      <input type="file" id="em-file-raw" accept="image/*,.pdf" multiple>
    </div>
    <div class="em-attach-list" id="em-list-raw"></div>
    <input type="hidden" id="em-attach-raw-data" data-field="em_attach_raw_data" value="\${E(v('em_attach_raw_data'))}">
  </div>

  <div id="qr-footer-wrap" style="margin-top:12px;"></div>
</div>
\`;

  if (formType==='evap_test') return \`
<style>
/* ══════ evap_test 전용 스타일 ══════ */
.en-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
  background:#fff;
  color:#111;
  border-radius:8px;
}
.en-doc-tag { font-size:8.5pt; font-weight:700; color:#444; margin:10px 0 4px; }
.en-main-title {
  font-size:13pt; font-weight:900; text-align:center;
  margin:4px 0 14px; letter-spacing:.03em; color:#111;
}
.en-tbl {
  width:100%; border-collapse:collapse;
  font-size:8.5pt; margin-bottom:0;
}
.en-tbl th, .en-tbl td {
  border:1px solid #888;
  padding:3px 5px;
  vertical-align:middle;
  color:#111;
}
.en-sec-th {
  background:#d6e4f7;
  font-weight:700; text-align:left;
  padding:4px 6px; font-size:8.5pt; color:#111;
}
.en-sub-th {
  background:#eef3fa;
  font-weight:700; text-align:left;
  padding:3px 6px; font-size:8.5pt; color:#111;
}
.en-th {
  background:#eef3fa;
  font-weight:600; text-align:center;
  font-size:8pt; color:#111;
}
.en-lbl {
  background:#f5f8ff;
  font-weight:600; color:#111;
  vertical-align:middle;
}
/* ── 복합 입력 필드 (텍스트 + 이미지) ── */
.en-field {
  display:flex; flex-direction:column; gap:4px;
  padding:3px 4px; box-sizing:border-box; width:100%;
}
.en-field-text {
  width:100%; font-size:8.5pt; font-family:inherit;
  border:none; background:transparent; padding:2px 0;
  box-sizing:border-box; resize:vertical; color:#111;
  min-height:36px; line-height:1.5;
}
.en-field-text::placeholder { color:#aaa; }
.en-field-text:focus { outline:none; border-bottom:1px dashed #4e90d8; }
/* 이미지 드롭존 */
.en-drop {
  border:1.5px dashed #b0c4de;
  border-radius:5px;
  background:#f8faff;
  padding:6px 8px;
  cursor:pointer;
  transition:border-color .15s, background .15s;
  position:relative;
  min-height:36px;
}
.en-drop:hover { border-color:#4e90d8; background:#eef3fa; }
.en-drop.drag-over { border-color:#2563eb; background:#dbeafe; }
.en-drop-hint {
  color:#aaa; font-size:7.5pt; text-align:center;
  pointer-events:none; user-select:none;
  display:flex; align-items:center; justify-content:center; gap:4px;
}
.en-drop input[type=file] { display:none; }
/* 이미지 미리보기 목록 */
.en-img-list {
  display:flex; flex-wrap:wrap; gap:6px; margin-top:4px;
}
.en-img-item {
  position:relative; display:inline-block;
}
.en-img-item img {
  max-width:140px; max-height:100px;
  border:1px solid #ccc; border-radius:3px;
  display:block; object-fit:contain; background:#fff;
}
.en-img-item-del {
  position:absolute; top:-6px; right:-6px;
  width:16px; height:16px; border-radius:50%;
  background:#ef4444; color:#fff; font-size:10px;
  display:flex; align-items:center; justify-content:center;
  cursor:pointer; line-height:1; border:none;
  box-shadow:0 1px 3px rgba(0,0,0,.3);
}
.en-img-item-del:hover { background:#dc2626; }
/* 헤더 셀의 텍스트 입력 (수입사 등 단순 1행 셀) */
.en-inp {
  border:none; background:transparent;
  width:100%; font-size:8.5pt;
  font-family:inherit; padding:0 2px;
  box-sizing:border-box; color:#111;
}
.en-inp::placeholder { color:#aaa; }
.en-inp:focus { outline:none; border-bottom:1px solid #4e90d8; }
@media print {
  /* ── 전체 래퍼 ── */
  .en-wrap { background:#fff !important; color:#000 !important; border-radius:0 !important; }

  /* ── 테이블 셀: 내용에 맞춰 높이 자동 확장, 잘림 방지 ── */
  .en-tbl { table-layout:fixed !important; width:100% !important; }
  .en-tbl th, .en-tbl td {
    border:1px solid #333 !important; color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important; overflow-wrap:break-word !important;
  }

  /* ── en-field: 인쇄 시 flex 유지, 높이 자동 ── */
  .en-field { height:auto !important; overflow:visible !important; display:flex !important; flex-direction:column !important; }

  /* ── textarea: 내용 전체 표시, 스크롤 없이 ── */
  textarea.en-field-text {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; min-height:0 !important; max-height:none !important;
    overflow:visible !important; resize:none !important;
    white-space:pre-wrap !important; word-break:break-word !important;
    overflow-wrap:break-word !important;
    display:block !important; box-sizing:border-box !important;
    -webkit-appearance:none !important; appearance:none !important;
    padding:2px 0 !important;
  }

  /* ── 단순 1행 input ── */
  .en-inp {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important;
  }

  /* ── hidden input 완전 숨김 ── */
  input[type=hidden] { display:none !important; }

  /* ── 이미지 드롭존: 테두리/배경 제거, 힌트/삭제버튼 숨김 ── */
  .en-drop {
    border:none !important; background:transparent !important;
    padding:0 !important; min-height:unset !important;
    height:auto !important; overflow:visible !important;
  }
  .en-drop-hint { display:none !important; }
  .en-img-item-del { display:none !important; }
  .en-img-list { gap:4px !important; margin-top:2px !important; }
  .en-img-item img {
    max-width:100% !important; max-height:none !important;
    page-break-inside:avoid;
  }
  /* 이미지가 없는 빈 en-drop은 공간 차지 안 함 */
  .en-drop:not(:has(img)) { display:none !important; }

  /* ── 섹션 헤더 배경색 유지 ── */
  .en-sec-th { background:#d6e4f7 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-sub-th { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-th     { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-lbl    { background:#f5f8ff !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }

  /* ── 페이지 분리 방지 (행 단위) ── */
  .en-tbl tr { page-break-inside:avoid; }
}

.ev-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
  background:#fff;
  color:#111;
  border-radius:8px;
}
.ev-doc-tag  { font-size:8.5pt; font-weight:700; color:#444; margin:10px 0 4px; }
.ev-main-title {
  font-size:13pt; font-weight:900; text-align:center;
  margin:4px 0 14px; letter-spacing:.03em; color:#111;
}
/* 공통 표 */
.ev-tbl {
  width:100%; border-collapse:collapse;
  font-size:8.5pt; margin-bottom:0;
}
.ev-tbl th, .ev-tbl td {
  border:1px solid #888;
  padding:3px 5px;
  vertical-align:middle;
  word-break:keep-all;
  overflow-wrap:break-word;
  color:#111;
}
.ev-th {
  background:#eef3fa;
  font-weight:600;
  white-space:nowrap;
  font-size:8pt;
  color:#111;
}
.ev-sec-th {
  background:#d6e4f7;
  font-weight:700; text-align:left;
  padding:3px 6px;
  font-size:8.5pt;
  color:#111;
}
.ev-inp {
  width:100%; background:transparent;
  border:none; outline:none;
  font-size:8.5pt; color:#111;
  font-family:inherit; padding:0 2px;
  box-sizing:border-box;
}
.ev-inp::placeholder { color:#aaa; }
.ev-inp:focus { border-bottom:1px solid #4e90d8; }
.ev-lbl { font-weight:600; white-space:nowrap; color:#111; }
.ev-chk-row { display:flex; align-items:center; gap:6px; }
.ev-chk-item { display:flex; align-items:center; gap:3px; font-size:8.5pt; cursor:pointer; }
/* 첨부 섹션 */
.ev-attach-section { margin-top:14px; }
.ev-attach-title { font-size:9pt; font-weight:700; margin-bottom:6px; color:#111; }
.ev-attach-note { font-size:8pt; color:#666; margin-bottom:8px; }
.ev-attach-drop {
  border:2px dashed #bbb; border-radius:8px;
  padding:16px; text-align:center; cursor:pointer;
  transition:.2s; color:#555; font-size:9pt; background:#fafafa;
}
.ev-attach-drop:hover { border-color:#4e90d8; background:rgba(79,142,247,.04); }
.ev-attach-drop input[type=file] { display:none; }
.ev-attach-list { margin-top:8px; display:flex; flex-direction:column; gap:4px; }
.ev-attach-item {
  display:flex; align-items:center; gap:8px;
  padding:4px 8px; border-radius:4px;
  background:#f0f4fa; font-size:8.5pt;
}
.ev-attach-item-name { flex:1; color:#111; word-break:break-all; }
.ev-attach-item-size { color:#666; white-space:nowrap; font-size:8pt; }
.ev-attach-item-del { color:#ef4444; cursor:pointer; padding:1px 5px; border-radius:3px; font-size:10pt; line-height:1; }
.ev-attach-item-del:hover { background:rgba(239,68,68,.12); }
/* 첨부문서: 인쇄 미리보기 기능 제거됨 (업로드/다운로드 전용) */
/* 인쇄 */
@media print {
  .ev-wrap { background:#fff !important; color:#000 !important; border-radius:0 !important; }
  .ev-tbl th, .ev-tbl td {
    border:1px solid #333 !important; color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
    vertical-align:middle !important; padding:3px 5px !important;
  }
  .ev-sec-th { background:#d6e4f7 !important; color:#000 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .ev-th     { background:#eef3fa !important; color:#000 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .ev-inp {
    border:none !important; background:transparent !important;
    height:auto !important; overflow:visible !important;
    font-size:8.5pt !important; font-family:'맑은 고딕','Malgun Gothic',sans-serif !important;
    padding:0 2px !important; color:#000 !important;
  }
  .ev-lbl { color:#000 !important; font-weight:600 !important; }
  .ev-chk-item { color:#000 !important; }
  /* 첨부문서 영역 인쇄 시 완전 숨김 */
  .ev-attach-section { display:none !important; }
}
</style>

<div class="ev-wrap">

  <!-- ── 최상단 헤더 (수입사/인증연도/배기량/동일차종기호) ── -->
  <table class="ev-tbl" style="margin-bottom:14px;">
    <thead>
      <tr>
        <th class="ev-th" style="width:35%;">\${BL('importer')}</th>
        <th class="ev-th" style="width:12%;">\${BL('cert_year')}</th>
        <th class="ev-th" style="width:13%;">\${BL('displacement')}</th>
        <th class="ev-th" style="width:40%;">\${BL('family_code')}</th>
      </tr>
    </thead>
    <tbody>
      <tr style="height:28px;">
        <td><input data-field="ev_importer"   class="ev-inp" type="text" placeholder="\${BL('ph_importer')}" value="\${E(v('ev_importer'))}"></td>
        <td><input data-field="ev_cert_year"  class="ev-inp" type="text" placeholder="\${BL('ph_cert_year')}" value="\${E(v('ev_cert_year'))}"></td>
        <td><input data-field="ev_disp"       class="ev-inp" type="text" placeholder="\${BL('ph_displacement')}" value="\${E(v('ev_disp'))}"></td>
        <td><input data-field="ev_fam_code"   class="ev-inp" type="text" placeholder="\${BL('ph_family_code')}" value="\${E(v('ev_fam_code'))}"></td>
      </tr>
    </tbody>
  </table>

  <div class="ev-doc-tag">[별지 제23호 서식]</div>
  <div class="ev-main-title">\${BL('ev_main_title')}</div>

  <!-- ══════════════════════════════════════════ -->
  <!-- 1. 일반 사항 -->
  <!-- ══════════════════════════════════════════ -->
  <table class="ev-tbl">
    <tbody>
      <tr>
        <th class="ev-sec-th" colspan="6">1. &nbsp;일 반 &nbsp;사 항</th>
      </tr>
      <!-- 인증차명(rowspan=2) / 시험차명 / 시험일시 -->
      <tr>
        <td style="width:16%;" class="ev-th">\${BL('ev_cert_name')}:</td>
        <td style="width:18%;"><input data-field="ev_cert_model"  class="ev-inp" type="text" value="\${E(v('ev_cert_model'))}"></td>
        <td style="width:14%;" class="ev-th" rowspan="2" style="vertical-align:middle;">\${BL('ev_test_name')}:</td>
        <td style="width:18%;" rowspan="2"><input data-field="ev_test_model"  class="ev-inp" type="text" value="\${E(v('ev_test_model'))}"></td>
        <td style="width:14%;" class="ev-th" rowspan="2" style="vertical-align:middle;">\${BL('ev_test_date')}:</td>
        <td style="width:20%;" rowspan="2"><input data-field="ev_test_date"   class="ev-inp" type="text" placeholder="YYYY-MM-DD" value="\${E(v('ev_test_date'))}"></td>
      </tr>
      <!-- 동일차종 (인증차명 아래 별도 행, 좌측 2칸만) -->
      <tr>
        <td class="ev-th">\${BL('ev_same_type')}:</td>
        <td><input data-field="ev_same_model" class="ev-inp" type="text" value="\${E(v('ev_same_model'))}"></td>
      </tr>
      <!-- 시험번호 / 장비작동자 / 검사책임자 -->
      <tr>
        <td class="ev-th">\${BL('ev_test_no')}:</td>
        <td><input data-field="ev_test_no"    class="ev-inp" type="text" value="\${E(v('ev_test_no'))}"></td>
        <td class="ev-th">\${BL('em_operator')}:</td>
        <td><input data-field="ev_operator"   class="ev-inp" type="text" value="\${E(v('ev_operator'))}"></td>
        <td class="ev-th">\${BL('em_inspector')}:</td>
        <td><input data-field="ev_inspector"  class="ev-inp" type="text" value="\${E(v('ev_inspector'))}"></td>
      </tr>
      <!-- 차대번호 / 엔진번호 / 적산거리 -->
      <tr>
        <td class="ev-th">\${BL('ev_vin')}:</td>
        <td><input data-field="ev_vin"        class="ev-inp" type="text" value="\${E(v('ev_vin'))}"></td>
        <td class="ev-th">\${BL('ev_eng_no')}</td>
        <td><input data-field="ev_eng_no"     class="ev-inp" type="text" value="\${E(v('ev_eng_no'))}"></td>
        <td class="ev-th">\${BL('ev_odo')}:</td>
        <td><input data-field="ev_mileage"    class="ev-inp" type="text" placeholder="km" value="\${E(v('ev_mileage'))}"></td>
      </tr>
      <!-- 시험구분 (체크박스) -->
      <tr>
        <td class="ev-th" style="text-align:center;">\${BL('ev_test_div')}</td>
        <td style="text-align:center;">
          <label class="ev-chk-item" style="justify-content:center;">
            <input type="checkbox" data-field="ev_type_dur" \${v('ev_type_dur')?'checked':''}>&nbsp;내구주행시험
          </label>
        </td>
        <td colspan="2" style="text-align:center;">
          <label class="ev-chk-item" style="justify-content:center;">
            <input type="checkbox" data-field="ev_type_emis" \${v('ev_type_emis')?'checked':''}>&nbsp;배출가스시험
          </label>
        </td>
        <td colspan="2" style="text-align:center;">
          <label class="ev-chk-item" style="justify-content:center;">
            <input type="checkbox" data-field="ev_type_etc" \${v('ev_type_etc')?'checked':''}>&nbsp;기타
          </label>
        </td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════════ -->
  <!-- 2. 측정실 및 측정장비                                    -->
  <!-- PDF 수직선 실측값 기반 완전 재설계 (표 너비 489.2px 기준) -->
  <!--                                                          -->
  <!-- [행별 셀 구조]                                           -->
  <!-- 행1: 29.6% | 14.3% | 15.0% | 17.0% | 24.1%  (5셀)      -->
  <!-- 행2: 33.4% | 33.6% | 33.0%               (3셀, 라벨+값) -->
  <!-- 행3: 33.4% | 33.6% | 33.0%               (3셀, 라벨+값) -->
  <!-- 행4: 16.2%(rowspan2) | 57.7% | 42.3%     (3셀)          -->
  <!-- 행5: [rowspan] | 43.9% | 27.7% | 28.4%   (3셀)          -->
  <!--                                                          -->
  <!-- table-layout:fixed + colgroup 없음 → 행별 td.width 적용 -->
  <!-- ══════════════════════════════════════════════════════════ -->
  <table class="ev-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <tbody>

      <!-- 섹션 헤더 -->
      <tr>
        <th class="ev-sec-th" colspan="5">2. &nbsp;측정실 및 측정장비</th>
      </tr>

      <!-- ─────────────────────────────────────────────────── -->
      <!-- 행1: 측정실(밀폐실) 규격                            -->
      <!-- PDF 수직선: 197.5 / 267.6 / 340.9 / 424.0          -->
      <!-- 셀: 29.6% | 14.3% | 15.0% | 17.0% | 24.1%          -->
      <!-- ─────────────────────────────────────────────────── -->
      <tr>
        <td class="ev-th" style="width:29.6%; white-space:nowrap;">\${BL('ev_chamber_spec')}:</td>
        <td style="width:14.3%; white-space:nowrap; padding:2px 3px;">
          <span class="ev-lbl" style="font-size:8.5pt;">\${BL('ev_height')}:</span>
          <input data-field="ev_room_h" class="ev-inp" type="text" style="width:52%;" value="\${E(v('ev_room_h'))}">
        </td>
        <td style="width:15.0%; white-space:nowrap; padding:2px 3px;">
          <span class="ev-lbl" style="font-size:8.5pt;">\${BL('ev_width')}:</span>
          <input data-field="ev_room_w" class="ev-inp" type="text" style="width:62%;" value="\${E(v('ev_room_w'))}">
        </td>
        <td style="width:17.0%; white-space:nowrap; padding:2px 3px;">
          <span class="ev-lbl" style="font-size:8.5pt;">\${BL('ev_length')}:</span>
          <input data-field="ev_room_l" class="ev-inp" type="text" style="width:58%;" value="\${E(v('ev_room_l'))}">
        </td>
        <td style="width:24.1%; white-space:nowrap; padding:2px 3px;">
          <span class="ev-lbl" style="font-size:8.5pt;">\${BL('ev_vol')}:</span>
          <input data-field="ev_room_vol" class="ev-inp" type="text" style="width:42%;" value="\${E(v('ev_room_vol'))}">
        </td>
      </tr>

      <!-- ─────────────────────────────────────────────────── -->
      <!-- 행2: 측정실 온도 조정방법 / 연료가열장치 / 측정실 모델 -->
      <!-- PDF 수직선: 216.2 / 380.8                           -->
      <!-- 셀: 33.4% | 33.6% | 33.0%  (라벨+입력 합칩)        -->
      <!-- ─────────────────────────────────────────────────── -->
      <tr>
        <td colspan="2" style="width:33.4%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">\${BL('ev_temp_method')}:</span>
          <input data-field="ev_temp_method" class="ev-inp" type="text" value="\${E(v('ev_temp_method'))}">
        </td>
        <td colspan="2" style="width:33.6%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">\${BL('ev_fuel_heater')}:</span>
          <input data-field="ev_fuel_heater" class="ev-inp" type="text" value="\${E(v('ev_fuel_heater'))}">
        </td>
        <td style="width:33.0%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">\${BL('ev_chamber_model')}:</span>
          <input data-field="ev_room_model" class="ev-inp" type="text" value="\${E(v('ev_room_model'))}">
        </td>
      </tr>

      <!-- ─────────────────────────────────────────────────── -->
      <!-- 행3: 분석장비 / HC 고정 방법 / 모델  (행2 동일 비율) -->
      <!-- ─────────────────────────────────────────────────── -->
      <tr>
        <td colspan="2" style="width:33.4%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">\${BL('ev_analyzer')}:</span>
          <input data-field="ev_analyzer" class="ev-inp" type="text" value="\${E(v('ev_analyzer'))}">
        </td>
        <td colspan="2" style="width:33.6%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">\${BL('ev_hc_fix')}:</span>
          <input data-field="ev_hc_method" class="ev-inp" type="text" value="\${E(v('ev_hc_method'))}">
        </td>
        <td style="width:33.0%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">\${BL('ev_model_label')}:</span>
          <input data-field="ev_hc_model" class="ev-inp" type="text" value="\${E(v('ev_hc_model'))}">
        </td>
      </tr>

      <!-- ─────────────────────────────────────────────────── -->
      <!-- 행4: 활성탄 채집트랙(rowspan=2) / 용기규격 / 보조채집 -->
      <!-- PDF 수직선: 132.3 / 335.2                           -->
      <!-- 활성탄(16.2%, rowspan=2) | 용기규격(57.7%) | 보조(42.3%는 행4만) -->
      <!-- 실제: 132.3~335.2=57.7% (용기규격) | 335.2~542.1=42.3% (보조) -->
      <!-- ─────────────────────────────────────────────────── -->
      <tr>
        <td class="ev-th" rowspan="2" style="width:16.2%; text-align:center; vertical-align:middle; white-space:nowrap; padding:2px 3px;">\${BL('ev_charcoal_trap')}</td>
        <td colspan="2" style="width:57.7%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">\${BL('ev_trap_spec')}:</span>
          <input data-field="ev_can_spec" class="ev-inp" type="text" value="\${E(v('ev_can_spec'))}">
        </td>
        <td colspan="2" style="width:42.3%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap; font-size:8pt;">\${BL('ev_trap_aux')}:</span>
          <input data-field="ev_aux_spec" class="ev-inp" type="text" value="\${E(v('ev_aux_spec'))}">
        </td>
      </tr>

      <!-- ─────────────────────────────────────────────────── -->
      <!-- 행5: [활성탄 rowspan 차지] / 채집용기무게 / 시험후무게 / 손무게 -->
      <!-- PDF 수직선: 132.3 / 267.6 / 402.9                  -->
      <!-- [rowspan] | 43.9% | 27.7% | 28.4%                  -->
      <!-- 실제: 132.3~267.6=27.7% | 267.6~402.9=27.7% | 402.9~542.1=28.4% -->
      <!-- ─────────────────────────────────────────────────── -->
      <tr>
        <td colspan="2" style="width:43.9%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">\${BL('ev_trap_weight_before')}:</span>
          <input data-field="ev_can_wt_before" class="ev-inp" type="text" placeholder="g" style="width:38%;" value="\${E(v('ev_can_wt_before'))}">
        </td>
        <td style="width:27.7%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">\${BL('ev_trap_weight_after')}:</span>
          <input data-field="ev_can_wt_after" class="ev-inp" type="text" placeholder="g" style="width:42%;" value="\${E(v('ev_can_wt_after'))}">
        </td>
        <td style="width:28.4%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">\${BL('ev_trap_net_weight')}:</span>
          <input data-field="ev_can_wt_loss" class="ev-inp" type="text" placeholder="g" style="width:42%;" value="\${E(v('ev_can_wt_loss'))}">
        </td>
      </tr>

    </tbody>
  </table>

  <!-- ══════════════════════════════════════════ -->
  <!-- 3. 시험결과 -->
  <!-- ══════════════════════════════════════════ -->
  <table class="ev-tbl" style="border-top:none;">
    <thead>
      <tr>
        <th class="ev-sec-th" colspan="8">3. &nbsp;\${BL('ev_test_results')}</th>
      </tr>
      <!-- 복합 헤더 1행 -->
      <tr>
        <th class="ev-th" rowspan="2" style="width:18%; vertical-align:middle;">\${BL('ev_col_div')}</th>
        <th class="ev-th" colspan="3">\${BL('ev_initial_phase')}</th>
        <th class="ev-th" colspan="3">\${BL('ev_final_phase')}</th>
        <th class="ev-th" rowspan="2" style="width:8%; vertical-align:middle;">\${BL('ev_result')}</th>
      </tr>
      <!-- 복합 헤더 2행 -->
      <tr>
        <th class="ev-th" style="width:9%;">\${BL('ev_temp')}</th>
        <th class="ev-th" style="width:10%;">\${BL('ev_pressure')}</th>
        <th class="ev-th" style="width:9%;">\${BL('ev_conc')}</th>
        <th class="ev-th" style="width:9%;">\${BL('ev_temp')}</th>
        <th class="ev-th" style="width:10%;">\${BL('ev_pressure')}</th>
        <th class="ev-th" style="width:9%;">\${BL('ev_conc')}</th>
      </tr>
    </thead>
    <tbody>
      <!-- 주간증발손실시험 -->
      <tr style="height:32px;">
        <td style="text-align:center; font-weight:600;">\${BL('ev_diurnal_test')}</td>
        <td><input data-field="ev_diurnal_t1"  class="ev-inp" type="text" value="\${E(v('ev_diurnal_t1'))}"></td>
        <td><input data-field="ev_diurnal_p1"  class="ev-inp" type="text" value="\${E(v('ev_diurnal_p1'))}"></td>
        <td><input data-field="ev_diurnal_c1"  class="ev-inp" type="text" value="\${E(v('ev_diurnal_c1'))}"></td>
        <td><input data-field="ev_diurnal_t2"  class="ev-inp" type="text" value="\${E(v('ev_diurnal_t2'))}"></td>
        <td><input data-field="ev_diurnal_p2"  class="ev-inp" type="text" value="\${E(v('ev_diurnal_p2'))}"></td>
        <td><input data-field="ev_diurnal_c2"  class="ev-inp" type="text" value="\${E(v('ev_diurnal_c2'))}"></td>
        <td><input data-field="ev_diurnal_res" class="ev-inp" type="text" value="\${E(v('ev_diurnal_res'))}"></td>
      </tr>
      <!-- 고온소오크시험 -->
      <tr style="height:32px;">
        <td style="text-align:center; font-weight:600;">\${BL('ev_hot_soak')}</td>
        <td><input data-field="ev_soak_t1"  class="ev-inp" type="text" value="\${E(v('ev_soak_t1'))}"></td>
        <td><input data-field="ev_soak_p1"  class="ev-inp" type="text" value="\${E(v('ev_soak_p1'))}"></td>
        <td><input data-field="ev_soak_c1"  class="ev-inp" type="text" value="\${E(v('ev_soak_c1'))}"></td>
        <td><input data-field="ev_soak_t2"  class="ev-inp" type="text" value="\${E(v('ev_soak_t2'))}"></td>
        <td><input data-field="ev_soak_p2"  class="ev-inp" type="text" value="\${E(v('ev_soak_p2'))}"></td>
        <td><input data-field="ev_soak_c2"  class="ev-inp" type="text" value="\${E(v('ev_soak_c2'))}"></td>
        <td><input data-field="ev_soak_res" class="ev-inp" type="text" value="\${E(v('ev_soak_res'))}"></td>
      </tr>
      <!-- 시험결과/테스트 -->
      <tr style="height:28px;">
        <td style="text-align:center; font-weight:600;">\${BL('ev_test_result_label')}</td>
        <td colspan="7"><input data-field="ev_test_result" class="ev-inp" type="text" value="\${E(v('ev_test_result'))}"></td>
      </tr>
      <!-- 열화계수(DF) -->
      <tr style="height:28px;">
        <td style="text-align:center; font-weight:600;">\${BL('ev_df')}</td>
        <td colspan="7"><input data-field="ev_df" class="ev-inp" type="text" value="\${E(v('ev_df'))}"></td>
      </tr>
      <!-- 최종결과 -->
      <tr style="height:28px;">
        <td style="text-align:center; font-weight:600;">최종결과</td>
        <td colspan="7"><input data-field="ev_final_result" class="ev-inp" type="text" value="\${E(v('ev_final_result'))}"></td>
      </tr>
      <!-- 기준치 -->
      <tr style="height:28px;">
        <td style="text-align:center; font-weight:600;">\${BL('ev_std_val')}</td>
        <td colspan="7"><input data-field="ev_std" class="ev-inp" type="text" value="\${E(v('ev_std'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- 첨부문서: 자체시험성적서 / RAW DATA -->
  <div class="ev-attach-section no-print" id="ev-attach-raw-section">
    <div class="ev-attach-title"><i class="fas fa-paperclip"></i> 첨부문서 (자체시험성적서 / RAW DATA)</div>
    <div class="ev-attach-note">이미지(JPG, PNG) 또는 PDF 파일을 업로드하세요. 첨부파일은 인쇄 시 출력되지 않습니다.</div>
    <div class="ev-attach-drop" id="ev-drop-raw" onclick="document.getElementById('ev-file-raw').click()">
      <input type="file" id="ev-file-raw" multiple accept="image/*,.pdf">
      <i class="fas fa-cloud-upload-alt" style="font-size:20pt;margin-bottom:6px;display:block;"></i>
      클릭하거나 파일을 드래그하여 업로드
    </div>
    <div class="ev-attach-list" id="ev-list-raw"></div>
    <input type="hidden" id="ev-attach-raw-data" data-field="ev_attach_raw_data" value="\${E(v('ev_attach_raw_data'))}">
  </div>

  <div id="qr-footer-wrap" style="margin-top:16px;"></div>
</div>
\`;

  if (formType==='obd_operation') return \`
<style>
/* ══════ obd_operation 전용 스타일 ══════ */
.en-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
  background:#fff;
  color:#111;
  border-radius:8px;
}
.en-doc-tag { font-size:8.5pt; font-weight:700; color:#444; margin:10px 0 4px; }
.en-main-title {
  font-size:13pt; font-weight:900; text-align:center;
  margin:4px 0 14px; letter-spacing:.03em; color:#111;
}
.en-tbl {
  width:100%; border-collapse:collapse;
  font-size:8.5pt; margin-bottom:0;
}
.en-tbl th, .en-tbl td {
  border:1px solid #888;
  padding:3px 5px;
  vertical-align:middle;
  color:#111;
}
.en-sec-th {
  background:#d6e4f7;
  font-weight:700; text-align:left;
  padding:4px 6px; font-size:8.5pt; color:#111;
}
.en-sub-th {
  background:#eef3fa;
  font-weight:700; text-align:left;
  padding:3px 6px; font-size:8.5pt; color:#111;
}
.en-th {
  background:#eef3fa;
  font-weight:600; text-align:center;
  font-size:8pt; color:#111;
}
.en-lbl {
  background:#f5f8ff;
  font-weight:600; color:#111;
  vertical-align:middle;
}
/* ── 복합 입력 필드 (텍스트 + 이미지) ── */
.en-field {
  display:flex; flex-direction:column; gap:4px;
  padding:3px 4px; box-sizing:border-box; width:100%;
}
.en-field-text {
  width:100%; font-size:8.5pt; font-family:inherit;
  border:none; background:transparent; padding:2px 0;
  box-sizing:border-box; resize:vertical; color:#111;
  min-height:36px; line-height:1.5;
}
.en-field-text::placeholder { color:#aaa; }
.en-field-text:focus { outline:none; border-bottom:1px dashed #4e90d8; }
/* 이미지 드롭존 */
.en-drop {
  border:1.5px dashed #b0c4de;
  border-radius:5px;
  background:#f8faff;
  padding:6px 8px;
  cursor:pointer;
  transition:border-color .15s, background .15s;
  position:relative;
  min-height:36px;
}
.en-drop:hover { border-color:#4e90d8; background:#eef3fa; }
.en-drop.drag-over { border-color:#2563eb; background:#dbeafe; }
.en-drop-hint {
  color:#aaa; font-size:7.5pt; text-align:center;
  pointer-events:none; user-select:none;
  display:flex; align-items:center; justify-content:center; gap:4px;
}
.en-drop input[type=file] { display:none; }
/* 이미지 미리보기 목록 */
.en-img-list {
  display:flex; flex-wrap:wrap; gap:6px; margin-top:4px;
}
.en-img-item {
  position:relative; display:inline-block;
}
.en-img-item img {
  max-width:140px; max-height:100px;
  border:1px solid #ccc; border-radius:3px;
  display:block; object-fit:contain; background:#fff;
}
.en-img-item-del {
  position:absolute; top:-6px; right:-6px;
  width:16px; height:16px; border-radius:50%;
  background:#ef4444; color:#fff; font-size:10px;
  display:flex; align-items:center; justify-content:center;
  cursor:pointer; line-height:1; border:none;
  box-shadow:0 1px 3px rgba(0,0,0,.3);
}
.en-img-item-del:hover { background:#dc2626; }
/* 헤더 셀의 텍스트 입력 (수입사 등 단순 1행 셀) */
.en-inp {
  border:none; background:transparent;
  width:100%; font-size:8.5pt;
  font-family:inherit; padding:0 2px;
  box-sizing:border-box; color:#111;
}
.en-inp::placeholder { color:#aaa; }
.en-inp:focus { outline:none; border-bottom:1px solid #4e90d8; }
@media print {
  /* ── 전체 래퍼 ── */
  .en-wrap { background:#fff !important; color:#000 !important; border-radius:0 !important; }

  /* ── 테이블 셀: 내용에 맞춰 높이 자동 확장, 잘림 방지 ── */
  .en-tbl { table-layout:fixed !important; width:100% !important; }
  .en-tbl th, .en-tbl td {
    border:1px solid #333 !important; color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important; overflow-wrap:break-word !important;
  }

  /* ── en-field: 인쇄 시 flex 유지, 높이 자동 ── */
  .en-field { height:auto !important; overflow:visible !important; display:flex !important; flex-direction:column !important; }

  /* ── textarea: 내용 전체 표시, 스크롤 없이 ── */
  textarea.en-field-text {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; min-height:0 !important; max-height:none !important;
    overflow:visible !important; resize:none !important;
    white-space:pre-wrap !important; word-break:break-word !important;
    overflow-wrap:break-word !important;
    display:block !important; box-sizing:border-box !important;
    -webkit-appearance:none !important; appearance:none !important;
    padding:2px 0 !important;
  }

  /* ── 단순 1행 input ── */
  .en-inp {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important;
  }

  /* ── hidden input 완전 숨김 ── */
  input[type=hidden] { display:none !important; }

  /* ── 이미지 드롭존: 테두리/배경 제거, 힌트/삭제버튼 숨김 ── */
  .en-drop {
    border:none !important; background:transparent !important;
    padding:0 !important; min-height:unset !important;
    height:auto !important; overflow:visible !important;
  }
  .en-drop-hint { display:none !important; }
  .en-img-item-del { display:none !important; }
  .en-img-list { gap:4px !important; margin-top:2px !important; }
  .en-img-item img {
    max-width:100% !important; max-height:none !important;
    page-break-inside:avoid;
  }
  /* 이미지가 없는 빈 en-drop은 공간 차지 안 함 */
  .en-drop:not(:has(img)) { display:none !important; }

  /* ── 섹션 헤더 배경색 유지 ── */
  .en-sec-th { background:#d6e4f7 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-sub-th { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-th     { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-lbl    { background:#f5f8ff !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }

  /* ── 페이지 분리 방지 (행 단위) ── */
  .en-tbl tr { page-break-inside:avoid; }
}

.obd-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
  background:#fff;
  color:#111;
  border-radius:8px;
}
.obd-doc-tag  { font-size:8.5pt; font-weight:700; color:#444; margin:10px 0 4px; }
.obd-main-title {
  font-size:13pt; font-weight:900; text-align:center;
  margin:4px 0 14px; letter-spacing:.03em; color:#111;
}
.obd-sec-label {
  font-size:9.5pt; font-weight:700; margin:16px 0 6px; color:#111;
}
.obd-tbl {
  width:100%; border-collapse:collapse; font-size:8.5pt; margin-bottom:4px;
}
.obd-tbl th, .obd-tbl td {
  border:1px solid #888; padding:3px 5px;
  vertical-align:middle; text-align:center;
  word-break:keep-all; overflow-wrap:break-word;
  color:#111;
}
.obd-th {
  background:#eef3fa; font-weight:600;
  font-size:8pt; text-align:center !important; color:#111;
}
.obd-inp {
  width:100%; background:transparent; border:none; outline:none;
  font-size:8.5pt; color:#111; font-family:inherit;
  padding:0 2px; text-align:left; box-sizing:border-box;
}
.obd-inp::placeholder { color:#aaa; }
.obd-inp:focus { border-bottom:1px solid #4e90d8; }
.obd-chk-row { display:flex; align-items:center; gap:10px; }
.obd-chk-item { display:flex; align-items:center; gap:3px; font-size:8.5pt; cursor:pointer; color:#111; }
.obd-result-th-top {
  background:#d6e4f7; font-weight:700; text-align:center !important; color:#111;
}
.obd-result-th-mid {
  background:#eef3fa; font-weight:700;
  text-align:center !important; font-size:8pt; color:#111;
}
.obd-result-td { text-align:center !important; padding:3px 2px !important; }
@media print {
  .obd-wrap { background:#fff !important; color:#000 !important; border-radius:0 !important; }
  .obd-tbl th, .obd-tbl td {
    border:1px solid #333 !important; color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }
  .obd-th         { background:#eef3fa !important; color:#000 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .obd-sec-th     { background:#d6e4f7 !important; color:#000 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .obd-sub-th     { background:#eef3fa !important; color:#000 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .obd-result-th-top { background:#d6e4f7 !important; color:#000 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .obd-result-th-mid { background:#eef3fa !important; color:#000 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .obd-lbl { background:#f5f8ff !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  /* 이미지 포함 테이블 셀: 높이 자동, 오버플로우 허용 */
  .obd-tbl td { height:auto !important; overflow:visible !important; }
  .obd-inp {
    border:none !important; background:transparent !important;
    height:auto !important; overflow:visible !important;
    font-size:8.5pt !important; font-family:'맑은 고딕','Malgun Gothic',sans-serif !important;
    padding:0 2px !important; color:#000 !important;
  }
  /* 헤더 읽기전용 input 인쇄 스타일 */
  .obd-field-text {
    border:none !important; background:transparent !important;
    font-size:8.5pt !important; font-family:'맑은 고딕','Malgun Gothic',sans-serif !important;
    color:#000 !important; padding:0 2px !important;
    height:auto !important;
  }
  /* textarea: 내용 전체 표시 */
  textarea.obd-field-text {
    height:auto !important; min-height:0 !important; max-height:none !important;
    overflow:visible !important; resize:none !important;
    white-space:pre-wrap !important; word-break:break-word !important;
    overflow-wrap:break-word !important;
    display:block !important; box-sizing:border-box !important;
    -webkit-appearance:none !important; appearance:none !important;
  }
  .obd-chk-item { color:#000 !important; }
  .obd-chk-item input[type=checkbox] { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .obd-note-text {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8pt !important;
    height:auto !important; min-height:0 !important; max-height:none !important;
    overflow:visible !important; resize:none !important;
    white-space:pre-wrap !important; word-break:break-word !important;
    display:block !important;
  }
  /* ── 이미지 드롭존: 테두리 제거, 이미지만 표시 ── */
  .obd-drop {
    border:none !important; background:transparent !important;
    padding:0 !important; min-height:unset !important;
    height:auto !important; overflow:visible !important;
    cursor:default !important;
  }
  .obd-drop-hint { display:none !important; }
  .obd-img-item-del { display:none !important; }
  /* 이미지 목록: 세로 나열, 각 이미지 100% 폭 */
  .obd-img-list {
    display:flex !important; flex-direction:column !important;
    gap:6px !important; margin-top:2px !important;
  }
  /* 이미지 아이템: block으로 전환, 셀 너비 꽉 채움 */
  .obd-img-item {
    display:block !important; width:100% !important;
    position:static !important;
  }
  .obd-img-item img {
    width:100% !important; height:auto !important;
    max-width:100% !important; max-height:none !important;
    object-fit:contain !important; display:block !important;
    border:none !important; border-radius:0 !important;
    background:transparent !important;
    page-break-inside:avoid;
  }
  /* 이미지가 없는 빈 드롭존은 공간 차지 안 함 */
  .obd-drop:not(:has(img)) { display:none !important; }
  /* 첨부문서 영역 인쇄 시 완전 숨김 */
  .obd-attach-section { display:none !important; }
  /* 행 페이지 분리 방지 */
  .obd-tbl tr { page-break-inside:avoid; }
}
/* ── OBD 첨부 섹션 ── */
.obd-attach-section { margin-top:14px; }
.obd-attach-title { font-size:9pt; font-weight:700; margin-bottom:6px; color:#111; }
.obd-attach-note { font-size:8pt; color:#666; margin-bottom:8px; }
.obd-attach-drop {
  border:2px dashed #bbb; border-radius:8px;
  padding:16px; text-align:center; cursor:pointer;
  transition:.2s; color:#555; font-size:9pt; background:#fafafa;
}
.obd-attach-drop:hover { border-color:#4e90d8; background:rgba(79,142,247,.04); }
.obd-attach-drop input[type=file] { display:none; }
.obd-attach-list { margin-top:8px; display:flex; flex-direction:column; gap:4px; }
.obd-attach-item {
  display:flex; align-items:center; gap:8px;
  padding:4px 8px; border-radius:4px;
  background:#f0f4fa; font-size:8.5pt;
}
.obd-attach-item-name { flex:1; color:#111; word-break:break-all; }
.obd-attach-item-size { color:#666; white-space:nowrap; font-size:8pt; }
.obd-attach-item-del { color:#ef4444; cursor:pointer; padding:1px 5px; border-radius:3px; font-size:10pt; line-height:1; }
.obd-attach-item-del:hover { background:rgba(239,68,68,.12); }
</style>

<div class="obd-wrap">
  <!-- ── 상단 헤더: 수입사 / 인증연도 / 배기량 / 동일차종기호 ── -->
  <table class="obd-tbl" style="margin-bottom:10px;">
    <colgroup><col style="width:25%;"><col style="width:25%;"><col style="width:25%;"><col style="width:25%;"></colgroup>
    <thead>
      <tr>
        <th class="obd-th">\${BL('importer')}</th>
        <th class="obd-th">\${BL('cert_year')}</th>
        <th class="obd-th">\${BL('displacement')}</th>
        <th class="obd-th">\${BL('family_code')}</th>
      </tr>
    </thead>
    <tbody>
      <tr style="height:28px;">
        <td><input data-field="oo_importer"  class="obd-inp" type="text" placeholder="\${BL('ph_importer')}"    value="\${E(v('oo_importer'))}"></td>
        <td><input data-field="oo_cert_year" class="obd-inp" type="text" placeholder="\${BL('ph_cert_year')}"  value="\${E(v('oo_cert_year'))}"></td>
        <td><input data-field="oo_disp"      class="obd-inp" type="text" placeholder="\${BL('ph_displacement')}" value="\${E(v('oo_disp'))}"></td>
        <td><input data-field="oo_fam_code"  class="obd-inp" type="text" placeholder="\${BL('ph_family_code')}" value="\${E(v('oo_fam_code'))}"></td>
      </tr>
    </tbody>
  </table>

  <div class="obd-doc-tag">[별지 제26호서식]</div>
  <div class="obd-main-title">\${BL('oo_main_title')}</div>

  <!-- ── □ 시험 일반 내용 ── -->
  <div class="obd-sec-label">\${BL('oo_sec_general')}</div>
  <table class="obd-tbl">
    <thead>
      <tr>
        <th class="obd-th" style="width:33%;">\${BL('oo_test_date')}</th>
        <th class="obd-th" style="width:33%;">\${BL('em_operator')}</th>
        <th class="obd-th" style="width:34%;">\${BL('em_inspector')}</th>
      </tr>
    </thead>
    <tbody>
      <tr style="height:32px;">
        <td><input data-field="obd_test_date"  class="obd-inp" type="text" placeholder="YYYY-MM-DD" value="\${E(v('obd_test_date'))}"></td>
        <td><input data-field="obd_operator"   class="obd-inp" type="text" value="\${E(v('obd_operator'))}"></td>
        <td><input data-field="obd_inspector"  class="obd-inp" type="text" value="\${E(v('obd_inspector'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- ── □ 시험자동차 제원 ── -->
  <div class="obd-sec-label">\${BL('oo_sec_vehicle')}</div>
  <table class="obd-tbl">
    <!-- 1. 일반제원 -->
    <thead>
      <tr>
        <th class="obd-th" colspan="6" style="text-align:left !important; padding-left:8px;">1. \${BL('oo_gen_spec')}</th>
      </tr>
      <tr>
        <th class="obd-th" style="width:13%;">\${BL('oo_car_name')}</th>
        <th class="obd-th" style="width:16%;">\${BL('oo_form')}</th>
        <th class="obd-th" style="width:13%;">\${BL('oo_car_type')}</th>
        <th class="obd-th" style="width:14%;">\${BL('sv_fuel')}</th>
        <th class="obd-th" style="width:16%;">변속기 종류</th>
        <th class="obd-th" style="width:28%;">\${BL('oo_gvw_kg')}</th>
      </tr>
    </thead>
    <tbody>
      <tr style="height:30px;">
        <td><input data-field="obd_car_name"   class="obd-inp" type="text" value="\${E(v('obd_car_name'))}"></td>
        <td><input data-field="obd_car_type"   class="obd-inp" type="text" value="\${E(v('obd_car_type'))}"></td>
        <td><input data-field="obd_car_class"  class="obd-inp" type="text" value="\${E(v('obd_car_class'))}"></td>
        <td><input data-field="obd_fuel"       class="obd-inp" type="text" value="\${E(v('obd_fuel'))}"></td>
        <td><input data-field="obd_trans"      class="obd-inp" type="text" value="\${E(v('obd_trans'))}"></td>
        <td><input data-field="obd_weight"     class="obd-inp" type="text" placeholder="kg" value="\${E(v('obd_weight'))}"></td>
      </tr>
    </tbody>
    <!-- 2. 엔진제원 -->
    <thead>
      <tr>
        <th class="obd-th" colspan="6" style="text-align:left !important; padding-left:8px; border-top:2px solid #888;">\${BL('oo_eng_spec_title')}</th>
      </tr>
      <tr>
        <th class="obd-th">\${BL('oo_form')}</th>
        <th class="obd-th">\${BL('em_max_power')}</th>
        <th class="obd-th">\${BL('nt_displacement')}</th>
        <th class="obd-th">\${BL('em_cycle')}</th>
        <th class="obd-th">\${BL('em_cycle')}</th>
        <th class="obd-th">\${BL('oo_purge_type')}</th>
      </tr>
    </thead>
    <tbody>
      <tr style="height:30px;">
        <td><input data-field="obd_eng_type"    class="obd-inp" type="text" value="\${E(v('obd_eng_type'))}"></td>
        <td><input data-field="obd_eng_power"   class="obd-inp" type="text" value="\${E(v('obd_eng_power'))}"></td>
        <td><input data-field="obd_eng_disp"    class="obd-inp" type="text" value="\${E(v('obd_eng_disp'))}"></td>
        <td><input data-field="obd_combustion"  class="obd-inp" type="text" value="\${E(v('obd_combustion'))}"></td>
        <td><input data-field="obd_cycle"       class="obd-inp" type="text" value="\${E(v('obd_cycle'))}"></td>
        <td><input data-field="obd_fuel_supply" class="obd-inp" type="text" value="\${E(v('obd_fuel_supply'))}"></td>
      </tr>
    </tbody>
    <!-- 3. 배출가스 제어장치 및 자기진단장치 제원 -->
    <thead>
      <tr>
        <th class="obd-th" colspan="6" style="text-align:left !important; padding-left:8px; border-top:2px solid #888;">3. 배출가스 제어장치 및 배출가스 자기진단장치 제원</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td colspan="2" style="text-align:left; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:3px;">\${BL('oo_catalyst_type')}</div>
          <input data-field="obd_catalyst" class="obd-inp" type="text" placeholder="형식 / 제작사" value="\${E(v('obd_catalyst'))}">
        </td>
        <td colspan="2" style="text-align:center; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:5px;">\${BL('oo_secondary_air')}</div>
          <div class="obd-chk-row" style="justify-content:center; gap:14px;">
            <label class="obd-chk-item"><input type="checkbox" data-field="obd_air2_y" \${v('obd_air2_y')?'checked':''}>&nbsp;유</label>
            <label class="obd-chk-item"><input type="checkbox" data-field="obd_air2_n" \${v('obd_air2_n')?'checked':''}>&nbsp;무</label>
          </div>
        </td>
        <td colspan="2" style="text-align:center; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:5px;">\${BL('oo_egr')}</div>
          <div class="obd-chk-row" style="justify-content:center; gap:14px;">
            <label class="obd-chk-item"><input type="checkbox" data-field="obd_egr_y" \${v('obd_egr_y')?'checked':''}>&nbsp;유</label>
            <label class="obd-chk-item"><input type="checkbox" data-field="obd_egr_n" \${v('obd_egr_n')?'checked':''}>&nbsp;무</label>
          </div>
        </td>
      </tr>
      <tr>
        <td colspan="2" style="text-align:left; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:3px;">\${BL('oo_ecu_type')}</div>
          <input data-field="obd_ecu" class="obd-inp" type="text" placeholder="형식 / 제작사" value="\${E(v('obd_ecu'))}">
        </td>
        <td colspan="2" style="text-align:left; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:3px;">\${BL('oo_o2_type')}</div>
          <input data-field="obd_o2sensor" class="obd-inp" type="text" placeholder="형식 / 제작사" value="\${E(v('obd_o2sensor'))}">
        </td>
        <td colspan="2" style="text-align:left; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:3px;">\${BL('oo_purge_type')}</div>
          <input data-field="obd_purge" class="obd-inp" type="text" placeholder="형식 / 제작사" value="\${E(v('obd_purge'))}">
        </td>
      </tr>
    </tbody>
  </table>

  <!-- ── □ 시 험 결 과 ── -->
  <div class="obd-sec-label">\${BL('oo_sec_result')}</div>
  <table class="obd-tbl" style="table-layout:fixed;">
    <colgroup>
      <col style="width:13%;"><!-- 장치명 -->
      <col style="width:15%;"><!-- 오작동 재현조건 -->
      <col style="width:7%;"><!-- CO(측정) -->
      <col style="width:7%;"><!-- NOx(측정) -->
      <col style="width:7%;"><!-- HC(측정) -->
      <col style="width:9%;"><!-- 오작동표시등 -->
      <col style="width:7%;"><!-- CO(기준) -->
      <col style="width:7%;"><!-- NOx(기준) -->
      <col style="width:7%;"><!-- HC(기준) -->
      <col style="width:11%;"><!-- 감시장치 적부판정 -->
    </colgroup>
    <thead>
      <!-- 1행: 대분류 -->
      <tr>
        <th class="obd-result-th-top" colspan="2">\${BL('oo_monitor_target')}</th>
        <th class="obd-result-th-top" colspan="4">\${BL('g_test_result')}</th>
        <th class="obd-result-th-top" colspan="4">\${BL('oo_verdict')}</th>
      </tr>
      <!-- 2행: 중분류 -->
      <tr>
        <th class="obd-result-th-mid" rowspan="2" style="vertical-align:middle;">\${BL('oo_device_name')}</th>
        <th class="obd-result-th-mid" rowspan="2" style="vertical-align:middle; font-size:7.5pt;">\${BL('oo_fault_cond2')}</th>
        <th class="obd-result-th-mid" colspan="3">\${BL('oo_cvs75')}</th>
        <th class="obd-result-th-mid" rowspan="2" style="vertical-align:middle; font-size:7pt;">\${BL('g_mil_lamp')}</th>
        <th class="obd-result-th-mid" colspan="3">\${BL('oo_fault_std')}</th>
        <th class="obd-result-th-mid" rowspan="2" style="vertical-align:middle; font-size:7pt;">\${BL('g_monitor_pass')}</th>
      </tr>
      <!-- 3행: CO·NOx·HC 소분류 -->
      <tr>
        <th class="obd-result-th-mid">CO</th>
        <th class="obd-result-th-mid">NOx</th>
        <th class="obd-result-th-mid">HC</th>
        <th class="obd-result-th-mid">CO</th>
        <th class="obd-result-th-mid">NOx</th>
        <th class="obd-result-th-mid">HC</th>
      </tr>
    </thead>
    <tbody>
      <tr style="height:34px;">
        <td class="obd-result-td"><input data-field="obd_r1_device"  class="obd-inp" type="text" value="\${E(v('obd_r1_device'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r1_cond"    class="obd-inp" type="text" value="\${E(v('obd_r1_cond'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r1_co"      class="obd-inp" type="text" value="\${E(v('obd_r1_co'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r1_nox"     class="obd-inp" type="text" value="\${E(v('obd_r1_nox'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r1_hc"      class="obd-inp" type="text" value="\${E(v('obd_r1_hc'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r1_mil"     class="obd-inp" type="text" value="\${E(v('obd_r1_mil'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r1_std_co"  class="obd-inp" type="text" value="\${E(v('obd_r1_std_co'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r1_std_nox" class="obd-inp" type="text" value="\${E(v('obd_r1_std_nox'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r1_std_hc"  class="obd-inp" type="text" value="\${E(v('obd_r1_std_hc'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r1_judge"   class="obd-inp" type="text" value="\${E(v('obd_r1_judge'))}"></td>
      </tr>
      <tr style="height:34px;">
        <td class="obd-result-td"><input data-field="obd_r2_device"  class="obd-inp" type="text" value="\${E(v('obd_r2_device'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r2_cond"    class="obd-inp" type="text" value="\${E(v('obd_r2_cond'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r2_co"      class="obd-inp" type="text" value="\${E(v('obd_r2_co'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r2_nox"     class="obd-inp" type="text" value="\${E(v('obd_r2_nox'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r2_hc"      class="obd-inp" type="text" value="\${E(v('obd_r2_hc'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r2_mil"     class="obd-inp" type="text" value="\${E(v('obd_r2_mil'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r2_std_co"  class="obd-inp" type="text" value="\${E(v('obd_r2_std_co'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r2_std_nox" class="obd-inp" type="text" value="\${E(v('obd_r2_std_nox'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r2_std_hc"  class="obd-inp" type="text" value="\${E(v('obd_r2_std_hc'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r2_judge"   class="obd-inp" type="text" value="\${E(v('obd_r2_judge'))}"></td>
      </tr>
      <tr style="height:34px;">
        <td class="obd-result-td"><input data-field="obd_r3_device"  class="obd-inp" type="text" value="\${E(v('obd_r3_device'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r3_cond"    class="obd-inp" type="text" value="\${E(v('obd_r3_cond'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r3_co"      class="obd-inp" type="text" value="\${E(v('obd_r3_co'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r3_nox"     class="obd-inp" type="text" value="\${E(v('obd_r3_nox'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r3_hc"      class="obd-inp" type="text" value="\${E(v('obd_r3_hc'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r3_mil"     class="obd-inp" type="text" value="\${E(v('obd_r3_mil'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r3_std_co"  class="obd-inp" type="text" value="\${E(v('obd_r3_std_co'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r3_std_nox" class="obd-inp" type="text" value="\${E(v('obd_r3_std_nox'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r3_std_hc"  class="obd-inp" type="text" value="\${E(v('obd_r3_std_hc'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r3_judge"   class="obd-inp" type="text" value="\${E(v('obd_r3_judge'))}"></td>
      </tr>
      <tr style="height:34px;">
        <td class="obd-result-td"><input data-field="obd_r4_device"  class="obd-inp" type="text" value="\${E(v('obd_r4_device'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r4_cond"    class="obd-inp" type="text" value="\${E(v('obd_r4_cond'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r4_co"      class="obd-inp" type="text" value="\${E(v('obd_r4_co'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r4_nox"     class="obd-inp" type="text" value="\${E(v('obd_r4_nox'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r4_hc"      class="obd-inp" type="text" value="\${E(v('obd_r4_hc'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r4_mil"     class="obd-inp" type="text" value="\${E(v('obd_r4_mil'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r4_std_co"  class="obd-inp" type="text" value="\${E(v('obd_r4_std_co'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r4_std_nox" class="obd-inp" type="text" value="\${E(v('obd_r4_std_nox'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r4_std_hc"  class="obd-inp" type="text" value="\${E(v('obd_r4_std_hc'))}"></td>
        <td class="obd-result-td"><input data-field="obd_r4_judge"   class="obd-inp" type="text" value="\${E(v('obd_r4_judge'))}"></td>
      </tr>
    </tbody>
  </table>

  <div id="qr-footer-wrap" style="margin-top:16px;"></div>

  <!-- 첨부문서 섹션 -->
  <div class="obd-attach-section no-print" id="obd-attach-section">
    <div class="obd-attach-title"><i class="fas fa-paperclip"></i> 첨부문서 (자체시험성적서 / RAW DATA)</div>
    <div class="obd-attach-note">이미지(JPG, PNG) 또는 PDF 파일을 업로드하세요. 첨부파일은 인쇄 시 출력되지 않습니다.</div>
    <div class="obd-attach-drop" id="obd-drop-zone" onclick="document.getElementById('obd-file-input').click()">
      <input type="file" id="obd-file-input" multiple accept="image/*,.pdf">
      <i class="fas fa-cloud-upload-alt" style="font-size:20pt;margin-bottom:6px;display:block;"></i>
      클릭하거나 파일을 드래그하여 업로드
    </div>
    <div class="obd-attach-list" id="obd-attach-list"></div>
    <input type="hidden" id="obd-attach-data" data-field="obd_attach_data" value="\${E(v('obd_attach_data'))}">
  </div>

</div>
\`;



  if (formType==='noise_test') return \`
<style>
/* ══════ noise_test 전용 스타일 ══════ */
.en-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
  background:#fff;
  color:#111;
  border-radius:8px;
}
.en-doc-tag { font-size:8.5pt; font-weight:700; color:#444; margin:10px 0 4px; }
.en-main-title {
  font-size:13pt; font-weight:900; text-align:center;
  margin:4px 0 14px; letter-spacing:.03em; color:#111;
}
.en-tbl {
  width:100%; border-collapse:collapse;
  font-size:8.5pt; margin-bottom:0;
}
.en-tbl th, .en-tbl td {
  border:1px solid #888;
  padding:3px 5px;
  vertical-align:middle;
  color:#111;
}
.en-sec-th {
  background:#d6e4f7;
  font-weight:700; text-align:left;
  padding:4px 6px; font-size:8.5pt; color:#111;
}
.en-sub-th {
  background:#eef3fa;
  font-weight:700; text-align:left;
  padding:3px 6px; font-size:8.5pt; color:#111;
}
.en-th {
  background:#eef3fa;
  font-weight:600; text-align:center;
  font-size:8pt; color:#111;
}
.en-lbl {
  background:#f5f8ff;
  font-weight:600; color:#111;
  vertical-align:middle;
}
/* ── 복합 입력 필드 (텍스트 + 이미지) ── */
.en-field {
  display:flex; flex-direction:column; gap:4px;
  padding:3px 4px; box-sizing:border-box; width:100%;
}
.en-field-text {
  width:100%; font-size:8.5pt; font-family:inherit;
  border:none; background:transparent; padding:2px 0;
  box-sizing:border-box; resize:vertical; color:#111;
  min-height:36px; line-height:1.5;
}
.en-field-text::placeholder { color:#aaa; }
.en-field-text:focus { outline:none; border-bottom:1px dashed #4e90d8; }
/* 이미지 드롭존 */
.en-drop {
  border:1.5px dashed #b0c4de;
  border-radius:5px;
  background:#f8faff;
  padding:6px 8px;
  cursor:pointer;
  transition:border-color .15s, background .15s;
  position:relative;
  min-height:36px;
}
.en-drop:hover { border-color:#4e90d8; background:#eef3fa; }
.en-drop.drag-over { border-color:#2563eb; background:#dbeafe; }
.en-drop-hint {
  color:#aaa; font-size:7.5pt; text-align:center;
  pointer-events:none; user-select:none;
  display:flex; align-items:center; justify-content:center; gap:4px;
}
.en-drop input[type=file] { display:none; }
/* 이미지 미리보기 목록 */
.en-img-list {
  display:flex; flex-wrap:wrap; gap:6px; margin-top:4px;
}
.en-img-item {
  position:relative; display:inline-block;
}
.en-img-item img {
  max-width:140px; max-height:100px;
  border:1px solid #ccc; border-radius:3px;
  display:block; object-fit:contain; background:#fff;
}
.en-img-item-del {
  position:absolute; top:-6px; right:-6px;
  width:16px; height:16px; border-radius:50%;
  background:#ef4444; color:#fff; font-size:10px;
  display:flex; align-items:center; justify-content:center;
  cursor:pointer; line-height:1; border:none;
  box-shadow:0 1px 3px rgba(0,0,0,.3);
}
.en-img-item-del:hover { background:#dc2626; }
/* 헤더 셀의 텍스트 입력 (수입사 등 단순 1행 셀) */
.en-inp {
  border:none; background:transparent;
  width:100%; font-size:8.5pt;
  font-family:inherit; padding:0 2px;
  box-sizing:border-box; color:#111;
}
.en-inp::placeholder { color:#aaa; }
.en-inp:focus { outline:none; border-bottom:1px solid #4e90d8; }
@media print {
  /* ── 전체 래퍼 ── */
  .en-wrap { background:#fff !important; color:#000 !important; border-radius:0 !important; }

  /* ── 테이블 셀: 내용에 맞춰 높이 자동 확장, 잘림 방지 ── */
  .en-tbl { table-layout:fixed !important; width:100% !important; }
  .en-tbl th, .en-tbl td {
    border:1px solid #333 !important; color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important; overflow-wrap:break-word !important;
  }

  /* ── en-field: 인쇄 시 flex 유지, 높이 자동 ── */
  .en-field { height:auto !important; overflow:visible !important; display:flex !important; flex-direction:column !important; }

  /* ── textarea: 내용 전체 표시, 스크롤 없이 ── */
  textarea.en-field-text {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; min-height:0 !important; max-height:none !important;
    overflow:visible !important; resize:none !important;
    white-space:pre-wrap !important; word-break:break-word !important;
    overflow-wrap:break-word !important;
    display:block !important; box-sizing:border-box !important;
    -webkit-appearance:none !important; appearance:none !important;
    padding:2px 0 !important;
  }

  /* ── 단순 1행 input ── */
  .en-inp {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important;
  }

  /* ── hidden input 완전 숨김 ── */
  input[type=hidden] { display:none !important; }

  /* ── 이미지 드롭존: 테두리/배경 제거, 힌트/삭제버튼 숨김 ── */
  .en-drop {
    border:none !important; background:transparent !important;
    padding:0 !important; min-height:unset !important;
    height:auto !important; overflow:visible !important;
  }
  .en-drop-hint { display:none !important; }
  .en-img-item-del { display:none !important; }
  .en-img-list { gap:4px !important; margin-top:2px !important; }
  .en-img-item img {
    max-width:100% !important; max-height:none !important;
    page-break-inside:avoid;
  }
  /* 이미지가 없는 빈 en-drop은 공간 차지 안 함 */
  .en-drop:not(:has(img)) { display:none !important; }

  /* ── 섹션 헤더 배경색 유지 ── */
  .en-sec-th { background:#d6e4f7 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-sub-th { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-th     { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-lbl    { background:#f5f8ff !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }

  /* ── 페이지 분리 방지 (행 단위) ── */
  .en-tbl tr { page-break-inside:avoid; }
}

.nt-wrap {
  box-sizing:border-box;
  font-family:'Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
  background:#fff;
  color:#111;
  border-radius:8px;
}
/* 상단 헤더 */
/* noise_test: emission_test 기준으로 통일된 헤더 테이블 */
.nt-header-tbl { width:100%; border-collapse:collapse; margin-bottom:12px; table-layout:fixed; }
.nt-header-lbl-cell { width:25%; border:1px solid #888; padding:3px 5px; background:#eef3fa; text-align:center; font-weight:600; font-size:8pt; color:#111; }
.nt-header-val-cell { width:25%; border:1px solid #888; padding:3px 5px; }
.nt-header-lbl { display:block; font-size:8pt; font-weight:600; color:#111; text-align:center; }
.nt-header-inp { width:100%; background:transparent; border:none; color:#111; font-size:8.5pt; padding:0 2px; outline:none; box-sizing:border-box; }
.nt-header-inp:focus { border-bottom:1px solid #4e90d8; }

/* 별지 서식명 / 대제목 */
.nt-form-tag { font-size:8.5pt; font-weight:700; color:#444; margin:10px 0 4px; }
.nt-main-title { font-size:13pt; font-weight:900; text-align:center; margin:4px 0 14px; letter-spacing:.03em; color:#111; }

/* 섹션 제목 */
.nt-sec-title { font-size:9.5pt; font-weight:700; margin:18px 0 8px; color:#111; }

/* 공통 표 */
.nt-tbl { width:100%; border-collapse:collapse; font-size:8.5pt; table-layout:fixed; margin-bottom:14px; }
.nt-tbl th, .nt-tbl td {
  border:1px solid #888; padding:3px 5px;
  vertical-align:middle; word-break:keep-all;
  overflow-wrap:break-word; text-align:center; color:#111;
}
.nt-th { background:#eef3fa; font-weight:600; font-size:8pt; color:#111; }
.nt-tbl th { background:#eef3fa; font-weight:600; font-size:8pt; color:#111; }
.nt-lbl { background:#f5f8ff; font-weight:600; text-align:center !important; color:#111; }
.nt-val { text-align:left !important; }
.nt-inp {
  width:100%; background:transparent; border:none; outline:none;
  font-size:8.5pt; color:#111; font-family:inherit;
  padding:0 2px; text-align:left; box-sizing:border-box;
}
.nt-inp::placeholder { color:#aaa; }
.nt-inp:focus { border-bottom:1px solid #4e90d8; }

/* 텍스트 입력 (1행짜리) */
.nt-inline { display:flex; align-items:center; gap:6px; margin:4px 0; }
.nt-inline-lbl { font-size:9pt; font-weight:600; white-space:nowrap; color:#111; }
.nt-inline-inp { flex:1; background:transparent; border:none; border-bottom:1px solid #bbb; color:#111; font-size:9pt; padding:2px 4px; outline:none; }
.nt-inline-inp:focus { border-bottom-color:#4e90d8; }
.nt-inline-inp::placeholder { color:#aaa; font-style:italic; }

/* 검사담당자 / 확인자 행 */
.nt-sign-row { display:flex; gap:40px; margin:12px 0 4px; }
.nt-sign-item { display:flex; align-items:center; gap:8px; }
.nt-sign-lbl { font-size:9pt; font-weight:600; white-space:nowrap; color:#111; }
.nt-sign-inp { min-width:120px; background:transparent; border:none; border-bottom:1px solid #bbb; color:#111; font-size:9pt; padding:2px 4px; outline:none; }
.nt-sign-inp:focus { border-bottom-color:#4e90d8; }

/* 첨부문서 업로드 영역 */
.nt-attach-section { margin-top:14px; }
.nt-attach-title { font-size:9pt; font-weight:700; margin-bottom:6px; color:#111; }
.nt-attach-note { font-size:8pt; color:#666; margin-bottom:8px; }
.nt-attach-drop {
  border:2px dashed #bbb; border-radius:8px;
  padding:16px; text-align:center; cursor:pointer;
  transition:.2s; color:#555; font-size:9pt; background:#fafafa;
}
.nt-attach-drop:hover { border-color:#4e90d8; background:rgba(79,142,247,.04); }
.nt-attach-drop input[type=file] { display:none; }
.nt-attach-list { margin-top:8px; display:flex; flex-direction:column; gap:4px; }
.nt-attach-item {
  display:flex; align-items:center; gap:8px;
  padding:4px 8px; border-radius:4px;
  background:#f0f4fa; font-size:8.5pt;
}
.nt-attach-item-name { flex:1; color:#111; word-break:break-all; }
.nt-attach-item-size { color:#666; white-space:nowrap; font-size:8pt; }
.nt-attach-item-del { color:#ef4444; cursor:pointer; padding:1px 5px; border-radius:3px; font-size:10pt; line-height:1; }
.nt-attach-item-del:hover { background:rgba(239,68,68,.12); }
/* 첨부문서: 인쇄 미리보기 기능 제거됨 (업로드/다운로드 전용) */

@media print {
  .nt-wrap { background:#fff !important; color:#000 !important; border-radius:0 !important; font-family:'Malgun Gothic',sans-serif !important; }
  .nt-header-tbl { border-collapse:collapse !important; }
  .nt-header-lbl-cell { border:1px solid #333 !important; background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .nt-header-val-cell { border:1px solid #333 !important; }
  .nt-header-lbl { color:#000 !important; }
  .nt-header-inp { color:#000 !important; border:none !important; background:transparent !important; }
  .nt-tbl th, .nt-tbl td { border:1px solid #333 !important; color:#000 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; padding:3px 4px !important; }
  .nt-th  { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .nt-tbl th { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .nt-lbl { background:#f5f8ff !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .nt-inp { color:#000 !important; border:none !important; background:transparent !important; padding:0 2px !important; }
  .nt-form-tag { color:#000 !important; }
  .nt-main-title { color:#000 !important; }
  .nt-sec-title { color:#000 !important; }
  .nt-inline-lbl { color:#000 !important; }
  .nt-inline-inp { color:#000 !important; border:none !important; border-bottom:1px solid #888 !important; background:transparent !important; }
  .nt-sign-lbl { color:#000 !important; }
  .nt-sign-inp { color:#000 !important; border:none !important; border-bottom:1px solid #888 !important; background:transparent !important; }
  /* 첨부문서 영역 인쇄 시 완전 숨김 */
  .nt-attach-section { display:none !important; }
}
</style>

<div class="nt-wrap">

<!-- ① 상단 헤더 -->
<table class="nt-header-tbl">
  <colgroup><col style="width:35%;"><col style="width:12%;"><col style="width:13%;"><col style="width:40%;"></colgroup>
  <tr>
    <td class="nt-header-lbl-cell"><span class="nt-header-lbl">\${BL('importer')}</span></td>
    <td class="nt-header-lbl-cell"><span class="nt-header-lbl">\${BL('cert_year')}</span></td>
    <td class="nt-header-lbl-cell"><span class="nt-header-lbl">\${BL('displacement')}</span></td>
    <td class="nt-header-lbl-cell"><span class="nt-header-lbl">\${BL('family_code')}</span></td>
  </tr>
  <tr>
    <td class="nt-header-val-cell"><input data-field="importer"     class="nt-header-inp" type="text" placeholder="\${BL('ph_importer')}"    value="\${E(v('importer'))}"></td>
    <td class="nt-header-val-cell"><input data-field="cert_year"    class="nt-header-inp" type="text" placeholder="\${BL('ph_cert_year')}"   value="\${E(v('cert_year'))}"></td>
    <td class="nt-header-val-cell"><input data-field="displacement" class="nt-header-inp" type="text" placeholder="\${BL('ph_displacement')}" value="\${E(v('displacement'))}"></td>
    <td class="nt-header-val-cell"><input data-field="family_code"  class="nt-header-inp" type="text" placeholder="\${BL('ph_family_code')}"  value="\${E(v('family_code'))}"></td>
  </tr>
</table>

<div class="nt-form-tag">[별지 제27호 내지 제27호의2호 서식]</div>
<div class="nt-main-title">\${BL('nt_main_title')}</div>

<!-- 1. 시험관련 규정 -->
<div class="nt-sec-title">\${BL('nt_sec1')}</div>
<div style="padding:4px 8px;">
  <input data-field="nt_reg_note" class="nt-inline-inp" type="text" style="width:100%; font-size:9pt;" placeholder="예) 가속주행 소음시험은 ECE 시험방법으로 측정함" value="\${E(v('nt_reg_note'))}">
</div>

<!-- 2. 시험일 -->
<div class="nt-inline" style="margin-top:10px;">
  <span class="nt-inline-lbl">2. 시험일 :</span>
  <input data-field="nt_test_date" class="nt-inline-inp" type="text" placeholder="예) 2025. 01. 01." value="\${E(v('nt_test_date'))}">
</div>

<!-- 3. 시험자동차 제원 -->
<div class="nt-sec-title" style="margin-top:16px;">\${BL('nt_sec3')}</div>
<table class="nt-tbl">
  <colgroup>
    <col style="width:18%;"><col style="width:14%;"><col style="width:22%;"><col style="width:14%;">
  </colgroup>
  <thead>
    <tr>
      <th>\${BL('th_item')}</th>
      <th>\${BL('th_content')}</th>
      <th>\${BL('th_item')}</th>
      <th>\${BL('th_content')}</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="nt-lbl">\${BL('nt_car_name')}</td>
      <td class="nt-val"><input data-field="nt_car_name"    class="nt-inp" type="text" value="\${E(v('nt_car_name'))}"></td>
      <td class="nt-lbl">\${BL('nt_maker_country')}</td>
      <td class="nt-val"><input data-field="nt_maker"       class="nt-inp" type="text" value="\${E(v('nt_maker'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_car_type')}</td>
      <td class="nt-val"><input data-field="nt_car_type"    class="nt-inp" type="text" value="\${E(v('nt_car_type'))}"></td>
      <td class="nt-lbl">\${BL('nt_vin')}</td>
      <td class="nt-val"><input data-field="nt_vin"         class="nt-inp" type="text" value="\${E(v('nt_vin'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_form')}</td>
      <td class="nt-val"><input data-field="nt_model_type"  class="nt-inp" type="text" value="\${E(v('nt_model_type'))}"></td>
      <td class="nt-lbl">\${BL('nt_eng_no')}</td>
      <td class="nt-val"><input data-field="nt_engine_no"   class="nt-inp" type="text" value="\${E(v('nt_engine_no'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_eng_type')}</td>
      <td class="nt-val"><input data-field="nt_engine_type" class="nt-inp" type="text" value="\${E(v('nt_engine_type'))}"></td>
      <td class="nt-lbl">\${BL('nt_max_power')}</td>
      <td class="nt-val"><input data-field="nt_max_power"   class="nt-inp" type="text" value="\${E(v('nt_max_power'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_chassis_type')}</td>
      <td class="nt-val"><input data-field="nt_chassis"     class="nt-inp" type="text" value="\${E(v('nt_chassis'))}"></td>
      <td class="nt-lbl">\${BL('nt_max_torque')}</td>
      <td class="nt-val"><input data-field="nt_max_torque"  class="nt-inp" type="text" value="\${E(v('nt_max_torque'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_displacement')}</td>
      <td class="nt-val"><input data-field="nt_disp_cc"     class="nt-inp" type="text" value="\${E(v('nt_disp_cc'))}"></td>
      <td class="nt-lbl">\${BL('nt_rpm_34')}</td>
      <td class="nt-val"><input data-field="nt_rpm_34"      class="nt-inp" type="text" value="\${E(v('nt_rpm_34'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_model_year')}</td>
      <td class="nt-val"><input data-field="nt_model_year"  class="nt-inp" type="text" value="\${E(v('nt_model_year'))}"></td>
      <td class="nt-lbl">\${BL('nt_rpm_12')}</td>
      <td class="nt-val"><input data-field="nt_rpm_12"      class="nt-inp" type="text" value="\${E(v('nt_rpm_12'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_trans_type')}</td>
      <td class="nt-val"><input data-field="nt_trans"       class="nt-inp" type="text" value="\${E(v('nt_trans'))}"></td>
      <td class="nt-lbl">\${BL('nt_eng_pos')}</td>
      <td class="nt-val"><input data-field="nt_eng_pos"     class="nt-inp" type="text" value="\${E(v('nt_eng_pos'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_gear_ratio')}</td>
      <td class="nt-val"><input data-field="nt_gear_ratio"  class="nt-inp" type="text" value="\${E(v('nt_gear_ratio'))}"></td>
      <td class="nt-lbl">\${BL('nt_axle_count')}</td>
      <td class="nt-val"><input data-field="nt_axles"       class="nt-inp" type="text" value="\${E(v('nt_axles'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_decel_ratio')}</td>
      <td class="nt-val"><input data-field="nt_final_ratio" class="nt-inp" type="text" value="\${E(v('nt_final_ratio'))}"></td>
      <td class="nt-lbl">\${BL('nt_drive_axle')}</td>
      <td class="nt-val"><input data-field="nt_drive_axles" class="nt-inp" type="text" value="\${E(v('nt_drive_axles'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_drive_shaft')}</td>
      <td class="nt-val"><input data-field="nt_drive_axle"  class="nt-inp" type="text" value="\${E(v('nt_drive_axle'))}"></td>
      <td class="nt-lbl">\${BL('nt_axle_ratio')}</td>
      <td class="nt-val"><input data-field="nt_axle_ratio"  class="nt-inp" type="text" value="\${E(v('nt_axle_ratio'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_curb_weight')}</td>
      <td class="nt-val"><input data-field="nt_curb_wt"     class="nt-inp" type="text" value="\${E(v('nt_curb_wt'))}"></td>
      <td class="nt-lbl">\${BL('nt_gvw')}</td>
      <td class="nt-val"><input data-field="nt_gvw"         class="nt-inp" type="text" value="\${E(v('nt_gvw'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_test_weight')}</td>
      <td class="nt-val"><input data-field="nt_test_wt"     class="nt-inp" type="text" value="\${E(v('nt_test_wt'))}"></td>
      <td class="nt-lbl">\${BL('nt_pmr')}</td>
      <td class="nt-val"><input data-field="nt_pmr"         class="nt-inp" type="text" value="\${E(v('nt_pmr'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_veh_length')}</td>
      <td class="nt-val"><input data-field="nt_length"      class="nt-inp" type="text" value="\${E(v('nt_length'))}"></td>
      <td class="nt-lbl">\${BL('nt_kp')}</td>
      <td class="nt-val"><input data-field="nt_kp"          class="nt-inp" type="text" value="\${E(v('nt_kp'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_drive_shaft')}</td>
      <td class="nt-val"><input data-field="nt_tire_radius" class="nt-inp" type="text" value="\${E(v('nt_tire_radius'))}"></td>
      <td class="nt-lbl">\${BL('nt_tire_pressure')}</td>
      <td class="nt-val"><input data-field="nt_tire_spec" class="nt-inp" type="text" value="\${E(v('nt_tire_spec'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_muffler_info')}</td>
      <td class="nt-val"><input data-field="nt_muffler" class="nt-inp" type="text" value="\${E(v('nt_muffler'))}"></td>
      <td class="nt-lbl">\${BL('nt_tire_pres_kpa')}</td>
      <td class="nt-val"><input data-field="nt_tire_pressure" class="nt-inp" type="text" value="\${E(v('nt_tire_pressure'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_auto_down')}</td>
      <td class="nt-val"><input data-field="nt_auto_downshift" class="nt-inp" type="text" value="\${E(v('nt_auto_downshift'))}"></td>
      <td class="nt-lbl">\${BL('nt_horn_type')}</td>
      <td class="nt-val"><input data-field="nt_horn"           class="nt-inp" type="text" value="\${E(v('nt_horn'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_etc')}</td>
      <td class="nt-val" colspan="3"><input data-field="nt_etc1" class="nt-inp" type="text" style="width:100%;" value="\${E(v('nt_etc1'))}"></td>
    </tr>
  </tbody>
</table>

<!-- 4. 시험장 주변조건 -->
<div class="nt-sec-title" style="margin-top:16px;">\${BL('nt_sec4')}</div>
<table class="nt-tbl">
  <colgroup>
    <col style="width:18%;"><col style="width:14%;"><col style="width:22%;"><col style="width:14%;">
  </colgroup>
  <thead>
    <tr>
      <th>\${BL('th_item')}</th>
      <th>\${BL('th_content')}</th>
      <th>\${BL('th_item')}</th>
      <th>\${BL('th_content')}</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="nt-lbl">\${BL('nt_place')}</td>
      <td class="nt-val"><input data-field="nt_site"     class="nt-inp" type="text" value="\${E(v('nt_site'))}"></td>
      <td class="nt-lbl">\${BL('nt_weather')}</td>
      <td class="nt-val"><input data-field="nt_weather"  class="nt-inp" type="text" value="\${E(v('nt_weather'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_wind_dir')}</td>
      <td class="nt-val"><input data-field="nt_wind_dir" class="nt-inp" type="text" value="\${E(v('nt_wind_dir'))}"></td>
      <td class="nt-lbl">\${BL('nt_wind_speed')}</td>
      <td class="nt-val"><input data-field="nt_wind_spd" class="nt-inp" type="text" value="\${E(v('nt_wind_spd'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_humidity')}</td>
      <td class="nt-val"><input data-field="nt_humidity" class="nt-inp" type="text" value="\${E(v('nt_humidity'))}"></td>
      <td class="nt-lbl">\${BL('nt_atm_pressure')}</td>
      <td class="nt-val"><input data-field="nt_pressure" class="nt-inp" type="text" value="\${E(v('nt_pressure'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_air_temp')}</td>
      <td class="nt-val"><input data-field="nt_temp"     class="nt-inp" type="text" value="\${E(v('nt_temp'))}"></td>
      <td class="nt-lbl">\${BL('nt_etc')}</td>
      <td class="nt-val"><input data-field="nt_env_etc"  class="nt-inp" type="text" value="\${E(v('nt_env_etc'))}"></td>
    </tr>
  </tbody>
</table>

<!-- 5. 소음측정장비 -->
<div class="nt-sec-title" style="margin-top:16px;">\${BL('nt_sec5')}</div>
<table class="nt-tbl">
  <colgroup>
    <col style="width:18%;"><col style="width:20%;"><col style="width:18%;"><col style="width:18%;"><col style="width:14%;">
  </colgroup>
  <thead>
    <tr>
      <th>\${BL('th_div')}</th><th>\${BL('g_maker')}</th><th>\${BL('nt_col_form')}</th><th>\${BL('nt_col_serial')}</th><th>\${BL('nt_col_cal_date')}</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="nt-lbl">\${BL('nt_sound_meter')}</td>
      <td class="nt-val"><input data-field="nt_eq1_maker" class="nt-inp" type="text" value="\${E(v('nt_eq1_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq1_type"  class="nt-inp" type="text" value="\${E(v('nt_eq1_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq1_no"    class="nt-inp" type="text" value="\${E(v('nt_eq1_no'))}"></td>
      <td class="nt-val"><input data-field="nt_eq1_cal"   class="nt-inp" type="text" value="\${E(v('nt_eq1_cal'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_calibrator')}</td>
      <td class="nt-val"><input data-field="nt_eq2_maker" class="nt-inp" type="text" value="\${E(v('nt_eq2_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq2_type"  class="nt-inp" type="text" value="\${E(v('nt_eq2_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq2_no"    class="nt-inp" type="text" value="\${E(v('nt_eq2_no'))}"></td>
      <td class="nt-val"><input data-field="nt_eq2_cal"   class="nt-inp" type="text" value="\${E(v('nt_eq2_cal'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_speedometer')}</td>
      <td class="nt-val"><input data-field="nt_eq3a_maker" class="nt-inp" type="text" value="\${E(v('nt_eq3a_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq3a_type"  class="nt-inp" type="text" value="\${E(v('nt_eq3a_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq3a_no"    class="nt-inp" type="text" value="\${E(v('nt_eq3a_no'))}"></td>
      <td class="nt-val"><input data-field="nt_eq3a_cal"   class="nt-inp" type="text" value="\${E(v('nt_eq3a_cal'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_rpm_meter')}</td>
      <td class="nt-val"><input data-field="nt_eq4_maker" class="nt-inp" type="text" value="\${E(v('nt_eq4_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq4_type"  class="nt-inp" type="text" value="\${E(v('nt_eq4_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq4_no"    class="nt-inp" type="text" value="\${E(v('nt_eq4_no'))}"></td>
      <td class="nt-val"><input data-field="nt_eq4_cal"   class="nt-inp" type="text" value="\${E(v('nt_eq4_cal'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_weather_eq')}</td>
      <td class="nt-val"><input data-field="nt_eq5a_maker" class="nt-inp" type="text" value="\${E(v('nt_eq5a_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq5a_type"  class="nt-inp" type="text" value="\${E(v('nt_eq5a_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq5a_no"    class="nt-inp" type="text" value="\${E(v('nt_eq5a_no'))}"></td>
      <td class="nt-val"><input data-field="nt_eq5a_cal"   class="nt-inp" type="text" value="\${E(v('nt_eq5a_cal'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_track')}</td>
      <td class="nt-val"><input data-field="nt_eq6_maker" class="nt-inp" type="text" value="\${E(v('nt_eq6_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq6_type"  class="nt-inp" type="text" value="\${E(v('nt_eq6_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq6_no"    class="nt-inp" type="text" value="\${E(v('nt_eq6_no'))}"></td>
      <td class="nt-lbl" style="text-align:center;">해당없음</td>
    </tr>
  </tbody>
</table>

<!-- 6. 가속주행소음 측정결과 -->
<!--
  PDF 분석 기반 정확한 컬럼 구조 (총 12컬럼):
  수직선 x: [55, 96, 136, 176, 217, 257, 313, 360, 395, 429, 468, 504, 540]
  col0(55-96)=사용변속기어  col1(96-136)=구분
  col2(136-176)=초기속도VAA  col3(176-217)=중간속도VPP
  col4(217-257)=탈출속도VBB  col5(257-313)=탈출엔진회전수NBB
  col6(313-360)=가속시작위치  col7(360-395)=좌측소음(가속)
  col8(395-429)=우측소음(가속)  col9(429-468)=가속도awot
  col10(468-504)=정속좌측소음  col11(504-540)=정속우측소음

  헤더 1행: 사용변속기어(rowspan=4, col0) + 구분(rowspan=4, col1)
            + 가속주행시험(colspan=8, col2~9) + 정속주행시험(colspan=2, col10~11)
  헤더 2~4행: 각 컬럼명/단위 (col2~11, 각각 단일 셀)
  
  데이터 행: 모든 셀 단일 셀 (col0~col11)
  평균 행: col1~col6 병합 "평균" + col7~col11 개별 입력
  
  시험결과 행: col0=시험결과 + col1~col4=가속주행소음라벨 + col5=값
              + col6~col9=정속주행소음라벨 + col10=값 + col11=LURBAN값
  최종결과 행: col0=최종결과 + col1~col5=L값 + col6~col7=기준치라벨 + col8~col11=기준값
              (수직선: [55,96,360,395,429,468,504,540])
-->
<div class="nt-sec-title" style="margin-top:18px;">\${BL('nt_sec6')}</div>
<div class="nt-sec-title" style="margin-top:12px; font-size:10pt;">\${BL('nt_sec6_1')}</div>
<table class="nt-tbl" style="table-layout:fixed;">
  <colgroup>
    <col style="width:8%;">   <!-- col0: 사용변속기어 -->
    <col style="width:7%;">   <!-- col1: 구분 -->
    <col style="width:8%;">   <!-- col2: 초기속도VAA -->
    <col style="width:8%;">   <!-- col3: 중간속도VPP -->
    <col style="width:8%;">   <!-- col4: 탈출속도VBB -->
    <col style="width:10%;">  <!-- col5: 탈출엔진회전수NBB -->
    <col style="width:9%;">   <!-- col6: 가속시작위치 -->
    <col style="width:7%;">   <!-- col7: 좌측소음(가속) -->
    <col style="width:7%;">   <!-- col8: 우측소음(가속) -->
    <col style="width:8%;">   <!-- col9: 가속도awot -->
    <col style="width:9%;">   <!-- col10: 정속좌측소음 -->
    <col style="width:9%;">   <!-- col11: 정속우측소음 -->
  </colgroup>
  <tbody>
    <!-- ① 상단 요약 4행 (수직선 없음 → 좌6칸/우6칸 균등 분할) -->
    <tr>
      <td class="nt-lbl" colspan="5">\${BL('nt_test_weight_kg')}</td>
      <td class="nt-val"><input data-field="nt_acc_test_wt" class="nt-inp" type="text" value="\${E(v('nt_acc_test_wt'))}"></td>
      <td class="nt-lbl" colspan="5">\${BL('nt_load_kg')}</td>
      <td class="nt-val"><input data-field="nt_acc_load_wt" class="nt-inp" type="text" value="\${E(v('nt_acc_load_wt'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl" colspan="5">\${BL('nt_gear_1')}</td>
      <td class="nt-val"><input data-field="nt_gear_i" class="nt-inp" type="text" value="\${E(v('nt_gear_i'))}"></td>
      <td class="nt-lbl" colspan="5">\${BL('nt_gear_2')}</td>
      <td class="nt-val"><input data-field="nt_gear_i1" class="nt-inp" type="text" value="\${E(v('nt_gear_i1'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl" colspan="5">\${BL('nt_a_urban')}</td>
      <td class="nt-val"><input data-field="nt_aurban" class="nt-inp" type="text" value="\${E(v('nt_aurban'))}"></td>
      <td class="nt-lbl" colspan="5">\${BL('nt_a_wotref')}</td>
      <td class="nt-val"><input data-field="nt_awotref" class="nt-inp" type="text" value="\${E(v('nt_awotref'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl" colspan="5">\${BL('nt_a_wot')}</td>
      <td class="nt-val"><input data-field="nt_awot_meas" class="nt-inp" type="text" value="\${E(v('nt_awot_meas'))}"></td>
      <td class="nt-lbl" colspan="3">\${BL('nt_kp_col')}</td>
      <td class="nt-val"><input data-field="nt_kp2" class="nt-inp" type="text" value="\${E(v('nt_kp2'))}"></td>
      <td class="nt-lbl">\${BL('nt_k_weight')}</td>
      <td class="nt-val"><input data-field="nt_k" class="nt-inp" type="text" value="\${E(v('nt_k'))}"></td>
    </tr>
    <!-- ② 헤더: 1행=가속/정속 구분, 2행=컬럼명, 3행=단위 (사용변속기어·구분은 rowspan=4) -->
    <tr>
      <th class="nt-th" rowspan="3">\${BL('nt_gear_used')}</th>
      <th class="nt-th" rowspan="3">\${BL('th_div')}</th>
      <th class="nt-th" colspan="8">\${BL('nt_accel_test')}</th>
      <th class="nt-th" colspan="2">\${BL('nt_const_test')}</th>
    </tr>
    <tr>
      <th class="nt-th">\${BL('nt_v_aa')}</th>
      <th class="nt-th">\${BL('nt_v_pp')}</th>
      <th class="nt-th">\${BL('nt_v_bb')}</th>
      <th class="nt-th">\${BL('nt_n_bb')}</th>
      <th class="nt-th">\${BL('nt_accel_start')}</th>
      <th class="nt-th">좌측<br>\${BL('sv_noise_simple')}</th>
      <th class="nt-th">우측<br>\${BL('sv_noise_simple')}</th>
      <th class="nt-th">\${BL('nt_accel_val')}</th>
      <th class="nt-th">좌측<br>\${BL('sv_noise_simple')}</th>
      <th class="nt-th">우측<br>\${BL('sv_noise_simple')}</th>
    </tr>
    <tr>
      <th class="nt-th">kph</th>
      <th class="nt-th">kph</th>
      <th class="nt-th">kph</th>
      <th class="nt-th">rpm</th>
      <th class="nt-th">m</th>
      <th class="nt-th">dB(A)</th>
      <th class="nt-th">dB(A)</th>
      <th class="nt-th">m/s²</th>
      <th class="nt-th">dB(A)</th>
      <th class="nt-th">dB(A)</th>
    </tr>
    <!-- ③ 기어 I - 1~4차 (정적 행, template literal 오류 방지) -->
    <tr>
      <td class="nt-lbl" rowspan="5" style="text-align:center;"><input data-field="nt_gear_sel1" class="nt-inp" type="text" style="width:100%;text-align:center;" value="\${E(v('nt_gear_sel1'))}"></td>
      <td class="nt-lbl">\${BL('nt_trial_1')}</td>
      <td class="nt-val"><input data-field="nt_g1_1_vaa" class="nt-inp" type="text" value="\${E(v('nt_g1_1_vaa'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_1_vpp" class="nt-inp" type="text" value="\${E(v('nt_g1_1_vpp'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_1_vbb" class="nt-inp" type="text" value="\${E(v('nt_g1_1_vbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_1_nbb" class="nt-inp" type="text" value="\${E(v('nt_g1_1_nbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_1_pos" class="nt-inp" type="text" value="\${E(v('nt_g1_1_pos'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_1_lL"  class="nt-inp" type="text" value="\${E(v('nt_g1_1_lL'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_1_lR"  class="nt-inp" type="text" value="\${E(v('nt_g1_1_lR'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_1_aw"  class="nt-inp" type="text" value="\${E(v('nt_g1_1_aw'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_1_cL"  class="nt-inp" type="text" value="\${E(v('nt_g1_1_cL'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_1_cR"  class="nt-inp" type="text" value="\${E(v('nt_g1_1_cR'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_trial_2')}</td>
      <td class="nt-val"><input data-field="nt_g1_2_vaa" class="nt-inp" type="text" value="\${E(v('nt_g1_2_vaa'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_2_vpp" class="nt-inp" type="text" value="\${E(v('nt_g1_2_vpp'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_2_vbb" class="nt-inp" type="text" value="\${E(v('nt_g1_2_vbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_2_nbb" class="nt-inp" type="text" value="\${E(v('nt_g1_2_nbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_2_pos" class="nt-inp" type="text" value="\${E(v('nt_g1_2_pos'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_2_lL"  class="nt-inp" type="text" value="\${E(v('nt_g1_2_lL'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_2_lR"  class="nt-inp" type="text" value="\${E(v('nt_g1_2_lR'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_2_aw"  class="nt-inp" type="text" value="\${E(v('nt_g1_2_aw'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_2_cL"  class="nt-inp" type="text" value="\${E(v('nt_g1_2_cL'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_2_cR"  class="nt-inp" type="text" value="\${E(v('nt_g1_2_cR'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_trial_3')}</td>
      <td class="nt-val"><input data-field="nt_g1_3_vaa" class="nt-inp" type="text" value="\${E(v('nt_g1_3_vaa'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_3_vpp" class="nt-inp" type="text" value="\${E(v('nt_g1_3_vpp'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_3_vbb" class="nt-inp" type="text" value="\${E(v('nt_g1_3_vbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_3_nbb" class="nt-inp" type="text" value="\${E(v('nt_g1_3_nbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_3_pos" class="nt-inp" type="text" value="\${E(v('nt_g1_3_pos'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_3_lL"  class="nt-inp" type="text" value="\${E(v('nt_g1_3_lL'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_3_lR"  class="nt-inp" type="text" value="\${E(v('nt_g1_3_lR'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_3_aw"  class="nt-inp" type="text" value="\${E(v('nt_g1_3_aw'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_3_cL"  class="nt-inp" type="text" value="\${E(v('nt_g1_3_cL'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_3_cR"  class="nt-inp" type="text" value="\${E(v('nt_g1_3_cR'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_trial_4')}</td>
      <td class="nt-val"><input data-field="nt_g1_4_vaa" class="nt-inp" type="text" value="\${E(v('nt_g1_4_vaa'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_4_vpp" class="nt-inp" type="text" value="\${E(v('nt_g1_4_vpp'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_4_vbb" class="nt-inp" type="text" value="\${E(v('nt_g1_4_vbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_4_nbb" class="nt-inp" type="text" value="\${E(v('nt_g1_4_nbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_4_pos" class="nt-inp" type="text" value="\${E(v('nt_g1_4_pos'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_4_lL"  class="nt-inp" type="text" value="\${E(v('nt_g1_4_lL'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_4_lR"  class="nt-inp" type="text" value="\${E(v('nt_g1_4_lR'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_4_aw"  class="nt-inp" type="text" value="\${E(v('nt_g1_4_aw'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_4_cL"  class="nt-inp" type="text" value="\${E(v('nt_g1_4_cL'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_4_cR"  class="nt-inp" type="text" value="\${E(v('nt_g1_4_cR'))}"></td>
    </tr>
    <!-- 기어 I 평균 행: col0은 rowspan=5로 이미 차지, col1~col6 병합 "평균" -->
    <tr>
      <td class="nt-lbl" colspan="6" style="text-align:center;">\${BL('nt_avg')}</td>
      <td class="nt-val"><input data-field="nt_g1_avg_lL" class="nt-inp" type="text" value="\${E(v('nt_g1_avg_lL'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_avg_lR" class="nt-inp" type="text" value="\${E(v('nt_g1_avg_lR'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_avg_aw" class="nt-inp" type="text" value="\${E(v('nt_g1_avg_aw'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_avg_cL" class="nt-inp" type="text" value="\${E(v('nt_g1_avg_cL'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_avg_cR" class="nt-inp" type="text" value="\${E(v('nt_g1_avg_cR'))}"></td>
    </tr>
    <!-- ④ 기어 I+1 - 1~4차 (정적 행) -->
    <tr>
      <td class="nt-lbl" rowspan="5" style="text-align:center;"><input data-field="nt_gear_sel2" class="nt-inp" type="text" style="width:100%;text-align:center;" value="\${E(v('nt_gear_sel2'))}"></td>
      <td class="nt-lbl">\${BL('nt_trial_1')}</td>
      <td class="nt-val"><input data-field="nt_g2_1_vaa" class="nt-inp" type="text" value="\${E(v('nt_g2_1_vaa'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_1_vpp" class="nt-inp" type="text" value="\${E(v('nt_g2_1_vpp'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_1_vbb" class="nt-inp" type="text" value="\${E(v('nt_g2_1_vbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_1_nbb" class="nt-inp" type="text" value="\${E(v('nt_g2_1_nbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_1_pos" class="nt-inp" type="text" value="\${E(v('nt_g2_1_pos'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_1_lL"  class="nt-inp" type="text" value="\${E(v('nt_g2_1_lL'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_1_lR"  class="nt-inp" type="text" value="\${E(v('nt_g2_1_lR'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_1_aw"  class="nt-inp" type="text" value="\${E(v('nt_g2_1_aw'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_1_cL"  class="nt-inp" type="text" value="\${E(v('nt_g2_1_cL'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_1_cR"  class="nt-inp" type="text" value="\${E(v('nt_g2_1_cR'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_trial_2')}</td>
      <td class="nt-val"><input data-field="nt_g2_2_vaa" class="nt-inp" type="text" value="\${E(v('nt_g2_2_vaa'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_2_vpp" class="nt-inp" type="text" value="\${E(v('nt_g2_2_vpp'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_2_vbb" class="nt-inp" type="text" value="\${E(v('nt_g2_2_vbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_2_nbb" class="nt-inp" type="text" value="\${E(v('nt_g2_2_nbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_2_pos" class="nt-inp" type="text" value="\${E(v('nt_g2_2_pos'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_2_lL"  class="nt-inp" type="text" value="\${E(v('nt_g2_2_lL'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_2_lR"  class="nt-inp" type="text" value="\${E(v('nt_g2_2_lR'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_2_aw"  class="nt-inp" type="text" value="\${E(v('nt_g2_2_aw'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_2_cL"  class="nt-inp" type="text" value="\${E(v('nt_g2_2_cL'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_2_cR"  class="nt-inp" type="text" value="\${E(v('nt_g2_2_cR'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_trial_3')}</td>
      <td class="nt-val"><input data-field="nt_g2_3_vaa" class="nt-inp" type="text" value="\${E(v('nt_g2_3_vaa'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_3_vpp" class="nt-inp" type="text" value="\${E(v('nt_g2_3_vpp'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_3_vbb" class="nt-inp" type="text" value="\${E(v('nt_g2_3_vbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_3_nbb" class="nt-inp" type="text" value="\${E(v('nt_g2_3_nbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_3_pos" class="nt-inp" type="text" value="\${E(v('nt_g2_3_pos'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_3_lL"  class="nt-inp" type="text" value="\${E(v('nt_g2_3_lL'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_3_lR"  class="nt-inp" type="text" value="\${E(v('nt_g2_3_lR'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_3_aw"  class="nt-inp" type="text" value="\${E(v('nt_g2_3_aw'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_3_cL"  class="nt-inp" type="text" value="\${E(v('nt_g2_3_cL'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_3_cR"  class="nt-inp" type="text" value="\${E(v('nt_g2_3_cR'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">\${BL('nt_trial_4')}</td>
      <td class="nt-val"><input data-field="nt_g2_4_vaa" class="nt-inp" type="text" value="\${E(v('nt_g2_4_vaa'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_4_vpp" class="nt-inp" type="text" value="\${E(v('nt_g2_4_vpp'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_4_vbb" class="nt-inp" type="text" value="\${E(v('nt_g2_4_vbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_4_nbb" class="nt-inp" type="text" value="\${E(v('nt_g2_4_nbb'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_4_pos" class="nt-inp" type="text" value="\${E(v('nt_g2_4_pos'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_4_lL"  class="nt-inp" type="text" value="\${E(v('nt_g2_4_lL'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_4_lR"  class="nt-inp" type="text" value="\${E(v('nt_g2_4_lR'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_4_aw"  class="nt-inp" type="text" value="\${E(v('nt_g2_4_aw'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_4_cL"  class="nt-inp" type="text" value="\${E(v('nt_g2_4_cL'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_4_cR"  class="nt-inp" type="text" value="\${E(v('nt_g2_4_cR'))}"></td>
    </tr>
    <!-- 기어 I+1 평균 행: col0은 rowspan=5로 이미 차지, col1~col6 병합 "평균" -->
    <tr>
      <td class="nt-lbl" colspan="6" style="text-align:center;">\${BL('nt_avg')}</td>
      <td class="nt-val"><input data-field="nt_g2_avg_lL" class="nt-inp" type="text" value="\${E(v('nt_g2_avg_lL'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_avg_lR" class="nt-inp" type="text" value="\${E(v('nt_g2_avg_lR'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_avg_aw" class="nt-inp" type="text" value="\${E(v('nt_g2_avg_aw'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_avg_cL" class="nt-inp" type="text" value="\${E(v('nt_g2_avg_cL'))}"></td>
      <td class="nt-val"><input data-field="nt_g2_avg_cR" class="nt-inp" type="text" value="\${E(v('nt_g2_avg_cR'))}"></td>
    </tr>
    <!-- ⑤ 시험결과 행 — PDF 이미지 직접 확인 기준
         헤더: col0=사용변속기어, col1=구분, col2~9=가속주행시험(8칸), col10~11=정속주행시험(2칸)
         시험결과행 셀 구조:
           col0       (1칸) : 시험결과 라벨
           col1~3     (3칸) : 가속주행소음 (L_WOTrep, dB(A)) 라벨
           col4       (1칸) : nt_lwot 값 입력
           col5~7     (3칸) : 정속주행소음 (L_CRSrep, dB(A)) 라벨  ← 3칸
           col8       (1칸) : nt_lcrs 값 입력
           col9~10    (2칸) : (L_URBAN, dB(A)) 라벨
           col11      (1칸) : nt_lurban 값 입력
    -->
    <tr>
      <td class="nt-lbl" style="text-align:center;">\${BL('nt_test_result')}</td>
      <td class="nt-lbl" colspan="3" style="text-align:center; line-height:1.5;">가속주행소음<br>(L<sub>WOTrep</sub>, dB(A))</td>
      <td class="nt-val"><input data-field="nt_lwot" class="nt-inp" type="text" value="\${E(v('nt_lwot'))}"></td>
      <td class="nt-lbl" colspan="3" style="text-align:center; line-height:1.5;">정속주행소음<br>(L<sub>CRSrep</sub>, dB(A))</td>
      <td class="nt-val"><input data-field="nt_lcrs" class="nt-inp" type="text" value="\${E(v('nt_lcrs'))}"></td>
      <td class="nt-lbl" colspan="2" style="text-align:center; line-height:1.5;">(L<sub>URBAN</sub>, dB(A))</td>
      <td class="nt-val"><input data-field="nt_lurban" class="nt-inp" type="text" value="\${E(v('nt_lurban'))}"></td>
    </tr>
    <!-- ⑥ 최종결과 행 — PDF 이미지 직접 확인 기준
         최종결과행 셀 구조:
           col0       (1칸) : 최종결과 라벨
           col1~3     (3칸) : L (dB(A)) 라벨
           col4       (1칸) : nt_final_L 값 입력
           col5~7     (3칸) : 빈칸  ← 정속주행소음 라벨 위치와 동일
           col8~10    (3칸) : 기준치 (dB(A)) 라벨  ← 정속주행시험 좌측소음 위치에 걸침
           col11      (1칸) : nt_limit 값 입력     ← 정속주행시험 우측소음 위치
    -->
    <tr>
      <td class="nt-lbl" style="text-align:center;">\${BL('nt_final_result')}</td>
      <td class="nt-lbl" colspan="3" style="text-align:center;">L (dB(A))</td>
      <td class="nt-val" colspan="4"><input data-field="nt_final_L" class="nt-inp" type="text" value="\${E(v('nt_final_L'))}"></td>
      <td class="nt-lbl" colspan="3" style="text-align:center;">\${BL('nt_std_val')}</td>
      <td class="nt-val"><input data-field="nt_limit" class="nt-inp" type="text" value="\${E(v('nt_limit'))}"></td>
    </tr>
  </tbody>
</table>


<!-- 6.2. KSAISO 362 가속주행소음 측정결과 -->
<div class="nt-sec-title" style="margin-top:16px;">\${BL('nt_sec6_2')}</div>
<table class="nt-tbl" style="table-layout:fixed;">
  <colgroup>
    <col style="width:7%;">   <!-- 구분 -->
    <col style="width:7%;">   <!-- 사용변속기어 -->
    <col style="width:8%;">   <!-- 진입지정차속 -->
    <col style="width:6%;">   <!-- 시험차속 가속초기 -->
    <col style="width:6%;">   <!-- 시험차속 가속종료 -->
    <col style="width:6%;">   <!-- 엔진회전수 가속초기 -->
    <col style="width:6%;">   <!-- 엔진회전수 가속종료 -->
    <col style="width:7%;">   <!-- 가속시작위치 -->
    <col style="width:8%;">   <!-- 암소음 -->
    <col style="width:8%;">   <!-- 측정소음 좌측 -->
    <col style="width:8%;">   <!-- 측정소음 우측 -->
    <col style="width:8%;">   <!-- 보정치 -->
    <col style="width:11%;">  <!-- 기준치 -->
  </colgroup>
  <thead>
    <tr>
      <th rowspan="3">구 분</th>
      <th rowspan="3">사용<br>변속<br>기어</th>
      <th rowspan="3">진입<br>지정<br>차속<br>(km/hr)</th>
      <th colspan="2">시험차속<br>(km/hr.)</th>
      <th colspan="2">엔진회전수<br>(rpm)</th>
      <th rowspan="3">가속<br>시작<br>위치<br>(m)</th>
      <th rowspan="3">암소음<br>[dB<br>(A)]</th>
      <th colspan="2">측정소음<br>[dB(A)]</th>
      <th rowspan="3">보정<br>치<br>[dB<br>(A)]</th>
      <th rowspan="3">기준치<br>[dB<br>(A)]</th>
    </tr>
    <tr>
      <th>가속<br>초기</th>
      <th>가속<br>종료</th>
      <th>가속<br>초기</th>
      <th>가속<br>종료</th>
      <th>좌측</th>
      <th>우측</th>
    </tr>
  </thead>
  <tbody>
    <!-- 세트1: 1~4차시험 + 평균 + 결과 -->
    <tr>
      <td class="nt-lbl">1차시험</td>
      <td class="nt-val"><input data-field="ks_s1_1_gear" class="nt-inp" type="text" value="\${E(v('ks_s1_1_gear'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_1_entry" class="nt-inp" type="text" value="\${E(v('ks_s1_1_entry'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_1_vs0" class="nt-inp" type="text" value="\${E(v('ks_s1_1_vs0'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_1_vs1" class="nt-inp" type="text" value="\${E(v('ks_s1_1_vs1'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_1_ne0" class="nt-inp" type="text" value="\${E(v('ks_s1_1_ne0'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_1_ne1" class="nt-inp" type="text" value="\${E(v('ks_s1_1_ne1'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_1_pos" class="nt-inp" type="text" value="\${E(v('ks_s1_1_pos'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_1_amb" class="nt-inp" type="text" value="\${E(v('ks_s1_1_amb'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_1_lL" class="nt-inp" type="text" value="\${E(v('ks_s1_1_lL'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_1_lR" class="nt-inp" type="text" value="\${E(v('ks_s1_1_lR'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_1_corr" class="nt-inp" type="text" value="\${E(v('ks_s1_1_corr'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_1_limit" class="nt-inp" type="text" value="\${E(v('ks_s1_1_limit'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">2차시험</td>
      <td class="nt-val"><input data-field="ks_s1_2_gear" class="nt-inp" type="text" value="\${E(v('ks_s1_2_gear'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_2_entry" class="nt-inp" type="text" value="\${E(v('ks_s1_2_entry'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_2_vs0" class="nt-inp" type="text" value="\${E(v('ks_s1_2_vs0'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_2_vs1" class="nt-inp" type="text" value="\${E(v('ks_s1_2_vs1'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_2_ne0" class="nt-inp" type="text" value="\${E(v('ks_s1_2_ne0'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_2_ne1" class="nt-inp" type="text" value="\${E(v('ks_s1_2_ne1'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_2_pos" class="nt-inp" type="text" value="\${E(v('ks_s1_2_pos'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_2_amb" class="nt-inp" type="text" value="\${E(v('ks_s1_2_amb'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_2_lL" class="nt-inp" type="text" value="\${E(v('ks_s1_2_lL'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_2_lR" class="nt-inp" type="text" value="\${E(v('ks_s1_2_lR'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_2_corr" class="nt-inp" type="text" value="\${E(v('ks_s1_2_corr'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_2_limit" class="nt-inp" type="text" value="\${E(v('ks_s1_2_limit'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">3차시험</td>
      <td class="nt-val"><input data-field="ks_s1_3_gear" class="nt-inp" type="text" value="\${E(v('ks_s1_3_gear'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_3_entry" class="nt-inp" type="text" value="\${E(v('ks_s1_3_entry'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_3_vs0" class="nt-inp" type="text" value="\${E(v('ks_s1_3_vs0'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_3_vs1" class="nt-inp" type="text" value="\${E(v('ks_s1_3_vs1'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_3_ne0" class="nt-inp" type="text" value="\${E(v('ks_s1_3_ne0'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_3_ne1" class="nt-inp" type="text" value="\${E(v('ks_s1_3_ne1'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_3_pos" class="nt-inp" type="text" value="\${E(v('ks_s1_3_pos'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_3_amb" class="nt-inp" type="text" value="\${E(v('ks_s1_3_amb'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_3_lL" class="nt-inp" type="text" value="\${E(v('ks_s1_3_lL'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_3_lR" class="nt-inp" type="text" value="\${E(v('ks_s1_3_lR'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_3_corr" class="nt-inp" type="text" value="\${E(v('ks_s1_3_corr'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_3_limit" class="nt-inp" type="text" value="\${E(v('ks_s1_3_limit'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">4차시험</td>
      <td class="nt-val"><input data-field="ks_s1_4_gear" class="nt-inp" type="text" value="\${E(v('ks_s1_4_gear'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_4_entry" class="nt-inp" type="text" value="\${E(v('ks_s1_4_entry'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_4_vs0" class="nt-inp" type="text" value="\${E(v('ks_s1_4_vs0'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_4_vs1" class="nt-inp" type="text" value="\${E(v('ks_s1_4_vs1'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_4_ne0" class="nt-inp" type="text" value="\${E(v('ks_s1_4_ne0'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_4_ne1" class="nt-inp" type="text" value="\${E(v('ks_s1_4_ne1'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_4_pos" class="nt-inp" type="text" value="\${E(v('ks_s1_4_pos'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_4_amb" class="nt-inp" type="text" value="\${E(v('ks_s1_4_amb'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_4_lL" class="nt-inp" type="text" value="\${E(v('ks_s1_4_lL'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_4_lR" class="nt-inp" type="text" value="\${E(v('ks_s1_4_lR'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_4_corr" class="nt-inp" type="text" value="\${E(v('ks_s1_4_corr'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_4_limit" class="nt-inp" type="text" value="\${E(v('ks_s1_4_limit'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl" style="text-align:center;">평 균</td>
      <td class="nt-val"><input data-field="ks_s1_avg_gear" class="nt-inp" type="text" value="\${E(v('ks_s1_avg_gear'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_avg_entry" class="nt-inp" type="text" value="\${E(v('ks_s1_avg_entry'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_avg_vs0" class="nt-inp" type="text" value="\${E(v('ks_s1_avg_vs0'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_avg_vs1" class="nt-inp" type="text" value="\${E(v('ks_s1_avg_vs1'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_avg_ne0" class="nt-inp" type="text" value="\${E(v('ks_s1_avg_ne0'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_avg_ne1" class="nt-inp" type="text" value="\${E(v('ks_s1_avg_ne1'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_avg_pos" class="nt-inp" type="text" value="\${E(v('ks_s1_avg_pos'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_avg_amb" class="nt-inp" type="text" value="\${E(v('ks_s1_avg_amb'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_avg_lL" class="nt-inp" type="text" value="\${E(v('ks_s1_avg_lL'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_avg_lR" class="nt-inp" type="text" value="\${E(v('ks_s1_avg_lR'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_avg_corr" class="nt-inp" type="text" value="\${E(v('ks_s1_avg_corr'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_avg_limit" class="nt-inp" type="text" value="\${E(v('ks_s1_avg_limit'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl" style="text-align:center;">결 과</td>
      <td class="nt-val" colspan="7"><input data-field="ks_s1_res_note" class="nt-inp" type="text" style="width:100%;" value="\${E(v('ks_s1_res_note'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_res_amb" class="nt-inp" type="text" value="\${E(v('ks_s1_res_amb'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_res_lL" class="nt-inp" type="text" value="\${E(v('ks_s1_res_lL'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_res_lR" class="nt-inp" type="text" value="\${E(v('ks_s1_res_lR'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_res_corr" class="nt-inp" type="text" value="\${E(v('ks_s1_res_corr'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_res_limit" class="nt-inp" type="text" value="\${E(v('ks_s1_res_limit'))}"></td>
    </tr>
    <!-- 세트2: 1~4차시험 + 평균 + 결과 -->
    <tr>
      <td class="nt-lbl">1차시험</td>
      <td class="nt-val"><input data-field="ks_s2_1_gear" class="nt-inp" type="text" value="\${E(v('ks_s2_1_gear'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_1_entry" class="nt-inp" type="text" value="\${E(v('ks_s2_1_entry'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_1_vs0" class="nt-inp" type="text" value="\${E(v('ks_s2_1_vs0'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_1_vs1" class="nt-inp" type="text" value="\${E(v('ks_s2_1_vs1'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_1_ne0" class="nt-inp" type="text" value="\${E(v('ks_s2_1_ne0'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_1_ne1" class="nt-inp" type="text" value="\${E(v('ks_s2_1_ne1'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_1_pos" class="nt-inp" type="text" value="\${E(v('ks_s2_1_pos'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_1_amb" class="nt-inp" type="text" value="\${E(v('ks_s2_1_amb'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_1_lL" class="nt-inp" type="text" value="\${E(v('ks_s2_1_lL'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_1_lR" class="nt-inp" type="text" value="\${E(v('ks_s2_1_lR'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_1_corr" class="nt-inp" type="text" value="\${E(v('ks_s2_1_corr'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_1_limit" class="nt-inp" type="text" value="\${E(v('ks_s2_1_limit'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">2차시험</td>
      <td class="nt-val"><input data-field="ks_s2_2_gear" class="nt-inp" type="text" value="\${E(v('ks_s2_2_gear'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_2_entry" class="nt-inp" type="text" value="\${E(v('ks_s2_2_entry'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_2_vs0" class="nt-inp" type="text" value="\${E(v('ks_s2_2_vs0'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_2_vs1" class="nt-inp" type="text" value="\${E(v('ks_s2_2_vs1'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_2_ne0" class="nt-inp" type="text" value="\${E(v('ks_s2_2_ne0'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_2_ne1" class="nt-inp" type="text" value="\${E(v('ks_s2_2_ne1'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_2_pos" class="nt-inp" type="text" value="\${E(v('ks_s2_2_pos'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_2_amb" class="nt-inp" type="text" value="\${E(v('ks_s2_2_amb'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_2_lL" class="nt-inp" type="text" value="\${E(v('ks_s2_2_lL'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_2_lR" class="nt-inp" type="text" value="\${E(v('ks_s2_2_lR'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_2_corr" class="nt-inp" type="text" value="\${E(v('ks_s2_2_corr'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_2_limit" class="nt-inp" type="text" value="\${E(v('ks_s2_2_limit'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">3차시험</td>
      <td class="nt-val"><input data-field="ks_s2_3_gear" class="nt-inp" type="text" value="\${E(v('ks_s2_3_gear'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_3_entry" class="nt-inp" type="text" value="\${E(v('ks_s2_3_entry'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_3_vs0" class="nt-inp" type="text" value="\${E(v('ks_s2_3_vs0'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_3_vs1" class="nt-inp" type="text" value="\${E(v('ks_s2_3_vs1'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_3_ne0" class="nt-inp" type="text" value="\${E(v('ks_s2_3_ne0'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_3_ne1" class="nt-inp" type="text" value="\${E(v('ks_s2_3_ne1'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_3_pos" class="nt-inp" type="text" value="\${E(v('ks_s2_3_pos'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_3_amb" class="nt-inp" type="text" value="\${E(v('ks_s2_3_amb'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_3_lL" class="nt-inp" type="text" value="\${E(v('ks_s2_3_lL'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_3_lR" class="nt-inp" type="text" value="\${E(v('ks_s2_3_lR'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_3_corr" class="nt-inp" type="text" value="\${E(v('ks_s2_3_corr'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_3_limit" class="nt-inp" type="text" value="\${E(v('ks_s2_3_limit'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">4차시험</td>
      <td class="nt-val"><input data-field="ks_s2_4_gear" class="nt-inp" type="text" value="\${E(v('ks_s2_4_gear'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_4_entry" class="nt-inp" type="text" value="\${E(v('ks_s2_4_entry'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_4_vs0" class="nt-inp" type="text" value="\${E(v('ks_s2_4_vs0'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_4_vs1" class="nt-inp" type="text" value="\${E(v('ks_s2_4_vs1'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_4_ne0" class="nt-inp" type="text" value="\${E(v('ks_s2_4_ne0'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_4_ne1" class="nt-inp" type="text" value="\${E(v('ks_s2_4_ne1'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_4_pos" class="nt-inp" type="text" value="\${E(v('ks_s2_4_pos'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_4_amb" class="nt-inp" type="text" value="\${E(v('ks_s2_4_amb'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_4_lL" class="nt-inp" type="text" value="\${E(v('ks_s2_4_lL'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_4_lR" class="nt-inp" type="text" value="\${E(v('ks_s2_4_lR'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_4_corr" class="nt-inp" type="text" value="\${E(v('ks_s2_4_corr'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_4_limit" class="nt-inp" type="text" value="\${E(v('ks_s2_4_limit'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl" style="text-align:center;">평 균</td>
      <td class="nt-val"><input data-field="ks_s2_avg_gear" class="nt-inp" type="text" value="\${E(v('ks_s2_avg_gear'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_avg_entry" class="nt-inp" type="text" value="\${E(v('ks_s2_avg_entry'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_avg_vs0" class="nt-inp" type="text" value="\${E(v('ks_s2_avg_vs0'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_avg_vs1" class="nt-inp" type="text" value="\${E(v('ks_s2_avg_vs1'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_avg_ne0" class="nt-inp" type="text" value="\${E(v('ks_s2_avg_ne0'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_avg_ne1" class="nt-inp" type="text" value="\${E(v('ks_s2_avg_ne1'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_avg_pos" class="nt-inp" type="text" value="\${E(v('ks_s2_avg_pos'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_avg_amb" class="nt-inp" type="text" value="\${E(v('ks_s2_avg_amb'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_avg_lL" class="nt-inp" type="text" value="\${E(v('ks_s2_avg_lL'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_avg_lR" class="nt-inp" type="text" value="\${E(v('ks_s2_avg_lR'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_avg_corr" class="nt-inp" type="text" value="\${E(v('ks_s2_avg_corr'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_avg_limit" class="nt-inp" type="text" value="\${E(v('ks_s2_avg_limit'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl" style="text-align:center;">결 과</td>
      <td class="nt-val" colspan="7"><input data-field="ks_s2_res_note" class="nt-inp" type="text" style="width:100%;" value="\${E(v('ks_s2_res_note'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_res_amb" class="nt-inp" type="text" value="\${E(v('ks_s2_res_amb'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_res_lL" class="nt-inp" type="text" value="\${E(v('ks_s2_res_lL'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_res_lR" class="nt-inp" type="text" value="\${E(v('ks_s2_res_lR'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_res_corr" class="nt-inp" type="text" value="\${E(v('ks_s2_res_corr'))}"></td>
      <td class="nt-val"><input data-field="ks_s2_res_limit" class="nt-inp" type="text" value="\${E(v('ks_s2_res_limit'))}"></td>
    </tr>
  </tbody>
</table>

<!-- 7. 배기소음측정결과 -->
<div class="nt-sec-title" style="margin-top:16px;">\${BL('nt_sec7')}</div>
<table class="nt-tbl">
  <colgroup>
    <col style="width:8%;"><col style="width:8%;"><col style="width:18%;"><col style="width:12%;"><col style="width:12%;"><col style="width:12%;"><col style="width:12%;"><col style="width:12%;">
  </colgroup>
  <thead>
    <tr>
      <th rowspan="5">배기<br>\${BL('sv_noise_simple')}<br>시험</th>
      <th rowspan="2">\${BL('nt_meas_count')}</th>
      <th rowspan="2" style="line-height:1.8;">원동기 최고 출력<br>회전속도의<br><input data-field="nt_ex_pct" class="nt-inp" type="text" style="width:3.5em;text-align:center;border-bottom:1px solid #888;" value="\${E(v('nt_ex_pct'))}">% 회전속도(rpm)</th>
      <th rowspan="2">\${BL('nt_bg_noise_a')}</th>
      <th colspan="2">\${BL('nt_exhaust_noise_val')}</th>
      <th rowspan="2">\${BL('nt_score_a')}</th>
      <th rowspan="2">\${BL('nt_std_a')}</th>
    </tr>
    <tr>
      <th>\${BL('nt_measured')}</th><th>\${BL('nt_corrected')}</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="nt-lbl">1</td>
      <td class="nt-val"><input data-field="nt_ex1_rpm"  class="nt-inp" type="text" value="\${E(v('nt_ex1_rpm'))}"></td>
      <td class="nt-val"><input data-field="nt_ex1_amb"  class="nt-inp" type="text" value="\${E(v('nt_ex1_amb'))}"></td>
      <td class="nt-val"><input data-field="nt_ex1_meas" class="nt-inp" type="text" value="\${E(v('nt_ex1_meas'))}"></td>
      <td class="nt-val"><input data-field="nt_ex1_corr" class="nt-inp" type="text" value="\${E(v('nt_ex1_corr'))}"></td>
      <td class="nt-val" rowspan="3"><input data-field="nt_ex_score" class="nt-inp" type="text" value="\${E(v('nt_ex_score'))}"></td>
      <td class="nt-val" rowspan="3"><input data-field="nt_ex_limit" class="nt-inp" type="text" value="\${E(v('nt_ex_limit'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">2</td>
      <td class="nt-val"><input data-field="nt_ex2_rpm"  class="nt-inp" type="text" value="\${E(v('nt_ex2_rpm'))}"></td>
      <td class="nt-val"><input data-field="nt_ex2_amb"  class="nt-inp" type="text" value="\${E(v('nt_ex2_amb'))}"></td>
      <td class="nt-val"><input data-field="nt_ex2_meas" class="nt-inp" type="text" value="\${E(v('nt_ex2_meas'))}"></td>
      <td class="nt-val"><input data-field="nt_ex2_corr" class="nt-inp" type="text" value="\${E(v('nt_ex2_corr'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">3</td>
      <td class="nt-val"><input data-field="nt_ex3_rpm"  class="nt-inp" type="text" value="\${E(v('nt_ex3_rpm'))}"></td>
      <td class="nt-val"><input data-field="nt_ex3_amb"  class="nt-inp" type="text" value="\${E(v('nt_ex3_amb'))}"></td>
      <td class="nt-val"><input data-field="nt_ex3_meas" class="nt-inp" type="text" value="\${E(v('nt_ex3_meas'))}"></td>
      <td class="nt-val"><input data-field="nt_ex3_corr" class="nt-inp" type="text" value="\${E(v('nt_ex3_corr'))}"></td>
    </tr>
  </tbody>
</table>

<!-- 8. 경적소음측정결과 -->
<div class="nt-sec-title" style="margin-top:16px;">\${BL('nt_sec8')}</div>
<table class="nt-tbl">
  <colgroup>
    <col style="width:8%;"><col style="width:10%;"><col style="width:12%;"><col style="width:10%;"><col style="width:12%;"><col style="width:12%;"><col style="width:12%;"><col style="width:12%;"><col style="width:10%;">
  </colgroup>
  <thead>
    <tr>
      <th rowspan="4">경적<br>\${BL('sv_noise_simple')}<br>시험</th>
      <th rowspan="2">\${BL('nt_meas_count')}</th>
      <th rowspan="2">\${BL('nt_horn_form')}</th>
      <th rowspan="2">\${BL('nt_horn_count')}</th>
      <th rowspan="2">\${BL('nt_bg_noise_c')}</th>
      <th colspan="2">\${BL('nt_horn_noise_val')}</th>
      <th rowspan="2">\${BL('nt_score_c')}</th>
      <th rowspan="2">\${BL('nt_std_c')}</th>
    </tr>
    <tr>
      <th>\${BL('nt_measured')}</th><th>\${BL('nt_corrected')}</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="nt-lbl">1</td>
      <td class="nt-val"><input data-field="nt_horn1_type" class="nt-inp" type="text" value="\${E(v('nt_horn1_type'))}"></td>
      <td class="nt-val"><input data-field="nt_horn1_cnt"  class="nt-inp" type="text" value="\${E(v('nt_horn1_cnt'))}"></td>
      <td class="nt-val"><input data-field="nt_horn1_amb"  class="nt-inp" type="text" value="\${E(v('nt_horn1_amb'))}"></td>
      <td class="nt-val"><input data-field="nt_horn1_meas" class="nt-inp" type="text" value="\${E(v('nt_horn1_meas'))}"></td>
      <td class="nt-val"><input data-field="nt_horn1_corr" class="nt-inp" type="text" value="\${E(v('nt_horn1_corr'))}"></td>
      <td class="nt-val" rowspan="2"><input data-field="nt_horn_score" class="nt-inp" type="text" value="\${E(v('nt_horn_score'))}"></td>
      <td class="nt-val" rowspan="2"><input data-field="nt_horn_limit" class="nt-inp" type="text" value="\${E(v('nt_horn_limit'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">2</td>
      <td class="nt-val"><input data-field="nt_horn2_type" class="nt-inp" type="text" value="\${E(v('nt_horn2_type'))}"></td>
      <td class="nt-val"><input data-field="nt_horn2_cnt"  class="nt-inp" type="text" value="\${E(v('nt_horn2_cnt'))}"></td>
      <td class="nt-val"><input data-field="nt_horn2_amb"  class="nt-inp" type="text" value="\${E(v('nt_horn2_amb'))}"></td>
      <td class="nt-val"><input data-field="nt_horn2_meas" class="nt-inp" type="text" value="\${E(v('nt_horn2_meas'))}"></td>
      <td class="nt-val"><input data-field="nt_horn2_corr" class="nt-inp" type="text" value="\${E(v('nt_horn2_corr'))}"></td>
    </tr>
  </tbody>
</table>

<!-- 검사담당자 / 확인자 -->
<div class="nt-sign-row" style="margin-top:14px;">
  <div class="nt-sign-item">
    <span class="nt-sign-lbl">\${BL('nt_tester')}:</span>
    <input data-field="nt_inspector" class="nt-sign-inp" type="text" placeholder="성명" value="\${E(v('nt_inspector'))}">
  </div>
  <div class="nt-sign-item">
    <span class="nt-sign-lbl">\${BL('nt_verifier')}:</span>
    <input data-field="nt_confirmer" class="nt-sign-inp" type="text" placeholder="성명" value="\${E(v('nt_confirmer'))}">
  </div>
</div>

<!-- 첨부문서 업로드/다운로드 (인쇄 제외) -->
<div class="nt-attach-section no-print">
  <div class="nt-attach-title"><i class="fas fa-paperclip"></i> 첨부문서 (자체시험성적서 / RAW DATA)</div>
  <div class="nt-attach-note">이미지(JPG, PNG) 또는 PDF 파일을 업로드하세요. 첨부파일은 인쇄 시 출력되지 않습니다.</div>
  <div class="nt-attach-drop" id="nt-drop-zone" onclick="document.getElementById('nt-file-input').click()">
    <input type="file" id="nt-file-input" multiple accept="image/*,.pdf">
    <i class="fas fa-cloud-upload-alt" style="font-size:20pt;margin-bottom:6px;display:block;"></i>
    클릭하거나 파일을 드래그하여 업로드
  </div>
  <div class="nt-attach-list" id="nt-attach-list"></div>
  <input type="hidden" id="nt-attach-data" data-field="nt_attach_data" value="\${E(v('nt_attach_data'))}">
</div>

</div>

<div id="qr-footer-wrap" style="margin-top:12px;"></div>

\`;

  if (formType==='confirmation') return \`
<style>
/* ══════════ confirmation 전용 스타일 ══════════ */
.en-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
  background:#fff;
  color:#111;
  border-radius:8px;
}
.en-doc-tag { font-size:8.5pt; font-weight:700; color:#444; margin:10px 0 4px; }
.en-main-title {
  font-size:13pt; font-weight:900; text-align:center;
  margin:4px 0 14px; letter-spacing:.03em; color:#111;
}
.en-tbl {
  width:100%; border-collapse:collapse;
  font-size:8.5pt; margin-bottom:0;
}
.en-tbl th, .en-tbl td {
  border:1px solid #888;
  padding:3px 5px;
  vertical-align:middle;
  color:#111;
}
.en-sec-th {
  background:#d6e4f7;
  font-weight:700; text-align:left;
  padding:4px 6px; font-size:8.5pt; color:#111;
}
.en-sub-th {
  background:#eef3fa;
  font-weight:700; text-align:left;
  padding:3px 6px; font-size:8.5pt; color:#111;
}
.en-th {
  background:#eef3fa;
  font-weight:600; text-align:center;
  font-size:8pt; color:#111;
}
.en-lbl {
  background:#f5f8ff;
  font-weight:600; color:#111;
  vertical-align:middle;
}
/* ── 복합 입력 필드 (텍스트 + 이미지) ── */
.en-field {
  display:flex; flex-direction:column; gap:4px;
  padding:3px 4px; box-sizing:border-box; width:100%;
}
.en-field-text {
  width:100%; font-size:8.5pt; font-family:inherit;
  border:none; background:transparent; padding:2px 0;
  box-sizing:border-box; resize:vertical; color:#111;
  min-height:36px; line-height:1.5;
}
.en-field-text::placeholder { color:#aaa; }
.en-field-text:focus { outline:none; border-bottom:1px dashed #4e90d8; }
/* 이미지 드롭존 */
.en-drop {
  border:1.5px dashed #b0c4de;
  border-radius:5px;
  background:#f8faff;
  padding:6px 8px;
  cursor:pointer;
  transition:border-color .15s, background .15s;
  position:relative;
  min-height:36px;
}
.en-drop:hover { border-color:#4e90d8; background:#eef3fa; }
.en-drop.drag-over { border-color:#2563eb; background:#dbeafe; }
.en-drop-hint {
  color:#aaa; font-size:7.5pt; text-align:center;
  pointer-events:none; user-select:none;
  display:flex; align-items:center; justify-content:center; gap:4px;
}
.en-drop input[type=file] { display:none; }
/* 이미지 미리보기 목록 */
.en-img-list {
  display:flex; flex-wrap:wrap; gap:6px; margin-top:4px;
}
.en-img-item {
  position:relative; display:inline-block;
}
.en-img-item img {
  max-width:140px; max-height:100px;
  border:1px solid #ccc; border-radius:3px;
  display:block; object-fit:contain; background:#fff;
}
.en-img-item-del {
  position:absolute; top:-6px; right:-6px;
  width:16px; height:16px; border-radius:50%;
  background:#ef4444; color:#fff; font-size:10px;
  display:flex; align-items:center; justify-content:center;
  cursor:pointer; line-height:1; border:none;
  box-shadow:0 1px 3px rgba(0,0,0,.3);
}
.en-img-item-del:hover { background:#dc2626; }
/* 헤더 셀의 텍스트 입력 (수입사 등 단순 1행 셀) */
.en-inp {
  border:none; background:transparent;
  width:100%; font-size:8.5pt;
  font-family:inherit; padding:0 2px;
  box-sizing:border-box; color:#111;
}
.en-inp::placeholder { color:#aaa; }
.en-inp:focus { outline:none; border-bottom:1px solid #4e90d8; }
@media print {
  /* ── 전체 래퍼 ── */
  .en-wrap { background:#fff !important; color:#000 !important; border-radius:0 !important; }

  /* ── 테이블 셀: 내용에 맞춰 높이 자동 확장, 잘림 방지 ── */
  .en-tbl { table-layout:fixed !important; width:100% !important; }
  .en-tbl th, .en-tbl td {
    border:1px solid #333 !important; color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important; overflow-wrap:break-word !important;
  }

  /* ── en-field: 인쇄 시 flex 유지, 높이 자동 ── */
  .en-field { height:auto !important; overflow:visible !important; display:flex !important; flex-direction:column !important; }

  /* ── textarea: 내용 전체 표시, 스크롤 없이 ── */
  textarea.en-field-text {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; min-height:0 !important; max-height:none !important;
    overflow:visible !important; resize:none !important;
    white-space:pre-wrap !important; word-break:break-word !important;
    overflow-wrap:break-word !important;
    display:block !important; box-sizing:border-box !important;
    -webkit-appearance:none !important; appearance:none !important;
    padding:2px 0 !important;
  }

  /* ── 단순 1행 input ── */
  .en-inp {
    border:none !important; background:transparent !important;
    color:#000 !important; font-size:8.5pt !important;
    font-family:'Malgun Gothic',sans-serif !important;
    height:auto !important; overflow:visible !important;
    word-break:break-word !important;
  }

  /* ── hidden input 완전 숨김 ── */
  input[type=hidden] { display:none !important; }

  /* ── 이미지 드롭존: 테두리/배경 제거, 힌트/삭제버튼 숨김 ── */
  .en-drop {
    border:none !important; background:transparent !important;
    padding:0 !important; min-height:unset !important;
    height:auto !important; overflow:visible !important;
  }
  .en-drop-hint { display:none !important; }
  .en-img-item-del { display:none !important; }
  .en-img-list { gap:4px !important; margin-top:2px !important; }
  .en-img-item img {
    max-width:100% !important; max-height:none !important;
    page-break-inside:avoid;
  }
  /* 이미지가 없는 빈 en-drop은 공간 차지 안 함 */
  .en-drop:not(:has(img)) { display:none !important; }

  /* ── 섹션 헤더 배경색 유지 ── */
  .en-sec-th { background:#d6e4f7 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-sub-th { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-th     { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .en-lbl    { background:#f5f8ff !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }

  /* ── 페이지 분리 방지 (행 단위) ── */
  .en-tbl tr { page-break-inside:avoid; }
}

/* PDF 원본 구조: 상단헤더(4칸) + 제목 + 단일 본문셀(1~5항목 + 확인문구 + 서명란) */
/* cf-wrap → en-wrap, cf-title → en-main-title 으로 대체됨 */

/* ── 본문 테이블 ── */
.cf-body-tbl {
  width:100%; border-collapse:collapse;
  border:1px solid #888;
}
.cf-body-tbl td {
  border:1px solid #888;
  vertical-align:top;
  padding:0;
}

/* ── 각 항목 행 ── */
.cf-item-row {
  display:flex; align-items:flex-start;
  padding:10px 14px;
  border-bottom:1px solid #ddd;
  min-height:40px;
  gap:0;
}
.cf-item-row:last-child { border-bottom:none; }
.cf-item-lbl {
  font-size:10pt; font-weight:600;
  white-space:nowrap;
  color:#111;
  min-width:110px;
  flex-shrink:0;
  padding-top:3px;
}
.cf-item-inp-wrap {
  flex:1; min-width:0;
}
.cf-item-inp {
  width:100%; background:transparent;
  border:none; border-bottom:1px solid #ccc;
  color:#111; font-size:10pt;
  padding:2px 4px; outline:none;
}
.cf-item-inp:focus { border-bottom-color:#4e90d8; }
.cf-item-inp::placeholder { color:#aaa; font-style:italic; }

/* 주소 TEL/FAX 행 */
.cf-tel-fax {
  display:flex; gap:10px; margin-top:8px; align-items:center;
}
.cf-tel-fax-lbl {
  font-size:10pt; white-space:nowrap;
  color:#555; font-weight:600;
}

/* ── 5. 보증내용 ── */
.cf-warranty-row {
  padding:10px 14px;
  border-bottom:1px solid #ddd;
}
.cf-warranty-top {
  display:flex; align-items:flex-start; gap:0; margin-bottom:8px;
}
.cf-warranty-lbl {
  font-size:10pt; font-weight:600;
  white-space:nowrap; min-width:110px; flex-shrink:0;
  padding-top:3px; color:#111;
}
.cf-warranty-subject-inp {
  flex:1; min-width:0;
  background:transparent;
  border:none; border-bottom:1px solid #ccc;
  color:#111; font-size:10pt;
  padding:2px 4px; outline:none;
}
.cf-warranty-subject-inp:focus { border-bottom-color:#4e90d8; }
.cf-warranty-subject-inp::placeholder { color:#aaa; font-style:italic; }
.cf-warranty-body {
  font-size:10pt; line-height:1.85;
  color:#333;
  word-break:keep-all; text-align:justify;
  padding-left:110px;
}

/* ── 당사확인 문구 ── */
.cf-confirm-stmt {
  text-align:center; font-size:10pt; font-weight:600;
  padding:16px 14px;
  border-bottom:1px solid #ddd;
  color:#111;
}

/* ── 제작사 확인 헤더 ── */
.cf-sign-head {
  text-align:center; font-size:10pt; font-weight:700;
  padding:8px 14px; letter-spacing:.08em;
  border-bottom:1px solid #ddd;
  background:#d6e4f7; color:#111;
}

/* ── 서명란 (Signed at / Date, Name / Title) ── */
.cf-sign-tbl {
  width:100%; border-collapse:collapse;
}
.cf-sign-tbl td {
  border:none; vertical-align:middle;
  padding:12px 14px;
}
.cf-sign-lbl {
  font-size:10pt; font-weight:700;
  white-space:nowrap; width:90px;
  color:#111;
}
.cf-sign-inp {
  width:100%; background:transparent;
  border:none; border-bottom:1.5px solid #ccc;
  color:#111; font-size:10pt;
  padding:4px 2px; outline:none;
}
.cf-sign-inp:focus { border-bottom-color:#4e90d8; }
.cf-sign-inp::placeholder { color:#aaa; font-style:italic; }
.cf-sign-divider {
  border:none; border-right:1px solid #ddd;
  padding:0; width:1px;
}

/* @media screen 오버라이드 불필요 - 고정값 사용 */

@media print {
  @page { size:A4 portrait; margin:18mm 15mm; }
  .no-print { display:none !important; }
  body { background:#fff !important; color:#000 !important; }
  -webkit-print-color-adjust:exact; print-color-adjust:exact;

  /* 전체 래퍼 */
  .cf-wrap {
    font-family:'맑은 고딕','Malgun Gothic','MS Gothic',sans-serif;
    font-size:9pt; color:#000;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }

          /* 제목 */
  .cf-title { font-size:14pt !important; font-weight:900 !important; color:#000 !important; background:#fff !important; border:1px solid #555 !important; border-top:none !important; padding:10px 8px !important; text-align:center !important; letter-spacing:.08em !important; }

  /* 본문 테이블 */
  .cf-body-tbl { border:1px solid #555 !important; border-top:none !important; border-collapse:collapse !important; width:100% !important; }
  .cf-body-tbl td { border:1px solid #555 !important; }

  /* 각 항목 행 — 인쇄 시 여백 넉넉하게 */
  .cf-item-row { padding:14px 14px !important; min-height:46px !important; border-bottom:1px solid #888 !important; }
  .cf-item-lbl { font-size:9pt !important; color:#000 !important; min-width:120px !important; }
  .cf-item-inp {
    font-size:9pt !important; color:#000 !important;
    background:transparent !important;
    border:none !important; border-bottom:1px solid #888 !important;
    padding:0 2px !important;
  }

  /* 보증내용 */
  .cf-warranty-row { padding:14px 14px !important; border-bottom:1px solid #888 !important; }
  .cf-warranty-lbl { font-size:9pt !important; color:#000 !important; min-width:120px !important; }
  .cf-warranty-subject-inp {
    font-size:9pt !important; color:#000 !important;
    background:transparent !important;
    border:none !important; border-bottom:1px solid #888 !important;
    padding:0 2px !important;
  }
  .cf-warranty-body { font-size:9pt !important; color:#000 !important; line-height:1.8 !important; padding-left:120px !important; }

  /* 당사확인 */
  .cf-confirm-stmt { font-size:9pt !important; color:#000 !important; padding:16px 14px !important; border-bottom:1px solid #888 !important; }

  /* 제작사 확인 헤더 */
  .cf-sign-head { background:#c8d4ea !important; color:#000 !important; font-size:9pt !important; border-bottom:1px solid #888 !important; padding:7px 14px !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }

  /* 서명란 */
  .cf-sign-tbl td { padding:14px 14px !important; }
  .cf-sign-lbl { font-size:9pt !important; color:#000 !important; width:80px !important; }
  .cf-sign-inp {
    font-size:9pt !important; color:#000 !important;
    background:transparent !important;
    border:none !important; border-bottom:1px solid #888 !important;
    padding:0 2px !important;
  }
  .cf-sign-divider { border-right:1px solid #888 !important; }
  .cf-tel-fax-lbl { font-size:9pt !important; color:#000 !important; }
}
</style>

<div class="en-wrap">

  <!-- ① 상단 헤더 (emission_noise와 동일: en-tbl thead/tbody 구조) -->
  <table class="en-tbl" style="margin-bottom:12px; table-layout:fixed;">
    <colgroup><col style="width:35%;"><col style="width:12%;"><col style="width:13%;"><col style="width:40%;"></colgroup>
    <thead>
      <tr>
        <th class="en-th">\${BL('importer')}</th>
        <th class="en-th">\${BL('cert_year')}</th>
        <th class="en-th">\${BL('displacement')}</th>
        <th class="en-th">\${BL('family_code')}</th>
      </tr>
    </thead>
    <tbody>
      <tr style="height:26px;">
        <td><input data-field="importer"     class="en-inp" type="text" placeholder="\${BL('ph_importer')}"    value="\${E(v('importer'))}"></td>
        <td><input data-field="cert_year"    class="en-inp" type="text" placeholder="\${BL('ph_cert_year')}"   value="\${E(v('cert_year'))}"></td>
        <td><input data-field="displacement" class="en-inp" type="text" placeholder="\${BL('ph_displacement')}" value="\${E(v('displacement'))}"></td>
        <td><input data-field="family_code"  class="en-inp" type="text" placeholder="\${BL('ph_family_code')}"  value="\${E(v('family_code'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- ② 제목 (emission_noise와 동일 구조) -->
  <div class="en-main-title">\${BL('cf_title')}</div>

  <!-- ③ 본문 — PDF 원본: 단일 셀 안에 1~5번 항목 나열 (3열 구조 없음) -->
  <table class="cf-body-tbl">
    <tbody>
      <tr>
        <td>

          <!-- 1. 제작사 -->
          <div class="cf-item-row">
            <span class="cf-item-lbl">1. 제작사 :</span>
            <div class="cf-item-inp-wrap">
              <input data-field="cf_maker" class="cf-item-inp" type="text"
                placeholder="예) HONDA Motor Co.,Ltd(일본)" value="\${E(v('cf_maker'))}">
            </div>
          </div>

          <!-- 2. 주소 -->
          <div class="cf-item-row" style="flex-direction:column;align-items:flex-start;">
            <div style="display:flex;align-items:flex-start;width:100%;gap:0;">
              <span class="cf-item-lbl">2. 주&nbsp;&nbsp;&nbsp;소 :</span>
              <div class="cf-item-inp-wrap">
                <input data-field="cf_address" class="cf-item-inp" type="text"
                  placeholder="제작사 주소" value="\${E(v('cf_address'))}">
              </div>
            </div>
            <div class="cf-tel-fax" style="padding-left:110px;width:100%;box-sizing:border-box;margin-top:10px;">
              <span class="cf-tel-fax-lbl">TEL)</span>
              <input data-field="cf_tel" class="cf-item-inp" type="text"
                placeholder="전화번호" value="\${E(v('cf_tel'))}" style="flex:1;min-width:0;">
              <span class="cf-tel-fax-lbl" style="margin-left:16px;">FAX)</span>
              <input data-field="cf_fax" class="cf-item-inp" type="text"
                placeholder="팩스번호" value="\${E(v('cf_fax'))}" style="flex:1;min-width:0;">
            </div>
          </div>

          <!-- 3. 모델 -->
          <div class="cf-item-row">
            <span class="cf-item-lbl">3. 모&nbsp;&nbsp;&nbsp;델 :</span>
            <div class="cf-item-inp-wrap">
              <input data-field="cf_model" class="cf-item-inp" type="text"
                placeholder="예) CB500F" value="\${E(v('cf_model'))}">
            </div>
          </div>

          <!-- 4. 수입자 -->
          <div class="cf-item-row">
            <span class="cf-item-lbl">4. 수입자 :</span>
            <div class="cf-item-inp-wrap">
              <input data-field="cf_importer" class="cf-item-inp" type="text"
                placeholder="예) ㈜○○모터스" value="\${E(v('cf_importer'))}">
            </div>
          </div>

          <!-- 5. 보증내용 -->
          <div class="cf-warranty-row">
            <div class="cf-warranty-top">
              <span class="cf-warranty-lbl">5. 보증내용 :</span>
              <input data-field="cf_warranty_subject" class="cf-warranty-subject-inp" type="text"
                placeholder="보증 주체명 (예: ㈜○○모터스)" value="\${E(v('cf_warranty_subject'))}">
            </div>
            <div class="cf-warranty-body">
              은 대기환경보전법 제46조, 48조, 50조, 51조 및 대기환경보전법 시행규칙 제63조 규정에 의한
              보증기간(130km/h이하 2년 또는 20,000km, 130km/h이상 2년 또는 35,000km) 까지 제작차 및
              운행차 배출허용기준에 만족할 수 있도록 품질관리, 사후책임 등에 관한 의무사항을 이행하며,
              수시검사 및 결함검사에서 결함이 확인될 경우 제작 결함 수정(리콜)의 의무를 이행한다.
            </div>
          </div>

          <!-- 당사확인 문구 -->
          <div class="cf-confirm-stmt">
            당사는 상기보증내용에 대해, 의무사항을 이행할 것을 확인합니다.
          </div>

          <!-- 제작사 확인 헤더 -->
          <div class="cf-sign-head">\${BL('cf_maker_confirm')}</div>

          <!-- 서명란: Signed at | Date / Name | Title (2열 구조) -->
          <table class="cf-sign-tbl">
            <colgroup>
              <col style="width:50%;">
              <col class="cf-sign-divider" style="width:1px;">
              <col style="width:50%;">
            </colgroup>
            <tbody>
              <tr>
                <!-- 좌: Signed at -->
                <td>
                  <div style="display:flex;align-items:center;gap:8px;">
                    <span class="cf-sign-lbl">Signed at</span>
                    <input data-field="cf_signed_at" class="cf-sign-inp" type="text"
                      placeholder="서명 장소" value="\${E(v('cf_signed_at'))}" style="flex:1;min-width:0;">
                  </div>
                </td>
                <td class="cf-sign-divider"></td>
                <!-- 우: Date -->
                <td>
                  <div style="display:flex;align-items:center;gap:8px;">
                    <span class="cf-sign-lbl">Date</span>
                    <input data-field="cf_sign_date" class="cf-sign-inp" type="text"
                      placeholder="예) 2025. 01. 01." value="\${E(v('cf_sign_date'))}" style="flex:1;min-width:0;">
                  </div>
                </td>
              </tr>
              <tr>
                <!-- 좌: Name -->
                <td>
                  <div style="display:flex;align-items:center;gap:8px;">
                    <span class="cf-sign-lbl">Name</span>
                    <input data-field="cf_name" class="cf-sign-inp" type="text"
                      placeholder="서명자 성명" value="\${E(v('cf_name'))}" style="flex:1;min-width:0;">
                  </div>
                </td>
                <td class="cf-sign-divider"></td>
                <!-- 우: Title -->
                <td>
                  <div style="display:flex;align-items:center;gap:8px;">
                    <span class="cf-sign-lbl">Title :</span>
                    <input data-field="cf_title" class="cf-sign-inp" type="text"
                      placeholder="직책" value="\${E(v('cf_title'))}" style="flex:1;min-width:0;">
                  </div>
                </td>
              </tr>
            </tbody>
          </table>

        </td>
      </tr>
    </tbody>
  </table>

</div>
<div id="qr-footer-wrap" style="margin-top:12px;"></div>
\`;

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
// 범용 필드 이미지 첨부 기능 (모든 폼의 dp-inp / dp-ta / en-inp 등)
// ================================================================

// ================================================================
// noise_test 첨부파일 기능
// ================================================================
// ── detail_plan 이미지 드롭존 공통 함수 ──────────────────────────────────
// ── detail_plan 이미지 드롭존 공통 함수 (emission_noise dpAddFiles 동일 방식) ──
(function(){
  function dpSaveImgs(hidId, imgs) {
    var hid = document.getElementById(hidId);
    if (hid) hid.value = JSON.stringify(imgs);
    // data-field sync
    var el = document.querySelector('[data-field="'+hidId+'"]');
    if (el && el !== hid) el.value = JSON.stringify(imgs);
  }
  function dpGetImgs(hidId) {
    var hid = document.getElementById(hidId);
    try { return JSON.parse((hid && hid.value) || '[]'); } catch(e) { return []; }
  }
  function dpRenderDrop(hidId, dropId) {
    var drop = document.getElementById(dropId);
    if (!drop) return;
    var list = drop.querySelector('.dp-img-list');
    if (!list) return;
    var imgs = dpGetImgs(hidId);
    // hint 표시/숨김
    var hint = drop.querySelector('.dp-drop-hint');
    if (hint) hint.style.display = imgs.length > 0 ? 'none' : '';
    list.innerHTML = '';
    imgs.forEach(function(src, idx) {
      var item = document.createElement('div');
      item.className = 'dp-img-item';
      var img = document.createElement('img');
      img.src = src; img.title = '클릭하여 크게 보기';
      img.onclick = function(e){ e.stopPropagation(); window.open(src,'_blank'); };
      var del = document.createElement('button');
      del.className = 'dp-img-item-del'; del.textContent = '\xd7';
      del.onclick = function(e){
        e.stopPropagation();
        var arr = dpGetImgs(hidId);
        arr.splice(idx, 1);
        dpSaveImgs(hidId, arr);
        dpRenderDrop(hidId, dropId);
      };
      item.appendChild(img); item.appendChild(del);
      list.appendChild(item);
    });
  }
  window.dpAddFiles = function(hidId, dropId, files) {
    var imgs = dpGetImgs(hidId);
    var pending = files.length;
    if (pending === 0) return;
    Array.from(files).forEach(function(f){
      if (!f.type.startsWith('image/')) { pending--; return; }
      var fr = new FileReader();
      fr.onload = function(e){
        imgs.push(e.target.result);
        pending--;
        if (pending <= 0) { dpSaveImgs(hidId, imgs); dpRenderDrop(hidId, dropId); }
      };
      fr.readAsDataURL(f);
    });
  };
  window.dpRestoreAll = function() {
    // fixed id 섹션 복원
    [
      ['dp_1_1_imgs','dp_1_1_drop'],
      ['dp_1_2_imgs','dp_1_2_drop'],
      ['dp_7_1_imgs','dp_7_1_drop'],
      ['dp_7_2_imgs','dp_7_2_drop'],
      ['dp_9_2_imgs','dp_9_2_drop'],
      ['dp_13_imgs','dp_13_drop'],
      ['dp_8_14_1_imgs','dp_8_14_1_drop'],
      ['dp_8_14_2_imgs','dp_8_14_2_drop'],
    ].forEach(function(pair){ dpRenderDrop(pair[0], pair[1]); });
    // 8.x diagram 복원
    ['dp_8_1','dp_8_2','dp_8_3','dp_8_4','dp_8_5','dp_8_6','dp_8_7','dp_8_8','dp_8_9'].forEach(function(pfx){
      dpRenderDrop(pfx+'_diagram_imgs', pfx+'_diagram_drop');
    });
  };
})();

// ── obd_config 이미지 드롭존 초기화 ─────────────────────────────────
function initObdImgDrops() {
  // obd-wrap 안의 모든 .obd-drop 을 자동 탐색하여 초기화
  var wrap = document.querySelector('.obd-wrap');
  if (!wrap) return;

  wrap.querySelectorAll('.obd-drop').forEach(function(drop) {
    var fileInput = drop.querySelector('input[type="file"]');
    if (!fileInput) return;

    // hidden input: drop 안에서 찾기
    var hidden = drop.querySelector('input[type="hidden"]');

    // img-list 컨테이너: drop 다음 형제 .obd-img-list 또는 ID 기반
    var listEl = null;
    if (drop.id) {
      listEl = document.getElementById(drop.id.replace('obd-drop-', 'obd-imgs-'));
    }
    if (!listEl) {
      var sib = drop.nextElementSibling;
      if (sib && sib.classList.contains('obd-img-list')) listEl = sib;
    }
    // listEl이 없으면 drop 자체를 컨테이너로
    var container = listEl || drop;

    // 이미지 배열 (메모리)
    var images = []; // string[]  (dataURL)

    // ── render ──────────────────────────────────────────────────
    function render() {
      // img-list 초기화
      container.querySelectorAll('.obd-img-item').forEach(function(el){ el.remove(); });
      var hint = drop.querySelector('.obd-drop-hint');
      if (images.length === 0) {
        if (hint) hint.style.display = '';
        if (hidden) hidden.value = '[]';
        return;
      }
      if (hint) hint.style.display = 'none';
      images.forEach(function(src, idx) {
        var item = document.createElement('div');
        item.className = 'obd-img-item';
        var img = document.createElement('img');
        img.src = src;
        var del = document.createElement('button');
        del.className = 'obd-img-item-del';
        del.innerHTML = '\xd7';
        del.title = '삭제';
        del.addEventListener('click', function(e) {
          e.stopPropagation();
          images.splice(idx, 1);
          render();
        });
        item.appendChild(img);
        item.appendChild(del);
        container.appendChild(item);
      });
      // hidden input 동기화
      if (hidden) hidden.value = JSON.stringify(images);
    }

    // ── 저장값 복원 ─────────────────────────────────────────────
    if (hidden && hidden.value && hidden.value !== '[]') {
      try {
        var parsed = JSON.parse(hidden.value);
        if (Array.isArray(parsed)) images = parsed;
        else if (typeof parsed === 'string' && parsed) images = [parsed];
      } catch(e) {
        if (hidden.value) images = [hidden.value];
      }
      render();
    }

    // ── 파일 처리 ───────────────────────────────────────────────
    function handleFiles(files) {
      Array.from(files).forEach(function(file) {
        if (!file.type.startsWith('image/')) return;
        var reader = new FileReader();
        reader.onload = function(ev) {
          images.push(ev.target.result);
          render();
        };
        reader.readAsDataURL(file);
      });
    }

    // 클릭 → 파일 선택
    fileInput.addEventListener('change', function() {
      handleFiles(this.files);
      this.value = '';
    });

    // 드래그앤드롭
    drop.addEventListener('dragover', function(e) {
      e.preventDefault(); drop.classList.add('drag-over');
    });
    drop.addEventListener('dragleave', function() {
      drop.classList.remove('drag-over');
    });
    drop.addEventListener('drop', function(e) {
      e.preventDefault(); drop.classList.remove('drag-over');
      handleFiles(e.dataTransfer.files);
    });
  });
}

function initEmissionAttach() {
  // 업로드/다운로드/저장 전용 (인쇄 출력 기능 없음)
  var hiddenInput = document.getElementById('em-attach-raw-data');
  var emAttachFiles = [];

  // 저장된 데이터 복원
  try {
    var saved = hiddenInput && hiddenInput.value ? JSON.parse(hiddenInput.value) : [];
    if (Array.isArray(saved) && saved.length > 0) emAttachFiles = saved;
  } catch(e) {}

  var dropZone  = document.getElementById('em-drop-raw');
  var fileInput = document.getElementById('em-file-raw');
  var listEl    = document.getElementById('em-list-raw');
  if (!dropZone || !fileInput) return;

  dropZone.addEventListener('dragover',  function(e){ e.preventDefault(); dropZone.style.borderColor='#4e90d8'; });
  dropZone.addEventListener('dragleave', function(){ dropZone.style.borderColor=''; });
  dropZone.addEventListener('drop',      function(e){ e.preventDefault(); dropZone.style.borderColor=''; handleEmFiles(e.dataTransfer.files); });
  dropZone.addEventListener('click',     function(){ fileInput.click(); });
  fileInput.addEventListener('change',   function(){ handleEmFiles(this.files); this.value=''; });

  function syncHidden() {
    if (hiddenInput) hiddenInput.value = JSON.stringify(emAttachFiles);
  }

  function handleEmFiles(files) {
    Array.from(files).forEach(function(file){
      var reader = new FileReader();
      reader.onload = function(ev){
        emAttachFiles.push({ name: file.name, size: file.size, type: file.type, dataUrl: ev.target.result });
        syncHidden(); renderEmList();
      };
      reader.readAsDataURL(file);
    });
  }

  function fmtSize(b){ return b<1024?b+'B':b<1048576?(b/1024).toFixed(1)+'KB':(b/1048576).toFixed(1)+'MB'; }

  function renderEmList(){
    listEl.innerHTML = '';
    emAttachFiles.forEach(function(f, idx){
      var div = document.createElement('div');
      div.className = 'em-attach-item';
      div.innerHTML =
        '<i class="fas '+(f.type==='application/pdf'?'fa-file-pdf':'fa-file-image')+'" style="color:#4e90d8;"></i>' +
        '<span class="em-attach-item-name">'+esc(f.name)+'</span>' +
        '<span class="em-attach-item-size">'+fmtSize(f.size)+'</span>' +
        '<a class="em-attach-item-dl" title="다운로드" href="'+f.dataUrl+'" download="'+esc(f.name)+'" style="color:#4e90d8;padding:1px 6px;border-radius:3px;font-size:10pt;line-height:1;"><i class="fas fa-download"></i></a>' +
        '<span class="em-attach-item-del" title="삭제" data-idx="'+idx+'">×</span>';
      listEl.appendChild(div);
    });
    listEl.querySelectorAll('.em-attach-item-del').forEach(function(btn){
      btn.addEventListener('click', function(e){
        e.stopPropagation();
        emAttachFiles.splice(parseInt(this.dataset.idx), 1);
        syncHidden(); renderEmList();
      });
    });
  }
  // 복원된 파일이 있으면 즉시 렌더링
  if (emAttachFiles.length > 0) renderEmList();
}

function initEvapAttach() {
  // 업로드/다운로드/저장 전용 (인쇄 출력 기능 없음)
  var hiddenInput = document.getElementById('ev-attach-raw-data');
  var evAttachFiles = [];

  // 저장된 데이터 복원
  try {
    var saved = hiddenInput && hiddenInput.value ? JSON.parse(hiddenInput.value) : [];
    if (Array.isArray(saved) && saved.length > 0) evAttachFiles = saved;
  } catch(e) {}

  var dropZone  = document.getElementById('ev-drop-raw');
  var fileInput = document.getElementById('ev-file-raw');
  var listEl    = document.getElementById('ev-list-raw');
  if (!dropZone || !fileInput) return;

  dropZone.addEventListener('dragover',  function(e){ e.preventDefault(); dropZone.style.borderColor='#4e90d8'; });
  dropZone.addEventListener('dragleave', function(){ dropZone.style.borderColor=''; });
  dropZone.addEventListener('drop',      function(e){ e.preventDefault(); dropZone.style.borderColor=''; handleEvFiles(e.dataTransfer.files); });
  fileInput.addEventListener('change',   function(){ handleEvFiles(this.files); this.value=''; });

  function syncHidden() {
    if (hiddenInput) hiddenInput.value = JSON.stringify(evAttachFiles);
  }

  function handleEvFiles(files) {
    Array.from(files).forEach(function(file){
      var reader = new FileReader();
      reader.onload = function(ev){
        evAttachFiles.push({ name: file.name, size: file.size, type: file.type, dataUrl: ev.target.result });
        syncHidden(); renderEvList();
      };
      reader.readAsDataURL(file);
    });
  }

  function fmtSize(b){ return b<1024?b+'B':b<1048576?(b/1024).toFixed(1)+'KB':(b/1048576).toFixed(1)+'MB'; }

  function renderEvList(){
    listEl.innerHTML = '';
    evAttachFiles.forEach(function(f, idx){
      var div = document.createElement('div');
      div.className = 'ev-attach-item';
      div.innerHTML =
        '<i class="fas '+(f.type==='application/pdf'?'fa-file-pdf':'fa-file-image')+'" style="color:#4e90d8;"></i>' +
        '<span class="ev-attach-item-name">'+esc(f.name)+'</span>' +
        '<span class="ev-attach-item-size">'+fmtSize(f.size)+'</span>' +
        '<a class="ev-attach-item-dl" title="다운로드" href="'+f.dataUrl+'" download="'+esc(f.name)+'" style="color:#4e90d8;padding:1px 6px;border-radius:3px;font-size:10pt;line-height:1;"><i class="fas fa-download"></i></a>' +
        '<span class="ev-attach-item-del" title="삭제" data-idx="'+idx+'">×</span>';
      listEl.appendChild(div);
    });
    listEl.querySelectorAll('.ev-attach-item-del').forEach(function(btn){
      btn.addEventListener('click', function(){
        evAttachFiles.splice(parseInt(this.dataset.idx), 1);
        syncHidden(); renderEvList();
      });
    });
  }
  // 복원된 파일이 있으면 즉시 렌더링
  if (evAttachFiles.length > 0) renderEvList();
}

// ================================================================
// emission_noise 복합 입력 필드 초기화 (텍스트 + 이미지 드롭존)
// ================================================================
function initEnFields() {
  // 모든 .en-drop 요소를 찾아 드래그&드롭 + 클릭 업로드 연결
  var drops = document.querySelectorAll('.en-drop');
  drops.forEach(function(drop) {
    var fileInput = drop.querySelector('input[type=file]');
    var imgList   = drop.querySelector('.en-img-list');
    var hint      = drop.querySelector('.en-drop-hint');
    if (!fileInput || !imgList) return;

    // data-field-img 속성으로 대응 hidden input 탐색
    var fieldName   = drop.getAttribute('data-field-img');
    var hiddenInput = fieldName
      ? document.querySelector('[data-field="' + fieldName + '_imgs"]')
      : null;

    var images = []; // { dataUrl, name }

    // ── 초기화: 저장된 이미지 복원 ──────────────────────────
    if (hiddenInput && hiddenInput.value) {
      try {
        var saved = JSON.parse(hiddenInput.value);
        if (Array.isArray(saved)) images = saved;
      } catch(e) { /* 파싱 실패 시 무시 */ }
      render();
    }

    // 클릭 → 파일 선택 (드롭존 내 input이 아닌 영역만)
    drop.addEventListener('click', function(e) {
      if (e.target === fileInput) return;
      fileInput.click();
    });

    // 드래그 오버
    drop.addEventListener('dragover', function(e) {
      e.preventDefault();
      drop.classList.add('drag-over');
    });
    drop.addEventListener('dragleave', function() {
      drop.classList.remove('drag-over');
    });
    drop.addEventListener('drop', function(e) {
      e.preventDefault();
      drop.classList.remove('drag-over');
      handleFiles(e.dataTransfer.files);
    });

    // 파일 선택
    fileInput.addEventListener('change', function() {
      handleFiles(this.files);
      this.value = '';
    });

    function handleFiles(files) {
      Array.from(files).forEach(function(file) {
        if (!file.type.startsWith('image/')) return;
        var reader = new FileReader();
        reader.onload = function(ev) {
          images.push({ dataUrl: ev.target.result, name: file.name });
          render();
        };
        reader.readAsDataURL(file);
      });
    }

    function render() {
      imgList.innerHTML = '';
      if (images.length === 0) {
        if (hint) hint.style.display = 'flex';
        // ── 빈 배열도 hidden input에 동기화 ─────────────────
        if (hiddenInput) hiddenInput.value = '[]';
        return;
      }
      if (hint) hint.style.display = 'none';
      images.forEach(function(img, idx) {
        var item = document.createElement('div');
        item.className = 'en-img-item';
        var imgEl = document.createElement('img');
        imgEl.src = img.dataUrl;
        imgEl.title = img.name;
        var delBtn = document.createElement('button');
        delBtn.className = 'en-img-item-del';
        delBtn.innerHTML = '&times;';
        delBtn.title = '삭제';
        delBtn.addEventListener('click', function(e) {
          e.stopPropagation();
          images.splice(idx, 1);
          render();
        });
        item.appendChild(imgEl);
        item.appendChild(delBtn);
        imgList.appendChild(item);
      });
      // ── 현재 이미지 배열을 hidden input에 JSON 직렬화 저장 ──
      if (hiddenInput) hiddenInput.value = JSON.stringify(images);
    }
  });
}

function initObdAttach() {
  var hiddenInput = document.getElementById('obd-attach-data');
  var obdAttachFiles = [];
  // 저장된 데이터 복원
  try {
    var saved = hiddenInput && hiddenInput.value ? JSON.parse(hiddenInput.value) : [];
    if (Array.isArray(saved) && saved.length > 0) obdAttachFiles = saved;
  } catch(e) {}

  var dropZone  = document.getElementById('obd-drop-zone');
  var fileInput = document.getElementById('obd-file-input');
  var listEl    = document.getElementById('obd-attach-list');
  if (!dropZone) return;

  dropZone.addEventListener('dragover', function(e){ e.preventDefault(); dropZone.style.borderColor='#4e90d8'; });
  dropZone.addEventListener('dragleave', function(){ dropZone.style.borderColor=''; });
  dropZone.addEventListener('drop', function(e){
    e.preventDefault(); dropZone.style.borderColor='';
    handleObdFiles(e.dataTransfer.files);
  });
  fileInput.addEventListener('change', function(){ handleObdFiles(this.files); this.value=''; });

  function syncHidden() {
    if (hiddenInput) hiddenInput.value = JSON.stringify(obdAttachFiles);
  }

  function handleObdFiles(files) {
    Array.from(files).forEach(function(file){
      var reader = new FileReader();
      reader.onload = function(ev){
        obdAttachFiles.push({ name: file.name, size: file.size, type: file.type, dataUrl: ev.target.result });
        syncHidden(); renderObdList();
      };
      reader.readAsDataURL(file);
    });
  }

  function fmtSize(b){ return b<1024?b+'B':b<1048576?(b/1024).toFixed(1)+'KB':(b/1048576).toFixed(1)+'MB'; }

  function renderObdList(){
    listEl.innerHTML = '';
    obdAttachFiles.forEach(function(f, idx){
      var div = document.createElement('div');
      div.className = 'obd-attach-item';
      div.innerHTML =
        '<i class="fas '+(f.type==='application/pdf'?'fa-file-pdf':'fa-file-image')+'" style="color:#4e90d8;"></i>' +
        '<span class="obd-attach-item-name">'+esc(f.name)+'</span>' +
        '<span class="obd-attach-item-size">'+fmtSize(f.size)+'</span>' +
        '<a class="obd-attach-item-dl" title="\ub2e4\uc6b4\ub85c\ub4dc" href="'+f.dataUrl+'" download="'+esc(f.name)+'" style="color:#4e90d8;padding:1px 6px;border-radius:3px;font-size:10pt;line-height:1;"><i class="fas fa-download"></i></a>' +
        '<span class="obd-attach-item-del" title="\uc0ad\uc81c" data-idx="'+idx+'">\xd7</span>';
      listEl.appendChild(div);
    });
    listEl.querySelectorAll('.obd-attach-item-del').forEach(function(btn){
      btn.addEventListener('click', function(){
        obdAttachFiles.splice(parseInt(this.dataset.idx),1);
        syncHidden(); renderObdList();
      });
    });
  }
  // 복원된 파일이 있으면 즉시 렌더링
  if (obdAttachFiles.length > 0) renderObdList();
}

function initNoiseAttach() {
  var hiddenInput = document.getElementById('nt-attach-data');
  var ntAttachFiles = [];
  // 저장된 데이터 복원
  try {
    var saved = hiddenInput && hiddenInput.value ? JSON.parse(hiddenInput.value) : [];
    if (Array.isArray(saved) && saved.length > 0) ntAttachFiles = saved;
  } catch(e) {}

  var dropZone  = document.getElementById('nt-drop-zone');
  var fileInput = document.getElementById('nt-file-input');
  var listEl    = document.getElementById('nt-attach-list');
  if (!dropZone) return;

  dropZone.addEventListener('dragover', function(e){ e.preventDefault(); dropZone.style.borderColor='var(--c-accent)'; });
  dropZone.addEventListener('dragleave', function(){ dropZone.style.borderColor=''; });
  dropZone.addEventListener('drop', function(e){
    e.preventDefault(); dropZone.style.borderColor='';
    handleNtFiles(e.dataTransfer.files);
  });
  fileInput.addEventListener('change', function(){ handleNtFiles(this.files); this.value=''; });

  function syncHidden() {
    if (hiddenInput) hiddenInput.value = JSON.stringify(ntAttachFiles);
  }

  function handleNtFiles(files) {
    Array.from(files).forEach(function(file){
      var reader = new FileReader();
      reader.onload = function(ev){
        ntAttachFiles.push({ name: file.name, size: file.size, type: file.type, dataUrl: ev.target.result });
        syncHidden(); renderNtList();
      };
      reader.readAsDataURL(file);
    });
  }

  function fmtSize(b){ return b<1024?b+'B':b<1048576?(b/1024).toFixed(1)+'KB':(b/1048576).toFixed(1)+'MB'; }

  function renderNtList(){
    listEl.innerHTML = '';
    ntAttachFiles.forEach(function(f, idx){
      var div = document.createElement('div');
      div.className = 'nt-attach-item';
      div.innerHTML =
        '<i class="fas '+(f.type==='application/pdf'?'fa-file-pdf':'fa-file-image')+'" style="color:var(--c-accent);"></i>' +
        '<span class="nt-attach-item-name">'+esc(f.name)+'</span>' +
        '<span class="nt-attach-item-size">'+fmtSize(f.size)+'</span>' +
        '<a class="nt-attach-item-dl" title="다운로드" href="'+f.dataUrl+'" download="'+esc(f.name)+'" style="color:var(--c-accent);padding:1px 6px;border-radius:3px;font-size:10pt;line-height:1;"><i class="fas fa-download"></i></a>' +
        '<span class="nt-attach-item-del" title="삭제" data-idx="'+idx+'">×</span>';
      listEl.appendChild(div);
    });
    listEl.querySelectorAll('.nt-attach-item-del').forEach(function(btn){
      btn.addEventListener('click', function(){
        ntAttachFiles.splice(parseInt(this.dataset.idx),1);
        syncHidden(); renderNtList();
      });
    });
  }
  // 복원된 파일이 있으면 즉시 렌더링
  if (ntAttachFiles.length > 0) renderNtList();
}

// ================================================================
// 초기 실행
// ================================================================
document.addEventListener('DOMContentLoaded', init);

// ================================================================
// 비밀번호 변경 모달
// ================================================================
function showChangePwModal() {
  document.getElementById('cpw-current').value = '';
  document.getElementById('cpw-new').value = '';
  document.getElementById('cpw-new2').value = '';
  const errEl = document.getElementById('cpw-error');
  errEl.style.display = 'none'; errEl.textContent = '';
  document.getElementById('modal-change-pw').classList.remove('hidden');
}
function closeChangePwModal() { document.getElementById('modal-change-pw').classList.add('hidden'); }

async function doChangePw() {
  const cur  = document.getElementById('cpw-current').value;
  const nw   = document.getElementById('cpw-new').value;
  const nw2  = document.getElementById('cpw-new2').value;
  const errEl = document.getElementById('cpw-error');
  errEl.style.display = 'none';
  if (!cur || !nw || !nw2) { errEl.textContent='모든 항목을 입력해주세요.'; errEl.style.display='block'; return; }
  if (nw.length < 4) { errEl.textContent='새 비밀번호는 4자 이상이어야 합니다.'; errEl.style.display='block'; return; }
  if (nw !== nw2) { errEl.textContent='새 비밀번호가 일치하지 않습니다.'; errEl.style.display='block'; return; }
  const btn = document.getElementById('cpw-btn');
  btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>처리중...';
  try {
    const res = await api('/api/auth/change-password', { method:'POST', body:JSON.stringify({current_password:cur, new_password:nw}) });
    const data = await res.json();
    if (res.ok) { closeChangePwModal(); showToast('비밀번호가 변경되었습니다.', 'success'); }
    else { errEl.textContent = data.error || '오류가 발생했습니다.'; errEl.style.display='block'; }
  } catch { errEl.textContent='네트워크 오류가 발생했습니다.'; errEl.style.display='block'; }
  finally { btn.disabled=false; btn.innerHTML='<i class="fas fa-check"></i>변경'; }
}

document.addEventListener('DOMContentLoaded', () => {
  const m = document.getElementById('modal-change-pw');
  if (m) m.addEventListener('click', function(e){ if(e.target===this)closeChangePwModal(); });
});
</script>

<!-- 비밀번호 변경 모달 -->
<div id="modal-change-pw" class="modal-backdrop hidden no-print">
  <div class="modal" onclick="event.stopPropagation()" style="max-width:420px;">
    <div class="modal-header">
      <h3 style="font-size:14pt;font-weight:700;"><i class="fas fa-key" style="margin-right:8px;color:var(--c-primary);"></i>비밀번호 변경</h3>
      <button class="btn btn-ghost btn-icon btn-sm" onclick="closeChangePwModal()"><i class="fas fa-times"></i></button>
    </div>
    <div class="modal-body">
      <div class="form-group">
        <label class="label">현재 비밀번호 <span style="color:var(--c-danger);">*</span></label>
        <input id="cpw-current" class="input" type="password" placeholder="현재 비밀번호를 입력하세요" autocomplete="current-password"
          onkeydown="if(event.key==='Enter')document.getElementById('cpw-new').focus()">
      </div>
      <div class="form-group">
        <label class="label">새 비밀번호 <span style="color:var(--c-danger);">*</span></label>
        <input id="cpw-new" class="input" type="password" placeholder="4자 이상" autocomplete="new-password"
          onkeydown="if(event.key==='Enter')document.getElementById('cpw-new2').focus()">
      </div>
      <div class="form-group">
        <label class="label">새 비밀번호 확인 <span style="color:var(--c-danger);">*</span></label>
        <input id="cpw-new2" class="input" type="password" placeholder="재입력" autocomplete="new-password"
          onkeydown="if(event.key==='Enter')doChangePw()">
      </div>
      <div id="cpw-error" class="auth-error" style="display:none;"></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="closeChangePwModal()">취소</button>
      <button id="cpw-btn" class="btn btn-primary" onclick="doChangePw()">
        <i class="fas fa-check"></i>변경
      </button>
    </div>
  </div>
</div>
</body>
</html>`;

app.get('/', (c) => {
  c.header('Cache-Control', 'no-store, no-cache, must-revalidate')
  c.header('Pragma', 'no-cache')
  return c.html(HTML)
})
app.get('*', (c) => {
  c.header('Cache-Control', 'no-store, no-cache, must-revalidate')
  c.header('Pragma', 'no-cache')
  return c.html(HTML)
})

export default app

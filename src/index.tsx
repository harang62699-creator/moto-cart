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
  display:flex;
  flex-direction:column;
  align-items:center;
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
#page-dashboard { max-width:1200px; width:100%; padding:36px 24px; }
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
#page-application { max-width:1200px; width:100%; padding:36px 24px; }
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
#page-form { max-width:860px; width:100%; padding:36px 24px; }
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
  #page-dashboard, #page-application, #page-form { padding:20px 16px; }
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
      <div class="appl-pct-label">전체 진행률</div>
      <div class="appl-pct" id="appl-progress-pct">0%</div>
      <div class="progress-track" style="width:140px;height:6px;margin-top:10px;">
        <div id="appl-progress-bar" class="progress-fill" style="height:6px;background:var(--grad-accent);width:0%;"></div>
      </div>
    </div>
  </div>

  <div class="forms-section-title">□ 제출 서류 목록</div>
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
      <button class="btn btn-ghost" onclick="showDashboard()">
        <i class="fas fa-arrow-left"></i>목록으로
      </button>
    </div>
    <div class="appl-action-bar-right">
      <button class="btn btn-ghost" onclick="printApplicationSummary()">
        <i class="fas fa-print"></i>인쇄
      </button>
      <button id="save-all-btn" class="btn btn-success" onclick="saveAllForms()">
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
    <button onclick="showDashboard()"><i class="fas fa-home"></i> 목록</button>
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
  { type:'obd_config',     title:'배출가스자기진단장치(OBD) 구성에 관한 서류', icon:'fa-microchip', color:'#6366f1', bg:'rgba(99,102,241,.12)' },
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
            <span style="font-size:10pt;color:var(--c-text3);flex-shrink:0;">\${done_f}/\${total_f}</span>
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
  // forms-grid 헤더 복원 (innerHTML 덮어쓰기 방지)
  const formsGrid = document.getElementById('forms-grid');
  formsGrid.innerHTML = \`
    <div class="forms-grid-head">
      <div style="width:48px;text-align:center;">번호</div>
      <div>서류명</div>
      <div style="width:90px;text-align:center;">상태</div>
      <div style="width:44px;text-align:center;"></div>
    </div>
    <div class="forms-grid-body">\${FORM_META.map((m,i) => {
      const fd    = currentForms.find(f=>f.form_type===m.type);
      const isDone = !!fd?.completed;
      return \`
        <div class="form-card \${isDone?'done':''}" onclick="openForm('\${m.type}')">
          <div class="fc-cell fc-num">\${i+1}</div>
          <div class="fc-cell fc-main">
            <div class="fc-main-inner">
              <div class="form-card-icon" style="background:\${isDone?'rgba(0,200,150,.12)':m.bg};color:\${isDone?'var(--c-success)':m.color};">
                <i class="fas \${m.icon}"></i>
              </div>
              <span class="form-card-name">\${m.title}</span>
            </div>
          </div>
          <div class="fc-cell fc-status">
            \${isDone
              ? '<span class="badge badge-green" style="font-size:9pt;"><i class="fas fa-check" style="margin-right:2px;"></i>완료</span>'
              : '<span class="badge badge-gray" style="font-size:9pt;">미완료</span>'
            }
          </div>
          <div class="fc-cell fc-action"><i class="fas fa-chevron-right form-card-chevron"></i></div>
        </div>
      \`;
    }).join('')}</div>
  \`;
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
  // auto-grow 초기화 (input[type=text] → textarea 자동 교체)
  setTimeout(() => initAutoGrow(document.getElementById('form-content')), 50);
  // QR 코드 비동기 생성 (폼 렌더 직후)
  setTimeout(() => generateFormQR(formType, meta.title), 100);
  // noise_test 첨부파일 기능 초기화
  if (formType === 'noise_test') setTimeout(() => initNoiseAttach(), 150);
  // emission_test 첨부파일 기능 초기화
  if (formType === 'emission_test') setTimeout(() => initEmissionAttach(), 150);
  // evap_test 첨부파일 기능 초기화
  if (formType === 'evap_test') setTimeout(() => initEvapAttach(), 150);
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

  // 4) cf-header-inp (확인서 헤더 입력 - 수입사, 연도 등 짧은 고정폭 제외)
  container.querySelectorAll('input[type="text"].cf-header-inp').forEach(replaceWithTextarea);

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

// 인쇄 버튼 클릭 시 QR이 준비됐는지 확인하고 인쇄
function printWithQR() {
  const wrap = document.getElementById('qr-footer-wrap');
  // 아직 로딩 중이거나 에러 상태면 잠시 기다린 후 인쇄
  if (wrap && wrap.querySelector('.qr-footer-pending')) {
    // QR이 pending이면 먼저 재생성 시도 후 인쇄
    const formType = currentFormType;
    const meta = FORM_META.find(m=>m.type===formType);
    if (meta) {
      generateFormQR(formType, meta.title).then(() => {
        setTimeout(() => window.print(), 300);
      });
      return;
    }
  }
  window.print();
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
  const btn = document.getElementById('save-all-btn');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>저장 중...';
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
      showToast(\`전체 \${successCount}개 서류가 저장되었습니다.\`, 'success');
    } else {
      showToast(\`\${successCount}개 저장 완료, \${failCount}개 실패\`, 'error');
    }
    // 최신 데이터 다시 로드
    await openApplication(currentApplicationId);
  } catch {
    showToast('저장 중 오류가 발생했습니다.', 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-save"></i>모두 저장';
  }
}

function printApplicationSummary() {
  window.print();
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
  // cert_type → 구분 기본값: 저장값이 없으면 현재 신청서의 cert_type 한글 라벨로 자동 채움
  const _certDefault = CERT_LABEL[currentApplication?.cert_type] || '';
  const v   = (k,def='') => {
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
.sv-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
}
/* ── 상단 헤더 4칸 테이블 ── */
.sv-header-tbl {
  width:100%; border-collapse:collapse;
  border:1px solid #888;
}
.sv-header-lbl-cell {
  width:25%; border:1px solid #888;
  padding:4px 8px; vertical-align:middle;
  background:rgba(79,142,247,.08);
}
.sv-header-val-cell {
  width:25%; border:1px solid #888;
  padding:4px 8px; vertical-align:middle;
}
.sv-header-lbl {
  display:block; font-size:.72rem; font-weight:700;
  color:var(--c-text2); margin-bottom:0;
  letter-spacing:.02em; text-align:center;
}
.sv-header-inp {
  width:100%; background:transparent;
  border:none; border-bottom:1px solid var(--c-border);
  color:var(--c-text); font-size:.9rem;
  padding:3px 0; outline:none;
}
.sv-header-inp:focus { border-bottom-color:var(--c-accent); }

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
  background:rgba(255,255,255,.02);
}
.sv-lbl {
  font-size:10pt; font-weight:500;
  padding:8px 10px; line-height:1.4;
  word-break:keep-all;
  background:rgba(255,255,255,.02);
}
.sv-val {
  padding:5px 10px;
}
.sv-val .sv-inp {
  width:100%; background:transparent;
  border:none; border-bottom:1px solid var(--c-border);
  color:var(--c-text); font-size:10pt;
  padding:4px 2px; outline:none;
}
.sv-val .sv-inp:focus { border-bottom-color:var(--c-accent); }
.sv-val .sv-sel {
  width:100%; background:transparent;
  border:1px solid var(--c-border);
  color:var(--c-text); font-size:10pt;
  padding:3px 4px; outline:none;
  border-radius:3px;
}
.sv-val .sv-sel:focus { border-color:var(--c-accent); }
.sv-val .sv-ta {
  width:100%; background:transparent;
  border:1px solid var(--c-border);
  color:var(--c-text); font-size:10pt;
  padding:4px 6px; outline:none; resize:vertical;
  border-radius:3px; min-height:52px;
}
.sv-val .sv-ta:focus { border-color:var(--c-accent); }

/* 4번 적용기준 구분선 */
.sv-sub-row {
  display:flex; align-items:center; gap:8px;
  padding:5px 10px;
}
.sv-sub-row + .sv-sub-row {
  border-top:1px solid var(--c-border);
}
.sv-sub-lbl {
  font-size:10pt; color:var(--c-text3);
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
.sv-rep-item-lbl { font-size:10pt; color:var(--c-text); white-space:nowrap; }
.sv-rep-item-inp {
  background:transparent;
  border:none; border-bottom:1px solid var(--c-border);
  color:var(--c-text); font-size:10pt;
  padding:2px 2px; outline:none; min-width:80px;
}
.sv-rep-item-inp:focus { border-bottom-color:var(--c-accent); }

/* 8번 보증기간 인라인 */
.sv-warranty-row {
  display:flex; align-items:center; gap:6px;
  padding:5px 10px;
}

@media screen {
  .sv-header-lbl-cell { border-color:var(--c-border); }
  .sv-header-val-cell { border-color:var(--c-border); }
  .sv-tbl thead th  { background:rgba(79,142,247,.10); color:var(--c-text); border-color:var(--c-border); }
  .sv-tbl th, .sv-tbl td { border-color:var(--c-border); }
  .sv-header-tbl    { border-color:var(--c-border); }
  .sv-title {
    background:rgba(79,142,247,.06);
    border-color:var(--c-border2); color:var(--c-text);
  }
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

  /* ── 상단 헤더 테이블 ── */
  .sv-header-tbl {
    border:1px solid #555 !important;
    width:100% !important; border-collapse:collapse !important;
  }
  .sv-header-lbl-cell {
    border:1px solid #555 !important;
    padding:3px 6px !important;
    background:#cdd5e8 !important;
    text-align:center !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }
  .sv-header-val-cell {
    border:1px solid #555 !important;
    padding:3px 6px !important;
    background:#fff !important;
  }
  .sv-header-lbl {
    font-size:8.5pt !important; font-weight:700 !important;
    color:#000 !important; display:block;
    letter-spacing:0 !important; text-transform:none !important;
    text-align:center !important;
  }
  .sv-header-inp {
    font-size:8.5pt !important; color:#000 !important;
    border:none !important; border-bottom:1px solid #888 !important;
    background:transparent !important; padding:1px 0 !important;
    width:100% !important; font-family:inherit !important;
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

<div class="sv-wrap">
  <!-- ① 상단 헤더 테이블 (4칸 균등 · PDF 동일 2행 구조) -->
  <table class="sv-header-tbl">
    <!-- 레이블 행 (배경색) -->
    <tr class="sv-header-row-lbl">
      <td class="sv-header-lbl-cell"><span class="sv-header-lbl">수입사</span></td>
      <td class="sv-header-lbl-cell"><span class="sv-header-lbl">인증연도</span></td>
      <td class="sv-header-lbl-cell"><span class="sv-header-lbl">배기량</span></td>
      <td class="sv-header-lbl-cell"><span class="sv-header-lbl">동일차종기호</span></td>
    </tr>
    <!-- 입력값 행 -->
    <tr class="sv-header-row-val">
      <td class="sv-header-val-cell"><input data-field="importer" class="sv-header-inp" type="text" placeholder="수입사명" value="\${E(v('importer'))}"></td>
      <td class="sv-header-val-cell"><input data-field="cert_year" class="sv-header-inp" type="text" placeholder="예) 2025" value="\${E(v('cert_year'))}"></td>
      <td class="sv-header-val-cell"><input data-field="displacement" class="sv-header-inp" type="text" placeholder="예) 1000cc" value="\${E(v('displacement'))}"></td>
      <td class="sv-header-val-cell"><input data-field="family_code" class="sv-header-inp" type="text" placeholder="기호 입력" value="\${E(v('family_code'))}"></td>
    </tr>
  </table>

  <!-- ② 제목 -->
  <div class="sv-title">배출가스 및 소음 인증신청 요약</div>

  <!-- ③ 본문 테이블 -->
  <table class="sv-tbl">
    <colgroup>
      <col class="sv-col-num">
      <col class="sv-col-label">
      <col class="sv-col-val">
    </colgroup>
    <thead>
      <tr>
        <th>구&nbsp;&nbsp;분</th>
        <th>항&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;목</th>
        <th>내&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;용</th>
      </tr>
    </thead>
    <tbody>
      <!-- 1. 제작사(제작국) -->
      <tr>
        <td class="sv-num">1</td>
        <td class="sv-lbl">제작사(제작국)</td>
        <td class="sv-val">
          <input data-field="maker" class="sv-inp" type="text" placeholder="예) PIAGGIO C.S.P.A(이태리)" value="\${E(v('maker'))}">
        </td>
      </tr>
      <!-- 2. 시험자동차 명칭(형식) -->
      <tr>
        <td class="sv-num">2</td>
        <td class="sv-lbl">시험자동차 명칭(형식)</td>
        <td class="sv-val">
          <input data-field="vehicle_name" class="sv-inp" type="text" placeholder="예) RSV4 1000 RR" value="\${E(v('vehicle_name'))}">
        </td>
      </tr>
      <!-- 3. 사용연료 -->
      <tr>
        <td class="sv-num">3</td>
        <td class="sv-lbl">사용연료</td>
        <td class="sv-val">
          <select data-field="fuel" class="sv-sel">
            <option value="" \${!v('fuel')?'selected':''}>선택</option>
            <option value="휘발유" \${v('fuel')==='휘발유'?'selected':''}>휘발유</option>
            <option value="경유"   \${v('fuel')==='경유'?'selected':''}>경유</option>
            <option value="전기"   \${v('fuel')==='전기'?'selected':''}>전기</option>
            <option value="LPG"   \${v('fuel')==='LPG'?'selected':''}>LPG</option>
          </select>
        </td>
      </tr>
      <!-- 4. 적용 기준 (배출가스 / 소음 2분할) -->
      <tr>
        <td class="sv-num" rowspan="2">4</td>
        <td class="sv-lbl" rowspan="2">적용 기준</td>
        <td style="padding:0;">
          <div class="sv-sub-row">
            <span class="sv-sub-lbl">배출가스</span>
            <input data-field="emission_std" class="sv-inp" type="text" placeholder="예) EURO 5" value="\${E(v('emission_std'))}" style="flex:1;min-width:0;">
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding:0;">
          <div class="sv-sub-row" style="border-top:1px solid var(--c-border);">
            <span class="sv-sub-lbl">소음</span>
            <input data-field="noise_std" class="sv-inp" type="text" placeholder="예) ECE R41-04" value="\${E(v('noise_std'))}" style="flex:1;min-width:0;">
          </div>
        </td>
      </tr>
      <!-- 5. 외국 기준 -->
      <tr>
        <td class="sv-num">5</td>
        <td class="sv-lbl">외국 기준<br><span style="font-weight:400;font-size:.88em;opacity:.7;">(유럽 또는 미국 기준)</span></td>
        <td class="sv-val">
          <input data-field="foreign_std" class="sv-inp" type="text" placeholder="예) EURO 5" value="\${E(v('foreign_std'))}">
        </td>
      </tr>
      <!-- 6. 증발가스 대표차 여부 및 자동차 명칭 -->
      <tr>
        <td class="sv-num">6</td>
        <td class="sv-lbl">증발가스 대표차 여부 및<br>자동차 명칭</td>
        <td style="padding:0;">
          <div class="sv-rep-inline">
            <div class="sv-rep-item">
              <span class="sv-rep-item-lbl">대표차량 :</span>
              <input data-field="evap_is_rep" class="sv-rep-item-inp" type="text" placeholder="대표/비대표" value="\${E(v('evap_is_rep'))}" style="width:90px;">
            </div>
            <div class="sv-rep-item">
              <span class="sv-rep-item-lbl">형식 :</span>
              <input data-field="evap_rep_model" class="sv-rep-item-inp" type="text" placeholder="차종 형식" value="\${E(v('evap_rep_model'))}" style="width:120px;">
            </div>
          </div>
        </td>
      </tr>
      <!-- 7. OBD 대표차 여부 및 자동차 명칭 -->
      <tr>
        <td class="sv-num">7</td>
        <td class="sv-lbl">OBD 대표차 여부 및<br>자동차 명칭</td>
        <td style="padding:0;">
          <div class="sv-rep-inline">
            <div class="sv-rep-item">
              <span class="sv-rep-item-lbl">대표차량 :</span>
              <input data-field="obd_is_rep" class="sv-rep-item-inp" type="text" placeholder="대표/비대표" value="\${E(v('obd_is_rep'))}" style="width:90px;">
            </div>
            <div class="sv-rep-item">
              <span class="sv-rep-item-lbl">형식 :</span>
              <input data-field="obd_rep_model" class="sv-rep-item-inp" type="text" placeholder="차종 형식" value="\${E(v('obd_rep_model'))}" style="width:120px;">
            </div>
          </div>
        </td>
      </tr>
      <!-- 8. 보증 기간 -->
      <tr>
        <td class="sv-num">8</td>
        <td class="sv-lbl">보증 기간</td>
        <td style="padding:0;">
          <div class="sv-warranty-row">
            <input data-field="warranty_year" class="sv-rep-item-inp" type="text" placeholder="년" value="\${E(v('warranty_year'))}" style="width:50px;text-align:right;">
            <span style="font-size:10pt;">년</span>
            <span style="font-size:10pt;">&nbsp;/&nbsp;</span>
            <input data-field="warranty_km" class="sv-rep-item-inp" type="text" placeholder="km" value="\${E(v('warranty_km'))}" style="width:90px;text-align:right;">
            <span style="font-size:10pt;">km</span>
          </div>
        </td>
      </tr>
      <!-- 9. 자체시험실시 내역 -->
      <tr>
        <td class="sv-num">9</td>
        <td class="sv-lbl">자체시험실시 내역</td>
        <td class="sv-val">
          <input data-field="self_test" class="sv-inp" type="text" placeholder="예) OBD, 소음, 증발가스" value="\${E(v('self_test'))}">
        </td>
      </tr>
      <!-- 10. 대표 기술 -->
      <tr>
        <td class="sv-num">10</td>
        <td class="sv-lbl">대표 기술</td>
        <td class="sv-val">
          <textarea data-field="key_tech" class="sv-ta" rows="3" placeholder="예) 산소센서, 삼원촉매, OBD, ECU, Idle control, 전자식 연료주입">\${E(v('key_tech'))}</textarea>
        </td>
      </tr>
    </tbody>
  </table>
</div>
<div id="qr-footer-wrap" style="margin-top:12px;"></div>
\`;

  if (formType==='gasoline') return \`
<style>
/* ══════════ gasoline 전용 스타일 ══════════ */
.g-wrap { box-sizing:border-box; }
.g-tbl  { width:100%; border-collapse:collapse; font-size:7pt; }
.g-tbl th, .g-tbl td {
  border:1px solid #888; padding:2px 3px;
  vertical-align:middle; word-break:keep-all; overflow-wrap:break-word;
}
.g-tbl th { background:#d0ddf0; font-weight:bold; text-align:center; }
.g-td-c  { text-align:center; background:#e8eef8; font-weight:600; white-space:nowrap; font-size:7pt; }
.g-td-n  { width:22px; text-align:center; background:#e8eef8; font-weight:700; font-size:7pt; }
.g-td-sub{ background:#f0f3f9; font-weight:600; white-space:nowrap; padding:2px 5px; font-size:7pt; }
.g-td-val{ padding:1px 3px; }
.g-ok-td { text-align:center; }

@media screen {
  .g-wrap { font-family:inherit; }
  .g-form-title {
    text-align:center; padding:10px 16px; font-size:10pt; font-weight:800;
    border-bottom:1px solid var(--c-border2); background:rgba(79,142,247,.06);
  }
  .g-header-grid {
    display:grid; grid-template-columns:repeat(4,1fr);
    border-bottom:1px solid var(--c-border2);
  }
  .g-header-cell { padding:4px 6px; border-right:1px solid var(--c-border); }
  .g-header-cell:last-child { border-right:none; }
  /* 기본(신청개요 제외) 섹션: 10pt */
  .g-header-label { font-size:10pt; font-weight:700; color:var(--c-text3); display:block; margin-bottom:2px; }
  .g-sec-title {
    font-size:10pt; font-weight:800; color:var(--c-accent);
    padding:6px 14px; border-bottom:1px solid var(--c-border2);
    background:rgba(79,142,247,.04); display:flex; align-items:center; gap:5px;
  }
  .g-sub-title { font-size:10pt; font-weight:700; color:var(--c-text2); padding:5px 14px 2px; }
  .g-sec-inner { padding:6px 14px; }
  .g-note { font-size:10pt; color:var(--c-text3); padding:3px 14px; }
  .g-tbl { font-size:10pt; }
  .g-tbl th { background:rgba(79,142,247,.10); color:var(--c-text); border-color:var(--c-border); }
  .g-tbl td { border-color:var(--c-border); }
  /* 구분·연료·허용기준 등 헤더셀: 화면에서 10pt 강제 */
  .g-td-c  { background:rgba(79,142,247,.06); color:var(--c-text2); font-size:10pt !important; white-space:normal; }
  .g-td-n  { background:rgba(79,142,247,.06); color:var(--c-text2); font-size:10pt !important; }
  .g-td-sub{ background:rgba(255,255,255,.02); color:var(--c-text2); font-size:10pt !important; white-space:normal; }
  .g-chk-row {
    display:flex; align-items:center; gap:5px; padding:3px 2px;
    font-size:10pt; cursor:pointer;
  }
  .g-chk-row input[type=checkbox] { width:13px; height:13px; accent-color:var(--c-accent); flex-shrink:0; }
  select.g-sel { font-size:10pt; padding:1px 3px; height:22px; }
  input.g-inp  { font-size:10pt; }

  /* ── 신청 개요 전용: 7pt ── */
  .g-overview-section .g-sec-title { font-size:10pt; }
  .g-overview-section .g-tbl { font-size:7pt; }
  .g-overview-section .g-tbl th,
  .g-overview-section .g-tbl td { font-size:7pt !important; padding:1px 2px; }
  .g-overview-section .g-td-c  { font-size:7pt !important; }
  .g-overview-section .g-td-n  { font-size:7pt !important; }
  .g-overview-section .g-td-sub{ font-size:7pt !important; }
  .g-overview-section input.g-inp  { font-size:7pt; }
  .g-overview-section select.g-sel { font-size:7pt; height:18px; padding:0 2px; }
}

@media print {
  .g-wrap {
    font-family:'맑은 고딕','Malgun Gothic',sans-serif;
    font-size:7pt; color:#000;
  }
  /* 세로 방향 인쇄 */
  @page { size: A4 portrait; margin:10mm 8mm; }

  .g-form-title {
    text-align:center; font-size:11pt; font-weight:bold;
    padding:4px 0; border-bottom:2px solid #000; margin-bottom:3px;
  }
  .g-header-grid {
    display:table; width:100%; border:1px solid #000; margin-bottom:3px;
  }
  .g-header-cell {
    display:table-cell; width:25%; padding:2px 5px; border-right:1px solid #000;
  }
  .g-header-cell:last-child { border-right:none; }
  .g-header-label { font-size:6pt; color:#444; display:block; }
  .g-sec-title {
    font-weight:bold; font-size:8pt; margin:4px 0 2px;
    padding:0; background:none; color:#000; display:block;
  }
  .g-sub-title { font-weight:bold; font-size:7.5pt; margin:3px 0 1px; padding:0; }
  .g-sec-inner { padding:0; }
  .g-note { font-size:6.5pt; margin:2px 0; padding:0; color:#333; }
  .g-tbl { font-size:6.5pt; }
  .g-tbl th {
    background:#d0ddf0 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }
  .g-td-c {
    background:#e8eef8 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }
  .g-td-sub {
    background:#f0f3f9 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }
  /* 촉매/O₂센서 셀 인쇄 시 10pt 유지 */
  .g-td-sub[style*="font-size:10pt"] {
    font-size:10pt !important;
  }
  .g-td-n {
    background:#e8eef8 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }
  /* input/select/textarea → 인쇄 시 내용만 표시 */
  input.input, input.g-inp {
    border:none !important; background:transparent !important;
    padding:0 !important; margin:0 !important;
    font-size:inherit !important; font-family:inherit !important;
    color:#000 !important; -webkit-appearance:none; appearance:none;
    outline:none; display:inline-block;
    width:100% !important; min-width:0 !important; box-sizing:border-box !important;
  }
  select.input, select.g-sel {
    border:none !important; background:transparent !important;
    padding:0 !important; margin:0 !important;
    font-size:inherit !important; font-family:inherit !important;
    color:#000 !important; -webkit-appearance:none; appearance:none;
    outline:none; display:inline; width:auto !important;
  }
  textarea.input, textarea.auto-grow {
    border:none !important; background:transparent !important;
    padding:0 !important; margin:0 !important;
    font-size:inherit !important; font-family:inherit !important;
    color:#000 !important; -webkit-appearance:none; appearance:none;
    resize:none !important; outline:none;
    display:block; width:100% !important; box-sizing:border-box !important;
    height:auto !important; min-height:0 !important; overflow:visible !important;
    white-space:pre-wrap; word-break:break-all;
  }
  /* g-td-val 안 div > input/textarea: 인쇄 시 전체 너비 확보 */
  .g-td-val div { display:block !important; }
  .g-td-val div input.g-inp, .g-td-val div textarea.auto-grow {
    width:100% !important; display:block !important; box-sizing:border-box !important;
  }
  /* 신청개요 인쇄 전용: 작은 글씨로 한 페이지 내 수용 */
  .g-overview-tbl { font-size:5.5pt !important; }
  .g-overview-tbl th, .g-overview-tbl td {
    padding:1px 2px !important;
    font-size:5.5pt !important;
    word-break:break-all !important;
  }
}
</style>

<!-- ■ 제목 + 헤더 -->
<div class="form-section g-wrap" style="padding:0;overflow:hidden;">
  <div class="g-form-title">휘발유차 인증신청 주요내용</div>
  <div class="g-header-grid">
    <div class="g-header-cell">
      <span class="g-header-label">수입사</span>
      <input data-field="importer" class="input g-inp" type="text" placeholder="수입사명" value="\${E(v('importer'))}" style="width:100%;">
    </div>
    <div class="g-header-cell">
      <span class="g-header-label">인증연도</span>
      <input data-field="cert_year" class="input g-inp" type="text" placeholder="예) 2025" value="\${E(v('cert_year'))}" style="width:100%;">
    </div>
    <div class="g-header-cell">
      <span class="g-header-label">배기량</span>
      <input data-field="displacement_cc" class="input g-inp" type="text" placeholder="예) 999cc" value="\${E(v('displacement_cc'))}" style="width:100%;">
    </div>
    <div class="g-header-cell">
      <span class="g-header-label">동일차종기호</span>
      <input data-field="family_code" class="input g-inp" type="text" placeholder="기호 입력" value="\${E(v('family_code'))}" style="width:100%;">
    </div>
  </div>
</div>

<!-- ■ PAGE 1 : 신청 개요 -->
<div class="form-section g-wrap g-overview-section" style="padding:0;overflow:hidden;margin-top:10px;">
  <div class="g-sec-title">□ 신청 개요</div>
  <div style="overflow-x:auto;padding:4px 6px 8px;">
    <table class="g-tbl g-overview-tbl" style="width:100%;table-layout:fixed;">
      <colgroup>
        <col style="width:9%;"><!-- 구분 -->
        <col style="width:10%;"><!-- 신청일 -->
        <col style="width:10%;"><!-- 제작사 -->
        <col style="width:13%;"><!-- 차명(형식) -->
        <col style="width:9%;"><!-- 차종 -->
        <col style="width:12%;"><!-- 출력 -->
        <col style="width:10%;"><!-- 적용기준 배출 -->
        <col style="width:10%;"><!-- 적용기준 소음 -->
        <col style="width:11%;"><!-- 인증번호 -->
        <col style="width:6%;"><!-- 비고 -->
      </colgroup>
      <thead>
        <tr>
          <th>구분</th>
          <th>신청일</th>
          <th>제작사</th>
          <th>차명<br>(형식)</th>
          <th>차종<br>(연료)</th>
          <th>출력(ps/rpm)<br>(배기량cc)</th>
          <th>적용기준<br>배출</th>
          <th>적용기준<br>소음</th>
          <th>인증번호</th>
          <th>비고</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td class="g-td-val">
            <select data-field="appl_div" class="input g-sel" style="width:100%;">
              \${ ['기본인증','변경인증','변경보고'].map(o=>\`<option value="\${o}" \${v('appl_div')===o?'selected':''}>\${o}</option>\`).join('') }
            </select>
          </td>
          <td class="g-td-val"><input data-field="appl_date" class="input g-inp" type="text" placeholder="YYYY-MM-DD" value="\${E(v('appl_date'))}" style="width:100%;"></td>
          <td class="g-td-val"><input data-field="maker" class="input g-inp" type="text" placeholder="제작사" value="\${E(v('maker'))}" style="width:100%;"></td>
          <td class="g-td-val"><input data-field="vehicle_name" class="input g-inp" type="text" placeholder="차명(형식)" value="\${E(v('vehicle_name'))}" style="width:100%;"></td>
          <td class="g-td-val">
            <select data-field="fuel_type" class="input g-sel" style="width:100%;">
              <option value="">(선택)</option>
              \${ ['휘발유','경유','LPG','전기'].map(o=>\`<option value="\${o}" \${v('fuel_type')===o?'selected':''}>\${o}</option>\`).join('') }
            </select>
          </td>
          <td class="g-td-val">
            <input data-field="power_rpm" class="input g-inp" type="text" placeholder="출력/rpm" value="\${E(v('power_rpm'))}" style="width:100%;display:block;margin-bottom:1px;">
            <input data-field="displacement_cc2" class="input g-inp" type="text" placeholder="배기량cc" value="\${E(v('displacement_cc2'))}" style="width:100%;">
          </td>
          <td class="g-td-val"><input data-field="emission_std_appl" class="input g-inp" type="text" placeholder="-" value="\${E(v('emission_std_appl'))}" style="width:100%;"></td>
          <td class="g-td-val"><input data-field="noise_std_appl" class="input g-inp" type="text" placeholder="-" value="\${E(v('noise_std_appl'))}" style="width:100%;"></td>
          <td class="g-td-val"><input data-field="cert_no" class="input g-inp" type="text" placeholder="인증번호" value="\${E(v('cert_no'))}" style="width:100%;"></td>
          <td class="g-td-val"><input data-field="appl_note" class="input g-inp" type="text" placeholder="-" value="\${E(v('appl_note'))}" style="width:100%;"></td>
        </tr>
      </tbody>
    </table>
  </div>
</div>

<!-- ■ PAGE 1 : 신청 유형 -->
<div class="form-section g-wrap" style="padding:0;overflow:hidden;margin-top:10px;">
  <div class="g-sec-title">□ 신청 유형</div>
  <!-- ★ 신청유형 아래 대표차종 안내 문구 (PDF 예시 반영) -->
  <div style="padding:4px 12px 6px;font-size:10pt;line-height:2.0;">
    <div style="display:flex;align-items:center;gap:0;">
      <span style="min-width:16px;">-</span>
      <span>EURO – 5 기준 적용 휘발유 이륜자동차 대표&nbsp;&nbsp;</span>
      <input data-field="rep_euro5_count" class="input g-inp" type="text" value="\${E(v('rep_euro5_count'))}" style="width:90px;border-bottom:1px solid #888;border-top:none;border-left:none;border-right:none;background:transparent;text-align:center;">
      <span>&nbsp;&nbsp;차종 인증신청</span>
    </div>
    <div style="display:flex;align-items:center;gap:0;">
      <span style="min-width:16px;">-</span>
      <span>OBD 대표&nbsp;&nbsp;</span>
      <input data-field="rep_obd_count" class="input g-inp" type="text" value="\${E(v('rep_obd_count'))}" style="width:90px;border-bottom:1px solid #888;border-top:none;border-left:none;border-right:none;background:transparent;text-align:center;">
      <span>&nbsp;&nbsp;차종,&nbsp;&nbsp;&nbsp;&nbsp;증발가스 대표&nbsp;&nbsp;</span>
      <input data-field="rep_evap_count" class="input g-inp" type="text" value="\${E(v('rep_evap_count'))}" style="width:90px;border-bottom:1px solid #888;border-top:none;border-left:none;border-right:none;background:transparent;text-align:center;">
      <span>&nbsp;&nbsp;차종</span>
    </div>
  </div>
  <div style="overflow-x:auto;padding:3px 10px 10px;">
    <table class="g-tbl" style="min-width:460px;table-layout:auto;">
      <thead>
        <tr>
          <th style="width:55px;">구분</th>
          <th style="width:42px;">연료</th>
          <th>인증서 기재 내용</th>
          <th style="width:58px;">해당여부</th>
        </tr>
      </thead>
      <tbody>
        <!-- ★ 배출가스 (휘발유 4행 통합 + 경유 1행) -->
        <tr>
          <td class="g-td-c" rowspan="5">배출가스</td>
          <td class="g-td-sub" rowspan="4">휘발유</td>
          <td style="font-size:10pt;">* 13년 휘발유 기준2의 나</td>
          <td class="g-ok-td"><select data-field="t_emis_g1" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_emis_g1')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td style="font-size:10pt;">* 13년 휘발유 기준1의 나</td>
          <td class="g-ok-td"><select data-field="t_emis_g2" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_emis_g2')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td style="font-size:10pt;">* 16년 휘발유 기준</td>
          <td class="g-ok-td"><select data-field="t_emis_g3" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_emis_g3')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td style="font-size:10pt;">* 20년 1월 이륜자동차(130km/h 이하) 기준</td>
          <td class="g-ok-td"><select data-field="t_emis_g4" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_emis_g4')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td class="g-td-sub">경유</td>
          <td style="font-size:10pt;">* 14년 9월 경유 소형승용 기준</td>
          <td class="g-ok-td"><select data-field="t_emis_d1" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_emis_d1')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <!-- ★ OBD2 (휘발유 5행 통합 + 경유 2행 통합) -->
        <tr>
          <td class="g-td-c" rowspan="7">OBD2</td>
          <td class="g-td-sub" rowspan="5">휘발유</td>
          <td style="font-size:10pt;">* OBD2 휘발유 기준 적용 대표(IUPR 1st 기준)</td>
          <td class="g-ok-td"><select data-field="t_obd_g1" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_obd_g1')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td style="font-size:10pt;">* OBD2 휘발유 기준 적용 동일 (대표: <input data-field="t_obd_g2_rep" class="input g-inp" type="text" placeholder="대표차명" value="\${E(v('t_obd_g2_rep'))}" style="width:70px;">, IUPR 1st)</td>
          <td class="g-ok-td"><select data-field="t_obd_g2" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_obd_g2')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td style="font-size:10pt;">* OBD2 휘발유 EURO6 기준 적용 대표(IUPR 2nd 기준)</td>
          <td class="g-ok-td"><select data-field="t_obd_g3" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_obd_g3')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td style="font-size:10pt;">* OBD2 휘발유 EURO6 기준 적용 대표 (대표: <input data-field="t_obd_g4_rep" class="input g-inp" type="text" placeholder="대표차명" value="\${E(v('t_obd_g4_rep'))}" style="width:70px;">, IUPR 2nd)</td>
          <td class="g-ok-td"><select data-field="t_obd_g4" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_obd_g4')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td style="font-size:10pt;">* OBD2 휘발유 EURO6 이륜자동차 기준 적용 대표(OBD Stage 2)</td>
          <td class="g-ok-td"><select data-field="t_obd_g5" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_obd_g5')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td class="g-td-sub" rowspan="2">경유</td>
          <td style="font-size:10pt;">* OBD2 경유 (다)기준 적용 대표 (IUPR 2nd 기준)</td>
          <td class="g-ok-td"><select data-field="t_obd_d1" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_obd_d1')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td style="font-size:10pt;">* OBD2 경유 (다)기준 적용 동일 (대표: <input data-field="t_obd_d2_rep" class="input g-inp" type="text" placeholder="대표차명" value="\${E(v('t_obd_d2_rep'))}" style="width:70px;">, IUPR 2nd)</td>
          <td class="g-ok-td"><select data-field="t_obd_d2" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_obd_d2')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <!-- 증발가스 -->
        <tr>
          <td class="g-td-c" rowspan="2">증발가스</td>
          <td colspan="2" style="font-size:10pt;">* 증발가스 대표</td>
          <td class="g-ok-td"><select data-field="t_evap1" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_evap1')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td colspan="2" style="font-size:10pt;">* 증발가스 동일 (대표: <input data-field="t_evap2_rep" class="input g-inp" type="text" placeholder="대표차명" value="\${E(v('t_evap2_rep'))}" style="width:70px;">)</td>
          <td class="g-ok-td"><select data-field="t_evap2" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_evap2')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <!-- ★ 보증기간 (휘발유 5행 통합 + 경유 1행) -->
        <tr>
          <td class="g-td-c" rowspan="6">보증기간</td>
          <td class="g-td-sub" rowspan="5">휘발유</td>
          <td style="font-size:10pt;">* 보증기간 : 10년 / 19만2천km</td>
          <td class="g-ok-td"><select data-field="t_warr_g1" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_warr_g1')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td style="font-size:10pt;">* 보증기간 : 10년 / 24만km</td>
          <td class="g-ok-td"><select data-field="t_warr_g2" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_warr_g2')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td style="font-size:10pt;">* 보증기간 : 15년 / 24만km</td>
          <td class="g-ok-td"><select data-field="t_warr_g3" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_warr_g3')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td style="font-size:10pt;">* 보증기간 : 02년 / 3.5만km</td>
          <td class="g-ok-td"><select data-field="t_warr_g4" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_warr_g4')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td style="font-size:10pt;">* 보증기간 : 02년 / 2만km</td>
          <td class="g-ok-td"><select data-field="t_warr_g5" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_warr_g5')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
        <tr>
          <td class="g-td-sub">경유</td>
          <td style="font-size:10pt;">* 보증기간 : 10년 / 16만km</td>
          <td class="g-ok-td"><select data-field="t_warr_d1" class="input g-sel" style="width:56px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v('t_warr_d1')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
        </tr>
      </tbody>
    </table>
  </div>
</div>

<!-- ■ PAGE 2 : 상세 내역 -->
<div class="form-section g-wrap" style="padding:0;overflow:hidden;margin-top:10px;">
  <div class="g-sec-title">□ 상세 내역</div>

  <!-- 가. 적용기술 -->
  <div class="g-sub-title">가. 적용기술</div>
  <div class="g-sec-inner">
    <div style="display:flex;gap:4px;align-items:flex-start;margin-bottom:4px;">
      <span style="flex-shrink:0;font-weight:600;font-size:10pt;">-</span>
      <textarea data-field="tech1" class="input" rows="2" placeholder="적용기술 내용 1" style="width:100%;font-size:10pt;">\${E(v('tech1'))}</textarea>
    </div>
    <div style="display:flex;gap:4px;align-items:flex-start;">
      <span style="flex-shrink:0;font-weight:600;font-size:10pt;">-</span>
      <textarea data-field="tech2" class="input" rows="2" placeholder="적용기술 내용 2" style="width:100%;font-size:10pt;">\${E(v('tech2'))}</textarea>
    </div>
  </div>

  <!-- 나. 자체시험 결과 -->
  <div class="g-sub-title">나. 자체시험 결과</div>
  <div class="g-sec-inner">
    <div style="font-size:10pt;margin-bottom:3px;">
      <span style="font-weight:700;">- 배출가스 :</span>
      <input data-field="self_test_emis" class="input g-inp" type="text" value="\${E(v('self_test_emis'))}" style="width:calc(100% - 90px);margin-left:4px;">
    </div>
    <div style="font-size:10pt;margin-bottom:6px;">
      <span style="font-weight:700;">- 소&nbsp;&nbsp;&nbsp;음 :</span>
      <input data-field="self_test_noise" class="input g-inp" type="text" value="\${E(v('self_test_noise'))}" style="width:calc(100% - 90px);margin-left:4px;">
    </div>

    <!-- 자체시험 결과 표: CO/NOx/THC/NMHC/증발가스/CO2/가속주행/배기소음/경적소음 -->
    <div style="overflow-x:auto;">
      <table class="g-tbl" style="min-width:580px;table-layout:fixed;">
        <colgroup>
          <col style="width:52px;"><!-- 구분 -->
          <col style="width:50px;"><!-- CO -->
          <col style="width:50px;"><!-- NOx -->
          <col style="width:48px;"><!-- THC -->
          <col style="width:52px;"><!-- NMHC -->
          <col style="width:58px;"><!-- 증발가스 -->
          <col style="width:46px;"><!-- CO2 -->
          <col style="width:54px;"><!-- 가속주행 dB(A) -->
          <col style="width:52px;"><!-- 배기소음 dB(A) -->
          <col style="width:52px;"><!-- 경적소음 dB(C) -->
        </colgroup>
        <thead>
          <tr>
            <th rowspan="2">구분</th>
            <th>CO</th>
            <th>NOx</th>
            <th colspan="3" style="text-align:center;">탄화수소</th>
            <th>CO₂</th>
            <th>가속주행</th>
            <th>배기소음</th>
            <th>경적소음</th>
          </tr>
          <tr>
            <th>(g/km)</th>
            <th>(g/km)</th>
            <th>THC<br>(g/km)</th>
            <th>NMHC<br>(g/km)</th>
            <th>증발가스<br>(g/Test)</th>
            <th>(g/km)</th>
            <th>dB(A)</th>
            <th>dB(A)</th>
            <th>dB(C)</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="g-td-c">허용기준</td>
            <td class="g-td-val"><input data-field="std_co" class="input g-inp" type="text" value="\${E(v('std_co'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="std_nox" class="input g-inp" type="text" value="\${E(v('std_nox'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="std_thc" class="input g-inp" type="text" value="\${E(v('std_thc'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="std_nmhc" class="input g-inp" type="text" value="\${E(v('std_nmhc'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="std_evap" class="input g-inp" type="text" value="\${E(v('std_evap'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="std_co2" class="input g-inp" type="text" value="\${E(v('std_co2'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="std_accel" class="input g-inp" type="text" value="\${E(v('std_accel'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="std_exhaust" class="input g-inp" type="text" value="\${E(v('std_exhaust'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="std_horn" class="input g-inp" type="text" value="\${E(v('std_horn'))}" style="width:100%;"></td>
          </tr>
          <tr>
            <td class="g-td-c">시험결과</td>
            <td class="g-td-val"><input data-field="res_co" class="input g-inp" type="text" value="\${E(v('res_co'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="res_nox" class="input g-inp" type="text" value="\${E(v('res_nox'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="res_thc" class="input g-inp" type="text" value="\${E(v('res_thc'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="res_nmhc" class="input g-inp" type="text" value="\${E(v('res_nmhc'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="res_evap" class="input g-inp" type="text" value="\${E(v('res_evap'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="res_co2" class="input g-inp" type="text" value="\${E(v('res_co2'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="res_accel" class="input g-inp" type="text" value="\${E(v('res_accel'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="res_exhaust" class="input g-inp" type="text" value="\${E(v('res_exhaust'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="res_horn" class="input g-inp" type="text" value="\${E(v('res_horn'))}" style="width:100%;"></td>
          </tr>
          <tr>
            <td class="g-td-c">기준만족도</td>
            <td class="g-td-val"><input data-field="rate_co" class="input g-inp" type="text" value="\${E(v('rate_co'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="rate_nox" class="input g-inp" type="text" value="\${E(v('rate_nox'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="rate_thc" class="input g-inp" type="text" value="\${E(v('rate_thc'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="rate_nmhc" class="input g-inp" type="text" value="\${E(v('rate_nmhc'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="rate_evap" class="input g-inp" type="text" value="\${E(v('rate_evap'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="rate_co2" class="input g-inp" type="text" value="\${E(v('rate_co2'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="rate_accel" class="input g-inp" type="text" value="\${E(v('rate_accel'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="rate_exhaust" class="input g-inp" type="text" value="\${E(v('rate_exhaust'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="rate_horn" class="input g-inp" type="text" value="\${E(v('rate_horn'))}" style="width:100%;"></td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- OBD 감시장치 시험결과 표 -->
    <!-- PDF 구조: 장치명 | 오작동재현조건 | WMTC결과(CO/NOx/HC) | 오작동표시등 | 오작동판단기준(CO/NOx/HC) | 적부판정 -->
    <!-- 감시장치: 촉매 + O₂센서(열화) 만 -->
    <div style="overflow-x:auto;margin-top:6px;">
      <table class="g-tbl" style="min-width:580px;table-layout:fixed;">
        <colgroup>
          <col style="width:52px;"><!-- 장치명 -->
          <col style="width:70px;"><!-- 오작동재현조건 -->
          <col style="width:44px;"><!-- WMTC CO -->
          <col style="width:44px;"><!-- WMTC NOx -->
          <col style="width:44px;"><!-- WMTC HC -->
          <col style="width:52px;"><!-- 표시등 -->
          <col style="width:44px;"><!-- 기준 CO -->
          <col style="width:44px;"><!-- 기준 NOx -->
          <col style="width:44px;"><!-- 기준 HC -->
          <col style="width:52px;"><!-- 적부판정 -->
        </colgroup>
        <thead>
          <tr>
            <th rowspan="2">시험대상<br>감시장치</th>
            <th rowspan="2">오작동<br>재현조건</th>
            <th colspan="3">WMTC 모드 결과 (g/km)</th>
            <th rowspan="2">오작동<br>표시등<br>점등여부</th>
            <th colspan="3">오작동 판단 기준 (g/km)</th>
            <th rowspan="2">감시장치<br>적부판정</th>
          </tr>
          <tr>
            <th>CO</th><th>NOx</th><th>HC</th>
            <th>CO</th><th>NOx</th><th>HC</th>
          </tr>
        </thead>
        <tbody>
          <!-- 촉매 행 -->
          <tr>
            <td class="g-td-sub" style="font-size:10pt;">촉매</td>
            <td class="g-td-val"><input data-field="obd_cat_cond" class="input g-inp" type="text" value="\${E(v('obd_cat_cond'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="obd_cat_co" class="input g-inp" type="text" value="\${E(v('obd_cat_co'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="obd_cat_nox" class="input g-inp" type="text" value="\${E(v('obd_cat_nox'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="obd_cat_hc" class="input g-inp" type="text" value="\${E(v('obd_cat_hc'))}" style="width:100%;"></td>
            <td class="g-ok-td"><select data-field="obd_cat_lamp" class="input g-sel" style="width:100%;">\${ ['','점등','미점등'].map(o=>\`<option value="\${o}" \${v('obd_cat_lamp')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
            <td class="g-td-val"><input data-field="obd_cat_std_co" class="input g-inp" type="text" value="\${E(v('obd_cat_std_co'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="obd_cat_std_nox" class="input g-inp" type="text" value="\${E(v('obd_cat_std_nox'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="obd_cat_std_hc" class="input g-inp" type="text" value="\${E(v('obd_cat_std_hc'))}" style="width:100%;"></td>
            <td class="g-ok-td"><select data-field="obd_cat_pass" class="input g-sel" style="width:100%;">\${ ['','OK','NO'].map(o=>\`<option value="\${o}" \${v('obd_cat_pass')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
          </tr>
          <!-- O₂센서 열화 행 -->
          <tr>
            <td class="g-td-sub" style="font-size:10pt;">O₂센서</td>
            <td class="g-td-val"><input data-field="obd_o2_cond" class="input g-inp" type="text" value="\${E(v('obd_o2_cond'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="obd_o2_co" class="input g-inp" type="text" value="\${E(v('obd_o2_co'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="obd_o2_nox" class="input g-inp" type="text" value="\${E(v('obd_o2_nox'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="obd_o2_hc" class="input g-inp" type="text" value="\${E(v('obd_o2_hc'))}" style="width:100%;"></td>
            <td class="g-ok-td"><select data-field="obd_o2_lamp" class="input g-sel" style="width:100%;">\${ ['','점등','미점등'].map(o=>\`<option value="\${o}" \${v('obd_o2_lamp')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
            <td class="g-td-val"><input data-field="obd_o2_std_co" class="input g-inp" type="text" value="\${E(v('obd_o2_std_co'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="obd_o2_std_nox" class="input g-inp" type="text" value="\${E(v('obd_o2_std_nox'))}" style="width:100%;"></td>
            <td class="g-td-val"><input data-field="obd_o2_std_hc" class="input g-inp" type="text" value="\${E(v('obd_o2_std_hc'))}" style="width:100%;"></td>
            <td class="g-ok-td"><select data-field="obd_o2_pass" class="input g-sel" style="width:100%;">\${ ['','OK','NO'].map(o=>\`<option value="\${o}" \${v('obd_o2_pass')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="g-note">
      주 1) 지정열화계수 적용 (CO: <input data-field="df_co" class="input g-inp" type="text" value="\${E(v('df_co'))}" style="width:35px;">,
      NOx: <input data-field="df_nox" class="input g-inp" type="text" value="\${E(v('df_nox'))}" style="width:35px;">,
      THC: <input data-field="df_thc" class="input g-inp" type="text" value="\${E(v('df_thc'))}" style="width:35px;">,
      증발가스: <input data-field="df_evap" class="input g-inp" type="text" value="\${E(v('df_evap'))}" style="width:35px;">)<br>
      주 2) 기준만족도(%) = 시험결과 / 기준치 × 100&nbsp;&nbsp;
      ※ 연비 : <input data-field="fuel_econ" class="input g-inp" type="text" value="\${E(v('fuel_econ'))}" style="width:50px;"> km/L
    </div>
  </div>
</div>

<!-- ■ 다. 항목별 제원 및 시험결과 등 -->
<div class="form-section g-wrap" style="padding:0;overflow:hidden;margin-top:10px;">
  <div class="g-sec-title">다. 항목별 제원 및 시험결과 등</div>
  <div style="overflow-x:auto;padding:6px 10px 10px;">
    <table class="g-tbl" style="min-width:500px;table-layout:fixed;">
      <colgroup>
        <col style="width:24px;">
        <col style="width:75px;">
        <col>
      </colgroup>
      <thead>
        <tr>
          <th>구분</th><th>항 목</th><th>내 용</th>
        </tr>
      </thead>
      <tbody>

        <!-- 1. 촉매,DPF 등 후처리장치 -->
        <tr>
          <td class="g-td-n">1</td>
          <td class="g-td-sub">촉매, DPF 등<br>후처리장치</td>
          <td class="g-td-val">
            <textarea data-field="item1_cat_spec" class="input" rows="3" style="width:100%;font-size:10pt;" placeholder="후처리장치 내용 입력">\${E(v('item1_cat_spec'))}</textarea>
          </td>
        </tr>

        <!-- 2. 증발가스 -->
        <tr>
          <td class="g-td-n">2</td>
          <td class="g-td-sub">증발가스</td>
          <td class="g-td-val">
            <div style="font-size:10pt;font-weight:700;margin-bottom:2px;">□ 증발가스 대표/동일 여부</div>
            <div style="font-size:10pt;">- <input data-field="item2_evap_rep" class="input g-inp" type="text" style="width:calc(100% - 14px);" value="\${E(v('item2_evap_rep'))}"></div>
          </td>
        </tr>

        <!-- 3. 블로바이가스 -->
        <tr>
          <td class="g-td-n">3</td>
          <td class="g-td-sub">블로바이가스</td>
          <td class="g-td-val">
            <div style="font-size:10pt;font-weight:700;margin-bottom:2px;">□ 블로바이가스 제어장치</div>
            <div style="font-size:10pt;">- <input data-field="item3_blowby" class="input g-inp" type="text" style="width:calc(100% - 14px);" value="\${E(v('item3_blowby'))}"></div>
          </td>
        </tr>

        <!-- 4. 배출가스자기진단장치(OBD2) -->
        <tr>
          <td class="g-td-n" rowspan="3">4</td>
          <td class="g-td-sub" rowspan="3">배출가스<br>자기진단<br>장치(OBD2)</td>
          <td class="g-td-val">
            <div style="font-size:10pt;font-weight:700;margin-bottom:2px;">□ OBD2 대표/동일 여부</div>
            <div style="font-size:10pt;">- <input data-field="item4_obd_rep" class="input g-inp" type="text" style="width:calc(100% - 14px);" value="\${E(v('item4_obd_rep'))}"></div>
          </td>
        </tr>
        <tr>
          <td class="g-td-val">
            <div style="font-size:10pt;font-weight:700;margin-bottom:3px;">□ 배출가스자기진단장치 기준</div>
            <table class="g-tbl" style="width:100%;">
              <thead><tr><th>OBD 기준명</th><th style="width:52px;">해당여부</th></tr></thead>
              <tbody>
                \${ [
                  ['obd_std_g1','휘발유 2006년 OBD 기준'],
                  ['obd_std_g2','휘발유 2013년 OBD IUPR 1st 기준'],
                  ['obd_std_g3','휘발유 2013년 OBD IUPR 2nd(2016년 1월) 기준'],
                  ['obd_std_g4','휘발유 EURO6 OBD IUPR 2nd 기준'],
                  ['obd_std_g5','휘발유 EURO5 OBD 이륜자동차 기준(OBD Stage 2) 기준'],
                  ['obd_std_d1','경유 2006년 OBD 기준'],
                  ['obd_std_d2','경유 2012년 OBD IUPR 1st 기준'],
                  ['obd_std_d3','경유 2014년 9월 OBD IUPR 2nd 기준']
                ].map(([field,label])=>\`<tr>
                  <td style="font-size:10pt;">\${label}</td>
                  <td class="g-ok-td"><select data-field="\${field}" class="input g-sel" style="width:50px;">\${ ['','해당','미해당'].map(o=>\`<option value="\${o}" \${v(field)===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
                </tr>\`).join('') }
              </tbody>
            </table>
          </td>
        </tr>
        <tr>
          <td class="g-td-val">
            <div style="font-size:10pt;font-weight:700;margin-bottom:2px;">□ OBD2 오작동 판정기준</div>
            <div style="font-size:10pt;">- <input data-field="item4_obd_fault1" class="input g-inp" type="text" style="width:calc(100% - 14px);" value="\${E(v('item4_obd_fault1'))}"></div>
            <div style="font-size:10pt;margin-top:2px;">- <input data-field="item4_obd_fault2" class="input g-inp" type="text" style="width:calc(100% - 14px);" value="\${E(v('item4_obd_fault2'))}"></div>
            <div style="font-size:10pt;font-weight:700;margin:4px 0 3px;">□ OBD2 감시항목별 시험여부</div>
            <table class="g-tbl" style="width:100%;">
              <thead><tr><th>감시항목</th><th style="width:50px;">시험여부</th><th>시험차명</th></tr></thead>
              <tbody>
                \${ [
                  ['mon_o2','산소센서'],
                  ['mon_egr','배기가스 재순환계통'],
                  ['mon_vvt','가변밸브타이밍계통'],
                  ['mon_fuel','연료계통'],
                  ['mon_mis','실화'],
                  ['mon_air','2차 공기계통'],
                  ['mon_cat','촉매']
                ].map(([field,label])=>\`<tr>
                  <td style="font-size:10pt;">\${label}</td>
                  <td class="g-ok-td"><select data-field="\${field}_yn" class="input g-sel" style="width:48px;">\${ ['','O','X'].map(o=>\`<option value="\${o}" \${v(field+'_yn')===o?'selected':''}>\${o}</option>\`).join('') }</select></td>
                  <td><input data-field="\${field}_car" class="input g-inp" type="text" style="width:100%;font-size:10pt;" value="\${E(v(field+'_car'))}"></td>
                </tr>\`).join('') }
              </tbody>
            </table>
          </td>
        </tr>
        <!-- 5. 시험시설 -->
        <tr>
          <td class="g-td-n">5</td>
          <td class="g-td-sub">시험시설</td>
          <td class="g-td-val">
            <div style="font-size:10pt;font-weight:700;margin-bottom:2px;">□ 자체시험을 실시한 시설에 대한 시설확인 내역</div>
            <div style="font-size:10pt;">- <input data-field="item5_fac1" class="input g-inp" type="text" style="width:calc(100% - 14px);" value="\${E(v('item5_fac1'))}"></div>
            <div style="font-size:10pt;margin-top:2px;">- <input data-field="item5_fac2" class="input g-inp" type="text" style="width:calc(100% - 14px);" value="\${E(v('item5_fac2'))}"></div>
          </td>
        </tr>

        <!-- 6. 시험차 선정근거 -->
        <tr>
          <td class="g-td-n">6</td>
          <td class="g-td-sub">시험차<br>선정근거</td>
          <td class="g-td-val">
            <div style="font-size:10pt;font-weight:700;margin-bottom:2px;">□ 배출가스 시험자동차 선정근거</div>
            <textarea data-field="item6_emis_basis" class="input" rows="2" style="width:100%;font-size:10pt;">\${E(v('item6_emis_basis'))}</textarea>
            <div style="font-size:10pt;font-weight:700;margin:3px 0 2px;">□ 소음 시험자동차 선정근거</div>
            <textarea data-field="item6_noise_basis" class="input" rows="2" style="width:100%;font-size:10pt;">\${E(v('item6_noise_basis'))}</textarea>
            <div style="font-size:10pt;font-weight:700;margin:3px 0 2px;">□ OBD 시험자동차 선정근거</div>
            <textarea data-field="item6_obd_basis" class="input" rows="2" style="width:100%;font-size:10pt;">\${E(v('item6_obd_basis'))}</textarea>
          </td>
        </tr>

        <!-- 7. 배출가스 시험 -->
        <tr>
          <td class="g-td-n">7</td>
          <td class="g-td-sub">배출가스<br>시험</td>
          <td class="g-td-val">
            <div style="font-size:10pt;font-weight:700;margin-bottom:2px;">□ 배출가스 시험모드 및 시험 회수</div>
            <div style="font-size:10pt;">- <input data-field="item7_mode" class="input g-inp" type="text" style="width:calc(100% - 14px);" value="\${E(v('item7_mode'))}"></div>
            <div style="font-size:10pt;font-weight:700;margin:3px 0 2px;">□ 배출가스 자체시험 성적서 제출 내역</div>
            <div style="font-size:10pt;">- <input data-field="item7_cert1" class="input g-inp" type="text" style="width:calc(100% - 14px);" value="\${E(v('item7_cert1'))}"></div>
            <div style="font-size:10pt;margin-top:2px;">- <input data-field="item7_cert2" class="input g-inp" type="text" style="width:calc(100% - 14px);" value="\${E(v('item7_cert2'))}"></div>
          </td>
        </tr>

        <!-- 8. 증발가스 시험 -->
        <tr>
          <td class="g-td-n">8</td>
          <td class="g-td-sub">증발가스<br>시험</td>
          <td class="g-td-val">
            <div style="font-size:10pt;font-weight:700;margin-bottom:2px;">□ 증발가스 자체시험 성적서 제출 내역</div>
            <div style="font-size:10pt;">- <input data-field="item8_cert" class="input g-inp" type="text" style="width:calc(100% - 14px);" value="\${E(v('item8_cert'))}"></div>
          </td>
        </tr>

        <!-- 9. 보증기간 및 열화계수 -->
        <tr>
          <td class="g-td-n" rowspan="2">9</td>
          <td class="g-td-sub" rowspan="2">보증기간 및<br>열화계수</td>
          <td class="g-td-val">
            <div style="font-size:10pt;font-weight:700;margin-bottom:2px;">□ 보증기간 및 열화계수 적용 내역</div>
            <div style="font-size:10pt;">- 보증기간 : <input data-field="item9_warr_km" class="input g-inp" type="text" style="width:60px;" value="\${E(v('item9_warr_km'))}"> km</div>
            <div style="font-size:10pt;margin-top:2px;">- 제작자동차 인증 및 검사 방법과 절차 등에 관한 규정 제21조 및 시행규칙 별표12 지정열화계수에 근거한 열화계수 적용</div>
          </td>
        </tr>
        <tr>
          <td class="g-td-val">
            <table class="g-tbl" style="width:100%;">
              <thead><tr><th>항목</th><th>적용 열화계수</th></tr></thead>
              <tbody>
                <tr><td class="g-td-sub" style="font-size:10pt;">일산화탄소(CO)</td><td class="g-td-val"><input data-field="item9_df_co" class="input g-inp" type="text" style="width:100%;font-size:10pt;" value="\${E(v('item9_df_co'))}"></td></tr>
                <tr><td class="g-td-sub" style="font-size:10pt;">배기관 탄화수소</td><td class="g-td-val"><input data-field="item9_df_hc" class="input g-inp" type="text" style="width:100%;font-size:10pt;" value="\${E(v('item9_df_hc'))}"></td></tr>
                <tr><td class="g-td-sub" style="font-size:10pt;">질소산화물</td><td class="g-td-val"><input data-field="item9_df_nox" class="input g-inp" type="text" style="width:100%;font-size:10pt;" value="\${E(v('item9_df_nox'))}"></td></tr>
                <tr><td class="g-td-sub" style="font-size:10pt;">증발 탄화수소</td><td class="g-td-val"><input data-field="item9_df_evap" class="input g-inp" type="text" style="width:100%;font-size:10pt;" value="\${E(v('item9_df_evap'))}"></td></tr>
              </tbody>
            </table>
          </td>
        </tr>

        <!-- 10. 내구 시험 -->
        <tr>
          <td class="g-td-n">10</td>
          <td class="g-td-sub">내구 시험</td>
          <td class="g-td-val">
            <div style="font-size:10pt;font-weight:700;margin-bottom:2px;">□ 내구시험 내역</div>
            <textarea data-field="item10_dur" class="input" rows="2" style="width:100%;font-size:10pt;">\${E(v('item10_dur'))}</textarea>
          </td>
        </tr>

        <!-- 11. 주기적재생지수(ki) 시험 -->
        <tr>
          <td class="g-td-n">11</td>
          <td class="g-td-sub">주기적재생<br>지수(ki)시험</td>
          <td class="g-td-val">
            <div style="font-size:10pt;font-weight:700;margin-bottom:2px;">□</div>
            <textarea data-field="item11_ki" class="input" rows="2" style="width:100%;font-size:10pt;">\${E(v('item11_ki'))}</textarea>
          </td>
        </tr>

        <!-- 12. 소음시험 -->
        <tr>
          <td class="g-td-n">12</td>
          <td class="g-td-sub">소음시험</td>
          <td class="g-td-val" style="min-height:120px;">
            <div style="font-size:10pt;font-weight:700;margin-bottom:2px;">□ 소음시험 성적서 제출 내역</div>
            <table style="width:100%;border:none;border-collapse:collapse;">
              <tr><td style="font-size:10pt;padding:1px 0;white-space:nowrap;">-</td><td style="width:100%;padding:1px 2px;"><input data-field="item12_cert1" class="input g-inp" type="text" style="width:100%;" value="\${E(v('item12_cert1'))}"></td></tr>
              <tr><td style="font-size:10pt;padding:1px 0;white-space:nowrap;">-</td><td style="width:100%;padding:1px 2px;"><input data-field="item12_cert2" class="input g-inp" type="text" style="width:100%;" value="\${E(v('item12_cert2'))}"></td></tr>
              <tr><td style="font-size:10pt;padding:1px 0;white-space:nowrap;">-</td><td style="width:100%;padding:1px 2px;"><input data-field="item12_cert3" class="input g-inp" type="text" style="width:100%;" value="\${E(v('item12_cert3'))}"></td></tr>
            </table>
            <div style="font-size:10pt;font-weight:700;margin:4px 0 2px;">□ 소음 시험방법</div>
            <table style="width:100%;border:none;border-collapse:collapse;">
              <tr><td style="font-size:10pt;padding:1px 0;white-space:nowrap;">- 가속주행소음 :</td><td style="width:100%;padding:1px 2px;"><input data-field="item12_accel" class="input g-inp" type="text" style="width:100%;" value="\${E(v('item12_accel'))}"></td></tr>
              <tr><td style="font-size:10pt;padding:1px 0;white-space:nowrap;">- 배기소음 :</td><td style="width:100%;padding:1px 2px;"><input data-field="item12_exhaust" class="input g-inp" type="text" style="width:100%;" value="\${E(v('item12_exhaust'))}"></td></tr>
              <tr><td style="font-size:10pt;padding:1px 0;white-space:nowrap;">- 경적소음 :</td><td style="width:100%;padding:1px 2px;"><input data-field="item12_horn" class="input g-inp" type="text" style="width:100%;" value="\${E(v('item12_horn'))}"></td></tr>
            </table>
          </td>
        </tr>

        <!-- 13. 동일차종 구성 -->
        <tr>
          <td class="g-td-n">13</td>
          <td class="g-td-sub">동일차종<br>구성</td>
          <td class="g-td-val">
            <div style="font-size:10pt;">- <textarea data-field="item13_fam1" class="input" rows="3" style="width:calc(100% - 14px);font-size:10pt;">\${E(v('item13_fam1'))}</textarea></div>
          </td>
        </tr>

      </tbody>
    </table>
  </div>
</div>
<div id="qr-footer-wrap" style="margin-top:12px;"></div>
\`;


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
      fld('PM 목표 (g/km)','target_pm','number'))+
    '<div id="qr-footer-wrap" style="margin-top:12px;"></div>'
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
      fld('배기소음 측정값 (dB(A))','exhaust_noise_meas','number')+fld('배기소음 기준값 (dB(A))','exhaust_noise_std','number'))+
    '<div id="qr-footer-wrap" style="margin-top:12px;"></div>'
  );

  if (formType==='obd_config') return \`
<style>
/* ══════ obd_config 전용 스타일 ══════ */
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
.obd-inp {
  border:none; background:transparent;
  width:100%; font-size:8.5pt;
  font-family:inherit; padding:0 2px;
  box-sizing:border-box; color:#111;
}
.obd-inp::placeholder { color:#aaa; }
.obd-inp:focus { outline:none; border-bottom:1px solid #4e90d8; }
.obd-section-label {
  font-size:8.5pt; font-weight:700;
  padding:4px 6px; color:#111;
  vertical-align:top;
}
.obd-img-cell {
  text-align:center; vertical-align:middle;
  color:#999; font-size:8pt; padding:8px;
  min-height:60px;
}
@media print {
  .obd-wrap { background:#fff !important; color:#000 !important; border-radius:0 !important; }
  .obd-tbl th, .obd-tbl td { border:1px solid #333 !important; color:#000 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .obd-inp { border:none !important; background:transparent !important; color:#000 !important; font-size:8.5pt !important; font-family:'맑은 고딕','Malgun Gothic',sans-serif !important; }
  .obd-sec-th { background:#d6e4f7 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .obd-th { background:#eef3fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .obd-lbl { background:#f5f8ff !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
}
</style>

<div class="obd-wrap">

  <!-- ── 상단 헤더 (수입사/인증연도/배기량/동일차종기호) ── -->
  <!-- PDF 측정: x=55.3,174.3,290.5,406.6,539.6 → 24.6%|24.0%|23.9%|27.5% -->
  <table class="obd-tbl" style="margin-bottom:12px; table-layout:fixed;">
    <colgroup>
      <col style="width:24.6%;"><col style="width:24.0%;"><col style="width:23.9%;"><col style="width:27.5%;">
    </colgroup>
    <thead>
      <tr>
        <th class="obd-th">수입사</th>
        <th class="obd-th">인증연도</th>
        <th class="obd-th">배기량</th>
        <th class="obd-th">동일차종기호</th>
      </tr>
    </thead>
    <tbody>
      <tr style="height:26px;">
        <td><input data-field="obd_importer"  class="obd-inp" type="text" value="\${E(v('obd_importer'))}"></td>
        <td><input data-field="obd_cert_year" class="obd-inp" type="text" value="\${E(v('obd_cert_year'))}"></td>
        <td><input data-field="obd_disp"      class="obd-inp" type="text" value="\${E(v('obd_disp'))}"></td>
        <td><input data-field="obd_fam_code"  class="obd-inp" type="text" value="\${E(v('obd_fam_code'))}"></td>
      </tr>
    </tbody>
  </table>

  <div class="obd-doc-tag">[별지 제9호 서식]</div>
  <div class="obd-main-title">배출가스자기진단장치(OBD) 구성에 관한 서류</div>

  <!-- ══════════════════════════════════════════════════════ -->
  <!-- 1. 배출가스자기진단장치(OBD) 종합정보에 관한 서류    -->
  <!-- PAGE1: x=55.3,143.2,304.9,539.6 → 18.0%|33.5%|48.5% -->
  <!-- ══════════════════════════════════════════════════════ -->
  <table class="obd-tbl" style="table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:18.0%;"><col style="width:33.5%;"><col style="width:48.5%;">
    </colgroup>
    <tbody>
      <tr>
        <th class="obd-sec-th" colspan="3">1. 배출가스자기진단장치(OBD) 종합정보에 관한 서류</th>
      </tr>
      <!-- 가. 부품 목록 -->
      <tr>
        <td class="obd-lbl" colspan="3" style="padding:4px 6px; font-size:8.5pt;">
          가. 센서·액츄에이터 등의 부품들과 같이 배출가스 자기진단장치에 의해 감시되는 자동차 배출가스 관련 부품 목록 및 기능적인 특성을 설명하는 자료
        </td>
      </tr>
      <tr>
        <th class="obd-th">구&nbsp;&nbsp;분</th>
        <th class="obd-th">자동차 배출가스 관련 부품</th>
        <th class="obd-th">기능적인 작동 특성</th>
      </tr>
      <!-- 센서 rowspan=5 -->
      <tr>
        <td class="obd-lbl" rowspan="5" style="text-align:center;">센&nbsp;&nbsp;서</td>
        <td class="obd-lbl">크랭크 포지션 센서(CPS)</td>
        <td><input data-field="obd_cps_func" class="obd-inp" type="text" value="\${E(v('obd_cps_func'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">온도 공기압 센서(T-MAP)</td>
        <td><input data-field="obd_tmap_func" class="obd-inp" type="text" value="\${E(v('obd_tmap_func'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">스로틀 포지션 센서(TPS)</td>
        <td><input data-field="obd_tps_func" class="obd-inp" type="text" value="\${E(v('obd_tps_func'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">엔진 온도 센서(WPS)</td>
        <td><input data-field="obd_wps_func" class="obd-inp" type="text" value="\${E(v('obd_wps_func'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">산소 센서(O₂)</td>
        <td><input data-field="obd_o2_func" class="obd-inp" type="text" value="\${E(v('obd_o2_func'))}"></td>
      </tr>
      <!-- 액츄에이터 rowspan=5 -->
      <tr>
        <td class="obd-lbl" rowspan="5" style="text-align:center;">액츄에이터</td>
        <td class="obd-lbl">연료분사장치(인젝터)</td>
        <td><input data-field="obd_inj_func" class="obd-inp" type="text" value="\${E(v('obd_inj_func'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">점화코일</td>
        <td><input data-field="obd_coil_func" class="obd-inp" type="text" value="\${E(v('obd_coil_func'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">O₂ 센서 히터</td>
        <td><input data-field="obd_o2h_func" class="obd-inp" type="text" value="\${E(v('obd_o2h_func'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">와이어 액츄에이터에 의한 스로틀</td>
        <td><input data-field="obd_wire_func" class="obd-inp" type="text" value="\${E(v('obd_wire_func'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">라디에이터 팬 릴레이</td>
        <td><input data-field="obd_fan_func" class="obd-inp" type="text" value="\${E(v('obd_fan_func'))}"></td>
      </tr>
      <!-- 기타 rowspan=2 -->
      <tr>
        <td class="obd-lbl" rowspan="2" style="text-align:center;">기&nbsp;&nbsp;타</td>
        <td class="obd-lbl">연료 펌프 릴레이</td>
        <td><input data-field="obd_pump_func" class="obd-inp" type="text" value="\${E(v('obd_pump_func'))}"></td>
      </tr>
      <tr>
        <td><input data-field="obd_etc_part" class="obd-inp" type="text" placeholder="기타 부품명" value="\${E(v('obd_etc_part'))}"></td>
        <td><input data-field="obd_etc_func" class="obd-inp" type="text" value="\${E(v('obd_etc_func'))}"></td>
      </tr>
      <!-- 나. 오작동 표시등 -->
      <tr>
        <td class="obd-lbl" colspan="3" style="padding:4px 6px; font-size:8.5pt;">
          나. 오작동을 알려주는 오작동표시등에 관한 설명자료
        </td>
      </tr>
      <tr>
        <td colspan="2" style="padding:4px 6px;">
          <input data-field="obd_mil_desc" class="obd-inp" type="text"
            placeholder="예) 이륜자동차에 결함코드가 확인되면 계기판에 엔진 체크등이 점등됨."
            value="\${E(v('obd_mil_desc'))}">
        </td>
        <td class="obd-img-cell" style="border-left:1px solid #888;">
          오작동 표시등의 형태 및 위치 이미지 첨부
        </td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════ -->
  <!-- PAGE2: 제어·자동표시기·인디케이터 위치 및 식별 기호  -->
  <!-- 2열: 22%|77%                                          -->
  <!-- ══════════════════════════════════════════════════════ -->
  <table class="obd-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:22%;"><col style="width:78%;">
    </colgroup>
    <tbody>
      <tr>
        <th class="obd-sec-th" colspan="2">제어, 자동표시기, 인디케이터 위치 및 식별 기호</th>
      </tr>
      <tr>
        <td class="obd-lbl" style="text-align:center; padding:5px 4px;">왼쪽 핸들 스위치의<br>제어 및 기호 도면<br>또는 이미지 첨부</td>
        <td class="obd-img-cell" style="min-height:80px;">
          <input data-field="obd_left_handle" class="obd-inp" type="text" placeholder="이미지 설명 또는 첨부 안내" value="\${E(v('obd_left_handle'))}">
        </td>
      </tr>
      <tr>
        <td class="obd-lbl" style="text-align:center; padding:5px 4px;">오른쪽 핸들 스위치의<br>제어 및 기호 도면<br>또는 이미지 첨부</td>
        <td class="obd-img-cell" style="min-height:80px;">
          <input data-field="obd_right_handle" class="obd-inp" type="text" placeholder="이미지 설명 또는 첨부 안내" value="\${E(v('obd_right_handle'))}">
        </td>
      </tr>
      <tr>
        <td class="obd-lbl" style="text-align:center; padding:5px 4px;">키박스 도면 또는<br>이미지 첨부</td>
        <td class="obd-img-cell" style="min-height:60px;">
          <input data-field="obd_keybox" class="obd-inp" type="text" placeholder="이미지 설명 또는 첨부 안내" value="\${E(v('obd_keybox'))}">
        </td>
      </tr>
      <!-- 다. 무단변경 금지 -->
      <tr>
        <td class="obd-lbl" colspan="2" style="padding:4px 6px; font-size:8.5pt;">
          다. 무단변경 및 배기가스제어컴퓨터의 수정을 금지하는 문구
        </td>
      </tr>
      <tr>
        <td colspan="2" style="padding:4px 6px;">
          <input data-field="obd_no_tamper" class="obd-inp" type="text"
            placeholder="예) 기계적으로 ECU는 임의로 설정을 변경할 수 없습니다. ECU ASSY는 부착 및 밀폐되어 있으며..."
            value="\${E(v('obd_no_tamper'))}">
        </td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════ -->
  <!-- PAGE3 라. 감시장치 기술적 설명자료                    -->
  <!-- 마. 기타 추가정보: 2열 83.6%|16.4%                   -->
  <!-- ══════════════════════════════════════════════════════ -->
  <table class="obd-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:100%;">
    </colgroup>
    <tbody>
      <tr>
        <td class="obd-lbl" style="padding:4px 6px; font-size:8.5pt;">
          라. 감시장치의 기술적인 설명자료(일반적인 작동원리)
        </td>
      </tr>
      <tr>
        <td style="padding:4px 8px; font-size:8pt; color:#555; line-height:1.8;">
          01. 촉매 감시장치 : <input data-field="obd_diag_01" class="obd-inp" type="text" style="width:80%;" placeholder="해당 사항 없음" value="\${E(v('obd_diag_01'))}"><br>
          02. 매연여과장치 감시장치 : <input data-field="obd_diag_02" class="obd-inp" type="text" style="width:78%;" placeholder="해당 사항 없음" value="\${E(v('obd_diag_02'))}"><br>
          03. 전자분사시스템 감시장치 : <input data-field="obd_diag_03" class="obd-inp" type="text" style="width:77%;" placeholder="해당 사항 없음" value="\${E(v('obd_diag_03'))}"><br>
          04. 배출가스자기진단장치에 의해 감시되는 부품들 : <input data-field="obd_diag_04" class="obd-inp" type="text" style="width:54%;" placeholder="부록 첨부" value="\${E(v('obd_diag_04'))}"><br>
          05. 오작동표시등 점등을 위한 기준 : <input data-field="obd_diag_05" class="obd-inp" type="text" style="width:67%;" placeholder="부록 첨부" value="\${E(v('obd_diag_05'))}"><br>
          06. 모든 배출가스자기진단장치 출력코드 목록과 사용된 양식 : <input data-field="obd_diag_06" class="obd-inp" type="text" style="width:40%;" placeholder="부록 첨부" value="\${E(v('obd_diag_06'))}">
        </td>
      </tr>
    </tbody>
  </table>

  <!-- 마. 기타 추가정보 (2열: 83.6%|16.4%) -->
  <!-- PDF 측정: x=55.3,460.0,539.6 → 83.6%|16.4% -->
  <table class="obd-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:83.6%;"><col style="width:16.4%;">
    </colgroup>
    <tbody>
      <tr>
        <td class="obd-lbl" colspan="2" style="padding:4px 6px; font-size:8.5pt;">
          마. 기타 추가정보
        </td>
      </tr>
      <tr>
        <th class="obd-th" style="text-align:left; padding:3px 8px;">시험 요구 사항 작동 기준(Ⅰ) 형</th>
        <th class="obd-th">적합 여부</th>
      </tr>
      <tr>
        <td style="padding:4px 8px; font-size:8.5pt; line-height:1.7;">
          오작동 재현을 위한 부품 또는 오작동 모터사이클을 위한 전자 장비를 장착한 차량을 시험할 때, 오작동 판단 기준 이하에서 오작동 경고등이 점등되며 배출가스 자기진단장치는 적합한 것으로 판정됨<br>
          배출가스 관련 부품 또는 배출가스와 관련되고 엔진 제어장치에 연결된 파워트레인 관련 부품의 전기적인 연속성을 감시하여야 함
        </td>
        <td style="text-align:center;">
          <input data-field="obd_ma_pass" class="obd-inp" type="text" placeholder="적합/부적합" value="\${E(v('obd_ma_pass'))}">
        </td>
      </tr>
    </tbody>
  </table>

  <!-- 마. 세부항목 3열 (PDF: x=55.3,216.7,378.2,539.6 → 33.3%|33.3%|33.4%) -->
  <table class="obd-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:33.3%;"><col style="width:33.3%;"><col style="width:33.4%;">
    </colgroup>
    <tbody>
      <tr>
        <td style="padding:4px 8px; font-size:8.5pt;">
          01. 오작동 확인시험을 위한 준비싸이클의 형식과 회수에 대한 설명 :
          <input data-field="obd_ma_01" class="obd-inp" type="text" placeholder="부록 첨부" value="\${E(v('obd_ma_01'))}">
        </td>
        <td style="padding:4px 8px; font-size:8.5pt;">
          02. 배출가스자기진단장치에 의해 감시되는 부품에 대한 확인시험을 위한 시험싸이클의 형식에 관한 설명 :
          <input data-field="obd_ma_02" class="obd-inp" type="text" placeholder="부록 첨부" value="\${E(v('obd_ma_02'))}">
        </td>
        <td style="padding:4px 8px; font-size:8.5pt;">
          03. 배출가스자기진단장치에 의해 감시되는 구성부품들에 대한 2차 감시변수들의 목록, 오작동 확인 및 오작동표시등 점등을 위한 방법을 포함한 포괄적인 설명자료 :
          <input data-field="obd_ma_03" class="obd-inp" type="text" placeholder="부록 첨부" value="\${E(v('obd_ma_03'))}">
        </td>
      </tr>
    </tbody>
  </table>

  <!-- 바. 자체시험결과 및 기술적 설명자료 -->
  <!-- PDF 측정: x=55.3,216.7,378.2,460.0,539.6 → 33.3%|33.3%|16.9%|16.4% -->
  <table class="obd-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:33.3%;"><col style="width:33.3%;"><col style="width:16.9%;"><col style="width:16.4%;">
    </colgroup>
    <tbody>
      <tr>
        <th class="obd-sec-th" colspan="4">바. 자체시험결과 및 기술적 설명자료 – 시험결과</th>
      </tr>
      <tr>
        <th class="obd-th">부품 점검</th>
        <th class="obd-th">MI 활성화 시기</th>
        <th class="obd-th" colspan="2">메모리에 저장된 오류코드 수정</th>
      </tr>
      <tr>
        <td><input data-field="obd_ba_part" class="obd-inp" type="text" value="\${E(v('obd_ba_part'))}"></td>
        <td><input data-field="obd_ba_mi"   class="obd-inp" type="text" value="\${E(v('obd_ba_mi'))}"></td>
        <td colspan="2"><input data-field="obd_ba_dtc"  class="obd-inp" type="text" value="\${E(v('obd_ba_dtc'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════ -->
  <!-- PAGE4: OBD 감시부품 테스트 및 진단                    -->
  <!-- PDF: x=55.3,189.7,259.2,314.5,361.2,458.9,539.6      -->
  <!-- → 27.8%|14.4%|11.4%|9.6%|20.2%|16.7%                -->
  <!-- ══════════════════════════════════════════════════════ -->
  <table class="obd-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:27.8%;"><col style="width:14.4%;"><col style="width:11.4%;"><col style="width:9.6%;"><col style="width:20.2%;"><col style="width:16.7%;">
    </colgroup>
    <tbody>
      <tr>
        <th class="obd-sec-th" colspan="6">OBD 감시부품의 테스트 및 진단</th>
      </tr>
      <tr>
        <th class="obd-th">항&nbsp;&nbsp;목</th>
        <th class="obd-th">부품/하네스</th>
        <th class="obd-th">스위치</th>
        <th class="obd-th">시&nbsp;동</th>
        <th class="obd-th">규&nbsp;&nbsp;격</th>
        <th class="obd-th">오작동표시등 점등</th>
      </tr>
      <tr>
        <td class="obd-lbl">크랭크 포지션 센서(CPS)</td>
        <td><input data-field="obd_t_cps_harn"  class="obd-inp" type="text" value="\${E(v('obd_t_cps_harn'))}"></td>
        <td><input data-field="obd_t_cps_sw"    class="obd-inp" type="text" value="\${E(v('obd_t_cps_sw'))}"></td>
        <td><input data-field="obd_t_cps_start" class="obd-inp" type="text" value="\${E(v('obd_t_cps_start'))}"></td>
        <td><input data-field="obd_t_cps_spec"  class="obd-inp" type="text" value="\${E(v('obd_t_cps_spec'))}"></td>
        <td><input data-field="obd_t_cps_mil"   class="obd-inp" type="text" value="\${E(v('obd_t_cps_mil'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">온도 공기압 센서(T-MAP)</td>
        <td><input data-field="obd_t_tmap_harn"  class="obd-inp" type="text" value="\${E(v('obd_t_tmap_harn'))}"></td>
        <td><input data-field="obd_t_tmap_sw"    class="obd-inp" type="text" value="\${E(v('obd_t_tmap_sw'))}"></td>
        <td><input data-field="obd_t_tmap_start" class="obd-inp" type="text" value="\${E(v('obd_t_tmap_start'))}"></td>
        <td><input data-field="obd_t_tmap_spec"  class="obd-inp" type="text" value="\${E(v('obd_t_tmap_spec'))}"></td>
        <td><input data-field="obd_t_tmap_mil"   class="obd-inp" type="text" value="\${E(v('obd_t_tmap_mil'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">스로틀 포지션 센서(TPS)</td>
        <td><input data-field="obd_t_tps_harn"  class="obd-inp" type="text" value="\${E(v('obd_t_tps_harn'))}"></td>
        <td><input data-field="obd_t_tps_sw"    class="obd-inp" type="text" value="\${E(v('obd_t_tps_sw'))}"></td>
        <td><input data-field="obd_t_tps_start" class="obd-inp" type="text" value="\${E(v('obd_t_tps_start'))}"></td>
        <td><input data-field="obd_t_tps_spec"  class="obd-inp" type="text" value="\${E(v('obd_t_tps_spec'))}"></td>
        <td><input data-field="obd_t_tps_mil"   class="obd-inp" type="text" value="\${E(v('obd_t_tps_mil'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">엔진 온도 센서(WPS)</td>
        <td><input data-field="obd_t_wps_harn"  class="obd-inp" type="text" value="\${E(v('obd_t_wps_harn'))}"></td>
        <td><input data-field="obd_t_wps_sw"    class="obd-inp" type="text" value="\${E(v('obd_t_wps_sw'))}"></td>
        <td><input data-field="obd_t_wps_start" class="obd-inp" type="text" value="\${E(v('obd_t_wps_start'))}"></td>
        <td><input data-field="obd_t_wps_spec"  class="obd-inp" type="text" value="\${E(v('obd_t_wps_spec'))}"></td>
        <td><input data-field="obd_t_wps_mil"   class="obd-inp" type="text" value="\${E(v('obd_t_wps_mil'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">산소 센서(O₂)</td>
        <td><input data-field="obd_t_o2_harn"  class="obd-inp" type="text" value="\${E(v('obd_t_o2_harn'))}"></td>
        <td><input data-field="obd_t_o2_sw"    class="obd-inp" type="text" value="\${E(v('obd_t_o2_sw'))}"></td>
        <td><input data-field="obd_t_o2_start" class="obd-inp" type="text" value="\${E(v('obd_t_o2_start'))}"></td>
        <td><input data-field="obd_t_o2_spec"  class="obd-inp" type="text" value="\${E(v('obd_t_o2_spec'))}"></td>
        <td><input data-field="obd_t_o2_mil"   class="obd-inp" type="text" value="\${E(v('obd_t_o2_mil'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">연료분사장치(인젝터)</td>
        <td><input data-field="obd_t_inj_harn"  class="obd-inp" type="text" value="\${E(v('obd_t_inj_harn'))}"></td>
        <td><input data-field="obd_t_inj_sw"    class="obd-inp" type="text" value="\${E(v('obd_t_inj_sw'))}"></td>
        <td><input data-field="obd_t_inj_start" class="obd-inp" type="text" value="\${E(v('obd_t_inj_start'))}"></td>
        <td><input data-field="obd_t_inj_spec"  class="obd-inp" type="text" value="\${E(v('obd_t_inj_spec'))}"></td>
        <td><input data-field="obd_t_inj_mil"   class="obd-inp" type="text" value="\${E(v('obd_t_inj_mil'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">점화코일</td>
        <td><input data-field="obd_t_coil_harn"  class="obd-inp" type="text" value="\${E(v('obd_t_coil_harn'))}"></td>
        <td><input data-field="obd_t_coil_sw"    class="obd-inp" type="text" value="\${E(v('obd_t_coil_sw'))}"></td>
        <td><input data-field="obd_t_coil_start" class="obd-inp" type="text" value="\${E(v('obd_t_coil_start'))}"></td>
        <td><input data-field="obd_t_coil_spec"  class="obd-inp" type="text" value="\${E(v('obd_t_coil_spec'))}"></td>
        <td><input data-field="obd_t_coil_mil"   class="obd-inp" type="text" value="\${E(v('obd_t_coil_mil'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">O₂ 센서 히터</td>
        <td><input data-field="obd_t_o2h_harn"  class="obd-inp" type="text" value="\${E(v('obd_t_o2h_harn'))}"></td>
        <td><input data-field="obd_t_o2h_sw"    class="obd-inp" type="text" value="\${E(v('obd_t_o2h_sw'))}"></td>
        <td><input data-field="obd_t_o2h_start" class="obd-inp" type="text" value="\${E(v('obd_t_o2h_start'))}"></td>
        <td><input data-field="obd_t_o2h_spec"  class="obd-inp" type="text" value="\${E(v('obd_t_o2h_spec'))}"></td>
        <td><input data-field="obd_t_o2h_mil"   class="obd-inp" type="text" value="\${E(v('obd_t_o2h_mil'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">와이어 액츄에이터에 의한 스로틀</td>
        <td><input data-field="obd_t_wire_harn"  class="obd-inp" type="text" value="\${E(v('obd_t_wire_harn'))}"></td>
        <td><input data-field="obd_t_wire_sw"    class="obd-inp" type="text" value="\${E(v('obd_t_wire_sw'))}"></td>
        <td><input data-field="obd_t_wire_start" class="obd-inp" type="text" value="\${E(v('obd_t_wire_start'))}"></td>
        <td><input data-field="obd_t_wire_spec"  class="obd-inp" type="text" value="\${E(v('obd_t_wire_spec'))}"></td>
        <td><input data-field="obd_t_wire_mil"   class="obd-inp" type="text" value="\${E(v('obd_t_wire_mil'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">라디에이터 팬 릴레이</td>
        <td><input data-field="obd_t_fan_harn"  class="obd-inp" type="text" value="\${E(v('obd_t_fan_harn'))}"></td>
        <td><input data-field="obd_t_fan_sw"    class="obd-inp" type="text" value="\${E(v('obd_t_fan_sw'))}"></td>
        <td><input data-field="obd_t_fan_start" class="obd-inp" type="text" value="\${E(v('obd_t_fan_start'))}"></td>
        <td><input data-field="obd_t_fan_spec"  class="obd-inp" type="text" value="\${E(v('obd_t_fan_spec'))}"></td>
        <td><input data-field="obd_t_fan_mil"   class="obd-inp" type="text" value="\${E(v('obd_t_fan_mil'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════ -->
  <!-- 2. 동일차종 설명에 관한 서류                          -->
  <!-- PAGE4 가. 자동차 제원 - 일반제원 6열                  -->
  <!-- ══════════════════════════════════════════════════════ -->
  <!-- ══════════════════════════════════════════════════════ -->
  <!-- 2. 동일차종 설명에 관한 서류                          -->
  <!-- PAGE4 가. 자동차 제원                                 -->
  <!-- ══════════════════════════════════════════════════════ -->
  <table class="obd-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <tbody>
      <tr>
        <th class="obd-sec-th" colspan="6">2. 동일차종 설명에 관한 서류</th>
      </tr>
      <tr>
        <th class="obd-sec-th" colspan="6">가. 자동차 제원(자기진단동일차종 중 대표차종)</th>
      </tr>
      <!-- 01. 일반 제원 -->
      <tr>
        <td class="obd-lbl" colspan="6" style="padding:3px 6px;">01. 일반 제원</td>
      </tr>
    </tbody>
  </table>

  <!-- PDF: x=55.3,134.7,214.1,293.5,355.5,424.0,539.6 → 16.4%|16.4%|16.4%|12.8%|14.1%|23.9% -->
  <table class="obd-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:16.4%;"><col style="width:16.4%;"><col style="width:16.4%;"><col style="width:12.8%;"><col style="width:14.1%;"><col style="width:23.9%;">
    </colgroup>
    <tbody>
      <tr>
        <th class="obd-th">차&nbsp;&nbsp;명</th>
        <th class="obd-th">형&nbsp;&nbsp;식</th>
        <th class="obd-th">차&nbsp;&nbsp;종</th>
        <th class="obd-th">사용연료</th>
        <th class="obd-th">변속기 종류</th>
        <th class="obd-th">총중량(공차중량, kg)</th>
      </tr>
      <tr>
        <td><input data-field="obd_veh_name"   class="obd-inp" type="text" value="\${E(v('obd_veh_name'))}"></td>
        <td><input data-field="obd_veh_form"   class="obd-inp" type="text" value="\${E(v('obd_veh_form'))}"></td>
        <td><input data-field="obd_veh_type"   class="obd-inp" type="text" value="\${E(v('obd_veh_type'))}"></td>
        <td><input data-field="obd_veh_fuel"   class="obd-inp" type="text" value="\${E(v('obd_veh_fuel'))}"></td>
        <td><input data-field="obd_veh_trans"  class="obd-inp" type="text" value="\${E(v('obd_veh_trans'))}"></td>
        <td><input data-field="obd_veh_weight" class="obd-inp" type="text" value="\${E(v('obd_veh_weight'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- 02. 엔진 제원 -->
  <!-- PDF: x=55.3,134.7,222.6,293.5,372.9,452.3,539.6 → 16.4%|18.1%|14.6%|16.4%|16.4%|18.0% -->
  <table class="obd-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:16.4%;"><col style="width:18.1%;"><col style="width:14.6%;"><col style="width:16.4%;"><col style="width:16.4%;"><col style="width:18.0%;">
    </colgroup>
    <tbody>
      <tr>
        <td class="obd-lbl" colspan="6" style="padding:3px 6px;">02. 엔진 제원</td>
      </tr>
      <tr>
        <th class="obd-th">형&nbsp;&nbsp;식</th>
        <th class="obd-th">최고출력(ps/rpm)</th>
        <th class="obd-th">배기량(cc)</th>
        <th class="obd-th">연소형식</th>
        <th class="obd-th">연소사이클</th>
        <th class="obd-th">연료 공급형태</th>
      </tr>
      <tr>
        <td><input data-field="obd_eng_form"   class="obd-inp" type="text" value="\${E(v('obd_eng_form'))}"></td>
        <td><input data-field="obd_eng_power"  class="obd-inp" type="text" value="\${E(v('obd_eng_power'))}"></td>
        <td><input data-field="obd_eng_cc"     class="obd-inp" type="text" value="\${E(v('obd_eng_cc'))}"></td>
        <td><input data-field="obd_eng_comb"   class="obd-inp" type="text" value="\${E(v('obd_eng_comb'))}"></td>
        <td><input data-field="obd_eng_cycle"  class="obd-inp" type="text" value="\${E(v('obd_eng_cycle'))}"></td>
        <td><input data-field="obd_eng_supply" class="obd-inp" type="text" value="\${E(v('obd_eng_supply'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- 03. 배출가스 제어장치 및 OBD 제원 -->
  <!-- PDF: x=55.3,214.1,372.9,539.6 → 32.8%|32.8%|34.4% -->
  <table class="obd-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:32.8%;"><col style="width:32.8%;"><col style="width:34.4%;">
    </colgroup>
    <tbody>
      <tr>
        <td class="obd-lbl" colspan="3" style="padding:3px 6px;">03. 배출가스 제어장치 및 배출가스 자기진단장치 제원</td>
      </tr>
      <tr>
        <th class="obd-th">촉매전환기 형식 (제작사)</th>
        <th class="obd-th">2차 공기 분사</th>
        <th class="obd-th">배출가스 재순환 장치</th>
      </tr>
      <tr>
        <td><input data-field="obd_cat_form"  class="obd-inp" type="text" value="\${E(v('obd_cat_form'))}"></td>
        <td style="text-align:center;">
          유 <input type="checkbox" data-field="obd_2air_y" \${v('obd_2air_y')?'checked':''}>
          &nbsp;&nbsp;무 <input type="checkbox" data-field="obd_2air_n" \${v('obd_2air_n')?'checked':''}>
        </td>
        <td style="text-align:center;">
          유 <input type="checkbox" data-field="obd_egr_y" \${v('obd_egr_y')?'checked':''}>
          &nbsp;&nbsp;무 <input type="checkbox" data-field="obd_egr_n" \${v('obd_egr_n')?'checked':''}>
        </td>
      </tr>
      <tr>
        <th class="obd-th">전자제어장치 형식 (제작사)</th>
        <th class="obd-th">산소센서 형식 (제작사)</th>
        <th class="obd-th">퍼지 제어밸브 형식 (제작사)</th>
      </tr>
      <tr>
        <td><input data-field="obd_ecu_form"   class="obd-inp" type="text" value="\${E(v('obd_ecu_form'))}"></td>
        <td><input data-field="obd_o2s_form"   class="obd-inp" type="text" value="\${E(v('obd_o2s_form'))}"></td>
        <td><input data-field="obd_purge_form" class="obd-inp" type="text" value="\${E(v('obd_purge_form'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- 나. 자기진단동일차종 - PAGE4 하단: 6열 -->
  <!-- PDF: x=55.3,134.7,214.1,293.5,355.5,424.0,539.6 → 16.4%|16.4%|16.4%|12.8%|14.1%|23.9% -->
  <table class="obd-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:16.4%;"><col style="width:16.4%;"><col style="width:16.4%;"><col style="width:12.8%;"><col style="width:14.1%;"><col style="width:23.9%;">
    </colgroup>
    <tbody>
      <tr>
        <th class="obd-sec-th" colspan="6">나. 자기진단동일차종</th>
      </tr>
      <tr>
        <th class="obd-th">차명(형식)</th>
        <th class="obd-th">엔진형식</th>
        <th class="obd-th">배기량(cc)</th>
        <th class="obd-th">최대출력</th>
        <th class="obd-th">변속기(단)</th>
        <th class="obd-th">총중량(공차중량, kg)</th>
      </tr>
      <tr>
        <td><input data-field="obd_same_name1" class="obd-inp" type="text" value="\${E(v('obd_same_name1'))}"></td>
        <td><input data-field="obd_same_eng1"  class="obd-inp" type="text" value="\${E(v('obd_same_eng1'))}"></td>
        <td><input data-field="obd_same_cc1"   class="obd-inp" type="text" value="\${E(v('obd_same_cc1'))}"></td>
        <td><input data-field="obd_same_pow1"  class="obd-inp" type="text" value="\${E(v('obd_same_pow1'))}"></td>
        <td><input data-field="obd_same_trans1" class="obd-inp" type="text" value="\${E(v('obd_same_trans1'))}"></td>
        <td><input data-field="obd_same_wt1"   class="obd-inp" type="text" value="\${E(v('obd_same_wt1'))}"></td>
      </tr>
      <tr>
        <td><input data-field="obd_same_name2" class="obd-inp" type="text" value="\${E(v('obd_same_name2'))}"></td>
        <td><input data-field="obd_same_eng2"  class="obd-inp" type="text" value="\${E(v('obd_same_eng2'))}"></td>
        <td><input data-field="obd_same_cc2"   class="obd-inp" type="text" value="\${E(v('obd_same_cc2'))}"></td>
        <td><input data-field="obd_same_pow2"  class="obd-inp" type="text" value="\${E(v('obd_same_pow2'))}"></td>
        <td><input data-field="obd_same_trans2" class="obd-inp" type="text" value="\${E(v('obd_same_trans2'))}"></td>
        <td><input data-field="obd_same_wt2"   class="obd-inp" type="text" value="\${E(v('obd_same_wt2'))}"></td>
      </tr>
      <tr>
        <td><input data-field="obd_same_name3" class="obd-inp" type="text" value="\${E(v('obd_same_name3'))}"></td>
        <td><input data-field="obd_same_eng3"  class="obd-inp" type="text" value="\${E(v('obd_same_eng3'))}"></td>
        <td><input data-field="obd_same_cc3"   class="obd-inp" type="text" value="\${E(v('obd_same_cc3'))}"></td>
        <td><input data-field="obd_same_pow3"  class="obd-inp" type="text" value="\${E(v('obd_same_pow3'))}"></td>
        <td><input data-field="obd_same_trans3" class="obd-inp" type="text" value="\${E(v('obd_same_trans3'))}"></td>
        <td><input data-field="obd_same_wt3"   class="obd-inp" type="text" value="\${E(v('obd_same_wt3'))}"></td>
      </tr>
      <tr>
        <td><input data-field="obd_same_name4" class="obd-inp" type="text" value="\${E(v('obd_same_name4'))}"></td>
        <td><input data-field="obd_same_eng4"  class="obd-inp" type="text" value="\${E(v('obd_same_eng4'))}"></td>
        <td><input data-field="obd_same_cc4"   class="obd-inp" type="text" value="\${E(v('obd_same_cc4'))}"></td>
        <td><input data-field="obd_same_pow4"  class="obd-inp" type="text" value="\${E(v('obd_same_pow4'))}"></td>
        <td><input data-field="obd_same_trans4" class="obd-inp" type="text" value="\${E(v('obd_same_trans4'))}"></td>
        <td><input data-field="obd_same_wt4"   class="obd-inp" type="text" value="\${E(v('obd_same_wt4'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════ -->
  <!-- PAGE5: 다. 배출가스자기진단장치 동일차종 설명         -->
  <!-- PDF: x=55.3,163.0,353.0,446.3,539.6                 -->
  <!-- → 22.0%|38.8%|19.1%|19.1%                           -->
  <!-- ══════════════════════════════════════════════════════ -->
  <table class="obd-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:22.0%;"><col style="width:38.8%;"><col style="width:19.1%;"><col style="width:19.1%;">
    </colgroup>
    <tbody>
      <tr>
        <th class="obd-sec-th" colspan="4">다. 배출가스자기진단장치 동일차종 설명</th>
      </tr>
      <!-- 차명(동일차명) 헤더행 + 입력칸 -->
      <tr>
        <th class="obd-th" colspan="2">차명(동일차명)</th>
        <td colspan="2"><input data-field="obd_same_veh_name" class="obd-inp" type="text" value="\${E(v('obd_same_veh_name'))}"></td>
      </tr>
      <!-- 구분/내용 서브헤더 -->
      <tr>
        <th class="obd-th">구&nbsp;&nbsp;분</th>
        <th class="obd-th">내&nbsp;&nbsp;용</th>
        <td colspan="2"></td>
      </tr>
      <!-- 엔진 -->
      <tr>
        <td class="obd-lbl" rowspan="2" style="text-align:center; vertical-align:middle;">엔&nbsp;&nbsp;진</td>
        <td class="obd-lbl">연소과정 (불꽃점화, 압축착화, 2행정, 4행정 등)</td>
        <td colspan="2"><input data-field="obd_eng_process" class="obd-inp" type="text" value="\${E(v('obd_eng_process'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">연료공급 방법 (기화기식, 연료분사식 등)</td>
        <td colspan="2"><input data-field="obd_fuel_supply" class="obd-inp" type="text" value="\${E(v('obd_fuel_supply'))}"></td>
      </tr>
      <!-- 배출가스 제어장치 -->
      <tr>
        <td class="obd-lbl" rowspan="4" style="text-align:center; vertical-align:middle;">배출가스<br>제어장치</td>
        <td class="obd-lbl">촉매전환기의 형식 (산화촉매, 삼원촉매, 가열식촉매 등)</td>
        <td colspan="2"><input data-field="obd_cat_type2" class="obd-inp" type="text" value="\${E(v('obd_cat_type2'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">매연여과장치의 형식</td>
        <td colspan="2"><input data-field="obd_dpf_type" class="obd-inp" type="text" value="\${E(v('obd_dpf_type'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">2차공기 분사의 유무</td>
        <td colspan="2"><input data-field="obd_2air2" class="obd-inp" type="text" placeholder="유/무" value="\${E(v('obd_2air2'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">배출가스 재순환장치의 유무</td>
        <td colspan="2"><input data-field="obd_egr2" class="obd-inp" type="text" placeholder="유/무" value="\${E(v('obd_egr2'))}"></td>
      </tr>
      <!-- 배출가스 자기진단장치의 구성 및 기능 -->
      <tr>
        <td class="obd-lbl" rowspan="3" style="text-align:center; vertical-align:middle;">배출가스<br>자기진단장치의<br>구성 및 기능</td>
        <td class="obd-lbl">배출가스 자기진단장치의 작동방법</td>
        <td colspan="2"><input data-field="obd_diag_method" class="obd-inp" type="text" value="\${E(v('obd_diag_method'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">감시장치의 오작동 확인 방법</td>
        <td colspan="2"><input data-field="obd_mon_method" class="obd-inp" type="text" value="\${E(v('obd_mon_method'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">오작동 표시방법</td>
        <td colspan="2"><input data-field="obd_mil_method" class="obd-inp" type="text" value="\${E(v('obd_mil_method'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- ══════════════════════════════════════════════════════ -->
  <!-- PAGE6: 3. 시험차량 선정에 관한 서류                   -->
  <!-- PDF: 3열 구조 항목(30%) | 구분(중간35%) | 시험차량(35%) -->
  <!-- 항목+구분 병합, 배출가스제어장치·자기진단장치·비고 포함 -->
  <!-- ══════════════════════════════════════════════════════ -->
  <table class="obd-tbl" style="border-top:none; table-layout:fixed; width:100%;">
    <colgroup>
      <col style="width:30%;"><col style="width:35%;"><col style="width:35%;">
    </colgroup>
    <tbody>
      <tr>
        <th class="obd-sec-th" colspan="3">3. 시험차량 선정에 관한 서류</th>
      </tr>
      <tr>
        <th class="obd-sec-th" colspan="3">가. 배출가스자기진단장치 시험차량 선정근거</th>
      </tr>
      <!-- 헤더: 구분 | 배출가스자기진단장치 시험차량 -->
      <tr>
        <th class="obd-th" rowspan="2">항&nbsp;&nbsp;목</th>
        <th class="obd-th" colspan="2">배출가스자기진단장치 시험차량</th>
      </tr>
      <tr>
        <th class="obd-th">모델명</th>
        <td><input data-field="obd_test_model" class="obd-inp" type="text" value="\${E(v('obd_test_model'))}"></td>
      </tr>
      <!-- 기본 항목들 -->
      <tr>
        <td class="obd-lbl" colspan="2">차대번호(엔진번호)</td>
        <td><input data-field="obd_test_vin" class="obd-inp" type="text" value="\${E(v('obd_test_vin'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl" colspan="2">배기량(cc)</td>
        <td><input data-field="obd_test_cc" class="obd-inp" type="text" value="\${E(v('obd_test_cc'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl" colspan="2">엔진형식</td>
        <td><input data-field="obd_test_eng" class="obd-inp" type="text" value="\${E(v('obd_test_eng'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl" colspan="2">변속기 형태</td>
        <td><input data-field="obd_test_trans" class="obd-inp" type="text" value="\${E(v('obd_test_trans'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl" colspan="2">변속절차</td>
        <td><input data-field="obd_test_trans_proc" class="obd-inp" type="text" value="\${E(v('obd_test_trans_proc'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl" colspan="2">등가관성중량(kg)</td>
        <td><input data-field="obd_test_inertia" class="obd-inp" type="text" value="\${E(v('obd_test_inertia'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl" colspan="2">종감속기</td>
        <td><input data-field="obd_test_final" class="obd-inp" type="text" value="\${E(v('obd_test_final'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl" colspan="2">N/V비, rpm/kph</td>
        <td><input data-field="obd_test_nv" class="obd-inp" type="text" value="\${E(v('obd_test_nv'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl" rowspan="2">타이어</td>
        <td class="obd-lbl">전</td>
        <td><input data-field="obd_test_tire_f" class="obd-inp" type="text" value="\${E(v('obd_test_tire_f'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">후</td>
        <td><input data-field="obd_test_tire_r" class="obd-inp" type="text" value="\${E(v('obd_test_tire_r'))}"></td>
      </tr>
      <!-- 배출가스 제어장치 -->
      <tr>
        <td class="obd-lbl" rowspan="5" style="text-align:center; vertical-align:middle;">배출가스<br>제어장치</td>
        <td class="obd-lbl">촉매전환기의 형식 (산화촉매, 삼원촉매, 가열식 촉매 등)</td>
        <td><input data-field="obd_sel_cat" class="obd-inp" type="text" value="\${E(v('obd_sel_cat'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">매연 여과장치의 형식</td>
        <td><input data-field="obd_sel_dpf" class="obd-inp" type="text" value="\${E(v('obd_sel_dpf'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">2차공기 분사의 유무</td>
        <td><input data-field="obd_sel_2air" class="obd-inp" type="text" placeholder="유/무" value="\${E(v('obd_sel_2air'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">배출가스 재순환 장치의 유무</td>
        <td><input data-field="obd_sel_egr" class="obd-inp" type="text" placeholder="유/무" value="\${E(v('obd_sel_egr'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">증발가스 제어장치</td>
        <td><input data-field="obd_sel_evap" class="obd-inp" type="text" value="\${E(v('obd_sel_evap'))}"></td>
      </tr>
      <!-- 배출가스 자기진단장치의 구성 및 기능 -->
      <tr>
        <td class="obd-lbl" rowspan="5" style="text-align:center; vertical-align:middle;">배출가스자기진단장치의<br>구성 및 기능</td>
        <td class="obd-lbl">배출가스 자기진단장치 작동방법</td>
        <td><input data-field="obd_sel_method" class="obd-inp" type="text" value="\${E(v('obd_sel_method'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">감시장치의 오작동 확인방법</td>
        <td><input data-field="obd_sel_mon" class="obd-inp" type="text" value="\${E(v('obd_sel_mon'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">오작동 표시 방법</td>
        <td><input data-field="obd_sel_mil" class="obd-inp" type="text" value="\${E(v('obd_sel_mil'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">감시항목</td>
        <td><input data-field="obd_sel_items" class="obd-inp" type="text" value="\${E(v('obd_sel_items'))}"></td>
      </tr>
      <tr>
        <td class="obd-lbl">비&nbsp;&nbsp;고</td>
        <td><input data-field="obd_sel_note" class="obd-inp" type="text" value="\${E(v('obd_sel_note'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- 비고: OBD TEST 사진 첨부 안내 -->
  <div style="margin-top:10px; padding:7px 10px; border:1px solid #aaa; font-size:8.5pt; background:#fafafa; color:#333;">
    ※ OBD TEST 사진 및 스캐너 사진 첨부 : 차량사진, 차대번호 사진, 엔진번호 사진 포함
  </div>

  <div id="qr-footer-wrap" style="margin-top:12px;"></div>
</div>
\`;

  if (formType==='emission_test') return \`
<style>
/* ══════ emission_test 전용 스타일 ══════ */
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
.em-attach-print-wrap { display:none; margin-top:10px; }
.em-attach-print-page { page-break-before:always; margin-top:20px; }
.em-attach-print-page img { max-width:100%; height:auto; display:block; }
.em-attach-print-page .em-attach-pdf-frame { width:100%; min-height:1100px; border:none; }

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
  /* 첨부 드롭존·목록은 숨기고 인쇄 렌더만 표시 */
  .em-attach-section { display:none !important; }
  .em-attach-print-wrap { display:block !important; }
  .em-attach-print-page { page-break-before:always; }
}
</style>

<div class="em-wrap">

  <!-- ── 최상단 헤더 (수입사/인증연도/배기량/동일차종기호) ── -->
  <!-- PDF 실측: 4등분 25.2%/24.7%/24.8%/25.2% -->
  <table class="em-tbl" style="margin-bottom:12px; table-layout:fixed;">
    <colgroup>
      <col style="width:25.2%;"><col style="width:24.7%;"><col style="width:24.9%;"><col style="width:25.2%;">
    </colgroup>
    <thead>
      <tr>
        <th class="em-th">수입사</th>
        <th class="em-th">인증연도</th>
        <th class="em-th">배기량</th>
        <th class="em-th">동일차종기호</th>
      </tr>
    </thead>
    <tbody>
      <tr style="height:26px;">
        <td><input data-field="em_importer"  class="em-inp" type="text" value="\${E(v('em_importer'))}"></td>
        <td><input data-field="em_cert_year" class="em-inp" type="text" value="\${E(v('em_cert_year'))}"></td>
        <td><input data-field="em_disp"      class="em-inp" type="text" value="\${E(v('em_disp'))}"></td>
        <td><input data-field="em_fam_code"  class="em-inp" type="text" value="\${E(v('em_fam_code'))}"></td>
      </tr>
    </tbody>
  </table>

  <div class="em-doc-tag">[별지 제18의2호 서식]</div>
  <div class="em-main-title">배출가스 시험내용 보고서(WMTC 모드)</div>

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
        <td class="em-th" colspan="3" style="width:33.5%;">인증차명(동일차종) :
          <input data-field="em_cert_model" class="em-inp" type="text" value="\${E(v('em_cert_model'))}">
        </td>
        <td class="em-th" colspan="2" style="width:31.5%;">시험차명 :
          <input data-field="em_test_model" class="em-inp" type="text" value="\${E(v('em_test_model'))}">
        </td>
        <td class="em-th" colspan="3" style="width:35.0%;">시험일시 :
          <input data-field="em_test_date" class="em-inp" type="text" placeholder="YYYY-MM-DD" value="\${E(v('em_test_date'))}">
        </td>
      </tr>
      <!-- 시험구분 -->
      <tr>
        <td class="em-th" colspan="1">시험구분</td>
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
        <td class="em-th" colspan="1">시험번호</td>
        <td colspan="1"><input data-field="em_test_no"   class="em-inp" type="text" value="\${E(v('em_test_no'))}"></td>
        <td class="em-th" colspan="1">운전자</td>
        <td colspan="1"><input data-field="em_driver"    class="em-inp" type="text" value="\${E(v('em_driver'))}"></td>
        <td class="em-th" colspan="1">장비작동자</td>
        <td colspan="1"><input data-field="em_operator"  class="em-inp" type="text" value="\${E(v('em_operator'))}"></td>
        <td class="em-th" colspan="1">검사책임자</td>
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
          <span class="em-th">차대번호 :</span>
          <input data-field="em_vin"        class="em-inp" type="text" value="\${E(v('em_vin'))}">
        </td>
        <td style="width:14.5%;">
          <span class="em-th">제작일 :</span>
          <input data-field="em_mfg_date"   class="em-inp" type="text" value="\${E(v('em_mfg_date'))}">
        </td>
        <td style="width:23.3%;">
          <span class="em-th">변속기형식 :</span>
          <input data-field="em_trans"      class="em-inp" type="text" value="\${E(v('em_trans'))}">
        </td>
        <td style="width:18.2%;">
          <span class="em-th">적산거리 :</span>
          <input data-field="em_mileage"    class="em-inp" type="text" placeholder="km" value="\${E(v('em_mileage'))}">
        </td>
        <td style="width:16.2%;">
          <span class="em-th">공차중량 :</span>
          <input data-field="em_curb_wt"    class="em-inp" type="text" placeholder="kg" value="\${E(v('em_curb_wt'))}">
        </td>
      </tr>
      <!-- 행2: 제작사(rowspan=1)/차량총중량/관성중량등급/연료탱크 용량 및 위치 -->
      <!-- PDF y=269: 22.3% | 20.0% | 23.3% | 34.4% -->
      <tr>
        <td style="width:27.8%;">
          <span class="em-th">제작사 :</span>
          <input data-field="em_maker"      class="em-inp" type="text" value="\${E(v('em_maker'))}">
        </td>
        <td style="width:14.5%;">
          <span class="em-th">차량총중량 :</span>
          <input data-field="em_gvw"        class="em-inp" type="text" placeholder="kg" value="\${E(v('em_gvw'))}">
        </td>
        <td style="width:23.3%;">
          <span class="em-th">관성중량등급 :</span>
          <input data-field="em_inertia"    class="em-inp" type="text" value="\${E(v('em_inertia'))}">
        </td>
        <td colspan="2" style="width:34.4%;">
          <span class="em-th">연료탱크 용량 및 위치 :</span>
          <input data-field="em_tank"       class="em-inp" type="text" value="\${E(v('em_tank'))}">
        </td>
      </tr>
      <!-- 행3: 도로부하력/코스트다운시간/촉매부착여부 -->
      <!-- PDF y=284: 42.3% | 23.3% | 34.4% (내부수직선 259.8, 373.7) -->
      <tr>
        <td colspan="2" style="width:42.3%;">
          <span class="em-th">도로 부하력 :</span>
          <input data-field="em_road_load"  class="em-inp" type="text" value="\${E(v('em_road_load'))}">
        </td>
        <td style="width:23.3%;">
          <span class="em-th">코스트다운 시간 :</span>
          <input data-field="em_coastdown"  class="em-inp" type="text" value="\${E(v('em_coastdown'))}">
        </td>
        <td colspan="2" style="width:34.4%;">
          <span class="em-th">촉매부착여부 :</span>
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
        <td><span class="em-th">엔진번호 :</span><input data-field="em_eng_no"    class="em-inp" type="text" value="\${E(v('em_eng_no'))}"></td>
        <td><span class="em-th">엔진방식 :</span><input data-field="em_eng_type"  class="em-inp" type="text" value="\${E(v('em_eng_type'))}"></td>
        <td><span class="em-th">최고출력 :</span><input data-field="em_max_pow"   class="em-inp" type="text" value="\${E(v('em_max_pow'))}"></td>
        <td><span class="em-th">총배기량 :</span><input data-field="em_total_cc"  class="em-inp" type="text" placeholder="cc" value="\${E(v('em_total_cc'))}"></td>
        <td><span class="em-th">실린더수 :</span><input data-field="em_cyl"       class="em-inp" type="text" value="\${E(v('em_cyl'))}"></td>
      </tr>
      <tr>
        <td><span class="em-th">공회전 :</span><input data-field="em_idle"       class="em-inp" type="text" placeholder="rpm" value="\${E(v('em_idle'))}"></td>
        <td><span class="em-th">냉각방식 :</span><input data-field="em_cooling"   class="em-inp" type="text" value="\${E(v('em_cooling'))}"></td>
        <td><span class="em-th">연소사이클 :</span><input data-field="em_cycle"    class="em-inp" type="text" value="\${E(v('em_cycle'))}"></td>
        <td colspan="2"><span class="em-th">시험연료 :</span><input data-field="em_fuel"     class="em-inp" type="text" value="\${E(v('em_fuel'))}"></td>
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
        <th class="em-th" style="text-align:center;">명&nbsp;&nbsp;&nbsp;칭</th>
        <th class="em-th" style="text-align:center;">형&nbsp;&nbsp;&nbsp;식</th>
        <th class="em-th" style="text-align:center;">제작사</th>
        <th class="em-th" style="text-align:center;">모델</th>
        <th class="em-th" style="text-align:center;">형식승인일자</th>
        <th class="em-th" style="text-align:center;">설치장소</th>
      </tr>
      <tr>
        <td class="em-th">다이나모 메타</td>
        <td><input data-field="em_dyn_form"   class="em-inp" type="text" value="\${E(v('em_dyn_form'))}"></td>
        <td><input data-field="em_dyn_maker"  class="em-inp" type="text" value="\${E(v('em_dyn_maker'))}"></td>
        <td><input data-field="em_dyn_model"  class="em-inp" type="text" value="\${E(v('em_dyn_model'))}"></td>
        <td><input data-field="em_dyn_appr"   class="em-inp" type="text" value="\${E(v('em_dyn_appr'))}"></td>
        <td><input data-field="em_dyn_loc"    class="em-inp" type="text" value="\${E(v('em_dyn_loc'))}"></td>
      </tr>
      <tr>
        <td class="em-th">분석 장치</td>
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
        <td class="em-th">냉각팬</td>
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
        <th class="em-th" style="text-align:center;">구&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;분</th>
        <th class="em-th" style="text-align:center;">1BAG</th>
        <th class="em-th" style="text-align:center;">2BAG</th>
        <th class="em-th" style="text-align:center;">3BAG</th>
        <th class="em-th" style="text-align:center;">비고</th>
      </tr>
      <tr>
        <td class="em-th">압&nbsp;&nbsp;&nbsp;력 &nbsp;&nbsp;&nbsp;mmHg</td>
        <td><input data-field="em_cvs_press1" class="em-inp" type="text" value="\${E(v('em_cvs_press1'))}"></td>
        <td><input data-field="em_cvs_press2" class="em-inp" type="text" value="\${E(v('em_cvs_press2'))}"></td>
        <td><input data-field="em_cvs_press3" class="em-inp" type="text" value="\${E(v('em_cvs_press3'))}"></td>
        <td><input data-field="em_cvs_press_note" class="em-inp" type="text" value="\${E(v('em_cvs_press_note'))}"></td>
      </tr>
      <tr>
        <td class="em-th">습구온도 &nbsp;&nbsp;&nbsp;℃</td>
        <td><input data-field="em_cvs_wet1"   class="em-inp" type="text" value="\${E(v('em_cvs_wet1'))}"></td>
        <td><input data-field="em_cvs_wet2"   class="em-inp" type="text" value="\${E(v('em_cvs_wet2'))}"></td>
        <td><input data-field="em_cvs_wet3"   class="em-inp" type="text" value="\${E(v('em_cvs_wet3'))}"></td>
        <td><input data-field="em_cvs_wet_note" class="em-inp" type="text" value="\${E(v('em_cvs_wet_note'))}"></td>
      </tr>
      <tr>
        <td class="em-th">건구온도 &nbsp;&nbsp;&nbsp;℃</td>
        <td><input data-field="em_cvs_dry1"   class="em-inp" type="text" value="\${E(v('em_cvs_dry1'))}"></td>
        <td><input data-field="em_cvs_dry2"   class="em-inp" type="text" value="\${E(v('em_cvs_dry2'))}"></td>
        <td><input data-field="em_cvs_dry3"   class="em-inp" type="text" value="\${E(v('em_cvs_dry3'))}"></td>
        <td><input data-field="em_cvs_dry_note" class="em-inp" type="text" value="\${E(v('em_cvs_dry_note'))}"></td>
      </tr>
      <tr>
        <td class="em-th">상대습도 &nbsp;&nbsp;&nbsp;%</td>
        <td><input data-field="em_cvs_rh1"    class="em-inp" type="text" value="\${E(v('em_cvs_rh1'))}"></td>
        <td><input data-field="em_cvs_rh2"    class="em-inp" type="text" value="\${E(v('em_cvs_rh2'))}"></td>
        <td><input data-field="em_cvs_rh3"    class="em-inp" type="text" value="\${E(v('em_cvs_rh3'))}"></td>
        <td><input data-field="em_cvs_rh_note" class="em-inp" type="text" value="\${E(v('em_cvs_rh_note'))}"></td>
      </tr>
      <tr>
        <td class="em-th">비교습도 H₂Og/kg Air</td>
        <td><input data-field="em_cvs_ha1"    class="em-inp" type="text" value="\${E(v('em_cvs_ha1'))}"></td>
        <td><input data-field="em_cvs_ha2"    class="em-inp" type="text" value="\${E(v('em_cvs_ha2'))}"></td>
        <td><input data-field="em_cvs_ha3"    class="em-inp" type="text" value="\${E(v('em_cvs_ha3'))}"></td>
        <td><input data-field="em_cvs_ha_note" class="em-inp" type="text" value="\${E(v('em_cvs_ha_note'))}"></td>
      </tr>
      <tr>
        <td class="em-th">배&nbsp;출&nbsp;량 &nbsp;&nbsp;&nbsp;㎥</td>
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
        <td class="em-th">운전거리 &nbsp;&nbsp;&nbsp;Km</td>
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
        <th class="em-th" rowspan="2" style="text-align:center; vertical-align:middle;">항&nbsp;목</th>
        <th class="em-th" colspan="2" style="text-align:center;">PHASE 1</th>
        <th class="em-th" colspan="2" style="text-align:center;">PHASE 2</th>
        <th class="em-th" colspan="2" style="text-align:center;">PHASE 3</th>
      </tr>
      <!-- 복합 헤더 2행: 배출질량/g/km -->
      <tr>
        <th class="em-th" style="text-align:center; font-size:7.5pt;">배출질량<br>(g/test)</th>
        <th class="em-th" style="text-align:center;">g/km</th>
        <th class="em-th" style="text-align:center; font-size:7.5pt;">배출질량<br>(g/test)</th>
        <th class="em-th" style="text-align:center;">g/km</th>
        <th class="em-th" style="text-align:center; font-size:7.5pt;">배출질량<br>(g/test)</th>
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
        <td class="em-th" style="font-size:7.5pt;">시험결과<br>(g/km)</td>
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
        <td class="em-th" style="text-align:center;">최종결과</td>
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
  <div class="em-attach-section" id="em-attach-raw-section">
    <div class="em-attach-title"><i class="fas fa-paperclip"></i>&nbsp;첨부문서 – 자체 배출가스 시험 성적서 / RAW DATA</div>
    <div class="em-attach-note">※ 이미지 또는 PDF 파일을 첨부하면 인쇄 시 자동으로 함께 인쇄됩니다.</div>
    <div class="em-attach-drop" id="em-drop-raw">
      <i class="fas fa-cloud-upload-alt" style="font-size:20px; color:var(--c-accent);"></i>
      <span style="font-size:8.5pt;">클릭하거나 파일을 여기에 끌어다 놓으세요</span>
      <span style="font-size:7.5pt; color:var(--c-text3);">지원 형식: 이미지(JPG, PNG, GIF), PDF</span>
      <input type="file" id="em-file-raw" accept="image/*,.pdf" multiple>
    </div>
    <div class="em-attach-list" id="em-list-raw"></div>
    <div class="em-attach-print-wrap" id="em-print-raw" style="display:none;"></div>
  </div>

  <div id="qr-footer-wrap" style="margin-top:12px;"></div>
</div>
\`;

  if (formType==='evap_test') return \`
<style>
/* ══════ evap_test 전용 스타일 ══════ */
.ev-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
}
.ev-doc-tag  { font-size:8.5pt; font-weight:700; color:var(--c-text2); margin:10px 0 4px; }
.ev-main-title {
  font-size:14pt; font-weight:900; text-align:center;
  margin:4px 0 16px; letter-spacing:.04em; color:var(--c-text);
}
/* 공통 표 */
.ev-tbl {
  width:100%; border-collapse:collapse;
  font-size:8.5pt; margin-bottom:0;
}
.ev-tbl th, .ev-tbl td {
  border:1px solid #888;
  padding:4px 6px;
  vertical-align:middle;
  word-break:keep-all;
  overflow-wrap:break-word;
}
.ev-th {
  background:rgba(79,142,247,.08);
  font-weight:700; text-align:center;
  white-space:nowrap;
}
.ev-sec-th {
  background:rgba(79,142,247,.06);
  font-weight:700; text-align:left;
  padding:5px 8px;
}
.ev-inp {
  width:100%; background:transparent;
  border:none; outline:none;
  font-size:8.5pt; color:var(--c-text);
  font-family:inherit; padding:2px 3px;
}
.ev-inp::placeholder { color:var(--c-text3); }
.ev-inp:focus { border-bottom:1px solid var(--c-accent); }
.ev-lbl { font-weight:600; white-space:nowrap; color:var(--c-text2); }
.ev-chk-row { display:flex; align-items:center; gap:6px; }
.ev-chk-item { display:flex; align-items:center; gap:3px; font-size:8.5pt; cursor:pointer; }
/* 첨부 섹션 */
.ev-attach-section { margin-top:14px; }
.ev-attach-title { font-size:9pt; font-weight:700; margin-bottom:6px; color:var(--c-text); }
.ev-attach-note { font-size:8pt; color:var(--c-text3); margin-bottom:8px; }
.ev-attach-drop {
  border:2px dashed var(--c-border); border-radius:8px;
  padding:16px; text-align:center; cursor:pointer;
  transition:border-color .2s, background .2s;
  display:flex; flex-direction:column; align-items:center; gap:4px;
}
.ev-attach-drop:hover { border-color:var(--c-accent); background:rgba(79,142,247,.04); }
.ev-attach-drop input[type=file] { display:none; }
.ev-attach-list { margin-top:8px; display:flex; flex-direction:column; gap:4px; }
.ev-attach-item {
  display:flex; align-items:center; gap:8px;
  padding:4px 8px; border-radius:4px;
  background:var(--c-surface2); font-size:8.5pt;
}
.ev-attach-item-name { flex:1; color:var(--c-text); word-break:break-all; }
.ev-attach-item-size { color:var(--c-text3); white-space:nowrap; font-size:8pt; }
.ev-attach-item-del { color:#ef4444; cursor:pointer; padding:1px 5px; border-radius:3px; font-size:10pt; line-height:1; }
.ev-attach-item-del:hover { background:rgba(239,68,68,.12); }
.ev-attach-print-wrap { margin-top:10px; }
.ev-attach-print-page { page-break-before:always; margin-top:20px; }
.ev-attach-print-page img { max-width:100%; height:auto; display:block; }
.ev-attach-print-page .ev-attach-pdf-frame { width:100%; min-height:600px; border:none; }
/* 인쇄 */
@media print {
  .ev-wrap { font-size:8.5pt !important; }
  .ev-main-title { font-size:13pt !important; }

  /* 표 테두리·색상 */
  .ev-tbl th, .ev-tbl td {
    border:1px solid #000 !important; color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
    vertical-align:middle !important;
    padding:3px 5px !important;
  }
  .ev-th {
    background:rgba(79,142,247,.10) !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }
  .ev-sec-th {
    background:rgba(79,142,247,.06) !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }

  /* ── ev-inp: input 원본 그대로 인쇄 (textarea 교체 안 함) ── */
  .ev-inp {
    display:inline-block !important;
    width:100% !important;
    background:transparent !important;
    border:none !important;
    outline:none !important;
    box-shadow:none !important;
    color:#000 !important;
    font-size:8.5pt !important;
    font-family:'맑은 고딕','Malgun Gothic',sans-serif !important;
    padding:1px 2px !important;
    margin:0 !important;
  }

  /* ev-lbl (높이:, 폭: 등 인라인 라벨) */
  .ev-lbl {
    color:#000 !important;
    font-weight:600 !important;
  }

  /* 첨부 영역 */
  .ev-attach-section { display:none !important; }
  .ev-attach-print-wrap { display:block !important; }
  .ev-attach-print-page { page-break-before:always; }
}
</style>

<div class="ev-wrap">

  <!-- ── 최상단 헤더 (수입사/인증연도/배기량/동일차종기호) ── -->
  <table class="ev-tbl" style="margin-bottom:14px;">
    <thead>
      <tr>
        <th class="ev-th" style="width:25%;">수입사</th>
        <th class="ev-th" style="width:25%;">인증연도</th>
        <th class="ev-th" style="width:25%;">배기량</th>
        <th class="ev-th" style="width:25%;">동일차종기호</th>
      </tr>
    </thead>
    <tbody>
      <tr style="height:28px;">
        <td><input data-field="ev_importer"   class="ev-inp" type="text" value="\${E(v('ev_importer'))}"></td>
        <td><input data-field="ev_cert_year"  class="ev-inp" type="text" value="\${E(v('ev_cert_year'))}"></td>
        <td><input data-field="ev_disp"       class="ev-inp" type="text" value="\${E(v('ev_disp'))}"></td>
        <td><input data-field="ev_fam_code"   class="ev-inp" type="text" value="\${E(v('ev_fam_code'))}"></td>
      </tr>
    </tbody>
  </table>

  <div class="ev-doc-tag">[별지 제23호 서식]</div>
  <div class="ev-main-title">증발가스 시험내용 보고서</div>

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
        <td style="width:16%;" class="ev-th">인증차명 :</td>
        <td style="width:18%;"><input data-field="ev_cert_model"  class="ev-inp" type="text" value="\${E(v('ev_cert_model'))}"></td>
        <td style="width:14%;" class="ev-th" rowspan="2" style="vertical-align:middle;">시험차명 :</td>
        <td style="width:18%;" rowspan="2"><input data-field="ev_test_model"  class="ev-inp" type="text" value="\${E(v('ev_test_model'))}"></td>
        <td style="width:14%;" class="ev-th" rowspan="2" style="vertical-align:middle;">시험일시 :</td>
        <td style="width:20%;" rowspan="2"><input data-field="ev_test_date"   class="ev-inp" type="text" placeholder="YYYY-MM-DD" value="\${E(v('ev_test_date'))}"></td>
      </tr>
      <!-- 동일차종 (인증차명 아래 별도 행, 좌측 2칸만) -->
      <tr>
        <td class="ev-th">동일차종 :</td>
        <td><input data-field="ev_same_model" class="ev-inp" type="text" value="\${E(v('ev_same_model'))}"></td>
      </tr>
      <!-- 시험번호 / 장비작동자 / 검사책임자 -->
      <tr>
        <td class="ev-th">시험번호 :</td>
        <td><input data-field="ev_test_no"    class="ev-inp" type="text" value="\${E(v('ev_test_no'))}"></td>
        <td class="ev-th">장비작동자 :</td>
        <td><input data-field="ev_operator"   class="ev-inp" type="text" value="\${E(v('ev_operator'))}"></td>
        <td class="ev-th">검사책임자 :</td>
        <td><input data-field="ev_inspector"  class="ev-inp" type="text" value="\${E(v('ev_inspector'))}"></td>
      </tr>
      <!-- 차대번호 / 엔진번호 / 적산거리 -->
      <tr>
        <td class="ev-th">차대번호 :</td>
        <td><input data-field="ev_vin"        class="ev-inp" type="text" value="\${E(v('ev_vin'))}"></td>
        <td class="ev-th">엔진번호</td>
        <td><input data-field="ev_eng_no"     class="ev-inp" type="text" value="\${E(v('ev_eng_no'))}"></td>
        <td class="ev-th">적산거리 :</td>
        <td><input data-field="ev_mileage"    class="ev-inp" type="text" placeholder="km" value="\${E(v('ev_mileage'))}"></td>
      </tr>
      <!-- 시험구분 (체크박스) -->
      <tr>
        <td class="ev-th" style="text-align:center;">시험구분</td>
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
        <td class="ev-th" style="width:29.6%; white-space:nowrap;">측정실(밀폐실) 규격 :</td>
        <td style="width:14.3%; white-space:nowrap; padding:2px 3px;">
          <span class="ev-lbl" style="font-size:8.5pt;">높이 :</span>
          <input data-field="ev_room_h" class="ev-inp" type="text" style="width:52%;" value="\${E(v('ev_room_h'))}">
        </td>
        <td style="width:15.0%; white-space:nowrap; padding:2px 3px;">
          <span class="ev-lbl" style="font-size:8.5pt;">폭 :</span>
          <input data-field="ev_room_w" class="ev-inp" type="text" style="width:62%;" value="\${E(v('ev_room_w'))}">
        </td>
        <td style="width:17.0%; white-space:nowrap; padding:2px 3px;">
          <span class="ev-lbl" style="font-size:8.5pt;">길이 :</span>
          <input data-field="ev_room_l" class="ev-inp" type="text" style="width:58%;" value="\${E(v('ev_room_l'))}">
        </td>
        <td style="width:24.1%; white-space:nowrap; padding:2px 3px;">
          <span class="ev-lbl" style="font-size:8.5pt;">순내부체적 :</span>
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
          <span class="ev-lbl ev-th" style="white-space:nowrap;">측정실 온도 조정방법 :</span>
          <input data-field="ev_temp_method" class="ev-inp" type="text" value="\${E(v('ev_temp_method'))}">
        </td>
        <td colspan="2" style="width:33.6%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">연료가열장치 :</span>
          <input data-field="ev_fuel_heater" class="ev-inp" type="text" value="\${E(v('ev_fuel_heater'))}">
        </td>
        <td style="width:33.0%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">측정실 모델 :</span>
          <input data-field="ev_room_model" class="ev-inp" type="text" value="\${E(v('ev_room_model'))}">
        </td>
      </tr>

      <!-- ─────────────────────────────────────────────────── -->
      <!-- 행3: 분석장비 / HC 고정 방법 / 모델  (행2 동일 비율) -->
      <!-- ─────────────────────────────────────────────────── -->
      <tr>
        <td colspan="2" style="width:33.4%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">분석장비 :</span>
          <input data-field="ev_analyzer" class="ev-inp" type="text" value="\${E(v('ev_analyzer'))}">
        </td>
        <td colspan="2" style="width:33.6%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">HC 고정 방법 :</span>
          <input data-field="ev_hc_method" class="ev-inp" type="text" value="\${E(v('ev_hc_method'))}">
        </td>
        <td style="width:33.0%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">모&nbsp;&nbsp;&nbsp;델 :</span>
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
        <td class="ev-th" rowspan="2" style="width:16.2%; text-align:center; vertical-align:middle; white-space:nowrap; padding:2px 3px;">활성탄<br>채집트랙</td>
        <td colspan="2" style="width:57.7%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">용기규격 및 재질 :</span>
          <input data-field="ev_can_spec" class="ev-inp" type="text" value="\${E(v('ev_can_spec'))}">
        </td>
        <td colspan="2" style="width:42.3%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap; font-size:8pt;">보조채집장치의 규격 및 재질 :</span>
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
          <span class="ev-lbl ev-th" style="white-space:nowrap;">채집용기 무게 :</span>
          <input data-field="ev_can_wt_before" class="ev-inp" type="text" placeholder="g" style="width:38%;" value="\${E(v('ev_can_wt_before'))}">
        </td>
        <td style="width:27.7%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">시험후 무게 :</span>
          <input data-field="ev_can_wt_after" class="ev-inp" type="text" placeholder="g" style="width:42%;" value="\${E(v('ev_can_wt_after'))}">
        </td>
        <td style="width:28.4%; padding:2px 4px;">
          <span class="ev-lbl ev-th" style="white-space:nowrap;">손&nbsp;무&nbsp;게 :</span>
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
        <th class="ev-sec-th" colspan="8">3. &nbsp;시험결과</th>
      </tr>
      <!-- 복합 헤더 1행 -->
      <tr>
        <th class="ev-th" rowspan="2" style="width:18%; vertical-align:middle;">구&nbsp;&nbsp;&nbsp;분</th>
        <th class="ev-th" colspan="3">초기단계(밀폐실)</th>
        <th class="ev-th" colspan="3">최종단계(밀폐실)</th>
        <th class="ev-th" rowspan="2" style="width:8%; vertical-align:middle;">결과<br>g</th>
      </tr>
      <!-- 복합 헤더 2행 -->
      <tr>
        <th class="ev-th" style="width:9%;">온도<br>℃</th>
        <th class="ev-th" style="width:10%;">압력<br>mmHg</th>
        <th class="ev-th" style="width:9%;">농도<br>ppm</th>
        <th class="ev-th" style="width:9%;">온도<br>℃</th>
        <th class="ev-th" style="width:10%;">압력<br>mmHg</th>
        <th class="ev-th" style="width:9%;">농도<br>ppm</th>
      </tr>
    </thead>
    <tbody>
      <!-- 주간증발손실시험 -->
      <tr style="height:32px;">
        <td style="text-align:center; font-weight:600;">주간증발손실시험</td>
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
        <td style="text-align:center; font-weight:600;">고온소오크시험</td>
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
        <td style="text-align:center; font-weight:600;">시험결과/테스트</td>
        <td colspan="7"><input data-field="ev_test_result" class="ev-inp" type="text" value="\${E(v('ev_test_result'))}"></td>
      </tr>
      <!-- 열화계수(DF) -->
      <tr style="height:28px;">
        <td style="text-align:center; font-weight:600;">열화계수(DF)</td>
        <td colspan="7"><input data-field="ev_df" class="ev-inp" type="text" value="\${E(v('ev_df'))}"></td>
      </tr>
      <!-- 최종결과 -->
      <tr style="height:28px;">
        <td style="text-align:center; font-weight:600;">최종결과</td>
        <td colspan="7"><input data-field="ev_final_result" class="ev-inp" type="text" value="\${E(v('ev_final_result'))}"></td>
      </tr>
      <!-- 기준치 -->
      <tr style="height:28px;">
        <td style="text-align:center; font-weight:600;">기 &nbsp;준 &nbsp;치</td>
        <td colspan="7"><input data-field="ev_std" class="ev-inp" type="text" value="\${E(v('ev_std'))}"></td>
      </tr>
    </tbody>
  </table>

  <!-- 첨부문서 1: 자체시험성적서 / RAW DATA -->
  <div class="ev-attach-section no-print" id="ev-attach-raw-section">
    <div class="ev-attach-title"><i class="fas fa-paperclip"></i> 첨부문서 ① – 자체시험성적서 / RAW DATA</div>
    <div class="ev-attach-note">이미지(JPG, PNG) 또는 PDF 파일을 첨부하면 인쇄 시 함께 출력됩니다.</div>
    <div class="ev-attach-drop" id="ev-drop-raw" onclick="document.getElementById('ev-file-raw').click()">
      <input type="file" id="ev-file-raw" multiple accept="image/*,.pdf">
      <i class="fas fa-cloud-upload-alt" style="font-size:20px;color:var(--c-accent);margin-bottom:4px;"></i>
      <div style="font-size:8.5pt;color:var(--c-text2);">클릭하거나 파일을 끌어다 놓으세요 (이미지 / PDF)</div>
    </div>
    <div class="ev-attach-list" id="ev-list-raw"></div>
  </div>
  <div class="ev-attach-print-wrap" id="ev-print-raw"></div>

  <!-- 첨부문서 2: 제작사의 확인서 -->
  <div class="ev-attach-section no-print" id="ev-attach-mfr-section">
    <div class="ev-attach-title"><i class="fas fa-paperclip"></i> 첨부문서 ② – 제작사의 확인서 <span style="font-size:8pt;font-weight:400;color:var(--c-text3);">(시험 차량이 한국 인증 차량과 상이할 경우)</span></div>
    <div class="ev-attach-note">이미지(JPG, PNG) 또는 PDF 파일을 첨부하면 인쇄 시 함께 출력됩니다.</div>
    <div class="ev-attach-drop" id="ev-drop-mfr" onclick="document.getElementById('ev-file-mfr').click()">
      <input type="file" id="ev-file-mfr" multiple accept="image/*,.pdf">
      <i class="fas fa-cloud-upload-alt" style="font-size:20px;color:var(--c-accent);margin-bottom:4px;"></i>
      <div style="font-size:8.5pt;color:var(--c-text2);">클릭하거나 파일을 끌어다 놓으세요 (이미지 / PDF)</div>
    </div>
    <div class="ev-attach-list" id="ev-list-mfr"></div>
  </div>
  <div class="ev-attach-print-wrap" id="ev-print-mfr"></div>

  <div id="qr-footer-wrap" style="margin-top:16px;"></div>
</div>
\`;

  if (formType==='obd_operation') return \`
<style>
/* ══════ obd_operation 전용 스타일 ══════ */
.obd-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
  padding:10px 2px;
}
.obd-doc-tag  { font-size:8.5pt; color:var(--c-text2); margin-bottom:6px; }
.obd-main-title {
  font-size:14pt; font-weight:900; text-align:center;
  margin:0 0 16px; letter-spacing:.04em; color:var(--c-text);
}
.obd-sec-label {
  font-size:9.5pt; font-weight:700; margin:16px 0 6px; color:var(--c-text);
}
.obd-tbl {
  width:100%; border-collapse:collapse; font-size:8.5pt; margin-bottom:4px;
}
.obd-tbl th, .obd-tbl td {
  border:1px solid #888; padding:4px 6px;
  vertical-align:middle; text-align:center;
  word-break:keep-all; overflow-wrap:break-word;
}
.obd-th {
  background:rgba(79,142,247,.08); font-weight:700;
  font-size:8.5pt; text-align:center !important;
}
.obd-inp {
  width:100%; background:transparent; border:none; outline:none;
  font-size:8.5pt; color:var(--c-text); font-family:inherit;
  padding:2px 3px; text-align:left;
}
.obd-inp::placeholder { color:var(--c-text3); }
.obd-inp:focus { border-bottom:1px solid var(--c-accent); }
.obd-chk-row { display:flex; align-items:center; gap:10px; }
.obd-chk-item { display:flex; align-items:center; gap:3px; font-size:8.5pt; cursor:pointer; }
.obd-result-th-top {
  background:rgba(79,142,247,.10); font-weight:700; text-align:center !important;
}
.obd-result-th-mid {
  background:rgba(79,142,247,.06); font-weight:700;
  text-align:center !important; font-size:8pt;
}
.obd-result-td { text-align:center !important; padding:3px 2px !important; }
@media print {
  .obd-wrap { font-size:8.5pt !important; }
  .obd-main-title { font-size:13pt !important; }
  .obd-tbl th, .obd-tbl td {
    border:1px solid #000 !important; color:#000 !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact;
  }
  .obd-th { background:rgba(79,142,247,.10) !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .obd-result-th-top { background:rgba(79,142,247,.12) !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .obd-result-th-mid { background:rgba(79,142,247,.07) !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .obd-inp { color:#000 !important; border-bottom:none !important; }
  .obd-chk-item input[type=checkbox] { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
}
</style>

<div class="obd-wrap">
  <div class="obd-doc-tag">[별지 제26호서식]</div>
  <div class="obd-main-title">배출가스자기진단장치 작동 확인시험내용 보고서</div>

  <!-- ── □ 시험 일반 내용 ── -->
  <div class="obd-sec-label">□ 시험 일반 내용</div>
  <table class="obd-tbl">
    <thead>
      <tr>
        <th class="obd-th" style="width:33%;">시험일</th>
        <th class="obd-th" style="width:33%;">장비작동자</th>
        <th class="obd-th" style="width:34%;">검사책임자</th>
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
  <div class="obd-sec-label">□ 시험자동차 제원</div>
  <table class="obd-tbl">
    <!-- 1. 일반제원 -->
    <thead>
      <tr>
        <th class="obd-th" colspan="6" style="text-align:left !important; padding-left:8px;">1. 일 반 제 원</th>
      </tr>
      <tr>
        <th class="obd-th" style="width:13%;">차 명</th>
        <th class="obd-th" style="width:16%;">형 식</th>
        <th class="obd-th" style="width:13%;">차 종</th>
        <th class="obd-th" style="width:14%;">사용연료</th>
        <th class="obd-th" style="width:16%;">변속기 종류</th>
        <th class="obd-th" style="width:28%;">총중량(공차중량)<br>(kg)</th>
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
        <th class="obd-th" colspan="6" style="text-align:left !important; padding-left:8px; border-top:2px solid #888;">2. 엔 진 제 원</th>
      </tr>
      <tr>
        <th class="obd-th">형 식</th>
        <th class="obd-th">최고출력<br>(ps/rpm)</th>
        <th class="obd-th">배기량<br>(cc)</th>
        <th class="obd-th">연소형식</th>
        <th class="obd-th">연소사이클</th>
        <th class="obd-th">연료공급형태</th>
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
          <div style="font-weight:600; margin-bottom:3px;">촉매전환기 형식 (제작사)</div>
          <input data-field="obd_catalyst" class="obd-inp" type="text" placeholder="형식 / 제작사" value="\${E(v('obd_catalyst'))}">
        </td>
        <td colspan="2" style="text-align:center; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:5px;">2차공기분사</div>
          <div class="obd-chk-row" style="justify-content:center; gap:14px;">
            <label class="obd-chk-item"><input type="checkbox" data-field="obd_air2_y" \${v('obd_air2_y')?'checked':''}>&nbsp;유</label>
            <label class="obd-chk-item"><input type="checkbox" data-field="obd_air2_n" \${v('obd_air2_n')?'checked':''}>&nbsp;무</label>
          </div>
        </td>
        <td colspan="2" style="text-align:center; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:5px;">배출가스 재순환장치</div>
          <div class="obd-chk-row" style="justify-content:center; gap:14px;">
            <label class="obd-chk-item"><input type="checkbox" data-field="obd_egr_y" \${v('obd_egr_y')?'checked':''}>&nbsp;유</label>
            <label class="obd-chk-item"><input type="checkbox" data-field="obd_egr_n" \${v('obd_egr_n')?'checked':''}>&nbsp;무</label>
          </div>
        </td>
      </tr>
      <tr>
        <td colspan="2" style="text-align:left; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:3px;">전자제어장치 형식 (제작사)</div>
          <input data-field="obd_ecu" class="obd-inp" type="text" placeholder="형식 / 제작사" value="\${E(v('obd_ecu'))}">
        </td>
        <td colspan="2" style="text-align:left; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:3px;">산소센서 형식 (제작사)</div>
          <input data-field="obd_o2sensor" class="obd-inp" type="text" placeholder="형식 / 제작사" value="\${E(v('obd_o2sensor'))}">
        </td>
        <td colspan="2" style="text-align:left; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:3px;">퍼지제어밸브 형식 (제작사)</div>
          <input data-field="obd_purge" class="obd-inp" type="text" placeholder="형식 / 제작사" value="\${E(v('obd_purge'))}">
        </td>
      </tr>
    </tbody>
  </table>

  <!-- ── □ 시 험 결 과 ── -->
  <div class="obd-sec-label">□ 시 험 결 과</div>
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
        <th class="obd-result-th-top" colspan="2" rowspan="2" style="vertical-align:middle;">시험대상 감시장치</th>
        <th class="obd-result-th-top" colspan="4">시험결과</th>
        <th class="obd-result-th-top" colspan="4">결과판정</th>
      </tr>
      <!-- 2행: 중분류 -->
      <tr>
        <th class="obd-result-th-mid" colspan="3">CVS-75모드<br>결과 (g/km)</th>
        <th class="obd-result-th-mid" rowspan="2" style="vertical-align:middle; font-size:7pt;">오작동<br>표시등<br>점등여부</th>
        <th class="obd-result-th-mid" colspan="3">오작동 판단 기준<br>(g/km)</th>
        <th class="obd-result-th-mid" rowspan="2" style="vertical-align:middle; font-size:7pt;">감시장치<br>적부판정</th>
      </tr>
      <!-- 3행: 장치명/재현조건 + CO·NOx·HC 소분류 — 모두 같은 행 -->
      <tr>
        <th class="obd-result-th-mid" style="vertical-align:middle;">장치명</th>
        <th class="obd-result-th-mid" style="vertical-align:middle;">오작동<br>재현조건</th>
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
</div>
\`;



  if (formType==='noise_test') return \`
<style>
/* ══════ noise_test 전용 스타일 ══════ */
.nt-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
  font-size:9pt;
}
/* 상단 헤더 */
.nt-header-tbl { width:100%; border-collapse:collapse; border:1px solid #888; }
.nt-header-lbl-cell { width:25%; border:1px solid #888; padding:3px 6px; background:rgba(79,142,247,.08); text-align:center; }
.nt-header-val-cell { width:25%; border:1px solid #888; padding:3px 6px; }
.nt-header-lbl { display:block; font-size:.72rem; font-weight:700; color:var(--c-text2); text-align:center; }
.nt-header-inp { width:100%; background:transparent; border:none; border-bottom:1px solid var(--c-border); color:var(--c-text); font-size:.9rem; padding:2px 0; outline:none; }
.nt-header-inp:focus { border-bottom-color:var(--c-accent); }

/* 별지 서식명 / 대제목 */
.nt-form-tag { font-size:9pt; font-weight:600; margin:10px 0 4px; color:var(--c-text2); }
.nt-main-title { font-size:14pt; font-weight:900; text-align:center; margin:6px 0 14px; letter-spacing:.04em; color:var(--c-text); }

/* 섹션 제목 */
.nt-sec-title { font-size:9.5pt; font-weight:700; margin:18px 0 8px; color:var(--c-text); }

/* 공통 표 */
.nt-tbl { width:100%; border-collapse:collapse; font-size:7.5pt; table-layout:fixed; margin-bottom:14px; }
.nt-tbl th, .nt-tbl td {
  border:1px solid #888; padding:5px 5px;
  vertical-align:middle; word-break:keep-all;
  overflow-wrap:break-word; text-align:center;
}
.nt-th { background:rgba(79,142,247,.08); font-weight:700; font-size:7.5pt; }
.nt-tbl th { background:rgba(79,142,247,.08); font-weight:700; font-size:7.5pt; }
.nt-lbl { background:rgba(79,142,247,.05); font-weight:600; text-align:center !important; }
.nt-val { text-align:left !important; }
.nt-inp {
  width:100%; background:transparent; border:none; outline:none;
  font-size:7.5pt; color:var(--c-text); font-family:inherit;
  padding:2px 3px; text-align:left;
}
.nt-inp::placeholder { color:var(--c-text3); }
.nt-inp:focus { border-bottom:1px solid var(--c-accent); }

/* 텍스트 입력 (1행짜리) */
.nt-inline { display:flex; align-items:center; gap:6px; margin:4px 0; }
.nt-inline-lbl { font-size:9pt; font-weight:600; white-space:nowrap; color:var(--c-text); }
.nt-inline-inp { flex:1; background:transparent; border:none; border-bottom:1px solid var(--c-border); color:var(--c-text); font-size:9pt; padding:2px 4px; outline:none; }
.nt-inline-inp:focus { border-bottom-color:var(--c-accent); }
.nt-inline-inp::placeholder { color:var(--c-text3); font-style:italic; }

/* 검사담당자 / 확인자 행 */
.nt-sign-row { display:flex; gap:40px; margin:12px 0 4px; }
.nt-sign-item { display:flex; align-items:center; gap:8px; }
.nt-sign-lbl { font-size:9pt; font-weight:600; white-space:nowrap; color:var(--c-text); }
.nt-sign-inp { min-width:120px; background:transparent; border:none; border-bottom:1px solid var(--c-border); color:var(--c-text); font-size:9pt; padding:2px 4px; outline:none; }
.nt-sign-inp:focus { border-bottom-color:var(--c-accent); }

/* 첨부문서 업로드 영역 */
.nt-attach-section { margin-top:14px; }
.nt-attach-title { font-size:9pt; font-weight:700; margin-bottom:6px; color:var(--c-text); }
.nt-attach-note { font-size:8pt; color:var(--c-text3); margin-bottom:8px; }
.nt-attach-drop {
  border:2px dashed var(--c-border2); border-radius:8px;
  padding:16px; text-align:center; cursor:pointer;
  transition:.2s; color:var(--c-text3); font-size:9pt;
  background:rgba(255,255,255,.02);
}
.nt-attach-drop:hover { border-color:var(--c-accent); background:rgba(79,142,247,.04); }
.nt-attach-drop input[type=file] { display:none; }
.nt-attach-list { margin-top:8px; display:flex; flex-direction:column; gap:4px; }
.nt-attach-item {
  display:flex; align-items:center; gap:8px;
  padding:5px 10px; border-radius:6px;
  background:rgba(79,142,247,.06); border:1px solid var(--c-border);
  font-size:8.5pt;
}
.nt-attach-item-name { flex:1; color:var(--c-text); word-break:break-all; }
.nt-attach-item-size { color:var(--c-text3); white-space:nowrap; font-size:8pt; }
.nt-attach-item-del { color:#ef4444; cursor:pointer; padding:1px 5px; border-radius:3px; font-size:10pt; line-height:1; }
.nt-attach-item-del:hover { background:rgba(239,68,68,.12); }
/* 첨부문서 인쇄 미리보기 */
.nt-attach-print-wrap { margin-top:10px; }
.nt-attach-print-page { page-break-before:always; margin-top:20px; }
.nt-attach-print-page img { max-width:100%; height:auto; display:block; }
.nt-attach-print-page .nt-attach-pdf-frame { width:100%; min-height:600px; border:none; }

@media screen {
  .nt-header-lbl-cell,.nt-header-val-cell { border-color:var(--c-border); }
  .nt-header-tbl { border-color:var(--c-border); }
  .nt-tbl th,.nt-tbl td { border-color:var(--c-border); }
  .nt-tbl th { background:rgba(79,142,247,.08); }
  .nt-lbl { background:rgba(79,142,247,.05); }
  .nt-attach-print-wrap { display:none; }
}
@media print {
  @page { size:A4 portrait; margin:12mm 10mm; }
  .no-print { display:none !important; }
  body { background:#fff !important; color:#000 !important; }
  -webkit-print-color-adjust:exact; print-color-adjust:exact;

  .nt-wrap { font-size:8pt; font-family:'맑은 고딕','Malgun Gothic','MS Gothic',sans-serif; color:#000; }
  .nt-header-tbl { border:1px solid #555 !important; }
  .nt-header-lbl-cell { border:1px solid #555 !important; background:#cdd5e8 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .nt-header-val-cell { border:1px solid #555 !important; background:#fff !important; }
  .nt-header-lbl { font-size:7.5pt !important; color:#000 !important; }
  .nt-header-inp { font-size:7.5pt !important; color:#000 !important; border:none !important; background:transparent !important; }
  .nt-main-title { font-size:12pt !important; color:#000 !important; }
  .nt-form-tag { font-size:8pt !important; color:#000 !important; }
  .nt-sec-title { font-size:8.5pt !important; color:#000 !important; }
  .nt-tbl { font-size:6.5pt !important; margin-bottom:8px !important; }
  .nt-th { background:#c8d4ea !important; color:#000 !important; font-size:6.5pt !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .nt-tbl th { background:#c8d4ea !important; color:#000 !important; font-size:6.5pt !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .nt-tbl td { font-size:6.5pt !important; color:#000 !important; }
  .nt-lbl { background:#eef2fa !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .nt-inp { font-size:6.5pt !important; color:#000 !important; border:none !important; background:transparent !important; padding:0 !important; }
  .nt-tbl th, .nt-tbl td { border:1px solid #555 !important; padding:3px 4px !important; }
  .nt-inline-lbl { font-size:8pt !important; color:#000 !important; }
  .nt-inline-inp { font-size:8pt !important; color:#000 !important; border:none !important; border-bottom:1px solid #888 !important; background:transparent !important; }
  .nt-sign-lbl { font-size:8pt !important; color:#000 !important; }
  .nt-sign-inp { font-size:8pt !important; color:#000 !important; border:none !important; border-bottom:1px solid #888 !important; background:transparent !important; }
  .nt-attach-section .nt-attach-drop { display:none !important; }
  .nt-attach-section .nt-attach-list { display:none !important; }
  .nt-attach-print-wrap { display:block !important; }
  .nt-attach-print-page { page-break-before:always; }
}
</style>

<div class="nt-wrap">

<!-- ① 상단 헤더 -->
<table class="nt-header-tbl">
  <tr>
    <td class="nt-header-lbl-cell"><span class="nt-header-lbl">수입사</span></td>
    <td class="nt-header-lbl-cell"><span class="nt-header-lbl">인증연도</span></td>
    <td class="nt-header-lbl-cell"><span class="nt-header-lbl">배기량</span></td>
    <td class="nt-header-lbl-cell"><span class="nt-header-lbl">동일차종기호</span></td>
  </tr>
  <tr>
    <td class="nt-header-val-cell"><input data-field="importer"     class="nt-header-inp" type="text" placeholder="수입사명"   value="\${E(v('importer'))}"></td>
    <td class="nt-header-val-cell"><input data-field="cert_year"    class="nt-header-inp" type="text" placeholder="예) 2025"   value="\${E(v('cert_year'))}"></td>
    <td class="nt-header-val-cell"><input data-field="displacement" class="nt-header-inp" type="text" placeholder="예) 1000cc" value="\${E(v('displacement'))}"></td>
    <td class="nt-header-val-cell"><input data-field="family_code"  class="nt-header-inp" type="text" placeholder="기호 입력"  value="\${E(v('family_code'))}"></td>
  </tr>
</table>

<div class="nt-form-tag">[별지 제27의2호 서식]</div>
<div class="nt-main-title">자동차소음 세부내용 보고서(ECE)</div>

<!-- 1. 시험관련 규정 -->
<div class="nt-sec-title">1. 시험관련 규정(ECE)</div>
<div style="padding:4px 8px; font-size:9pt; color:var(--c-text2);">
  가속주행 소음시험은 ECE 시험방법으로 측정함
</div>

<!-- 2. 시험일 -->
<div class="nt-inline" style="margin-top:10px;">
  <span class="nt-inline-lbl">2. 시험일 :</span>
  <input data-field="nt_test_date" class="nt-inline-inp" type="text" placeholder="예) 2025. 01. 01." value="\${E(v('nt_test_date'))}">
</div>

<!-- 3. 시험자동차 제원 -->
<div class="nt-sec-title" style="margin-top:16px;">3. 시험자동차 제원</div>
<table class="nt-tbl">
  <colgroup>
    <col style="width:18%;"><col style="width:14%;"><col style="width:22%;"><col style="width:14%;">
  </colgroup>
  <thead>
    <tr>
      <th>항&nbsp;&nbsp;&nbsp;목</th>
      <th>내&nbsp;&nbsp;&nbsp;용</th>
      <th>항&nbsp;&nbsp;&nbsp;목</th>
      <th>내&nbsp;&nbsp;&nbsp;용</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="nt-lbl">차명</td>
      <td class="nt-val"><input data-field="nt_car_name"    class="nt-inp" type="text" value="\${E(v('nt_car_name'))}"></td>
      <td class="nt-lbl">제작사(국)</td>
      <td class="nt-val"><input data-field="nt_maker"       class="nt-inp" type="text" value="\${E(v('nt_maker'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">차종</td>
      <td class="nt-val"><input data-field="nt_car_type"    class="nt-inp" type="text" value="\${E(v('nt_car_type'))}"></td>
      <td class="nt-lbl">차대번호</td>
      <td class="nt-val"><input data-field="nt_vin"         class="nt-inp" type="text" value="\${E(v('nt_vin'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">형식</td>
      <td class="nt-val"><input data-field="nt_model_type"  class="nt-inp" type="text" value="\${E(v('nt_model_type'))}"></td>
      <td class="nt-lbl">엔진번호</td>
      <td class="nt-val"><input data-field="nt_engine_no"   class="nt-inp" type="text" value="\${E(v('nt_engine_no'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">엔진형식</td>
      <td class="nt-val"><input data-field="nt_engine_type" class="nt-inp" type="text" value="\${E(v('nt_engine_type'))}"></td>
      <td class="nt-lbl" style="font-size:6.5pt;">최고출력(PS/rpm, kw/rpm)</td>
      <td class="nt-val"><input data-field="nt_max_power"   class="nt-inp" type="text" value="\${E(v('nt_max_power'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">차대형식</td>
      <td class="nt-val"><input data-field="nt_chassis"     class="nt-inp" type="text" value="\${E(v('nt_chassis'))}"></td>
      <td class="nt-lbl">최대토크(kg.m/rpm)</td>
      <td class="nt-val"><input data-field="nt_max_torque"  class="nt-inp" type="text" value="\${E(v('nt_max_torque'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">배기량(cc)</td>
      <td class="nt-val"><input data-field="nt_disp_cc"     class="nt-inp" type="text" value="\${E(v('nt_disp_cc'))}"></td>
      <td class="nt-lbl" style="font-size:6.5pt;">엔진회전 수(Pmax 3/4, rpm)</td>
      <td class="nt-val"><input data-field="nt_rpm_34"      class="nt-inp" type="text" value="\${E(v('nt_rpm_34'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">차량연식</td>
      <td class="nt-val"><input data-field="nt_model_year"  class="nt-inp" type="text" value="\${E(v('nt_model_year'))}"></td>
      <td class="nt-lbl" style="font-size:6.5pt;">엔진회전 수(Pmax 1/2, rpm)</td>
      <td class="nt-val"><input data-field="nt_rpm_12"      class="nt-inp" type="text" value="\${E(v('nt_rpm_12'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">변속기종류 및 단수</td>
      <td class="nt-val"><input data-field="nt_trans"       class="nt-inp" type="text" value="\${E(v('nt_trans'))}"></td>
      <td class="nt-lbl">엔진위치</td>
      <td class="nt-val"><input data-field="nt_eng_pos"     class="nt-inp" type="text" value="\${E(v('nt_eng_pos'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">변속비(또는 기어비)</td>
      <td class="nt-val"><input data-field="nt_gear_ratio"  class="nt-inp" type="text" value="\${E(v('nt_gear_ratio'))}"></td>
      <td class="nt-lbl">축수</td>
      <td class="nt-val"><input data-field="nt_axles"       class="nt-inp" type="text" value="\${E(v('nt_axles'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">감속비</td>
      <td class="nt-val"><input data-field="nt_final_ratio" class="nt-inp" type="text" value="\${E(v('nt_final_ratio'))}"></td>
      <td class="nt-lbl">구동축수</td>
      <td class="nt-val"><input data-field="nt_drive_axles" class="nt-inp" type="text" value="\${E(v('nt_drive_axles'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">구동축</td>
      <td class="nt-val"><input data-field="nt_drive_axle"  class="nt-inp" type="text" value="\${E(v('nt_drive_axle'))}"></td>
      <td class="nt-lbl">축비</td>
      <td class="nt-val"><input data-field="nt_axle_ratio"  class="nt-inp" type="text" value="\${E(v('nt_axle_ratio'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">공차중량(kg)</td>
      <td class="nt-val"><input data-field="nt_curb_wt"     class="nt-inp" type="text" value="\${E(v('nt_curb_wt'))}"></td>
      <td class="nt-lbl">차량총중량(kg)</td>
      <td class="nt-val"><input data-field="nt_gvw"         class="nt-inp" type="text" value="\${E(v('nt_gvw'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">시험중량(kg)</td>
      <td class="nt-val"><input data-field="nt_test_wt"     class="nt-inp" type="text" value="\${E(v('nt_test_wt'))}"></td>
      <td class="nt-lbl" style="font-size:6.5pt;">중량대 출력비(PMR, KW/t)</td>
      <td class="nt-val"><input data-field="nt_pmr"         class="nt-inp" type="text" value="\${E(v('nt_pmr'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">자동차의 길이(m)</td>
      <td class="nt-val"><input data-field="nt_length"      class="nt-inp" type="text" value="\${E(v('nt_length'))}"></td>
      <td class="nt-lbl">부분출력계수(K<sub>p</sub>)</td>
      <td class="nt-val"><input data-field="nt_kp"          class="nt-inp" type="text" value="\${E(v('nt_kp'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl" rowspan="2">구동륜타이어<br>동하중반경(m)</td>
      <td class="nt-val" rowspan="2"><input data-field="nt_tire_radius" class="nt-inp" type="text" value="\${E(v('nt_tire_radius'))}"></td>
      <td class="nt-lbl" rowspan="2">타이어규격 및<br>트레드깊이</td>
      <td class="nt-val"><span style="font-size:6.5pt;color:var(--c-text3);">전&nbsp;</span><input data-field="nt_tire_spec_f" class="nt-inp" type="text" style="width:calc(100% - 20px);" value="\${E(v('nt_tire_spec_f'))}"></td>
    </tr>
    <tr>
      <td class="nt-val"><span style="font-size:6.5pt;color:var(--c-text3);">후&nbsp;</span><input data-field="nt_tire_spec_r" class="nt-inp" type="text" style="width:calc(100% - 20px);" value="\${E(v('nt_tire_spec_r'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl" rowspan="2">소음기형태 및<br>부착위치. 수량</td>
      <td class="nt-val" rowspan="2"><input data-field="nt_muffler" class="nt-inp" type="text" value="\${E(v('nt_muffler'))}"></td>
      <td class="nt-lbl" rowspan="2">타이어<br>공기압력(kPa)</td>
      <td class="nt-val"><span style="font-size:6.5pt;color:var(--c-text3);">전&nbsp;</span><input data-field="nt_tire_pres_f" class="nt-inp" type="text" style="width:calc(100% - 20px);" value="\${E(v('nt_tire_pres_f'))}"></td>
    </tr>
    <tr>
      <td class="nt-val"><span style="font-size:6.5pt;color:var(--c-text3);">후&nbsp;</span><input data-field="nt_tire_pres_r" class="nt-inp" type="text" style="width:calc(100% - 20px);" value="\${E(v('nt_tire_pres_r'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">자동저단번속장치<br>작동여부</td>
      <td class="nt-val"><input data-field="nt_auto_downshift" class="nt-inp" type="text" value="\${E(v('nt_auto_downshift'))}"></td>
      <td class="nt-lbl">경음기 형식 및 수량</td>
      <td class="nt-val"><input data-field="nt_horn"           class="nt-inp" type="text" value="\${E(v('nt_horn'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">기타</td>
      <td class="nt-val" colspan="3"><input data-field="nt_etc1" class="nt-inp" type="text" style="width:100%;" value="\${E(v('nt_etc1'))}"></td>
    </tr>
  </tbody>
</table>

<!-- 4. 시험장 주변조건 -->
<div class="nt-sec-title" style="margin-top:16px;">4. 시험장 주변조건</div>
<table class="nt-tbl">
  <colgroup>
    <col style="width:18%;"><col style="width:14%;"><col style="width:22%;"><col style="width:14%;">
  </colgroup>
  <thead>
    <tr>
      <th>항&nbsp;&nbsp;&nbsp;목</th>
      <th>내&nbsp;&nbsp;&nbsp;용</th>
      <th>항&nbsp;&nbsp;&nbsp;목</th>
      <th>내&nbsp;&nbsp;&nbsp;용</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="nt-lbl">장소</td>
      <td class="nt-val"><input data-field="nt_site"     class="nt-inp" type="text" value="\${E(v('nt_site'))}"></td>
      <td class="nt-lbl">날씨</td>
      <td class="nt-val"><input data-field="nt_weather"  class="nt-inp" type="text" value="\${E(v('nt_weather'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">풍향</td>
      <td class="nt-val"><input data-field="nt_wind_dir" class="nt-inp" type="text" value="\${E(v('nt_wind_dir'))}"></td>
      <td class="nt-lbl">풍속</td>
      <td class="nt-val"><input data-field="nt_wind_spd" class="nt-inp" type="text" value="\${E(v('nt_wind_spd'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">대기습도</td>
      <td class="nt-val"><input data-field="nt_humidity" class="nt-inp" type="text" value="\${E(v('nt_humidity'))}"></td>
      <td class="nt-lbl">대기압력</td>
      <td class="nt-val"><input data-field="nt_pressure" class="nt-inp" type="text" value="\${E(v('nt_pressure'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">대기온도</td>
      <td class="nt-val"><input data-field="nt_temp"     class="nt-inp" type="text" value="\${E(v('nt_temp'))}"></td>
      <td class="nt-lbl">기타</td>
      <td class="nt-val"><input data-field="nt_env_etc"  class="nt-inp" type="text" value="\${E(v('nt_env_etc'))}"></td>
    </tr>
  </tbody>
</table>

<!-- 5. 소음측정장비 -->
<div class="nt-sec-title" style="margin-top:16px;">5. 소음측정장비</div>
<table class="nt-tbl">
  <colgroup>
    <col style="width:18%;"><col style="width:20%;"><col style="width:18%;"><col style="width:18%;"><col style="width:14%;">
  </colgroup>
  <thead>
    <tr>
      <th>구분</th><th>제작사</th><th>형식</th><th>기기번호</th><th>검/교정일</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="nt-lbl">소음계</td>
      <td class="nt-val"><input data-field="nt_eq1_maker" class="nt-inp" type="text" value="\${E(v('nt_eq1_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq1_type"  class="nt-inp" type="text" value="\${E(v('nt_eq1_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq1_no"    class="nt-inp" type="text" value="\${E(v('nt_eq1_no'))}"></td>
      <td class="nt-val"><input data-field="nt_eq1_cal"   class="nt-inp" type="text" value="\${E(v('nt_eq1_cal'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">교정기</td>
      <td class="nt-val"><input data-field="nt_eq2_maker" class="nt-inp" type="text" value="\${E(v('nt_eq2_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq2_type"  class="nt-inp" type="text" value="\${E(v('nt_eq2_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq2_no"    class="nt-inp" type="text" value="\${E(v('nt_eq2_no'))}"></td>
      <td class="nt-val"><input data-field="nt_eq2_cal"   class="nt-inp" type="text" value="\${E(v('nt_eq2_cal'))}"></td>
    </tr>
    <!-- 차속계: 구분 셀은 rowspan=2, 오른쪽 4칸은 2개 행으로 분리 (PDF 구조 반영) -->
    <tr>
      <td class="nt-lbl" rowspan="2">차속계</td>
      <td class="nt-val"><input data-field="nt_eq3a_maker" class="nt-inp" type="text" value="\${E(v('nt_eq3a_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq3a_type"  class="nt-inp" type="text" value="\${E(v('nt_eq3a_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq3a_no"    class="nt-inp" type="text" value="\${E(v('nt_eq3a_no'))}"></td>
      <td class="nt-val"><input data-field="nt_eq3a_cal"   class="nt-inp" type="text" value="\${E(v('nt_eq3a_cal'))}"></td>
    </tr>
    <tr>
      <td class="nt-val"><input data-field="nt_eq3b_maker" class="nt-inp" type="text" value="\${E(v('nt_eq3b_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq3b_type"  class="nt-inp" type="text" value="\${E(v('nt_eq3b_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq3b_no"    class="nt-inp" type="text" value="\${E(v('nt_eq3b_no'))}"></td>
      <td class="nt-val"><input data-field="nt_eq3b_cal"   class="nt-inp" type="text" value="\${E(v('nt_eq3b_cal'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">엔진속도<br>측정기</td>
      <td class="nt-val"><input data-field="nt_eq4_maker" class="nt-inp" type="text" value="\${E(v('nt_eq4_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq4_type"  class="nt-inp" type="text" value="\${E(v('nt_eq4_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq4_no"    class="nt-inp" type="text" value="\${E(v('nt_eq4_no'))}"></td>
      <td class="nt-val"><input data-field="nt_eq4_cal"   class="nt-inp" type="text" value="\${E(v('nt_eq4_cal'))}"></td>
    </tr>
    <!-- 기상관측장비: 구분 셀은 rowspan=2, 오른쪽 4칸은 2개 행으로 분리 (PDF 구조 반영) -->
    <tr>
      <td class="nt-lbl" rowspan="2">기상관측장비<br>(풍속, 온도)</td>
      <td class="nt-val"><input data-field="nt_eq5a_maker" class="nt-inp" type="text" value="\${E(v('nt_eq5a_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq5a_type"  class="nt-inp" type="text" value="\${E(v('nt_eq5a_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq5a_no"    class="nt-inp" type="text" value="\${E(v('nt_eq5a_no'))}"></td>
      <td class="nt-val"><input data-field="nt_eq5a_cal"   class="nt-inp" type="text" value="\${E(v('nt_eq5a_cal'))}"></td>
    </tr>
    <tr>
      <td class="nt-val"><input data-field="nt_eq5b_maker" class="nt-inp" type="text" value="\${E(v('nt_eq5b_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq5b_type"  class="nt-inp" type="text" value="\${E(v('nt_eq5b_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq5b_no"    class="nt-inp" type="text" value="\${E(v('nt_eq5b_no'))}"></td>
      <td class="nt-val"><input data-field="nt_eq5b_cal"   class="nt-inp" type="text" value="\${E(v('nt_eq5b_cal'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">소음 주행로</td>
      <td class="nt-val"><input data-field="nt_eq6_maker" class="nt-inp" type="text" value="\${E(v('nt_eq6_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq6_type"  class="nt-inp" type="text" value="\${E(v('nt_eq6_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq6_no"    class="nt-inp" type="text" value="\${E(v('nt_eq6_no'))}"></td>
      <td class="nt-val"><input data-field="nt_eq6_cal"   class="nt-inp" type="text" value="\${E(v('nt_eq6_cal'))}"></td>
    </tr>
    <tr>
      <td class="nt-val"><input data-field="nt_eq7_name"  class="nt-inp" type="text" placeholder="장비명" value="\${E(v('nt_eq7_name'))}"></td>
      <td class="nt-val"><input data-field="nt_eq7_maker" class="nt-inp" type="text" value="\${E(v('nt_eq7_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq7_type"  class="nt-inp" type="text" value="\${E(v('nt_eq7_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq7_no"    class="nt-inp" type="text" value="\${E(v('nt_eq7_no'))}"></td>
      <td class="nt-val"><input data-field="nt_eq7_cal"   class="nt-inp" type="text" value="\${E(v('nt_eq7_cal'))}"></td>
    </tr>
    <tr>
      <td class="nt-val"><input data-field="nt_eq8_name"  class="nt-inp" type="text" placeholder="장비명" value="\${E(v('nt_eq8_name'))}"></td>
      <td class="nt-val"><input data-field="nt_eq8_maker" class="nt-inp" type="text" value="\${E(v('nt_eq8_maker'))}"></td>
      <td class="nt-val"><input data-field="nt_eq8_type"  class="nt-inp" type="text" value="\${E(v('nt_eq8_type'))}"></td>
      <td class="nt-val"><input data-field="nt_eq8_no"    class="nt-inp" type="text" value="\${E(v('nt_eq8_no'))}"></td>
      <td class="nt-val"><input data-field="nt_eq8_cal"   class="nt-inp" type="text" value="\${E(v('nt_eq8_cal'))}"></td>
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
<div class="nt-sec-title" style="margin-top:18px;">6. 가속주행소음 측정결과</div>
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
      <td class="nt-lbl" colspan="5" style="font-size:6pt;">시험중량 (Tested Vehicle weight, kg)</td>
      <td class="nt-val"><input data-field="nt_acc_test_wt" class="nt-inp" type="text" value="\${E(v('nt_acc_test_wt'))}"></td>
      <td class="nt-lbl" colspan="5" style="font-size:6pt;">적재중량 (Vehicle load, kg)</td>
      <td class="nt-val"><input data-field="nt_acc_load_wt" class="nt-inp" type="text" value="\${E(v('nt_acc_load_wt'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl" colspan="5" style="font-size:6pt;">선택기어 (Gear selected, I)</td>
      <td class="nt-val"><input data-field="nt_gear_i" class="nt-inp" type="text" value="\${E(v('nt_gear_i'))}"></td>
      <td class="nt-lbl" colspan="5" style="font-size:6pt;">선택기어 (Gear selected, I+1)</td>
      <td class="nt-val"><input data-field="nt_gear_i1" class="nt-inp" type="text" value="\${E(v('nt_gear_i1'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl" colspan="5" style="font-size:6pt;">목표 가속도 (a<sub>urban</sub>, m/s²)</td>
      <td class="nt-val"><input data-field="nt_aurban" class="nt-inp" type="text" value="\${E(v('nt_aurban'))}"></td>
      <td class="nt-lbl" colspan="5" style="font-size:6pt;">기준 가속도 (a<sub>wotref</sub>, m/s²)</td>
      <td class="nt-val"><input data-field="nt_awotref" class="nt-inp" type="text" value="\${E(v('nt_awotref'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl" colspan="5" style="font-size:6pt;">측정 가속도 (a<sub>wot</sub>, m/s²)</td>
      <td class="nt-val"><input data-field="nt_awot_meas" class="nt-inp" type="text" value="\${E(v('nt_awot_meas'))}"></td>
      <td class="nt-lbl" colspan="3" style="font-size:6pt;">부분출력계수 (K<sub>p</sub>)</td>
      <td class="nt-val"><input data-field="nt_kp2" class="nt-inp" type="text" value="\${E(v('nt_kp2'))}"></td>
      <td class="nt-lbl" style="font-size:5.5pt;">가중계수<br>(k)</td>
      <td class="nt-val"><input data-field="nt_k" class="nt-inp" type="text" value="\${E(v('nt_k'))}"></td>
    </tr>
    <!-- ② 헤더: 1행=가속/정속 구분, 2행=컬럼명, 3행=단위 (사용변속기어·구분은 rowspan=4) -->
    <tr>
      <th class="nt-th" rowspan="3" style="font-size:5pt;">사용<br>변속<br>기어</th>
      <th class="nt-th" rowspan="3" style="font-size:5pt;">구분</th>
      <th class="nt-th" colspan="8" style="font-size:6pt;">가속주행시험</th>
      <th class="nt-th" colspan="2" style="font-size:6pt;">정속주행시험</th>
    </tr>
    <tr>
      <th class="nt-th" style="font-size:5pt;">초기속도<br>(V<sub>AA′</sub>)</th>
      <th class="nt-th" style="font-size:5pt;">중간속도<br>(V<sub>PP′</sub>)</th>
      <th class="nt-th" style="font-size:5pt;">탈출속도<br>(V<sub>BB′</sub>)</th>
      <th class="nt-th" style="font-size:5pt;">탈출엔진<br>회전수<br>(N<sub>BB′</sub>)</th>
      <th class="nt-th" style="font-size:5pt;">가속<br>시작위치</th>
      <th class="nt-th" style="font-size:5pt;">좌측<br>소음</th>
      <th class="nt-th" style="font-size:5pt;">우측<br>소음</th>
      <th class="nt-th" style="font-size:5pt;">가속도<br>(a<sub>wot</sub>)</th>
      <th class="nt-th" style="font-size:5pt;">좌측<br>소음</th>
      <th class="nt-th" style="font-size:5pt;">우측<br>소음</th>
    </tr>
    <tr>
      <th class="nt-th" style="font-size:5pt;">kph</th>
      <th class="nt-th" style="font-size:5pt;">kph</th>
      <th class="nt-th" style="font-size:5pt;">kph</th>
      <th class="nt-th" style="font-size:5pt;">rpm</th>
      <th class="nt-th" style="font-size:5pt;">m</th>
      <th class="nt-th" style="font-size:5pt;">dB(A)</th>
      <th class="nt-th" style="font-size:5pt;">dB(A)</th>
      <th class="nt-th" style="font-size:5pt;">m/s²</th>
      <th class="nt-th" style="font-size:5pt;">dB(A)</th>
      <th class="nt-th" style="font-size:5pt;">dB(A)</th>
    </tr>
    <!-- ③ 기어 I - 1~4차 (정적 행, template literal 오류 방지) -->
    <tr>
      <td class="nt-lbl" rowspan="5" style="font-size:6pt; text-align:center;"><input data-field="nt_gear_sel1" class="nt-inp" type="text" style="width:100%;text-align:center;" value="\${E(v('nt_gear_sel1'))}"></td>
      <td class="nt-lbl" style="font-size:6pt;">1차</td>
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
      <td class="nt-lbl" style="font-size:6pt;">2차</td>
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
      <td class="nt-lbl" style="font-size:6pt;">3차</td>
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
      <td class="nt-lbl" style="font-size:6pt;">4차</td>
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
      <td class="nt-lbl" colspan="6" style="font-size:6pt; text-align:center;">평균</td>
      <td class="nt-val"><input data-field="nt_g1_avg_lL" class="nt-inp" type="text" value="\${E(v('nt_g1_avg_lL'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_avg_lR" class="nt-inp" type="text" value="\${E(v('nt_g1_avg_lR'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_avg_aw" class="nt-inp" type="text" value="\${E(v('nt_g1_avg_aw'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_avg_cL" class="nt-inp" type="text" value="\${E(v('nt_g1_avg_cL'))}"></td>
      <td class="nt-val"><input data-field="nt_g1_avg_cR" class="nt-inp" type="text" value="\${E(v('nt_g1_avg_cR'))}"></td>
    </tr>
    <!-- ④ 기어 I+1 - 1~4차 (정적 행) -->
    <tr>
      <td class="nt-lbl" rowspan="5" style="font-size:6pt; text-align:center;"><input data-field="nt_gear_sel2" class="nt-inp" type="text" style="width:100%;text-align:center;" value="\${E(v('nt_gear_sel2'))}"></td>
      <td class="nt-lbl" style="font-size:6pt;">1차</td>
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
      <td class="nt-lbl" style="font-size:6pt;">2차</td>
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
      <td class="nt-lbl" style="font-size:6pt;">3차</td>
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
      <td class="nt-lbl" style="font-size:6pt;">4차</td>
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
      <td class="nt-lbl" colspan="6" style="font-size:6pt; text-align:center;">평균</td>
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
      <td class="nt-lbl" style="font-size:6pt; text-align:center;">시험<br>결과</td>
      <td class="nt-lbl" colspan="3" style="font-size:5pt; text-align:center; line-height:1.5;">가속주행소음<br>(L<sub>WOTrep</sub>, dB(A))</td>
      <td class="nt-val"><input data-field="nt_lwot" class="nt-inp" type="text" value="\${E(v('nt_lwot'))}"></td>
      <td class="nt-lbl" colspan="3" style="font-size:5pt; text-align:center; line-height:1.5;">정속주행소음<br>(L<sub>CRSrep</sub>, dB(A))</td>
      <td class="nt-val"><input data-field="nt_lcrs" class="nt-inp" type="text" value="\${E(v('nt_lcrs'))}"></td>
      <td class="nt-lbl" colspan="2" style="font-size:5pt; text-align:center; line-height:1.5;">(L<sub>URBAN</sub>, dB(A))</td>
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
      <td class="nt-lbl" style="font-size:6pt; text-align:center;">최종<br>결과</td>
      <td class="nt-lbl" colspan="3" style="font-size:5pt; text-align:center;">L (dB(A))</td>
      <td class="nt-val"><input data-field="nt_final_L" class="nt-inp" type="text" value="\${E(v('nt_final_L'))}"></td>
      <td colspan="3"></td>
      <td class="nt-lbl" colspan="3" style="font-size:5pt; text-align:center;">기준치 (dB(A))</td>
      <td class="nt-val"><input data-field="nt_limit" class="nt-inp" type="text" value="\${E(v('nt_limit'))}"></td>
    </tr>
  </tbody>
</table>

<!-- 7. 배기소음측정결과 -->
<div class="nt-sec-title" style="margin-top:16px;">7. 배기소음측정결과(KSAISO 362)</div>
<table class="nt-tbl">
  <colgroup>
    <col style="width:8%;"><col style="width:8%;"><col style="width:18%;"><col style="width:12%;"><col style="width:12%;"><col style="width:12%;"><col style="width:12%;"><col style="width:12%;">
  </colgroup>
  <thead>
    <tr>
      <th rowspan="2" colspan="2">배기<br>소음<br>시험</th>
      <th rowspan="2">원동기 최고 출력<br>회전속도의<br><input data-field="nt_ex_pct" class="nt-inp" type="text" style="width:2.2em;text-align:right;" value="\${E(v('nt_ex_pct'))}">% 회전속도(rpm)</th>
      <th rowspan="2">암소음<br>(dB(A))</th>
      <th colspan="2">배기소음(dB(A))</th>
      <th rowspan="2">성적<br>(dB(A))</th>
      <th rowspan="2">기준치<br>(dB(A))</th>
    </tr>
    <tr>
      <th>측정치</th><th>보정치</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="nt-lbl" rowspan="3">배기<br>소음<br>시험</td>
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
<div class="nt-sec-title" style="margin-top:16px;">8. 경적소음측정결과(KSAISO 362)</div>
<table class="nt-tbl">
  <colgroup>
    <col style="width:8%;"><col style="width:10%;"><col style="width:12%;"><col style="width:10%;"><col style="width:12%;"><col style="width:12%;"><col style="width:12%;"><col style="width:12%;"><col style="width:10%;">
  </colgroup>
  <thead>
    <tr>
      <th rowspan="2" colspan="2">경적<br>소음<br>시험</th>
      <th rowspan="2">경음기<br>형식</th>
      <th rowspan="2">경음기 수</th>
      <th rowspan="2">암소음<br>(dB(C))</th>
      <th colspan="2">경적소음(dB(C))</th>
      <th rowspan="2">성적<br>(dB(C))</th>
      <th rowspan="2">기준치<br>(dB(C))</th>
    </tr>
    <tr>
      <th>측정치</th><th>보정치</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="nt-lbl" rowspan="2">경적<br>소음<br>시험</td>
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
    <span class="nt-sign-lbl">검사 담당자 :</span>
    <input data-field="nt_inspector" class="nt-sign-inp" type="text" placeholder="성명" value="\${E(v('nt_inspector'))}">
  </div>
  <div class="nt-sign-item">
    <span class="nt-sign-lbl">확인자 :</span>
    <input data-field="nt_confirmer" class="nt-sign-inp" type="text" placeholder="성명" value="\${E(v('nt_confirmer'))}">
  </div>
</div>
<div style="font-size:9pt; margin-top:8px; color:var(--c-text2);">자체시험성적서 및 RAW DATA 첨부</div>

<!-- 첨부문서 업로드 -->
<div class="nt-attach-section no-print">
  <div class="nt-attach-title"><i class="fas fa-paperclip"></i> 첨부문서 (자체시험성적서 / RAW DATA)</div>
  <div class="nt-attach-note">이미지(JPG, PNG) 또는 PDF 파일을 첨부하면 인쇄 시 함께 출력됩니다.</div>
  <div class="nt-attach-drop" id="nt-drop-zone" onclick="document.getElementById('nt-file-input').click()">
    <input type="file" id="nt-file-input" multiple accept="image/*,.pdf">
    <i class="fas fa-cloud-upload-alt" style="font-size:20pt;margin-bottom:6px;display:block;"></i>
    클릭하거나 파일을 드래그하여 첨부
  </div>
  <div class="nt-attach-list" id="nt-attach-list"></div>
</div>

<!-- 인쇄용 첨부문서 미리보기 (화면에서는 숨김) -->
<div class="nt-attach-print-wrap" id="nt-attach-print-wrap"></div>

</div>

<div id="qr-footer-wrap" style="margin-top:12px;"></div>

\`;

  if (formType==='confirmation') return \`
<style>
/* ══════════ confirmation 전용 스타일 ══════════
   PDF 원본 구조: 상단헤더(4칸) + 제목셀 + 단일 본문셀(1~5항목 + 확인문구 + 서명란)
   인증신청 요약서와 달리 3열(구분/항목/내용) 구조 없음
   ══════════════════════════════════════════════ */

/* ── 전체 래퍼 ── */
.cf-wrap {
  box-sizing:border-box;
  font-family:'맑은 고딕','Malgun Gothic',sans-serif;
}

/* ── 상단 헤더 (요약서와 동일) ── */
.cf-header-tbl {
  width:100%; border-collapse:collapse;
  border:1px solid #888;
}
.cf-header-lbl-cell {
  width:25%; border:1px solid #888;
  padding:4px 8px; vertical-align:middle;
  background:rgba(79,142,247,.08);
  text-align:center;
}
.cf-header-val-cell {
  width:25%; border:1px solid #888;
  padding:4px 8px; vertical-align:middle;
}
.cf-header-lbl {
  display:block; font-size:.72rem; font-weight:700;
  color:var(--c-text2); letter-spacing:.02em; text-align:center;
}
.cf-header-inp {
  width:100%; background:transparent;
  border:none; border-bottom:1px solid var(--c-border);
  color:var(--c-text); font-size:.9rem;
  padding:3px 0; outline:none;
}
.cf-header-inp:focus { border-bottom-color:var(--c-accent); }

/* ── 제목 셀 ── */
.cf-title {
  text-align:center;
  font-size:14pt; font-weight:800;
  letter-spacing:.08em;
  padding:14px 10px;
  border:1px solid #888; border-top:none;
}

/* ── 본문 테이블 (단일 셀 구조 - PDF 원본과 동일) ── */
.cf-body-tbl {
  width:100%; border-collapse:collapse;
  border:1px solid #888; border-top:none;
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
  border-bottom:1px solid var(--c-border);
  min-height:40px;
  gap:0;
}
.cf-item-row:last-child { border-bottom:none; }
.cf-item-lbl {
  font-size:10pt; font-weight:600;
  white-space:nowrap;
  color:var(--c-text);
  min-width:110px;
  flex-shrink:0;
  padding-top:3px;
}
.cf-item-inp-wrap {
  flex:1; min-width:0;
}
.cf-item-inp {
  width:100%; background:transparent;
  border:none; border-bottom:1px solid var(--c-border);
  color:var(--c-text); font-size:10pt;
  padding:2px 4px; outline:none;
}
.cf-item-inp:focus { border-bottom-color:var(--c-accent); }
.cf-item-inp::placeholder { color:var(--c-text3); font-style:italic; }

/* 주소 TEL/FAX 행 */
.cf-tel-fax {
  display:flex; gap:10px; margin-top:8px; align-items:center;
}
.cf-tel-fax-lbl {
  font-size:10pt; white-space:nowrap;
  color:var(--c-text3); font-weight:600;
}

/* ── 5. 보증내용 ── */
.cf-warranty-row {
  padding:10px 14px;
  border-bottom:1px solid var(--c-border);
}
.cf-warranty-top {
  display:flex; align-items:flex-start; gap:0; margin-bottom:8px;
}
.cf-warranty-lbl {
  font-size:10pt; font-weight:600;
  white-space:nowrap; min-width:110px; flex-shrink:0;
  padding-top:3px; color:var(--c-text);
}
.cf-warranty-subject-inp {
  flex:1; min-width:0;
  background:transparent;
  border:none; border-bottom:1px solid var(--c-border);
  color:var(--c-text); font-size:10pt;
  padding:2px 4px; outline:none;
}
.cf-warranty-subject-inp:focus { border-bottom-color:var(--c-accent); }
.cf-warranty-subject-inp::placeholder { color:var(--c-text3); font-style:italic; }
.cf-warranty-body {
  font-size:10pt; line-height:1.85;
  color:var(--c-text2);
  word-break:keep-all; text-align:justify;
  padding-left:110px;
}

/* ── 당사확인 문구 ── */
.cf-confirm-stmt {
  text-align:center; font-size:10pt; font-weight:600;
  padding:16px 14px;
  border-bottom:1px solid var(--c-border);
  color:var(--c-text);
}

/* ── 제작사 확인 헤더 ── */
.cf-sign-head {
  text-align:center; font-size:10pt; font-weight:700;
  padding:8px 14px; letter-spacing:.08em;
  border-bottom:1px solid var(--c-border);
  background:rgba(79,142,247,.08);
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
  color:var(--c-text);
}
.cf-sign-inp {
  width:100%; background:transparent;
  border:none; border-bottom:1.5px solid var(--c-border);
  color:var(--c-text); font-size:10pt;
  padding:4px 2px; outline:none;
}
.cf-sign-inp:focus { border-bottom-color:var(--c-accent); }
.cf-sign-inp::placeholder { color:var(--c-text3); font-style:italic; }
.cf-sign-divider {
  border:none; border-right:1px solid var(--c-border);
  padding:0; width:1px;
}

@media screen {
  .cf-header-lbl-cell { border-color:var(--c-border); }
  .cf-header-val-cell { border-color:var(--c-border); }
  .cf-header-tbl { border-color:var(--c-border); }
  .cf-title { background:rgba(79,142,247,.06); border-color:var(--c-border2); color:var(--c-text); }
  .cf-body-tbl { border-color:var(--c-border); }
  .cf-body-tbl td { border-color:var(--c-border); }
  .cf-sign-head { background:rgba(79,142,247,.06); border-color:var(--c-border); }
}

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

  /* 상단 헤더 */
  .cf-header-tbl { border:1px solid #555 !important; border-collapse:collapse !important; width:100% !important; }
  .cf-header-lbl-cell { border:1px solid #555 !important; padding:3px 6px !important; background:#cdd5e8 !important; text-align:center !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .cf-header-val-cell { border:1px solid #555 !important; padding:3px 6px !important; background:#fff !important; }
  .cf-header-lbl { font-size:8.5pt !important; font-weight:700 !important; color:#000 !important; display:block; text-align:center !important; }
  .cf-header-inp { font-size:8.5pt !important; color:#000 !important; border:none !important; border-bottom:1px solid #888 !important; background:transparent !important; padding:1px 0 !important; width:100% !important; font-family:inherit !important; }

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

<div class="cf-wrap">

  <!-- ① 상단 헤더 (요약서와 동일 2행 구조) -->
  <table class="cf-header-tbl">
    <tr>
      <td class="cf-header-lbl-cell"><span class="cf-header-lbl">수입사</span></td>
      <td class="cf-header-lbl-cell"><span class="cf-header-lbl">인증연도</span></td>
      <td class="cf-header-lbl-cell"><span class="cf-header-lbl">배기량</span></td>
      <td class="cf-header-lbl-cell"><span class="cf-header-lbl">동일차종기호</span></td>
    </tr>
    <tr>
      <td class="cf-header-val-cell"><input data-field="importer"     class="cf-header-inp" type="text" placeholder="수입사명"   value="\${E(v('importer'))}"></td>
      <td class="cf-header-val-cell"><input data-field="cert_year"    class="cf-header-inp" type="text" placeholder="예) 2025"   value="\${E(v('cert_year'))}"></td>
      <td class="cf-header-val-cell"><input data-field="displacement" class="cf-header-inp" type="text" placeholder="예) 1000cc" value="\${E(v('displacement'))}"></td>
      <td class="cf-header-val-cell"><input data-field="family_code"  class="cf-header-inp" type="text" placeholder="기호 입력"  value="\${E(v('family_code'))}"></td>
    </tr>
  </table>

  <!-- ② 제목 (PDF 원본: 전체 너비 단독 셀) -->
  <div class="cf-title">확 &nbsp;&nbsp; 인 &nbsp;&nbsp; 서</div>

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
          <div class="cf-sign-head">제 작 사 &nbsp;&nbsp; 확 인</div>

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
// noise_test 첨부파일 기능
// ================================================================
function initEmissionAttach() {
  function makeAttach(dropId, fileInputId, listId, printWrapId) {
    var files = [];
    var dropZone  = document.getElementById(dropId);
    var fileInput = document.getElementById(fileInputId);
    var listEl    = document.getElementById(listId);
    var printWrap = document.getElementById(printWrapId);
    if (!dropZone || !fileInput) return;

    dropZone.addEventListener('dragover',  function(e){ e.preventDefault(); dropZone.style.borderColor='var(--c-accent)'; });
    dropZone.addEventListener('dragleave', function(){ dropZone.style.borderColor=''; });
    dropZone.addEventListener('drop',      function(e){ e.preventDefault(); dropZone.style.borderColor=''; handleFiles(e.dataTransfer.files); });
    dropZone.addEventListener('click',     function(){ fileInput.click(); });
    fileInput.addEventListener('change',   function(){ handleFiles(this.files); this.value=''; });

    function handleFiles(flist) {
      Array.from(flist).forEach(function(file){
        var reader = new FileReader();
        reader.onload = function(ev){
          files.push({ name:file.name, size:file.size, type:file.type, dataUrl:ev.target.result });
          renderList(); renderPrint();
        };
        reader.readAsDataURL(file);
      });
    }
    function fmtSize(b){ return b<1024?b+'B':b<1048576?(b/1024).toFixed(1)+'KB':(b/1048576).toFixed(1)+'MB'; }
    function renderList(){
      listEl.innerHTML='';
      files.forEach(function(f,idx){
        var div=document.createElement('div');
        div.className='em-attach-item';
        div.innerHTML='<i class="fas '+(f.type==='application/pdf'?'fa-file-pdf':'fa-file-image')+'" style="color:var(--c-accent);"></i>'+
          '<span class="em-attach-item-name">'+f.name+'</span>'+
          '<span class="em-attach-item-size">'+fmtSize(f.size)+'</span>'+
          '<span class="em-attach-item-del" title="삭제" data-idx="'+idx+'">×</span>';
        listEl.appendChild(div);
      });
      listEl.querySelectorAll('.em-attach-item-del').forEach(function(btn){
        btn.addEventListener('click',function(e){
          e.stopPropagation();
          files.splice(parseInt(this.dataset.idx),1);
          renderList(); renderPrint();
        });
      });
    }
    function renderPrint(){
      if (!printWrap) return;
      printWrap.innerHTML='';
      if (files.length === 0) { printWrap.style.display='none'; return; }
      printWrap.style.display='block';
      files.forEach(function(f){
        var page=document.createElement('div');
        page.className='em-attach-print-page';
        var lbl=document.createElement('div');
        lbl.style.cssText='font-size:9pt;font-weight:700;margin-bottom:6px;color:#000;';
        lbl.textContent='첨부: '+f.name;
        page.appendChild(lbl);
        if(f.type==='application/pdf'){
          var iframe=document.createElement('iframe');
          iframe.src=f.dataUrl;
          iframe.className='em-attach-pdf-frame';
          iframe.style.cssText='width:100%;min-height:700px;border:none;';
          page.appendChild(iframe);
        } else {
          var img=document.createElement('img');
          img.src=f.dataUrl;
          img.style.cssText='max-width:100%;height:auto;display:block;';
          page.appendChild(img);
        }
        printWrap.appendChild(page);
      });
    }
  }
  // 자체 배출가스 시험 성적서 / RAW DATA
  makeAttach('em-drop-raw','em-file-raw','em-list-raw','em-print-raw');
}

function initEvapAttach() {
  function makeAttach(dropId, fileInputId, listId, printWrapId) {
    var files = [];
    var dropZone  = document.getElementById(dropId);
    var fileInput = document.getElementById(fileInputId);
    var listEl    = document.getElementById(listId);
    var printWrap = document.getElementById(printWrapId);
    if (!dropZone || !fileInput) return;

    dropZone.addEventListener('dragover',  function(e){ e.preventDefault(); dropZone.style.borderColor='var(--c-accent)'; });
    dropZone.addEventListener('dragleave', function(){ dropZone.style.borderColor=''; });
    dropZone.addEventListener('drop',      function(e){ e.preventDefault(); dropZone.style.borderColor=''; handleFiles(e.dataTransfer.files); });
    fileInput.addEventListener('change',   function(){ handleFiles(this.files); this.value=''; });

    function handleFiles(flist) {
      Array.from(flist).forEach(function(file){
        var reader = new FileReader();
        reader.onload = function(ev){
          files.push({ name:file.name, size:file.size, type:file.type, dataUrl:ev.target.result });
          renderList(); renderPrint();
        };
        reader.readAsDataURL(file);
      });
    }
    function fmtSize(b){ return b<1024?b+'B':b<1048576?(b/1024).toFixed(1)+'KB':(b/1048576).toFixed(1)+'MB'; }
    function renderList(){
      listEl.innerHTML='';
      files.forEach(function(f,idx){
        var div=document.createElement('div');
        div.className='ev-attach-item';
        div.innerHTML='<i class="fas '+(f.type==='application/pdf'?'fa-file-pdf':'fa-file-image')+'" style="color:var(--c-accent);"></i>'+
          '<span class="ev-attach-item-name">'+f.name+'</span>'+
          '<span class="ev-attach-item-size">'+fmtSize(f.size)+'</span>'+
          '<span class="ev-attach-item-del" title="삭제" data-idx="'+idx+'">×</span>';
        listEl.appendChild(div);
      });
      listEl.querySelectorAll('.ev-attach-item-del').forEach(function(btn){
        btn.addEventListener('click',function(){
          files.splice(parseInt(this.dataset.idx),1);
          renderList(); renderPrint();
        });
      });
    }
    function renderPrint(){
      printWrap.innerHTML='';
      files.forEach(function(f){
        var page=document.createElement('div');
        page.className='ev-attach-print-page';
        var lbl=document.createElement('div');
        lbl.style.cssText='font-size:9pt;font-weight:700;margin-bottom:6px;';
        lbl.textContent='첨부: '+f.name;
        page.appendChild(lbl);
        if(f.type==='application/pdf'){
          var iframe=document.createElement('iframe');
          iframe.src=f.dataUrl;
          iframe.style.cssText='width:100%;min-height:700px;border:none;';
          page.appendChild(iframe);
        } else {
          var img=document.createElement('img');
          img.src=f.dataUrl;
          img.style.cssText='max-width:100%;height:auto;display:block;';
          page.appendChild(img);
        }
        printWrap.appendChild(page);
      });
    }
  }
  // 자체시험성적서 / RAW DATA
  makeAttach('ev-drop-raw','ev-file-raw','ev-list-raw','ev-print-raw');
  // 제작사의 확인서
  makeAttach('ev-drop-mfr','ev-file-mfr','ev-list-mfr','ev-print-mfr');
}

function initNoiseAttach() {
  var ntAttachFiles = [];
  var dropZone  = document.getElementById('nt-drop-zone');
  var fileInput = document.getElementById('nt-file-input');
  var listEl    = document.getElementById('nt-attach-list');
  var printWrap = document.getElementById('nt-attach-print-wrap');
  if (!dropZone) return;

  dropZone.addEventListener('dragover', function(e){ e.preventDefault(); dropZone.style.borderColor='var(--c-accent)'; });
  dropZone.addEventListener('dragleave', function(){ dropZone.style.borderColor=''; });
  dropZone.addEventListener('drop', function(e){
    e.preventDefault(); dropZone.style.borderColor='';
    handleNtFiles(e.dataTransfer.files);
  });
  fileInput.addEventListener('change', function(){ handleNtFiles(this.files); this.value=''; });

  function handleNtFiles(files) {
    Array.from(files).forEach(function(file){
      var reader = new FileReader();
      reader.onload = function(ev){
        ntAttachFiles.push({ name: file.name, size: file.size, type: file.type, dataUrl: ev.target.result });
        renderNtList(); renderNtPrint();
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
        '<span class="nt-attach-item-del" title="삭제" data-idx="'+idx+'">×</span>';
      listEl.appendChild(div);
    });
    listEl.querySelectorAll('.nt-attach-item-del').forEach(function(btn){
      btn.addEventListener('click', function(){
        ntAttachFiles.splice(parseInt(this.dataset.idx),1);
        renderNtList(); renderNtPrint();
      });
    });
  }

  function renderNtPrint(){
    printWrap.innerHTML = '';
    ntAttachFiles.forEach(function(f){
      var page = document.createElement('div');
      page.className = 'nt-attach-print-page';
      var label = document.createElement('div');
      label.style.cssText = 'font-size:9pt;font-weight:700;margin-bottom:6px;';
      label.textContent = '첨부: ' + f.name;
      page.appendChild(label);
      if (f.type === 'application/pdf') {
        var iframe = document.createElement('iframe');
        iframe.src = f.dataUrl;
        iframe.style.cssText = 'width:100%;min-height:700px;border:none;';
        page.appendChild(iframe);
      } else {
        var img = document.createElement('img');
        img.src = f.dataUrl;
        img.style.cssText = 'max-width:100%;height:auto;display:block;';
        page.appendChild(img);
      }
      printWrap.appendChild(page);
    });
  }
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

app.get('/', (c) => c.html(HTML))
app.get('*', (c) => c.html(HTML))

export default app

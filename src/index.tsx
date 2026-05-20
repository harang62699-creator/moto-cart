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
  dp_s10:'10. 배출가스 보증', dp_s11:'11. 시험차량', dp_s12:'12. 교정정보',
  dp_s13:'13. 기타',
  dp_1_1_lbl:'1.1. 인증대상 자동차 개발배경 및 특성',
  dp_1_2_lbl:'1.2. 배출가스관련 신기술 또는 주요기술',
  dp_5_1_lbl:'5.1. 배출가스 시험 정보',
  dp_5_2_lbl:'5.2. 주행거리축적',
  dp_5_3_lbl:'5.3. 소음 시험 정보',
  dp_5_4_lbl:'5.4. 증발가스 시험 정보',
  dp_7_1_lbl:'7.1. 배출가스 시험 결과',
  dp_7_2_lbl:'7.2. 배출가스 시험 성적서',
  nt_rpm_unit:'% 회전속도(rpm)',
  obd_ph_dtc_default:'이륜자동차에 결함코드가 확인되면 계기판에 엔진 체크등이 점등됨.',
  // 회원정보 모달
  profile_modal_title:'회원정보',
  profile_tab_info:'기본정보 수정',
  profile_tab_pw:'비밀번호 변경',
  profile_lbl_username:'아이디',
  profile_lbl_company:'회사명',
  profile_lbl_rep:'담당자명',
  profile_lbl_bizno:'사업자번호',
  profile_lbl_phone:'연락처',
  profile_ph_company:'회사명 입력',
  profile_ph_rep:'담당자명 입력',
  profile_ph_bizno:'사업자등록번호',
  profile_ph_phone:'010-0000-0000',
  profile_btn_save:'정보 저장',
  profile_saved_ok:'회원정보가 수정되었습니다.',
  profile_err_required:'회사명, 담당자명, 사업자번호는 필수입니다.',
  // 비밀번호 변경
  pw_change_title:'비밀번호 변경',
  pw_lbl_current:'현재 비밀번호',
  pw_lbl_new:'새 비밀번호',
  pw_lbl_confirm:'새 비밀번호 확인',
  pw_ph_current:'현재 비밀번호를 입력하세요',
  pw_ph_new:'4자 이상',
  pw_ph_confirm:'재입력',
  pw_changed_ok:'비밀번호가 변경되었습니다.',
  // 공통 버튼/메시지
  btn_cancel:'취소',
  btn_change:'변경',
  btn_processing:'처리 중...',
  btn_logout:'로그아웃',
  err_occurred:'오류가 발생했습니다.',
  err_network:'네트워크 오류가 발생했습니다.',
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

app.put('/api/auth/profile', authMiddleware, async (c) => {
  const payload = c.get('user') as any
  const { company_name, representative, business_number, phone } = await c.req.json()
  if (!company_name || !representative || !business_number)
    return c.json({ error: '회사명, 담당자명, 사업자번호는 필수입니다.' }, 400)
  await c.env.DB.prepare(
    'UPDATE users SET company_name=?, representative=?, business_number=?, phone=? WHERE id=?'
  ).bind(company_name, representative, business_number, phone || '', payload.id).run()
  const user = await c.env.DB.prepare('SELECT id, username, company_name, representative, business_number, phone FROM users WHERE id = ?').bind(payload.id).first()
  return c.json({ ok: true, user })
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
.btn-secondary {
  background:rgba(100,130,200,.12);
  color:#6082c8;
  border:1px solid rgba(100,130,200,.28);
}
.btn-secondary:hover:not(:disabled) { background:rgba(100,130,200,.22); }
.btn-sm { padding:7px 14px; font-size:.8rem; border-radius:8px; }
/* 회원정보 모달 탭 */
.profile-tab {
  padding:10px 18px;
  font-size:.85rem;
  font-weight:500;
  background:transparent;
  border:none;
  border-bottom:2px solid transparent;
  color:var(--c-text-muted);
  cursor:pointer;
  transition:color .18s, border-color .18s;
  outline:none;
  margin-bottom:-1px;
}
.profile-tab:hover { color:var(--c-primary); }
.profile-tab.profile-tab-active {
  color:var(--c-primary);
  border-bottom-color:var(--c-primary);
  font-weight:700;
}
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
  display:flex; align-items:center; justify-content:center;
  overflow:hidden; flex-shrink:0;
}
.logo-icon img { width:100%; height:100%; object-fit:cover; border-radius:9px; }
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
#page-dashboard { max-width:1200px; width:100%; padding:36px 24px; margin:0 auto; align-self:center; box-sizing:border-box; }
.dash-header {
  display:flex; align-items:center; justify-content:space-between;
  flex-wrap:wrap; gap:12px; margin-bottom:32px;
}
.dash-title { font-size:1.4rem; font-weight:800; letter-spacing:-.03em; }
.dash-sub { font-size:.85rem; color:var(--c-text2); margin-top:4px; }

/* ── 검색창 ── */
.dash-search-wrap { margin-bottom:20px; }
.dash-search-box {
  position:relative; display:flex; align-items:center;
  background:var(--c-surface); border:1.5px solid var(--c-border);
  border-radius:12px; padding:0 14px; gap:10px;
  transition:border-color .2s, box-shadow .2s;
}
.dash-search-box:focus-within {
  border-color:var(--c-accent);
  box-shadow:0 0 0 3px rgba(79,142,247,.15);
}
.dash-search-icon { color:var(--c-text3); font-size:.9rem; flex-shrink:0; }
.dash-search-input {
  flex:1; border:none; outline:none; background:transparent;
  font-size:.92rem; color:var(--c-text); padding:12px 0;
  font-family:inherit;
}
.dash-search-input::placeholder { color:var(--c-text3); }
.dash-search-clear {
  background:none; border:none; cursor:pointer;
  color:var(--c-text3); padding:4px; border-radius:50%;
  display:flex; align-items:center; justify-content:center;
  transition:background .15s;
}
.dash-search-clear:hover { background:var(--c-border); color:var(--c-text); }
.dash-search-result {
  font-size:.82rem; color:var(--c-text3); margin-top:8px; padding:0 4px;
}

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
#page-application { max-width:1200px; width:100%; padding:36px 24px; margin:0 auto; align-self:center; box-sizing:border-box; }
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
#page-form { max-width:860px; width:100%; padding:36px 24px; margin:0 auto; align-self:center; box-sizing:border-box; }
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
      <div class="logo-icon"><img src="https://www.genspark.ai/api/files/s/NOlEfCY7" alt="logo"></div>
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
            <input id="reg-password2" class="input" type="password" placeholder="\${BL('pw_ph_confirm')}" autocomplete="new-password">
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
    <div id="dash-title" class="dash-title" style="display:none;"></div>
    <div id="dash-subtitle" class="dash-sub" style="display:none;"></div>
    <button id="btn-new-appl" class="btn btn-primary" onclick="showNewAppModal()">
      <i class="fas fa-plus"></i>새 신청서 작성
    </button>
  </div>

  <!-- 검색창 -->
  <div class="dash-search-wrap">
    <div class="dash-search-box">
      <i class="fas fa-search dash-search-icon"></i>
      <input id="dash-search-input" class="dash-search-input" type="text"
        placeholder="신청서 제목, 수입사, 연도로 검색..."
        oninput="filterAppList(this.value)">
      <button class="dash-search-clear" id="dash-search-clear" onclick="clearSearch()" style="display:none;" title="초기화">
        <i class="fas fa-times"></i>
      </button>
    </div>
    <div id="dash-search-result" class="dash-search-result" style="display:none;"></div>
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
        <i class="fas fa-save"></i><span id="save-btn-lbl">저장</span>
      </button>
      <button id="print-btn-top" class="btn btn-ghost" onclick="printWithQR()">
        <i class="fas fa-print"></i><span id="print-btn-top-lbl">인쇄</span>
      </button>
      <button id="btn-toc-print" class="btn btn-ghost" onclick="printDetailPlanToc()" style="display:none;">
        <i class="fas fa-list-ol"></i><span id="toc-print-lbl">목차인쇄</span>
      </button>
    </div>
  </div>

  <div id="form-content"></div>

  <!-- 완료 체크 -->
  <div class="complete-card no-print" id="complete-card" onclick="toggleComplete()">
    <input type="checkbox" id="form-completed-chk" class="complete-checkbox" onclick="event.stopPropagation();updateCompleteCard();">
    <div>
      <div class="complete-label-title" id="complete-label-title-el">이 서류 작성을 완료했습니다</div>
      <div class="complete-label-sub" id="complete-label-sub-el">체크하면 진행률에 반영됩니다</div>
    </div>
    <i class="fas fa-check-circle" style="margin-left:auto;font-size:10pt;color:var(--c-success);opacity:0;transition:opacity .2s;" id="complete-check-icon"></i>
  </div>

  <!-- 하단 액션 바 -->
  <div class="form-action-bar no-print">
    <div class="form-action-bar-left">
      <button class="btn btn-ghost" onclick="goBackToApplication()">
        <i class="fas fa-arrow-left"></i><span id="btn-list-lbl">목록</span>
      </button>
    </div>
    <div class="form-action-bar-right">
      <button class="btn btn-ghost" onclick="printWithQR()">
        <i class="fas fa-print"></i><span id="print-btn-bottom-lbl">인쇄</span>
      </button>
      <button id="save-btn-bottom" class="btn btn-success" onclick="saveForm()">
        <i class="fas fa-save"></i><span id="save-btn-bottom-lbl">저장</span>
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

<!-- ═══════════════════════════════════════════════
     MODAL: 신청서 정보 수정
════════════════════════════════════════════════ -->
<div id="modal-edit-app" class="modal-backdrop hidden no-print">
  <div class="modal" onclick="event.stopPropagation()">
    <div class="modal-header">
      <div style="font-size:10pt;font-weight:800;letter-spacing:-.02em;">
        <i class="fas fa-pen" style="color:var(--c-accent);margin-right:8px;"></i><span id="edit-modal-title-lbl">신청서 정보 수정</span>
      </div>
      <button class="btn btn-ghost btn-icon btn-sm" onclick="closeEditAppModal()"><i class="fas fa-times"></i></button>
    </div>
    <div class="modal-body">
      <input type="hidden" id="edit-app-id">
      <div class="field-wrap">
        <label class="label" id="edit-lbl-title">신청 제목 <span style="color:var(--c-danger);">*</span></label>
        <input id="edit-title" class="input" type="text" placeholder="예) 2025년 Honda CB125R 기본인증">
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div class="field-wrap">
          <label class="label" id="edit-lbl-cert-type">인증 유형 <span style="color:var(--c-danger);">*</span></label>
          <select id="edit-cert-type" class="input" onchange="onEditCertTypeChange()">
            <option value="basic">기본인증 — 신규 수입이륜차</option>
            <option value="change">변경인증 — 인증사항 중요 변경</option>
            <option value="report">변경보고 — 경미한 사항 변경</option>
          </select>
        </div>
        <div class="field-wrap">
          <label class="label" id="edit-lbl-lang">서류 언어</label>
          <select id="edit-lang" class="input">
            <option value="ko">🇰🇷 한국어</option>
            <option value="en">🇺🇸 English</option>
            <option value="ja">🇯🇵 日本語</option>
            <option value="zh">🇨🇳 中文</option>
          </select>
        </div>
      </div>
      <div id="edit-prev-cert-wrap" class="field-wrap" style="display:none;">
        <label class="label" id="edit-lbl-prev-cert">기존 인증번호 <span style="color:var(--c-danger);">*</span></label>
        <input id="edit-prev-cert" class="input" type="text" placeholder="기존 인증번호 입력">
      </div>
      <div style="display:grid;grid-template-columns:2fr 1fr 1fr 2.5fr;gap:12px;">
        <div class="field-wrap">
          <label class="label" id="edit-lbl-importer">수입사</label>
          <input id="edit-importer" class="input" type="text" placeholder="Honda Korea">
        </div>
        <div class="field-wrap">
          <label class="label" id="edit-lbl-cert-year">인증연도</label>
          <input id="edit-cert-year" class="input" type="text" placeholder="2025">
        </div>
        <div class="field-wrap">
          <label class="label" id="edit-lbl-displacement">배기량</label>
          <input id="edit-displacement" class="input" type="text" placeholder="125cc">
        </div>
        <div class="field-wrap">
          <label class="label" id="edit-lbl-family-code">동일차종기호 <span style="font-size:.75rem;color:var(--c-text3);font-weight:400;">(17자리)</span></label>
          <input id="edit-family-code" class="input" type="text" placeholder="예) ABCDE12345FGHIJ67" maxlength="17">
        </div>
      </div>
      <div id="edit-modal-error" class="auth-error"></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="closeEditAppModal()" id="edit-cancel-btn">취소</button>
      <button id="edit-update-btn" class="btn btn-primary" onclick="updateApplication()">
        <i class="fas fa-check"></i><span id="edit-update-btn-lbl">수정 완료</span>
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
      img.src = src; img.title = BL('img_click_to_zoom');
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
        img.src = src; img.title = BL('img_click_to_zoom');
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
    g_doc_tag:'[별지 제2호 서식]',
    g_sec1:'1. 신청 개요', g_sec2:'2. 신청 유형', g_sec3:'3. 상세내역',
    g_th_div:'구분', g_th_apply_date:'신청일', g_th_maker:'제작사',
    g_th_model:'차명<br>(형식)', g_th_fuel_type:'차종<br>(사용연료)',
    g_th_output:'출력(ps/rpm)<br>(배기량 cc)', g_th_std:'적용기준',
    g_th_cert_no:'인증번호', g_th_note:'비고',
    g_th_div2:'구분', g_th_fuel:'연료', g_th_cert_content:'인증서 기재 내용', g_th_applicable:'해당여부',
    g_cat_emission:'배출기준', g_cat_obd:'OBD기준', g_cat_evap:'증발가스', g_cat_warranty:'보증기간',
    g_fuel_gasoline:'휘발유', g_fuel_diesel:'경유',
    g_emit_colon:'배출 :', g_noise_colon:'소음 :',
    sv_applicable:'해당여부',
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
    en_muffler_diagram_title:'1.2 머플러 내부 구조도',
    en_muffler_spec_title:'1.3 소음기 상세제원',
    en_1_3_1:'구조 및 소음저감 원리', en_1_3_2:'흐름도', en_1_3_3:'제작사',
    en_1_3_4:'내외부 재질', en_1_3_5:'치수 도면',
    en_cat_spec_title:'1.4 촉매장치 상세제원',
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
    dash_title:'환경인증 신청 목록',
    stat_total_lbl:'전체 신청서', stat_prog_lbl:'작성중', stat_done_lbl:'완료', stat_draft_lbl:'임시저장',
    btn_new_appl:'새 신청서 작성', btn_first_appl:'첫 신청서 작성하기',
    btn_write:'작성', btn_delete:'삭제', btn_cancel:'취소', btn_edit_appl:'수정', btn_logout:'로그아웃',
    modal_edit_title:'신청서 정보 수정', btn_update_appl:'수정 완료', msg_update_ok:'신청서 정보가 수정되었습니다.', msg_update_fail:'수정에 실패했습니다.',
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
    dp_1_2_lbl:'1.2. 배출가스관련 신기술 또는 주요기술',
    dp_1_3_lbl:'1.3. 개발 목표 (수입차의 경우 외국인증성적 등으로 갈음)',
    dp_1_4_lbl:'1.4. 인증대상자동차 제원',
    dp_2_1_lbl:'2.1. 기밀에 대한 요청',
    dp_3_lbl:'3.1. 인증시험 연료',
    dp_5_1_lbl:'5.1. 배출가스 시험', dp_5_2_lbl:'5.2. 주행거리축적', dp_5_3_lbl:'5.3. 소음시험',
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

    // === emission_noise 추가 섹션 ===
    en_4_3_1_2:'4.3.1.2. 연료탱크 위치', en_tank_pos_ph:'위치 설명',
    en_4_3_1_3:'4.3.1.3. 연료탱크 형상', en_tank_shape_ph:'형상 설명',
    en_4_3_2:'4.3.2. 스로틀바디',
    en_4_3_2_1:'4.3.2.1. 스로틀바디 상세제원', en_throttle_spec_ph:'스로틀바디 상세제원',
    en_4_3_2_2:'4.3.2.2. 스로틀바디 형상 및 치수제원',
    en_4_3_3:'4.3.3. 연료인젝터',
    en_4_3_3_1:'4.3.3.1. 연료인젝터 상세제원', en_injector_spec_ph:'연료인젝터 상세제원',
    en_4_3_3_2:'4.3.3.2. 연료인젝터 형상 및 치수제원',
    en_4_3_4:'4.3.4. 연료펌프',
    en_4_3_4_1:'4.3.4.1. 연료펌프 상세제원', en_pump_spec_ph:'연료펌프 상세제원',
    en_4_3_4_2:'4.3.4.2. 연료펌프 형상 및 치수제원',
    en_4_4_fuel_photo:'4.4. 연료장치 사진', en_fuel_photo_ph:'연료장치 사진 설명',
    en_sec5:'5. 흡배기장치', en_5_1:'5.1. 흡기계통',
    en_5_1_1:'5.1.1. 흡기다기관 구성도', en_intake_diagram_ph:'흡기다기관 구성 설명',
    en_5_1_2:'5.1.2. 흡기메니폴드', en_intake_manifold_ph:'흡기메니폴드 제원 또는 설명',
    en_5_1_3:'5.1.3. 에어필터', en_air_filter_ph:'에어필터 제원 또는 설명',
    en_5_2:'5.2. 배기계통',
    en_5_2_1:'5.2.1. 배기다기관 구성도', en_exhaust_diagram_ph:'배기다기관 구성 설명',
    en_5_2_2:'5.2.2. 배기메니폴드', en_exhaust_manifold_ph:'배기메니폴드 제원 또는 설명',
    en_sec6:'6. 차량외관 및 치수', en_6_1:'6.1. 차량사진',
    en_6_1_1:'6.1.1. 차량 전면', en_veh_front_ph:'차량 전면 설명',
    en_6_1_2:'6.1.2. 차량 후면', en_veh_rear_ph:'차량 후면 설명',
    en_6_1_3:'6.1.3. 차량 측면', en_veh_side_ph:'차량 측면 설명',
    en_6_1_4:'6.1.4. 차량 상면', en_veh_top_ph:'차량 상면 설명',
    en_6_2:'6.2. 외형도',
    en_6_2_1:'6.2.1. 외형 측면', en_ext_side_ph:'외형 측면 설명',
    en_6_2_2:'6.2.2. 외형 상면', en_ext_top_ph:'외형 상면 설명',
    en_6_2_3:'6.2.3. 외형 뒷면', en_ext_rear_ph:'외형 뒷면 설명',
    en_sec7:'7. 기타', en_7_1:'7.1. 그 외 배출가스 및 소음 저감기술',
    en_other_tech_ph:'그 외 배출가스 및 소음 저감기술을 기재하세요',
    obd_yn_y:'유', obd_yn_n:'무',
    obd_max_power_ph:'최대출력', obd_trans_ph:'변속기(단)',
    obd_combustion_ph:'예) 불꽃점화, 4행정', obd_fuel_supply_ph:'예) 연료분사식(EFI)',
    obd_cat_type_ph:'예) 삼원촉매', obd_yn_ph:'유 / 무',
    obd_nv_lbl:'N/V비, rpm/kph', obd_tire_lbl:'타이어',
    obd_tire_f_lbl:'전', obd_tire_r_lbl:'후',
    obd_tire_f_ph:'전 타이어 규격', obd_tire_r_ph:'후 타이어 규격',
    obd_cat_type_lbl:'촉매 전환기의 형식', obd_cat_type_sub:'(산화촉매, 삼원촉매, 가열식 촉매 등)',
    obd_dpf_lbl:'매연 여과장치의 형식', obd_egr_lbl:'배출가스 재 순환 장치의 유무',
    obd_evap_lbl:'증발가스 제어장치', obd_evap_ph:'증발가스 제어장치',
    obd_diag_lbl:'배출가스자기진단장치의 구성 및 기능',
    obd_diag_op_lbl:'배출가스 자기진단장치 작동방법',
    obd_mi_check_lbl:'감시장치의 오작동 확인방법', obd_mi_check_ph:'오작동 확인방법 입력',
    obd_mi_disp_lbl:'오작동 표시 방법',
    obd_monitor_ph:'감시항목 입력', obd_note_ph:'비고',
    obd_photo_title:'OBD TEST 사진 및 스캐너 사진 첨부 : 차량사진, 차대번호 사진, 엔진번호 사진 포함',
    obd_veh_photo_lbl:'차량 사진', obd_veh_photo_desc:'차량 전체 사진 (전면/측면/후면 포함)',
    obd_vin_photo_lbl:'차대번호 사진', obd_vin_photo_desc:'차대번호(VIN) 확인 사진',
    obd_eng_photo_lbl:'엔진번호 사진', obd_eng_photo_desc:'엔진번호 확인 사진',
    obd_scanner_photo_lbl:'OBD 스캐너 사진', obd_scanner_photo_desc:'OBD 스캐너 연결 및 결과 화면 사진 (복수 첨부 가능)',
    obd_attach_title:'첨부문서 (자체시험성적서 / RAW DATA)',
    obd_upload_hint:'클릭하거나 파일을 드래그하여 업로드',
    em_item_th:'항&nbsp;목', em_fuel_econ_th:'연 비<br>(km/ℓ)', em_std_td:'기&nbsp;준&nbsp;치',
    ev_gen_section:'1. &nbsp;일 반 &nbsp;사 항',
    oo_yn_y:'유', oo_yn_n:'무',
    nt_reg_note_ph:'예) 가속주행 소음시험은 ECE 시험방법으로 측정함',
    nt_test_date_ph:'예) 2025. 01. 01.',
    nt_div_th:'구 분', nt_2nd_lbl:'2차시험', nt_3rd_lbl:'3차시험',
    nt_4th_lbl:'4차시험', nt_avg_lbl:'평 균', nt_result_lbl:'결 과',
    nt_inspector_ph:'성명', nt_confirmer_ph:'성명',
    nt_attach_title:'첨부문서 (자체시험성적서 / RAW DATA)',
    nt_ex_pct_lbl:'원동기 최고 출력<br>회전속도의',
    nt_upload_hint:'클릭하거나 파일을 드래그하여 업로드',
    cf_maker_ph:'예) HONDA Motor Co.,Ltd(일본)',
    cf_addr_lbl2:'2. 주&nbsp;&nbsp;&nbsp;소 :', cf_model_lbl2:'3. 모&nbsp;&nbsp;&nbsp;델 :',
    cf_model_ph:'예) CB500F', cf_importer_ph:'예) ㈜○○모터스',
    cf_warranty_lbl2:'5. 보증내용 :',
    cf_warranty_subject_ph:'보증 주체명 (예: ㈜○○모터스)',
    cf_law_text:'은 대기환경보전법 제46조, 48조, 50조, 51조 및 대기환경보전법 시행규칙 제63조 규정에 의한',
    cf_law_period:'보증기간(130km/h이하 2년 또는 20,000km, 130km/h이상 2년 또는 35,000km) 까지 제작차 및',
    cf_law_obligation:'운행차 배출허용기준에 만족할 수 있도록 품질관리, 사후책임 등에 관한 의무사항을 이행하며,',
    cf_law_recall:'수시검사 및 결함검사에서 결함이 확인될 경우 제작 결함 수정(리콜)의 의무를 이행한다.',
    cf_confirm_text:'당사는 상기보증내용에 대해, 의무사항을 이행할 것을 확인합니다.',
    cf_signed_at_ph:'서명 장소', cf_sign_date_ph:'예) 2025. 01. 01.',
    cf_name_ph:'서명자 성명', cf_title_ph:'직책',

    // === emission_noise 내 detail_plan 섹션 헤더 ===
    dp_th_item:'항목', dp_th_sub_item:'세부항목',
    dp_th_structure:'구조/업체/크기/용량 등',
    dp_th_ctrl_tech:'제어기술/제어원리', dp_th_emission_eff:'배출가스 저감효과',
    dp_th_sensor_var:'감지변수', dp_th_fuel_afr:'연료(공연비)',
    dp_th_ign_timing:'점화시기',
    dp_th_canister_purge:'캐니스터 퍼지 / 공회전수 / 배출가스재순환',
    dp_th_note:'비고',
    dp_th_part_no:'부품번호', dp_th_mfr:'제조업체명', dp_th_mfr_country:'제조국',
    dp_th_evap_code:'증발가스Code',
    dp_th_nominal_tank:'공칭탱크<br>용량(L)',
    dp_th_max_evap:'40%연료시 탱크의<br>최대 증발가스 용량',
    dp_th_reservoir:'기화기/연료분사장치의<br>reservoir의 최대용량',
    dp_th_model_name:'적용차명',
    dp_th_category:'구 분', dp_th_basic_model:'기본 차종',
    dp_th_emission_equiv:'배출가스 및 소음<br>동일차종',
    dp_th_evap_equiv:'증발가스 동일차종',
    dp_th_obd_equiv:'배출가스자기진단장치 동일차종',
    dp_th_dur_test:'내구성 시험차량', dp_th_emission_test_v:'배출가스시험차량',
    dp_lbl_intake_manifold:'흡기 매니폴드', dp_lbl_intake_port_size:'흡입포트크기',
    dp_lbl_intake_port_shape:'흡입포트 형상',
    dp_lbl_exhaust_manifold:'배기 매니폴드', dp_lbl_exhaust_port_size:'배기포트크기',
    dp_lbl_exhaust_port_shape:'배기포트 형상',
    dp_lbl_valve_timing:'흡배기폐기시',
    dp_lbl_intake_valve:'흡입<br>밸브', dp_lbl_exhaust_valve:'배기<br>밸브',
    dp_lbl_open:'열기', dp_lbl_close:'닫기',
    dp_lbl_valve_count:'기통별 밸브수',
    dp_lbl_valve_intake:'흡기', dp_lbl_valve_exhaust:'배기',
    dp_lbl_valve_size:'밸브크기',
    dp_lbl_air_intake:'공기 흡입 방식',
    dp_lbl_cat_type_lbl:'종류', dp_lbl_noble_metal:'귀금속 성분',
    dp_lbl_noble_amount:'귀금속량(g)', dp_lbl_volume:'용량(㎤)',
    dp_lbl_noble_ratio:'귀금속물질비(Pt:Pd:Rh)',
    dp_lbl_canister_design:'캐니스터<br>설계 특성',
    dp_lbl_evap_absorp:'증발가스 흡수용량',
    dp_lbl_canister_cnt:'캐니스터 개수 및 연결방법',
    dp_lbl_canister_shape:'캐니스터 형상',
    dp_lbl_canister_structure:'캐니스터 구조',
    dp_lbl_canister_material:'캐니스터 재질',
    dp_lbl_fuel_system:'연료시스템', dp_lbl_filler_seal:'주유관 밀폐구조',
    dp_lbl_emission_ctrl:'배출가스<br>제어장치', dp_lbl_emission_gas:'배출가스',
    dp_lbl_dur_test_select:'내구성 시험차량 선정',

    // === emission_noise detail_plan 5.x 라벨 ===
    dp_5_1_1_lbl:'5.1.1. 시험장소', dp_5_1_2_lbl:'5.1.2. 시험절차',
    dp_5_2_1_lbl:'5.2.1. 내구성시험 주행여부', dp_5_2_2_lbl:'5.2.2. 길들이기 주행여부',
    dp_5_2_3_lbl:'5.2.3. 주행예정 기간', dp_5_2_4_lbl:'5.2.4. 주행장소',
    dp_5_2_5_lbl:'5.2.5. 주행절차',
    dp_5_3_1_lbl:'5.3.1. 시험장소', dp_5_3_2_lbl:'5.3.2. 시험절차',
    dp_5_4_1_lbl:'5.4.1. 시험장소', dp_5_4_2_lbl:'5.4.2. 시험절차',
    dp_lbl_engine:'엔진', dp_lbl_ignition:'점화장치', dp_lbl_chassis:'샤시',
    dp_8_14_1_lbl:'8.14.1. 전동기 및 전동기 제어장치',
    dp_8_14_2_lbl:'8.14.2. 축전지 및 축전지 제어장치',
    // === 회원정보 / 비밀번호 모달 ===
    profile_modal_title:'회원정보', profile_tab_info:'기본정보 수정', profile_tab_pw:'비밀번호 변경',
    profile_lbl_username:'아이디', profile_lbl_company:'회사명', profile_lbl_rep:'담당자명',
    profile_lbl_bizno:'사업자번호', profile_lbl_phone:'연락처',
    profile_ph_company:'회사명 입력', profile_ph_rep:'담당자명 입력',
    profile_ph_bizno:'사업자등록번호', profile_ph_phone:'010-0000-0000',
    profile_btn_save:'정보 저장', profile_saved_ok:'회원정보가 수정되었습니다.',
    profile_err_required:'회사명, 담당자명, 사업자번호는 필수입니다.',
    pw_change_title:'비밀번호 변경',
    pw_current_lbl:'현재 비밀번호', pw_new_lbl:'새 비밀번호',
    pw_confirm_lbl:'새 비밀번호 확인',
    pw_current_ph:'현재 비밀번호를 입력하세요', pw_new_ph:'4자 이상',
    pw_confirm_ph:'재입력',
    pw_cancel_btn:'취소', pw_change_btn:'변경',
    btn_processing:'처리 중...',
    btn_change:'변경',
    pw_err_required:'모든 항목을 입력하세요.', pw_err_too_short:'비밀번호는 4자 이상이어야 합니다.',
    pw_err_mismatch:'새 비밀번호가 일치하지 않습니다.', pw_changed_ok:'비밀번호가 변경되었습니다.',
    err_occurred:'오류가 발생했습니다.', err_network:'네트워크 오류가 발생했습니다.',
    btn_create_app:'신청서 생성', btn_creating:'생성 중...', msg_create_fail:'생성에 실패했습니다.',
    msg_app_created:'신청서가 생성되었습니다.', err_cert_no_required:'기존 인증번호를 입력하세요.',
    err_title_required_ko:'신청 제목을 입력하세요.',
    msg_delete_confirm:'정말 삭제하시겠습니까?', msg_deleted:'삭제되었습니다.', msg_delete_fail:'삭제에 실패했습니다.',
    save_error:'저장 중 오류가 발생했습니다.',
    btn_processing:'처리 중...',
    btn_change:'변경',
    qr_auth_code_lbl:'진위여부코드',
    qr_verify_title:'진위여부 확인',
    qr_doc_name:'서류명',
    qr_application:'신청서',
    qr_issued_at:'발급일시',
    qr_issuer:'발급기관',
    obd_lbl_tire:'타이어',
    obd_ph_trans_step:'변속기(단)',
    obd_sec1_label:'OBD 종합정보에 관한 서류',
    obd_1_1_desc:'1.1. 센서·액츄에이터 등의 부품 목록 및 기능 설명',
    obd_1_2_desc:'1.2. 오작동표시등에 관한 설명자료',
    obd_1_3_desc:'1.3. 무단변경 및 배기가스제어컴퓨터 수정 금지 문구',
    obd_1_4_desc:'1.4. 감시장치의 기술적인 설명자료',
    obd_1_5_desc:'1.5. 기타 추가정보',
    obd_1_6_desc:'1.6. 자체시험결과 및 기술적 설명자료',
    obd_sec2_label:'동일차종 설명에 관한 서류',
    obd_sec3_label:'시험차량 선정에 관한 서류',
    obd_sec2_title:'2. 동일차종 설명에 관한 서류',
    obd_sec3_title:'3. 시험차량 선정에 관한 서류',
    obd_2_1_title:'2.1. 자동차 제원(자기진단동일차종 중 대표차종)',
    obd_gen_spec_title:'1. 일반 제원',
    obd_eng_spec_title:'2. 엔진 제원',
    obd_em_ctrl_spec_title:'3. 배출가스 제어장치 및 OBD 제원',
    obd_1_6_1_title:'1.6.1. 시험결과',
    obd_1_6_2_title:'1.6.2. OBD 감시부품의 테스트 및 진단',
    obd_2_2_title:'2.2. 자기진단동일차종',
    obd_2_3_title:'2.3. 배출가스자기진단장치 동일차종 설명',
    obd_3_1_title:'3.1. 배출가스자기진단장치 시험차량 선정근거',
    obd_lbl_cat_monitor:'촉매 감시장치',
    obd_lbl_dpf_monitor:'매연여과장치 감시장치',
    obd_lbl_eis_monitor:'전자분사시스템 감시장치',
    obd_lbl_obd_parts:'배출가스자기진단장치에 의해 감시되는 부품들',
    obd_lbl_mil_criteria:'오작동표시등 점등을 위한 기준',
    obd_lbl_dtc_list:'모든 OBD 출력코드 목록과 사용된 양식',
    obd_th_test_req:'시험 요구 사항 작동 기준(Ⅰ)형',
    obd_th_compliance:'적합 여부',
    obd_th_part_check:'부품 점검',
    obd_th_mi_time:'MI 활성화 시기',
    obd_th_mem_err:'메모리에 저장된 오류코드 수정',
    obd_th_obd_same:'배출가스자기진단장치 동일차종',
    obd_th_obd_test_car:'배출가스자기진단장치 시험차량',
    obd_lbl_modelname:'모델명',
    obd_lbl_vin:'차대번호(엔진번호)',
    obd_lbl_trans_type:'변속기 형태',
    obd_lbl_trans_proc:'변속절차',
    obd_lbl_equiv_inertia:'등가관성중량(kg)',
    obd_lbl_final_drive:'종감속기',
    obd_lbl_same_carname:'차명(동일차명)',
    obd_lbl_engine:'엔진',
    obd_lbl_combustion:'연소과정 (불꽃점화, 압축착화, 2행정, 4행정 등)',
    obd_lbl_fuel_method:'연료공급 방법 (기화기식, 연료분사식 등)',
    obd_lbl_cat_type:'촉매전환기의 형식 (산화촉매, 삼원촉매 등)',
    obd_lbl_dpf_type:'매연여과장치의 형식',
    obd_lbl_2ndair_yn:'2차공기 분사의 유무',
    obd_lbl_egr_yn:'배출가스 재순환장치의 유무',
    obd_lbl_obd_method:'배출가스 자기진단장치의 작동방법',
    obd_lbl_monitor_check:'감시장치의 오작동 확인 방법',
    obd_lbl_mal_display:'오작동 표시방법',
    obd_ph_name_type:'차명(형식)',
    obd_ph_total_weight:'총중량(공차중량)',
    obd_ph_na_or_type:'해당없음 또는 형식 입력',
    obd_ph_method:'작동방법 입력',
    obd_ph_check_method:'오작동 확인 방법 입력',
    obd_ph_display_method:'오작동 표시방법 입력',
    obd_ph_vin:'차대번호(엔진번호)',
    obd_ph_trans_type:'변속기 형태',
    obd_ph_trans_proc:'변속절차',
    obd_ph_equiv_inertia:'등가관성중량(kg)',
    obd_ph_final_drive:'종감속기',
    obd_ph_same_carname:'동일차명',
    obd_lbl_prep_cycle:'오작동 확인시험을 위한 준비싸이클 형식과 회수',
    obd_lbl_test_cycle:'감시되는 부품에 대한 확인시험 시험싸이클 형식 설명',
    obd_lbl_2nd_monitor:'감시되는 구성부품들에 대한 2차 감시변수들의 목록',
    obd_lbl_ctrl_indicator:'제어, 자동표시기, 인디케이터 위치 및 식별 기호',
    obd_div_mil_location:'오작동 표시등의 형태 및 위치 : 형태 및 위치를 알 수 있는 도면 또는 사진',
    obd_div_left_switch:'왼쪽 핸들 스위치의 제어 및 기호 도면',
    obd_div_right_switch:'오른쪽 핸들 스위치의 제어 및 기호 도면',
    obd_div_keybox:'키박스 도면',
    obd_txt_malfunction_test:'오작동 재현을 위한 부품 또는 오작동 모터사이클을 위한 전자 장비를 장착한 차량을 시험할 때, 오작동 판단 기준 이하에서 오작동 경고등이 점등되며 배출가스 자기진단장치는 적합한 것으로 판정됨',
    obd_txt_electrical_continuity:'배출가스 관련 부품 또는 배출가스와 관련되고 엔진 제어장치에 연결된 파워트레인 관련 부품의 전기적인 연속성을 감시하여야 함',
    obd_ph_dtc_default:'이륜자동차에 결함코드가 확인되면 계기판에 엔진 체크등이 점등됨.',
    obd_ph_no_modify:'무단변경 및 배기가스제어컴퓨터의 수정을 금지하는 문구 입력',
    nt_th_gear:'사용<br>변속<br>기어',
    nt_th_entry_speed:'진입<br>지정<br>차속<br>(km/hr)',
    nt_th_test_speed:'시험차속<br>(km/hr.)',
    nt_th_rpm:'엔진회전수<br>(rpm)',
    nt_th_accel_pos:'가속<br>시작<br>위치<br>(m)',
    nt_th_bg_noise:'암소음<br>[dB<br>(A)]',
    nt_th_meas_noise:'측정소음<br>[dB(A)]',
    nt_th_correction:'보정<br>치<br>[dB<br>(A)]',
    nt_th_std_val:'기준치<br>[dB<br>(A)]',
    nt_th_accel_init:'가속<br>초기',
    nt_th_accel_end:'가속<br>종료',
    nt_th_left:'좌측',
    nt_th_right:'우측',
    nt_lbl_1st:'1차시험',
    nt_lbl_wot_noise:'가속주행소음<br>(L_WOTrep, dB(A))',
    nt_lbl_crs_noise:'정속주행소음<br>(L_CRSrep, dB(A))',
    em_val_dur_run:'내구주행시험',
    em_sec5_cvs:'5. CVS 운전시험상태',
    em_sec6_result:'6. 시험결과',
    ev_sec2:'2. 측정실 및 측정장비',
    ev_upload_hint:'클릭하거나 파일을 드래그하여 업로드',
    oo_th_fuel_econ:'연비<br>(km/ℓ)',
    oo_th_exhaust_gas:'배기관<br>가스',
    oo_th_det_factor:'열화계수<br>(DF)',
    oo_sec3_emission:'3. 배출가스 제어',
    g_th_compliance_pct:'기준만족도(%)',
    g_obd_std_2006_gas:'휘발유 2006년 OBD 기준',
    g_obd_std_2013_1st:'휘발유 2013년 OBD IUPR 1st 기준',
    g_obd_std_2013_2nd:'휘발유 2013년 OBD IUPR 2nd(2016년 1월) 기준',
    g_obd_std_euro6:'휘발유 EURO6 OBD IUPR 2nd 기준',
    g_obd_std_euro5_2w:'휘발유 EURO5 OBD 이륜자동차 기준(OBD Stage 2)',
    g_obd_std_2006_diesel:'경유 2006년 OBD 기준',
    g_obd_std_2012_diesel:'경유 2012년 OBD IUPR 1st 기준',
    g_obd_std_2014_diesel:'경유 2014년 9월 OBD IUPR 2nd 기준',
    g_ph_obd_mal:'OBD2 오작동 판정기준 관련 내용',
    g_th_monitor_item:'감시항목',
    g_th_test_yn:'시험여부',
    g_th_test_vehicle:'시험차명',
    g_th_applicable2:'적용여부',
    g_th_meas_result:'측정결과',
    g_lbl_test_facility:'시험시설',
    g_ph_facility_detail:'자체시험을 실시한 시설에 대한 시설확인 내역',
    g_lbl_vehicle_sel:'시험차 선정근거',
    g_vehicle_sel_title:'시험자동차 선정근거',
    g_vehicle_sel_em:'- 배출가스 시험차량 : 「제작자동차 인증 및 검사방법과 절차 등에 관한 규정」 제11조에 따라 시험차량 선정',
    g_vehicle_sel_noise:'- 소음 시험차량 : 「제작자동차 인증 및 검사방법과 절차 등에 관한 규정」 제12조에 따라 시험차량 선정',
    g_vehicle_sel_obd:'- OBD 시험차량 : 「제작자동차 인증 및 검사방법과 절차 등에 관한 규정」 제23조에 따라 시험차량 선정',
    g_ph_additional:'추가 사항 기재',
    g_ph_em_mode:'배출가스 시험모드, 시험 회수, 자체시험 성적 등',
    g_lbl_evap_test:'증발가스 시험',
    g_ph_evap_submit:'증발가스 자체시험 성적서 제출 내역 등',
    g_lbl_warranty_det:'보증기간 및 열화계수',
    g_ph_warranty_detail:'보증기간 및 열화계수 적용 내역',
    g_lbl_warranty_km:'보증기간(km) :',
    g_th_det_factor:'적용 열화계수',
    g_em_co:'일산화탄소(CO)',
    g_em_exhaust_hc:'배기관 탄화수소',
    g_em_nox:'질소산화물',
    g_em_evap_hc:'증발 탄화수소',
    g_lbl_endurance:'내구 시험',
    g_ph_endurance_note:'내구 시험 내용을 기재하세요',
    g_lbl_ki:'주기적재생지수<br>(ki) 시험',
    g_ph_ki_note:'주기적재생지수(ki) 시험 내용',
    g_lbl_noise_test:'소음시험',
    g_noise_submit:'소음시험 성적서 제출 내역',
    g_ph_noise_submit:'소음시험 성적서 제출 내역을 기재하세요',
    g_noise_method:'소음 시험방법',
    g_noise_accel_lbl:'- 가속주행소음 :',
    g_noise_exhaust_lbl:'- 배기소음 :',
    g_noise_horn_lbl:'- 경적소음 :',
    g_lbl_same_type:'동일차종 구성',
    g_th_div_lbl:'구분',
    g_lbl_o2_sensor:'산소센서',
    g_lbl_egr:'배기가스 재순환계통',
    g_lbl_vvt:'가변밸브타이밍계통',
    g_lbl_fuel_system:'연료계통',
    g_lbl_misfire:'실화',
    g_lbl_2nd_air:'2차 공기계통',
    en_ph_inner_diag:'내부 구조 설명',
    en_ph_flow_desc:'흐름도 설명',
    en_ph_maker_name:'제작사명',
    en_ph_inner_mat:'내부 재질/사양',
    en_ph_outer_mat:'외부 재질/사양',
    en_ph_dim_desc:'치수 도면 설명',
    en_ph_cat_principle:'촉매 원리 또는 효과를 기재하세요',
    en_ph_attach_desc:'부착위치 설명',
    en_1_5_lbl:'1.5. 센서 상세제원',
    en_1_5_1_lbl:'1.5.1. 센서 제작사',
    en_1_5_2_lbl:'1.5.2. 센서 재질',
    en_1_5_3_lbl:'1.5.3. 센서 치수 도면',
    en_ph_sensor_mat:'센서 재질',
    en_1_6_lbl:'1.6. 머플러 도면',
    en_1_7_lbl:'1.7. 머플러 사진',
    en_ph_muffler_draw:'머플러 도면 설명',
    en_ph_muffler_photo:'머플러 사진 설명',
    en_sec2_valve:'2. 밸브 장치(Valve Train)',
    en_2_1_valve:'2.1. 밸브 기구의 관성력',
    en_ph_valve_inertia:'밸브 기구의 관성력에 관한 내용을 기재하세요',
    en_2_2_surging:'2.2. 밸브 스프링의 Surging 현상 대응기술',
    en_ph_surging:'Surging 현상 대응기술을 기재하세요',
    en_2_3_cam:'2.3. 캠프로파일 및 제원',
    en_2_3_1_valve:'2.3.1. 밸브 제원',
    en_ph_valve_spec:'밸브 제원을 기재하세요',
    en_2_3_2_cam:'2.3.2. Cam 제원',
    en_ph_cam_spec:'Cam 제원을 기재하세요',
    en_2_3_3_cam_dim:'2.3.3. Cam 치수 도면',
    en_ph_cam_dim:'Cam 치수 도면 설명',
    en_2_4_valve_mat:'2.4. Valve 기구의 재질 등에 관한 내용',
    en_ph_valve_mat:'Valve 기구의 재질 등에 관한 내용을 기재하세요',
    en_2_5_valve_clearance:'2.5. 밸브 간극',
    en_ph_valve_clearance:'밸브 간극 수치 또는 설명',
    en_sec3_ignition:'3. 점화장치',
    en_3_1_ign_diag:'3.1. 점화장치 구성도',
    en_ph_ign_diag:'점화장치 구성 설명',
    en_3_2_ign_ctrl:'3.2. 점화장치 제어특성',
    en_ph_ign_ctrl:'점화장치 제어특성을 기재하세요',
    en_3_3_ign_spec:'3.3. 점화장치 상세제원',
    en_3_3_1_gen:'3.3.1. 제너레이터',
    en_3_3_1_1_gen_spec:'3.3.1.1. 제너레이터 상세제원',
    en_ph_gen_spec:'제너레이터 상세제원',
    en_3_3_1_2_gen_dim:'3.3.1.2. 제너레이터 형상 및 치수제원',
    en_ph_shape_dim:'형상 및 치수 설명',
    en_3_3_2_1_cdi_spec:'3.3.2.1. CDI UNIT 상세제원',
    en_ph_cdi_spec:'CDI UNIT 상세제원',
    en_3_3_2_2_cdi_dim:'3.3.2.2. CDI UNIT 형상 및 치수제원',
    en_3_3_3_coil:'3.3.3. 점화코일',
    en_3_3_3_1_coil_spec:'3.3.3.1. 점화코일 상세제원',
    en_ph_coil_spec:'점화코일 상세제원',
    en_3_3_3_2_coil_dim:'3.3.3.2. 점화코일 형상 및 치수제원',
    en_3_3_4_plug:'3.3.4. 점화플러그',
    en_3_3_4_1_plug_spec:'3.3.4.1. 점화플러그 상세제원',
    en_ph_plug_spec:'점화플러그 상세제원',
    en_3_3_4_2_plug_dim:'3.3.4.2. 점화플러그 형상 및 치수제원',
    en_3_3_5_ecu:'3.3.5. ECU 상세제원',
    en_3_3_5_1_ecu_spec:'3.3.5.1. ECU 상세제원',
    en_ph_ecu_spec:'ECU 상세제원',
    en_3_3_5_2_ecu_dim:'3.3.5.2. ECU 형상 및 치수제원',
    en_3_4_ign_photo:'3.4. 점화장치 사진',
    en_ph_ign_photo:'점화장치 사진 설명',
    en_sec4_fuel:'4. 연료장치',
    en_4_1_fuel_sys:'4.1. 연료장치 구성 및 제어방식',
    en_ph_fuel_sys:'연료장치 구성 및 제어방식을 기재하세요',
    en_4_2_fuel_drawing:'4.2. 연료장치 도면 및 치수',
    en_ph_drawing_dim:'도면 및 치수 설명',
    en_4_3_fuel_spec:'4.3. 연료장치 상세제원',
    en_4_3_1_tank:'4.3.1. 연료탱크',
    en_4_3_1_1_tank_spec:'4.3.1.1. 연료탱크 상세제원',
    en_ph_tank_spec:'연료탱크 상세제원',
    obd_wps_lbl:'엔진 온도 센서(WPS)',
    obd_o2_lbl:'산소 센서(O₂)',
    obd_injector_lbl2:'연료분사장치(인젝터)',
    obd_o2heater_lbl:'O₂ 센서 히터',
    obd_wire_throttle:'와이어 액츄에이터에 의한 스로틀',
    obd_fanrelay_lbl:'라디에이터 팬 릴레이',
    obd_pumprelay_lbl:'연료 펌프 릴레이',
    obd_ph_content:'내용 입력',
    obd_ph_carname:'차명',
    obd_ph_type:'형식',
    obd_ph_carkind:'차종',
    obd_ph_fuel:'사용연료',
    obd_ph_weight:'총중량(공차중량, kg)',
    obd_ph_engtype:'엔진형식',
    obd_ph_maxpower:'최고출력',
    obd_ph_cc:'배기량(cc)',
    obd_ph_combtype:'연소형식',
    obd_ph_cycle:'연소사이클',
    obd_ph_supplytype:'연료 공급형태',
    obd_ph_cat_info:'촉매전환기 형식 및 제작사',
    obd_ph_ecu_info:'전자제어장치 형식 및 제작사',
    obd_ph_o2s_info:'산소센서 형식 및 제작사',
    obd_ph_purge_info:'퍼지 제어밸브 형식 및 제작사',
    obd_val_pass:'적합',
    obd_val_fail:'부적합',
    obd_th_part_harness:'부품/하네스',
    obd_th_switch:'스위치',
    obd_th_start:'시동',
    obd_th_spec:'규격',
    obd_th_mil:'오작동표시등 점등',
    obd_th_carname:'차명',
    obd_th_type:'형식',
    obd_th_carkind:'차종',
    obd_th_weight:'총중량(공차중량, kg)',
    obd_th_cc:'배기량(cc)',
    obd_th_combtype:'연소형식',
    obd_th_cycle:'연소사이클',
    obd_th_supplytype:'연료 공급형태',
    obd_th_cat:'촉매전환기 형식 (제작사)',
    obd_th_2nd_air:'2차 공기 분사',
    obd_th_egr:'배출가스 재순환 장치',
    obd_th_ecu:'전자제어장치 형식 (제작사)',
    obd_th_o2s:'산소센서 형식 (제작사)',
    obd_th_purge:'퍼지 제어밸브 형식 (제작사)',
    obd_th_name_type:'차명(형식)',
    obd_th_engtype:'엔진형식',
    obd_th_maxpower:'최대출력',
    obd_th_trans_step:'변속기(단)',
    obd_ph_part_check:'부품 점검 내용',
    obd_ph_mi_time:'MI 활성화 시기',
    obd_ph_err_fix:'오류코드 수정',
    obd_ph_part_harness:'부품/하네스',
    obd_ph_switch:'스위치',
    obd_ph_start:'시동',
    obd_ph_spec:'규격',
    em_ph_engtype:'엔진형식 또는 기술 내용',
    g_2_1_label:'2.1. EURO–5 기준 적용 휘발유 이륜자동차 인증신청, 대표차종 :',
    g_2_2_obd:'2.2. OBD 대표 차종 :',
    g_evap_rep_lbl:'증발가스 대표 차종 :',
    g_em1_txt:'* 13년 휘발유 기준2의 나',
    g_em2_txt:'* 13년 휘발유 기준1의 나',
    g_em3_txt:'* 16년 휘발유 기준',
    g_em4_txt:'* 20년 1월 이륜자동차(130km/h 이하) 기준',
    g_em5_txt:'* 14년 9월 경유 소형승용 기준',
    g_obd1_txt:'* OBD2 휘발유 기준 적용 대표(IUPR 1st 기준)',
    g_obd2_txt:'* OBD2 가솔린 기준 적용 동일(IUPR 1st 기준), 대표 차종:',
    g_obd3_txt:'* OBD2 휘발유 EURO6 기준 적용 대표(IUPR 2nd 기준)',
    g_obd4_txt:'* OBD2 가솔린 EURO6 기준 적용 동일(IUPR 2nd 기준), 대표 차종:',
    g_obd5_txt:'* OBD2 휘발유 EURO5 이륜자동차 기준 적용 대표(OBD Stage 2)',
    g_obd6_txt:'* OBD2 경유 (다)기준 적용 대표 (IUPR 2nd 기준)',
    g_obd7_txt:'* OBD2 경유(다) 기준 적용 동일(IUPR 2nd 기준), 대표 차종:',
    g_evap1_txt:'* 증발가스 대표',
    g_evap2_txt:'* 증발가스 동일, 대표 차종:',
    g_war1_txt:'* 보증기간 : 10년 / 19만2천km',
    g_war2_txt:'* 보증기간 : 10년 / 24만km',
    g_war3_txt:'* 보증기간 : 15년 / 24만km',
    g_war4_txt:'* 보증기간 : 02년 / 3.5만km',
    g_war5_txt:'* 보증기간 : 02년 / 2만km',
    g_war6_txt:'* 보증기간 : 10년 / 16만km',
    g_3_1_lbl:'3.1. 적용기술',
    g_3_2_1_lbl:'3.2.1. 배출',
    g_3_2_2_lbl:'3.2.2. 소음',
    g_3_3_lbl:'3.3. 상세 기술내용',
    g_3_4_lbl:'3.4. 시험 시설',
    g_3_5_lbl:'3.5. 배출가스 시험',
    g_3_6_lbl:'3.6. 증발가스 시험',
    g_3_7_lbl:'3.7. 보증 및 악화계수',
    g_3_8_lbl:'3.8. 내구성 시험',
    g_3_9_lbl:'3.9. KI 시험',
    g_3_10_lbl:'3.10. 소음시험',
    g_3_11_lbl:'3.11. 동일차종',
    g_th_hc:'탄화수소',
    g_th_allow_std:'허용기준',
    g_th_test_result:'시험결과',
    g_th_accel_db:'가속주행<br>dB(A)',
    g_th_exhaust_db:'배기<br>dB(A)',
    g_th_horn_db:'경적<br>dB(A)',
    g_th_co_gkm:'CO<br>(g/km)',
    g_th_hcnox_gkm:'HC+NOx<br>(g/km)',
    g_th_pm_gkm:'PM<br>(g/km)',
    g_th_exhaust_hc:'배기 HC<br>(g/km)',
    g_th_evap_hc:'증발 HC<br>(g/test)',
    g_th_obd_std:'OBD 기준명',
    g_th_monitor_dev:'시험대상 감시장치',
    g_th_wmtc:'WMTC 모드<br>CO(g/km)',
    g_th_mil_on:'표시등<br>점등여부',
    g_th_judge_std:'판단기준<br>CO(g/km)',
    g_th_monitor_judge:'감시장치<br>적부판정',
    g_th_item:'항 목',
    g_th_content:'내 용',
    g_th_result_judge:'결과 판정',
    g_th_malfunction:'오작동 재현 조건',
    g_th_device_name:'장치 명',
    g_lbl_catalyst:'촉매, DPF 등 후처리장치',
    g_lbl_evap:'증발가스',
    g_lbl_blowby:'블로바이가스',
    g_lbl_obd2:'배출가스자기진단장치<br>(OBD2)',
    g_lbl_catalyst_br:'촉매, DPF 등<br>후처리장치',
    g_lbl_catalyst2:'촉매',
    g_lbl_o2:'O₂센서',
    g_ph_tech:'적용된 배출가스·소음 저감 기술을 기재하세요',
    g_ph_em_result:'배출가스 자체시험 결과',
    g_ph_noise_result:'소음 자체시험 결과',
    g_ph_catalyst:'후처리장치 상세 내용',
    g_ph_evap_detail:'증발가스 대표/동일 여부 및 관련 내용',
    g_ph_blowby:'블로바이가스 제어장치 내용',
    g_ph_obd_rep:'OBD2 대표/동일 여부 및 관련 내용',
    g_ph_facility:'시험시설 상세',
    g_ph_em_test:'배출가스 시험 내용',
    g_ph_evap_test:'증발가스 시험 내용',
    g_ph_warranty:'보증 및 악화계수 내용',
    g_ph_endurance:'내구성 시험 내용',
    g_ph_ki:'KI 시험 내용',
    g_ph_noise_test:'소음시험 내용',
    g_ph_same_type:'동일차종 구성 내용을 기재하세요',
    g_ph_applicable:'해당/미해당',
    g_ph_misfire:'실화',
    g_ph_degradation:'열화',
    g_ph_yn:'유/무',
    g_ph_pass_fail:'적합/부적합',
    g_ph_img:'이미지 드래그 또는 클릭',
    en_doc_tag:'[별지 제5호 서식]',
    en_main_title_txt:'배출가스 소음 저감장치 자료',
    en_sec1:'1. 소음기(머플러)',
    en_1_1_lbl:'1.1 머플러 구성 내역',
    en_1_2_lbl:'1.2 머플러 내부 구조도',
    en_1_3_lbl:'1.3 소음기 상세제원',
    en_1_4_lbl:'1.4 촉매장치 상세제원',
    en_sec2:'2. 공기청정기(에어크리너)',
    en_2_1_lbl:'2.1 공기청정기 상세제원',
    en_1_3_1_lbl:'구조 및 소음저감 원리',
    en_1_3_2_lbl:'흐름도',
    en_1_3_3_lbl:'제작사',
    en_inside_lbl:'내부 :',
    en_outside_lbl:'외부 :',
    en_dim_draw_lbl:'치수 도면',
    en_principle_lbl:'원리 또는 효과',
    en_attach_pos_lbl:'부착 위치',
    en_cat_maker_lbl:'촉매 제작사',
    en_cat_material_lbl:'촉매 재질',
    en_cat_perf_lbl:'촉매 성능 및 치수',
    en_inside_mat_lbl:'내부 재질',
    en_outside_mat_lbl:'외부 재질',
    en_ph_muffler_comp:'머플러 구성 내역을 기재하세요',
    en_ph_muffler_diag:'머플러 내부 구조도를 기재하세요',
    en_ph_noise_principle:'소음저감 원리를 기재하세요',
    en_ph_flow:'흐름도를 기재하세요',
    en_ph_maker:'제작사를 기재하세요',
    en_ph_inside:'내부 재질을 기재하세요',
    en_ph_outside:'외부 재질을 기재하세요',
    en_ph_dim:'치수 도면을 기재하세요',
    en_ph_cat_maker:'촉매 제작사를 기재하세요',
    en_ph_cat_mat:'촉매 재질을 기재하세요',
    en_ph_cat_perf:'촉매 성능 및 치수를 기재하세요',
    en_ph_principle:'원리 또는 효과를 기재하세요',
    en_ph_pos:'부착 위치를 기재하세요',
    en_ph_aircleaner:'공기청정기 상세제원을 기재하세요',
    obd_doc_tag:'[별지 제9호 서식]',
    obd_main_title_txt:'배출가스자기진단장치(OBD) 구성에 관한 서류',
    obd_sec1:'1. 배출가스자기진단장치(OBD) 종합정보에 관한 서류',
    obd_sec2:'2. 배출가스자기진단장치(OBD) 기능에 관한 서류',
    obd_th_parts:'자동차 배출가스 관련 부품',
    obd_th_func:'기능적인 작동 특성',
    obd_lbl_sensor:'센서',
    obd_lbl_actuator:'액추에이터',
    obd_cps_lbl:'크랭크 포지션 센서(CPS)',
    obd_tmap_lbl:'온도 공기압 센서(T-MAP)',
    obd_wts_lbl:'냉각수 온도 센서(WTS)',
    obd_o2s_lbl:'산소 센서(HO2S)',
    obd_tps_lbl:'스로틀 포지션 센서(TPS)',
    obd_injector_lbl:'연료 인젝터',
    obd_pump_lbl:'연료 펌프',
    obd_idle_lbl:'공회전 속도 제어',
    obd_coil_lbl:'점화 코일',
    obd_cat_lbl:'촉매 전환 장치',
    obd_egr_lbl:'EGR 시스템',
    obd_evap_sys_lbl:'증발가스 제어 시스템',
    obd_air2_lbl:'이차 공기 분사 시스템',
    obd_fuel_sys_lbl:'연료 시스템',
    obd_trans_lbl:'변속기',
    obd_ph_func:'기능적인 작동 특성을 기재하세요',
    obd_2_1_lbl:'2.1. 고장코드(DTC) 읽기 기능',
    obd_2_2_lbl:'2.2. 준비완료 모니터(Readiness) 상태',
    obd_2_3_lbl:'2.3. 동결 프레임(Freeze Frame) 데이터 지원 여부',
    obd_2_4_lbl:'2.4. 고장코드 삭제 기능',
    obd_2_5_lbl:'2.5. 진단 장비 통신 프로토콜',
    obd_th_item2:'항목',
    obd_th_content2:'내용',
    obd_th_support:'지원 여부',
    obd_val_support:'지원',
    obd_val_nosupport:'미지원',
    obd_ph_yn:'예/아니오',
    obd_ph_protocol:'통신 프로토콜을 기재하세요',
    em_doc_tag:'[별지 제18의2호 서식]',
    em_sec1:'1. 일반 사항',
    em_sec2:'2. 시험자동차 제원',
    em_sec3:'3. 시험차 엔진제원',
    em_sec4:'4. 시험장비',
    em_th_test_div:'시험 구분',
    em_val_dur:'내구시험',
    em_val_emis:'배출가스 시험',
    em_val_insp:'정기검사',
    em_val_etc:'기타',
    em_lbl_cvs:'CVS 장치',
    em_lbl_analyzer:'분석기',
    em_lbl_chassis:'섀시 다이나모미터',
    em_lbl_eng_type:'엔진 형식',
    em_lbl_total_cc:'총배기량(cc)',
    em_lbl_comp_ratio:'압축비',
    em_lbl_max_power:'최고출력(ps/rpm)',
    em_lbl_fuel_supply:'연료공급방식',
    em_lbl_cooling:'냉각방식',
    em_lbl_ignition:'점화방식',
    em_lbl_valves:'밸브 수',
    em_lbl_cc_per_cyl:'배기량(cc/기통)',
    em_lbl_cylinders:'기통수',
    em_lbl_maker_model:'제조사 및 모델명',
    em_lbl_range:'측정범위',
    em_lbl_maker2:'제조사',
    em_lbl_model2:'모델명',
    em_lbl_max_abs:'최대 흡수력(kW)',
    em_lbl_inertia:'관성중량(kg)',
    ev_doc_tag:'[별지 제23호 서식]',
    ev_attach_title:'첨부문서 (자체시험성적서 / RAW DATA)',
    ev_attach_note:'이미지(JPG, PNG) 또는 PDF 파일을 업로드하세요. 첨부파일은 인쇄 시 출력되지 않습니다.',
    oo_doc_tag:'[별지 제26호서식]',
    oo_th_trans_type:'변속기 종류',
    oo_ph_type_maker:'형식 / 제작사',
    nt_doc_tag:'[별지 제27호 내지 제27호의2호 서식]',
    nt_test_date_lbl:'2. 시험일 :',
    nt_na:'해당없음',
    nt_accel_noise_meas:'가속주행소음<br>측정',
    cf_maker_lbl:'1. 제작사 :',
    cf_addr_lbl:'2. 주   소 :',
    cf_model_lbl:'3. 모   델 :',
    cf_importer_lbl:'4. 수입자 :',
    // gasoline/emission_noise/obd_config/emission_test/evap_test/obd_operation/noise_test/confirmation 폼 신규 키
    g_ph_maker:'예) PIAGGIO C.S.P.A(이태리)',
    g_ph_model:'예) RSV4 1000 RR',
    g_ph_fuel:'예) 휘발유, 경유, LPG',
    g_ph_euro5:'예) EURO 5',
    g_ph_ece_noise:'예) ECE R41-04',
    g_ph_rep_nonrep:'대표/비대표',
    g_ph_cert_id:'예) ABC-123',
    g_ph_warranty_yr:'년',
    g_ph_self_test:'예) OBD, 소음, 증발가스',
    g_ph_key_tech:'예) 산소센서, 삼원촉매, OBD, ECU, Idle control, 전자식 연료주입',
    g_category:'구분',
    dp_valve_close:'닫기',
    dp_valve_per_cyl:'기통별 밸브수',
    dp_valve_intake:'흡기',
    dp_valve_exhaust:'배기',
    dp_valve_size:'밸브크기',
    dp_air_intake_type:'공기 흡입 방식',
    dp_type:'종류',
    dp_noble_metal:'귀금속 성분',
    dp_noble_metal_g:'귀금속량(g)',
    dp_capacity_cc:'용량(㎤)',
    dp_noble_ratio:'귀금속물질비(Pt:Pd:Rh)',
    dp_10_1_crank_cam_lbl:'크랭크 축 중심선에서 캠축 중심선까지의 거리(mm)',
    dp_10_1_crank_head_lbl:'크랭크 축 중심선에서 실린더 블록 헤드 면 상부까지의 거리(mm)',
    dp_10_1_tdc_lbl:'TDC 상태에서 연소실 표면적 체적비율',
    dp_10_1_fuel_supply_lbl:'연료 공급 방식',
    dp_10_1_inj_range_lbl:'분사 시기 제어범위',
    dp_10_1_cam_timing_lbl:'캠축타이밍',
    dp_10_1_inertia_lbl:'등가관성 중량',
    dp_10_1_roadload_lbl:'도로부하마력',
    dp_10_2_title:'10.2. 증발가스 동일차종 설명',
    dp_10_2_category:'구 분',
    dp_10_2_base:'기본 차종',
    dp_10_2_same:'증발가스 동일차종',
    dp_10_2_certno_lbl:'배출가스 인증번호',
    dp_10_2_carname_lbl:'자동차 명칭',
    dp_10_2_type_lbl:'자동차 형식',
    dp_10_2_eng_lbl:'원동기 형식',
    dp_10_2_cartype_lbl:'차종',
    dp_10_2_fuel_lbl:'사용연료',
    dp_10_2_evap_type_lbl:'증발가스 저장형식',
    dp_canister_design:'캐니스터 설계 특성',
    dp_canister_capacity:'증발가스 흡수용량',
    dp_canister_count:'캐니스터 개수 및 연결방법',
    dp_canister_shape:'캐니스터 형상',
    dp_canister_struct:'캐니스터 구조',
    dp_canister_mat:'캐니스터 재질',
    dp_fuel_system:'연료시스템',
    dp_filler_seal:'주유관 밀폐구조',
    dp_10_2_ctrl_lbl:'증발가스 제어시스템',
    dp_10_2_purge_lbl:'퍼지제어 시스템',
    dp_10_2_hose_mat_lbl:'증발가스 호스 재질',
    dp_10_2_tank_mat_lbl:'연료탱크 재질',
    dp_10_3_title:'10.3. 배출가스자기진단장치 동일차종 설명',
    dp_10_3_category:'구 분',
    dp_10_3_base:'기본 차종',
    dp_10_3_same:'배출가스자기진단장치 동일차종',
    dp_10_3_certno_lbl:'배출가스 인증번호',
    dp_10_3_carname_lbl:'자동차 명칭',
    dp_10_3_type_lbl:'자동차 형식',
    dp_10_3_eng_lbl:'원동기 형식',
    dp_10_3_cartype_lbl:'차종',
    dp_10_3_fuel_lbl:'사용연료',
    dp_10_3_obd_op_lbl:'배출가스 자가진단 장치의 작동법',
    dp_10_3_std_lbl:'배출가스 허용기준',
    dp_10_3_cycle_lbl:'연소싸이클',
    dp_10_3_fuel_supply_lbl:'연료공급방식',
    dp_10_3_cat_lbl:'촉매전환장치 형태',
    dp_10_3_dpf_lbl:'입자상물질 포집장치 형태',
    dp_10_3_air2_lbl:'2차 공기 분사 유무',
    dp_10_3_egr_lbl:'배출가스 재순환장치 유무',
    dp_11_1_title:'11.1. 시험차량 선정',
    dp_11_1_category:'구 분',
    dp_11_1_dur:'내구성 시험차량',
    dp_11_1_emis:'배출가스시험차량',
    dp_11_1_vin_lbl:'차대번호(엔진번호)',
    dp_11_1_disp_lbl:'배기량(cc)',
    dp_11_1_eng_code_lbl:'엔진코드',
    dp_11_1_evap_code_lbl:'증발가스 코드',
    dp_11_1_cat_code_lbl:'촉매코드',
    dp_11_1_emis_ctrl:'배출가스 제어장치',
    dp_11_1_emis_gas:'배출가스',
    dp_11_1_model_lbl:'모델명',
    dp_11_1_trans_lbl:'변속기 형태',
    dp_11_1_trans_proc_lbl:'변속 절차',
    dp_11_1_inertia_lbl:'등가관성 중량(kg)',
    dp_11_1_final_red_lbl:'종 감속기',
    dp_11_1_nv_lbl:'N/V 비, RRM/KPH',
    dp_11_1_tire_lbl:'타이어',
    dp_11_1_note_lbl:'비고',
    dp_11_1_sub_hdr_ph:'자동차 형식',
    dp_11_1_sub_name_lbl:'자동차 명',
    dp_11_1_sub_type_lbl:'자동차 형식',
    dp_11_1_sub_trans_lbl:'변속기',
    dp_11_1_sub_eng_lbl:'원동기 형식',
    dp_11_1_sub_disp_lbl:'배기량',
    dp_11_1_sub_weight_lbl:'공차중량',
    dp_11_1_sub_inertia_lbl:'등가관성중량',
    dp_11_1_sub_roadload_lbl:'도로부하마력',
    dp_11_1_sub_tankvol_lbl:'연료탱크용량',
    dp_11_1_sub_finalred_lbl:'종 감속비(제1감속비)',
    dp_11_1_sub_sales_lbl:'판매대수',
    dp_11_2_title:'11.2. 내구성 시험차량 선정',
    dp_11_2_sel_lbl:'내구성 시험차량 선정',
    dp_11_2_note_ph:'내구성 시험차량 선정 내용을 기재하세요',
    dp_11_3_title:'11.3. 배출가스 시험차량 선정',
    dp_11_3_a_case:'A. 섀시 다이나모미터를 사용하는 경우:',
    dp_11_3_a_0_lbl:'동일차종 중 등가관성중량이 가장 큰 것',
    dp_11_3_a_1_lbl:'상기 조건 내에서 도로 부하력이 가장 큰 것',
    dp_11_3_a_2_lbl:'상기 조건 내에서 배기량이 가장 큰 것',
    dp_11_3_a_3_lbl:'상기 조건 내에서 가장 높은 최종기어비를 갖는 변속기',
    dp_11_3_a_4_lbl:'상기 조건 내에서 연료탱크 용량이 가장 큰 것',
    dp_11_3_b_case:'B. 엔진 다이나모미터를 사용하는 경우:',
    dp_11_3_b_0_lbl:'최고 토오크 시 속도에서 행정당 연료배분율이 가장 큰 원동기',
    dp_11_3_b_1_lbl:'최고 속도 시 행정당 연료배분율이 가장 큰 원동기',
    dp_11_4_title:'11.4. 소음 시험차량 선정',
    dp_11_4_0_lbl:'공차중량이 가장 무거운 자동차',
    dp_11_4_1_lbl:'배기량이 가장 큰 자동차',
    dp_11_4_2_lbl:'최종기어비율(오버드라이브를 포함한다)이 가장 높은 변속기를 장착한 자동차',
    dp_11_4_3_lbl:'차축비가 가장 높은 자동차',
    dp_12_ph:'불가피한 사유 명시',
    dp_13_ph:'기타 사항',
    en_tank_pos_sec:'4.3.1.2. 연료탱크 위치',
    en_tank_pos_ph:'위치 설명',
    en_tank_shape_sec:'4.3.1.3. 연료탱크 형상',
    en_tank_shape_ph:'형상 설명',
    en_throttle_sec:'4.3.2. 스로틀바디',
    en_throttle_spec_sec:'4.3.2.1. 스로틀바디 상세제원',
    en_throttle_spec_ph:'스로틀바디 상세제원',
    en_throttle_dim_sec:'4.3.2.2. 스로틀바디 형상 및 치수제원',
    en_injector_sec:'4.3.3. 연료인젝터',
    en_injector_spec_sec:'4.3.3.1. 연료인젝터 상세제원',
    en_injector_spec_ph:'연료인젝터 상세제원',
    en_injector_dim_sec:'4.3.3.2. 연료인젝터 형상 및 치수제원',
    en_pump_sec:'4.3.4. 연료펌프',
    en_pump_spec_sec:'4.3.4.1. 연료펌프 상세제원',
    en_pump_spec_ph:'연료펌프 상세제원',
    en_pump_dim_sec:'4.3.4.2. 연료펌프 형상 및 치수제원',
    en_fuel_photo_sec:'4.4. 연료장치 사진',
    en_fuel_photo_ph:'연료장치 사진 설명',
    en_intake_sec:'5. 흡배기장치',
    en_intake_sub:'5.1. 흡기계통',
    en_intake_diagram_sec:'5.1.1. 흡기다기관 구성도',
    en_intake_diagram_ph:'흡기다기관 구성 설명',
    en_intake_manifold_sec:'5.1.2. 흡기메니폴드',
    en_intake_manifold_ph:'흡기메니폴드 제원 또는 설명',
    en_air_filter_sec:'5.1.3. 에어필터',
    en_air_filter_ph:'에어필터 제원 또는 설명',
    en_exhaust_sub:'5.2. 배기계통',
    en_exhaust_diagram_sec:'5.2.1. 배기다기관 구성도',
    en_exhaust_diagram_ph:'배기다기관 구성 설명',
    en_exhaust_manifold_sec:'5.2.2. 배기메니폴드',
    en_exhaust_manifold_ph:'배기메니폴드 제원 또는 설명',
    en_veh_sec:'6. 차량외관 및 치수',
    en_veh_photo_sub:'6.1. 차량사진',
    en_veh_front_sec:'6.1.1. 차량 전면',
    en_veh_front_ph:'차량 전면 설명',
    en_veh_rear_sec:'6.1.2. 차량 후면',
    en_veh_rear_ph:'차량 후면 설명',
    en_veh_side_sec:'6.1.3. 차량 측면',
    en_veh_side_ph:'차량 측면 설명',
    en_veh_top_sec:'6.1.4. 차량 상면',
    en_veh_top_ph:'차량 상면 설명',
    en_ext_sub:'6.2. 외형도',
    en_ext_side_sec:'6.2.1. 외형 측면',
    en_ext_side_ph:'외형 측면 설명',
    en_ext_top_sec:'6.2.2. 외형 상면',
    en_ext_top_ph:'외형 상면 설명',
    en_ext_rear_sec:'6.2.3. 외형 뒷면',
    en_ext_rear_ph:'외형 뒷면 설명',
    en_other_sec:'7. 기타',
    en_other_tech_sub:'7.1. 그 외 배출가스 및 소음 저감기술',
    en_other_tech_ph:'그 외 배출가스 및 소음 저감기술을 기재하세요',
    obd_y:'유',
    obd_n:'무',
    obd_ph_max_power:'최대출력',
    obd_ph_trans:'변속기(단)',
    obd_ph_combustion:'예) 불꽃점화, 4행정',
    obd_ph_fuel_supply:'예) 연료분사식(EFI)',
    obd_ph_cat_type:'예) 삼원촉매',
    obd_ph_yn:'유 / 무',
    obd_nv_lbl:'N/V비, rpm/kph',
    obd_nv_ph:'N/V비, rpm/kph',
    obd_tire_lbl:'타이어',
    obd_tire_f_lbl:'전',
    obd_tire_f_ph:'전 타이어 규격',
    obd_tire_r_lbl:'후',
    obd_tire_r_ph:'후 타이어 규격',
    obd_cat_lbl:'촉매 전환기의 형식',
    obd_cat_ph:'촉매 전환기의 형식',
    obd_dpf_lbl:'매연 여과장치의 형식',
    obd_air2_lbl:'2차 공기 분사 장치의 유무',
    obd_egr_lbl2:'배출가스 재 순환 장치의 유무',
    obd_evap_lbl:'증발가스 제어장치',
    obd_evap_ph:'증발가스 제어장치',
    obd_obd_func_lbl:'배출가스자기진단장치의 구성 및 기능',
    obd_obd_op_lbl:'배출가스 자기진단장치 작동방법',
    obd_obd_check_lbl:'감시장치의 오작동 확인방법',
    obd_obd_check_ph:'오작동 확인방법 입력',
    obd_mi_lbl:'오작동 표시 방법',
    obd_monitor_ph:'감시항목 입력',
    obd_note_ph:'비고',
    obd_photo_title:'OBD TEST 사진 및 스캐너 사진 첨부 : 차량사진, 차대번호 사진, 엔진번호 사진 포함',
    obd_veh_photo_lbl:'차량 사진',
    obd_veh_photo_desc:'차량 전체 사진 (전면/측면/후면 포함)',
    obd_vin_photo_lbl:'차대번호 사진',
    obd_vin_photo_desc:'차대번호(VIN) 확인 사진',
    obd_eng_photo_lbl:'엔진번호 사진',
    obd_eng_photo_desc:'엔진번호 확인 사진',
    obd_scanner_photo_lbl:'OBD 스캐너 사진',
    obd_scanner_photo_desc:'OBD 스캐너 연결 및 결과 화면 사진 (복수 첨부 가능)',
    obd_attach_title:'첨부문서 (자체시험성적서 / RAW DATA)',
    upload_click_drag:'클릭하거나 파일을 드래그하여 업로드',
    em_item_hdr:'항&nbsp;목',
    em_fuel_eff_hdr:'연비 (km/ℓ)',
    em_std_lbl:'기&nbsp;준&nbsp;치',
    ev_gen_info_hdr:'1. &nbsp;일 반 &nbsp;사 항',
    obd_air2_y_lbl:'유',
    obd_air2_n_lbl:'무',
    obd_egr_y_lbl:'유',
    obd_egr_n_lbl:'무',
    nt_reg_note_ph:'예) 가속주행소음 시험방법 (ECE R41-04)',
    nt_test_date_ph:'예) 2025. 01. 01.',
    nt_inspector_ph:'성명',
    cf_maker_ph:'예) HONDA Motor Co.,Ltd(일본)',
    cf_model_ph:'예) CB500F',
    cf_importer_ph:'예) ㈜○○모터스',
    cf_warranty_subject_ph:'보증 주체명 (예: ㈜○○모터스)',
    cf_warranty_text1:'은 대기환경보전법 제46조, 48조, 50조, 51조 및 대기환경보전법 시행규칙 제63조 규정에 의한',
    cf_warranty_text2:'보증기간(130km/h이하 2년 또는 20,000km, 130km/h이상 2년 또는 35,000km) 까지 제작차 및',
    cf_warranty_text3:'운행차 배출허용기준에 만족할 수 있도록 품질관리, 사후책임 등에 관한 의무사항을 이행하며,',
    cf_warranty_text4:'수시검사 및 결함검사에서 결함이 확인될 경우 제작 결함 수정(리콜)의 의무를 이행한다.',
    cf_warranty_confirm:'당사는 상기보증내용에 대해, 의무사항을 이행할 것을 확인합니다.',
    cf_signed_at_ph:'서명 장소',
    cf_sign_date_ph:'예) 2025. 01. 01.',
    cf_name_ph:'서명자 성명',
    cf_title_ph:'직책',
    attach_dl_title:'다운로드',
    attach_del_title:'삭제',
    lbl_address:'2. 주&nbsp;&nbsp;&nbsp;소 :',
    lbl_model_lbl:'3. 모&nbsp;&nbsp;&nbsp;델 :',
    lbl_warranty_content:'5. 보증내용 :',
    nt_attach_title:'첨부문서 (자체시험성적서 / RAW DATA)',
    nt_inspector_ph2:'성명',
// 8.x 부품 섹션 및 하위 항목
    dp_s8_1:'8.1. 연료장치',
    dp_s8_2:'8.2. 흡배기장치',
    dp_s8_3:'8.3. 점화장치',
    dp_s8_4:'8.4. 크랭크케이스제어장치',
    dp_s8_5:'8.5. 엔진',
    dp_s8_6:'8.6. 촉매전환기',
    dp_s8_7:'8.7. 배출가스 재순환장치(EGR)',
    dp_s8_8:'8.8. 전자제어장치',
    dp_s8_9:'8.9. 기타 배출가스 제어장치',
    dp_8_1_0:'연료공급계', dp_8_1_1:'연료제어계', dp_8_1_2:'연료분사계',
    dp_8_2_0:'흡기장치', dp_8_2_1:'배기장치',
    dp_8_3_0:'점화장치',
    dp_8_4_0:'크랭크케이스제어장치',
    dp_8_5_0:'엔진',
    dp_8_6_0:'촉매형식', dp_8_6_1:'촉매물질 구성', dp_8_6_2:'체적', dp_8_6_3:'촉매무게',
    dp_8_7_0:'배출가스재순환장치',
    dp_8_8_0:'장치/제원/입출력신호', dp_8_8_1:'엔진토크 산출방법과 적합성 자료',
    dp_8_9_0:'기타 장치',
    dp_5_4_lbl:'5.4. 소음 시험 계획',
g_obd_std2_rep_lbl:'* OBD2 가솔린 기준 적용 동일(IUPR 1st 기준), 대표 차종:',
    g_obd_std4_rep_lbl:'* OBD2 가솔린 EURO6 기준 적용 동일(IUPR 2nd 기준), 대표 차종:',
    g_obd_std_die_rep_lbl:'* OBD2 경유(다) 기준 적용 동일(IUPR 2nd 기준), 대표 차종:',
    g_evap_same_rep_lbl:'* 증발가스 동일, 대표 차종:',
img_click_to_zoom:'클릭하여 크게 보기',
    pw_err_required:'모든 항목을 입력해주세요.',
    pw_err_too_short:'새 비밀번호는 4자 이상이어야 합니다.',
    pw_err_mismatch:'새 비밀번호가 일치하지 않습니다.',
    err_occurred:'오류가 발생했습니다.',
    err_network:'네트워크 오류가 발생했습니다.',
    btn_processing:'처리중...',
    btn_change:'변경',
    pw_changed_ok:'비밀번호가 변경되었습니다.',
    cf_ph_address:'제작사 주소',
    cf_ph_phone:'전화번호',
    cf_ph_fax:'팩스번호',
    msg_popup_blocked:'팝업이 차단되었습니다. 팝업 허용 후 다시 시도하세요.',
    msg_qr_generating:'진위확인 코드 생성 중...',
    msg_network_error:'네트워크 오류',
    dp_ph_year_ex:'예) 2025',
    dp_ph_disp_ex:'예) 125cc',
    dp_lbl_count:'수',
    dp_lbl_gear2:'2단',
    dp_lbl_gear3:'3단',
    dp_lbl_gear4:'4단',
    dp_lbl_gear5:'5단',
    dp_lbl_gear6:'6단',
    dp_lbl_gear7:'7단',
    dp_lbl_nv_ratio:'N/V 비',
    dp_lbl_rear:'후',
    dp_lbl_category:'구분',
    dp_lbl_item:'항목',
    dp_lbl_car_name:'차명',
    dp_lbl_car_type:'자동차 형식',
    dp_lbl_passenger:'승차인원',
    dp_lbl_model_year:'모델년도',
    dp_lbl_spec_no:'제원관리번호',
    dp_lbl_drive:'구동형태',
    dp_lbl_car_class:'차종',
    dp_lbl_purpose:'용도',
    dp_lbl_trans_type:'변속기 종류',
    dp_lbl_body_shape:'차체형상',
    dp_lbl_curb_wt:'공차중량(kg)',
    dp_lbl_gvw:'차량 총 중량(kg)',
    dp_lbl_inertia_wt:'등가관성 중량(kg)',
    dp_lbl_dyno_hp:'실제 다이나모 마력(hp)',
    dp_lbl_dimensions:'치수',
    dp_lbl_length:'전장(mm)',
    dp_lbl_width:'전폭(mm)',
    dp_lbl_height:'전고(mm)',
    dp_lbl_manufacturer:'제작회사',
    dp_lbl_combustion:'연소방식',
    dp_lbl_eng_type:'원동기 형식',
    dp_lbl_displacement:'배기량(cc)',
    dp_lbl_eng_pos:'원동기부착위치',
    dp_lbl_fuel_type:'사용연료',
    dp_lbl_cyl_count:'실린더 수',
    dp_lbl_cyl_arr:'실린더 배열',
    dp_lbl_chamber_type:'연소실 형식',
    dp_lbl_max_power:'최대출력(ps/rpm)',
    dp_lbl_max_torque:'최대토크(kg-m/rpm)',
    dp_lbl_bore_stroke:'보어*스트로크(mm)',
    dp_lbl_idle_rpm:'공회전속도(rpm)',
    dp_lbl_intake_method:'공기흡입방식',
    dp_lbl_port_size:'포트크기',
    dp_lbl_port_size_mm:'포트크기(mm)',
    dp_lbl_port_shape:'포트형상',
    dp_lbl_ign_timing:'점화시기(Degree)',
    dp_lbl_fuel_tank:'연료탱크',
    dp_lbl_capacity_l:'용량(ℓ)',
    dp_lbl_position:'위치',
    dp_lbl_material:'재질',
    dp_lbl_air_cleaner:'제어공기청정기',
    dp_lbl_form_type:'형식',
    dp_lbl_drivetrain:'동력전달장치',
    dp_lbl_clutch:'클러치',
    dp_lbl_operation:'조작방식',
    dp_lbl_gear_ratio:'변속비',
    dp_lbl_gear_1:'1단',
    dp_lbl_forward:'전진',
    dp_lbl_reverse:'후진',
    dp_lbl_red_ratio:'감속비',
    dp_lbl_red1:'제1 감속비',
    dp_lbl_red2:'제2 감속비',
    dp_lbl_ev_spec:'전기자동차 관련 제원',
    dp_lbl_motor_type:'전동기 형식',
    dp_lbl_batt_cap:'축전지 정격전압 및 용량',
    dp_lbl_motor_power:'전동기 최대출력',
    dp_lbl_ev_range:'1회충전 주행거리',
    dp_lbl_tire:'타이어',
    dp_lbl_tire_maker:'타이어 제조회사',
    dp_lbl_tire_struct:'타이어 구조',
    dp_lbl_tire_size:'타이어 크기',
    dp_lbl_front:'전',
    dp_lbl_tire_pres:'타이어 공기압',
    dp_lbl_precious_comp:'귀금속 성분',
    dp_lbl_precious_g:'귀금속량(g)',
    dp_lbl_vol_cc:'용량(㎤)',
    dp_lbl_pm_ratio:'귀금속 물질비(Pt:Pd:Rh)',
    dp_lbl_em_test_info:'배출가스 시험에 관한 사항',
    dp_lbl_road_load:'실 도로 부하력(hp)',
    dp_lbl_road_coef:'도로흡력력계수',
    dp_lbl_coast_down:'코스트다운 시간(sec)',
    dp_lbl_canister:'캐니스터',
    dp_lbl_can_cap:'캐니스터의 흡수 용량',
    dp_lbl_can_size:'캐니스터의 크기(cc)',
    dp_lbl_can_media:'캐니스터의 매체',
    dp_lbl_evap_cap:'40%연료시 탱크의 최대 증발가스 용량',
    dp_lbl_muffler:'소음기',
    dp_lbl_muf_main:'주 소음기',
    dp_lbl_muf_sub:'보조 소음기',
    dp_lbl_vol_l:'용량(L)',
    dp_lbl_horn_dev:'경보장치',
    dp_lbl_horn:'경음기',
    dp_lbl_horn_db:'성능(dB(C))',
    dp_lbl_ignition:'점화장치',
    dp_lbl_chassis:'샤시',
    dp_lbl_other:'기타',
    dp_lbl_remark:'비고',
    dp_lbl_left:'좌측',
    dp_lbl_right:'우측',
    dp_lbl_compress_ratio:'압축비',
    dp_lbl_car_spec:'자동차 제원',
    dp_lbl_fuel_system:'연료장치',
    dp_lbl_type_kind:'종류',
    dp_lbl_test_fuel:'시험용연료',
    dp_lbl_acc_fuel:'주행거리 축적용 연료',
    dp_lbl_gasoline:'휘발유',
    dp_lbl_octane:'옥탄가(리서치법)',
    dp_lbl_aromatic:'방향족화합물함량(부피%)',
    dp_lbl_benzene:'벤젠함량(부피%)',
    dp_lbl_oxygen:'산소함량(무게%)',
    dp_lbl_lead:'납함량(g/ℓ)',
    dp_lbl_phosphorus:'인함량(g/ℓ)',
    dp_lbl_olefin:'올레핀함량(부피%)',
    dp_lbl_vapor_p:'증기압(kPa)',
    dp_lbl_90pct_temp:'90%유출온도(℃)',
    dp_lbl_sulfur:'황함량(무게%)',
    dp_lbl_diesel:'경유',
    dp_lbl_residual_carbon:'10% 잔류탄소량(%)',
    dp_lbl_cetane:'세탄지수',
    dp_lbl_fuel_source:'연료구입처',
    dp_fuel_note:'비고 : 자동차 인증시험연료는 국내에서 시판되는 자동차 연료를 원칙으로 하되, 대기규칙 별표 30 규정에 의한 자동차연료 제조기준에 해당하는 항목의 경우 이의 기재로 갈음한다.',
    dp_4_1_title:'4.1. 배출가스 측정장비',
    dp_4_2_title:'4.2. 소음 측정장비',
    dp_th_equip_name:'설비, 장비명',
    dp_th_model:'모델명',
    dp_th_type_no:'형식승인번호',
    dp_th_type_date:'형식승인일자',
    dp_th_lab_name:'실험실명',
    dp_th_calib_date:'최종정도검사일',
    dp_equip_note:'비고 : 외국 제작자의 설비·장비를 사용하는 경우에는 해당국 설정에 부합되는 공인 검정 또는 승인번호 등을 형식승인번호에 갈음하여 기재할 수 있음',
    dp_5_1_2_lbl:'5.1.2. 시험절차',
    dp_5_2_2_lbl:'5.2.2. 길들이기 주행여부',
    dp_5_2_4_lbl:'5.2.4. 주행장소',
    dp_5_3_2_lbl:'5.3.2. 시험절차',
    dp_5_4_2_lbl:'5.4.2. 시험절차',
    dp_6_1_title:'6.1. 시험차량의 정비계획',
    dp_6_1_1_title:'6.1.1. 정기정비',
    dp_6_1_2_title:'6.1.2. 비정기정비',
    dp_6_2_title:'6.2. 차량구입자에 대한 추천정비',
    dp_6_3_title:'6.3. 보증에 관한 설명',
    dp_6_3_1_lbl:'보증내용',
    dp_6_3_2_lbl:'보증기간',
    dp_6_3_3_lbl:'보증에서 제외되는 사항',
    dp_6_3_4_lbl:'차량소유자의 의무',
    dp_1_3_title:'1.3. 개발 목표 (수입차의 경우 외국인증성적 등으로 갈음)',
    dp_1_4_title:'인증대상자동차 제원',
    dp_1_3_r0:'허용기준',
    dp_1_3_r1:'개발 목표치',
    dp_1_3_r2:'현행기준 만족도(%)',
    dp_th_formaldehyde:'포름알데히드(g/km)',
    dp_th_smoke:'매연(%/kWh)',
    dp_2_1_title:'2.1. 기밀에 대한 요청',
    dp_8_10_title:'8.10. 감지변수 대 제어변수',
    dp_8_11_title:'8.11. 부품목록',
    dp_8_12_title:'8.12. 선택적촉매장치(SCR) 성능 및 원리 등 설명',
    dp_8_13_title:'8.13. SCR용 요소수용액 성분분석 결과',
    dp_8_14_title:'8.14. 전기자동차 제어장치',
    dp_8_11_ign:'점화장치',
    dp_8_11_fuel:'연료공급장치',
    dp_8_11_cat:'배출가스 전환장치',
    dp_8_11_egr:'배출가스 재순환장치',
    dp_8_11_evap:'연료증발가스 방지장치',
    dp_8_11_blow:'브로바이가스 환원장치',
    dp_8_11_air:'2차공기 분사장치',
    dp_8_12_r0:'공급계',
    dp_8_12_r1:'제어계',
    dp_8_12_r2:'분사계',
    dp_8_12_r3:'충전경고 시스템',
    dp_th_analysis_result:'분석결과',
    dp_th_analysis_org:'분석기관',
    dp_th_analysis_method:'분석방법',
    dp_th_analysis_date:'분석년월일',
    dp_th_proof_no:'증빙번호',
    dp_sv_o2:'배출가스 중 산소농도',
    dp_sv_air_flow:'흡입공기 유량',
    dp_sv_air_temp:'흡입공기 온도',
    dp_sv_coolant:'냉각수 온도',
    dp_sv_throttle:'스로틀 위치',
    dp_sv_baro:'대기압',
    dp_sv_intake_vac:'흡기부압',
    dp_sv_crank:'크랭크샤프트 위치',
    dp_sv_cam:'캠 샤프트 위치',
    dp_sv_batt:'배터리 전압',
    dp_sv_speed:'차량 속도',
    dp_sv_rpm:'원동기 회전수',
    dp_sv_gear:'변속기 기어',
    dp_sv_idle:'정지 및 중립',
    dp_sv_brake:'브레이크 적용',
    dp_sv_ac:'에어컨 가동',
    dp_sv_knock:'원동기 녹킹',
    dp_9_1_title:'9.1. 증발가스 제어장치 설명',
    dp_th_storage:'저장 장치',
    dp_th_absorb_cap:'흡수용량(C)',
    dp_th_size_media:'크기(㎤)/매체',
    dp_9_1_r0:'캐니스터',
    dp_9_1_r1:'에어클리너',
    dp_9_1_r2:'크랭크케이스',
    dp_9_1_r3:'기타',
    dp_9_2_title:'9.2. 제어장치 구성도',
    dp_9_2_parts_title:'증발가스 제어장치 부품리스트(보조배출가스 제어장치 포함)',
    dp_10_1_title:'10.1. 배출가스 및 소음 동일차종(원동기) 설명',
    dp_10_1_cyl_dist_lbl:'실린더 보어 중심간의 거리(mm)',
    dp_10_1_block_lbl:'실린더 블록 형상',
    dp_10_1_head_lbl:'실린더 헤드 방식',
    dp_durability_note:'내구성 시험을 실시하는 경우로서 인증신청 당시까지 세부개발계획이 확정되지 않는 등 불가피한 사유로 최초 제출하는 신청서류에 기재할 수 없는 사항이 있는 경우 그 사유를 명시하고, 내구성시험 최종보고서 제출 시 확정된 사항을 일괄적으로 제출할 수 있다.',
    dp_ph_dev_bg:'개발배경 및 특성을 기재하세요',
    dp_ph_new_tech:'신기술 내용을 기재하세요',
    dp_ph_confidential:'기밀 요청 내용을 기재하세요',
    dp_ph_engine_content:'엔진 내용',
    dp_ph_ignition_content:'점화장치 내용',
    dp_ph_chassis_content:'샤시 내용',
    dp_ph_other_content:'기타 내용',
    dp_ph_warranty_content:'보증내용',
    dp_ph_warranty_period:'보증기간',
    dp_ph_warranty_exclusion:'보증에서 제외되는 사항',
    dp_ph_owner_duty:'차량소유자의 의무',
    dp_ph_sign_desc:'표지판 견본 설명',
    dp_ph_attach_pos:'부착위치 등 기재',
    dp_ph_motor_ctrl:'전동기 및 전동기 제어장치 설명',
    dp_ph_batt_ctrl:'축전지 및 축전지 제어장치 설명',
    dp_ph_ctrl_diagram:'제어장치 구성도 설명',
    dp_ph_em_detail:'적서 제출 내역 등',
    dp_lbl_diagram_attach:'{sec} 구성도 첨부:',
    obd_dtc_default_val:'이륜자동차에 결함코드가 확인되면',
    obd_lbl_2nd_monitor_suffix:'등을 위한 방법을 포함한 포괄적인 설명자료',
    obd_lbl_ctrl_dev:'제어장치',
    obd_lbl_diag_config:'자기진단장치의 구성',
    msg_coming_soon:'준비 중입니다.',
    msg_qr_login_check:'QR 코드를 생성하려면 로그인 상태를 확인하세요.',
    msg_qr_fail:'QR생성실패',
    btn_saving:'저장 중...',
    msg_saved:'저장되었습니다.',
    msg_save_fail:'저장 실패',
    btn_save:'저장',
    btn_list:'목록', btn_toc_print:'목차인쇄',
    complete_title:'이 서류 작성을 완료했습니다', complete_sub:'체크하면 진행률에 반영됩니다',
    nt_rpm_unit:'% 회전속도(rpm)',
    btn_create_app:'신청서 생성',
    err_title_required:'신청 제목을 입력하세요.',
    err_cert_no_required:'기존 인증번호를 입력하세요.',
    btn_creating:'생성 중...',
    msg_create_fail:'생성 실패',
    msg_app_created:'신청서가 생성되었습니다.',
    msg_delete_confirm:'신청서를 삭제하면 모든 서류 데이터도 함께 삭제됩니다.\\n계속하시겠습니까?',
    msg_deleted:'삭제되었습니다.',
    msg_delete_fail:'삭제 실패',
    pw_lbl_current:'현재 비밀번호',
    pw_ph_current:'현재 비밀번호를 입력하세요',
    pw_lbl_new:'새 비밀번호',
    pw_ph_new:'4자 이상',
    pw_lbl_confirm:'새 비밀번호 확인',
    pw_ph_confirm:'재입력',
    
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
    g_doc_tag:'[Annex 2]',
    g_sec1:'1. Application Overview', g_sec2:'2. Application Type', g_sec3:'3. Details',
    g_th_div:'Type', g_th_apply_date:'Date', g_th_maker:'Manufacturer',
    g_th_model:'Model<br>(Type)', g_th_fuel_type:'Category<br>(Fuel)',
    g_th_output:'Power(ps/rpm)<br>(Disp. cc)', g_th_std:'Applicable Standard',
    g_th_cert_no:'Cert. No.', g_th_note:'Remarks',
    g_th_div2:'Category', g_th_fuel:'Fuel', g_th_cert_content:'Cert. Description', g_th_applicable:'Applicable',
    g_cat_emission:'Emission Std.', g_cat_obd:'OBD Std.', g_cat_evap:'Evaporative', g_cat_warranty:'Warranty',
    g_fuel_gasoline:'Gasoline', g_fuel_diesel:'Diesel',
    g_emit_colon:'Emission :', g_noise_colon:'Noise :',
    sv_applicable:'Applicable',
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
    en_muffler_diagram_title:'1.2 Muffler Internal Structure',
    en_muffler_spec_title:'1.3 Silencer Detailed Specifications',
    en_1_3_1:'Structure & Noise Reduction Principle', en_1_3_2:'Flow Diagram', en_1_3_3:'Manufacturer',
    en_1_3_4:'Inner/Outer Material', en_1_3_5:'Dimensional Drawing',
    en_cat_spec_title:'1.4 Catalyst Device Detailed Specifications',
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
    btn_write:'Edit', btn_delete:'Delete', btn_cancel:'Cancel', btn_edit_appl:'Edit Info', btn_logout:'Logout',
    modal_edit_title:'Edit Application Info', btn_update_appl:'Save Changes', msg_update_ok:'Application updated successfully.', msg_update_fail:'Failed to update application.',
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
    dp_1_2_lbl:'1.2. New or Key Emission-Related Technology',
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

    en_4_3_1_2:'4.3.1.2. Fuel Tank Location', en_tank_pos_ph:'Location description',
    en_4_3_1_3:'4.3.1.3. Fuel Tank Shape', en_tank_shape_ph:'Shape description',
    en_4_3_2:'4.3.2. Throttle Body',
    en_4_3_2_1:'4.3.2.1. Throttle Body Specifications', en_throttle_spec_ph:'Throttle body specifications',
    en_4_3_2_2:'4.3.2.2. Throttle Body Shape and Dimensions',
    en_4_3_3:'4.3.3. Fuel Injector',
    en_4_3_3_1:'4.3.3.1. Fuel Injector Specifications', en_injector_spec_ph:'Fuel injector specifications',
    en_4_3_3_2:'4.3.3.2. Fuel Injector Shape and Dimensions',
    en_4_3_4:'4.3.4. Fuel Pump',
    en_4_3_4_1:'4.3.4.1. Fuel Pump Specifications', en_pump_spec_ph:'Fuel pump specifications',
    en_4_3_4_2:'4.3.4.2. Fuel Pump Shape and Dimensions',
    en_4_4_fuel_photo:'4.4. Fuel System Photos', en_fuel_photo_ph:'Fuel system photo description',
    en_sec5:'5. Intake/Exhaust System', en_5_1:'5.1. Intake System',
    en_5_1_1:'5.1.1. Intake Manifold Diagram', en_intake_diagram_ph:'Intake manifold description',
    en_5_1_2:'5.1.2. Intake Manifold', en_intake_manifold_ph:'Intake manifold specs or description',
    en_5_1_3:'5.1.3. Air Filter', en_air_filter_ph:'Air filter specs or description',
    en_5_2:'5.2. Exhaust System',
    en_5_2_1:'5.2.1. Exhaust Manifold Diagram', en_exhaust_diagram_ph:'Exhaust manifold description',
    en_5_2_2:'5.2.2. Exhaust Manifold', en_exhaust_manifold_ph:'Exhaust manifold specs or description',
    en_sec6:'6. Vehicle Exterior and Dimensions', en_6_1:'6.1. Vehicle Photos',
    en_6_1_1:'6.1.1. Vehicle Front', en_veh_front_ph:'Vehicle front description',
    en_6_1_2:'6.1.2. Vehicle Rear', en_veh_rear_ph:'Vehicle rear description',
    en_6_1_3:'6.1.3. Vehicle Side', en_veh_side_ph:'Vehicle side description',
    en_6_1_4:'6.1.4. Vehicle Top', en_veh_top_ph:'Vehicle top description',
    en_6_2:'6.2. Exterior Drawing',
    en_6_2_1:'6.2.1. Exterior Side View', en_ext_side_ph:'Exterior side view description',
    en_6_2_2:'6.2.2. Exterior Top View', en_ext_top_ph:'Exterior top view description',
    en_6_2_3:'6.2.3. Exterior Rear View', en_ext_rear_ph:'Exterior rear view description',
    en_sec7:'7. Others', en_7_1:'7.1. Other Emission/Noise Reduction Technologies',
    en_other_tech_ph:'Enter other emission and noise reduction technologies',
    obd_yn_y:'Yes', obd_yn_n:'No',
    obd_max_power_ph:'Max output', obd_trans_ph:'Transmission (gear)',
    obd_combustion_ph:'e.g.) Spark ignition, 4-stroke', obd_fuel_supply_ph:'e.g.) Fuel injection (EFI)',
    obd_cat_type_ph:'e.g.) Three-way catalyst', obd_yn_ph:'Yes / No',
    obd_nv_lbl:'N/V ratio, rpm/kph', obd_tire_lbl:'Tires',
    obd_tire_f_lbl:'Front', obd_tire_r_lbl:'Rear',
    obd_tire_f_ph:'Front tire size', obd_tire_r_ph:'Rear tire size',
    obd_cat_type_lbl:'Catalytic converter type', obd_cat_type_sub:'(oxidation catalyst, three-way catalyst, heated catalyst, etc.)',
    obd_dpf_lbl:'DPF type', obd_egr_lbl:'EGR system presence',
    obd_evap_lbl:'Evaporative emission control', obd_evap_ph:'Evaporative emission control device',
    obd_diag_lbl:'OBD system composition and function',
    obd_diag_op_lbl:'OBD system operation method',
    obd_mi_check_lbl:'MIL malfunction check method', obd_mi_check_ph:'Enter malfunction check method',
    obd_mi_disp_lbl:'Malfunction indication method',
    obd_monitor_ph:'Enter monitoring items', obd_note_ph:'Notes',
    obd_photo_title:'OBD TEST photos: vehicle photo, VIN photo, engine number photo',
    obd_veh_photo_lbl:'Vehicle Photo', obd_veh_photo_desc:'Full vehicle photo (front/side/rear)',
    obd_vin_photo_lbl:'VIN Photo', obd_vin_photo_desc:'VIN confirmation photo',
    obd_eng_photo_lbl:'Engine No. Photo', obd_eng_photo_desc:'Engine number confirmation photo',
    obd_scanner_photo_lbl:'OBD Scanner Photo', obd_scanner_photo_desc:'OBD scanner connection and result screen (multiple allowed)',
    obd_attach_title:'Attachments (Self-test report / RAW DATA)',
    obd_upload_hint:'Click or drag files to upload',
    em_item_th:'Item', em_fuel_econ_th:'Fuel Economy<br>(km/L)', em_std_td:'Standard Value',
    ev_gen_section:'1. &nbsp;General &nbsp;Information',
    oo_yn_y:'Yes', oo_yn_n:'No',
    nt_reg_note_ph:'e.g.) Acceleration noise test conducted by ECE method',
    nt_test_date_ph:'e.g.) 2025. 01. 01.',
    nt_div_th:'Category', nt_2nd_lbl:'2nd Test', nt_3rd_lbl:'3rd Test',
    nt_4th_lbl:'4th Test', nt_avg_lbl:'Average', nt_result_lbl:'Result',
    nt_inspector_ph:'Name', nt_confirmer_ph:'Name',
    nt_attach_title:'Attachments (Self-test report / RAW DATA)',
    nt_ex_pct_lbl:'Max Engine Output<br>Speed Ratio',
    nt_upload_hint:'Click or drag files to upload',
    cf_maker_ph:'e.g.) HONDA Motor Co.,Ltd (Japan)',
    cf_addr_lbl2:'2. Address :', cf_model_lbl2:'3. Model :',
    cf_model_ph:'e.g.) CB500F', cf_importer_ph:'e.g.) ABC Motors Co., Ltd',
    cf_warranty_lbl2:'5. Warranty :',
    cf_warranty_subject_ph:'Warranty provider name (e.g.) ABC Motors Co., Ltd)',
    cf_law_text:'hereby certifies compliance with Article 46, 48, 50, 51 of the Clean Air Conservation Act and Article 63 of its Enforcement Regulations',
    cf_law_period:'for the warranty period (2 years or 20,000km for vehicles under 130km/h, 2 years or 35,000km for vehicles at/above 130km/h) for manufactured and',
    cf_law_obligation:'in-use vehicles to meet emission standards, fulfilling quality management and post-sale obligations,',
    cf_law_recall:'and agrees to implement recall corrections if defects are confirmed through periodic or defect inspections.',
    cf_confirm_text:'We confirm that we will fulfill our obligations regarding the above warranty.',
    cf_signed_at_ph:'Signature location', cf_sign_date_ph:'e.g.) 2025. 01. 01.',
    cf_name_ph:'Signatory name', cf_title_ph:'Title',

    // === emission_noise 내 detail_plan 섹션 헤더 ===
    dp_th_item:'Item', dp_th_sub_item:'Sub-item',
    dp_th_structure:'Structure/Manufacturer/Size/Capacity, etc.',
    dp_th_ctrl_tech:'Control Technology/Principle', dp_th_emission_eff:'Emission Reduction Effect',
    dp_th_sensor_var:'Sensor Variable', dp_th_fuel_afr:'Fuel (A/F Ratio)',
    dp_th_ign_timing:'Ignition Timing',
    dp_th_canister_purge:'Canister Purge / Idle Speed / EGR',
    dp_th_note:'Remarks',
    dp_th_part_no:'Part No.', dp_th_mfr:'Manufacturer', dp_th_mfr_country:'Country',
    dp_th_evap_code:'Evap. Code',
    dp_th_nominal_tank:'Nominal Tank<br>Volume (L)',
    dp_th_max_evap:'Max. Evap. Volume at 40% Fuel',
    dp_th_reservoir:'Max. Reservoir Vol. of Carburetor/Injector',
    dp_th_model_name:'Applicable Model',
    dp_th_category:'Category', dp_th_basic_model:'Base Model',
    dp_th_emission_equiv:'Emission & Noise<br>Equivalent Model',
    dp_th_evap_equiv:'Evap. Equivalent Model',
    dp_th_obd_equiv:'OBD Equivalent Model',
    dp_th_dur_test:'Durability Test Vehicle', dp_th_emission_test_v:'Emission Test Vehicle',
    dp_lbl_intake_manifold:'Intake Manifold', dp_lbl_intake_port_size:'Intake Port Size',
    dp_lbl_intake_port_shape:'Intake Port Shape',
    dp_lbl_exhaust_manifold:'Exhaust Manifold', dp_lbl_exhaust_port_size:'Exhaust Port Size',
    dp_lbl_exhaust_port_shape:'Exhaust Port Shape',
    dp_lbl_valve_timing:'Valve Open/Close',
    dp_lbl_intake_valve:'Intake<br>Valve', dp_lbl_exhaust_valve:'Exhaust<br>Valve',
    dp_lbl_open:'Open', dp_lbl_close:'Close',
    dp_lbl_valve_count:'Valves per Cylinder',
    dp_lbl_valve_intake:'Intake', dp_lbl_valve_exhaust:'Exhaust',
    dp_lbl_valve_size:'Valve Size',
    dp_lbl_air_intake:'Air Intake Method',
    dp_lbl_cat_type_lbl:'Type', dp_lbl_noble_metal:'Precious Metals',
    dp_lbl_noble_amount:'Precious Metal Amount (g)', dp_lbl_volume:'Volume (cm³)',
    dp_lbl_noble_ratio:'Precious Metal Ratio (Pt:Pd:Rh)',
    dp_lbl_canister_design:'Canister<br>Design Spec',
    dp_lbl_evap_absorp:'Evap. Absorption Capacity',
    dp_lbl_canister_cnt:'Canister Count & Connection',
    dp_lbl_canister_shape:'Canister Shape',
    dp_lbl_canister_structure:'Canister Structure',
    dp_lbl_canister_material:'Canister Material',
    dp_lbl_fuel_system:'Fuel System', dp_lbl_filler_seal:'Filler Neck Seal',
    dp_lbl_emission_ctrl:'Emission<br>Control', dp_lbl_emission_gas:'Emissions',
    dp_lbl_dur_test_select:'Durability Test Vehicle Selection',

    dp_5_1_1_lbl:'5.1.1. Test Location', dp_5_1_2_lbl:'5.1.2. Test Procedure',
    dp_5_2_1_lbl:'5.2.1. Durability Test Driving', dp_5_2_2_lbl:'5.2.2. Break-in Driving',
    dp_5_2_3_lbl:'5.2.3. Planned Driving Period', dp_5_2_4_lbl:'5.2.4. Driving Location',
    dp_5_2_5_lbl:'5.2.5. Driving Procedure',
    dp_5_3_1_lbl:'5.3.1. Test Location', dp_5_3_2_lbl:'5.3.2. Test Procedure',
    dp_5_4_1_lbl:'5.4.1. Test Location', dp_5_4_2_lbl:'5.4.2. Test Procedure',
    dp_lbl_engine:'Engine', dp_lbl_ignition:'Ignition System', dp_lbl_chassis:'Chassis',
    dp_8_14_1_lbl:'8.14.1. Motor and Motor Controller',
    dp_8_14_2_lbl:'8.14.2. Battery and Battery Controller',
    // === 회원정보 / 비밀번호 모달 ===
    profile_modal_title:'My Profile', profile_tab_info:'Edit Profile', profile_tab_pw:'Change Password',
    profile_lbl_username:'Username', profile_lbl_company:'Company', profile_lbl_rep:'Contact Person',
    profile_lbl_bizno:'Business No.', profile_lbl_phone:'Phone',
    profile_ph_company:'Enter company name', profile_ph_rep:'Enter contact name',
    profile_ph_bizno:'Business registration number', profile_ph_phone:'Phone number',
    profile_btn_save:'Save', profile_saved_ok:'Profile updated successfully.',
    profile_err_required:'Company, contact, and business number are required.',
    pw_change_title:'Change Password',
    pw_current_lbl:'Current Password', pw_new_lbl:'New Password',
    pw_confirm_lbl:'Confirm New Password',
    pw_current_ph:'Enter current password', pw_new_ph:'At least 4 characters',
    pw_confirm_ph:'Re-enter password',
    pw_cancel_btn:'Cancel', pw_change_btn:'Change',
    btn_processing:'Processing...', btn_change:'Change',
    pw_err_required:'Please fill in all fields.', pw_err_too_short:'Password must be at least 4 characters.',
    pw_err_mismatch:'Passwords do not match.', pw_changed_ok:'Password changed successfully.',
    err_occurred:'An error occurred.', err_network:'Network error.',
    btn_create_app:'Create', btn_creating:'Creating...', msg_create_fail:'Failed to create.',
    msg_app_created:'Application created.', err_cert_no_required:'Enter the existing certificate number.',
    msg_delete_confirm:'Are you sure you want to delete?', msg_deleted:'Deleted.', msg_delete_fail:'Failed to delete.',
    save_error:'An error occurred while saving.',
    qr_auth_code_lbl:'Auth Code',
    qr_verify_title:'Authenticity Verification',
    qr_doc_name:'Document',
    qr_application:'Application',
    qr_issued_at:'Issued At',
    qr_issuer:'Issuer',
    obd_lbl_tire:'Tire',
    obd_ph_trans_step:'Transmission (Stage)',
    obd_sec1_label:'OBD Comprehensive Information Documents',
    obd_1_1_desc:'1.1. Parts list & functional description of OBD-monitored components',
    obd_1_2_desc:'1.2. Description of malfunction indicator lamp',
    obd_1_3_desc:'1.3. Statement prohibiting unauthorized modification',
    obd_1_4_desc:'1.4. Technical description of monitoring devices',
    obd_1_5_desc:'1.5. Additional Information',
    obd_1_6_desc:'1.6. Self-test Results & Technical Description',
    obd_sec2_label:'Documents on Same Vehicle Type Description',
    obd_sec3_label:'Documents on Test Vehicle Selection',
    obd_sec2_title:'2. Documents on Same Vehicle Type',
    obd_sec3_title:'3. Documents on Test Vehicle Selection',
    obd_2_1_title:'2.1. Vehicle Specs (Representative of OBD Same Type)',
    obd_gen_spec_title:'1. General Specifications',
    obd_eng_spec_title:'2. Engine Specifications',
    obd_em_ctrl_spec_title:'3. Emission Control & OBD Specs',
    obd_1_6_1_title:'1.6.1. Test Results',
    obd_1_6_2_title:'1.6.2. OBD Monitor Part Test & Diagnosis',
    obd_2_2_title:'2.2. OBD Same Vehicle Type',
    obd_2_3_title:'2.3. OBD Same Vehicle Type Description',
    obd_3_1_title:'3.1. OBD Test Vehicle Selection Basis',
    obd_lbl_cat_monitor:'Catalyst Monitor',
    obd_lbl_dpf_monitor:'DPF Monitor',
    obd_lbl_eis_monitor:'EIS Monitor',
    obd_lbl_obd_parts:'Parts monitored by OBD system',
    obd_lbl_mil_criteria:'MIL activation criteria',
    obd_lbl_dtc_list:'All OBD output code list and forms used',
    obd_th_test_req:'Test Requirement Criteria (Type Ⅰ)',
    obd_th_compliance:'Compliance',
    obd_th_part_check:'Part Check',
    obd_th_mi_time:'MI Activation Timing',
    obd_th_mem_err:'Memory Stored Error Code Fix',
    obd_th_obd_same:'OBD Same Vehicle Type',
    obd_th_obd_test_car:'OBD Test Vehicle',
    obd_lbl_modelname:'Model Name',
    obd_lbl_vin:'VIN (Engine No.)',
    obd_lbl_trans_type:'Transmission Type',
    obd_lbl_trans_proc:'Shift Procedure',
    obd_lbl_equiv_inertia:'Equivalent Inertia Weight (kg)',
    obd_lbl_final_drive:'Final Drive',
    obd_lbl_same_carname:'Vehicle Name (Same Type)',
    obd_lbl_engine:'Engine',
    obd_lbl_combustion:'Combustion process (spark/compression, 2/4-stroke)',
    obd_lbl_fuel_method:'Fuel supply method (carburetor, injection, etc.)',
    obd_lbl_cat_type:'Catalytic converter type (oxidation, three-way, etc.)',
    obd_lbl_dpf_type:'DPF Type',
    obd_lbl_2ndair_yn:'Secondary Air Injection Y/N',
    obd_lbl_egr_yn:'EGR Device Y/N',
    obd_lbl_obd_method:'OBD system operating method',
    obd_lbl_monitor_check:'Monitor malfunction check method',
    obd_lbl_mal_display:'Malfunction display method',
    obd_ph_name_type:'Vehicle name (type)',
    obd_ph_total_weight:'Total weight (curb)',
    obd_ph_na_or_type:'N/A or enter type',
    obd_ph_method:'Enter operating method',
    obd_ph_check_method:'Enter malfunction check method',
    obd_ph_display_method:'Enter malfunction display method',
    obd_ph_vin:'VIN (Engine No.)',
    obd_ph_trans_type:'Transmission type',
    obd_ph_trans_proc:'Shift procedure',
    obd_ph_equiv_inertia:'Equiv. inertia weight (kg)',
    obd_ph_final_drive:'Final drive',
    obd_ph_same_carname:'Same vehicle name',
    obd_lbl_prep_cycle:'Prep cycle type and count for malfunction verification',
    obd_lbl_test_cycle:'Test cycle description for OBD-monitored parts',
    obd_lbl_2nd_monitor:'List of 2nd monitor variables for OBD-monitored parts',
    obd_lbl_ctrl_indicator:'Control, auto-indicator, indicator positions & symbols',
    obd_div_mil_location:'MIL type & location: drawing or photo showing type/location',
    obd_div_left_switch:'Left handlebar switch control & symbol drawing',
    obd_div_right_switch:'Right handlebar switch control & symbol drawing',
    obd_div_keybox:'Key box drawing',
    obd_txt_malfunction_test:'When testing a vehicle equipped with parts for malfunction reproduction or electronic equipment for malfunction motorcycle, the MIL shall illuminate below the malfunction judgment standard and the OBD system shall be considered conforming.',
    obd_txt_electrical_continuity:'The electrical continuity of emission-related parts or powertrain parts connected to the engine control unit shall be monitored.',
    obd_ph_dtc_default:'When a fault code is confirmed in a two-wheeler, the engine check light on the dashboard turns on.',
    obd_ph_no_modify:'Enter statement prohibiting unauthorized modification',
    nt_th_gear:'Gear<br>Used',
    nt_th_entry_speed:'Entry<br>Designated<br>Speed<br>(km/hr)',
    nt_th_test_speed:'Test Speed<br>(km/hr.)',
    nt_th_rpm:'Engine RPM<br>(rpm)',
    nt_th_accel_pos:'Accel.<br>Start<br>Pos.<br>(m)',
    nt_th_bg_noise:'Bkg.<br>Noise<br>[dB<br>(A)]',
    nt_th_meas_noise:'Meas. Noise<br>[dB(A)]',
    nt_th_correction:'Correction<br>[dB<br>(A)]',
    nt_th_std_val:'Std.<br>Value<br>[dB<br>(A)]',
    nt_th_accel_init:'Accel.<br>Init.',
    nt_th_accel_end:'Accel.<br>End',
    nt_th_left:'Left',
    nt_th_right:'Right',
    nt_lbl_1st:'1st Test',
    nt_lbl_wot_noise:'Acceleration Noise<br>(L_WOTrep, dB(A))',
    nt_lbl_crs_noise:'Constant Speed Noise<br>(L_CRSrep, dB(A))',
    em_val_dur_run:'Durability Drive Test',
    em_sec5_cvs:'5. CVS Driving Test Status',
    em_sec6_result:'6. Test Results',
    ev_sec2:'2. Test Room & Equipment',
    ev_upload_hint:'Click or drag file to upload',
    oo_th_fuel_econ:'Fuel Economy<br>(km/ℓ)',
    oo_th_exhaust_gas:'Exhaust<br>Gas',
    oo_th_det_factor:'Det. Factor<br>(DF)',
    oo_sec3_emission:'3. Emission Control',
    g_th_compliance_pct:'Compliance Rate(%)',
    g_obd_std_2006_gas:'Gasoline 06 OBD Standard',
    g_obd_std_2013_1st:'Gasoline 13 OBD IUPR 1st',
    g_obd_std_2013_2nd:'Gasoline 13 OBD IUPR 2nd (Jan 16)',
    g_obd_std_euro6:'Gasoline EURO6 OBD IUPR 2nd',
    g_obd_std_euro5_2w:'Gasoline EURO5 OBD Two-Wheeler (Stage 2)',
    g_obd_std_2006_diesel:'Diesel 06 OBD Standard',
    g_obd_std_2012_diesel:'Diesel 12 OBD IUPR 1st',
    g_obd_std_2014_diesel:'Diesel Sep 14 OBD IUPR 2nd',
    g_ph_obd_mal:'OBD2 malfunction judgment related details',
    g_th_monitor_item:'Monitoring Item',
    g_th_test_yn:'Test Y/N',
    g_th_test_vehicle:'Test Vehicle',
    g_th_applicable2:'Applied Y/N',
    g_th_meas_result:'Measurement Result',
    g_lbl_test_facility:'Test Facility',
    g_ph_facility_detail:'Facility verification for self-test',
    g_lbl_vehicle_sel:'Test Vehicle Selection Basis',
    g_vehicle_sel_title:'Test Vehicle Selection Basis',
    g_vehicle_sel_em:'- Emission test vehicle: selected per Article 11',
    g_vehicle_sel_noise:'- Noise test vehicle: selected per Article 12',
    g_vehicle_sel_obd:'- OBD test vehicle: selected per Article 23',
    g_ph_additional:'Enter additional notes',
    g_ph_em_mode:'Emission test mode, count, self-test result',
    g_lbl_evap_test:'Evaporative Test',
    g_ph_evap_submit:'Evaporative self-test report submission details',
    g_lbl_warranty_det:'Warranty & Deterioration Factor',
    g_ph_warranty_detail:'Warranty and deterioration factor application details',
    g_lbl_warranty_km:'Warranty (km) :',
    g_th_det_factor:'Applied Deterioration Factor',
    g_em_co:'Carbon Monoxide (CO)',
    g_em_exhaust_hc:'Exhaust Pipe HC',
    g_em_nox:'NOx',
    g_em_evap_hc:'Evaporative HC',
    g_lbl_endurance:'Endurance Test',
    g_ph_endurance_note:'Describe endurance test details',
    g_lbl_ki:'Periodic Regeneration Index<br>(ki) Test',
    g_ph_ki_note:'KI test details',
    g_lbl_noise_test:'Noise Test',
    g_noise_submit:'Noise test report submission details',
    g_ph_noise_submit:'Describe noise test report submission',
    g_noise_method:'Noise Test Method',
    g_noise_accel_lbl:'- Acceleration Noise :',
    g_noise_exhaust_lbl:'- Exhaust Noise :',
    g_noise_horn_lbl:'- Horn Noise :',
    g_lbl_same_type:'Same Vehicle Type Configuration',
    g_th_div_lbl:'Category',
    g_lbl_o2_sensor:'Oxygen Sensor',
    g_lbl_egr:'EGR System',
    g_lbl_vvt:'Variable Valve Timing System',
    g_lbl_fuel_system:'Fuel System',
    g_lbl_misfire:'Misfire',
    g_lbl_2nd_air:'Secondary Air System',
    en_ph_inner_diag:'Describe internal structure',
    en_ph_flow_desc:'Flow diagram description',
    en_ph_maker_name:'Manufacturer name',
    en_ph_inner_mat:'Inner material/spec',
    en_ph_outer_mat:'Outer material/spec',
    en_ph_dim_desc:'Dimension drawing description',
    en_ph_cat_principle:'Describe catalyst principle or effect',
    en_ph_attach_desc:'Attachment position description',
    en_1_5_lbl:'1.5. Sensor Detailed Specs',
    en_1_5_1_lbl:'1.5.1. Sensor Manufacturer',
    en_1_5_2_lbl:'1.5.2. Sensor Material',
    en_1_5_3_lbl:'1.5.3. Sensor Dimension Drawing',
    en_ph_sensor_mat:'Sensor material',
    en_1_6_lbl:'1.6. Muffler Drawing',
    en_1_7_lbl:'1.7. Muffler Photo',
    en_ph_muffler_draw:'Muffler drawing description',
    en_ph_muffler_photo:'Muffler photo description',
    en_sec2_valve:'2. Valve Train',
    en_2_1_valve:'2.1. Valve Train Inertia',
    en_ph_valve_inertia:'Describe valve train inertia',
    en_2_2_surging:'2.2. Valve Spring Surging Technology',
    en_ph_surging:'Describe Surging countermeasure technology',
    en_2_3_cam:'2.3. Cam Profile & Specs',
    en_2_3_1_valve:'2.3.1. Valve Specs',
    en_ph_valve_spec:'Describe valve specs',
    en_2_3_2_cam:'2.3.2. Cam Specs',
    en_ph_cam_spec:'Describe cam specs',
    en_2_3_3_cam_dim:'2.3.3. Cam Dimension Drawing',
    en_ph_cam_dim:'Cam dimension drawing description',
    en_2_4_valve_mat:'2.4. Valve Train Material & Details',
    en_ph_valve_mat:'Describe valve train material details',
    en_2_5_valve_clearance:'2.5. Valve Clearance',
    en_ph_valve_clearance:'Valve clearance value or description',
    en_sec3_ignition:'3. Ignition System',
    en_3_1_ign_diag:'3.1. Ignition System Diagram',
    en_ph_ign_diag:'Ignition system configuration description',
    en_3_2_ign_ctrl:'3.2. Ignition Control Characteristics',
    en_ph_ign_ctrl:'Describe ignition control characteristics',
    en_3_3_ign_spec:'3.3. Ignition System Detailed Specs',
    en_3_3_1_gen:'3.3.1. Generator',
    en_3_3_1_1_gen_spec:'3.3.1.1. Generator Detailed Specs',
    en_ph_gen_spec:'Generator detailed specs',
    en_3_3_1_2_gen_dim:'3.3.1.2. Generator Shape & Dimensions',
    en_ph_shape_dim:'Shape and dimension description',
    en_3_3_2_1_cdi_spec:'3.3.2.1. CDI UNIT Detailed Specs',
    en_ph_cdi_spec:'CDI UNIT detailed specs',
    en_3_3_2_2_cdi_dim:'3.3.2.2. CDI UNIT Shape & Dimensions',
    en_3_3_3_coil:'3.3.3. Ignition Coil',
    en_3_3_3_1_coil_spec:'3.3.3.1. Ignition Coil Detailed Specs',
    en_ph_coil_spec:'Ignition coil detailed specs',
    en_3_3_3_2_coil_dim:'3.3.3.2. Ignition Coil Shape & Dimensions',
    en_3_3_4_plug:'3.3.4. Spark Plug',
    en_3_3_4_1_plug_spec:'3.3.4.1. Spark Plug Detailed Specs',
    en_ph_plug_spec:'Spark plug detailed specs',
    en_3_3_4_2_plug_dim:'3.3.4.2. Spark Plug Shape & Dimensions',
    en_3_3_5_ecu:'3.3.5. ECU Detailed Specs',
    en_3_3_5_1_ecu_spec:'3.3.5.1. ECU Detailed Specs',
    en_ph_ecu_spec:'ECU detailed specs',
    en_3_3_5_2_ecu_dim:'3.3.5.2. ECU Shape & Dimensions',
    en_3_4_ign_photo:'3.4. Ignition System Photo',
    en_ph_ign_photo:'Ignition system photo description',
    en_sec4_fuel:'4. Fuel System',
    en_4_1_fuel_sys:'4.1. Fuel System Configuration & Control',
    en_ph_fuel_sys:'Describe fuel system configuration and control',
    en_4_2_fuel_drawing:'4.2. Fuel System Drawing & Dimensions',
    en_ph_drawing_dim:'Drawing and dimension description',
    en_4_3_fuel_spec:'4.3. Fuel System Detailed Specs',
    en_4_3_1_tank:'4.3.1. Fuel Tank',
    en_4_3_1_1_tank_spec:'4.3.1.1. Fuel Tank Detailed Specs',
    en_ph_tank_spec:'Fuel tank detailed specs',
    obd_wps_lbl:'Engine Temp Sensor (WPS)',
    obd_o2_lbl:'Oxygen Sensor (O₂)',
    obd_injector_lbl2:'Fuel Injector',
    obd_o2heater_lbl:'O₂ Sensor Heater',
    obd_wire_throttle:'Wire Actuator Throttle',
    obd_fanrelay_lbl:'Radiator Fan Relay',
    obd_pumprelay_lbl:'Fuel Pump Relay',
    obd_ph_content:'Enter content',
    obd_ph_carname:'Vehicle Name',
    obd_ph_type:'Type',
    obd_ph_carkind:'Vehicle Type',
    obd_ph_fuel:'Fuel Type',
    obd_ph_weight:'Total Weight (Curb, kg)',
    obd_ph_engtype:'Engine Type',
    obd_ph_maxpower:'Max Power',
    obd_ph_cc:'Displacement (cc)',
    obd_ph_combtype:'Combustion Type',
    obd_ph_cycle:'Combustion Cycle',
    obd_ph_supplytype:'Fuel Supply Type',
    obd_ph_cat_info:'Catalytic converter type & manufacturer',
    obd_ph_ecu_info:'ECU type & manufacturer',
    obd_ph_o2s_info:'O2 sensor type & manufacturer',
    obd_ph_purge_info:'Purge valve type & manufacturer',
    obd_val_pass:'Pass',
    obd_val_fail:'Fail',
    obd_th_part_harness:'Part/Harness',
    obd_th_switch:'Switch',
    obd_th_start:'Start',
    obd_th_spec:'Spec',
    obd_th_mil:'MIL Activation',
    obd_th_carname:'Vehicle Name',
    obd_th_type:'Type',
    obd_th_carkind:'Vehicle Type',
    obd_th_weight:'Total Weight (Curb, kg)',
    obd_th_cc:'Displacement (cc)',
    obd_th_combtype:'Combustion Type',
    obd_th_cycle:'Combustion Cycle',
    obd_th_supplytype:'Fuel Supply Type',
    obd_th_cat:'Catalytic Converter Type (Maker)',
    obd_th_2nd_air:'Secondary Air Injection',
    obd_th_egr:'EGR Device',
    obd_th_ecu:'ECU Type (Maker)',
    obd_th_o2s:'O2 Sensor Type (Maker)',
    obd_th_purge:'Purge Valve Type (Maker)',
    obd_th_name_type:'Vehicle Name (Type)',
    obd_th_engtype:'Engine Type',
    obd_th_maxpower:'Max Power',
    obd_th_trans_step:'Transmission (Stage)',
    obd_ph_part_check:'Part inspection details',
    obd_ph_mi_time:'MI activation timing',
    obd_ph_err_fix:'Error code correction',
    obd_ph_part_harness:'Part/Harness',
    obd_ph_switch:'Switch',
    obd_ph_start:'Start',
    obd_ph_spec:'Spec',
    em_ph_engtype:'Engine type or technical details',
    g_2_1_label:'2.1. EURO–5 Gasoline Two-Wheeled Vehicle Certification, Representative Model :',
    g_2_2_obd:'2.2. OBD Representative Model :',
    g_evap_rep_lbl:'Evaporative Representative Model :',
    g_em1_txt:'* 13 Gasoline Standard 2-B',
    g_em2_txt:'* 13 Gasoline Standard 1-B',
    g_em3_txt:'* 16 Gasoline Standard',
    g_em4_txt:'* Jan 20 Two-Wheeler (≤130km/h) Standard',
    g_em5_txt:'* Sep 14 Diesel Small Passenger Standard',
    g_obd1_txt:'* OBD2 Gasoline Standard Rep. (IUPR 1st)',
    g_obd2_txt:'* OBD2 Gasoline Standard Same (IUPR 1st), Rep. Model :',
    g_obd3_txt:'* OBD2 Gasoline EURO6 Standard Rep. (IUPR 2nd)',
    g_obd4_txt:'* OBD2 Gasoline EURO6 Standard Same (IUPR 2nd), Rep. Model :',
    g_obd5_txt:'* OBD2 Gasoline EURO5 Two-Wheeler Standard Rep. (OBD Stage 2)',
    g_obd6_txt:'* OBD2 Diesel (C) Standard Rep. (IUPR 2nd)',
    g_obd7_txt:'* OBD2 Diesel (C) Standard Same (IUPR 2nd), Rep. Model :',
    g_evap1_txt:'* Evaporative Representative',
    g_evap2_txt:'* Evaporative Same, Rep. Model :',
    g_war1_txt:'* Warranty : 10yr / 192,000km',
    g_war2_txt:'* Warranty : 10yr / 240,000km',
    g_war3_txt:'* Warranty : 15yr / 240,000km',
    g_war4_txt:'* Warranty : 2yr / 35,000km',
    g_war5_txt:'* Warranty : 2yr / 20,000km',
    g_war6_txt:'* Warranty : 10yr / 160,000km',
    g_3_1_lbl:'3.1. Applied Technology',
    g_3_2_1_lbl:'3.2.1. Emission',
    g_3_2_2_lbl:'3.2.2. Noise',
    g_3_3_lbl:'3.3. Detailed Technical Content',
    g_3_4_lbl:'3.4. Test Facility',
    g_3_5_lbl:'3.5. Emission Test',
    g_3_6_lbl:'3.6. Evaporative Test',
    g_3_7_lbl:'3.7. Warranty & Deterioration Factor',
    g_3_8_lbl:'3.8. Endurance Test',
    g_3_9_lbl:'3.9. KI Test',
    g_3_10_lbl:'3.10. Noise Test',
    g_3_11_lbl:'3.11. Same Vehicle Type',
    g_th_hc:'Hydrocarbon',
    g_th_allow_std:'Allowable Standard',
    g_th_test_result:'Test Result',
    g_th_accel_db:'Acceleration<br>dB(A)',
    g_th_exhaust_db:'Exhaust<br>dB(A)',
    g_th_horn_db:'Horn<br>dB(A)',
    g_th_co_gkm:'CO<br>(g/km)',
    g_th_hcnox_gkm:'HC+NOx<br>(g/km)',
    g_th_pm_gkm:'PM<br>(g/km)',
    g_th_exhaust_hc:'Exhaust HC<br>(g/km)',
    g_th_evap_hc:'Evap HC<br>(g/test)',
    g_th_obd_std:'OBD Standard Name',
    g_th_monitor_dev:'Monitoring Device',
    g_th_wmtc:'WMTC Mode<br>CO(g/km)',
    g_th_mil_on:'MIL<br>ON/OFF',
    g_th_judge_std:'Judgment Std.<br>CO(g/km)',
    g_th_monitor_judge:'Monitor<br>Pass/Fail',
    g_th_item:'Item',
    g_th_content:'Content',
    g_th_result_judge:'Result Judgment',
    g_th_malfunction:'Malfunction Condition',
    g_th_device_name:'Device Name',
    g_lbl_catalyst:'Catalyst, DPF & After-treatment',
    g_lbl_evap:'Evaporative Gas',
    g_lbl_blowby:'Blow-by Gas',
    g_lbl_obd2:'OBD2 System',
    g_lbl_catalyst_br:'Catalyst, DPF &<br>After-treatment',
    g_lbl_catalyst2:'Catalyst',
    g_lbl_o2:'O₂ Sensor',
    g_ph_tech:'Describe applied emission/noise reduction technology',
    g_ph_em_result:'Self-test emission result',
    g_ph_noise_result:'Self-test noise result',
    g_ph_catalyst:'After-treatment device details',
    g_ph_evap_detail:'Evaporative rep./same status and details',
    g_ph_blowby:'Blow-by gas control device details',
    g_ph_obd_rep:'OBD2 rep./same status and details',
    g_ph_facility:'Test facility details',
    g_ph_em_test:'Emission test details',
    g_ph_evap_test:'Evaporative test details',
    g_ph_warranty:'Warranty and deterioration factor details',
    g_ph_endurance:'Endurance test details',
    g_ph_ki:'KI test details',
    g_ph_noise_test:'Noise test details',
    g_ph_same_type:'Describe same vehicle type configuration',
    g_ph_applicable:'Applicable/N.A.',
    g_ph_misfire:'Misfire',
    g_ph_degradation:'Degradation',
    g_ph_yn:'Yes/No',
    g_ph_pass_fail:'Pass/Fail',
    g_ph_img:'Drag or click image',
    en_doc_tag:'[Annex 5]',
    en_main_title_txt:'Emission & Noise Reduction Device Data',
    en_sec1:'1. Muffler',
    en_1_1_lbl:'1.1 Muffler Configuration',
    en_1_2_lbl:'1.2 Muffler Internal Structure',
    en_1_3_lbl:'1.3 Muffler Detailed Specs',
    en_1_4_lbl:'1.4 Catalyst Detailed Specs',
    en_sec2:'2. Air Cleaner',
    en_2_1_lbl:'2.1 Air Cleaner Detailed Specs',
    en_1_3_1_lbl:'Structure & Noise Reduction Principle',
    en_1_3_2_lbl:'Flow Diagram',
    en_1_3_3_lbl:'Manufacturer',
    en_inside_lbl:'Inside :',
    en_outside_lbl:'Outside :',
    en_dim_draw_lbl:'Dimension Drawing',
    en_principle_lbl:'Principle or Effect',
    en_attach_pos_lbl:'Attachment Position',
    en_cat_maker_lbl:'Catalyst Manufacturer',
    en_cat_material_lbl:'Catalyst Material',
    en_cat_perf_lbl:'Catalyst Performance & Dimensions',
    en_inside_mat_lbl:'Inside Material',
    en_outside_mat_lbl:'Outside Material',
    en_ph_muffler_comp:'Describe muffler configuration',
    en_ph_muffler_diag:'Describe muffler internal structure',
    en_ph_noise_principle:'Describe noise reduction principle',
    en_ph_flow:'Describe flow diagram',
    en_ph_maker:'Describe manufacturer',
    en_ph_inside:'Describe inside material',
    en_ph_outside:'Describe outside material',
    en_ph_dim:'Describe dimension drawing',
    en_ph_cat_maker:'Describe catalyst manufacturer',
    en_ph_cat_mat:'Describe catalyst material',
    en_ph_cat_perf:'Describe catalyst performance and dimensions',
    en_ph_principle:'Describe principle or effect',
    en_ph_pos:'Describe attachment position',
    en_ph_aircleaner:'Describe air cleaner detailed specs',
    obd_doc_tag:'[Annex 9]',
    obd_main_title_txt:'Documents on OBD System Configuration',
    obd_sec1:'1. OBD System Comprehensive Information',
    obd_sec2:'2. Documents on OBD System Functions',
    obd_th_parts:'Vehicle Emission-Related Parts',
    obd_th_func:'Functional Characteristics',
    obd_lbl_sensor:'Sensor',
    obd_lbl_actuator:'Actuator',
    obd_cps_lbl:'Crank Position Sensor (CPS)',
    obd_tmap_lbl:'Temperature & Pressure Sensor (T-MAP)',
    obd_wts_lbl:'Coolant Temp Sensor (WTS)',
    obd_o2s_lbl:'Oxygen Sensor (HO2S)',
    obd_tps_lbl:'Throttle Position Sensor (TPS)',
    obd_injector_lbl:'Fuel Injector',
    obd_pump_lbl:'Fuel Pump',
    obd_idle_lbl:'Idle Speed Control',
    obd_coil_lbl:'Ignition Coil',
    obd_cat_lbl:'Catalytic Converter',
    obd_egr_lbl:'EGR System',
    obd_evap_sys_lbl:'Evaporative Control System',
    obd_air2_lbl:'Secondary Air Injection System',
    obd_fuel_sys_lbl:'Fuel System',
    obd_trans_lbl:'Transmission',
    obd_ph_func:'Describe functional characteristics',
    obd_2_1_lbl:'2.1. DTC Read Function',
    obd_2_2_lbl:'2.2. Readiness Monitor Status',
    obd_2_3_lbl:'2.3. Freeze Frame Data Support',
    obd_2_4_lbl:'2.4. DTC Clear Function',
    obd_2_5_lbl:'2.5. Diagnostic Communication Protocol',
    obd_th_item2:'Item',
    obd_th_content2:'Content',
    obd_th_support:'Support',
    obd_val_support:'Supported',
    obd_val_nosupport:'Not Supported',
    obd_ph_yn:'Yes/No',
    obd_ph_protocol:'Describe communication protocol',
    em_doc_tag:'[Annex 18-2]',
    em_sec1:'1. General Information',
    em_sec2:'2. Test Vehicle Specifications',
    em_sec3:'3. Test Vehicle Engine Specs',
    em_sec4:'4. Test Equipment',
    em_th_test_div:'Test Category',
    em_val_dur:'Durability Test',
    em_val_emis:'Emission Test',
    em_val_insp:'Regular Inspection',
    em_val_etc:'Other',
    em_lbl_cvs:'CVS Device',
    em_lbl_analyzer:'Analyzer',
    em_lbl_chassis:'Chassis Dynamometer',
    em_lbl_eng_type:'Engine Type',
    em_lbl_total_cc:'Total Displacement(cc)',
    em_lbl_comp_ratio:'Compression Ratio',
    em_lbl_max_power:'Max Power(ps/rpm)',
    em_lbl_fuel_supply:'Fuel Supply System',
    em_lbl_cooling:'Cooling System',
    em_lbl_ignition:'Ignition System',
    em_lbl_valves:'No. of Valves',
    em_lbl_cc_per_cyl:'Displacement(cc/cyl)',
    em_lbl_cylinders:'No. of Cylinders',
    em_lbl_maker_model:'Manufacturer & Model',
    em_lbl_range:'Measurement Range',
    em_lbl_maker2:'Manufacturer',
    em_lbl_model2:'Model Name',
    em_lbl_max_abs:'Max Absorption(kW)',
    em_lbl_inertia:'Inertia Weight(kg)',
    ev_doc_tag:'[Annex 23]',
    ev_attach_title:'Attachments (Self-test Report / RAW DATA)',
    ev_attach_note:'Upload JPG, PNG or PDF. Attachments will not be printed.',
    oo_doc_tag:'[Annex 26]',
    oo_th_trans_type:'Transmission Type',
    oo_ph_type_maker:'Type / Manufacturer',
    nt_doc_tag:'[Annex 27 to 27-2]',
    nt_test_date_lbl:'2. Test Date :',
    nt_na:'N/A',
    nt_accel_noise_meas:'Acceleration Noise<br>Measurement',
    cf_maker_lbl:'1. Manufacturer :',
    cf_addr_lbl:'2. Address :',
    cf_model_lbl:'3. Model :',
    cf_importer_lbl:'4. Importer :',
    g_ph_maker:'e.g. PIAGGIO C.S.P.A(Italy)',
    g_ph_model:'e.g. RSV4 1000 RR',
    g_ph_fuel:'e.g. Gasoline, Diesel, LPG',
    g_ph_euro5:'e.g. EURO 5',
    g_ph_ece_noise:'e.g. ECE R41-04',
    g_ph_rep_nonrep:'Rep/Non-rep',
    g_ph_cert_id:'e.g. ABC-123',
    g_ph_warranty_yr:'year',
    g_ph_self_test:'e.g. OBD, Noise, Evap',
    g_ph_key_tech:'e.g. O2 sensor, TWC, OBD, ECU, Idle control, EFI',
    g_category:'Category',
    dp_valve_close:'Close',
    dp_valve_per_cyl:'Valves per Cylinder',
    dp_valve_intake:'Intake',
    dp_valve_exhaust:'Exhaust',
    dp_valve_size:'Valve Size',
    dp_air_intake_type:'Air Intake Type',
    dp_type:'Type',
    dp_noble_metal:'Precious Metal',
    dp_noble_metal_g:'Precious Metal (g)',
    dp_capacity_cc:'Capacity (cc)',
    dp_noble_ratio:'Noble Metal Ratio (Pt:Pd:Rh)',
    dp_10_1_crank_cam_lbl:'Distance from crankshaft centerline to camshaft centerline (mm)',
    dp_10_1_crank_head_lbl:'Distance from crankshaft centerline to cylinder block head top (mm)',
    dp_10_1_tdc_lbl:'Combustion chamber surface area/volume ratio at TDC',
    dp_10_1_fuel_supply_lbl:'Fuel supply method',
    dp_10_1_inj_range_lbl:'Injection timing control range',
    dp_10_1_cam_timing_lbl:'Camshaft timing',
    dp_10_1_inertia_lbl:'Equivalent inertia mass',
    dp_10_1_roadload_lbl:'Road load power',
    dp_10_2_title:'10.2. Evap. Same-type Vehicle Description',
    dp_10_2_category:'Category',
    dp_10_2_base:'Base Vehicle',
    dp_10_2_same:'Evap. Same-type Vehicle',
    dp_10_2_certno_lbl:'Emission Cert. No.',
    dp_10_2_carname_lbl:'Vehicle Name',
    dp_10_2_type_lbl:'Vehicle Type',
    dp_10_2_eng_lbl:'Engine Type',
    dp_10_2_cartype_lbl:'Vehicle Class',
    dp_10_2_fuel_lbl:'Fuel Type',
    dp_10_2_evap_type_lbl:'Evap. Storage Type',
    dp_canister_design:'Canister Design Characteristics',
    dp_canister_capacity:'Evap. Absorption Capacity',
    dp_canister_count:'Canister Count & Connection',
    dp_canister_shape:'Canister Shape',
    dp_canister_struct:'Canister Structure',
    dp_canister_mat:'Canister Material',
    dp_fuel_system:'Fuel System',
    dp_filler_seal:'Filler Sealed Structure',
    dp_10_2_ctrl_lbl:'Evap. Control System',
    dp_10_2_purge_lbl:'Purge Control System',
    dp_10_2_hose_mat_lbl:'Evap. Hose Material',
    dp_10_2_tank_mat_lbl:'Fuel Tank Material',
    dp_10_3_title:'10.3. OBD Same-type Vehicle Description',
    dp_10_3_category:'Category',
    dp_10_3_base:'Base Vehicle',
    dp_10_3_same:'OBD Same-type Vehicle',
    dp_10_3_certno_lbl:'Emission Cert. No.',
    dp_10_3_carname_lbl:'Vehicle Name',
    dp_10_3_type_lbl:'Vehicle Type',
    dp_10_3_eng_lbl:'Engine Type',
    dp_10_3_cartype_lbl:'Vehicle Class',
    dp_10_3_fuel_lbl:'Fuel Type',
    dp_10_3_obd_op_lbl:'OBD Operation Method',
    dp_10_3_std_lbl:'Emission Limit Standard',
    dp_10_3_cycle_lbl:'Combustion Cycle',
    dp_10_3_fuel_supply_lbl:'Fuel Supply Method',
    dp_10_3_cat_lbl:'Catalyst Type',
    dp_10_3_dpf_lbl:'DPF Type',
    dp_10_3_air2_lbl:'Secondary Air Injection',
    dp_10_3_egr_lbl:'EGR Device',
    dp_11_1_title:'11.1. Test Vehicle Selection',
    dp_11_1_category:'Category',
    dp_11_1_dur:'Durability Test Vehicle',
    dp_11_1_emis:'Emission Test Vehicle',
    dp_11_1_vin_lbl:'VIN (Engine No.)',
    dp_11_1_disp_lbl:'Displacement (cc)',
    dp_11_1_eng_code_lbl:'Engine Code',
    dp_11_1_evap_code_lbl:'Evap. Code',
    dp_11_1_cat_code_lbl:'Catalyst Code',
    dp_11_1_emis_ctrl:'Emission Control Device',
    dp_11_1_emis_gas:'Emission Gas',
    dp_11_1_model_lbl:'Model Name',
    dp_11_1_trans_lbl:'Transmission Type',
    dp_11_1_trans_proc_lbl:'Shift Procedure',
    dp_11_1_inertia_lbl:'Equivalent Inertia (kg)',
    dp_11_1_final_red_lbl:'Final Reduction',
    dp_11_1_nv_lbl:'N/V Ratio, RPM/KPH',
    dp_11_1_tire_lbl:'Tires',
    dp_11_1_note_lbl:'Remarks',
    dp_11_1_sub_hdr_ph:'Vehicle Type',
    dp_11_1_sub_name_lbl:'Vehicle Name',
    dp_11_1_sub_type_lbl:'Vehicle Type',
    dp_11_1_sub_trans_lbl:'Transmission',
    dp_11_1_sub_eng_lbl:'Engine Type',
    dp_11_1_sub_disp_lbl:'Displacement',
    dp_11_1_sub_weight_lbl:'Curb Weight',
    dp_11_1_sub_inertia_lbl:'Equiv. Inertia',
    dp_11_1_sub_roadload_lbl:'Road Load Power',
    dp_11_1_sub_tankvol_lbl:'Fuel Tank Volume',
    dp_11_1_sub_finalred_lbl:'Final Reduction Ratio',
    dp_11_1_sub_sales_lbl:'Units Sold',
    dp_11_2_title:'11.2. Durability Test Vehicle Selection',
    dp_11_2_sel_lbl:'Durability Test Vehicle Selection',
    dp_11_2_note_ph:'Describe durability test vehicle selection',
    dp_11_3_title:'11.3. Emission Test Vehicle Selection',
    dp_11_3_a_case:'A. Using chassis dynamometer:',
    dp_11_3_a_0_lbl:'Highest equivalent inertia among same-type vehicles',
    dp_11_3_a_1_lbl:'Highest road load within above conditions',
    dp_11_3_a_2_lbl:'Largest displacement within above conditions',
    dp_11_3_a_3_lbl:'Highest final gear ratio transmission within above conditions',
    dp_11_3_a_4_lbl:'Largest fuel tank capacity within above conditions',
    dp_11_3_b_case:'B. Using engine dynamometer:',
    dp_11_3_b_0_lbl:'Engine with highest fuel distribution per stroke at max torque speed',
    dp_11_3_b_1_lbl:'Engine with highest fuel distribution per stroke at max speed',
    dp_11_4_title:'11.4. Noise Test Vehicle Selection',
    dp_11_4_0_lbl:'Heaviest curb weight vehicle',
    dp_11_4_1_lbl:'Largest displacement vehicle',
    dp_11_4_2_lbl:'Vehicle with highest final gear ratio (including overdrive)',
    dp_11_4_3_lbl:'Vehicle with highest axle ratio',
    dp_12_ph:'State unavoidable reason',
    dp_13_ph:'Other matters',
    en_tank_pos_sec:'4.3.1.2. Fuel Tank Location',
    en_tank_pos_ph:'Location description',
    en_tank_shape_sec:'4.3.1.3. Fuel Tank Shape',
    en_tank_shape_ph:'Shape description',
    en_throttle_sec:'4.3.2. Throttle Body',
    en_throttle_spec_sec:'4.3.2.1. Throttle Body Specifications',
    en_throttle_spec_ph:'Throttle body specifications',
    en_throttle_dim_sec:'4.3.2.2. Throttle Body Dimensions',
    en_injector_sec:'4.3.3. Fuel Injector',
    en_injector_spec_sec:'4.3.3.1. Fuel Injector Specifications',
    en_injector_spec_ph:'Fuel injector specifications',
    en_injector_dim_sec:'4.3.3.2. Fuel Injector Dimensions',
    en_pump_sec:'4.3.4. Fuel Pump',
    en_pump_spec_sec:'4.3.4.1. Fuel Pump Specifications',
    en_pump_spec_ph:'Fuel pump specifications',
    en_pump_dim_sec:'4.3.4.2. Fuel Pump Dimensions',
    en_fuel_photo_sec:'4.4. Fuel System Photos',
    en_fuel_photo_ph:'Fuel system photo description',
    en_intake_sec:'5. Intake/Exhaust System',
    en_intake_sub:'5.1. Intake System',
    en_intake_diagram_sec:'5.1.1. Intake Manifold Diagram',
    en_intake_diagram_ph:'Intake manifold diagram description',
    en_intake_manifold_sec:'5.1.2. Intake Manifold',
    en_intake_manifold_ph:'Intake manifold spec or description',
    en_air_filter_sec:'5.1.3. Air Filter',
    en_air_filter_ph:'Air filter spec or description',
    en_exhaust_sub:'5.2. Exhaust System',
    en_exhaust_diagram_sec:'5.2.1. Exhaust Manifold Diagram',
    en_exhaust_diagram_ph:'Exhaust manifold diagram description',
    en_exhaust_manifold_sec:'5.2.2. Exhaust Manifold',
    en_exhaust_manifold_ph:'Exhaust manifold spec or description',
    en_veh_sec:'6. Vehicle Exterior & Dimensions',
    en_veh_photo_sub:'6.1. Vehicle Photos',
    en_veh_front_sec:'6.1.1. Front View',
    en_veh_front_ph:'Front view description',
    en_veh_rear_sec:'6.1.2. Rear View',
    en_veh_rear_ph:'Rear view description',
    en_veh_side_sec:'6.1.3. Side View',
    en_veh_side_ph:'Side view description',
    en_veh_top_sec:'6.1.4. Top View',
    en_veh_top_ph:'Top view description',
    en_ext_sub:'6.2. Exterior Drawing',
    en_ext_side_sec:'6.2.1. Exterior Side View',
    en_ext_side_ph:'Exterior side view description',
    en_ext_top_sec:'6.2.2. Exterior Top View',
    en_ext_top_ph:'Exterior top view description',
    en_ext_rear_sec:'6.2.3. Exterior Rear View',
    en_ext_rear_ph:'Exterior rear view description',
    en_other_sec:'7. Other',
    en_other_tech_sub:'7.1. Other Emission/Noise Reduction Technologies',
    en_other_tech_ph:'Describe other emission and noise reduction technologies',
    obd_y:'Yes',
    obd_n:'No',
    obd_ph_max_power:'Max Power',
    obd_ph_trans:'Transmission (gear)',
    obd_ph_combustion:'e.g. Spark ignition, 4-stroke',
    obd_ph_fuel_supply:'e.g. Fuel injection (EFI)',
    obd_ph_cat_type:'e.g. Three-way catalyst',
    obd_ph_yn:'Yes / No',
    obd_nv_lbl:'N/V ratio, rpm/kph',
    obd_nv_ph:'N/V ratio, rpm/kph',
    obd_tire_lbl:'Tires',
    obd_tire_f_lbl:'Front',
    obd_tire_f_ph:'Front tire spec',
    obd_tire_r_lbl:'Rear',
    obd_tire_r_ph:'Rear tire spec',
    obd_cat_lbl:'Catalyst Converter Type',
    obd_cat_ph:'Catalyst converter type',
    obd_dpf_lbl:'DPF Type',
    obd_air2_lbl:'Secondary Air Injection Device',
    obd_egr_lbl2:'EGR Device',
    obd_evap_lbl:'Evap. Control Device',
    obd_evap_ph:'Evap. control device',
    obd_obd_func_lbl:'OBD Composition & Function',
    obd_obd_op_lbl:'OBD Operation Method',
    obd_obd_check_lbl:'OBD Malfunction Verification Method',
    obd_obd_check_ph:'Malfunction verification method',
    obd_mi_lbl:'Malfunction Indication Method',
    obd_monitor_ph:'Enter monitoring items',
    obd_note_ph:'Remarks',
    obd_photo_title:'OBD Test Photos: Include vehicle, VIN, engine number photos',
    obd_veh_photo_lbl:'Vehicle Photo',
    obd_veh_photo_desc:'Full vehicle photo (front/side/rear)',
    obd_vin_photo_lbl:'VIN Photo',
    obd_vin_photo_desc:'VIN confirmation photo',
    obd_eng_photo_lbl:'Engine No. Photo',
    obd_eng_photo_desc:'Engine number confirmation photo',
    obd_scanner_photo_lbl:'OBD Scanner Photo',
    obd_scanner_photo_desc:'OBD scanner connection and result screen photos (multiple allowed)',
    obd_attach_title:'Attachments (Self-test Report / RAW DATA)',
    upload_click_drag:'Click or drag files to upload',
    em_item_hdr:'Item',
    em_fuel_eff_hdr:'Fuel Eff. (km/ℓ)',
    em_std_lbl:'Standard',
    ev_gen_info_hdr:'1. General Information',
    obd_air2_y_lbl:'Yes',
    obd_air2_n_lbl:'No',
    obd_egr_y_lbl:'Yes',
    obd_egr_n_lbl:'No',
    nt_reg_note_ph:'e.g. Acceleration noise test (ECE R41-04)',
    nt_test_date_ph:'e.g. 2025. 01. 01.',
    nt_inspector_ph:'Name',
    cf_maker_ph:'e.g. HONDA Motor Co.,Ltd (Japan)',
    cf_model_ph:'e.g. CB500F',
    cf_importer_ph:'e.g. ○○ Motors Co.,Ltd',
    cf_warranty_subject_ph:'Warranty issuer name',
    cf_warranty_text1:'shall comply with Article 46, 48, 50, 51 of the Clean Air Conservation Act',
    cf_warranty_text2:'within the warranty period (≤130km/h: 2yr/20,000km; >130km/h: 2yr/35,000km)',
    cf_warranty_text3:'to meet emission standards for new and in-use vehicles,',
    cf_warranty_text4:'and perform recall obligations if defects are confirmed.',
    cf_warranty_confirm:'We confirm that we will fulfill the above warranty obligations.',
    cf_signed_at_ph:'Signing location',
    cf_sign_date_ph:'e.g. 2025. 01. 01.',
    cf_name_ph:'Signer name',
    cf_title_ph:'Position',
    attach_dl_title:'Download',
    attach_del_title:'Delete',
    lbl_address:'2. Address:',
    lbl_model_lbl:'3. Model:',
    lbl_warranty_content:'5. Warranty Content:',
    nt_attach_title:'Attachments (Self-test Report / RAW DATA)',
    nt_inspector_ph2:'Name',
dp_s8_1:'8.1. Fuel System',
    dp_s8_2:'8.2. Intake/Exhaust',
    dp_s8_3:'8.3. Ignition',
    dp_s8_4:'8.4. Crankcase Control',
    dp_s8_5:'8.5. Engine',
    dp_s8_6:'8.6. Catalytic Converter',
    dp_s8_7:'8.7. EGR',
    dp_s8_8:'8.8. Electronic Control',
    dp_s8_9:'8.9. Other Emission Control',
    dp_8_1_0:'Fuel Supply', dp_8_1_1:'Fuel Control', dp_8_1_2:'Fuel Injection',
    dp_8_2_0:'Intake', dp_8_2_1:'Exhaust',
    dp_8_3_0:'Ignition',
    dp_8_4_0:'Crankcase Control',
    dp_8_5_0:'Engine',
    dp_8_6_0:'Catalyst Type', dp_8_6_1:'Catalyst Composition', dp_8_6_2:'Volume', dp_8_6_3:'Catalyst Weight',
    dp_8_7_0:'EGR Device',
    dp_8_8_0:'Device/Spec/I-O Signal', dp_8_8_1:'Engine Torque Calculation & Compliance',
    dp_8_9_0:'Other Device',
    dp_5_4_lbl:'5.4. Noise Test Plan',
g_obd_std2_rep_lbl:'* OBD2 Gasoline (IUPR 1st) Same, Rep. Vehicle:',
    g_obd_std4_rep_lbl:'* OBD2 Gasoline EURO6 (IUPR 2nd) Same, Rep. Vehicle:',
    g_obd_std_die_rep_lbl:'* OBD2 Diesel (c) (IUPR 2nd) Same, Rep. Vehicle:',
    g_evap_same_rep_lbl:'* Evap. Same, Rep. Vehicle:',
img_click_to_zoom:'Click to zoom',
    pw_err_required:'Please fill in all fields.',
    pw_err_too_short:'New password must be at least 4 characters.',
    pw_err_mismatch:'New passwords do not match.',
    err_occurred:'An error occurred.',
    err_network:'Network error occurred.',
    btn_processing:'Processing...',
    btn_change:'Change',
    pw_changed_ok:'Password changed successfully.',
    cf_ph_address:'Manufacturer Address',
    cf_ph_phone:'Phone Number',
    cf_ph_fax:'Fax Number',
    msg_popup_blocked:'Popup is blocked. Please allow popups and try again.',
    msg_qr_generating:'Generating verification code...',
    msg_network_error:'Network error',
    dp_ph_year_ex:'e.g. 2025',
    dp_ph_disp_ex:'e.g. 125cc',
    dp_lbl_count:'Count',
    dp_lbl_gear2:'2nd',
    dp_lbl_gear3:'3rd',
    dp_lbl_gear4:'4th',
    dp_lbl_gear5:'5th',
    dp_lbl_gear6:'6th',
    dp_lbl_gear7:'7th',
    dp_lbl_nv_ratio:'N/V Ratio',
    dp_lbl_rear:'Rear',
    dp_lbl_category:'Category',
    dp_lbl_item:'Item',
    dp_lbl_car_name:'Vehicle Name',
    dp_lbl_car_type:'Vehicle Type',
    dp_lbl_passenger:'Passengers',
    dp_lbl_model_year:'Model Year',
    dp_lbl_spec_no:'Spec No.',
    dp_lbl_drive:'Drive Type',
    dp_lbl_car_class:'Vehicle Class',
    dp_lbl_purpose:'Purpose',
    dp_lbl_trans_type:'Transmission Type',
    dp_lbl_body_shape:'Body Shape',
    dp_lbl_curb_wt:'Curb Weight(kg)',
    dp_lbl_gvw:'GVW(kg)',
    dp_lbl_inertia_wt:'Equiv. Inertia Wt(kg)',
    dp_lbl_dyno_hp:'Actual Dyno Power(hp)',
    dp_lbl_dimensions:'Dimensions',
    dp_lbl_length:'Length(mm)',
    dp_lbl_width:'Width(mm)',
    dp_lbl_height:'Height(mm)',
    dp_lbl_manufacturer:'Manufacturer',
    dp_lbl_combustion:'Combustion Type',
    dp_lbl_eng_type:'Engine Type',
    dp_lbl_displacement:'Displacement(cc)',
    dp_lbl_eng_pos:'Engine Position',
    dp_lbl_fuel_type:'Fuel Type',
    dp_lbl_cyl_count:'No. of Cylinders',
    dp_lbl_cyl_arr:'Cylinder Arrangement',
    dp_lbl_chamber_type:'Chamber Type',
    dp_lbl_max_power:'Max Power(ps/rpm)',
    dp_lbl_max_torque:'Max Torque(kg-m/rpm)',
    dp_lbl_bore_stroke:'Bore*Stroke(mm)',
    dp_lbl_idle_rpm:'Idle Speed(rpm)',
    dp_lbl_intake_method:'Air Intake Method',
    dp_lbl_port_size:'Port Size',
    dp_lbl_port_size_mm:'Port Size(mm)',
    dp_lbl_port_shape:'Port Shape',
    dp_lbl_ign_timing:'Ignition Timing(Degree)',
    dp_lbl_fuel_tank:'Fuel Tank',
    dp_lbl_capacity_l:'Capacity(ℓ)',
    dp_lbl_position:'Position',
    dp_lbl_material:'Material',
    dp_lbl_air_cleaner:'Air Cleaner',
    dp_lbl_form_type:'Type',
    dp_lbl_drivetrain:'Drivetrain',
    dp_lbl_clutch:'Clutch',
    dp_lbl_operation:'Operation',
    dp_lbl_gear_ratio:'Gear Ratio',
    dp_lbl_gear_1:'1st',
    dp_lbl_forward:'Forward',
    dp_lbl_reverse:'Reverse',
    dp_lbl_red_ratio:'Reduction Ratio',
    dp_lbl_red1:'1st Reduction Ratio',
    dp_lbl_red2:'2nd Reduction Ratio',
    dp_lbl_ev_spec:'EV Specifications',
    dp_lbl_motor_type:'Motor Type',
    dp_lbl_batt_cap:'Battery Rated Voltage & Capacity',
    dp_lbl_motor_power:'Motor Max Power',
    dp_lbl_ev_range:'Single Charge Range',
    dp_lbl_tire:'Tire',
    dp_lbl_tire_maker:'Tire Manufacturer',
    dp_lbl_tire_struct:'Tire Structure',
    dp_lbl_tire_size:'Tire Size',
    dp_lbl_front:'Front',
    dp_lbl_tire_pres:'Tire Pressure',
    dp_lbl_precious_comp:'Precious Metal Composition',
    dp_lbl_precious_g:'Precious Metal Amount(g)',
    dp_lbl_vol_cc:'Volume(cc)',
    dp_lbl_pm_ratio:'Precious Metal Ratio(Pt:Pd:Rh)',
    dp_lbl_em_test_info:'Emission Test Info',
    dp_lbl_road_load:'Road Load(hp)',
    dp_lbl_road_coef:'Road Load Coeff.',
    dp_lbl_coast_down:'Coast Down Time(sec)',
    dp_lbl_canister:'Canister',
    dp_lbl_can_cap:'Canister Absorption Capacity',
    dp_lbl_can_size:'Canister Size(cc)',
    dp_lbl_can_media:'Canister Media',
    dp_lbl_evap_cap:'Max Evap Cap @ 40% Fuel',
    dp_lbl_muffler:'Muffler',
    dp_lbl_muf_main:'Main Muffler',
    dp_lbl_muf_sub:'Sub Muffler',
    dp_lbl_vol_l:'Volume(L)',
    dp_lbl_horn_dev:'Warning Device',
    dp_lbl_horn:'Horn',
    dp_lbl_horn_db:'Performance(dB(C))',
    dp_lbl_ignition:'Ignition',
    dp_lbl_chassis:'Chassis',
    dp_lbl_other:'Other',
    dp_lbl_remark:'Remark',
    dp_lbl_left:'Left',
    dp_lbl_right:'Right',
    dp_lbl_compress_ratio:'Compression Ratio',
    dp_lbl_car_spec:'Vehicle Specifications',
    dp_lbl_fuel_system:'Fuel System',
    dp_lbl_type_kind:'Type',
    dp_lbl_test_fuel:'Test Fuel',
    dp_lbl_acc_fuel:'Mileage Accumulation Fuel',
    dp_lbl_gasoline:'Gasoline',
    dp_lbl_octane:'Octane No.(Research)',
    dp_lbl_aromatic:'Aromatic Content(vol%)',
    dp_lbl_benzene:'Benzene Content(vol%)',
    dp_lbl_oxygen:'Oxygen Content(wt%)',
    dp_lbl_lead:'Lead Content(g/ℓ)',
    dp_lbl_phosphorus:'Phosphorus Content(g/ℓ)',
    dp_lbl_olefin:'Olefin Content(vol%)',
    dp_lbl_vapor_p:'Vapor Pressure(kPa)',
    dp_lbl_90pct_temp:'90% Distillation Temp(℃)',
    dp_lbl_sulfur:'Sulfur Content(wt%)',
    dp_lbl_diesel:'Diesel',
    dp_lbl_residual_carbon:'10% Residual Carbon(%)',
    dp_lbl_cetane:'Cetane Index',
    dp_lbl_fuel_source:'Fuel Source',
    dp_fuel_note:'Note: Certification test fuel shall in principle be commercially available fuel; items meeting automobile fuel standards under Air Quality Rules Schedule 30 may be substituted.',
    dp_4_1_title:'4.1. Emission Test Equipment',
    dp_4_2_title:'4.2. Noise Test Equipment',
    dp_th_equip_name:'Equipment Name',
    dp_th_model:'Model',
    dp_th_type_no:'Type Approval No.',
    dp_th_type_date:'Type Approval Date',
    dp_th_lab_name:'Lab Name',
    dp_th_calib_date:'Last Calibration Date',
    dp_equip_note:'Note: For foreign-manufactured equipment, authorized certification or approval numbers from the respective country may be entered in lieu of the type approval number.',
    dp_5_1_2_lbl:'5.1.2. Test Procedure',
    dp_5_2_2_lbl:'5.2.2. Break-in Drive',
    dp_5_2_4_lbl:'5.2.4. Drive Location',
    dp_5_3_2_lbl:'5.3.2. Test Procedure',
    dp_5_4_2_lbl:'5.4.2. Test Procedure',
    dp_6_1_title:'6.1. Test Vehicle Maintenance Plan',
    dp_6_1_1_title:'6.1.1. Scheduled Maintenance',
    dp_6_1_2_title:'6.1.2. Unscheduled Maintenance',
    dp_6_2_title:'6.2. Recommended Maintenance for Buyers',
    dp_6_3_title:'6.3. Warranty Description',
    dp_6_3_1_lbl:'Warranty Content',
    dp_6_3_2_lbl:'Warranty Period',
    dp_6_3_3_lbl:'Warranty Exclusions',
    dp_6_3_4_lbl:'Owner Obligations',
    dp_1_3_title:'1.3. Development Target (Imported: Foreign Cert. Records)',
    dp_1_4_title:'Certification Vehicle Specifications',
    dp_1_3_r0:'Standard Limit',
    dp_1_3_r1:'Dev. Target Value',
    dp_1_3_r2:'Current Std. Compliance(%)',
    dp_th_formaldehyde:'Formaldehyde(g/km)',
    dp_th_smoke:'Smoke(%/kWh)',
    dp_2_1_title:'2.1. Confidentiality Request',
    dp_8_10_title:'8.10. Sensing vs. Control Variables',
    dp_8_11_title:'8.11. Parts List',
    dp_8_12_title:'8.12. SCR Performance & Principle',
    dp_8_13_title:'8.13. SCR Urea Solution Analysis',
    dp_8_14_title:'8.14. EV Control System',
    dp_8_11_ign:'Ignition System',
    dp_8_11_fuel:'Fuel Supply System',
    dp_8_11_cat:'Emission Converter',
    dp_8_11_egr:'EGR System',
    dp_8_11_evap:'Evap. Control System',
    dp_8_11_blow:'Blowby Gas Reduction',
    dp_8_11_air:'Secondary Air Injection',
    dp_8_12_r0:'Supply System',
    dp_8_12_r1:'Control System',
    dp_8_12_r2:'Injection System',
    dp_8_12_r3:'Refill Warning System',
    dp_th_analysis_result:'Analysis Result',
    dp_th_analysis_org:'Analysis Organization',
    dp_th_analysis_method:'Analysis Method',
    dp_th_analysis_date:'Analysis Date',
    dp_th_proof_no:'Proof No.',
    dp_sv_o2:'O2 in Exhaust',
    dp_sv_air_flow:'Intake Air Flow',
    dp_sv_air_temp:'Intake Air Temp.',
    dp_sv_coolant:'Coolant Temp.',
    dp_sv_throttle:'Throttle Position',
    dp_sv_baro:'Barometric Pressure',
    dp_sv_intake_vac:'Intake Vacuum',
    dp_sv_crank:'Crankshaft Position',
    dp_sv_cam:'Cam Shaft Position',
    dp_sv_batt:'Battery Voltage',
    dp_sv_speed:'Vehicle Speed',
    dp_sv_rpm:'Engine RPM',
    dp_sv_gear:'Transmission Gear',
    dp_sv_idle:'Stop & Neutral',
    dp_sv_brake:'Brake Applied',
    dp_sv_ac:'A/C Operation',
    dp_sv_knock:'Engine Knock',
    dp_9_1_title:'9.1. Evap. Control System Description',
    dp_th_storage:'Storage Device',
    dp_th_absorb_cap:'Absorb Capacity(C)',
    dp_th_size_media:'Size(cc)/Media',
    dp_9_1_r0:'Canister',
    dp_9_1_r1:'Air Cleaner',
    dp_9_1_r2:'Crankcase',
    dp_9_1_r3:'Other',
    dp_9_2_title:'9.2. Control System Diagram',
    dp_9_2_parts_title:'Evap. Control System Parts List (incl. auxiliary)',
    dp_10_1_title:'10.1. Emission & Noise Equivalent Model Description',
    dp_10_1_cyl_dist_lbl:'Cylinder Bore Center Distance(mm)',
    dp_10_1_block_lbl:'Cylinder Block Shape',
    dp_10_1_head_lbl:'Cylinder Head Type',
    dp_durability_note:'When conducting durability tests, if unavoidable circumstances prevent items from being recorded in the initial application, the reason shall be stated and confirmed items may be submitted together with the final durability test report.',
    dp_ph_dev_bg:'Enter development background & characteristics',
    dp_ph_new_tech:'Enter new technology content',
    dp_ph_confidential:'Enter confidentiality request content',
    dp_ph_engine_content:'Engine details',
    dp_ph_ignition_content:'Ignition system details',
    dp_ph_chassis_content:'Chassis details',
    dp_ph_other_content:'Other details',
    dp_ph_warranty_content:'Warranty content',
    dp_ph_warranty_period:'Warranty period',
    dp_ph_warranty_exclusion:'Warranty exclusions',
    dp_ph_owner_duty:'Owner obligations',
    dp_ph_sign_desc:'Sign sample description',
    dp_ph_attach_pos:'Describe attachment position etc.',
    dp_ph_motor_ctrl:'Motor & motor controller description',
    dp_ph_batt_ctrl:'Battery & battery controller description',
    dp_ph_ctrl_diagram:'Control system diagram description',
    dp_ph_em_detail:'submission history etc.',
    dp_lbl_diagram_attach:'{sec} Diagram Attach:',
    obd_dtc_default_val:'If a fault code is detected in the motorcycle,',
    obd_lbl_2nd_monitor_suffix:'and other comprehensive description including methods',
    obd_lbl_ctrl_dev:'Control Device',
    obd_lbl_diag_config:'OBD Configuration',
    msg_coming_soon:'Coming soon.',
    msg_qr_login_check:'Please verify your login status to generate QR code.',
    msg_qr_fail:'QR generation failed',
    btn_saving:'Saving...',
    msg_saved:'Saved successfully.',
    msg_save_fail:'Save failed',
    btn_save:'Save',
    btn_list:'List', btn_toc_print:'Print TOC',
    complete_title:'Document completed', complete_sub:'Check to reflect in progress',
    nt_rpm_unit:'% Rotational Speed (rpm)',
    btn_create_app:'Create Application',
    err_title_required:'Please enter the application title.',
    err_cert_no_required:'Please enter the existing certification number.',
    btn_creating:'Creating...',
    msg_create_fail:'Creation failed',
    msg_app_created:'Application has been created.',
    msg_delete_confirm:'Deleting the application will also delete all document data.\\nContinue?',
    msg_deleted:'Deleted.',
    msg_delete_fail:'Delete failed',
    pw_lbl_current:'Current Password',
    pw_ph_current:'Enter current password',
    pw_lbl_new:'New Password',
    pw_ph_new:'4+ characters',
    pw_lbl_confirm:'Confirm New Password',
    pw_ph_confirm:'Re-enter',
    
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
    g_doc_tag:'[別紙第2号様式]',
    g_sec1:'1. 申請概要', g_sec2:'2. 申請類型', g_sec3:'3. 詳細内訳',
    g_th_div:'区分', g_th_apply_date:'申請日', g_th_maker:'製造社',
    g_th_model:'車名<br>(形式)', g_th_fuel_type:'車種<br>(使用燃料)',
    g_th_output:'出力(ps/rpm)<br>(排気量 cc)', g_th_std:'適用基準',
    g_th_cert_no:'認証番号', g_th_note:'備考',
    g_th_div2:'区分', g_th_fuel:'燃料', g_th_cert_content:'認証書記載内容', g_th_applicable:'該当有無',
    g_cat_emission:'排出基準', g_cat_obd:'OBD基準', g_cat_evap:'蒸発ガス', g_cat_warranty:'保証期間',
    g_fuel_gasoline:'ガソリン', g_fuel_diesel:'軽油',
    g_emit_colon:'排出 :', g_noise_colon:'騒音 :',
    sv_applicable:'該当有無',
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
    en_muffler_diagram_title:'1.2 マフラー内部構造図',
    en_muffler_spec_title:'1.3 消音器詳細諸元',
    en_1_3_1:'構造及び騒音低減原理', en_1_3_2:'フロー図', en_1_3_3:'製造社',
    en_1_3_4:'内外部材質', en_1_3_5:'寸法図面',
    en_cat_spec_title:'1.4 触媒装置詳細諸元',
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
    nt_tire_pres_kpa:'タイヤ空気圧力(kPa)',
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
    btn_write:'編集', btn_delete:'削除', btn_cancel:'キャンセル', btn_edit_appl:'情報修正', btn_logout:'ログアウト',
    modal_edit_title:'申請書情報の修正', btn_update_appl:'修正完了', msg_update_ok:'申請書情報が修正されました。', msg_update_fail:'修正に失敗しました。',
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
    dp_1_2_lbl:'1.2. 排気ガス関連新技術または主要技術',
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

    en_4_3_1_2:'4.3.1.2. 燃料タンク位置', en_tank_pos_ph:'位置の説明',
    en_4_3_1_3:'4.3.1.3. 燃料タンク形状', en_tank_shape_ph:'形状の説明',
    en_4_3_2:'4.3.2. スロットルボディ',
    en_4_3_2_1:'4.3.2.1. スロットルボディ仕様', en_throttle_spec_ph:'スロットルボディ仕様',
    en_4_3_2_2:'4.3.2.2. スロットルボディ形状・寸法',
    en_4_3_3:'4.3.3. 燃料インジェクター',
    en_4_3_3_1:'4.3.3.1. 燃料インジェクター仕様', en_injector_spec_ph:'燃料インジェクター仕様',
    en_4_3_3_2:'4.3.3.2. 燃料インジェクター形状・寸法',
    en_4_3_4:'4.3.4. 燃料ポンプ',
    en_4_3_4_1:'4.3.4.1. 燃料ポンプ仕様', en_pump_spec_ph:'燃料ポンプ仕様',
    en_4_3_4_2:'4.3.4.2. 燃料ポンプ形状・寸法',
    en_4_4_fuel_photo:'4.4. 燃料系統写真', en_fuel_photo_ph:'燃料系統写真の説明',
    en_sec5:'5. 吸排気装置', en_5_1:'5.1. 吸気系統',
    en_5_1_1:'5.1.1. 吸気マニホールド構成図', en_intake_diagram_ph:'吸気マニホールドの説明',
    en_5_1_2:'5.1.2. 吸気マニホールド', en_intake_manifold_ph:'吸気マニホールド仕様または説明',
    en_5_1_3:'5.1.3. エアフィルター', en_air_filter_ph:'エアフィルター仕様または説明',
    en_5_2:'5.2. 排気系統',
    en_5_2_1:'5.2.1. 排気マニホールド構成図', en_exhaust_diagram_ph:'排気マニホールドの説明',
    en_5_2_2:'5.2.2. 排気マニホールド', en_exhaust_manifold_ph:'排気マニホールド仕様または説明',
    en_sec6:'6. 車両外観・寸法', en_6_1:'6.1. 車両写真',
    en_6_1_1:'6.1.1. 車両前面', en_veh_front_ph:'車両前面の説明',
    en_6_1_2:'6.1.2. 車両後面', en_veh_rear_ph:'車両後面の説明',
    en_6_1_3:'6.1.3. 車両側面', en_veh_side_ph:'車両側面の説明',
    en_6_1_4:'6.1.4. 車両上面', en_veh_top_ph:'車両上面の説明',
    en_6_2:'6.2. 外形図',
    en_6_2_1:'6.2.1. 外形側面', en_ext_side_ph:'外形側面の説明',
    en_6_2_2:'6.2.2. 外形上面', en_ext_top_ph:'外形上面の説明',
    en_6_2_3:'6.2.3. 外形後面', en_ext_rear_ph:'外形後面の説明',
    en_sec7:'7. その他', en_7_1:'7.1. その他排出ガス・騒音低減技術',
    en_other_tech_ph:'その他の排出ガス・騒音低減技術を記載してください',
    obd_yn_y:'有', obd_yn_n:'無',
    obd_max_power_ph:'最大出力', obd_trans_ph:'変速機（段）',
    obd_combustion_ph:'例) 火花点火、4ストローク', obd_fuel_supply_ph:'例) 燃料噴射式(EFI)',
    obd_cat_type_ph:'例) 三元触媒', obd_yn_ph:'有 / 無',
    obd_nv_lbl:'N/V比、rpm/kph', obd_tire_lbl:'タイヤ',
    obd_tire_f_lbl:'前', obd_tire_r_lbl:'後',
    obd_tire_f_ph:'前タイヤ規格', obd_tire_r_ph:'後タイヤ規格',
    obd_cat_type_lbl:'触媒コンバータの形式', obd_cat_type_sub:'(酸化触媒、三元触媒、加熱式触媒 等)',
    obd_dpf_lbl:'DPF形式', obd_egr_lbl:'EGRシステムの有無',
    obd_evap_lbl:'蒸発ガス制御装置', obd_evap_ph:'蒸発ガス制御装置',
    obd_diag_lbl:'OBDシステムの構成および機能',
    obd_diag_op_lbl:'OBDシステムの操作方法',
    obd_mi_check_lbl:'MIL故障確認方法', obd_mi_check_ph:'故障確認方法を入力',
    obd_mi_disp_lbl:'故障表示方法',
    obd_monitor_ph:'監視項目を入力', obd_note_ph:'備考',
    obd_photo_title:'OBD TESTの写真：車両写真、VIN写真、エンジン番号写真を含む',
    obd_veh_photo_lbl:'車両写真', obd_veh_photo_desc:'車両全体写真（前面/側面/後面を含む）',
    obd_vin_photo_lbl:'VIN写真', obd_vin_photo_desc:'VIN確認写真',
    obd_eng_photo_lbl:'エンジン番号写真', obd_eng_photo_desc:'エンジン番号確認写真',
    obd_scanner_photo_lbl:'OBDスキャナー写真', obd_scanner_photo_desc:'OBDスキャナー接続・結果画面写真（複数可）',
    obd_attach_title:'添付書類（自己試験成績書 / RAW DATA）',
    obd_upload_hint:'クリックまたはファイルをドラッグしてアップロード',
    em_item_th:'項目', em_fuel_econ_th:'燃費<br>(km/ℓ)', em_std_td:'基準値',
    ev_gen_section:'1. &nbsp;一般事項',
    oo_yn_y:'有', oo_yn_n:'無',
    nt_reg_note_ph:'例) 加速走行騒音試験はECE試験方法で測定',
    nt_test_date_ph:'例) 2025. 01. 01.',
    nt_div_th:'区分', nt_2nd_lbl:'第2回試験', nt_3rd_lbl:'第3回試験',
    nt_4th_lbl:'第4回試験', nt_avg_lbl:'平均', nt_result_lbl:'結果',
    nt_inspector_ph:'氏名', nt_confirmer_ph:'氏名',
    nt_attach_title:'添付書類（自己試験成績書 / RAW DATA）',
    nt_ex_pct_lbl:'原動機最高出力<br>回転速度の',
    nt_upload_hint:'クリックまたはファイルをドラッグしてアップロード',
    cf_maker_ph:'例) HONDA Motor Co.,Ltd（日本）',
    cf_addr_lbl2:'2. 住&nbsp;&nbsp;&nbsp;所 :', cf_model_lbl2:'3. モデル :',
    cf_model_ph:'例) CB500F', cf_importer_ph:'例) ○○モーターズ株式会社',
    cf_warranty_lbl2:'5. 保証内容 :',
    cf_warranty_subject_ph:'保証主体名（例）○○モーターズ株式会社）',
    cf_law_text:'は大気環境保全法第46条、48条、50条、51条及び同法施行規則第63条の規定に基づき',
    cf_law_period:'保証期間（130km/h以下：2年又は20,000km、130km/h以上：2年又は35,000km）まで製作車及び',
    cf_law_obligation:'使用中の車両の排出許容基準を満足するよう、品質管理・事後責任等の義務事項を履行し、',
    cf_law_recall:'随時検査及び欠陥検査において欠陥が確認された場合、欠陥修正（リコール）の義務を履行する。',
    cf_confirm_text:'当社は上記保証内容について、義務事項を履行することを確認します。',
    cf_signed_at_ph:'署名場所', cf_sign_date_ph:'例) 2025. 01. 01.',
    cf_name_ph:'署名者氏名', cf_title_ph:'役職',

    dp_th_item:'項目', dp_th_sub_item:'サブ項目',
    dp_th_structure:'構造/メーカー/サイズ/容量等',
    dp_th_ctrl_tech:'制御技術/制御原理', dp_th_emission_eff:'排出ガス低減効果',
    dp_th_sensor_var:'検出変数', dp_th_fuel_afr:'燃料（A/F比）',
    dp_th_ign_timing:'点火時期',
    dp_th_canister_purge:'キャニスターパージ/アイドル/EGR',
    dp_th_note:'備考',
    dp_th_part_no:'部品番号', dp_th_mfr:'製造業者', dp_th_mfr_country:'製造国',
    dp_th_evap_code:'蒸発ガスコード',
    dp_th_nominal_tank:'公称タンク<br>容量(L)',
    dp_th_max_evap:'40%燃料時の最大蒸発ガス容量',
    dp_th_reservoir:'キャブ/インジェクターのリザーバー最大容量',
    dp_th_model_name:'適用車名',
    dp_th_category:'区分', dp_th_basic_model:'基本車種',
    dp_th_emission_equiv:'排出ガス・騒音<br>同一車種',
    dp_th_evap_equiv:'蒸発ガス同一車種',
    dp_th_obd_equiv:'OBD同一車種',
    dp_th_dur_test:'耐久試験車両', dp_th_emission_test_v:'排出ガス試験車両',
    dp_lbl_intake_manifold:'吸気マニホールド', dp_lbl_intake_port_size:'吸気ポートサイズ',
    dp_lbl_intake_port_shape:'吸気ポート形状',
    dp_lbl_exhaust_manifold:'排気マニホールド', dp_lbl_exhaust_port_size:'排気ポートサイズ',
    dp_lbl_exhaust_port_shape:'排気ポート形状',
    dp_lbl_valve_timing:'バルブ開閉時期',
    dp_lbl_intake_valve:'吸気<br>バルブ', dp_lbl_exhaust_valve:'排気<br>バルブ',
    dp_lbl_open:'開く', dp_lbl_close:'閉じる',
    dp_lbl_valve_count:'気筒別バルブ数',
    dp_lbl_valve_intake:'吸気', dp_lbl_valve_exhaust:'排気',
    dp_lbl_valve_size:'バルブサイズ',
    dp_lbl_air_intake:'吸気方式',
    dp_lbl_cat_type_lbl:'種類', dp_lbl_noble_metal:'貴金属成分',
    dp_lbl_noble_amount:'貴金属量(g)', dp_lbl_volume:'容量(cm³)',
    dp_lbl_noble_ratio:'貴金属比(Pt:Pd:Rh)',
    dp_lbl_canister_design:'キャニスター<br>設計特性',
    dp_lbl_evap_absorp:'蒸発ガス吸収容量',
    dp_lbl_canister_cnt:'キャニスター数・接続方法',
    dp_lbl_canister_shape:'キャニスター形状',
    dp_lbl_canister_structure:'キャニスター構造',
    dp_lbl_canister_material:'キャニスター材質',
    dp_lbl_fuel_system:'燃料システム', dp_lbl_filler_seal:'給油口シール構造',
    dp_lbl_emission_ctrl:'排出ガス<br>制御装置', dp_lbl_emission_gas:'排出ガス',
    dp_lbl_dur_test_select:'耐久試験車両選定',

    dp_5_1_1_lbl:'5.1.1. 試験場所', dp_5_1_2_lbl:'5.1.2. 試験手順',
    dp_5_2_1_lbl:'5.2.1. 耐久走行の有無', dp_5_2_2_lbl:'5.2.2. 慣らし走行の有無',
    dp_5_2_3_lbl:'5.2.3. 走行予定期間', dp_5_2_4_lbl:'5.2.4. 走行場所',
    dp_5_2_5_lbl:'5.2.5. 走行手順',
    dp_5_3_1_lbl:'5.3.1. 試験場所', dp_5_3_2_lbl:'5.3.2. 試験手順',
    dp_5_4_1_lbl:'5.4.1. 試験場所', dp_5_4_2_lbl:'5.4.2. 試験手順',
    dp_lbl_engine:'エンジン', dp_lbl_ignition:'点火装置', dp_lbl_chassis:'シャシー',
    dp_8_14_1_lbl:'8.14.1. 電動機および電動機制御装置',
    dp_8_14_2_lbl:'8.14.2. 蓄電池および蓄電池制御装置',
    profile_modal_title:'マイページ', profile_tab_info:'基本情報変更', profile_tab_pw:'パスワード変更',
    profile_lbl_username:'ユーザーID', profile_lbl_company:'会社名', profile_lbl_rep:'担当者名',
    profile_lbl_bizno:'事業者番号', profile_lbl_phone:'連絡先',
    profile_ph_company:'会社名を入力', profile_ph_rep:'担当者名を入力',
    profile_ph_bizno:'事業者登録番号', profile_ph_phone:'電話番号',
    profile_btn_save:'保存', profile_saved_ok:'会員情報が更新されました。',
    profile_err_required:'会社名・担当者名・事業者番号は必須です。',
    pw_change_title:'パスワード変更',
    pw_current_lbl:'現在のパスワード', pw_new_lbl:'新しいパスワード',
    pw_confirm_lbl:'新しいパスワード確認',
    pw_current_ph:'現在のパスワードを入力', pw_new_ph:'4文字以上',
    pw_confirm_ph:'再入力',
    pw_cancel_btn:'キャンセル', pw_change_btn:'変更',
    btn_processing:'処理中...', btn_change:'変更',
    pw_err_required:'すべての項目を入力してください。', pw_err_too_short:'パスワードは4文字以上にしてください。',
    pw_err_mismatch:'新しいパスワードが一致しません。', pw_changed_ok:'パスワードが変更されました。',
    err_occurred:'エラーが発生しました。', err_network:'ネットワークエラーが発生しました。',
    btn_create_app:'申請書作成', btn_creating:'作成中...', msg_create_fail:'作成に失敗しました。',
    msg_app_created:'申請書が作成されました。', err_cert_no_required:'既存認証番号を入力してください。',
    msg_delete_confirm:'本当に削除しますか？', msg_deleted:'削除されました。', msg_delete_fail:'削除に失敗しました。',
    save_error:'保存中にエラーが発生しました。',
    qr_auth_code_lbl:'真偽確認コード',
    qr_verify_title:'真偽確認',
    qr_doc_name:'書類名',
    qr_application:'申請書',
    qr_issued_at:'発給日時',
    qr_issuer:'発給機関',
    obd_lbl_tire:'タイヤ',
    obd_ph_trans_step:'変速機(段)',
    obd_sec1_label:'OBD総合情報に関する書類',
    obd_1_1_desc:'1.1. センサー・アクチュエーター等の部品一覧及び機能説明',
    obd_1_2_desc:'1.2. 誤作動表示灯に関する説明資料',
    obd_1_3_desc:'1.3. 無断変更及び排気ガス制御コンピューター修正禁止文句',
    obd_1_4_desc:'1.4. 監視装置の技術的な説明資料',
    obd_1_5_desc:'1.5. その他追加情報',
    obd_1_6_desc:'1.6. 自体試験結果及び技術的説明資料',
    obd_sec2_label:'同一車種説明に関する書類',
    obd_sec3_label:'試験車両選定に関する書類',
    obd_sec2_title:'2. 同一車種説明に関する書類',
    obd_sec3_title:'3. 試験車両選定に関する書類',
    obd_2_1_title:'2.1. 自動車諸元(自己診断同一車種中の代表車種)',
    obd_gen_spec_title:'1. 一般諸元',
    obd_eng_spec_title:'2. エンジン諸元',
    obd_em_ctrl_spec_title:'3. 排出ガス制御装置及びOBD諸元',
    obd_1_6_1_title:'1.6.1. 試験結果',
    obd_1_6_2_title:'1.6.2. OBD監視部品のテスト及び診断',
    obd_2_2_title:'2.2. 自己診断同一車種',
    obd_2_3_title:'2.3. 排出ガス自己診断装置同一車種説明',
    obd_3_1_title:'3.1. 排出ガス自己診断装置試験車両選定根拠',
    obd_lbl_cat_monitor:'触媒監視装置',
    obd_lbl_dpf_monitor:'煤煙濾過装置監視装置',
    obd_lbl_eis_monitor:'電子噴射システム監視装置',
    obd_lbl_obd_parts:'OBDシステムにより監視される部品',
    obd_lbl_mil_criteria:'誤作動表示灯点灯のための基準',
    obd_lbl_dtc_list:'全OBD出力コード一覧と使用された様式',
    obd_th_test_req:'試験要求事項作動基準(Ⅰ)型',
    obd_th_compliance:'適合有無',
    obd_th_part_check:'部品点検',
    obd_th_mi_time:'MI活性化時期',
    obd_th_mem_err:'メモリに保存されたエラーコード修正',
    obd_th_obd_same:'排出ガス自己診断装置同一車種',
    obd_th_obd_test_car:'排出ガス自己診断装置試験車両',
    obd_lbl_modelname:'モデル名',
    obd_lbl_vin:'車台番号(エンジン番号)',
    obd_lbl_trans_type:'変速機形態',
    obd_lbl_trans_proc:'変速手順',
    obd_lbl_equiv_inertia:'等価慣性重量(kg)',
    obd_lbl_final_drive:'終減速器',
    obd_lbl_same_carname:'車名(同一車名)',
    obd_lbl_engine:'エンジン',
    obd_lbl_combustion:'燃焼過程(火花点火・圧縮着火・2行程・4行程等)',
    obd_lbl_fuel_method:'燃料供給方法(気化器式・燃料噴射式等)',
    obd_lbl_cat_type:'触媒転換器の形式(酸化触媒・三元触媒等)',
    obd_lbl_dpf_type:'煤煙濾過装置の形式',
    obd_lbl_2ndair_yn:'2次空気噴射の有無',
    obd_lbl_egr_yn:'排出ガス再循環装置の有無',
    obd_lbl_obd_method:'排出ガス自己診断装置の作動方法',
    obd_lbl_monitor_check:'監視装置の誤作動確認方法',
    obd_lbl_mal_display:'誤作動表示方法',
    obd_ph_name_type:'車名(形式)',
    obd_ph_total_weight:'総重量(空車重量)',
    obd_ph_na_or_type:'該当なし又は形式入力',
    obd_ph_method:'作動方法入力',
    obd_ph_check_method:'誤作動確認方法入力',
    obd_ph_display_method:'誤作動表示方法入力',
    obd_ph_vin:'車台番号(エンジン番号)',
    obd_ph_trans_type:'変速機形態',
    obd_ph_trans_proc:'変速手順',
    obd_ph_equiv_inertia:'等価慣性重量(kg)',
    obd_ph_final_drive:'終減速器',
    obd_ph_same_carname:'同一車名',
    obd_lbl_prep_cycle:'誤作動確認試験のための準備サイクル形式と回数',
    obd_lbl_test_cycle:'監視される部品の確認試験サイクル形式の説明',
    obd_lbl_2nd_monitor:'監視される構成部品の2次監視変数一覧',
    obd_lbl_ctrl_indicator:'制御・自動表示器・インジケーター位置及び識別記号',
    obd_div_mil_location:'誤作動表示灯の形態及び位置：形態及び位置が分かる図面または写真',
    obd_div_left_switch:'左側ハンドルスイッチの制御及び記号図面',
    obd_div_right_switch:'右側ハンドルスイッチの制御及び記号図面',
    obd_div_keybox:'キーボックス図面',
    obd_txt_malfunction_test:'誤作動再現のための部品または誤作動モーターサイクルのための電子装備を装着した車両を試験する際、誤作動判定基準以下で誤作動警告灯が点灯し、排出ガス自己診断装置は適合と判定される。',
    obd_txt_electrical_continuity:'排出ガス関連部品または排出ガスに関連し、エンジン制御装置に接続されたパワートレイン関連部品の電気的連続性を監視しなければならない。',
    obd_ph_dtc_default:'二輪自動車に欠陥コードが確認されると計器盤にエンジンチェックランプが点灯する。',
    obd_ph_no_modify:'無断変更及び排気ガス制御コンピューターの修正を禁止する文句入力',
    nt_th_gear:'使用<br>変速<br>ギア',
    nt_th_entry_speed:'進入<br>指定<br>車速<br>(km/hr)',
    nt_th_test_speed:'試験車速<br>(km/hr.)',
    nt_th_rpm:'エンジン回転数<br>(rpm)',
    nt_th_accel_pos:'加速<br>開始<br>位置<br>(m)',
    nt_th_bg_noise:'暗騒音<br>[dB<br>(A)]',
    nt_th_meas_noise:'測定騒音<br>[dB(A)]',
    nt_th_correction:'補正<br>値<br>[dB<br>(A)]',
    nt_th_std_val:'基準値<br>[dB<br>(A)]',
    nt_th_accel_init:'加速<br>初期',
    nt_th_accel_end:'加速<br>終了',
    nt_th_left:'左側',
    nt_th_right:'右側',
    nt_lbl_1st:'1次試験',
    nt_lbl_wot_noise:'加速走行騒音<br>(L_WOTrep, dB(A))',
    nt_lbl_crs_noise:'定速走行騒音<br>(L_CRSrep, dB(A))',
    em_val_dur_run:'耐久走行試験',
    em_sec5_cvs:'5. CVS運転試験状態',
    em_sec6_result:'6. 試験結果',
    ev_sec2:'2. 測定室及び測定装備',
    ev_upload_hint:'クリックするかファイルをドラッグしてアップロード',
    oo_th_fuel_econ:'燃費<br>(km/ℓ)',
    oo_th_exhaust_gas:'排気管<br>ガス',
    oo_th_det_factor:'悪化係数<br>(DF)',
    oo_sec3_emission:'3. 排出ガス制御',
    g_th_compliance_pct:'基準満足度(%)',
    g_obd_std_2006_gas:'ガソリン2006年OBD基準',
    g_obd_std_2013_1st:'ガソリン2013年OBD IUPR 1st基準',
    g_obd_std_2013_2nd:'ガソリン2013年OBD IUPR 2nd(2016年1月)基準',
    g_obd_std_euro6:'ガソリンEURO6 OBD IUPR 2nd基準',
    g_obd_std_euro5_2w:'ガソリンEURO5 OBD二輪自動車基準(Stage 2)',
    g_obd_std_2006_diesel:'軽油2006年OBD基準',
    g_obd_std_2012_diesel:'軽油2012年OBD IUPR 1st基準',
    g_obd_std_2014_diesel:'軽油2014年9月OBD IUPR 2nd基準',
    g_ph_obd_mal:'OBD2誤作動判定基準関連内容',
    g_th_monitor_item:'監視項目',
    g_th_test_yn:'試験有無',
    g_th_test_vehicle:'試験車名',
    g_th_applicable2:'適用有無',
    g_th_meas_result:'測定結果',
    g_lbl_test_facility:'試験施設',
    g_ph_facility_detail:'自体試験を実施した施設の施設確認内訳',
    g_lbl_vehicle_sel:'試験車選定根拠',
    g_vehicle_sel_title:'試験自動車選定根拠',
    g_vehicle_sel_em:'- 排出ガス試験車両：規定第11条に従い選定',
    g_vehicle_sel_noise:'- 騒音試験車両：規定第12条に従い選定',
    g_vehicle_sel_obd:'- OBD試験車両：規定第23条に従い選定',
    g_ph_additional:'追加事項記載',
    g_ph_em_mode:'排出ガス試験モード、試験回数、自体試験成績等',
    g_lbl_evap_test:'蒸発ガス試験',
    g_ph_evap_submit:'蒸発ガス自体試験成績書提出内訳等',
    g_lbl_warranty_det:'保証期間及び悪化係数',
    g_ph_warranty_detail:'保証期間及び悪化係数適用内訳',
    g_lbl_warranty_km:'保証期間(km) :',
    g_th_det_factor:'適用悪化係数',
    g_em_co:'一酸化炭素(CO)',
    g_em_exhaust_hc:'排気管炭化水素',
    g_em_nox:'窒素酸化物',
    g_em_evap_hc:'蒸発炭化水素',
    g_lbl_endurance:'耐久試験',
    g_ph_endurance_note:'耐久試験内容を記載してください',
    g_lbl_ki:'周期的再生指数<br>(ki)試験',
    g_ph_ki_note:'周期的再生指数(ki)試験内容',
    g_lbl_noise_test:'騒音試験',
    g_noise_submit:'騒音試験成績書提出内訳',
    g_ph_noise_submit:'騒音試験成績書提出内訳を記載してください',
    g_noise_method:'騒音試験方法',
    g_noise_accel_lbl:'- 加速走行騒音：',
    g_noise_exhaust_lbl:'- 排気騒音：',
    g_noise_horn_lbl:'- 警笛騒音：',
    g_lbl_same_type:'同一車種構成',
    g_th_div_lbl:'区分',
    g_lbl_o2_sensor:'酸素センサー',
    g_lbl_egr:'排気ガス再循環系統',
    g_lbl_vvt:'可変バルブタイミング系統',
    g_lbl_fuel_system:'燃料系統',
    g_lbl_misfire:'失火',
    g_lbl_2nd_air:'2次空気系統',
    en_ph_inner_diag:'内部構造説明',
    en_ph_flow_desc:'流れ図説明',
    en_ph_maker_name:'製造社名',
    en_ph_inner_mat:'内部材質/仕様',
    en_ph_outer_mat:'外部材質/仕様',
    en_ph_dim_desc:'寸法図面説明',
    en_ph_cat_principle:'触媒原理または効果を記載してください',
    en_ph_attach_desc:'取付位置説明',
    en_1_5_lbl:'1.5. センサー詳細諸元',
    en_1_5_1_lbl:'1.5.1. センサー製造社',
    en_1_5_2_lbl:'1.5.2. センサー材質',
    en_1_5_3_lbl:'1.5.3. センサー寸法図面',
    en_ph_sensor_mat:'センサー材質',
    en_1_6_lbl:'1.6. マフラー図面',
    en_1_7_lbl:'1.7. マフラー写真',
    en_ph_muffler_draw:'マフラー図面説明',
    en_ph_muffler_photo:'マフラー写真説明',
    en_sec2_valve:'2. バルブ装置(Valve Train)',
    en_2_1_valve:'2.1. バルブ機構の慣性力',
    en_ph_valve_inertia:'バルブ機構の慣性力に関する内容を記載してください',
    en_2_2_surging:'2.2. バルブスプリングのSurging現象対応技術',
    en_ph_surging:'Surging現象対応技術を記載してください',
    en_2_3_cam:'2.3. カムプロファイル及び諸元',
    en_2_3_1_valve:'2.3.1. バルブ諸元',
    en_ph_valve_spec:'バルブ諸元を記載してください',
    en_2_3_2_cam:'2.3.2. Cam諸元',
    en_ph_cam_spec:'Cam諸元を記載してください',
    en_2_3_3_cam_dim:'2.3.3. Cam寸法図面',
    en_ph_cam_dim:'Cam寸法図面説明',
    en_2_4_valve_mat:'2.4. バルブ機構の材質等に関する内容',
    en_ph_valve_mat:'バルブ機構の材質等に関する内容を記載してください',
    en_2_5_valve_clearance:'2.5. バルブクリアランス',
    en_ph_valve_clearance:'バルブクリアランス数値または説明',
    en_sec3_ignition:'3. 点火装置',
    en_3_1_ign_diag:'3.1. 点火装置構成図',
    en_ph_ign_diag:'点火装置構成説明',
    en_3_2_ign_ctrl:'3.2. 点火装置制御特性',
    en_ph_ign_ctrl:'点火装置制御特性を記載してください',
    en_3_3_ign_spec:'3.3. 点火装置詳細諸元',
    en_3_3_1_gen:'3.3.1. ジェネレーター',
    en_3_3_1_1_gen_spec:'3.3.1.1. ジェネレーター詳細諸元',
    en_ph_gen_spec:'ジェネレーター詳細諸元',
    en_3_3_1_2_gen_dim:'3.3.1.2. ジェネレーター形状及び寸法諸元',
    en_ph_shape_dim:'形状及び寸法説明',
    en_3_3_2_1_cdi_spec:'3.3.2.1. CDI UNIT詳細諸元',
    en_ph_cdi_spec:'CDI UNIT詳細諸元',
    en_3_3_2_2_cdi_dim:'3.3.2.2. CDI UNIT形状及び寸法諸元',
    en_3_3_3_coil:'3.3.3. 点火コイル',
    en_3_3_3_1_coil_spec:'3.3.3.1. 点火コイル詳細諸元',
    en_ph_coil_spec:'点火コイル詳細諸元',
    en_3_3_3_2_coil_dim:'3.3.3.2. 点火コイル形状及び寸法諸元',
    en_3_3_4_plug:'3.3.4. 点火プラグ',
    en_3_3_4_1_plug_spec:'3.3.4.1. 点火プラグ詳細諸元',
    en_ph_plug_spec:'点火プラグ詳細諸元',
    en_3_3_4_2_plug_dim:'3.3.4.2. 点火プラグ形状及び寸法諸元',
    en_3_3_5_ecu:'3.3.5. ECU詳細諸元',
    en_3_3_5_1_ecu_spec:'3.3.5.1. ECU詳細諸元',
    en_ph_ecu_spec:'ECU詳細諸元',
    en_3_3_5_2_ecu_dim:'3.3.5.2. ECU形状及び寸法諸元',
    en_3_4_ign_photo:'3.4. 点火装置写真',
    en_ph_ign_photo:'点火装置写真説明',
    en_sec4_fuel:'4. 燃料装置',
    en_4_1_fuel_sys:'4.1. 燃料装置構成及び制御方式',
    en_ph_fuel_sys:'燃料装置構成及び制御方式を記載してください',
    en_4_2_fuel_drawing:'4.2. 燃料装置図面及び寸法',
    en_ph_drawing_dim:'図面及び寸法説明',
    en_4_3_fuel_spec:'4.3. 燃料装置詳細諸元',
    en_4_3_1_tank:'4.3.1. 燃料タンク',
    en_4_3_1_1_tank_spec:'4.3.1.1. 燃料タンク詳細諸元',
    en_ph_tank_spec:'燃料タンク詳細諸元',
    obd_wps_lbl:'エンジン温度センサー(WPS)',
    obd_o2_lbl:'酸素センサー(O₂)',
    obd_injector_lbl2:'燃料噴射装置(インジェクター)',
    obd_o2heater_lbl:'O₂センサーヒーター',
    obd_wire_throttle:'ワイヤーアクチュエーターによるスロットル',
    obd_fanrelay_lbl:'ラジエーターファンリレー',
    obd_pumprelay_lbl:'燃料ポンプリレー',
    obd_ph_content:'内容入力',
    obd_ph_carname:'車名',
    obd_ph_type:'形式',
    obd_ph_carkind:'車種',
    obd_ph_fuel:'使用燃料',
    obd_ph_weight:'総重量(空車重量, kg)',
    obd_ph_engtype:'エンジン形式',
    obd_ph_maxpower:'最高出力',
    obd_ph_cc:'排気量(cc)',
    obd_ph_combtype:'燃焼形式',
    obd_ph_cycle:'燃焼サイクル',
    obd_ph_supplytype:'燃料供給形態',
    obd_ph_cat_info:'触媒転換器形式及び製造社',
    obd_ph_ecu_info:'電子制御装置形式及び製造社',
    obd_ph_o2s_info:'酸素センサー形式及び製造社',
    obd_ph_purge_info:'パージ制御バルブ形式及び製造社',
    obd_val_pass:'適合',
    obd_val_fail:'不適合',
    obd_th_part_harness:'部品/ハーネス',
    obd_th_switch:'スイッチ',
    obd_th_start:'始動',
    obd_th_spec:'規格',
    obd_th_mil:'誤作動表示灯点灯',
    obd_th_carname:'車名',
    obd_th_type:'形式',
    obd_th_carkind:'車種',
    obd_th_weight:'総重量(空車重量, kg)',
    obd_th_cc:'排気量(cc)',
    obd_th_combtype:'燃焼形式',
    obd_th_cycle:'燃焼サイクル',
    obd_th_supplytype:'燃料供給形態',
    obd_th_cat:'触媒転換器形式(製造社)',
    obd_th_2nd_air:'2次空気噴射',
    obd_th_egr:'排出ガス再循環装置',
    obd_th_ecu:'電子制御装置形式(製造社)',
    obd_th_o2s:'酸素センサー形式(製造社)',
    obd_th_purge:'パージ制御バルブ形式(製造社)',
    obd_th_name_type:'車名(形式)',
    obd_th_engtype:'エンジン形式',
    obd_th_maxpower:'最大出力',
    obd_th_trans_step:'変速機(段)',
    obd_ph_part_check:'部品点検内容',
    obd_ph_mi_time:'MI活性化時期',
    obd_ph_err_fix:'エラーコード修正',
    obd_ph_part_harness:'部品/ハーネス',
    obd_ph_switch:'スイッチ',
    obd_ph_start:'始動',
    obd_ph_spec:'規格',
    em_ph_engtype:'エンジン形式または技術内容',
    g_2_1_label:'2.1. EURO–5基準適用 ガソリン二輪自動車 認証申請, 代表車種 :',
    g_2_2_obd:'2.2. OBD代表車種 :',
    g_evap_rep_lbl:'蒸発ガス代表車種 :',
    g_em1_txt:'* 13年ガソリン基準2のナ',
    g_em2_txt:'* 13年ガソリン基準1のナ',
    g_em3_txt:'* 16年ガソリン基準',
    g_em4_txt:'* 20年1月二輪自動車(130km/h以下)基準',
    g_em5_txt:'* 14年9月軽油小型乗用基準',
    g_obd1_txt:'* OBD2ガソリン基準適用代表(IUPR 1st基準)',
    g_obd2_txt:'* OBD2ガソリン基準適用同一(IUPR 1st基準), 代表車種 :',
    g_obd3_txt:'* OBD2ガソリンEURO6基準適用代表(IUPR 2nd基準)',
    g_obd4_txt:'* OBD2ガソリンEURO6基準適用同一(IUPR 2nd基準), 代表車種 :',
    g_obd5_txt:'* OBD2ガソリンEURO5二輪自動車基準適用代表(OBD Stage 2)',
    g_obd6_txt:'* OBD2軽油(다)基準適用代表(IUPR 2nd基準)',
    g_obd7_txt:'* OBD2軽油(다)基準適用同一(IUPR 2nd基準), 代表車種 :',
    g_evap1_txt:'* 蒸発ガス代表',
    g_evap2_txt:'* 蒸発ガス同一, 代表車種 :',
    g_war1_txt:'* 保証期間 : 10年 / 192,000km',
    g_war2_txt:'* 保証期間 : 10年 / 240,000km',
    g_war3_txt:'* 保証期間 : 15年 / 240,000km',
    g_war4_txt:'* 保証期間 : 2年 / 35,000km',
    g_war5_txt:'* 保証期間 : 2年 / 20,000km',
    g_war6_txt:'* 保証期間 : 10年 / 160,000km',
    g_3_1_lbl:'3.1. 適用技術',
    g_3_2_1_lbl:'3.2.1. 排出',
    g_3_2_2_lbl:'3.2.2. 騒音',
    g_3_3_lbl:'3.3. 詳細技術内容',
    g_3_4_lbl:'3.4. 試験施設',
    g_3_5_lbl:'3.5. 排出ガス試験',
    g_3_6_lbl:'3.6. 蒸発ガス試験',
    g_3_7_lbl:'3.7. 保証及び悪化係数',
    g_3_8_lbl:'3.8. 耐久性試験',
    g_3_9_lbl:'3.9. KI試験',
    g_3_10_lbl:'3.10. 騒音試験',
    g_3_11_lbl:'3.11. 同一車種',
    g_th_hc:'炭化水素',
    g_th_allow_std:'許容基準',
    g_th_test_result:'試験結果',
    g_th_accel_db:'加速走行<br>dB(A)',
    g_th_exhaust_db:'排気<br>dB(A)',
    g_th_horn_db:'警笛<br>dB(A)',
    g_th_co_gkm:'CO<br>(g/km)',
    g_th_hcnox_gkm:'HC+NOx<br>(g/km)',
    g_th_pm_gkm:'PM<br>(g/km)',
    g_th_exhaust_hc:'排気HC<br>(g/km)',
    g_th_evap_hc:'蒸発HC<br>(g/test)',
    g_th_obd_std:'OBD基準名',
    g_th_monitor_dev:'試験対象監視装置',
    g_th_wmtc:'WMTCモード<br>CO(g/km)',
    g_th_mil_on:'表示灯<br>点灯有無',
    g_th_judge_std:'判断基準<br>CO(g/km)',
    g_th_monitor_judge:'監視装置<br>適否判定',
    g_th_item:'項目',
    g_th_content:'内容',
    g_th_result_judge:'結果判定',
    g_th_malfunction:'誤作動再現条件',
    g_th_device_name:'装置名',
    g_lbl_catalyst:'触媒・DPF等後処理装置',
    g_lbl_evap:'蒸発ガス',
    g_lbl_blowby:'ブローバイガス',
    g_lbl_obd2:'排出ガス自己診断装置<br>(OBD2)',
    g_lbl_catalyst_br:'触媒・DPF等<br>後処理装置',
    g_lbl_catalyst2:'触媒',
    g_lbl_o2:'O₂センサー',
    g_ph_tech:'適用された排出ガス・騒音低減技術を記載してください',
    g_ph_em_result:'排出ガス自体試験結果',
    g_ph_noise_result:'騒音自体試験結果',
    g_ph_catalyst:'後処理装置詳細内容',
    g_ph_evap_detail:'蒸発ガス代表/同一可否及び関連内容',
    g_ph_blowby:'ブローバイガス制御装置内容',
    g_ph_obd_rep:'OBD2代表/同一可否及び関連内容',
    g_ph_facility:'試験施設詳細',
    g_ph_em_test:'排出ガス試験内容',
    g_ph_evap_test:'蒸発ガス試験内容',
    g_ph_warranty:'保証及び悪化係数内容',
    g_ph_endurance:'耐久性試験内容',
    g_ph_ki:'KI試験内容',
    g_ph_noise_test:'騒音試験内容',
    g_ph_same_type:'同一車種構成内容を記載してください',
    g_ph_applicable:'該当/非該当',
    g_ph_misfire:'失火',
    g_ph_degradation:'劣化',
    g_ph_yn:'有/無',
    g_ph_pass_fail:'適合/不適合',
    g_ph_img:'画像をドラッグまたはクリック',
    en_doc_tag:'[別紙第5号様式]',
    en_main_title_txt:'排出ガス騒音低減装置資料',
    en_sec1:'1. 消音器（マフラー）',
    en_1_1_lbl:'1.1 マフラー構成内訳',
    en_1_2_lbl:'1.2 マフラー内部構造図',
    en_1_3_lbl:'1.3 消音器詳細諸元',
    en_1_4_lbl:'1.4 触媒装置詳細諸元',
    en_sec2:'2. 空気清浄器（エアクリーナー）',
    en_2_1_lbl:'2.1 空気清浄器詳細諸元',
    en_1_3_1_lbl:'構造及び騒音低減原理',
    en_1_3_2_lbl:'流れ図',
    en_1_3_3_lbl:'製造社',
    en_inside_lbl:'内部 :',
    en_outside_lbl:'外部 :',
    en_dim_draw_lbl:'寸法図面',
    en_principle_lbl:'原理または効果',
    en_attach_pos_lbl:'取付位置',
    en_cat_maker_lbl:'触媒製造社',
    en_cat_material_lbl:'触媒材質',
    en_cat_perf_lbl:'触媒性能及び寸法',
    en_inside_mat_lbl:'内部材質',
    en_outside_mat_lbl:'外部材質',
    en_ph_muffler_comp:'マフラー構成内訳を記載してください',
    en_ph_muffler_diag:'マフラー内部構造図を記載してください',
    en_ph_noise_principle:'騒音低減原理を記載してください',
    en_ph_flow:'流れ図を記載してください',
    en_ph_maker:'製造社を記載してください',
    en_ph_inside:'内部材質を記載してください',
    en_ph_outside:'外部材質を記載してください',
    en_ph_dim:'寸法図面を記載してください',
    en_ph_cat_maker:'触媒製造社を記載してください',
    en_ph_cat_mat:'触媒材質を記載してください',
    en_ph_cat_perf:'触媒性能及び寸法を記載してください',
    en_ph_principle:'原理または効果を記載してください',
    en_ph_pos:'取付位置を記載してください',
    en_ph_aircleaner:'空気清浄器詳細諸元を記載してください',
    obd_doc_tag:'[別紙第9号様式]',
    obd_main_title_txt:'排出ガス自己診断装置(OBD)構成に関する書類',
    obd_sec1:'1. 排出ガス自己診断装置(OBD)総合情報に関する書類',
    obd_sec2:'2. 排出ガス自己診断装置(OBD)機能に関する書類',
    obd_th_parts:'自動車排出ガス関連部品',
    obd_th_func:'機能的な作動特性',
    obd_lbl_sensor:'センサー',
    obd_lbl_actuator:'アクチュエーター',
    obd_cps_lbl:'クランクポジションセンサー(CPS)',
    obd_tmap_lbl:'温度・空気圧センサー(T-MAP)',
    obd_wts_lbl:'冷却水温度センサー(WTS)',
    obd_o2s_lbl:'酸素センサー(HO2S)',
    obd_tps_lbl:'スロットルポジションセンサー(TPS)',
    obd_injector_lbl:'燃料インジェクター',
    obd_pump_lbl:'燃料ポンプ',
    obd_idle_lbl:'アイドル速度制御',
    obd_coil_lbl:'点火コイル',
    obd_cat_lbl:'触媒転換装置',
    obd_egr_lbl:'EGRシステム',
    obd_evap_sys_lbl:'蒸発ガス制御システム',
    obd_air2_lbl:'二次空気噴射システム',
    obd_fuel_sys_lbl:'燃料システム',
    obd_trans_lbl:'変速機',
    obd_ph_func:'機能的な作動特性を記載してください',
    obd_2_1_lbl:'2.1. 故障コード(DTC)読取機能',
    obd_2_2_lbl:'2.2. 準備完了モニター(Readiness)状態',
    obd_2_3_lbl:'2.3. フリーズフレームデータ対応有無',
    obd_2_4_lbl:'2.4. 故障コード削除機能',
    obd_2_5_lbl:'2.5. 診断機器通信プロトコル',
    obd_th_item2:'項目',
    obd_th_content2:'内容',
    obd_th_support:'対応有無',
    obd_val_support:'対応',
    obd_val_nosupport:'非対応',
    obd_ph_yn:'はい/いいえ',
    obd_ph_protocol:'通信プロトコルを記載してください',
    em_doc_tag:'[別紙第18の2号様式]',
    em_sec1:'1. 一般事項',
    em_sec2:'2. 試験自動車諸元',
    em_sec3:'3. 試験車エンジン諸元',
    em_sec4:'4. 試験装備',
    em_th_test_div:'試験区分',
    em_val_dur:'耐久試験',
    em_val_emis:'排出ガス試験',
    em_val_insp:'定期検査',
    em_val_etc:'その他',
    em_lbl_cvs:'CVS装置',
    em_lbl_analyzer:'分析器',
    em_lbl_chassis:'シャシーダイナモメーター',
    em_lbl_eng_type:'エンジン形式',
    em_lbl_total_cc:'総排気量(cc)',
    em_lbl_comp_ratio:'圧縮比',
    em_lbl_max_power:'最高出力(ps/rpm)',
    em_lbl_fuel_supply:'燃料供給方式',
    em_lbl_cooling:'冷却方式',
    em_lbl_ignition:'点火方式',
    em_lbl_valves:'バルブ数',
    em_lbl_cc_per_cyl:'排気量(cc/気筒)',
    em_lbl_cylinders:'気筒数',
    em_lbl_maker_model:'製造社及びモデル名',
    em_lbl_range:'測定範囲',
    em_lbl_maker2:'製造社',
    em_lbl_model2:'モデル名',
    em_lbl_max_abs:'最大吸収力(kW)',
    em_lbl_inertia:'慣性重量(kg)',
    ev_doc_tag:'[別紙第23号様式]',
    ev_attach_title:'添付書類（自体試験成績書 / RAW DATA）',
    ev_attach_note:'画像(JPG, PNG)またはPDFファイルをアップロードしてください。添付ファイルは印刷時に出力されません。',
    oo_doc_tag:'[別紙第26号様式]',
    oo_th_trans_type:'変速機種類',
    oo_ph_type_maker:'形式 / 製造社',
    nt_doc_tag:'[別紙第27号乃至第27号の2号様式]',
    nt_test_date_lbl:'2. 試験日 :',
    nt_na:'該当なし',
    nt_accel_noise_meas:'加速走行騒音<br>測定',
    cf_maker_lbl:'1. 製造社 :',
    cf_addr_lbl:'2. 住　　所 :',
    cf_model_lbl:'3. モ　デ　ル :',
    cf_importer_lbl:'4. 輸入者 :',
    g_ph_maker:'例) PIAGGIO C.S.P.A(イタリア)',
    g_ph_model:'例) RSV4 1000 RR',
    g_ph_fuel:'例) ガソリン、軽油、LPG',
    g_ph_euro5:'例) EURO 5',
    g_ph_ece_noise:'例) ECE R41-04',
    g_ph_rep_nonrep:'代表/非代表',
    g_ph_cert_id:'例) ABC-123',
    g_ph_warranty_yr:'年',
    g_ph_self_test:'例) OBD、騒音、蒸発ガス',
    g_ph_key_tech:'例) O2センサー、三元触媒、OBD、ECU、アイドル制御、電子式燃料噴射',
    g_category:'区分',
    dp_valve_close:'閉じる',
    dp_valve_per_cyl:'気筒別バルブ数',
    dp_valve_intake:'吸気',
    dp_valve_exhaust:'排気',
    dp_valve_size:'バルブサイズ',
    dp_air_intake_type:'空気吸入方式',
    dp_type:'種類',
    dp_noble_metal:'貴金属成分',
    dp_noble_metal_g:'貴金属量(g)',
    dp_capacity_cc:'容量(㎤)',
    dp_noble_ratio:'貴金属比率(Pt:Pd:Rh)',
    dp_10_1_crank_cam_lbl:'クランク軸中心からカム軸中心までの距離(mm)',
    dp_10_1_crank_head_lbl:'クランク軸中心からシリンダーブロックヘッド面上部までの距離(mm)',
    dp_10_1_tdc_lbl:'TDC状態での燃焼室表面積体積比率',
    dp_10_1_fuel_supply_lbl:'燃料供給方式',
    dp_10_1_inj_range_lbl:'噴射時期制御範囲',
    dp_10_1_cam_timing_lbl:'カム軸タイミング',
    dp_10_1_inertia_lbl:'等価慣性質量',
    dp_10_1_roadload_lbl:'道路負荷馬力',
    dp_10_2_title:'10.2. 蒸発ガス同一車種説明',
    dp_10_2_category:'区分',
    dp_10_2_base:'基本車種',
    dp_10_2_same:'蒸発ガス同一車種',
    dp_10_2_certno_lbl:'排出ガス認証番号',
    dp_10_2_carname_lbl:'自動車名称',
    dp_10_2_type_lbl:'自動車型式',
    dp_10_2_eng_lbl:'原動機型式',
    dp_10_2_cartype_lbl:'車種',
    dp_10_2_fuel_lbl:'使用燃料',
    dp_10_2_evap_type_lbl:'蒸発ガス貯蔵形式',
    dp_canister_design:'キャニスター設計特性',
    dp_canister_capacity:'蒸発ガス吸収容量',
    dp_canister_count:'キャニスター個数及び接続方法',
    dp_canister_shape:'キャニスター形状',
    dp_canister_struct:'キャニスター構造',
    dp_canister_mat:'キャニスター材質',
    dp_fuel_system:'燃料システム',
    dp_filler_seal:'給油口密閉構造',
    dp_10_2_ctrl_lbl:'蒸発ガス制御システム',
    dp_10_2_purge_lbl:'パージ制御システム',
    dp_10_2_hose_mat_lbl:'蒸発ガスホース材質',
    dp_10_2_tank_mat_lbl:'燃料タンク材質',
    dp_10_3_title:'10.3. 排出ガス自己診断装置同一車種説明',
    dp_10_3_category:'区分',
    dp_10_3_base:'基本車種',
    dp_10_3_same:'排出ガス自己診断装置同一車種',
    dp_10_3_certno_lbl:'排出ガス認証番号',
    dp_10_3_carname_lbl:'自動車名称',
    dp_10_3_type_lbl:'自動車型式',
    dp_10_3_eng_lbl:'原動機型式',
    dp_10_3_cartype_lbl:'車種',
    dp_10_3_fuel_lbl:'使用燃料',
    dp_10_3_obd_op_lbl:'OBD作動方法',
    dp_10_3_std_lbl:'排出ガス許容基準',
    dp_10_3_cycle_lbl:'燃焼サイクル',
    dp_10_3_fuel_supply_lbl:'燃料供給方式',
    dp_10_3_cat_lbl:'触媒変換装置形態',
    dp_10_3_dpf_lbl:'粒子状物質捕集装置形態',
    dp_10_3_air2_lbl:'2次空気噴射有無',
    dp_10_3_egr_lbl:'EGR装置有無',
    dp_11_1_title:'11.1. 試験車両選定',
    dp_11_1_category:'区分',
    dp_11_1_dur:'耐久性試験車両',
    dp_11_1_emis:'排出ガス試験車両',
    dp_11_1_vin_lbl:'車台番号(エンジン番号)',
    dp_11_1_disp_lbl:'排気量(cc)',
    dp_11_1_eng_code_lbl:'エンジンコード',
    dp_11_1_evap_code_lbl:'蒸発ガスコード',
    dp_11_1_cat_code_lbl:'触媒コード',
    dp_11_1_emis_ctrl:'排出ガス制御装置',
    dp_11_1_emis_gas:'排出ガス',
    dp_11_1_model_lbl:'モデル名',
    dp_11_1_trans_lbl:'変速機形態',
    dp_11_1_trans_proc_lbl:'変速手順',
    dp_11_1_inertia_lbl:'等価慣性質量(kg)',
    dp_11_1_final_red_lbl:'最終減速機',
    dp_11_1_nv_lbl:'N/V比, RPM/KPH',
    dp_11_1_tire_lbl:'タイヤ',
    dp_11_1_note_lbl:'備考',
    dp_11_1_sub_hdr_ph:'自動車型式',
    dp_11_1_sub_name_lbl:'自動車名',
    dp_11_1_sub_type_lbl:'自動車型式',
    dp_11_1_sub_trans_lbl:'変速機',
    dp_11_1_sub_eng_lbl:'原動機型式',
    dp_11_1_sub_disp_lbl:'排気量',
    dp_11_1_sub_weight_lbl:'車両重量',
    dp_11_1_sub_inertia_lbl:'等価慣性質量',
    dp_11_1_sub_roadload_lbl:'道路負荷馬力',
    dp_11_1_sub_tankvol_lbl:'燃料タンク容量',
    dp_11_1_sub_finalred_lbl:'最終減速比',
    dp_11_1_sub_sales_lbl:'販売台数',
    dp_11_2_title:'11.2. 耐久性試験車両選定',
    dp_11_2_sel_lbl:'耐久性試験車両選定',
    dp_11_2_note_ph:'耐久性試験車両選定内容を記載してください',
    dp_11_3_title:'11.3. 排出ガス試験車両選定',
    dp_11_3_a_case:'A. シャシダイナモメータを使用する場合：',
    dp_11_3_a_0_lbl:'同一車種中、等価慣性質量が最も大きいもの',
    dp_11_3_a_1_lbl:'上記条件内で道路負荷力が最も大きいもの',
    dp_11_3_a_2_lbl:'上記条件内で排気量が最も大きいもの',
    dp_11_3_a_3_lbl:'上記条件内で最も高い最終ギア比を持つ変速機',
    dp_11_3_a_4_lbl:'上記条件内で燃料タンク容量が最も大きいもの',
    dp_11_3_b_case:'B. エンジンダイナモメータを使用する場合：',
    dp_11_3_b_0_lbl:'最大トルク時速度で行程当たり燃料分配率が最も高い原動機',
    dp_11_3_b_1_lbl:'最高速度時行程当たり燃料分配率が最も高い原動機',
    dp_11_4_title:'11.4. 騒音試験車両選定',
    dp_11_4_0_lbl:'車両重量が最も重い自動車',
    dp_11_4_1_lbl:'排気量が最も大きい自動車',
    dp_11_4_2_lbl:'最終ギア比率が最も高い変速機を搭載した自動車',
    dp_11_4_3_lbl:'車軸比が最も高い自動車',
    dp_12_ph:'やむを得ない事由を明示',
    dp_13_ph:'その他事項',
    en_tank_pos_sec:'4.3.1.2. 燃料タンク位置',
    en_tank_pos_ph:'位置説明',
    en_tank_shape_sec:'4.3.1.3. 燃料タンク形状',
    en_tank_shape_ph:'形状説明',
    en_throttle_sec:'4.3.2. スロットルボディ',
    en_throttle_spec_sec:'4.3.2.1. スロットルボディ詳細仕様',
    en_throttle_spec_ph:'スロットルボディ詳細仕様',
    en_throttle_dim_sec:'4.3.2.2. スロットルボディ形状及び寸法仕様',
    en_injector_sec:'4.3.3. 燃料インジェクター',
    en_injector_spec_sec:'4.3.3.1. 燃料インジェクター詳細仕様',
    en_injector_spec_ph:'燃料インジェクター詳細仕様',
    en_injector_dim_sec:'4.3.3.2. 燃料インジェクター形状及び寸法仕様',
    en_pump_sec:'4.3.4. 燃料ポンプ',
    en_pump_spec_sec:'4.3.4.1. 燃料ポンプ詳細仕様',
    en_pump_spec_ph:'燃料ポンプ詳細仕様',
    en_pump_dim_sec:'4.3.4.2. 燃料ポンプ形状及び寸法仕様',
    en_fuel_photo_sec:'4.4. 燃料装置写真',
    en_fuel_photo_ph:'燃料装置写真説明',
    en_intake_sec:'5. 吸排気装置',
    en_intake_sub:'5.1. 吸気系統',
    en_intake_diagram_sec:'5.1.1. 吸気マニフォールド構成図',
    en_intake_diagram_ph:'吸気マニフォールド構成説明',
    en_intake_manifold_sec:'5.1.2. 吸気マニフォールド',
    en_intake_manifold_ph:'吸気マニフォールド仕様または説明',
    en_air_filter_sec:'5.1.3. エアフィルター',
    en_air_filter_ph:'エアフィルター仕様または説明',
    en_exhaust_sub:'5.2. 排気系統',
    en_exhaust_diagram_sec:'5.2.1. 排気マニフォールド構成図',
    en_exhaust_diagram_ph:'排気マニフォールド構成説明',
    en_exhaust_manifold_sec:'5.2.2. 排気マニフォールド',
    en_exhaust_manifold_ph:'排気マニフォールド仕様または説明',
    en_veh_sec:'6. 車両外観及び寸法',
    en_veh_photo_sub:'6.1. 車両写真',
    en_veh_front_sec:'6.1.1. 車両前面',
    en_veh_front_ph:'車両前面説明',
    en_veh_rear_sec:'6.1.2. 車両後面',
    en_veh_rear_ph:'車両後面説明',
    en_veh_side_sec:'6.1.3. 車両側面',
    en_veh_side_ph:'車両側面説明',
    en_veh_top_sec:'6.1.4. 車両上面',
    en_veh_top_ph:'車両上面説明',
    en_ext_sub:'6.2. 外形図',
    en_ext_side_sec:'6.2.1. 外形側面',
    en_ext_side_ph:'外形側面説明',
    en_ext_top_sec:'6.2.2. 外形上面',
    en_ext_top_ph:'外形上面説明',
    en_ext_rear_sec:'6.2.3. 外形後面',
    en_ext_rear_ph:'外形後面説明',
    en_other_sec:'7. その他',
    en_other_tech_sub:'7.1. その他の排出ガス及び騒音低減技術',
    en_other_tech_ph:'その他の排出ガス及び騒音低減技術を記載してください',
    obd_y:'有',
    obd_n:'無',
    obd_ph_max_power:'最大出力',
    obd_ph_trans:'変速機(段)',
    obd_ph_combustion:'例) 火花点火、4ストローク',
    obd_ph_fuel_supply:'例) 燃料噴射式(EFI)',
    obd_ph_cat_type:'例) 三元触媒',
    obd_ph_yn:'有 / 無',
    obd_nv_lbl:'N/V比, rpm/kph',
    obd_nv_ph:'N/V比, rpm/kph',
    obd_tire_lbl:'タイヤ',
    obd_tire_f_lbl:'前',
    obd_tire_f_ph:'前タイヤ仕様',
    obd_tire_r_lbl:'後',
    obd_tire_r_ph:'後タイヤ仕様',
    obd_cat_lbl:'触媒変換器形式',
    obd_cat_ph:'触媒変換器形式',
    obd_dpf_lbl:'DPF形式',
    obd_air2_lbl:'2次空気噴射装置の有無',
    obd_egr_lbl2:'排出ガス再循環装置の有無',
    obd_evap_lbl:'蒸発ガス制御装置',
    obd_evap_ph:'蒸発ガス制御装置',
    obd_obd_func_lbl:'OBD構成及び機能',
    obd_obd_op_lbl:'OBD作動方法',
    obd_obd_check_lbl:'OBD誤作動確認方法',
    obd_obd_check_ph:'誤作動確認方法を入力',
    obd_mi_lbl:'誤作動表示方法',
    obd_monitor_ph:'監視項目を入力',
    obd_note_ph:'備考',
    obd_photo_title:'OBDテスト写真：車両、車台番号、エンジン番号写真を含む',
    obd_veh_photo_lbl:'車両写真',
    obd_veh_photo_desc:'車両全体写真（前面/側面/後面）',
    obd_vin_photo_lbl:'車台番号写真',
    obd_vin_photo_desc:'車台番号(VIN)確認写真',
    obd_eng_photo_lbl:'エンジン番号写真',
    obd_eng_photo_desc:'エンジン番号確認写真',
    obd_scanner_photo_lbl:'OBDスキャナー写真',
    obd_scanner_photo_desc:'OBDスキャナー接続及び結果画面写真（複数添付可）',
    obd_attach_title:'添付書類（自体試験成績書 / RAW DATA）',
    upload_click_drag:'クリックまたはファイルをドラッグしてアップロード',
    em_item_hdr:'項目',
    em_fuel_eff_hdr:'燃費 (km/ℓ)',
    em_std_lbl:'基準値',
    ev_gen_info_hdr:'1.　一般事項',
    obd_air2_y_lbl:'有',
    obd_air2_n_lbl:'無',
    obd_egr_y_lbl:'有',
    obd_egr_n_lbl:'無',
    nt_reg_note_ph:'例) 加速走行騒音試験方法（ECE R41-04）',
    nt_test_date_ph:'例) 2025. 01. 01.',
    nt_inspector_ph:'氏名',
    cf_maker_ph:'例) HONDA Motor Co.,Ltd（日本）',
    cf_model_ph:'例) CB500F',
    cf_importer_ph:'例) ○○モーターズ（株）',
    cf_warranty_subject_ph:'保証主体名',
    cf_warranty_text1:'は、大気環境保全法第46条等の規定による',
    cf_warranty_text2:'保証期間内（≤130km/h：2年/20,000km；>130km/h：2年/35,000km）',
    cf_warranty_text3:'新車及び使用中の自動車の排出許容基準を満たすよう義務を履行し、',
    cf_warranty_text4:'欠陥確認時はリコール義務を履行する。',
    cf_warranty_confirm:'当社は上記保証内容について義務を履行することを確認します。',
    cf_signed_at_ph:'署名場所',
    cf_sign_date_ph:'例) 2025. 01. 01.',
    cf_name_ph:'署名者氏名',
    cf_title_ph:'役職',
    attach_dl_title:'ダウンロード',
    attach_del_title:'削除',
    lbl_address:'2. 住&nbsp;&nbsp;&nbsp;所：',
    lbl_model_lbl:'3. モデル：',
    lbl_warranty_content:'5. 保証内容：',
    nt_attach_title:'添付書類（自体試験成績書 / RAW DATA）',
    nt_inspector_ph2:'氏名',
dp_s8_1:'8.1. 燃料装置',
    dp_s8_2:'8.2. 吸排気装置',
    dp_s8_3:'8.3. 点火装置',
    dp_s8_4:'8.4. クランクケース制御装置',
    dp_s8_5:'8.5. エンジン',
    dp_s8_6:'8.6. 触媒変換器',
    dp_s8_7:'8.7. 排出ガス再循環装置(EGR)',
    dp_s8_8:'8.8. 電子制御装置',
    dp_s8_9:'8.9. その他排出ガス制御装置',
    dp_8_1_0:'燃料供給系', dp_8_1_1:'燃料制御系', dp_8_1_2:'燃料噴射系',
    dp_8_2_0:'吸気装置', dp_8_2_1:'排気装置',
    dp_8_3_0:'点火装置',
    dp_8_4_0:'クランクケース制御装置',
    dp_8_5_0:'エンジン',
    dp_8_6_0:'触媒形式', dp_8_6_1:'触媒物質組成', dp_8_6_2:'体積', dp_8_6_3:'触媒重量',
    dp_8_7_0:'排出ガス再循環装置',
    dp_8_8_0:'装置/仕様/入出力信号', dp_8_8_1:'エンジントルク算出方法と適合性資料',
    dp_8_9_0:'その他装置',
    dp_5_4_lbl:'5.4. 騒音試験計画',
g_obd_std2_rep_lbl:'* OBD2 ガソリン基準適用同一(IUPR 1st基準)、代表車種：',
    g_obd_std4_rep_lbl:'* OBD2 ガソリンEURO6基準適用同一(IUPR 2nd基準)、代表車種：',
    g_obd_std_die_rep_lbl:'* OBD2 軽油(ハ)基準適用同一(IUPR 2nd基準)、代表車種：',
    g_evap_same_rep_lbl:'* 蒸発ガス同一、代表車種：',
img_click_to_zoom:'クリックして拡大',
    pw_err_required:'すべての項目を入力してください。',
    pw_err_too_short:'新しいパスワードは4文字以上必要です。',
    pw_err_mismatch:'新しいパスワードが一致しません。',
    err_occurred:'エラーが発生しました。',
    err_network:'ネットワークエラーが発生しました。',
    btn_processing:'処理中...',
    btn_change:'変更',
    pw_changed_ok:'パスワードが変更されました。',
    cf_ph_address:'製造社住所',
    cf_ph_phone:'電話番号',
    cf_ph_fax:'ファックス番号',
    msg_popup_blocked:'ポップアップがブロックされました。ポップアップを許可してから再試行してください。',
    msg_qr_generating:'真正確認コード生成中...',
    msg_network_error:'ネットワークエラー',
    dp_ph_year_ex:'例) 2025',
    dp_ph_disp_ex:'例) 125cc',
    dp_lbl_count:'数',
    dp_lbl_gear2:'2速',
    dp_lbl_gear3:'3速',
    dp_lbl_gear4:'4速',
    dp_lbl_gear5:'5速',
    dp_lbl_gear6:'6速',
    dp_lbl_gear7:'7速',
    dp_lbl_nv_ratio:'N/V 比',
    dp_lbl_rear:'後',
    dp_lbl_category:'区分',
    dp_lbl_item:'項目',
    dp_lbl_car_name:'車名',
    dp_lbl_car_type:'自動車形式',
    dp_lbl_passenger:'乗車定員',
    dp_lbl_model_year:'モデル年式',
    dp_lbl_spec_no:'諸元管理番号',
    dp_lbl_drive:'駆動形態',
    dp_lbl_car_class:'車種',
    dp_lbl_purpose:'用途',
    dp_lbl_trans_type:'変速機種類',
    dp_lbl_body_shape:'車体形状',
    dp_lbl_curb_wt:'車両重量(kg)',
    dp_lbl_gvw:'車両総重量(kg)',
    dp_lbl_inertia_wt:'等価慣性質量(kg)',
    dp_lbl_dyno_hp:'実ダイナモ出力(hp)',
    dp_lbl_dimensions:'寸法',
    dp_lbl_length:'全長(mm)',
    dp_lbl_width:'全幅(mm)',
    dp_lbl_height:'全高(mm)',
    dp_lbl_manufacturer:'製造会社',
    dp_lbl_combustion:'燃焼方式',
    dp_lbl_eng_type:'原動機形式',
    dp_lbl_displacement:'排気量(cc)',
    dp_lbl_eng_pos:'原動機取付位置',
    dp_lbl_fuel_type:'使用燃料',
    dp_lbl_cyl_count:'シリンダ数',
    dp_lbl_cyl_arr:'シリンダ配列',
    dp_lbl_chamber_type:'燃焼室形式',
    dp_lbl_max_power:'最大出力(ps/rpm)',
    dp_lbl_max_torque:'最大トルク(kg-m/rpm)',
    dp_lbl_bore_stroke:'ボア*ストローク(mm)',
    dp_lbl_idle_rpm:'アイドル回転数(rpm)',
    dp_lbl_intake_method:'空気吸入方式',
    dp_lbl_port_size:'ポートサイズ',
    dp_lbl_port_size_mm:'ポートサイズ(mm)',
    dp_lbl_port_shape:'ポート形状',
    dp_lbl_ign_timing:'点火時期(Degree)',
    dp_lbl_fuel_tank:'燃料タンク',
    dp_lbl_capacity_l:'容量(ℓ)',
    dp_lbl_position:'位置',
    dp_lbl_material:'材質',
    dp_lbl_air_cleaner:'エアクリーナー',
    dp_lbl_form_type:'形式',
    dp_lbl_drivetrain:'動力伝達装置',
    dp_lbl_clutch:'クラッチ',
    dp_lbl_operation:'操作方式',
    dp_lbl_gear_ratio:'変速比',
    dp_lbl_gear_1:'1速',
    dp_lbl_forward:'前進',
    dp_lbl_reverse:'後退',
    dp_lbl_red_ratio:'減速比',
    dp_lbl_red1:'第1減速比',
    dp_lbl_red2:'第2減速比',
    dp_lbl_ev_spec:'電気自動車関連諸元',
    dp_lbl_motor_type:'電動機形式',
    dp_lbl_batt_cap:'蓄電池定格電圧及び容量',
    dp_lbl_motor_power:'電動機最大出力',
    dp_lbl_ev_range:'一充電走行距離',
    dp_lbl_tire:'タイヤ',
    dp_lbl_tire_maker:'タイヤ製造会社',
    dp_lbl_tire_struct:'タイヤ構造',
    dp_lbl_tire_size:'タイヤサイズ',
    dp_lbl_front:'前',
    dp_lbl_tire_pres:'タイヤ空気圧',
    dp_lbl_precious_comp:'貴金属成分',
    dp_lbl_precious_g:'貴金属量(g)',
    dp_lbl_vol_cc:'容量(㎤)',
    dp_lbl_pm_ratio:'貴金属物質比(Pt:Pd:Rh)',
    dp_lbl_em_test_info:'排出ガス試験に関する事項',
    dp_lbl_road_load:'実路面負荷力(hp)',
    dp_lbl_road_coef:'道路吸力係数',
    dp_lbl_coast_down:'コーストダウン時間(sec)',
    dp_lbl_canister:'キャニスター',
    dp_lbl_can_cap:'キャニスターの吸収容量',
    dp_lbl_can_size:'キャニスターのサイズ(cc)',
    dp_lbl_can_media:'キャニスターの媒体',
    dp_lbl_evap_cap:'40%燃料時タンク最大蒸発ガス容量',
    dp_lbl_muffler:'マフラー',
    dp_lbl_muf_main:'主マフラー',
    dp_lbl_muf_sub:'補助マフラー',
    dp_lbl_vol_l:'容量(L)',
    dp_lbl_horn_dev:'警報装置',
    dp_lbl_horn:'ホーン',
    dp_lbl_horn_db:'性能(dB(C))',
    dp_lbl_ignition:'点火装置',
    dp_lbl_chassis:'シャシー',
    dp_lbl_other:'その他',
    dp_lbl_remark:'備考',
    dp_lbl_left:'左側',
    dp_lbl_right:'右側',
    dp_lbl_compress_ratio:'圧縮比',
    dp_lbl_car_spec:'自動車諸元',
    dp_lbl_fuel_system:'燃料装置',
    dp_lbl_type_kind:'種類',
    dp_lbl_test_fuel:'試験用燃料',
    dp_lbl_acc_fuel:'走行距離蓄積用燃料',
    dp_lbl_gasoline:'ガソリン',
    dp_lbl_octane:'オクタン価(リサーチ法)',
    dp_lbl_aromatic:'芳香族化合物含量(体積%)',
    dp_lbl_benzene:'ベンゼン含量(体積%)',
    dp_lbl_oxygen:'酸素含量(重量%)',
    dp_lbl_lead:'鉛含量(g/ℓ)',
    dp_lbl_phosphorus:'リン含量(g/ℓ)',
    dp_lbl_olefin:'オレフィン含量(体積%)',
    dp_lbl_vapor_p:'蒸気圧(kPa)',
    dp_lbl_90pct_temp:'90%留出温度(℃)',
    dp_lbl_sulfur:'硫黄含量(重量%)',
    dp_lbl_diesel:'軽油',
    dp_lbl_residual_carbon:'10%残留炭素量(%)',
    dp_lbl_cetane:'セタン指数',
    dp_lbl_fuel_source:'燃料購入先',
    dp_fuel_note:'備考：自動車認証試験燃料は国内で市販されている自動車燃料を原則とする。大気規則別表30の自動車燃料製造基準に該当する項目はこれにより記載を代えることができる。',
    dp_4_1_title:'4.1. 排出ガス測定機器',
    dp_4_2_title:'4.2. 騒音測定機器',
    dp_th_equip_name:'設備・機器名',
    dp_th_model:'モデル名',
    dp_th_type_no:'形式承認番号',
    dp_th_type_date:'形式承認日',
    dp_th_lab_name:'実験室名',
    dp_th_calib_date:'最終精度検査日',
    dp_equip_note:'備考：外国製造者の設備・機器を使用する場合は、当該国の公認検定または承認番号等を形式承認番号に代えて記載できる。',
    dp_5_1_2_lbl:'5.1.2. 試験手順',
    dp_5_2_2_lbl:'5.2.2. ならし走行有無',
    dp_5_2_4_lbl:'5.2.4. 走行場所',
    dp_5_3_2_lbl:'5.3.2. 試験手順',
    dp_5_4_2_lbl:'5.4.2. 試験手順',
    dp_6_1_title:'6.1. 試験車両の整備計画',
    dp_6_1_1_title:'6.1.1. 定期整備',
    dp_6_1_2_title:'6.1.2. 非定期整備',
    dp_6_2_title:'6.2. 車両購入者への推奨整備',
    dp_6_3_title:'6.3. 保証に関する説明',
    dp_6_3_1_lbl:'保証内容',
    dp_6_3_2_lbl:'保証期間',
    dp_6_3_3_lbl:'保証から除外される事項',
    dp_6_3_4_lbl:'車両所有者の義務',
    dp_1_3_title:'1.3. 開発目標（輸入車は外国認証成績等で代替）',
    dp_1_4_title:'認証対象自動車諸元',
    dp_1_3_r0:'許容基準',
    dp_1_3_r1:'開発目標値',
    dp_1_3_r2:'現行基準充足度(%)',
    dp_th_formaldehyde:'ホルムアルデヒド(g/km)',
    dp_th_smoke:'スモーク(%/kWh)',
    dp_2_1_title:'2.1. 機密についての要請',
    dp_8_10_title:'8.10. 感知変数対制御変数',
    dp_8_11_title:'8.11. 部品リスト',
    dp_8_12_title:'8.12. SCR性能・原理説明',
    dp_8_13_title:'8.13. SCR用尿素水溶液成分分析結果',
    dp_8_14_title:'8.14. 電気自動車制御装置',
    dp_8_11_ign:'点火装置',
    dp_8_11_fuel:'燃料供給装置',
    dp_8_11_cat:'排出ガス転換装置',
    dp_8_11_egr:'排出ガス再循環装置',
    dp_8_11_evap:'燃料蒸発ガス防止装置',
    dp_8_11_blow:'ブローバイガス還元装置',
    dp_8_11_air:'2次空気噴射装置',
    dp_8_12_r0:'供給系',
    dp_8_12_r1:'制御系',
    dp_8_12_r2:'噴射系',
    dp_8_12_r3:'充填警告システム',
    dp_th_analysis_result:'分析結果',
    dp_th_analysis_org:'分析機関',
    dp_th_analysis_method:'分析方法',
    dp_th_analysis_date:'分析年月日',
    dp_th_proof_no:'証憑番号',
    dp_sv_o2:'排出ガス中酸素濃度',
    dp_sv_air_flow:'吸入空気流量',
    dp_sv_air_temp:'吸入空気温度',
    dp_sv_coolant:'冷却水温度',
    dp_sv_throttle:'スロットル位置',
    dp_sv_baro:'大気圧',
    dp_sv_intake_vac:'吸気負圧',
    dp_sv_crank:'クランクシャフト位置',
    dp_sv_cam:'カムシャフト位置',
    dp_sv_batt:'バッテリー電圧',
    dp_sv_speed:'車速',
    dp_sv_rpm:'原動機回転数',
    dp_sv_gear:'変速機ギア',
    dp_sv_idle:'停止及びニュートラル',
    dp_sv_brake:'ブレーキ適用',
    dp_sv_ac:'エアコン作動',
    dp_sv_knock:'エンジンノッキング',
    dp_9_1_title:'9.1. 蒸発ガス制御装置説明',
    dp_th_storage:'貯蔵装置',
    dp_th_absorb_cap:'吸収容量(C)',
    dp_th_size_media:'サイズ(㎤)/媒体',
    dp_9_1_r0:'キャニスター',
    dp_9_1_r1:'エアクリーナー',
    dp_9_1_r2:'クランクケース',
    dp_9_1_r3:'その他',
    dp_9_2_title:'9.2. 制御装置構成図',
    dp_9_2_parts_title:'蒸発ガス制御装置部品リスト（補助排出ガス制御装置含む）',
    dp_10_1_title:'10.1. 排出ガス及び騒音同一車種（原動機）説明',
    dp_10_1_cyl_dist_lbl:'シリンダーボア中心間距離(mm)',
    dp_10_1_block_lbl:'シリンダーブロック形状',
    dp_10_1_head_lbl:'シリンダーヘッド方式',
    dp_durability_note:'耐久性試験を実施する場合で、認証申請当時までに詳細開発計画が確定しないなどやむを得ない理由で最初の申請書類に記載できない事項がある場合、その理由を明示し、耐久性試験最終報告書提出時に確定事項を一括提出できる。',
    dp_ph_dev_bg:'開発背景及び特性を記載してください',
    dp_ph_new_tech:'新技術内容を記載してください',
    dp_ph_confidential:'機密要請内容を記載してください',
    dp_ph_engine_content:'エンジン内容',
    dp_ph_ignition_content:'点火装置内容',
    dp_ph_chassis_content:'シャシー内容',
    dp_ph_other_content:'その他内容',
    dp_ph_warranty_content:'保証内容',
    dp_ph_warranty_period:'保証期間',
    dp_ph_warranty_exclusion:'保証除外事項',
    dp_ph_owner_duty:'車両所有者の義務',
    dp_ph_sign_desc:'標識見本説明',
    dp_ph_attach_pos:'取付位置等を記載',
    dp_ph_motor_ctrl:'電動機および電動機制御装置説明',
    dp_ph_batt_ctrl:'蓄電池および蓄電池制御装置説明',
    dp_ph_ctrl_diagram:'制御装置構成図説明',
    dp_ph_em_detail:'適合書提出内訳等',
    dp_lbl_diagram_attach:'{sec} 構成図添付:',
    obd_dtc_default_val:'二輪自動車に欠陥コードが確認されたら',
    obd_lbl_2nd_monitor_suffix:'等のための方法を含む包括的な説明資料',
    obd_lbl_ctrl_dev:'制御装置',
    obd_lbl_diag_config:'自己診断装置の構成',
    msg_coming_soon:'準備中です。',
    msg_qr_login_check:'QRコードを生成するにはログイン状態を確認してください。',
    msg_qr_fail:'QR生成失敗',
    btn_saving:'保存中...',
    msg_saved:'保存されました。',
    msg_save_fail:'保存失敗',
    btn_save:'保存',
    btn_list:'一覧', btn_toc_print:'目次印刷',
    complete_title:'この書類の作成を完了しました', complete_sub:'チェックすると進捗に反映されます',
    nt_rpm_unit:'% 回転速度(rpm)',
    btn_create_app:'申請書作成',
    err_title_required:'申請タイトルを入力してください。',
    err_cert_no_required:'既存の認証番号を入力してください。',
    btn_creating:'作成中...',
    msg_create_fail:'作成失敗',
    msg_app_created:'申請書が作成されました。',
    msg_delete_confirm:'申請書を削除するとすべての書類データも削除されます。\\n続けますか？',
    msg_deleted:'削除されました。',
    msg_delete_fail:'削除失敗',
    pw_lbl_current:'現在のパスワード',
    pw_ph_current:'現在のパスワードを入力してください',
    pw_lbl_new:'新しいパスワード',
    pw_ph_new:'4文字以上',
    pw_lbl_confirm:'新しいパスワード確認',
    pw_ph_confirm:'再入力',
    
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
    g_doc_tag:'[附件第2号格式]',
    g_sec1:'1. 申请概要', g_sec2:'2. 申请类型', g_sec3:'3. 详细内容',
    g_th_div:'区分', g_th_apply_date:'申请日', g_th_maker:'制造商',
    g_th_model:'车名<br>(型式)', g_th_fuel_type:'车种<br>(使用燃料)',
    g_th_output:'功率(ps/rpm)<br>(排量 cc)', g_th_std:'适用标准',
    g_th_cert_no:'认证编号', g_th_note:'备注',
    g_th_div2:'区分', g_th_fuel:'燃料', g_th_cert_content:'认证书记载内容', g_th_applicable:'适用与否',
    g_cat_emission:'排放标准', g_cat_obd:'OBD标准', g_cat_evap:'蒸发气体', g_cat_warranty:'保证期间',
    g_fuel_gasoline:'汽油', g_fuel_diesel:'柴油',
    g_emit_colon:'排放 :', g_noise_colon:'噪音 :',
    sv_applicable:'适用与否',
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
    en_muffler_diagram_title:'1.2 消音器内部结构图',
    en_muffler_spec_title:'1.3 消音器详细规格',
    en_1_3_1:'结构及降噪原理', en_1_3_2:'流程图', en_1_3_3:'制造商',
    en_1_3_4:'内外部材质', en_1_3_5:'尺寸图纸',
    en_cat_spec_title:'1.4 催化装置详细规格',
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
    nt_tire_pres_kpa:'轮胎气压力(kPa)',
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
    btn_write:'编辑', btn_delete:'删除', btn_cancel:'取消', btn_edit_appl:'修改信息', btn_logout:'退出登录',
    modal_edit_title:'修改申请信息', btn_update_appl:'完成修改', msg_update_ok:'申请信息已修改。', msg_update_fail:'修改失败。',
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
    dp_1_2_lbl:'1.2. 排放相关新技术或主要技术',
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

    en_4_3_1_2:'4.3.1.2. 燃油箱位置', en_tank_pos_ph:'位置说明',
    en_4_3_1_3:'4.3.1.3. 燃油箱形状', en_tank_shape_ph:'形状说明',
    en_4_3_2:'4.3.2. 节气门体',
    en_4_3_2_1:'4.3.2.1. 节气门体详细规格', en_throttle_spec_ph:'节气门体规格',
    en_4_3_2_2:'4.3.2.2. 节气门体形状及尺寸',
    en_4_3_3:'4.3.3. 燃油喷嘴',
    en_4_3_3_1:'4.3.3.1. 燃油喷嘴详细规格', en_injector_spec_ph:'燃油喷嘴规格',
    en_4_3_3_2:'4.3.3.2. 燃油喷嘴形状及尺寸',
    en_4_3_4:'4.3.4. 燃油泵',
    en_4_3_4_1:'4.3.4.1. 燃油泵详细规格', en_pump_spec_ph:'燃油泵规格',
    en_4_3_4_2:'4.3.4.2. 燃油泵形状及尺寸',
    en_4_4_fuel_photo:'4.4. 燃油系统照片', en_fuel_photo_ph:'燃油系统照片说明',
    en_sec5:'5. 进排气装置', en_5_1:'5.1. 进气系统',
    en_5_1_1:'5.1.1. 进气歧管结构图', en_intake_diagram_ph:'进气歧管说明',
    en_5_1_2:'5.1.2. 进气歧管', en_intake_manifold_ph:'进气歧管规格或说明',
    en_5_1_3:'5.1.3. 空气滤清器', en_air_filter_ph:'空气滤清器规格或说明',
    en_5_2:'5.2. 排气系统',
    en_5_2_1:'5.2.1. 排气歧管结构图', en_exhaust_diagram_ph:'排气歧管说明',
    en_5_2_2:'5.2.2. 排气歧管', en_exhaust_manifold_ph:'排气歧管规格或说明',
    en_sec6:'6. 车辆外观及尺寸', en_6_1:'6.1. 车辆照片',
    en_6_1_1:'6.1.1. 车辆正面', en_veh_front_ph:'车辆正面说明',
    en_6_1_2:'6.1.2. 车辆后面', en_veh_rear_ph:'车辆后面说明',
    en_6_1_3:'6.1.3. 车辆侧面', en_veh_side_ph:'车辆侧面说明',
    en_6_1_4:'6.1.4. 车辆顶面', en_veh_top_ph:'车辆顶面说明',
    en_6_2:'6.2. 外形图',
    en_6_2_1:'6.2.1. 外形侧视图', en_ext_side_ph:'外形侧视图说明',
    en_6_2_2:'6.2.2. 外形顶视图', en_ext_top_ph:'外形顶视图说明',
    en_6_2_3:'6.2.3. 外形后视图', en_ext_rear_ph:'外形后视图说明',
    en_sec7:'7. 其他', en_7_1:'7.1. 其他排放及噪声减排技术',
    en_other_tech_ph:'请填写其他排放和噪声减排技术',
    obd_yn_y:'有', obd_yn_n:'无',
    obd_max_power_ph:'最大输出功率', obd_trans_ph:'变速箱（档）',
    obd_combustion_ph:'例）火花点火，4冲程', obd_fuel_supply_ph:'例）燃油喷射式(EFI)',
    obd_cat_type_ph:'例）三元催化', obd_yn_ph:'有 / 无',
    obd_nv_lbl:'N/V比，rpm/kph', obd_tire_lbl:'轮胎',
    obd_tire_f_lbl:'前', obd_tire_r_lbl:'后',
    obd_tire_f_ph:'前轮胎规格', obd_tire_r_ph:'后轮胎规格',
    obd_cat_type_lbl:'催化转化器形式', obd_cat_type_sub:'(氧化催化、三元催化、加热式催化 等)',
    obd_dpf_lbl:'DPF形式', obd_egr_lbl:'EGR系统有无',
    obd_evap_lbl:'蒸发排放控制装置', obd_evap_ph:'蒸发排放控制装置',
    obd_diag_lbl:'OBD系统组成及功能', obd_diag_op_lbl:'OBD系统操作方法',
    obd_mi_check_lbl:'MIL故障确认方法', obd_mi_check_ph:'输入故障确认方法',
    obd_mi_disp_lbl:'故障显示方法',
    obd_monitor_ph:'输入监控项目', obd_note_ph:'备注',
    obd_photo_title:'OBD TEST照片：车辆照片、VIN照片、发动机号照片',
    obd_veh_photo_lbl:'车辆照片', obd_veh_photo_desc:'整车照片（含正面/侧面/后面）',
    obd_vin_photo_lbl:'VIN照片', obd_vin_photo_desc:'VIN确认照片',
    obd_eng_photo_lbl:'发动机号照片', obd_eng_photo_desc:'发动机号确认照片',
    obd_scanner_photo_lbl:'OBD扫描仪照片', obd_scanner_photo_desc:'OBD扫描仪连接及结果画面照片（可多张）',
    obd_attach_title:'附件（自检报告 / RAW DATA）',
    obd_upload_hint:'点击或拖拽文件上传',
    em_item_th:'项目', em_fuel_econ_th:'燃油经济性<br>(km/ℓ)', em_std_td:'标准值',
    ev_gen_section:'1. &nbsp;一般事项',
    oo_yn_y:'有', oo_yn_n:'无',
    nt_reg_note_ph:'例）加速行驶噪声试验采用ECE试验方法',
    nt_test_date_ph:'例）2025. 01. 01.',
    nt_div_th:'类别', nt_2nd_lbl:'第2次试验', nt_3rd_lbl:'第3次试验',
    nt_4th_lbl:'第4次试验', nt_avg_lbl:'平均', nt_result_lbl:'结果',
    nt_inspector_ph:'姓名', nt_confirmer_ph:'姓名',
    nt_attach_title:'附件（自检报告 / RAW DATA）',
    nt_ex_pct_lbl:'发动机最高输出<br>转速的',
    nt_upload_hint:'点击或拖拽文件上传',
    cf_maker_ph:'例）HONDA Motor Co.,Ltd（日本）',
    cf_addr_lbl2:'2. 地&nbsp;&nbsp;&nbsp;址 :', cf_model_lbl2:'3. 型&nbsp;&nbsp;&nbsp;号 :',
    cf_model_ph:'例）CB500F', cf_importer_ph:'例）○○汽车有限公司',
    cf_warranty_lbl2:'5. 保证内容 :',
    cf_warranty_subject_ph:'保证主体名称（例）○○汽车有限公司）',
    cf_law_text:'依据大气环境保全法第46条、48条、50条、51条及其施行规则第63条之规定',
    cf_law_period:'在保修期间（130km/h以下：2年或20,000km，130km/h以上：2年或35,000km）内，对制造车辆及',
    cf_law_obligation:'在用车辆满足排放标准，履行质量管理、售后责任等义务，',
    cf_law_recall:'在例行检查及缺陷检查中确认缺陷时，履行缺陷修正（召回）义务。',
    cf_confirm_text:'本公司确认将履行上述保证内容所规定的义务。',
    cf_signed_at_ph:'签名地点', cf_sign_date_ph:'例）2025. 01. 01.',
    cf_name_ph:'签名人姓名', cf_title_ph:'职务',

    dp_th_item:'项目', dp_th_sub_item:'子项目',
    dp_th_structure:'结构/厂商/尺寸/容量等',
    dp_th_ctrl_tech:'控制技术/控制原理', dp_th_emission_eff:'排放减少效果',
    dp_th_sensor_var:'检测变量', dp_th_fuel_afr:'燃料（空燃比）',
    dp_th_ign_timing:'点火时机',
    dp_th_canister_purge:'碳罐净化/怠速/EGR',
    dp_th_note:'备注',
    dp_th_part_no:'零件号', dp_th_mfr:'制造商', dp_th_mfr_country:'制造国',
    dp_th_evap_code:'蒸发气体代码',
    dp_th_nominal_tank:'标称油箱<br>容量(L)',
    dp_th_max_evap:'40%燃油时最大蒸发气体容量',
    dp_th_reservoir:'化油器/喷油装置蓄液池最大容量',
    dp_th_model_name:'适用车型',
    dp_th_category:'类别', dp_th_basic_model:'基础车型',
    dp_th_emission_equiv:'排放及噪声<br>同一车型',
    dp_th_evap_equiv:'蒸发气体同一车型',
    dp_th_obd_equiv:'OBD同一车型',
    dp_th_dur_test:'耐久性试验车辆', dp_th_emission_test_v:'排放试验车辆',
    dp_lbl_intake_manifold:'进气歧管', dp_lbl_intake_port_size:'进气口尺寸',
    dp_lbl_intake_port_shape:'进气口形状',
    dp_lbl_exhaust_manifold:'排气歧管', dp_lbl_exhaust_port_size:'排气口尺寸',
    dp_lbl_exhaust_port_shape:'排气口形状',
    dp_lbl_valve_timing:'气门开闭',
    dp_lbl_intake_valve:'进气<br>门', dp_lbl_exhaust_valve:'排气<br>门',
    dp_lbl_open:'开启', dp_lbl_close:'关闭',
    dp_lbl_valve_count:'每缸气门数',
    dp_lbl_valve_intake:'进气', dp_lbl_valve_exhaust:'排气',
    dp_lbl_valve_size:'气门尺寸',
    dp_lbl_air_intake:'进气方式',
    dp_lbl_cat_type_lbl:'类型', dp_lbl_noble_metal:'贵金属成分',
    dp_lbl_noble_amount:'贵金属量(g)', dp_lbl_volume:'容量(cm³)',
    dp_lbl_noble_ratio:'贵金属比(Pt:Pd:Rh)',
    dp_lbl_canister_design:'碳罐<br>设计特性',
    dp_lbl_evap_absorp:'蒸发气体吸收容量',
    dp_lbl_canister_cnt:'碳罐数量及连接方式',
    dp_lbl_canister_shape:'碳罐形状',
    dp_lbl_canister_structure:'碳罐结构',
    dp_lbl_canister_material:'碳罐材质',
    dp_lbl_fuel_system:'燃油系统', dp_lbl_filler_seal:'加油管密封结构',
    dp_lbl_emission_ctrl:'排放<br>控制装置', dp_lbl_emission_gas:'排放气体',
    dp_lbl_dur_test_select:'耐久性试验车辆选定',

    dp_5_1_1_lbl:'5.1.1. 试验场所', dp_5_1_2_lbl:'5.1.2. 试验程序',
    dp_5_2_1_lbl:'5.2.1. 耐久性试验行驶', dp_5_2_2_lbl:'5.2.2. 磨合行驶',
    dp_5_2_3_lbl:'5.2.3. 计划行驶期间', dp_5_2_4_lbl:'5.2.4. 行驶场所',
    dp_5_2_5_lbl:'5.2.5. 行驶程序',
    dp_5_3_1_lbl:'5.3.1. 试验场所', dp_5_3_2_lbl:'5.3.2. 试验程序',
    dp_5_4_1_lbl:'5.4.1. 试验场所', dp_5_4_2_lbl:'5.4.2. 试验程序',
    dp_lbl_engine:'发动机', dp_lbl_ignition:'点火装置', dp_lbl_chassis:'底盘',
    dp_8_14_1_lbl:'8.14.1. 电动机及电动机控制装置',
    dp_8_14_2_lbl:'8.14.2. 蓄电池及蓄电池控制装置',
    profile_modal_title:'会员信息', profile_tab_info:'修改基本信息', profile_tab_pw:'修改密码',
    profile_lbl_username:'用户名', profile_lbl_company:'公司名', profile_lbl_rep:'负责人',
    profile_lbl_bizno:'营业执照号', profile_lbl_phone:'联系方式',
    profile_ph_company:'输入公司名称', profile_ph_rep:'输入负责人姓名',
    profile_ph_bizno:'营业执照编号', profile_ph_phone:'联系电话',
    profile_btn_save:'保存', profile_saved_ok:'会员信息已修改。',
    profile_err_required:'公司名、负责人、营业执照号为必填项。',
    pw_change_title:'修改密码',
    pw_current_lbl:'当前密码', pw_new_lbl:'新密码',
    pw_confirm_lbl:'确认新密码',
    pw_current_ph:'请输入当前密码', pw_new_ph:'至少4个字符',
    pw_confirm_ph:'请重新输入',
    pw_cancel_btn:'取消', pw_change_btn:'修改',
    btn_processing:'处理中...', btn_change:'修改',
    pw_err_required:'请填写所有项目。', pw_err_too_short:'密码至少需要4个字符。',
    pw_err_mismatch:'新密码不一致。', pw_changed_ok:'密码已修改成功。',
    err_occurred:'发生错误。', err_network:'网络错误。',
    btn_create_app:'创建申请', btn_creating:'创建中...', msg_create_fail:'创建失败。',
    msg_app_created:'申请书已创建。', err_cert_no_required:'请输入原有认证编号。',
    msg_delete_confirm:'确定要删除吗？', msg_deleted:'已删除。', msg_delete_fail:'删除失败。',
    save_error:'保存时发生错误。',
    qr_auth_code_lbl:'真伪确认码',
    qr_verify_title:'真伪验证',
    qr_doc_name:'文件名',
    qr_application:'申请书',
    qr_issued_at:'签发日期',
    qr_issuer:'签发机构',
    obd_lbl_tire:'轮胎',
    obd_ph_trans_step:'变速器(档)',
    obd_sec1_label:'OBD综合信息文件',
    obd_1_1_desc:'1.1. 传感器·执行器等部件清单及功能说明',
    obd_1_2_desc:'1.2. 故障指示灯说明资料',
    obd_1_3_desc:'1.3. 禁止擅自修改及排放控制计算机修改声明',
    obd_1_4_desc:'1.4. 监控装置技术说明资料',
    obd_1_5_desc:'1.5. 其他补充信息',
    obd_1_6_desc:'1.6. 自测结果及技术说明资料',
    obd_sec2_label:'同一车种说明文件',
    obd_sec3_label:'试验车辆选定文件',
    obd_sec2_title:'2. 同一车种说明文件',
    obd_sec3_title:'3. 试验车辆选定文件',
    obd_2_1_title:'2.1. 车辆规格(OBD同一车种中的代表车种)',
    obd_gen_spec_title:'1. 一般规格',
    obd_eng_spec_title:'2. 发动机规格',
    obd_em_ctrl_spec_title:'3. 排放控制装置及OBD规格',
    obd_1_6_1_title:'1.6.1. 试验结果',
    obd_1_6_2_title:'1.6.2. OBD监控部件测试及诊断',
    obd_2_2_title:'2.2. OBD同一车种',
    obd_2_3_title:'2.3. OBD同一车种说明',
    obd_3_1_title:'3.1. OBD试验车辆选定依据',
    obd_lbl_cat_monitor:'催化剂监控装置',
    obd_lbl_dpf_monitor:'DPF监控装置',
    obd_lbl_eis_monitor:'电喷系统监控装置',
    obd_lbl_obd_parts:'OBD系统监控的部件',
    obd_lbl_mil_criteria:'故障指示灯点亮标准',
    obd_lbl_dtc_list:'所有OBD输出码清单及使用格式',
    obd_th_test_req:'试验要求作动标准(Ⅰ)型',
    obd_th_compliance:'合格与否',
    obd_th_part_check:'零件检查',
    obd_th_mi_time:'MI激活时机',
    obd_th_mem_err:'内存中错误码修正',
    obd_th_obd_same:'OBD同一车种',
    obd_th_obd_test_car:'OBD试验车辆',
    obd_lbl_modelname:'型号',
    obd_lbl_vin:'车架号(发动机号)',
    obd_lbl_trans_type:'变速器型式',
    obd_lbl_trans_proc:'换挡程序',
    obd_lbl_equiv_inertia:'等效惯性重量(kg)',
    obd_lbl_final_drive:'最终传动',
    obd_lbl_same_carname:'车名(同一车名)',
    obd_lbl_engine:'发动机',
    obd_lbl_combustion:'燃烧过程(火花点火、压燃、二冲程、四冲程等)',
    obd_lbl_fuel_method:'燃油供给方式(化油器式、喷射式等)',
    obd_lbl_cat_type:'催化转化器型式(氧化催化器、三元催化器等)',
    obd_lbl_dpf_type:'DPF型式',
    obd_lbl_2ndair_yn:'二次空气喷射有无',
    obd_lbl_egr_yn:'废气再循环装置有无',
    obd_lbl_obd_method:'OBD系统工作方法',
    obd_lbl_monitor_check:'监控装置故障确认方法',
    obd_lbl_mal_display:'故障显示方法',
    obd_ph_name_type:'车名(型式)',
    obd_ph_total_weight:'总重量(整备质量)',
    obd_ph_na_or_type:'不适用或填写型式',
    obd_ph_method:'填写工作方法',
    obd_ph_check_method:'填写故障确认方法',
    obd_ph_display_method:'填写故障显示方法',
    obd_ph_vin:'车架号(发动机号)',
    obd_ph_trans_type:'变速器型式',
    obd_ph_trans_proc:'换挡程序',
    obd_ph_equiv_inertia:'等效惯性重量(kg)',
    obd_ph_final_drive:'最终传动',
    obd_ph_same_carname:'同一车名',
    obd_lbl_prep_cycle:'故障确认试验准备循环型式及次数',
    obd_lbl_test_cycle:'监控部件确认试验循环型式说明',
    obd_lbl_2nd_monitor:'监控部件二级监控变量清单',
    obd_lbl_ctrl_indicator:'控制、自动指示器、指示器位置及标识符号',
    obd_div_mil_location:'故障指示灯形态及位置：显示形态/位置的图纸或照片',
    obd_div_left_switch:'左侧手把开关控制及标号图纸',
    obd_div_right_switch:'右侧手把开关控制及标号图纸',
    obd_div_keybox:'钥匙盒图纸',
    obd_txt_malfunction_test:'测试配备故障再现零件或故障摩托车电子设备的车辆时，故障警告灯应在故障判定标准以下点亮，排放自诊断装置判定为合格。',
    obd_txt_electrical_continuity:'应监控排放相关部件或与排放相关且连接到发动机控制单元的动力总成部件的电气连续性。',
    obd_ph_dtc_default:'当两轮车检测到故障码时，仪表盘上的发动机故障灯点亮。',
    obd_ph_no_modify:'填写禁止擅自修改及排放控制计算机修改声明',
    nt_th_gear:'使用<br>变速<br>挡',
    nt_th_entry_speed:'进入<br>指定<br>车速<br>(km/hr)',
    nt_th_test_speed:'试验车速<br>(km/hr.)',
    nt_th_rpm:'发动机转速<br>(rpm)',
    nt_th_accel_pos:'加速<br>起始<br>位置<br>(m)',
    nt_th_bg_noise:'背景<br>噪音<br>[dB<br>(A)]',
    nt_th_meas_noise:'测量噪音<br>[dB(A)]',
    nt_th_correction:'修正<br>值<br>[dB<br>(A)]',
    nt_th_std_val:'基准值<br>[dB<br>(A)]',
    nt_th_accel_init:'加速<br>初始',
    nt_th_accel_end:'加速<br>结束',
    nt_th_left:'左侧',
    nt_th_right:'右侧',
    nt_lbl_1st:'第1次试验',
    nt_lbl_wot_noise:'加速行驶噪音<br>(L_WOTrep, dB(A))',
    nt_lbl_crs_noise:'定速行驶噪音<br>(L_CRSrep, dB(A))',
    em_val_dur_run:'耐久行驶试验',
    em_sec5_cvs:'5. CVS驾驶试验状态',
    em_sec6_result:'6. 试验结果',
    ev_sec2:'2. 测量室及测量设备',
    ev_upload_hint:'点击或拖拽文件上传',
    oo_th_fuel_econ:'燃油经济性<br>(km/ℓ)',
    oo_th_exhaust_gas:'排气管<br>气体',
    oo_th_det_factor:'劣化系数<br>(DF)',
    oo_sec3_emission:'3. 排放控制',
    g_th_compliance_pct:'达标率(%)',
    g_obd_std_2006_gas:'汽油2006年OBD标准',
    g_obd_std_2013_1st:'汽油2013年OBD IUPR 1st标准',
    g_obd_std_2013_2nd:'汽油2013年OBD IUPR 2nd(2016年1月)标准',
    g_obd_std_euro6:'汽油EURO6 OBD IUPR 2nd标准',
    g_obd_std_euro5_2w:'汽油EURO5 OBD两轮车标准(Stage 2)',
    g_obd_std_2006_diesel:'柴油2006年OBD标准',
    g_obd_std_2012_diesel:'柴油2012年OBD IUPR 1st标准',
    g_obd_std_2014_diesel:'柴油2014年9月OBD IUPR 2nd标准',
    g_ph_obd_mal:'OBD2故障判定标准相关内容',
    g_th_monitor_item:'监控项目',
    g_th_test_yn:'试验与否',
    g_th_test_vehicle:'试验车辆',
    g_th_applicable2:'适用与否',
    g_th_meas_result:'测量结果',
    g_lbl_test_facility:'试验设施',
    g_ph_facility_detail:'自测实施设施的设施确认明细',
    g_lbl_vehicle_sel:'试验车辆选定依据',
    g_vehicle_sel_title:'试验车辆选定依据',
    g_vehicle_sel_em:'- 排放试验车辆：依据第11条选定',
    g_vehicle_sel_noise:'- 噪音试验车辆：依据第12条选定',
    g_vehicle_sel_obd:'- OBD试验车辆：依据第23条选定',
    g_ph_additional:'填写附加事项',
    g_ph_em_mode:'排放试验模式、试验次数、自测成绩等',
    g_lbl_evap_test:'蒸发气体试验',
    g_ph_evap_submit:'蒸发气体自测成绩单提交明细等',
    g_lbl_warranty_det:'保证期限及劣化系数',
    g_ph_warranty_detail:'保证期限及劣化系数适用明细',
    g_lbl_warranty_km:'保证期限(km)：',
    g_th_det_factor:'适用劣化系数',
    g_em_co:'一氧化碳(CO)',
    g_em_exhaust_hc:'排气管碳氢化合物',
    g_em_nox:'氮氧化物',
    g_em_evap_hc:'蒸发碳氢化合物',
    g_lbl_endurance:'耐久试验',
    g_ph_endurance_note:'请填写耐久试验内容',
    g_lbl_ki:'周期再生系数<br>(ki)试验',
    g_ph_ki_note:'周期再生系数(ki)试验内容',
    g_lbl_noise_test:'噪音试验',
    g_noise_submit:'噪音试验成绩单提交明细',
    g_ph_noise_submit:'请填写噪音试验成绩单提交明细',
    g_noise_method:'噪音试验方法',
    g_noise_accel_lbl:'- 加速行驶噪音：',
    g_noise_exhaust_lbl:'- 排气噪音：',
    g_noise_horn_lbl:'- 喇叭噪音：',
    g_lbl_same_type:'同一车种构成',
    g_th_div_lbl:'类别',
    g_lbl_o2_sensor:'氧传感器',
    g_lbl_egr:'废气再循环系统',
    g_lbl_vvt:'可变气门正时系统',
    g_lbl_fuel_system:'燃油系统',
    g_lbl_misfire:'失火',
    g_lbl_2nd_air:'二次空气系统',
    en_ph_inner_diag:'内部结构说明',
    en_ph_flow_desc:'流程图说明',
    en_ph_maker_name:'制造商名称',
    en_ph_inner_mat:'内部材质/规格',
    en_ph_outer_mat:'外部材质/规格',
    en_ph_dim_desc:'尺寸图纸说明',
    en_ph_cat_principle:'请填写催化剂原理或效果',
    en_ph_attach_desc:'安装位置说明',
    en_1_5_lbl:'1.5. 传感器详细规格',
    en_1_5_1_lbl:'1.5.1. 传感器制造商',
    en_1_5_2_lbl:'1.5.2. 传感器材质',
    en_1_5_3_lbl:'1.5.3. 传感器尺寸图纸',
    en_ph_sensor_mat:'传感器材质',
    en_1_6_lbl:'1.6. 消音器图纸',
    en_1_7_lbl:'1.7. 消音器照片',
    en_ph_muffler_draw:'消音器图纸说明',
    en_ph_muffler_photo:'消音器照片说明',
    en_sec2_valve:'2. 气门机构(Valve Train)',
    en_2_1_valve:'2.1. 气门机构惯性力',
    en_ph_valve_inertia:'请填写气门机构惯性力相关内容',
    en_2_2_surging:'2.2. 气门弹簧共振对策技术',
    en_ph_surging:'请填写共振对策技术',
    en_2_3_cam:'2.3. 凸轮轮廓及规格',
    en_2_3_1_valve:'2.3.1. 气门规格',
    en_ph_valve_spec:'请填写气门规格',
    en_2_3_2_cam:'2.3.2. 凸轮规格',
    en_ph_cam_spec:'请填写凸轮规格',
    en_2_3_3_cam_dim:'2.3.3. 凸轮尺寸图纸',
    en_ph_cam_dim:'凸轮尺寸图纸说明',
    en_2_4_valve_mat:'2.4. 气门机构材质等内容',
    en_ph_valve_mat:'请填写气门机构材质等内容',
    en_2_5_valve_clearance:'2.5. 气门间隙',
    en_ph_valve_clearance:'气门间隙数值或说明',
    en_sec3_ignition:'3. 点火系统',
    en_3_1_ign_diag:'3.1. 点火系统构成图',
    en_ph_ign_diag:'点火系统构成说明',
    en_3_2_ign_ctrl:'3.2. 点火控制特性',
    en_ph_ign_ctrl:'请填写点火控制特性',
    en_3_3_ign_spec:'3.3. 点火系统详细规格',
    en_3_3_1_gen:'3.3.1. 发电机',
    en_3_3_1_1_gen_spec:'3.3.1.1. 发电机详细规格',
    en_ph_gen_spec:'发电机详细规格',
    en_3_3_1_2_gen_dim:'3.3.1.2. 发电机形状及尺寸规格',
    en_ph_shape_dim:'形状及尺寸说明',
    en_3_3_2_1_cdi_spec:'3.3.2.1. CDI UNIT详细规格',
    en_ph_cdi_spec:'CDI UNIT详细规格',
    en_3_3_2_2_cdi_dim:'3.3.2.2. CDI UNIT形状及尺寸规格',
    en_3_3_3_coil:'3.3.3. 点火线圈',
    en_3_3_3_1_coil_spec:'3.3.3.1. 点火线圈详细规格',
    en_ph_coil_spec:'点火线圈详细规格',
    en_3_3_3_2_coil_dim:'3.3.3.2. 点火线圈形状及尺寸规格',
    en_3_3_4_plug:'3.3.4. 火花塞',
    en_3_3_4_1_plug_spec:'3.3.4.1. 火花塞详细规格',
    en_ph_plug_spec:'火花塞详细规格',
    en_3_3_4_2_plug_dim:'3.3.4.2. 火花塞形状及尺寸规格',
    en_3_3_5_ecu:'3.3.5. ECU详细规格',
    en_3_3_5_1_ecu_spec:'3.3.5.1. ECU详细规格',
    en_ph_ecu_spec:'ECU详细规格',
    en_3_3_5_2_ecu_dim:'3.3.5.2. ECU形状及尺寸规格',
    en_3_4_ign_photo:'3.4. 点火系统照片',
    en_ph_ign_photo:'点火系统照片说明',
    en_sec4_fuel:'4. 燃油装置',
    en_4_1_fuel_sys:'4.1. 燃油装置构成及控制方式',
    en_ph_fuel_sys:'请填写燃油装置构成及控制方式',
    en_4_2_fuel_drawing:'4.2. 燃油装置图纸及尺寸',
    en_ph_drawing_dim:'图纸及尺寸说明',
    en_4_3_fuel_spec:'4.3. 燃油装置详细规格',
    en_4_3_1_tank:'4.3.1. 燃油箱',
    en_4_3_1_1_tank_spec:'4.3.1.1. 燃油箱详细规格',
    en_ph_tank_spec:'燃油箱详细规格',
    obd_wps_lbl:'发动机温度传感器(WPS)',
    obd_o2_lbl:'氧传感器(O₂)',
    obd_injector_lbl2:'燃油喷射装置(喷射器)',
    obd_o2heater_lbl:'O₂传感器加热器',
    obd_wire_throttle:'线控节气门',
    obd_fanrelay_lbl:'散热器风扇继电器',
    obd_pumprelay_lbl:'燃油泵继电器',
    obd_ph_content:'填写内容',
    obd_ph_carname:'车名',
    obd_ph_type:'型式',
    obd_ph_carkind:'车种',
    obd_ph_fuel:'使用燃料',
    obd_ph_weight:'总重量(整备质量, kg)',
    obd_ph_engtype:'发动机型式',
    obd_ph_maxpower:'最大功率',
    obd_ph_cc:'排量(cc)',
    obd_ph_combtype:'燃烧型式',
    obd_ph_cycle:'燃烧循环',
    obd_ph_supplytype:'燃油供给形式',
    obd_ph_cat_info:'催化转化器型式及制造商',
    obd_ph_ecu_info:'电子控制装置型式及制造商',
    obd_ph_o2s_info:'氧传感器型式及制造商',
    obd_ph_purge_info:'净化控制阀型式及制造商',
    obd_val_pass:'合格',
    obd_val_fail:'不合格',
    obd_th_part_harness:'零件/线束',
    obd_th_switch:'开关',
    obd_th_start:'启动',
    obd_th_spec:'规格',
    obd_th_mil:'故障指示灯点亮',
    obd_th_carname:'车名',
    obd_th_type:'型式',
    obd_th_carkind:'车种',
    obd_th_weight:'总重量(整备质量, kg)',
    obd_th_cc:'排量(cc)',
    obd_th_combtype:'燃烧型式',
    obd_th_cycle:'燃烧循环',
    obd_th_supplytype:'燃油供给形式',
    obd_th_cat:'催化转化器型式(制造商)',
    obd_th_2nd_air:'二次空气喷射',
    obd_th_egr:'废气再循环装置',
    obd_th_ecu:'电子控制装置型式(制造商)',
    obd_th_o2s:'氧传感器型式(制造商)',
    obd_th_purge:'净化控制阀型式(制造商)',
    obd_th_name_type:'车名(型式)',
    obd_th_engtype:'发动机型式',
    obd_th_maxpower:'最大功率',
    obd_th_trans_step:'变速器(档)',
    obd_ph_part_check:'零件检查内容',
    obd_ph_mi_time:'MI激活时机',
    obd_ph_err_fix:'错误码修正',
    obd_ph_part_harness:'零件/线束',
    obd_ph_switch:'开关',
    obd_ph_start:'启动',
    obd_ph_spec:'规格',
    em_ph_engtype:'发动机型式或技术内容',
    g_2_1_label:'2.1. EURO–5标准适用 汽油两轮车认证申请，代表车种：',
    g_2_2_obd:'2.2. OBD代表车种：',
    g_evap_rep_lbl:'蒸发气体代表车种：',
    g_em1_txt:'* 13年汽油标准2-乙',
    g_em2_txt:'* 13年汽油标准1-乙',
    g_em3_txt:'* 16年汽油标准',
    g_em4_txt:'* 2020年1月两轮车(≤130km/h)标准',
    g_em5_txt:'* 14年9月柴油小型乘用标准',
    g_obd1_txt:'* OBD2汽油标准适用代表(IUPR 1st标准)',
    g_obd2_txt:'* OBD2汽油标准适用同一(IUPR 1st), 代表车种：',
    g_obd3_txt:'* OBD2汽油EURO6标准适用代表(IUPR 2nd标准)',
    g_obd4_txt:'* OBD2汽油EURO6标准适用同一(IUPR 2nd), 代表车种：',
    g_obd5_txt:'* OBD2汽油EURO5两轮车标准适用代表(OBD Stage 2)',
    g_obd6_txt:'* OBD2柴油(丙)标准适用代表(IUPR 2nd标准)',
    g_obd7_txt:'* OBD2柴油(丙)标准适用同一(IUPR 2nd), 代表车种：',
    g_evap1_txt:'* 蒸发气体代表',
    g_evap2_txt:'* 蒸发气体同一, 代表车种：',
    g_war1_txt:'* 保证期限：10年/19.2万km',
    g_war2_txt:'* 保证期限：10年/24万km',
    g_war3_txt:'* 保证期限：15年/24万km',
    g_war4_txt:'* 保证期限：2年/3.5万km',
    g_war5_txt:'* 保证期限：2年/2万km',
    g_war6_txt:'* 保证期限：10年/16万km',
    g_3_1_lbl:'3.1. 适用技术',
    g_3_2_1_lbl:'3.2.1. 排放',
    g_3_2_2_lbl:'3.2.2. 噪音',
    g_3_3_lbl:'3.3. 详细技术内容',
    g_3_4_lbl:'3.4. 试验设施',
    g_3_5_lbl:'3.5. 排放试验',
    g_3_6_lbl:'3.6. 蒸发气体试验',
    g_3_7_lbl:'3.7. 保证及劣化系数',
    g_3_8_lbl:'3.8. 耐久试验',
    g_3_9_lbl:'3.9. KI试验',
    g_3_10_lbl:'3.10. 噪音试验',
    g_3_11_lbl:'3.11. 同一车种',
    g_th_hc:'碳氢化合物',
    g_th_allow_std:'允许标准',
    g_th_test_result:'试验结果',
    g_th_accel_db:'加速行驶<br>dB(A)',
    g_th_exhaust_db:'排气<br>dB(A)',
    g_th_horn_db:'喇叭<br>dB(A)',
    g_th_co_gkm:'CO<br>(g/km)',
    g_th_hcnox_gkm:'HC+NOx<br>(g/km)',
    g_th_pm_gkm:'PM<br>(g/km)',
    g_th_exhaust_hc:'排气HC<br>(g/km)',
    g_th_evap_hc:'蒸发HC<br>(g/test)',
    g_th_obd_std:'OBD标准名称',
    g_th_monitor_dev:'试验监控装置',
    g_th_wmtc:'WMTC模式<br>CO(g/km)',
    g_th_mil_on:'指示灯<br>点亮与否',
    g_th_judge_std:'判断标准<br>CO(g/km)',
    g_th_monitor_judge:'监控装置<br>合格判定',
    g_th_item:'项目',
    g_th_content:'内容',
    g_th_result_judge:'结果判定',
    g_th_malfunction:'故障再现条件',
    g_th_device_name:'装置名称',
    g_lbl_catalyst:'催化器·DPF等后处理装置',
    g_lbl_evap:'蒸发气体',
    g_lbl_blowby:'窜气',
    g_lbl_obd2:'排放气体自诊断装置<br>(OBD2)',
    g_lbl_catalyst_br:'催化器·DPF等<br>后处理装置',
    g_lbl_catalyst2:'催化器',
    g_lbl_o2:'O₂传感器',
    g_ph_tech:'请填写适用的排放及噪音减排技术',
    g_ph_em_result:'排放自测结果',
    g_ph_noise_result:'噪音自测结果',
    g_ph_catalyst:'后处理装置详细内容',
    g_ph_evap_detail:'蒸发气体代表/同一与否及相关内容',
    g_ph_blowby:'窜气控制装置内容',
    g_ph_obd_rep:'OBD2代表/同一与否及相关内容',
    g_ph_facility:'试验设施详情',
    g_ph_em_test:'排放试验内容',
    g_ph_evap_test:'蒸发气体试验内容',
    g_ph_warranty:'保证及劣化系数内容',
    g_ph_endurance:'耐久试验内容',
    g_ph_ki:'KI试验内容',
    g_ph_noise_test:'噪音试验内容',
    g_ph_same_type:'请填写同一车种构成内容',
    g_ph_applicable:'适用/不适用',
    g_ph_misfire:'失火',
    g_ph_degradation:'劣化',
    g_ph_yn:'有/无',
    g_ph_pass_fail:'合格/不合格',
    g_ph_img:'拖放或点击图片',
    en_doc_tag:'[附件第5号格式]',
    en_main_title_txt:'排放噪音减排装置资料',
    en_sec1:'1. 消音器（消声器）',
    en_1_1_lbl:'1.1 消音器构成明细',
    en_1_2_lbl:'1.2 消音器内部结构图',
    en_1_3_lbl:'1.3 消音器详细规格',
    en_1_4_lbl:'1.4 催化装置详细规格',
    en_sec2:'2. 空气滤清器',
    en_2_1_lbl:'2.1 空气滤清器详细规格',
    en_1_3_1_lbl:'结构及降噪原理',
    en_1_3_2_lbl:'流程图',
    en_1_3_3_lbl:'制造商',
    en_inside_lbl:'内部：',
    en_outside_lbl:'外部：',
    en_dim_draw_lbl:'尺寸图纸',
    en_principle_lbl:'原理或效果',
    en_attach_pos_lbl:'安装位置',
    en_cat_maker_lbl:'催化剂制造商',
    en_cat_material_lbl:'催化剂材质',
    en_cat_perf_lbl:'催化剂性能及尺寸',
    en_inside_mat_lbl:'内部材质',
    en_outside_mat_lbl:'外部材质',
    en_ph_muffler_comp:'请填写消音器构成明细',
    en_ph_muffler_diag:'请填写消音器内部结构图',
    en_ph_noise_principle:'请填写降噪原理',
    en_ph_flow:'请填写流程图',
    en_ph_maker:'请填写制造商',
    en_ph_inside:'请填写内部材质',
    en_ph_outside:'请填写外部材质',
    en_ph_dim:'请填写尺寸图纸',
    en_ph_cat_maker:'请填写催化剂制造商',
    en_ph_cat_mat:'请填写催化剂材质',
    en_ph_cat_perf:'请填写催化剂性能及尺寸',
    en_ph_principle:'请填写原理或效果',
    en_ph_pos:'请填写安装位置',
    en_ph_aircleaner:'请填写空气滤清器详细规格',
    obd_doc_tag:'[附件第9号格式]',
    obd_main_title_txt:'关于排放气体自诊断装置(OBD)构成的文件',
    obd_sec1:'1. 排放气体自诊断装置(OBD)综合信息文件',
    obd_sec2:'2. 关于OBD系统功能的文件',
    obd_th_parts:'汽车排放相关部件',
    obd_th_func:'功能运行特性',
    obd_lbl_sensor:'传感器',
    obd_lbl_actuator:'执行器',
    obd_cps_lbl:'曲轴位置传感器(CPS)',
    obd_tmap_lbl:'温度气压传感器(T-MAP)',
    obd_wts_lbl:'冷却水温度传感器(WTS)',
    obd_o2s_lbl:'氧传感器(HO2S)',
    obd_tps_lbl:'节气门位置传感器(TPS)',
    obd_injector_lbl:'燃油喷射器',
    obd_pump_lbl:'燃油泵',
    obd_idle_lbl:'怠速控制',
    obd_coil_lbl:'点火线圈',
    obd_cat_lbl:'催化转化器',
    obd_egr_lbl:'EGR系统',
    obd_evap_sys_lbl:'蒸发控制系统',
    obd_air2_lbl:'二次空气喷射系统',
    obd_fuel_sys_lbl:'燃油系统',
    obd_trans_lbl:'变速器',
    obd_ph_func:'请填写功能运行特性',
    obd_2_1_lbl:'2.1. 故障码(DTC)读取功能',
    obd_2_2_lbl:'2.2. 就绪监控状态',
    obd_2_3_lbl:'2.3. 冻结帧数据支持与否',
    obd_2_4_lbl:'2.4. 故障码清除功能',
    obd_2_5_lbl:'2.5. 诊断设备通信协议',
    obd_th_item2:'项目',
    obd_th_content2:'内容',
    obd_th_support:'支持与否',
    obd_val_support:'支持',
    obd_val_nosupport:'不支持',
    obd_ph_yn:'是/否',
    obd_ph_protocol:'请填写通信协议',
    em_doc_tag:'[附件第18-2号格式]',
    em_sec1:'1. 一般事项',
    em_sec2:'2. 试验车辆规格',
    em_sec3:'3. 试验车发动机规格',
    em_sec4:'4. 试验设备',
    em_th_test_div:'试验类别',
    em_val_dur:'耐久试验',
    em_val_emis:'排放试验',
    em_val_insp:'定期检验',
    em_val_etc:'其他',
    em_lbl_cvs:'CVS装置',
    em_lbl_analyzer:'分析仪',
    em_lbl_chassis:'底盘测功机',
    em_lbl_eng_type:'发动机型式',
    em_lbl_total_cc:'总排量(cc)',
    em_lbl_comp_ratio:'压缩比',
    em_lbl_max_power:'最大功率(ps/rpm)',
    em_lbl_fuel_supply:'燃油供给方式',
    em_lbl_cooling:'冷却方式',
    em_lbl_ignition:'点火方式',
    em_lbl_valves:'气门数',
    em_lbl_cc_per_cyl:'排量(cc/缸)',
    em_lbl_cylinders:'气缸数',
    em_lbl_maker_model:'制造商及型号',
    em_lbl_range:'测量范围',
    em_lbl_maker2:'制造商',
    em_lbl_model2:'型号',
    em_lbl_max_abs:'最大吸收力(kW)',
    em_lbl_inertia:'惯性重量(kg)',
    ev_doc_tag:'[附件第23号格式]',
    ev_attach_title:'附件（自检报告 / 原始数据）',
    ev_attach_note:'上传JPG、PNG或PDF文件。附件在打印时不会输出。',
    oo_doc_tag:'[附件第26号格式]',
    oo_th_trans_type:'变速器类型',
    oo_ph_type_maker:'型式/制造商',
    nt_doc_tag:'[附件第27号至第27-2号格式]',
    nt_test_date_lbl:'2. 试验日期：',
    nt_na:'不适用',
    nt_accel_noise_meas:'加速行驶噪音<br>测量',
    cf_maker_lbl:'1. 制造商：',
    cf_addr_lbl:'2. 地　　址：',
    cf_model_lbl:'3. 型　　号：',
    cf_importer_lbl:'4. 进口商：',
    g_ph_maker:'例) PIAGGIO C.S.P.A(意大利)',
    g_ph_model:'例) RSV4 1000 RR',
    g_ph_fuel:'例) 汽油、柴油、液化石油气',
    g_ph_euro5:'例) EURO 5',
    g_ph_ece_noise:'例) ECE R41-04',
    g_ph_rep_nonrep:'代表/非代表',
    g_ph_cert_id:'例) ABC-123',
    g_ph_warranty_yr:'年',
    g_ph_self_test:'例) OBD、噪声、蒸发气体',
    g_ph_key_tech:'例) 氧传感器、三元催化剂、OBD、ECU、怠速控制、电子燃油喷射',
    g_category:'区分',
    dp_valve_close:'关闭',
    dp_valve_per_cyl:'每缸气门数',
    dp_valve_intake:'进气',
    dp_valve_exhaust:'排气',
    dp_valve_size:'气门尺寸',
    dp_air_intake_type:'空气进气方式',
    dp_type:'类型',
    dp_noble_metal:'贵金属成分',
    dp_noble_metal_g:'贵金属量(g)',
    dp_capacity_cc:'容量(㎤)',
    dp_noble_ratio:'贵金属比率(Pt:Pd:Rh)',
    dp_10_1_crank_cam_lbl:'曲轴中心线到凸轮轴中心线距离(mm)',
    dp_10_1_crank_head_lbl:'曲轴中心线到气缸体缸盖面上部距离(mm)',
    dp_10_1_tdc_lbl:'TDC状态下燃烧室表面积体积比率',
    dp_10_1_fuel_supply_lbl:'燃油供应方式',
    dp_10_1_inj_range_lbl:'喷射正时控制范围',
    dp_10_1_cam_timing_lbl:'凸轮轴正时',
    dp_10_1_inertia_lbl:'等效惯性质量',
    dp_10_1_roadload_lbl:'道路负荷功率',
    dp_10_2_title:'10.2. 蒸发排放同型车辆说明',
    dp_10_2_category:'区分',
    dp_10_2_base:'基本车型',
    dp_10_2_same:'蒸发排放同型车辆',
    dp_10_2_certno_lbl:'排放认证编号',
    dp_10_2_carname_lbl:'车辆名称',
    dp_10_2_type_lbl:'车辆型式',
    dp_10_2_eng_lbl:'发动机型式',
    dp_10_2_cartype_lbl:'车种',
    dp_10_2_fuel_lbl:'使用燃料',
    dp_10_2_evap_type_lbl:'蒸发气体储存形式',
    dp_canister_design:'碳罐设计特性',
    dp_canister_capacity:'蒸发气体吸收容量',
    dp_canister_count:'碳罐数量及连接方式',
    dp_canister_shape:'碳罐形状',
    dp_canister_struct:'碳罐结构',
    dp_canister_mat:'碳罐材质',
    dp_fuel_system:'燃油系统',
    dp_filler_seal:'加油口密封结构',
    dp_10_2_ctrl_lbl:'蒸发气体控制系统',
    dp_10_2_purge_lbl:'吹扫控制系统',
    dp_10_2_hose_mat_lbl:'蒸发气体软管材质',
    dp_10_2_tank_mat_lbl:'燃油箱材质',
    dp_10_3_title:'10.3. 排放自诊断装置同型车辆说明',
    dp_10_3_category:'区分',
    dp_10_3_base:'基本车型',
    dp_10_3_same:'排放自诊断装置同型车辆',
    dp_10_3_certno_lbl:'排放认证编号',
    dp_10_3_carname_lbl:'车辆名称',
    dp_10_3_type_lbl:'车辆型式',
    dp_10_3_eng_lbl:'发动机型式',
    dp_10_3_cartype_lbl:'车种',
    dp_10_3_fuel_lbl:'使用燃料',
    dp_10_3_obd_op_lbl:'OBD操作方法',
    dp_10_3_std_lbl:'排放许可基准',
    dp_10_3_cycle_lbl:'燃烧循环',
    dp_10_3_fuel_supply_lbl:'燃油供应方式',
    dp_10_3_cat_lbl:'催化转化装置形态',
    dp_10_3_dpf_lbl:'颗粒物捕集装置形态',
    dp_10_3_air2_lbl:'二次空气喷射有无',
    dp_10_3_egr_lbl:'EGR装置有无',
    dp_11_1_title:'11.1. 试验车辆选定',
    dp_11_1_category:'区分',
    dp_11_1_dur:'耐久性试验车辆',
    dp_11_1_emis:'排放试验车辆',
    dp_11_1_vin_lbl:'车架号(发动机号)',
    dp_11_1_disp_lbl:'排量(cc)',
    dp_11_1_eng_code_lbl:'发动机代码',
    dp_11_1_evap_code_lbl:'蒸发气体代码',
    dp_11_1_cat_code_lbl:'催化剂代码',
    dp_11_1_emis_ctrl:'排放控制装置',
    dp_11_1_emis_gas:'排放气体',
    dp_11_1_model_lbl:'型号名称',
    dp_11_1_trans_lbl:'变速器形态',
    dp_11_1_trans_proc_lbl:'换挡程序',
    dp_11_1_inertia_lbl:'等效惯性质量(kg)',
    dp_11_1_final_red_lbl:'末级减速器',
    dp_11_1_nv_lbl:'N/V比, RPM/KPH',
    dp_11_1_tire_lbl:'轮胎',
    dp_11_1_note_lbl:'备注',
    dp_11_1_sub_hdr_ph:'车辆型式',
    dp_11_1_sub_name_lbl:'车辆名称',
    dp_11_1_sub_type_lbl:'车辆型式',
    dp_11_1_sub_trans_lbl:'变速器',
    dp_11_1_sub_eng_lbl:'发动机型式',
    dp_11_1_sub_disp_lbl:'排量',
    dp_11_1_sub_weight_lbl:'整备质量',
    dp_11_1_sub_inertia_lbl:'等效惯性质量',
    dp_11_1_sub_roadload_lbl:'道路负荷功率',
    dp_11_1_sub_tankvol_lbl:'燃油箱容量',
    dp_11_1_sub_finalred_lbl:'最终传动比',
    dp_11_1_sub_sales_lbl:'销售台数',
    dp_11_2_title:'11.2. 耐久性试验车辆选定',
    dp_11_2_sel_lbl:'耐久性试验车辆选定',
    dp_11_2_note_ph:'请填写耐久性试验车辆选定内容',
    dp_11_3_title:'11.3. 排放试验车辆选定',
    dp_11_3_a_case:'A. 使用底盘测功机的情况：',
    dp_11_3_a_0_lbl:'同型车辆中等效惯性质量最大的',
    dp_11_3_a_1_lbl:'上述条件下道路负荷力最大的',
    dp_11_3_a_2_lbl:'上述条件下排量最大的',
    dp_11_3_a_3_lbl:'上述条件下最高最终传动比变速器',
    dp_11_3_a_4_lbl:'上述条件下燃油箱容量最大的',
    dp_11_3_b_case:'B. 使用发动机测功机的情况：',
    dp_11_3_b_0_lbl:'最大扭矩转速下每行程燃油分配率最高的发动机',
    dp_11_3_b_1_lbl:'最高转速下每行程燃油分配率最高的发动机',
    dp_11_4_title:'11.4. 噪声试验车辆选定',
    dp_11_4_0_lbl:'整备质量最重的车辆',
    dp_11_4_1_lbl:'排量最大的车辆',
    dp_11_4_2_lbl:'最终传动比最高的变速器车辆',
    dp_11_4_3_lbl:'车轴比最高的车辆',
    dp_12_ph:'说明不可避免的理由',
    dp_13_ph:'其他事项',
    en_tank_pos_sec:'4.3.1.2. 燃油箱位置',
    en_tank_pos_ph:'位置说明',
    en_tank_shape_sec:'4.3.1.3. 燃油箱形状',
    en_tank_shape_ph:'形状说明',
    en_throttle_sec:'4.3.2. 节气门体',
    en_throttle_spec_sec:'4.3.2.1. 节气门体详细规格',
    en_throttle_spec_ph:'节气门体详细规格',
    en_throttle_dim_sec:'4.3.2.2. 节气门体形状及尺寸规格',
    en_injector_sec:'4.3.3. 燃油喷射器',
    en_injector_spec_sec:'4.3.3.1. 燃油喷射器详细规格',
    en_injector_spec_ph:'燃油喷射器详细规格',
    en_injector_dim_sec:'4.3.3.2. 燃油喷射器形状及尺寸规格',
    en_pump_sec:'4.3.4. 燃油泵',
    en_pump_spec_sec:'4.3.4.1. 燃油泵详细规格',
    en_pump_spec_ph:'燃油泵详细规格',
    en_pump_dim_sec:'4.3.4.2. 燃油泵形状及尺寸规格',
    en_fuel_photo_sec:'4.4. 燃油装置照片',
    en_fuel_photo_ph:'燃油装置照片说明',
    en_intake_sec:'5. 进排气装置',
    en_intake_sub:'5.1. 进气系统',
    en_intake_diagram_sec:'5.1.1. 进气歧管构成图',
    en_intake_diagram_ph:'进气歧管构成说明',
    en_intake_manifold_sec:'5.1.2. 进气歧管',
    en_intake_manifold_ph:'进气歧管规格或说明',
    en_air_filter_sec:'5.1.3. 空气滤清器',
    en_air_filter_ph:'空气滤清器规格或说明',
    en_exhaust_sub:'5.2. 排气系统',
    en_exhaust_diagram_sec:'5.2.1. 排气歧管构成图',
    en_exhaust_diagram_ph:'排气歧管构成说明',
    en_exhaust_manifold_sec:'5.2.2. 排气歧管',
    en_exhaust_manifold_ph:'排气歧管规格或说明',
    en_veh_sec:'6. 车辆外观及尺寸',
    en_veh_photo_sub:'6.1. 车辆照片',
    en_veh_front_sec:'6.1.1. 车辆前面',
    en_veh_front_ph:'车辆前面说明',
    en_veh_rear_sec:'6.1.2. 车辆后面',
    en_veh_rear_ph:'车辆后面说明',
    en_veh_side_sec:'6.1.3. 车辆侧面',
    en_veh_side_ph:'车辆侧面说明',
    en_veh_top_sec:'6.1.4. 车辆上面',
    en_veh_top_ph:'车辆上面说明',
    en_ext_sub:'6.2. 外形图',
    en_ext_side_sec:'6.2.1. 外形侧面',
    en_ext_side_ph:'外形侧面说明',
    en_ext_top_sec:'6.2.2. 外形上面',
    en_ext_top_ph:'外形上面说明',
    en_ext_rear_sec:'6.2.3. 外形后面',
    en_ext_rear_ph:'外形后面说明',
    en_other_sec:'7. 其他',
    en_other_tech_sub:'7.1. 其他排放及噪声降低技术',
    en_other_tech_ph:'请填写其他排放及噪声降低技术',
    obd_y:'有',
    obd_n:'无',
    obd_ph_max_power:'最大功率',
    obd_ph_trans:'变速器(档)',
    obd_ph_combustion:'例) 火花点火，4冲程',
    obd_ph_fuel_supply:'例) 燃油喷射式(EFI)',
    obd_ph_cat_type:'例) 三元催化剂',
    obd_ph_yn:'有 / 无',
    obd_nv_lbl:'N/V比, rpm/kph',
    obd_nv_ph:'N/V比, rpm/kph',
    obd_tire_lbl:'轮胎',
    obd_tire_f_lbl:'前',
    obd_tire_f_ph:'前轮胎规格',
    obd_tire_r_lbl:'后',
    obd_tire_r_ph:'后轮胎规格',
    obd_cat_lbl:'催化转化器型式',
    obd_cat_ph:'催化转化器型式',
    obd_dpf_lbl:'颗粒捕集器型式',
    obd_air2_lbl:'二次空气喷射装置有无',
    obd_egr_lbl2:'排放气体再循环装置有无',
    obd_evap_lbl:'蒸发气体控制装置',
    obd_evap_ph:'蒸发气体控制装置',
    obd_obd_func_lbl:'OBD构成及功能',
    obd_obd_op_lbl:'OBD操作方法',
    obd_obd_check_lbl:'OBD故障确认方法',
    obd_obd_check_ph:'输入故障确认方法',
    obd_mi_lbl:'故障指示方法',
    obd_monitor_ph:'输入监控项目',
    obd_note_ph:'备注',
    obd_photo_title:'OBD测试照片：包含车辆、车架号、发动机号照片',
    obd_veh_photo_lbl:'车辆照片',
    obd_veh_photo_desc:'车辆整体照片（前面/侧面/后面）',
    obd_vin_photo_lbl:'车架号照片',
    obd_vin_photo_desc:'车架号(VIN)确认照片',
    obd_eng_photo_lbl:'发动机号照片',
    obd_eng_photo_desc:'发动机号确认照片',
    obd_scanner_photo_lbl:'OBD扫描仪照片',
    obd_scanner_photo_desc:'OBD扫描仪连接及结果界面照片（可多张）',
    obd_attach_title:'附件（自测报告 / RAW DATA）',
    upload_click_drag:'点击或拖拽文件上传',
    em_item_hdr:'项目',
    em_fuel_eff_hdr:'燃油效率 (km/ℓ)',
    em_std_lbl:'基准值',
    ev_gen_info_hdr:'1. 一般事项',
    obd_air2_y_lbl:'有',
    obd_air2_n_lbl:'无',
    obd_egr_y_lbl:'有',
    obd_egr_n_lbl:'无',
    nt_reg_note_ph:'例) 加速行驶噪声试验方法（ECE R41-04）',
    nt_test_date_ph:'例) 2025. 01. 01.',
    nt_inspector_ph:'姓名',
    cf_maker_ph:'例) HONDA Motor Co.,Ltd（日本）',
    cf_model_ph:'例) CB500F',
    cf_importer_ph:'例) ○○汽车有限公司',
    cf_warranty_subject_ph:'保证主体名称',
    cf_warranty_text1:'依据《大气环境保护法》第46、48、50、51条等规定',
    cf_warranty_text2:'在保证期限内（≤130km/h：2年/20,000km；>130km/h：2年/35,000km）',
    cf_warranty_text3:'确保新车及在用车辆符合排放标准，履行相关义务，',
    cf_warranty_text4:'发现缺陷时履行召回义务。',
    cf_warranty_confirm:'本公司确认将履行上述保证内容的义务事项。',
    cf_signed_at_ph:'签署地点',
    cf_sign_date_ph:'例) 2025. 01. 01.',
    cf_name_ph:'签署者姓名',
    cf_title_ph:'职务',
    attach_dl_title:'下载',
    attach_del_title:'删除',
    lbl_address:'2. 地&nbsp;&nbsp;&nbsp;址：',
    lbl_model_lbl:'3. 型&nbsp;&nbsp;&nbsp;号：',
    lbl_warranty_content:'5. 保证内容：',
    nt_attach_title:'附件（自测报告 / RAW DATA）',
    nt_inspector_ph2:'姓名',
dp_s8_1:'8.1. 燃油系统',
    dp_s8_2:'8.2. 进排气装置',
    dp_s8_3:'8.3. 点火装置',
    dp_s8_4:'8.4. 曲轴箱控制装置',
    dp_s8_5:'8.5. 发动机',
    dp_s8_6:'8.6. 催化转化器',
    dp_s8_7:'8.7. 排放气体再循环装置(EGR)',
    dp_s8_8:'8.8. 电子控制装置',
    dp_s8_9:'8.9. 其他排放控制装置',
    dp_8_1_0:'燃油供应系', dp_8_1_1:'燃油控制系', dp_8_1_2:'燃油喷射系',
    dp_8_2_0:'进气装置', dp_8_2_1:'排气装置',
    dp_8_3_0:'点火装置',
    dp_8_4_0:'曲轴箱控制装置',
    dp_8_5_0:'发动机',
    dp_8_6_0:'催化形式', dp_8_6_1:'催化物质组成', dp_8_6_2:'体积', dp_8_6_3:'催化重量',
    dp_8_7_0:'排放气体再循环装置',
    dp_8_8_0:'装置/规格/输入输出信号', dp_8_8_1:'发动机转矩计算方法与适合性资料',
    dp_8_9_0:'其他装置',
    dp_5_4_lbl:'5.4. 噪声试验计划',
g_obd_std2_rep_lbl:'* OBD2汽油基准适用同型(IUPR 1st基准)，代表车型：',
    g_obd_std4_rep_lbl:'* OBD2汽油EURO6基准适用同型(IUPR 2nd基准)，代表车型：',
    g_obd_std_die_rep_lbl:'* OBD2柴油(丙)基准适用同型(IUPR 2nd基准)，代表车型：',
    g_evap_same_rep_lbl:'* 蒸发气体同型，代表车型：',
img_click_to_zoom:'点击放大',
    pw_err_required:'请填写所有字段。',
    pw_err_too_short:'新密码至少需要4个字符。',
    pw_err_mismatch:'新密码不匹配。',
    err_occurred:'发生了错误。',
    err_network:'发生了网络错误。',
    btn_processing:'处理中...',
    btn_change:'更改',
    pw_changed_ok:'密码已更改成功。',
    cf_ph_address:'制造商地址',
    cf_ph_phone:'电话号码',
    cf_ph_fax:'传真号码',
    msg_popup_blocked:'弹出窗口被阻止。请允许弹出窗口后重试。',
    msg_qr_generating:'正在生成验证码...',
    msg_network_error:'网络错误',
    dp_ph_year_ex:'例) 2025',
    dp_ph_disp_ex:'例) 125cc',
    dp_lbl_count:'数量',
    dp_lbl_gear2:'2挡',
    dp_lbl_gear3:'3挡',
    dp_lbl_gear4:'4挡',
    dp_lbl_gear5:'5挡',
    dp_lbl_gear6:'6挡',
    dp_lbl_gear7:'7挡',
    dp_lbl_nv_ratio:'N/V 比',
    dp_lbl_rear:'后',
    dp_lbl_category:'分类',
    dp_lbl_item:'项目',
    dp_lbl_car_name:'车名',
    dp_lbl_car_type:'车辆型式',
    dp_lbl_passenger:'载客人数',
    dp_lbl_model_year:'型号年度',
    dp_lbl_spec_no:'规格管理编号',
    dp_lbl_drive:'驱动形式',
    dp_lbl_car_class:'车型',
    dp_lbl_purpose:'用途',
    dp_lbl_trans_type:'变速器种类',
    dp_lbl_body_shape:'车身形状',
    dp_lbl_curb_wt:'整备质量(kg)',
    dp_lbl_gvw:'车辆总重量(kg)',
    dp_lbl_inertia_wt:'等效惯性质量(kg)',
    dp_lbl_dyno_hp:'实测测功机功率(hp)',
    dp_lbl_dimensions:'尺寸',
    dp_lbl_length:'全长(mm)',
    dp_lbl_width:'全宽(mm)',
    dp_lbl_height:'全高(mm)',
    dp_lbl_engine:'发动机',
    dp_lbl_manufacturer:'制造公司',
    dp_lbl_combustion:'燃烧方式',
    dp_lbl_eng_type:'发动机型式',
    dp_lbl_displacement:'排量(cc)',
    dp_lbl_eng_pos:'发动机安装位置',
    dp_lbl_fuel_type:'使用燃料',
    dp_lbl_cyl_count:'气缸数',
    dp_lbl_cyl_arr:'气缸排列',
    dp_lbl_chamber_type:'燃烧室形式',
    dp_lbl_max_power:'最大功率(ps/rpm)',
    dp_lbl_max_torque:'最大扭矩(kg-m/rpm)',
    dp_lbl_bore_stroke:'缸径*冲程(mm)',
    dp_lbl_idle_rpm:'怠速转速(rpm)',
    dp_lbl_intake_method:'进气方式',
    dp_lbl_intake_manifold:'进气歧管',
    dp_lbl_exhaust_manifold:'排气歧管',
    dp_lbl_port_size:'气口尺寸',
    dp_lbl_port_size_mm:'气口尺寸(mm)',
    dp_lbl_port_shape:'气口形状',
    dp_lbl_ign_timing:'点火正时(度)',
    dp_lbl_fuel_tank:'燃油箱',
    dp_lbl_capacity_l:'容量(ℓ)',
    dp_lbl_position:'位置',
    dp_lbl_material:'材质',
    dp_lbl_air_cleaner:'空气滤清器',
    dp_lbl_form_type:'形式',
    dp_lbl_drivetrain:'动力传动装置',
    dp_lbl_clutch:'离合器',
    dp_lbl_operation:'操作方式',
    dp_lbl_gear_ratio:'变速比',
    dp_lbl_gear_1:'1档',
    dp_lbl_forward:'前进',
    dp_lbl_reverse:'倒退',
    dp_lbl_red_ratio:'减速比',
    dp_lbl_red1:'第1减速比',
    dp_lbl_red2:'第2减速比',
    dp_lbl_ev_spec:'电动车相关规格',
    dp_lbl_motor_type:'电机形式',
    dp_lbl_batt_cap:'蓄电池额定电压及容量',
    dp_lbl_motor_power:'电机最大功率',
    dp_lbl_ev_range:'单次充电行驶距离',
    dp_lbl_tire:'轮胎',
    dp_lbl_tire_maker:'轮胎制造商',
    dp_lbl_tire_struct:'轮胎结构',
    dp_lbl_tire_size:'轮胎尺寸',
    dp_lbl_front:'前',
    dp_lbl_tire_pres:'轮胎气压',
    dp_lbl_precious_comp:'贵金属成分',
    dp_lbl_precious_g:'贵金属量(g)',
    dp_lbl_vol_cc:'容量(㎤)',
    dp_lbl_pm_ratio:'贵金属物质比(Pt:Pd:Rh)',
    dp_lbl_em_test_info:'排放气体试验相关事项',
    dp_lbl_road_load:'实际道路负荷力(hp)',
    dp_lbl_road_coef:'道路阻力系数',
    dp_lbl_coast_down:'滑行时间(sec)',
    dp_lbl_canister:'碳罐',
    dp_lbl_can_cap:'碳罐吸收容量',
    dp_lbl_can_size:'碳罐尺寸(cc)',
    dp_lbl_can_media:'碳罐介质',
    dp_lbl_evap_cap:'40%燃料时油箱最大蒸发气容量',
    dp_lbl_muffler:'消音器',
    dp_lbl_muf_main:'主消音器',
    dp_lbl_muf_sub:'副消音器',
    dp_lbl_vol_l:'容量(L)',
    dp_lbl_horn_dev:'报警装置',
    dp_lbl_horn:'喇叭',
    dp_lbl_horn_db:'性能(dB(C))',
    dp_lbl_ignition:'点火装置',
    dp_lbl_chassis:'底盘',
    dp_lbl_other:'其他',
    dp_lbl_remark:'备注',
    dp_lbl_left:'左侧',
    dp_lbl_right:'右侧',
    dp_lbl_compress_ratio:'压缩比',
    dp_lbl_car_spec:'汽车规格',
    dp_lbl_fuel_system:'燃料系统',
    dp_lbl_type_kind:'种类',
    dp_lbl_test_fuel:'试验用燃料',
    dp_lbl_acc_fuel:'里程累积用燃料',
    dp_lbl_gasoline:'汽油',
    dp_lbl_octane:'辛烷值(研究法)',
    dp_lbl_aromatic:'芳香族化合物含量(体积%)',
    dp_lbl_benzene:'苯含量(体积%)',
    dp_lbl_oxygen:'氧含量(重量%)',
    dp_lbl_lead:'铅含量(g/ℓ)',
    dp_lbl_phosphorus:'磷含量(g/ℓ)',
    dp_lbl_olefin:'烯烃含量(体积%)',
    dp_lbl_vapor_p:'蒸气压(kPa)',
    dp_lbl_90pct_temp:'90%馏出温度(℃)',
    dp_lbl_sulfur:'硫含量(重量%)',
    dp_lbl_diesel:'柴油',
    dp_lbl_residual_carbon:'10%残炭量(%)',
    dp_lbl_cetane:'十六烷值',
    dp_lbl_fuel_source:'燃料来源',
    dp_fuel_note:'备注：汽车认证试验燃料原则上使用国内市售汽车燃料；符合大气规则附表30汽车燃料制造标准项目的，可以此记载代替。',
    dp_4_1_title:'4.1. 排放气体测量设备',
    dp_4_2_title:'4.2. 噪音测量设备',
    dp_th_equip_name:'设备、仪器名称',
    dp_th_model:'型号名称',
    dp_th_type_no:'型式批准编号',
    dp_th_type_date:'型式批准日期',
    dp_th_lab_name:'实验室名称',
    dp_th_calib_date:'最近校准日期',
    dp_equip_note:'备注：使用外国制造商设备时，可填写该国公认检定或批准编号等以代替型式批准编号。',
    dp_5_1_1_lbl:'5.1.1. 试验场所',
    dp_5_1_2_lbl:'5.1.2. 试验程序',
    dp_5_2_1_lbl:'5.2.1. 耐久试验行驶与否',
    dp_5_2_2_lbl:'5.2.2. 磨合行驶与否',
    dp_5_2_3_lbl:'5.2.3. 计划行驶期间',
    dp_5_2_4_lbl:'5.2.4. 行驶场所',
    dp_5_2_5_lbl:'5.2.5. 行驶程序',
    dp_5_3_1_lbl:'5.3.1. 试验场所',
    dp_5_3_2_lbl:'5.3.2. 试验程序',
    dp_5_4_1_lbl:'5.4.1. 试验场所',
    dp_5_4_2_lbl:'5.4.2. 试验程序',
    dp_6_1_title:'6.1. 试验车辆维护计划',
    dp_6_1_1_title:'6.1.1. 定期维护',
    dp_6_1_2_title:'6.1.2. 非定期维护',
    dp_6_2_title:'6.2. 对购车者的推荐维护',
    dp_6_3_title:'6.3. 保修说明',
    dp_6_3_1_lbl:'保修内容',
    dp_6_3_2_lbl:'保修期限',
    dp_6_3_3_lbl:'不在保修范围内的事项',
    dp_6_3_4_lbl:'车辆所有者义务',
    dp_1_3_title:'1.3. 开发目标（进口车以外国认证成绩等代替）',
    dp_1_4_title:'认证对象汽车规格',
    dp_1_3_r0:'允许标准',
    dp_1_3_r1:'开发目标值',
    dp_1_3_r2:'现行标准满足度(%)',
    dp_th_formaldehyde:'甲醛(g/km)',
    dp_th_smoke:'烟尘(%/kWh)',
    dp_2_1_title:'2.1. 保密申请',
    dp_8_10_title:'8.10. 感知变量与控制变量',
    dp_8_11_title:'8.11. 零件清单',
    dp_8_12_title:'8.12. 选择性催化还原装置(SCR)性能及原理说明',
    dp_8_13_title:'8.13. SCR用尿素溶液成分分析结果',
    dp_8_14_title:'8.14. 电动汽车控制装置',
    dp_8_14_1_lbl:'电动机及电动机控制装置',
    dp_8_14_2_lbl:'蓄电池及蓄电池控制装置',
    dp_8_11_ign:'点火装置',
    dp_8_11_fuel:'燃料供给装置',
    dp_8_11_cat:'排放气体转换装置',
    dp_8_11_egr:'废气再循环装置',
    dp_8_11_evap:'燃料蒸发气体防止装置',
    dp_8_11_blow:'窜气还原装置',
    dp_8_11_air:'二次空气喷射装置',
    dp_8_12_r0:'供应系',
    dp_8_12_r1:'控制系',
    dp_8_12_r2:'喷射系',
    dp_8_12_r3:'充注警告系统',
    dp_th_item:'项目',
    dp_th_analysis_result:'分析结果',
    dp_th_analysis_org:'分析机构',
    dp_th_analysis_method:'分析方法',
    dp_th_analysis_date:'分析日期',
    dp_th_proof_no:'凭证编号',
    dp_sv_o2:'排放气体中氧浓度',
    dp_sv_air_flow:'进气流量',
    dp_sv_air_temp:'进气温度',
    dp_sv_coolant:'冷却水温度',
    dp_sv_throttle:'节气门位置',
    dp_sv_baro:'大气压',
    dp_sv_intake_vac:'进气真空度',
    dp_sv_crank:'曲轴位置',
    dp_sv_cam:'凸轮轴位置',
    dp_sv_batt:'电池电压',
    dp_sv_speed:'车速',
    dp_sv_rpm:'发动机转速',
    dp_sv_gear:'变速器档位',
    dp_sv_idle:'停止及空挡',
    dp_sv_brake:'制动应用',
    dp_sv_ac:'空调运行',
    dp_sv_knock:'发动机爆震',
    dp_9_1_title:'9.1. 蒸发气体控制装置说明',
    dp_th_storage:'储存装置',
    dp_th_absorb_cap:'吸收容量(C)',
    dp_th_size_media:'尺寸(㎤)/介质',
    dp_9_1_r0:'碳罐',
    dp_9_1_r1:'空气滤清器',
    dp_9_1_r2:'曲轴箱',
    dp_9_1_r3:'其他',
    dp_9_2_title:'9.2. 控制装置构成图',
    dp_9_2_parts_title:'蒸发气体控制装置零件清单（含辅助排放控制装置）',
    dp_10_1_title:'10.1. 排放气体及噪音同类车型（发动机）说明',
    dp_10_1_cyl_dist_lbl:'气缸孔中心距(mm)',
    dp_10_1_block_lbl:'气缸体形状',
    dp_10_1_head_lbl:'气缸盖方式',
    dp_10_2_title:'10.2. 蒸发气体同类车型说明',
    dp_10_3_title:'10.3. 排放气体自诊断装置同类车型说明',
    dp_11_1_title:'11.1. 试验车辆选定',
    dp_11_2_title:'11.2. 耐久试验车辆选定',
    dp_11_3_title:'11.3. 排放气体试验车辆选定',
    dp_11_4_title:'11.4. 噪音试验车辆选定',
    dp_durability_note:'在进行耐久试验的情况下，如因不可避免的原因导致初次提交申请文件时无法记录某些事项，应说明原因，并可在提交耐久试验最终报告时统一提交确定事项。',
    dp_ph_dev_bg:'请填写开发背景及特性',
    dp_ph_new_tech:'请填写新技术内容',
    dp_ph_confidential:'请填写保密申请内容',
    dp_ph_engine_content:'发动机内容',
    dp_ph_ignition_content:'点火装置内容',
    dp_ph_chassis_content:'底盘内容',
    dp_ph_other_content:'其他内容',
    dp_ph_warranty_content:'保修内容',
    dp_ph_warranty_period:'保修期限',
    dp_ph_warranty_exclusion:'不在保修范围内的事项',
    dp_ph_owner_duty:'车辆所有者义务',
    dp_ph_sign_desc:'标志样本说明',
    dp_ph_attach_pos:'填写附着位置等',
    dp_ph_motor_ctrl:'电动机及电动机控制装置说明',
    dp_ph_batt_ctrl:'蓄电池及蓄电池控制装置说明',
    dp_ph_ctrl_diagram:'控制装置构成图说明',
    dp_ph_em_detail:'提交记录等',
    dp_lbl_diagram_attach:'{sec} 构成图附件:',
    obd_dtc_default_val:'当摩托车检测到故障代码时，',
    obd_lbl_2nd_monitor_suffix:'等综合说明资料，包括相关方法',
    obd_lbl_ctrl_dev:'控制装置',
    obd_lbl_diag_config:'自诊断装置的构成',
    msg_coming_soon:'准备中。',
    msg_qr_login_check:'请确认登录状态以生成QR码。',
    msg_qr_fail:'QR生成失败',
    btn_saving:'保存中...',
    msg_saved:'保存成功。',
    msg_save_fail:'保存失败',
    btn_save:'保存',
    btn_list:'列表', btn_toc_print:'打印目录',
    complete_title:'此文件已完成', complete_sub:'勾选后将反映在进度中',
    nt_rpm_unit:'% 转速(rpm)',
    btn_create_app:'创建申请',
    err_title_required:'请输入申请标题。',
    err_cert_no_required:'请输入现有认证编号。',
    btn_creating:'创建中...',
    msg_create_fail:'创建失败',
    msg_app_created:'申请已创建。',
    msg_delete_confirm:'删除申请将同时删除所有文件数据。\\n是否继续？',
    msg_deleted:'已删除。',
    msg_delete_fail:'删除失败',
    pw_lbl_current:'当前密码',
    pw_ph_current:'请输入当前密码',
    pw_lbl_new:'新密码',
    pw_ph_new:'4位以上',
    pw_lbl_confirm:'确认新密码',
    pw_ph_confirm:'重新输入',
    
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
    <button class="btn btn-ghost btn-sm" onclick="showProfileModal()" title="${LL('profile_modal_title')}">
      <i class="fas fa-user-circle"></i>
    </button>
    <button class="btn btn-ghost btn-sm" onclick="doLogout()">
      <i class="fas fa-sign-out-alt"></i>${LL('btn_logout')}
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
  document.getElementById('dash-subtitle').textContent = '';
  // 검색창 초기화
  const inp = document.getElementById('dash-search-input');
  if (inp) inp.value = '';
  const clearBtn = document.getElementById('dash-search-clear');
  if (clearBtn) clearBtn.style.display = 'none';
  const resultEl = document.getElementById('dash-search-result');
  if (resultEl) resultEl.style.display = 'none';
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
          <button class="btn btn-secondary btn-sm btn-icon" onclick="showEditAppModal(event,\${a.id})" title="\${(LANG_DICT[lang]||LANG_DICT.ko)['btn_edit_appl']||LL('btn_edit_appl')}">
            <i class="fas fa-pen"></i>
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
// 검색 필터
// ================================================================
function filterAppList(query) {
  const q = (query || '').trim().toLowerCase();
  const clearBtn = document.getElementById('dash-search-clear');
  const resultEl = document.getElementById('dash-search-result');
  if (clearBtn) clearBtn.style.display = q ? 'flex' : 'none';

  const listEl  = document.getElementById('app-list');
  const emptyEl = document.getElementById('app-empty');
  if (!currentApplications.length) return;

  if (!q) {
    // 검색어 없으면 전체 표시
    if (resultEl) resultEl.style.display = 'none';
    renderAppList();
    return;
  }

  const filtered = currentApplications.filter(a => {
    const fields = [
      a.title || '',
      a.importer || '',
      String(a.cert_year || ''),
      String(a.displacement || ''),
      a.family_code || '',
      a.cert_type || '',
    ].join(' ').toLowerCase();
    return fields.includes(q);
  });

  if (resultEl) {
    resultEl.style.display = 'block';
    resultEl.textContent = \`검색 결과: \${filtered.length}건\`;
  }

  if (!filtered.length) {
    listEl.innerHTML = '';
    emptyEl.style.display = 'block';
    const emptyTitle = document.getElementById('empty-title');
    if (emptyTitle) emptyTitle.textContent = '검색 결과가 없습니다';
    return;
  }

  emptyEl.style.display = 'none';
  const localeMap = { ko:'ko-KR', en:'en-US', ja:'ja-JP', zh:'zh-CN' };
  const certLabelFor   = (lang,type) => (LANG_DICT[lang]||LANG_DICT.ko)['cert_'+type]   || (LANG_DICT.ko['cert_'+type]||type);
  const statusLabelFor = (lang,st)   => { const k={draft:'status_draft',in_progress:'status_inprogress',completed:'status_completed'}[st]||st; return (LANG_DICT[lang]||LANG_DICT.ko)[k]||(LANG_DICT.ko[k]||st); };
  const modifiedFor    = (lang)      => (LANG_DICT[lang]||LANG_DICT.ko)['meta_modified'] || (LANG_DICT.ko['meta_modified']||'수정');
  listEl.innerHTML = filtered.map(a => {
    const lang    = (a.lang && ['ko','en','ja','zh'].includes(a.lang)) ? a.lang : 'ko';
    const locale  = localeMap[lang] || 'ko-KR';
    const done_f  = a.completed_forms || 0;
    const total_f = a.total_forms || 10;
    const pct     = Math.round(done_f/total_f*100);
    const date    = new Date(a.updated_at).toLocaleDateString(locale,{month:'short',day:'numeric'});
    const yearSfx = lang==='ko' ? '년' : lang==='ja' ? '年' : '';
    const metaStr = [a.importer,a.cert_year?(a.cert_year+yearSfx):'',a.displacement?(a.displacement+'cc'):''].filter(Boolean).join(' ');
    const certBadge = { basic:'badge-blue', change:'badge-violet', report:'badge-yellow' }[a.cert_type] || 'badge-gray';
    // 검색어 하이라이트 헬퍼
    const hl = (str) => {
      if (!str) return '';
      const escaped = esc(str);
      const idx = escaped.toLowerCase().indexOf(q);
      if (idx < 0) return escaped;
      return escaped.slice(0,idx) + '<mark style="background:#fff3cd;border-radius:2px;">' + escaped.slice(idx,idx+q.length) + '</mark>' + escaped.slice(idx+q.length);
    };
    return \`
      <div class="app-item">
        <div class="app-item-icon"><i class="fas fa-file-alt"></i></div>
        <div class="app-item-body">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap;">
            <span class="badge \${certBadge}">\${certLabelFor(lang,a.cert_type)}</span>
            <span class="badge \${STATUS_BADGE[a.status]||'badge-gray'}">\${statusLabelFor(lang,a.status)}</span>
          </div>
          <div class="app-item-title">\${hl(a.title)}</div>
          <div class="app-item-meta">\${hl(metaStr)} &nbsp;·&nbsp; \${date} \${modifiedFor(lang)}</div>
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
          <button class="btn btn-secondary btn-sm btn-icon" onclick="showEditAppModal(event,\${a.id})" title="\${(LANG_DICT[lang]||LANG_DICT.ko)['btn_edit_appl']||LL('btn_edit_appl')}">
            <i class="fas fa-pen"></i>
          </button>
          <button class="btn btn-danger btn-sm btn-icon" onclick="deleteApplication(event,\${a.id})" title="\${(LANG_DICT[lang]||LANG_DICT.ko)['btn_delete']||LL('btn_delete')}">
            <i class="fas fa-trash-alt"></i>
          </button>
        </div>
      </div>
    \`;
  }).join('');
}

function clearSearch() {
  const inp = document.getElementById('dash-search-input');
  if (inp) { inp.value = ''; inp.focus(); }
  const clearBtn = document.getElementById('dash-search-clear');
  if (clearBtn) clearBtn.style.display = 'none';
  const resultEl = document.getElementById('dash-search-result');
  if (resultEl) resultEl.style.display = 'none';
  renderAppList();
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
  } catch { showToast(BL('err_network'),'error'); }
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
  // emission_noise / gasoline 복합 입력 필드(en-drop) 초기화
  if (formType === 'emission_noise' || formType === 'gasoline') setTimeout(() => initEnFields(), 150);
  // obd_config 이미지 드롭존 초기화 + 첨부파일 기능 초기화
  if (formType === 'obd_config') {
    setTimeout(() => initObdImgDrops(), 150);
    setTimeout(() => initObdConfigAttach(), 200);
  }
  // detail_plan 이미지 첨부 복원 (저장된 이미지 썸네일 재표시)
  // detail_plan 이미지 드롭존 복원 (dp-drop 방식)
  if (formType === 'detail_plan') setTimeout(() => {
    if (typeof window.dpRestoreAll === 'function') window.dpRestoreAll();
  }, 200);
  // 목차인쇄 버튼: detail_plan 폼에서만 표시
  const tocBtn = document.getElementById('btn-toc-print');
  if (tocBtn) tocBtn.style.display = (formType === 'detail_plan') ? '' : 'none';
  // ── 폼 페이지 UI 버튼/텍스트 다국어 갱신 ──
  const setFormSpan = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  setFormSpan('save-btn-lbl',       _fLt('btn_save'));
  setFormSpan('save-btn-bottom-lbl',_fLt('btn_save'));
  setFormSpan('print-btn-top-lbl',  _fLt('btn_print'));
  setFormSpan('print-btn-bottom-lbl',_fLt('btn_print'));
  setFormSpan('btn-list-lbl',       _fLt('btn_list'));
  setFormSpan('toc-print-lbl',      _fLt('btn_toc_print'));
  setFormSpan('complete-label-title-el', _fLt('complete_title'));
  setFormSpan('complete-label-sub-el',   _fLt('complete_sub'));
  // breadcrumb 목록 버튼
  const btnHomeForm2 = document.getElementById('btn-breadcrumb-home-form');
  if (btnHomeForm2) btnHomeForm2.innerHTML = '<i class="fas fa-home"></i> ' + _fLt('dash_title');
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
    <div class="qr-footer-code-label">\${BL('qr_auth_code_lbl')}</div>
    <div class="qr-footer-short-code">\${shortCode||'-'}</div>
  </div>
  <div class="qr-footer-info">
    <div class="qr-footer-title"><i class="fas fa-qrcode"></i>&nbsp;\${BL('qr_verify_title')}\${pageLabel ? ' — '+pageLabel : ''}</div>
    <div class="qr-footer-rows">
      \${BL('qr_doc_name')} &nbsp;&nbsp;: <span>\${formTitle}</span><br>
      \${BL('qr_application')} &nbsp;&nbsp;: <span>\${currentApplication?.title||'-'}</span><br>
      \${BL('qr_issued_at')} &nbsp;: <span>\${dt}</span><br>
      \${BL('qr_issuer')} &nbsp;: <span>\${currentUser?.company_name||currentUser?.username||'-'}</span><br>
      \${BL('qr_auth_code_lbl')}: <span style="font-family:monospace;font-size:8pt;letter-spacing:.1em;font-weight:800;">\${shortCode||'-'}</span>
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
  if (!w) { alert(BL('msg_popup_blocked')); return; }
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
    el.innerHTML = ('<div class="qr-footer-pending"><i class="fas fa-spinner fa-spin"></i> '+BL('msg_qr_generating')+'</div>');
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
      el.innerHTML = ('<div class="qr-footer-pending">⚠ '+BL('msg_qr_login_check')+'</div>');
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
      if (qrEl) qrEl.innerHTML = ('<div style="font-size:7pt;color:#888;">'+BL('msg_qr_fail')+'</div>');
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
  const completedEl = document.getElementById('form-completed-chk');
  const completed = completedEl ? completedEl.checked : false;
  const btns = [document.getElementById('save-btn'), document.getElementById('save-btn-bottom')].filter(Boolean);
  btns.forEach(b => { b.disabled = true; b.innerHTML = '<div class="spinner"></div>'+LL('btn_saving'); });
  try {
    const res = await api('/api/applications/'+currentApplicationId+'/forms/'+currentFormType,
      { method:'PUT', body:JSON.stringify({data,completed}) });
    if (res.ok) {
      showToast(LL('msg_saved'),'success');
      const idx = currentForms.findIndex(f=>f.form_type===currentFormType);
      if (idx>=0) { currentForms[idx].data=JSON.stringify(data); currentForms[idx].completed=completed?1:0; }
    } else { showToast(LL('msg_save_fail'),'error'); }
  } catch(e) { console.error('saveForm error:', e); showToast(LL('msg_network_error'),'error'); }
  finally {
    const saveLbl = LL('btn_save');
    btns.forEach(b => { b.disabled=false; b.innerHTML='<i class="fas fa-save"></i><span>'+saveLbl+'</span>'; });
  }
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
  document.getElementById('create-btn').innerHTML = '<i class="fas fa-check"></i>'+BL('btn_create_app');
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
    if (currentFormType==='emission_noise' || currentFormType==='gasoline') setTimeout(()=>initEnFields(),150);
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
  if (!title) { errEl.textContent=BL('err_title_required'); errEl.style.display='block'; document.getElementById('new-title').focus(); return; }
  if ((cert_type==='change'||cert_type==='report')&&!prev_cert) {
    errEl.textContent=BL('err_cert_no_required'); errEl.style.display='block'; return; }
  const btn = document.getElementById('create-btn');
  btn.disabled=true; btn.innerHTML='<div class="spinner"></div>'+BL('btn_creating');
  try {
    const res  = await api('/api/applications',{method:'POST',body:JSON.stringify({
      title, cert_type, lang, importer, cert_year, displacement, family_code, prev_cert_number:prev_cert
    })});
    const data = await res.json();
    if (!res.ok) { errEl.textContent=data.error||BL('msg_create_fail'); errEl.style.display='block'; return; }
    // 선택한 언어를 전역 상태에 반영
    currentLang = lang;
    closeNewAppModal();
    showToast(BL('msg_app_created'),'success');
    await openApplication(data.application.id);
  } catch { errEl.textContent=BL('err_network'); errEl.style.display='block'; }
  finally { btn.disabled=false; btn.innerHTML='<i class="fas fa-check"></i>'+BL('btn_create_app'); }
}

async function deleteApplication(e, id) {
  e.stopPropagation();
  if (!confirm(LL('msg_delete_confirm'))) return;
  const res = await api('/api/applications/'+id,{method:'DELETE'});
  if (res.ok) { showToast(LL('msg_deleted'),'info'); await loadApplications(); }
  else showToast(LL('msg_delete_fail'),'error');
}

// ================================================================
// 신청서 정보 수정 모달
// ================================================================
function showEditAppModal(e, id) {
  e.stopPropagation();
  const app = currentApplications.find(a => a.id === id);
  if (!app) return;

  // 모달 제목·버튼 라벨 언어 적용
  const setT = (elId, key) => { const el = document.getElementById(elId); if (el) el.textContent = LL(key); };
  setT('edit-modal-title-lbl', 'modal_edit_title');
  setT('edit-update-btn-lbl',  'btn_update_appl');
  setT('edit-cancel-btn',      'btn_cancel');

  // 현재 값 채우기
  document.getElementById('edit-app-id').value          = id;
  document.getElementById('edit-title').value           = app.title        || '';
  document.getElementById('edit-cert-type').value       = app.cert_type    || 'basic';
  document.getElementById('edit-lang').value            = app.lang         || 'ko';
  document.getElementById('edit-importer').value        = app.importer     || '';
  document.getElementById('edit-cert-year').value       = app.cert_year    || '';
  document.getElementById('edit-displacement').value    = app.displacement  || '';
  document.getElementById('edit-family-code').value     = app.family_code  || '';
  document.getElementById('edit-prev-cert').value       = app.prev_cert_number || '';
  document.getElementById('edit-modal-error').style.display = 'none';
  document.getElementById('edit-update-btn').disabled   = false;

  onEditCertTypeChange();
  document.getElementById('modal-edit-app').classList.remove('hidden');
  setTimeout(() => document.getElementById('edit-title').focus(), 150);
}

function closeEditAppModal() {
  document.getElementById('modal-edit-app').classList.add('hidden');
}

function onEditCertTypeChange() {
  const v = document.getElementById('edit-cert-type').value;
  document.getElementById('edit-prev-cert-wrap').style.display = v === 'basic' ? 'none' : 'flex';
}

async function updateApplication() {
  const id          = document.getElementById('edit-app-id').value;
  const title       = document.getElementById('edit-title').value.trim();
  const cert_type   = document.getElementById('edit-cert-type').value;
  const lang        = document.getElementById('edit-lang').value;
  const importer    = document.getElementById('edit-importer').value.trim();
  const cert_year   = document.getElementById('edit-cert-year').value.trim();
  const displacement= document.getElementById('edit-displacement').value.trim();
  const family_code = document.getElementById('edit-family-code').value.trim();
  const prev_cert   = document.getElementById('edit-prev-cert')?.value.trim() || '';
  const errEl       = document.getElementById('edit-modal-error');
  errEl.style.display = 'none';

  if (!title) {
    errEl.textContent = LL('err_title_required');
    errEl.style.display = 'block';
    document.getElementById('edit-title').focus();
    return;
  }
  if ((cert_type === 'change' || cert_type === 'report') && !prev_cert) {
    errEl.textContent = LL('err_cert_no_required');
    errEl.style.display = 'block';
    return;
  }

  const btn = document.getElementById('edit-update-btn');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>' + LL('btn_saving');

  try {
    const app = currentApplications.find(a => a.id == id);
    const res = await api('/api/applications/' + id, {
      method: 'PUT',
      body: JSON.stringify({
        title, cert_type, lang, importer, cert_year, displacement,
        family_code, prev_cert_number: prev_cert,
        status: app?.status || 'draft'
      })
    });
    const data = await res.json();
    if (!res.ok) {
      errEl.textContent = data.error || LL('msg_update_fail');
      errEl.style.display = 'block';
      return;
    }
    closeEditAppModal();
    showToast(LL('msg_update_ok'), 'success');
    // 목록 새로고침
    await loadApplications();
  } catch(e) {
    console.error('updateApplication error:', e);
    errEl.textContent = LL('msg_network_error');
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-check"></i>' + LL('btn_update_appl');
  }
}

// 수정 모달 배경 클릭시 닫기
document.getElementById('modal-edit-app').addEventListener('click', function(e) {
  if (e.target === this) closeEditAppModal();
});

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
    // gasoline 헤더 4개 필드 자동채움
    if (k==='g_importer')  { const mv=currentApplication?.importer;    if(mv) return mv; }
    if (k==='g_cert_year') { const mv=currentApplication?.cert_year;   if(mv) return mv; }
    if (k==='g_disp')      { const mv=currentApplication?.displacement; if(mv) return mv; }
    if (k==='g_fam_code')  { const mv=currentApplication?.family_code;  if(mv) return mv; }
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
            placeholder="\${BL('g_ph_maker')}"
            value="\${E(v('maker'))}">
        </td>
      </tr>

      <!-- 2. 시험자동차 명칭(형식) -->
      <tr>
        <td class="sv-num">2</td>
        <td class="sv-lbl">\${BL('sv_vehicle_name')}</td>
        <td class="sv-val">
          <input data-field="vehicle_name" class="sv-inp" type="text"
            placeholder="\${BL('g_ph_model')}"
            value="\${E(v('vehicle_name'))}">
        </td>
      </tr>

      <!-- 3. 사용연료 -->
      <tr>
        <td class="sv-num">3</td>
        <td class="sv-lbl">\${BL('sv_fuel')}</td>
        <td class="sv-val">
          <input data-field="fuel" class="sv-inp" type="text"
            placeholder="\${BL('g_ph_fuel')}"
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
              placeholder="\${BL('g_ph_euro5')}"
              value="\${E(v('emission_std'))}" style="flex:1;min-width:0;">
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding:0;">
          <div class="sv-sub-row">
            <span class="sv-sub-lbl">\${BL('sv_noise_simple')}</span>
            <input data-field="noise_std" class="sv-inp" type="text"
              placeholder="\${BL('g_ph_ece_noise')}"
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
            placeholder="\${BL('g_ph_euro5')}"
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
              placeholder="\${BL('g_ph_rep_nonrep')}"
              value="\${E(v('evap_is_rep'))}" style="flex:1;min-width:0;">
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding:0; border-bottom:1px solid #ccc;">
          <div class="sv-sub-row">
            <span class="sv-sub-lbl" style="width:64px;">\${BL('sv_vehicle_name_lbl')}</span>
            <input data-field="evap_rep_name" class="sv-inp" type="text"
              placeholder="\${BL('g_ph_model')}"
              value="\${E(v('evap_rep_name'))}" style="flex:1;min-width:0;">
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding:0;">
          <div class="sv-sub-row">
            <span class="sv-sub-lbl" style="width:64px;">\${BL('sv_type_lbl')}</span>
            <input data-field="evap_rep_type" class="sv-inp" type="text"
              placeholder="\${BL('g_ph_cert_id')}"
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
              placeholder="\${BL('g_ph_rep_nonrep')}"
              value="\${E(v('obd_is_rep'))}" style="flex:1;min-width:0;">
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding:0; border-bottom:1px solid #ccc;">
          <div class="sv-sub-row">
            <span class="sv-sub-lbl" style="width:64px;">\${BL('sv_vehicle_name_lbl')}</span>
            <input data-field="obd_rep_name" class="sv-inp" type="text"
              placeholder="\${BL('g_ph_model')}"
              value="\${E(v('obd_rep_name'))}" style="flex:1;min-width:0;">
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding:0;">
          <div class="sv-sub-row">
            <span class="sv-sub-lbl" style="width:64px;">\${BL('sv_type_lbl')}</span>
            <input data-field="obd_rep_type" class="sv-inp" type="text"
              placeholder="\${BL('g_ph_cert_id')}"
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
              placeholder="\${BL('g_ph_warranty_yr')}" value="\${E(v('warranty_year'))}" style="width:50px;text-align:right;">
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
            placeholder="\${BL('g_ph_self_test')}"
            value="\${E(v('self_test'))}">
        </td>
      </tr>

      <!-- 10. 대표 기술 -->
      <tr>
        <td class="sv-num">10</td>
        <td class="sv-lbl">\${BL('sv_key_tech')}</td>
        <td class="sv-val">
          <textarea data-field="key_tech" class="sv-ta" rows="3"
            placeholder="\${BL('g_ph_key_tech')}">\${E(v('key_tech'))}</textarea>
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
        <td><input data-field="g_importer"  class="en-inp" type="text" readonly style="background:#f5f8ff;pointer-events:none;cursor:default;" value="\${E(v('g_importer'))}"></td>
        <td><input data-field="g_cert_year" class="en-inp" type="text" readonly style="background:#f5f8ff;pointer-events:none;cursor:default;" value="\${E(v('g_cert_year'))}"></td>
        <td><input data-field="g_disp"      class="en-inp" type="text" readonly style="background:#f5f8ff;pointer-events:none;cursor:default;" value="\${E(v('g_disp'))}"></td>
        <td><input data-field="g_fam_code"  class="en-inp" type="text" readonly style="background:#f5f8ff;pointer-events:none;cursor:default;" value="\${E(v('g_fam_code'))}"></td>
      </tr>
    </tbody>
  </table>

  <div class="en-doc-tag">\${BL('g_doc_tag')}</div>
  <div class="en-main-title">\${BL('gasoline_title')}</div>

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
        <th class="en-sec-th" colspan="9">\${BL('g_sec1')}</th>
      </tr>
      <tr>
        <th class="en-th">\${BL('g_th_div')}</th>
        <th class="en-th">\${BL('g_th_apply_date')}</th>
        <th class="en-th">\${BL('g_th_maker')}</th>
        <th class="en-th">\${BL('g_th_model')}</th>
        <th class="en-th">\${BL('g_th_fuel_type')}</th>
        <th class="en-th">\${BL('g_th_output')}</th>
        <th class="en-th">\${BL('g_th_std')}</th>
        <th class="en-th">\${BL('g_th_cert_no')}</th>
        <th class="en-th">\${BL('g_th_note')}</th>
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
          \${BL('g_emit_colon')} <input class="en-inp" data-field="g_std_emission" type="text" value="\${E(v('g_std_emission'))}" style="width:75%;"><br>
          \${BL('g_noise_colon')} <input class="en-inp" data-field="g_std_noise"    type="text" value="\${E(v('g_std_noise'))}"    style="width:75%;">
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
      <tr><th class="en-sec-th">\${BL('g_sec2')}</th></tr>

      <!-- 2.1 EURO-5 기준 적용 -->
      <tr>
        <td style="padding:4px 8px;">
          <div class="g-chk-row">
            
            <span>\${BL('g_2_1_label')}</span>
            <input class="g-chk-inp" data-field="g_euro5_rep" type="text" value="\${E(v('g_euro5_rep'))}">
          </div>
        </td>
      </tr>

      <!-- 2.2 OBD/증발가스 대표 차종 -->
      <tr>
        <td style="padding:4px 8px;">
          <div class="g-chk-row">
            <span>\${BL('g_2_2_obd')}</span>
            <input class="g-chk-inp" data-field="g_obd_rep" type="text" value="\${E(v('g_obd_rep'))}" style="width:100px;">
            <span style="margin-left:12px;">\${BL('g_evap_rep_lbl')}</span>
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
        <th class="en-th">\${BL('g_th_div2')}</th>
        <th class="en-th">\${BL('g_th_fuel')}</th>
        <th class="en-th">\${BL('g_th_cert_content')}</th>
        <th class="en-th">\${BL('g_th_applicable')}</th>
      </tr>
    </thead>
    <tbody>
      <!-- ── 배출기준 ── -->
      <tr>
        <td class="en-lbl" rowspan="5" style="text-align:center; font-weight:700;">\${BL('g_cat_emission')}</td>
        <td class="en-lbl" rowspan="4" style="text-align:center;">\${BL('g_fuel_gasoline')}</td>
        <td>\${BL('g_em1_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_em1" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_em1'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>\${BL('g_em2_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_em2" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_em2'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>\${BL('g_em3_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_em3" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_em3'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>\${BL('g_em4_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_em4" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_em4'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td class="en-lbl" style="text-align:center;">\${BL('g_fuel_diesel')}</td>
        <td>\${BL('g_em5_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_em5" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_em5'))}" style="width:100%;">
        </td>
      </tr>

      <!-- ── OBD 2 ── -->
      <tr>
        <td class="en-lbl" rowspan="7" style="text-align:center; font-weight:700;">OBD 2</td>
        <td class="en-lbl" rowspan="5" style="text-align:center;">\${BL('g_fuel_gasoline')}</td>
        <td>\${BL('g_obd1_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_obd1" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_obd1'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td style="padding:3px 5px;">
          \${BL('g_obd_std2_rep_lbl')}
          <input class="g-chk-inp" data-field="g_obd_std2_rep" type="text" value="\${E(v('g_obd_std2_rep'))}" style="width:90px;">
        </td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_obd2" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_obd2'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>\${BL('g_obd3_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_obd3" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_obd3'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td style="padding:3px 5px;">
          \${BL('g_obd_std4_rep_lbl')}
          <input class="g-chk-inp" data-field="g_obd_std4_rep" type="text" value="\${E(v('g_obd_std4_rep'))}" style="width:90px;">
        </td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_obd4" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_obd4'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>\${BL('g_obd5_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_obd5" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_obd5'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td class="en-lbl" rowspan="2" style="text-align:center;">\${BL('g_fuel_diesel')}</td>
        <td>\${BL('g_obd6_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_obd6" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_obd6'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td style="padding:3px 5px;">
          \${BL('g_obd_std_die_rep_lbl')}
          <input class="g-chk-inp" data-field="g_obd_std7_rep" type="text" value="\${E(v('g_obd_std7_rep'))}" style="width:90px;">
        </td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_obd7" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_obd7'))}" style="width:100%;">
        </td>
      </tr>

      <!-- ── 증발가스 ── -->
      <tr>
        <td class="en-lbl" rowspan="2" style="text-align:center; font-weight:700;">\${BL('g_lbl_evap')}</td>
        <td class="en-lbl" rowspan="2" style="text-align:center;"> </td>
        <td>\${BL('g_evap1_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_evap1" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_evap1'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td style="padding:3px 5px;">
          \${BL('g_evap_same_rep_lbl')}
          <input class="g-chk-inp" data-field="g_evap_std2_rep" type="text" value="\${E(v('g_evap_std2_rep'))}" style="width:120px;">
        </td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_evap2" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_evap2'))}" style="width:100%;">
        </td>
      </tr>

      <!-- ── 보증기간 ── -->
      <tr>
        <td class="en-lbl" rowspan="6" style="text-align:center; font-weight:700;">\${BL('g_cat_warranty')}</td>
        <td class="en-lbl" rowspan="5" style="text-align:center;">\${BL('g_fuel_gasoline')}</td>
        <td>\${BL('g_war1_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_war1" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_war1'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>\${BL('g_war2_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_war2" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_war2'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>\${BL('g_war3_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_war3" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_war3'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>\${BL('g_war4_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_war4" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_war4'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td>\${BL('g_war5_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_war5" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_war5'))}" style="width:100%;">
        </td>
      </tr>
      <tr>
        <td class="en-lbl" style="text-align:center;">\${BL('g_fuel_diesel')}</td>
        <td>\${BL('g_war6_txt')}</td>
        <td style="text-align:center;">
<input class="en-inp" data-field="g_app_war6" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_app_war6'))}" style="width:100%;">
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
      <tr><th class="en-sec-th" colspan="3">\${BL('g_sec3')}</th></tr>
    </thead>
    <tbody>

      <!-- 3.1 적용기술 -->
      <tr>
        <td class="en-lbl" style="text-align:center; font-weight:700;">1</td>
        <td class="en-sub-th">\${BL('g_3_1_lbl')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_tech_applied" rows="3" placeholder="\${BL('g_ph_tech')}">\${E(v('g_tech_applied'))}</textarea>
            <input type="hidden" data-field="g_tech_applied_imgs" value="\${E(v('g_tech_applied_imgs'))}">
            <div class="en-drop" data-field-img="g_tech_applied"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.2 자체시험결과 -->
      <tr>
        <td class="en-lbl" style="text-align:center; font-weight:700;" rowspan="2">2</td>
        <td class="en-sub-th">\${BL('g_3_2_1_lbl')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_self_test_emission" rows="2" placeholder="\${BL('g_ph_em_result')}">\${E(v('g_self_test_emission'))}</textarea>
          </div>
        </td>
      </tr>
      <tr>
        <td class="en-sub-th">\${BL('g_3_2_2_lbl')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_self_test_noise" rows="2" placeholder="\${BL('g_ph_noise_result')}">\${E(v('g_self_test_noise'))}</textarea>
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
        <th class="en-th" rowspan="2">\${BL('g_category')}</th>
        <th class="en-th" rowspan="2">\${BL('g_th_co_gkm')}</th>
        <th class="en-th" rowspan="2">NOx<br>(g/km)</th>
        <th class="en-th" colspan="3">\${BL('g_th_hc')}</th>
        <th class="en-th" rowspan="2">CO₂<br>(g/km)</th>
        <th class="en-th" rowspan="2">\${BL('g_th_accel_db')}</th>
        <th class="en-th" rowspan="2">\${BL('g_th_accel_db')}</th>
        <th class="en-th" rowspan="2">\${BL('g_th_accel_db')}</th>
      </tr>
      <tr>
        <th class="en-th">THC<br>(g/km)</th>
        <th class="en-th">NMHC<br>(g/km)</th>
        <th class="en-th">\${BL('g_lbl_evap')}<br>(g/Test)</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td class="en-lbl">\${BL('g_th_allow_std')}</td>
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
        <td class="en-lbl">\${BL('g_th_test_result')}</td>
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
        <td class="en-lbl">\${BL('g_th_compliance_pct')}</td>
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
        <th class="en-th" colspan="2">\${BL('g_th_monitor_dev')}</th>
        <th class="en-th" colspan="4">\${BL('g_th_test_result')}</th>
        <th class="en-th" colspan="4">\${BL('g_th_result_judge')}</th>
      </tr>
      <tr>
        <th class="en-th">\${BL('g_th_device_name')}</th>
        <th class="en-th">\${BL('g_th_malfunction')}</th>
        <th class="en-th">\${BL('g_th_wmtc')}</th>
        <th class="en-th">NOx<br>(g/km)</th>
        <th class="en-th">HC<br>(g/km)</th>
        <th class="en-th">\${BL('g_th_mil_on')}</th>
        <th class="en-th">\${BL('g_th_judge_std')}</th>
        <th class="en-th">NOx<br>(g/km)</th>
        <th class="en-th">HC<br>(g/km)</th>
        <th class="en-th">\${BL('g_th_monitor_judge')}</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td class="en-lbl">\${BL('g_lbl_catalyst2')}</td>
        <td><input class="en-inp" data-field="g_obd_cond1" type="text" placeholder="\${BL('g_ph_misfire')}" value="\${E(v('g_obd_cond1'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r1_co" type="text" value="\${E(v('g_obd_r1_co'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r1_nox" type="text" value="\${E(v('g_obd_r1_nox'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r1_hc"  type="text" value="\${E(v('g_obd_r1_hc'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r1_led" type="text" placeholder="\${BL('g_ph_yn')}" value="\${E(v('g_obd_r1_led'))}"></td>
        <td><input class="en-inp" data-field="g_obd_c1_co"  type="text" value="\${E(v('g_obd_c1_co'))}"></td>
        <td><input class="en-inp" data-field="g_obd_c1_nox" type="text" value="\${E(v('g_obd_c1_nox'))}"></td>
        <td><input class="en-inp" data-field="g_obd_c1_hc"  type="text" value="\${E(v('g_obd_c1_hc'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r1_judg" type="text" placeholder="\${BL('g_ph_pass_fail')}" value="\${E(v('g_obd_r1_judg'))}"></td>
      </tr>
      <tr>
        <td class="en-lbl">\${BL('g_lbl_o2')}</td>
        <td><input class="en-inp" data-field="g_obd_cond2" type="text" placeholder="\${BL('g_ph_degradation')}" value="\${E(v('g_obd_cond2'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r2_co" type="text" value="\${E(v('g_obd_r2_co'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r2_nox" type="text" value="\${E(v('g_obd_r2_nox'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r2_hc"  type="text" value="\${E(v('g_obd_r2_hc'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r2_led" type="text" placeholder="\${BL('g_ph_yn')}" value="\${E(v('g_obd_r2_led'))}"></td>
        <td><input class="en-inp" data-field="g_obd_c2_co"  type="text" value="\${E(v('g_obd_c2_co'))}"></td>
        <td><input class="en-inp" data-field="g_obd_c2_nox" type="text" value="\${E(v('g_obd_c2_nox'))}"></td>
        <td><input class="en-inp" data-field="g_obd_c2_hc"  type="text" value="\${E(v('g_obd_c2_hc'))}"></td>
        <td><input class="en-inp" data-field="g_obd_r2_judg" type="text" placeholder="\${BL('g_ph_pass_fail')}" value="\${E(v('g_obd_r2_judg'))}"></td>
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
      <tr><th class="en-sub-th" colspan="3">\${BL('g_3_3_lbl')}</th></tr>
      <tr>
        <th class="en-th">\${BL('g_th_div')}</th>
        <th class="en-th">\${BL('g_th_item')}</th>
        <th class="en-th">\${BL('g_th_content')}</th>
      </tr>
    </thead>
    <tbody>
      <!-- 1. 촉매, DPF 등 후처리장치 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">1</td>
        <td class="en-lbl">\${BL('g_lbl_catalyst')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_catalyst" rows="2" placeholder="\${BL('g_ph_catalyst')}">\${E(v('g_catalyst'))}</textarea>
            <input type="hidden" data-field="g_catalyst_imgs" value="\${E(v('g_catalyst_imgs'))}">
            <div class="en-drop" data-field-img="g_catalyst"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 2. 증발가스 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">2</td>
        <td class="en-lbl">\${BL('g_lbl_evap')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_evap_content" rows="3" placeholder="\${BL('g_ph_evap_detail')}">\${E(v('g_evap_content'))}</textarea>
            <input type="hidden" data-field="g_evap_content_imgs" value="\${E(v('g_evap_content_imgs'))}">
            <div class="en-drop" data-field-img="g_evap_content"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3. 블로바이가스 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">3</td>
        <td class="en-lbl">\${BL('g_lbl_blowby')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_blowby_detail" rows="2" placeholder="\${BL('g_ph_blowby')}">\${E(v('g_blowby_detail'))}</textarea>
            <input type="hidden" data-field="g_blowby_detail_imgs" value="\${E(v('g_blowby_detail_imgs'))}">
            <div class="en-drop" data-field-img="g_blowby_detail"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 4. 배출가스자기진단장치(OBD2) -->
      <tr>
        <td class="en-lbl" style="text-align:center; vertical-align:top; padding-top:8px;">4</td>
        <td class="en-lbl" style="vertical-align:top; padding-top:8px;">\${BL('g_lbl_obd2')}</td>
        <td style="padding:4px 6px;">
          <!-- OBD2 대표/동일 여부 -->
          <div class="en-field" style="margin-bottom:6px;">
            <textarea class="en-field-text" data-field="g_obd_rep_detail" rows="2" placeholder="\${BL('g_ph_obd_rep')}">\${E(v('g_obd_rep_detail'))}</textarea>
            <input type="hidden" data-field="g_obd_rep_detail_imgs" value="\${E(v('g_obd_rep_detail_imgs'))}">
            <div class="en-drop" data-field-img="g_obd_rep_detail"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>

          <!-- OBD 기준 테이블 -->
          <table class="en-tbl" style="margin:6px 0; font-size:8pt;">
            <thead>
              <tr>
                <th class="en-th" style="width:70%;">\${BL('g_th_obd_std')}</th>
                <th class="en-th" style="width:30%;">\${BL('g_th_applicable')}</th>
              </tr>
            </thead>
            <tbody>
              <tr><td>\${BL('g_obd_std_2006_gas')}</td>
                  <td><input class="en-inp" data-field="g_obd_std1" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_obd_std1'))}"></td></tr>
              <tr><td>\${BL('g_obd_std_2013_1st')}</td>
                  <td><input class="en-inp" data-field="g_obd_std2" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_obd_std2'))}"></td></tr>
              <tr><td>\${BL('g_obd_std_2013_2nd')}</td>
                  <td><input class="en-inp" data-field="g_obd_std3" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_obd_std3'))}"></td></tr>
              <tr><td>\${BL('g_obd_std_euro6')}</td>
                  <td><input class="en-inp" data-field="g_obd_std4" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_obd_std4'))}"></td></tr>
              <tr><td>\${BL('g_obd_std_euro5_2w')}</td>
                  <td><input class="en-inp" data-field="g_obd_std5" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_obd_std5'))}"></td></tr>
              <tr><td>\${BL('g_obd_std_2006_diesel')}</td>
                  <td><input class="en-inp" data-field="g_obd_std6" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_obd_std6'))}"></td></tr>
              <tr><td>\${BL('g_obd_std_2012_diesel')}</td>
                  <td><input class="en-inp" data-field="g_obd_std7" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_obd_std7'))}"></td></tr>
              <tr><td>\${BL('g_obd_std_2014_diesel')}</td>
                  <td><input class="en-inp" data-field="g_obd_std8" type="text" placeholder="\${BL('g_ph_applicable')}" value="\${E(v('g_obd_std8'))}"></td></tr>
            </tbody>
          </table>

          <!-- OBD2 오작동 판정기준 -->
          <div class="en-field" style="margin-bottom:6px;">
            <textarea class="en-field-text" data-field="g_obd_mal_detail" rows="2" placeholder="\${BL('g_ph_obd_mal')}">\${E(v('g_obd_mal_detail'))}</textarea>
            <input type="hidden" data-field="g_obd_mal_detail_imgs" value="\${E(v('g_obd_mal_detail_imgs'))}">
            <div class="en-drop" data-field-img="g_obd_mal_detail"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>

          <!-- OBD2 감시항목별 시험여부 -->
          <table class="en-tbl" style="margin:6px 0; font-size:8pt;">
            <thead>
              <tr>
                <th class="en-th" style="width:40%;">\${BL('g_th_monitor_item')}</th>
                <th class="en-th" style="width:30%;">\${BL('g_th_test_yn')}</th>
                <th class="en-th" style="width:30%;">\${BL('g_th_test_vehicle')}</th>
              </tr>
            </thead>
            <tbody>
              <tr><td>\${BL('g_lbl_o2_sensor')}</td>
                  <td><input class="en-inp" data-field="g_mon_o2_yn"  type="text" value="\${E(v('g_mon_o2_yn'))}"></td>
                  <td><input class="en-inp" data-field="g_mon_o2_car" type="text" value="\${E(v('g_mon_o2_car'))}"></td></tr>
              <tr><td>\${BL('g_lbl_egr')}</td>
                  <td><input class="en-inp" data-field="g_mon_egr_yn"  type="text" value="\${E(v('g_mon_egr_yn'))}"></td>
                  <td><input class="en-inp" data-field="g_mon_egr_car" type="text" value="\${E(v('g_mon_egr_car'))}"></td></tr>
              <tr><td>\${BL('g_lbl_vvt')}</td>
                  <td><input class="en-inp" data-field="g_mon_vvt_yn"  type="text" value="\${E(v('g_mon_vvt_yn'))}"></td>
                  <td><input class="en-inp" data-field="g_mon_vvt_car" type="text" value="\${E(v('g_mon_vvt_car'))}"></td></tr>
              <tr><td>\${BL('g_lbl_fuel_system')}</td>
                  <td><input class="en-inp" data-field="g_mon_fuel_yn"  type="text" value="\${E(v('g_mon_fuel_yn'))}"></td>
                  <td><input class="en-inp" data-field="g_mon_fuel_car" type="text" value="\${E(v('g_mon_fuel_car'))}"></td></tr>
              <tr><td>\${BL('g_lbl_misfire')}</td>
                  <td><input class="en-inp" data-field="g_mon_mis_yn"  type="text" value="\${E(v('g_mon_mis_yn'))}"></td>
                  <td><input class="en-inp" data-field="g_mon_mis_car" type="text" value="\${E(v('g_mon_mis_car'))}"></td></tr>
              <tr><td>\${BL('g_lbl_2nd_air')}</td>
                  <td><input class="en-inp" data-field="g_mon_air_yn"  type="text" value="\${E(v('g_mon_air_yn'))}"></td>
                  <td><input class="en-inp" data-field="g_mon_air_car" type="text" value="\${E(v('g_mon_air_car'))}"></td></tr>
              <tr><td>\${BL('g_lbl_catalyst2')}</td>
                  <td><input class="en-inp" data-field="g_mon_cat_yn"  type="text" value="\${E(v('g_mon_cat_yn'))}"></td>
                  <td><input class="en-inp" data-field="g_mon_cat_car" type="text" value="\${E(v('g_mon_cat_car'))}"></td></tr>
            </tbody>
          </table>

          <!-- IUPR 적용내역 -->
          <table class="en-tbl" style="margin:6px 0; font-size:8pt;">
            <thead>
              <tr>
                <th class="en-th" style="width:30%;">\${BL('g_th_monitor_item')}</th>
                <th class="en-th" style="width:20%;">\${BL('g_th_applicable2')}</th>
                <th class="en-th" style="width:25%;">\${BL('g_th_meas_result')}</th>
                <th class="en-th" style="width:25%;">\${BL('g_th_test_vehicle')}</th>
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
        <td class="en-lbl">\${BL('g_lbl_test_facility')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_test_facility" rows="2" placeholder="\${BL('g_ph_facility_detail')}">\${E(v('g_test_facility'))}</textarea>
            <input type="hidden" data-field="g_test_facility_imgs" value="\${E(v('g_test_facility_imgs'))}">
            <div class="en-drop" data-field-img="g_test_facility"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 6. 시험차 선정근거 -->
      <tr>
        <td class="en-lbl" style="text-align:center; vertical-align:top; padding-top:8px;">6</td>
        <td class="en-lbl" style="vertical-align:top; padding-top:8px;">\${BL('g_lbl_vehicle_sel')}</td>
        <td style="padding:4px 6px; font-size:8.5pt; line-height:1.7;">
          <div>\${BL('g_vehicle_sel_title')}</div>
          <div>\${BL('g_vehicle_sel_em')}</div>
          <div>\${BL('g_vehicle_sel_noise')}</div>
          <div>\${BL('g_vehicle_sel_obd')}</div>
          <div style="margin-top:4px;">
            <input class="en-inp" data-field="g_vehicle_sel_note" type="text" placeholder="\${BL('g_ph_additional')}" value="\${E(v('g_vehicle_sel_note'))}" style="width:100%;">
          </div>
        </td>
      </tr>

      <!-- 7. 배출가스 시험 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">7</td>
        <td class="en-lbl">\${BL('em_val_emis')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_em_test_detail" rows="3" placeholder="\${BL('g_ph_em_mode')}\${BL('dp_ph_em_detail')}">\${E(v('g_em_test_detail'))}</textarea>
            <input type="hidden" data-field="g_em_test_imgs" value="\${E(v('g_em_test_imgs'))}">
            <div class="en-drop" data-field-img="g_em_test"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 8. 증발가스 시험 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">8</td>
        <td class="en-lbl">\${BL('g_lbl_evap_test')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_evap_test_detail" rows="3" placeholder="\${BL('g_ph_evap_submit')}">\${E(v('g_evap_test_detail'))}</textarea>
            <input type="hidden" data-field="g_evap_test_imgs" value="\${E(v('g_evap_test_imgs'))}">
            <div class="en-drop" data-field-img="g_evap_test"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 9. 보증기간 및 열화계수 -->
      <tr>
        <td class="en-lbl" style="text-align:center; vertical-align:top; padding-top:8px;">9</td>
        <td class="en-lbl" style="vertical-align:top; padding-top:8px;">\${BL('g_lbl_warranty_det')}</td>
        <td style="padding:4px 6px;">
          <!-- 보증기간 및 열화계수 적용 내역 -->
          <div class="en-field" style="margin-bottom:6px;">
            <textarea class="en-field-text" data-field="g_warranty_detail" rows="2" placeholder="\${BL('g_ph_warranty_detail')}">\${E(v('g_warranty_detail'))}</textarea>
            <input type="hidden" data-field="g_warranty_detail_imgs" value="\${E(v('g_warranty_detail_imgs'))}">
            <div class="en-drop" data-field-img="g_warranty_detail"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
          <div style="padding:2px 6px; font-size:8.5pt;">
            \${BL('g_lbl_warranty_km')} <input class="g-chk-inp" data-field="g_warranty_km" type="text" value="\${E(v('g_warranty_km'))}" style="width:120px;">
          </div>
          <table class="en-tbl" style="margin:6px 0; font-size:8pt;">
            <thead>
              <tr>
                <th class="en-th" style="width:50%;">\${BL('g_th_item')}</th>
                <th class="en-th" style="width:50%;">\${BL('g_th_det_factor')}</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>\${BL('g_em_co')}</td>
                <td><input class="en-inp" data-field="g_deter_co" type="text" value="\${E(v('g_deter_co'))}"></td>
              </tr>
              <tr>
                <td>\${BL('g_em_exhaust_hc')}</td>
                <td><input class="en-inp" data-field="g_deter_hc" type="text" value="\${E(v('g_deter_hc'))}"></td>
              </tr>
              <tr>
                <td>\${BL('g_em_nox')}</td>
                <td><input class="en-inp" data-field="g_deter_nox" type="text" value="\${E(v('g_deter_nox'))}"></td>
              </tr>
              <tr>
                <td>\${BL('g_em_evap_hc')}</td>
                <td><input class="en-inp" data-field="g_deter_evap" type="text" value="\${E(v('g_deter_evap'))}"></td>
              </tr>
            </tbody>
          </table>
        </td>
      </tr>

      <!-- 10. 내구 시험 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">10</td>
        <td class="en-lbl">\${BL('g_lbl_endurance')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_endurance" rows="3" placeholder="\${BL('g_ph_endurance_note')}">\${E(v('g_endurance'))}</textarea>
            <input type="hidden" data-field="g_endurance_imgs" value="\${E(v('g_endurance_imgs'))}">
            <div class="en-drop" data-field-img="g_endurance"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 11. 주기적재생지수(ki) 시험 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">11</td>
        <td class="en-lbl">\${BL('g_lbl_ki')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_ki_test" rows="3" placeholder="\${BL('g_ph_ki_note')}">\${E(v('g_ki_test'))}</textarea>
            <input type="hidden" data-field="g_ki_test_imgs" value="\${E(v('g_ki_test_imgs'))}">
            <div class="en-drop" data-field-img="g_ki_test"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 12. 소음시험 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">12</td>
        <td class="en-lbl">\${BL('g_lbl_noise_test')}</td>
        <td style="padding:4px 6px; font-size:8.5pt;">
          <div class="g-chk-row">
            
            <span>\${BL('g_noise_submit')}</span>
          </div>
          <div class="en-field" style="padding:2px 4px 6px;">
            <textarea class="en-field-text" data-field="g_noise_cert" rows="2" placeholder="\${BL('g_ph_noise_submit')}">\${E(v('g_noise_cert'))}</textarea>
            <input type="hidden" data-field="g_noise_cert_imgs" value="\${E(v('g_noise_cert_imgs'))}">
            <div class="en-drop" data-field-img="g_noise_cert">
              <input type="file" accept="image/*" multiple>
              <div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div>
              <div class="en-img-list"></div>
            </div>
          </div>
          <div class="g-chk-row">
            
            <span>\${BL('g_noise_method')}</span>
          </div>
          <div style="padding:2px 8px; font-size:8.5pt; line-height:2.0;">
            \${BL('g_noise_accel_lbl')} <input class="g-chk-inp" data-field="g_noise_accel" type="text" value="\${E(v('g_noise_accel'))}" style="width:200px;"><br>
            \${BL('g_noise_exhaust_lbl')} <input class="g-chk-inp" data-field="g_noise_exhaust" type="text" value="\${E(v('g_noise_exhaust'))}" style="width:200px;"><br>
            \${BL('g_noise_horn_lbl')} <input class="g-chk-inp" data-field="g_noise_horn" type="text" value="\${E(v('g_noise_horn'))}" style="width:200px;">
          </div>
        </td>
      </tr>

      <!-- 13. 동일차종 구성 -->
      <tr>
        <td class="en-lbl" style="text-align:center;">13</td>
        <td class="en-lbl">\${BL('g_lbl_same_type')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="g_same_type" rows="3" placeholder="\${BL('g_ph_same_type')}">\${E(v('g_same_type'))}</textarea>
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
      <td><input data-field="dp_cert_year" class="dp-inp" type="text" placeholder="\${BL('dp_ph_year_ex')}" value="\${E(v('dp_cert_year'))}"></td>
      <td><input data-field="dp_disp"      class="dp-inp" type="text" placeholder="\${BL('dp_ph_disp_ex')}" value="\${E(v('dp_disp'))}"></td>
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
    <tr><th class="dp-sec-th" colspan="2">\${BL('dp_s1')}</th></tr>

    <!-- 1.1 개발배경 및 특성 -->
    <tr>
      <td class="dp-lbl">\${BL('dp_1_1_lbl')}</td>
      <td>
        <div class="dp-field">
          <textarea class="dp-field-text" data-field="dp_1_1" rows="4" placeholder="\${BL('dp_ph_dev_bg')}">\${E(v('dp_1_1'))}</textarea>
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
      <td class="dp-lbl">\${BL('dp_1_2_lbl')}</td>
      <td>
        <div class="dp-field">
          <textarea class="dp-field-text" data-field="dp_1_2" rows="4" placeholder="\${BL('dp_ph_new_tech')}">\${E(v('dp_1_2'))}</textarea>
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
    <tr><td class="dp-sub-th" colspan="2">\${BL('dp_1_3_title')}</td></tr>
  </tbody>
</table>
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup>
    <col style="width:12%;"><col style="width:11%;"><col style="width:11%;"><col style="width:11%;"><col style="width:11%;"><col style="width:11%;"><col style="width:11%;"><col style="width:11%;"><col style="width:11%;">
  </colgroup>
  <thead>
    <tr>
      <th class="dp-th">\${BL('dp_lbl_category')}</th>
      <th class="dp-th">\${BL('g_th_co_gkm')}</th>
      <th class="dp-th">NOx<br>(g/km)</th>
      <th class="dp-th">MHHC<br>(g/km)</th>
      <th class="dp-th">\${BL('g_lbl_evap')}<br>(g/test)</th>
      <th class="dp-th">\${BL('g_th_pm_gkm')}</th>
      <th class="dp-th">\${BL('dp_th_formaldehyde')}</th>
      <th class="dp-th">\${BL('dp_th_smoke')}</th>
      <th class="dp-th">Cold CO<br>(g/km)</th>
    </tr>
  </thead>
  <tbody>
    \${[BL('dp_1_3_r0'),BL('dp_1_3_r1'),BL('dp_1_3_r2')].map((row,ri)=>\`
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
    <tr><th class="dp-sub-th" colspan="3">1.4.&nbsp;\${BL('dp_1_4_title')}</th></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_car_name')}</td><td><input class="dp-inp" data-field="dp_1_4_carname" type="text" value="\${E(v('dp_1_4_carname'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_car_type')}</td><td><input class="dp-inp" data-field="dp_1_4_type" type="text" value="\${E(v('dp_1_4_type'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="13">\${BL('dp_lbl_car_spec')}</td><td class="dp-lbl">\${BL('en_1_3_3_lbl')}</td><td><input class="dp-inp" data-field="dp_1_4_maker" type="text" value="\${E(v('dp_1_4_maker'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_passenger')}</td><td><input class="dp-inp" data-field="dp_1_4_passenger" type="text" value="\${E(v('dp_1_4_passenger'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_model_year')}</td><td><input class="dp-inp" data-field="dp_1_4_modelyear" type="text" value="\${E(v('dp_1_4_modelyear'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_spec_no')}</td><td><input class="dp-inp" data-field="dp_1_4_specno" type="text" value="\${E(v('dp_1_4_specno'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_drive')}</td><td><input class="dp-inp" data-field="dp_1_4_drive" type="text" value="\${E(v('dp_1_4_drive'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_car_class')}</td><td><input class="dp-inp" data-field="dp_1_4_cartype" type="text" value="\${E(v('dp_1_4_cartype'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_purpose')}</td><td><input class="dp-inp" data-field="dp_1_4_purpose" type="text" value="\${E(v('dp_1_4_purpose'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_trans_type')}</td><td><input class="dp-inp" data-field="dp_1_4_trans" type="text" value="\${E(v('dp_1_4_trans'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_body_shape')}</td><td><input class="dp-inp" data-field="dp_1_4_body" type="text" value="\${E(v('dp_1_4_body'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_curb_wt')}</td><td><input class="dp-inp" data-field="dp_1_4_curb" type="text" value="\${E(v('dp_1_4_curb'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_gvw')}</td><td><input class="dp-inp" data-field="dp_1_4_gvw" type="text" value="\${E(v('dp_1_4_gvw'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_inertia_wt')}</td><td><input class="dp-inp" data-field="dp_1_4_inertia" type="text" value="\${E(v('dp_1_4_inertia'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_dyno_hp')}</td><td><input class="dp-inp" data-field="dp_1_4_dyno" type="text" value="\${E(v('dp_1_4_dyno'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="3">\${BL('dp_lbl_dimensions')}</td><td class="dp-lbl">\${BL('dp_lbl_length')}</td><td><input class="dp-inp" data-field="dp_1_4_len" type="text" value="\${E(v('dp_1_4_len'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_width')}</td><td><input class="dp-inp" data-field="dp_1_4_width" type="text" value="\${E(v('dp_1_4_width'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_height')}</td><td><input class="dp-inp" data-field="dp_1_4_height" type="text" value="\${E(v('dp_1_4_height'))}"></td></tr>
  </tbody>
</table>

<!-- ── Page 2: 원동기(rowspan=21) + 연료장치(rowspan=6) (4col: 20/20/20/40) ── -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:20%;"><col style="width:20%;"><col style="width:20%;"><col style="width:40%;"></colgroup>
  <tbody>
    <tr><td class="dp-lbl" rowspan="21">\${BL('dp_lbl_engine')}</td><td class="dp-lbl" colspan="2">\${BL('dp_lbl_manufacturer')}</td><td><input class="dp-inp" data-field="dp_1_4_eng_maker" type="text" value="\${E(v('dp_1_4_eng_maker'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_combustion')}</td><td><input class="dp-inp" data-field="dp_1_4_eng_comb" type="text" value="\${E(v('dp_1_4_eng_comb'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_eng_type')}</td><td><input class="dp-inp" data-field="dp_1_4_eng_type" type="text" value="\${E(v('dp_1_4_eng_type'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_displacement')}</td><td><input class="dp-inp" data-field="dp_1_4_eng_disp" type="text" value="\${E(v('dp_1_4_eng_disp'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_eng_pos')}</td><td><input class="dp-inp" data-field="dp_1_4_eng_pos" type="text" value="\${E(v('dp_1_4_eng_pos'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_fuel_type')}</td><td><input class="dp-inp" data-field="dp_1_4_eng_fuel" type="text" value="\${E(v('dp_1_4_eng_fuel'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_cyl_count')}</td><td><input class="dp-inp" data-field="dp_1_4_eng_cyl" type="text" value="\${E(v('dp_1_4_eng_cyl'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_cyl_arr')}</td><td><input class="dp-inp" data-field="dp_1_4_eng_cylarr" type="text" value="\${E(v('dp_1_4_eng_cylarr'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_chamber_type')}</td><td><input class="dp-inp" data-field="dp_1_4_eng_chamber" type="text" value="\${E(v('dp_1_4_eng_chamber'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_max_power')}</td><td><input class="dp-inp" data-field="dp_1_4_eng_maxpow" type="text" value="\${E(v('dp_1_4_eng_maxpow'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_max_torque')}</td><td><input class="dp-inp" data-field="dp_1_4_eng_maxtq" type="text" value="\${E(v('dp_1_4_eng_maxtq'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_bore_stroke')}</td><td><input class="dp-inp" data-field="dp_1_4_eng_bore" type="text" value="\${E(v('dp_1_4_eng_bore'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_idle_rpm')}</td><td><input class="dp-inp" data-field="dp_1_4_eng_idle" type="text" value="\${E(v('dp_1_4_eng_idle'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('em_lbl_cooling')}</td><td><input class="dp-inp" data-field="dp_1_4_eng_cool" type="text" value="\${E(v('dp_1_4_eng_cool'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_intake_method')}</td><td><input class="dp-inp" data-field="dp_1_4_eng_intake" type="text" value="\${E(v('dp_1_4_eng_intake'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">\${BL('dp_lbl_intake_manifold')}</td><td class="dp-lbl">\${BL('dp_lbl_port_size')}</td><td><input class="dp-inp" data-field="dp_1_4_inm_size" type="text" value="\${E(v('dp_1_4_inm_size'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_port_shape')}</td><td><input class="dp-inp" data-field="dp_1_4_inm_shape" type="text" value="\${E(v('dp_1_4_inm_shape'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">\${BL('dp_lbl_exhaust_manifold')}</td><td class="dp-lbl">\${BL('dp_lbl_port_size_mm')}</td><td><input class="dp-inp" data-field="dp_1_4_exm_size" type="text" value="\${E(v('dp_1_4_exm_size'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_port_shape')}</td><td><input class="dp-inp" data-field="dp_1_4_exm_shape" type="text" value="\${E(v('dp_1_4_exm_shape'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('em_lbl_comp_ratio')}</td><td><input class="dp-inp" data-field="dp_1_4_compress" type="text" value="\${E(v('dp_1_4_compress'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_ign_timing')}</td><td><input class="dp-inp" data-field="dp_1_4_ign_timing" type="text" value="\${E(v('dp_1_4_ign_timing'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="6">\${BL('dp_lbl_fuel_system')}</td><td class="dp-lbl" colspan="2">\${BL('em_lbl_fuel_supply')}</td><td><input class="dp-inp" data-field="dp_1_4_fuel_supply" type="text" value="\${E(v('dp_1_4_fuel_supply'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="3">\${BL('dp_lbl_fuel_tank')}</td><td class="dp-lbl">\${BL('dp_lbl_capacity_l')}</td><td><input class="dp-inp" data-field="dp_1_4_tank_vol" type="text" value="\${E(v('dp_1_4_tank_vol'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_position')}</td><td><input class="dp-inp" data-field="dp_1_4_tank_pos" type="text" value="\${E(v('dp_1_4_tank_pos'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_material')}</td><td><input class="dp-inp" data-field="dp_1_4_tank_mat" type="text" value="\${E(v('dp_1_4_tank_mat'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">\${BL('dp_lbl_air_cleaner')}</td><td class="dp-lbl">\${BL('dp_lbl_form_type')}</td><td><input class="dp-inp" data-field="dp_1_4_air_type" type="text" value="\${E(v('dp_1_4_air_type'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_count')}</td><td><input class="dp-inp" data-field="dp_1_4_filter_cnt" type="text" value="\${E(v('dp_1_4_filter_cnt'))}"></td></tr>
  </tbody>
</table>

<!-- ── Page 3: 동력전달장치 + 전기자동차 + 타이어 (5col: 15/15/15/15/40) ── -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:15%;"><col style="width:15%;"><col style="width:15%;"><col style="width:15%;"><col style="width:40%;"></colgroup>
  <tbody>
    <tr><td class="dp-lbl" rowspan="16">\${BL('dp_lbl_drivetrain')}</td><td class="dp-lbl" rowspan="2">\${BL('dp_lbl_clutch')}</td><td class="dp-lbl" colspan="2">\${BL('dp_lbl_form_type')}</td><td><input class="dp-inp" data-field="dp_1_4_clutch_type" type="text" value="\${E(v('dp_1_4_clutch_type'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_operation')}</td><td><input class="dp-inp" data-field="dp_1_4_clutch_op" type="text" value="\${E(v('dp_1_4_clutch_op'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="11">\${BL('obd_trans_lbl')}</td><td class="dp-lbl" rowspan="2">\${BL('dp_lbl_form_type')}</td><td class="dp-lbl">\${BL('dp_lbl_forward')}</td><td><input class="dp-inp" data-field="dp_1_4_trans_fwd" type="text" value="\${E(v('dp_1_4_trans_fwd'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_reverse')}</td><td><input class="dp-inp" data-field="dp_1_4_trans_rev" type="text" value="\${E(v('dp_1_4_trans_rev'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_operation')}</td><td><input class="dp-inp" data-field="dp_1_4_trans_op" type="text" value="\${E(v('dp_1_4_trans_op'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="8">\${BL('dp_lbl_gear_ratio')}</td><td class="dp-lbl">\${BL('dp_lbl_gear_1')}</td><td><input class="dp-inp" data-field="dp_1_4_gear_1" type="text" value="\${E(v('dp_1_4_gear_1'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_gear2')}</td><td><input class="dp-inp" data-field="dp_1_4_gear_2" type="text" value="\${E(v('dp_1_4_gear_2'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_gear3')}</td><td><input class="dp-inp" data-field="dp_1_4_gear_3" type="text" value="\${E(v('dp_1_4_gear_3'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_gear4')}</td><td><input class="dp-inp" data-field="dp_1_4_gear_4" type="text" value="\${E(v('dp_1_4_gear_4'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_gear5')}</td><td><input class="dp-inp" data-field="dp_1_4_gear_5" type="text" value="\${E(v('dp_1_4_gear_5'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_gear6')}</td><td><input class="dp-inp" data-field="dp_1_4_gear_6" type="text" value="\${E(v('dp_1_4_gear_6'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_gear7')}</td><td><input class="dp-inp" data-field="dp_1_4_gear_7" type="text" value="\${E(v('dp_1_4_gear_7'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_reverse')}</td><td><input class="dp-inp" data-field="dp_1_4_gear_8" type="text" value="\${E(v('dp_1_4_gear_8'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">\${BL('dp_lbl_red_ratio')}</td><td class="dp-lbl" colspan="2">\${BL('dp_lbl_red1')}</td><td><input class="dp-inp" data-field="dp_1_4_red1" type="text" value="\${E(v('dp_1_4_red1'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_red2')}</td><td><input class="dp-inp" data-field="dp_1_4_red2" type="text" value="\${E(v('dp_1_4_red2'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="3">\${BL('dp_lbl_nv_ratio')}</td><td><input class="dp-inp" data-field="dp_1_4_nv" type="text" value="\${E(v('dp_1_4_nv'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="4">\${BL('dp_lbl_ev_spec')}</td><td class="dp-lbl" colspan="3">\${BL('dp_lbl_motor_type')}</td><td><input class="dp-inp" data-field="dp_1_4_ev_motor" type="text" value="\${E(v('dp_1_4_ev_motor'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="3">\${BL('dp_lbl_batt_cap')}</td><td><input class="dp-inp" data-field="dp_1_4_ev_batt" type="text" value="\${E(v('dp_1_4_ev_batt'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="3">\${BL('dp_lbl_motor_power')}</td><td><input class="dp-inp" data-field="dp_1_4_ev_pow" type="text" value="\${E(v('dp_1_4_ev_pow'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="3">\${BL('dp_lbl_ev_range')}</td><td><input class="dp-inp" data-field="dp_1_4_ev_range" type="text" value="\${E(v('dp_1_4_ev_range'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="6">\${BL('dp_lbl_tire')}</td><td class="dp-lbl" colspan="3">\${BL('dp_lbl_tire_maker')}</td><td><input class="dp-inp" data-field="dp_1_4_tire_maker" type="text" value="\${E(v('dp_1_4_tire_maker'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="3">\${BL('dp_lbl_tire_struct')}</td><td><input class="dp-inp" data-field="dp_1_4_tire_struct" type="text" value="\${E(v('dp_1_4_tire_struct'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">\${BL('dp_lbl_tire_size')}</td><td class="dp-lbl" colspan="2">\${BL('dp_lbl_front')}</td><td><input class="dp-inp" data-field="dp_1_4_tire_fsize" type="text" value="\${E(v('dp_1_4_tire_fsize'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_rear')}</td><td><input class="dp-inp" data-field="dp_1_4_tire_rsize" type="text" value="\${E(v('dp_1_4_tire_rsize'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">\${BL('dp_lbl_tire_pres')}</td><td class="dp-lbl" colspan="2">\${BL('dp_lbl_front')}</td><td><input class="dp-inp" data-field="dp_1_4_tire_fpres" type="text" value="\${E(v('dp_1_4_tire_fpres'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_rear')}</td><td><input class="dp-inp" data-field="dp_1_4_tire_rpres" type="text" value="\${E(v('dp_1_4_tire_rpres'))}"></td></tr>
  </tbody>
</table>

<!-- ── Page 4: 촉매/배출가스/캐니스터/소음기/경보장치 (4col: 20/20/20/40) ── -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:20%;"><col style="width:20%;"><col style="width:20%;"><col style="width:40%;"></colgroup>
  <tbody>
    <tr><td class="dp-lbl" rowspan="5">\${BL('g_lbl_catalyst2')}</td><td class="dp-lbl" colspan="2">\${BL('dp_lbl_type_kind')}</td><td><input class="dp-inp" data-field="dp_1_4_cat_type" type="text" value="\${E(v('dp_1_4_cat_type'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_precious_comp')}</td><td><input class="dp-inp" data-field="dp_1_4_cat_pm" type="text" value="\${E(v('dp_1_4_cat_pm'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_precious_g')}</td><td><input class="dp-inp" data-field="dp_1_4_cat_pmg" type="text" value="\${E(v('dp_1_4_cat_pmg'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_vol_cc')}</td><td><input class="dp-inp" data-field="dp_1_4_cat_vol" type="text" value="\${E(v('dp_1_4_cat_vol'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_pm_ratio')}</td><td><input class="dp-inp" data-field="dp_1_4_cat_ratio" type="text" value="\${E(v('dp_1_4_cat_ratio'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="3">\${BL('dp_lbl_em_test_info')}</td><td class="dp-lbl" colspan="2">\${BL('dp_lbl_road_load')}</td><td><input class="dp-inp" data-field="dp_1_4_roadload" type="text" value="\${E(v('dp_1_4_roadload'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_road_coef')}</td><td><input class="dp-inp" data-field="dp_1_4_roadcoef" type="text" value="\${E(v('dp_1_4_roadcoef'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_coast_down')}</td><td><input class="dp-inp" data-field="dp_1_4_coastdown" type="text" value="\${E(v('dp_1_4_coastdown'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="4">\${BL('dp_lbl_canister')}</td><td class="dp-lbl" colspan="2">\${BL('dp_lbl_can_cap')}</td><td><input class="dp-inp" data-field="dp_1_4_can_cap" type="text" value="\${E(v('dp_1_4_can_cap'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_can_size')}</td><td><input class="dp-inp" data-field="dp_1_4_can_size" type="text" value="\${E(v('dp_1_4_can_size'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_can_media')}</td><td><input class="dp-inp" data-field="dp_1_4_can_media" type="text" value="\${E(v('dp_1_4_can_media'))}"></td></tr>
    <tr><td class="dp-lbl" colspan="2">\${BL('dp_lbl_evap_cap')}</td><td><input class="dp-inp" data-field="dp_1_4_can_evap" type="text" value="\${E(v('dp_1_4_can_evap'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="4">\${BL('dp_lbl_muffler')}</td><td class="dp-lbl" rowspan="2">\${BL('dp_lbl_muf_main')}</td><td class="dp-lbl">\${BL('dp_lbl_material')}</td><td><input class="dp-inp" data-field="dp_1_4_muf_main_mat" type="text" value="\${E(v('dp_1_4_muf_main_mat'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_vol_l')}</td><td><input class="dp-inp" data-field="dp_1_4_muf_main_vol" type="text" value="\${E(v('dp_1_4_muf_main_vol'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">\${BL('dp_lbl_muf_sub')}</td><td class="dp-lbl">\${BL('dp_lbl_material')}</td><td><input class="dp-inp" data-field="dp_1_4_muf_sub_mat" type="text" value="\${E(v('dp_1_4_muf_sub_mat'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_vol_l')}</td><td><input class="dp-inp" data-field="dp_1_4_muf_sub_vol" type="text" value="\${E(v('dp_1_4_muf_sub_vol'))}"></td></tr>
    <tr><td class="dp-lbl" rowspan="2">\${BL('dp_lbl_horn_dev')}</td><td class="dp-lbl" rowspan="2">\${BL('dp_lbl_horn')}</td><td class="dp-lbl">\${BL('dp_lbl_form_type')}</td><td><input class="dp-inp" data-field="dp_1_4_horn_type" type="text" value="\${E(v('dp_1_4_horn_type'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_lbl_horn_db')}</td><td><input class="dp-inp" data-field="dp_1_4_horn_db" type="text" value="\${E(v('dp_1_4_horn_db'))}"></td></tr>
  </tbody>
</table>

<!-- ══ 2. 기밀사항 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:100%;"></colgroup>
  <tbody>
    <tr><th class="dp-sec-th">\${BL('dp_s2')}</th></tr>
    <tr><td class="dp-sub-th">\${BL('dp_2_1_title')}</td></tr>
    <tr><td>
      <div class="dp-field">
        <textarea class="dp-field-text" data-field="dp_2_1" rows="3" placeholder="\${BL('dp_ph_confidential')}">\${E(v('dp_2_1'))}</textarea>
      </div>
    </td></tr>
  </tbody>
</table>

<!-- ══ 3. 인증시험 연료 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:18%;"><col style="width:27%;"><col style="width:27%;"><col style="width:28%;"></colgroup>
  <thead>
    <tr><th class="dp-sec-th" colspan="4">\${BL('dp_s3')}</th></tr>
    <tr>
      <th class="dp-th">\${BL('dp_lbl_category')}</th>
      <th class="dp-th">\${BL('dp_lbl_item')}</th>
      <th class="dp-th">\${BL('dp_lbl_test_fuel')}</th>
      <th class="dp-th">\${BL('dp_lbl_acc_fuel')}</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="dp-lbl" rowspan="10">\${BL('dp_lbl_gasoline')}</td>
      <td class="dp-lbl">\${BL('dp_lbl_octane')}</td>
      <td><input class="dp-inp" data-field="dp_f_gas_oct_test" type="text" value="\${E(v('dp_f_gas_oct_test'))}"></td>
      <td><input class="dp-inp" data-field="dp_f_gas_oct_acc" type="text" value="\${E(v('dp_f_gas_oct_acc'))}"></td>
    </tr>
    \${[
      [BL('dp_lbl_aromatic'),'dp_f_gas_arom'],
      [BL('dp_lbl_benzene'),'dp_f_gas_benz'],
      [BL('dp_lbl_oxygen'),'dp_f_gas_oxy'],
      [BL('dp_lbl_lead'),'dp_f_gas_pb'],
      [BL('dp_lbl_phosphorus'),'dp_f_gas_p'],
      [BL('dp_lbl_olefin'),'dp_f_gas_olef'],
      [BL('dp_lbl_vapor_p'),'dp_f_gas_vp'],
      [BL('dp_lbl_90pct_temp'),'dp_f_gas_90t'],
      [BL('dp_lbl_sulfur'),'dp_f_gas_s'],
    ].map(([item,fld])=>\`<tr>
      <td class="dp-lbl">\${item}</td>
      <td><input class="dp-inp" data-field="\${fld}_test" type="text" value="\${E(v('\${fld}_test'))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_acc" type="text" value="\${E(v('\${fld}_acc'))}"></td>
    </tr>\`).join('')}
    <tr>
      <td class="dp-lbl" rowspan="5">\${BL('dp_lbl_diesel')}</td>
      <td class="dp-lbl">\${BL('dp_lbl_residual_carbon')}</td>
      <td><input class="dp-inp" data-field="dp_f_die_rc_test" type="text" value="\${E(v('dp_f_die_rc_test'))}"></td>
      <td><input class="dp-inp" data-field="dp_f_die_rc_acc" type="text" value="\${E(v('dp_f_die_rc_acc'))}"></td>
    </tr>
    \${[
      [BL('dp_lbl_sulfur'),'dp_f_die_s'],
      [BL('dp_lbl_cetane'),'dp_f_die_ci'],
      [BL('dp_lbl_90pct_temp'),'dp_f_die_90t'],
      [BL('dp_lbl_aromatic'),'dp_f_die_arom'],
    ].map(([item,fld])=>\`<tr>
      <td class="dp-lbl">\${item}</td>
      <td><input class="dp-inp" data-field="\${fld}_test" type="text" value="\${E(v('\${fld}_test'))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_acc" type="text" value="\${E(v('\${fld}_acc'))}"></td>
    </tr>\`).join('')}
    <tr>
      <td class="dp-lbl" rowspan="2">LPG</td>
      <td class="dp-lbl">\${BL('dp_lbl_residual_carbon')}</td>
      <td><input class="dp-inp" data-field="dp_f_lpg_rc_test" type="text" value="\${E(v('dp_f_lpg_rc_test'))}"></td>
      <td><input class="dp-inp" data-field="dp_f_lpg_rc_acc" type="text" value="\${E(v('dp_f_lpg_rc_acc'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_sulfur')}</td>
      <td><input class="dp-inp" data-field="dp_f_lpg_s_test" type="text" value="\${E(v('dp_f_lpg_s_test'))}"></td>
      <td><input class="dp-inp" data-field="dp_f_lpg_s_acc" type="text" value="\${E(v('dp_f_lpg_s_acc'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">\${BL('dp_lbl_fuel_source')}</td>
      <td colspan="2"><input class="dp-inp" data-field="dp_f_source" type="text" value="\${E(v('dp_f_source'))}"></td>
    </tr>
    <tr>
      <td colspan="4" style="font-size:8pt; padding:4px 6px; border-top:1px solid #ccc; line-height:1.5;">
        \${BL('dp_fuel_note')}
      </td>
    </tr>
  </tbody>
</table>

<!-- ══ 4. 시험설비 및 배출가스·소음 측정장비 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:22%;"><col style="width:13%;"><col style="width:13%;"><col style="width:13%;"><col style="width:16%;"><col style="width:13%;"><col style="width:10%;"></colgroup>
  <thead>
    <tr><th class="dp-sec-th" colspan="7">\${BL('dp_s4')}</th></tr>
    <tr><th class="dp-sub-th" colspan="7">\${BL('dp_4_1_title')}</th></tr>
    <tr>
      <th class="dp-th">\${BL('dp_th_equip_name')}</th>
      <th class="dp-th">\${BL('en_1_3_3_lbl')}</th>
      <th class="dp-th">\${BL('dp_th_model')}</th>
      <th class="dp-th">\${BL('dp_th_type_no')}</th>
      <th class="dp-th">\${BL('dp_th_type_date')}</th>
      <th class="dp-th">\${BL('dp_th_lab_name')}</th>
      <th class="dp-th">\${BL('dp_th_calib_date')}</th>
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
    <tr><th class="dp-sub-th" colspan="7">\${BL('dp_4_2_title')}</th></tr>
    <tr>
      <th class="dp-th">\${BL('dp_th_equip_name')}</th>
      <th class="dp-th">\${BL('en_1_3_3_lbl')}</th>
      <th class="dp-th">\${BL('dp_th_model')}</th>
      <th class="dp-th">\${BL('dp_th_type_no')}</th>
      <th class="dp-th">\${BL('dp_th_type_date')}</th>
      <th class="dp-th">\${BL('dp_th_lab_name')}</th>
      <th class="dp-th">\${BL('dp_th_calib_date')}</th>
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
    <tr>
      <td colspan="7" style="font-size:8pt; padding:4px 6px; border-top:1px solid #ccc; line-height:1.5;">
        \${BL('dp_equip_note')}
      </td>
    </tr>
  </tbody>
</table>

<!-- ══ 5. 시험절차 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:28%;"><col style="width:72%;"></colgroup>
  <tbody>
    <tr><th class="dp-sec-th" colspan="2">\${BL('dp_s5')}</th></tr>
    <tr><th class="dp-sub-th" colspan="2">\${BL('dp_5_1_lbl')}</th></tr>
    <tr><td class="dp-lbl">\${BL('dp_5_1_1_lbl')}</td><td><input class="dp-inp" data-field="dp_5_1_1" type="text" value="\${E(v('dp_5_1_1'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_5_1_2_lbl')}</td><td><input class="dp-inp" data-field="dp_5_1_2" type="text" value="\${E(v('dp_5_1_2'))}"></td></tr>
    <tr><th class="dp-sub-th" colspan="2">\${BL('dp_5_2_lbl')}</th></tr>
    <tr><td class="dp-lbl">\${BL('dp_5_2_1_lbl')}</td><td><input class="dp-inp" data-field="dp_5_2_1" type="text" value="\${E(v('dp_5_2_1'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_5_2_2_lbl')}</td><td><input class="dp-inp" data-field="dp_5_2_2" type="text" value="\${E(v('dp_5_2_2'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_5_2_3_lbl')}</td><td><input class="dp-inp" data-field="dp_5_2_3" type="text" value="\${E(v('dp_5_2_3'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_5_2_4_lbl')}</td><td><input class="dp-inp" data-field="dp_5_2_4" type="text" value="\${E(v('dp_5_2_4'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_5_2_5_lbl')}</td><td><input class="dp-inp" data-field="dp_5_2_5" type="text" value="\${E(v('dp_5_2_5'))}"></td></tr>
    <tr><th class="dp-sub-th" colspan="2">\${BL('dp_5_3_lbl')}</th></tr>
    <tr><td class="dp-lbl">\${BL('dp_5_3_1_lbl')}</td><td><input class="dp-inp" data-field="dp_5_3_1" type="text" value="\${E(v('dp_5_3_1'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_5_3_2_lbl')}</td><td><input class="dp-inp" data-field="dp_5_3_2" type="text" value="\${E(v('dp_5_3_2'))}"></td></tr>
    <tr><th class="dp-sub-th" colspan="2">\${BL('dp_5_4_lbl')}</th></tr>
    <tr><td class="dp-lbl">\${BL('dp_5_4_1_lbl')}</td><td><input class="dp-inp" data-field="dp_5_4_1" type="text" value="\${E(v('dp_5_4_1'))}"></td></tr>
    <tr><td class="dp-lbl">\${BL('dp_5_4_2_lbl')}</td><td><input class="dp-inp" data-field="dp_5_4_2" type="text" value="\${E(v('dp_5_4_2'))}"></td></tr>
  </tbody>
</table>

<!-- ══ 6. 정비 및 보증 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:12%;"><col style="width:18%;"><col style="width:10%;"><col style="width:10%;"><col style="width:10%;"><col style="width:10%;"><col style="width:10%;"><col style="width:20%;"></colgroup>
  <tbody>
    <tr><th class="dp-sec-th" colspan="8">\${BL('dp_s6')}</th></tr>
    <tr><th class="dp-sub-th" colspan="8">\${BL('dp_6_1_title')}</th></tr>
    <tr><th class="dp-sub-th" colspan="8">\${BL('dp_6_1_1_title')}</th></tr>
    <tr>
      <th class="dp-th">\${BL('dp_lbl_category')}</th><th class="dp-th">\${BL('dp_lbl_item')}</th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_1_1_km_0" type="text" value="\${E(v('dp_6_1_1_km_0'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_1_1_km_1" type="text" value="\${E(v('dp_6_1_1_km_1'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_1_1_km_2" type="text" value="\${E(v('dp_6_1_1_km_2'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_1_1_km_3" type="text" value="\${E(v('dp_6_1_1_km_3'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_1_1_km_4" type="text" value="\${E(v('dp_6_1_1_km_4'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th">\${BL('dp_th_note')}</th>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_engine')}</td><td><input class="dp-inp" data-field="dp_6_1_1_0_item" type="text" value="\${E(v('dp_6_1_1_0_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_0_0" type="text" value="\${E(v('dp_6_1_1_0_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_0_1" type="text" value="\${E(v('dp_6_1_1_0_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_0_2" type="text" value="\${E(v('dp_6_1_1_0_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_0_3" type="text" value="\${E(v('dp_6_1_1_0_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_0_4" type="text" value="\${E(v('dp_6_1_1_0_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_0_note" type="text" value="\${E(v('dp_6_1_1_0_note'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_ignition')}</td><td><input class="dp-inp" data-field="dp_6_1_1_1_item" type="text" value="\${E(v('dp_6_1_1_1_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_1_0" type="text" value="\${E(v('dp_6_1_1_1_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_1_1" type="text" value="\${E(v('dp_6_1_1_1_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_1_2" type="text" value="\${E(v('dp_6_1_1_1_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_1_3" type="text" value="\${E(v('dp_6_1_1_1_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_1_4" type="text" value="\${E(v('dp_6_1_1_1_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_1_note" type="text" value="\${E(v('dp_6_1_1_1_note'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_chassis')}</td><td><input class="dp-inp" data-field="dp_6_1_1_2_item" type="text" value="\${E(v('dp_6_1_1_2_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_2_0" type="text" value="\${E(v('dp_6_1_1_2_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_2_1" type="text" value="\${E(v('dp_6_1_1_2_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_2_2" type="text" value="\${E(v('dp_6_1_1_2_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_2_3" type="text" value="\${E(v('dp_6_1_1_2_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_2_4" type="text" value="\${E(v('dp_6_1_1_2_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_2_note" type="text" value="\${E(v('dp_6_1_1_2_note'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('em_val_etc')}</td><td><input class="dp-inp" data-field="dp_6_1_1_3_item" type="text" value="\${E(v('dp_6_1_1_3_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_3_0" type="text" value="\${E(v('dp_6_1_1_3_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_3_1" type="text" value="\${E(v('dp_6_1_1_3_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_3_2" type="text" value="\${E(v('dp_6_1_1_3_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_3_3" type="text" value="\${E(v('dp_6_1_1_3_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_3_4" type="text" value="\${E(v('dp_6_1_1_3_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_1_1_3_note" type="text" value="\${E(v('dp_6_1_1_3_note'))}"></td>
    </tr>
    <tr><th class="dp-sub-th" colspan="8">\${BL('dp_6_1_2_title')}</th></tr>
    <tr>
      <td class="dp-lbl" colspan="2">A.&nbsp;\${BL('dp_lbl_engine')} :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_1_2_0" rows="2" placeholder="\${BL('dp_ph_engine_content')}">\${E(v('dp_6_1_2_0'))}</textarea></div></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">B.&nbsp;\${BL('dp_lbl_ignition')} :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_1_2_1" rows="2" placeholder="\${BL('dp_ph_ignition_content')}">\${E(v('dp_6_1_2_1'))}</textarea></div></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">C.&nbsp;\${BL('dp_lbl_chassis')} :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_1_2_2" rows="2" placeholder="\${BL('dp_ph_chassis_content')}">\${E(v('dp_6_1_2_2'))}</textarea></div></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">D.&nbsp;\${BL('dp_lbl_other')} :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_1_2_3" rows="2" placeholder="\${BL('dp_ph_other_content')}">\${E(v('dp_6_1_2_3'))}</textarea></div></td>
    </tr>
    <tr><th class="dp-sub-th" colspan="8">\${BL('dp_6_2_title')}</th></tr>
    <tr>
      <th class="dp-th">\${BL('dp_lbl_category')}</th><th class="dp-th">\${BL('dp_lbl_item')}</th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_2_km_0" type="text" value="\${E(v('dp_6_2_km_0'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_2_km_1" type="text" value="\${E(v('dp_6_2_km_1'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_2_km_2" type="text" value="\${E(v('dp_6_2_km_2'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_2_km_3" type="text" value="\${E(v('dp_6_2_km_3'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th"><input class="dp-inp" data-field="dp_6_2_km_4" type="text" value="\${E(v('dp_6_2_km_4'))}" placeholder="km" style="text-align:center;width:100%;"></th>
      <th class="dp-th">\${BL('dp_th_note')}</th>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_engine')}</td><td><input class="dp-inp" data-field="dp_6_2_0_item" type="text" value="\${E(v('dp_6_2_0_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_0_0" type="text" value="\${E(v('dp_6_2_0_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_0_1" type="text" value="\${E(v('dp_6_2_0_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_0_2" type="text" value="\${E(v('dp_6_2_0_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_0_3" type="text" value="\${E(v('dp_6_2_0_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_0_4" type="text" value="\${E(v('dp_6_2_0_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_0_note" type="text" value="\${E(v('dp_6_2_0_note'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_ignition')}</td><td><input class="dp-inp" data-field="dp_6_2_1_item" type="text" value="\${E(v('dp_6_2_1_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_1_0" type="text" value="\${E(v('dp_6_2_1_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_1_1" type="text" value="\${E(v('dp_6_2_1_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_1_2" type="text" value="\${E(v('dp_6_2_1_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_1_3" type="text" value="\${E(v('dp_6_2_1_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_1_4" type="text" value="\${E(v('dp_6_2_1_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_1_note" type="text" value="\${E(v('dp_6_2_1_note'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_chassis')}</td><td><input class="dp-inp" data-field="dp_6_2_2_item" type="text" value="\${E(v('dp_6_2_2_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_2_0" type="text" value="\${E(v('dp_6_2_2_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_2_1" type="text" value="\${E(v('dp_6_2_2_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_2_2" type="text" value="\${E(v('dp_6_2_2_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_2_3" type="text" value="\${E(v('dp_6_2_2_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_2_4" type="text" value="\${E(v('dp_6_2_2_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_2_note" type="text" value="\${E(v('dp_6_2_2_note'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('em_val_etc')}</td><td><input class="dp-inp" data-field="dp_6_2_3_item" type="text" value="\${E(v('dp_6_2_3_item'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_3_0" type="text" value="\${E(v('dp_6_2_3_0'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_3_1" type="text" value="\${E(v('dp_6_2_3_1'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_3_2" type="text" value="\${E(v('dp_6_2_3_2'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_3_3" type="text" value="\${E(v('dp_6_2_3_3'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_3_4" type="text" value="\${E(v('dp_6_2_3_4'))}"></td>
      <td><input class="dp-inp" data-field="dp_6_2_3_note" type="text" value="\${E(v('dp_6_2_3_note'))}"></td>
    </tr>
    <tr><th class="dp-sub-th" colspan="8">\${BL('dp_6_3_title')}</th></tr>
    <tr>
      <td class="dp-lbl" colspan="2">6.3.1.&#8202;\${BL('dp_6_3_1_lbl')} :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_3_0" rows="2" placeholder="\${BL('dp_ph_warranty_content')}">\${E(v('dp_6_3_0'))}</textarea></div></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">6.3.2.&#8202;\${BL('dp_6_3_2_lbl')} :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_3_1" rows="2" placeholder="\${BL('dp_ph_warranty_period')}">\${E(v('dp_6_3_1'))}</textarea></div></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">6.3.3.&#8202;\${BL('dp_6_3_3_lbl')} :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_3_2" rows="2" placeholder="\${BL('dp_ph_warranty_exclusion')}">\${E(v('dp_6_3_2'))}</textarea></div></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">6.3.4.&#8202;\${BL('dp_6_3_4_lbl')} :</td>
      <td colspan="6"><div class="dp-field"><textarea class="dp-field-text" data-field="dp_6_3_3" rows="2" placeholder="\${BL('dp_ph_owner_duty')}">\${E(v('dp_6_3_3'))}</textarea></div></td>
    </tr>
  </tbody>
</table>

<!-- ══ 7. 배출가스 표지판 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:28%;"><col style="width:72%;"></colgroup>
  <tbody>
    <tr><th class="dp-sec-th" colspan="2">\${BL('dp_s7')}</th></tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_7_1_lbl')}</td>
      <td>
        <div class="dp-field">
          <textarea class="dp-field-text" data-field="dp_7_1" rows="3" placeholder="\${BL('dp_ph_sign_desc')}">\${E(v('dp_7_1'))}</textarea>
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
      <td class="dp-lbl">\${BL('dp_7_2_lbl')}</td>
      <td>
        <div class="dp-field">
          <textarea class="dp-field-text" data-field="dp_7_2" rows="3" placeholder="\${BL('dp_ph_attach_pos')}">\${E(v('dp_7_2'))}</textarea>
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
    <tr><th class="dp-sec-th" colspan="5">\${BL('dp_s8')}</th></tr>
    \${[
      [BL('dp_s8_1'),'dp_8_1',[BL('dp_8_1_0'),BL('dp_8_1_1'),BL('dp_8_1_2')]],
      [BL('dp_s8_2'),'dp_8_2',[BL('dp_8_2_0'),BL('dp_8_2_1')]],
      [BL('dp_s8_3'),'dp_8_3',[BL('dp_8_3_0')]],
      [BL('dp_s8_4'),'dp_8_4',[BL('dp_8_4_0')]],
      [BL('dp_s8_5'),'dp_8_5',[BL('dp_8_5_0')]],
      [BL('dp_s8_6'),'dp_8_6',[BL('dp_8_6_0'),BL('dp_8_6_1'),BL('dp_8_6_2'),BL('dp_8_6_3')]],
      [BL('dp_s8_7'),'dp_8_7',[BL('dp_8_7_0')]],
      [BL('dp_s8_8'),'dp_8_8',[BL('dp_8_8_0'),BL('dp_8_8_1')]],
      [BL('dp_s8_9'),'dp_8_9',[BL('dp_8_9_0')]],
    ].map(([sec,pfx,rows])=>\`
    <tr><th class="dp-sub-th" colspan="5">\${sec}</th></tr>
    <tr>
      <th class="dp-th">\${BL('dp_th_item')}</th><th class="dp-th">\${BL('dp_th_sub_item')}</th>
      <th class="dp-th">\${BL('dp_th_structure')}</th>
      <th class="dp-th">\${BL('dp_th_ctrl_tech')}</th>
      <th class="dp-th">\${BL('dp_th_emission_eff')}</th>
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
          <span style="font-size:7.5pt;color:#666;white-space:nowrap;padding-top:6px;">\${BL('dp_lbl_diagram_attach').replace('{sec}',sec.replace(/^[\d.]+\s*/,''))}</span>
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
    <tr><th class="dp-sub-th" colspan="5">\${BL('dp_8_10_title')}</th></tr>
    <tr>
      <th class="dp-th">\${BL('dp_th_sensor_var')}</th>
      <th class="dp-th">\${BL('dp_th_fuel_afr')}</th>
      <th class="dp-th">\${BL('dp_th_ign_timing')}</th>
      <th class="dp-th">\${BL('dp_th_canister_purge')}</th>
      <th class="dp-th">\${BL('dp_th_note')}</th>
    </tr>
    \${[BL('dp_sv_o2'),BL('dp_sv_air_flow'),BL('dp_sv_air_temp'),BL('dp_sv_coolant'),BL('dp_sv_throttle'),BL('dp_sv_baro'),BL('dp_sv_intake_vac'),BL('dp_sv_crank'),BL('dp_sv_cam'),BL('dp_sv_batt'),BL('dp_sv_speed'),BL('dp_sv_rpm'),BL('dp_sv_gear'),BL('dp_sv_idle'),BL('dp_sv_brake'),BL('dp_sv_ac'),BL('dp_sv_knock')].map((row,ri)=>\`<tr>
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
    <tr><th class="dp-sub-th" colspan="6">\${BL('dp_8_11_title')}</th></tr>
    <tr>
      <th class="dp-th" rowspan="2">\${BL('dp_th_item')}</th>
      <th class="dp-th" rowspan="2">\${BL('dp_th_sub_item')}</th>
      <th class="dp-th" rowspan="2">\${BL('dp_th_part_no')}</th>
      <th class="dp-th" colspan="2">\${BL('em_lbl_maker2')}</th>
      <th class="dp-th" rowspan="2">\${BL('dp_lbl_remark')}</th>
    </tr>
    <tr>
      <th class="dp-th">\${BL('dp_th_mfr')}</th>
      <th class="dp-th">\${BL('dp_th_mfr_country')}</th>
    </tr>
    \${[BL('dp_8_11_ign'),BL('dp_8_11_fuel'),BL('dp_8_11_cat'),BL('dp_8_11_egr'),BL('dp_8_11_evap'),BL('dp_8_11_blow'),BL('dp_8_11_air')].map((item,ii)=>\`<tr>
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
    <tr><th class="dp-sub-th" colspan="5">\${BL('dp_8_12_title')}</th></tr>
    <tr>
      <th class="dp-th">\${BL('dp_th_item')}</th><th class="dp-th">\${BL('dp_th_sub_item')}</th>
      <th class="dp-th">\${BL('dp_th_structure')}</th>
      <th class="dp-th">\${BL('dp_th_ctrl_tech')}</th>
      <th class="dp-th">\${BL('dp_th_emission_eff')}</th>
    </tr>
    \${[BL('dp_8_12_r0'),BL('dp_8_12_r1'),BL('dp_8_12_r2'),BL('dp_8_12_r3')].map((row,ri)=>\`<tr>
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
    <tr><th class="dp-sub-th" colspan="6">\${BL('dp_8_13_title')}</th></tr>
    <tr>
      <th class="dp-th">\${BL('dp_th_item')}</th><th class="dp-th">\${BL('dp_th_analysis_result')}</th>
      <th class="dp-th">\${BL('dp_th_analysis_org')}</th><th class="dp-th">\${BL('dp_th_analysis_method')}</th>
      <th class="dp-th">\${BL('dp_th_analysis_date')}</th><th class="dp-th">\${BL('dp_th_proof_no')}</th>
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
    <tr><th class="dp-sub-th" colspan="2">\${BL('dp_8_14_title')}</th></tr>
    <tr><td class="dp-lbl">8.14.1. \${BL('dp_8_14_1_lbl')}</td><td>
      <div class="dp-field"><textarea class="dp-field-text" data-field="dp_8_14_1" rows="2" placeholder="\${BL('dp_ph_motor_ctrl')}">\${E(v('dp_8_14_1'))}</textarea></div>
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
    <tr><td class="dp-lbl">8.14.2. \${BL('dp_8_14_2_lbl')}</td><td>
      <div class="dp-field"><textarea class="dp-field-text" data-field="dp_8_14_2" rows="2" placeholder="\${BL('dp_ph_batt_ctrl')}">\${E(v('dp_8_14_2'))}</textarea></div>
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
    <tr><th class="dp-sec-th" colspan="3">\${BL('dp_s9')}</th></tr>
    <tr><th class="dp-sub-th" colspan="3">\${BL('dp_9_1_title')}</th></tr>
    <tr>
      <th class="dp-th">\${BL('dp_th_storage')}</th>
      <th class="dp-th">\${BL('dp_th_absorb_cap')}</th>
      <th class="dp-th">\${BL('dp_th_size_media')}</th>
    </tr>
    \${[BL('dp_9_1_r0'),BL('dp_9_1_r1'),BL('dp_9_1_r2'),BL('dp_9_1_r3')].map((dev,di)=>\`<tr>
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
    <tr><th class="dp-sub-th" colspan="5">\${BL('dp_9_2_parts_title')}</th></tr>
    <tr>
      <th class="dp-th">\${BL('dp_th_evap_code')}</th>
      <th class="dp-th">\${BL('dp_th_nominal_tank')}</th>
      <th class="dp-th">\${BL('dp_th_max_evap')}</th>
      <th class="dp-th">\${BL('dp_th_reservoir')}</th>
      <th class="dp-th">\${BL('dp_th_model_name')}</th>
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
        <strong>\${BL('dp_9_2_title')}</strong>
      </td>
    </tr>
    <tr>
      <td>
        <div class="dp-field">
          <textarea class="dp-field-text" data-field="dp_9_2" rows="3" placeholder="\${BL('dp_ph_ctrl_diagram')}">\${E(v('dp_9_2'))}</textarea>
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
    <tr><th class="dp-sec-th" colspan="5">\${BL('dp_s10')}</th></tr>
    <tr><th class="dp-sub-th" colspan="5">\${BL('dp_10_1_title')}</th></tr>
    <tr>
      <th class="dp-th" colspan="3">\${BL('dp_th_category')}</th>
      <th class="dp-th">\${BL('dp_th_basic_model')}</th>
      <th class="dp-th">\${BL('dp_th_emission_equiv')}</th>
    </tr>
    <!-- 단순 1행 항목들 -->
    \${[
      [BL('dp_lbl_car_name'),'dp_10_1_carname'],[BL('dp_lbl_car_type'),'dp_10_1_type'],[BL('dp_lbl_body_shape'),'dp_10_1_body'],
      [BL('dp_lbl_passenger'),'dp_10_1_passenger'],[BL('dp_lbl_fuel_type'),'dp_10_1_fuel'],[BL('dp_lbl_displacement'),'dp_10_1_disp'],
      [BL('dp_lbl_combustion'),'dp_10_1_comb'],[BL('dp_lbl_cyl_count'),'dp_10_1_cyl'],[BL('dp_lbl_max_power'),'dp_10_1_maxpow'],
      [BL('dp_lbl_max_torque'),'dp_10_1_maxtq'],[BL('dp_lbl_bore_stroke'),'dp_10_1_bore'],[BL('dp_lbl_compress_ratio'),'dp_10_1_compress'],
      [BL('dp_10_1_cyl_dist_lbl'),'dp_10_1_cyl_dist'],[BL('dp_10_1_block_lbl'),'dp_10_1_block'],
      [BL('dp_lbl_cyl_arr'),'dp_10_1_cylarr'],[BL('dp_10_1_head_lbl'),'dp_10_1_head'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl" colspan="3">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_base" type="text" value="\${E(v(\`\${fld}_base\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_same" type="text" value="\${E(v(\`\${fld}_same\`))}"></td>
    </tr>\`).join('')}
    <!-- 흡기 매니폴드 rowspan=2 -->
    <tr>
      <td class="dp-lbl" colspan="2" rowspan="2">\${BL('dp_lbl_intake_manifold')}</td>
      <td class="dp-lbl">\${BL('dp_lbl_intake_port_size')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_inport_base" type="text" value="\${E(v('dp_10_1_inport_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_inport_same" type="text" value="\${E(v('dp_10_1_inport_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_intake_port_shape')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_inshape_base" type="text" value="\${E(v('dp_10_1_inshape_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_inshape_same" type="text" value="\${E(v('dp_10_1_inshape_same'))}"></td>
    </tr>
    <!-- 배기 매니폴드 rowspan=2 -->
    <tr>
      <td class="dp-lbl" colspan="2" rowspan="2">\${BL('dp_lbl_exhaust_manifold')}</td>
      <td class="dp-lbl">\${BL('dp_lbl_exhaust_port_size')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_export_base" type="text" value="\${E(v('dp_10_1_export_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_export_same" type="text" value="\${E(v('dp_10_1_export_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_exhaust_port_shape')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_exshape_base" type="text" value="\${E(v('dp_10_1_exshape_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_exshape_same" type="text" value="\${E(v('dp_10_1_exshape_same'))}"></td>
    </tr>
    <!-- 흡배기폐기시 rowspan=4 -->
    <tr>
      <td class="dp-lbl" rowspan="4">\${BL('dp_lbl_valve_timing')}</td>
      <td class="dp-lbl" rowspan="2">\${BL('dp_lbl_intake_valve')}</td>
      <td class="dp-lbl">\${BL('dp_lbl_open')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_in_open_base" type="text" value="\${E(v('dp_10_1_in_open_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_in_open_same" type="text" value="\${E(v('dp_10_1_in_open_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_close')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_in_close_base" type="text" value="\${E(v('dp_10_1_in_close_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_in_close_same" type="text" value="\${E(v('dp_10_1_in_close_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl" rowspan="2">\${BL('dp_lbl_exhaust_valve')}</td>
      <td class="dp-lbl">\${BL('dp_lbl_open')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_ex_open_base" type="text" value="\${E(v('dp_10_1_ex_open_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_ex_open_same" type="text" value="\${E(v('dp_10_1_ex_open_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_close')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_ex_close_base" type="text" value="\${E(v('dp_10_1_ex_close_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_ex_close_same" type="text" value="\${E(v('dp_10_1_ex_close_same'))}"></td>
    </tr>
    <!-- 기통별 밸브수 rowspan=2 -->
    <tr>
      <td class="dp-lbl" colspan="2" rowspan="2">\${BL('dp_lbl_valve_count')}</td>
      <td class="dp-lbl">\${BL('dp_lbl_valve_intake')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_valve_in_base" type="text" value="\${E(v('dp_10_1_valve_in_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_valve_in_same" type="text" value="\${E(v('dp_10_1_valve_in_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_valve_exhaust')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_valve_ex_base" type="text" value="\${E(v('dp_10_1_valve_ex_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_valve_ex_same" type="text" value="\${E(v('dp_10_1_valve_ex_same'))}"></td>
    </tr>
    <!-- 밸브크기 rowspan=2 -->
    <tr>
      <td class="dp-lbl" colspan="2" rowspan="2">\${BL('dp_lbl_valve_size')}</td>
      <td class="dp-lbl">\${BL('dp_lbl_valve_intake')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_vsize_in_base" type="text" value="\${E(v('dp_10_1_vsize_in_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_vsize_in_same" type="text" value="\${E(v('dp_10_1_vsize_in_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_valve_exhaust')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_vsize_ex_base" type="text" value="\${E(v('dp_10_1_vsize_ex_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_vsize_ex_same" type="text" value="\${E(v('dp_10_1_vsize_ex_same'))}"></td>
    </tr>
    <!-- 공기 흡입 방식 -->
    <tr>
      <td class="dp-lbl" colspan="3">\${BL('dp_lbl_air_intake')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_airtype_base" type="text" value="\${E(v('dp_10_1_airtype_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_airtype_same" type="text" value="\${E(v('dp_10_1_airtype_same'))}"></td>
    </tr>
    <!-- 촉매 rowspan=5 (Page2 이어짐) -->
    <tr>
      <td class="dp-lbl" colspan="2" rowspan="5">\${BL('g_lbl_catalyst2')}</td>
      <td class="dp-lbl">\${BL('dp_lbl_cat_type_lbl')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_type_base" type="text" value="\${E(v('dp_10_1_cat_type_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_type_same" type="text" value="\${E(v('dp_10_1_cat_type_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_noble_metal')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_pm_base" type="text" value="\${E(v('dp_10_1_cat_pm_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_pm_same" type="text" value="\${E(v('dp_10_1_cat_pm_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_noble_amount')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_pmg_base" type="text" value="\${E(v('dp_10_1_cat_pmg_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_pmg_same" type="text" value="\${E(v('dp_10_1_cat_pmg_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_volume')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_vol_base" type="text" value="\${E(v('dp_10_1_cat_vol_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_vol_same" type="text" value="\${E(v('dp_10_1_cat_vol_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_noble_ratio')}</td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_ratio_base" type="text" value="\${E(v('dp_10_1_cat_ratio_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_1_cat_ratio_same" type="text" value="\${E(v('dp_10_1_cat_ratio_same'))}"></td>
    </tr>
    <!-- 단순 1행 항목들 (Page2 나머지) -->
    \${[
      [BL('dp_10_1_crank_cam_lbl'),'dp_10_1_crank_cam'],
      [BL('dp_10_1_crank_head_lbl'),'dp_10_1_crank_head'],
      [BL('dp_10_1_tdc_lbl'),'dp_10_1_tdc'],
      [BL('dp_10_1_fuel_supply_lbl'),'dp_10_1_fuel_supply'],
      [BL('dp_10_1_inj_range_lbl'),'dp_10_1_inj_range'],
      [BL('dp_10_1_cam_timing_lbl'),'dp_10_1_cam_timing'],
      [BL('dp_10_1_inertia_lbl'),'dp_10_1_inertia'],
      [BL('dp_10_1_roadload_lbl'),'dp_10_1_roadload'],
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
    <tr><th class="dp-sub-th" colspan="4">\${BL('dp_10_2_title')}</th></tr>
    <tr>
      <th class="dp-th" colspan="2">\${BL('dp_th_category')}</th>
      <th class="dp-th">\${BL('dp_th_basic_model')}</th>
      <th class="dp-th">\${BL('dp_th_evap_equiv')}</th>
    </tr>
    <!-- 단순 1행 항목들 -->
    \${[
      [BL('dp_10_2_certno_lbl'),'dp_10_2_certno'],[BL('dp_10_2_carname_lbl'),'dp_10_2_carname'],
      [BL('dp_10_2_type_lbl'),'dp_10_2_type'],[BL('dp_10_2_eng_lbl'),'dp_10_2_eng'],
      [BL('dp_10_2_cartype_lbl'),'dp_10_2_cartype'],[BL('dp_10_2_fuel_lbl'),'dp_10_2_fuel'],
      [BL('dp_10_2_evap_type_lbl'),'dp_10_2_evap_type'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl" colspan="2">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_base" type="text" value="\${E(v(\`\${fld}_base\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_same" type="text" value="\${E(v(\`\${fld}_same\`))}"></td>
    </tr>\`).join('')}
    <!-- 캐니스터 설계 특성 rowspan=5 -->
    <tr>
      <td class="dp-lbl" rowspan="5">\${BL('dp_lbl_canister_design')}</td>
      <td class="dp-lbl">\${BL('dp_lbl_evap_absorp')}</td>
      <td><input class="dp-inp" data-field="dp_10_2_evap_cap_base" type="text" value="\${E(v('dp_10_2_evap_cap_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_2_evap_cap_same" type="text" value="\${E(v('dp_10_2_evap_cap_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_canister_cnt')}</td>
      <td><input class="dp-inp" data-field="dp_10_2_can_cnt_base" type="text" value="\${E(v('dp_10_2_can_cnt_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_2_can_cnt_same" type="text" value="\${E(v('dp_10_2_can_cnt_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_canister_shape')}</td>
      <td><input class="dp-inp" data-field="dp_10_2_can_shape_base" type="text" value="\${E(v('dp_10_2_can_shape_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_2_can_shape_same" type="text" value="\${E(v('dp_10_2_can_shape_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_canister_structure')}</td>
      <td><input class="dp-inp" data-field="dp_10_2_can_struct_base" type="text" value="\${E(v('dp_10_2_can_struct_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_2_can_struct_same" type="text" value="\${E(v('dp_10_2_can_struct_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_canister_material')}</td>
      <td><input class="dp-inp" data-field="dp_10_2_can_mat_base" type="text" value="\${E(v('dp_10_2_can_mat_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_2_can_mat_same" type="text" value="\${E(v('dp_10_2_can_mat_same'))}"></td>
    </tr>
    <!-- 연료시스템 / 주유관 밀폐구조 (별도 행) -->
    <tr>
      <td class="dp-lbl" colspan="2">\${BL('dp_lbl_fuel_system')}</td>
      <td><input class="dp-inp" data-field="dp_10_2_fuel_sys_base" type="text" value="\${E(v('dp_10_2_fuel_sys_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_2_fuel_sys_same" type="text" value="\${E(v('dp_10_2_fuel_sys_same'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl" colspan="2">\${BL('dp_lbl_filler_seal')}</td>
      <td><input class="dp-inp" data-field="dp_10_2_fuel_seal_base" type="text" value="\${E(v('dp_10_2_fuel_seal_base'))}"></td>
      <td><input class="dp-inp" data-field="dp_10_2_fuel_seal_same" type="text" value="\${E(v('dp_10_2_fuel_seal_same'))}"></td>
    </tr>
    <!-- 나머지 항목 -->
    \${[
      [BL('dp_10_2_ctrl_lbl'),'dp_10_2_ctrl'],[BL('dp_10_2_purge_lbl'),'dp_10_2_purge'],
      [BL('dp_10_2_hose_mat_lbl'),'dp_10_2_hose_mat'],[BL('dp_10_2_tank_mat_lbl'),'dp_10_2_tank_mat'],
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
    <tr><th class="dp-sub-th" colspan="3">\${BL('dp_10_3_title')}</th></tr>
    <tr>
      <th class="dp-th">\${BL('dp_th_category')}</th>
      <th class="dp-th">\${BL('dp_th_basic_model')}</th>
      <th class="dp-th">\${BL('dp_th_obd_equiv')}</th>
    </tr>
    \${[
      [BL('dp_10_3_certno_lbl'),'dp_10_3_certno'],[BL('dp_10_3_carname_lbl'),'dp_10_3_carname'],
      [BL('dp_10_3_type_lbl'),'dp_10_3_type'],[BL('dp_10_3_eng_lbl'),'dp_10_3_eng'],
      [BL('dp_10_3_cartype_lbl'),'dp_10_3_cartype'],[BL('dp_10_3_fuel_lbl'),'dp_10_3_fuel'],
      [BL('dp_10_3_obd_op_lbl'),'dp_10_3_obd_op'],[BL('dp_10_3_std_lbl'),'dp_10_3_std'],
      [BL('dp_10_3_cycle_lbl'),'dp_10_3_cycle'],[BL('dp_10_3_fuel_supply_lbl'),'dp_10_3_fuel_supply'],
      [BL('dp_10_3_cat_lbl'),'dp_10_3_cat'],[BL('dp_10_3_dpf_lbl'),'dp_10_3_dpf'],
      [BL('dp_10_3_air2_lbl'),'dp_10_3_air2'],[BL('dp_10_3_egr_lbl'),'dp_10_3_egr'],
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
    <tr><th class="dp-sec-th" colspan="4">\${BL('dp_s11')}</th></tr>
    <tr><th class="dp-sub-th" colspan="4">\${BL('dp_11_1_title')}</th></tr>
    <tr>
      <th class="dp-th" colspan="2">\${BL('dp_th_category')}</th>
      <th class="dp-th">\${BL('dp_th_dur_test')}</th>
      <th class="dp-th">\${BL('dp_th_emission_test_v')}</th>
    </tr>
    <!-- 단순 1행 항목들 -->
    \${[
      [BL('dp_11_1_vin_lbl'),'dp_11_1_vin'],[BL('dp_11_1_disp_lbl'),'dp_11_1_disp'],
      [BL('dp_11_1_eng_code_lbl'),'dp_11_1_eng_code'],[BL('dp_11_1_evap_code_lbl'),'dp_11_1_evap_code'],
      [BL('dp_11_1_cat_code_lbl'),'dp_11_1_cat_code'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl" colspan="2">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_dur" type="text" value="\${E(v(\`\${fld}_dur\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_em" type="text" value="\${E(v(\`\${fld}_em\`))}"></td>
    </tr>\`).join('')}
    <!-- 배출가스 제어장치 rowspan=2 -->
    <tr>
      <td class="dp-lbl" rowspan="2">\${BL('dp_lbl_emission_ctrl')}</td>
      <td class="dp-lbl">\${BL('dp_lbl_emission_gas')}</td>
      <td><input class="dp-inp" data-field="dp_11_1_ctrl_em_dur" type="text" value="\${E(v('dp_11_1_ctrl_em_dur'))}"></td>
      <td><input class="dp-inp" data-field="dp_11_1_ctrl_em_em" type="text" value="\${E(v('dp_11_1_ctrl_em_em'))}"></td>
    </tr>
    <tr>
      <td class="dp-lbl">\${BL('g_lbl_evap')}</td>
      <td><input class="dp-inp" data-field="dp_11_1_ctrl_evap_dur" type="text" value="\${E(v('dp_11_1_ctrl_evap_dur'))}"></td>
      <td><input class="dp-inp" data-field="dp_11_1_ctrl_evap_em" type="text" value="\${E(v('dp_11_1_ctrl_evap_em'))}"></td>
    </tr>
    <!-- 나머지 단순 항목들 -->
    \${[
      [BL('dp_11_1_model_lbl'),'dp_11_1_model'],[BL('dp_11_1_trans_lbl'),'dp_11_1_trans'],
      [BL('dp_11_1_trans_proc_lbl'),'dp_11_1_trans_proc'],[BL('dp_11_1_inertia_lbl'),'dp_11_1_inertia'],
      [BL('dp_11_1_final_red_lbl'),'dp_11_1_final_red'],[BL('dp_11_1_nv_lbl'),'dp_11_1_nv'],
      [BL('dp_11_1_tire_lbl'),'dp_11_1_tire'],
      [BL('dp_11_1_note_lbl'),'dp_11_1_note'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl" colspan="2">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_dur" type="text" value="\${E(v(\`\${fld}_dur\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_em" type="text" value="\${E(v(\`\${fld}_em\`))}"></td>
    </tr>\`).join('')}
    <!-- 비고 아래 차량제원 비교표 -->
    <tr>
      <th class="dp-th" colspan="2">\${BL('dp_th_category')}</th>
      <td><input class="dp-inp" data-field="dp_11_1_sub_hdr1" type="text" placeholder="\${BL('dp_11_1_sub_hdr_ph')}" value="\${E(v('dp_11_1_sub_hdr1'))}"></td>
      <td><input class="dp-inp" data-field="dp_11_1_sub_hdr2" type="text" placeholder="\${BL('dp_11_1_sub_hdr_ph')}" value="\${E(v('dp_11_1_sub_hdr2'))}"></td>
    </tr>
    \${[
      [BL('dp_11_1_sub_name_lbl'),'dp_11_1_sub_name'],
      [BL('dp_11_1_sub_type_lbl'),'dp_11_1_sub_type'],
      [BL('dp_11_1_sub_trans_lbl'),'dp_11_1_sub_trans'],
      [BL('dp_11_1_sub_eng_lbl'),'dp_11_1_sub_eng'],
      [BL('dp_11_1_sub_disp_lbl'),'dp_11_1_sub_disp'],
      [BL('dp_11_1_sub_weight_lbl'),'dp_11_1_sub_weight'],
      [BL('dp_11_1_sub_inertia_lbl'),'dp_11_1_sub_inertia'],
      [BL('dp_11_1_sub_roadload_lbl'),'dp_11_1_sub_roadload'],
      [BL('dp_11_1_sub_tankvol_lbl'),'dp_11_1_sub_tankvol'],
      [BL('dp_11_1_sub_finalred_lbl'),'dp_11_1_sub_finalred'],
      [BL('dp_11_1_sub_sales_lbl'),'dp_11_1_sub_sales'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl" colspan="2">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_1" type="text" value="\${E(v(\`\${fld}_1\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_2" type="text" value="\${E(v(\`\${fld}_2\`))}"></td>
    </tr>\`).join('')}
  </tbody>
</table>

<!-- ── 11.2 내구성 시험차량 선정 ── -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:28%;"><col style="width:72%;"></colgroup>
  <tbody>
    <tr><th class="dp-sub-th" colspan="2">\${BL('dp_11_2_title')}</th></tr>
    <tr>
      <td class="dp-lbl">\${BL('dp_lbl_dur_test_select')}</td>
      <td>
        <div class="dp-field">
          <textarea class="dp-field-text" data-field="dp_11_2_note" rows="4" placeholder="\${BL('dp_11_2_note_ph')}">\${E(v('dp_11_2_note'))}</textarea>
          <input type="hidden" id="dp_11_2_imgs" data-field="dp_11_2_imgs" value="\${E(v('dp_11_2_imgs'))}">
          <div class="dp-drop" id="dp_11_2_drop" onclick="document.getElementById('dp_11_2_fi').click();" ondragover="event.preventDefault();this.classList.add('drag-over');" ondragleave="this.classList.remove('drag-over');" ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('dp_11_2_imgs','dp_11_2_drop',event.dataTransfer.files);">
            <input type="file" id="dp_11_2_fi" accept="image/*" multiple onchange="dpAddFiles('dp_11_2_imgs','dp_11_2_drop',this.files);this.value='';">
            <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
            <div class="dp-img-list" id="dp_11_2_imgs_list"></div>
          </div>
        </div>
      </td>
    </tr>
  </tbody>
</table>

<!-- ── 11.3 배출가스 시험차량 선정 ── -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup>
    <col style="width:40%;"><col style="width:30%;"><col style="width:30%;">
  </colgroup>
  <tbody>
    <tr><th class="dp-sub-th" colspan="3">\${BL('dp_11_3_title')}</th></tr>
    <!-- A. 차대 동력계 -->
    <tr>
      <td class="dp-lbl" colspan="3" style="font-weight:600; background:#f5f5f5;">
        \${BL('dp_11_3_a_case')}
      </td>
    </tr>
    <tr>
      <th class="dp-th">\${BL('g_th_item')}</th>
      <td><input class="dp-inp" data-field="dp_11_3_a_hdr1" type="text" placeholder="\${BL('dp_11_1_sub_hdr_ph')}" value="\${E(v('dp_11_3_a_hdr1'))}"></td>
      <td><input class="dp-inp" data-field="dp_11_3_a_hdr2" type="text" placeholder="\${BL('dp_11_1_sub_hdr_ph')}" value="\${E(v('dp_11_3_a_hdr2'))}"></td>
    </tr>
    \${[
      [BL('dp_11_1_sub_hdr_ph'),'dp_11_3_a_type'],
      [BL('dp_11_3_a_0_lbl'),'dp_11_3_a_0'],
      [BL('dp_11_3_a_1_lbl'),'dp_11_3_a_1'],
      [BL('dp_11_3_a_2_lbl'),'dp_11_3_a_2'],
      [BL('dp_11_3_a_3_lbl'),'dp_11_3_a_3'],
      [BL('dp_11_3_a_4_lbl'),'dp_11_3_a_4'],
    ].map(([lbl,fld])=>\`<tr>
      <td class="dp-lbl">\${lbl}</td>
      <td><input class="dp-inp" data-field="\${fld}_1" type="text" value="\${E(v(\`\${fld}_1\`))}"></td>
      <td><input class="dp-inp" data-field="\${fld}_2" type="text" value="\${E(v(\`\${fld}_2\`))}"></td>
    </tr>\`).join('')}
    <!-- B. 원동기 동력계 -->
    <tr>
      <td class="dp-lbl" colspan="3" style="font-weight:600; background:#f5f5f5;">
        \${BL('dp_11_3_b_case')}
      </td>
    </tr>
    <tr>
      <th class="dp-th">\${BL('g_th_item')}</th>
      <td><input class="dp-inp" data-field="dp_11_3_b_hdr1" type="text" placeholder="\${BL('dp_11_1_sub_hdr_ph')}" value="\${E(v('dp_11_3_b_hdr1'))}"></td>
      <td><input class="dp-inp" data-field="dp_11_3_b_hdr2" type="text" placeholder="\${BL('dp_11_1_sub_hdr_ph')}" value="\${E(v('dp_11_3_b_hdr2'))}"></td>
    </tr>
    \${[
      [BL('dp_11_3_b_0_lbl'),'dp_11_3_b_0'],
      [BL('dp_11_3_b_1_lbl'),'dp_11_3_b_1'],
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
    <tr><th class="dp-sub-th" colspan="3">\${BL('dp_11_4_title')}</th></tr>
    <tr>
      <th class="dp-th">\${BL('g_th_item')}</th>
      <td><input class="dp-inp" data-field="dp_11_4_hdr1" type="text" placeholder="\${BL('dp_11_1_sub_hdr_ph')}" value="\${E(v('dp_11_4_hdr1'))}"></td>
      <td><input class="dp-inp" data-field="dp_11_4_hdr2" type="text" placeholder="\${BL('dp_11_1_sub_hdr_ph')}" value="\${E(v('dp_11_4_hdr2'))}"></td>
    </tr>
    \${[
      [BL('dp_11_4_0_lbl'),'dp_11_4_0'],
      [BL('dp_11_4_1_lbl'),'dp_11_4_1'],
      [BL('dp_11_4_2_lbl'),'dp_11_4_2'],
      [BL('dp_11_4_3_lbl'),'dp_11_4_3'],
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
    <tr><th class="dp-sec-th">\${BL('dp_s12')}</th></tr>
    <tr><td style="font-size:7.5pt;color:#555;padding:4px 6px;">
      \${BL('dp_durability_note')}
    </td></tr>
    <tr><td>
      <div class="dp-field"><textarea class="dp-field-text" data-field="dp_12" rows="4" placeholder="\${BL('dp_12_ph')}">\${E(v('dp_12'))}</textarea></div>
    </td></tr>
  </tbody>
</table>

<!-- ══ 13. 기타 ══ -->
<table class="dp-tbl" style="table-layout:fixed; width:100%; margin-bottom:0;">
  <colgroup><col style="width:100%;"></colgroup>
  <tbody>
    <tr><th class="dp-sec-th">\${BL('dp_s13')}</th></tr>
    <tr><td>
      <div class="dp-field">
        <textarea class="dp-field-text" data-field="dp_13" rows="3" placeholder="\${BL('dp_13_ph')}">\${E(v('dp_13'))}</textarea>
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

  <div class="en-doc-tag">\${BL('en_doc_tag')}</div>
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
            <textarea class="en-field-text" data-field="en_muffler_comp" rows="3" placeholder="\${BL('en_ph_muffler_comp')}">\${E(v('en_muffler_comp'))}</textarea>
            <input type="hidden" data-field="en_muffler_comp_imgs" value="\${E(v('en_muffler_comp_imgs'))}"><div class="en-drop" data-field-img="en_muffler_comp"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.2 머플러 내부 구조도 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_muffler_diagram_title')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_muffler_diagram" rows="2" placeholder="\${BL('en_ph_inner_diag')}">\${E(v('en_muffler_diagram'))}</textarea>
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
            <textarea class="en-field-text" data-field="en_muffler_principle" rows="3" placeholder="\${BL('en_ph_noise_principle')}">\${E(v('en_muffler_principle'))}</textarea>
            <input type="hidden" data-field="en_muffler_principle_imgs" value="\${E(v('en_muffler_principle_imgs'))}"><div class="en-drop" data-field-img="en_muffler_principle"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.3.2 소음기내의 배출가스 흐름도 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_3_2')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_muffler_flow" rows="2" placeholder="\${BL('en_ph_flow_desc')}">\${E(v('en_muffler_flow'))}</textarea>
            <input type="hidden" data-field="en_muffler_flow_imgs" value="\${E(v('en_muffler_flow_imgs'))}"><div class="en-drop" data-field-img="en_muffler_flow"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.3.3 소음기 제작사 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_3_3')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_muffler_maker" rows="2" placeholder="\${BL('en_ph_maker_name')}">\${E(v('en_muffler_maker'))}</textarea>
            <input type="hidden" data-field="en_muffler_maker_imgs" value="\${E(v('en_muffler_maker_imgs'))}"><div class="en-drop" data-field-img="en_muffler_maker"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.3.4 소음기 내부/외부 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_3_4')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <div style="display:flex; gap:8px; align-items:flex-start; flex-wrap:wrap;">
              <label style="font-size:8pt; white-space:nowrap; margin-top:4px;">\${BL('en_inside_lbl')}</label>
              <textarea class="en-field-text" data-field="en_muffler_inside" rows="2" placeholder="\${BL('en_ph_inner_mat')}" style="flex:1; min-width:80px;">\${E(v('en_muffler_inside'))}</textarea>
              <label style="font-size:8pt; white-space:nowrap; margin-top:4px;">\${BL('en_outside_lbl')}</label>
              <textarea class="en-field-text" data-field="en_muffler_outside" rows="2" placeholder="\${BL('en_ph_outer_mat')}" style="flex:1; min-width:80px;">\${E(v('en_muffler_outside'))}</textarea>
            </div>
            <input type="hidden" data-field="en_muffler_inout_imgs" value="\${E(v('en_muffler_inout_imgs'))}"><div class="en-drop" data-field-img="en_muffler_inout"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.3.5 소음기 치수 도면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_3_5')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_muffler_dim" rows="2" placeholder="\${BL('en_ph_dim_desc')}">\${E(v('en_muffler_dim'))}</textarea>
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
            <textarea class="en-field-text" data-field="en_cat_maker" rows="2" placeholder="\${BL('en_ph_maker_name')}">\${E(v('en_cat_maker'))}</textarea>
            <input type="hidden" data-field="en_cat_maker_imgs" value="\${E(v('en_cat_maker_imgs'))}"><div class="en-drop" data-field-img="en_cat_maker"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.4.2 촉매 재질 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_4_2')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cat_material" rows="2" placeholder="\${BL('en_cat_material_lbl')}">\${E(v('en_cat_material'))}</textarea>
            <input type="hidden" data-field="en_cat_material_imgs" value="\${E(v('en_cat_material_imgs'))}"><div class="en-drop" data-field-img="en_cat_material"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.4.3 촉매 성능 및 치수 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_4_3')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cat_spec" rows="2" placeholder="\${BL('en_cat_perf_lbl')}">\${E(v('en_cat_spec'))}</textarea>
            <input type="hidden" data-field="en_cat_spec_imgs" value="\${E(v('en_cat_spec_imgs'))}"><div class="en-drop" data-field-img="en_cat_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.4.4 촉매 치수 도면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_4_4')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cat_dim" rows="2" placeholder="\${BL('en_ph_dim_desc')}">\${E(v('en_cat_dim'))}</textarea>
            <input type="hidden" data-field="en_cat_dim_imgs" value="\${E(v('en_cat_dim_imgs'))}"><div class="en-drop" data-field-img="en_cat_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.4.5 촉매 원리 또는 효과 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_4_5')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cat_principle" rows="3" placeholder="\${BL('en_ph_cat_principle')}">\${E(v('en_cat_principle'))}</textarea>
            <input type="hidden" data-field="en_cat_principle_imgs" value="\${E(v('en_cat_principle_imgs'))}"><div class="en-drop" data-field-img="en_cat_principle"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.4.6 촉매 부착위치 도면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_4_6')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cat_pos" rows="2" placeholder="\${BL('en_ph_attach_desc')}">\${E(v('en_cat_pos'))}</textarea>
            <input type="hidden" data-field="en_cat_pos_imgs" value="\${E(v('en_cat_pos_imgs'))}"><div class="en-drop" data-field-img="en_cat_pos"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.5 센서 상세제원 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_1_5_lbl')}</td></tr>

      <!-- 1.5.1 센서 제작사 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_5_1_lbl')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_sensor_maker" rows="2" placeholder="\${BL('en_ph_maker_name')}">\${E(v('en_sensor_maker'))}</textarea>
            <input type="hidden" data-field="en_sensor_maker_imgs" value="\${E(v('en_sensor_maker_imgs'))}"><div class="en-drop" data-field-img="en_sensor_maker"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.5.2 센서 재질 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_5_2_lbl')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_sensor_material" rows="2" placeholder="\${BL('en_ph_sensor_mat')}">\${E(v('en_sensor_material'))}</textarea>
            <input type="hidden" data-field="en_sensor_material_imgs" value="\${E(v('en_sensor_material_imgs'))}"><div class="en-drop" data-field-img="en_sensor_material"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.5.3 센서 치수 도면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_1_5_3_lbl')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_sensor_dim" rows="2" placeholder="\${BL('en_ph_dim_desc')}">\${E(v('en_sensor_dim'))}</textarea>
            <input type="hidden" data-field="en_sensor_dim_imgs" value="\${E(v('en_sensor_dim_imgs'))}"><div class="en-drop" data-field-img="en_sensor_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.6 머플러 도면 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_1_6_lbl')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_muffler_drawing" rows="2" placeholder="\${BL('en_ph_muffler_draw')}">\${E(v('en_muffler_drawing'))}</textarea>
            <input type="hidden" data-field="en_muffler_drawing_imgs" value="\${E(v('en_muffler_drawing_imgs'))}"><div class="en-drop" data-field-img="en_muffler_drawing"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 1.7 머플러 사진 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_1_7_lbl')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_muffler_photo" rows="2" placeholder="\${BL('en_ph_muffler_photo')}">\${E(v('en_muffler_photo'))}</textarea>
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
      <tr><th class="en-sec-th" colspan="2">\${BL('en_sec2_valve')}</th></tr>

      <!-- 2.1 밸브 기구의 관성력 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_2_1_valve')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_valve_inertia" rows="3" placeholder="\${BL('en_ph_valve_inertia')}">\${E(v('en_valve_inertia'))}</textarea>
            <input type="hidden" data-field="en_valve_inertia_imgs" value="\${E(v('en_valve_inertia_imgs'))}"><div class="en-drop" data-field-img="en_valve_inertia"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 2.2 밸브 스프링의 Surging 현상 대응기술 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_2_2_surging')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_valve_surging" rows="3" placeholder="\${BL('en_ph_surging')}">\${E(v('en_valve_surging'))}</textarea>
            <input type="hidden" data-field="en_valve_surging_imgs" value="\${E(v('en_valve_surging_imgs'))}"><div class="en-drop" data-field-img="en_valve_surging"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 2.3 캠프로파일 및 제원 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_2_3_cam')}</td></tr>

      <!-- 2.3.1 밸브 제원 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_2_3_1_valve')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_valve_spec" rows="2" placeholder="\${BL('en_ph_valve_spec')}">\${E(v('en_valve_spec'))}</textarea>
            <input type="hidden" data-field="en_valve_spec_imgs" value="\${E(v('en_valve_spec_imgs'))}"><div class="en-drop" data-field-img="en_valve_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 2.3.2 Cam 제원 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_2_3_2_cam')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cam_spec" rows="2" placeholder="\${BL('en_ph_cam_spec')}">\${E(v('en_cam_spec'))}</textarea>
            <input type="hidden" data-field="en_cam_spec_imgs" value="\${E(v('en_cam_spec_imgs'))}"><div class="en-drop" data-field-img="en_cam_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 2.3.3 Cam 치수 도면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_2_3_3_cam_dim')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cam_dim" rows="2" placeholder="\${BL('en_ph_cam_dim')}">\${E(v('en_cam_dim'))}</textarea>
            <input type="hidden" data-field="en_cam_dim_imgs" value="\${E(v('en_cam_dim_imgs'))}"><div class="en-drop" data-field-img="en_cam_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 2.4 Valve 기구의 재질 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_2_4_valve_mat')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_valve_material" rows="3" placeholder="\${BL('en_ph_valve_mat')}">\${E(v('en_valve_material'))}</textarea>
            <input type="hidden" data-field="en_valve_material_imgs" value="\${E(v('en_valve_material_imgs'))}"><div class="en-drop" data-field-img="en_valve_material"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 2.5 밸브 간극 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_2_5_valve_clearance')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_valve_clearance" rows="2" placeholder="\${BL('en_ph_valve_clearance')}">\${E(v('en_valve_clearance'))}</textarea>
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
      <tr><th class="en-sec-th" colspan="2">\${BL('en_sec3_ignition')}</th></tr>

      <!-- 3.1 점화장치 구성도 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_3_1_ign_diag')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ign_diagram" rows="2" placeholder="\${BL('en_ph_ign_diag')}">\${E(v('en_ign_diagram'))}</textarea>
            <input type="hidden" data-field="en_ign_diagram_imgs" value="\${E(v('en_ign_diagram_imgs'))}"><div class="en-drop" data-field-img="en_ign_diagram"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.2 점화장치 제어특성 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_3_2_ign_ctrl')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ign_control" rows="3" placeholder="\${BL('en_ph_ign_ctrl')}">\${E(v('en_ign_control'))}</textarea>
            <input type="hidden" data-field="en_ign_control_imgs" value="\${E(v('en_ign_control_imgs'))}"><div class="en-drop" data-field-img="en_ign_control"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.3 점화장치 상세제원 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_3_3_ign_spec')}</td></tr>

      <!-- 3.3.1 제너레이터 -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">\${BL('en_3_3_1_gen')}</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_3_3_1_1_gen_spec')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_gen_spec" rows="2" placeholder="\${BL('en_ph_gen_spec')}">\${E(v('en_gen_spec'))}</textarea>
            <input type="hidden" data-field="en_gen_spec_imgs" value="\${E(v('en_gen_spec_imgs'))}"><div class="en-drop" data-field-img="en_gen_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_3_3_1_2_gen_dim')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_gen_dim" rows="2" placeholder="\${BL('en_ph_shape_dim')}">\${E(v('en_gen_dim'))}</textarea>
            <input type="hidden" data-field="en_gen_dim_imgs" value="\${E(v('en_gen_dim_imgs'))}"><div class="en-drop" data-field-img="en_gen_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.3.2 CDI UNIT -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">3.3.2. CDI UNIT</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_3_3_2_1_cdi_spec')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cdi_spec" rows="2" placeholder="\${BL('en_ph_cdi_spec')}">\${E(v('en_cdi_spec'))}</textarea>
            <input type="hidden" data-field="en_cdi_spec_imgs" value="\${E(v('en_cdi_spec_imgs'))}"><div class="en-drop" data-field-img="en_cdi_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_3_3_2_2_cdi_dim')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_cdi_dim" rows="2" placeholder="\${BL('en_ph_shape_dim')}">\${E(v('en_cdi_dim'))}</textarea>
            <input type="hidden" data-field="en_cdi_dim_imgs" value="\${E(v('en_cdi_dim_imgs'))}"><div class="en-drop" data-field-img="en_cdi_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.3.3 점화코일 -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">\${BL('en_3_3_3_coil')}</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_3_3_3_1_coil_spec')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_coil_spec" rows="2" placeholder="\${BL('en_ph_coil_spec')}">\${E(v('en_coil_spec'))}</textarea>
            <input type="hidden" data-field="en_coil_spec_imgs" value="\${E(v('en_coil_spec_imgs'))}"><div class="en-drop" data-field-img="en_coil_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_3_3_3_2_coil_dim')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_coil_dim" rows="2" placeholder="\${BL('en_ph_shape_dim')}">\${E(v('en_coil_dim'))}</textarea>
            <input type="hidden" data-field="en_coil_dim_imgs" value="\${E(v('en_coil_dim_imgs'))}"><div class="en-drop" data-field-img="en_coil_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.3.4 점화플러그 -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">\${BL('en_3_3_4_plug')}</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_3_3_4_1_plug_spec')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_plug_spec" rows="2" placeholder="\${BL('en_ph_plug_spec')}">\${E(v('en_plug_spec'))}</textarea>
            <input type="hidden" data-field="en_plug_spec_imgs" value="\${E(v('en_plug_spec_imgs'))}"><div class="en-drop" data-field-img="en_plug_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_3_3_4_2_plug_dim')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_plug_dim" rows="2" placeholder="\${BL('en_ph_shape_dim')}">\${E(v('en_plug_dim'))}</textarea>
            <input type="hidden" data-field="en_plug_dim_imgs" value="\${E(v('en_plug_dim_imgs'))}"><div class="en-drop" data-field-img="en_plug_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.3.5 ECU -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">\${BL('en_3_3_5_ecu')}</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_3_3_5_1_ecu_spec')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ecu_spec" rows="2" placeholder="\${BL('en_ph_ecu_spec')}">\${E(v('en_ecu_spec'))}</textarea>
            <input type="hidden" data-field="en_ecu_spec_imgs" value="\${E(v('en_ecu_spec_imgs'))}"><div class="en-drop" data-field-img="en_ecu_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_3_3_5_2_ecu_dim')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ecu_dim" rows="2" placeholder="\${BL('en_ph_shape_dim')}">\${E(v('en_ecu_dim'))}</textarea>
            <input type="hidden" data-field="en_ecu_dim_imgs" value="\${E(v('en_ecu_dim_imgs'))}"><div class="en-drop" data-field-img="en_ecu_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 3.4 점화장치 사진 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_3_4_ign_photo')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ign_photo" rows="2" placeholder="\${BL('en_ph_ign_photo')}">\${E(v('en_ign_photo'))}</textarea>
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
      <tr><th class="en-sec-th" colspan="2">\${BL('en_sec4_fuel')}</th></tr>

      <!-- 4.1 연료장치 구성 및 제어방식 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_4_1_fuel_sys')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_fuel_sys" rows="3" placeholder="\${BL('en_ph_fuel_sys')}">\${E(v('en_fuel_sys'))}</textarea>
            <input type="hidden" data-field="en_fuel_sys_imgs" value="\${E(v('en_fuel_sys_imgs'))}"><div class="en-drop" data-field-img="en_fuel_sys"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 4.2 연료장치 도면 및 치수 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_4_2_fuel_drawing')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_fuel_drawing" rows="2" placeholder="\${BL('en_ph_drawing_dim')}">\${E(v('en_fuel_drawing'))}</textarea>
            <input type="hidden" data-field="en_fuel_drawing_imgs" value="\${E(v('en_fuel_drawing_imgs'))}"><div class="en-drop" data-field-img="en_fuel_drawing"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 4.3 연료장치 상세제원 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_4_3_fuel_spec')}</td></tr>

      <!-- 4.3.1 연료탱크 -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">\${BL('en_4_3_1_tank')}</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_4_3_1_1_tank_spec')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_tank_spec" rows="2" placeholder="\${BL('en_ph_tank_spec')}">\${E(v('en_tank_spec'))}</textarea>
            <input type="hidden" data-field="en_tank_spec_imgs" value="\${E(v('en_tank_spec_imgs'))}"><div class="en-drop" data-field-img="en_tank_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_4_3_1_2')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_tank_pos" rows="2" placeholder="\${BL('en_tank_pos_ph')}">\${E(v('en_tank_pos'))}</textarea>
            <input type="hidden" data-field="en_tank_pos_imgs" value="\${E(v('en_tank_pos_imgs'))}"><div class="en-drop" data-field-img="en_tank_pos"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_4_3_1_3')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_tank_shape" rows="2" placeholder="\${BL('en_tank_shape_ph')}">\${E(v('en_tank_shape'))}</textarea>
            <input type="hidden" data-field="en_tank_shape_imgs" value="\${E(v('en_tank_shape_imgs'))}"><div class="en-drop" data-field-img="en_tank_shape"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 4.3.2 스로틀바디 -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">\${BL('en_4_3_2')}</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_4_3_2_1')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_throttle_spec" rows="2" placeholder="\${BL('en_throttle_spec_ph')}">\${E(v('en_throttle_spec'))}</textarea>
            <input type="hidden" data-field="en_throttle_spec_imgs" value="\${E(v('en_throttle_spec_imgs'))}"><div class="en-drop" data-field-img="en_throttle_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_4_3_2_2')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_throttle_dim" rows="2" placeholder="\${BL('en_ph_shape_dim')}">\${E(v('en_throttle_dim'))}</textarea>
            <input type="hidden" data-field="en_throttle_dim_imgs" value="\${E(v('en_throttle_dim_imgs'))}"><div class="en-drop" data-field-img="en_throttle_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 4.3.3 연료인젝터 -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">\${BL('en_4_3_3')}</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_4_3_3_1')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_injector_spec" rows="2" placeholder="\${BL('en_injector_spec_ph')}">\${E(v('en_injector_spec'))}</textarea>
            <input type="hidden" data-field="en_injector_spec_imgs" value="\${E(v('en_injector_spec_imgs'))}"><div class="en-drop" data-field-img="en_injector_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_4_3_3_2')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_injector_dim" rows="2" placeholder="\${BL('en_ph_shape_dim')}">\${E(v('en_injector_dim'))}</textarea>
            <input type="hidden" data-field="en_injector_dim_imgs" value="\${E(v('en_injector_dim_imgs'))}"><div class="en-drop" data-field-img="en_injector_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 4.3.4 연료펌프 -->
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:12px;">\${BL('en_4_3_4')}</td><td></td></tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_4_3_4_1')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_pump_spec" rows="2" placeholder="\${BL('en_pump_spec_ph')}">\${E(v('en_pump_spec'))}</textarea>
            <input type="hidden" data-field="en_pump_spec_imgs" value="\${E(v('en_pump_spec_imgs'))}"><div class="en-drop" data-field-img="en_pump_spec"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>
      <tr><td class="en-lbl" style="padding:3px 6px; padding-left:20px;">\${BL('en_4_3_4_2')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_pump_dim" rows="2" placeholder="\${BL('en_ph_shape_dim')}">\${E(v('en_pump_dim'))}</textarea>
            <input type="hidden" data-field="en_pump_dim_imgs" value="\${E(v('en_pump_dim_imgs'))}"><div class="en-drop" data-field-img="en_pump_dim"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 4.4 연료장치 사진 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_4_4_fuel_photo')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_fuel_photo" rows="2" placeholder="\${BL('en_fuel_photo_ph')}">\${E(v('en_fuel_photo'))}</textarea>
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
      <tr><th class="en-sec-th" colspan="2">\${BL('en_sec5')}</th></tr>

      <!-- 5.1 흡기계통 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_5_1')}</td></tr>

      <!-- 5.1.1 흡기다기관 구성도 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_5_1_1')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_intake_diagram" rows="2" placeholder="\${BL('en_intake_diagram_ph')}">\${E(v('en_intake_diagram'))}</textarea>
            <input type="hidden" data-field="en_intake_diagram_imgs" value="\${E(v('en_intake_diagram_imgs'))}"><div class="en-drop" data-field-img="en_intake_diagram"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 5.1.2 흡기메니폴드 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_5_1_2')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_intake_manifold" rows="2" placeholder="\${BL('en_intake_manifold_ph')}">\${E(v('en_intake_manifold'))}</textarea>
            <input type="hidden" data-field="en_intake_manifold_imgs" value="\${E(v('en_intake_manifold_imgs'))}"><div class="en-drop" data-field-img="en_intake_manifold"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 5.1.3 에어필터 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_5_1_3')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_air_filter" rows="2" placeholder="\${BL('en_air_filter_ph')}">\${E(v('en_air_filter'))}</textarea>
            <input type="hidden" data-field="en_air_filter_imgs" value="\${E(v('en_air_filter_imgs'))}"><div class="en-drop" data-field-img="en_air_filter"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 5.2 배기계통 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_5_2')}</td></tr>

      <!-- 5.2.1 배기다기관 구성도 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_5_2_1')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_exhaust_diagram" rows="2" placeholder="\${BL('en_exhaust_diagram_ph')}">\${E(v('en_exhaust_diagram'))}</textarea>
            <input type="hidden" data-field="en_exhaust_diagram_imgs" value="\${E(v('en_exhaust_diagram_imgs'))}"><div class="en-drop" data-field-img="en_exhaust_diagram"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 5.2.2 배기메니폴드 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_5_2_2')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_exhaust_manifold" rows="2" placeholder="\${BL('en_exhaust_manifold_ph')}">\${E(v('en_exhaust_manifold'))}</textarea>
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
      <tr><th class="en-sec-th" colspan="2">\${BL('en_sec6')}</th></tr>

      <!-- 6.1 차량사진 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_6_1')}</td></tr>

      <!-- 6.1.1 차량 전면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_6_1_1')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_veh_front" rows="2" placeholder="\${BL('en_veh_front_ph')}">\${E(v('en_veh_front'))}</textarea>
            <input type="hidden" data-field="en_veh_front_imgs" value="\${E(v('en_veh_front_imgs'))}"><div class="en-drop" data-field-img="en_veh_front"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 6.1.2 차량 후면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_6_1_2')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_veh_rear" rows="2" placeholder="\${BL('en_veh_rear_ph')}">\${E(v('en_veh_rear'))}</textarea>
            <input type="hidden" data-field="en_veh_rear_imgs" value="\${E(v('en_veh_rear_imgs'))}"><div class="en-drop" data-field-img="en_veh_rear"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 6.1.3 차량 측면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_6_1_3')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_veh_side" rows="2" placeholder="\${BL('en_veh_side_ph')}">\${E(v('en_veh_side'))}</textarea>
            <input type="hidden" data-field="en_veh_side_imgs" value="\${E(v('en_veh_side_imgs'))}"><div class="en-drop" data-field-img="en_veh_side"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 6.1.4 차량 상면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_6_1_4')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_veh_top" rows="2" placeholder="\${BL('en_veh_top_ph')}">\${E(v('en_veh_top'))}</textarea>
            <input type="hidden" data-field="en_veh_top_imgs" value="\${E(v('en_veh_top_imgs'))}"><div class="en-drop" data-field-img="en_veh_top"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 6.2 외형도 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_6_2')}</td></tr>

      <!-- 6.2.1 외형 측면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_6_2_1')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ext_side" rows="2" placeholder="\${BL('en_ext_side_ph')}">\${E(v('en_ext_side'))}</textarea>
            <input type="hidden" data-field="en_ext_side_imgs" value="\${E(v('en_ext_side_imgs'))}"><div class="en-drop" data-field-img="en_ext_side"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 6.2.2 외형 상면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_6_2_2')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ext_top" rows="2" placeholder="\${BL('en_ext_top_ph')}">\${E(v('en_ext_top'))}</textarea>
            <input type="hidden" data-field="en_ext_top_imgs" value="\${E(v('en_ext_top_imgs'))}"><div class="en-drop" data-field-img="en_ext_top"><input type="file" accept="image/*" multiple><div class="en-drop-hint"><i class="fas fa-image"></i> \${BL('img_hint')}</div><div class="en-img-list"></div></div>
          </div>
        </td>
      </tr>

      <!-- 6.2.3 외형 뒷면 -->
      <tr><td class="en-lbl" style="padding:3px 6px;">\${BL('en_6_2_3')}</td>
        <td style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_ext_rear" rows="2" placeholder="\${BL('en_ext_rear_ph')}">\${E(v('en_ext_rear'))}</textarea>
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
      <tr><th class="en-sec-th" colspan="2">\${BL('en_sec7')}</th></tr>

      <!-- 7.1 그 외 배출가스 및 소음 저감기술 -->
      <tr><td class="en-sub-th" colspan="2">\${BL('en_7_1')}</td></tr>
      <tr>
        <td colspan="2" style="padding:2px 4px;">
          <div class="en-field">
            <textarea class="en-field-text" data-field="en_other_tech" rows="4" placeholder="\${BL('en_other_tech_ph')}">\${E(v('en_other_tech'))}</textarea>
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

  /* ── dp-drop 방식 인쇄 (obd_config 1.2.2, 1.2.3.x) ── */
  .dp-drop {
    border:none !important; background:transparent !important;
    padding:0 !important; min-height:unset !important;
    height:auto !important; overflow:visible !important;
    cursor:default !important;
  }
  .dp-drop-hint { display:none !important; }
  .dp-img-item-del { display:none !important; }
  .dp-img-list {
    display:flex !important; flex-direction:column !important;
    gap:6px !important; margin-top:2px !important;
  }
  .dp-img-item {
    display:block !important; width:100% !important;
    position:static !important;
  }
  .dp-img-item img {
    width:100% !important; height:auto !important;
    max-width:100% !important; max-height:none !important;
    object-fit:contain !important; display:block !important;
    border:none !important; border-radius:0 !important;
    background:transparent !important;
    page-break-inside:avoid;
  }
  .dp-drop:not(:has(img)) { display:none !important; }
  /* 첨부문서 영역 인쇄 시 숨김 */
  .oc-attach-section { display:none !important; }
  /* 행 페이지 분리 방지 */
  .obd-tbl tr { page-break-inside:avoid; }
}

/* ── obd_config 첨부문서 섹션 ── */
.oc-attach-section { margin-top:14px; }
.oc-attach-title { font-size:9pt; font-weight:700; margin-bottom:6px; color:#111; }
.oc-attach-note { font-size:8pt; color:#666; margin-bottom:8px; }
.oc-attach-drop {
  border:2px dashed #bbb; border-radius:8px;
  padding:16px; text-align:center; cursor:pointer;
  transition:.2s; color:#555; font-size:9pt; background:#fafafa;
  display:flex; flex-direction:column; align-items:center; gap:4px;
}
.oc-attach-drop:hover { border-color:#4e90d8; background:rgba(79,142,247,.04); }
.oc-attach-drop input[type=file] { display:none; }
.oc-attach-list { margin-top:8px; display:flex; flex-direction:column; gap:4px; }
.oc-attach-item {
  display:flex; align-items:center; gap:8px;
  padding:4px 8px; border-radius:4px;
  background:#f0f4fa; font-size:8.5pt;
}
.oc-attach-item-name { flex:1; color:#111; word-break:break-all; }
.oc-attach-item-size { color:#666; white-space:nowrap; font-size:8pt; }
.oc-attach-item-del { color:#ef4444; cursor:pointer; padding:1px 5px; border-radius:3px; font-size:10pt; line-height:1; }
.oc-attach-item-del:hover { background:rgba(239,68,68,.12); }

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
/* dp-drop 방식 (1.2.2, 1.2.3.x) — detail_plan과 동일한 스타일 */
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

<div class="obd-doc-tag">\${BL('obd_doc_tag')}</div>
<div class="obd-main-title">\${BL('obd_main_title_txt')}</div>

<!-- ══════════════════════════════════════════════════
     \${BL('obd_sec1_label')}
══════════════════════════════════════════════════ -->
<div class="obd-section-label">\${BL('obd_sec1')}</div>

<!-- 1.1 부품 목록 -->
<div style="font-size:8pt; font-weight:600; padding:4px 2px 2px; color:#333;">
  \${BL('obd_1_1_desc')}
</div>
<table class="obd-tbl">
  <colgroup><col style="width:14%"><col style="width:38%"><col style="width:48%"></colgroup>
  <tr>
    <th class="obd-th">\${BL('th_div')}</th>
    <th class="obd-th">\${BL('obd_th_parts')}</th>
    <th class="obd-th">\${BL('obd_th_func')}</th>
  </tr>
  <!-- 센서 -->
  <tr>
    <td class="obd-lbl" rowspan="5" style="text-align:center; font-weight:700;">\${BL('obd_lbl_sensor')}</td>
    <td class="obd-lbl" style="font-weight:400;">\${BL('obd_cps_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_cps_char" placeholder="\${BL('obd_ph_func')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">\${BL('obd_tmap_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_tmap_char" placeholder="\${BL('obd_ph_func')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">\${BL('obd_tps_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_tps_char" placeholder="\${BL('obd_ph_func')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">\${BL('obd_wps_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_wps_char" placeholder="\${BL('obd_ph_func')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">\${BL('obd_o2_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_o2_char" placeholder="\${BL('obd_ph_func')}"></textarea></td>
  </tr>
  <!-- 액츄에이터 -->
  <tr>
    <td class="obd-lbl" rowspan="4" style="text-align:center; font-weight:700;">\${BL('obd_lbl_actuator')}</td>
    <td class="obd-lbl" style="font-weight:400;">\${BL('obd_injector_lbl2')}</td>
    <td><textarea class="obd-field-text" data-field="obd_injector_char" placeholder="\${BL('obd_ph_func')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">\${BL('obd_coil_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_coil_char" placeholder="\${BL('obd_ph_func')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">\${BL('obd_o2heater_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_o2heater_char" placeholder="\${BL('obd_ph_func')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">\${BL('obd_wire_throttle')}</td>
    <td><textarea class="obd-field-text" data-field="obd_throttle_char" placeholder="\${BL('obd_ph_func')}"></textarea></td>
  </tr>
  <!-- 기타 -->
  <tr>
    <td class="obd-lbl" rowspan="2" style="text-align:center; font-weight:700;">\${BL('nt_etc')}</td>
    <td class="obd-lbl" style="font-weight:400;">\${BL('obd_fanrelay_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_fanrelay_char" placeholder="\${BL('obd_ph_func')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400;">\${BL('obd_pumprelay_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_pumprelay_char" placeholder="\${BL('obd_ph_func')}"></textarea></td>
  </tr>
</table>

<!-- 1.2 오작동표시등 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">
  \${BL('obd_1_2_desc')}
</div>
<table class="obd-tbl">
  <tr>
    <td class="obd-lbl" style="width:8%; text-align:center; white-space:nowrap;">1.2.1.</td>
    <td><textarea class="obd-field-text" data-field="obd_1_2_1" placeholder="\${BL('obd_ph_dtc_default')}">\${E(v('obd_1_2_1')) || BL('obd_ph_dtc_default')}</textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap; vertical-align:top; padding-top:6px;">1.2.2.</td>
    <td>
      <div style="font-size:8pt; padding:2px 0; color:#333; margin-bottom:4px;">\${BL('obd_div_mil_location')}</div>
      <input type="hidden" id="obd_1_2_2_imgs" data-field="obd_1_2_2_imgs" value="\${E(v('obd_1_2_2_imgs'))}">
      <div class="dp-drop" id="obd_1_2_2_drop"
           onclick="document.getElementById('obd_1_2_2_fi').click();"
           ondragover="event.preventDefault();this.classList.add('drag-over');"
           ondragleave="this.classList.remove('drag-over');"
           ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('obd_1_2_2_imgs','obd_1_2_2_drop',event.dataTransfer.files);">
        <input type="file" id="obd_1_2_2_fi" accept="image/*" multiple
               onchange="dpAddFiles('obd_1_2_2_imgs','obd_1_2_2_drop',this.files);this.value='';">
        <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
        <div class="dp-img-list" id="obd_1_2_2_imgs_list"></div>
      </div>
    </td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap; vertical-align:middle; padding-top:6px;">1.2.3.</td>
    <td style="vertical-align:middle; padding:4px 6px; font-size:8pt; color:#333; font-weight:600;">\${BL('obd_lbl_ctrl_indicator')}</td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap; vertical-align:top; padding-top:6px;">1.2.3.1.</td>
    <td>
      <div style="font-size:8pt; padding:2px 0; color:#333; margin-bottom:4px;">\${BL('obd_div_left_switch')}</div>
      <input type="hidden" id="obd_1_2_3_1_imgs" data-field="obd_1_2_3_1_imgs" value="\${E(v('obd_1_2_3_1_imgs'))}">
      <div class="dp-drop" id="obd_1_2_3_1_drop"
           onclick="document.getElementById('obd_1_2_3_1_fi').click();"
           ondragover="event.preventDefault();this.classList.add('drag-over');"
           ondragleave="this.classList.remove('drag-over');"
           ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('obd_1_2_3_1_imgs','obd_1_2_3_1_drop',event.dataTransfer.files);">
        <input type="file" id="obd_1_2_3_1_fi" accept="image/*" multiple
               onchange="dpAddFiles('obd_1_2_3_1_imgs','obd_1_2_3_1_drop',this.files);this.value='';">
        <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
        <div class="dp-img-list" id="obd_1_2_3_1_imgs_list"></div>
      </div>
    </td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap; vertical-align:top; padding-top:6px;">1.2.3.2.</td>
    <td>
      <div style="font-size:8pt; padding:2px 0; color:#333; margin-bottom:4px;">\${BL('obd_div_right_switch')}</div>
      <input type="hidden" id="obd_1_2_3_2_imgs" data-field="obd_1_2_3_2_imgs" value="\${E(v('obd_1_2_3_2_imgs'))}">
      <div class="dp-drop" id="obd_1_2_3_2_drop"
           onclick="document.getElementById('obd_1_2_3_2_fi').click();"
           ondragover="event.preventDefault();this.classList.add('drag-over');"
           ondragleave="this.classList.remove('drag-over');"
           ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('obd_1_2_3_2_imgs','obd_1_2_3_2_drop',event.dataTransfer.files);">
        <input type="file" id="obd_1_2_3_2_fi" accept="image/*" multiple
               onchange="dpAddFiles('obd_1_2_3_2_imgs','obd_1_2_3_2_drop',this.files);this.value='';">
        <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
        <div class="dp-img-list" id="obd_1_2_3_2_imgs_list"></div>
      </div>
    </td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap; vertical-align:top; padding-top:6px;">1.2.3.3.</td>
    <td>
      <div style="font-size:8pt; padding:2px 0; color:#333; margin-bottom:4px;">\${BL('obd_div_keybox')}</div>
      <input type="hidden" id="obd_1_2_3_3_imgs" data-field="obd_1_2_3_3_imgs" value="\${E(v('obd_1_2_3_3_imgs'))}">
      <div class="dp-drop" id="obd_1_2_3_3_drop"
           onclick="document.getElementById('obd_1_2_3_3_fi').click();"
           ondragover="event.preventDefault();this.classList.add('drag-over');"
           ondragleave="this.classList.remove('drag-over');"
           ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('obd_1_2_3_3_imgs','obd_1_2_3_3_drop',event.dataTransfer.files);">
        <input type="file" id="obd_1_2_3_3_fi" accept="image/*" multiple
               onchange="dpAddFiles('obd_1_2_3_3_imgs','obd_1_2_3_3_drop',this.files);this.value='';">
        <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
        <div class="dp-img-list" id="obd_1_2_3_3_imgs_list"></div>
      </div>
    </td>
  </tr>
</table>

<!-- 1.3 무단변경 금지 문구 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">
  \${BL('obd_1_3_desc')}
</div>
<table class="obd-tbl">
  <tr>
    <td>
      <textarea class="obd-field-text" data-field="obd_1_3" placeholder="\${BL('obd_ph_no_modify')}" style="min-height:40px;"></textarea>
    </td>
  </tr>
</table>

<!-- 1.4 감시장치 기술적 설명 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">
  \${BL('obd_1_4_desc')}
</div>
<table class="obd-tbl">
  <colgroup><col style="width:5%"><col style="width:55%"><col style="width:40%"></colgroup>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap;">1.4.2.</td>
    <td class="obd-lbl">\${BL('obd_lbl_cat_monitor')}</td>
    <td><textarea class="obd-field-text" data-field="obd_1_4_2" placeholder="\${BL('obd_ph_content')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap;">1.4.3.</td>
    <td class="obd-lbl">\${BL('obd_lbl_dpf_monitor')}</td>
    <td><textarea class="obd-field-text" data-field="obd_1_4_3" placeholder="\${BL('obd_ph_content')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap;">1.4.4.</td>
    <td class="obd-lbl">\${BL('obd_lbl_eis_monitor')}</td>
    <td><textarea class="obd-field-text" data-field="obd_1_4_4" placeholder="\${BL('obd_ph_content')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap;">1.4.5.</td>
    <td class="obd-lbl">\${BL('obd_lbl_obd_parts')}</td>
    <td><textarea class="obd-field-text" data-field="obd_1_4_5" placeholder="\${BL('obd_ph_content')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap;">1.4.6.</td>
    <td class="obd-lbl">\${BL('obd_lbl_mil_criteria')}</td>
    <td><textarea class="obd-field-text" data-field="obd_1_4_6" placeholder="\${BL('obd_ph_content')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap;">1.4.7.</td>
    <td class="obd-lbl">\${BL('obd_lbl_dtc_list')}</td>
    <td><textarea class="obd-field-text" data-field="obd_1_4_7" placeholder="\${BL('obd_ph_content')}"></textarea></td>
  </tr>
</table>

<!-- 1.5 기타 추가정보 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">
  \${BL('obd_1_5_desc')}
</div>
<table class="obd-tbl">
  <colgroup><col style="width:70%"><col style="width:30%"></colgroup>
  <tr>
    <th class="obd-th">\${BL('obd_th_test_req')}</th>
    <th class="obd-th">\${BL('obd_th_compliance')}</th>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400; font-size:8pt; line-height:1.6;">
      \${BL('obd_txt_malfunction_test')}
    </td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_1_5_1_pass"> \${BL('obd_val_pass')}</label>
        <label><input type="checkbox" data-field="obd_1_5_1_fail"> \${BL('obd_val_fail')}</label>
      </div>
    </td>
  </tr>
  <tr>
    <td class="obd-lbl" style="font-weight:400; font-size:8pt; line-height:1.6;">
      \${BL('obd_txt_electrical_continuity')}
    </td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_1_5_2_pass"> \${BL('obd_val_pass')}</label>
        <label><input type="checkbox" data-field="obd_1_5_2_fail"> \${BL('obd_val_fail')}</label>
      </div>
    </td>
  </tr>
</table>

<!-- 1.5.1 ~ 1.5.3 -->
<table class="obd-tbl" style="margin-top:2px;">
  <tr>
    <td class="obd-lbl" style="width:5%; text-align:center; white-space:nowrap; vertical-align:top; padding-top:6px;">1.5.1.</td>
    <td class="obd-lbl" style="width:55%; vertical-align:top; padding-top:6px;">\${BL('obd_lbl_prep_cycle')}</td>
    <td><textarea class="obd-field-text" data-field="obd_1_5_1_desc" placeholder="\${BL('obd_ph_content')}" style="min-height:36px;"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap; vertical-align:top; padding-top:6px;">1.5.2.</td>
    <td class="obd-lbl" style="vertical-align:top; padding-top:6px;">\${BL('obd_lbl_test_cycle')}</td>
    <td><textarea class="obd-field-text" data-field="obd_1_5_2_desc" placeholder="\${BL('obd_ph_content')}" style="min-height:36px;"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap; vertical-align:top; padding-top:6px;">1.5.3.</td>
    <td class="obd-lbl" style="vertical-align:top; padding-top:6px;">\${BL('obd_lbl_2nd_monitor')}\${BL('obd_lbl_2nd_monitor_suffix')}</td>
    <td><textarea class="obd-field-text" data-field="obd_1_5_3_desc" placeholder="\${BL('obd_ph_content')}" style="min-height:36px;"></textarea></td>
  </tr>
</table>

<!-- 1.6 자체시험결과 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">
  \${BL('obd_1_6_desc')}
</div>
<div style="font-size:8pt; font-weight:600; padding:2px 2px 2px; color:#333;">\${BL('obd_1_6_1_title')}</div>
<table class="obd-tbl">
  <colgroup><col style="width:34%"><col style="width:33%"><col style="width:33%"></colgroup>
  <tr>
    <th class="obd-th">\${BL('obd_th_part_check')}</th>
    <th class="obd-th">\${BL('obd_th_mi_time')}</th>
    <th class="obd-th">\${BL('obd_th_mem_err')}</th>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_part1" placeholder="\${BL('obd_ph_part_check')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_mi1" placeholder="\${BL('obd_ph_mi_time')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_err1" placeholder="\${BL('obd_ph_err_fix')}"></textarea></td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_part2" placeholder="\${BL('obd_ph_part_check')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_mi2" placeholder="\${BL('obd_ph_mi_time')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_err2" placeholder="\${BL('obd_ph_err_fix')}"></textarea></td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_part3" placeholder="\${BL('obd_ph_part_check')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_mi3" placeholder="\${BL('obd_ph_mi_time')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_err3" placeholder="\${BL('obd_ph_err_fix')}"></textarea></td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_part4" placeholder="\${BL('obd_ph_part_check')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_mi4" placeholder="\${BL('obd_ph_mi_time')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_err4" placeholder="\${BL('obd_ph_err_fix')}"></textarea></td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_part5" placeholder="\${BL('obd_ph_part_check')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_mi5" placeholder="\${BL('obd_ph_mi_time')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_1_err5" placeholder="\${BL('obd_ph_err_fix')}"></textarea></td>
  </tr>
</table>

<!-- 1.6.2 OBD 감시부품 테스트 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">\${BL('obd_1_6_2_title')}</div>
<table class="obd-tbl">
  <colgroup><col style="width:24%"><col style="width:18%"><col style="width:12%"><col style="width:12%"><col style="width:18%"><col style="width:16%"></colgroup>
  <tr>
    <th class="obd-th">\${BL('th_item')}</th>
    <th class="obd-th">\${BL('obd_th_part_harness')}</th>
    <th class="obd-th">\${BL('obd_th_switch')}</th>
    <th class="obd-th">\${BL('obd_th_start')}</th>
    <th class="obd-th">\${BL('obd_th_spec')}</th>
    <th class="obd-th">\${BL('obd_th_mil')}</th>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_item1" placeholder="\${BL('obd_th_item2')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_part1" placeholder="\${BL('obd_ph_part_harness')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_sw1" placeholder="\${BL('obd_ph_switch')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_start1" placeholder="\${BL('obd_ph_start')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_spec1" placeholder="\${BL('obd_ph_spec')}"></textarea></td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_1_6_2_mi1_y"> \${BL('obd_yn_y')}</label>
        <label><input type="checkbox" data-field="obd_1_6_2_mi1_n"> \${BL('obd_yn_n')}</label>
      </div>
    </td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_item2" placeholder="\${BL('obd_th_item2')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_part2" placeholder="\${BL('obd_ph_part_harness')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_sw2" placeholder="\${BL('obd_ph_switch')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_start2" placeholder="\${BL('obd_ph_start')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_spec2" placeholder="\${BL('obd_ph_spec')}"></textarea></td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_1_6_2_mi2_y"> \${BL('obd_yn_y')}</label>
        <label><input type="checkbox" data-field="obd_1_6_2_mi2_n"> \${BL('obd_yn_n')}</label>
      </div>
    </td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_item3" placeholder="\${BL('obd_th_item2')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_part3" placeholder="\${BL('obd_ph_part_harness')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_sw3" placeholder="\${BL('obd_ph_switch')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_start3" placeholder="\${BL('obd_ph_start')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_spec3" placeholder="\${BL('obd_ph_spec')}"></textarea></td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_1_6_2_mi3_y"> \${BL('obd_yn_y')}</label>
        <label><input type="checkbox" data-field="obd_1_6_2_mi3_n"> \${BL('obd_yn_n')}</label>
      </div>
    </td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_item4" placeholder="\${BL('obd_th_item2')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_part4" placeholder="\${BL('obd_ph_part_harness')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_sw4" placeholder="\${BL('obd_ph_switch')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_start4" placeholder="\${BL('obd_ph_start')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_spec4" placeholder="\${BL('obd_ph_spec')}"></textarea></td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_1_6_2_mi4_y"> \${BL('obd_yn_y')}</label>
        <label><input type="checkbox" data-field="obd_1_6_2_mi4_n"> \${BL('obd_yn_n')}</label>
      </div>
    </td>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_item5" placeholder="\${BL('obd_th_item2')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_part5" placeholder="\${BL('obd_ph_part_harness')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_sw5" placeholder="\${BL('obd_ph_switch')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_start5" placeholder="\${BL('obd_ph_start')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_1_6_2_spec5" placeholder="\${BL('obd_ph_spec')}"></textarea></td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_1_6_2_mi5_y"> \${BL('obd_yn_y')}</label>
        <label><input type="checkbox" data-field="obd_1_6_2_mi5_n"> \${BL('obd_yn_n')}</label>
      </div>
    </td>
  </tr>
</table>

<!-- ══════════════════════════════════════════════════
     \${BL('obd_sec2_label')}
══════════════════════════════════════════════════ -->
<div class="obd-section-label" style="margin-top:12px;">\${BL('obd_sec2_title')}</div>
<div style="font-size:8pt; font-weight:600; padding:2px 2px 2px; color:#333;">\${BL('obd_2_1_title')}</div>

<!-- 1. 일반 제원 -->
<div style="font-size:8pt; font-weight:600; padding:4px 2px 1px; color:#555;">\${BL('obd_gen_spec_title')}</div>
<table class="obd-tbl">
  <colgroup><col style="width:14%"><col style="width:14%"><col style="width:14%"><col style="width:14%"><col style="width:14%"><col style="width:30%"></colgroup>
  <tr>
    <th class="obd-th">\${BL('obd_th_carname')}</th>
    <th class="obd-th">\${BL('obd_th_type')}</th>
    <th class="obd-th">\${BL('obd_th_carkind')}</th>
    <th class="obd-th">\${BL('sv_fuel')}</th>
    <th class="obd-th">\${BL('oo_trans_type')}</th>
    <th class="obd-th">\${BL('obd_th_weight')}</th>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_2_1_1_name" placeholder="\${BL('obd_ph_carname')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_1_type" placeholder="\${BL('obd_ph_type')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_1_kind" placeholder="\${BL('obd_ph_carkind')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_1_fuel" placeholder="\${BL('obd_ph_fuel')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_1_trans" placeholder="\${BL('oo_th_trans_type')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_1_weight" placeholder="\${BL('obd_ph_weight')}"></textarea></td>
  </tr>
</table>

<!-- 2. 엔진 제원 -->
<div style="font-size:8pt; font-weight:600; padding:4px 2px 1px; color:#555;">\${BL('obd_eng_spec_title')}</div>
<table class="obd-tbl">
  <colgroup><col><col><col><col><col><col></colgroup>
  <tr>
    <th class="obd-th">\${BL('obd_th_type')}</th>
    <th class="obd-th">\${BL('em_lbl_max_power')}</th>
    <th class="obd-th">\${BL('obd_th_cc')}</th>
    <th class="obd-th">\${BL('obd_th_combtype')}</th>
    <th class="obd-th">\${BL('obd_th_cycle')}</th>
    <th class="obd-th">\${BL('obd_th_supplytype')}</th>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_2_1_2_etype" placeholder="\${BL('obd_ph_engtype')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_2_power" placeholder="\${BL('obd_ph_maxpower')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_2_cc" placeholder="\${BL('obd_ph_cc')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_2_comb" placeholder="\${BL('obd_ph_combtype')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_2_cycle" placeholder="\${BL('obd_ph_cycle')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_2_supply" placeholder="\${BL('obd_ph_supplytype')}"></textarea></td>
  </tr>
</table>

<!-- 3. 배출가스 제어장치 및 OBD 제원 -->
<div style="font-size:8pt; font-weight:600; padding:4px 2px 1px; color:#555;">\${BL('obd_em_ctrl_spec_title')}</div>
<table class="obd-tbl">
  <colgroup><col style="width:34%"><col style="width:22%"><col style="width:22%"><col style="width:22%"></colgroup>
  <tr>
    <th class="obd-th">\${BL('obd_th_cat')}</th>
    <th class="obd-th">\${BL('obd_th_2nd_air')}</th>
    <th class="obd-th" colspan="2">\${BL('obd_th_egr')}</th>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_2_1_3_cat" placeholder="\${BL('obd_ph_cat_info')}"></textarea></td>
    <td>
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_2_1_3_air_y"> \${BL('obd_yn_y')}</label>
        <label><input type="checkbox" data-field="obd_2_1_3_air_n"> \${BL('obd_yn_n')}</label>
      </div>
    </td>
    <td colspan="2">
      <div class="obd-check-row" style="justify-content:center;">
        <label><input type="checkbox" data-field="obd_2_1_3_egr_y"> \${BL('obd_yn_y')}</label>
        <label><input type="checkbox" data-field="obd_2_1_3_egr_n"> \${BL('obd_yn_n')}</label>
      </div>
    </td>
  </tr>
  <tr>
    <th class="obd-th">\${BL('obd_th_ecu')}</th>
    <th class="obd-th">\${BL('obd_th_o2s')}</th>
    <th class="obd-th" colspan="2">\${BL('obd_th_purge')}</th>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_2_1_3_ecu" placeholder="\${BL('obd_ph_ecu_info')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_1_3_o2s" placeholder="\${BL('obd_ph_o2s_info')}"></textarea></td>
    <td colspan="2"><textarea class="obd-field-text" data-field="obd_2_1_3_purge" placeholder="\${BL('obd_ph_purge_info')}"></textarea></td>
  </tr>
</table>

<!-- 2.2 자기진단동일차종 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">\${BL('obd_2_2_title')}</div>
<table class="obd-tbl">
  <colgroup><col><col><col><col><col><col></colgroup>
  <tr>
    <th class="obd-th">\${BL('obd_th_name_type')}</th>
    <th class="obd-th">\${BL('obd_th_engtype')}</th>
    <th class="obd-th">\${BL('obd_th_cc')}</th>
    <th class="obd-th">\${BL('obd_th_maxpower')}</th>
    <th class="obd-th">\${BL('obd_th_trans_step')}</th>
    <th class="obd-th">\${BL('obd_th_weight')}</th>
  </tr>
  <tr>
    <td><textarea class="obd-field-text" data-field="obd_2_2_name1" placeholder="\${BL('obd_ph_name_type')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_2_etype1" placeholder="\${BL('obd_ph_engtype')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_2_cc1" placeholder="\${BL('obd_ph_cc')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_2_power1" placeholder="\${BL('obd_ph_maxpower')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_2_trans1" placeholder="\${BL('obd_ph_trans_step')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_2_weight1" placeholder="\${BL('obd_ph_total_weight')}"></textarea></td>
  </tr>
</table>

<!-- 2.3 OBD 동일차종 설명 -->
<div style="font-size:8pt; font-weight:600; padding:6px 2px 2px; color:#333;">\${BL('obd_2_3_title')}</div>
<table class="obd-tbl">
  <colgroup><col style="width:18%"><col style="width:32%"><col style="width:25%"><col style="width:25%"></colgroup>
  <tr>
    <th class="obd-th" colspan="2">\${BL('th_item')}</th>
    <th class="obd-th" colspan="2">\${BL('obd_th_obd_same')}</th>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2" style="text-align:center;">\${BL('obd_lbl_same_carname')}</td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_name_1" placeholder="\${BL('obd_ph_carname')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_name_2" placeholder="\${BL('obd_ph_same_carname')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" rowspan="2" style="text-align:center; vertical-align:middle;">\${BL('obd_lbl_engine')}</td>
    <td class="obd-lbl">\${BL('obd_lbl_combustion')}</td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_combustion_1" placeholder="\${BL('obd_combustion_ph')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_combustion_2" placeholder="\${BL('obd_combustion_ph')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">\${BL('obd_lbl_fuel_method')}</td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_fuel_supply_1" placeholder="\${BL('obd_fuel_supply_ph')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_fuel_supply_2" placeholder="\${BL('obd_fuel_supply_ph')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" rowspan="4" style="text-align:center; vertical-align:middle;">\${BL('sv_emission')}<br>\${BL('obd_lbl_ctrl_dev')}</td>
    <td class="obd-lbl">\${BL('obd_lbl_cat_type')}</td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_cat_type_1" placeholder="\${BL('obd_cat_type_ph')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_cat_type_2" placeholder="\${BL('obd_cat_type_ph')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">\${BL('obd_lbl_dpf_type')}</td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_dpf_1" placeholder="\${BL('obd_ph_na_or_type')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_dpf_2" placeholder="\${BL('obd_ph_na_or_type')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">\${BL('obd_lbl_2ndair_yn')}</td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_air2_1" placeholder="\${BL('obd_yn_ph')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_air2_2" placeholder="\${BL('obd_yn_ph')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">\${BL('obd_lbl_egr_yn')}</td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_egr_1" placeholder="\${BL('obd_yn_ph')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_egr_2" placeholder="\${BL('obd_yn_ph')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" rowspan="3" style="text-align:center; vertical-align:middle;">\${BL('sv_emission')}<br>\${BL('obd_lbl_diag_config')} 및 기능</td>
    <td class="obd-lbl">\${BL('obd_lbl_obd_method')}</td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_obd_method_1" placeholder="\${BL('obd_ph_method')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_obd_method_2" placeholder="\${BL('obd_ph_method')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">\${BL('obd_lbl_monitor_check')}</td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_obd_check_1" placeholder="\${BL('obd_ph_check_method')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_obd_check_2" placeholder="\${BL('obd_ph_check_method')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">\${BL('obd_lbl_mal_display')}</td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_obd_display_1" placeholder="\${BL('obd_ph_display_method')}"></textarea></td>
    <td><textarea class="obd-field-text" data-field="obd_2_3_obd_display_2" placeholder="\${BL('obd_ph_display_method')}"></textarea></td>
  </tr>
</table>

<!-- ══════════════════════════════════════════════════
     \${BL('obd_sec3_label')}
══════════════════════════════════════════════════ -->
<div class="obd-section-label" style="margin-top:12px;">\${BL('obd_sec3_title')}</div>
<div style="font-size:8pt; font-weight:600; padding:2px 2px 2px; color:#333;">\${BL('obd_3_1_title')}</div>
<table class="obd-tbl">
  <colgroup><col style="width:25%"><col style="width:25%"><col style="width:50%"></colgroup>
  <tr>
    <th class="obd-th" colspan="2">\${BL('th_item')}</th>
    <th class="obd-th">\${BL('obd_th_obd_test_car')}</th>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">\${BL('obd_lbl_modelname')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_model" placeholder="\${BL('em_lbl_model2')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">\${BL('obd_lbl_vin')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_vin" placeholder="\${BL('obd_ph_vin')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">\${BL('nt_displacement')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_cc" placeholder="\${BL('obd_ph_cc')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">\${BL('nt_eng_type')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_etype" placeholder="\${BL('obd_ph_engtype')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">\${BL('obd_lbl_trans_type')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_trans_type" placeholder="\${BL('obd_ph_trans_type')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">\${BL('obd_lbl_trans_proc')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_trans_proc" placeholder="\${BL('obd_ph_trans_proc')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">\${BL('obd_lbl_equiv_inertia')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_inertia" placeholder="\${BL('obd_ph_equiv_inertia')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">\${BL('obd_lbl_final_drive')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_final_drive" placeholder="\${BL('obd_ph_final_drive')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">\${BL('obd_nv_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_nv" placeholder="\${BL('obd_nv_lbl')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" rowspan="2">\${BL('obd_lbl_tire')}</td>
    <td class="obd-lbl">\${BL('obd_tire_f_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_tire_f" placeholder="\${BL('obd_tire_f_ph')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">\${BL('obd_tire_r_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_tire_r" placeholder="\${BL('obd_tire_r_ph')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" rowspan="5">\${BL('sv_emission')}<br>제어장치</td>
    <td class="obd-lbl">\${BL('obd_cat_type_lbl')}<br><small style="font-weight:400;">\${BL('obd_cat_type_sub')}</small></td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_cat" placeholder="\${BL('obd_cat_type_ph')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">\${BL('obd_dpf_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_dpf" placeholder="\${BL('obd_ph_na_or_type')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">\${BL('obd_lbl_2ndair_yn')}</td>
    <td>
      <div class="obd-check-row">
        <label><input type="checkbox" data-field="obd_3_1_air2_y"> \${BL('obd_yn_y')}</label>
        <label><input type="checkbox" data-field="obd_3_1_air2_n"> \${BL('obd_yn_n')}</label>
      </div>
    </td>
  </tr>
  <tr>
    <td class="obd-lbl">\${BL('obd_egr_lbl')}</td>
    <td>
      <div class="obd-check-row">
        <label><input type="checkbox" data-field="obd_3_1_egr_y"> \${BL('obd_yn_y')}</label>
        <label><input type="checkbox" data-field="obd_3_1_egr_n"> \${BL('obd_yn_n')}</label>
      </div>
    </td>
  </tr>
  <tr>
    <td class="obd-lbl">\${BL('obd_evap_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_evap" placeholder="\${BL('obd_evap_ph')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" rowspan="4">\${BL('obd_diag_lbl')}</td>
    <td class="obd-lbl">\${BL('obd_diag_op_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_obd_method" placeholder="\${BL('obd_ph_method')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">\${BL('obd_mi_check_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_obd_check" placeholder="\${BL('obd_mi_check_ph')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">\${BL('obd_mi_disp_lbl')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_obd_display" placeholder="\${BL('obd_ph_display_method')}"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl">\${BL('g_monitor_item')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_monitor" placeholder="\${BL('obd_monitor_ph')}" style="min-height:40px;"></textarea></td>
  </tr>
  <tr>
    <td class="obd-lbl" colspan="2">\${BL('g_note')}</td>
    <td><textarea class="obd-field-text" data-field="obd_3_1_note" placeholder="\${BL('obd_note_ph')}" style="min-height:36px;"></textarea></td>
  </tr>
</table>

<!-- OBD TEST 사진 첨부 -->
<div style="font-size:8pt; font-weight:600; padding:8px 2px 4px; color:#333;">
  \${BL('obd_photo_title')}
</div>
<table class="obd-tbl">
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap; vertical-align:top; padding-top:6px; width:10%;">\${BL('obd_veh_photo_lbl')}</td>
    <td>
      <div style="font-size:8pt; padding:2px 0; color:#333; margin-bottom:4px;">\${BL('obd_veh_photo_desc')}</div>
      <input type="hidden" id="obd_car_imgs" data-field="obd_car_imgs" value="\${E(v('obd_car_imgs'))}">
      <div class="dp-drop" id="obd_car_imgs_drop"
           onclick="document.getElementById('obd_car_imgs_fi').click();"
           ondragover="event.preventDefault();this.classList.add('drag-over');"
           ondragleave="this.classList.remove('drag-over');"
           ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('obd_car_imgs','obd_car_imgs_drop',event.dataTransfer.files);">
        <input type="file" id="obd_car_imgs_fi" accept="image/*" multiple
               onchange="dpAddFiles('obd_car_imgs','obd_car_imgs_drop',this.files);this.value='';">
        <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
        <div class="dp-img-list" id="obd_car_imgs_list"></div>
      </div>
    </td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap; vertical-align:top; padding-top:6px;">\${BL('obd_vin_photo_lbl')}</td>
    <td>
      <div style="font-size:8pt; padding:2px 0; color:#333; margin-bottom:4px;">\${BL('obd_vin_photo_desc')}</div>
      <input type="hidden" id="obd_vin_imgs" data-field="obd_vin_imgs" value="\${E(v('obd_vin_imgs'))}">
      <div class="dp-drop" id="obd_vin_imgs_drop"
           onclick="document.getElementById('obd_vin_imgs_fi').click();"
           ondragover="event.preventDefault();this.classList.add('drag-over');"
           ondragleave="this.classList.remove('drag-over');"
           ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('obd_vin_imgs','obd_vin_imgs_drop',event.dataTransfer.files);">
        <input type="file" id="obd_vin_imgs_fi" accept="image/*" multiple
               onchange="dpAddFiles('obd_vin_imgs','obd_vin_imgs_drop',this.files);this.value='';">
        <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
        <div class="dp-img-list" id="obd_vin_imgs_list"></div>
      </div>
    </td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap; vertical-align:top; padding-top:6px;">\${BL('obd_eng_photo_lbl')}</td>
    <td>
      <div style="font-size:8pt; padding:2px 0; color:#333; margin-bottom:4px;">\${BL('obd_eng_photo_desc')}</div>
      <input type="hidden" id="obd_eng_imgs" data-field="obd_eng_imgs" value="\${E(v('obd_eng_imgs'))}">
      <div class="dp-drop" id="obd_eng_imgs_drop"
           onclick="document.getElementById('obd_eng_imgs_fi').click();"
           ondragover="event.preventDefault();this.classList.add('drag-over');"
           ondragleave="this.classList.remove('drag-over');"
           ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('obd_eng_imgs','obd_eng_imgs_drop',event.dataTransfer.files);">
        <input type="file" id="obd_eng_imgs_fi" accept="image/*" multiple
               onchange="dpAddFiles('obd_eng_imgs','obd_eng_imgs_drop',this.files);this.value='';">
        <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
        <div class="dp-img-list" id="obd_eng_imgs_list"></div>
      </div>
    </td>
  </tr>
  <tr>
    <td class="obd-lbl" style="text-align:center; white-space:nowrap; vertical-align:top; padding-top:6px;">\${BL('obd_scanner_photo_lbl')}</td>
    <td>
      <div style="font-size:8pt; padding:2px 0; color:#333; margin-bottom:4px;">\${BL('obd_scanner_photo_desc')}</div>
      <input type="hidden" id="obd_scanner_imgs" data-field="obd_scanner_imgs" value="\${E(v('obd_scanner_imgs'))}">
      <div class="dp-drop" id="obd_scanner_imgs_drop"
           onclick="document.getElementById('obd_scanner_imgs_fi').click();"
           ondragover="event.preventDefault();this.classList.add('drag-over');"
           ondragleave="this.classList.remove('drag-over');"
           ondrop="event.preventDefault();this.classList.remove('drag-over');dpAddFiles('obd_scanner_imgs','obd_scanner_imgs_drop',event.dataTransfer.files);">
        <input type="file" id="obd_scanner_imgs_fi" accept="image/*" multiple
               onchange="dpAddFiles('obd_scanner_imgs','obd_scanner_imgs_drop',this.files);this.value='';">
        <div class="dp-drop-hint"><i class="fas fa-image"></i> \${BL('dp_img_hint')}</div>
        <div class="dp-img-list" id="obd_scanner_imgs_list"></div>
      </div>
    </td>
  </tr>
</table>

<!-- ── 첨부문서: 자체시험성적서 / RAW DATA ── -->
<div class="oc-attach-section no-print" id="oc-attach-section">
  <div class="oc-attach-title"><i class="fas fa-paperclip"></i> \${BL('obd_attach_title')}</div>
  <div class="oc-attach-note">\${BL('ev_attach_note')}</div>
  <div class="oc-attach-drop" id="oc-drop-zone" onclick="document.getElementById('oc-file-input').click()">
    <input type="file" id="oc-file-input" multiple accept="image/*,.pdf">
    <i class="fas fa-cloud-upload-alt" style="font-size:20pt;margin-bottom:6px;display:block;"></i>
    \${BL('obd_upload_hint')}
  </div>
  <div class="oc-attach-list" id="oc-attach-list"></div>
  <input type="hidden" id="oc-attach-data" data-field="obd_config_attach_data" value="\${E(v('obd_config_attach_data'))}">
</div>

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

  <div class="em-doc-tag">\${BL('em_doc_tag')}</div>
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
        <th class="em-sec-th" colspan="8">\${BL('em_sec1')}</th>
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
          <label class="em-chk"><input type="checkbox" data-field="em_type_dur" \${v('em_type_dur')?'checked':''}>\${BL('em_val_dur_run')}</label>
        </td>
        <td colspan="2" style="text-align:center;">
          <label class="em-chk"><input type="checkbox" data-field="em_type_emis" \${v('em_type_emis')?'checked':''}>\${BL('em_val_emis')}</label>
        </td>
        <td colspan="2" style="text-align:center;">
          <label class="em-chk"><input type="checkbox" data-field="em_type_insp" \${v('em_type_insp')?'checked':''}>\${BL('em_val_insp')}</label>
        </td>
        <td colspan="1" style="text-align:center;">
          <label class="em-chk"><input type="checkbox" data-field="em_type_etc" \${v('em_type_etc')?'checked':''}>\${BL('em_val_etc')}</label>
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
        <th class="em-sec-th" colspan="5">\${BL('em_sec2')}</th>
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
        <th class="em-sec-th" colspan="5">\${BL('em_sec3')}</th>
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
        <th class="em-sec-th" colspan="6">\${BL('em_sec4')}</th>
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
        <td class="em-th">\${BL('em_lbl_cvs')}</td>
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
        <th class="em-sec-th" colspan="5">\${BL('em_sec5_cvs')}</th>
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
        <th class="em-sec-th" colspan="7">\${BL('em_sec6_result')}</th>
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
        <td class="em-th" style="text-align:center; font-size:7.5pt;">\${BL('oo_th_fuel_econ')}</td>
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
        <th class="em-th" rowspan="2" style="text-align:center; vertical-align:middle;">\${BL('em_item_th')}</th>
        <th class="em-th" rowspan="2" style="text-align:center; vertical-align:middle;">CO</th>
        <th class="em-th" rowspan="2" style="text-align:center; vertical-align:middle;">NOx</th>
        <th class="em-th" colspan="3" style="text-align:center;">HC</th>
        <th class="em-th" rowspan="2" style="text-align:center; vertical-align:middle;">PM</th>
        <th class="em-th" rowspan="2" style="text-align:center; vertical-align:middle;">CO₂</th>
        <th class="em-th" rowspan="2" style="text-align:center; vertical-align:middle; font-size:7.5pt;">\${BL('em_fuel_econ_th')}</th>
      </tr>
      <tr>
        <th class="em-th" style="text-align:center; font-size:7.5pt;">\${BL('oo_th_exhaust_gas')}</th>
        <th class="em-th" style="text-align:center;">NMHC</th>
        <th class="em-th" style="text-align:center; font-size:7.5pt;">\${BL('g_lbl_evap')}<br>(g/test)</th>
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
        <td class="em-th" style="font-size:7.5pt;">\${BL('oo_th_det_factor')}</td>
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
        <td class="em-th" style="text-align:center;">\${BL('em_std_td')}</td>
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
    <div class="em-attach-title"><i class="fas fa-paperclip"></i> \${BL('ev_attach_title')}</div>
    <div class="em-attach-note">\${BL('ev_attach_note')}</div>
    <div class="em-attach-drop" id="em-drop-raw">
      <i class="fas fa-cloud-upload-alt" style="font-size:20pt;margin-bottom:6px;display:block;"></i>
      \${BL('ev_upload_hint')}
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

  <div class="ev-doc-tag">\${BL('ev_doc_tag')}</div>
  <div class="ev-main-title">\${BL('ev_main_title')}</div>

  <!-- ══════════════════════════════════════════ -->
  <!-- 1. 일반 사항 -->
  <!-- ══════════════════════════════════════════ -->
  <table class="ev-tbl">
    <tbody>
      <tr>
        <th class="ev-sec-th" colspan="6">\${BL('ev_gen_section')}</th>
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
            <input type="checkbox" data-field="ev_type_dur" \${v('ev_type_dur')?'checked':''}>\${BL('em_val_dur_run')}
          </label>
        </td>
        <td colspan="2" style="text-align:center;">
          <label class="ev-chk-item" style="justify-content:center;">
            <input type="checkbox" data-field="ev_type_emis" \${v('ev_type_emis')?'checked':''}>\${BL('em_val_emis')}
          </label>
        </td>
        <td colspan="2" style="text-align:center;">
          <label class="ev-chk-item" style="justify-content:center;">
            <input type="checkbox" data-field="ev_type_etc" \${v('ev_type_etc')?'checked':''}>\${BL('em_val_etc')}
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
        <th class="ev-sec-th" colspan="5">\${BL('ev_sec2')}</th>
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
        <td style="text-align:center; font-weight:600;">\${BL('ev_final_result')}</td>
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
    <div class="ev-attach-title"><i class="fas fa-paperclip"></i> \${BL('ev_attach_title')}</div>
    <div class="ev-attach-note">\${BL('ev_attach_note')}</div>
    <div class="ev-attach-drop" id="ev-drop-raw" onclick="document.getElementById('ev-file-raw').click()">
      <input type="file" id="ev-file-raw" multiple accept="image/*,.pdf">
      <i class="fas fa-cloud-upload-alt" style="font-size:20pt;margin-bottom:6px;display:block;"></i>
      \${BL('ev_upload_hint')}
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

  <div class="obd-doc-tag">\${BL('oo_doc_tag')}</div>
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
        <th class="obd-th" style="width:16%;">\${BL('oo_th_trans_type')}</th>
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
        <th class="obd-th" colspan="6" style="text-align:left !important; padding-left:8px; border-top:2px solid #888;">\${BL('oo_sec3_emission')}장치 및 배출가스 자기진단장치 제원</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td colspan="2" style="text-align:left; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:3px;">\${BL('oo_catalyst_type')}</div>
          <input data-field="obd_catalyst" class="obd-inp" type="text" placeholder="\${BL('oo_ph_type_maker')}" value="\${E(v('obd_catalyst'))}">
        </td>
        <td colspan="2" style="text-align:center; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:5px;">\${BL('oo_secondary_air')}</div>
          <div class="obd-chk-row" style="justify-content:center; gap:14px;">
            <label class="obd-chk-item"><input type="checkbox" data-field="obd_air2_y" \${v('obd_air2_y')?'checked':''}>&nbsp;\${BL('oo_yn_y')}</label>
            <label class="obd-chk-item"><input type="checkbox" data-field="obd_air2_n" \${v('obd_air2_n')?'checked':''}>&nbsp;\${BL('oo_yn_n')}</label>
          </div>
        </td>
        <td colspan="2" style="text-align:center; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:5px;">\${BL('oo_egr')}</div>
          <div class="obd-chk-row" style="justify-content:center; gap:14px;">
            <label class="obd-chk-item"><input type="checkbox" data-field="obd_egr_y" \${v('obd_egr_y')?'checked':''}>&nbsp;\${BL('oo_yn_y')}</label>
            <label class="obd-chk-item"><input type="checkbox" data-field="obd_egr_n" \${v('obd_egr_n')?'checked':''}>&nbsp;\${BL('oo_yn_n')}</label>
          </div>
        </td>
      </tr>
      <tr>
        <td colspan="2" style="text-align:left; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:3px;">\${BL('oo_ecu_type')}</div>
          <input data-field="obd_ecu" class="obd-inp" type="text" placeholder="\${BL('oo_ph_type_maker')}" value="\${E(v('obd_ecu'))}">
        </td>
        <td colspan="2" style="text-align:left; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:3px;">\${BL('oo_o2_type')}</div>
          <input data-field="obd_o2sensor" class="obd-inp" type="text" placeholder="\${BL('oo_ph_type_maker')}" value="\${E(v('obd_o2sensor'))}">
        </td>
        <td colspan="2" style="text-align:left; padding:5px 8px;">
          <div style="font-weight:600; margin-bottom:3px;">\${BL('oo_purge_type')}</div>
          <input data-field="obd_purge" class="obd-inp" type="text" placeholder="\${BL('oo_ph_type_maker')}" value="\${E(v('obd_purge'))}">
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
    <div class="obd-attach-title"><i class="fas fa-paperclip"></i> \${BL('ev_attach_title')}</div>
    <div class="obd-attach-note">\${BL('ev_attach_note')}</div>
    <div class="obd-attach-drop" id="obd-drop-zone" onclick="document.getElementById('obd-file-input').click()">
      <input type="file" id="obd-file-input" multiple accept="image/*,.pdf">
      <i class="fas fa-cloud-upload-alt" style="font-size:20pt;margin-bottom:6px;display:block;"></i>
      \${BL('ev_upload_hint')}
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
.nt-tbl { width:100%; border-collapse:collapse; font-size:8.5pt; table-layout:fixed; margin-bottom:14px; box-sizing:border-box; overflow:visible; }
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
/* rowspan 셀: 테두리 명시 + 세로 중앙 정렬 */
.nt-rowspan-cell { border:1px solid #888 !important; vertical-align:middle !important; text-align:center !important; }
.nt-rowspan-cell .nt-inp { text-align:center; }

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
  .nt-tbl td[rowspan] { border:1px solid #333 !important; }
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

<div class="nt-form-tag">\${BL('nt_doc_tag')}</div>
<div class="nt-main-title">\${BL('nt_main_title')}</div>

<!-- 1. 시험관련 규정 -->
<div class="nt-sec-title">\${BL('nt_sec1')}</div>
<div style="padding:4px 8px;">
  <input data-field="nt_reg_note" class="nt-inline-inp" type="text" style="width:100%; font-size:9pt;" placeholder="\${BL('nt_reg_note_ph')}" value="\${E(v('nt_reg_note'))}">
</div>

<!-- 2. 시험일 -->
<div class="nt-inline" style="margin-top:10px;">
  <span class="nt-inline-lbl">\${BL('nt_test_date_lbl')}</span>
  <input data-field="nt_test_date" class="nt-inline-inp" type="text" placeholder="\${BL('nt_test_date_ph')}" value="\${E(v('nt_test_date'))}">
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
      <td class="nt-lbl" style="text-align:center;">\${BL('nt_na')}</td>
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
      <th class="nt-th">\${BL('dp_lbl_left')}<br>\${BL('sv_noise_simple')}</th>
      <th class="nt-th">\${BL('dp_lbl_right')}<br>\${BL('sv_noise_simple')}</th>
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
      <td class="nt-lbl" colspan="3" style="text-align:center; line-height:1.5;">\${BL('nt_lbl_wot_noise')}</td>
      <td class="nt-val"><input data-field="nt_lwot" class="nt-inp" type="text" value="\${E(v('nt_lwot'))}"></td>
      <td class="nt-lbl" colspan="3" style="text-align:center; line-height:1.5;">\${BL('nt_lbl_crs_noise')}</td>
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
      <th rowspan="3">\${BL('nt_div_th')}</th>
      <th rowspan="3">\${BL('nt_th_gear')}</th>
      <th rowspan="3">\${BL('nt_th_entry_speed')}</th>
      <th colspan="2">\${BL('nt_th_test_speed')}</th>
      <th colspan="2">\${BL('nt_th_rpm')}</th>
      <th rowspan="3">\${BL('nt_th_accel_pos')}</th>
      <th rowspan="3">\${BL('nt_th_bg_noise')}</th>
      <th colspan="2">\${BL('nt_th_meas_noise')}</th>
      <th rowspan="3">\${BL('nt_th_correction')}</th>
      <th rowspan="3">\${BL('nt_th_std_val')}</th>
    </tr>
    <tr>
      <th>\${BL('nt_th_accel_init')}</th>
      <th>\${BL('nt_th_accel_end')}</th>
      <th>\${BL('nt_th_accel_init')}</th>
      <th>\${BL('nt_th_accel_end')}</th>
      <th>\${BL('nt_th_left')}</th>
      <th>\${BL('nt_th_right')}</th>
    </tr>
  </thead>
  <tbody>
    <!-- 세트1: 1~4차시험 + 평균 + 결과 -->
    <tr>
      <td class="nt-lbl">\${BL('nt_lbl_1st')}</td>
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
      <td class="nt-lbl">\${BL('nt_2nd_lbl')}</td>
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
      <td class="nt-lbl">\${BL('nt_3rd_lbl')}</td>
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
      <td class="nt-lbl">\${BL('nt_4th_lbl')}</td>
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
      <td class="nt-lbl" style="text-align:center;">\${BL('nt_avg_lbl')}</td>
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
      <td class="nt-lbl" style="text-align:center;">\${BL('nt_result_lbl')}</td>
      <td class="nt-val" colspan="7"><input data-field="ks_s1_res_note" class="nt-inp" type="text" style="width:100%;" value="\${E(v('ks_s1_res_note'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_res_amb" class="nt-inp" type="text" value="\${E(v('ks_s1_res_amb'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_res_lL" class="nt-inp" type="text" value="\${E(v('ks_s1_res_lL'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_res_lR" class="nt-inp" type="text" value="\${E(v('ks_s1_res_lR'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_res_corr" class="nt-inp" type="text" value="\${E(v('ks_s1_res_corr'))}"></td>
      <td class="nt-val"><input data-field="ks_s1_res_limit" class="nt-inp" type="text" value="\${E(v('ks_s1_res_limit'))}"></td>
    </tr>
    <!-- 세트2: 1~4차시험 + 평균 + 결과 -->
    <tr>
      <td class="nt-lbl">\${BL('nt_lbl_1st')}</td>
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
      <td class="nt-lbl">\${BL('nt_2nd_lbl')}</td>
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
      <td class="nt-lbl">\${BL('nt_3rd_lbl')}</td>
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
      <td class="nt-lbl">\${BL('nt_4th_lbl')}</td>
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
      <td class="nt-lbl" style="text-align:center;">\${BL('nt_avg_lbl')}</td>
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
      <td class="nt-lbl" style="text-align:center;">\${BL('nt_result_lbl')}</td>
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
<table class="nt-tbl" style="table-layout:fixed;">
  <colgroup>
    <col style="width:7%;"><col style="width:7%;"><col style="width:18%;"><col style="width:11%;"><col style="width:11%;"><col style="width:11%;"><col style="width:17%;"><col style="width:18%;">
  </colgroup>
  <thead>
    <tr>
      <th rowspan="2">\${BL('sv_noise_simple')}<br>시험</th>
      <th rowspan="2">\${BL('nt_meas_count')}</th>
      <th rowspan="2" style="line-height:1.8;">\${BL('nt_ex_pct_lbl')}<br><input data-field="nt_ex_pct" class="nt-inp" type="text" style="width:3.5em;text-align:center;border-bottom:1px solid #888;" value="\${E(v('nt_ex_pct'))}">\${BL('nt_rpm_unit')}</th>
      <th rowspan="2">\${BL('nt_bg_noise_a')}</th>
      <th colspan="2">\${BL('nt_exhaust_noise_val')}</th>
      <th rowspan="2">\${BL('nt_score_a')}</th>
      <th rowspan="2">\${BL('nt_std_a')}</th>
    </tr>
    <tr>
      <th>\${BL('nt_measured')}</th>
      <th>\${BL('nt_corrected')}</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="nt-lbl">1</td>
      <td class="nt-val"><input data-field="nt_ex1_cnt"  class="nt-inp" type="text" value="\${E(v('nt_ex1_cnt'))}"></td>
      <td class="nt-val"><input data-field="nt_ex1_rpm"  class="nt-inp" type="text" value="\${E(v('nt_ex1_rpm'))}"></td>
      <td class="nt-val"><input data-field="nt_ex1_amb"  class="nt-inp" type="text" value="\${E(v('nt_ex1_amb'))}"></td>
      <td class="nt-val"><input data-field="nt_ex1_meas" class="nt-inp" type="text" value="\${E(v('nt_ex1_meas'))}"></td>
      <td class="nt-val"><input data-field="nt_ex1_corr" class="nt-inp" type="text" value="\${E(v('nt_ex1_corr'))}"></td>
      <td class="nt-val nt-rowspan-cell" rowspan="3"><input data-field="nt_ex_score" class="nt-inp" type="text" value="\${E(v('nt_ex_score'))}"></td>
      <td class="nt-val nt-rowspan-cell" rowspan="3"><input data-field="nt_ex_limit" class="nt-inp" type="text" value="\${E(v('nt_ex_limit'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">2</td>
      <td class="nt-val"><input data-field="nt_ex2_cnt"  class="nt-inp" type="text" value="\${E(v('nt_ex2_cnt'))}"></td>
      <td class="nt-val"><input data-field="nt_ex2_rpm"  class="nt-inp" type="text" value="\${E(v('nt_ex2_rpm'))}"></td>
      <td class="nt-val"><input data-field="nt_ex2_amb"  class="nt-inp" type="text" value="\${E(v('nt_ex2_amb'))}"></td>
      <td class="nt-val"><input data-field="nt_ex2_meas" class="nt-inp" type="text" value="\${E(v('nt_ex2_meas'))}"></td>
      <td class="nt-val"><input data-field="nt_ex2_corr" class="nt-inp" type="text" value="\${E(v('nt_ex2_corr'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">3</td>
      <td class="nt-val"><input data-field="nt_ex3_cnt"  class="nt-inp" type="text" value="\${E(v('nt_ex3_cnt'))}"></td>
      <td class="nt-val"><input data-field="nt_ex3_rpm"  class="nt-inp" type="text" value="\${E(v('nt_ex3_rpm'))}"></td>
      <td class="nt-val"><input data-field="nt_ex3_amb"  class="nt-inp" type="text" value="\${E(v('nt_ex3_amb'))}"></td>
      <td class="nt-val"><input data-field="nt_ex3_meas" class="nt-inp" type="text" value="\${E(v('nt_ex3_meas'))}"></td>
      <td class="nt-val"><input data-field="nt_ex3_corr" class="nt-inp" type="text" value="\${E(v('nt_ex3_corr'))}"></td>
    </tr>
  </tbody>
</table>

<!-- 8. 경적소음측정결과 -->
<div class="nt-sec-title" style="margin-top:16px;">\${BL('nt_sec8')}</div>
<table class="nt-tbl" style="table-layout:fixed;">
  <colgroup>
    <col style="width:7%;"><col style="width:7%;"><col style="width:12%;"><col style="width:9%;"><col style="width:11%;"><col style="width:11%;"><col style="width:11%;"><col style="width:16%;"><col style="width:16%;">
  </colgroup>
  <thead>
    <tr>
      <th rowspan="2">\${BL('sv_noise_simple')}<br>시험</th>
      <th rowspan="2">\${BL('nt_meas_count')}</th>
      <th rowspan="2">\${BL('nt_horn_form')}</th>
      <th rowspan="2">\${BL('nt_horn_count')}</th>
      <th rowspan="2">\${BL('nt_bg_noise_c')}</th>
      <th colspan="2">\${BL('nt_horn_noise_val')}</th>
      <th rowspan="2">\${BL('nt_score_c')}</th>
      <th rowspan="2">\${BL('nt_std_c')}</th>
    </tr>
    <tr>
      <th>\${BL('nt_measured')}</th>
      <th>\${BL('nt_corrected')}</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td class="nt-lbl">1</td>
      <td class="nt-val"><input data-field="nt_horn1_seq"  class="nt-inp" type="text" value="\${E(v('nt_horn1_seq'))}"></td>
      <td class="nt-val"><input data-field="nt_horn1_type" class="nt-inp" type="text" value="\${E(v('nt_horn1_type'))}"></td>
      <td class="nt-val"><input data-field="nt_horn1_cnt"  class="nt-inp" type="text" value="\${E(v('nt_horn1_cnt'))}"></td>
      <td class="nt-val"><input data-field="nt_horn1_amb"  class="nt-inp" type="text" value="\${E(v('nt_horn1_amb'))}"></td>
      <td class="nt-val"><input data-field="nt_horn1_meas" class="nt-inp" type="text" value="\${E(v('nt_horn1_meas'))}"></td>
      <td class="nt-val"><input data-field="nt_horn1_corr" class="nt-inp" type="text" value="\${E(v('nt_horn1_corr'))}"></td>
      <td class="nt-val nt-rowspan-cell" rowspan="2"><input data-field="nt_horn_score" class="nt-inp" type="text" value="\${E(v('nt_horn_score'))}"></td>
      <td class="nt-val nt-rowspan-cell" rowspan="2"><input data-field="nt_horn_limit" class="nt-inp" type="text" value="\${E(v('nt_horn_limit'))}"></td>
    </tr>
    <tr>
      <td class="nt-lbl">2</td>
      <td class="nt-val"><input data-field="nt_horn2_seq"  class="nt-inp" type="text" value="\${E(v('nt_horn2_seq'))}"></td>
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
    <input data-field="nt_inspector" class="nt-sign-inp" type="text" placeholder="\${BL('nt_inspector_ph')}" value="\${E(v('nt_inspector'))}">
  </div>
  <div class="nt-sign-item">
    <span class="nt-sign-lbl">\${BL('nt_verifier')}:</span>
    <input data-field="nt_confirmer" class="nt-sign-inp" type="text" placeholder="\${BL('nt_confirmer_ph')}" value="\${E(v('nt_confirmer'))}">
  </div>
</div>

<!-- 첨부문서 업로드/다운로드 (인쇄 제외) -->
<div class="nt-attach-section no-print">
  <div class="nt-attach-title"><i class="fas fa-paperclip"></i> \${BL('nt_attach_title')}</div>
  <div class="nt-attach-note">\${BL('ev_attach_note')}</div>
  <div class="nt-attach-drop" id="nt-drop-zone" onclick="document.getElementById('nt-file-input').click()">
    <input type="file" id="nt-file-input" multiple accept="image/*,.pdf">
    <i class="fas fa-cloud-upload-alt" style="font-size:20pt;margin-bottom:6px;display:block;"></i>
    \${BL('obd_upload_hint')}
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
            <span class="cf-item-lbl">\${BL('cf_maker_lbl')}</span>
            <div class="cf-item-inp-wrap">
              <input data-field="cf_maker" class="cf-item-inp" type="text"
                placeholder="\${BL('cf_maker_ph')}" value="\${E(v('cf_maker'))}">
            </div>
          </div>

          <!-- 2. 주소 -->
          <div class="cf-item-row" style="flex-direction:column;align-items:flex-start;">
            <div style="display:flex;align-items:flex-start;width:100%;gap:0;">
              <span class="cf-item-lbl">\${BL('cf_addr_lbl2')}</span>
              <div class="cf-item-inp-wrap">
                <input data-field="cf_address" class="cf-item-inp" type="text"
                  placeholder="\${BL('cf_ph_address')}" value="\${E(v('cf_address'))}">
              </div>
            </div>
            <div class="cf-tel-fax" style="padding-left:110px;width:100%;box-sizing:border-box;margin-top:10px;">
              <span class="cf-tel-fax-lbl">TEL)</span>
              <input data-field="cf_tel" class="cf-item-inp" type="text"
                placeholder="\${BL('cf_ph_phone')}" value="\${E(v('cf_tel'))}" style="flex:1;min-width:0;">
              <span class="cf-tel-fax-lbl" style="margin-left:16px;">FAX)</span>
              <input data-field="cf_fax" class="cf-item-inp" type="text"
                placeholder="\${BL('cf_ph_fax')}" value="\${E(v('cf_fax'))}" style="flex:1;min-width:0;">
            </div>
          </div>

          <!-- 3. 모델 -->
          <div class="cf-item-row">
            <span class="cf-item-lbl">\${BL('cf_model_lbl2')}</span>
            <div class="cf-item-inp-wrap">
              <input data-field="cf_model" class="cf-item-inp" type="text"
                placeholder="\${BL('cf_model_ph')}" value="\${E(v('cf_model'))}">
            </div>
          </div>

          <!-- 4. 수입자 -->
          <div class="cf-item-row">
            <span class="cf-item-lbl">\${BL('cf_importer_lbl')}</span>
            <div class="cf-item-inp-wrap">
              <input data-field="cf_importer" class="cf-item-inp" type="text"
                placeholder="\${BL('cf_importer_ph')}" value="\${E(v('cf_importer'))}">
            </div>
          </div>

          <!-- 5. 보증내용 -->
          <div class="cf-warranty-row">
            <div class="cf-warranty-top">
              <span class="cf-warranty-lbl">\${BL('cf_warranty_lbl2')}</span>
              <input data-field="cf_warranty_subject" class="cf-warranty-subject-inp" type="text"
                placeholder="\${BL('cf_warranty_subject_ph')}" value="\${E(v('cf_warranty_subject'))}">
            </div>
            <div class="cf-warranty-body">
              \${BL('cf_law_text')}
              \${BL('cf_law_period')}
              \${BL('cf_law_obligation')}
              \${BL('cf_law_recall')}
            </div>
          </div>

          <!-- 당사확인 문구 -->
          <div class="cf-confirm-stmt">
            \${BL('cf_confirm_text')}
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
                      placeholder="\${BL('cf_signed_at_ph')}" value="\${E(v('cf_signed_at'))}" style="flex:1;min-width:0;">
                  </div>
                </td>
                <td class="cf-sign-divider"></td>
                <!-- 우: Date -->
                <td>
                  <div style="display:flex;align-items:center;gap:8px;">
                    <span class="cf-sign-lbl">Date</span>
                    <input data-field="cf_sign_date" class="cf-sign-inp" type="text"
                      placeholder="\${BL('cf_sign_date_ph')}" value="\${E(v('cf_sign_date'))}" style="flex:1;min-width:0;">
                  </div>
                </td>
              </tr>
              <tr>
                <!-- 좌: Name -->
                <td>
                  <div style="display:flex;align-items:center;gap:8px;">
                    <span class="cf-sign-lbl">Name</span>
                    <input data-field="cf_name" class="cf-sign-inp" type="text"
                      placeholder="\${BL('cf_name_ph')}" value="\${E(v('cf_name'))}" style="flex:1;min-width:0;">
                  </div>
                </td>
                <td class="cf-sign-divider"></td>
                <!-- 우: Title -->
                <td>
                  <div style="display:flex;align-items:center;gap:8px;">
                    <span class="cf-sign-lbl">Title :</span>
                    <input data-field="cf_title" class="cf-sign-inp" type="text"
                      placeholder="\${BL('cf_title_ph')}" value="\${E(v('cf_title'))}" style="flex:1;min-width:0;">
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

  return '<div class="form-section" style="text-align:center;color:var(--c-text3);padding:40px;">'+BL('msg_coming_soon')+'</div>';
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
      img.src = src; img.title = BL('img_click_to_zoom');
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
      ['dp_11_2_imgs','dp_11_2_drop'],
      ['dp_13_imgs','dp_13_drop'],
      ['dp_8_14_1_imgs','dp_8_14_1_drop'],
      ['dp_8_14_2_imgs','dp_8_14_2_drop'],
      // obd_config 1.2.2, 1.2.3.x 드롭존
      ['obd_1_2_2_imgs','obd_1_2_2_drop'],
      ['obd_1_2_3_1_imgs','obd_1_2_3_1_drop'],
      ['obd_1_2_3_2_imgs','obd_1_2_3_2_drop'],
      ['obd_1_2_3_3_imgs','obd_1_2_3_3_drop'],
      // obd_config OBD TEST 사진 드롭존
      ['obd_car_imgs','obd_car_imgs_drop'],
      ['obd_vin_imgs','obd_vin_imgs_drop'],
      ['obd_eng_imgs','obd_eng_imgs_drop'],
      ['obd_scanner_imgs','obd_scanner_imgs_drop'],
    ].forEach(function(pair){ dpRenderDrop(pair[0], pair[1]); });
    // 8.x diagram 복원
    ['dp_8_1','dp_8_2','dp_8_3','dp_8_4','dp_8_5','dp_8_6','dp_8_7','dp_8_8','dp_8_9'].forEach(function(pfx){
      dpRenderDrop(pfx+'_diagram_imgs', pfx+'_diagram_drop');
    });
  };
})();

// ── obd_config 이미지 드롭존 초기화 ─────────────────────────────────
function initObdImgDrops() {
  // dp-drop 방식 드롭존 복원 (1.2.2, 1.2.3.x)
  if (typeof window.dpRestoreAll === 'function') window.dpRestoreAll();

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
        del.title = BL('attach_del_title');
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
        '<a class="em-attach-item-dl" title="'+BL('attach_dl_title')+'" href="'+f.dataUrl+'" download="'+esc(f.name)+'" style="color:#4e90d8;padding:1px 6px;border-radius:3px;font-size:10pt;line-height:1;"><i class="fas fa-download"></i></a>' +
        '<span class="em-attach-item-del" title="'+BL('attach_del_title')+'" data-idx="'+idx+'">×</span>';
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
        '<a class="ev-attach-item-dl" title="'+BL('attach_dl_title')+'" href="'+f.dataUrl+'" download="'+esc(f.name)+'" style="color:#4e90d8;padding:1px 6px;border-radius:3px;font-size:10pt;line-height:1;"><i class="fas fa-download"></i></a>' +
        '<span class="ev-attach-item-del" title="'+BL('attach_del_title')+'" data-idx="'+idx+'">×</span>';
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
      } catch(e) { /* parse error ignored */ }
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
        delBtn.title = BL('attach_del_title');
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

function initObdConfigAttach() {
  var hiddenInput = document.getElementById('oc-attach-data');
  var ocAttachFiles = [];
  // 저장된 데이터 복원
  try {
    var saved = hiddenInput && hiddenInput.value ? JSON.parse(hiddenInput.value) : [];
    if (Array.isArray(saved) && saved.length > 0) ocAttachFiles = saved;
  } catch(e) {}

  var dropZone  = document.getElementById('oc-drop-zone');
  var fileInput = document.getElementById('oc-file-input');
  var listEl    = document.getElementById('oc-attach-list');
  if (!dropZone || !fileInput) return;

  dropZone.addEventListener('dragover',  function(e){ e.preventDefault(); dropZone.style.borderColor='#4e90d8'; });
  dropZone.addEventListener('dragleave', function(){ dropZone.style.borderColor=''; });
  dropZone.addEventListener('drop',      function(e){ e.preventDefault(); dropZone.style.borderColor=''; handleOcFiles(e.dataTransfer.files); });
  fileInput.addEventListener('change',   function(){ handleOcFiles(this.files); this.value=''; });

  function syncHidden() {
    if (hiddenInput) hiddenInput.value = JSON.stringify(ocAttachFiles);
  }

  function handleOcFiles(files) {
    Array.from(files).forEach(function(file){
      var reader = new FileReader();
      reader.onload = function(ev){
        ocAttachFiles.push({ name: file.name, size: file.size, type: file.type, dataUrl: ev.target.result });
        syncHidden(); renderOcList();
      };
      reader.readAsDataURL(file);
    });
  }

  function fmtSize(b){ return b<1024?b+'B':b<1048576?(b/1024).toFixed(1)+'KB':(b/1048576).toFixed(1)+'MB'; }

  function renderOcList(){
    if (!listEl) return;
    listEl.innerHTML = '';
    ocAttachFiles.forEach(function(f, idx){
      var div = document.createElement('div');
      div.className = 'oc-attach-item';
      div.innerHTML =
        '<i class="fas '+(f.type==='application/pdf'?'fa-file-pdf':'fa-file-image')+'" style="color:#4e90d8;"></i>' +
        '<span class="oc-attach-item-name">'+esc(f.name)+'</span>' +
        '<span class="oc-attach-item-size">'+fmtSize(f.size)+'</span>' +
        '<a class="oc-attach-item-dl" title="'+BL('attach_dl_title')+'" href="'+f.dataUrl+'" download="'+esc(f.name)+'" style="color:#4e90d8;padding:1px 6px;border-radius:3px;font-size:10pt;line-height:1;"><i class="fas fa-download"></i></a>' +
        '<span class="oc-attach-item-del" title="'+BL('attach_del_title')+'" data-idx="'+idx+'">×</span>';
      listEl.appendChild(div);
    });
    listEl.querySelectorAll('.oc-attach-item-del').forEach(function(btn){
      btn.addEventListener('click', function(e){
        e.stopPropagation();
        ocAttachFiles.splice(parseInt(this.dataset.idx), 1);
        syncHidden(); renderOcList();
      });
    });
  }
  // 복원된 파일이 있으면 즉시 렌더링
  if (ocAttachFiles.length > 0) renderOcList();
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
        '<a class="nt-attach-item-dl" title="'+BL('attach_dl_title')+'" href="'+f.dataUrl+'" download="'+esc(f.name)+'" style="color:var(--c-accent);padding:1px 6px;border-radius:3px;font-size:10pt;line-height:1;"><i class="fas fa-download"></i></a>' +
        '<span class="nt-attach-item-del" title="'+BL('attach_del_title')+'" data-idx="'+idx+'">×</span>';
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
// 회원정보 모달 (기본정보 + 비밀번호 변경 탭)
// ================================================================
function showProfileModal() {
  // 현재 사용자 정보 채우기
  if (currentUser) {
    const usernameEl = document.getElementById('profile-username');
    const companyEl  = document.getElementById('profile-company');
    const repEl      = document.getElementById('profile-rep');
    const biznoEl    = document.getElementById('profile-bizno');
    const phoneEl    = document.getElementById('profile-phone');
    if (usernameEl) usernameEl.value = currentUser.username || '';
    if (companyEl)  companyEl.value  = currentUser.company_name || '';
    if (repEl)      repEl.value      = currentUser.representative || '';
    if (biznoEl)    biznoEl.value    = currentUser.business_number || '';
    if (phoneEl)    phoneEl.value    = currentUser.phone || '';
  }
  // 비밀번호 필드 초기화
  ['profile-cpw-current','profile-cpw-new','profile-cpw-new2'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });
  // 에러 숨기기
  ['profile-info-error','profile-pw-error'].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.style.display='none'; el.textContent=''; }
  });
  // 기본 탭으로
  switchProfileTab('info');
  document.getElementById('modal-profile').classList.remove('hidden');
}
function closeProfileModal() { document.getElementById('modal-profile').classList.add('hidden'); }

function switchProfileTab(tab) {
  const isInfo = tab === 'info';
  document.getElementById('panel-profile-info').style.display = isInfo ? '' : 'none';
  document.getElementById('panel-profile-pw').style.display  = isInfo ? 'none' : '';
  document.getElementById('tab-profile-info').classList.toggle('profile-tab-active', isInfo);
  document.getElementById('tab-profile-pw').classList.toggle('profile-tab-active', !isInfo);
  // 저장 버튼 라벨 변경
  const saveBtn = document.getElementById('profile-save-btn');
  if (saveBtn) {
    if (isInfo) {
      saveBtn.innerHTML = '<i class="fas fa-save"></i>' + LL('profile_btn_save');
    } else {
      saveBtn.innerHTML = '<i class="fas fa-check"></i>' + LL('btn_change');
    }
    saveBtn.disabled = false;
  }
}

async function doUpdateProfile() {
  const company  = document.getElementById('profile-company').value.trim();
  const rep      = document.getElementById('profile-rep').value.trim();
  const bizno    = document.getElementById('profile-bizno').value.trim();
  const phone    = document.getElementById('profile-phone').value.trim();
  const errEl    = document.getElementById('profile-info-error');
  errEl.style.display = 'none'; errEl.textContent = '';
  if (!company || !rep || !bizno) {
    errEl.textContent = LL('profile_err_required'); errEl.style.display = 'block'; return;
  }
  const btn = document.getElementById('profile-save-btn');
  btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>' + LL('btn_processing');
  try {
    const res  = await api('/api/auth/profile', { method:'PUT', body:JSON.stringify({company_name:company, representative:rep, business_number:bizno, phone}) });
    const data = await res.json();
    if (res.ok) {
      if (data.user) currentUser = data.user;
      closeProfileModal();
      showToast(LL('profile_saved_ok'), 'success');
    } else {
      errEl.textContent = data.error || LL('err_occurred'); errEl.style.display = 'block';
    }
  } catch { errEl.textContent = LL('err_network'); errEl.style.display = 'block'; }
  finally { btn.disabled = false; btn.innerHTML = '<i class="fas fa-save"></i>' + LL('profile_btn_save'); }
}

async function doChangePw() {
  const cur  = document.getElementById('profile-cpw-current').value;
  const nw   = document.getElementById('profile-cpw-new').value;
  const nw2  = document.getElementById('profile-cpw-new2').value;
  const errEl = document.getElementById('profile-pw-error');
  errEl.style.display = 'none'; errEl.textContent = '';
  if (!cur || !nw || !nw2) { errEl.textContent=LL('pw_err_required'); errEl.style.display='block'; return; }
  if (nw.length < 4) { errEl.textContent=LL('pw_err_too_short'); errEl.style.display='block'; return; }
  if (nw !== nw2) { errEl.textContent=LL('pw_err_mismatch'); errEl.style.display='block'; return; }
  const btn = document.getElementById('profile-cpw-btn');
  btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>'+LL('btn_processing');
  try {
    const res = await api('/api/auth/change-password', { method:'POST', body:JSON.stringify({current_password:cur, new_password:nw}) });
    const data = await res.json();
    if (res.ok) { closeProfileModal(); showToast(LL('pw_changed_ok'), 'success'); }
    else { errEl.textContent = data.error || LL('err_occurred'); errEl.style.display='block'; }
  } catch { errEl.textContent=LL('err_network'); errEl.style.display='block'; }
  finally { btn.disabled=false; btn.innerHTML='<i class="fas fa-check"></i>'+LL('btn_change'); }
}

document.addEventListener('DOMContentLoaded', () => {
  const m = document.getElementById('modal-profile');
  if (m) m.addEventListener('click', function(e){ if(e.target===this)closeProfileModal(); });
});
</script>

<!-- 회원정보 모달 (기본정보 + 비밀번호 변경 탭) -->
<div id="modal-profile" class="modal-backdrop hidden no-print">
  <div class="modal" onclick="event.stopPropagation()" style="max-width:480px;">
    <div class="modal-header">
      <h3 style="font-size:14pt;font-weight:700;">
        <i class="fas fa-user-circle" style="margin-right:8px;color:var(--c-primary);"></i>
        ${LL('profile_modal_title')}
      </h3>
      <button class="btn btn-ghost btn-icon btn-sm" onclick="closeProfileModal()"><i class="fas fa-times"></i></button>
    </div>
    <!-- 탭 버튼 -->
    <div style="display:flex;border-bottom:1px solid var(--c-border);padding:0 20px;gap:4px;background:var(--c-bg-card);">
      <button id="tab-profile-info" class="profile-tab profile-tab-active" onclick="switchProfileTab('info')">
        <i class="fas fa-user" style="margin-right:6px;"></i>${LL('profile_tab_info')}
      </button>
      <button id="tab-profile-pw" class="profile-tab" onclick="switchProfileTab('pw')">
        <i class="fas fa-lock" style="margin-right:6px;"></i>${LL('profile_tab_pw')}
      </button>
    </div>
    <!-- 기본정보 탭 패널 -->
    <div id="panel-profile-info" class="modal-body">
      <div class="form-group">
        <label class="label">${LL('profile_lbl_username')}</label>
        <input id="profile-username" class="input" type="text" readonly
          style="background:var(--c-bg);color:var(--c-text-muted);cursor:not-allowed;">
      </div>
      <div class="form-group">
        <label class="label">${LL('profile_lbl_company')} <span style="color:var(--c-danger);">*</span></label>
        <input id="profile-company" class="input" type="text" placeholder="${LL('profile_ph_company')}"
          onkeydown="if(event.key==='Enter')document.getElementById('profile-rep').focus()">
      </div>
      <div class="form-group">
        <label class="label">${LL('profile_lbl_rep')} <span style="color:var(--c-danger);">*</span></label>
        <input id="profile-rep" class="input" type="text" placeholder="${LL('profile_ph_rep')}"
          onkeydown="if(event.key==='Enter')document.getElementById('profile-bizno').focus()">
      </div>
      <div class="form-group">
        <label class="label">${LL('profile_lbl_bizno')} <span style="color:var(--c-danger);">*</span></label>
        <input id="profile-bizno" class="input" type="text" placeholder="${LL('profile_ph_bizno')}"
          onkeydown="if(event.key==='Enter')document.getElementById('profile-phone').focus()">
      </div>
      <div class="form-group">
        <label class="label">${LL('profile_lbl_phone')}</label>
        <input id="profile-phone" class="input" type="text" placeholder="${LL('profile_ph_phone')}"
          onkeydown="if(event.key==='Enter')doUpdateProfile()">
      </div>
      <div id="profile-info-error" class="auth-error" style="display:none;"></div>
    </div>
    <!-- 비밀번호 변경 탭 패널 -->
    <div id="panel-profile-pw" class="modal-body" style="display:none;">
      <div class="form-group">
        <label class="label">${LL('pw_lbl_current')} <span style="color:var(--c-danger);">*</span></label>
        <input id="profile-cpw-current" class="input" type="password" placeholder="${LL('pw_ph_current')}" autocomplete="current-password"
          onkeydown="if(event.key==='Enter')document.getElementById('profile-cpw-new').focus()">
      </div>
      <div class="form-group">
        <label class="label">${LL('pw_lbl_new')} <span style="color:var(--c-danger);">*</span></label>
        <input id="profile-cpw-new" class="input" type="password" placeholder="${LL('pw_ph_new')}" autocomplete="new-password"
          onkeydown="if(event.key==='Enter')document.getElementById('profile-cpw-new2').focus()">
      </div>
      <div class="form-group">
        <label class="label">${LL('pw_lbl_confirm')} <span style="color:var(--c-danger);">*</span></label>
        <input id="profile-cpw-new2" class="input" type="password" placeholder="${LL('pw_ph_confirm')}" autocomplete="new-password"
          onkeydown="if(event.key==='Enter')doChangePw()">
      </div>
      <div id="profile-pw-error" class="auth-error" style="display:none;"></div>
    </div>
    <!-- 푸터: 탭에 따라 다른 버튼 -->
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="closeProfileModal()">${LL('btn_cancel')}</button>
      <button id="profile-save-btn" class="btn btn-primary"
        onclick="document.getElementById('panel-profile-info').style.display!=='none'?doUpdateProfile():doChangePw()">
        <i class="fas fa-save"></i>${LL('profile_btn_save')}
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

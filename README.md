# MotoCart — 수입이륜차 인증신청 지원 시스템

## 프로젝트 개요
- **이름**: MotoCart
- **목적**: 수입이륜차 배출가스·소음 환경인증 서류 작성 지원
- **기술 스택**: Hono + TypeScript + Cloudflare Pages + D1 SQLite
- **언어 지원**: 한국어(ko) / 영어(en) / 일본어(ja) / 중국어(zh)

## 배포 URL
| 구분 | URL |
|------|-----|
| Cloudflare Pages | https://moto-cart.pages.dev |
| 커스텀 도메인 | https://motorcar-t.com |
| www | https://www.motorcar-t.com |

## GitHub
- **저장소**: https://github.com/harang62699-creator/moto-cart

---

## 🚀 Genspark 온스페이스(AI Developer) 셋업 가이드

새 온스페이스 세션에서 아래 순서대로 실행하면 됩니다.

### 1단계 — 저장소 클론

```bash
cd /home/user
git clone https://github.com/harang62699-creator/moto-cart.git webapp
cd webapp
```

### 2단계 — 의존성 설치

```bash
npm install
```

### 3단계 — 로컬 D1 DB 초기화

```bash
npm run db:migrate:local
```

> migrations/ 폴더의 SQL이 자동 적용됩니다.

### 4단계 — 빌드

```bash
npm run build
```

### 5단계 — PM2로 서버 시작

```bash
pm2 start ecosystem.config.cjs
```

### 6단계 — 접속 확인

```bash
curl http://localhost:3000
```

온스페이스 URL 버튼(포트 3000)으로 브라우저에서 확인하세요.

---

## 테스트 계정

| 아이디 | 비밀번호 | 비고 |
|--------|----------|------|
| harang2009 | 1234 | 기본 테스트 계정 |
| motoadmin | 1234 | 관리자 계정 |

> ⚠️ 새 온스페이스에서는 DB가 비어 있으므로 회원가입 후 사용하거나,  
> 아래 명령으로 테스트 계정을 직접 추가하세요.

**테스트 계정 수동 추가 (선택사항)**

```bash
# Node.js로 PBKDF2 해시 생성
node -e "
const { subtle } = require('crypto').webcrypto;
async function hash(pw) {
  const enc = new TextEncoder();
  const key = await subtle.importKey('raw', enc.encode(pw), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode('moto-cert-salt'), iterations: 100000, hash: 'SHA-256' },
    key, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
}
hash('1234').then(h => {
  console.log('INSERT INTO users (username, password_hash, company_name, representative, business_number, phone)');
  console.log('VALUES (' + JSON.stringify('harang2009') + ', ' + JSON.stringify(h) + ', ' + JSON.stringify('홍길동모터스') + ', ' + JSON.stringify('홍길동') + ', ' + JSON.stringify('123-45-67890') + ', ' + JSON.stringify('010-0000-0000') + ');');
});
"
```

생성된 INSERT 문을 `.wrangler/state/v3/d1/` 하위 최신 `.sqlite` 파일에 Python으로 직접 삽입합니다.

---

## 데이터 구조

### D1 테이블
| 테이블 | 설명 |
|--------|------|
| `users` | 회원 정보 (username, password_hash, company_name, representative, business_number, phone) |
| `applications` | 인증신청 목록 (cert_type, status, title, importer, cert_year, displacement, family_code, lang) |
| `form_data` | 서류별 입력 데이터 JSON (application_id, form_type, data, completed) |

### 인증 타입 (`cert_type`)
- `basic` — 신규 인증
- `change` — 변경 인증
- `report` — 보고

### 서류 타입 (`form_type`)
`dp` / `en` / `nt` / `em` / `ev` / `oo` / `ob` 등

---

## 주요 API 엔드포인트

| 메서드 | 경로 | 설명 |
|--------|------|------|
| POST | `/api/auth/register` | 회원가입 |
| POST | `/api/auth/login` | 로그인 (JWT 반환) |
| GET | `/api/auth/me` | 현재 사용자 정보 |
| PUT | `/api/auth/profile` | 회원정보 수정 |
| POST | `/api/auth/change-password` | 비밀번호 변경 |
| GET | `/api/applications` | 신청서 목록 |
| POST | `/api/applications` | 신청서 생성 |
| PUT | `/api/applications/:id` | 신청서 수정 |
| DELETE | `/api/applications/:id` | 신청서 삭제 |
| GET | `/api/form/:appId/:formType` | 서류 데이터 조회 |
| POST | `/api/form/:appId/:formType` | 서류 데이터 저장 |

---

## 개발 명령어

```bash
npm run build            # 빌드
npm run dev:sandbox      # 로컬 D1 포함 개발 서버 (포트 3000)
npm run db:migrate:local # 로컬 DB 마이그레이션
npm run db:migrate:prod  # 프로덕션 DB 마이그레이션
npm run db:reset         # 로컬 DB 초기화 후 재마이그레이션
npm run deploy           # 빌드 + Cloudflare Pages 배포
```

---

## Cloudflare 리소스

| 리소스 | 이름 | ID |
|--------|------|-----|
| Pages 프로젝트 | moto-cart | — |
| D1 데이터베이스 | moto-cart-production | `c143fce4-8f36-4542-9711-a78521ca158d` |

---

## 배포 상태

- **플랫폼**: Cloudflare Pages
- **상태**: ✅ 운영 중
- **마지막 업데이트**: 2026-05-29

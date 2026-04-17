import { Hono } from 'hono'
import { serveStatic } from 'hono/cloudflare-workers'

const app = new Hono()

// Serve static files
app.use('/static/*', serveStatic({ root: './public' }))

// Main page
app.get('/', (c) => {
  return c.html(`<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>수입자동차 배출가스·소음 인증신청 지원 시스템</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🚗</text></svg>" />
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css"/>
  <link rel="stylesheet" href="/static/style.css" />
</head>
<body class="bg-gray-50 min-h-screen">

<!-- Header -->
<header class="bg-gradient-to-r from-green-800 to-green-600 text-white shadow-lg">
  <div class="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
    <div class="flex items-center gap-3">
      <div class="bg-white rounded-full p-2">
        <i class="fas fa-car text-green-700 text-xl"></i>
      </div>
      <div>
        <h1 class="text-xl font-bold leading-tight">수입자동차 배출가스·소음 인증신청 지원 시스템</h1>
        <p class="text-green-200 text-xs">대기환경보전법 제48조 · 소음진동관리법 기반</p>
      </div>
    </div>
    <div class="hidden md:flex items-center gap-4 text-sm">
      <a href="https://kencis.mcee.go.kr" target="_blank" class="bg-white/20 hover:bg-white/30 px-3 py-1.5 rounded-lg transition flex items-center gap-1">
        <i class="fas fa-external-link-alt text-xs"></i> KENCIS 바로가기
      </a>
    </div>
  </div>
  <!-- Nav tabs -->
  <nav class="max-w-7xl mx-auto px-4 pb-0">
    <div class="flex gap-1 overflow-x-auto scrollbar-hide">
      <button onclick="showTab('tab-home')" id="nav-home" class="nav-tab active-tab whitespace-nowrap px-4 py-2.5 text-sm font-medium rounded-t-lg transition">
        <i class="fas fa-home mr-1"></i> 홈
      </button>
      <button onclick="showTab('tab-guide')" id="nav-guide" class="nav-tab whitespace-nowrap px-4 py-2.5 text-sm font-medium rounded-t-lg transition">
        <i class="fas fa-info-circle mr-1"></i> 인증 안내
      </button>
      <button onclick="showTab('tab-docs-cert')" id="nav-docs-cert" class="nav-tab whitespace-nowrap px-4 py-2.5 text-sm font-medium rounded-t-lg transition">
        <i class="fas fa-file-alt mr-1"></i> 인증신청 서류
      </button>
      <button onclick="showTab('tab-form')" id="nav-form" class="nav-tab whitespace-nowrap px-4 py-2.5 text-sm font-medium rounded-t-lg transition">
        <i class="fas fa-edit mr-1"></i> 신청서 작성
      </button>
      <button onclick="showTab('tab-checklist')" id="nav-checklist" class="nav-tab whitespace-nowrap px-4 py-2.5 text-sm font-medium rounded-t-lg transition">
        <i class="fas fa-tasks mr-1"></i> 체크리스트
      </button>
      <button onclick="showTab('tab-fee')" id="nav-fee" class="nav-tab whitespace-nowrap px-4 py-2.5 text-sm font-medium rounded-t-lg transition">
        <i class="fas fa-won-sign mr-1"></i> 수수료
      </button>
    </div>
  </nav>
</header>

<main class="max-w-7xl mx-auto px-4 py-6">

<!-- ===== TAB: 홈 ===== -->
<section id="tab-home" class="tab-section">
  <!-- 알림 배너 -->
  <div class="bg-blue-50 border-l-4 border-blue-500 p-4 rounded-lg mb-6 flex items-start gap-3">
    <i class="fas fa-info-circle text-blue-500 mt-0.5 text-lg"></i>
    <div>
      <p class="font-semibold text-blue-800">온라인 신청 안내</p>
      <p class="text-blue-700 text-sm mt-0.5">KENCIS(자동차 배출가스 및 소음 인증시스템)에서 온라인 신청이 가능합니다. 공인인증서 필요.</p>
    </div>
  </div>

  <!-- 신청 유형 카드 -->
  <h2 class="text-lg font-bold text-gray-800 mb-4"><i class="fas fa-th-large text-green-600 mr-2"></i>신청 유형 선택</h2>
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">

    <div class="card-hover bg-white rounded-xl border-2 border-green-200 p-5 cursor-pointer" onclick="showTab('tab-docs-cert')">
      <div class="flex items-center gap-3 mb-3">
        <div class="bg-green-100 rounded-lg p-3">
          <i class="fas fa-certificate text-green-600 text-2xl"></i>
        </div>
        <div>
          <h3 class="font-bold text-gray-800">배출가스 인증신청</h3>
          <span class="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full">처리기간 15일</span>
        </div>
      </div>
      <p class="text-sm text-gray-600">신규 수입자동차의 배출가스 기준 적합 여부를 인증받는 절차입니다.</p>
      <div class="mt-3 text-green-600 text-sm font-medium">서류 확인하기 →</div>
    </div>

    <div class="card-hover bg-white rounded-xl border-2 border-purple-200 p-5 cursor-pointer" onclick="showTab('tab-form')">
      <div class="flex items-center gap-3 mb-3">
        <div class="bg-purple-100 rounded-lg p-3">
          <i class="fas fa-pen-alt text-purple-600 text-2xl"></i>
        </div>
        <div>
          <h3 class="font-bold text-gray-800">신청서 작성 도우미</h3>
          <span class="text-xs bg-purple-100 text-purple-700 px-2 py-0.5 rounded-full">자동 완성</span>
        </div>
      </div>
      <p class="text-sm text-gray-600">신청서 항목을 단계적으로 입력하고 검토할 수 있습니다.</p>
      <div class="mt-3 text-purple-600 text-sm font-medium">작성 시작하기 →</div>
    </div>

    <div class="card-hover bg-white rounded-xl border-2 border-orange-200 p-5 cursor-pointer" onclick="showTab('tab-checklist')">
      <div class="flex items-center gap-3 mb-3">
        <div class="bg-orange-100 rounded-lg p-3">
          <i class="fas fa-clipboard-check text-orange-600 text-2xl"></i>
        </div>
        <div>
          <h3 class="font-bold text-gray-800">서류 체크리스트</h3>
          <span class="text-xs bg-orange-100 text-orange-700 px-2 py-0.5 rounded-full">진행률 확인</span>
        </div>
      </div>
      <p class="text-sm text-gray-600">제출 서류 준비 현황을 체크하고 진행률을 관리합니다.</p>
      <div class="mt-3 text-orange-600 text-sm font-medium">체크리스트 열기 →</div>
    </div>

    <div class="card-hover bg-white rounded-xl border-2 border-red-200 p-5 cursor-pointer" onclick="showTab('tab-fee')">
      <div class="flex items-center gap-3 mb-3">
        <div class="bg-red-100 rounded-lg p-3">
          <i class="fas fa-calculator text-red-600 text-2xl"></i>
        </div>
        <div>
          <h3 class="font-bold text-gray-800">수수료 안내</h3>
          <span class="text-xs bg-red-100 text-red-700 px-2 py-0.5 rounded-full">자동 계산</span>
        </div>
      </div>
      <p class="text-sm text-gray-600">인증 유형별 수수료를 확인하고 자동 계산합니다.</p>
      <div class="mt-3 text-red-600 text-sm font-medium">수수료 계산하기 →</div>
    </div>

    <div class="card-hover bg-white rounded-xl border-2 border-gray-200 p-5 cursor-pointer" onclick="showTab('tab-guide')">
      <div class="flex items-center gap-3 mb-3">
        <div class="bg-gray-100 rounded-lg p-3">
          <i class="fas fa-route text-gray-600 text-2xl"></i>
        </div>
        <div>
          <h3 class="font-bold text-gray-800">인증 절차 안내</h3>
          <span class="text-xs bg-gray-100 text-gray-700 px-2 py-0.5 rounded-full">단계별 가이드</span>
        </div>
      </div>
      <p class="text-sm text-gray-600">인증 신청부터 발급까지 전체 절차를 안내합니다.</p>
      <div class="mt-3 text-gray-600 text-sm font-medium">절차 보기 →</div>
    </div>
  </div>

  <!-- 법령 근거 -->
  <div class="bg-white rounded-xl border border-gray-200 p-5">
    <h3 class="font-bold text-gray-800 mb-3"><i class="fas fa-gavel text-green-600 mr-2"></i>관련 법령</h3>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
      <div class="flex items-start gap-2 p-3 bg-gray-50 rounded-lg">
        <i class="fas fa-book text-green-500 mt-0.5"></i>
        <div>
          <p class="font-medium text-sm text-gray-800">대기환경보전법 제48조 제1항</p>
          <p class="text-xs text-gray-500">배출가스 인증 근거 규정</p>
        </div>
      </div>
      <div class="flex items-start gap-2 p-3 bg-gray-50 rounded-lg">
        <i class="fas fa-book text-green-500 mt-0.5"></i>
        <div>
          <p class="font-medium text-sm text-gray-800">대기환경보전법 시행규칙 제64조</p>
          <p class="text-xs text-gray-500">인증신청 절차 및 첨부서류</p>
        </div>
      </div>
      <div class="flex items-start gap-2 p-3 bg-gray-50 rounded-lg">
        <i class="fas fa-book text-blue-500 mt-0.5"></i>
        <div>
          <p class="font-medium text-sm text-gray-800">소음진동관리법 시행규칙 제75조</p>
          <p class="text-xs text-gray-500">소음 인증생략 수수료 근거</p>
        </div>
      </div>
      <div class="flex items-start gap-2 p-3 bg-gray-50 rounded-lg">
        <i class="fas fa-book text-blue-500 mt-0.5"></i>
        <div>
          <p class="font-medium text-sm text-gray-800">제작자동차 인증 및 검사방법과 절차에 관한 규정</p>
          <p class="text-xs text-gray-500">인증시험 방법 및 절차 규정</p>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- ===== TAB: 인증 안내 ===== -->
<section id="tab-guide" class="tab-section hidden">
  <div class="bg-white rounded-xl border border-gray-200 p-6 mb-6">
    <h2 class="text-lg font-bold text-gray-800 mb-4"><i class="fas fa-route text-green-600 mr-2"></i>인증 업무 절차</h2>
    
    <!-- 인증 절차 -->
    <div class="mb-6">
      <h3 class="font-semibold text-gray-700 mb-3 flex items-center gap-2">
        <span class="bg-green-100 text-green-700 text-xs px-2 py-0.5 rounded-full">인증신청</span> 처리기간: 15일
      </h3>
      <div class="flex flex-col md:flex-row gap-2 items-center">
        <div class="step-box bg-green-50 border border-green-200 rounded-lg p-3 text-center flex-1">
          <div class="text-2xl mb-1">📋</div>
          <div class="font-semibold text-sm text-green-800">1. 신청서 작성</div>
          <div class="text-xs text-gray-500 mt-1">KENCIS 시스템 또는<br/>방문/우편</div>
        </div>
        <div class="text-gray-400 text-xl font-bold hidden md:block">→</div>
        <div class="step-box bg-green-50 border border-green-200 rounded-lg p-3 text-center flex-1">
          <div class="text-2xl mb-1">📁</div>
          <div class="font-semibold text-sm text-green-800">2. 서류 제출</div>
          <div class="text-xs text-gray-500 mt-1">첨부서류 준비 후<br/>한국환경공단 제출</div>
        </div>
        <div class="text-gray-400 text-xl font-bold hidden md:block">→</div>
        <div class="step-box bg-green-50 border border-green-200 rounded-lg p-3 text-center flex-1">
          <div class="text-2xl mb-1">🔬</div>
          <div class="font-semibold text-sm text-green-800">3. 시험 의뢰</div>
          <div class="text-xs text-gray-500 mt-1">국립환경과학원<br/>배출가스 시험</div>
        </div>
        <div class="text-gray-400 text-xl font-bold hidden md:block">→</div>
        <div class="step-box bg-green-50 border border-green-200 rounded-lg p-3 text-center flex-1">
          <div class="text-2xl mb-1">✅</div>
          <div class="font-semibold text-sm text-green-800">4. 심사·결정</div>
          <div class="text-xs text-gray-500 mt-1">적합/부적합 판정</div>
        </div>
        <div class="text-gray-400 text-xl font-bold hidden md:block">→</div>
        <div class="step-box bg-green-50 border border-green-200 rounded-lg p-3 text-center flex-1">
          <div class="text-2xl mb-1">📄</div>
          <div class="font-semibold text-sm text-green-800">5. 인증서 발급</div>
          <div class="text-xs text-gray-500 mt-1">인증서 수령</div>
        </div>
      </div>
    </div>

    <!-- 인증생략 절차 -->
    <div>
      <h3 class="font-semibold text-gray-700 mb-3 flex items-center gap-2">
        <span class="bg-blue-100 text-blue-700 text-xs px-2 py-0.5 rounded-full">인증생략신청</span> 처리기간: 10일
      </h3>
      <div class="flex flex-col md:flex-row gap-2 items-center">
        <div class="step-box bg-blue-50 border border-blue-200 rounded-lg p-3 text-center flex-1">
          <div class="text-2xl mb-1">📋</div>
          <div class="font-semibold text-sm text-blue-800">1. 생략신청서 작성</div>
          <div class="text-xs text-gray-500 mt-1">KENCIS 또는<br/>방문/우편</div>
        </div>
        <div class="text-gray-400 text-xl font-bold hidden md:block">→</div>
        <div class="step-box bg-blue-50 border border-blue-200 rounded-lg p-3 text-center flex-1">
          <div class="text-2xl mb-1">📁</div>
          <div class="font-semibold text-sm text-blue-800">2. 서류 제출</div>
          <div class="text-xs text-gray-500 mt-1">한국환경공단 제출</div>
        </div>
        <div class="text-gray-400 text-xl font-bold hidden md:block">→</div>
        <div class="step-box bg-blue-50 border border-blue-200 rounded-lg p-3 text-center flex-1">
          <div class="text-2xl mb-1">🔍</div>
          <div class="font-semibold text-sm text-blue-800">3. 서류 검토</div>
          <div class="text-xs text-gray-500 mt-1">한국환경공단<br/>서류 적합성 검토</div>
        </div>
        <div class="text-gray-400 text-xl font-bold hidden md:block">→</div>
        <div class="step-box bg-blue-50 border border-blue-200 rounded-lg p-3 text-center flex-1">
          <div class="text-2xl mb-1">📄</div>
          <div class="font-semibold text-sm text-blue-800">4. 생략서 발급</div>
          <div class="text-xs text-gray-500 mt-1">인증생략서 수령</div>
        </div>
      </div>
    </div>
  </div>

  <!-- 인증생략 대상 -->
  <div class="bg-white rounded-xl border border-gray-200 p-6 mb-6">
    <h2 class="text-lg font-bold text-gray-800 mb-4"><i class="fas fa-car-side text-blue-600 mr-2"></i>인증생략 대상 차량</h2>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div class="border border-gray-200 rounded-lg p-4">
        <div class="flex items-center gap-2 mb-2">
          <div class="bg-blue-100 rounded p-1.5"><i class="fas fa-truck text-blue-600"></i></div>
          <h4 class="font-semibold text-gray-800">특장차</h4>
        </div>
        <p class="text-sm text-gray-600">기인증된 엔진을 가지고 제작된 차량을 이용하여 개조를 하여 사용하는 차량으로 제작차와 동일차종으로 인정되는 차량</p>
      </div>
      <div class="border border-gray-200 rounded-lg p-4">
        <div class="flex items-center gap-2 mb-2">
          <div class="bg-green-100 rounded p-1.5"><i class="fas fa-plane text-green-600"></i></div>
          <h4 class="font-semibold text-gray-800">준이사자 차량</h4>
        </div>
        <p class="text-sm text-gray-600">해외에서 6개월 이상 1년 미만 체류 후 1인 이상 동반가족과 함께 입국하는 분이 이사물품으로 반입하는 차량 1대</p>
      </div>
      <div class="border border-gray-200 rounded-lg p-4">
        <div class="flex items-center gap-2 mb-2">
          <div class="bg-orange-100 rounded p-1.5"><i class="fas fa-tools text-orange-600"></i></div>
          <h4 class="font-semibold text-gray-800">특수 목적 차량</h4>
        </div>
        <p class="text-sm text-gray-600">한정된 장소 또는 공익 목적의 특수용도로 사용하는 차량으로 배출가스 시험 결과를 토대로 인증 생략</p>
      </div>
      <div class="border border-gray-200 rounded-lg p-4">
        <div class="flex items-center gap-2 mb-2">
          <div class="bg-purple-100 rounded p-1.5"><i class="fas fa-car text-purple-600"></i></div>
          <h4 class="font-semibold text-gray-800">개별 자동차</h4>
        </div>
        <p class="text-sm text-gray-600">동일시점에 통관한 동일차종의 신차에 대해 대표로 일부 차량이 인증서를 받으면 나머지 차량은 생략 가능</p>
      </div>
    </div>
  </div>

  <!-- 제출처 안내 -->
  <div class="bg-white rounded-xl border border-gray-200 p-6">
    <h2 class="text-lg font-bold text-gray-800 mb-4"><i class="fas fa-map-marker-alt text-red-500 mr-2"></i>제출처 안내</h2>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div class="bg-green-50 rounded-lg p-4">
        <h4 class="font-semibold text-green-800 mb-2"><i class="fas fa-building mr-1"></i>한국환경공단</h4>
        <p class="text-sm text-gray-600 mb-1">인증대행기관 (접수·서류검토·인증생략서 발급)</p>
        <p class="text-sm font-medium text-gray-700">📞 1577-7766</p>
        <p class="text-sm text-gray-500">인천광역시 서구 환경로 42</p>
      </div>
      <div class="bg-blue-50 rounded-lg p-4">
        <h4 class="font-semibold text-blue-800 mb-2"><i class="fas fa-flask mr-1"></i>국립환경과학원</h4>
        <p class="text-sm text-gray-600 mb-1">배출가스 시험 실시 기관</p>
        <p class="text-sm font-medium text-gray-700">📞 032-560-7114</p>
        <p class="text-sm text-gray-500">인천광역시 서구 환경로 42</p>
      </div>
    </div>
    <div class="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
      <p class="text-sm text-yellow-800"><i class="fas fa-globe mr-1"></i><strong>온라인 신청:</strong> <a href="https://kencis.mcee.go.kr" target="_blank" class="text-blue-600 underline">kencis.mcee.go.kr</a> (공인인증서 필요, 회원가입 후 사용)</p>
    </div>
  </div>
</section>

<!-- ===== TAB: 인증신청 서류 ===== -->
<section id="tab-docs-cert" class="tab-section hidden">
  <div class="bg-white rounded-xl border border-gray-200 p-6 mb-6">
    <h2 class="text-lg font-bold text-gray-800 mb-2"><i class="fas fa-file-alt text-green-600 mr-2"></i>배출가스·소음 인증신청 첨부서류</h2>
    <p class="text-sm text-gray-500 mb-4">대기환경보전법 시행규칙 제64조 제1항 근거</p>
    
    <div class="mb-4 p-3 bg-green-50 border border-green-200 rounded-lg text-sm text-green-800">
      <i class="fas fa-info-circle mr-1"></i>
      <strong>배출가스 인증신청 대상:</strong> 신규 수입자동차 (제작차 인증이 없는 차량). 시험기관에서 배출가스 시험 필요.
    </div>

    <!-- 필수 서류 목록 -->
    <div class="space-y-3">
      <div class="doc-item border border-gray-200 rounded-lg p-4">
        <div class="flex items-start gap-3">
          <div class="bg-red-100 rounded-full w-7 h-7 flex items-center justify-center text-red-700 font-bold text-sm flex-shrink-0 mt-0.5">1</div>
          <div class="flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <h4 class="font-semibold text-gray-800">배출가스 감지·저감장치 등의 구성에 관한 서류</h4>
              <span class="badge-required">필수</span>
            </div>
            <p class="text-sm text-gray-600 mt-1">엔진 배출가스 저감 시스템, 촉매장치, EGR 등 관련 기술 문서</p>
            <div class="mt-2 bg-gray-50 rounded p-2 text-xs text-gray-500">
              <i class="fas fa-file-pdf text-red-400 mr-1"></i>포함 내용: 원동기 구조 설명서, 배출가스 감지장치 다이어그램, 저감장치 사양서
            </div>
          </div>
        </div>
      </div>

      <div class="doc-item border border-gray-200 rounded-lg p-4">
        <div class="flex items-start gap-3">
          <div class="bg-red-100 rounded-full w-7 h-7 flex items-center justify-center text-red-700 font-bold text-sm flex-shrink-0 mt-0.5">2</div>
          <div class="flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <h4 class="font-semibold text-gray-800">연료효율 관련 장치 등의 구성에 관한 서류</h4>
              <span class="badge-required">필수</span>
            </div>
            <p class="text-sm text-gray-600 mt-1">연료분사 시스템, 연비 관련 제어장치 기술 문서</p>
            <div class="mt-2 bg-gray-50 rounded p-2 text-xs text-gray-500">
              <i class="fas fa-file-pdf text-red-400 mr-1"></i>포함 내용: 연료계통 구성도, 연료효율 측정 방식, 에너지소비효율 관련 데이터
            </div>
          </div>
        </div>
      </div>

      <div class="doc-item border border-gray-200 rounded-lg p-4">
        <div class="flex items-start gap-3">
          <div class="bg-red-100 rounded-full w-7 h-7 flex items-center justify-center text-red-700 font-bold text-sm flex-shrink-0 mt-0.5">3</div>
          <div class="flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <h4 class="font-semibold text-gray-800">인증에 필요한 세부계획에 관한 서류</h4>
              <span class="badge-required">필수</span>
            </div>
            <p class="text-sm text-gray-600 mt-1">인증 시험 세부 계획, 차량 기술 사양, 제작사 정보 등</p>
            <div class="mt-2 bg-gray-50 rounded p-2 text-xs text-gray-500">
              <i class="fas fa-file-pdf text-red-400 mr-1"></i>별지 제4호 서식 또는 별지 제4의2호 서식(전기차) 사용
            </div>
          </div>
        </div>
      </div>

      <div class="doc-item border border-gray-200 rounded-lg p-4">
        <div class="flex items-start gap-3">
          <div class="bg-red-100 rounded-full w-7 h-7 flex items-center justify-center text-red-700 font-bold text-sm flex-shrink-0 mt-0.5">4</div>
          <div class="flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <h4 class="font-semibold text-gray-800">자동차배출가스 시험결과 보고에 관한 서류</h4>
              <span class="badge-required">필수</span>
            </div>
            <p class="text-sm text-gray-600 mt-1">배출가스 시험성적서, 인증시험 결과값 등</p>
            <div class="mt-2 bg-gray-50 rounded p-2 text-xs text-gray-500">
              <i class="fas fa-file-pdf text-red-400 mr-1"></i>국립환경과학원 또는 공인시험기관 발급 시험성적서 포함
            </div>
          </div>
        </div>
      </div>

      <div class="doc-item border border-gray-200 rounded-lg p-4">
        <div class="flex items-start gap-3">
          <div class="bg-red-100 rounded-full w-7 h-7 flex items-center justify-center text-red-700 font-bold text-sm flex-shrink-0 mt-0.5">5</div>
          <div class="flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <h4 class="font-semibold text-gray-800">배출가스 보증에 관한 제작자 확인서 또는 계약서</h4>
              <span class="badge-required">필수</span>
            </div>
            <p class="text-sm text-gray-600 mt-1">자동차제작자가 아닌 자로부터 수입하는 경우, 기후에너지환경부장관이 고시하는 서류로 갈음 가능</p>
            <div class="mt-2 bg-gray-50 rounded p-2 text-xs text-gray-500">
              <i class="fas fa-file-pdf text-red-400 mr-1"></i>제작자-수입자간 배출가스 보증 계약서 또는 제작자 확인서
            </div>
          </div>
        </div>
      </div>

      <div class="doc-item border border-gray-200 rounded-lg p-4">
        <div class="flex items-start gap-3">
          <div class="bg-red-100 rounded-full w-7 h-7 flex items-center justify-center text-red-700 font-bold text-sm flex-shrink-0 mt-0.5">6</div>
          <div class="flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <h4 class="font-semibold text-gray-800">제작차 배출허용기준에 관한 사항</h4>
              <span class="badge-required">필수</span>
            </div>
            <p class="text-sm text-gray-600 mt-1">저공해자동차 등의 배출허용기준 포함, 해당 차량이 충족하는 배출 기준값</p>
          </div>
        </div>
      </div>

      <div class="doc-item border border-gray-200 rounded-lg p-4">
        <div class="flex items-start gap-3">
          <div class="bg-yellow-100 rounded-full w-7 h-7 flex items-center justify-center text-yellow-700 font-bold text-sm flex-shrink-0 mt-0.5">7</div>
          <div class="flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <h4 class="font-semibold text-gray-800">배출가스 자가진단장치(OBD) 구성에 관한 서류</h4>
              <span class="badge-conditional">조건부 필수</span>
            </div>
            <p class="text-sm text-gray-600 mt-1">기후에너지환경부장관이 정하여 고시하는 자동차의 경우에만 제출 (일반적으로 승용차, 소형 화물차 등)</p>
            <div class="mt-2 bg-yellow-50 rounded p-2 text-xs text-yellow-700">
              <i class="fas fa-exclamation-triangle mr-1"></i>OBD 장착 대상 차량 확인 후 제출 여부 결정
            </div>
          </div>
        </div>
      </div>

      <div class="doc-item border border-gray-200 rounded-lg p-4">
        <div class="flex items-start gap-3">
          <div class="bg-yellow-100 rounded-full w-7 h-7 flex items-center justify-center text-yellow-700 font-bold text-sm flex-shrink-0 mt-0.5">8</div>
          <div class="flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <h4 class="font-semibold text-gray-800">축전지·모터·제너레이터 부품 보증에 관한 사항</h4>
              <span class="badge-conditional">전기차/수소차 한정</span>
            </div>
            <p class="text-sm text-gray-600 mt-1">전기자동차, 수소전기자동차, 전기건설기계, 수소전기건설기계에 사용될 원동기의 경우에만 제출</p>
          </div>
        </div>
      </div>

      <div class="doc-item border border-gray-200 rounded-lg p-4">
        <div class="flex items-start gap-3">
          <div class="bg-yellow-100 rounded-full w-7 h-7 flex items-center justify-center text-yellow-700 font-bold text-sm flex-shrink-0 mt-0.5">9</div>
          <div class="flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <h4 class="font-semibold text-gray-800">충전기 보증에 관한 사항</h4>
              <span class="badge-conditional">전기차 한정</span>
            </div>
            <p class="text-sm text-gray-600 mt-1">전기자동차, 전기건설기계에 사용될 원동기의 경우에만 제출</p>
          </div>
        </div>
      </div>
    </div>

    <!-- 소음 인증 서류 -->
    <div class="mt-6 p-4 bg-purple-50 border border-purple-200 rounded-lg">
      <h3 class="font-semibold text-purple-800 mb-3"><i class="fas fa-volume-off mr-1"></i>소음 인증신청 추가 서류</h3>
      <div class="space-y-2">
        <div class="flex items-start gap-2">
          <span class="badge-required text-xs mt-0.5">필수</span>
          <div>
            <p class="text-sm font-medium text-gray-800">자동차 소음저감에 관한 서류</p>
            <p class="text-xs text-gray-500">소음저감장치(머플러, 흡음재 등) 구성 및 소음시험 결과 포함</p>
          </div>
        </div>
        <div class="flex items-start gap-2">
          <span class="badge-required text-xs mt-0.5">필수</span>
          <div>
            <p class="text-sm font-medium text-gray-800">소음시험 결과보고서</p>
            <p class="text-xs text-gray-500">주행소음, 정지소음 등 각 항목별 시험 결과치</p>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- 신청 방법 -->
  <div class="bg-white rounded-xl border border-gray-200 p-6">
    <h3 class="font-semibold text-gray-800 mb-3"><i class="fas fa-paper-plane text-green-600 mr-2"></i>신청 방법</h3>
    <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
      <div class="bg-green-50 rounded-lg p-3 text-center">
        <i class="fas fa-laptop text-green-600 text-2xl mb-2"></i>
        <p class="font-medium text-sm text-green-800">온라인 신청</p>
        <p class="text-xs text-gray-500 mt-1">kencis.mcee.go.kr<br/>(공인인증서 필요)</p>
      </div>
      <div class="bg-blue-50 rounded-lg p-3 text-center">
        <i class="fas fa-walking text-blue-600 text-2xl mb-2"></i>
        <p class="font-medium text-sm text-blue-800">방문 신청</p>
        <p class="text-xs text-gray-500 mt-1">한국환경공단<br/>인천 본원 방문</p>
      </div>
      <div class="bg-orange-50 rounded-lg p-3 text-center">
        <i class="fas fa-envelope text-orange-600 text-2xl mb-2"></i>
        <p class="font-medium text-sm text-orange-800">우편 신청</p>
        <p class="text-xs text-gray-500 mt-1">서류 우편 발송<br/>(등기우편 권장)</p>
      </div>
    </div>
  </div>
</section>

<!-- ===== TAB: 신청서 작성 ===== -->
<section id="tab-form" class="tab-section hidden">
  <div class="bg-white rounded-xl border border-gray-200 p-6">
    <h2 class="text-lg font-bold text-gray-800 mb-2"><i class="fas fa-edit text-purple-600 mr-2"></i>배출가스·소음 인증신청서 작성 도우미</h2>
    <p class="text-sm text-gray-500 mb-6">대기환경보전법 시행규칙 별지 제30호 서식 기반</p>

    <!-- 진행 단계 표시 -->
    <div class="flex items-center justify-center mb-8 overflow-x-auto">
      <div class="flex items-center gap-2 min-w-max">
        <div id="step-dot-1" class="step-dot active-step">1</div>
        <div class="h-0.5 w-10 bg-gray-300" id="step-line-1"></div>
        <div id="step-dot-2" class="step-dot">2</div>
        <div class="h-0.5 w-10 bg-gray-300" id="step-line-2"></div>
        <div id="step-dot-3" class="step-dot">3</div>
        <div class="h-0.5 w-10 bg-gray-300" id="step-line-3"></div>
        <div id="step-dot-4" class="step-dot">4</div>
      </div>
    </div>
    <div class="flex justify-center gap-12 mb-8 text-xs text-gray-500 overflow-x-auto">
      <span id="step-label-1" class="font-medium text-purple-700 whitespace-nowrap">신청자 정보</span>
      <span id="step-label-2" class="whitespace-nowrap">차량 정보</span>
      <span id="step-label-3" class="whitespace-nowrap">기술 정보</span>
      <span id="step-label-4" class="whitespace-nowrap">확인·완료</span>
    </div>

    <!-- Step 1: 신청자 정보 -->
    <div id="form-step-1" class="form-step">
      <h3 class="font-semibold text-gray-800 mb-4 pb-2 border-b"><i class="fas fa-user text-purple-500 mr-2"></i>신청자 정보</h3>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">신청 유형 <span class="text-red-500">*</span></label>
          <select id="f-cert-type" class="form-input w-full">
            <option value="">선택하세요</option>
            <option value="cert">배출가스·소음 인증신청</option>

          </select>
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">수입자(신청인) 상호 <span class="text-red-500">*</span></label>
          <input type="text" id="f-company" class="form-input w-full" placeholder="예: (주)ABC모터스" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">대표자명 <span class="text-red-500">*</span></label>
          <input type="text" id="f-ceo" class="form-input w-full" placeholder="대표자 성명" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">사업자등록번호 <span class="text-red-500">*</span></label>
          <input type="text" id="f-bizno" class="form-input w-full" placeholder="000-00-00000" maxlength="12" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">담당자명 <span class="text-red-500">*</span></label>
          <input type="text" id="f-manager" class="form-input w-full" placeholder="담당자 성명" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">연락처 <span class="text-red-500">*</span></label>
          <input type="tel" id="f-tel" class="form-input w-full" placeholder="02-0000-0000" />
        </div>
        <div class="md:col-span-2">
          <label class="block text-sm font-medium text-gray-700 mb-1">사업장 주소 <span class="text-red-500">*</span></label>
          <input type="text" id="f-addr" class="form-input w-full" placeholder="도로명 주소 입력" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">이메일</label>
          <input type="email" id="f-email" class="form-input w-full" placeholder="email@example.com" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">신청일</label>
          <input type="date" id="f-date" class="form-input w-full" />
        </div>
      </div>
    </div>

    <!-- Step 2: 차량 정보 -->
    <div id="form-step-2" class="form-step hidden">
      <h3 class="font-semibold text-gray-800 mb-4 pb-2 border-b"><i class="fas fa-car text-purple-500 mr-2"></i>차량 정보</h3>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">제작사(브랜드) <span class="text-red-500">*</span></label>
          <input type="text" id="f-brand" class="form-input w-full" placeholder="예: BMW, Mercedes-Benz" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">차종명(모델명) <span class="text-red-500">*</span></label>
          <input type="text" id="f-model" class="form-input w-full" placeholder="예: 5 Series, E-Class" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">차량 종류 <span class="text-red-500">*</span></label>
          <select id="f-vtype" class="form-input w-full">
            <option value="">선택하세요</option>
            <option value="passenger">승용차</option>
            <option value="van">승합차</option>
            <option value="truck">화물차</option>
            <option value="special">특수차</option>
            <option value="ev">전기자동차</option>
            <option value="hydrogen">수소전기자동차</option>
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">연료 종류 <span class="text-red-500">*</span></label>
          <select id="f-fuel" class="form-input w-full">
            <option value="">선택하세요</option>
            <option value="gasoline">휘발유</option>
            <option value="diesel">경유</option>
            <option value="lpg">LPG</option>
            <option value="electric">전기</option>
            <option value="hydrogen">수소</option>
            <option value="hybrid">하이브리드</option>
            <option value="phev">플러그인 하이브리드</option>
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">배기량(cc) </label>
          <input type="number" id="f-disp" class="form-input w-full" placeholder="예: 1998 (전기차는 0)" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">최고출력(kW)</label>
          <input type="text" id="f-power" class="form-input w-full" placeholder="예: 150" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">차대번호(VIN) <span class="text-red-500">*</span></label>
          <input type="text" id="f-vin" class="form-input w-full" placeholder="17자리 VIN 번호" maxlength="17" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">제작연도 <span class="text-red-500">*</span></label>
          <input type="number" id="f-year" class="form-input w-full" placeholder="예: 2024" min="2000" max="2030" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">차량 수량</label>
          <input type="number" id="f-qty" class="form-input w-full" placeholder="수입 대수" min="1" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">원산지 국가 <span class="text-red-500">*</span></label>
          <input type="text" id="f-origin" class="form-input w-full" placeholder="예: 독일, 미국, 일본" />
        </div>
      </div>
    </div>

    <!-- Step 3: 기술 정보 -->
    <div id="form-step-3" class="form-step hidden">
      <h3 class="font-semibold text-gray-800 mb-4 pb-2 border-b"><i class="fas fa-cog text-purple-500 mr-2"></i>기술 정보 및 인증 관련 사항</h3>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">배출가스 인증 기준 단계</label>
          <select id="f-emstd" class="form-input w-full">
            <option value="">선택하세요</option>
            <option value="euro6d">Euro 6d (최신)</option>
            <option value="euro6c">Euro 6c</option>
            <option value="euro6">Euro 6</option>
            <option value="tier3">Tier 3 (미국)</option>
            <option value="jnc2018">JNC2018 (일본)</option>
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">변속기 종류</label>
          <select id="f-trans" class="form-input w-full">
            <option value="">선택하세요</option>
            <option value="auto">자동변속기</option>
            <option value="manual">수동변속기</option>
            <option value="cvt">CVT</option>
            <option value="dct">DCT(이중클러치)</option>
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">촉매변환장치 장착 여부</label>
          <select id="f-cat" class="form-input w-full">
            <option value="y">예 (장착)</option>
            <option value="n">아니오 (미장착)</option>
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">OBD(자가진단) 장착 여부</label>
          <select id="f-obd" class="form-input w-full">
            <option value="y">예 (장착)</option>
            <option value="n">아니오 (미장착)</option>
          </select>
        </div>
        <div class="md:col-span-2">
          <label class="block text-sm font-medium text-gray-700 mb-1">원제작사 해외 인증 번호 (있는 경우)</label>
          <input type="text" id="f-foreign-cert" class="form-input w-full" placeholder="해외 배출가스 인증 번호 입력" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">주행소음 측정값 (dB)</label>
          <input type="text" id="f-noise" class="form-input w-full" placeholder="예: 72 dB(A)" />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">정지소음 측정값 (dB)</label>
          <input type="text" id="f-noise-static" class="form-input w-full" placeholder="예: 89 dB(A)" />
        </div>
        <div class="md:col-span-2">
          <label class="block text-sm font-medium text-gray-700 mb-1">특이사항 / 비고</label>
          <textarea id="f-note" class="form-input w-full h-20" placeholder="기타 특이사항이나 추가 설명을 입력하세요"></textarea>
        </div>
      </div>
    </div>

    <!-- Step 4: 확인·완료 -->
    <div id="form-step-4" class="form-step hidden">
      <h3 class="font-semibold text-gray-800 mb-4 pb-2 border-b"><i class="fas fa-check-circle text-purple-500 mr-2"></i>입력 내용 확인</h3>
      <div id="form-preview" class="space-y-4">
        <!-- JS로 채워짐 -->
      </div>
      <div class="mt-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg text-sm text-yellow-800">
        <i class="fas fa-exclamation-triangle mr-1"></i>
        <strong>주의:</strong> 이 내용을 확인하고 실제 신청서(KENCIS 또는 별지 제30호 서식)에 옮겨 적으시기 바랍니다. 이 시스템은 작성 보조 도구이며 법적 효력이 없습니다.
      </div>
      <div class="flex gap-3 mt-4">
        <button onclick="printForm()" class="bg-green-600 text-white px-4 py-2 rounded-lg text-sm hover:bg-green-700 transition flex items-center gap-2">
          <i class="fas fa-print"></i> 미리보기/출력
        </button>
        <button onclick="resetForm()" class="bg-gray-200 text-gray-700 px-4 py-2 rounded-lg text-sm hover:bg-gray-300 transition flex items-center gap-2">
          <i class="fas fa-redo"></i> 처음부터 다시
        </button>
      </div>
    </div>

    <!-- 네비게이션 버튼 -->
    <div class="flex justify-between mt-8 pt-4 border-t">
      <button id="btn-prev" onclick="prevStep()" class="bg-gray-100 text-gray-700 px-5 py-2.5 rounded-lg text-sm hover:bg-gray-200 transition hidden">
        <i class="fas fa-arrow-left mr-1"></i> 이전
      </button>
      <button id="btn-next" onclick="nextStep()" class="bg-purple-600 text-white px-5 py-2.5 rounded-lg text-sm hover:bg-purple-700 transition ml-auto">
        다음 <i class="fas fa-arrow-right ml-1"></i>
      </button>
    </div>
  </div>
</section>

<!-- ===== TAB: 체크리스트 ===== -->
<section id="tab-checklist" class="tab-section hidden">
  <div class="bg-white rounded-xl border border-gray-200 p-6">
    <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
      <div>
        <h2 class="text-lg font-bold text-gray-800"><i class="fas fa-tasks text-orange-600 mr-2"></i>서류 준비 체크리스트</h2>
        <p class="text-sm text-gray-500">준비된 서류를 체크하여 진행 현황을 관리하세요</p>
      </div>
      <div class="flex gap-2">
        <button onclick="setChecklistType('cert')" id="cl-btn-cert" class="cl-btn active-cl px-3 py-2 rounded-lg text-sm border font-medium">배출가스 인증</button>

      </div>
    </div>

    <!-- 진행률 바 -->
    <div class="mb-6">
      <div class="flex justify-between text-sm mb-1">
        <span class="font-medium text-gray-700">서류 준비 진행률</span>
        <span id="progress-text" class="font-bold text-orange-600">0%</span>
      </div>
      <div class="w-full bg-gray-200 rounded-full h-3">
        <div id="progress-bar" class="bg-gradient-to-r from-orange-400 to-green-500 h-3 rounded-full transition-all duration-500" style="width:0%"></div>
      </div>
    </div>

    <!-- 체크리스트 항목 -->
    <div id="checklist-items" class="space-y-2">
      <!-- JS로 채워짐 -->
    </div>

    <!-- 메모 -->
    <div class="mt-6">
      <label class="block text-sm font-medium text-gray-700 mb-2"><i class="fas fa-sticky-note mr-1"></i>메모</label>
      <textarea id="cl-memo" class="form-input w-full h-20" placeholder="준비 과정에서 특이사항이나 메모를 남기세요..."></textarea>
    </div>

    <div class="mt-4 flex gap-3">
      <button onclick="saveChecklist()" class="bg-orange-500 text-white px-4 py-2 rounded-lg text-sm hover:bg-orange-600 transition flex items-center gap-2">
        <i class="fas fa-save"></i> 저장
      </button>
      <button onclick="resetChecklist()" class="bg-gray-200 text-gray-700 px-4 py-2 rounded-lg text-sm hover:bg-gray-300 transition flex items-center gap-2">
        <i class="fas fa-redo"></i> 초기화
      </button>
    </div>
  </div>
</section>

<!-- ===== TAB: 수수료 ===== -->
<section id="tab-fee" class="tab-section hidden">
  <div class="bg-white rounded-xl border border-gray-200 p-6 mb-6">
    <h2 class="text-lg font-bold text-gray-800 mb-4"><i class="fas fa-calculator text-red-600 mr-2"></i>수수료 안내 및 계산기</h2>
    <p class="text-xs text-gray-500 mb-4">※ 2013년 3월 1일부터 부가세 10% 포함 금액</p>

    <!-- 수수료 테이블 -->
    <div class="mb-6 overflow-x-auto">
      <h3 class="font-semibold text-gray-700 mb-3">인증생략 수수료</h3>
      <table class="w-full border-collapse text-sm">
        <thead>
          <tr class="bg-red-50">
            <th class="border border-gray-200 px-4 py-2 text-left text-gray-700">구분</th>
            <th class="border border-gray-200 px-4 py-2 text-center text-gray-700">수수료(원)</th>
            <th class="border border-gray-200 px-4 py-2 text-left text-gray-700">근거 법령</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="border border-gray-200 px-4 py-2">배출가스 인증생략</td>
            <td class="border border-gray-200 px-4 py-2 text-center font-medium text-red-700">5,500원</td>
            <td class="border border-gray-200 px-4 py-2 text-gray-500 text-xs">대기환경보전법 시행규칙 제135조</td>
          </tr>
          <tr class="bg-gray-50">
            <td class="border border-gray-200 px-4 py-2">소음 인증생략</td>
            <td class="border border-gray-200 px-4 py-2 text-center font-medium text-red-700">5,500원</td>
            <td class="border border-gray-200 px-4 py-2 text-gray-500 text-xs">소음진동관리법 시행규칙 제75조</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="mb-6 overflow-x-auto">
      <h3 class="font-semibold text-gray-700 mb-3">인증생략 확인 시험 수수료</h3>
      <table class="w-full border-collapse text-sm">
        <thead>
          <tr class="bg-blue-50">
            <th class="border border-gray-200 px-4 py-2 text-left text-gray-700">검사 종류</th>
            <th class="border border-gray-200 px-4 py-2 text-center text-gray-700">구내 시험(원)</th>
            <th class="border border-gray-200 px-4 py-2 text-center text-gray-700">현지조사(원)</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="border border-gray-200 px-4 py-2">자동차 (건설기계 포함)</td>
            <td class="border border-gray-200 px-4 py-2 text-center font-medium">23,540원</td>
            <td class="border border-gray-200 px-4 py-2 text-center font-medium">140,250원</td>
          </tr>
          <tr class="bg-gray-50">
            <td class="border border-gray-200 px-4 py-2">이륜차</td>
            <td class="border border-gray-200 px-4 py-2 text-center font-medium">12,210원</td>
            <td class="border border-gray-200 px-4 py-2 text-center font-medium">98,340원</td>
          </tr>
        </tbody>
      </table>
      <p class="text-xs text-gray-500 mt-2">* 현지조사 시 여러 대 신청의 경우: 1대는 전액, 나머지는 각 25% 적용하여 합산</p>
    </div>

    <div class="mb-6 overflow-x-auto">
      <h3 class="font-semibold text-gray-700 mb-3">인증 수수료 (제작차/개별수입자)</h3>
      <table class="w-full border-collapse text-sm">
        <thead>
          <tr class="bg-green-50">
            <th class="border border-gray-200 px-4 py-2 text-left text-gray-700">신청 종류</th>
            <th class="border border-gray-200 px-4 py-2 text-center text-gray-700">수수료</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="border border-gray-200 px-4 py-2">인증 (자동차 제작자)</td>
            <td class="border border-gray-200 px-4 py-2 text-center font-medium">30만원</td>
          </tr>
          <tr class="bg-gray-50">
            <td class="border border-gray-200 px-4 py-2">인증 (이륜자동차 제작자)</td>
            <td class="border border-gray-200 px-4 py-2 text-center font-medium">10만원</td>
          </tr>
          <tr>
            <td class="border border-gray-200 px-4 py-2">인증 (개별자동차 수입자)</td>
            <td class="border border-gray-200 px-4 py-2 text-center font-medium text-green-700">1만원</td>
          </tr>
          <tr class="bg-gray-50">
            <td class="border border-gray-200 px-4 py-2">인증생략</td>
            <td class="border border-gray-200 px-4 py-2 text-center font-medium text-green-700">5천원</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 수수료 계산기 -->
    <div class="bg-gray-50 rounded-xl border border-gray-200 p-5">
      <h3 class="font-semibold text-gray-800 mb-4"><i class="fas fa-calculator text-red-500 mr-2"></i>수수료 자동 계산기</h3>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">신청 유형</label>
          <select id="fee-type" class="form-input w-full" onchange="calcFee()">
            <option value="">선택하세요</option>
            <option value="cert-individual">인증신청 (개별수입자)</option>
            <option value="cert-maker">인증신청 (자동차 제작자)</option>
            <option value="omit">인증생략 신청</option>
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">차량 유형</label>
          <select id="fee-vehicle" class="form-input w-full" onchange="calcFee()">
            <option value="car">자동차</option>
            <option value="two-wheel">이륜차</option>
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">소음 인증 포함</label>
          <select id="fee-noise" class="form-input w-full" onchange="calcFee()">
            <option value="yes">예 (배출가스+소음)</option>
            <option value="no">아니오 (배출가스만)</option>
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">현지조사 여부 (인증생략 시)</label>
          <select id="fee-onsite" class="form-input w-full" onchange="calcFee()">
            <option value="no">아니오 (구내 시험)</option>
            <option value="yes">예 (현지조사)</option>
          </select>
        </div>
        <div id="fee-qty-wrap">
          <label class="block text-sm font-medium text-gray-700 mb-1">현지조사 차량 수 (현지조사 시)</label>
          <input type="number" id="fee-qty" class="form-input w-full" value="1" min="1" onchange="calcFee()" />
        </div>
      </div>

      <!-- 계산 결과 -->
      <div id="fee-result" class="bg-white rounded-lg border-2 border-red-200 p-4 hidden">
        <h4 class="font-semibold text-gray-800 mb-3 text-sm">계산 결과</h4>
        <div id="fee-breakdown" class="space-y-2 text-sm text-gray-600 mb-3"></div>
        <div class="border-t pt-3 flex items-center justify-between">
          <span class="font-bold text-gray-800">합계</span>
          <span id="fee-total" class="text-xl font-bold text-red-700"></span>
        </div>
      </div>
    </div>
  </div>
</section>

</main>

<!-- Footer -->
<footer class="bg-gray-800 text-gray-300 text-center py-4 text-xs mt-8">
  <p>본 시스템은 수입자동차 인증신청 보조 도구입니다. 법적 효력이 없으며 실제 신청은 KENCIS(kencis.mcee.go.kr) 또는 한국환경공단을 통해 진행하세요.</p>
  <p class="mt-1 text-gray-500">근거법령: 대기환경보전법 제48조 · 소음진동관리법 · 대기환경보전법 시행규칙 제64조</p>
</footer>

<script src="/static/app.js"></script>
</body>
</html>`)
})

export default app

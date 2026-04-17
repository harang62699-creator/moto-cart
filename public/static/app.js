// =============================================
// 수입자동차 배출가스·소음 인증신청 지원 시스템
// =============================================

// ===== 탭 전환 =====
function showTab(tabId) {
  document.querySelectorAll('.tab-section').forEach(s => s.classList.add('hidden'));
  document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active-tab'));
  const section = document.getElementById(tabId);
  if (section) section.classList.remove('hidden');
  const navMap = {
    'tab-home': 'nav-home',
    'tab-guide': 'nav-guide',
    'tab-docs-cert': 'nav-docs-cert',
    'tab-form': 'nav-form',
    'tab-checklist': 'nav-checklist',
    'tab-fee': 'nav-fee'
  };
  const navId = navMap[tabId];
  if (navId) document.getElementById(navId)?.classList.add('active-tab');

  // 체크리스트 탭 열릴 때 렌더
  if (tabId === 'tab-checklist') renderChecklist();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}


// ===== 신청서 작성 (다단계 폼) =====
let currentStep = 1;
const totalSteps = 4;

function updateStepUI() {
  for (let i = 1; i <= totalSteps; i++) {
    const dot = document.getElementById('step-dot-' + i);
    const label = document.getElementById('step-label-' + i);
    const line = document.getElementById('step-line-' + i);
    const step = document.getElementById('form-step-' + i);

    if (!dot) continue;

    if (i < currentStep) {
      dot.className = 'step-dot done-step';
      dot.innerHTML = '<i class="fas fa-check text-xs"></i>';
      if (line) line.classList.replace('bg-gray-300', 'bg-green-400');
    } else if (i === currentStep) {
      dot.className = 'step-dot active-step';
      dot.textContent = i;
      if (label) { label.className = 'font-medium text-purple-700 whitespace-nowrap'; }
    } else {
      dot.className = 'step-dot';
      dot.textContent = i;
      if (label) { label.className = 'whitespace-nowrap text-gray-400'; }
      if (line) line.classList.replace('bg-green-400', 'bg-gray-300');
    }

    if (step) {
      step.classList.toggle('hidden', i !== currentStep);
    }
  }

  const prevBtn = document.getElementById('btn-prev');
  const nextBtn = document.getElementById('btn-next');
  if (prevBtn) prevBtn.classList.toggle('hidden', currentStep === 1);
  if (nextBtn) {
    if (currentStep === totalSteps) {
      nextBtn.classList.add('hidden');
    } else {
      nextBtn.classList.remove('hidden');
      nextBtn.innerHTML = currentStep === totalSteps - 1
        ? '완료 <i class="fas fa-check ml-1"></i>'
        : '다음 <i class="fas fa-arrow-right ml-1"></i>';
    }
  }
}

function nextStep() {
  if (currentStep < totalSteps) {
    if (!validateStep(currentStep)) return;
    currentStep++;
    if (currentStep === totalSteps) buildPreview();
    updateStepUI();
    document.getElementById('tab-form')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function prevStep() {
  if (currentStep > 1) {
    currentStep--;
    updateStepUI();
  }
}

function validateStep(step) {
  const requiredMap = {
    1: ['f-cert-type', 'f-company', 'f-ceo', 'f-bizno', 'f-manager', 'f-tel'],
    2: ['f-brand', 'f-model', 'f-vtype', 'f-fuel', 'f-vin', 'f-year', 'f-origin'],
    3: []
  };
  const required = requiredMap[step] || [];
  let valid = true;
  required.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    if (!el.value.trim()) {
      el.style.borderColor = '#ef4444';
      el.style.boxShadow = '0 0 0 3px rgba(239,68,68,0.15)';
      valid = false;
      setTimeout(() => {
        el.style.borderColor = '';
        el.style.boxShadow = '';
      }, 2500);
    }
  });
  if (!valid) showToast('⚠️ 필수 항목을 입력해 주세요.');
  return valid;
}

function getVal(id) {
  const el = document.getElementById(id);
  return el ? el.value.trim() : '';
}

function buildPreview() {
  const certTypeMap = { cert: '배출가스·소음 인증신청' };
  const vtypeMap = { passenger: '승용차', van: '승합차', truck: '화물차', special: '특수차', ev: '전기자동차', hydrogen: '수소전기자동차' };
  const fuelMap = { gasoline: '휘발유', diesel: '경유', lpg: 'LPG', electric: '전기', hydrogen: '수소', hybrid: '하이브리드', phev: '플러그인 하이브리드' };
  const transMap = { auto: '자동변속기', manual: '수동변속기', cvt: 'CVT', dct: 'DCT' };

  const data = [
    { title: '신청자 정보', rows: [
      ['신청 유형', certTypeMap[getVal('f-cert-type')] || '-'],
      ['수입자 상호', getVal('f-company')],
      ['대표자명', getVal('f-ceo')],
      ['사업자등록번호', getVal('f-bizno')],
      ['담당자', getVal('f-manager')],
      ['연락처', getVal('f-tel')],
      ['주소', getVal('f-addr')],
      ['이메일', getVal('f-email')],
      ['신청일', getVal('f-date')]
    ]},
    { title: '차량 정보', rows: [
      ['제작사(브랜드)', getVal('f-brand')],
      ['차종명(모델)', getVal('f-model')],
      ['차량 종류', vtypeMap[getVal('f-vtype')] || getVal('f-vtype')],
      ['연료 종류', fuelMap[getVal('f-fuel')] || getVal('f-fuel')],
      ['배기량', getVal('f-disp') ? getVal('f-disp') + ' cc' : '-'],
      ['최고출력', getVal('f-power') ? getVal('f-power') + ' kW' : '-'],
      ['차대번호(VIN)', getVal('f-vin')],
      ['제작연도', getVal('f-year')],
      ['수량', getVal('f-qty') ? getVal('f-qty') + ' 대' : '-'],
      ['원산지', getVal('f-origin')]
    ]},
    { title: '기술 정보', rows: [
      ['배출가스 기준', getVal('f-emstd')],
      ['변속기', transMap[getVal('f-trans')] || '-'],
      ['촉매변환장치', getVal('f-cat') === 'y' ? '장착' : '미장착'],
      ['OBD 장착', getVal('f-obd') === 'y' ? '장착' : '미장착'],
      ['해외 인증번호', getVal('f-foreign-cert') || '-'],
      ['주행소음', getVal('f-noise') ? getVal('f-noise') + ' dB(A)' : '-'],
      ['정지소음', getVal('f-noise-static') ? getVal('f-noise-static') + ' dB(A)' : '-'],
      ['비고', getVal('f-note') || '-']
    ]}
  ];

  const container = document.getElementById('form-preview');
  if (!container) return;
  container.innerHTML = data.map(section => `
    <div class="border border-gray-200 rounded-lg overflow-hidden">
      <div class="bg-purple-50 px-4 py-2 font-semibold text-purple-800 text-sm">${section.title}</div>
      <table class="w-full text-sm">
        ${section.rows.map(([k, v]) => `
          <tr class="border-t border-gray-100">
            <td class="px-4 py-2 text-gray-500 w-40 font-medium">${k}</td>
            <td class="px-4 py-2 text-gray-800">${v || '-'}</td>
          </tr>`).join('')}
      </table>
    </div>
  `).join('');
}

function printForm() {
  const preview = document.getElementById('form-preview');
  if (!preview) return;
  const win = window.open('', '_blank');
  win.document.write(`
    <html><head><title>수입자동차 인증신청서</title>
    <style>
      body { font-family: 'Malgun Gothic', sans-serif; padding: 20px; }
      h1 { font-size: 18pt; text-align: center; border-bottom: 2px solid #333; padding-bottom: 10px; margin-bottom: 20px; }
      h2 { font-size: 12pt; background: #f3f4f6; padding: 8px 12px; margin-top: 16px; }
      table { width: 100%; border-collapse: collapse; font-size: 10pt; }
      td { border: 1px solid #ddd; padding: 6px 10px; }
      td:first-child { background: #f9f9f9; width: 30%; font-weight: bold; }
      .footer { margin-top: 30px; font-size: 9pt; color: #666; text-align: center; border-top: 1px solid #eee; padding-top: 10px; }
    </style></head>
    <body>
      <h1>수입자동차 배출가스·소음 인증신청서</h1>
      ${preview.innerHTML.replace(/class="[^"]*"/g, '')}
      <div class="footer">※ 이 문서는 작성 보조 목적으로 생성된 것이며 법적 효력이 없습니다. 실제 신청은 KENCIS(kencis.mcee.go.kr)를 이용하세요.</div>
    </body></html>
  `);
  win.document.close();
  setTimeout(() => win.print(), 500);
}

function resetForm() {
  if (!confirm('작성 내용을 초기화하겠습니까?')) return;
  document.querySelectorAll('.form-input').forEach(el => {
    if (el.tagName === 'SELECT') el.selectedIndex = 0;
    else el.value = '';
  });
  currentStep = 1;
  updateStepUI();
  showToast('✅ 초기화되었습니다.');
}

// ===== 체크리스트 데이터 =====
const CHECKLIST_DATA = {
  cert: [
    { id: 'c1', text: '배출가스 감지·저감장치 구성에 관한 서류', note: '엔진 배출가스 저감 시스템 기술 문서', required: true },
    { id: 'c2', text: '연료효율 관련 장치 구성에 관한 서류', note: '연료계통 구성도, 연비 관련 데이터', required: true },
    { id: 'c3', text: '인증에 필요한 세부계획 서류', note: '별지 제4호 서식 (전기차는 별지 제4의2호)', required: true },
    { id: 'c4', text: '자동차배출가스 시험결과 보고 서류', note: '국립환경과학원 또는 공인시험기관 발급', required: true },
    { id: 'c5', text: '배출가스 보증 제작자 확인서 또는 계약서', note: '제작자-수입자 간 보증 계약서', required: true },
    { id: 'c6', text: '제작차 배출허용기준 관련 사항', note: '저공해차 배출허용기준 포함', required: true },
    { id: 'c7', text: 'OBD(자가진단장치) 구성 서류', note: '해당 차량 OBD 장착 여부 확인 후 제출', required: false },
    { id: 'c8', text: '소음저감장치 구성 서류', note: '소음 인증 신청 시 필수', required: true },
    { id: 'c9', text: '소음시험 결과보고서', note: '주행소음·정지소음 측정치 포함', required: true },
    { id: 'c10', text: '인증신청서 (별지 제30호 서식)', note: 'KENCIS 온라인 또는 서면 작성', required: true },
    { id: 'c11', text: '수수료 납부 영수증', note: '개별수입자: 1만원', required: true },
    { id: 'c12', text: '배출가스 이행 보증보험증권', note: '보증보험회사 발급', required: true },
  ],

};

let currentChecklistType = 'cert';
let checklistState = {};

function setChecklistType(type) {
  currentChecklistType = type;
  document.querySelectorAll('.cl-btn').forEach(b => b.classList.remove('active-cl'));
  const btn = document.getElementById('cl-btn-' + type);
  if (btn) btn.classList.add('active-cl');
  renderChecklist();
}

function renderChecklist() {
  const items = CHECKLIST_DATA[currentChecklistType] || [];
  const container = document.getElementById('checklist-items');
  if (!container) return;

  // 저장된 상태 불러오기
  const savedKey = 'checklist_' + currentChecklistType;
  const saved = JSON.parse(localStorage.getItem(savedKey) || '{}');

  container.innerHTML = items.map((item, idx) => {
    const isChecked = saved[item.id] === true;
    return `
      <div class="checklist-item ${isChecked ? 'checked' : ''}" id="cl-item-${item.id}" onclick="toggleCheck('${item.id}')">
        <input type="checkbox" id="ck-${item.id}" ${isChecked ? 'checked' : ''} onclick="event.stopPropagation(); toggleCheck('${item.id}')" />
        <div class="flex-1">
          <div class="flex items-center gap-2 flex-wrap">
            <span class="cl-label font-medium text-sm text-gray-800">${idx + 1}. ${item.text}</span>
            ${item.required
              ? '<span class="badge-required">필수</span>'
              : '<span style="background:#f3f4f6;color:#6b7280;font-size:0.65rem;padding:1px 7px;border-radius:9999px;font-weight:600;">해당시</span>'}
          </div>
          <p class="text-xs text-gray-500 mt-0.5">${item.note}</p>
        </div>
        <div class="flex-shrink-0">
          ${isChecked
            ? '<i class="fas fa-check-circle text-green-500 text-lg"></i>'
            : '<i class="far fa-circle text-gray-300 text-lg"></i>'}
        </div>
      </div>`;
  }).join('');

  updateProgress();
}

function toggleCheck(id) {
  const savedKey = 'checklist_' + currentChecklistType;
  const saved = JSON.parse(localStorage.getItem(savedKey) || '{}');
  saved[id] = !saved[id];
  localStorage.setItem(savedKey, JSON.stringify(saved));
  renderChecklist();
}

function updateProgress() {
  const items = CHECKLIST_DATA[currentChecklistType] || [];
  const savedKey = 'checklist_' + currentChecklistType;
  const saved = JSON.parse(localStorage.getItem(savedKey) || '{}');
  const total = items.length;
  const done = items.filter(i => saved[i.id] === true).length;
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;

  const bar = document.getElementById('progress-bar');
  const txt = document.getElementById('progress-text');
  if (bar) bar.style.width = pct + '%';
  if (txt) {
    txt.textContent = pct + '% (' + done + '/' + total + ')';
    txt.style.color = pct === 100 ? '#16a34a' : pct >= 50 ? '#d97706' : '#ea580c';
  }
}

function saveChecklist() {
  const memo = document.getElementById('cl-memo')?.value || '';
  localStorage.setItem('checklist_memo_' + currentChecklistType, memo);
  showToast('✅ 저장되었습니다.');
}

function resetChecklist() {
  if (!confirm('체크리스트를 초기화하겠습니까?')) return;
  const savedKey = 'checklist_' + currentChecklistType;
  localStorage.removeItem(savedKey);
  const memo = document.getElementById('cl-memo');
  if (memo) memo.value = '';
  renderChecklist();
  showToast('✅ 초기화되었습니다.');
}

// ===== 수수료 계산기 =====
function calcFee() {
  const type = document.getElementById('fee-type')?.value;
  const vehicle = document.getElementById('fee-vehicle')?.value;
  const noise = document.getElementById('fee-noise')?.value;
  const onsite = document.getElementById('fee-onsite')?.value;
  const qty = parseInt(document.getElementById('fee-qty')?.value || '1');

  const result = document.getElementById('fee-result');
  const breakdown = document.getElementById('fee-breakdown');
  const totalEl = document.getElementById('fee-total');

  if (!type) {
    if (result) result.classList.add('hidden');
    return;
  }

  let items = [];
  let total = 0;

  if (type === 'cert-individual') {
    items.push({ label: '인증신청 수수료 (개별자동차 수입자)', amount: 10000 });
    total += 10000;
  } else if (type === 'cert-maker') {
    const amt = vehicle === 'two-wheel' ? 100000 : 300000;
    items.push({ label: `인증신청 수수료 (${vehicle === 'two-wheel' ? '이륜' : ''}자동차 제작자)`, amount: amt });
    total += amt;
  } else if (type === 'omit') {
    items.push({ label: '배출가스 인증생략 수수료', amount: 5500 });
    total += 5500;
    if (noise === 'yes') {
      items.push({ label: '소음 인증생략 수수료', amount: 5500 });
      total += 5500;
    }
  }

  // 확인 시험 수수료 (인증생략 대상 차량 확인)
  if (type === 'omit') {
    const baseAmt = vehicle === 'two-wheel'
      ? (onsite === 'yes' ? 98340 : 12210)
      : (onsite === 'yes' ? 140250 : 23540);

    if (onsite === 'yes' && qty > 1) {
      const addAmt = Math.round(baseAmt * 0.25) * (qty - 1);
      items.push({ label: `확인 시험 수수료 (현지조사, 1대)`, amount: baseAmt });
      items.push({ label: `확인 시험 수수료 (추가 ${qty - 1}대 × 25%)`, amount: addAmt });
      total += baseAmt + addAmt;
    } else {
      items.push({ label: `확인 시험 수수료 (${onsite === 'yes' ? '현지조사' : '구내시험'})`, amount: baseAmt });
      total += baseAmt;
    }
  }

  if (result) result.classList.remove('hidden');
  if (breakdown) {
    breakdown.innerHTML = items.map(i =>
      `<div class="flex justify-between"><span>${i.label}</span><span class="font-medium text-gray-800">${i.amount.toLocaleString()}원</span></div>`
    ).join('');
  }
  if (totalEl) totalEl.textContent = total.toLocaleString() + '원';
}

// ===== 토스트 알림 =====
function showToast(msg) {
  let toast = document.getElementById('toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toast';
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2500);
}

// ===== 초기화 =====
document.addEventListener('DOMContentLoaded', () => {
  // 오늘 날짜 기본값 설정
  const dateEl = document.getElementById('f-date');
  if (dateEl) dateEl.value = new Date().toISOString().split('T')[0];

  // 폼 단계 초기화
  updateStepUI();

  // 체크리스트 메모 복원
  const savedMemo = localStorage.getItem('checklist_memo_cert');
  if (savedMemo) {
    const memo = document.getElementById('cl-memo');
    if (memo) memo.value = savedMemo;
  }

  // 사업자번호 자동 포맷
  const bizno = document.getElementById('f-bizno');
  if (bizno) {
    bizno.addEventListener('input', function () {
      let v = this.value.replace(/\D/g, '');
      if (v.length > 3) v = v.slice(0,3) + '-' + v.slice(3);
      if (v.length > 6) v = v.slice(0,6) + '-' + v.slice(6);
      this.value = v.slice(0, 12);
    });
  }

  // VIN 대문자 자동 변환
  const vin = document.getElementById('f-vin');
  if (vin) {
    vin.addEventListener('input', function () {
      this.value = this.value.toUpperCase();
    });
  }
});

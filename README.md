# registry_analysis_tools
# Windows Registry Forensic Analyzer v4.0

> 레지스트리 바이너리 하이브에서 포렌식 아티팩트를 자동 추출하고,
> 
> 
> **Multi-Hive 상관관계 분석 + AI 인사이트**까지 제공하는 통합 분석 도구
> 

---

## Overview

Windows Registry는 운영체제 설정, 사용자 활동, 프로그램 실행/설치 이력 등 **디지털 포렌식의 핵심 단서**를 담고 있다.

본 도구는 레지스트리 하이브를 **바이너리 레벨에서 직접 파싱**해, 분석가가 즉시 활용 가능한 포렌식 아티팩트를 구조화된 결과로 출력한다.

---

## Key Features

- **20개 포렌식 아티팩트 타입 자동 추출**
- **Multi-Hive 통합 분석**
    - 7개 하이브를 동시에 분석
    - Cross-Hive 상관관계 자동 탐지
- **AI 기반 자동 해석**
    - Gemini / OpenAI Provider 선택 지원
- **반응형 GUI**
    - 모니터 크기 자동 최적화
    - 패널 크기 드래그 조절
    - 파일 목록 자동 접기/펼치기

---

## Project Structure

```
registry-analyzer-v4/
├── core/
│   └── registry_parser.py       # 레지스트리 바이너리 파서
├── analyzers/
│   ├── forensics_analyzer.py    # 20개 포렌식 모듈
│   ├── multi_hive_analyzer.py   # Multi-Hive 상관관계 분석
│   └── ai_analyzer.py           # AI 분석 (Gemini/OpenAI)
├── gui/
│   └── main_window.py           # Tkinter GUI
└── main.py                      # 메인 실행 파일

```

---

## Installation & Run

```bash
# 필수 패키지 설치
pip install python-registry requests

# GUI 실행
python3 main.py

```

---

## How It Works

### 1) Binary Parsing

레지스트리 파일은 바이너리 포맷이므로 텍스트로 열면 의미 있는 정보를 얻기 어렵다.

본 도구는 **바이너리에서 특정 문자열/구조 패턴을 탐지한 뒤 주변 바이트를 복원**해 아티팩트를 추출한다.

**ShimCache 추출 예시**

```python
def analyze_shimcache(self):
    results = []
    patterns = ['.exe', '.dll', '.sys', '.scr']

    for pattern in patterns:
        offsets = self.parser.search_pattern(pattern)

        for offset in offsets:
            path = self._extract_shimcache_path(offset)
            timestamp = self._extract_shimcache_timestamp(offset)
            file_size = self._extract_shimcache_filesize(offset)

            if path and ':\\' in path:
                results.append({
                    'path': path,
                    'timestamp': timestamp,
                    'fileSize': file_size
                })

    return results

```

**동작 흐름**

1. 바이너리 데이터에서 실행 파일 확장자 패턴 탐색
2. 오프셋 주변 데이터를 기반으로 경로 문자열 복원
3. 인접 영역에서 FILETIME, 파일 크기 등 메타데이터 추출
4. 중복 제거 후 결과화

---

### 2) ROT13 Decoding (UserAssist)

UserAssist는 사용자 실행 기록을 저장하지만 **ROT13 인코딩**되어 있어 디코딩이 필요하다.

```python
def analyze_userassist(self):
    results = []

    patterns = [
        'HRZR_PGYFRFFVBA',  # ROT13: UEME_CTLSESSION
        'HRZR_EHAPZH'       # ROT13: UEME_RUNPMU
    ]

    for pattern in patterns:
        offsets = self.parser.search_pattern(pattern)

        for offset in offsets:
            context = self._get_context_strings(offset, 200)

            for ctx in context:
                decoded = self._rot13_decode(ctx)

                if self._is_valid_path(decoded):
                    run_count = self._extract_userassist_runcount(offset)
                    focus_time = self._extract_userassist_focustime(offset)

                    results.append({
                        'program': decoded,
                        'runCount': run_count,
                        'focusTime': focus_time
                    })

    return results

```

**ROT13 변환 예시**

- `HRZR_PGYFRFFVBA` → `UEME_CTLSESSION`
- `C:\Cebtenz Svyrf\...` → `C:\Program Files\...`

---

### 3) SHA1 Hash Extraction (Amcache)

Amcache는 프로그램 설치/실행 메타데이터와 함께 **SHA1 해시**를 포함한다.

```python
def analyze_amcache(self):
    results = []
    patterns = ['.exe', '.dll', '.sys', '.msi']

    for pattern in patterns:
        offsets = self.parser.search_pattern(pattern)

        for offset in offsets:
            file_path = self._extract_path_at_offset(offset)
            sha1 = self._extract_sha1_hash(offset)

            timestamp = self._find_nearby_timestamp(offset)
            file_size = self._extract_file_size(offset)
            publisher = self._extract_publisher(offset)
            version = self._extract_version(offset)

            results.append({
                'programName': file_path.split('\\')[-1],
                'filePath': file_path,
                'sha1': sha1,
                'timestamp': timestamp,
                'fileSize': file_size,
                'publisher': publisher,
                'version': version
            })

    return results

```

---

## Forensic Artifacts (20)

| Artifact | Extraction Method | Use Case |
| --- | --- | --- |
| ShimCache | `.exe` 패턴 → 경로 + FILETIME | 프로그램 실행 이력 |
| Amcache | `.exe` 패턴 → SHA1(20B) + 메타데이터 | 설치/실행 프로그램 식별 |
| UserAssist | ROT13 패턴 디코딩 + 실행 횟수 | 사용자 활동 |
| BAM/DAM | `\Device\HarddiskVolume` → 타임스탬프 | 실행 시점 추적 |
| USB Devices | `USB\VID_`, `USBSTOR` 패턴 | USB 연결 이력 |
| Recent Docs | `.doc`, `.pdf` 패턴 | 최근 열람 문서 |
| MuiCache | `.exe` + UI 캐시 | 프로그램 표시명 |
| Run Keys | `...\CurrentVersion\Run` | 자동 실행 |
| Services | `...\ControlSet\Services\` | 서비스 등록 |
| SAM Users | `\SAM\Domains\Account\Users\` | 계정/ SID |
| Network | `ProfileGuid`, `SSID` | 네트워크 기록 |
| Installed Software | `\Uninstall\` | 설치 프로그램 |
| MRU Lists | `ComDlg32` | 최근 사용 경로 |
| Typed URLs | `TypedURLs` | 주소창 입력 |
| ShellBags | `BagMRU` | 폴더 탐색 |
| Prefetch | `.pf` 패턴 | 실행 빈도 |
| LNK Files | `.lnk` 패턴 | 바로가기 분석 |
| Security | `\Policy\PolAdtEv` | 보안 정책 |
| TypedPaths | `TypedPaths` | 탐색기 입력 |
| RecentApps | `RecentApps` | 최근 앱 실행 |

---

## Multi-Hive Correlation

7개 하이브를 동시에 분석해 **연결된 사건/행동을 교차 검증**한다.

### Supported Hives

- SYSTEM — 시스템 설정, USB, 네트워크
- SOFTWARE — 설치/실행 기록
- SAM — 사용자 계정
- SECURITY — 정책/보안 설정
- NTUSER.DAT — 사용자 활동(UserAssist, TypedPaths)
- UsrClass.dat — UI 캐시, ShellBags
- Amcache.hve — 프로그램 상세 정보

### Correlation Patterns (7)

1. **ShimCache ↔ Amcache 매칭**

```python
def _correlate_shimcache_amcache(self):
    shimcache = self.hives['SYSTEM']['findings']['shimcache']
    amcache = self.hives['SOFTWARE']['findings']['amcache']

    shimcache_map = {item['path'].lower(): item for item in shimcache}

    for am_item in amcache:
        program_name = am_item['programName'].lower()

        for sc_path, sc_item in shimcache_map.items():
            if program_name in sc_path:
                self.correlations.append({
                    'type': 'ShimCache-Amcache Match',
                    'confidence': 'HIGH',
                    'program': program_name,
                    'shimcache_timestamp': sc_item['timestamp'],
                    'amcache_sha1': am_item['sha1'],
                    'insight': '두 하이브에서 같은 프로그램 발견 → 실행 증거 강화'
                })

```

1. **사용자 활동 패턴**
    - UserAssist + Prefetch + BAM/DAM 교차 분석
    - 특정 프로그램의 실행 빈도/시간/사용 흐름 재구성
2. **USB 사용 증거**
    - SYSTEM의 USB 연결 기록
    - Recent Docs에서 USB 드라이브 경로 접근 기록
    - 매칭 시 USB 기반 파일 접근 증거 강화
3. **네트워크 활동**
    - Network Profiles + WLAN + TypedPaths
    - 특정 네트워크 접속 시점과 접근 파일/URL 연계
4. **자동 실행 프로그램 검증**
    - Run Keys + Installed Software
    - 자동 실행 항목이 실제 설치되어 있는지 확인
5. **서비스-소프트웨어 연관**
    - Services + Installed Software
    - 서비스 등록 프로그램의 설치 메타데이터 매칭
6. **시간대 보정**
    - TimeZone 정보 기반 UTC ↔ Local 변환

---

## AI Analysis

Gemini 또는 OpenAI API를 통해 **아티팩트에 대한 자동 해석**을 제공한다.

```python
def analyze_with_gemini(api_key, hive_type, strings, raw_findings):
    prompt = f"""
    레지스트리 {hive_type} 하이브의 포렌식 데이터를 분석하세요.

    추출된 원시 데이터:
    {json.dumps(raw_findings, indent=2)}

    추출된 문자열:
    {strings}

    다음 내용을 JSON 형식으로 제공:
    - summary
    - suspiciousActivities
    - timeline
    - recommendations
    """

    response = requests.post(
        f'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}',
        json={'contents': [{'parts': [{'text': prompt}]}]}
    )

    content = response.json()['candidates'][0]['content']['parts'][0]['text']
    return json.loads(content)

```

**AI Output**

- Summary — 주요 활동 요약
- Suspicious Activities — 이상 실행/악성 경로/자동 실행 의심
- Timeline — 시간순 이벤트 재구성
- Recommendations — 추가 조사/보안 권장사항

---

## GUI Highlights

### Responsive Layout

**자동 화면 맞춤**

```python
screen_width = self.root.winfo_screenwidth()
screen_height = self.root.winfo_screenheight()

window_width = int(screen_width * 0.85)
window_height = int(screen_height * 0.85)

window_width = max(1000, min(window_width, 1920))
window_height = max(700, min(window_height, 1080))

x = (screen_width - window_width) // 2
y = (screen_height - window_height) // 2

self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")

```

**좌우 드래그 패널**

```python
main_container = tk.PanedWindow(
    self.root,
    orient=tk.HORIZONTAL,
    sashrelief=tk.RAISED,
    sashwidth=5
)

```

**파일 목록 토글**

```python
def toggle_file_list(self):
    if self.file_list_visible.get():
        self.file_list_container.pack_forget()
        self.toggle_btn.config(text="▼ 펼치기")
    else:
        self.file_list_container.pack(fill=tk.BOTH, expand=True)
        self.toggle_btn.config(text="▲ 접기")

if count > 0:
    self.root.after(500, self.toggle_file_list)

```

---

## Usage

### Single Hive

```
1) AI Provider 선택 (Gemini)
2) API Key 입력
3) SYSTEM 하이브 선택
4) 분석 시작

```

**Output**

- ShimCache / USB / Services 등 하이브 기반 결과
- AI Insight 자동 생성

---

### Multi-Hive (Recommended)

```
1) 7개 하이브 전체 선택
   SYSTEM / SOFTWARE / SAM / SECURITY / NTUSER.DAT / UsrClass.dat / Amcache.hve

2) Multi-Hive 분석 실행

```

**Output Sections**

1. DETAILED ARTIFACTS
2. CROSS-HIVE CORRELATIONS
3. UNIFIED TIMELINE
4. AI-POWERED ANALYSIS

---

### Type-safe Timeline Sort

```python
def safe_sort_key(event):
    timestamp = event.get('timestamp')

    if isinstance(timestamp, datetime):
        return timestamp
    elif isinstance(timestamp, str):
        try:
            return datetime.fromisoformat(timestamp)
        except:
            return datetime.min
    else:
        return datetime.min

timeline.sort(key=safe_sort_key)

```

---

### Deduplication

```python
def _deduplicate_shimcache_entries(results):
    seen = {}
    unique = []

    for item in results:
        path = item['path'].lower()
        if path not in seen:
            seen[path] = True
            unique.append(item)

    return unique

```

---

## Performance

- Single Hive: ~5s
- Multi-Hive (7): ~20s
- AI Analysis: ~10s (Gemini) / ~15s (OpenAI)

Memory

- Single Hive: ~50MB
- Multi-Hive: ~150MB

---

## Limitations

1. **Binary Parsing Uncertainty**
    - 문자열 경계/타임포맷 판별 100% 보장 불가
    - 삭제·손상 데이터 복원 불가
2. **AI Interpretation**
    - API 비용/인터넷 필요
    - 품질 변동 (특히 Gemini)
    - JSON 파싱 실패 가능성
        - Gemini ~10% / OpenAI ~1%
3. **GUI Freeze**
    - Multi-Hive 분석 중 20초 전후 UI 정지
    - 메인 스레드 처리 구조 때문

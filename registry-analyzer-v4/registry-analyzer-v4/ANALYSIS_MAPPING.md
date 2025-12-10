# Windows Registry Forensic Analyzer - 분석 모듈 매핑 가이드

## 📋 전체 분석 모듈 (15개)

v3.0에서는 **총 15개의 포렌식 분석 모듈**을 제공합니다.

---

## 🗂️ 레지스트리 하이브별 분석 가능 모듈

### 1. SYSTEM 하이브
**파일 위치**: `C:\Windows\System32\config\SYSTEM`

| 분석 모듈 | 설명 | 주요 정보 |
|----------|------|----------|
| 🚀 **ShimCache** | 실행된 프로그램 추적 | 실행 파일 경로, 타임스탬프, 파일 크기 |
| 🎯 **BAM/DAM** | 백그라운드 활동 모니터 | 프로그램 실행 이력, 실행 시간 |
| 🔌 **USB Devices** | USB 장치 연결 이력 | 장치 이름, 벤더 ID, 시리얼 번호 |
| 🌐 **Network Profiles** | 네트워크 연결 프로필 | SSID, 연결 타입, 마지막 연결 시간 |

**사용 시나리오**: 시스템 부팅 정보, USB 사용 내역, 네트워크 연결 이력 분석

---

### 2. SOFTWARE 하이브
**파일 위치**: `C:\Windows\System32\config\SOFTWARE`

| 분석 모듈 | 설명 | 주요 정보 |
|----------|------|----------|
| 🚀 **ShimCache** | 실행된 프로그램 추적 (SYSTEM과 동일) | 실행 파일 경로, 타임스탬프 |
| 📦 **Amcache** | 응용 프로그램 호환성 캐시 | 프로그램 경로, SHA1 해시, 설치 날짜 |
| ⚡ **Prefetch** | 프로그램 실행 최적화 캐시 | 프로그램 이름, 실행 횟수, 마지막 실행 |
| 🏃 **Run Keys** | 자동 시작 프로그램 | 프로그램 이름, 실행 경로 |
| 💿 **Installed Software** | 설치된 소프트웨어 상세 | 프로그램 이름, 버전, 게시자, 설치 날짜, 크기 |

**사용 시나리오**: 설치된 프로그램 목록, 자동 실행 프로그램, 응용 프로그램 실행 이력

---

### 3. NTUSER.DAT (사용자별 하이브)
**파일 위치**: `C:\Users\[Username]\NTUSER.DAT`

| 분석 모듈 | 설명 | 주요 정보 |
|----------|------|----------|
| 👤 **UserAssist** | 사용자 활동 추적 (ROT13 암호화) | 실행 프로그램, 실행 횟수, 포커스 시간 |
| 📁 **ShellBags** | 탐색기 폴더 접근 이력 | 폴더 경로, 접근 시간 |
| 🎨 **MuiCache** | 응용 프로그램 UI 캐시 | 실행 파일 경로, 응용 프로그램 이름 |
| 📄 **Recent Docs** | 최근 문서 이력 | 파일 경로, 확장자, 타임스탬프 |
| 🔗 **LNK Files** | 바로가기 파일 이력 | 바로가기 경로, 타겟 경로, 생성 시간 |
| 🏃 **Run Keys** | 사용자별 자동 시작 프로그램 | 프로그램 이름, 경로 |

**사용 시나리오**: 개별 사용자 활동 분석, 파일 접근 이력, 프로그램 사용 패턴

---

### 4. UsrClass.dat (사용자 클래스 하이브)
**파일 위치**: `C:\Users\[Username]\AppData\Local\Microsoft\Windows\UsrClass.dat`

| 분석 모듈 | 설명 | 주요 정보 |
|----------|------|----------|
| 📁 **ShellBags** | 탐색기 폴더 접근 이력 (확장) | 폴더 경로, 뷰 설정 |
| 🎨 **MuiCache** | 응용 프로그램 UI 캐시 | 실행 파일 경로 |
| 🔗 **LNK Files** | 바로가기 파일 이력 | 바로가기 경로, 타겟 |

**사용 시나리오**: NTUSER.DAT와 함께 사용자 활동 종합 분석

---

### 5. SAM 하이브
**파일 위치**: `C:\Windows\System32\config\SAM`

| 분석 모듈 | 설명 | 주요 정보 |
|----------|------|----------|
| 👥 **SAM Users** | 로컬 사용자 계정 정보 | 사용자 이름, RID, 마지막 로그인, 로그인 카운트 |

**사용 시나리오**: 로컬 계정 관리, 사용자 로그인 이력 분석

---

### 6. SECURITY 하이브
**파일 위치**: `C:\Windows\System32\config\SECURITY`

| 분석 모듈 | 설명 | 주요 정보 |
|----------|------|----------|
| 🔐 **Security Detailed** | 보안 정책 및 권한 분석 | 정책 키, SID, 정책 값, SID 타입 |

**사용 시나리오**: 보안 정책 검토, 권한 분석, LSA Secrets

---

### 7. Amcache.hve
**파일 위치**: `C:\Windows\AppCompat\Programs\Amcache.hve`

| 분석 모듈 | 설명 | 주요 정보 |
|----------|------|----------|
| 📦 **Amcache** | 응용 프로그램 실행 캐시 | 프로그램 경로, SHA1, 실행 시간 |
| ⚡ **Prefetch** | 프리패치 참조 | 프로그램 이름, 실행 횟수 |

**사용 시나리오**: 프로그램 실행 이력 상세 분석, 해시 값 추출

---

## 📊 분석 모듈 상세 설명

### 🚀 1. ShimCache (AppCompatCache)
- **대상 하이브**: SYSTEM, SOFTWARE
- **목적**: Windows 응용 프로그램 호환성을 위해 실행된 파일 추적
- **포렌식 가치**: 
  - 실행된 프로그램 전체 경로
  - 실행 시간 (FILETIME)
  - 파일 크기
  - 삭제된 파일도 추적 가능
- **주의사항**: 실행 여부만 기록, 실행 횟수는 기록 안 됨

---

### 📦 2. Amcache
- **대상 하이브**: SOFTWARE, Amcache.hve
- **목적**: Windows 7 이후 ShimCache 보완용 응용 프로그램 캐시
- **포렌식 가치**:
  - 프로그램 전체 경로
  - SHA1 파일 해시 (파일 무결성 검증)
  - 설치 날짜
  - 프로그램 버전 정보
- **주의사항**: Windows 8 이후에만 존재

---

### 👤 3. UserAssist
- **대상 하이브**: NTUSER.DAT
- **목적**: 사용자가 실행한 프로그램 추적 (ROT13 암호화)
- **포렌식 가치**:
  - 실행 프로그램 이름 (ROT13 디코딩 필요)
  - 실행 횟수
  - 포커스 시간 (프로그램 사용 시간)
  - 마지막 실행 시간
- **특징**: GUI 프로그램만 추적, 콘솔 프로그램은 제외

---

### 🎯 4. BAM/DAM
- **대상 하이브**: SYSTEM
- **목적**: Windows 10+ 백그라운드 활동 모니터링
- **포렌식 가치**:
  - 프로그램 실행 경로
  - 정확한 마지막 실행 시간
  - 사용자별 실행 이력
- **주의사항**: Windows 10 1709 이상에서만 사용 가능

---

### 📁 5. ShellBags
- **대상 하이브**: NTUSER.DAT, UsrClass.dat
- **목적**: 탐색기 폴더 접근 이력 및 뷰 설정 추적
- **포렌식 가치**:
  - 폴더 경로 (네트워크 경로 포함)
  - 마지막 접근 시간
  - 폴더 뷰 설정 (아이콘, 리스트 등)
  - 삭제된 폴더도 추적 가능
- **특징**: USB, 네트워크 드라이브 접근도 기록

---

### 🎨 6. MuiCache
- **대상 하이브**: NTUSER.DAT, UsrClass.dat
- **목적**: 응용 프로그램 UI 언어 캐시
- **포렌식 가치**:
  - 실행 파일 전체 경로
  - 응용 프로그램 친근한 이름 (FriendlyAppName)
  - 실행 시간
- **특징**: GUI 프로그램의 표시 이름 추적

---

### ⚡ 7. Prefetch
- **대상 하이브**: SOFTWARE, Amcache.hve, NTUSER.DAT
- **목적**: 프로그램 실행 최적화를 위한 캐시
- **포렌식 가치**:
  - 프로그램 이름 (.pf 파일)
  - 실행 횟수
  - 마지막 실행 시간
  - 참조 파일 목록
- **주의사항**: 레지스트리에는 참조만, 실제 .pf 파일은 `C:\Windows\Prefetch\`

---

### 🔗 8. LNK Files
- **대상 하이브**: NTUSER.DAT, UsrClass.dat
- **목적**: 바로가기 파일 이력 추적
- **포렌식 가치**:
  - 바로가기 파일 경로
  - 타겟 파일 경로
  - 생성 시간
  - 최근 문서 목록
- **특징**: 최근 문서, 점프 리스트 추적

---

### 💿 9. Installed Software (상세)
- **대상 하이브**: SOFTWARE
- **목적**: 설치된 프로그램 상세 정보
- **포렌식 가치**:
  - 프로그램 표시 이름 (DisplayName)
  - 게시자 (Publisher)
  - 버전 (DisplayVersion)
  - 설치 날짜 (InstallDate)
  - 설치 위치 (InstallLocation)
  - 제거 명령 (UninstallString)
  - 예상 크기 (EstimatedSize)
- **특징**: 32비트/64비트 프로그램 모두 추적

---

### 🔐 10. SECURITY 상세
- **대상 하이브**: SECURITY
- **목적**: 시스템 보안 정책 및 권한 분석
- **포렌식 가치**:
  - 보안 정책 키
  - LSA Secrets (암호화된 자격 증명)
  - SID (보안 식별자)
  - SAM 도메인 정보
  - 정책 값
- **주의사항**: SYSTEM 권한 필요, 암호화된 데이터 많음

---

### 🔌 11. USB Devices
- **대상 하이브**: SYSTEM
- **목적**: USB 장치 연결 이력
- **포렌식 가치**:
  - 장치 이름
  - 벤더 ID (VID)
  - 제품 ID (PID)
  - 시리얼 번호
  - 마지막 연결 시간
- **특징**: USB 드라이브, 외장 하드, 스마트폰 등 모두 추적

---

### 📄 12. Recent Docs
- **대상 하이브**: NTUSER.DAT
- **목적**: 최근 문서 접근 이력
- **포렌식 가치**:
  - 파일 경로
  - 파일 확장자
  - 접근 시간
  - MRU (Most Recently Used) 순서
- **특징**: Office 문서, PDF, 이미지 등 모든 파일 추적

---

### 🏃 13. Run Keys
- **대상 하이브**: SOFTWARE, NTUSER.DAT
- **목적**: 자동 시작 프로그램 추적
- **포렌식 가치**:
  - 프로그램 이름
  - 실행 경로
  - 명령줄 인수
  - 레지스트리 키 위치
- **특징**: 악성코드 지속성 확인에 중요

---

### 👥 14. SAM Users
- **대상 하이브**: SAM
- **목적**: 로컬 사용자 계정 정보
- **포렌식 가치**:
  - 사용자 이름
  - RID (상대 식별자)
  - 마지막 로그인 시간
  - 로그인 카운트
  - 계정 생성 시간
- **주의사항**: 도메인 계정은 Active Directory에 저장

---

### 🌐 15. Network Profiles
- **대상 하이브**: SYSTEM
- **목적**: 네트워크 연결 프로필 이력
- **포렌식 가치**:
  - SSID (Wi-Fi 이름)
  - 연결 타입 (유선/무선)
  - 마지막 연결 시간
  - 프로필 생성 날짜
- **특징**: Wi-Fi 접속 이력, 네트워크 위치 추적

---

## 🎯 포렌식 시나리오별 권장 하이브

### 시나리오 1: 악성코드 분석
**권장 하이브**: SYSTEM, SOFTWARE, NTUSER.DAT
- ShimCache: 악성코드 실행 이력
- Run Keys: 지속성 확인
- UserAssist: 사용자 실행 프로그램
- BAM/DAM: 정확한 실행 시간

### 시나리오 2: 데이터 유출 조사
**권장 하이브**: NTUSER.DAT, UsrClass.dat, SYSTEM
- ShellBags: 폴더 접근 이력
- Recent Docs: 최근 문서
- USB Devices: USB 장치 연결
- Network Profiles: 네트워크 연결

### 시나리오 3: 사용자 활동 분석
**권장 하이브**: NTUSER.DAT, UsrClass.dat
- UserAssist: 실행 프로그램 + 사용 시간
- ShellBags: 폴더 탐색 패턴
- Recent Docs: 문서 접근
- LNK Files: 바로가기 사용

### 시나리오 4: 프로그램 설치 이력
**권장 하이브**: SOFTWARE, Amcache.hve
- Installed Software: 설치된 프로그램 목록
- Amcache: 설치 날짜 + 해시
- Prefetch: 실행 이력

### 시나리오 5: 계정 및 권한 조사
**권장 하이브**: SAM, SECURITY
- SAM Users: 로컬 계정 정보
- Security Detailed: 보안 정책 + SID

---

## 💡 사용 팁

### 1. 하이브 복사 방법
관리자 권한 CMD에서:
```cmd
reg save HKLM\SYSTEM C:\forensics\SYSTEM
reg save HKLM\SOFTWARE C:\forensics\SOFTWARE
reg save HKLM\SAM C:\forensics\SAM
reg save HKLM\SECURITY C:\forensics\SECURITY
reg save HKCU C:\forensics\NTUSER.DAT
```

또는 직접 파일 복사 (오프라인):
```cmd
copy C:\Windows\System32\config\SYSTEM C:\forensics\
copy C:\Windows\System32\config\SOFTWARE C:\forensics\
copy C:\Users\[Username]\NTUSER.DAT C:\forensics\
```

### 2. 여러 하이브 동시 분석
종합 분석을 위해 다음 순서로 분석:
1. SYSTEM (시스템 전역 정보)
2. SOFTWARE (프로그램 설치 정보)
3. NTUSER.DAT (사용자 활동)
4. SAM (계정 정보)
5. SECURITY (보안 정책)

### 3. 타임라인 구성
타임스탬프가 있는 모듈 우선 분석:
- ShimCache → Amcache → UserAssist → BAM/DAM
- 시간순 정렬로 사건 재구성

### 4. 검색 기능 활용
v3.0 검색 기능 사용:
- 정규표현식으로 특정 패턴 검색
- 악성코드 이름, 특정 경로, 시간대 필터링

---

## 📝 결론

v3.0에서는 **15개의 포렌식 분석 모듈**을 통해 Windows 시스템의 다양한 활동을 추적할 수 있습니다.

각 레지스트리 하이브는 고유한 포렌식 정보를 담고 있으므로, **분석 목적에 맞는 하이브를 선택**하는 것이 중요합니다.

**가장 많은 정보를 얻으려면**: SYSTEM + SOFTWARE + NTUSER.DAT 조합 권장

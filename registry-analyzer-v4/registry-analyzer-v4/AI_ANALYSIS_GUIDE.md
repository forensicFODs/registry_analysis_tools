# 🤖 AI 기반 포렌식 분석 사용 가이드

## 📋 개요

Windows Registry Forensic Analyzer v4.0은 AI를 활용하여 레지스트리 데이터를 자동으로 분석하고 포렌식 인사이트를 제공합니다.

---

## 🌟 지원 AI 모델

### 1. Google Gemini 2.0 Flash (무료) ⭐ 권장

**장점**:
- ✅ **완전 무료** - 비용 부담 없음
- ✅ **빠른 응답** - 평균 5-10초
- ✅ **높은 할당량** - 시간당 1,500 요청
- ✅ **최신 모델** - 2024년 12월 출시

**단점**:
- ⚠️ 간혹 JSON 형식 오류

**API 키 발급**:
1. https://makersuite.google.com/app/apikey 접속
2. Google 계정 로그인
3. "Create API Key" 클릭
4. API 키 복사

### 2. OpenAI GPT-4o-mini (유료)

**장점**:
- ✅ **고품질 분석** - 정확한 인사이트
- ✅ **안정적인 JSON** - 형식 오류 거의 없음
- ✅ **일관된 응답** - 재현성 높음

**단점**:
- ⚠️ **유료** - 토큰당 과금 ($0.15/1M input tokens)
- ⚠️ API 키 필요 (신용카드 등록)

**API 키 발급**:
1. https://platform.openai.com/api-keys 접속
2. OpenAI 계정 로그인 (신용카드 등록 필요)
3. "Create new secret key" 클릭
4. API 키 복사 (한 번만 표시됨)

---

## 🚀 사용 방법

### Step 1: AI 설정

1. **GUI 실행**
   ```bash
   python3 main.py
   ```

2. **AI Provider 선택**
   - 🟢 **Gemini (무료)** - 권장
   - 🔵 **OpenAI (유료)** - 고품질

3. **API Key 입력**
   - 발급받은 API 키를 입력창에 붙여넣기
   - 키는 세션 동안 저장됨 (재시작 시 다시 입력 필요)

### Step 2: 레지스트리 분석

1. **파일 선택**
   - "📂 Select File" 버튼 클릭
   - 레지스트리 하이브 선택 (SYSTEM, SOFTWARE, etc.)

2. **분석 실행**
   - "🔍 Analyze" 버튼 클릭
   - 바이너리 분석 자동 실행 (18개 모듈)
   - AI 분석 자동 시작

3. **결과 확인**
   - 바이너리 분석 결과 먼저 표시
   - AI 분석 결과 하단에 표시

### Step 3: AI 분석 결과 해석

AI 분석 결과는 4개 섹션으로 구성:

#### 1. 📊 Summary (요약)
```
전체 분석 내용의 간단한 요약
- 발견된 주요 아티팩트 개수
- 전체적인 시스템 상태 평가
```

#### 2. ⚠️ Suspicious Activities (의심스러운 활동)
```
보안 관점에서 주의가 필요한 항목들:
- 비정상적인 프로그램 실행 패턴
- 의심스러운 USB 장치 연결
- 알려지지 않은 네트워크 연결
- 자동 실행 설정된 의심 프로그램
```

#### 3. ⏱️ Timeline (타임라인)
```
주요 이벤트의 시간순 정리:
- 프로그램 설치/실행 시간
- USB 장치 연결 시간
- 네트워크 연결 시간
- 사용자 활동 시간
```

#### 4. 💡 Recommendations (권장사항)
```
보안 강화를 위한 권장사항:
- 삭제 권장 프로그램
- 비활성화 권장 서비스
- 추가 조사 필요 항목
- 보안 정책 변경 제안
```

---

## 💡 활용 예시

### 예시 1: 악성코드 감염 의심 시스템 분석

**시나리오**: 사용자 PC가 이상 동작을 보임

**분석 절차**:
1. SYSTEM, SOFTWARE, NTUSER.DAT 하이브 수집
2. Multi-Hive 분석 실행
3. AI 분석으로 의심스러운 패턴 자동 탐지

**AI 분석 결과 예시**:
```json
{
  "summary": "최근 7일간 3개의 알려지지 않은 프로그램이 자동 실행으로 등록되었으며, 
             비정상적인 네트워크 연결 패턴이 발견되었습니다.",
  
  "suspiciousActivities": [
    "C:\\Users\\Admin\\AppData\\Temp\\svchost32.exe - 정상 시스템 파일을 모방한 이름",
    "알려지지 않은 USB 장치 연결 (VID: 0000, PID: 0000)",
    "새벽 3시 자동 네트워크 연결 시도 (suspicious-domain.ru)"
  ],
  
  "timeline": [
    {"timestamp": "2024-01-10 03:15:20", "event": "svchost32.exe 자동 실행 등록"},
    {"timestamp": "2024-01-10 03:15:45", "event": "suspicious-domain.ru 연결 시도"},
    {"timestamp": "2024-01-12 14:30:10", "event": "알려지지 않은 USB 장치 연결"}
  ],
  
  "recommendations": [
    "C:\\Users\\Admin\\AppData\\Temp\\svchost32.exe 즉시 삭제 및 정밀 검사",
    "suspicious-domain.ru 도메인 차단",
    "USB 자동 실행 기능 비활성화",
    "전체 시스템 악성코드 검사 실행"
  ]
}
```

### 예시 2: 내부자 정보 유출 조사

**시나리오**: 기밀 정보가 유출된 것으로 의심되는 직원 PC 조사

**분석 절차**:
1. NTUSER.DAT, UsrClass.dat로 사용자 활동 분석
2. SYSTEM으로 USB 장치 연결 이력 확인
3. AI 분석으로 의심스러운 파일 접근 패턴 탐지

**AI 분석 결과 예시**:
```json
{
  "summary": "퇴사 2일 전 대용량 USB 장치 연결 및 기밀 문서 폴더 접근이 
             평소보다 10배 증가했습니다.",
  
  "suspiciousActivities": [
    "Kingston 256GB USB 장치 연결 (2024-01-15 18:30 ~ 19:15)",
    "\\\\Server\\Confidential 폴더 비정상 접근 (150회 in 1시간)",
    "대용량 ZIP 파일 생성 (C:\\Temp\\backup_20240115.zip, 2.5GB)"
  ],
  
  "timeline": [
    {"timestamp": "2024-01-15 18:30:10", "event": "Kingston USB 장치 연결"},
    {"timestamp": "2024-01-15 18:35:00", "event": "기밀 폴더 접근 시작"},
    {"timestamp": "2024-01-15 19:10:30", "event": "ZIP 파일 생성 완료"},
    {"timestamp": "2024-01-15 19:15:00", "event": "USB 장치 분리"}
  ],
  
  "recommendations": [
    "Kingston USB 장치 추적 및 회수",
    "backup_20240115.zip 파일 복구 시도",
    "네트워크 로그에서 외부 전송 여부 확인",
    "해당 직원 계정 접근 로그 상세 분석"
  ]
}
```

### 예시 3: 시스템 성능 저하 원인 분석

**시나리오**: PC 부팅 및 실행 속도가 현저히 느려짐

**분석 절차**:
1. SYSTEM, SOFTWARE로 자동 실행 프로그램 확인
2. Services 분석으로 불필요한 서비스 탐지
3. AI 분석으로 성능 저하 원인 파악

**AI 분석 결과 예시**:
```json
{
  "summary": "25개의 자동 실행 프로그램과 18개의 백그라운드 서비스가 
             부팅 시 동시에 실행되어 성능 저하를 유발하고 있습니다.",
  
  "suspiciousActivities": [
    "오래된 소프트웨어 업데이터 3개 중복 실행",
    "제거되지 않은 이전 백신 프로그램 서비스 활성화",
    "불필요한 브라우저 확장 프로그램 15개 자동 실행"
  ],
  
  "timeline": [
    {"timestamp": "2023-06-15", "event": "Norton 백신 설치"},
    {"timestamp": "2023-09-20", "event": "AVG 백신 설치 (Norton 미제거)"},
    {"timestamp": "2024-01-10", "event": "Chrome 확장 15개 추가"}
  ],
  
  "recommendations": [
    "사용하지 않는 백신 프로그램 완전 제거 (Norton)",
    "중복된 소프트웨어 업데이터 비활성화",
    "불필요한 Chrome 확장 프로그램 제거",
    "부팅 시 자동 실행 프로그램 10개 이하로 축소"
  ]
}
```

---

## ⚠️ 주의사항

### 1. API 키 보안
- ❌ API 키를 코드에 하드코딩하지 마세요
- ❌ 공개 저장소에 API 키를 커밋하지 마세요
- ✅ 사용 후 창을 닫으면 API 키는 메모리에서 삭제됩니다

### 2. 데이터 전송
- AI 분석 시 레지스트리 데이터가 외부 API 서버로 전송됩니다
- **민감한 시스템**의 경우:
  - ⚠️ 기밀 데이터 포함 여부 확인
  - ⚠️ 회사 보안 정책 준수
  - ✅ 필요시 AI 분석 비활성화 가능

### 3. 비용 (OpenAI)
- GPT-4o-mini: $0.15/1M input tokens, $0.60/1M output tokens
- 평균 분석 비용: 약 $0.01 ~ $0.05 per analysis
- API 사용량 모니터링: https://platform.openai.com/usage

### 4. 분석 결과 해석
- AI 분석은 **참고용**입니다
- 최종 판단은 **포렌식 전문가**가 해야 합니다
- 의심스러운 항목은 **추가 조사** 필요

---

## 🔧 문제 해결

### API 오류: "API key not valid"
**원인**: API 키가 잘못 입력되었거나 만료됨
**해결**:
1. API 키를 다시 복사하여 입력
2. 공백이나 특수문자가 포함되지 않았는지 확인
3. API 키 발급 사이트에서 키 상태 확인

### AI 응답 오류: "Invalid JSON response"
**원인**: AI 모델이 JSON 형식을 제대로 생성하지 못함
**해결**:
1. 다시 분석 시도 (일시적 오류일 수 있음)
2. 다른 AI Provider로 변경 (Gemini ↔ OpenAI)
3. API 키 재입력

### 네트워크 오류: "Connection timeout"
**원인**: 인터넷 연결 문제 또는 방화벽 차단
**해결**:
1. 인터넷 연결 확인
2. 방화벽 설정 확인:
   - Gemini: generativelanguage.googleapis.com
   - OpenAI: api.openai.com
3. 프록시 설정 확인

### 분석 결과가 이상함
**원인**: AI 모델의 한계 또는 데이터 부족
**해결**:
1. 더 많은 레지스트리 하이브 제공 (Multi-Hive 분석)
2. 다른 AI Provider로 재분석
3. 바이너리 분석 결과를 직접 확인

---

## 📊 AI 분석 품질 비교

| 기준 | Gemini 2.0 Flash | OpenAI GPT-4o-mini |
|------|------------------|-------------------|
| **비용** | 무료 | 유료 (~$0.03/분석) |
| **응답 속도** | 5-10초 | 10-15초 |
| **정확도** | 85% | 95% |
| **한국어 품질** | 우수 | 매우 우수 |
| **JSON 안정성** | 보통 (90%) | 매우 높음 (99%) |
| **할당량** | 1,500/시간 | API 키별 상이 |
| **권장 사용** | 일반 분석 | 중요 사건 조사 |

---

## 🎓 고급 활용

### 1. 배치 분석
여러 시스템을 한 번에 분석:
```python
from analyzers import ForensicsAnalyzer, AIAnalyzer
from core.registry_parser import RegistryParser

systems = ['PC-001', 'PC-002', 'PC-003']
api_key = 'YOUR_GEMINI_API_KEY'

for system in systems:
    with open(f'{system}/SYSTEM', 'rb') as f:
        parser = RegistryParser(f.read(), 'SYSTEM')
        analyzer = ForensicsAnalyzer(parser, 'SYSTEM')
        findings = analyzer.analyze_all()
        
        ai_result = AIAnalyzer.analyze_with_gemini(
            api_key, 'SYSTEM', 
            parser.extract_strings()[:1000], 
            findings
        )
        
        # 결과 저장
        with open(f'{system}_ai_report.json', 'w') as out:
            json.dump(ai_result, out, indent=2, ensure_ascii=False)
```

### 2. 커스텀 프롬프트
AI 분석 프롬프트를 커스터마이징하려면 `analyzers/ai_analyzer.py` 수정:
```python
prompt = f"""특정 악성코드 패턴을 집중 분석하세요:
- 랜섬웨어 특성 (파일 암호화, 확장자 변경)
- 키로거 특성 (키보드 후킹)
- 백도어 특성 (원격 접속)

데이터: {json.dumps(raw_findings)}
"""
```

---

## 📚 참고 자료

### AI 모델 문서
- [Gemini API Docs](https://ai.google.dev/docs)
- [OpenAI API Docs](https://platform.openai.com/docs)

### 포렌식 배경 지식
- [SANS Digital Forensics](https://www.sans.org/cyber-security-courses/windows-forensic-analysis/)
- [Windows Registry Forensics](https://dfir.blog/registry-analysis/)

---

## 🤝 피드백

AI 분석 결과가 부정확하거나 개선이 필요한 부분이 있다면 이슈를 등록해주세요!

---

**마지막 업데이트**: 2025-11-21  
**버전**: v4.0

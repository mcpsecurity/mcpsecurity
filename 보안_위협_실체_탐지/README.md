
# 🛡️ MCP Security

**MCP 기반 보안 취약점 점검 시스템**  
**대기고등학교 정보보안 프로젝트**

---

## 📌 프로젝트 개요

본 프로젝트는 **대기고등학교 정보보안 동아리**에서 실습 중심으로 개발한 **AI 기반 자동 보안 진단 도구**입니다.  
**Windows 운영체제**를 대상으로 다음과 같은 3가지 보안 점검 기능을 제공합니다:

1. ✅ **시스템 보안 설정 점검** (레지스트리 기반)
2. 🧠 **악성코드 의심 프로세스 탐지 및 대응**
3. 🔐 **민감 정보 포함 파일 탐지** (주민번호, 카드번호 등)

모든 기능은 **MCP (Multi-functional Command Platform)** 서버 구조로 작동하며, **Claude AI API**와 연동되어 결과를 해석하고 조치사항을 제공합니다.

---

## 📁 프로젝트 구성

| 모듈 이름 | 주요 기능 | 포트 | 메인 실행 파일 |
|-----------|----------|------|----------------|
| `registry_checker` | 시스템 보안 레지스트리 자동 점검 | 5002 | `registry_checker.py` |
| `malware_checker` | 악성 프로세스 탐지 및 종료 | 5003 | `malware_checker.py` |
| `sensitive_data_scanner` | 주민번호, 카드번호 등 민감 정보 포함 파일 스캔 | 5004 | `sensitive_data_scanner.py` |

---

## 🛠️ 설치 및 실행 방법

### 1. Python 설치
- Python 3.8 이상 필요  
  [https://www.python.org/](https://www.python.org/)

### 2. 가상환경 및 의존성 설치
```bash
python -m venv security_env
.\security_env\Scriptsctivate  # Windows 기준
pip install psutil requests fastmcp
```

### 3. Claude API 환경변수 등록
```powershell
$env:CLAUDE_API_KEY = "<YOUR_CLAUDE_API_KEY>"
```

### 4. MCP 서버 실행
```bash
python registry_checker.py         # 시스템 보안 점검
python malware_checker.py          # 악성 프로세스 점검
python sensitive_data_scanner.py   # 민감 정보 스캔
```

---

## 🤖 Claude AI 연동 방식

- 각 도구는 분석 요약본을 **Claude AI API**에 전달하여 사람이 이해하기 쉬운 해석을 받아옵니다.
- `call_claude_api(prompt)` 함수는 내부적으로 API 키를 사용하여 LLM 호출을 처리하며, 요약 리포트에 AI 해석 결과가 포함됩니다.

---

## 🔐 시스템 보안 설정 점검

### ✔️ 점검 항목
- Windows 방화벽 설정
- 자동 업데이트 상태
- 사용자 계정 컨트롤(UAC)
- 원격 데스크톱 허용 여부
- LM 해시 저장 여부
- SMB 서명 요구 여부 등

### 📂 결과 저장
- `c:/test/` 디렉토리에 JSON 보고서 자동 저장
- Claude 분석 결과 포함

### 🛠️ 주요 함수

| 함수명 | 설명 |
|--------|------|
| `check_registry_security()` | 전체 레지스트리 보안 설정을 점검하고 요약 보고서 + Claude 해석 포함 반환 |
| `get_security_recommendations()` | 이전 보고서 기반 권장 설정 자동 추출 |
| `read_file_internal`, `write_file_internal` | 내부 보고서 읽기/쓰기 처리 |

---

## 🧠 악성코드 의심 프로세스 탐지

### ✔️ 탐지 방식
- 프로세스 이름/경로/명령행 인자 분석
- CPU/메모리/네트워크 리소스 사용량 평가
- 의심스러운 포트 사용 및 위장 여부 확인
- 점수 기반(0~100)으로 위험도 분류

### 📂 결과 저장 및 해석
- `malware_scan_report_*.json` 형식으로 저장
- Claude AI가 의심 프로세스와 조치사항 평가

### 🛠️ 주요 함수

| 함수명 | 설명 |
|--------|------|
| `scan_suspicious_processes()` | 전체 프로세스 스캔 후 위험도 분류 및 요약 보고서 + Claude 분석 포함 반환 |
| `kill_suspicious_process(pid)` | PID 기준으로 악성 의심 프로세스 안전 종료 |
| `get_process_details(pid)` | 프로세스 상세정보 + 의심도 점수 및 분석 반환 |

---

## 🔐 민감 정보 포함 파일 탐지

### ✔️ 탐지 항목 (정규표현식 기반)

| 분류 | 설명 | 위험도 |
|------|------|--------|
| 주민등록번호 | 901010-1234567 등 | 🔴 CRITICAL |
| 신용카드번호 | 16자리 또는 Visa/MC 등 | 🟠 HIGH |
| 비밀번호 | password=admin123 등 | 🔴 CRITICAL |
| 이메일 / 전화번호 | 일반 패턴 매칭 | 🟡 MEDIUM / 🔵 LOW |
| API 키 / IP / 계좌번호 등 | 개발 환경 민감 정보 포함 | 다양 |

### 📂 탐지 결과
- 10MB 이하 텍스트 파일만 탐지
- 최대 500개까지 스캔 (기본값)
- 심각도별 분류 + 상위 항목 요약
- Claude 분석 결과 포함

### 🛠️ 주요 함수

| 함수명 | 설명 |
|--------|------|
| `scan_sensitive_data(target_dirs, max_files)` | 전체 디렉토리 대상 민감 정보 스캔 수행 |
| `scan_specific_file(file_path)` | 특정 파일 1개에 대해 분석 수행 |
| `get_scan_patterns()` | 사용 중인 정규표현식 목록 확인 |

---

## 📊 예시 결과 출력

### 시스템 보안 점검 (registry_checker)
```
전체 상태: FAIL
❌ 방화벽 비활성화
✅ Claude 설명: 일부 항목이 취약하며, Windows Update는 정상...
```

### 악성 프로세스 탐지 (malware_checker)
```
의심 프로세스 3개 발견
- [높음] 12345.exe - 다운로드 폴더에서 실행, CPU 95% 사용 중...
🤖 Claude 분석: 자동 실행되는 프로그램이 사용자 행위 없이 실행되어 위험합니다...
```

### 민감 정보 스캔 (sensitive_data_scanner)
```
🔴 주민등록번호 2건 발견
📁 C:\Users\User\Documents\private.txt
🤖 Claude 분석: 즉시 암호화 또는 삭제를 권장합니다.
```

---

## ⚠️ 사용 시 주의사항

- **관리자 권한으로 실행**하지 않으면 일부 기능이 동작하지 않을 수 있습니다.
- 민감 정보는 사용자의 허가 없이 외부로 전송되지 않으며, **로컬에서만 처리**됩니다.
- Claude API를 사용하려면 반드시 `CLAUDE_API_KEY`를 환경변수로 등록해야 합니다.

---

## 🤝 기여 방법

오픈소스로 누구나 기여 가능합니다:

- 탐지 패턴 및 알고리즘 개선 제안
- GUI / 웹 대시보드 기능 추가
- 크로스 플랫폼 지원 (macOS, Linux 등)

GitHub에서 Pull Request 또는 Issue로 의견을 주세요.

---

## 🏁 프로젝트 목표

- **고등학생 수준에서 실현 가능한 실습형 보안 프로젝트 구현**
- **AI 분석 기반 자동 보안 점검 도구 제공**
- 누구나 쉽게 사용 가능한 **오픈소스 보안 실습 플랫폼** 구축

---

## 📎 참고 자료

- [Python 공식 문서](https://docs.python.org/3/)
- [Windows Registry 구조](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry)
- [psutil 라이브러리](https://psutil.readthedocs.io/)
- [Anthropic Claude API 문서](https://docs.anthropic.com)

---

## 🚀 향후 발전 방향

- [ ] 리눅스 및 MacOS 대응
- [ ] 웹 UI 기반 시각화 결과 제공
- [ ] 스캔 결과 자동 백업 및 암호화
- [ ] 이메일, 슬랙 등 자동 알림 기능 추가
- [ ] 조직 단위 배포 가능한 에이전트 형태 개발

---

## 🙇 기여자

본 프로젝트는 **대기고등학교 정보보안 동아리** 학생들이 직접 기획 및 개발하였습니다.

> 📧 문의: [example@daegihigh.kr](mailto:example@daegihigh.kr)

---

## 📝 라이선스

MIT License  
**상업적 사용 시 원 저작자 표기**를 권장합니다.

---

## ✅ 마무리

> 단순한 보안 스크립트를 넘어서, **AI 기반 실시간 보안 점검 자동화**라는 실용 기술을 실현한 사례입니다.  
> 보안은 더 이상 전문가만의 영역이 아닙니다.  
> **당신의 시스템은 오늘 얼마나 안전한가요?**

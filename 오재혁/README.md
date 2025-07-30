# 🛡️ MCP Security

**MCP 기반 보안 취약점 점검 시스템**  
**대기고등학교 정보보안 프로젝트**

---

## 📌 프로젝트 개요

본 프로젝트는 **대기고등학교 정보보안 동아리**에서 진행한 실습 중심의 보안 진단 자동화 시스템입니다.

Windows 운영체제를 대상으로, 다음과 같은 3가지 보안 점검 기능을 제공합니다:

1. **시스템 보안 설정 자동 점검** (레지스트리 기반)
2. **악성코드 의심 프로세스 탐지 및 대응**
3. **민감한 데이터(주민번호, 카드번호 등) 파일 내 포함 여부 분석**

각 기능은 **MCP(Multi-functional Command Platform)**를 기반으로 독립적인 서버 형태로 동작하며, 명령어 호출을 통해 점검 결과를 받아볼 수 있습니다. 또한, **Claude AI API**를 통해 생성된 리포트에 대해 사람이 이해하기 쉬운 형태로 분석 결과를 제공합니다.

---

## 📁 프로젝트 구성

| 프로젝트 이름 | 기능 요약 | 포트 | 메인 파일명 |
|---------------|-----------|------|--------------|
| registry_checker | 보안 레지스트리 설정 자동 점검 | 5002 | `registry_checker.py` |
| malware_checker | 악성 프로세스 탐지 및 대응 | 5003 | `malware_checker.py` |
| sensitive_data_scanner | 민감 정보 포함 파일 탐지 | 5004 | `sensitive_data_scanner.py` |

---

## 🛠️ 설치 및 실행 방법

### 1. Python 설치
- Python 3.8 이상 ([https://www.python.org/](https://www.python.org/))

### 2. 의존성 설치
```bash
pip install psutil requests
```

### 3. Claude API 환경 변수 등록
```bash
# Windows PowerShell 기준
$env:CLAUDE_API_KEY="<YOUR_CLAUDE_API_KEY>"
```

### 4. 각 MCP 서버 실행
```bash
python registry_checker.py         # 시스템 보안 점검
python malware_checker.py          # 악성 프로세스 점검
python sensitive_data_scanner.py   # 민감 정보 탐지
```

---

## 🔐 프로젝트 1: 시스템 보안 설정 점검

### 📌 기능 설명
- Windows 레지스트리의 주요 보안 항목을 점검합니다.
- 결과를 요약 보고서와 JSON 파일로 저장하고 Claude AI를 통해 해석합니다.
- 이전 점검 결과 기반 권장 설정도 제공합니다.

### 🧠 주요 함수 설명

| 함수 | 설명 |
|------|------|
| `call_claude_api(prompt)` | Claude AI에게 점검 요약을 보내 사람이 이해하기 쉬운 해석을 요청합니다. |
| `read_registry_value(hkey, path, name)` | 보안 설정 레지스트리 키 값을 읽고 예외를 처리합니다. |
| `analyze_security_setting(category, config)` | 현재값과 기대값을 비교하여 PASS/FAIL/ERROR 결과를 생성합니다. |
| `check_registry_security()` | 전체 설정을 점검하고 JSON 보고서를 생성하며 Claude 응답 포함 결과 반환 |
| `get_security_recommendations()` | 이전 보고서 기반 보완 권장사항을 추출합니다. |
| `write_file_internal(filename, content)` | `C:\test` 경로에 결과 파일 저장 |
| `read_file_internal(filename)` | 저장된 결과 파일 읽기 |

---

## 🧬 프로젝트 2: 악성코드 의심 프로세스 탐지

### 📌 기능 설명
- 실행 중인 프로세스의 리소스/행위를 분석하여 악성 가능성을 점수화합니다.
- Claude API를 통해 리포트를 AI가 평가하고 조치까지 제안합니다.

### 🧠 주요 함수 설명

| 함수 | 설명 |
|------|------|
| `analyze_process_behavior(process)` | PID를 기준으로 실행 파일 경로, CPU/메모리/I/O, 네트워크 상태 수집 |
| `calculate_suspicion_score(info)` | 수집된 항목 기반 악성 가능성 점수(0~100점) 및 사유 생성 |
| `scan_suspicious_processes()` | 전체 프로세스 스캔 후 결과 정리 및 요약 보고서 생성 |
| `kill_suspicious_process(pid)` | 특정 PID의 프로세스를 안전하게 종료 (중요 시스템 제외) |
| `get_process_details(pid)` | PID 기준 상세 정보와 점수 및 원인 분석 |
| `call_claude_api(prompt)` | Claude로 보고서 내용을 전달하고 해석 결과를 수신 |

---

## 📂 프로젝트 3: 민감 정보 스캐너

### 📌 기능 설명
- 다양한 파일에서 주민등록번호, 카드번호 등 민감 정보가 포함되었는지 탐지합니다.
- 정규표현식 기반 검색을 사용하며, 위험도별로 분류합니다.

### 🧠 주요 함수 설명

| 함수 | 설명 |
|------|------|
| `scan_sensitive_data(target_dirs, max_files)` | 지정된 폴더에서 텍스트 파일을 찾아 민감 정보 포함 여부를 확인 |
| `scan_specific_file(file_path)` | 단일 파일 대상 탐지 수행 |
| `get_scan_patterns()` | 탐지에 사용되는 정규표현식 패턴 목록 출력 |
| `is_text_file(file_path)` | 확장자 및 MIME 유형 기준으로 텍스트 파일 여부 판단 |
| `scan_file_content(file_path)` | 파일 내용을 읽고 패턴과 일치하는 민감 데이터 추출 |
| `get_files_to_scan(directories)` | 디렉토리 내 탐색 대상 파일 목록 수집 (최대 개수 제한 포함) |
| `call_claude_api(prompt)` | 요약 결과를 Claude에 보내고 해석 결과를 수신 |

---

## 🧪 예시 결과

### 보안 점검 예시

응답:

```
전체 상태: FAIL
❌ 방화벽 비활성화
✅ Claude 설명: 이 컴퓨터는 자동 업데이트가 설정되어 있지만, 일부 항목이 취약합니다...
```

### 악성 프로세스 탐지 예시

응답:

```
의심 프로세스 3개 발견
- [높음] 12345.exe - 다운로드 폴더에서 실행, CPU 95% 사용 중...
```

### 민감 정보 스캔 예시

응답:

```
🔴 주민등록번호 2건 발견
📁 C:\Users\User\Documents\private.txt
🤖 Claude 분석: 이 파일은 외부 유출 시 큰 피해를 줄 수 있습니다. 즉시 암호화하거나 삭제를 권장합니다.
```

---

## ⚠️ 주의사항

- 민감 정보 스캔은 최대 500개 파일까지 검사하며, 10MB 이상 파일은 생략됩니다.
- 관리자 권한으로 실행하지 않으면 일부 레지스트리나 프로세스를 확인할 수 없습니다.
- Claude API를 사용하려면 키를 환경변수로 반드시 등록해야 합니다.

---

## 🤝 기여 방법

이 프로젝트는 오픈소스입니다. 다음 방식으로 기여할 수 있습니다:

- 탐지 알고리즘 개선 제안
- 다양한 OS 지원 코드 추가
- 코드 리팩토링 및 사용자 친화적 UI 제안

Pull Request 또는 Issue로 참여해주세요!

---

## 🏁 프로젝트 목표

- 보안 개념을 실습을 통해 체득하는 학습 플랫폼
- AI 기반 분석 도입으로 비전문가의 보안 이해력 향상
- 학교 교육을 넘어 누구나 쓸 수 있는 오픈소스 보안 툴 개발

---

## 📎 참고 자료 및 향후 발전 방향

- **관련 기술**
  - [Python 공식 문서](https://docs.python.org/3/)
  - [Windows 레지스트리 구조](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry)
  - [psutil 문서](https://psutil.readthedocs.io/)
  - [Anthropic Claude API 가이드](https://docs.anthropic.com)

- **향후 계획**
  - 리눅스 및 MacOS 호환 버전 개발
  - 웹 대시보드 형태의 시각적 보안 진단 UI 연동
  - 탐지 결과 자동 백업 및 암호화 기능 추가
  - 자동 알림 기능 (이메일/슬랙 등) 연동

---

## 🙇 프로젝트 기여자

본 프로젝트는 **대기고등학교 정보보안 동아리** 학생들이 직접 기획 및 개발하였으며, 보안 학습과 실습을 병행한 결과물입니다.

> 📧 문의: [example@daegihigh.kr](mailto:example@daegihigh.kr)

---

## 📝 라이선스

MIT License에 따라 자유롭게 수정, 배포, 사용이 가능합니다.  
다만, **상업적 목적 사용 시 원 저작자 표기**를 권장합니다.

---

## ⭐ 마무리

이 프로젝트는 단순한 보안 스크립트를 넘어서, **AI 기반 보안 점검 자동화**라는 실용적 기술을 실습을 통해 구현한 사례입니다. 누구나 쉽게 사용할 수 있는 구조로 만들어졌으며, **실제 보안 진단 도구로서도 충분한 가치**를 지닙니다.

보안은 선택이 아닌 필수입니다.\
당신의 시스템은 오늘 얼마나 안전한가요?

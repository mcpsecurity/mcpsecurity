# 🛡️ MCP Security

**MCP 기반 보안 취약점 점검 시스템**\
**대기고등학교 정보보안 프로젝트**

---

## 📌 프로젝트 개요

이 프로젝트는 대기고등학교 학생들이 Windows 환경에서 직접 보안 상태를 점검할 수 있도록 개발된 **MCP(Multi-functional Command Platform)** 기반 보안 진단 시스템입니다.

총 3개의 독립적인 MCP 서버를 통해 **보안 설정, 실행 중인 악성 프로세스, 민감한 데이터 유출 위험**을 자동으로 점검할 수 있습니다. 또한 Claude API와 연동하여 점검 결과에 대한 **AI 해석 및 조언**을 제공합니다.

---

## 📂 프로젝트 구성

### ✅ 프로젝트1: 시스템 보안 설정 점검 (`registry_checker.py`)

**주요 기능:**

- Windows 레지스트리에서 주요 보안 항목의 설정 상태를 확인합니다.
- 방화벽, 자동 업데이트, UAC, 원격 데스크톱, LM 해시 저장 여부 등을 점검합니다.
- 점검 결과를 자동으로 요약 보고서로 생성하며, Claude API를 통해 설명을 붙여줍니다.

**실행 포트:** 5002

### ✅ 프로젝트2: 악성코드 의심 프로세스 탐지 (`malware_checker.py`)

**주요 기능:**

- 현재 시스템에서 실행 중인 프로세스를 분석하여, 악성 가능성이 있는 프로세스를 점수화합니다.
- 실행 파일 경로, 프로세스 이름, 리소스 사용량, 네트워크 연결, 명령행 인자 등을 기준으로 평가합니다.
- 위험도가 높은 프로세스를 종료하거나 상세 정보를 확인할 수 있습니다.

**실행 포트:** 5003

### ✅ 프로젝트3: 민감 정보 스캐너 (`sensitive_data_scanner.py`)

**주요 기능:**

- 사용자 디렉토리, Temp 디렉토리 등에서 주민등록번호, 신용카드 번호, 이메일, 전화번호 등의 민감 정보를 탐지합니다.
- 정규표현식 기반으로 텍스트 파일 내 내용을 분석하며, 심각도별로 분류해 보여줍니다.

**실행 포트:** 5004

---

## 🛠️ 설치 및 실행 방법

### 1. Python 설치

- Python 3.8 이상 설치 필요 ([https://www.python.org/](https://www.python.org/))

### 2. 필수 라이브러리 설치

```bash
pip install psutil requests
```

### 3. Claude API 키 등록

- Claude API를 사용하려면 환경변수에 `CLAUDE_API_KEY`를 등록해야 합니다.

```bash
set CLAUDE_API_KEY=your_api_key_here
```

### 4. MCP 서버 실행

```bash
# 보안 설정 점검 서버 실행
python registry_checker.py

# 악성 프로세스 탐지 서버 실행
python malware_checker.py

# 민감 정보 탐지 서버 실행
python sensitive_data_scanner.py
```

각 서버는 다음 포트에서 실행됩니다:

- 5002 (보안 설정 점검)
- 5003 (악성 프로세스 탐지)
- 5004 (민감 정보 스캔)

---

## 🧠 함수 설명 (초보자용)

### 🔐 프로젝트1 - 레지스트리 보안 점검

| 함수 이름                                        | 설명                                |
| -------------------------------------------- | --------------------------------- |
| `call_claude_api(prompt)`                    | Claude AI에게 텍스트 요약이나 분석 요청을 보냅니다. |
| `read_registry_value(hkey, path, name)`      | 특정 레지스트리 키의 값을 안전하게 읽습니다.         |
| `analyze_security_setting(category, config)` | 설정된 항목이 기대값과 일치하는지 확인합니다.         |
| `check_registry_security()`                  | 전체 보안 항목을 점검하고 보고서를 생성합니다.        |
| `get_security_recommendations()`             | 이전 보고서를 불러와 문제점에 대한 조언을 생성합니다.    |
| `write_file_internal(filename, content)`     | C:\test 폴더에 파일을 저장합니다.            |
| `read_file_internal(filename)`               | 저장된 파일을 불러옵니다.                    |

### 🧬 프로젝트2 - 악성 프로세스 탐지

| 함수 이름                               | 설명                                |
| ----------------------------------- | --------------------------------- |
| `analyze_process_behavior(process)` | 프로세스의 CPU, 메모리, 경로, 포트 등을 분석합니다.  |
| `calculate_suspicion_score(info)`   | 프로세스의 의심스러움을 0~100점으로 평가합니다.     |
| `scan_suspicious_processes()`       | 현재 실행 중인 모든 프로세스를 분석하고 보고서를 만듭니다. |
| `kill_suspicious_process(pid)`      | 의심스러운 프로세스를 종료합니다 (주의 필요).        |
| `get_process_details(pid)`          | PID를 이용해 특정 프로세스의 상세 정보를 출력합니다.   |
| `call_claude_api(prompt)`           | Claude AI를 호출해 분석 결과를 요약합니다.      |

### 📂 프로젝트3 - 민감 정보 탐지

| 함수 이름                                         | 설명                            |
| --------------------------------------------- | ----------------------------- |
| `scan_sensitive_data(target_dirs, max_files)` | 지정한 폴더 내 텍스트 파일을 모두 스캔합니다.    |
| `scan_specific_file(file_path)`               | 단일 파일에서 민감 정보를 탐색합니다.         |
| `get_scan_patterns()`                         | 현재 사용 중인 정규표현식 패턴 목록을 출력합니다.  |
| `is_text_file(file_path)`                     | 해당 파일이 텍스트 파일인지 확인합니다.        |
| `scan_file_content(file_path)`                | 파일의 내용을 읽고 민감정보 탐색 결과를 반환합니다. |
| `get_files_to_scan(directories)`              | 전체 스캔 대상 파일을 수집합니다.           |

---

## 🧪 예시 결과

### 보안 점검 예시

```
POST http://127.0.0.1:5002/tools/check_registry_security
```

응답:

```
전체 상태: FAIL
❌ 방화벽 비활성화
✅ Claude 설명: 이 컴퓨터는 자동 업데이트가 설정되어 있지만, 일부 항목이 취약합니다...
```

### 악성 프로세스 탐지 예시

```
POST http://127.0.0.1:5003/tools/scan_suspicious_processes
```

응답:

```
의심 프로세스 3개 발견
- [높음] 12345.exe - 다운로드 폴더에서 실행, CPU 95% 사용 중...
```

### 민감 정보 스캔 예시

```
POST http://127.0.0.1:5004/tools/scan_sensitive_data
```

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

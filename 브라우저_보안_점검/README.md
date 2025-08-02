🔒 MCP 브라우저 및 소프트웨어 보안 점검 도구
License: MIT | Python 3.8+ | Windows 전용

📋 개요
이 프로젝트는 Windows 환경에서 실행되는 3가지 보안 분석 기능을 제공하는 오픈소스 MCP 서버입니다. Claude AI와 연동되어 사용자에게 다음과 같은 점검 기능을 자연어로 제공할 수 있습니다:

1. 브라우저 보안 설정 분석

2. 설치된 소프트웨어의 CVE 기반 취약점 점검

3. 자동 실행 프로그램 및 스케줄 작업 분석

각 분석 결과는 요약 보고서 및 JSON 파일로 저장 가능하며, 관리자 권한에서 더욱 정밀한 분석이 가능합니다.

🎯 주요 기능

✅ 브라우저 보안 설정 분석

- Chrome, Firefox, Edge, Opera 등 설정 분석

- JavaScript, 쿠키, 안전한 브라우징, 비밀번호 관리자 등 점검

- 확장 프로그램 위험도 평가 (권한 기반)

✅ 설치된 소프트웨어 취약점 점검

- 레지스트리 및 WMIC 기반 소프트웨어 목록 추출

- NVD API(CVE 2.0) 연동

- 버전 정규화 및 매칭 신뢰도 분석

✅ 자동 실행 프로그램 분석

- 레지스트리 Run 키, 시작 폴더, 스케줄 작업 점검

- 의심스러운 경로/명령어/파일명 패턴 감지

- 디지털 서명 유무 확인 및 위험도 분류

🚀 1단계: 환경 준비

OS: Windows 10 또는 11

Python 3.8 이상 (64bit 권장)

관리자 권한 권장 (autorun/schedule 분석 정확도 향상)

# Python 버전 확인
python --version

📦 2단계: 프로젝트 설정

mkdir mcp-security-tools
cd mcp-security-tools

# 가상환경 생성 (선택)
python -m venv venv
venv\Scripts\activate

# 필요한 라이브러리 설치
pip install requests packaging psutil

아래 3개의 Python 파일을 프로젝트에 추가하세요:

browser_analyzer.py

vulnerability_scanner.py

autorun_analyzer.py

⚙️ 3단계: Claude Desktop에 MCP 연결

// claude_desktop_config.json 예시
{
  "mcpServers": {
    "browser-check": {
      "command": "python",
      "args": ["C:/.../mcp-security-tools/browser_analyzer.py"]
    },
    "software-vuln-check": {
      "command": "python",
      "args": ["C:/.../mcp-security-tools/vulnerability_scanner.py"]
    },
    "autorun-check": {
      "command": "python",
      "args": ["C:/.../mcp-security-tools/autorun_analyzer.py"]
    }
  }
}

🧪 4단계: MCP 서버 실행 및 테스트

# 예시: 브라우저 분석 실행
python browser_analyzer.py

# 예시: 소프트웨어 취약점 점검 실행
python vulnerability_scanner.py

# 예시: 자동 실행 항목 분석 실행
python autorun_analyzer.py

출력 예시:

🔒 브라우저 보안 설정 분석기
운영체제: Windows
분석된 브라우저: 3개
발견된 확장 프로그램: 24개
HIGH 위험도 확장 프로그램: 4개

💬 5단계: Claude를 통한 사용법
Claude에게 다음과 같이 요청해보세요:

"내 브라우저 보안 설정을 점검해줘"

"설치된 소프트웨어의 취약점이 있는지 확인해줘"

"자동 실행 프로그램 중 위험한 항목이 있는지 확인해줘"

Claude는 MCP 서버를 통해 실행 후 요약된 보안 결과 및 조치 권고를 제공합니다.

📊 6단계: 결과 해석 가이드

📌 브라우저 분석

✅ PASS: 안전한 설정 유지 중

⚠️ WARNING: 설정 변경 권장

❌ FAIL: 보안상 위험한 상태

🔌 확장 프로그램: HIGH/MEDIUM/LOW 위험도 분류

📌 취약점 점검

🔴 HIGH: 즉시 패치 필요

🟡 MEDIUM: 업데이트 권장

🟢 LOW: 낮은 위험

📌 자동 실행 프로그램 분석

HIGH: 의심 경로, 무서명, 악성 의심

MEDIUM: 시스템 외 경로 또는 이상 행동

LOW/SAFE: 정상 또는 알려진 프로그램

🛠️ 7단계: 문제 해결

requests 모듈 오류 → pip install requests

NVD API 제한 → 1초 이상 delay 필요 (이미 적용됨)

관리자 권한 필요 메시지 → PowerShell을 관리자 권한으로 실행

⚙️ 8단계: 고급 사용법

Windows 작업 스케줄러에 등록해 정기 분석 실행 가능

JSON 보고서를 로그 서버 또는 SIEM에 업로드

확장 프로그램 화이트리스트 설정 기능 추가 가능

📌 9단계: 실제 사용 시나리오

✔️ 정기 점검 자동화

"매주 월요일 오전에 자동 실행 항목과 확장 프로그램 분석 실행"

✔️ 의심스러운 활동 발견 시

"시스템이 느려졌어요. 악성 자동 실행 항목이 있는지 확인해줘"

✔️ CVE 대응

"최근 Adobe 취약점 관련해서 내 설치된 프로그램에 영향 있는지 확인해줘"

📞 지원 및 문의

GitHub Issues 및 Discussions 이용

보고서 출력 예시, 확장 프로그램 DB 공유 등 협업 환영

📄 라이센스
이 도구는 MIT 라이선스로 배포되며, 누구나 자유롭게 수정 및 재배포가 가능합니다.

⚠️ 면책 조항

이 도구는 보안 전문가의 진단을 대체하지 않습니다.

판단 결과에 따라 의심 파일은 백신 또는 전문가에게 재검증 바랍니다.

NVD 데이터는 공개 API 기반이며 완전성을 보장하지 않습니다.


# 🔒 시스템 보안 점검 MCP (AI를 통한 오픈소스 시스템 취약점 점검)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Windows](https://img.shields.io/badge/platform-Windows-blue.svg)](https://www.microsoft.com/windows)

## 📋 개요

이 프로젝트는 Windows 시스템의 기본적인 보안 상태를 점검할 수 있는 오픈소스 MCP(Model Context Protocol) 서버입니다. Claude AI와 연동하여 사용자가 자연어로 보안 점검을 요청하면, 시스템을 자동으로 점검하고 결과를 분석하여 조치사항을 제공합니다.

## 🎯 주요 기능

### 1. 시스템 업데이트 상태 점검
- Windows Update 서비스 상태 확인
- 최근 설치된 업데이트 조회
- 보류 중인 업데이트 확인  
- 자동 업데이트 설정 검증

### 2. 방화벽 정책 점검
- Windows 방화벽 프로필 상태 확인
- 인바운드/아웃바운드 규칙 통계
- 의심스러운 허용 규칙 탐지
- 방화벽 서비스 상태 점검

### 3. 백신/보안 소프트웨어 상태 점검
- Windows Defender 상태 확인
- 설치된 보안 소프트웨어 탐지
- 실시간 보호 기능 점검
- 바이러스 정의 파일 업데이트 상태
- 최근 위협 탐지 이력

## 🚀 설치 및 사용법

### 필요 조건
- Windows 10/11
- Python 3.8 이상
- 일부 기능은 관리자 권한 필요

### 설치 방법

1. **저장소 클론**
   ```bash
   git clone https://github.com/your-repo/security-check-mcp.git
   cd security-check-mcp
   ```

2. **의존성(요구사항) 설치**
   ```bash
   pip install mcp
   pip install fastmcp
   ```

3. **MCP 서버 실행**
   ```bash
   python security_check_mcp.py
   ```

### Claude와 연동 사용법

1. MCP 서버를 실행한 상태에서 Claude에게 다음과 같이 요청하세요:

   ```
   "내 컴퓨터 보안 상태를 점검해줘"
   "시스템 취약점을 확인해줘"
   "방화벽 상태만 확인해줘"
   "종합적인 보안 점검을 해줘"
   ```

2. Claude가 MCP 도구를 사용하여 시스템을 점검하고 결과를 분석하여 제공합니다.

## 🛠️ 사용 가능한 도구

| 도구명 | 설명 | 관리자 권한 필요 |
|--------|------|------------------|
| `check_system_updates()` | 시스템 업데이트 상태 점검 | 부분적 |
| `check_firewall_status()` | 방화벽 정책 및 상태 점검 | 부분적 |
| `check_antivirus_status()` | 백신/보안 소프트웨어 상태 점검 | 부분적 |
| `run_comprehensive_security_check()` | 종합적인 보안 점검 실행 | 권장 |
| `get_security_recommendations()` | 보안 강화 권장사항 제공 | 불필요 |

## 📊 점검 결과 예시

```json
{
  "timestamp": "2025-07-19T10:30:00",
  "system_info": {
    "os": "nt",
    "admin_privileges": true
  },
  "update_check": {
    "check_status": "완료",
    "recent_updates": "...",
    "auto_update_settings": "..."
  },
  "firewall_check": {
    "firewall_profiles": "...",
    "suspicious_rules": "..."
  },
  "antivirus_check": {
    "defender_status": "...",
    "realtime_protection_settings": "..."
  }
}
```

## 🔧 커스터마이징

이 도구는 오픈소스로 제공되므로 다음과 같이 확장할 수 있습니다:

### 새로운 점검 기능 추가
```python
@mcp.tool()
def check_custom_security_feature() -> str:
    """사용자 정의 보안 점검 기능"""
    # 여기에 점검 로직 구현
    pass
```

### 점검 기준 수정
- 각 도구 함수 내의 PowerShell 명령을 수정하여 점검 기준을 조정할 수 있습니다
- 결과 해석 로직을 수정하여 조직의 보안 정책에 맞게 조정 가능합니다

## 🛡️ 보안 고려사항

- 이 도구는 **읽기 전용** 점검만 수행하며, 시스템을 수정하지 않습니다
- 모든 소스 코드가 공개되어 있어 사용자가 직접 검토할 수 있습니다
- 네트워크를 통한 데이터 전송은 없으며, 로컬에서만 동작합니다
- 개인정보나 민감한 데이터를 수집하지 않습니다

## 🤝 기여 방법

1. 이 저장소를 포크하세요
2. 새로운 기능 브랜치를 생성하세요 (`git checkout -b feature/new-security-check`)
3. 변경사항을 커밋하세요 (`git commit -m 'Add new security check'`)
4. 브랜치에 푸시하세요 (`git push origin feature/new-security-check`)
5. Pull Request를 생성하세요

## 📄 라이센스

이 프로젝트는 MIT 라이센스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

## ⚠️ 면책 조항

- 이 도구는 기본적인 보안 점검만 제공하며, 전문적인 보안 솔루션을 대체하지 않습니다
- 시스템 보안은 복합적인 요소들을 고려해야 하므로, 추가적인 보안 조치가 필요할 수 있습니다
- 사용자는 자신의 책임 하에 이 도구를 사용해야 합니다

## 📞 지원 및 문의

- Issues: [GitHub Issues](https://github.com/your-repo/security-check-mcp/issues)
- Discussions: [GitHub Discussions](https://github.com/your-repo/security-check-mcp/discussions)

---

**정보보안 의식 고취를 위해 함께 노력합시다! 🔐**

------ 다음은 설치 및 사용 상세 가이드입니다. -------

# 🔒 MCP 시스템 보안 점검 도구 - 완전 설치 및 사용 가이드

## 🚀 1단계: 환경 준비

### 1.1 필요 조건 확인
- **운영체제**: Windows 10/11
- **Python**: 3.8 이상
- **권장**: 관리자 권한으로 실행

### 1.2 Python 설치 확인
```bash
# 명령 프롬프트에서 확인
python --version
# 또는
python3 --version
```

## 📦 2단계: 프로젝트 설정

### 2.1 프로젝트 폴더 생성
```bash
mkdir security-check-mcp
cd security-check-mcp
```

### 2.2 필요한 파일 생성

**파일 1: 요구사항(MCP,FASTMCP) 설치
```
pip install mcp
pip install fastmcp
```

**파일 2: security_check_mcp.py**
(위에서 제공한 전체 코드를 복사해서 저장)

### 2.3 가상환경 생성 (권장)
```bash
# 가상환경 생성
python -m venv security_env

# 가상환경 활성화
# Windows
security_env\Scripts\activate

# 의존성(요구사항) 설치
pip install mcp
pip install fastmcp
```

## ⚙️ 3단계: Claude Desktop에 MCP 연결

### 3.1 Claude Desktop 설정 파일 수정

Claude Desktop의 설정 파일에 MCP 서버를 추가해야 합니다:

**Windows에서 설정 파일 위치:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

**설정 파일 내용 예시:**
```json
{
  "mcpServers": {
    "security-check": {
      "command": "python",
      "args": ["C:\\path\\to\\your\\security-check-mcp\\security_check_mcp.py"],
      "env": {}
    }
  }
}
```

### 3.2 경로 설정 주의사항
- `C:\\path\\to\\your\\security-check-mcp\\security_check_mcp.py` 부분을 실제 파일 경로로 변경
- 백슬래시(`\`)를 두 번 사용하거나 슬래시(`/`) 사용
- 가상환경 사용 시 python 경로도 가상환경 경로로 설정

## 🔧 4단계: MCP 서버 실행 및 테스트

### 4.1 직접 실행으로 테스트
```bash
# 관리자 권한으로 명령 프롬프트 실행 후
cd C:\path\to\your\security-check-mcp
python security_check_mcp.py
```

**정상 실행 시 출력 예시:**
```
==================================================
시스템 보안 점검 MCP 서버 시작
==================================================
사용 가능한 도구:
- check_system_updates(): 시스템 업데이트 상태 점검
- check_firewall_status(): 방화벽 상태 점검
- check_antivirus_status(): 백신 상태 점검
- run_comprehensive_security_check(): 종합 보안 점검
- get_security_recommendations(): 보안 권장사항 제공
==================================================
⚠️  관리자 권한으로 실행하면 더 정확한 점검 결과를 얻을 수 있습니다.
```

### 4.2 Claude Desktop 재시작
- Claude Desktop 완전 종료 후 다시 시작
- MCP 연결 상태 확인

## 💬 5단계: Claude를 통한 사용법

### 5.1 기본 사용 명령어

Claude에게 다음과 같이 요청하세요:

**종합 점검:**
```
내 컴퓨터 보안 상태를 종합적으로 점검해줘
```

**개별 점검:**
```
시스템 업데이트 상태만 확인해줘
방화벽 설정을 점검해줘
백신 상태를 확인해줘
```

**보안 권장사항:**
```
시스템 보안 강화 방법을 알려줘
```

### 5.2 Claude 응답 예시

사용자가 "내 컴퓨터 보안 상태를 점검해줘"라고 요청하면, Claude는 다음과 같이 응답합니다:

1. **MCP 도구 실행**: `run_comprehensive_security_check()` 호출
2. **결과 분석**: 점검 결과를 분석하여 이해하기 쉽게 설명
3. **조치사항 제공**: 발견된 문제에 대한 구체적인 해결 방법 제시
4. **우선순위 제공**: 중요한 보안 이슈부터 우선 처리하도록 안내

## 🔍 6단계: 결과 해석 가이드

### 6.1 시스템 업데이트 점검 결과
- ✅ **정상**: 최신 업데이트가 설치되고 자동 업데이트가 활성화됨
- ⚠️ **주의**: 일부 업데이트가 보류 중
- ❌ **위험**: 중요한 보안 업데이트가 미설치됨

### 6.2 방화벽 점검 결과
- ✅ **정상**: 방화벽이 활성화되고 적절한 규칙이 설정됨
- ⚠️ **주의**: 일부 의심스러운 허용 규칙 존재
- ❌ **위험**: 방화벽이 비활성화되거나 너무 많은 허용 규칙

### 6.3 백신 점검 결과
- ✅ **정상**: 백신이 활성화되고 정의 파일이 최신
- ⚠️ **주의**: 백신은 설치되었으나 일부 기능이 비활성화
- ❌ **위험**: 백신이 설치되지 않았거나 완전히 비활성화

## 🚨 7단계: 문제 해결

### 7.1 일반적인 오류와 해결방법

**"모듈을 찾을 수 없습니다" 오류:**
```bash
pip install mcp fastmcp
```

**권한 관련 오류:**
- 관리자 권한으로 명령 프롬프트 실행
- 또는 UAC 설정 확인

**PowerShell 실행 정책 오류:**
```powershell
# PowerShell을 관리자 권한으로 실행 후
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Claude에서 MCP 도구가 인식되지 않는 경우:**
1. claude_desktop_config.json 파일 경로 및 내용 재확인
2. Claude Desktop 완전 재시작
3. MCP 서버가 정상 실행되는지 확인

### 7.2 디버깅 방법

**MCP 연결 상태 확인:**
Claude에게 다음과 같이 물어보세요:
```
사용 가능한 도구들을 보여줘
```

**로그 확인:**
MCP 서버 실행 창에서 오류 메시지 확인

## 📋 8단계: 고급 사용법

### 8.1 정기 점검 스케줄링
Windows 작업 스케줄러를 사용하여 정기적으로 점검 실행:

```batch
# batch 파일 생성 (security_check.bat)
@echo off
cd C:\path\to\your\security-check-mcp
python security_check_mcp.py
```

### 8.2 결과 로깅
점검 결과를 파일로 저장하려면 코드 수정:

```python
# 결과를 파일로 저장하는 기능 추가
with open(f"security_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", "w", encoding="utf-8") as f:
    json.dump(result, f, ensure_ascii=False, indent=2)
```

## 🎯 9단계: 실제 사용 시나리오

### 시나리오 1: 정기 보안 점검
```
매주 월요일 오전에 Claude에게:
"이번 주 시스템 보안 점검을 해주세요. 지난주와 달라진 점이 있다면 알려주세요."
```

### 시나리오 2: 의심스러운 활동 후 점검
```
"시스템에서 이상한 동작을 발견했는데, 보안 상태를 긴급 점검해주세요."
```

### 시나리오 3: 새 소프트웨어 설치 후 점검
```
"새 프로그램을 설치한 후 방화벽 규칙이 어떻게 변경되었는지 확인해주세요."
```

이제 MCP 시스템 보안 점검 도구를 완전히 활용할 수 있습니다! 추가 질문이나 문제가 있으시면 언제든 말씀해 주세요.
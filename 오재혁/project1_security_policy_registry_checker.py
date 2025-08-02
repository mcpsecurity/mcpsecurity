from mcp.server.fastmcp import FastMCP
import winreg  # Windows 레지스트리 접근 모듈
import json
import os
from datetime import datetime
from typing import Dict, List, Any
import requests  # Claude API 호출 위해 추가

mcp = FastMCP(name="system_security_checker", host="127.0.0.1", port=5002, timeout=30)

# @mcp.tool()
# def scan_sensitive_data():
#     return "스캔 완료"

# if __name__ == "__main__":
#     mcp.run()

# MCP 서버 생성 (127.0.0.1:5002)
mcp = FastMCP(name="system_security_checker", host="127.0.0.1", port=5002, timeout=30)

# Claude API 호출 함수 추가
def call_claude_api(prompt_text: str) -> str:
    CLAUDE_API_URL = "https://api.anthropic.com/v1/complete"
    API_KEY = os.getenv("CLAUDE_API_KEY")  # ✅ 반드시 환경 변수로 설정되어 있어야 함
    
    if not API_KEY:
        return "❌ Claude API 키가 설정되지 않았습니다."


    headers = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json",
    }
    data = {
        "model": "claude-v1",
        "prompt": f"\n\nHuman: {prompt_text}\n\nAssistant:",
        "max_tokens_to_sample": 500,
        "temperature": 0.5,
        "stop_sequences": ["\n\nHuman:"]
    }
    try:
        response = requests.post(CLAUDE_API_URL, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        return result.get("completion", "응답이 없습니다.")
    except Exception as e:
        return f"❌ Claude API 호출 중 오류 발생: {str(e)}"
    

# 보안 점검 항목 정의: 레지스트리 위치, 기대값, 설명 포함
SECURITY_CHECKS = {
    "firewall_settings": {
        "key": winreg.HKEY_LOCAL_MACHINE,
        "path": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        "values": {
            "EnableFirewall": {"expected": 1, "description": "Windows 방화벽 활성화"},
            "DisableNotifications": {"expected": 0, "description": "방화벽 알림 활성화"}
        }
    },
    "auto_update": {
        "key": winreg.HKEY_LOCAL_MACHINE,
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update",
        "values": {
            "AUOptions": {"expected": 4, "description": "자동 업데이트 활성화"}
        }
    },
    "uac_settings": {
        "key": winreg.HKEY_LOCAL_MACHINE,
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "values": {
            "EnableLUA": {"expected": 1, "description": "사용자 계정 컨트롤(UAC) 활성화"},
            "ConsentPromptBehaviorAdmin": {"expected": 2, "description": "관리자 승격 프롬프트 동작"}
        }
    },
    "password_policy": {
        "key": winreg.HKEY_LOCAL_MACHINE,
        "path": r"SYSTEM\CurrentControlSet\Control\Lsa",
        "values": {
            "NoLMHash": {"expected": 1, "description": "LM 해시 저장 비활성화"}
        }
    },
    "remote_desktop": {
        "key": winreg.HKEY_LOCAL_MACHINE,
        "path": r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "values": {
            "fDenyTSConnections": {"expected": 1, "description": "원격 데스크톱 연결 비활성화"}
        }
    },
    "network_security": {
        "key": winreg.HKEY_LOCAL_MACHINE,
        "path": r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "values": {
            "RequireSecuritySignature": {"expected": 1, "description": "SMB 서명 요구"}
        }
    }
}

# 레지스트리 값을 읽는 함수, 예외 처리 포함
def read_registry_value(hkey: int, key_path: str, value_name: str) -> tuple:
    try:
        with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_READ) as key:
            value, reg_type = winreg.QueryValueEx(key, value_name)
            return value, None
    except FileNotFoundError:
        return None, "레지스트리 키를 찾을 수 없습니다."
    except PermissionError:
        return None, "레지스트리 키에 대한 접근 권한이 없습니다."
    except Exception as e:
        return None, f"레지스트리 읽기 오류: {str(e)}"

# 한 카테고리 보안 설정을 검사하는 함수
def analyze_security_setting(category: str, config: Dict[str, Any]) -> Dict[str, Any]:
    results = {
        "category": category,
        "status": "PASS",
        "issues": [],
        "recommendations": [],
        "details": {}
    }
    for value_name, expected_config in config["values"].items():
        current_value, error = read_registry_value(config["key"], config["path"], value_name)
        if error:
            results["status"] = "ERROR"
            results["issues"].append(f"{value_name}: {error}")
            continue
        expected_value = expected_config["expected"]
        description = expected_config["description"]
        results["details"][value_name] = {
            "current": current_value,
            "expected": expected_value,
            "description": description,
            "compliant": current_value == expected_value
        }
        if current_value != expected_value:
            results["status"] = "FAIL"
            results["issues"].append(f"{description}: 현재값 {current_value}, 권장값 {expected_value}")
            results["recommendations"].append(f"{description} 설정을 {expected_value}로 변경하세요.")
    return results

# 내부 파일 저장 함수 (c:/test/)
def write_file_internal(file_name: str, content: str) -> str:
    try:
        os.makedirs("c:/test", exist_ok=True)
        file_path = os.path.join("c:/test", file_name)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"파일 '{file_name}' 가 생성되었습니다."
    except Exception as e:
        return f"파일 쓰기 오류: {str(e)}"

# 내부 파일 읽기 함수 (c:/test/)
def read_file_internal(file_name: str) -> str:
    try:
        file_path = os.path.join("c:/test", file_name)
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            return content
        else:
            return None
    except Exception:
        return None

# MCP 도구: 전체 레지스트리 보안 점검 및 보고서 생성
@mcp.tool()
def check_registry_security() -> dict:
    try:
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        security_report = {
            "scan_time": scan_time,
            "overall_status": "PASS",
            "categories_passed": 0,
            "categories_failed": 0,
            "categories_error": 0,
            "total_issues": 0,
            "critical_issues": [],
            "detailed_results": {}
        }
        for category, config in SECURITY_CHECKS.items():
            result = analyze_security_setting(category, config)
            security_report["detailed_results"][category] = result
            if result["status"] == "PASS":
                security_report["categories_passed"] += 1
            elif result["status"] == "FAIL":
                security_report["categories_failed"] += 1
                security_report["total_issues"] += len(result["issues"])
                security_report["critical_issues"].extend(result["issues"])
            elif result["status"] == "ERROR":
                security_report["categories_error"] += 1
                security_report["critical_issues"].extend(result["issues"])
        if security_report["categories_failed"] > 0 or security_report["categories_error"] > 0:
            security_report["overall_status"] = "FAIL"
        report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        write_file_internal(report_filename, json.dumps(security_report, indent=2, ensure_ascii=False))
        summary = f"""
=== Windows 레지스트리 보안 점검 보고서 ===
점검 시간: {scan_time}
전체 상태: {security_report['overall_status']}

📊 점검 결과 요약:
- 통과: {security_report['categories_passed']}개 카테고리
- 실패: {security_report['categories_failed']}개 카테고리  
- 오류: {security_report['categories_error']}개 카테고리
- 총 발견된 문제: {security_report['total_issues']}개

🔍 주요 발견사항:
"""
        for category, result in security_report["detailed_results"].items():
            summary += f"\n[{category.upper()}] - {result['status']}"
            if result["issues"]:
                for issue in result["issues"]:
                    summary += f"\n  ❌ {issue}"
        summary += f"\n\n📋 상세 보고서가 '{report_filename}' 파일에 저장되었습니다."

        # Claude API 호출 부분 추가
        prompt_for_claude = f"다음 Windows 보안 점검 요약 내용을 쉽게 설명해줘:\n{summary}"
        claude_response = call_claude_api(prompt_for_claude)

        return {
            "status" : "완료",
            "summary" : summary,
            "claude_explanation" : claude_response,
            "result" : security_report
        }

    except Exception as e:
        return f"시스템 보안 점검 중 오류가 발생했습니다: {str(e)}"
    
@mcp.tool()
def scan_sensitive_data():
    return check_registry_security()


# MCP 도구: 최근 보고서 기반 권장사항 출력
@mcp.tool()
def get_security_recommendations() -> str:
    try:
        test_dir = "c:/test"
        if not os.path.exists(test_dir):
            return "이전 보안 점검 결과를 찾을 수 없습니다. 먼저 check_registry_security()를 실행해주세요."
        report_files = [f for f in os.listdir(test_dir) if f.startswith("security_report_") and f.endswith(".json")]
        if not report_files:
            return "이전 보안 점검 결과를 찾을 수 없습니다. 먼저 check_registry_security()를 실행해주세요."
        latest_report = max(report_files)
        report_content = read_file_internal(latest_report)
        if report_content is None:
            return "보고서 파일을 읽을 수 없습니다."
        report_data = json.loads(report_content)
        recommendations = """
=== 보안 문제 해결 방안 ===

🔧 권장 조치사항:
"""
        has_recommendations = False
        for category, result in report_data["detailed_results"].items():
            if result["status"] == "FAIL" and result["recommendations"]:
                recommendations += f"\n[{category.upper()}]"
                for rec in result["recommendations"]:
                    recommendations += f"\n  ✅ {rec}"
                recommendations += "\n"
                has_recommendations = True
        if not has_recommendations:
            recommendations += "\n현재 발견된 보안 문제가 없습니다. 시스템이 양호한 상태입니다.\n"
        recommendations += """
⚠️ 주의사항:
- 레지스트리 수정 전 시스템 백업을 권장합니다.
- 일부 설정은 시스템 재부팅 후 적용됩니다.
- 조직의 보안 정책에 따라 설정값이 다를 수 있습니다.

🔍 추가 점검 권장사항:
- Windows Defender 실시간 보호 상태 확인
- 정기적인 보안 업데이트 설치
- 사용자 계정 권한 검토
- 네트워크 보안 설정 점검
"""
        return recommendations
    except Exception as e:
        return f"보안 권장사항 생성 중 오류가 발생했습니다: {str(e)}"

# MCP 도구: 파일 읽기
@mcp.tool()
def read_file(file_name: str) -> str:
    try:
        file_path = os.path.join("c:/test", file_name)
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            return f"파일 '{file_name}' 의 내용은:\n{content}"
        else:
            return f"파일 '{file_name}' 는 존재하지 않습니다."
    except Exception as e:
        return f"파일 읽기 오류: {str(e)}"

# MCP 도구: 파일 쓰기
@mcp.tool()
def write_file(file_name: str, content: str) -> str:
    try:
        os.makedirs("c:/test", exist_ok=True)
        file_path = os.path.join("c:/test", file_name)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"파일 '{file_name}' 가 생성되었습니다."
    except Exception as e:
        return f"파일 쓰기 오류: {str(e)}"

# 서버 실행부
if __name__ == "__main__":
    try:
        print("Windows 보안 점검 MCP 서버를 시작합니다...")
        print("서버 주소: http://127.0.0.1:5002")

        # ✅ 직접 호출 (테스트용)
        # result = check_registry_security()
        # print(json.dumps(result, indent=2, ensure_ascii=False))

        # MCP 도구 서버 시작
        mcp.run()
    except Exception as e:
        print(f"서버 시작 중 오류가 발생했습니다: {str(e)}")
        input("Press Enter to exit...")


from mcp.server.fastmcp import FastMCP
import psutil
import json
import os
import re
import hashlib
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Tuple
import requests  # Claude API 호출용 라이브러리

mcp = FastMCP(name="sensitive_data_scanner", host="127.0.0.1", port=5004, timeout=60)

@mcp.tool()
def scan_sensitive_data():
    return "스캔 완료"

if __name__ == "__main__":
    mcp.run()

# MCP 서버 생성 (127.0.0.1:5003)
mcp = FastMCP(name="malware_detection_checker", host="127.0.0.1", port=5003, timeout=30)

# 악성코드 의심 프로세스 탐지용 패턴 및 임계값 정의
SUSPICIOUS_PATTERNS = {
    "suspicious_names": [
        r".*\.tmp\.exe$", r".*\.scr$", r".*\.pif$", r".*\.bat\.exe$",
        r"^[a-f0-9]{8,}\.exe$", r"^temp\d+\.exe$", r"^[0-9]+\.exe$",
        r"^[a-zA-Z]{1,3}\.exe$", r".*\d{8,}\.exe$"
    ],
    "legitimate_system_processes": [
        "svchost.exe", "winlogon.exe", "explorer.exe", "lsass.exe",
        "csrss.exe", "wininit.exe", "services.exe", "smss.exe"
    ],
    "suspicious_paths": [
        r"C:\\Windows\\Temp\\.*",
        r"C:\\Users\\.*\\AppData\\Local\\Temp\\.*",
        r"C:\\Temp\\.*",
        r"C:\\ProgramData\\.*\.exe$",
        r".*\\Desktop\\.*\.exe$",
        r".*\\Downloads\\.*\.exe$",
        r".*\\Public\\.*\.exe$"
    ],
    "high_resource_thresholds": {
        "cpu_threshold": 80.0,                      # CPU 사용률 임계값 (80%)
        "memory_threshold": 500 * 1024 * 1024,     # 메모리 사용량 임계값 (500MB)
        "io_threshold": 100 * 1024 * 1024           # I/O 임계값 (100MB/s)
    },
    "suspicious_ports": [1433, 3389, 4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345]  # 의심 포트 리스트
}

# 파일 쓰기 함수
def write_file(filename: str, content: str) -> None:
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
    except Exception as e:
        print(f"파일 쓰기 오류: {e}")

# 프로세스 행동 분석 함수
def analyze_process_behavior(process: psutil.Process) -> Dict[str, Any]:
    try:
        # 프로세스 기본 정보 초기화
        info = {
            "pid": process.pid,
            "name": process.name(),
            "exe": "N/A",
            "cmdline": "N/A",
            "cwd": "N/A",
            "create_time": datetime.fromtimestamp(process.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
            "status": process.status(),
            "username": "N/A"
        }
        
        # 실행 파일 경로 가져오기 (권한 예외 처리)
        try:
            info["exe"] = process.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
            
        # 명령행 인자 가져오기
        try:
            info["cmdline"] = " ".join(process.cmdline())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
            
        # 현재 작업 디렉토리 가져오기
        try:
            info["cwd"] = process.cwd()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
            
        # 프로세스 소유자 정보 가져오기
        try:
            info["username"] = process.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        # 리소스 사용량 수집
        try:
            cpu_percent = process.cpu_percent(interval=1)
            memory_info = process.memory_info()
            io_counters = process.io_counters() if hasattr(process, 'io_counters') else None
            
            info.update({
                "cpu_percent": cpu_percent,
                "memory_rss": memory_info.rss,
                "memory_vms": memory_info.vms,
                "io_read_bytes": io_counters.read_bytes if io_counters else 0,
                "io_write_bytes": io_counters.write_bytes if io_counters else 0
            })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            info.update({
                "cpu_percent": 0,
                "memory_rss": 0,
                "memory_vms": 0,
                "io_read_bytes": 0,
                "io_write_bytes": 0
            })
        
        # 네트워크 연결 정보 수집
        try:
            connections = process.connections()
            info["network_connections"] = len(connections)
            info["listening_ports"] = [conn.laddr.port for conn in connections if conn.status == 'LISTEN']
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            info["network_connections"] = 0
            info["listening_ports"] = []
        
        return info
        
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return {"error": str(e), "pid": process.pid}

# 의심도 점수 계산 함수 (0~100)
def calculate_suspicion_score(process_info: Dict[str, Any]) -> Tuple[int, List[str]]:
    score = 0
    reasons = []
    
    if "error" in process_info:
        return 0, ["프로세스 정보 접근 불가"]
    
    process_name = process_info.get("name", "").lower()
    process_exe = process_info.get("exe", "").lower()
    
    # 1. 의심스러운 프로세스 이름 패턴 검사
    for pattern in SUSPICIOUS_PATTERNS["suspicious_names"]:
        if re.match(pattern, process_name, re.IGNORECASE):
            score += 20
            reasons.append(f"의심스러운 프로세스 이름 패턴: {process_name}")
            break
    
    # 2. 의심스러운 실행 경로 검사
    for pattern in SUSPICIOUS_PATTERNS["suspicious_paths"]:
        if re.match(pattern, process_exe, re.IGNORECASE):
            score += 25
            reasons.append(f"의심스러운 실행 경로: {process_exe}")
            break
    
    # 3. 시스템 프로세스 위장 여부 검사
    if process_name in SUSPICIOUS_PATTERNS["legitimate_system_processes"]:
        if not process_exe.lower().startswith("c:\\windows\\system32\\"):
            score += 30
            reasons.append(f"시스템 프로세스 위장 의심: {process_name}")
    
    # 4. 비정상적 리소스 사용량 검사
    cpu_percent = process_info.get("cpu_percent", 0)
    memory_usage = process_info.get("memory_rss", 0)
    
    if cpu_percent > SUSPICIOUS_PATTERNS["high_resource_thresholds"]["cpu_threshold"]:
        score += 15
        reasons.append(f"비정상적으로 높은 CPU 사용량: {cpu_percent:.1f}%")
    
    if memory_usage > SUSPICIOUS_PATTERNS["high_resource_thresholds"]["memory_threshold"]:
        score += 10
        reasons.append(f"비정상적으로 높은 메모리 사용량: {memory_usage // (1024*1024)}MB")
    
    # 5. 네트워크 연결 및 포트 검사
    network_connections = process_info.get("network_connections", 0)
    listening_ports = process_info.get("listening_ports", [])
    
    if network_connections > 20:
        score += 10
        reasons.append(f"과도한 네트워크 연결: {network_connections}개")
    
    for port in listening_ports:
        if port in SUSPICIOUS_PATTERNS["suspicious_ports"]:
            score += 20
            reasons.append(f"의심스러운 포트 사용: {port}")
    
    # 6. 명령행 인자 내 의심 단어 검사
    cmdline = process_info.get("cmdline", "").lower()
    suspicious_args = ["powershell", "cmd", "wget", "curl", "certutil", "bitsadmin"]
    for arg in suspicious_args:
        if arg in cmdline:
            score += 5
            reasons.append(f"의심스러운 명령행 인자: {arg}")
    
    return min(score, 100), reasons

# MCP 도구: 파일 쓰기 (이미 존재하는 함수지만 코드 흐름상 포함)
def write_file(filename: str, content: str) -> None:
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
    except Exception as e:
        print(f"파일 쓰기 오류: {e}")

# Claude API 호출 함수
def call_claude_api(prompt: str) -> str:
    api_url = "https://api.anthropic.com/v1/complete"
    api_key = os.getenv("CLAUDE_API_KEY")
    if not api_key:
        return "❌ CLAUDE_API_KEY 환경변수가 설정되어 있지 않습니다."

    headers = {
        "x-api-key": api_key,
        "Content-Type": "application/json"
    }
    data = {
        "model": "claude-v1",
        "prompt": f"\n\nHuman: {prompt}\n\nAssistant:",
        "max_tokens_to_sample": 200,
        "temperature": 0.5,
        "stop_sequences": ["\n\nHuman:"]
    }

    try:
        response = requests.post(api_url, headers=headers, json=data, timeout=15)
        response.raise_for_status()
        result = response.json()
        return result.get("completion", "응답이 없습니다.")
    except Exception as e:
        return f"❌ Claude API 호출 중 오류 발생: {str(e)}"

# MCP 도구: 의심 프로세스 스캔 (원래 있던 함수에 claude 호출 추가 포함)
@mcp.tool()
def scan_suspicious_processes() -> str:
    try:
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        all_processes = []
        suspicious_processes = []
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                process_info = analyze_process_behavior(proc)
                if "error" not in process_info:
                    score, reasons = calculate_suspicion_score(process_info)
                    
                    process_data = {
                        "process_info": process_info,
                        "suspicion_score": score,
                        "reasons": reasons
                    }
                    
                    all_processes.append(process_data)
                    
                    if score >= 30:  # 의심도 30 이상인 경우
                        suspicious_processes.append(process_data)
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # 보고서 생성
        report = {
            "scan_time": scan_time,
            "total_processes": len(all_processes),
            "suspicious_count": len(suspicious_processes),
            "high_risk_count": len([p for p in suspicious_processes if p["suspicion_score"] >= 70]),
            "medium_risk_count": len([p for p in suspicious_processes if 50 <= p["suspicion_score"] < 70]),
            "low_risk_count": len([p for p in suspicious_processes if 30 <= p["suspicion_score"] < 50]),
            "suspicious_processes": suspicious_processes
        }
        
        # 결과 JSON 파일 저장
        report_filename = f"malware_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        write_file(report_filename, json.dumps(report, indent=2, ensure_ascii=False))
        
        # 요약 보고서 문자열 생성
        summary = f"""
=== 악성코드 의심 프로세스 탐지 보고서 ===
스캔 시간: {scan_time}
총 프로세스 수: {report['total_processes']}개
의심 프로세스 수: {report['suspicious_count']}개

🚨 위험도별 분류:
- 높음 (70점 이상): {report['high_risk_count']}개
- 중간 (50-69점): {report['medium_risk_count']}개  
- 낮음 (30-49점): {report['low_risk_count']}개

🔍 의심 프로세스 상세:
"""
        
        for proc_data in suspicious_processes[:10]:  # 상위 10개만 표시
            proc_info = proc_data["process_info"]
            score = proc_data["suspicion_score"]
            reasons = proc_data["reasons"]
            
            risk_level = "높음" if score >= 70 else "중간" if score >= 50 else "낮음"
            
            summary += f"""
[{risk_level}] {proc_info['name']} (PID: {proc_info['pid']}) - 의심도: {score}점
- 실행 파일: {proc_info['exe']}
- 메모리 사용량: {proc_info['memory_rss'] // (1024*1024)}MB
- CPU 사용량: {proc_info['cpu_percent']}%
- 의심 사유: {', '.join(reasons[:3])}
"""
        
        if len(suspicious_processes) > 10:
            summary += f"\n... 외 {len(suspicious_processes) - 10}개 더 (상세 보고서 참조)"
        
        summary += f"\n\n📋 상세 보고서: {report_filename}"
        
        # — 여기서 claude에게 요약 리포트 평가 요청 후 결과 받기
        claude_prompt = f"다음은 악성코드 의심 프로세스 스캔 요약입니다. 의심 프로세스들이 실제 악성 가능성이 얼마나 되는지, 추가로 추천할 만한 조치가 있으면 알려주세요:\n{summary}"
        claude_response = call_claude_api(claude_prompt)
        
        summary += f"\n\n🤖 Claude 분석:\n{claude_response}"
        
        return summary
        
    except Exception as e:
        return f"프로세스 스캔 중 오류가 발생했습니다: {str(e)}"

# MCP 도구: 의심 프로세스 종료 (신중히 사용)
@mcp.tool()
def kill_suspicious_process(pid: int) -> str:
    try:
        process = psutil.Process(pid)
        process_name = process.name()
        
        # 시스템 중요 프로세스 리스트
        critical_processes = [
            "winlogon.exe", "csrss.exe", "services.exe", "lsass.exe",
            "wininit.exe", "smss.exe", "dwm.exe", "explorer.exe"
        ]
        
        if process_name.lower() in [p.lower() for p in critical_processes]:
            return f"❌ 중요한 시스템 프로세스는 종료할 수 없습니다: {process_name}"
        
        # 프로세스 정상 종료 시도
        process.terminate()
        
        # 3초 대기 후 강제 종료 시도
        try:
            process.wait(timeout=3)
        except psutil.TimeoutExpired:
            process.kill()
            process.wait()
        
        return f"✅ 프로세스가 성공적으로 종료되었습니다: {process_name} (PID: {pid})"
        
    except psutil.NoSuchProcess:
        return f"❌ 프로세스를 찾을 수 없습니다: PID {pid}"
    except psutil.AccessDenied:
        return f"❌ 프로세스 종료 권한이 없습니다: PID {pid} (관리자 권한 필요)"
    except Exception as e:
        return f"❌ 프로세스 종료 중 오류가 발생했습니다: {str(e)}"

# MCP 도구: 특정 프로세스 상세 정보 조회
@mcp.tool()
def get_process_details(pid: int) -> str:
    try:
        process = psutil.Process(pid)
        process_info = analyze_process_behavior(process)
        
        if "error" in process_info:
            return f"❌ 프로세스 정보를 가져올 수 없습니다: {process_info['error']}"
        
        score, reasons = calculate_suspicion_score(process_info)
        
        # 상세 정보 출력 문자열 생성
        details = f"""
=== 프로세스 상세 정보 ===
📋 기본 정보:
- 프로세스 ID: {process_info['pid']}
- 이름: {process_info['name']}
- 실행 파일: {process_info['exe']}
- 상태: {process_info['status']}
- 사용자: {process_info['username']}
- 생성 시간: {process_info['create_time']}
- 작업 디렉토리: {process_info['cwd']}

💻 리소스 사용량:
- CPU 사용률: {process_info['cpu_percent']}%
- 메모리 사용량: {process_info['memory_rss'] // (1024*1024)}MB (RSS)
- 가상 메모리: {process_info['memory_vms'] // (1024*1024)}MB (VMS)
- I/O 읽기: {process_info['io_read_bytes'] // (1024*1024)}MB
- I/O 쓰기: {process_info['io_write_bytes'] // (1024*1024)}MB

🌐 네트워크 정보:
- 연결 수: {process_info['network_connections']}개
- 수신 포트: {process_info['listening_ports']}

🔍 명령행 인자:
{process_info['cmdline']}

🚨 의심도 분석:
- 의심도 점수: {score}/100
- 위험도: {"높음" if score >= 70 else "중간" if score >= 50 else "낮음" if score >= 30 else "정상"}
- 의심 사유: {', '.join(reasons) if reasons else '없음'}
"""
        
        return details
        
    except psutil.NoSuchProcess:
        return f"❌ 프로세스를 스캔하지 못하였습니다."

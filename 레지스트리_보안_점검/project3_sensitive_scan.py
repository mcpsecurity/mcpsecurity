from mcp.server.fastmcp import FastMCP
import os
import re
import json
import glob
import mimetypes
from datetime import datetime
from typing import Dict, List, Any, Set
import hashlib
import requests  # Claude API 호출용 라이브러리


# MCP 서버 생성
mcp = FastMCP(name="sensitive_data_scanner", host="127.0.0.1", port=5004, timeout=60)

# 민감한 데이터 패턴 정의
SENSITIVE_PATTERNS = {
    "credit_card": {
        "patterns": [
            r"\b4[0-9]{12}(?:[0-9]{3})?\b",  # Visa
            r"\b5[1-5][0-9]{14}\b",          # MasterCard
            r"\b3[47][0-9]{13}\b",           # American Express
            r"\b3[0-9]{4}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}\b",  # Diners Club
            r"\b(?:\d{4}[\s\-]?){3}\d{4}\b"  # 일반적인 신용카드 패턴
        ],
        "description": "신용카드 번호",
        "severity": "HIGH"
    },
    "ssn": {
        "patterns": [
            r"\b\d{3}-\d{2}-\d{4}\b",        # 미국 SSN
            r"\b\d{6}-\d{7}\b",              # 한국 주민등록번호
            r"\b\d{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])-[1-4][0-9]{6}\b"  # 한국 주민등록번호 상세
        ],
        "description": "주민등록번호/사회보장번호",
        "severity": "CRITICAL"
    },
    "phone": {
        "patterns": [
            r"\b\d{3}-\d{3,4}-\d{4}\b",      # 한국 전화번호
            r"\b\d{2,3}-\d{3,4}-\d{4}\b",   # 일반 전화번호
            r"\b\(\d{3}\)\s?\d{3}-\d{4}\b",  # 미국 전화번호
            r"\b\+\d{1,3}\s?\d{1,3}\s?\d{3,4}\s?\d{4}\b"  # 국제 전화번호
        ],
        "description": "전화번호",
        "severity": "MEDIUM"
    },
    "email": {
        "patterns": [
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        ],
        "description": "이메일 주소",
        "severity": "LOW"
    },
    "ip_address": {
        "patterns": [
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        ],
        "description": "IP 주소",
        "severity": "LOW"
    },
    "password": {
        "patterns": [
            r"(?i)password\s*[:=]\s*['\"]?([^'\"\\s]+)",
            r"(?i)pwd\s*[:=]\s*['\"]?([^'\"\\s]+)",
            r"(?i)pass\s*[:=]\s*['\"]?([^'\"\\s]+)",
            r"(?i)secret\s*[:=]\s*['\"]?([^'\"\\s]+)"
        ],
        "description": "비밀번호",
        "severity": "CRITICAL"
    },
    "api_key": {
        "patterns": [
            r"(?i)api[_\-]?key\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,})",
            r"(?i)access[_\-]?token\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,})",
            r"(?i)secret[_\-]?key\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,})"
        ],
        "description": "API 키/토큰",
        "severity": "HIGH"
    },
    "bank_account": {
        "patterns": [
            r"\b\d{10,16}\b",  # 일반적인 계좌번호
            r"\b\d{3}-\d{2}-\d{6}\b",  # 한국 계좌번호 형식
            r"\b\d{3}-\d{6}-\d{2}\b"   # 다른 계좌번호 형식
        ],
        "description": "은행 계좌번호",
        "severity": "HIGH"
    }
}

# 검색 대상 디렉토리 및 파일 확장자
SCAN_LOCATIONS = [
    os.path.expanduser("~"),  # 사용자 홈 디렉토리
    "C:\\Temp\\",
    "C:\\Windows\\Temp\\",
    "C:\\ProgramData\\"
]

SCAN_EXTENSIONS = [
    ".txt", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".log", ".csv",
    ".json", ".xml", ".cfg", ".conf", ".ini", ".sql", ".bak",
    ".py", ".js", ".html", ".htm", ".php", ".asp", ".aspx"
]

# 제외할 디렉토리 (성능 및 안정성)
EXCLUDE_DIRS = [
    "Windows\\System32", "Windows\\WinSxS", "Windows\\assembly",
    "Program Files", "Program Files (x86)", "AppData\\Local\\Microsoft",
    "node_modules", ".git", ".svn", "__pycache__"
]

def is_excluded_directory(path: str) -> bool:
    """제외할 디렉토리인지 확인"""
    path_lower = path.lower()
    for exclude_dir in EXCLUDE_DIRS:
        if exclude_dir.lower() in path_lower:
            return True
    return False

def is_text_file(file_path: str) -> bool:
    """텍스트 파일인지 확인"""
    try:
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type and mime_type.startswith('text'):
            return True
        
        # 확장자로도 확인
        _, ext = os.path.splitext(file_path.lower())
        return ext in SCAN_EXTENSIONS
    except:
        return False

def scan_file_content(file_path: str) -> List[Dict[str, Any]]:
    """파일 내용에서 민감한 데이터 스캔"""
    findings = []
    
    try:
        # 파일 크기 제한 (10MB)
        if os.path.getsize(file_path) > 10 * 1024 * 1024:
            return findings
        
        # 텍스트 파일만 스캔
        if not is_text_file(file_path):
            return findings
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # 각 패턴으로 검사
        for pattern_name, pattern_info in SENSITIVE_PATTERNS.items():
            for pattern in pattern_info["patterns"]:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                
                for match in matches:
                    # 컨텍스트 추출 (앞뒤 50자)
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].replace('\n', ' ').replace('\r', ' ')
                    
                    # 라인 번호 계산
                    line_num = content[:match.start()].count('\n') + 1
                    
                    finding = {
                        "file_path": file_path,
                        "pattern_type": pattern_name,
                        "description": pattern_info["description"],
                        "severity": pattern_info["severity"],
                        "matched_text": match.group(0),
                        "line_number": line_num,
                        "context": context,
                        "file_size": os.path.getsize(file_path),
                        "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                    }
                    findings.append(finding)
        
    except Exception as e:
        pass  # 파일 읽기 오류 무시
    
    return findings

def get_files_to_scan(directories: List[str], max_files: int = 1000) -> List[str]:
    """스캔할 파일 목록 생성"""
    files_to_scan = []
    
    for directory in directories:
        if not os.path.exists(directory):
            continue
        
        try:
            for root, dirs, files in os.walk(directory):
                # 제외할 디렉토리 필터링
                if is_excluded_directory(root):
                    dirs.clear()  # 하위 디렉토리도 스캔하지 않음
                    continue
                
                # 숨김 디렉토리 제외
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                for file in files:
                    if len(files_to_scan) >= max_files:
                        return files_to_scan
                    
                    file_path = os.path.join(root, file)
                    
                    # 파일 확장자 확인
                    _, ext = os.path.splitext(file.lower())
                    if ext in SCAN_EXTENSIONS:
                        files_to_scan.append(file_path)
        
        except (PermissionError, OSError):
            continue
    
    return files_to_scan

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
        "max_tokens_to_sample": 300,
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

@mcp.tool()
def scan_sensitive_data(target_directories: str = None, max_files: int = 500) -> str:
    """
    지정된 디렉토리에서 민감한 데이터를 스캔합니다.
    
    Args:
        target_directories: 스캔할 디렉토리 (쉼표로 구분, 미지정시 기본 위치)
        max_files: 최대 스캔할 파일 수
    """
    try:
        scan_start_time = datetime.now()
        
        # 스캔할 디렉토리 결정
        if target_directories:
            directories = [d.strip() for d in target_directories.split(',')]
        else:
            directories = SCAN_LOCATIONS
        
        # 존재하는 디렉토리만 필터링
        directories = [d for d in directories if os.path.exists(d)]
        
        if not directories:
            return "❌ 스캔할 유효한 디렉토리가 없습니다."
        
        # 스캔할 파일 목록 생성
        files_to_scan = get_files_to_scan(directories, max_files)
        
        if not files_to_scan:
            return "❌ 스캔할 파일이 없습니다."
        
        # 파일 스캔 실행
        all_findings = []
        scanned_files = 0
        
        for file_path in files_to_scan:
            try:
                findings = scan_file_content(file_path)
                all_findings.extend(findings)
                scanned_files += 1
                
                # 진행상황 출력 (매 100파일마다)
                if scanned_files % 100 == 0:
                    print(f"스캔 진행중... {scanned_files}/{len(files_to_scan)} 파일")
                    
            except Exception as e:
                continue
        
        # 결과 분석
        scan_end_time = datetime.now()
        scan_duration = (scan_end_time - scan_start_time).total_seconds()
        
        # 심각도별 분류
        critical_findings = [f for f in all_findings if f['severity'] == 'CRITICAL']
        high_findings = [f for f in all_findings if f['severity'] == 'HIGH']
        medium_findings = [f for f in all_findings if f['severity'] == 'MEDIUM']
        low_findings = [f for f in all_findings if f['severity'] == 'LOW']
        
        # 보고서 생성
        report = {
            "scan_info": {
                "start_time": scan_start_time.isoformat(),
                "end_time": scan_end_time.isoformat(),
                "duration_seconds": scan_duration,
                "directories_scanned": directories,
                "files_scanned": scanned_files,
                "total_findings": len(all_findings)
            },
            "severity_summary": {
                "critical": len(critical_findings),
                "high": len(high_findings),
                "medium": len(medium_findings),
                "low": len(low_findings)
            },
            "findings": all_findings
        }
        
        # 보고서 파일 저장
        report_filename = f"sensitive_data_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(report_filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"보고서 저장 실패: {e}")
        
        # 요약 보고서 생성
        summary = f"""
=== 민감한 데이터 스캔 보고서 ===
🕐 스캔 시간: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')} ~ {scan_end_time.strftime('%H:%M:%S')}
⏱️ 소요 시간: {scan_duration:.1f}초
📁 스캔 디렉토리: {len(directories)}개
📄 스캔 파일: {scanned_files}개

🚨 발견된 민감 데이터:
- 🔴 CRITICAL: {len(critical_findings)}건
- 🟠 HIGH: {len(high_findings)}건  
- 🟡 MEDIUM: {len(medium_findings)}건
- 🔵 LOW: {len(low_findings)}건
- 📊 총합: {len(all_findings)}건

🔍 상위 발견 항목:
"""
        
        # 심각도 높은 순으로 상위 10개 표시
        sorted_findings = sorted(all_findings, key=lambda x: 
            {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}[x['severity']], reverse=True)
        
        for i, finding in enumerate(sorted_findings[:10]):
            severity_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}[finding['severity']]
            summary += f"""
{i+1}. {severity_icon} {finding['description']}
   📁 파일: {finding['file_path']}
   📍 위치: {finding['line_number']}행
   🔎 내용: {finding['matched_text'][:50]}...
"""
        
        if len(all_findings) > 10:
            summary += f"\n... 외 {len(all_findings) - 10}건 더 (상세 보고서 참조)"
        
        summary += f"\n\n📋 상세 보고서: {report_filename}"
        
        if len(critical_findings) > 0 or len(high_findings) > 0:
            summary += "\n\n⚠️ 주의: 높은 위험도의 민감한 데이터가 발견되었습니다. 즉시 보안 조치를 취하세요!"

        # Claude API 호출하여 분석
        claude_prompt = (
            f"다음은 민감한 데이터 스캔 결과 요약입니다. "
            f"발견된 민감한 데이터의 심각성과 보안 대응 방안을 간단히 분석해 주세요.\n\n{summary}"
        )
        claude_response = call_claude_api(claude_prompt)
        summary += f"\n\n🤖 Claude 분석:\n{claude_response}"
        
        return summary
        
    except Exception as e:
        return f"❌ 민감한 데이터 스캔 중 오류가 발생했습니다: {str(e)}"

@mcp.tool()
def scan_specific_file(file_path: str) -> str:
    """
    특정 파일에서 민감한 데이터를 스캔합니다.
    """
    try:
        if not os.path.exists(file_path):
            return f"❌ 파일을 찾을 수 없습니다: {file_path}"
        
        if not is_text_file(file_path):
            return f"❌ 텍스트 파일이 아닙니다: {file_path}"
        
        findings = scan_file_content(file_path)
        
        if not findings:
            return f"✅ 민감한 데이터가 발견되지 않았습니다: {file_path}"
        
        # 결과 포맷팅
        result = f"📄 파일: {file_path}\n🔍 발견된 민감 데이터: {len(findings)}건\n\n"
        
        for i, finding in enumerate(findings, 1):
            severity_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}[finding['severity']]
            result += f"""
{i}. {severity_icon} {finding['description']} ({finding['severity']})
   📍 위치: {finding['line_number']}행
   🔎 발견 내용: {finding['matched_text']}
   📝 컨텍스트: {finding['context'][:100]}...
"""
        
        return result
        
    except Exception as e:
        return f"❌ 파일 스캔 중 오류가 발생했습니다: {str(e)}"

@mcp.tool()
def get_scan_patterns() -> str:
    """
    현재 설정된 민감한 데이터 검색 패턴을 조회합니다.
    """
    try:
        patterns_info = "=== 민감한 데이터 검색 패턴 ===\n\n"
        
        for pattern_name, pattern_info in SENSITIVE_PATTERNS.items():
            severity_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}[pattern_info['severity']]
            patterns_info += f"{severity_icon} {pattern_name} ({pattern_info['description']})\n"
            for p in pattern_info["patterns"]:
                patterns_info += f"  - {p}\n"
            patterns_info += "\n"
        
        return patterns_info
    except Exception as e:
        return f"❌ 패턴 조회 중 오류가 발생했습니다: {str(e)}"
    

if __name__ == "__main__":
    
    try:
        print("서버 주소: http://127.0.0.1:5004")
        mcp.run()
        
    except KeyboardInterrupt:
        print("\n서버가 종료되었습니다.")
    except Exception as e:
        print(f"서버 실행 중 오류: {e}")

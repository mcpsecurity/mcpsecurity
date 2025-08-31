"""
AI를 통한 오픈소스 시스템 취약점 점검 MCP 서버
GitHub: https://github.com/your-repo/security-check-mcp
라이센스: MIT License

이 도구는 Windows 시스템의 기본적인 보안 상태를 점검합니다:
1. 시스템 업데이트 상태 점검
2. 방화벽 정책 점검  
3. 백신/보안 소프트웨어 상태 점검

사용법:
1. 이 MCP 서버를 실행합니다
2. Claude에게 "내 컴퓨터 보안 상태를 점검해줘"라고 요청합니다
3. Claude가 이 도구들을 사용하여 시스템을 점검하고 결과를 분석합니다
"""

import subprocess
import json
import winreg
import ctypes
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any
from mcp.server.fastmcp import FastMCP

# 관리자 권한 확인 함수
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# PowerShell 명령 실행 함수
def run_powershell_command(command: str) -> str:
    try:
        result = subprocess.run(
            ["powershell", "-Command", command],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "명령 실행 시간 초과"
    except Exception as e:
        return f"오류 발생: {str(e)}"

 
# MCP 서버 생성
mcp = FastMCP(name="security_check_mcp")
 
 
# 간단한 에코 도구
@mcp.tool()
def echo(message: str) -> str:
    return message + " 라는 메시지가 입력되었습니다. 안찍어 볼 수 없죠! hello world!"
 
@mcp.tool()
def hello(message: str) -> str:
    return message + "안녕하세요!" 
 
@mcp.tool()
def check_system_updates() -> str:
    """
    Windows 시스템 업데이트 상태를 점검합니다.
    
    Returns:
        str: 업데이트 상태 점검 결과 (JSON 형태)
    """
    try:
        # Windows Update 서비스 상태 확인
        update_service_cmd = "Get-Service -Name 'wuauserv' | Select-Object Status, StartType"
        service_status = run_powershell_command(update_service_cmd)
        
        # 최근 설치된 업데이트 확인 (최근 30일)
        recent_updates_cmd = """
        Get-WmiObject -Class Win32_QuickFixEngineering | 
        Where-Object {$_.InstalledOn -gt (Get-Date).AddDays(-30)} | 
        Select-Object HotFixID, Description, InstalledOn | 
        ConvertTo-Json
        """
        recent_updates = run_powershell_command(recent_updates_cmd)
        
        # 보류 중인 업데이트 확인
        pending_updates_cmd = """
        if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
            Import-Module PSWindowsUpdate
            Get-WindowsUpdate -AcceptAll -Download -Install -IgnoreReboot | ConvertTo-Json
        } else {
            "PSWindowsUpdate 모듈이 설치되지 않음"
        }
        """
        pending_updates = run_powershell_command(pending_updates_cmd)
        
        # 자동 업데이트 설정 확인
        auto_update_cmd = """
        $AUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
        @{
            'NotificationLevel' = $AUSettings.NotificationLevel
            'ScheduledInstallationDay' = $AUSettings.ScheduledInstallationDay
            'ScheduledInstallationTime' = $AUSettings.ScheduledInstallationTime
        } | ConvertTo-Json
        """
        auto_update_settings = run_powershell_command(auto_update_cmd)
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "update_service_status": service_status,
            "recent_updates": recent_updates,
            "pending_updates": pending_updates,
            "auto_update_settings": auto_update_settings,
            "admin_required": not is_admin(),
            "check_status": "완료"
        }
        
        return json.dumps(result, ensure_ascii=False, indent=2)
        
    except Exception as e:
        error_result = {
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "check_status": "오류 발생",
            "admin_required": not is_admin()
        }
        return json.dumps(error_result, ensure_ascii=False, indent=2)

@mcp.tool()
def check_firewall_status() -> str:
    """
    Windows 방화벽 정책 및 상태를 점검합니다.
    
    Returns:
        str: 방화벽 상태 점검 결과 (JSON 형태)
    """
    try:
        # 방화벽 프로필 상태 확인
        firewall_profiles_cmd = """
        Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogFileName | ConvertTo-Json
        """
        firewall_profiles = run_powershell_command(firewall_profiles_cmd)
        
        # 방화벽 규칙 통계
        firewall_rules_cmd = """
        $AllRules = Get-NetFirewallRule
        $EnabledRules = $AllRules | Where-Object {$_.Enabled -eq $true}
        $InboundRules = $EnabledRules | Where-Object {$_.Direction -eq 'Inbound'}
        $OutboundRules = $EnabledRules | Where-Object {$_.Direction -eq 'Outbound'}
        
        @{
            'TotalRules' = $AllRules.Count
            'EnabledRules' = $EnabledRules.Count
            'InboundRules' = $InboundRules.Count
            'OutboundRules' = $OutboundRules.Count
        } | ConvertTo-Json
        """
        firewall_rules_stats = run_powershell_command(firewall_rules_cmd)
        
        # 의심스러운 허용 규칙 확인
        suspicious_rules_cmd = """
        Get-NetFirewallRule | Where-Object {
            $_.Enabled -eq $true -and 
            $_.Direction -eq 'Inbound' -and 
            $_.Action -eq 'Allow' -and
            $_.DisplayName -notlike '*Windows*' -and
            $_.DisplayName -notlike '*Microsoft*'
        } | Select-Object DisplayName, Direction, Action, Enabled -First 10 | ConvertTo-Json
        """
        suspicious_rules = run_powershell_command(suspicious_rules_cmd)
        
        # Windows Defender 방화벽 서비스 상태
        firewall_service_cmd = """
        Get-Service -Name 'MpsSvc' | Select-Object Status, StartType | ConvertTo-Json
        """
        firewall_service = run_powershell_command(firewall_service_cmd)
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "firewall_profiles": firewall_profiles,
            "firewall_rules_stats": firewall_rules_stats,
            "suspicious_rules": suspicious_rules,
            "firewall_service": firewall_service,
            "admin_required": not is_admin(),
            "check_status": "완료"
        }
        
        return json.dumps(result, ensure_ascii=False, indent=2)
        
    except Exception as e:
        error_result = {
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "check_status": "오류 발생",
            "admin_required": not is_admin()
        }
        return json.dumps(error_result, ensure_ascii=False, indent=2)

@mcp.tool()
def check_antivirus_status() -> str:
    """
    백신 및 보안 소프트웨어 상태를 점검합니다.
    
    Returns:
        str: 백신 상태 점검 결과 (JSON 형태)
    """
    try:
        # Windows Defender 상태 확인
        defender_status_cmd = """
        Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, 
        IoavProtectionEnabled, OnAccessProtectionEnabled, AntivirusSignatureLastUpdated, 
        AntivirusSignatureVersion | ConvertTo-Json
        """
        defender_status = run_powershell_command(defender_status_cmd)
        
        # 설치된 보안 소프트웨어 확인
        security_software_cmd = """
        Get-CimInstance -Namespace 'root\\SecurityCenter2' -ClassName 'AntivirusProduct' | 
        Select-Object DisplayName, ProductState, Timestamp | ConvertTo-Json
        """
        security_software = run_powershell_command(security_software_cmd)
        
        # Windows Security Center 상태
        security_center_cmd = """
        Get-Service -Name 'SecurityHealthService' | Select-Object Status, StartType | ConvertTo-Json
        """
        security_center = run_powershell_command(security_center_cmd)
        
        # 실시간 보호 기능 확인
        realtime_protection_cmd = """
        Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring, 
        DisableOnAccessProtection, DisableIOAVProtection, DisableScriptScanning | ConvertTo-Json
        """
        realtime_protection = run_powershell_command(realtime_protection_cmd)
        
        # 최근 스캔 정보
        scan_history_cmd = """
        Get-MpThreatDetection | Select-Object -First 5 ActionSuccess, DetectionTime, 
        ThreatName, Resources | ConvertTo-Json
        """
        scan_history = run_powershell_command(scan_history_cmd)
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "defender_status": defender_status,
            "installed_security_software": security_software,
            "security_center_service": security_center,
            "realtime_protection_settings": realtime_protection,
            "recent_threat_detections": scan_history,
            "admin_required": not is_admin(),
            "check_status": "완료"
        }
        
        return json.dumps(result, ensure_ascii=False, indent=2)
        
    except Exception as e:
        error_result = {
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "check_status": "오류 발생",
            "admin_required": not is_admin()
        }
        return json.dumps(error_result, ensure_ascii=False, indent=2)

@mcp.tool()
def run_comprehensive_security_check() -> str:
    """
    종합적인 시스템 보안 점검을 실행합니다.
    모든 보안 점검 도구를 순차적으로 실행하고 결과를 통합합니다.
    
    Returns:
        str: 종합 보안 점검 결과 (JSON 형태)
    """
    try:
        print("시스템 보안 점검을 시작합니다...")
        
        # 1. 시스템 업데이트 점검
        print("1. 시스템 업데이트 상태 점검 중...")
        update_results = check_system_updates()
        
        # 2. 방화벽 점검
        print("2. 방화벽 상태 점검 중...")
        firewall_results = check_firewall_status()
        
        # 3. 백신 점검
        print("3. 백신 상태 점검 중...")
        antivirus_results = check_antivirus_status()
        
        # 결과 통합
        comprehensive_result = {
            "timestamp": datetime.now().isoformat(),
            "system_info": {
                "os": os.name,
                "admin_privileges": is_admin(),
                "python_version": sys.version
            },
            "update_check": json.loads(update_results),
            "firewall_check": json.loads(firewall_results),
            "antivirus_check": json.loads(antivirus_results),
            "overall_status": "점검 완료"
        }
        
        return json.dumps(comprehensive_result, ensure_ascii=False, indent=2)
        
    except Exception as e:
        error_result = {
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "overall_status": "점검 실패",
            "admin_required": not is_admin()
        }
        return json.dumps(error_result, ensure_ascii=False, indent=2)

@mcp.tool()
def get_security_recommendations() -> str:
    """
    시스템 보안 강화를 위한 일반적인 권장사항을 제공합니다.
    
    Returns:
        str: 보안 권장사항 (JSON 형태)
    """
    recommendations = {
        "timestamp": datetime.now().isoformat(),
        "general_recommendations": {
            "system_updates": [
                "정기적으로 Windows 업데이트를 확인하고 설치하세요",
                "자동 업데이트를 활성화하여 보안 패치가 자동으로 설치되도록 하세요",
                "중요한 보안 업데이트는 즉시 설치하세요"
            ],
            "firewall": [
                "Windows 방화벽을 항상 활성화하세요",
                "불필요한 인바운드 규칙을 제거하세요",
                "의심스러운 외부 연결을 차단하세요",
                "방화벽 로그를 정기적으로 확인하세요"
            ],
            "antivirus": [
                "신뢰할 수 있는 백신 소프트웨어를 설치하고 실시간 보호를 활성화하세요",
                "바이러스 정의 파일을 항상 최신 상태로 유지하세요",
                "정기적으로 전체 시스템 스캔을 실행하세요",
                "의심스러운 파일은 실행하지 마세요"
            ],
            "additional_security": [
                "강력한 비밀번호를 사용하고 정기적으로 변경하세요",
                "이중 인증(2FA)을 활성화하세요",
                "정기적으로 시스템 백업을 수행하세요",
                "불필요한 서비스와 프로그램을 제거하세요",
                "최신 보안 위협 정보를 정기적으로 확인하세요"
            ]
        },
        "emergency_actions": [
            "의심스러운 활동이 감지되면 즉시 인터넷 연결을 차단하세요",
            "시스템이 감염되었다고 의심되면 전문가의 도움을 받으세요",
            "중요한 파일은 안전한 곳에 백업하세요",
            "보안 사고 발생 시 관련 로그를 보존하세요"
        ]
    }
    
    return json.dumps(recommendations, ensure_ascii=False, indent=2)

# 서버 실행
if __name__ == "__main__":
    mcp.run()
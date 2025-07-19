import json
import os
import re
import subprocess
import winreg
import hashlib
import psutil
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import requests

@dataclass
class AutorunEntry:
    """자동 실행 항목 정보"""
    name: str
    path: str
    command: str
    location: str  # 발견 위치 (레지스트리 키, 폴더 등)
    enabled: bool
    description: str
    digital_signature: Optional[str]
    file_hash: Optional[str]
    risk_level: str  # HIGH, MEDIUM, LOW, SAFE
    analysis_result: str

@dataclass
class ScheduledTask:
    """스케줄 작업 정보"""
    name: str
    path: str
    state: str
    next_run: Optional[str]
    last_run: Optional[str]
    author: str
    description: str
    actions: List[str]
    triggers: List[str]
    risk_level: str
    analysis_result: str

@dataclass
class SuspiciousIndicator:
    """의심스러운 지표"""
    indicator_type: str
    value: str
    description: str
    severity: str

class AutorunAnalyzer:
    def __init__(self):
        self.autorun_entries = []
        self.scheduled_tasks = []
        self.suspicious_indicators = []
        
        # 화이트리스트 - 알려진 안전한 프로그램들
        self.whitelist = {
            'processes': {
                'explorer.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe', 'lsass.exe',
                'services.exe', 'svchost.exe', 'spoolsv.exe', 'dwm.exe', 'taskhost.exe',
                'taskhostw.exe', 'sihost.exe', 'winlogon.exe', 'userinit.exe',
                'ctfmon.exe', 'rundll32.exe', 'conhost.exe', 'fontdrvhost.exe',
                'wininit.exe', 'audiodg.exe', 'dllhost.exe', 'runtimebroker.exe',
                'searchindexer.exe', 'wuauclt.exe', 'wmiprvse.exe', 'mscorsvw.exe',
                'ngen.exe', 'ngentask.exe', 'trustedinstaller.exe', 'tiworker.exe'
            },
            'paths': {
                'c:\\windows\\system32\\',
                'c:\\windows\\syswow64\\',
                'c:\\program files\\',
                'c:\\program files (x86)\\',
                'c:\\windows\\',
                'c:\\programdata\\microsoft\\',
                'c:\\users\\all users\\microsoft\\'
            },
            'publishers': {
                'Microsoft Corporation',
                'Microsoft Windows',
                'Google LLC',
                'Adobe Systems Incorporated',
                'Intel Corporation',
                'NVIDIA Corporation',
                'Realtek Semiconductor',
                'Apple Inc.',
                'Mozilla Corporation',
                'Oracle Corporation'
            }
        }
        
        # 의심스러운 패턴
        self.suspicious_patterns = {
            'file_names': [
                r'.*\.tmp\.exe$',
                r'.*\d{5,}\.exe$',
                r'svchost\.exe$',  # 시스템 폴더가 아닌 경우
                r'csrss\.exe$',    # 시스템 폴더가 아닌 경우
                r'winlogon\.exe$', # 시스템 폴더가 아닌 경우
                r'.*[0-9a-f]{8,}\.exe$',
                r'.*backup.*\.exe$',
                r'.*update.*\.exe$',
                r'.*service.*\.exe$'
            ],
            'paths': [
                r'.*\\temp\\.*',
                r'.*\\appdata\\roaming\\.*',
                r'.*\\appdata\\local\\temp\\.*',
                r'.*\\downloads\\.*',
                r'.*\\desktop\\.*',
                r'.*\\documents\\.*',
                r'.*\\music\\.*',
                r'.*\\pictures\\.*',
                r'.*\\videos\\.*'
            ],
            'command_lines': [
                r'.*powershell.*-enc.*',
                r'.*powershell.*-encoded.*',
                r'.*powershell.*-windowstyle hidden.*',
                r'.*cmd.*\/c.*',
                r'.*rundll32.*',
                r'.*regsvr32.*',
                r'.*mshta.*',
                r'.*wscript.*',
                r'.*cscript.*',
                r'.*bitsadmin.*'
            ]
        }

    def get_registry_autorun_entries(self) -> List[AutorunEntry]:
        """레지스트리에서 자동 실행 항목 추출"""
        entries = []
        
        # 주요 자동 실행 레지스트리 키
        autorun_keys = [
            # 현재 사용자 시작 프로그램
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            
            # 모든 사용자 시작 프로그램
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            
            # 32비트 프로그램 (64비트 시스템에서)
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        
        for hkey, subkey_path in autorun_keys:
            try:
                registry_key = winreg.OpenKey(hkey, subkey_path)
                key_name = f"{hkey}\\{subkey_path}"
                
                # 값 개수 확인
                num_values = winreg.QueryInfoKey(registry_key)[1]
                
                for i in range(num_values):
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(registry_key, i)
                        
                        if value_type == winreg.REG_SZ or value_type == winreg.REG_EXPAND_SZ:
                            entry = self._create_autorun_entry(
                                value_name, value_data, key_name
                            )
                            if entry:
                                entries.append(entry)
                    except WindowsError:
                        continue
                
                winreg.CloseKey(registry_key)
            except WindowsError:
                continue
        
        return entries

    def get_startup_folders(self) -> List[AutorunEntry]:
        """시작 폴더에서 자동 실행 항목 추출"""
        entries = []
        
        # 시작 폴더 경로들
        startup_folders = [
            Path(os.environ.get('APPDATA', '')) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup',
            Path(os.environ.get('ALLUSERSPROFILE', '')) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup',
            Path('C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup')
        ]
        
        for folder in startup_folders:
            if folder.exists():
                for item in folder.iterdir():
                    if item.is_file():
                        entry = self._create_autorun_entry(
                            item.name, str(item), f"Startup Folder: {folder}"
                        )
                        if entry:
                            entries.append(entry)
        
        return entries

    def get_scheduled_tasks(self) -> List[ScheduledTask]:
        """스케줄 작업 목록 추출"""
        tasks = []
        
        try:
            # schtasks 명령어로 작업 목록 가져오기
            result = subprocess.run([
                'schtasks', '/query', '/fo', 'csv', '/v'
            ], capture_output=True, text=True, encoding='utf-8')
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    headers = lines[0].split(',')
                    headers = [h.strip('"') for h in headers]
                    
                    for line in lines[1:]:
                        if line.strip():
                            values = self._parse_csv_line(line)
                            if len(values) >= len(headers):
                                task_data = dict(zip(headers, values))
                                task = self._create_scheduled_task(task_data)
                                if task:
                                    tasks.append(task)
        except Exception as e:
            print(f"스케줄 작업 조회 중 오류: {e}")
        
        return tasks

    def _parse_csv_line(self, line: str) -> List[str]:
        """CSV 라인 파싱 (따옴표 처리 포함)"""
        values = []
        current_value = ""
        in_quotes = False
        
        for char in line:
            if char == '"':
                in_quotes = not in_quotes
            elif char == ',' and not in_quotes:
                values.append(current_value.strip())
                current_value = ""
            else:
                current_value += char
        
        values.append(current_value.strip())
        return values

    def _create_autorun_entry(self, name: str, command: str, location: str) -> Optional[AutorunEntry]:
        """자동 실행 항목 생성"""
        if not name or not command:
            return None
        
        # 경로 추출
        path = self._extract_path_from_command(command)
        
        # 파일 해시 계산
        file_hash = self._calculate_file_hash(path) if path and os.path.exists(path) else None
        
        # 디지털 서명 확인
        digital_signature = self._get_digital_signature(path) if path and os.path.exists(path) else None
        
        # 위험도 평가
        risk_level, analysis_result = self._analyze_autorun_risk(name, path, command, location)
        
        # 설명 추출
        description = self._get_file_description(path) if path and os.path.exists(path) else ""
        
        return AutorunEntry(
            name=name,
            path=path or "",
            command=command,
            location=location,
            enabled=True,
            description=description,
            digital_signature=digital_signature,
            file_hash=file_hash,
            risk_level=risk_level,
            analysis_result=analysis_result
        )

    def _create_scheduled_task(self, task_data: Dict) -> Optional[ScheduledTask]:
        """스케줄 작업 생성"""
        try:
            name = task_data.get('TaskName', '').strip('\\')
            path = task_data.get('Task To Run', '')
            state = task_data.get('Status', '')
            next_run = task_data.get('Next Run Time', '')
            last_run = task_data.get('Last Run Time', '')
            author = task_data.get('Author', '')
            
            # 위험도 평가
            risk_level, analysis_result = self._analyze_task_risk(name, path, author)
            
            return ScheduledTask(
                name=name,
                path=path,
                state=state,
                next_run=next_run if next_run != 'N/A' else None,
                last_run=last_run if last_run != 'N/A' else None,
                author=author,
                description=task_data.get('Comment', ''),
                actions=[path],
                triggers=[],
                risk_level=risk_level,
                analysis_result=analysis_result
            )
        except Exception as e:
            print(f"스케줄 작업 생성 중 오류: {e}")
            return None

    def _extract_path_from_command(self, command: str) -> Optional[str]:
        """명령어에서 실행 파일 경로 추출"""
        if not command:
            return None
        
        # 따옴표로 둘러싸인 경로 추출
        quote_match = re.search(r'"([^"]+)"', command)
        if quote_match:
            path = quote_match.group(1)
            if os.path.exists(path):
                return path
        
        # 공백으로 구분된 첫 번째 토큰 (경로)
        first_token = command.split()[0] if command.split() else ""
        if first_token and os.path.exists(first_token):
            return first_token
        
        # 확장자 기반 추출
        exe_match = re.search(r'([^\s]+\.exe)', command, re.IGNORECASE)
        if exe_match:
            path = exe_match.group(1)
            if os.path.exists(path):
                return path
        
        return None

    def _calculate_file_hash(self, file_path: str) -> Optional[str]:
        """파일 해시 계산"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                while chunk := f.read(8192):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except Exception:
            return None

    def _get_digital_signature(self, file_path: str) -> Optional[str]:
        """디지털 서명 정보 추출"""
        try:
            result = subprocess.run([
                'powershell', '-Command',
                f'Get-AuthenticodeSignature -FilePath "{file_path}" | Select-Object -ExpandProperty SignerCertificate | Select-Object -ExpandProperty Subject'
            ], capture_output=True, text=True, encoding='utf-8')
            
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass
        
        return None

    def _get_file_description(self, file_path: str) -> str:
        """파일 설명 추출"""
        try:
            result = subprocess.run([
                'powershell', '-Command',
                f'(Get-ItemProperty -Path "{file_path}").VersionInfo.FileDescription'
            ], capture_output=True, text=True, encoding='utf-8')
            
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass
        
        return ""

    def _analyze_autorun_risk(self, name: str, path: str, command: str, location: str) -> Tuple[str, str]:
        """자동 실행 항목 위험도 분석"""
        risk_factors = []
        risk_score = 0
        
        # 파일 경로 분석
        if path:
            path_lower = path.lower()
            
            # 시스템 경로가 아닌 경우
            if not any(safe_path in path_lower for safe_path in self.whitelist['paths']):
                risk_score += 2
                risk_factors.append("시스템 경로가 아닌 위치")
            
            # 의심스러운 경로 패턴
            for pattern in self.suspicious_patterns['paths']:
                if re.search(pattern, path_lower):
                    risk_score += 3
                    risk_factors.append(f"의심스러운 경로 패턴")
                    break
            
            # 파일명 분석
            filename = os.path.basename(path_lower)
            for pattern in self.suspicious_patterns['file_names']:
                if re.search(pattern, filename):
                    risk_score += 3
                    risk_factors.append(f"의심스러운 파일명 패턴")
                    break
            
            # 알려진 프로세스 이름이지만 다른 경로에 있는 경우
            if filename in self.whitelist['processes'] and 'system32' not in path_lower:
                risk_score += 4
                risk_factors.append("시스템 프로세스 이름을 사용하지만 다른 경로")
        
        # 명령어 분석
        command_lower = command.lower()
        for pattern in self.suspicious_patterns['command_lines']:
            if re.search(pattern, command_lower):
                risk_score += 3
                risk_factors.append(f"의심스러운 명령어 패턴")
                break
        
        # 디지털 서명 확인
        signature = self._get_digital_signature(path) if path and os.path.exists(path) else None
        if not signature:
            risk_score += 2
            risk_factors.append("디지털 서명 없음")
        elif signature and not any(publisher in signature for publisher in self.whitelist['publishers']):
            risk_score += 1
            risk_factors.append("신뢰할 수 없는 게시자")
        
        # 위험도 결정
        if risk_score >= 6:
            risk_level = "HIGH"
        elif risk_score >= 3:
            risk_level = "MEDIUM"
        elif risk_score >= 1:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"
        
        analysis_result = "; ".join(risk_factors) if risk_factors else "정상적인 항목"
        
        return risk_level, analysis_result

    def _analyze_task_risk(self, name: str, path: str, author: str) -> Tuple[str, str]:
        """스케줄 작업 위험도 분석"""
        risk_factors = []
        risk_score = 0
        
        # 작업 이름 분석
        if not name or len(name) < 3:
            risk_score += 2
            risk_factors.append("의심스러운 작업 이름")
        
        # 경로 분석
        if path:
            path_lower = path.lower()
            
            # 시스템 경로가 아닌 경우
            if not any(safe_path in path_lower for safe_path in self.whitelist['paths']):
                risk_score += 2
                risk_factors.append("시스템 경로가 아닌 위치")
            
            # 의심스러운 경로 패턴
            for pattern in self.suspicious_patterns['paths']:
                if re.search(pattern, path_lower):
                    risk_score += 3
                    risk_factors.append(f"의심스러운 경로 패턴")
                    break
            
            # 의심스러운 명령어 패턴
            for pattern in self.suspicious_patterns['command_lines']:
                if re.search(pattern, path_lower):
                    risk_score += 3
                    risk_factors.append(f"의심스러운 명령어 패턴")
                    break
        
        # 작성자 분석
        if not author or author.lower() in ['unknown', 'n/a', '']:
            risk_score += 2
            risk_factors.append("알 수 없는 작성자")
        elif author and not any(publisher in author for publisher in self.whitelist['publishers']):
            risk_score += 1
            risk_factors.append("신뢰할 수 없는 작성자")
        
        # 위험도 결정
        if risk_score >= 6:
            risk_level = "HIGH"
        elif risk_score >= 3:
            risk_level = "MEDIUM"
        elif risk_score >= 1:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"
        
        analysis_result = "; ".join(risk_factors) if risk_factors else "정상적인 작업"
        
        return risk_level, analysis_result

    def detect_suspicious_patterns(self, entries: List[AutorunEntry], tasks: List[ScheduledTask]):
        """의심스러운 패턴 탐지"""
        # 중복 실행 파일 탐지
        file_paths = {}
        for entry in entries:
            if entry.path:
                path_lower = entry.path.lower()
                if path_lower in file_paths:
                    file_paths[path_lower].append(entry)
                else:
                    file_paths[path_lower] = [entry]
        
        for path, entries_list in file_paths.items():
            if len(entries_list) > 1:
                self.suspicious_indicators.append(SuspiciousIndicator(
                    indicator_type="중복 실행",
                    value=path,
                    description=f"같은 파일이 {len(entries_list)}개 위치에서 실행됨",
                    severity="MEDIUM"
                ))
        
        # 임시 폴더 실행 탐지
        temp_patterns = [r'.*\\temp\\.*', r'.*\\tmp\\.*', r'.*\\appdata\\local\\temp\\.*']
        for entry in entries:
            if entry.path:
                for pattern in temp_patterns:
                    if re.search(pattern, entry.path.lower()):
                        self.suspicious_indicators.append(SuspiciousIndicator(
                            indicator_type="임시 폴더 실행",
                            value=entry.path,
                            description="임시 폴더에서 실행되는 프로그램",
                            severity="HIGH"
                        ))
                        break

    def analyze_system(self):
        """시스템 전체 분석 실행"""
        print("=" * 60)
        print("Windows 자동실행 분석기")
        print("=" * 60)
        print()
        
        # 1. 레지스트리 자동 실행 항목 분석
        print("1. 레지스트리 자동 실행 항목 분석 중...")
        registry_entries = self.get_registry_autorun_entries()
        self.autorun_entries.extend(registry_entries)
        print(f"   발견된 항목: {len(registry_entries)}개")
        
        # 2. 시작 폴더 분석
        print("2. 시작 폴더 분석 중...")
        startup_entries = self.get_startup_folders()
        self.autorun_entries.extend(startup_entries)
        print(f"   발견된 항목: {len(startup_entries)}개")
        
        # 3. 스케줄 작업 분석
        print("3. 스케줄 작업 분석 중...")
        scheduled_tasks = self.get_scheduled_tasks()
        self.scheduled_tasks.extend(scheduled_tasks)
        print(f"   발견된 작업: {len(scheduled_tasks)}개")
        
        # 4. 의심스러운 패턴 탐지
        print("4. 의심스러운 패턴 탐지 중...")
        self.detect_suspicious_patterns(self.autorun_entries, self.scheduled_tasks)
        print(f"   발견된 의심 지표: {len(self.suspicious_indicators)}개")
        
        print()
        print("분석 완료!")
        print("=" * 60)

    def print_summary(self):
        """분석 결과 요약 출력"""
        print("\n📊 분석 결과 요약")
        print("-" * 40)
        
        # 자동 실행 항목 위험도별 통계
        risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
        for entry in self.autorun_entries:
            risk_counts[entry.risk_level] += 1
        
        print(f"🔍 자동 실행 항목: {len(self.autorun_entries)}개")
        print(f"   - 높은 위험: {risk_counts['HIGH']}개")
        print(f"   - 중간 위험: {risk_counts['MEDIUM']}개")
        print(f"   - 낮은 위험: {risk_counts['LOW']}개")
        print(f"   - 안전: {risk_counts['SAFE']}개")
        
        # 스케줄 작업 위험도별 통계
        task_risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
        for task in self.scheduled_tasks:
            task_risk_counts[task.risk_level] += 1
        
        print(f"\n⏰ 스케줄 작업: {len(self.scheduled_tasks)}개")
        print(f"   - 높은 위험: {task_risk_counts['HIGH']}개")
        print(f"   - 중간 위험: {task_risk_counts['MEDIUM']}개")
        print(f"   - 낮은 위험: {task_risk_counts['LOW']}개")
        print(f"   - 안전: {task_risk_counts['SAFE']}개")
        
        print(f"\n⚠️  의심스러운 지표: {len(self.suspicious_indicators)}개")

    def print_high_risk_items(self):
        """고위험 항목 상세 출력"""
        print("\n🚨 고위험 항목 상세")
        print("-" * 40)
        
        high_risk_entries = [entry for entry in self.autorun_entries if entry.risk_level == "HIGH"]
        high_risk_tasks = [task for task in self.scheduled_tasks if task.risk_level == "HIGH"]
        
        if not high_risk_entries and not high_risk_tasks:
            print("고위험 항목이 발견되지 않았습니다.")
            return
        
        # 고위험 자동 실행 항목
        if high_risk_entries:
            print("🔴 고위험 자동 실행 항목:")
            for i, entry in enumerate(high_risk_entries, 1):
                print(f"\n{i}. {entry.name}")
                print(f"   경로: {entry.path}")
                print(f"   위치: {entry.location}")
                print(f"   위험 요소: {entry.analysis_result}")
                if entry.digital_signature:
                    print(f"   디지털 서명: {entry.digital_signature}")
        
        # 고위험 스케줄 작업
        if high_risk_tasks:
            print("\n🔴 고위험 스케줄 작업:")
            for i, task in enumerate(high_risk_tasks, 1):
                print(f"\n{i}. {task.name}")
                print(f"   경로: {task.path}")
                print(f"   상태: {task.state}")
                print(f"   작성자: {task.author}")
                print(f"   위험 요소: {task.analysis_result}")

    def save_results(self, filename: str = "autorun_analysis_results.json"):
        """분석 결과를 JSON 파일로 저장"""
        results = {
            "analysis_date": datetime.now().isoformat(),
            "summary": {
                "total_autorun_entries": len(self.autorun_entries),
                "total_scheduled_tasks": len(self.scheduled_tasks),
                "total_suspicious_indicators": len(self.suspicious_indicators)
            },
            "autorun_entries": [
                {
                    "name": entry.name,
                    "path": entry.path,
                    "command": entry.command,
                    "location": entry.location,
                    "risk_level": entry.risk_level,
                    "analysis_result": entry.analysis_result,
                    "digital_signature": entry.digital_signature,
                    "file_hash": entry.file_hash
                }
                for entry in self.autorun_entries
            ],
            "scheduled_tasks": [
                {
                    "name": task.name,
                    "path": task.path,
                    "state": task.state,
                    "author": task.author,
                    "risk_level": task.risk_level,
                    "analysis_result": task.analysis_result
                }
                for task in self.scheduled_tasks
            ],
            "suspicious_indicators": [
                {
                    "type": indicator.indicator_type,
                    "value": indicator.value,
                    "description": indicator.description,
                    "severity": indicator.severity
                }
                for indicator in self.suspicious_indicators
            ]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 분석 결과가 '{filename}' 파일로 저장되었습니다.")

def main():
    """메인 실행 함수"""
    try:
        # 관리자 권한 확인
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠️  일부 기능은 관리자 권한이 필요할 수 있습니다.")
            print("   더 정확한 분석을 위해 관리자 권한으로 실행하는 것을 권장합니다.")
            print()
        
        # 분석기 생성 및 실행
        analyzer = AutorunAnalyzer()
        analyzer.analyze_system()
        
        # 결과 출력
        analyzer
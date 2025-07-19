import json
import re
import requests
import sqlite3
import subprocess
import winreg
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import threading
import time
from packaging import version
import hashlib
import sys
import os

@dataclass
class InstalledSoftware:
    """설치된 소프트웨어 정보"""
    name: str
    version: str
    vendor: str
    install_date: Optional[str]
    install_location: Optional[str]
    uninstall_string: Optional[str]
    registry_key: str

@dataclass
class Vulnerability:
    """취약점 정보"""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published_date: str
    modified_date: str
    affected_products: List[str]
    references: List[str]

@dataclass
class VulnerabilityMatch:
    """취약점 매칭 결과"""
    software: InstalledSoftware
    vulnerability: Vulnerability
    match_confidence: str  # HIGH, MEDIUM, LOW
    match_reason: str

class SoftwareVulnerabilityScanner:
    def __init__(self, cache_duration_hours: int = 24):
        self.cache_duration = timedelta(hours=cache_duration_hours)
        self.cache_file = Path("vulnerability_cache.db")
        self.init_database()
        self.cve_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Software-Vulnerability-Scanner/1.0'
        })
        
        # 소프트웨어 이름 매핑 (정규화를 위한)
        self.software_mappings = {
            'adobe reader': 'adobe acrobat reader',
            'adobe acrobat reader dc': 'adobe acrobat reader',
            'google chrome': 'chrome',
            'mozilla firefox': 'firefox',
            'microsoft office': 'office',
            'visual studio code': 'vscode',
            'notepad++': 'notepad plus plus',
            'vlc media player': 'vlc',
            'winrar': 'winrar',
            '7-zip': '7zip',
        }

    def init_database(self):
        """로컬 캐시 데이터베이스 초기화"""
        conn = sqlite3.connect(self.cache_file)
        cursor = conn.cursor()
        
        # CVE 캐시 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                data TEXT,
                cached_at TIMESTAMP,
                expires_at TIMESTAMP
            )
        ''')
        
        # 소프트웨어 스캔 기록 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                software_name TEXT,
                version TEXT,
                scan_date TIMESTAMP,
                vulnerabilities_found INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()

    def get_installed_software_registry(self) -> List[InstalledSoftware]:
        """Windows 레지스트리에서 설치된 소프트웨어 목록 추출"""
        if sys.platform != 'win32':
            print("이 기능은 Windows에서만 사용 가능합니다.")
            return []
            
        software_list = []
        
        # 64비트 및 32비트 소프트웨어 키 경로
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        ]
        
        for hkey, subkey_path in registry_paths:
            try:
                registry_key = winreg.OpenKey(hkey, subkey_path)
                
                # 하위 키 개수 확인
                num_subkeys = winreg.QueryInfoKey(registry_key)[0]
                
                for i in range(num_subkeys):
                    try:
                        subkey_name = winreg.EnumKey(registry_key, i)
                        subkey = winreg.OpenKey(registry_key, subkey_name)
                        
                        # 소프트웨어 정보 추출
                        software_info = self._extract_software_info(subkey, subkey_name)
                        if software_info:
                            software_list.append(software_info)
                        
                        winreg.CloseKey(subkey)
                    except WindowsError:
                        continue
                
                winreg.CloseKey(registry_key)
            except WindowsError:
                continue
        
        return software_list

    def _extract_software_info(self, registry_key, key_name: str) -> Optional[InstalledSoftware]:
        """레지스트리 키에서 소프트웨어 정보 추출"""
        try:
            # 필수 필드 추출
            try:
                display_name = winreg.QueryValueEx(registry_key, "DisplayName")[0]
            except FileNotFoundError:
                return None
            
            # 시스템 구성 요소나 업데이트 제외
            if self._should_exclude_software(display_name):
                return None
            
            # 선택적 필드 추출
            version = self._get_registry_value(registry_key, "DisplayVersion", "Unknown")
            vendor = self._get_registry_value(registry_key, "Publisher", "Unknown")
            install_date = self._get_registry_value(registry_key, "InstallDate", None)
            install_location = self._get_registry_value(registry_key, "InstallLocation", None)
            uninstall_string = self._get_registry_value(registry_key, "UninstallString", None)
            
            # 날짜 형식 변환
            if install_date and len(install_date) == 8:
                try:
                    install_date = f"{install_date[:4]}-{install_date[4:6]}-{install_date[6:8]}"
                except:
                    install_date = None
            
            return InstalledSoftware(
                name=display_name.strip(),
                version=version.strip() if version else "Unknown",
                vendor=vendor.strip() if vendor else "Unknown",
                install_date=install_date,
                install_location=install_location,
                uninstall_string=uninstall_string,
                registry_key=key_name
            )
            
        except Exception as e:
            print(f"소프트웨어 정보 추출 중 오류: {e}")
            return None

    def _get_registry_value(self, registry_key, value_name: str, default: Any) -> Any:
        """레지스트리 값 안전하게 가져오기"""
        try:
            return winreg.QueryValueEx(registry_key, value_name)[0]
        except FileNotFoundError:
            return default

    def _should_exclude_software(self, display_name: str) -> bool:
        """제외할 소프트웨어 판단"""
        exclude_patterns = [
            r"Microsoft Visual C\+\+ \d{4}",
            r"Microsoft \.NET Framework",
            r"Windows.*Update",
            r"Security Update",
            r"Hotfix",
            r"KB\d+",
            r"Microsoft Office.*MUI",
            r"Microsoft.*Runtime",
            r"DirectX",
            r"Windows.*Components",
            r"Microsoft.*Redistributable"
        ]
        
        for pattern in exclude_patterns:
            if re.search(pattern, display_name, re.IGNORECASE):
                return True
        
        return False

    def get_installed_software_wmic(self) -> List[InstalledSoftware]:
        """WMIC 명령어를 사용하여 설치된 소프트웨어 목록 추출"""
        if sys.platform != 'win32':
            print("이 기능은 Windows에서만 사용 가능합니다.")
            return []
            
        try:
            # WMIC 명령어 실행
            result = subprocess.run([
                'wmic', 'product', 'get', 
                'Name,Version,Vendor,InstallDate,InstallLocation', 
                '/format:csv'
            ], capture_output=True, text=True, encoding='utf-8')
            
            if result.returncode != 0:
                print("WMIC 명령어 실행 실패")
                return []
            
            software_list = []
            lines = result.stdout.strip().split('\n')[1:]  # 헤더 제거
            
            for line in lines:
                if line.strip():
                    parts = line.split(',')
                    if len(parts) >= 6:
                        software_list.append(InstalledSoftware(
                            name=parts[2].strip() if parts[2] else "Unknown",
                            version=parts[5].strip() if parts[5] else "Unknown",
                            vendor=parts[4].strip() if parts[4] else "Unknown",
                            install_date=parts[1].strip() if parts[1] else None,
                            install_location=parts[3].strip() if parts[3] else None,
                            uninstall_string=None,
                            registry_key="WMIC"
                        ))
            
            return software_list
            
        except Exception as e:
            print(f"WMIC를 통한 소프트웨어 목록 추출 중 오류: {e}")
            return []

    def get_sample_software(self) -> List[InstalledSoftware]:
        """테스트용 샘플 소프트웨어 목록 (Windows가 아닌 환경에서 사용)"""
        return [
            InstalledSoftware(
                name="Google Chrome",
                version="119.0.6045.199",
                vendor="Google LLC",
                install_date="2023-11-01",
                install_location="C:\\Program Files\\Google\\Chrome\\Application\\",
                uninstall_string=None,
                registry_key="sample_chrome"
            ),
            InstalledSoftware(
                name="Mozilla Firefox",
                version="120.0.1",
                vendor="Mozilla Corporation",
                install_date="2023-11-15",
                install_location="C:\\Program Files\\Mozilla Firefox\\",
                uninstall_string=None,
                registry_key="sample_firefox"
            ),
            InstalledSoftware(
                name="VLC Media Player",
                version="3.0.18",
                vendor="VideoLAN",
                install_date="2023-10-20",
                install_location="C:\\Program Files\\VideoLAN\\VLC\\",
                uninstall_string=None,
                registry_key="sample_vlc"
            )
        ]

    def normalize_software_name(self, name: str) -> str:
        """소프트웨어 이름 정규화"""
        name = name.lower().strip()
        
        # 매핑 테이블 적용
        for key, value in self.software_mappings.items():
            if key in name:
                return value
        
        # 일반적인 정규화 규칙
        name = re.sub(r'\s+', ' ', name)  # 다중 공백 제거
        name = re.sub(r'\(.*?\)', '', name)  # 괄호 내용 제거
        name = re.sub(r'\s+v?\d+(\.\d+)*.*$', '', name)  # 버전 정보 제거
        name = re.sub(r'\s+(x86|x64|32-bit|64-bit).*$', '', name)  # 아키텍처 정보 제거
        
        return name.strip()

    def search_cve_database(self, software_name: str, version: str) -> List[Vulnerability]:
        """CVE 데이터베이스에서 취약점 검색"""
        normalized_name = self.normalize_software_name(software_name)
        
        # 캐시에서 먼저 확인
        cached_cves = self._get_cached_cves(normalized_name)
        if cached_cves:
            return self._filter_cves_by_version(cached_cves, version)
        
        # NVD API를 통해 검색
        try:
            vulnerabilities = []
            
            # 키워드 기반 검색
            params = {
                'keywordSearch': normalized_name,
                'resultsPerPage': 100,
                'startIndex': 0
            }
            
            response = self.session.get(f"{self.cve_api_base}", params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for cve_item in data.get('vulnerabilities', []):
                    cve_data = cve_item.get('cve', {})
                    
                    # 취약점 정보 추출
                    vulnerability = self._parse_cve_data(cve_data)
                    if vulnerability and self._is_software_affected(vulnerability, normalized_name):
                        vulnerabilities.append(vulnerability)
                
                # 캐시에 저장
                self._cache_cves(normalized_name, vulnerabilities)
            
            return self._filter_cves_by_version(vulnerabilities, version)
            
        except requests.exceptions.RequestException as e:
            print(f"CVE 검색 중 네트워크 오류: {e}")
            return []
        except Exception as e:
            print(f"CVE 검색 중 오류: {e}")
            return []

    def _parse_cve_data(self, cve_data: Dict) -> Optional[Vulnerability]:
        """CVE 데이터 파싱"""
        try:
            cve_id = cve_data.get('id', '')
            
            # 설명 추출
            descriptions = cve_data.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')
            
            # 심각도 및 CVSS 점수 추출
            metrics = cve_data.get('metrics', {})
            cvss_score = 0.0
            severity = 'UNKNOWN'
            
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = self._cvss_v2_to_severity(cvss_score)
            
            # 날짜 정보
            published_date = cve_data.get('published', '')
            modified_date = cve_data.get('lastModified', '')
            
            # 영향받는 제품 추출
            affected_products = []
            configurations = cve_data.get('configurations', [])
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        if cpe_match.get('vulnerable', False):
                            affected_products.append(cpe_match.get('criteria', ''))
            
            # 참조 링크 추출
            references = []
            for ref in cve_data.get('references', []):
                references.append(ref.get('url', ''))
            
            return Vulnerability(
                cve_id=cve_id,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                published_date=published_date,
                modified_date=modified_date,
                affected_products=affected_products,
                references=references
            )
            
        except Exception as e:
            print(f"CVE 데이터 파싱 중 오류: {e}")
            return None

    def _cvss_v2_to_severity(self, score: float) -> str:
        """CVSS v2 점수를 심각도로 변환"""
        if score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _is_software_affected(self, vulnerability: Vulnerability, software_name: str) -> bool:
        """소프트웨어가 취약점의 영향을 받는지 확인"""
        # 설명에서 소프트웨어 이름 검색
        if software_name in vulnerability.description.lower():
            return True
        
        # 영향받는 제품 목록에서 확인
        for product in vulnerability.affected_products:
            if software_name in product.lower():
                return True
        
        return False

    def _filter_cves_by_version(self, vulnerabilities: List[Vulnerability], software_version: str) -> List[Vulnerability]:
        """버전별로 취약점 필터링"""
        if software_version == "Unknown":
            return vulnerabilities
        
        filtered_vulnerabilities = []
        
        for vuln in vulnerabilities:
            # 간단한 버전 매칭 (실제로는 더 복잡한 로직 필요)
            try:
                # CPE 문자열에서 버전 정보 추출 및 비교
                for product in vuln.affected_products:
                    if self._is_version_affected(product, software_version):
                        filtered_vulnerabilities.append(vuln)
                        break
                else:
                    # 버전 정보가 없으면 포함
                    filtered_vulnerabilities.append(vuln)
            except:
                # 버전 비교 실패 시 포함
                filtered_vulnerabilities.append(vuln)
        
        return filtered_vulnerabilities

    def _is_version_affected(self, cpe_string: str, software_version: str) -> bool:
        """CPE 문자열과 소프트웨어 버전 비교"""
        try:
            # CPE 형식: cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
            parts = cpe_string.split(':')
            if len(parts) >= 6:
                cpe_version = parts[5]
                
                # 와일드카드 또는 범위 처리
                if cpe_version == '*' or cpe_version == '-':
                    return True
                
                # 버전 비교
                try:
                    return version.parse(software_version) <= version.parse(cpe_version)
                except:
                    return cpe_version in software_version
            
            return True
        except:
            return True

    def _get_cached_cves(self, software_name: str) -> Optional[List[Vulnerability]]:
        """캐시에서 CVE 데이터 가져오기"""
        try:
            conn = sqlite3.connect(self.cache_file)
            cursor = conn.cursor()
            
            cache_key = hashlib.md5(software_name.encode()).hexdigest()
            
            cursor.execute('''
                SELECT data FROM cve_cache 
                WHERE cve_id = ? AND expires_at > datetime('now')
            ''', (cache_key,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                vuln_data = json.loads(result[0])
                vulnerabilities = []
                for data in vuln_data:
                    vulnerabilities.append(Vulnerability(**data))
                return vulnerabilities
            
            return None
            
        except Exception as e:
            print(f"캐시 조회 중 오류: {e}")
            return None

    def _cache_cves(self, software_name: str, vulnerabilities: List[Vulnerability]):
        """CVE 데이터 캐시에 저장"""
        try:
            conn = sqlite3.connect(self.cache_file)
            cursor = conn.cursor()
            
            cache_key = hashlib.md5(software_name.encode()).hexdigest()
            expires_at = datetime.now() + self.cache_duration
            
            # 직렬화 가능한 형태로 변환
            vuln_data = []
            for vuln in vulnerabilities:
                vuln_data.append(asdict(vuln))
            
            cursor.execute('''
                INSERT OR REPLACE INTO cve_cache (cve_id, data, cached_at, expires_at)
                VALUES (?, ?, datetime('now'), ?)
            ''', (cache_key, json.dumps(vuln_data), expires_at))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"캐시 저장 중 오류: {e}")

    def match_vulnerabilities(self, software_list: List[InstalledSoftware]) -> List[VulnerabilityMatch]:
        """소프트웨어와 취약점 매칭"""
        matches = []
        
        print(f"총 {len(software_list)}개의 소프트웨어에 대한 취약점 검색 시작...")
        
        for i, software in enumerate(software_list):
            print(f"[{i+1}/{len(software_list)}] {software.name} ({software.version}) 검색 중...")
            
            # API 호출 제한을 위한 지연
            time.sleep(1)
            
            try:
                vulnerabilities = self.search_cve_database(software.name, software.version)
                
                for vuln in vulnerabilities:
                    # 매칭 신뢰도 계산
                    confidence = self._calculate_match_confidence(software, vuln)
                    reason = self._get_match_reason(software, vuln)
                    
                    matches.append(VulnerabilityMatch(
                        software=software,
                        vulnerability=vuln,
                        match_confidence=confidence,
                        match_reason=reason
                    ))
                
                print(f"  {len(vulnerabilities)}개의 취약점 발견")
                
                # 스캔 기록 저장
                self._save_scan_record(software, len(vulnerabilities))
                
            except Exception as e:
                print(f"  오류 발생: {e}")
                continue
        
        return matches

    def _calculate_match_confidence(self, software: InstalledSoftware, vuln: Vulnerability) -> str:
        """매칭 신뢰도 계산"""
        software_name = self.normalize_software_name(software.name)
        
        # 정확한 이름 매칭
        if software_name in vuln.description.lower():
            return 'HIGH'
        
        # 부분 매칭
        name_parts = software_name.split()
        if len(name_parts) > 1:
            for part in name_parts:
                if len(part) > 3 and part in vuln.description.lower():
                    return 'MEDIUM'
        
        # 제품 목록에서 매칭
        for product in vuln.affected_products:
            if software_name in product.lower():
                return 'HIGH'
        
        return 'LOW'

    def _get_match_reason(self, software: InstalledSoftware, vuln: Vulnerability) -> str:
        """매칭 이유 설명"""
        software_name = self.normalize_software_name(software.name)
        
        if software_name in vuln.description.lower():
            return f"CVE 설명에서 '{software_name}' 발견"
        
        for product in vuln.affected_products:
            if software_name in product.lower():
                return f"영향받는 제품 목록에서 매칭: {product}"
        
        return "부분 매칭 또는 키워드 검색"

    def _save_scan_record(self, software: InstalledSoftware, vuln_count: int):
        """스캔 기록 저장"""
        try:
            conn = sqlite3.connect(self.cache_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO scan_history (software_name, version, scan_date, vulnerabilities_found)
                VALUES (?, ?, datetime('now'), ?)
            ''', (software.name, software.version, vuln_count))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"스캔 기록 저장 중 오류: {e}")

    def generate_report(self, software_list: List[InstalledSoftware], matches: List[VulnerabilityMatch]) -> str:
        """취약점 검사 보고서 생성"""
        report = f"\n{'='*80}\n"
        report += f"소프트웨어 취약점 검사 보고서\n"
        report += f"스캔 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"{'='*80}\n\n"
        
        # 요약 통계
        total_software = len(software_list)
        vulnerable_software = len(set(match.software.name for match in matches))
        total_vulnerabilities = len(matches)
        
        report += f"📊 검사 요약\n"
        report += f"-" * 40 + "\n"
        report += f"총 소프트웨어: {total_software}개\n"
        report += f"취약점 발견된 소프트웨어: {vulnerable_software}개\n"
        report += f"발견된 취약점: {total_vulnerabilities}개\n\n"
        
        # 심각도별 통계
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        for match in matches:
            severity_counts[match.vulnerability.severity] += 1
        
        report += f"🚨 심각도별 취약점 분포\n"
        report += f"-" * 40 + "\n"
        for severity, count in severity_counts.items():
            if count > 0:
                icon = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢', 'UNKNOWN': '⚪'}[severity]
                report += f"{icon} {severity}: {count}개\n"
        report += "\n"
        
        # 고위험 취약점 상세 정보
        high_risk_matches = [m for m in matches if m.vulnerability.severity == 'HIGH']
        if high_risk_matches:
            report += f"🔴 고위험 취약점 상세 정보\n"
            report += f"-" * 40 + "\n"
            
            for match in high_risk_matches[:10]:  # 상위 10개만 표시
                report += f"소프트웨어: {match.software.name} v{match.software.version}\n"
                report += f"CVE ID: {match.vulnerability.cve_id}\n"
                report += f"CVSS 점수: {match.vulnerability.cvss_score}\n"
                report += f"발행일: {match.vulnerability.published_date[:10]}\n"
                report += f"설명: {match.vulnerability.description[:200]}...\n"
                report += f"매칭 신뢰도: {match.match_confidence}\n"
                report += f"매칭 이유: {match.match_reason}\n"
                report += f"참조: {match.vulnerability.references[0] if match.vulnerability.references else 'N/A'}\n"
                report += f"-" * 40 + "\n"
        
        # 권장사항
        report += f"\n💡 보안 권장사항\n"
        report += f"-" * 40 + "\n"
        report += f"1. 고위험 취약점이 발견된 소프트웨어를 즉시 업데이트하세요.\n"
        report += f"2. 정기적으로 소프트웨어 업데이트를 확인하세요.\n"
        report += f"3. 불필요한 소프트웨어는 제거하세요.\n"
        report += f"4. 보안 패치가 제공되지 않는 오래된 소프트웨어는 대체하세요.\n"
        report += f"5. 자동 업데이트 기능을 활성화하세요.\n"
        
        return report

    def export_to_json(self, software_list: List[InstalledSoftware], matches: List[VulnerabilityMatch], filename: str):
        """결과를 JSON 파일로 내보내기"""
        data = {
            'scan_date': datetime.now().isoformat(),
            'total_software': len(software_list),
            'total_vulnerabilities': len(matches),
            'software_list': [asdict(s) for s in software_list],
            'vulnerability_matches': [
                {
                    'software': asdict(m.software),
                    'vulnerability': asdict(m.vulnerability),
                    'match_confidence': m.match_confidence,
                    'match_reason': m.match_reason
                } for m in matches
            ]
        }
        
        with open(filename, 'w', encoding='utf-8
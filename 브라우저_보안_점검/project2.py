#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
소프트웨어 취약점 점검기 (CLI + MCP 서버 지원)
"""

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
import time
from packaging import version
import hashlib
import sys
import os

# === MCP 서버 지원 추가 ===
from mcp.server.fastmcp import FastMCP
mcp = FastMCP(name="vulnerability_scanner", host="127.0.0.1", port=5006)


@dataclass
class InstalledSoftware:
    name: str
    version: str
    vendor: str
    install_date: Optional[str]
    install_location: Optional[str]
    uninstall_string: Optional[str]
    registry_key: str

@dataclass
class Vulnerability:
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
    software: InstalledSoftware
    vulnerability: Vulnerability
    match_confidence: str
    match_reason: str


class SoftwareVulnerabilityScanner:
    def __init__(self, cache_duration_hours: int = 24):
        self.cache_duration = timedelta(hours=cache_duration_hours)
        self.cache_file = Path("vulnerability_cache.db")
        self.init_database()
        self.cve_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Software-Vulnerability-Scanner/1.0'})
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
        conn = sqlite3.connect(self.cache_file)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                data TEXT,
                cached_at TIMESTAMP,
                expires_at TIMESTAMP
            )
        ''')
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
        if sys.platform != 'win32':
            print("이 기능은 Windows에서만 사용 가능합니다.")
            return []
        software_list = []
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        ]
        for hkey, subkey_path in registry_paths:
            try:
                registry_key = winreg.OpenKey(hkey, subkey_path)
                num_subkeys = winreg.QueryInfoKey(registry_key)[0]
                for i in range(num_subkeys):
                    try:
                        subkey_name = winreg.EnumKey(registry_key, i)
                        subkey = winreg.OpenKey(registry_key, subkey_name)
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
        try:
            try:
                display_name = winreg.QueryValueEx(registry_key, "DisplayName")[0]
            except FileNotFoundError:
                return None
            if self._should_exclude_software(display_name):
                return None
            version_str = self._get_registry_value(registry_key, "DisplayVersion", "Unknown")
            vendor = self._get_registry_value(registry_key, "Publisher", "Unknown")
            install_date = self._get_registry_value(registry_key, "InstallDate", None)
            install_location = self._get_registry_value(registry_key, "InstallLocation", None)
            uninstall_string = self._get_registry_value(registry_key, "UninstallString", None)
            if install_date and len(install_date) == 8:
                try:
                    install_date = f"{install_date[:4]}-{install_date[4:6]}-{install_date[6:8]}"
                except:
                    install_date = None
            return InstalledSoftware(
                name=display_name.strip(),
                version=version_str.strip() if version_str else "Unknown",
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
        try:
            return winreg.QueryValueEx(registry_key, value_name)[0]
        except FileNotFoundError:
            return default

    def _should_exclude_software(self, display_name: str) -> bool:
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

    def get_sample_software(self) -> List[InstalledSoftware]:
        return [
            InstalledSoftware("Google Chrome","119.0.6045.199","Google LLC","2023-11-01",
                              "C:\\Program Files\\Google\\Chrome\\Application\\",None,"sample_chrome"),
            InstalledSoftware("Mozilla Firefox","120.0.1","Mozilla Corporation","2023-11-15",
                              "C:\\Program Files\\Mozilla Firefox\\",None,"sample_firefox"),
            InstalledSoftware("VLC Media Player","3.0.18","VideoLAN","2023-10-20",
                              "C:\\Program Files\\VideoLAN\\VLC\\",None,"sample_vlc")
        ]

    def normalize_software_name(self, name: str) -> str:
        name = name.lower().strip()
        for key, value in self.software_mappings.items():
            if key in name:
                return value
        name = re.sub(r'\s+', ' ', name)
        name = re.sub(r'\(.*?\)', '', name)
        name = re.sub(r'\s+v?\d+(\.\d+)*.*$', '', name)
        name = re.sub(r'\s+(x86|x64|32-bit|64-bit).*$', '', name)
        return name.strip()

    def search_cve_database(self, software_name: str, version: str) -> List[Vulnerability]:
        normalized_name = self.normalize_software_name(software_name)
        cached_cves = self._get_cached_cves(normalized_name)
        if cached_cves:
            return self._filter_cves_by_version(cached_cves, version)
        try:
            vulnerabilities = []
            params = {'keywordSearch': normalized_name,'resultsPerPage': 100,'startIndex': 0}
            response = self.session.get(f"{self.cve_api_base}", params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for cve_item in data.get('vulnerabilities', []):
                    cve_data = cve_item.get('cve', {})
                    vulnerability = self._parse_cve_data(cve_data)
                    if vulnerability and self._is_software_affected(vulnerability, normalized_name):
                        vulnerabilities.append(vulnerability)
                self._cache_cves(normalized_name, vulnerabilities)
            return self._filter_cves_by_version(vulnerabilities, version)
        except requests.exceptions.RequestException as e:
            print(f"CVE 검색 중 네트워크 오류: {e}")
            return []
        except Exception as e:
            print(f"CVE 검색 중 오류: {e}")
            return []

    def _parse_cve_data(self, cve_data: Dict) -> Optional[Vulnerability]:
        try:
            cve_id = cve_data.get('id', '')
            descriptions = cve_data.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')
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
            published_date = cve_data.get('published', '')
            modified_date = cve_data.get('lastModified', '')
            affected_products = []
            configurations = cve_data.get('configurations', [])
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        if cpe_match.get('vulnerable', False):
                            affected_products.append(cpe_match.get('criteria', ''))
            references = []
            for ref in cve_data.get('references', []):
                references.append(ref.get('url', ''))
            return Vulnerability(cve_id, description, severity, cvss_score,
                                 published_date, modified_date, affected_products, references)
        except Exception as e:
            print(f"CVE 데이터 파싱 중 오류: {e}")
            return None

    def _cvss_v2_to_severity(self, score: float) -> str:
        if score >= 7.0: return 'HIGH'
        elif score >= 4.0: return 'MEDIUM'
        else: return 'LOW'

    def _is_software_affected(self, vulnerability: Vulnerability, software_name: str) -> bool:
        if software_name in vulnerability.description.lower():
            return True
        for product in vulnerability.affected_products:
            if software_name in product.lower():
                return True
        return False

    def _filter_cves_by_version(self, vulnerabilities: List[Vulnerability], software_version: str) -> List[Vulnerability]:
        if software_version == "Unknown": return vulnerabilities
        filtered = []
        for vuln in vulnerabilities:
            try:
                for product in vuln.affected_products:
                    if self._is_version_affected(product, software_version):
                        filtered.append(vuln); break
                else:
                    filtered.append(vuln)
            except:
                filtered.append(vuln)
        return filtered

    def _is_version_affected(self, cpe_string: str, software_version: str) -> bool:
        try:
            parts = cpe_string.split(':')
            if len(parts) >= 6:
                cpe_version = parts[5]
                if cpe_version in ['*','-']: return True
                try: return version.parse(software_version) <= version.parse(cpe_version)
                except: return cpe_version in software_version
            return True
        except: return True

    def _get_cached_cves(self, software_name: str) -> Optional[List[Vulnerability]]:
        try:
            conn = sqlite3.connect(self.cache_file)
            cursor = conn.cursor()
            cache_key = hashlib.md5(software_name.encode()).hexdigest()
            cursor.execute('SELECT data FROM cve_cache WHERE cve_id = ? AND expires_at > datetime("now")',(cache_key,))
            result = cursor.fetchone(); conn.close()
            if result:
                vuln_data = json.loads(result[0]); return [Vulnerability(**data) for data in vuln_data]
            return None
        except Exception as e:
            print(f"캐시 조회 중 오류: {e}"); return None

    def _cache_cves(self, software_name: str, vulnerabilities: List[Vulnerability]):
        try:
            conn = sqlite3.connect(self.cache_file); cursor = conn.cursor()
            cache_key = hashlib.md5(software_name.encode()).hexdigest()
            expires_at = datetime.now() + self.cache_duration
            vuln_data = [asdict(vuln) for vuln in vulnerabilities]
            cursor.execute('''
                INSERT OR REPLACE INTO cve_cache (cve_id, data, cached_at, expires_at)
                VALUES (?, ?, datetime('now'), ?)''',
                (cache_key, json.dumps(vuln_data), expires_at))
            conn.commit(); conn.close()
        except Exception as e:
            print(f"캐시 저장 중 오류: {e}")

    def match_vulnerabilities(self, software_list: List[InstalledSoftware]) -> List[VulnerabilityMatch]:
        matches = []
        print(f"총 {len(software_list)}개의 소프트웨어에 대한 취약점 검색 시작...")
        for i, software in enumerate(software_list):
            print(f"[{i+1}/{len(software_list)}] {software.name} ({software.version}) 검색 중...")
            time.sleep(1)
            try:
                vulns = self.search_cve_database(software.name, software.version)
                for vuln in vulns:
                    confidence = self._calculate_match_confidence(software, vuln)
                    reason = self._get_match_reason(software, vuln)
                    matches.append(VulnerabilityMatch(software,vuln,confidence,reason))
                print(f"  {len(vulns)}개의 취약점 발견")
                self._save_scan_record(software, len(vulns))
            except Exception as e:
                print(f"  오류 발생: {e}"); continue
        return matches

    def _calculate_match_confidence(self, software: InstalledSoftware, vuln: Vulnerability) -> str:
        name = self.normalize_software_name(software.name)
        if name in vuln.description.lower(): return 'HIGH'
        parts = name.split()
        if len(parts) > 1:
            for part in parts:
                if len(part) > 3 and part in vuln.description.lower(): return 'MEDIUM'
        for product in vuln.affected_products:
            if name in product.lower(): return 'HIGH'
        return 'LOW'

    def _get_match_reason(self, software: InstalledSoftware, vuln: Vulnerability) -> str:
        name = self.normalize_software_name(software.name)
        if name in vuln.description.lower(): return f"CVE 설명에서 '{name}' 발견"
        for product in vuln.affected_products:
            if name in product.lower(): return f"영향받는 제품 목록에서 매칭: {product}"
        return "부분 매칭 또는 키워드 검색"

    def _save_scan_record(self, software: InstalledSoftware, vuln_count: int):
        try:
            conn = sqlite3.connect(self.cache_file); cursor = conn.cursor()
            cursor.execute('INSERT INTO scan_history (software_name, version, scan_date, vulnerabilities_found) VALUES (?,?,datetime("now"),?)',
                           (software.name, software.version, vuln_count))
            conn.commit(); conn.close()
        except Exception as e: print(f"스캔 기록 저장 중 오류: {e}")

    def generate_report(self, software_list: List[InstalledSoftware], matches: List[VulnerabilityMatch]) -> str:
        report = f"\n{'='*80}\n소프트웨어 취약점 검사 보고서\n스캔 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*80}\n\n"
        total_software = len(software_list)
        vulnerable_software = len(set(m.software.name for m in matches))
        total_vulns = len(matches)
        report += f"📊 검사 요약\n{'-'*40}\n총 소프트웨어: {total_software}개\n취약점 발견된 소프트웨어: {vulnerable_software}개\n발견된 취약점: {total_vulns}개\n\n"
        severity_counts = {'HIGH':0,'MEDIUM':0,'LOW':0,'UNKNOWN':0}
        for m in matches: severity_counts[m.vulnerability.severity]+=1
        report += f"🚨 심각도별 취약점 분포\n{'-'*40}\n"
        for sev,cnt in severity_counts.items():
            if cnt>0:
                icon={'HIGH':'🔴','MEDIUM':'🟡','LOW':'🟢','UNKNOWN':'⚪'}[sev]
                report+=f"{icon} {sev}: {cnt}개\n"
        report+="\n"
        high_risk=[m for m in matches if m.vulnerability.severity=='HIGH']
        if high_risk:
            report+="🔴 고위험 취약점 상세 정보\n"+'-'*40+"\n"
            for m in high_risk[:10]:
                report+=f"소프트웨어: {m.software.name} v{m.software.version}\nCVE ID: {m.vulnerability.cve_id}\nCVSS 점수: {m.vulnerability.cvss_score}\n발행일: {m.vulnerability.published_date[:10]}\n설명: {m.vulnerability.description[:200]}...\n매칭 신뢰도: {m.match_confidence}\n매칭 이유: {m.match_reason}\n참조: {m.vulnerability.references[0] if m.vulnerability.references else 'N/A'}\n{'-'*40}\n"
        report+="\n💡 보안 권장사항\n"+'-'*40+"\n1. 고위험 취약점이 발견된 소프트웨어를 즉시 업데이트하세요.\n2. 정기적으로 소프트웨어 업데이트를 확인하세요.\n3. 불필요한 소프트웨어는 제거하세요.\n4. 보안 패치가 제공되지 않는 오래된 소프트웨어는 대체하세요.\n5. 자동 업데이트 기능을 활성화하세요.\n"
        return report

    def export_to_json(self, software_list: List[InstalledSoftware], matches: List[VulnerabilityMatch], filename: str):
        data={'scan_date':datetime.now().isoformat(),'total_software':len(software_list),'total_vulnerabilities':len(matches),
              'software_list':[asdict(s) for s in software_list],
              'vulnerability_matches':[{'software':asdict(m.software),'vulnerability':asdict(m.vulnerability),
                                        'match_confidence':m.match_confidence,'match_reason':m.match_reason} for m in matches]}
        with open(filename,'w',encoding='utf-8') as f: json.dump(data,f,indent=2,ensure_ascii=False)


scanner = SoftwareVulnerabilityScanner()


@mcp.tool()
def scan_installed_software(use_sample: bool = False) -> Dict[str, Any]:
    if use_sample or sys.platform != "win32":
        software_list = scanner.get_sample_software()
    else:
        software_list = scanner.get_installed_software_registry()
    matches = scanner.match_vulnerabilities(software_list)
    return {
        "software_list": [asdict(s) for s in software_list],
        "vulnerability_matches": [
            {"software": asdict(m.software),
             "vulnerability": asdict(m.vulnerability),
             "match_confidence": m.match_confidence,
             "match_reason": m.match_reason}
            for m in matches
        ]
    }


@mcp.tool()
def generate_vulnerability_report(use_sample: bool = False) -> str:
    if use_sample or sys.platform != "win32":
        software_list = scanner.get_sample_software()
    else:
        software_list = scanner.get_installed_software_registry()
    matches = scanner.match_vulnerabilities(software_list)
    return scanner.generate_report(software_list, matches)


if __name__ == "__main__":
    run_cli = ("--cli" in sys.argv)
    if not run_cli:
        transport = os.getenv("MCP_TRANSPORT","stdio").lower()
        try:
            if transport=="http": mcp.run(transport="http")
            else: mcp.run()
        except TypeError: mcp.run()
    else:
        sw_list = scanner.get_sample_software() if sys.platform != "win32" else scanner.get_installed_software_registry()
        matches = scanner.match_vulnerabilities(sw_list)
        print(scanner.generate_report(sw_list, matches))
        scanner.export_to_json(sw_list, matches, "vulnerability_results.json")

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
브라우저 보안 설정 분석기
주요 브라우저의 보안 설정과 확장 프로그램을 분석하여 보안 위험도를 평가합니다.
"""

import json
import os
import sqlite3
import configparser
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import platform
import sys

@dataclass
class SecurityCheck:
    """보안 체크 결과를 저장하는 클래스"""
    name: str
    status: str  # 'PASS', 'FAIL', 'WARNING', 'INFO'
    description: str
    recommendation: str = ""

@dataclass
class ExtensionInfo:
    """확장 프로그램 정보를 저장하는 클래스"""
    id: str
    name: str
    version: str
    enabled: bool
    permissions: List[str]
    risk_level: str  # 'LOW', 'MEDIUM', 'HIGH'

class BrowserSecurityAnalyzer:
    def __init__(self):
        self.system = platform.system()
        self.security_checks = []
        self.extensions_info = []
        
        # 보안 체크리스트 정의
        self.security_checklist = {
            'javascript_enabled': {
                'description': 'JavaScript 활성화 상태',
                'recommendation': 'JavaScript는 보안상 위험할 수 있으나 대부분의 웹사이트에서 필요합니다.'
            },
            'cookies_policy': {
                'description': '쿠키 정책 설정',
                'recommendation': '서드파티 쿠키를 차단하고 SameSite 설정을 활성화하세요.'
            },
            'popup_blocker': {
                'description': '팝업 차단 설정',
                'recommendation': '팝업 차단을 활성화하여 악성 팝업을 방지하세요.'
            },
            'safe_browsing': {
                'description': '안전한 브라우징 설정',
                'recommendation': '안전한 브라우징을 활성화하여 악성 사이트를 차단하세요.'
            },
            'download_protection': {
                'description': '다운로드 보호 설정',
                'recommendation': '다운로드 보호를 활성화하여 악성 파일을 차단하세요.'
            },
            'password_manager': {
                'description': '비밀번호 관리자 설정',
                'recommendation': '내장 비밀번호 관리자 사용을 고려하거나 별도의 보안 솔루션을 사용하세요.'
            }
        }

    def get_browser_paths(self) -> Dict[str, Path]:
        """운영체제별 브라우저 설정 파일 경로를 반환"""
        paths = {}
        
        if self.system == "Windows":
            # Windows 환경에서 경로 처리 개선
            appdata = os.environ.get('APPDATA', '')
            localappdata = os.environ.get('LOCALAPPDATA', '')
            
            if appdata and localappdata:
                paths.update({
                    'chrome': Path(localappdata) / 'Google' / 'Chrome' / 'User Data' / 'Default',
                    'firefox': Path(appdata) / 'Mozilla' / 'Firefox' / 'Profiles',
                    'edge': Path(localappdata) / 'Microsoft' / 'Edge' / 'User Data' / 'Default',
                    'opera': Path(appdata) / 'Opera Software' / 'Opera Stable'
                })
                
        elif self.system == "Darwin":  # macOS
            home = Path.home()
            paths.update({
                'chrome': home / 'Library' / 'Application Support' / 'Google' / 'Chrome' / 'Default',
                'firefox': home / 'Library' / 'Application Support' / 'Firefox' / 'Profiles',
                'edge': home / 'Library' / 'Application Support' / 'Microsoft Edge' / 'Default',
                'safari': home / 'Library' / 'Preferences',
                'opera': home / 'Library' / 'Application Support' / 'com.operasoftware.Opera'
            })
        else:  # Linux
            home = Path.home()
            paths.update({
                'chrome': home / '.config' / 'google-chrome' / 'Default',
                'firefox': home / '.mozilla' / 'firefox',
                'edge': home / '.config' / 'microsoft-edge' / 'Default',
                'opera': home / '.config' / 'opera'
            })
        
        return paths

    def safe_json_load(self, file_path: Path) -> Optional[Dict]:
        """안전한 JSON 파일 로드"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
            print(f"파일 로드 실패 {file_path}: {e}")
            return None

    def analyze_chrome_settings(self, profile_path: Path) -> List[SecurityCheck]:
        """Chrome 설정 분석"""
        checks = []
        
        try:
            # Preferences 파일 분석
            prefs_file = profile_path / 'Preferences'
            if not prefs_file.exists():
                checks.append(SecurityCheck(
                    'chrome_prefs', 'WARNING',
                    'Chrome 설정 파일을 찾을 수 없습니다.',
                    '브라우저가 설치되지 않았거나 처음 실행되지 않았을 수 있습니다.'
                ))
                return checks
            
            prefs = self.safe_json_load(prefs_file)
            if not prefs:
                checks.append(SecurityCheck(
                    'chrome_prefs', 'FAIL',
                    'Chrome 설정 파일을 읽을 수 없습니다.'
                ))
                return checks
            
            # JavaScript 설정 확인
            js_settings = prefs.get('profile', {}).get('content_settings', {}).get('exceptions', {}).get('javascript', {})
            if js_settings:
                checks.append(SecurityCheck(
                    'javascript_enabled', 'INFO', 
                    'JavaScript 사용자 정의 설정이 있습니다.',
                    self.security_checklist['javascript_enabled']['recommendation']
                ))
            else:
                checks.append(SecurityCheck(
                    'javascript_enabled', 'INFO', 
                    'JavaScript가 기본 설정으로 활성화되어 있습니다.',
                    self.security_checklist['javascript_enabled']['recommendation']
                ))
            
            # 쿠키 정책 확인
            cookie_controls = prefs.get('profile', {}).get('cookie_controls_mode', 0)
            if cookie_controls >= 1:
                checks.append(SecurityCheck(
                    'cookies_policy', 'PASS',
                    '서드파티 쿠키가 적절히 제한되어 있습니다.'
                ))
            else:
                checks.append(SecurityCheck(
                    'cookies_policy', 'WARNING',
                    '서드파티 쿠키가 허용되어 있습니다.',
                    self.security_checklist['cookies_policy']['recommendation']
                ))
            
            # 팝업 차단 확인
            popup_setting = prefs.get('profile', {}).get('content_settings', {}).get('exceptions', {}).get('popups', {})
            if popup_setting:
                checks.append(SecurityCheck(
                    'popup_blocker', 'PASS',
                    '팝업 차단 설정이 구성되어 있습니다.'
                ))
            else:
                checks.append(SecurityCheck(
                    'popup_blocker', 'INFO',
                    '팝업 차단이 기본 설정으로 활성화되어 있습니다.'
                ))
            
            # 안전한 브라우징 확인
            safe_browsing = prefs.get('safebrowsing', {}).get('enabled', True)
            if safe_browsing:
                checks.append(SecurityCheck(
                    'safe_browsing', 'PASS',
                    '안전한 브라우징이 활성화되어 있습니다.'
                ))
            else:
                checks.append(SecurityCheck(
                    'safe_browsing', 'FAIL',
                    '안전한 브라우징이 비활성화되어 있습니다.',
                    self.security_checklist['safe_browsing']['recommendation']
                ))
            
            # 비밀번호 관리자 확인
            password_manager = prefs.get('profile', {}).get('password_manager_enabled', True)
            if password_manager:
                checks.append(SecurityCheck(
                    'password_manager', 'INFO',
                    '내장 비밀번호 관리자가 활성화되어 있습니다.',
                    self.security_checklist['password_manager']['recommendation']
                ))
            else:
                checks.append(SecurityCheck(
                    'password_manager', 'WARNING',
                    '내장 비밀번호 관리자가 비활성화되어 있습니다.',
                    self.security_checklist['password_manager']['recommendation']
                ))
                
        except Exception as e:
            checks.append(SecurityCheck(
                'chrome_analysis', 'FAIL',
                f'Chrome 설정 분석 중 오류 발생: {str(e)}'
            ))
        
        return checks

    def analyze_firefox_settings(self, profile_path: Path) -> List[SecurityCheck]:
        """Firefox 설정 분석"""
        checks = []
        
        try:
            # profiles.ini 파일에서 프로필 찾기
            profiles_ini = profile_path / 'profiles.ini'
            if not profiles_ini.exists():
                checks.append(SecurityCheck(
                    'firefox_profiles', 'WARNING',
                    'Firefox 프로필을 찾을 수 없습니다.',
                    '브라우저가 설치되지 않았거나 처음 실행되지 않았을 수 있습니다.'
                ))
                return checks
            
            config = configparser.ConfigParser()
            config.read(profiles_ini, encoding='utf-8')
            
            # 기본 프로필 찾기
            default_profile = None
            for section in config.sections():
                if 'Profile' in section:
                    if config.getboolean(section, 'Default', fallback=False):
                        default_profile = config.get(section, 'Path')
                        break
            
            if not default_profile:
                # 기본 프로필이 없으면 첫 번째 프로필 사용
                for section in config.sections():
                    if 'Profile' in section:
                        default_profile = config.get(section, 'Path')
                        break
            
            if default_profile:
                if not os.path.isabs(default_profile):
                    profile_dir = profile_path / default_profile
                else:
                    profile_dir = Path(default_profile)
                
                prefs_file = profile_dir / 'prefs.js'
                
                if prefs_file.exists():
                    with open(prefs_file, 'r', encoding='utf-8') as f:
                        prefs_content = f.read()
                    
                    # 보안 설정 확인
                    if 'user_pref("javascript.enabled", false)' in prefs_content:
                        checks.append(SecurityCheck(
                            'javascript_enabled', 'INFO',
                            'JavaScript가 사용자에 의해 비활성화되어 있습니다.'
                        ))
                    else:
                        checks.append(SecurityCheck(
                            'javascript_enabled', 'INFO',
                            'JavaScript가 기본 설정으로 활성화되어 있습니다.'
                        ))
                    
                    # 쿠키 정책 확인
                    if 'network.cookie.cookieBehavior' in prefs_content:
                        checks.append(SecurityCheck(
                            'cookies_policy', 'INFO',
                            '쿠키 정책이 사용자 정의되어 있습니다.'
                        ))
                    else:
                        checks.append(SecurityCheck(
                            'cookies_policy', 'INFO',
                            '쿠키 정책이 기본 설정으로 되어 있습니다.'
                        ))
                    
                    # 팝업 차단 확인
                    if 'dom.disable_open_during_load' in prefs_content:
                        checks.append(SecurityCheck(
                            'popup_blocker', 'PASS',
                            '팝업 차단이 설정되어 있습니다.'
                        ))
                    else:
                        checks.append(SecurityCheck(
                            'popup_blocker', 'INFO',
                            '팝업 차단이 기본 설정으로 활성화되어 있습니다.'
                        ))
                    
                    # 안전한 브라우징 확인
                    if 'browser.safebrowsing.malware.enabled' in prefs_content:
                        if 'user_pref("browser.safebrowsing.malware.enabled", false)' in prefs_content:
                            checks.append(SecurityCheck(
                                'safe_browsing', 'FAIL',
                                '안전한 브라우징이 비활성화되어 있습니다.',
                                self.security_checklist['safe_browsing']['recommendation']
                            ))
                        else:
                            checks.append(SecurityCheck(
                                'safe_browsing', 'PASS',
                                '안전한 브라우징이 활성화되어 있습니다.'
                            ))
                    else:
                        checks.append(SecurityCheck(
                            'safe_browsing', 'PASS',
                            '안전한 브라우징이 기본 설정으로 활성화되어 있습니다.'
                        ))
                else:
                    checks.append(SecurityCheck(
                        'firefox_prefs', 'WARNING',
                        'Firefox 설정 파일(prefs.js)을 찾을 수 없습니다.'
                    ))
            else:
                checks.append(SecurityCheck(
                    'firefox_profile', 'WARNING',
                    'Firefox 기본 프로필을 찾을 수 없습니다.'
                ))
                
        except Exception as e:
            checks.append(SecurityCheck(
                'firefox_analysis', 'FAIL',
                f'Firefox 설정 분석 중 오류 발생: {str(e)}'
            ))
        
        return checks

    def analyze_extensions(self, browser: str, profile_path: Path) -> List[ExtensionInfo]:
        """확장 프로그램 정보 분석"""
        extensions = []
        
        try:
            if browser in ['chrome', 'edge', 'opera']:
                # Chromium 기반 브라우저 확장 프로그램 분석
                extensions_path = profile_path / 'Extensions'
                if extensions_path.exists():
                    for ext_dir in extensions_path.iterdir():
                        if ext_dir.is_dir() and ext_dir.name != 'Temp':
                            try:
                                # 최신 버전 폴더 찾기
                                version_dirs = [d for d in ext_dir.iterdir() if d.is_dir()]
                                if version_dirs:
                                    # 버전 번호로 정렬 (숫자 비교)
                                    try:
                                        latest_version = max(version_dirs, key=lambda x: tuple(map(int, x.name.split('.'))))
                                    except ValueError:
                                        latest_version = max(version_dirs, key=lambda x: x.name)
                                    
                                    manifest_file = latest_version / 'manifest.json'
                                    
                                    if manifest_file.exists():
                                        manifest = self.safe_json_load(manifest_file)
                                        if manifest:
                                            permissions = manifest.get('permissions', [])
                                            if 'host_permissions' in manifest:
                                                permissions.extend(manifest.get('host_permissions', []))
                                            
                                            risk_level = self.assess_extension_risk(permissions)
                                            
                                            extensions.append(ExtensionInfo(
                                                id=ext_dir.name,
                                                name=manifest.get('name', 'Unknown Extension'),
                                                version=manifest.get('version', 'Unknown'),
                                                enabled=True,  # 설치된 확장은 기본적으로 활성화
                                                permissions=permissions,
                                                risk_level=risk_level
                                            ))
                            except Exception as e:
                                print(f"확장 프로그램 분석 오류 ({ext_dir.name}): {e}")
                                continue
            
            elif browser == 'firefox':
                # Firefox 확장 프로그램 분석 시도
                default_profile = self.get_firefox_default_profile(profile_path)
                if default_profile:
                    extensions_db = default_profile / 'extensions.json'
                    if extensions_db.exists():
                        data = self.safe_json_load(extensions_db)
                        if data:
                            for addon in data.get('addons', []):
                                if addon.get('type') == 'extension':
                                    permissions = addon.get('userPermissions', {}).get('permissions', [])
                                    risk_level = self.assess_extension_risk(permissions)
                                    
                                    extensions.append(ExtensionInfo(
                                        id=addon.get('id', 'Unknown'),
                                        name=addon.get('defaultLocale', {}).get('name', 
                                              addon.get('name', 'Unknown Extension')),
                                        version=addon.get('version', 'Unknown'),
                                        enabled=addon.get('active', False),
                                        permissions=permissions,
                                        risk_level=risk_level
                                    ))
                            
        except Exception as e:
            print(f"확장 프로그램 분석 중 오류 발생: {str(e)}")
        
        return extensions

    def assess_extension_risk(self, permissions: List[str]) -> str:
        """확장 프로그램 권한 기반 위험도 평가"""
        high_risk_permissions = [
            'activeTab', 'tabs', 'webNavigation', 'webRequest', 'webRequestBlocking',
            'privacy', 'management', 'downloads', 'nativeMessaging', 'debugger',
            'contentSettings', 'proxy', 'desktopCapture', 'tabCapture'
        ]
        
        medium_risk_permissions = [
            'storage', 'cookies', 'history', 'bookmarks', 'topSites', 'geolocation',
            'notifications', 'clipboardRead', 'clipboardWrite', 'contextMenus'
        ]
        
        # 호스트 권한 확인 (모든 사이트 접근)
        dangerous_host_permissions = ['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*']
        
        high_risk_count = sum(1 for perm in permissions if perm in high_risk_permissions)
        medium_risk_count = sum(1 for perm in permissions if perm in medium_risk_permissions)
        dangerous_host_count = sum(1 for perm in permissions if perm in dangerous_host_permissions)
        
        if high_risk_count >= 2 or dangerous_host_count >= 1:
            return 'HIGH'
        elif high_risk_count >= 1 or medium_risk_count >= 3:
            return 'MEDIUM'
        else:
            return 'LOW'

    def generate_report(self, browser: str, security_checks: List[SecurityCheck], extensions: List[ExtensionInfo]) -> str:
        """보안 분석 보고서 생성"""
        report = f"\n{'='*60}\n"
        report += f"브라우저 보안 분석 보고서 - {browser.upper()}\n"
        report += f"분석 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"{'='*60}\n\n"
        
        # 보안 설정 체크 결과
        report += "📋 보안 설정 체크 결과\n"
        report += "-" * 40 + "\n"
        
        status_counts = {'PASS': 0, 'FAIL': 0, 'WARNING': 0, 'INFO': 0}
        
        for check in security_checks:
            status_counts[check.status] += 1
            status_icon = {
                'PASS': '✅', 'FAIL': '❌', 'WARNING': '⚠️', 'INFO': 'ℹ️'
            }[check.status]
            
            report += f"{status_icon} {check.name}: {check.description}\n"
            if check.recommendation:
                report += f"   💡 권장사항: {check.recommendation}\n"
            report += "\n"
        
        # 요약 통계
        report += "📊 보안 체크 요약\n"
        report += "-" * 40 + "\n"
        for status, count in status_counts.items():
            report += f"{status}: {count}개\n"
        report += "\n"
        
        # 확장 프로그램 분석
        if extensions:
            report += "🔌 확장 프로그램 분석\n"
            report += "-" * 40 + "\n"
            
            risk_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            
            for ext in extensions:
                risk_counts[ext.risk_level] += 1
                risk_icon = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}[ext.risk_level]
                status_icon = '✅' if ext.enabled else '❌'
                
                report += f"{risk_icon} {ext.name} (v{ext.version})\n"
                report += f"   상태: {status_icon} {'활성화' if ext.enabled else '비활성화'}\n"
                report += f"   위험도: {ext.risk_level}\n"
                report += f"   권한: {', '.join(ext.permissions[:5])}"
                if len(ext.permissions) > 5:
                    report += f" (+{len(ext.permissions)-5}개 더)"
                report += "\n\n"
            
            report += "🔌 확장 프로그램 위험도 요약\n"
            report += "-" * 40 + "\n"
            for risk, count in risk_counts.items():
                report += f"{risk}: {count}개\n"
        else:
            report += "🔌 확장 프로그램이 발견되지 않았습니다.\n\n"
        
        return report

    def get_firefox_default_profile(self, firefox_path: Path) -> Optional[Path]:
        """Firefox 기본 프로필 경로 반환"""
        try:
            profiles_ini = firefox_path / 'profiles.ini'
            if profiles_ini.exists():
                config = configparser.ConfigParser()
                config.read(profiles_ini, encoding='utf-8')
                
                # 기본 프로필 찾기
                for section in config.sections():
                    if 'Profile' in section and config.getboolean(section, 'Default', fallback=False):
                        profile_path = config.get(section, 'Path')
                        if not os.path.isabs(profile_path):
                            return firefox_path / profile_path
                        else:
                            return Path(profile_path)
                
                # 기본 프로필이 없으면 첫 번째 프로필 반환
                for section in config.sections():
                    if 'Profile' in section:
                        profile_path = config.get(section, 'Path')
                        if not os.path.isabs(profile_path):
                            return firefox_path / profile_path
                        else:
                            return Path(profile_path)
        except Exception as e:
            print(f"Firefox 프로필 경로 찾기 실패: {e}")
        
        return None

    def analyze_all_browsers(self) -> Dict[str, Any]:
        """모든 브라우저 분석"""
        browser_paths = self.get_browser_paths()
        results = {}
        
        for browser, path in browser_paths.items():
            print(f"\n{browser.upper()} 브라우저 분석 중...")
            
            if path.exists():
                try:
                    # 보안 설정 분석
                    if browser == 'chrome':
                        security_checks = self.analyze_chrome_settings(path)
                        extensions = self.analyze_extensions(browser, path)
                    elif browser == 'firefox':
                        security_checks = self.analyze_firefox_settings(path)
                        extensions = self.analyze_extensions(browser, path)
                    else:
                        security_checks = self.analyze_chrome_settings(path)  # Edge, Opera는 Chromium 기반
                        extensions = self.analyze_extensions(browser, path)
                    
                    # 보고서 생성
                    report = self.generate_report(browser, security_checks, extensions)
                    
                    results[browser] = {
                        'security_checks': security_checks,
                        'extensions': extensions,
                        'report': report
                    }
                    
                    print(report)
                    
                except Exception as e:
                    error_msg = f"{browser.upper()} 브라우저 분석 중 오류 발생: {str(e)}"
                    print(error_msg)
                    results[browser] = {
                        'security_checks': [SecurityCheck('analysis_error', 'FAIL', error_msg)],
                        'extensions': [],
                        'report': error_msg
                    }
            else:
                print(f"{browser.upper()} 브라우저가 설치되지 않았거나 경로를 찾을 수 없습니다.")
                results[browser] = {
                    'security_checks': [SecurityCheck('not_found', 'INFO', '브라우저를 찾을 수 없습니다.')],
                    'extensions': [],
                    'report': '브라우저를 찾을 수 없습니다.'
                }
        
        return results

    def save_results_to_file(self, results: Dict[str, Any], filename: str = None):
        """결과를 파일로 저장"""
        if filename is None:
            filename = f"browser_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # 결과를 JSON 직렬화 가능한 형태로 변환
        json_results = {}
        for browser, data in results.items():
            json_results[browser] = {
                'security_checks': [asdict(check) for check in data['security_checks']],
                'extensions': [asdict(ext) for ext in data['extensions']],
                'report': data['report']
            }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(json_results, f, ensure_ascii=False, indent=2)
            print(f"\n결과가 '{filename}' 파일에 저장되었습니다.")
        except Exception as e:
            print(f"파일 저장 중 오류 발생: {e}")

def main():
    """메인 실행 함수"""
    print("🔒 브라우저 보안 설정 분석기")
    print("=" * 60)
    print(f"운영체제: {platform.system()}")
    print(f"Python 버전: {sys.version}")
    print("=" * 60)
    
    try:
        analyzer = BrowserSecurityAnalyzer()
        results = analyzer.analyze_all_browsers()
        
        # 전체 요약
        print("\n" + "=" * 60)
        print("📄 전체 분석 요약")
        print("=" * 60)
        
        analyzed_browsers = [browser for browser, data in results.items() 
                           if data['security_checks'] and data['security_checks'][0].status != 'INFO']
        total_extensions = sum(len(result['extensions']) for result in results.values())
        
        print(f"분석된 브라우저: {len(analyzed_browsers)}개")
        print(f"발견된 확장 프로그램: {total_extensions}개")
        
        # 위험도별 확장 프로그램 통계
        risk_summary = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for result in results.values():
            for ext in result['extensions']:
                risk_summary[ext.risk_level] += 1
        
        print("\n🔌 전체 확장 프로그램 위험도 분포:")
        for risk, count in risk_summary.items():
            print(f"  {risk}: {count}개")
        
        # 보안 권장사항
        print("\n💡 주요 보안 권장사항:")
        recommendations = [
            "정기적으로 확장 프로그램을 점검하고 불필요한 확장은 제거하세요.",
            "서드파티 쿠키를 차단하여 추적을 방지하세요.",
            "안전한 브라우징 기능을 활성화하여 악성 사이트를 차단하세요.",
            "브라우저를 최신 버전으로 유지하세요.",
            "의심스러운 다운로드나 팝업을 피하세요.",
            "중요한 사이트에서는 2단계 인증을 사용하세요."
        ]
        
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        
        # 결과를 파일로 저장할지 묻기
        save_choice = input("\n결과를 파일로 저장하시겠습니까? (y/n): ").lower().strip()
        if save_choice in ['y', 'yes']:
            analyzer.save_results_to_file(results)
        
        print("\n분석이 완료되었습니다!")
        
    except KeyboardInterrupt:
        print("\n\n분석이 사용자에 의해 중단되었습니다.")
    except Exception as e:
        print(f"\n분석 중 오류가 발생했습니다: {str(e)}")
        print("오류가 지속되면 관리자 권한으로 실행해보세요.")

if __name__ == "__main__":
    """메인 실행 함수"""
    print("🔒 브라우저 보안 설정 분석기")
    print("=" * 60)
    print(f"운영체제: {platform.system()}")
    print(f"Python 버전: {sys.version}")
    print("=" * 60)
    
    try:
        analyzer = BrowserSecurityAnalyzer()
        results = analyzer.analyze_all_browsers()
        
        # 전체 요약
        print("\n" + "=" * 60)
        print("📄 전체 분석 요약")
        print("=" * 60)
        
        analyzed_browsers = [browser for browser, data in results.items() 
                           if data['security_checks'] and data['security_checks'][0].status != 'INFO']
        total_extensions = sum(len(result['extensions']) for result in results.values())
        
        print(f"분석된 브라우저: {len(analyzed_browsers)}개")
        print(f"발견된 확장 프로그램: {total_extensions}개")
        
        # 위험도별 확장 프로그램 통계
        risk_summary = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for result in results.values():
            for ext in result['extensions']:
                risk_summary[ext.risk_level] += 1
        
        print("\n🔌 전체 확장 프로그램 위험도 분포:")
        for risk, count in risk_summary.items():
            print(f"  {risk}: {count}개")
        
        # 보안 권장사항
        print("\n💡 주요 보안 권장사항:")
        recommendations = [
            "정기적으로 확장 프로그램을 점검하고 불필요한 확장은 제거하세요.",
            "서드파티 쿠키를 차단하여 추적을 방지하세요.",
            "안전한 브라우징 기능을 활성화하여 악성 사이트를 차단하세요.",
            "브라우저를 최신 버전으로 유지하세요.",
            "의심스러운 다운로드나 팝업을 피하세요.",
            "중요한 사이트에서는 2단계 인증을 사용하세요."
        ]
        
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        
        # 결과를 파일로 저장할지 묻기
        save_choice = input("\n결과를 파일로 저장하시겠습니까? (y/n): ").lower().strip()
        if save_choice in ['y', 'yes']:
            analyzer.save_results_to_file(results)
        
        print("\n분석이 완료되었습니다!")
        
    except KeyboardInterrupt:
        print("\n\n분석이 사용자에 의해 중단되었습니다.")
    except Exception as e:
        print(f"\n분석 중 오류가 발생했습니다: {str(e)}")
        print("오류가 지속되면 관리자 권한으로 실행해보세요.")
 
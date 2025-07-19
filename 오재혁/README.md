# mcpsecurity
mcp로 보안 취약점 점검을 하는 대기고등학교 프로젝트

## 프로젝트 설명

MCP를 통한 보안 취약점 점검을 위한 프로젝트입니다. 이 프로젝트는 대기고등학교 학생들이 보안 취약점 점검을 할 수 있도록 만든 프로젝트입니다.

## 프로젝트 상세 내용

각 프로젝트에는 README.md 파일이 있습니다. 이 파일에는 프로젝트에 대한 자세한 설명과 사용 방법이 포함되어 있습니다.

```
# 프로젝트 설명
- 프로젝트1: Windows의 주요 레지스트리 보안 설정을 자동 점검, 결과를 분석하여 요약 보고서를 생성, 이전 결과 기반으로 보안 권장 사항도 안내, MCP 서버 형태로 실행되며, HTTP 요청을 통해 도구를 호출 가능

- 프로젝트2: 파일 내부에 포함된 민감한 정보를 정규표현식 기반으로 탐색, 전체 폴더를 순회하며 민감 정보 존재 여부를 분석
탐지 대상: 주민등록번호, 이메일, 전화번호, 카드번호 등

- 프로젝트3: 현재 시스템에서 실행 중인 의심스러운 프로세스 탐지, 일반적인 바이러스 or RAT or 크랙툴 or 스파이웨어 실행 여부 확인, 특정 프로세스를 종료하거나 상세 정보를 출력 가능, Windows 보안 센터 연동하여 전반적인 시스템 상태 확인


# 사용 방법
- 요구사항: 
- MCP 서버 실행: 

# 프로젝트1 함수
- 함수 call_claude_api: 실행 시 사용하는 Claude API 호출 함수
- 함수 read_registry_value: 레지스트리 값을 읽는 함수, 예외 처리 포함
- 함수 anayze_security_setting: 카테고리 별 보안 설정을 검사하는 함수
- 함수 write_file_internal: 내부 파일 저장 함수
- 함수 read_file_internal: 내부 파일 읽기 함수
- 함수 check_regisry_security: 전체 레지스트리 보안 점검 및 보고서 생성
- 함수 get_security_recommendations: 실행 결과 기반 권장 보완 사항 출력
- 함수 read_file: 파일 읽기
- 함수 write_file: 파일 쓰기

# 프로젝트2 함수
- 함수: scan_sensitive_data: 
- 함수: write_file: 파일 쓰기
- 함수: anaylze_process_behavior: 프로세스 행동 분석
- 함수: calculate_suspicion_score: 의심도(악성 프로세스) 점수 계산
- 함수: call_claude_api: Claude API 호출 함수
- 함수: scan_suspicious_processes: 의심 프로세스 스캔
- 함수: kill_suspicious_process: 의심 프로세스 종료(신중한 사용 필요)
- 함수: get_process_details: 특정 프로세스 상세 정보 조회

# 프로젝트3 함수
- 함수: scan_sensitive_data: 
- 함수: is_excluded_directory: 제외할 디렉토리 확인
- 함수: is_text_file: 텍스트 파일 여부 확인
- 함수: scan_file_content: 파일 내용에서 민감한 데이터 스캔
- 함수: get_files_to_scan: 스캔할 파일 목록 생성
- 함수: call_claude_api: Calude API 호출
- 함수: scan_sensitive_data: 지정된 디렉토리에서 민감한 데이터 스캔
- 함수: scan_specific_file: 특정 파일에서 민감한 데이터 스캔
- 함수: get_scan_patterns: 현재 설정된 민감함 데이터 검색 패턴 조회
```
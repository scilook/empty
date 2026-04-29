# 작업물 기능 명세

## 1) 기능 개요
- 제품명: vuln-patch-agent
- 형태: Ubuntu CLI 애플리케이션 + Debian 패키지
- 목적: 취약점 데이터 동기화, 로컬 취약 패키지 탐지, 선택적 패치, 감사/리포트 자동화

## 2) 실행 인터페이스
- 실행 파일: /usr/bin/vuln-patch-agent
- 내부 실행 대상: /usr/lib/vuln-patch-agent/patch_agent.py
- 공통 옵션
- --config <path>: JSON 설정 파일 경로 지정

## 3) 명령 기능 명세
- init-db
- 기능: SQLite 스키마 초기화
- 입력: db_path(config)
- 출력: {"status":"ok","db_path":"..."}
- 부작용: 테이블/인덱스 생성, 감사로그(db_initialized) 기록

- sync-nvd
- 기능: NVD API 2.0 취약점 데이터 동기화(증분)
- 입력: --api-key, --api-key-env, --since, --max-pages
- 출력: 시작/종료 시각, 페이지 수, 업서트 건수 요약 JSON
- 부작용: vulnerabilities, affected_packages 갱신, sync_state(nvd_last_mod_start) 갱신, 감사로그 기록

- import-oval
- 기능: Ubuntu OVAL XML에서 패키지 alias(cpe_name -> dpkg_name) 추출/반영
- 입력: --file <oval.xml>
- 출력: 처리 파일 경로, alias 업서트 건수 JSON
- 부작용: package_aliases 갱신, 감사로그 기록

- scan
- 기능: 로컬 설치 패키지와 취약점 DB 매칭
- 입력: --output (선택)
- 출력: 설치 패키지 수, 취약 판정 수, 취약 패키지 목록 JSON
- 부작용: scan_history 저장, 감사로그(scan_completed) 기록

- patch
- 기능: 취약 패키지 선택 업그레이드
- 입력: --scan-file, --dry-run, --output
- 출력: 대상 패키지, 전후 취약 건수, 완화율, 명령 실행 결과 JSON
- 부작용: (dry-run이 아니고 대상 존재 시) apt-get update, apt-get install --only-upgrade -y <targets> 실행, patch_history 저장, 감사로그(patch_completed) 기록

- run
- 기능: 전체 파이프라인 실행(sync -> optional import-oval -> scan -> optional patch)
- 입력: --api-key, --api-key-env, --since, --max-pages, --oval-file, --patch, --dry-run, --output
- 출력: 단계별 결과 JSON
- 부작용: 각 단계별 DB/로그/파일 출력 발생

- report
- 기능: 최신 scan_history, patch_history 기반 종합 리포트 생성
- 입력: --output (선택)
- 출력: latest_scan, latest_patch, mitigation_success_rate 포함 JSON
- 부작용: 리포트 파일 저장, 감사로그(report_generated) 기록

## 4) 설정 파일 명세
- 기본 경로: /etc/vuln-patch-agent/config.json
- 키 정의
- db_path: SQLite 파일 경로
- audit_log: JSON 라인 감사로그 파일 경로
- scan_output: scan 기본 출력 경로
- report_output: report 기본 출력 경로
- nvd_endpoint: NVD API 2.0 엔드포인트
- results_per_page: NVD 페이지 크기

## 5) 데이터 저장소 명세(SQLite)
- vulnerabilities
- 용도: CVE 메타데이터 저장
- 주요 컬럼: cve_id(PK), description, cvss_score, published_date, last_modified_date

- affected_packages
- 용도: CVE별 영향 제품/버전 범위 저장
- 주요 컬럼: cve_id(FK), product_name, version_start/end, inclusive 플래그, source

- package_aliases
- 용도: CPE 제품명과 dpkg 패키지명 매핑
- 주요 컬럼: cpe_name(PK), dpkg_name, source, updated_at

- sync_state
- 용도: 증분 동기화 포인터 저장
- 주요 컬럼: key(PK), value, updated_at

- scan_history
- 용도: 스캔 실행 이력/원본 결과 저장
- 주요 컬럼: run_at, vulnerable_findings, vulnerable_packages, output_json

- patch_history
- 용도: 패치 실행 이력/원본 결과 저장
- 주요 컬럼: run_at, target_count, success_count, failed_count, output_json

## 6) 버전 비교 및 매칭 규칙
- 패키지 버전 비교 우선순위
- 1순위: python3-apt의 apt_pkg.version_compare
- 2순위: dpkg --compare-versions 폴백

- 매칭 규칙
- 설치 패키지명(dpkg-query 결과)을 normalize 후 비교.
- product_name 및 alias(cpe_name -> dpkg_name) 양쪽 후보를 사용.
- version_start/version_end와 inclusive/exclusive 조건으로 취약 범위 판정.

## 7) 보안/권한 명세
- 서비스 계정: patch-agent(비로그인)
- sudo 허용 명령(선택적)
- /usr/bin/apt-get update
- /usr/bin/apt-get install --only-upgrade *
- 권한 최소화
- 작업 디렉터리 권한 0750 유지
- 앱 실행 권한을 서비스 계정 기준으로 분리 운용 가능

## 8) 로깅/감사 명세
- 감사 로그 포맷: JSON Lines
- 기본 로그 파일: /var/log/vuln-patch-agent/audit.log
- 공통 필드: timestamp, level, event, details
- 주요 이벤트
- db_initialized
- nvd_sync_completed / nvd_sync_failed
- oval_import_completed
- scan_completed
- patch_completed
- report_generated
- agent_error

## 9) 제약사항 및 가정
- Ubuntu 22.04 LTS 환경 중심의 MVP 설계.
- 네트워크 접근성에 따라 NVD 동기화 성공 여부가 달라질 수 있음.
- OVAL alias import 정확도는 입력 XML 품질에 의존.
- 실제 완화율은 저장소 상태 및 업데이트 가능 패키지에 의해 변동.

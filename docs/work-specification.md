# 작업 내용 명세

## 1) 문서 정보
- 문서명: Ubuntu Vulnerability Patch Agent 작업 내용 명세
- 대상 프로젝트: vuln-patch-agent (MVP)
- 버전: 0.1.0
- 작성일: 2026-04-22
- 기준 요구사항 문서: gemini-code-1776844178420.md

## 2) 작업 목표
- Ubuntu 22.04 환경에서 취약점 탐지와 선택적 패치를 수행하는 CLI 애플리케이션을 패키지 형태로 제공.
- 단일 ELF 바이너리가 아닌 설치 패키지 산출물(.deb, .tar.gz) 제공.
- 설치 과정에서 서비스 계정 생성, 최소 권한 구성, 초기화 작업까지 자동화.

## 3) 작업 범위
- 포함 범위
- NVD API 2.0 기반 취약점 데이터 수집 및 증분 동기화 구현.
- SQLite3 기반 취약점/영향 패키지/이력 저장소 구현.
- OVAL XML 기반 alias import(제품명 매핑) 구현.
- dpkg-query 기반 로컬 패키지 탐지 및 버전 비교 기반 취약 여부 판정 구현.
- 선택적 패치 실행(apt-get update, install --only-upgrade) 구현.
- JSON 감사 로그, 스캔 결과, 패치 결과, 종합 리포트 생성 구현.
- Debian 패키지 구조 및 maintainer script(postinst/postrm) 작성.

- 제외 범위
- 커널 라이브 패치(Kpatch, KGraft 등) 미구현.
- GUI 대시보드 미구현.
- 타 OS 지원 미구현(Ubuntu 22.04 중심 MVP).

## 4) 구현 산출물
- 앱 엔트리포인트: /usr/bin/vuln-patch-agent
- 앱 본체: /usr/lib/vuln-patch-agent/patch_agent.py
- 기본 설정: /etc/vuln-patch-agent/config.json
- 문서: /usr/share/doc/vuln-patch-agent/README.Debian
- 패키지 메타/스크립트
- DEBIAN/control
- DEBIAN/conffiles
- DEBIAN/postinst
- DEBIAN/postrm

## 5) 설치 자동화(계정/권한) 작업 명세
- postinst에서 patch-agent 시스템 그룹/계정 생성.
- patch-agent 계정은 /usr/sbin/nologin 쉘로 생성(비로그인 서비스 계정).
- 런타임 디렉터리 생성 및 소유권 부여.
- /var/lib/vuln-patch-agent
- /var/log/vuln-patch-agent
- 위 두 디렉터리에 0750 권한 적용.
- /etc/sudoers.d/patch-agent 생성 후 아래 명령만 NOPASSWD 허용.
- /usr/bin/apt-get update
- /usr/bin/apt-get install --only-upgrade *
- visudo -cf 검증 수행(가능한 경우).
- 설치 직후 init-db 실행 시도(실패 시 설치를 중단하지 않음).

## 6) 패키징 작업 명세
- 패키지명: vuln-patch-agent
- 버전: 0.1.0
- 아키텍처: all
- 의존성: python3 (>= 3.10), python3-apt, sudo, dpkg, apt
- 생성 산출물
- dist/vuln-patch-agent_0.1.0_all.deb
- dist/vuln-patch-agent_0.1.0.tar.gz
- 빌드 시 권한 규칙 적용
- 디렉터리: 0755
- 일반 파일: 0644
- 실행 스크립트(postinst/postrm, 실행 엔트리, 메인 스크립트): 0755

## 7) 검증 작업 명세
- 정적 검증
- Python 문법 검증(py_compile) 통과.
- dpkg-deb 메타데이터 검사 통과.
- dpkg-deb 파일 목록 검사 통과.

- 동작 검증
- init-db 실행 확인.
- scan 실행 및 JSON 출력 확인.
- patch --dry-run 실행 확인.
- report 실행 및 완화율 필드 출력 확인.

## 8) 요구사항 반영 요약
- 앱설치 요구사항 반영
- Debian 설치 패키지(.deb) 제공.
- 압축 배포본(.tar.gz) 추가 제공.

- 계정관리 요구사항 반영
- 설치 시 patch-agent 서비스 계정 자동 생성.
- 비로그인 정책 및 최소 권한 sudo 정책 반영.

- 데이터/매칭/패치 요구사항 반영
- NVD API 증분 동기화, SQLite 저장, OVAL alias import, 로컬 스캔, 선택적 업그레이드, JSON 감사로그 구현.

## 9) 운영 시 유의사항
- 실제 패치 수행(patch 명령, dry-run 제외)은 sudoers 정책과 네트워크 환경(apt, NVD 접근)에 영향을 받음.
- NVD API 사용량이 많은 경우 API 키 설정 권장.
- Ubuntu OVAL 파일 경로를 지정해야 alias 매칭 정확도를 높일 수 있음.

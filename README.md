# USAG-Lib v1.4.4

Universal Security Assistant Gear - Library

- python: 테스트와 스크립팅에 사용합니다. 구현 표준으로, 다른 구현체는 파이썬 버전에 호환성을 맞춰야 합니다.
Used for testing and scripting. As the reference implementation, other implementations must maintain compatibility with the Python version.
- javascript: 웹에서 사용합니다. Node.js와 브라우저 환경을 모두 지원하지만, 공식 테스트는 브라우저 환경만 진행되었습니다.
Used for the web. Supports both Node.js and browser environments, but official tests were conducted only in the browser environment.
- golang: 데스크탑 앱과 서버에 사용합니다. 성능 최적화가 가장 잘 되어있습니다.
Used for desktop apps and servers. It has the best performance optimization.
- java: 안드로이드 앱과 일부 데스크탑 앱에 사용합니다. 공식 테스트는 데스크탑 환경만 진행되었습니다.
Used for Android apps and some desktop apps. Official tests were conducted only in the desktop environment.

### macro

프로젝트 보조 코드, 자동화 코드, 설정 값 등을 포함합니다.
Contains project auxiliary codes, automation codes, configuration values, etc.

### Icons

아이콘 이미지 바이너리를 제공합니다.
Provides icon image binaries.

### Szip

간단화한 ZIP64 컨테이너 형식을 읽고 씁니다.
Reads and writes a simplified ZIP64 container format.

### Star

간단화한 TAR-PAX 컨테이너 형식을 읽고 씁니다.
Reads and writes a simplified TAR-PAX container format.

### Bencode

이진 데이터를 문자열로 인코딩하고 다시 디코딩하는 기능을 제공합니다.
Provides functions to encode binary data into strings and decode them back.

### Bencrypt

기본 암호화 기능을 담당합니다.
Handles basic encryption functions.

### Opsec

복합 암호화 기능과 암호파일 형식화를 담당합니다.
Handles complex encryption functions and encrypted file formatting.

# Setup Env in Windows

Windows OS is independent from programming language setup.

### python

- delete old version
- install new version with "add to PATH" option
- `py --version`

### golang

- install new version (old version will be deleted automatically)
- `go version`

# Setup Env in Linux

Linux OS can be dependent of programming language setup. Root and user privileges use different library spaces.

### python

Remove the existing Python and add a private repository to download it.

```bash
sudo apt update
sudo apt upgrade
sudo apt autoremove
apt update
apt upgrade
apt autoremove

sudo apt install software-properties-common
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update

sudo apt remove python3.12
apt remove python3.12
rm ~/pip3.12 # /home/%%user%%/.local/bin

sudo apt install python3.15
curl -sS https://bootstrap.pypa.io/get-pip.py | python3.15

echo "export PATH=$PATH:/home/%%user%%/.local/bin" >> ~/.profile
source ~/.profile

python --version
python3.15 --version
pip --version
pip3.15 --version

sudo apt install python3.13-venv
python3.15 -m venv .venv
source .venv/bin/activate
sudo apt-get install python3.15-dev
sudo apt-get install python3.15-tk
```

### golang

Remove the existing Golang and unzip it directly to a local folder.

```bash
apt remove golang
sudo apt remove golang
sudo rm -rf /usr/local/go

sudo tar -C /usr/local/ -xzf go1.26.3.linux-amd64.tar.gz # download from go.dev

echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.profile
source ~/.profile

go version
```

# Coding Conventions

- Name module with `PascalCase`. (MyModule.ext)
- Name global variable, function and class with `PascalCase`. (MyClass)
- Name local/private object with `camelCase`, Adding underbar is allowed. (isCond, _table)
- Name filename of documents (README, LICENSE) all capital, but extensions should be always lower.
- Write short, readable, unified, non-verbose code.

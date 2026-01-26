# USAG-Lib

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

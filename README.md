# NoZic: Archive Utility Security Configuration and ZipCrypto File Converter

[![GitHub Stars](https://img.shields.io/github/stars/cadetB/NoZic?style=social)](https://github.com/cadetB/NoZic/stargazers)
[![GitHub License](https://img.shields.io/github/license/cadetB/NoZic)](LICENSE)

---

## 💡 Introduction

**NoZic** is a utility that **enforces** the use of the secure **AES-256** algorithm, preventing the use of the security-vulnerable **ZipCrypto** for ZIP file encryption, and **automatically converts** existing vulnerable files.

The tool performs two core functions to ensure the confidentiality of critical files:

1.  **Automated Security Hardening:** **Fixes** the default encryption setting of **5 archive utilities** (including **Bandizip, 7-Zip, WinRAR, WinZip, and Peazip**) from ZipCrypto to **AES-256**. (Via Registry or File Modification)
2.  **Vulnerable File Conversion:** **Automatically converts** all **ZipCrypto-encrypted files** within a user-selected folder into secure **AES-256 encrypted files**.

The implementation of this program is based on **research currently submitted to a KCI-level journal competition**.


## ✨ Features

* **Automatic Configuration:** Enforces **AES-256** as the default encryption algorithm for the 5 archive utilities.
* **Batch Vulnerable File Conversion:** Safely converts ZipCrypto files to AES-256 using the **old password and a new password** within a user-specified folder.

## 📖 Usage

### 1. Using the Executable (Windows)

1.  Download the **`NoZic.exe`** file from the GitHub Release page.
2.  Run the downloaded file.
3.  **Upon execution, you can select one of the two main functions on the main screen:**
    * **Change AES Setting:** Modifies the registry values of 5 archive utilities to permanently fix the default encryption algorithm to **AES**.
    * **Convert ZIPCRYPTO Files:** Prompts the user to select a folder and input the **old password and a new password** to automatically convert all ZipCrypto files within that folder to **AES-256**.
4.  The program's operation process and conversion results can be tracked in **real-time via the terminal output** at the bottom.

-   **Test Files (ZipCrypto, AES)**
    1.  `Test_zip crypto.zip`: ZIP format compressed with Zip Crypto (pw: 123)
    2.  `Test_zip crypto(AES로 변환완료).zip`: ZIP format converted to AES256 using the program (pw: 123456789)


## 📄 Related Research

The development of this tool is awaiting the results of the following journal competition:

* **Paper Title (English):** A Study on Mitigation for Insecure ZipCrypto Usage in Archive Utilities: Focusing on a Tool for Security Configuration Enforcement and AES Conversion of Legacy ZIP Files
* **Journal:** 「Journal of Defense and Security」(KCI-level) - *Currently submitted and under review*
* **Authors:** Geunho Baek, Donghyun Kim



## 📝 License

This project is distributed under the **[---]** License.
---
---
# NoZic: 압축 유틸리티 보안 설정 및 ZipCrypto 파일 변환 도구

[![GitHub Stars](https://img.shields.io/github/stars/cadetB/NoZic?style=social)](https://github.com/cadetB/NoZic/stargazers)
[![GitHub License](https://img.shields.io/github/license/cadetB/NoZic)](LICENSE)

---

## 💡 소개 (Introduction)

**NoZic**은 ZIP 파일 암호화에 있어 보안에 취약한 **ZipCrypto**의 사용을 방지하고 안전한 **AES-256** 알고리즘 사용을 **강제**하며, 기존의 취약한 파일을 **자동으로 변환**하는 유틸리티이다.

이 도구는 크게 두 가지 핵심 기능을 수행하여 중요 파일의 기밀성을 보장한다:

1.  **자동 보안 강화:** **반디집, 7-Zip, WinRAR, WinZip, Peazip**를 포함한 **5종 압축 유틸리티**의 기본 암호화 설정을 ZipCrypto에서 **AES-256으로 고정** (레지스트리 혹은 파일 수정)
2.  **취약 파일 변환:** 사용자가 선택한 폴더 내의 **ZipCrypto로 암호화된 모든 파일**을 안전한 **AES-256 암호화 파일로 자동 변환**

이 프로그램의 구현은 **KCI급 학술지 논문 공모 중인 연구 결과**를 바탕으로 한다.

## ✨ 주요 기능 (Features)

* **자동 설정 변경:** 5종 압축 유틸리티의 기본 암호화 알고리즘을 **AES-256**으로 강제 설정
* **취약 파일 일괄 변환:** 사용자가 지정한 폴더 내의 ZipCrypto 파일을 기존 비밀번호와 새 비밀번호를 이용해 AES-256으로 안전하게 변환

## 📖 사용법 (Usage)

### 1. 실행 파일 사용 (Windows)

1.  GitHub Release 페이지에서 **`NoZic.exe`** 파일을 다운로드
2.  다운로드한 파일을 실행
3.  **프로그램 실행 후, 메인 화면에서 다음과 같은 두 가지 주요 기능을 선택할 수 있음:**
    * **AES 설정 변경:** 5종 압축 유틸리티의 레지스트리 값을 수정하여 기본 암호화 알고리즘을 **AES로 고정**
    * **ZIPCRYPTO 파일 변환:** 사용자에게 폴더 선택을 요청하고, **기존 비밀번호와 새 비밀번호를 입력**받아 해당 폴더 내의 모든 ZipCrypto 파일을 **AES-256으로 자동 변환**
4.  프로그램 작동 과정과 변환 결과는 하단부 **터미널 출력을 통해 실시간으로 파악**

- 테스트 파일 (ZipCrypto, AES)
  1. Test_zip crypto.zip : Zip Crypto로 압축된 zip 포맷 (pw: 123)
  2. Test_zip crypto(AES로 변환완료).zip : 프로그램을 통해 AES256으로 변환한 zip 포맷 (pw: 123456789)

  
## 📄 관련 논문 (Related Research)

이 도구의 개발은 다음 논문 공모 결과를 기다리고 있다:

* **논문 제목 (한글):** 압축 유틸리티의 취약한 ZipCrypto 사용 문제에 대한 해결 방안 연구: 보안 설정 변경 및 기존 ZIP 파일의 AES 변환 도구 구현을 중심으로
* **학술지:** 「국방과 보안」 (KCI급) - *현재 논문 공모 및 심사 진행 중*
* **저자:** 백근호, 김동현

## 📝 라이선스 (License)

이 프로젝트는 **[---]** 하에 배포됩니다.

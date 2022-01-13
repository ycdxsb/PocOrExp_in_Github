# Update 2022-01-13
## CVE-2021-32099
 A SQL injection vulnerability in the pandora_console component of Artica Pandora FMS 742 allows an unauthenticated attacker to upgrade his unprivileged session via the /include/chart_generator.php session_id parameter, leading to a login bypass.

- [https://github.com/zjicmDarkWing/CVE-2021-32099](https://github.com/zjicmDarkWing/CVE-2021-32099) :  ![starts](https://img.shields.io/github/stars/zjicmDarkWing/CVE-2021-32099.svg) ![forks](https://img.shields.io/github/forks/zjicmDarkWing/CVE-2021-32099.svg)


## CVE-2021-31956
 Windows NTFS Elevation of Privilege Vulnerability

- [https://github.com/aazhuliang/CVE-2021-31956-EXP](https://github.com/aazhuliang/CVE-2021-31956-EXP) :  ![starts](https://img.shields.io/github/stars/aazhuliang/CVE-2021-31956-EXP.svg) ![forks](https://img.shields.io/github/forks/aazhuliang/CVE-2021-31956-EXP.svg)


## CVE-2021-0434
 In onReceive of BluetoothPermissionRequest.java, there is a possible phishing attack allowing a malicious Bluetooth device to acquire permissions based on insufficient information presented to the user in the consent dialog. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-9Android ID: A-167403112

- [https://github.com/Nivaskumark/CVE-2021-0434_packages_apps_Settings](https://github.com/Nivaskumark/CVE-2021-0434_packages_apps_Settings) :  ![starts](https://img.shields.io/github/stars/Nivaskumark/CVE-2021-0434_packages_apps_Settings.svg) ![forks](https://img.shields.io/github/forks/Nivaskumark/CVE-2021-0434_packages_apps_Settings.svg)
- [https://github.com/Nivaskumark/CVE-2021-0434_packages_apps_Settings_beforefix](https://github.com/Nivaskumark/CVE-2021-0434_packages_apps_Settings_beforefix) :  ![starts](https://img.shields.io/github/stars/Nivaskumark/CVE-2021-0434_packages_apps_Settings_beforefix.svg) ![forks](https://img.shields.io/github/forks/Nivaskumark/CVE-2021-0434_packages_apps_Settings_beforefix.svg)


## CVE-2020-7352
 The GalaxyClientService component of GOG Galaxy runs with elevated SYSTEM privileges in a Windows environment. Due to the software shipping with embedded, static RSA private key, an attacker with this key material and local user permissions can effectively send any operating system command to the service for execution in this elevated context. The service listens for such commands on a locally-bound network port, localhost:9978. A Metasploit module has been published which exploits this vulnerability. This issue affects the 2.0.x branch of the software (2.0.12 and earlier) as well as the 1.2.x branch (1.2.64 and earlier). A fix was issued for the 2.0.x branch of the affected software.

- [https://github.com/szerszen199/PS-CVE-2020-7352](https://github.com/szerszen199/PS-CVE-2020-7352) :  ![starts](https://img.shields.io/github/stars/szerszen199/PS-CVE-2020-7352.svg) ![forks](https://img.shields.io/github/forks/szerszen199/PS-CVE-2020-7352.svg)


## CVE-2019-18276
 An issue was discovered in disable_priv_mode in shell.c in GNU Bash through 5.0 patch 11. By default, if Bash is run with its effective UID not equal to its real UID, it will drop privileges by setting its effective UID to its real UID. However, it does so incorrectly. On Linux and other systems that support &quot;saved UID&quot; functionality, the saved UID is not dropped. An attacker with command execution in the shell can use &quot;enable -f&quot; for runtime loading of a new builtin, which can be a shared object that calls setuid() and therefore regains privileges. However, binaries running with an effective UID of 0 are unaffected.

- [https://github.com/SABI-Ensimag/CVE-2019-18276](https://github.com/SABI-Ensimag/CVE-2019-18276) :  ![starts](https://img.shields.io/github/stars/SABI-Ensimag/CVE-2019-18276.svg) ![forks](https://img.shields.io/github/forks/SABI-Ensimag/CVE-2019-18276.svg)


## CVE-2019-17240
 bl-kernel/security.class.php in Bludit 3.9.2 allows attackers to bypass a brute-force protection mechanism by using many different forged X-Forwarded-For or Client-IP HTTP headers.

- [https://github.com/k4yhan/CVE-2019-17240](https://github.com/k4yhan/CVE-2019-17240) :  ![starts](https://img.shields.io/github/stars/k4yhan/CVE-2019-17240.svg) ![forks](https://img.shields.io/github/forks/k4yhan/CVE-2019-17240.svg)


## CVE-2019-16113
 Bludit 3.9.2 allows remote code execution via bl-kernel/ajax/upload-images.php because PHP code can be entered with a .jpg file name, and then this PHP code can write other PHP code to a ../ pathname.

- [https://github.com/k4yhan/CVE-2019-16113](https://github.com/k4yhan/CVE-2019-16113) :  ![starts](https://img.shields.io/github/stars/k4yhan/CVE-2019-16113.svg) ![forks](https://img.shields.io/github/forks/k4yhan/CVE-2019-16113.svg)


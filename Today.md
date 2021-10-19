# Update 2021-10-19
## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/twseptian/CVE-2021-42013-Docker-Lab](https://github.com/twseptian/CVE-2021-42013-Docker-Lab) :  ![starts](https://img.shields.io/github/stars/twseptian/CVE-2021-42013-Docker-Lab.svg) ![forks](https://img.shields.io/github/forks/twseptian/CVE-2021-42013-Docker-Lab.svg)


## CVE-2021-40449
 Win32k Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-40450, CVE-2021-41357.

- [https://github.com/ly4k/CallbackHell](https://github.com/ly4k/CallbackHell) :  ![starts](https://img.shields.io/github/stars/ly4k/CallbackHell.svg) ![forks](https://img.shields.io/github/forks/ly4k/CallbackHell.svg)


## CVE-2021-40438
 A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the remote user. This issue affects Apache HTTP Server 2.4.48 and earlier.

- [https://github.com/xiaojiangxl/CVE-2021-40438](https://github.com/xiaojiangxl/CVE-2021-40438) :  ![starts](https://img.shields.io/github/stars/xiaojiangxl/CVE-2021-40438.svg) ![forks](https://img.shields.io/github/forks/xiaojiangxl/CVE-2021-40438.svg)


## CVE-2021-34527
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/ly4k/PrintNightmare](https://github.com/ly4k/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/ly4k/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/ly4k/PrintNightmare.svg)


## CVE-2021-1675
 Windows Print Spooler Elevation of Privilege Vulnerability

- [https://github.com/ly4k/PrintNightmare](https://github.com/ly4k/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/ly4k/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/ly4k/PrintNightmare.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/ly4k/SMBGhost](https://github.com/ly4k/SMBGhost) :  ![starts](https://img.shields.io/github/stars/ly4k/SMBGhost.svg) ![forks](https://img.shields.io/github/forks/ly4k/SMBGhost.svg)


## CVE-2020-0610
 A remote code execution vulnerability exists in Windows Remote Desktop Gateway (RD Gateway) when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Windows Remote Desktop Gateway (RD Gateway) Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0609.

- [https://github.com/ly4k/BlueGate](https://github.com/ly4k/BlueGate) :  ![starts](https://img.shields.io/github/stars/ly4k/BlueGate.svg) ![forks](https://img.shields.io/github/forks/ly4k/BlueGate.svg)


## CVE-2020-0609
 A remote code execution vulnerability exists in Windows Remote Desktop Gateway (RD Gateway) when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Windows Remote Desktop Gateway (RD Gateway) Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0610.

- [https://github.com/ly4k/BlueGate](https://github.com/ly4k/BlueGate) :  ![starts](https://img.shields.io/github/stars/ly4k/BlueGate.svg) ![forks](https://img.shields.io/github/forks/ly4k/BlueGate.svg)


## CVE-2020-0601
 A spoofing vulnerability exists in the way Windows CryptoAPI (Crypt32.dll) validates Elliptic Curve Cryptography (ECC) certificates.An attacker could exploit the vulnerability by using a spoofed code-signing certificate to sign a malicious executable, making it appear the file was from a trusted, legitimate source, aka 'Windows CryptoAPI Spoofing Vulnerability'.

- [https://github.com/ly4k/CurveBall](https://github.com/ly4k/CurveBall) :  ![starts](https://img.shields.io/github/stars/ly4k/CurveBall.svg) ![forks](https://img.shields.io/github/forks/ly4k/CurveBall.svg)


## CVE-2019-17662
 ThinVNC 1.0b1 is vulnerable to arbitrary file read, which leads to a compromise of the VNC server. The vulnerability exists even when authentication is turned on during the deployment of the VNC server. The password for authentication is stored in cleartext in a file that can be read via a ../../ThinVnc.ini directory traversal attack vector.

- [https://github.com/rajendrakumaryadav/CVE-2019-17662-Exploit](https://github.com/rajendrakumaryadav/CVE-2019-17662-Exploit) :  ![starts](https://img.shields.io/github/stars/rajendrakumaryadav/CVE-2019-17662-Exploit.svg) ![forks](https://img.shields.io/github/forks/rajendrakumaryadav/CVE-2019-17662-Exploit.svg)


## CVE-2018-15365
 A Reflected Cross-Site Scripting (XSS) vulnerability in Trend Micro Deep Discovery Inspector 3.85 and below could allow an attacker to bypass CSRF protection and conduct an attack on vulnerable installations. An attacker must be an authenticated user in order to exploit the vulnerability.

- [https://github.com/nixwizard/CVE-2018-15365](https://github.com/nixwizard/CVE-2018-15365) :  ![starts](https://img.shields.io/github/stars/nixwizard/CVE-2018-15365.svg) ![forks](https://img.shields.io/github/forks/nixwizard/CVE-2018-15365.svg)


## CVE-2018-15133
 In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.

- [https://github.com/huydoppa/CVE-2018-15133](https://github.com/huydoppa/CVE-2018-15133) :  ![starts](https://img.shields.io/github/stars/huydoppa/CVE-2018-15133.svg) ![forks](https://img.shields.io/github/forks/huydoppa/CVE-2018-15133.svg)


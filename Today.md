# Update 2025-02-19
## CVE-2025-21420
 Windows Disk Cleanup Tool Elevation of Privilege Vulnerability

- [https://github.com/Network-Sec/CVE-2025-21420-PoC](https://github.com/Network-Sec/CVE-2025-21420-PoC) :  ![starts](https://img.shields.io/github/stars/Network-Sec/CVE-2025-21420-PoC.svg) ![forks](https://img.shields.io/github/forks/Network-Sec/CVE-2025-21420-PoC.svg)


## CVE-2025-0851
 A path traversal issue in ZipUtils.unzip and TarUtils.untar in Deep Java Library (DJL) on all platforms allows a bad actor to write files to arbitrary locations.

- [https://github.com/skrkcb2/CVE-2025-0851](https://github.com/skrkcb2/CVE-2025-0851) :  ![starts](https://img.shields.io/github/stars/skrkcb2/CVE-2025-0851.svg) ![forks](https://img.shields.io/github/forks/skrkcb2/CVE-2025-0851.svg)


## CVE-2024-56477
 IBM Power Hardware Management Console V10.3.1050.0 could allow an authenticated user to traverse directories on the system. An attacker could send a specially crafted URL request containing "dot dot" sequences (/../) to view arbitrary files on the system.

- [https://github.com/0xbughunter/CVE-2024-56477](https://github.com/0xbughunter/CVE-2024-56477) :  ![starts](https://img.shields.io/github/stars/0xbughunter/CVE-2024-56477.svg) ![forks](https://img.shields.io/github/forks/0xbughunter/CVE-2024-56477.svg)


## CVE-2024-43762
 In multiple locations, there is a possible way to avoid unbinding of a service from the system due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Mahesh-970/CVE-2024-43762](https://github.com/Mahesh-970/CVE-2024-43762) :  ![starts](https://img.shields.io/github/stars/Mahesh-970/CVE-2024-43762.svg) ![forks](https://img.shields.io/github/forks/Mahesh-970/CVE-2024-43762.svg)


## CVE-2024-23666
at least version 7.4.0 and 7.2.0 through 7.2.6 and 7.0.1 through 7.0.6 and 6.4.5 through 6.4.7 and 6.2.5, FortiManager version 7.4.0 through 7.4.1 and 7.2.0 through 7.2.4 and 7.0.0 through 7.0.11 and 6.4.0 through 6.4.14, FortiAnalyzer version 7.4.0 through 7.4.1 and 7.2.0 through 7.2.4 and 7.0.0 through 7.0.11 and 6.4.0 through 6.4.14 allows attacker to improper access control via crafted requests.

- [https://github.com/synacktiv/CVE-2023-42791_CVE-2024-23666](https://github.com/synacktiv/CVE-2023-42791_CVE-2024-23666) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2023-42791_CVE-2024-23666.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2023-42791_CVE-2024-23666.svg)


## CVE-2024-10924
 The Really Simple Security (Free, Pro, and Pro Multisite) plugins for WordPress are vulnerable to authentication bypass in versions 9.0.0 to 9.1.1.1. This is due to improper user check error handling in the two-factor REST API actions with the 'check_login_and_get_user' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, when the "Two-Factor Authentication" setting is enabled (disabled by default).

- [https://github.com/sariamubeen/CVE-2024-10924](https://github.com/sariamubeen/CVE-2024-10924) :  ![starts](https://img.shields.io/github/stars/sariamubeen/CVE-2024-10924.svg) ![forks](https://img.shields.io/github/forks/sariamubeen/CVE-2024-10924.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/inpentest/CVE-2024-4367-PoC](https://github.com/inpentest/CVE-2024-4367-PoC) :  ![starts](https://img.shields.io/github/stars/inpentest/CVE-2024-4367-PoC.svg) ![forks](https://img.shields.io/github/forks/inpentest/CVE-2024-4367-PoC.svg)


## CVE-2023-48795
 The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80, AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0, Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15, SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3, Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh crate before 0.40.2 for Rust.

- [https://github.com/sameeralam3127/rhel8_cve_2023_48795](https://github.com/sameeralam3127/rhel8_cve_2023_48795) :  ![starts](https://img.shields.io/github/stars/sameeralam3127/rhel8_cve_2023_48795.svg) ![forks](https://img.shields.io/github/forks/sameeralam3127/rhel8_cve_2023_48795.svg)


## CVE-2023-42791
 A relative path traversal in Fortinet FortiManager version 7.4.0 and 7.2.0 through 7.2.3 and 7.0.0 through 7.0.8 and 6.4.0 through 6.4.12 and 6.2.0 through 6.2.11 allows attacker to execute unauthorized code or commands via crafted HTTP requests.

- [https://github.com/synacktiv/CVE-2023-42791_CVE-2024-23666](https://github.com/synacktiv/CVE-2023-42791_CVE-2024-23666) :  ![starts](https://img.shields.io/github/stars/synacktiv/CVE-2023-42791_CVE-2024-23666.svg) ![forks](https://img.shields.io/github/forks/synacktiv/CVE-2023-42791_CVE-2024-23666.svg)


## CVE-2023-33584
 Sourcecodester Enrollment System Project V1.0 is vulnerable to SQL Injection (SQLI) attacks, which allow an attacker to manipulate the SQL queries executed by the application. The application fails to properly validate user-supplied input in the username and password fields during the login process, enabling an attacker to inject malicious SQL code.

- [https://github.com/sudovivek/Published-CVE](https://github.com/sudovivek/Published-CVE) :  ![starts](https://img.shields.io/github/stars/sudovivek/Published-CVE.svg) ![forks](https://img.shields.io/github/forks/sudovivek/Published-CVE.svg)


## CVE-2023-33580
 Phpgurukul Student Study Center Management System V1.0 is vulnerable to Cross Site Scripting (XSS) in the "Admin Name" field on Admin Profile page.

- [https://github.com/sudovivek/Published-CVE](https://github.com/sudovivek/Published-CVE) :  ![starts](https://img.shields.io/github/stars/sudovivek/Published-CVE.svg) ![forks](https://img.shields.io/github/forks/sudovivek/Published-CVE.svg)


## CVE-2022-47522
 The IEEE 802.11 specifications through 802.11ax allow physically proximate attackers to intercept (possibly cleartext) target-destined frames by spoofing a target's MAC address, sending Power Save frames to the access point, and then sending other frames to the access point (such as authentication frames or re-association frames) to remove the target's original security context. This behavior occurs because the specifications do not require an access point to purge its transmit queue before removing a client's pairwise encryption key.

- [https://github.com/toffeenutt/CVE-2022-47522-PoC](https://github.com/toffeenutt/CVE-2022-47522-PoC) :  ![starts](https://img.shields.io/github/stars/toffeenutt/CVE-2022-47522-PoC.svg) ![forks](https://img.shields.io/github/forks/toffeenutt/CVE-2022-47522-PoC.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)


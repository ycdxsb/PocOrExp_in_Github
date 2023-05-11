# Update 2023-05-11
## CVE-2023-30777
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/securitymike2310/ms-word-zero-day-rce-poc](https://github.com/securitymike2310/ms-word-zero-day-rce-poc) :  ![starts](https://img.shields.io/github/stars/securitymike2310/ms-word-zero-day-rce-poc.svg) ![forks](https://img.shields.io/github/forks/securitymike2310/ms-word-zero-day-rce-poc.svg)


## CVE-2023-30256
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ahrixia/CVE-2023-30256](https://github.com/ahrixia/CVE-2023-30256) :  ![starts](https://img.shields.io/github/stars/ahrixia/CVE-2023-30256.svg) ![forks](https://img.shields.io/github/forks/ahrixia/CVE-2023-30256.svg)


## CVE-2023-29930
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/YSaxon/TFTPlunder](https://github.com/YSaxon/TFTPlunder) :  ![starts](https://img.shields.io/github/stars/YSaxon/TFTPlunder.svg) ![forks](https://img.shields.io/github/forks/YSaxon/TFTPlunder.svg)


## CVE-2023-27328
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/kn32/parallels-plist-escape](https://github.com/kn32/parallels-plist-escape) :  ![starts](https://img.shields.io/github/stars/kn32/parallels-plist-escape.svg) ![forks](https://img.shields.io/github/forks/kn32/parallels-plist-escape.svg)


## CVE-2023-27327
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/kn32/parallels-plist-escape](https://github.com/kn32/parallels-plist-escape) :  ![starts](https://img.shields.io/github/stars/kn32/parallels-plist-escape.svg) ![forks](https://img.shields.io/github/forks/kn32/parallels-plist-escape.svg)


## CVE-2023-24932
 Secure Boot Security Feature Bypass Vulnerability

- [https://github.com/Wack0/CVE-2022-21894](https://github.com/Wack0/CVE-2022-21894) :  ![starts](https://img.shields.io/github/stars/Wack0/CVE-2022-21894.svg) ![forks](https://img.shields.io/github/forks/Wack0/CVE-2022-21894.svg)


## CVE-2023-0461
 There is a use-after-free vulnerability in the Linux Kernel which can be exploited to achieve local privilege escalation. To reach the vulnerability kernel configuration flag CONFIG_TLS or CONFIG_XFRM_ESPINTCP has to be configured, but the operation does not require any privilege. There is a use-after-free bug of icsk_ulp_data of a struct inet_connection_sock. When CONFIG_TLS is enabled, user can install a tls context (struct tls_context) on a connected tcp socket. The context is not cleared if this socket is disconnected and reused as a listener. If a new socket is created from the listener, the context is inherited and vulnerable. The setsockopt TCP_ULP operation does not require any privilege. We recommend upgrading past commit 2c02d41d71f90a5168391b6a5f2954112ba2307c

- [https://github.com/hshivhare67/kernel_v4.19.72_CVE-2023-0461](https://github.com/hshivhare67/kernel_v4.19.72_CVE-2023-0461) :  ![starts](https://img.shields.io/github/stars/hshivhare67/kernel_v4.19.72_CVE-2023-0461.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/kernel_v4.19.72_CVE-2023-0461.svg)


## CVE-2023-0386
 A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel&#8217;s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

- [https://github.com/hshivhare67/kernel_v4.19.72_CVE-2023-0386](https://github.com/hshivhare67/kernel_v4.19.72_CVE-2023-0386) :  ![starts](https://img.shields.io/github/stars/hshivhare67/kernel_v4.19.72_CVE-2023-0386.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/kernel_v4.19.72_CVE-2023-0386.svg)


## CVE-2022-0543
 It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.

- [https://github.com/SiennaSkies/redisHack](https://github.com/SiennaSkies/redisHack) :  ![starts](https://img.shields.io/github/stars/SiennaSkies/redisHack.svg) ![forks](https://img.shields.io/github/forks/SiennaSkies/redisHack.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)


## CVE-2021-26088
 An improper authentication vulnerability in FSSO Collector version 5.0.295 and below may allow an unauthenticated user to bypass a FSSO firewall policy and access the protected network via sending specifically crafted UDP login notification packets.

- [https://github.com/theogobinet/CVE-2021-26088](https://github.com/theogobinet/CVE-2021-26088) :  ![starts](https://img.shields.io/github/stars/theogobinet/CVE-2021-26088.svg) ![forks](https://img.shields.io/github/forks/theogobinet/CVE-2021-26088.svg)


## CVE-2020-25213
 The File Manager (wp-file-manager) plugin before 6.9 for WordPress allows remote attackers to upload and execute arbitrary PHP code because it renames an unsafe example elFinder connector file to have the .php extension. This, for example, allows attackers to run the elFinder upload (or mkfile and put) command to write PHP code into the wp-content/plugins/wp-file-manager/lib/files/ directory. This was exploited in the wild in August and September 2020.

- [https://github.com/forse01/CVE-2020-25213-Wordpress](https://github.com/forse01/CVE-2020-25213-Wordpress) :  ![starts](https://img.shields.io/github/stars/forse01/CVE-2020-25213-Wordpress.svg) ![forks](https://img.shields.io/github/forks/forse01/CVE-2020-25213-Wordpress.svg)


## CVE-2020-10204
 Sonatype Nexus Repository before 3.21.2 allows Remote Code Execution.

- [https://github.com/zhzyker/exphub](https://github.com/zhzyker/exphub) :  ![starts](https://img.shields.io/github/stars/zhzyker/exphub.svg) ![forks](https://img.shields.io/github/forks/zhzyker/exphub.svg)


## CVE-2020-1206
 An information disclosure vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Information Disclosure Vulnerability'.

- [https://github.com/jamf/CVE-2020-1206-POC](https://github.com/jamf/CVE-2020-1206-POC) :  ![starts](https://img.shields.io/github/stars/jamf/CVE-2020-1206-POC.svg) ![forks](https://img.shields.io/github/forks/jamf/CVE-2020-1206-POC.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/jamf/CVE-2020-0796-RCE-POC](https://github.com/jamf/CVE-2020-0796-RCE-POC) :  ![starts](https://img.shields.io/github/stars/jamf/CVE-2020-0796-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/jamf/CVE-2020-0796-RCE-POC.svg)
- [https://github.com/jamf/CVE-2020-0796-LPE-POC](https://github.com/jamf/CVE-2020-0796-LPE-POC) :  ![starts](https://img.shields.io/github/stars/jamf/CVE-2020-0796-LPE-POC.svg) ![forks](https://img.shields.io/github/forks/jamf/CVE-2020-0796-LPE-POC.svg)
- [https://github.com/jamf/SMBGhost-SMBleed-scanner](https://github.com/jamf/SMBGhost-SMBleed-scanner) :  ![starts](https://img.shields.io/github/stars/jamf/SMBGhost-SMBleed-scanner.svg) ![forks](https://img.shields.io/github/forks/jamf/SMBGhost-SMBleed-scanner.svg)


## CVE-2019-19194
 The Bluetooth Low Energy Secure Manager Protocol (SMP) implementation on Telink Semiconductor BLE SDK versions before November 2019 for TLSR8x5x through 3.4.0, TLSR823x through 1.3.0, and TLSR826x through 3.3 devices installs a zero long term key (LTK) if an out-of-order link-layer encryption request is received during Secure Connections pairing. An attacker in radio range can have arbitrary read/write access to protected GATT service data, cause a device crash, or possibly control a device's function by establishing an encrypted session with the zero LTK.

- [https://github.com/louisabricot/writeup-cve-2019-19194](https://github.com/louisabricot/writeup-cve-2019-19194) :  ![starts](https://img.shields.io/github/stars/louisabricot/writeup-cve-2019-19194.svg) ![forks](https://img.shields.io/github/forks/louisabricot/writeup-cve-2019-19194.svg)


## CVE-2018-15133
 In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.

- [https://github.com/0xSalle/cve-2018-15133](https://github.com/0xSalle/cve-2018-15133) :  ![starts](https://img.shields.io/github/stars/0xSalle/cve-2018-15133.svg) ![forks](https://img.shields.io/github/forks/0xSalle/cve-2018-15133.svg)


## CVE-2017-5941
 An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the unserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).

- [https://github.com/Cr4zyD14m0nd137/Lab-for-CVE-2017-5941](https://github.com/Cr4zyD14m0nd137/Lab-for-CVE-2017-5941) :  ![starts](https://img.shields.io/github/stars/Cr4zyD14m0nd137/Lab-for-CVE-2017-5941.svg) ![forks](https://img.shields.io/github/forks/Cr4zyD14m0nd137/Lab-for-CVE-2017-5941.svg)


## CVE-2008-5862
 Directory traversal vulnerability in webcamXP 5.3.2.375 and 5.3.2.410 build 2132 allows remote attackers to read arbitrary files via a ..%2F (encoded dot dot slash) in the URI.

- [https://github.com/K3ysTr0K3R/CVE-2008-5862-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2008-5862-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2008-5862-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2008-5862-EXPLOIT.svg)


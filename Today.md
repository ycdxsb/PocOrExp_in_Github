# Update 2024-11-16
## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present. Disabling follow_symlinks and using a reverse proxy are encouraged mitigations. Version 3.9.2 fixes this issue.

- [https://github.com/TheRedP4nther/LFI-aiohttp-CVE-2024-23334-PoC](https://github.com/TheRedP4nther/LFI-aiohttp-CVE-2024-23334-PoC) :  ![starts](https://img.shields.io/github/stars/TheRedP4nther/LFI-aiohttp-CVE-2024-23334-PoC.svg) ![forks](https://img.shields.io/github/forks/TheRedP4nther/LFI-aiohttp-CVE-2024-23334-PoC.svg)


## CVE-2024-5764
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/fin3ss3g0d/CVE-2024-5764](https://github.com/fin3ss3g0d/CVE-2024-5764) :  ![starts](https://img.shields.io/github/stars/fin3ss3g0d/CVE-2024-5764.svg) ![forks](https://img.shields.io/github/forks/fin3ss3g0d/CVE-2024-5764.svg)


## CVE-2024-5230
 A vulnerability has been found in EnvaySoft FleetCart up to 4.1.1 and classified as problematic. Affected by this vulnerability is an unknown functionality. The manipulation of the argument razorpayKeyId leads to information disclosure. The attack can be launched remotely. It is recommended to upgrade the affected component. The identifier VDB-265981 was assigned to this vulnerability.

- [https://github.com/d3sca/CVE-2024-52302](https://github.com/d3sca/CVE-2024-52302) :  ![starts](https://img.shields.io/github/stars/d3sca/CVE-2024-52302.svg) ![forks](https://img.shields.io/github/forks/d3sca/CVE-2024-52302.svg)
- [https://github.com/Nyamort/CVE-2024-52301](https://github.com/Nyamort/CVE-2024-52301) :  ![starts](https://img.shields.io/github/stars/Nyamort/CVE-2024-52301.svg) ![forks](https://img.shields.io/github/forks/Nyamort/CVE-2024-52301.svg)


## CVE-2024-4757
 The Logo Manager For Enamad WordPress plugin through 0.7.0 does not have CSRF check in some places, and is missing sanitisation as well as escaping, which could allow attackers to make logged in admin add Stored XSS payloads via a CSRF attack

- [https://github.com/watchtowrlabs/Fortijump-Exploit-CVE-2024-47575](https://github.com/watchtowrlabs/Fortijump-Exploit-CVE-2024-47575) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/Fortijump-Exploit-CVE-2024-47575.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/Fortijump-Exploit-CVE-2024-47575.svg)


## CVE-2024-4638
 OnCell G3470A-LTE Series firmware versions v1.7.7 and prior have been identified as vulnerable due to a lack of neutralized inputs in the web key upload function. An attacker could modify the intended commands sent to target functions, which could cause malicious users to execute unauthorized commands.

- [https://github.com/nitinronge91/Sensitive-Information-disclosure-via-SPI-flash-firmware-for-Hathway-router-CVE-2024-46383](https://github.com/nitinronge91/Sensitive-Information-disclosure-via-SPI-flash-firmware-for-Hathway-router-CVE-2024-46383) :  ![starts](https://img.shields.io/github/stars/nitinronge91/Sensitive-Information-disclosure-via-SPI-flash-firmware-for-Hathway-router-CVE-2024-46383.svg) ![forks](https://img.shields.io/github/forks/nitinronge91/Sensitive-Information-disclosure-via-SPI-flash-firmware-for-Hathway-router-CVE-2024-46383.svg)


## CVE-2024-4462
 The Nafeza Prayer Time plugin for WordPress is vulnerable to Stored Cross-Site Scripting via admin settings in all versions up to, and including, 1.2.9 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.

- [https://github.com/Fysac/CVE-2024-44625](https://github.com/Fysac/CVE-2024-44625) :  ![starts](https://img.shields.io/github/stars/Fysac/CVE-2024-44625.svg) ![forks](https://img.shields.io/github/forks/Fysac/CVE-2024-44625.svg)


## CVE-2024-1092
 The RSS Aggregator by Feedzy &#8211; Feed to Post, Autoblogging, News &amp; YouTube Video Feeds Aggregator plugin for WordPress is vulnerable to unauthorized data modification due to a missing capability check on the feedzy dashboard in all versions up to, and including, 4.4.1. This makes it possible for authenticated attackers, with contributor access or higher, to create, edit or delete feed categories created by them.

- [https://github.com/RandomRobbieBF/CVE-2024-10924](https://github.com/RandomRobbieBF/CVE-2024-10924) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-10924.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-10924.svg)


## CVE-2023-36424
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/zerozenxlabs/CVE-2023-36424](https://github.com/zerozenxlabs/CVE-2023-36424) :  ![starts](https://img.shields.io/github/stars/zerozenxlabs/CVE-2023-36424.svg) ![forks](https://img.shields.io/github/forks/zerozenxlabs/CVE-2023-36424.svg)


## CVE-2023-27997
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS version 7.2.4 and below, version 7.0.11 and below, version 6.4.12 and below, version 6.0.16 and below and FortiProxy version 7.2.3 and below, version 7.0.9 and below, version 2.0.12 and below, version 1.2 all versions, version 1.1 all versions SSL-VPN may allow a remote attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/node011/CVE-2023-27997-POC](https://github.com/node011/CVE-2023-27997-POC) :  ![starts](https://img.shields.io/github/stars/node011/CVE-2023-27997-POC.svg) ![forks](https://img.shields.io/github/forks/node011/CVE-2023-27997-POC.svg)


## CVE-2023-7261
 Inappropriate implementation in Google Updator prior to 1.3.36.351 in Google Chrome allowed a local attacker to perform privilege escalation via a malicious file. (Chromium security severity: High)

- [https://github.com/zerozenxlabs/CVE-2023-7261](https://github.com/zerozenxlabs/CVE-2023-7261) :  ![starts](https://img.shields.io/github/stars/zerozenxlabs/CVE-2023-7261.svg) ![forks](https://img.shields.io/github/forks/zerozenxlabs/CVE-2023-7261.svg)


## CVE-2022-20474
 In readLazyValue of Parcel.java, there is a possible loading of arbitrary code into the System Settings app due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-240138294

- [https://github.com/cxxsheng/CVE-2022-20474](https://github.com/cxxsheng/CVE-2022-20474) :  ![starts](https://img.shields.io/github/stars/cxxsheng/CVE-2022-20474.svg) ![forks](https://img.shields.io/github/forks/cxxsheng/CVE-2022-20474.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)


## CVE-2019-1653
 A vulnerability in the web-based management interface of Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an unauthenticated, remote attacker to retrieve sensitive information. The vulnerability is due to improper access controls for URLs. An attacker could exploit this vulnerability by connecting to an affected device via HTTP or HTTPS and requesting specific URLs. A successful exploit could allow the attacker to download the router configuration or detailed diagnostic information. Cisco has released firmware updates that address this vulnerability.

- [https://github.com/elzerjp/nuclei-CiscoRV320Dump-CVE-2019-1653](https://github.com/elzerjp/nuclei-CiscoRV320Dump-CVE-2019-1653) :  ![starts](https://img.shields.io/github/stars/elzerjp/nuclei-CiscoRV320Dump-CVE-2019-1653.svg) ![forks](https://img.shields.io/github/forks/elzerjp/nuclei-CiscoRV320Dump-CVE-2019-1653.svg)


## CVE-2018-25031
 Swagger UI before 4.1.3 could allow a remote attacker to conduct spoofing attacks. By persuading a victim to open a crafted URL, an attacker could exploit this vulnerability to display remote OpenAPI definitions.

- [https://github.com/KonEch0/CVE-2018-25031-SG](https://github.com/KonEch0/CVE-2018-25031-SG) :  ![starts](https://img.shields.io/github/stars/KonEch0/CVE-2018-25031-SG.svg) ![forks](https://img.shields.io/github/forks/KonEch0/CVE-2018-25031-SG.svg)


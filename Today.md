# Update 2024-12-11
## CVE-2024-24549
 Denial of Service due to improper input validation vulnerability for HTTP/2 requests in Apache Tomcat. When processing an HTTP/2 request, if the request exceeded any of the configured limits for headers, the associated HTTP/2 stream was not reset until after all of the headers had been processed.This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M16, from 10.1.0-M1 through 10.1.18, from 9.0.0-M1 through 9.0.85, from 8.5.0 through 8.5.98. Users are recommended to upgrade to version 11.0.0-M17, 10.1.19, 9.0.86 or 8.5.99 which fix the issue.

- [https://github.com/JFOZ1010/CVE-2024-24549](https://github.com/JFOZ1010/CVE-2024-24549) :  ![starts](https://img.shields.io/github/stars/JFOZ1010/CVE-2024-24549.svg) ![forks](https://img.shields.io/github/forks/JFOZ1010/CVE-2024-24549.svg)


## CVE-2024-23346
 Pymatgen (Python Materials Genomics) is an open-source Python library for materials analysis. A critical security vulnerability exists in the `JonesFaithfulTransformation.from_transformation_str()` method within the `pymatgen` library prior to version 2024.2.20. This method insecurely utilizes `eval()` for processing input, enabling execution of arbitrary code when parsing untrusted input. Version 2024.2.20 fixes this issue.

- [https://github.com/MAWK0235/CVE-2024-23346](https://github.com/MAWK0235/CVE-2024-23346) :  ![starts](https://img.shields.io/github/stars/MAWK0235/CVE-2024-23346.svg) ![forks](https://img.shields.io/github/forks/MAWK0235/CVE-2024-23346.svg)


## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present. Disabling follow_symlinks and using a reverse proxy are encouraged mitigations. Version 3.9.2 fixes this issue.

- [https://github.com/Betan423/CVE-2024-23334-PoC](https://github.com/Betan423/CVE-2024-23334-PoC) :  ![starts](https://img.shields.io/github/stars/Betan423/CVE-2024-23334-PoC.svg) ![forks](https://img.shields.io/github/forks/Betan423/CVE-2024-23334-PoC.svg)


## CVE-2024-4899
 The SEOPress WordPress plugin before 7.8 does not sanitise and escape some of its Post settings, which could allow high privilege users such as contributor to perform Stored Cross-Site Scripting attacks.

- [https://github.com/CyberCrowCC/CVE-2024-48990](https://github.com/CyberCrowCC/CVE-2024-48990) :  ![starts](https://img.shields.io/github/stars/CyberCrowCC/CVE-2024-48990.svg) ![forks](https://img.shields.io/github/forks/CyberCrowCC/CVE-2024-48990.svg)


## CVE-2024-1227
 An open redirect vulnerability, the exploitation of which could allow an attacker to create a custom URL and redirect a legitimate page to a malicious site.

- [https://github.com/RandomRobbieBF/CVE-2024-12270](https://github.com/RandomRobbieBF/CVE-2024-12270) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-12270.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-12270.svg)


## CVE-2024-1220
 A stack-based buffer overflow in the built-in web server in Moxa NPort W2150A/W2250A Series firmware version 2.3 and prior allows a remote attacker to exploit the vulnerability by sending crafted payload to the web service. Successful exploitation of the vulnerability could result in denial of service.

- [https://github.com/RandomRobbieBF/CVE-2024-12209](https://github.com/RandomRobbieBF/CVE-2024-12209) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-12209.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-12209.svg)


## CVE-2024-0044
 In createSessionInternal of PackageInstallerService.java, there is a possible run-as any app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Dit-Developers/CVE-2024-0044-](https://github.com/Dit-Developers/CVE-2024-0044-) :  ![starts](https://img.shields.io/github/stars/Dit-Developers/CVE-2024-0044-.svg) ![forks](https://img.shields.io/github/forks/Dit-Developers/CVE-2024-0044-.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)


## CVE-2021-21389
 BuddyPress is an open source WordPress plugin to build a community site. In releases of BuddyPress from 5.0.0 before 7.2.1 it's possible for a non-privileged, regular user to obtain administrator rights by exploiting an issue in the REST API members endpoint. The vulnerability has been fixed in BuddyPress 7.2.1. Existing installations of the plugin should be updated to this version to mitigate the issue.

- [https://github.com/mynameSumin/CVE-2021-21389](https://github.com/mynameSumin/CVE-2021-21389) :  ![starts](https://img.shields.io/github/stars/mynameSumin/CVE-2021-21389.svg) ![forks](https://img.shields.io/github/forks/mynameSumin/CVE-2021-21389.svg)


## CVE-2018-25031
 Swagger UI before 4.1.3 could allow a remote attacker to conduct spoofing attacks. By persuading a victim to open a crafted URL, an attacker could exploit this vulnerability to display remote OpenAPI definitions.

- [https://github.com/Proklinius897/CVE-2018-25031-tests](https://github.com/Proklinius897/CVE-2018-25031-tests) :  ![starts](https://img.shields.io/github/stars/Proklinius897/CVE-2018-25031-tests.svg) ![forks](https://img.shields.io/github/forks/Proklinius897/CVE-2018-25031-tests.svg)


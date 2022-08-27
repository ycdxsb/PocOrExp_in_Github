# Update 2022-08-27
## CVE-2022-37042
 Zimbra Collaboration Suite (ZCS) 8.8.15 and 9.0 has mboximport functionality that receives a ZIP archive and extracts files from it. By bypassing authentication (i.e., not having an authtoken), an attacker can upload arbitrary files to the system, leading to directory traversal and remote code execution. NOTE: this issue exists because of an incomplete fix for CVE-2022-27925.

- [https://github.com/aels/CVE-2022-37042](https://github.com/aels/CVE-2022-37042) :  ![starts](https://img.shields.io/github/stars/aels/CVE-2022-37042.svg) ![forks](https://img.shields.io/github/forks/aels/CVE-2022-37042.svg)


## CVE-2022-21371
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Web Container). Supported versions that are affected are 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/Vulnmachines/Oracle-WebLogic-CVE-2022-21371](https://github.com/Vulnmachines/Oracle-WebLogic-CVE-2022-21371) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/Oracle-WebLogic-CVE-2022-21371.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/Oracle-WebLogic-CVE-2022-21371.svg)


## CVE-2021-25642
 ZKConfigurationStore which is optionally used by CapacityScheduler of Apache Hadoop YARN deserializes data obtained from ZooKeeper without validation. An attacker having access to ZooKeeper can run arbitrary commands as YARN user by exploiting this. Users should upgrade to Apache Hadoop 2.10.2, 3.2.4, 3.3.4 or later (containing YARN-11126) if ZKConfigurationStore is used.

- [https://github.com/safe3s/CVE-2021-25642](https://github.com/safe3s/CVE-2021-25642) :  ![starts](https://img.shields.io/github/stars/safe3s/CVE-2021-25642.svg) ![forks](https://img.shields.io/github/forks/safe3s/CVE-2021-25642.svg)


## CVE-2020-35669
 An issue was discovered in the http package through 0.12.2 for Dart. If the attacker controls the HTTP method and the app is using Request directly, it's possible to achieve CRLF injection in an HTTP request.

- [https://github.com/n0npax/CVE-2020-35669](https://github.com/n0npax/CVE-2020-35669) :  ![starts](https://img.shields.io/github/stars/n0npax/CVE-2020-35669.svg) ![forks](https://img.shields.io/github/forks/n0npax/CVE-2020-35669.svg)


## CVE-2020-0416
 In multiple settings screens, there are possible tapjacking attacks due to an insecure default value. This could lead to local escalation of privilege and permissions with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-9 Android-10 Android-11 Android-8.0 Android-8.1Android ID: A-155288585

- [https://github.com/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2020-0416](https://github.com/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2020-0416) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2020-0416.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/packages_apps_Settings_AOSP10_r33_CVE-2020-0416.svg)


## CVE-2019-16763
 In Pannellum from 2.5.0 through 2.5.4 URLs were not sanitized for data URIs (or vbscript:), allowing for potential XSS attacks. Such an attack would require a user to click on a hot spot to execute and would require an attacker-provided configuration. The most plausible potential attack would be if pannellum.htm was hosted on a domain that shared cookies with the targeted site's user authentication; an &amp;lt;iframe&amp;gt; could then be embedded on the attacker's site using pannellum.htm from the targeted site, which would allow the attacker to potentially access information from the targeted site as the authenticated user (or worse if the targeted site did not have adequate CSRF protections) if the user clicked on a hot spot in the attacker's embedded panorama viewer. This was patched in version 2.5.5.

- [https://github.com/ossf-cve-benchmark/CVE-2019-16763](https://github.com/ossf-cve-benchmark/CVE-2019-16763) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2019-16763.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2019-16763.svg)


## CVE-2019-5418
 There is a File Content Disclosure vulnerability in Action View &lt;5.2.2.1, &lt;5.1.6.2, &lt;5.0.7.2, &lt;4.2.11.1 and v3 where specially crafted accept headers can cause contents of arbitrary files on the target system's filesystem to be exposed.

- [https://github.com/NotoriousRebel/RailRoadBandit](https://github.com/NotoriousRebel/RailRoadBandit) :  ![starts](https://img.shields.io/github/stars/NotoriousRebel/RailRoadBandit.svg) ![forks](https://img.shields.io/github/forks/NotoriousRebel/RailRoadBandit.svg)


## CVE-2017-9097
 In Anti-Web through 3.8.7, as used on NetBiter FGW200 devices through 3.21.2, WS100 devices through 3.30.5, EC150 devices through 1.40.0, WS200 devices through 3.30.4, EC250 devices through 1.40.0, and other products, an LFI vulnerability allows a remote attacker to read or modify files through a path traversal technique, as demonstrated by reading the password file, or using the template parameter to cgi-bin/write.cgi to write to an arbitrary file.

- [https://github.com/MDudek-ICS/AntiWeb_testing-Suite](https://github.com/MDudek-ICS/AntiWeb_testing-Suite) :  ![starts](https://img.shields.io/github/stars/MDudek-ICS/AntiWeb_testing-Suite.svg) ![forks](https://img.shields.io/github/forks/MDudek-ICS/AntiWeb_testing-Suite.svg)


## CVE-2008-0166
 OpenSSL 0.9.8c-1 up to versions before 0.9.8g-9 on Debian-based operating systems uses a random number generator that generates predictable numbers, which makes it easier for remote attackers to conduct brute force guessing attacks against cryptographic keys.

- [https://github.com/demining/Vulnerable-to-Debian-OpenSSL-bug-CVE-2008-0166](https://github.com/demining/Vulnerable-to-Debian-OpenSSL-bug-CVE-2008-0166) :  ![starts](https://img.shields.io/github/stars/demining/Vulnerable-to-Debian-OpenSSL-bug-CVE-2008-0166.svg) ![forks](https://img.shields.io/github/forks/demining/Vulnerable-to-Debian-OpenSSL-bug-CVE-2008-0166.svg)


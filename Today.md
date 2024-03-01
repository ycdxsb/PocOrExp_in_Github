# Update 2024-03-01
## CVE-2024-25600
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/gobysec/Goby](https://github.com/gobysec/Goby) :  ![starts](https://img.shields.io/github/stars/gobysec/Goby.svg) ![forks](https://img.shields.io/github/forks/gobysec/Goby.svg)
- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)
- [https://github.com/peiqiF4ck/WebFrameworkTools-5.1-main](https://github.com/peiqiF4ck/WebFrameworkTools-5.1-main) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.1-main.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.1-main.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/gobysec/Goby](https://github.com/gobysec/Goby) :  ![starts](https://img.shields.io/github/stars/gobysec/Goby.svg) ![forks](https://img.shields.io/github/forks/gobysec/Goby.svg)
- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)


## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present. Disabling follow_symlinks and using a reverse proxy are encouraged mitigations. Version 3.9.2 fixes this issue.

- [https://github.com/ox1111/CVE-2024-23334](https://github.com/ox1111/CVE-2024-23334) :  ![starts](https://img.shields.io/github/stars/ox1111/CVE-2024-23334.svg) ![forks](https://img.shields.io/github/forks/ox1111/CVE-2024-23334.svg)


## CVE-2024-21893
 A server-side request forgery vulnerability in the SAML component of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure (9.x, 22.x) and Ivanti Neurons for ZTA allows an attacker to access certain restricted resources without authentication.

- [https://github.com/gobysec/Goby](https://github.com/gobysec/Goby) :  ![starts](https://img.shields.io/github/stars/gobysec/Goby.svg) ![forks](https://img.shields.io/github/forks/gobysec/Goby.svg)
- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)


## CVE-2024-21887
 A command injection vulnerability in web components of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure (9.x, 22.x) allows an authenticated administrator to send specially crafted requests and execute arbitrary commands on the appliance.

- [https://github.com/gobysec/Goby](https://github.com/gobysec/Goby) :  ![starts](https://img.shields.io/github/stars/gobysec/Goby.svg) ![forks](https://img.shields.io/github/forks/gobysec/Goby.svg)
- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)


## CVE-2024-21762
 A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, 2.0.0 through 2.0.13, 1.2.0 through 1.2.13, 1.1.0 through 1.1.6, 1.0.0 through 1.0.7 allows attacker to execute unauthorized code or commands via specifically crafted requests

- [https://github.com/c0d3b3af/CVE-2024-21762-POC](https://github.com/c0d3b3af/CVE-2024-21762-POC) :  ![starts](https://img.shields.io/github/stars/c0d3b3af/CVE-2024-21762-POC.svg) ![forks](https://img.shields.io/github/forks/c0d3b3af/CVE-2024-21762-POC.svg)


## CVE-2024-21413
 Microsoft Outlook Remote Code Execution Vulnerability

- [https://github.com/DevAkabari/CVE-2024-21413](https://github.com/DevAkabari/CVE-2024-21413) :  ![starts](https://img.shields.io/github/stars/DevAkabari/CVE-2024-21413.svg) ![forks](https://img.shields.io/github/forks/DevAkabari/CVE-2024-21413.svg)


## CVE-2024-20931
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/gobysec/Goby](https://github.com/gobysec/Goby) :  ![starts](https://img.shields.io/github/stars/gobysec/Goby.svg) ![forks](https://img.shields.io/github/forks/gobysec/Goby.svg)
- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)


## CVE-2024-0204
 Authentication bypass in Fortra's GoAnywhere MFT prior to 7.4.1 allows an unauthorized user to create an admin user via the administration portal.

- [https://github.com/gobysec/Goby](https://github.com/gobysec/Goby) :  ![starts](https://img.shields.io/github/stars/gobysec/Goby.svg) ![forks](https://img.shields.io/github/forks/gobysec/Goby.svg)
- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)


## CVE-2023-51467
 The vulnerability permits attackers to circumvent authentication processes, enabling them to remotely execute arbitrary code

- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)


## CVE-2023-43757
 Inadequate encryption strength vulnerability in multiple routers provided by ELECOM CO.,LTD. and LOGITEC CORPORATION allows a network-adjacent unauthenticated attacker to guess the encryption key used for wireless LAN communication and intercept the communication. As for the affected products/versions, see the information provided by the vendor under [References] section.

- [https://github.com/sharmashreejaa/CVE-2023-43757](https://github.com/sharmashreejaa/CVE-2023-43757) :  ![starts](https://img.shields.io/github/stars/sharmashreejaa/CVE-2023-43757.svg) ![forks](https://img.shields.io/github/forks/sharmashreejaa/CVE-2023-43757.svg)


## CVE-2023-42820
 JumpServer is an open source bastion host. This vulnerability is due to exposing the random number seed to the API, potentially allowing the randomly generated verification codes to be replayed, which could lead to password resets. If MFA is enabled users are not affect. Users not using local authentication are also not affected. Users are advised to upgrade to either version 2.28.19 or to 3.6.5. There are no known workarounds or this issue.

- [https://github.com/tarihub/blackjump](https://github.com/tarihub/blackjump) :  ![starts](https://img.shields.io/github/stars/tarihub/blackjump.svg) ![forks](https://img.shields.io/github/forks/tarihub/blackjump.svg)


## CVE-2023-42442
 JumpServer is an open source bastion host and a professional operation and maintenance security audit system. Starting in version 3.0.0 and prior to versions 3.5.5 and 3.6.4, session replays can download without authentication. Session replays stored in S3, OSS, or other cloud storage are not affected. The api `/api/v1/terminal/sessions/` permission control is broken and can be accessed anonymously. SessionViewSet permission classes set to `[RBACPermission | IsSessionAssignee]`, relation is or, so any permission matched will be allowed. Versions 3.5.5 and 3.6.4 have a fix. After upgrading, visit the api `$HOST/api/v1/terminal/sessions/?limit=1`. The expected http response code is 401 (`not_authenticated`).

- [https://github.com/tarihub/blackjump](https://github.com/tarihub/blackjump) :  ![starts](https://img.shields.io/github/stars/tarihub/blackjump.svg) ![forks](https://img.shields.io/github/forks/tarihub/blackjump.svg)


## CVE-2023-41993
 The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14. Processing web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 16.7.

- [https://github.com/J3Ss0u/CVE-2023-41993](https://github.com/J3Ss0u/CVE-2023-41993) :  ![starts](https://img.shields.io/github/stars/J3Ss0u/CVE-2023-41993.svg) ![forks](https://img.shields.io/github/forks/J3Ss0u/CVE-2023-41993.svg)


## CVE-2023-40000
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/rxerium/CVE-2023-40000](https://github.com/rxerium/CVE-2023-40000) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2023-40000.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2023-40000.svg)


## CVE-2023-39362
 Cacti is an open source operational monitoring and fault management framework. In Cacti 1.2.24, under certain conditions, an authenticated privileged user, can use a malicious string in the SNMP options of a Device, performing command injection and obtaining remote code execution on the underlying server. The `lib/snmp.php` file has a set of functions, with similar behavior, that accept in input some variables and place them into an `exec` call without a proper escape or validation. This issue has been addressed in version 1.2.25. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/jakabakos/CVE-2023-39362-cacti-snmp-command-injection-poc](https://github.com/jakabakos/CVE-2023-39362-cacti-snmp-command-injection-poc) :  ![starts](https://img.shields.io/github/stars/jakabakos/CVE-2023-39362-cacti-snmp-command-injection-poc.svg) ![forks](https://img.shields.io/github/forks/jakabakos/CVE-2023-39362-cacti-snmp-command-injection-poc.svg)


## CVE-2023-36407
 Windows Hyper-V Elevation of Privilege Vulnerability

- [https://github.com/pwndorei/CVE-2023-36407](https://github.com/pwndorei/CVE-2023-36407) :  ![starts](https://img.shields.io/github/stars/pwndorei/CVE-2023-36407.svg) ![forks](https://img.shields.io/github/forks/pwndorei/CVE-2023-36407.svg)


## CVE-2023-22527
 A template injection vulnerability on older versions of Confluence Data Center and Server allows an unauthenticated attacker to achieve RCE on an affected instance. Customers using an affected version must take immediate action. Most recent supported versions of Confluence Data Center and Server are not affected by this vulnerability as it was ultimately mitigated during regular version updates. However, Atlassian recommends that customers take care to install the latest version to protect their instances from non-critical vulnerabilities outlined in Atlassian&#8217;s January Security Bulletin.

- [https://github.com/gobysec/Goby](https://github.com/gobysec/Goby) :  ![starts](https://img.shields.io/github/stars/gobysec/Goby.svg) ![forks](https://img.shields.io/github/forks/gobysec/Goby.svg)
- [https://github.com/gobysec/GobyVuls](https://github.com/gobysec/GobyVuls) :  ![starts](https://img.shields.io/github/stars/gobysec/GobyVuls.svg) ![forks](https://img.shields.io/github/forks/gobysec/GobyVuls.svg)


## CVE-2023-21144
 In doInBackground of NotificationContentInflater.java, there is a possible temporary denial or service due to long running operations. This could lead to remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-12 Android-12L Android-13Android ID: A-252766417

- [https://github.com/hshivhare67/Framework_base_AOSP10_r33_CVE-2023-21144_old](https://github.com/hshivhare67/Framework_base_AOSP10_r33_CVE-2023-21144_old) :  ![starts](https://img.shields.io/github/stars/hshivhare67/Framework_base_AOSP10_r33_CVE-2023-21144_old.svg) ![forks](https://img.shields.io/github/forks/hshivhare67/Framework_base_AOSP10_r33_CVE-2023-21144_old.svg)


## CVE-2022-44875
 KioWare through 8.33 on Windows sets KioScriptingUrlACL.AclActions.AllowHigh for the about:blank origin, which allows attackers to obtain SYSTEM access via KioUtils.Execute in JavaScript code.

- [https://github.com/AesirSec/CVE-2022-44875-Test](https://github.com/AesirSec/CVE-2022-44875-Test) :  ![starts](https://img.shields.io/github/stars/AesirSec/CVE-2022-44875-Test.svg) ![forks](https://img.shields.io/github/forks/AesirSec/CVE-2022-44875-Test.svg)


## CVE-2020-35489
 The contact-form-7 (aka Contact Form 7) plugin before 5.3.2 for WordPress allows Unrestricted File Upload and remote code execution because a filename may contain special characters.

- [https://github.com/thebunjo/CVE-2020-35489](https://github.com/thebunjo/CVE-2020-35489) :  ![starts](https://img.shields.io/github/stars/thebunjo/CVE-2020-35489.svg) ![forks](https://img.shields.io/github/forks/thebunjo/CVE-2020-35489.svg)


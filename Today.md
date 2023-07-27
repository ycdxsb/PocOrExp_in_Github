# Update 2023-07-27
## CVE-2023-37623
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/benjaminpsinclair/Netdisco-CVE-2023-37623](https://github.com/benjaminpsinclair/Netdisco-CVE-2023-37623) :  ![starts](https://img.shields.io/github/stars/benjaminpsinclair/Netdisco-CVE-2023-37623.svg) ![forks](https://img.shields.io/github/forks/benjaminpsinclair/Netdisco-CVE-2023-37623.svg)


## CVE-2023-35801
 A directory traversal vulnerability in Safe Software FME Server before 2022.2.5 allows an attacker to bypass validation when editing a network-based resource connection, resulting in the unauthorized reading and writing of arbitrary files. Successful exploitation requires an attacker to have access to a user account with write privileges. FME Flow 2023.0 is also a fixed version.

- [https://github.com/trustcves/CVE-2023-35801](https://github.com/trustcves/CVE-2023-35801) :  ![starts](https://img.shields.io/github/stars/trustcves/CVE-2023-35801.svg) ![forks](https://img.shields.io/github/forks/trustcves/CVE-2023-35801.svg)


## CVE-2023-34960
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/hheeyywweellccoommee/Chamilo__CVE-2023-34960_RCE-ouvuu](https://github.com/hheeyywweellccoommee/Chamilo__CVE-2023-34960_RCE-ouvuu) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/Chamilo__CVE-2023-34960_RCE-ouvuu.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/Chamilo__CVE-2023-34960_RCE-ouvuu.svg)


## CVE-2023-27587
 ReadtoMyShoe, a web app that lets users upload articles and listen to them later, generates an error message containing sensitive information prior to commit 8533b01. If an error occurs when adding an article, the website shows the user an error message. If the error originates from the Google Cloud TTS request, then it will include the full URL of the request. The request URL contains the Google Cloud API key. This has been patched in commit 8533b01. Upgrading should be accompanied by deleting the current GCP API key and issuing a new one. There are no known workarounds.

- [https://github.com/vagnerd/CVE-2023-27587-PoC](https://github.com/vagnerd/CVE-2023-27587-PoC) :  ![starts](https://img.shields.io/github/stars/vagnerd/CVE-2023-27587-PoC.svg) ![forks](https://img.shields.io/github/forks/vagnerd/CVE-2023-27587-PoC.svg)


## CVE-2023-24489
 A vulnerability has been discovered in the customer-managed ShareFile storage zones controller which, if exploited, could allow an unauthenticated attacker to remotely compromise the customer-managed ShareFile storage zones controller.

- [https://github.com/codeb0ss/CVE-2023-24489-PoC](https://github.com/codeb0ss/CVE-2023-24489-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2023-24489-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2023-24489-PoC.svg)


## CVE-2023-2986
 The Abandoned Cart Lite for WooCommerce plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 5.14.2. This is due to insufficient encryption on the user being supplied during the abandoned cart link decode through the plugin. This allows unauthenticated attackers to log in as users who have abandoned the cart, who are typically customers. Further security hardening was introduced in version 5.15.1 that ensures sites are no longer vulnerable through historical check-out links, and additional hardening was introduced in version 5.15.2 that ensured null key values wouldn't permit the authentication bypass.

- [https://github.com/Ayantaker/CVE-2023-2986](https://github.com/Ayantaker/CVE-2023-2986) :  ![starts](https://img.shields.io/github/stars/Ayantaker/CVE-2023-2986.svg) ![forks](https://img.shields.io/github/forks/Ayantaker/CVE-2023-2986.svg)


## CVE-2023-2636
 The AN_GradeBook WordPress plugin through 5.0.1 does not properly sanitise and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by users with a role as low as subscriber

- [https://github.com/lukinneberg/CVE-2023-2636](https://github.com/lukinneberg/CVE-2023-2636) :  ![starts](https://img.shields.io/github/stars/lukinneberg/CVE-2023-2636.svg) ![forks](https://img.shields.io/github/forks/lukinneberg/CVE-2023-2636.svg)


## CVE-2023-1454
 A vulnerability classified as critical has been found in jeecg-boot 3.5.0. This affects an unknown part of the file jmreport/qurestSql. The manipulation of the argument apiSelectId leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-223299.

- [https://github.com/cjybao/CVE-2023-1454](https://github.com/cjybao/CVE-2023-1454) :  ![starts](https://img.shields.io/github/stars/cjybao/CVE-2023-1454.svg) ![forks](https://img.shields.io/github/forks/cjybao/CVE-2023-1454.svg)


## CVE-2022-41114
 Windows Bind Filter Driver Elevation of Privilege Vulnerability

- [https://github.com/gmh5225/CVE-2022-41114](https://github.com/gmh5225/CVE-2022-41114) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2022-41114.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2022-41114.svg)


## CVE-2022-30190
 Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

- [https://github.com/yrkuo/CVE-2022-30190](https://github.com/yrkuo/CVE-2022-30190) :  ![starts](https://img.shields.io/github/stars/yrkuo/CVE-2022-30190.svg) ![forks](https://img.shields.io/github/forks/yrkuo/CVE-2022-30190.svg)


## CVE-2022-23305
 By design, the JDBCAppender in Log4j 1.2.x accepts an SQL statement as a configuration parameter where the values to be inserted are converters from PatternLayout. The message converter, %m, is likely to always be included. This allows attackers to manipulate the SQL by entering crafted strings into input fields or headers of an application that are logged allowing unintended SQL queries to be executed. Note this issue only affects Log4j 1.x when specifically configured to use the JDBCAppender, which is not the default. Beginning in version 2.0-beta8, the JDBCAppender was re-introduced with proper support for parameterized SQL queries and further customization over the columns written to in logs. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/tkomlodi/CVE-2022-23305_POC](https://github.com/tkomlodi/CVE-2022-23305_POC) :  ![starts](https://img.shields.io/github/stars/tkomlodi/CVE-2022-23305_POC.svg) ![forks](https://img.shields.io/github/forks/tkomlodi/CVE-2022-23305_POC.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/G01d3nW01f/CVE-2022-22963](https://github.com/G01d3nW01f/CVE-2022-22963) :  ![starts](https://img.shields.io/github/stars/G01d3nW01f/CVE-2022-22963.svg) ![forks](https://img.shields.io/github/forks/G01d3nW01f/CVE-2022-22963.svg)


## CVE-2022-0739
 The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied POST data before it is used in a dynamically constructed SQL query via the bookingpress_front_get_category_services AJAX action (available to unauthenticated users), leading to an unauthenticated SQL Injection

- [https://github.com/G01d3nW01f/CVE-2022-0739](https://github.com/G01d3nW01f/CVE-2022-0739) :  ![starts](https://img.shields.io/github/stars/G01d3nW01f/CVE-2022-0739.svg) ![forks](https://img.shields.io/github/forks/G01d3nW01f/CVE-2022-0739.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/G01d3nW01f/CVE-2021-43798](https://github.com/G01d3nW01f/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/G01d3nW01f/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/G01d3nW01f/CVE-2021-43798.svg)


## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.

- [https://github.com/G01d3nW01f/CVE-2021-29447](https://github.com/G01d3nW01f/CVE-2021-29447) :  ![starts](https://img.shields.io/github/stars/G01d3nW01f/CVE-2021-29447.svg) ![forks](https://img.shields.io/github/forks/G01d3nW01f/CVE-2021-29447.svg)


## CVE-2021-28378
 Gitea 1.12.x and 1.13.x before 1.13.4 allows XSS via certain issue data in some situations.

- [https://github.com/pandatix/CVE-2021-28378](https://github.com/pandatix/CVE-2021-28378) :  ![starts](https://img.shields.io/github/stars/pandatix/CVE-2021-28378.svg) ![forks](https://img.shields.io/github/forks/pandatix/CVE-2021-28378.svg)


## CVE-2021-21315
 The System Information Library for Node.JS (npm package &quot;systeminformation&quot;) is an open source collection of functions to retrieve detailed hardware, system and OS information. In systeminformation before version 5.3.1 there is a command injection vulnerability. Problem was fixed in version 5.3.1. As a workaround instead of upgrading, be sure to check or sanitize service parameters that are passed to si.inetLatency(), si.inetChecksite(), si.services(), si.processLoad() ... do only allow strings, reject any arrays. String sanitation works as expected.

- [https://github.com/G01d3nW01f/CVE-2021-21315](https://github.com/G01d3nW01f/CVE-2021-21315) :  ![starts](https://img.shields.io/github/stars/G01d3nW01f/CVE-2021-21315.svg) ![forks](https://img.shields.io/github/forks/G01d3nW01f/CVE-2021-21315.svg)


## CVE-2021-3449
 An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL pointer dereference will result, leading to a crash and a denial of service attack. A server is only vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j).

- [https://github.com/terorie/cve-2021-3449](https://github.com/terorie/cve-2021-3449) :  ![starts](https://img.shields.io/github/stars/terorie/cve-2021-3449.svg) ![forks](https://img.shields.io/github/forks/terorie/cve-2021-3449.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/miko550/CVE-2021-3129](https://github.com/miko550/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/miko550/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/miko550/CVE-2021-3129.svg)


## CVE-2020-29607
 A file upload restriction bypass vulnerability in Pluck CMS before 4.7.13 allows an admin privileged user to gain access in the host through the &quot;manage files&quot; functionality, which may result in remote code execution.

- [https://github.com/0xAbbarhSF/CVE-2020-29607](https://github.com/0xAbbarhSF/CVE-2020-29607) :  ![starts](https://img.shields.io/github/stars/0xAbbarhSF/CVE-2020-29607.svg) ![forks](https://img.shields.io/github/forks/0xAbbarhSF/CVE-2020-29607.svg)


## CVE-2020-23160
 Remote code execution in Pyrescom Termod4 time management devices before 10.04k allows authenticated remote attackers to arbitrary commands as root on the devices.

- [https://github.com/Outpost24/Pyrescom-Termod-PoC](https://github.com/Outpost24/Pyrescom-Termod-PoC) :  ![starts](https://img.shields.io/github/stars/Outpost24/Pyrescom-Termod-PoC.svg) ![forks](https://img.shields.io/github/forks/Outpost24/Pyrescom-Termod-PoC.svg)


## CVE-2020-21224
 A Remote Code Execution vulnerability has been found in Inspur ClusterEngine V4.0. A remote attacker can send a malicious login packet to the control server

- [https://github.com/5l1v3r1/CVE-2020-21224](https://github.com/5l1v3r1/CVE-2020-21224) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-21224.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-21224.svg)


## CVE-2020-8644
 PlaySMS before 1.4.3 does not sanitize inputs from a malicious string.

- [https://github.com/H3rm1tR3b0rn/CVE-2020-8644-PlaySMS-1.4](https://github.com/H3rm1tR3b0rn/CVE-2020-8644-PlaySMS-1.4) :  ![starts](https://img.shields.io/github/stars/H3rm1tR3b0rn/CVE-2020-8644-PlaySMS-1.4.svg) ![forks](https://img.shields.io/github/forks/H3rm1tR3b0rn/CVE-2020-8644-PlaySMS-1.4.svg)
- [https://github.com/hheeyywweellccoommee/CVE-2020-8644-PlaySMS-1.4-rlvpp](https://github.com/hheeyywweellccoommee/CVE-2020-8644-PlaySMS-1.4-rlvpp) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/CVE-2020-8644-PlaySMS-1.4-rlvpp.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/CVE-2020-8644-PlaySMS-1.4-rlvpp.svg)


## CVE-2020-2883
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/ZZZWD/CVE-2020-2883](https://github.com/ZZZWD/CVE-2020-2883) :  ![starts](https://img.shields.io/github/stars/ZZZWD/CVE-2020-2883.svg) ![forks](https://img.shields.io/github/forks/ZZZWD/CVE-2020-2883.svg)


## CVE-2020-2553
 Vulnerability in the Oracle Knowledge product of Oracle Knowledge (component: Information Manager Console). Supported versions that are affected are 8.6.0-8.6.3. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Knowledge. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Knowledge accessible data as well as unauthorized read access to a subset of Oracle Knowledge accessible data. CVSS 3.0 Base Score 4.8 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).

- [https://github.com/5l1v3r1/CVE-2020-2553](https://github.com/5l1v3r1/CVE-2020-2553) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-2553.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-2553.svg)


## CVE-2020-2551
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/0xAbbarhSF/CVE-Exploit](https://github.com/0xAbbarhSF/CVE-Exploit) :  ![starts](https://img.shields.io/github/stars/0xAbbarhSF/CVE-Exploit.svg) ![forks](https://img.shields.io/github/forks/0xAbbarhSF/CVE-Exploit.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/cube0x0/CVE-2020-1472](https://github.com/cube0x0/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/cube0x0/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/cube0x0/CVE-2020-1472.svg)
- [https://github.com/sv3nbeast/CVE-2020-1472](https://github.com/sv3nbeast/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/sv3nbeast/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/sv3nbeast/CVE-2020-1472.svg)
- [https://github.com/CanciuCostin/CVE-2020-1472](https://github.com/CanciuCostin/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/CanciuCostin/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/CanciuCostin/CVE-2020-1472.svg)
- [https://github.com/Sajuwithgithub/CVE2020-1472](https://github.com/Sajuwithgithub/CVE2020-1472) :  ![starts](https://img.shields.io/github/stars/Sajuwithgithub/CVE2020-1472.svg) ![forks](https://img.shields.io/github/forks/Sajuwithgithub/CVE2020-1472.svg)
- [https://github.com/midpipps/CVE-2020-1472-Easy](https://github.com/midpipps/CVE-2020-1472-Easy) :  ![starts](https://img.shields.io/github/stars/midpipps/CVE-2020-1472-Easy.svg) ![forks](https://img.shields.io/github/forks/midpipps/CVE-2020-1472-Easy.svg)
- [https://github.com/Whippet0/CVE-2020-1472](https://github.com/Whippet0/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/Whippet0/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/Whippet0/CVE-2020-1472.svg)
- [https://github.com/TheJoyOfHacking/dirkjanm-CVE-2020-1472](https://github.com/TheJoyOfHacking/dirkjanm-CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/TheJoyOfHacking/dirkjanm-CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/TheJoyOfHacking/dirkjanm-CVE-2020-1472.svg)


## CVE-2020-1066
 An elevation of privilege vulnerability exists in .NET Framework which could allow an attacker to elevate their privilege level.To exploit the vulnerability, an attacker would first have to access the local machine, and then run a malicious program.The update addresses the vulnerability by correcting how .NET Framework activates COM objects., aka '.NET Framework Elevation of Privilege Vulnerability'.

- [https://github.com/cbwang505/CVE-2020-1066-EXP](https://github.com/cbwang505/CVE-2020-1066-EXP) :  ![starts](https://img.shields.io/github/stars/cbwang505/CVE-2020-1066-EXP.svg) ![forks](https://img.shields.io/github/forks/cbwang505/CVE-2020-1066-EXP.svg)


## CVE-2020-1054
 An elevation of privilege vulnerability exists in Windows when the Windows kernel-mode driver fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1143.

- [https://github.com/KaLendsi/CVE-2020-1054](https://github.com/KaLendsi/CVE-2020-1054) :  ![starts](https://img.shields.io/github/stars/KaLendsi/CVE-2020-1054.svg) ![forks](https://img.shields.io/github/forks/KaLendsi/CVE-2020-1054.svg)


## CVE-2019-19782
 The FTP client in AceaXe Plus 1.0 allows a buffer overflow via a long EHLO response from an FTP server.

- [https://github.com/Underwood12/CVE-2019-19782](https://github.com/Underwood12/CVE-2019-19782) :  ![starts](https://img.shields.io/github/stars/Underwood12/CVE-2019-19782.svg) ![forks](https://img.shields.io/github/forks/Underwood12/CVE-2019-19782.svg)


## CVE-2006-6184
 Multiple stack-based buffer overflows in Allied Telesyn TFTP Server (AT-TFTP) 1.9, and possibly earlier, allow remote attackers to cause a denial of service (crash) or execute arbitrary code via a long filename in a (1) GET or (2) PUT command.

- [https://github.com/shauntdergrigorian/cve-2006-6184](https://github.com/shauntdergrigorian/cve-2006-6184) :  ![starts](https://img.shields.io/github/stars/shauntdergrigorian/cve-2006-6184.svg) ![forks](https://img.shields.io/github/forks/shauntdergrigorian/cve-2006-6184.svg)


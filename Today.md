# Update 2023-03-28
## CVE-2023-28858
 redis-py before 4.5.3, as used in ChatGPT and other products, leaves a connection open after canceling an async Redis command at an inopportune time (in the case of a pipeline operation), and can send response data to the client of an unrelated request in an off-by-one manner. The fixed versions for this CVE Record are 4.3.6, 4.4.3, and 4.5.3; however, CVE-2023-28859 is a separate vulnerability.

- [https://github.com/improbably-you/poc_cve_2023_28858](https://github.com/improbably-you/poc_cve_2023_28858) :  ![starts](https://img.shields.io/github/stars/improbably-you/poc_cve_2023_28858.svg) ![forks](https://img.shields.io/github/forks/improbably-you/poc_cve_2023_28858.svg)


## CVE-2023-28432
 Minio is a Multi-Cloud Object Storage framework. In a cluster deployment starting with RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns all environment variables, including `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`, resulting in information disclosure. All users of distributed deployment are impacted. All users are advised to upgrade to RELEASE.2023-03-20T20-16-18Z.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.1-main](https://github.com/peiqiF4ck/WebFrameworkTools-5.1-main) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.1-main.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.1-main.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/0xNahim/CVE-2023-23752](https://github.com/0xNahim/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/0xNahim/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/0xNahim/CVE-2023-23752.svg)


## CVE-2022-47909
 Livestatus Query Language (LQL) injection in the AuthUser HTTP query header of Tribe29's Checkmk &lt;= 2.1.0p11, Checkmk &lt;= 2.0.0p28, and all versions of Checkmk 1.6.0 (EOL) allows an attacker to perform direct queries to the application's core from localhost.

- [https://github.com/JacobEbben/CVE-2022-47909_unauth_arbitrary_file_deletion](https://github.com/JacobEbben/CVE-2022-47909_unauth_arbitrary_file_deletion) :  ![starts](https://img.shields.io/github/stars/JacobEbben/CVE-2022-47909_unauth_arbitrary_file_deletion.svg) ![forks](https://img.shields.io/github/forks/JacobEbben/CVE-2022-47909_unauth_arbitrary_file_deletion.svg)


## CVE-2022-40494
 NPS before v0.26.10 was discovered to contain an authentication bypass vulnerability via constantly generating and sending the Auth key and Timestamp parameters.

- [https://github.com/carr0t2/nps-auth-bypass](https://github.com/carr0t2/nps-auth-bypass) :  ![starts](https://img.shields.io/github/stars/carr0t2/nps-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/carr0t2/nps-auth-bypass.svg)


## CVE-2022-39197
 An XSS (Cross Site Scripting) vulnerability was found in HelpSystems Cobalt Strike through 4.7 that allowed a remote attacker to execute HTML on the Cobalt Strike teamserver. To exploit the vulnerability, one must first inspect a Cobalt Strike payload, and then modify the username field in the payload (or create a new payload with the extracted information and then modify that username field to be malformed).

- [https://github.com/hluwa/cobaltstrike_swing_xss2rce](https://github.com/hluwa/cobaltstrike_swing_xss2rce) :  ![starts](https://img.shields.io/github/stars/hluwa/cobaltstrike_swing_xss2rce.svg) ![forks](https://img.shields.io/github/forks/hluwa/cobaltstrike_swing_xss2rce.svg)


## CVE-2022-24716
 Icinga Web 2 is an open source monitoring web interface, framework and command-line interface. Unauthenticated users can leak the contents of files of the local system accessible to the web-server user, including `icingaweb2` configuration files with database credentials. This issue has been resolved in versions 2.9.6 and 2.10 of Icinga Web 2. Database credentials should be rotated.

- [https://github.com/doosec101/CVE-2022-24716](https://github.com/doosec101/CVE-2022-24716) :  ![starts](https://img.shields.io/github/stars/doosec101/CVE-2022-24716.svg) ![forks](https://img.shields.io/github/forks/doosec101/CVE-2022-24716.svg)


## CVE-2022-24637
 Open Web Analytics (OWA) before 1.7.4 allows an unauthenticated remote attacker to obtain sensitive user information, which can be used to gain admin privileges by leveraging cache hashes. This occurs because files generated with '&lt;?php (instead of the intended &quot;&lt;?php sequence) aren't handled by the PHP interpreter.

- [https://github.com/0xM4hm0ud/CVE-2022-24637](https://github.com/0xM4hm0ud/CVE-2022-24637) :  ![starts](https://img.shields.io/github/stars/0xM4hm0ud/CVE-2022-24637.svg) ![forks](https://img.shields.io/github/forks/0xM4hm0ud/CVE-2022-24637.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/Ki11i0n4ir3/CVE-2022-22963](https://github.com/Ki11i0n4ir3/CVE-2022-22963) :  ![starts](https://img.shields.io/github/stars/Ki11i0n4ir3/CVE-2022-22963.svg) ![forks](https://img.shields.io/github/forks/Ki11i0n4ir3/CVE-2022-22963.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/ELIZEUOPAIN/CVE-2019-9053-CMS-Made-Simple-2.2.10---SQL-Injection-Exploit](https://github.com/ELIZEUOPAIN/CVE-2019-9053-CMS-Made-Simple-2.2.10---SQL-Injection-Exploit) :  ![starts](https://img.shields.io/github/stars/ELIZEUOPAIN/CVE-2019-9053-CMS-Made-Simple-2.2.10---SQL-Injection-Exploit.svg) ![forks](https://img.shields.io/github/forks/ELIZEUOPAIN/CVE-2019-9053-CMS-Made-Simple-2.2.10---SQL-Injection-Exploit.svg)
- [https://github.com/zmiddle/Simple_CMS_SQLi](https://github.com/zmiddle/Simple_CMS_SQLi) :  ![starts](https://img.shields.io/github/stars/zmiddle/Simple_CMS_SQLi.svg) ![forks](https://img.shields.io/github/forks/zmiddle/Simple_CMS_SQLi.svg)


## CVE-2019-1653
 A vulnerability in the web-based management interface of Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an unauthenticated, remote attacker to retrieve sensitive information. The vulnerability is due to improper access controls for URLs. An attacker could exploit this vulnerability by connecting to an affected device via HTTP or HTTPS and requesting specific URLs. A successful exploit could allow the attacker to download the router configuration or detailed diagnostic information. Cisco has released firmware updates that address this vulnerability.

- [https://github.com/ibrahimzx/CVE-2019-1653](https://github.com/ibrahimzx/CVE-2019-1653) :  ![starts](https://img.shields.io/github/stars/ibrahimzx/CVE-2019-1653.svg) ![forks](https://img.shields.io/github/forks/ibrahimzx/CVE-2019-1653.svg)


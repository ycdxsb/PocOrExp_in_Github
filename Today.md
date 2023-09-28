# Update 2023-09-28
## CVE-2023-43263
 A Cross-site scripting (XSS) vulnerability in Froala Editor v.4.1.1 allows attackers to execute arbitrary code via the Markdown component.

- [https://github.com/b0marek/CVE-2023-43263](https://github.com/b0marek/CVE-2023-43263) :  ![starts](https://img.shields.io/github/stars/b0marek/CVE-2023-43263.svg) ![forks](https://img.shields.io/github/forks/b0marek/CVE-2023-43263.svg)


## CVE-2023-42442
 JumpServer is an open source bastion host and a professional operation and maintenance security audit system. Starting in version 3.0.0 and prior to versions 3.5.5 and 3.6.4, session replays can download without authentication. Session replays stored in S3, OSS, or other cloud storage are not affected. The api `/api/v1/terminal/sessions/` permission control is broken and can be accessed anonymously. SessionViewSet permission classes set to `[RBACPermission | IsSessionAssignee]`, relation is or, so any permission matched will be allowed. Versions 3.5.5 and 3.6.4 have a fix. After upgrading, visit the api `$HOST/api/v1/terminal/sessions/?limit=1`. The expected http response code is 401 (`not_authenticated`).

- [https://github.com/HolyGu/CVE-2023-42442](https://github.com/HolyGu/CVE-2023-42442) :  ![starts](https://img.shields.io/github/stars/HolyGu/CVE-2023-42442.svg) ![forks](https://img.shields.io/github/forks/HolyGu/CVE-2023-42442.svg)


## CVE-2023-36845
 A PHP External Variable Modification vulnerability in J-Web of Juniper Networks Junos OS on EX Series and SRX Series allows an unauthenticated, network-based attacker to remotely execute code. Using a crafted request which sets the variable PHPRC an attacker is able to modify the PHP execution environment allowing the injection und execution of code. This issue affects Juniper Networks Junos OS on EX Series and SRX Series: * All versions prior to 20.4R3-S9; * 21.1 versions 21.1R1 and later; * 21.2 versions prior to 21.2R3-S7; * 21.3 versions prior to 21.3R3-S5; * 21.4 versions prior to 21.4R3-S5; * 22.1 versions prior to 22.1R3-S4; * 22.2 versions prior to 22.2R3-S2; * 22.3 versions prior to 22.3R2-S2, 22.3R3-S1; * 22.4 versions prior to 22.4R2-S1, 22.4R3; * 23.2 versions prior to 23.2R1-S1, 23.2R2.

- [https://github.com/kljunowsky/CVE-2023-36845](https://github.com/kljunowsky/CVE-2023-36845) :  ![starts](https://img.shields.io/github/stars/kljunowsky/CVE-2023-36845.svg) ![forks](https://img.shields.io/github/forks/kljunowsky/CVE-2023-36845.svg)


## CVE-2023-35793
 An issue was discovered in Cassia Access Controller 2.1.1.2303271039. Establishing a web SSH session to gateways is vulnerable to Cross Site Request Forgery (CSRF) attacks.

- [https://github.com/Dodge-MPTC/CVE-2023-35793-CSRF-On-Web-SSH](https://github.com/Dodge-MPTC/CVE-2023-35793-CSRF-On-Web-SSH) :  ![starts](https://img.shields.io/github/stars/Dodge-MPTC/CVE-2023-35793-CSRF-On-Web-SSH.svg) ![forks](https://img.shields.io/github/forks/Dodge-MPTC/CVE-2023-35793-CSRF-On-Web-SSH.svg)


## CVE-2023-34152
 A vulnerability was found in ImageMagick. This security flaw cause a remote code execution vulnerability in OpenBlob with --enable-pipes configured.

- [https://github.com/overgrowncarrot1/ImageTragick_CVE-2023-34152](https://github.com/overgrowncarrot1/ImageTragick_CVE-2023-34152) :  ![starts](https://img.shields.io/github/stars/overgrowncarrot1/ImageTragick_CVE-2023-34152.svg) ![forks](https://img.shields.io/github/forks/overgrowncarrot1/ImageTragick_CVE-2023-34152.svg)


## CVE-2023-32364
 A logic issue was addressed with improved restrictions. This issue is fixed in macOS Ventura 13.5. A sandboxed process may be able to circumvent sandbox restrictions.

- [https://github.com/gergelykalman/CVE-2023-32364-macos-app-sandbox-escape](https://github.com/gergelykalman/CVE-2023-32364-macos-app-sandbox-escape) :  ![starts](https://img.shields.io/github/stars/gergelykalman/CVE-2023-32364-macos-app-sandbox-escape.svg) ![forks](https://img.shields.io/github/forks/gergelykalman/CVE-2023-32364-macos-app-sandbox-escape.svg)


## CVE-2023-29357
 Microsoft SharePoint Server Elevation of Privilege Vulnerability

- [https://github.com/Chocapikk/CVE-2023-29357](https://github.com/Chocapikk/CVE-2023-29357) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2023-29357.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2023-29357.svg)


## CVE-2023-24955
 Microsoft SharePoint Server Remote Code Execution Vulnerability

- [https://github.com/Chocapikk/CVE-2023-29357](https://github.com/Chocapikk/CVE-2023-29357) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2023-29357.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2023-29357.svg)


## CVE-2023-21272
 In readFrom of Uri.java, there is a possible bad URI permission grant due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Trinadh465/frameworks_base_AOSP-4.2.2_r1_CVE-2023-21272](https://github.com/Trinadh465/frameworks_base_AOSP-4.2.2_r1_CVE-2023-21272) :  ![starts](https://img.shields.io/github/stars/Trinadh465/frameworks_base_AOSP-4.2.2_r1_CVE-2023-21272.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/frameworks_base_AOSP-4.2.2_r1_CVE-2023-21272.svg)


## CVE-2023-5024
 A vulnerability was found in Planno 23.04.04. It has been classified as problematic. This affects an unknown part of the component Comment Handler. The manipulation leads to cross site scripting. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-239865 was assigned to this vulnerability.

- [https://github.com/PH03N1XSP/CVE-2023-5024](https://github.com/PH03N1XSP/CVE-2023-5024) :  ![starts](https://img.shields.io/github/stars/PH03N1XSP/CVE-2023-5024.svg) ![forks](https://img.shields.io/github/forks/PH03N1XSP/CVE-2023-5024.svg)


## CVE-2022-40317
 OpenKM 6.3.11 allows stored XSS related to the javascript&amp;colon; substring in an A element.

- [https://github.com/izdiwho/CVE-2022-40317](https://github.com/izdiwho/CVE-2022-40317) :  ![starts](https://img.shields.io/github/stars/izdiwho/CVE-2022-40317.svg) ![forks](https://img.shields.io/github/forks/izdiwho/CVE-2022-40317.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/yTxZx/CVE-2022-26134](https://github.com/yTxZx/CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/yTxZx/CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/yTxZx/CVE-2022-26134.svg)


## CVE-2022-21894
 Secure Boot Security Feature Bypass Vulnerability.

- [https://github.com/nova-master/Wack0-CVE-2022-21894](https://github.com/nova-master/Wack0-CVE-2022-21894) :  ![starts](https://img.shields.io/github/stars/nova-master/Wack0-CVE-2022-21894.svg) ![forks](https://img.shields.io/github/forks/nova-master/Wack0-CVE-2022-21894.svg)
- [https://github.com/nova-master/Wack00-CVE-2022-21894](https://github.com/nova-master/Wack00-CVE-2022-21894) :  ![starts](https://img.shields.io/github/stars/nova-master/Wack00-CVE-2022-21894.svg) ![forks](https://img.shields.io/github/forks/nova-master/Wack00-CVE-2022-21894.svg)


## CVE-2022-3786
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed a malicious certificate or for an application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects.

- [https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc](https://github.com/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc) :  ![starts](https://img.shields.io/github/stars/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg) ![forks](https://img.shields.io/github/forks/rbowes-r7/cve-2022-3602-and-cve-2022-3786-openssl-poc.svg)


## CVE-2022-1040
 An authentication bypass vulnerability in the User Portal and Webadmin allows a remote attacker to execute code in Sophos Firewall version v18.5 MR3 and older.

- [https://github.com/Cyb3rEnthusiast/CVE-2022-1040](https://github.com/Cyb3rEnthusiast/CVE-2022-1040) :  ![starts](https://img.shields.io/github/stars/Cyb3rEnthusiast/CVE-2022-1040.svg) ![forks](https://img.shields.io/github/forks/Cyb3rEnthusiast/CVE-2022-1040.svg)


## CVE-2021-4428
 A vulnerability has been found in what3words Autosuggest Plugin up to 4.0.0 on WordPress and classified as problematic. Affected by this vulnerability is the function enqueue_scripts of the file w3w-autosuggest/public/class-w3w-autosuggest-public.php of the component Setting Handler. The manipulation leads to information disclosure. The attack can be launched remotely. Upgrading to version 4.0.1 is able to address this issue. The patch is named dd59cbac5f86057d6a73b87007c08b8bfa0c32ac. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-234247.

- [https://github.com/lov3r/cve-2021-44228-log4j-exploits](https://github.com/lov3r/cve-2021-44228-log4j-exploits) :  ![starts](https://img.shields.io/github/stars/lov3r/cve-2021-44228-log4j-exploits.svg) ![forks](https://img.shields.io/github/forks/lov3r/cve-2021-44228-log4j-exploits.svg)


## CVE-2021-2394
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/fasanhlieu/CVE-2021-2394](https://github.com/fasanhlieu/CVE-2021-2394) :  ![starts](https://img.shields.io/github/stars/fasanhlieu/CVE-2021-2394.svg) ![forks](https://img.shields.io/github/forks/fasanhlieu/CVE-2021-2394.svg)


## CVE-2019-15642
 rpc.cgi in Webmin through 1.920 allows authenticated Remote Code Execution via a crafted object name because unserialise_variable makes an eval call. NOTE: the Webmin_Servers_Index documentation states &quot;RPC can be used to run any command or modify any file on a server, which is why access to it must not be granted to un-trusted Webmin users.&quot;

- [https://github.com/CLincat/vulcat](https://github.com/CLincat/vulcat) :  ![starts](https://img.shields.io/github/stars/CLincat/vulcat.svg) ![forks](https://img.shields.io/github/forks/CLincat/vulcat.svg)


## CVE-2018-11790
 When loading a document with Apache Open Office 4.1.5 and earlier with smaller end line termination than the operating system uses, the defect occurs. In this case OpenOffice runs into an Arithmetic Overflow at a string length calculation.

- [https://github.com/anmuxi-bai/CVE-2018-11790](https://github.com/anmuxi-bai/CVE-2018-11790) :  ![starts](https://img.shields.io/github/stars/anmuxi-bai/CVE-2018-11790.svg) ![forks](https://img.shields.io/github/forks/anmuxi-bai/CVE-2018-11790.svg)


## CVE-2018-11776
 Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then: results are used with no namespace and in same time, its upper package have no or wildcard namespace and similar to results, same possibility when using url tag which doesn't have value and action set and in same time, its upper package have no or wildcard namespace.

- [https://github.com/mazen160/struts-pwn_CVE-2018-11776](https://github.com/mazen160/struts-pwn_CVE-2018-11776) :  ![starts](https://img.shields.io/github/stars/mazen160/struts-pwn_CVE-2018-11776.svg) ![forks](https://img.shields.io/github/forks/mazen160/struts-pwn_CVE-2018-11776.svg)
- [https://github.com/hook-s3c/CVE-2018-11776-Python-PoC](https://github.com/hook-s3c/CVE-2018-11776-Python-PoC) :  ![starts](https://img.shields.io/github/stars/hook-s3c/CVE-2018-11776-Python-PoC.svg) ![forks](https://img.shields.io/github/forks/hook-s3c/CVE-2018-11776-Python-PoC.svg)
- [https://github.com/649/Apache-Struts-Shodan-Exploit](https://github.com/649/Apache-Struts-Shodan-Exploit) :  ![starts](https://img.shields.io/github/stars/649/Apache-Struts-Shodan-Exploit.svg) ![forks](https://img.shields.io/github/forks/649/Apache-Struts-Shodan-Exploit.svg)
- [https://github.com/Ekultek/Strutter](https://github.com/Ekultek/Strutter) :  ![starts](https://img.shields.io/github/stars/Ekultek/Strutter.svg) ![forks](https://img.shields.io/github/forks/Ekultek/Strutter.svg)
- [https://github.com/brianwrf/S2-057-CVE-2018-11776](https://github.com/brianwrf/S2-057-CVE-2018-11776) :  ![starts](https://img.shields.io/github/stars/brianwrf/S2-057-CVE-2018-11776.svg) ![forks](https://img.shields.io/github/forks/brianwrf/S2-057-CVE-2018-11776.svg)
- [https://github.com/xfox64x/CVE-2018-11776](https://github.com/xfox64x/CVE-2018-11776) :  ![starts](https://img.shields.io/github/stars/xfox64x/CVE-2018-11776.svg) ![forks](https://img.shields.io/github/forks/xfox64x/CVE-2018-11776.svg)
- [https://github.com/ArunBhandarii/Apache-Struts-0Day-Exploit](https://github.com/ArunBhandarii/Apache-Struts-0Day-Exploit) :  ![starts](https://img.shields.io/github/stars/ArunBhandarii/Apache-Struts-0Day-Exploit.svg) ![forks](https://img.shields.io/github/forks/ArunBhandarii/Apache-Struts-0Day-Exploit.svg)
- [https://github.com/Fnzer0/S2-057-poc](https://github.com/Fnzer0/S2-057-poc) :  ![starts](https://img.shields.io/github/stars/Fnzer0/S2-057-poc.svg) ![forks](https://img.shields.io/github/forks/Fnzer0/S2-057-poc.svg)
- [https://github.com/jiguangsdf/CVE-2018-11776](https://github.com/jiguangsdf/CVE-2018-11776) :  ![starts](https://img.shields.io/github/stars/jiguangsdf/CVE-2018-11776.svg) ![forks](https://img.shields.io/github/forks/jiguangsdf/CVE-2018-11776.svg)
- [https://github.com/bhdresh/CVE-2018-11776](https://github.com/bhdresh/CVE-2018-11776) :  ![starts](https://img.shields.io/github/stars/bhdresh/CVE-2018-11776.svg) ![forks](https://img.shields.io/github/forks/bhdresh/CVE-2018-11776.svg)
- [https://github.com/knqyf263/CVE-2018-11776](https://github.com/knqyf263/CVE-2018-11776) :  ![starts](https://img.shields.io/github/stars/knqyf263/CVE-2018-11776.svg) ![forks](https://img.shields.io/github/forks/knqyf263/CVE-2018-11776.svg)
- [https://github.com/tuxotron/cve-2018-11776-docker](https://github.com/tuxotron/cve-2018-11776-docker) :  ![starts](https://img.shields.io/github/stars/tuxotron/cve-2018-11776-docker.svg) ![forks](https://img.shields.io/github/forks/tuxotron/cve-2018-11776-docker.svg)
- [https://github.com/HxDDD/CVE-PoC](https://github.com/HxDDD/CVE-PoC) :  ![starts](https://img.shields.io/github/stars/HxDDD/CVE-PoC.svg) ![forks](https://img.shields.io/github/forks/HxDDD/CVE-PoC.svg)
- [https://github.com/cved-sources/cve-2018-11776](https://github.com/cved-sources/cve-2018-11776) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2018-11776.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2018-11776.svg)
- [https://github.com/gh0st27/Struts2Scanner](https://github.com/gh0st27/Struts2Scanner) :  ![starts](https://img.shields.io/github/stars/gh0st27/Struts2Scanner.svg) ![forks](https://img.shields.io/github/forks/gh0st27/Struts2Scanner.svg)
- [https://github.com/cucadili/CVE-2018-11776](https://github.com/cucadili/CVE-2018-11776) :  ![starts](https://img.shields.io/github/stars/cucadili/CVE-2018-11776.svg) ![forks](https://img.shields.io/github/forks/cucadili/CVE-2018-11776.svg)
- [https://github.com/sonpt-afk/CVE-2018-11776-FIS](https://github.com/sonpt-afk/CVE-2018-11776-FIS) :  ![starts](https://img.shields.io/github/stars/sonpt-afk/CVE-2018-11776-FIS.svg) ![forks](https://img.shields.io/github/forks/sonpt-afk/CVE-2018-11776-FIS.svg)
- [https://github.com/freshdemo/ApacheStruts-CVE-2018-11776](https://github.com/freshdemo/ApacheStruts-CVE-2018-11776) :  ![starts](https://img.shields.io/github/stars/freshdemo/ApacheStruts-CVE-2018-11776.svg) ![forks](https://img.shields.io/github/forks/freshdemo/ApacheStruts-CVE-2018-11776.svg)
- [https://github.com/OzNetNerd/apche-struts-vuln-demo-cve-2018-11776](https://github.com/OzNetNerd/apche-struts-vuln-demo-cve-2018-11776) :  ![starts](https://img.shields.io/github/stars/OzNetNerd/apche-struts-vuln-demo-cve-2018-11776.svg) ![forks](https://img.shields.io/github/forks/OzNetNerd/apche-struts-vuln-demo-cve-2018-11776.svg)
- [https://github.com/jezzus/CVE-2018-11776-Python-PoC](https://github.com/jezzus/CVE-2018-11776-Python-PoC) :  ![starts](https://img.shields.io/github/stars/jezzus/CVE-2018-11776-Python-PoC.svg) ![forks](https://img.shields.io/github/forks/jezzus/CVE-2018-11776-Python-PoC.svg)


## CVE-2018-11770
 From version 1.3.0 onward, Apache Spark's standalone master exposes a REST API for job submission, in addition to the submission mechanism used by spark-submit. In standalone, the config property 'spark.authenticate.secret' establishes a shared secret for authenticating requests to submit jobs via spark-submit. However, the REST API does not use this or any other authentication mechanism, and this is not adequately documented. In this case, a user would be able to run a driver program without authenticating, but not launch executors, using the REST API. This REST API is also used by Mesos, when set up to run in cluster mode (i.e., when also running MesosClusterDispatcher), for job submission. Future versions of Spark will improve documentation on these points, and prohibit setting 'spark.authenticate.secret' when running the REST APIs, to make this clear. Future versions will also disable the REST API by default in the standalone master by changing the default value of 'spark.master.rest.enabled' to 'false'.

- [https://github.com/ivanitlearning/CVE-2018-11770](https://github.com/ivanitlearning/CVE-2018-11770) :  ![starts](https://img.shields.io/github/stars/ivanitlearning/CVE-2018-11770.svg) ![forks](https://img.shields.io/github/forks/ivanitlearning/CVE-2018-11770.svg)


## CVE-2018-1160
 Netatalk before 3.1.12 is vulnerable to an out of bounds write in dsi_opensess.c. This is due to lack of bounds checking on attacker controlled data. A remote unauthenticated attacker can leverage this vulnerability to achieve arbitrary code execution.

- [https://github.com/SachinThanushka/CVE-2018-1160](https://github.com/SachinThanushka/CVE-2018-1160) :  ![starts](https://img.shields.io/github/stars/SachinThanushka/CVE-2018-1160.svg) ![forks](https://img.shields.io/github/forks/SachinThanushka/CVE-2018-1160.svg)


## CVE-2016-8020
 Improper control of generation of code vulnerability in Intel Security VirusScan Enterprise Linux (VSEL) 2.0.3 (and earlier) allows remote authenticated users to execute arbitrary code via a crafted HTTP request parameter.

- [https://github.com/opsxcq/exploit-CVE-2016-8016-25](https://github.com/opsxcq/exploit-CVE-2016-8016-25) :  ![starts](https://img.shields.io/github/stars/opsxcq/exploit-CVE-2016-8016-25.svg) ![forks](https://img.shields.io/github/forks/opsxcq/exploit-CVE-2016-8016-25.svg)


## CVE-2015-5602
 sudoedit in Sudo before 1.8.15 allows local users to gain privileges via a symlink attack on a file whose full path is defined using multiple wildcards in /etc/sudoers, as demonstrated by &quot;/home/*/*/file.txt.&quot;

- [https://github.com/t0kx/privesc-CVE-2015-5602](https://github.com/t0kx/privesc-CVE-2015-5602) :  ![starts](https://img.shields.io/github/stars/t0kx/privesc-CVE-2015-5602.svg) ![forks](https://img.shields.io/github/forks/t0kx/privesc-CVE-2015-5602.svg)
- [https://github.com/cved-sources/cve-2015-5602](https://github.com/cved-sources/cve-2015-5602) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2015-5602.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2015-5602.svg)


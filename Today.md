# Update 2023-12-15
## CVE-2023-50164
 An attacker can manipulate file upload params to enable paths traversal and under some circumstances this can lead to uploading a malicious file which can be used to perform Remote Code Execution. Users are recommended to upgrade to versions Struts 2.5.33 or Struts 6.3.0.2 or greater to fix this issue.

- [https://github.com/jakabakos/CVE-2023-50164-Apache-Struts-RCE](https://github.com/jakabakos/CVE-2023-50164-Apache-Struts-RCE) :  ![starts](https://img.shields.io/github/stars/jakabakos/CVE-2023-50164-Apache-Struts-RCE.svg) ![forks](https://img.shields.io/github/forks/jakabakos/CVE-2023-50164-Apache-Struts-RCE.svg)


## CVE-2023-49038
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/christopher-pace/CVE-2023-49038](https://github.com/christopher-pace/CVE-2023-49038) :  ![starts](https://img.shields.io/github/stars/christopher-pace/CVE-2023-49038.svg) ![forks](https://img.shields.io/github/forks/christopher-pace/CVE-2023-49038.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/SpamixOfficial/CVE-2023-38831](https://github.com/SpamixOfficial/CVE-2023-38831) :  ![starts](https://img.shields.io/github/stars/SpamixOfficial/CVE-2023-38831.svg) ![forks](https://img.shields.io/github/forks/SpamixOfficial/CVE-2023-38831.svg)


## CVE-2023-28432
 Minio is a Multi-Cloud Object Storage framework. In a cluster deployment starting with RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns all environment variables, including `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`, resulting in information disclosure. All users of distributed deployment are impacted. All users are advised to upgrade to RELEASE.2023-03-20T20-16-18Z.

- [https://github.com/unam4/CVE-2023-28432-minio_update_rce](https://github.com/unam4/CVE-2023-28432-minio_update_rce) :  ![starts](https://img.shields.io/github/stars/unam4/CVE-2023-28432-minio_update_rce.svg) ![forks](https://img.shields.io/github/forks/unam4/CVE-2023-28432-minio_update_rce.svg)


## CVE-2023-27035
 An issue discovered in Obsidian Canvas 1.1.9 allows remote attackers to send desktop notifications, record user audio and other unspecified impacts via embedded website on the canvas page.

- [https://github.com/fivex3/CVE-2023-27035](https://github.com/fivex3/CVE-2023-27035) :  ![starts](https://img.shields.io/github/stars/fivex3/CVE-2023-27035.svg) ![forks](https://img.shields.io/github/forks/fivex3/CVE-2023-27035.svg)


## CVE-2023-26035
 ZoneMinder is a free, open source Closed-circuit television software application for Linux which supports IP, USB and Analog cameras. Versions prior to 1.36.33 and 1.37.33 are vulnerable to Unauthenticated Remote Code Execution via Missing Authorization. There are no permissions check on the snapshot action, which expects an id to fetch an existing monitor but can be passed an object to create a new one instead. TriggerOn ends up calling shell_exec using the supplied Id. This issue is fixed in This issue is fixed in versions 1.36.33 and 1.37.33.

- [https://github.com/heapbytes/CVE-2023-26035](https://github.com/heapbytes/CVE-2023-26035) :  ![starts](https://img.shields.io/github/stars/heapbytes/CVE-2023-26035.svg) ![forks](https://img.shields.io/github/forks/heapbytes/CVE-2023-26035.svg)


## CVE-2023-20198
 Cisco is providing an update for the ongoing investigation into observed exploitation of the web UI feature in Cisco IOS XE Software. We are updating the list of fixed releases and adding the Software Checker. Our investigation has determined that the actors exploited two previously unknown issues. The attacker first exploited CVE-2023-20198 to gain initial access and issued a privilege 15 command to create a local user and password combination. This allowed the user to log in with normal user access. The attacker then exploited another component of the web UI feature, leveraging the new local user to elevate privilege to root and write the implant to the file system. Cisco has assigned CVE-2023-20273 to this issue. CVE-2023-20198 has been assigned a CVSS Score of 10.0. CVE-2023-20273 has been assigned a CVSS Score of 7.2. Both of these CVEs are being tracked by CSCwh87343.

- [https://github.com/codeb0ss/CVE-2023-20198-PoC](https://github.com/codeb0ss/CVE-2023-20198-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2023-20198-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2023-20198-PoC.svg)


## CVE-2023-6553
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Chocapikk/CVE-2023-6553](https://github.com/Chocapikk/CVE-2023-6553) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2023-6553.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2023-6553.svg)


## CVE-2023-5561
 WordPress does not properly restrict which user fields are searchable via the REST API, allowing unauthenticated attackers to discern the email addresses of users who have published public posts on an affected website via an Oracle style attack

- [https://github.com/pog007/CVE-2023-5561-PoC](https://github.com/pog007/CVE-2023-5561-PoC) :  ![starts](https://img.shields.io/github/stars/pog007/CVE-2023-5561-PoC.svg) ![forks](https://img.shields.io/github/forks/pog007/CVE-2023-5561-PoC.svg)


## CVE-2023-4636
 The WordPress File Sharing Plugin plugin for WordPress is vulnerable to Stored Cross-Site Scripting via admin settings in versions up to, and including, 2.0.3 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.

- [https://github.com/ThatNotEasy/CVE-2023-4636](https://github.com/ThatNotEasy/CVE-2023-4636) :  ![starts](https://img.shields.io/github/stars/ThatNotEasy/CVE-2023-4636.svg) ![forks](https://img.shields.io/github/forks/ThatNotEasy/CVE-2023-4636.svg)


## CVE-2022-31181
 PrestaShop is an Open Source e-commerce platform. In versions from 1.6.0.10 and before 1.7.8.7 PrestaShop is subject to an SQL injection vulnerability which can be chained to call PHP's Eval function on attacker input. The problem is fixed in version 1.7.8.7. Users are advised to upgrade. Users unable to upgrade may delete the MySQL Smarty cache feature.

- [https://github.com/drkbcn/lblfixer_cve_2022_31181](https://github.com/drkbcn/lblfixer_cve_2022_31181) :  ![starts](https://img.shields.io/github/stars/drkbcn/lblfixer_cve_2022_31181.svg) ![forks](https://img.shields.io/github/forks/drkbcn/lblfixer_cve_2022_31181.svg)


## CVE-2022-4047
 The Return Refund and Exchange For WooCommerce WordPress plugin before 4.0.9 does not validate attachment files to be uploaded via an AJAX action available to unauthenticated users, which could allow them to upload arbitrary files such as PHP and lead to RCE

- [https://github.com/entroychang/CVE-2022-4047](https://github.com/entroychang/CVE-2022-4047) :  ![starts](https://img.shields.io/github/stars/entroychang/CVE-2022-4047.svg) ![forks](https://img.shields.io/github/forks/entroychang/CVE-2022-4047.svg)


## CVE-2022-2586
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/pirenga/2022-LPE-UAF](https://github.com/pirenga/2022-LPE-UAF) :  ![starts](https://img.shields.io/github/stars/pirenga/2022-LPE-UAF.svg) ![forks](https://img.shields.io/github/forks/pirenga/2022-LPE-UAF.svg)


## CVE-2022-2414
 Access to external entities when parsing XML documents can lead to XML external entity (XXE) attacks. This flaw allows a remote attacker to potentially retrieve the content of arbitrary files by sending specially crafted HTTP requests.

- [https://github.com/superhac/CVE-2022-2414-POC](https://github.com/superhac/CVE-2022-2414-POC) :  ![starts](https://img.shields.io/github/stars/superhac/CVE-2022-2414-POC.svg) ![forks](https://img.shields.io/github/forks/superhac/CVE-2022-2414-POC.svg)


## CVE-2021-36958
 Windows Print Spooler Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-36936, CVE-2021-36947.

- [https://github.com/Tomparte/PrintNightmare](https://github.com/Tomparte/PrintNightmare) :  ![starts](https://img.shields.io/github/stars/Tomparte/PrintNightmare.svg) ![forks](https://img.shields.io/github/forks/Tomparte/PrintNightmare.svg)


## CVE-2020-10199
 Sonatype Nexus Repository before 3.21.2 allows JavaEL Injection (issue 1 of 2).

- [https://github.com/magicming200/CVE-2020-10199_CVE-2020-10204](https://github.com/magicming200/CVE-2020-10199_CVE-2020-10204) :  ![starts](https://img.shields.io/github/stars/magicming200/CVE-2020-10199_CVE-2020-10204.svg) ![forks](https://img.shields.io/github/forks/magicming200/CVE-2020-10199_CVE-2020-10204.svg)


## CVE-2020-8813
 graph_realtime.php in Cacti 1.2.8 allows remote attackers to execute arbitrary OS commands via shell metacharacters in a cookie, if a guest user has the graph real-time privilege.

- [https://github.com/cocomelonc/vulnexipy](https://github.com/cocomelonc/vulnexipy) :  ![starts](https://img.shields.io/github/stars/cocomelonc/vulnexipy.svg) ![forks](https://img.shields.io/github/forks/cocomelonc/vulnexipy.svg)


## CVE-2019-8449
 The /rest/api/latest/groupuserpicker resource in Jira before version 8.4.0 allows remote attackers to enumerate usernames via an information disclosure vulnerability.

- [https://github.com/und3sc0n0c1d0/UserEnumJira](https://github.com/und3sc0n0c1d0/UserEnumJira) :  ![starts](https://img.shields.io/github/stars/und3sc0n0c1d0/UserEnumJira.svg) ![forks](https://img.shields.io/github/forks/und3sc0n0c1d0/UserEnumJira.svg)


## CVE-2019-5029
 An exploitable command injection vulnerability exists in the Config editor of the Exhibitor Web UI versions 1.0.9 to 1.7.1. Arbitrary shell commands surrounded by backticks or $() can be inserted into the editor and will be executed by the Exhibitor process when it launches ZooKeeper. An attacker can execute any command as the user running the Exhibitor process.

- [https://github.com/thehunt1s0n/Exihibitor-RCE](https://github.com/thehunt1s0n/Exihibitor-RCE) :  ![starts](https://img.shields.io/github/stars/thehunt1s0n/Exihibitor-RCE.svg) ![forks](https://img.shields.io/github/forks/thehunt1s0n/Exihibitor-RCE.svg)


## CVE-2019-0539
 A remote code execution vulnerability exists in the way that the Chakra scripting engine handles objects in memory in Microsoft Edge, aka &quot;Chakra Scripting Engine Memory Corruption Vulnerability.&quot; This affects Microsoft Edge, ChakraCore. This CVE ID is unique from CVE-2019-0567, CVE-2019-0568.

- [https://github.com/SpiralBL0CK/cve2019-0539](https://github.com/SpiralBL0CK/cve2019-0539) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/cve2019-0539.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/cve2019-0539.svg)


## CVE-2018-25031
 Swagger UI before 4.1.3 could allow a remote attacker to conduct spoofing attacks. By persuading a victim to open a crafted URL, an attacker could exploit this vulnerability to display remote OpenAPI definitions.

- [https://github.com/hev0x/CVE-2018-25031-PoC](https://github.com/hev0x/CVE-2018-25031-PoC) :  ![starts](https://img.shields.io/github/stars/hev0x/CVE-2018-25031-PoC.svg) ![forks](https://img.shields.io/github/forks/hev0x/CVE-2018-25031-PoC.svg)
- [https://github.com/ThiiagoEscobar/CVE-2018-25031](https://github.com/ThiiagoEscobar/CVE-2018-25031) :  ![starts](https://img.shields.io/github/stars/ThiiagoEscobar/CVE-2018-25031.svg) ![forks](https://img.shields.io/github/forks/ThiiagoEscobar/CVE-2018-25031.svg)


## CVE-2017-16995
 The check_alu_op function in kernel/bpf/verifier.c in the Linux kernel through 4.4 allows local users to cause a denial of service (memory corruption) or possibly have unspecified other impact by leveraging incorrect sign extension.

- [https://github.com/mareks1007/cve-2017-16995](https://github.com/mareks1007/cve-2017-16995) :  ![starts](https://img.shields.io/github/stars/mareks1007/cve-2017-16995.svg) ![forks](https://img.shields.io/github/forks/mareks1007/cve-2017-16995.svg)


## CVE-2015-5195
 ntp_openssl.m4 in ntpd in NTP before 4.2.7p112 allows remote attackers to cause a denial of service (segmentation fault) via a crafted statistics or filegen configuration command that is not enabled during compilation.

- [https://github.com/theglife214/CVE-2015-5195](https://github.com/theglife214/CVE-2015-5195) :  ![starts](https://img.shields.io/github/stars/theglife214/CVE-2015-5195.svg) ![forks](https://img.shields.io/github/forks/theglife214/CVE-2015-5195.svg)


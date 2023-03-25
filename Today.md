# Update 2023-03-25
## CVE-2023-28434
 Minio is a Multi-Cloud Object Storage framework. Prior to RELEASE.2023-03-20T20-16-18Z, an attacker can use crafted requests to bypass metadata bucket name checking and put an object into any bucket while processing `PostPolicyBucket`. To carry out this attack, the attacker requires credentials with `arn:aws:s3:::*` permission, as well as enabled Console API access. This issue has been patched in RELEASE.2023-03-20T20-16-18Z. As a workaround, enable browser API access and turn off `MINIO_BROWSER=off`.

- [https://github.com/Mr-xn/CVE-2023-28432](https://github.com/Mr-xn/CVE-2023-28432) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2023-28432.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2023-28432.svg)


## CVE-2023-28432
 Minio is a Multi-Cloud Object Storage framework. In a cluster deployment starting with RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns all environment variables, including `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`, resulting in information disclosure. All users of distributed deployment are impacted. All users are advised to upgrade to RELEASE.2023-03-20T20-16-18Z.

- [https://github.com/Mr-xn/CVE-2023-28432](https://github.com/Mr-xn/CVE-2023-28432) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2023-28432.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2023-28432.svg)
- [https://github.com/gobysec/CVE-2023-28432](https://github.com/gobysec/CVE-2023-28432) :  ![starts](https://img.shields.io/github/stars/gobysec/CVE-2023-28432.svg) ![forks](https://img.shields.io/github/forks/gobysec/CVE-2023-28432.svg)
- [https://github.com/Okaytc/minio_unauth_check](https://github.com/Okaytc/minio_unauth_check) :  ![starts](https://img.shields.io/github/stars/Okaytc/minio_unauth_check.svg) ![forks](https://img.shields.io/github/forks/Okaytc/minio_unauth_check.svg)


## CVE-2023-28343
 OS command injection affects Altenergy Power Control Software C1.2.5 via shell metacharacters in the index.php/management/set_timezone timezone parameter, because of set_timezone in models/management_model.php.

- [https://github.com/superzerosec/CVE-2023-28343](https://github.com/superzerosec/CVE-2023-28343) :  ![starts](https://img.shields.io/github/stars/superzerosec/CVE-2023-28343.svg) ![forks](https://img.shields.io/github/forks/superzerosec/CVE-2023-28343.svg)


## CVE-2023-27532
 Vulnerability in Veeam Backup &amp; Replication component allows encrypted credentials stored in the configuration database to be obtained. This may lead to gaining access to the backup infrastructure hosts.

- [https://github.com/horizon3ai/CVE-2023-27532](https://github.com/horizon3ai/CVE-2023-27532) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2023-27532.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2023-27532.svg)
- [https://github.com/sfewer-r7/CVE-2023-27532](https://github.com/sfewer-r7/CVE-2023-27532) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/CVE-2023-27532.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/CVE-2023-27532.svg)


## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/stevesec/CVE-2023-23397](https://github.com/stevesec/CVE-2023-23397) :  ![starts](https://img.shields.io/github/stars/stevesec/CVE-2023-23397.svg) ![forks](https://img.shields.io/github/forks/stevesec/CVE-2023-23397.svg)
- [https://github.com/securiteinfo/expl_outlook_cve_2023_23397_securiteinfo.yar](https://github.com/securiteinfo/expl_outlook_cve_2023_23397_securiteinfo.yar) :  ![starts](https://img.shields.io/github/stars/securiteinfo/expl_outlook_cve_2023_23397_securiteinfo.yar.svg) ![forks](https://img.shields.io/github/forks/securiteinfo/expl_outlook_cve_2023_23397_securiteinfo.yar.svg)


## CVE-2023-21036
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/maddiethecafebabe/discord-acropolypse-bot](https://github.com/maddiethecafebabe/discord-acropolypse-bot) :  ![starts](https://img.shields.io/github/stars/maddiethecafebabe/discord-acropolypse-bot.svg) ![forks](https://img.shields.io/github/forks/maddiethecafebabe/discord-acropolypse-bot.svg)


## CVE-2023-1454
 A vulnerability classified as critical has been found in jeecg-boot 3.5.0. This affects an unknown part of the file jmreport/qurestSql. The manipulation of the argument apiSelectId leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-223299.

- [https://github.com/gobysec/CVE-2023-1454](https://github.com/gobysec/CVE-2023-1454) :  ![starts](https://img.shields.io/github/stars/gobysec/CVE-2023-1454.svg) ![forks](https://img.shields.io/github/forks/gobysec/CVE-2023-1454.svg)


## CVE-2022-42475
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through 7.0.8, 6.4.0 through 6.4.10, 6.2.0 through 6.2.11, 6.0.15 and earlier and FortiProxy SSL-VPN 7.2.0 through 7.2.1, 7.0.7 and earlier may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/CKevens/CVE-2022-42475-RCE-POC](https://github.com/CKevens/CVE-2022-42475-RCE-POC) :  ![starts](https://img.shields.io/github/stars/CKevens/CVE-2022-42475-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/CKevens/CVE-2022-42475-RCE-POC.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/0x01-sec/CVE-2021-4034-](https://github.com/0x01-sec/CVE-2021-4034-) :  ![starts](https://img.shields.io/github/stars/0x01-sec/CVE-2021-4034-.svg) ![forks](https://img.shields.io/github/forks/0x01-sec/CVE-2021-4034-.svg)


## CVE-2020-10220
 An issue was discovered in rConfig through 3.9.4. The web interface is prone to a SQL injection via the commands.inc.php searchColumn parameter.

- [https://github.com/arvind2022/isac_rconfig3.9](https://github.com/arvind2022/isac_rconfig3.9) :  ![starts](https://img.shields.io/github/stars/arvind2022/isac_rconfig3.9.svg) ![forks](https://img.shields.io/github/forks/arvind2022/isac_rconfig3.9.svg)


## CVE-2020-8835
 In the Linux kernel 5.5.0 and newer, the bpf verifier (kernel/bpf/verifier.c) did not properly restrict the register bounds for 32-bit operations, leading to out-of-bounds reads and writes in kernel memory. The vulnerability also affects the Linux 5.4 stable series, starting with v5.4.7, as the introducing commit was backported to that branch. This vulnerability was fixed in 5.6.1, 5.5.14, and 5.4.29. (issue is aka ZDI-CAN-10780)

- [https://github.com/johnatag/INF8602-CVE-2020-8835](https://github.com/johnatag/INF8602-CVE-2020-8835) :  ![starts](https://img.shields.io/github/stars/johnatag/INF8602-CVE-2020-8835.svg) ![forks](https://img.shields.io/github/forks/johnatag/INF8602-CVE-2020-8835.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/doggycheng/CNVD-2020-10487](https://github.com/doggycheng/CNVD-2020-10487) :  ![starts](https://img.shields.io/github/stars/doggycheng/CNVD-2020-10487.svg) ![forks](https://img.shields.io/github/forks/doggycheng/CNVD-2020-10487.svg)


## CVE-2019-11932
 A double free vulnerability in the DDGifSlurp function in decoding.c in the android-gif-drawable library before version 1.2.18, as used in WhatsApp for Android before version 2.19.244 and many other Android applications, allows remote attackers to execute arbitrary code or cause a denial of service when the library is used to parse a specially crafted GIF image.

- [https://github.com/primebeast/CVE-2019-11932](https://github.com/primebeast/CVE-2019-11932) :  ![starts](https://img.shields.io/github/stars/primebeast/CVE-2019-11932.svg) ![forks](https://img.shields.io/github/forks/primebeast/CVE-2019-11932.svg)


## CVE-2018-14847
 MikroTik RouterOS through 6.42 allows unauthenticated remote attackers to read arbitrary files and remote authenticated attackers to write arbitrary files due to a directory traversal vulnerability in the WinBox interface.

- [https://github.com/Tr33-He11/winboxPOC](https://github.com/Tr33-He11/winboxPOC) :  ![starts](https://img.shields.io/github/stars/Tr33-He11/winboxPOC.svg) ![forks](https://img.shields.io/github/forks/Tr33-He11/winboxPOC.svg)


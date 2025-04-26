# Update 2025-04-26
## CVE-2025-34028
This issue affects Command Center Innovation Release: 11.38.

- [https://github.com/watchtowrlabs/watchTowr-vs-Commvault-PreAuth-RCE-CVE-2025-34028](https://github.com/watchtowrlabs/watchTowr-vs-Commvault-PreAuth-RCE-CVE-2025-34028) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Commvault-PreAuth-RCE-CVE-2025-34028.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Commvault-PreAuth-RCE-CVE-2025-34028.svg)
- [https://github.com/tinkerlev/commvault-cve2025-34028-check](https://github.com/tinkerlev/commvault-cve2025-34028-check) :  ![starts](https://img.shields.io/github/stars/tinkerlev/commvault-cve2025-34028-check.svg) ![forks](https://img.shields.io/github/forks/tinkerlev/commvault-cve2025-34028-check.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/rizky412/CVE-2025-32433](https://github.com/rizky412/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/rizky412/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/rizky412/CVE-2025-32433.svg)
- [https://github.com/ps-interactive/lab_CVE-2025-32433](https://github.com/ps-interactive/lab_CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/ps-interactive/lab_CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/ps-interactive/lab_CVE-2025-32433.svg)
- [https://github.com/TeneBrae93/CVE-2025-3243](https://github.com/TeneBrae93/CVE-2025-3243) :  ![starts](https://img.shields.io/github/stars/TeneBrae93/CVE-2025-3243.svg) ![forks](https://img.shields.io/github/forks/TeneBrae93/CVE-2025-3243.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/SUPRAAA-1337/CVE-2025-31161](https://github.com/SUPRAAA-1337/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/SUPRAAA-1337/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/SUPRAAA-1337/CVE-2025-31161.svg)
- [https://github.com/SUPRAAA-1337/CVE-2025-31161_exploit](https://github.com/SUPRAAA-1337/CVE-2025-31161_exploit) :  ![starts](https://img.shields.io/github/stars/SUPRAAA-1337/CVE-2025-31161_exploit.svg) ![forks](https://img.shields.io/github/forks/SUPRAAA-1337/CVE-2025-31161_exploit.svg)
- [https://github.com/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825](https://github.com/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825) :  ![starts](https://img.shields.io/github/stars/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825.svg) ![forks](https://img.shields.io/github/forks/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825.svg)


## CVE-2025-30406
 Gladinet CentreStack through 16.1.10296.56315 (fixed in 16.4.10315.56368) has a deserialization vulnerability due to the CentreStack portal's hardcoded machineKey use, as exploited in the wild in March 2025. This enables threat actors (who know the machineKey) to serialize a payload for server-side deserialization to achieve remote code execution. NOTE: a CentreStack admin can manually delete the machineKey defined in portal\web.config.

- [https://github.com/W01fh4cker/CVE-2025-30406](https://github.com/W01fh4cker/CVE-2025-30406) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/CVE-2025-30406.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/CVE-2025-30406.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/r0ngy40/CVE-2025-30208-Series](https://github.com/r0ngy40/CVE-2025-30208-Series) :  ![starts](https://img.shields.io/github/stars/r0ngy40/CVE-2025-30208-Series.svg) ![forks](https://img.shields.io/github/forks/r0ngy40/CVE-2025-30208-Series.svg)


## CVE-2025-29529
 ITC Systems Multiplan/Matrix OneCard platform v3.7.4.1002 was discovered to contain a SQL injection vulnerability via the component Forgotpassword.aspx.

- [https://github.com/Yoshik0xF6/CVE-2025-29529](https://github.com/Yoshik0xF6/CVE-2025-29529) :  ![starts](https://img.shields.io/github/stars/Yoshik0xF6/CVE-2025-29529.svg) ![forks](https://img.shields.io/github/forks/Yoshik0xF6/CVE-2025-29529.svg)


## CVE-2025-21497
 Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB).  Supported versions that are affected are 8.0.40 and prior, 8.4.3 and prior and  9.1.0 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server as well as  unauthorized update, insert or delete access to some of MySQL Server accessible data. CVSS 3.1 Base Score 5.5 (Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H).

- [https://github.com/Urbank-61/cve-2025-21497-lab](https://github.com/Urbank-61/cve-2025-21497-lab) :  ![starts](https://img.shields.io/github/stars/Urbank-61/cve-2025-21497-lab.svg) ![forks](https://img.shields.io/github/forks/Urbank-61/cve-2025-21497-lab.svg)


## CVE-2025-3776
 The Verification SMS with TargetSMS plugin for WordPress is vulnerable to limited Remote Code Execution in all versions up to, and including, 1.5 via the 'targetvr_ajax_handler' function. This is due to a lack of validation on the type of function that can be called. This makes it possible for unauthenticated attackers to execute any callable function on the site, such as phpinfo().

- [https://github.com/Nxploited/CVE-2025-3776](https://github.com/Nxploited/CVE-2025-3776) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-3776.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-3776.svg)


## CVE-2025-2825
 DO NOT USE THIS CVE RECORD. ConsultIDs: CVE-2025-31161. Reason: This Record is a reservation duplicate of CVE-2025-31161. Notes: All CVE users should reference CVE-2025-31161 instead of this Record. All references and descriptions in this Record have been removed to prevent accidental usage.

- [https://github.com/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825](https://github.com/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825) :  ![starts](https://img.shields.io/github/stars/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825.svg) ![forks](https://img.shields.io/github/forks/SUPRAAA-1337/Nuclei_CVE-2025-31161_CVE-2025-2825.svg)


## CVE-2025-2120
 A vulnerability was found in Thinkware Car Dashcam F800 Pro up to 20250226. It has been rated as problematic. This issue affects some unknown processing of the file /tmp/hostapd.conf of the component Configuration File Handler. The manipulation leads to cleartext storage in a file or on disk. It is possible to launch the attack on the physical device. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/mmotti/Reset-inetpub](https://github.com/mmotti/Reset-inetpub) :  ![starts](https://img.shields.io/github/stars/mmotti/Reset-inetpub.svg) ![forks](https://img.shields.io/github/forks/mmotti/Reset-inetpub.svg)


## CVE-2024-42471
 actions/artifact is the GitHub ToolKit for developing GitHub Actions.  Versions of `actions/artifact` on the 2.x branch before 2.1.2 are vulnerable to arbitrary file write when using `downloadArtifactInternal`, `downloadArtifactPublic`, or `streamExtractExternal` for extracting a specifically crafted artifact that contains path traversal filenames. Users are advised to upgrade to version 2.1.2 or higher. There are no known workarounds for this issue.

- [https://github.com/theMcSam/CVE-2024-42471-PoC](https://github.com/theMcSam/CVE-2024-42471-PoC) :  ![starts](https://img.shields.io/github/stars/theMcSam/CVE-2024-42471-PoC.svg) ![forks](https://img.shields.io/github/forks/theMcSam/CVE-2024-42471-PoC.svg)


## CVE-2024-12905
This issue affects tar-fs: from 0.0.0 before 1.16.4, from 2.0.0 before 2.1.2, from 3.0.0 before 3.0.8.

- [https://github.com/theMcSam/CVE-2024-12905-PoC](https://github.com/theMcSam/CVE-2024-12905-PoC) :  ![starts](https://img.shields.io/github/stars/theMcSam/CVE-2024-12905-PoC.svg) ![forks](https://img.shields.io/github/forks/theMcSam/CVE-2024-12905-PoC.svg)


## CVE-2024-7120
 A vulnerability, which was classified as critical, was found in Raisecom MSG1200, MSG2100E, MSG2200 and MSG2300 3.90. This affects an unknown part of the file list_base_config.php of the component Web Interface. The manipulation of the argument template leads to os command injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-272451.

- [https://github.com/jokeir07x/CVE-2024-7120-Exploit-by-Dark-07x](https://github.com/jokeir07x/CVE-2024-7120-Exploit-by-Dark-07x) :  ![starts](https://img.shields.io/github/stars/jokeir07x/CVE-2024-7120-Exploit-by-Dark-07x.svg) ![forks](https://img.shields.io/github/forks/jokeir07x/CVE-2024-7120-Exploit-by-Dark-07x.svg)


## CVE-2023-30212
 OURPHP = 7.2.0 is vulnerale to Cross Site Scripting (XSS) via /client/manage/ourphp_out.php.

- [https://github.com/sungmin20/cve-2023-30212](https://github.com/sungmin20/cve-2023-30212) :  ![starts](https://img.shields.io/github/stars/sungmin20/cve-2023-30212.svg) ![forks](https://img.shields.io/github/forks/sungmin20/cve-2023-30212.svg)


## CVE-2023-25157
 GeoServer is an open source software server written in Java that allows users to share and edit geospatial data. GeoServer includes support for the OGC Filter expression language and the OGC Common Query Language (CQL) as part of the Web Feature Service (WFS) and Web Map Service (WMS) protocols.  CQL is also supported through the Web Coverage Service (WCS) protocol for ImageMosaic coverages. Users are advised to upgrade to either version 2.21.4, or version 2.22.2 to resolve this issue. Users unable to upgrade should disable the PostGIS Datastore *encode functions* setting to mitigate ``strEndsWith``, ``strStartsWith`` and ``PropertyIsLike `` misuse and enable the PostGIS DataStore *preparedStatements* setting to mitigate the ``FeatureId`` misuse.

- [https://github.com/charis3306/CVE-2023-25157](https://github.com/charis3306/CVE-2023-25157) :  ![starts](https://img.shields.io/github/stars/charis3306/CVE-2023-25157.svg) ![forks](https://img.shields.io/github/forks/charis3306/CVE-2023-25157.svg)


## CVE-2021-43857
 Gerapy is a distributed crawler management framework. Gerapy prior to version 0.9.8 is vulnerable to remote code execution, and this issue is patched in version 0.9.8.

- [https://github.com/G4sp4rCS/CVE-2021-43857-POC](https://github.com/G4sp4rCS/CVE-2021-43857-POC) :  ![starts](https://img.shields.io/github/stars/G4sp4rCS/CVE-2021-43857-POC.svg) ![forks](https://img.shields.io/github/forks/G4sp4rCS/CVE-2021-43857-POC.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)
- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)


## CVE-2018-15745
 Argus Surveillance DVR 4.0.0.0 devices allow Unauthenticated Directory Traversal, leading to File Disclosure via a ..%2F in the WEBACCOUNT.CGI RESULTPAGE parameter.

- [https://github.com/Jasurbek-Masimov/CVE-2018-15745](https://github.com/Jasurbek-Masimov/CVE-2018-15745) :  ![starts](https://img.shields.io/github/stars/Jasurbek-Masimov/CVE-2018-15745.svg) ![forks](https://img.shields.io/github/forks/Jasurbek-Masimov/CVE-2018-15745.svg)


## CVE-2017-1000170
 jqueryFileTree 2.1.5 and older Directory Traversal

- [https://github.com/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal](https://github.com/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal) :  ![starts](https://img.shields.io/github/stars/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal.svg) ![forks](https://img.shields.io/github/forks/Nickguitar/Jquery-File-Tree-1.6.6-Path-Traversal.svg)


## CVE-2017-11907
 Internet Explorer in Microsoft Windows 7 SP1, Windows Server 2008 and R2 SP1, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold, 1511, 1607, 1703, 1709, and Windows Server 2016 allows an attacker to gain the same user rights as the current user, due to how Internet Explorer handles objects in memory, aka "Scripting Engine Memory Corruption Vulnerability". This CVE ID is unique from CVE-2017-11886, CVE-2017-11889, CVE-2017-11890, CVE-2017-11893, CVE-2017-11894, CVE-2017-11895, CVE-2017-11901, CVE-2017-11903, CVE-2017-11905, CVE-2017-11905, CVE-2017-11908, CVE-2017-11909, CVE-2017-11910, CVE-2017-11911, CVE-2017-11912, CVE-2017-11913, CVE-2017-11914, CVE-2017-11916, CVE-2017-11918, and CVE-2017-11930.

- [https://github.com/AV1080p/CVE-2017-11907](https://github.com/AV1080p/CVE-2017-11907) :  ![starts](https://img.shields.io/github/stars/AV1080p/CVE-2017-11907.svg) ![forks](https://img.shields.io/github/forks/AV1080p/CVE-2017-11907.svg)


## CVE-2017-11826
 Microsoft Office 2010, SharePoint Enterprise Server 2010, SharePoint Server 2010, Web Applications, Office Web Apps Server 2010 and 2013, Word Viewer, Word 2007, 2010, 2013 and 2016, Word Automation Services, and Office Online Server allow remote code execution when the software fails to properly handle objects in memory.

- [https://github.com/thatskriptkid/CVE-2017-11826](https://github.com/thatskriptkid/CVE-2017-11826) :  ![starts](https://img.shields.io/github/stars/thatskriptkid/CVE-2017-11826.svg) ![forks](https://img.shields.io/github/forks/thatskriptkid/CVE-2017-11826.svg)
- [https://github.com/9aylas/DDE-MS_WORD-Exploit_Detector](https://github.com/9aylas/DDE-MS_WORD-Exploit_Detector) :  ![starts](https://img.shields.io/github/stars/9aylas/DDE-MS_WORD-Exploit_Detector.svg) ![forks](https://img.shields.io/github/forks/9aylas/DDE-MS_WORD-Exploit_Detector.svg)


## CVE-2017-11610
 The XML-RPC server in supervisor before 3.0.1, 3.1.x before 3.1.4, 3.2.x before 3.2.4, and 3.3.x before 3.3.3 allows remote authenticated users to execute arbitrary commands via a crafted XML-RPC request, related to nested supervisord namespace lookups.

- [https://github.com/yaunsky/CVE-2017-11610](https://github.com/yaunsky/CVE-2017-11610) :  ![starts](https://img.shields.io/github/stars/yaunsky/CVE-2017-11610.svg) ![forks](https://img.shields.io/github/forks/yaunsky/CVE-2017-11610.svg)
- [https://github.com/ivanitlearning/CVE-2017-11610](https://github.com/ivanitlearning/CVE-2017-11610) :  ![starts](https://img.shields.io/github/stars/ivanitlearning/CVE-2017-11610.svg) ![forks](https://img.shields.io/github/forks/ivanitlearning/CVE-2017-11610.svg)


## CVE-2017-11104
 Knot DNS before 2.4.5 and 2.5.x before 2.5.2 contains a flaw within the TSIG protocol implementation that would allow an attacker with a valid key name and algorithm to bypass TSIG authentication if no additional ACL restrictions are set, because of an improper TSIG validity period check.

- [https://github.com/saaph/CVE-2017-3143](https://github.com/saaph/CVE-2017-3143) :  ![starts](https://img.shields.io/github/stars/saaph/CVE-2017-3143.svg) ![forks](https://img.shields.io/github/forks/saaph/CVE-2017-3143.svg)


## CVE-2017-7529
 Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.

- [https://github.com/en0f/CVE-2017-7529_PoC](https://github.com/en0f/CVE-2017-7529_PoC) :  ![starts](https://img.shields.io/github/stars/en0f/CVE-2017-7529_PoC.svg) ![forks](https://img.shields.io/github/forks/en0f/CVE-2017-7529_PoC.svg)
- [https://github.com/liusec/CVE-2017-7529](https://github.com/liusec/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/liusec/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/liusec/CVE-2017-7529.svg)
- [https://github.com/gemboxteam/exploit-nginx-1.10.3](https://github.com/gemboxteam/exploit-nginx-1.10.3) :  ![starts](https://img.shields.io/github/stars/gemboxteam/exploit-nginx-1.10.3.svg) ![forks](https://img.shields.io/github/forks/gemboxteam/exploit-nginx-1.10.3.svg)
- [https://github.com/Shehzadcyber/CVE-2017-7529](https://github.com/Shehzadcyber/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/Shehzadcyber/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/Shehzadcyber/CVE-2017-7529.svg)
- [https://github.com/MaxSecurity/CVE-2017-7529-POC](https://github.com/MaxSecurity/CVE-2017-7529-POC) :  ![starts](https://img.shields.io/github/stars/MaxSecurity/CVE-2017-7529-POC.svg) ![forks](https://img.shields.io/github/forks/MaxSecurity/CVE-2017-7529-POC.svg)
- [https://github.com/cyberharsh/nginx-CVE-2017-7529](https://github.com/cyberharsh/nginx-CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/cyberharsh/nginx-CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/cyberharsh/nginx-CVE-2017-7529.svg)
- [https://github.com/mo3zj/Nginx-Remote-Integer-Overflow-Vulnerability](https://github.com/mo3zj/Nginx-Remote-Integer-Overflow-Vulnerability) :  ![starts](https://img.shields.io/github/stars/mo3zj/Nginx-Remote-Integer-Overflow-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/mo3zj/Nginx-Remote-Integer-Overflow-Vulnerability.svg)
- [https://github.com/cved-sources/cve-2017-7529](https://github.com/cved-sources/cve-2017-7529) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-7529.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-7529.svg)
- [https://github.com/Fenil2511/CVE-2017-7529-POC](https://github.com/Fenil2511/CVE-2017-7529-POC) :  ![starts](https://img.shields.io/github/stars/Fenil2511/CVE-2017-7529-POC.svg) ![forks](https://img.shields.io/github/forks/Fenil2511/CVE-2017-7529-POC.svg)
- [https://github.com/CalebFIN/EXP-CVE-2017-75](https://github.com/CalebFIN/EXP-CVE-2017-75) :  ![starts](https://img.shields.io/github/stars/CalebFIN/EXP-CVE-2017-75.svg) ![forks](https://img.shields.io/github/forks/CalebFIN/EXP-CVE-2017-75.svg)
- [https://github.com/cyberk1w1/CVE-2017-7529](https://github.com/cyberk1w1/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/cyberk1w1/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/cyberk1w1/CVE-2017-7529.svg)
- [https://github.com/SirEagIe/CVE-2017-7529](https://github.com/SirEagIe/CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/SirEagIe/CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/SirEagIe/CVE-2017-7529.svg)
- [https://github.com/youngmin0104/CVE-2017-7529-](https://github.com/youngmin0104/CVE-2017-7529-) :  ![starts](https://img.shields.io/github/stars/youngmin0104/CVE-2017-7529-.svg) ![forks](https://img.shields.io/github/forks/youngmin0104/CVE-2017-7529-.svg)
- [https://github.com/coolman6942o/-Exploit-CVE-2017-7529](https://github.com/coolman6942o/-Exploit-CVE-2017-7529) :  ![starts](https://img.shields.io/github/stars/coolman6942o/-Exploit-CVE-2017-7529.svg) ![forks](https://img.shields.io/github/forks/coolman6942o/-Exploit-CVE-2017-7529.svg)
- [https://github.com/daehee/nginx-overflow](https://github.com/daehee/nginx-overflow) :  ![starts](https://img.shields.io/github/stars/daehee/nginx-overflow.svg) ![forks](https://img.shields.io/github/forks/daehee/nginx-overflow.svg)
- [https://github.com/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit](https://github.com/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit) :  ![starts](https://img.shields.io/github/stars/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit.svg) ![forks](https://img.shields.io/github/forks/fu2x2000/CVE-2017-7529-Nginx---Remote-Integer-Overflow-Exploit.svg)
- [https://github.com/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability](https://github.com/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability) :  ![starts](https://img.shields.io/github/stars/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/fardeen-ahmed/Remote-Integer-Overflow-Vulnerability.svg)
- [https://github.com/devansh3008/Cve_Finder_2017-7529](https://github.com/devansh3008/Cve_Finder_2017-7529) :  ![starts](https://img.shields.io/github/stars/devansh3008/Cve_Finder_2017-7529.svg) ![forks](https://img.shields.io/github/forks/devansh3008/Cve_Finder_2017-7529.svg)


## CVE-2017-7472
 The KEYS subsystem in the Linux kernel before 4.10.13 allows local users to cause a denial of service (memory consumption) via a series of KEY_REQKEY_DEFL_THREAD_KEYRING keyctl_set_reqkey_keyring calls.

- [https://github.com/homjxi0e/CVE-2017-7472](https://github.com/homjxi0e/CVE-2017-7472) :  ![starts](https://img.shields.io/github/stars/homjxi0e/CVE-2017-7472.svg) ![forks](https://img.shields.io/github/forks/homjxi0e/CVE-2017-7472.svg)


## CVE-2017-4971
 An issue was discovered in Pivotal Spring Web Flow through 2.4.4. Applications that do not change the value of the MvcViewFactoryCreator useSpringBinding property which is disabled by default (i.e., set to 'false') can be vulnerable to malicious EL expressions in view states that process form submissions but do not have a sub-element to declare explicit data binding property mappings.

- [https://github.com/cved-sources/cve-2017-4971](https://github.com/cved-sources/cve-2017-4971) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2017-4971.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2017-4971.svg)


## CVE-2016-3116
 CRLF injection vulnerability in Dropbear SSH before 2016.72 allows remote authenticated users to bypass intended shell-command restrictions via crafted X11 forwarding data.

- [https://github.com/tintinweb/pub](https://github.com/tintinweb/pub) :  ![starts](https://img.shields.io/github/stars/tintinweb/pub.svg) ![forks](https://img.shields.io/github/forks/tintinweb/pub.svg)
- [https://github.com/mxypoo/CVE-2016-3116-DropbearSSH](https://github.com/mxypoo/CVE-2016-3116-DropbearSSH) :  ![starts](https://img.shields.io/github/stars/mxypoo/CVE-2016-3116-DropbearSSH.svg) ![forks](https://img.shields.io/github/forks/mxypoo/CVE-2016-3116-DropbearSSH.svg)


## CVE-2015-8351
 PHP remote file inclusion vulnerability in the Gwolle Guestbook plugin before 1.5.4 for WordPress, when allow_url_include is enabled, allows remote authenticated users to execute arbitrary PHP code via a URL in the abspath parameter to frontend/captcha/ajaxresponse.php.  NOTE: this can also be leveraged to include and execute arbitrary local files via directory traversal sequences regardless of whether allow_url_include is enabled.

- [https://github.com/G4sp4rCS/exploit-CVE-2015-8351](https://github.com/G4sp4rCS/exploit-CVE-2015-8351) :  ![starts](https://img.shields.io/github/stars/G4sp4rCS/exploit-CVE-2015-8351.svg) ![forks](https://img.shields.io/github/forks/G4sp4rCS/exploit-CVE-2015-8351.svg)
- [https://github.com/G01d3nW01f/CVE-2015-8351](https://github.com/G01d3nW01f/CVE-2015-8351) :  ![starts](https://img.shields.io/github/stars/G01d3nW01f/CVE-2015-8351.svg) ![forks](https://img.shields.io/github/forks/G01d3nW01f/CVE-2015-8351.svg)


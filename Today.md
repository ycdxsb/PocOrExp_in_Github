# Update 2024-01-09
## CVE-2024-21633
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/0x33c0unt/CVE-2024-21633](https://github.com/0x33c0unt/CVE-2024-21633) :  ![starts](https://img.shields.io/github/stars/0x33c0unt/CVE-2024-21633.svg) ![forks](https://img.shields.io/github/forks/0x33c0unt/CVE-2024-21633.svg)


## CVE-2023-51467
 The vulnerability allows attackers to bypass authentication to achieve a simple Server-Side Request Forgery (SSRF)

- [https://github.com/UserConnecting/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz](https://github.com/UserConnecting/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz) :  ![starts](https://img.shields.io/github/stars/UserConnecting/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz.svg) ![forks](https://img.shields.io/github/forks/UserConnecting/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz.svg)


## CVE-2023-49070
 Pre-auth RCE in Apache Ofbiz 18.12.09. It's due to XML-RPC no longer maintained still present. This issue affects Apache OFBiz: before 18.12.10. Users are recommended to upgrade to version 18.12.10

- [https://github.com/UserConnecting/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz](https://github.com/UserConnecting/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz) :  ![starts](https://img.shields.io/github/stars/UserConnecting/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz.svg) ![forks](https://img.shields.io/github/forks/UserConnecting/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz.svg)


## CVE-2023-46813
 An issue was discovered in the Linux kernel before 6.5.9, exploitable by local users with userspace access to MMIO registers. Incorrect access checking in the #VC handler and instruction emulation of the SEV-ES emulation of MMIO accesses could lead to arbitrary write access to kernel memory (and thus privilege escalation). This depends on a race condition through which userspace can replace an instruction before the #VC handler reads it.

- [https://github.com/Freax13/cve-2023-46813-poc](https://github.com/Freax13/cve-2023-46813-poc) :  ![starts](https://img.shields.io/github/stars/Freax13/cve-2023-46813-poc.svg) ![forks](https://img.shields.io/github/forks/Freax13/cve-2023-46813-poc.svg)


## CVE-2023-42793
 In JetBrains TeamCity before 2023.05.4 authentication bypass leading to RCE on TeamCity Server was possible

- [https://github.com/johnossawy/CVE-2023-42793_POC](https://github.com/johnossawy/CVE-2023-42793_POC) :  ![starts](https://img.shields.io/github/stars/johnossawy/CVE-2023-42793_POC.svg) ![forks](https://img.shields.io/github/forks/johnossawy/CVE-2023-42793_POC.svg)


## CVE-2023-41991
 A certificate validation issue was addressed. This issue is fixed in macOS Ventura 13.6, iOS 16.7 and iPadOS 16.7. A malicious app may be able to bypass signature validation. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 16.7.

- [https://github.com/Zenyith/CVE-2023-41991](https://github.com/Zenyith/CVE-2023-41991) :  ![starts](https://img.shields.io/github/stars/Zenyith/CVE-2023-41991.svg) ![forks](https://img.shields.io/github/forks/Zenyith/CVE-2023-41991.svg)


## CVE-2023-36844
 A PHP External Variable Modification vulnerability in J-Web of Juniper Networks Junos OS on EX Series allows an unauthenticated, network-based attacker to control certain, important environment variables. Using a crafted request an attacker is able to modify certain PHP environment variables leading to partial loss of integrity, which may allow chaining to other vulnerabilities. This issue affects Juniper Networks Junos OS on EX Series: * All versions prior to 20.4R3-S9; * 21.1 versions 21.1R1 and later; * 21.2 versions prior to 21.2R3-S7; * 21.3 versions prior to 21.3R3-S5; * 21.4 versions prior to 21.4R3-S5; * 22.1 versions prior to 22.1R3-S4; * 22.2 versions prior to 22.2R3-S2; * 22.3 versions prior to 22.3R3-S1; * 22.4 versions prior to 22.4R2-S2, 22.4R3; * 23.2 versions prior to 23.2R1-S1, 23.2R2.

- [https://github.com/watchtowrlabs/juniper-rce_cve-2023-36844](https://github.com/watchtowrlabs/juniper-rce_cve-2023-36844) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/juniper-rce_cve-2023-36844.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/juniper-rce_cve-2023-36844.svg)


## CVE-2023-28432
 Minio is a Multi-Cloud Object Storage framework. In a cluster deployment starting with RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns all environment variables, including `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`, resulting in information disclosure. All users of distributed deployment are impacted. All users are advised to upgrade to RELEASE.2023-03-20T20-16-18Z.

- [https://github.com/netuseradministrator/CVE-2023-28432](https://github.com/netuseradministrator/CVE-2023-28432) :  ![starts](https://img.shields.io/github/stars/netuseradministrator/CVE-2023-28432.svg) ![forks](https://img.shields.io/github/forks/netuseradministrator/CVE-2023-28432.svg)


## CVE-2023-26035
 ZoneMinder is a free, open source Closed-circuit television software application for Linux which supports IP, USB and Analog cameras. Versions prior to 1.36.33 and 1.37.33 are vulnerable to Unauthenticated Remote Code Execution via Missing Authorization. There are no permissions check on the snapshot action, which expects an id to fetch an existing monitor but can be passed an object to create a new one instead. TriggerOn ends up calling shell_exec using the supplied Id. This issue is fixed in This issue is fixed in versions 1.36.33 and 1.37.33.

- [https://github.com/srinathkarli7/CVE-2023-26035-exploit.sh.sh.sh](https://github.com/srinathkarli7/CVE-2023-26035-exploit.sh.sh.sh) :  ![starts](https://img.shields.io/github/stars/srinathkarli7/CVE-2023-26035-exploit.sh.sh.sh.svg) ![forks](https://img.shields.io/github/forks/srinathkarli7/CVE-2023-26035-exploit.sh.sh.sh.svg)


## CVE-2023-3460
 The Ultimate Member WordPress plugin before 2.6.7 does not prevent visitors from creating user accounts with arbitrary capabilities, effectively allowing attackers to create administrator accounts at will. This is actively being exploited in the wild.

- [https://github.com/EmadYaY/CVE-2023-3460](https://github.com/EmadYaY/CVE-2023-3460) :  ![starts](https://img.shields.io/github/stars/EmadYaY/CVE-2023-3460.svg) ![forks](https://img.shields.io/github/forks/EmadYaY/CVE-2023-3460.svg)
- [https://github.com/ollie-blue/CVE_2023_3460](https://github.com/ollie-blue/CVE_2023_3460) :  ![starts](https://img.shields.io/github/stars/ollie-blue/CVE_2023_3460.svg) ![forks](https://img.shields.io/github/forks/ollie-blue/CVE_2023_3460.svg)


## CVE-2022-45481
 The default configuration of Lazy Mouse does not require a password, allowing remote unauthenticated users to execute arbitrary code with no prior authorization or authentication. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

- [https://github.com/M507/nmap-vulnerability-scan-scripts](https://github.com/M507/nmap-vulnerability-scan-scripts) :  ![starts](https://img.shields.io/github/stars/M507/nmap-vulnerability-scan-scripts.svg) ![forks](https://img.shields.io/github/forks/M507/nmap-vulnerability-scan-scripts.svg)


## CVE-2022-23046
 PhpIPAM v1.4.4 allows an authenticated admin user to inject SQL sentences in the &quot;subnet&quot; parameter while searching a subnet via app/admin/routing/edit-bgp-mapping-search.php

- [https://github.com/bernauers/CVE-2022-23046](https://github.com/bernauers/CVE-2022-23046) :  ![starts](https://img.shields.io/github/stars/bernauers/CVE-2022-23046.svg) ![forks](https://img.shields.io/github/forks/bernauers/CVE-2022-23046.svg)


## CVE-2022-21350
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of Oracle WebLogic Server. CVSS 3.1 Base Score 6.5 (Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L).

- [https://github.com/hktalent/CVE-2022-21350](https://github.com/hktalent/CVE-2022-21350) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE-2022-21350.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE-2022-21350.svg)


## CVE-2022-1386
 The Fusion Builder WordPress plugin before 3.6.2, used in the Avada theme, does not validate a parameter in its forms which could be used to initiate arbitrary HTTP requests. The data returned is then reflected back in the application's response. This could be used to interact with hosts on the server's local network bypassing firewalls and access control measures.

- [https://github.com/imhunterand/CVE-2022-1386](https://github.com/imhunterand/CVE-2022-1386) :  ![starts](https://img.shields.io/github/stars/imhunterand/CVE-2022-1386.svg) ![forks](https://img.shields.io/github/forks/imhunterand/CVE-2022-1386.svg)


## CVE-2021-44142
 The Samba vfs_fruit module uses extended file attributes (EA, xattr) to provide &quot;...enhanced compatibility with Apple SMB clients and interoperability with a Netatalk 3 AFP fileserver.&quot; Samba versions prior to 4.13.17, 4.14.12 and 4.15.5 with vfs_fruit configured allow out-of-bounds heap read and write via specially crafted extended file attributes. A remote attacker with write access to extended file attributes can execute arbitrary code with the privileges of smbd, typically root.

- [https://github.com/horizon3ai/CVE-2021-44142](https://github.com/horizon3ai/CVE-2021-44142) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2021-44142.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2021-44142.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/imhunterand/CVE-2021-42013](https://github.com/imhunterand/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/imhunterand/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/imhunterand/CVE-2021-42013.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)
- [https://github.com/MatanelGordon/docker-cve-2021-41773](https://github.com/MatanelGordon/docker-cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/MatanelGordon/docker-cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/MatanelGordon/docker-cve-2021-41773.svg)
- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)


## CVE-2020-2883
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/zhzyker/exphub](https://github.com/zhzyker/exphub) :  ![starts](https://img.shields.io/github/stars/zhzyker/exphub.svg) ![forks](https://img.shields.io/github/forks/zhzyker/exphub.svg)


## CVE-2019-12086
 A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x before 2.9.9. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint, the service has the mysql-connector-java jar (8.0.14 or earlier) in the classpath, and an attacker can host a crafted MySQL server reachable by the victim, an attacker can send a crafted JSON message that allows them to read arbitrary local files on the server. This occurs because of missing com.mysql.cj.jdbc.admin.MiniAdmin validation.

- [https://github.com/Al1ex/CVE-2019-12086](https://github.com/Al1ex/CVE-2019-12086) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2019-12086.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2019-12086.svg)


## CVE-2019-9978
 The social-warfare plugin before 3.5.3 for WordPress has stored XSS via the wp-admin/admin-post.php?swp_debug=load_options swp_url parameter, as exploited in the wild in March 2019. This affects Social Warfare and Social Warfare Pro.

- [https://github.com/cved-sources/cve-2019-9978](https://github.com/cved-sources/cve-2019-9978) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2019-9978.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2019-9978.svg)


## CVE-2009-0473
 Open redirect vulnerability in the web interface in the Rockwell Automation ControlLogix 1756-ENBT/A EtherNet/IP Bridge Module allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via unspecified vectors.

- [https://github.com/akbarq/CVE-2009-0473-check](https://github.com/akbarq/CVE-2009-0473-check) :  ![starts](https://img.shields.io/github/stars/akbarq/CVE-2009-0473-check.svg) ![forks](https://img.shields.io/github/forks/akbarq/CVE-2009-0473-check.svg)


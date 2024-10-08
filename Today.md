# Update 2024-10-08
## CVE-2024-4627
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ayato-shitomi/CVE-2024-46278-teedy_1.11_account-takeover](https://github.com/ayato-shitomi/CVE-2024-46278-teedy_1.11_account-takeover) :  ![starts](https://img.shields.io/github/stars/ayato-shitomi/CVE-2024-46278-teedy_1.11_account-takeover.svg) ![forks](https://img.shields.io/github/forks/ayato-shitomi/CVE-2024-46278-teedy_1.11_account-takeover.svg)


## CVE-2023-22527
 A template injection vulnerability on older versions of Confluence Data Center and Server allows an unauthenticated attacker to achieve RCE on an affected instance. Customers using an affected version must take immediate action. Most recent supported versions of Confluence Data Center and Server are not affected by this vulnerability as it was ultimately mitigated during regular version updates. However, Atlassian recommends that customers take care to install the latest version to protect their instances from non-critical vulnerabilities outlined in Atlassian&#8217;s January Security Bulletin.

- [https://github.com/kh4sh3i/CVE-2023-22527](https://github.com/kh4sh3i/CVE-2023-22527) :  ![starts](https://img.shields.io/github/stars/kh4sh3i/CVE-2023-22527.svg) ![forks](https://img.shields.io/github/forks/kh4sh3i/CVE-2023-22527.svg)


## CVE-2019-9193
 ** DISPUTED ** In PostgreSQL 9.3 through 11.2, the &quot;COPY TO/FROM PROGRAM&quot; function allows superusers and users in the 'pg_execute_server_program' group to execute arbitrary code in the context of the database's operating system user. This functionality is enabled by default and can be abused to run arbitrary operating system commands on Windows, Linux, and macOS. NOTE: Third parties claim/state this is not an issue because PostgreSQL functionality for &#8216;COPY TO/FROM PROGRAM&#8217; is acting as intended. References state that in PostgreSQL, a superuser can execute commands as the server user without using the &#8216;COPY FROM PROGRAM&#8217;.

- [https://github.com/geniuszlyy/CVE-2019-9193](https://github.com/geniuszlyy/CVE-2019-9193) :  ![starts](https://img.shields.io/github/stars/geniuszlyy/CVE-2019-9193.svg) ![forks](https://img.shields.io/github/forks/geniuszlyy/CVE-2019-9193.svg)
- [https://github.com/AxthonyV/CVE-2019-9193](https://github.com/AxthonyV/CVE-2019-9193) :  ![starts](https://img.shields.io/github/stars/AxthonyV/CVE-2019-9193.svg) ![forks](https://img.shields.io/github/forks/AxthonyV/CVE-2019-9193.svg)
- [https://github.com/A0be/CVE-2019-9193](https://github.com/A0be/CVE-2019-9193) :  ![starts](https://img.shields.io/github/stars/A0be/CVE-2019-9193.svg) ![forks](https://img.shields.io/github/forks/A0be/CVE-2019-9193.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/likekabin/CVE-2019-5736](https://github.com/likekabin/CVE-2019-5736) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2019-5736.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2019-5736.svg)
- [https://github.com/likekabin/cve-2019-5736-poc](https://github.com/likekabin/cve-2019-5736-poc) :  ![starts](https://img.shields.io/github/stars/likekabin/cve-2019-5736-poc.svg) ![forks](https://img.shields.io/github/forks/likekabin/cve-2019-5736-poc.svg)


## CVE-2019-1253
 An elevation of privilege vulnerability exists when the Windows AppX Deployment Server improperly handles junctions.To exploit this vulnerability, an attacker would first have to gain execution on the victim system, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-1215, CVE-2019-1278, CVE-2019-1303.

- [https://github.com/likekabin/CVE-2019-1253](https://github.com/likekabin/CVE-2019-1253) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2019-1253.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2019-1253.svg)


## CVE-2019-0841
 An elevation of privilege vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links, aka 'Windows Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2019-0730, CVE-2019-0731, CVE-2019-0796, CVE-2019-0805, CVE-2019-0836.

- [https://github.com/likekabin/CVE-2019-0841](https://github.com/likekabin/CVE-2019-0841) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2019-0841.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2019-0841.svg)


## CVE-2019-0604
 A remote code execution vulnerability exists in Microsoft SharePoint when the software fails to check the source markup of an application package, aka 'Microsoft SharePoint Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-0594.

- [https://github.com/likekabin/CVE-2019-0604_sharepoint_CVE](https://github.com/likekabin/CVE-2019-0604_sharepoint_CVE) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2019-0604_sharepoint_CVE.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2019-0604_sharepoint_CVE.svg)


## CVE-2018-20250
 In WinRAR versions prior to and including 5.61, There is path traversal vulnerability when crafting the filename field of the ACE format (in UNACEV2.dll). When the filename field is manipulated with specific patterns, the destination (extraction) folder is ignored, thus treating the filename as an absolute path.

- [https://github.com/likekabin/CVE-2018-20250](https://github.com/likekabin/CVE-2018-20250) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2018-20250.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2018-20250.svg)


## CVE-2018-17182
 An issue was discovered in the Linux kernel through 4.18.8. The vmacache_flush_all function in mm/vmacache.c mishandles sequence number overflows. An attacker can trigger a use-after-free (and possibly gain privileges) via certain thread creation, map, unmap, invalidation, and dereference operations.

- [https://github.com/likekabin/vmacache_CVE-2018-17182](https://github.com/likekabin/vmacache_CVE-2018-17182) :  ![starts](https://img.shields.io/github/stars/likekabin/vmacache_CVE-2018-17182.svg) ![forks](https://img.shields.io/github/forks/likekabin/vmacache_CVE-2018-17182.svg)
- [https://github.com/likekabin/CVE-2018-17182](https://github.com/likekabin/CVE-2018-17182) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2018-17182.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2018-17182.svg)


## CVE-2018-10933
 A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.

- [https://github.com/likekabin/CVE-2018-10933-libSSH-Authentication-Bypass](https://github.com/likekabin/CVE-2018-10933-libSSH-Authentication-Bypass) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2018-10933-libSSH-Authentication-Bypass.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2018-10933-libSSH-Authentication-Bypass.svg)
- [https://github.com/likekabin/CVE-2018-10933_ssh](https://github.com/likekabin/CVE-2018-10933_ssh) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2018-10933_ssh.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2018-10933_ssh.svg)


## CVE-2018-8174
 A remote code execution vulnerability exists in the way that the VBScript engine handles objects in memory, aka &quot;Windows VBScript Engine Remote Code Execution Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.

- [https://github.com/likekabin/CVE-2018-8174-msf](https://github.com/likekabin/CVE-2018-8174-msf) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2018-8174-msf.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2018-8174-msf.svg)


## CVE-2018-4121
 An issue was discovered in certain Apple products. iOS before 11.3 is affected. Safari before 11.1 is affected. iCloud before 7.4 on Windows is affected. iTunes before 12.7.4 on Windows is affected. tvOS before 11.3 is affected. watchOS before 4.3 is affected. The issue involves the &quot;WebKit&quot; component. It allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) via a crafted web site.

- [https://github.com/likekabin/CVE-2018-4121](https://github.com/likekabin/CVE-2018-4121) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2018-4121.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2018-4121.svg)


## CVE-2018-2628
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/likekabin/CVE-2018-2628](https://github.com/likekabin/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2018-2628.svg)


## CVE-2018-0802
 Equation Editor in Microsoft Office 2007, Microsoft Office 2010, Microsoft Office 2013, and Microsoft Office 2016 allow a remote code execution vulnerability due to the way objects are handled in memory, aka &quot;Microsoft Office Memory Corruption Vulnerability&quot;. This CVE is unique from CVE-2018-0797 and CVE-2018-0812.

- [https://github.com/likekabin/CVE-2018-0802_CVE-2017-11882](https://github.com/likekabin/CVE-2018-0802_CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2018-0802_CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2018-0802_CVE-2017-11882.svg)


## CVE-2017-11882
 Microsoft Office 2007 Service Pack 3, Microsoft Office 2010 Service Pack 2, Microsoft Office 2013 Service Pack 1, and Microsoft Office 2016 allow an attacker to run arbitrary code in the context of the current user by failing to properly handle objects in memory, aka &quot;Microsoft Office Memory Corruption Vulnerability&quot;. This CVE ID is unique from CVE-2017-11884.

- [https://github.com/likekabin/CVE-2018-0802_CVE-2017-11882](https://github.com/likekabin/CVE-2018-0802_CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2018-0802_CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2018-0802_CVE-2017-11882.svg)
- [https://github.com/likekabin/CVE-2017-11882](https://github.com/likekabin/CVE-2017-11882) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2017-11882.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2017-11882.svg)


## CVE-2017-7269
 Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with &quot;If: &lt;http://&quot; in a PROPFIND request, as exploited in the wild in July or August 2016.

- [https://github.com/geniuszlyy/CVE-2017-7269](https://github.com/geniuszlyy/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/geniuszlyy/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/geniuszlyy/CVE-2017-7269.svg)
- [https://github.com/AxthonyV/CVE-2017-7269](https://github.com/AxthonyV/CVE-2017-7269) :  ![starts](https://img.shields.io/github/stars/AxthonyV/CVE-2017-7269.svg) ![forks](https://img.shields.io/github/forks/AxthonyV/CVE-2017-7269.svg)


## CVE-2017-0541
 A remote code execution vulnerability in sonivox in Mediaserver could enable an attacker using a specially crafted file to cause memory corruption during media file and data processing. This issue is rated as Critical due to the possibility of remote code execution within the context of the Mediaserver process. Product: Android. Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-34031018.

- [https://github.com/likekabin/CVE-2017-0541](https://github.com/likekabin/CVE-2017-0541) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2017-0541.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2017-0541.svg)


## CVE-2017-0478
 A remote code execution vulnerability in the Framesequence library could enable an attacker using a specially crafted file to execute arbitrary code in the context of an unprivileged process. This issue is rated as High due to the possibility of remote code execution in an application that uses the Framesequence library. Product: Android. Versions: 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1. Android ID: A-33718716.

- [https://github.com/likekabin/CVE-2017-0478](https://github.com/likekabin/CVE-2017-0478) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2017-0478.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2017-0478.svg)


## CVE-2017-0213
 Windows COM Aggregate Marshaler in Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 Gold, 1511, 1607, and 1703, and Windows Server 2016 allows an elevation privilege vulnerability when an attacker runs a specially crafted application, aka &quot;Windows COM Elevation of Privilege Vulnerability&quot;. This CVE ID is unique from CVE-2017-0214.

- [https://github.com/likekabin/CVE-2017-0213](https://github.com/likekabin/CVE-2017-0213) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2017-0213.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2017-0213.svg)


## CVE-2017-0199
 Microsoft Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1 allow remote attackers to execute arbitrary code via a crafted document, aka &quot;Microsoft Office/WordPad Remote Code Execution Vulnerability w/Windows API.&quot;

- [https://github.com/likekabin/CVE-2017-0199](https://github.com/likekabin/CVE-2017-0199) :  ![starts](https://img.shields.io/github/stars/likekabin/CVE-2017-0199.svg) ![forks](https://img.shields.io/github/forks/likekabin/CVE-2017-0199.svg)


## CVE-2015-5477
 named in ISC BIND 9.x before 9.9.7-P2 and 9.10.x before 9.10.2-P3 allows remote attackers to cause a denial of service (REQUIRE assertion failure and daemon exit) via TKEY queries.

- [https://github.com/likekabin/ShareDoc_cve-2015-5477](https://github.com/likekabin/ShareDoc_cve-2015-5477) :  ![starts](https://img.shields.io/github/stars/likekabin/ShareDoc_cve-2015-5477.svg) ![forks](https://img.shields.io/github/forks/likekabin/ShareDoc_cve-2015-5477.svg)


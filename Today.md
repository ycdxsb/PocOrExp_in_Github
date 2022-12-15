# Update 2022-12-15
## CVE-2022-45771
 An issue in the /api/audits component of Pwndoc v0.5.3 allows attackers to escalate privileges and execute arbitrary code via uploading a crafted audit file.

- [https://github.com/p0dalirius/CVE-2022-45771-Pwndoc-LFI-to-RCE](https://github.com/p0dalirius/CVE-2022-45771-Pwndoc-LFI-to-RCE) :  ![starts](https://img.shields.io/github/stars/p0dalirius/CVE-2022-45771-Pwndoc-LFI-to-RCE.svg) ![forks](https://img.shields.io/github/forks/p0dalirius/CVE-2022-45771-Pwndoc-LFI-to-RCE.svg)


## CVE-2022-41717
 An attacker can cause excessive memory growth in a Go server accepting HTTP/2 requests. HTTP/2 server connections contain a cache of HTTP header keys sent by the client. While the total number of entries in this cache is capped, an attacker sending very large keys can cause the server to allocate approximately 64 MiB per open connection.

- [https://github.com/domdom82/h2conn-exploit](https://github.com/domdom82/h2conn-exploit) :  ![starts](https://img.shields.io/github/stars/domdom82/h2conn-exploit.svg) ![forks](https://img.shields.io/github/forks/domdom82/h2conn-exploit.svg)


## CVE-2022-41272
 An unauthenticated attacker over the network can attach to an open interface exposed through JNDI by the User Defined Search (UDS) of SAP NetWeaver Process Integration (PI) - version 7.50 and make use of an open naming and directory API to access services which can be used to perform unauthorized operations affecting users and data across the entire system. This allows the attacker to have full read access to user data, make limited modifications to user data, and degrade the performance of the system, leading to a high impact on confidentiality and a limited impact on the availability and integrity of the application.

- [https://github.com/redrays-io/CVE-2022-41272](https://github.com/redrays-io/CVE-2022-41272) :  ![starts](https://img.shields.io/github/stars/redrays-io/CVE-2022-41272.svg) ![forks](https://img.shields.io/github/forks/redrays-io/CVE-2022-41272.svg)


## CVE-2022-3786
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed a malicious certificate or for an application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects.

- [https://github.com/plharraud/cve-2022-3786](https://github.com/plharraud/cve-2022-3786) :  ![starts](https://img.shields.io/github/stars/plharraud/cve-2022-3786.svg) ![forks](https://img.shields.io/github/forks/plharraud/cve-2022-3786.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/YourKeeper/SunScope](https://github.com/YourKeeper/SunScope) :  ![starts](https://img.shields.io/github/stars/YourKeeper/SunScope.svg) ![forks](https://img.shields.io/github/forks/YourKeeper/SunScope.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)


## CVE-2021-26865
 Windows Container Execution Agent Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-26891.

- [https://github.com/34zY/APT-Backpack](https://github.com/34zY/APT-Backpack) :  ![starts](https://img.shields.io/github/stars/34zY/APT-Backpack.svg) ![forks](https://img.shields.io/github/forks/34zY/APT-Backpack.svg)


## CVE-2021-26858
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26857, CVE-2021-27065, CVE-2021-27078.

- [https://github.com/34zY/APT-Backpack](https://github.com/34zY/APT-Backpack) :  ![starts](https://img.shields.io/github/stars/34zY/APT-Backpack.svg) ![forks](https://img.shields.io/github/forks/34zY/APT-Backpack.svg)


## CVE-2021-26857
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.

- [https://github.com/34zY/APT-Backpack](https://github.com/34zY/APT-Backpack) :  ![starts](https://img.shields.io/github/stars/34zY/APT-Backpack.svg) ![forks](https://img.shields.io/github/forks/34zY/APT-Backpack.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.

- [https://github.com/34zY/APT-Backpack](https://github.com/34zY/APT-Backpack) :  ![starts](https://img.shields.io/github/stars/34zY/APT-Backpack.svg) ![forks](https://img.shields.io/github/forks/34zY/APT-Backpack.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/34zY/APT-Backpack](https://github.com/34zY/APT-Backpack) :  ![starts](https://img.shields.io/github/stars/34zY/APT-Backpack.svg) ![forks](https://img.shields.io/github/forks/34zY/APT-Backpack.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/34zY/APT-Backpack](https://github.com/34zY/APT-Backpack) :  ![starts](https://img.shields.io/github/stars/34zY/APT-Backpack.svg) ![forks](https://img.shields.io/github/forks/34zY/APT-Backpack.svg)


## CVE-2021-22006
 The vCenter Server contains a reverse proxy bypass vulnerability due to the way the endpoints handle the URI. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to access restricted endpoints.

- [https://github.com/34zY/APT-Backpack](https://github.com/34zY/APT-Backpack) :  ![starts](https://img.shields.io/github/stars/34zY/APT-Backpack.svg) ![forks](https://img.shields.io/github/forks/34zY/APT-Backpack.svg)


## CVE-2021-20090
 A path traversal vulnerability in the web interfaces of Buffalo WSR-2533DHPL2 firmware version &lt;= 1.02 and WSR-2533DHP3 firmware version &lt;= 1.24 could allow unauthenticated remote attackers to bypass authentication.

- [https://github.com/34zY/APT-Backpack](https://github.com/34zY/APT-Backpack) :  ![starts](https://img.shields.io/github/stars/34zY/APT-Backpack.svg) ![forks](https://img.shields.io/github/forks/34zY/APT-Backpack.svg)


## CVE-2021-1497
 Multiple vulnerabilities in the web-based management interface of Cisco HyperFlex HX could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device. For more information about these vulnerabilities, see the Details section of this advisory.

- [https://github.com/34zY/APT-Backpack](https://github.com/34zY/APT-Backpack) :  ![starts](https://img.shields.io/github/stars/34zY/APT-Backpack.svg) ![forks](https://img.shields.io/github/forks/34zY/APT-Backpack.svg)


## CVE-2019-10220
 Linux kernel CIFS implementation, version 4.9.0 is vulnerable to a relative paths injection in directory entry lists.

- [https://github.com/Trinadh465/linux_3.0.35_CVE-2019-10220](https://github.com/Trinadh465/linux_3.0.35_CVE-2019-10220) :  ![starts](https://img.shields.io/github/stars/Trinadh465/linux_3.0.35_CVE-2019-10220.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/linux_3.0.35_CVE-2019-10220.svg)
- [https://github.com/Trinadh465/linux-4.19.72_CVE-2019-10220](https://github.com/Trinadh465/linux-4.19.72_CVE-2019-10220) :  ![starts](https://img.shields.io/github/stars/Trinadh465/linux-4.19.72_CVE-2019-10220.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/linux-4.19.72_CVE-2019-10220.svg)


## CVE-2018-25032
 zlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many distant matches.

- [https://github.com/Satheesh575555/external_zlib-1.2.7_CVE-2018-25032](https://github.com/Satheesh575555/external_zlib-1.2.7_CVE-2018-25032) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/external_zlib-1.2.7_CVE-2018-25032.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/external_zlib-1.2.7_CVE-2018-25032.svg)


# Update 2023-06-17
## CVE-2023-34362
 In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements. NOTE: this is exploited in the wild in May and June 2023; exploitation of unpatched systems can occur via HTTP or HTTPS. All versions (e.g., 2020.0 and 2019x) before the five explicitly mentioned versions are affected, including older unsupported versions.

- [https://github.com/sickthecat/CVE-2023-34362](https://github.com/sickthecat/CVE-2023-34362) :  ![starts](https://img.shields.io/github/stars/sickthecat/CVE-2023-34362.svg) ![forks](https://img.shields.io/github/forks/sickthecat/CVE-2023-34362.svg)
- [https://github.com/kenbuckler/MOVEit-CVE-2023-34362](https://github.com/kenbuckler/MOVEit-CVE-2023-34362) :  ![starts](https://img.shields.io/github/stars/kenbuckler/MOVEit-CVE-2023-34362.svg) ![forks](https://img.shields.io/github/forks/kenbuckler/MOVEit-CVE-2023-34362.svg)


## CVE-2023-27997
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS version 7.2.4 and below, version 7.0.11 and below, version 6.4.12 and below, version 6.0.16 and below and FortiProxy version 7.2.3 and below, version 7.0.9 and below, version 2.0.12 and below, version 1.2 all versions, version 1.1 all versions SSL-VPN may allow a remote attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/Pik-sec/cve-2023-27997](https://github.com/Pik-sec/cve-2023-27997) :  ![starts](https://img.shields.io/github/stars/Pik-sec/cve-2023-27997.svg) ![forks](https://img.shields.io/github/forks/Pik-sec/cve-2023-27997.svg)
- [https://github.com/rio128128/CVE-2023-27997-POC](https://github.com/rio128128/CVE-2023-27997-POC) :  ![starts](https://img.shields.io/github/stars/rio128128/CVE-2023-27997-POC.svg) ![forks](https://img.shields.io/github/forks/rio128128/CVE-2023-27997-POC.svg)


## CVE-2023-1829
 A use-after-free vulnerability in the Linux Kernel traffic control index filter (tcindex) can be exploited to achieve local privilege escalation. The tcindex_delete function which does not properly deactivate filters in case of a perfect hashes while deleting the underlying structure which can later lead to double freeing the structure. A local attacker user can use this vulnerability to elevate its privileges to root. We recommend upgrading past commit 8c710f75256bb3cf05ac7b1672c82b92c43f3d28.

- [https://github.com/lanleft/CVE2023-1829](https://github.com/lanleft/CVE2023-1829) :  ![starts](https://img.shields.io/github/stars/lanleft/CVE2023-1829.svg) ![forks](https://img.shields.io/github/forks/lanleft/CVE2023-1829.svg)


## CVE-2023-0297
 Code Injection in GitHub repository pyload/pyload prior to 0.5.0b3.dev31.

- [https://github.com/overgrowncarrot1/CVE-2023-0297](https://github.com/overgrowncarrot1/CVE-2023-0297) :  ![starts](https://img.shields.io/github/stars/overgrowncarrot1/CVE-2023-0297.svg) ![forks](https://img.shields.io/github/forks/overgrowncarrot1/CVE-2023-0297.svg)


## CVE-2022-2586
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/lanleft/CVE2022-2586](https://github.com/lanleft/CVE2022-2586) :  ![starts](https://img.shields.io/github/stars/lanleft/CVE2022-2586.svg) ![forks](https://img.shields.io/github/forks/lanleft/CVE2022-2586.svg)


## CVE-2022-1609
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/realsiao/cve-2022-1609-exploit](https://github.com/realsiao/cve-2022-1609-exploit) :  ![starts](https://img.shields.io/github/stars/realsiao/cve-2022-1609-exploit.svg) ![forks](https://img.shields.io/github/forks/realsiao/cve-2022-1609-exploit.svg)


## CVE-2022-1011
 A use-after-free flaw was found in the Linux kernel&#8217;s FUSE filesystem in the way a user triggers write(). This flaw allows a local user to gain unauthorized access to data from the FUSE filesystem, resulting in privilege escalation.

- [https://github.com/xkaneiki/CVE-2022-1011](https://github.com/xkaneiki/CVE-2022-1011) :  ![starts](https://img.shields.io/github/stars/xkaneiki/CVE-2022-1011.svg) ![forks](https://img.shields.io/github/forks/xkaneiki/CVE-2022-1011.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-24647
 The Registration Forms &#8211; User profile, Content Restriction, Spam Protection, Payment Gateways, Invitation Codes WordPress plugin before 3.1.7.6 has a flaw in the social login implementation, allowing unauthenticated attacker to login as any user on the site by only knowing their user ID or username

- [https://github.com/RandomRobbieBF/CVE-2021-24647](https://github.com/RandomRobbieBF/CVE-2021-24647) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2021-24647.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2021-24647.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/kukudechen-chen/cve-2020-1938](https://github.com/kukudechen-chen/cve-2020-1938) :  ![starts](https://img.shields.io/github/stars/kukudechen-chen/cve-2020-1938.svg) ![forks](https://img.shields.io/github/forks/kukudechen-chen/cve-2020-1938.svg)


## CVE-2016-2386
 SQL injection vulnerability in the UDDI server in SAP NetWeaver J2EE Engine 7.40 allows remote attackers to execute arbitrary SQL commands via unspecified vectors, aka SAP Security Note 2101079.

- [https://github.com/murataydemir/CVE-2016-2386](https://github.com/murataydemir/CVE-2016-2386) :  ![starts](https://img.shields.io/github/stars/murataydemir/CVE-2016-2386.svg) ![forks](https://img.shields.io/github/forks/murataydemir/CVE-2016-2386.svg)


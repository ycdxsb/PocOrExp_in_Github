# Update 2023-08-08
## CVE-2023-22809
 In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a &quot;--&quot; argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.

- [https://github.com/Toothless5143/CVE-2023-22809](https://github.com/Toothless5143/CVE-2023-22809) :  ![starts](https://img.shields.io/github/stars/Toothless5143/CVE-2023-22809.svg) ![forks](https://img.shields.io/github/forks/Toothless5143/CVE-2023-22809.svg)


## CVE-2023-3519
 Unauthenticated remote code execution

- [https://github.com/rwincey/cve-2023-3519](https://github.com/rwincey/cve-2023-3519) :  ![starts](https://img.shields.io/github/stars/rwincey/cve-2023-3519.svg) ![forks](https://img.shields.io/github/forks/rwincey/cve-2023-3519.svg)


## CVE-2022-21445
 Vulnerability in the Oracle JDeveloper product of Oracle Fusion Middleware (component: ADF Faces). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle JDeveloper. Successful attacks of this vulnerability can result in takeover of Oracle JDeveloper. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/StevenMeow/CVE-2022-21445](https://github.com/StevenMeow/CVE-2022-21445) :  ![starts](https://img.shields.io/github/stars/StevenMeow/CVE-2022-21445.svg) ![forks](https://img.shields.io/github/forks/StevenMeow/CVE-2022-21445.svg)


## CVE-2022-1015
 A flaw was found in the Linux kernel in linux/net/netfilter/nf_tables_api.c of the netfilter subsystem. This flaw allows a local user to cause an out-of-bounds write issue.

- [https://github.com/more-kohii/CVE-2022-1015](https://github.com/more-kohii/CVE-2022-1015) :  ![starts](https://img.shields.io/github/stars/more-kohii/CVE-2022-1015.svg) ![forks](https://img.shields.io/github/forks/more-kohii/CVE-2022-1015.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)


## CVE-2021-35942
 The wordexp function in the GNU C Library (aka glibc) through 2.33 may crash or read arbitrary memory in parse_param (in posix/wordexp.c) when called with an untrusted, crafted pattern, potentially resulting in a denial of service or disclosure of information. This occurs because atoi was used but strtoul should have been used to ensure correct calculations.

- [https://github.com/zer0qs/CVE-2021-35042](https://github.com/zer0qs/CVE-2021-35042) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-35042.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-35042.svg)


## CVE-2021-35042
 Django 3.1.x before 3.1.13 and 3.2.x before 3.2.5 allows QuerySet.order_by SQL injection if order_by is untrusted input from a client of a web application.

- [https://github.com/zer0qs/CVE-2021-35042](https://github.com/zer0qs/CVE-2021-35042) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-35042.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-35042.svg)


## CVE-2018-4416
 Multiple memory corruption issues were addressed with improved memory handling. This issue affected versions prior to iOS 12.1, tvOS 12.1, watchOS 5.1, Safari 12.0.1, iTunes 12.9.1, iCloud for Windows 7.8.

- [https://github.com/erupmi/CVE-2018-4416](https://github.com/erupmi/CVE-2018-4416) :  ![starts](https://img.shields.io/github/stars/erupmi/CVE-2018-4416.svg) ![forks](https://img.shields.io/github/forks/erupmi/CVE-2018-4416.svg)


## CVE-2018-2628
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Core Components). Supported versions that are affected are 10.3.6.0, 12.1.3.0, 12.2.1.2 and 12.2.1.3. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Lighird/CVE-2018-2628](https://github.com/Lighird/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/Lighird/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/Lighird/CVE-2018-2628.svg)
- [https://github.com/victor0013/CVE-2018-2628](https://github.com/victor0013/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/victor0013/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/victor0013/CVE-2018-2628.svg)
- [https://github.com/R0B1NL1N/CVE-2018-2628](https://github.com/R0B1NL1N/CVE-2018-2628) :  ![starts](https://img.shields.io/github/stars/R0B1NL1N/CVE-2018-2628.svg) ![forks](https://img.shields.io/github/forks/R0B1NL1N/CVE-2018-2628.svg)


## CVE-2010-2075
 UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.

- [https://github.com/imperialbyte/CVE-2010-2075](https://github.com/imperialbyte/CVE-2010-2075) :  ![starts](https://img.shields.io/github/stars/imperialbyte/CVE-2010-2075.svg) ![forks](https://img.shields.io/github/forks/imperialbyte/CVE-2010-2075.svg)


# Update 2025-01-25
## CVE-2024-50379
Users are recommended to upgrade to version 11.0.2, 10.1.34 or 9.0.98, which fixes the issue.

- [https://github.com/pwnosec/CVE-2024-50379](https://github.com/pwnosec/CVE-2024-50379) :  ![starts](https://img.shields.io/github/stars/pwnosec/CVE-2024-50379.svg) ![forks](https://img.shields.io/github/forks/pwnosec/CVE-2024-50379.svg)


## CVE-2024-46982
 Next.js is a React framework for building full-stack web applications. By sending a crafted HTTP request, it is possible to poison the cache of a non-dynamic server-side rendered route in the pages router (this does not affect the app router). When this crafted request is sent it could coerce Next.js to cache a route that is meant to not be cached and send a `Cache-Control: s-maxage=1, stale-while-revalidate` header which some upstream CDNs may cache as well. To be potentially affected all of the following must apply: 1. Next.js between 13.5.1 and 14.2.9, 2. Using pages router, & 3. Using non-dynamic server-side rendered routes e.g. `pages/dashboard.tsx` not `pages/blog/[slug].tsx`. This vulnerability was resolved in Next.js v13.5.7, v14.2.10, and later. We recommend upgrading regardless of whether you can reproduce the issue or not. There are no official or recommended workarounds for this issue, we recommend that users patch to a safe version.

- [https://github.com/Lercas/CVE-2024-46982](https://github.com/Lercas/CVE-2024-46982) :  ![starts](https://img.shields.io/github/stars/Lercas/CVE-2024-46982.svg) ![forks](https://img.shields.io/github/forks/Lercas/CVE-2024-46982.svg)


## CVE-2024-38077
 Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability

- [https://github.com/Accord96/CVE-2024-38077-POC](https://github.com/Accord96/CVE-2024-38077-POC) :  ![starts](https://img.shields.io/github/stars/Accord96/CVE-2024-38077-POC.svg) ![forks](https://img.shields.io/github/forks/Accord96/CVE-2024-38077-POC.svg)


## CVE-2024-5775
 A vulnerability was found in SourceCodester Vehicle Management System 1.0 and classified as critical. Affected by this issue is some unknown functionality of the file updatebill.php. The manipulation of the argument id leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. VDB-267458 is the identifier assigned to this vulnerability.

- [https://github.com/l00neyhacker/CVE-2024-57754](https://github.com/l00neyhacker/CVE-2024-57754) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2024-57754.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2024-57754.svg)
- [https://github.com/l00neyhacker/CVE-2024-57753](https://github.com/l00neyhacker/CVE-2024-57753) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2024-57753.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2024-57753.svg)
- [https://github.com/l00neyhacker/CVE-2024-57750](https://github.com/l00neyhacker/CVE-2024-57750) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2024-57750.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2024-57750.svg)
- [https://github.com/l00neyhacker/CVE-2024-57756](https://github.com/l00neyhacker/CVE-2024-57756) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2024-57756.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2024-57756.svg)


## CVE-2024-5774
 A vulnerability has been found in SourceCodester Stock Management System 1.0 and classified as critical. Affected by this vulnerability is an unknown functionality of the file index.php of the component Login. The manipulation of the argument username/password leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-267457 was assigned to this vulnerability.

- [https://github.com/l00neyhacker/CVE-2024-57744](https://github.com/l00neyhacker/CVE-2024-57744) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2024-57744.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2024-57744.svg)
- [https://github.com/l00neyhacker/CVE-2024-57746](https://github.com/l00neyhacker/CVE-2024-57746) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2024-57746.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2024-57746.svg)
- [https://github.com/l00neyhacker/CVE-2024-57748](https://github.com/l00neyhacker/CVE-2024-57748) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2024-57748.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2024-57748.svg)


## CVE-2024-5450
 The Bug Library WordPress plugin before 2.1.1 does not check the file type on user-submitted bug reports, allowing an unauthenticated user to upload PHP files

- [https://github.com/jprx/CVE-2024-54507](https://github.com/jprx/CVE-2024-54507) :  ![starts](https://img.shields.io/github/stars/jprx/CVE-2024-54507.svg) ![forks](https://img.shields.io/github/forks/jprx/CVE-2024-54507.svg)


## CVE-2022-40684
 An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

- [https://github.com/XalfiE/Fortigate-Belsen-Leak-Dump-CVE-2022-40684-](https://github.com/XalfiE/Fortigate-Belsen-Leak-Dump-CVE-2022-40684-) :  ![starts](https://img.shields.io/github/stars/XalfiE/Fortigate-Belsen-Leak-Dump-CVE-2022-40684-.svg) ![forks](https://img.shields.io/github/forks/XalfiE/Fortigate-Belsen-Leak-Dump-CVE-2022-40684-.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2021-40438
 A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the remote user. This issue affects Apache HTTP Server 2.4.48 and earlier.

- [https://github.com/yakir2b/check-point-gateways-rce](https://github.com/yakir2b/check-point-gateways-rce) :  ![starts](https://img.shields.io/github/stars/yakir2b/check-point-gateways-rce.svg) ![forks](https://img.shields.io/github/forks/yakir2b/check-point-gateways-rce.svg)


## CVE-2020-10136
 IP-in-IP protocol specifies IP Encapsulation within IP standard (RFC 2003, STD 1) that decapsulate and route IP-in-IP traffic is vulnerable to spoofing, access-control bypass and other unexpected behavior due to the lack of validation to verify network packets before decapsulation and routing.

- [https://github.com/GustavoHGP/ipeeyoupeewepee](https://github.com/GustavoHGP/ipeeyoupeewepee) :  ![starts](https://img.shields.io/github/stars/GustavoHGP/ipeeyoupeewepee.svg) ![forks](https://img.shields.io/github/forks/GustavoHGP/ipeeyoupeewepee.svg)


## CVE-2018-14881
 The BGP parser in tcpdump before 4.9.3 has a buffer over-read in print-bgp.c:bgp_capabilities_print() (BGP_CAPCODE_RESTART).

- [https://github.com/uthrasri/CVE-2018-14881_no_patch](https://github.com/uthrasri/CVE-2018-14881_no_patch) :  ![starts](https://img.shields.io/github/stars/uthrasri/CVE-2018-14881_no_patch.svg) ![forks](https://img.shields.io/github/forks/uthrasri/CVE-2018-14881_no_patch.svg)


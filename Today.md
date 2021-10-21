# Update 2021-10-21
## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/ksanchezcld/httpd-2.4.49](https://github.com/ksanchezcld/httpd-2.4.49) :  ![starts](https://img.shields.io/github/stars/ksanchezcld/httpd-2.4.49.svg) ![forks](https://img.shields.io/github/forks/ksanchezcld/httpd-2.4.49.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/ksanchezcld/httpd-2.4.49](https://github.com/ksanchezcld/httpd-2.4.49) :  ![starts](https://img.shields.io/github/stars/ksanchezcld/httpd-2.4.49.svg) ![forks](https://img.shields.io/github/forks/ksanchezcld/httpd-2.4.49.svg)
- [https://github.com/cloudbyteelias/CVE-2021-41773](https://github.com/cloudbyteelias/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/cloudbyteelias/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/cloudbyteelias/CVE-2021-41773.svg)
- [https://github.com/ajdumanhug/CVE-2021-41773](https://github.com/ajdumanhug/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/ajdumanhug/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/ajdumanhug/CVE-2021-41773.svg)


## CVE-2021-28480
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-28481, CVE-2021-28482, CVE-2021-28483.

- [https://github.com/ZephrFish/CVE-2021-28480_HoneyPoC3](https://github.com/ZephrFish/CVE-2021-28480_HoneyPoC3) :  ![starts](https://img.shields.io/github/stars/ZephrFish/CVE-2021-28480_HoneyPoC3.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/CVE-2021-28480_HoneyPoC3.svg)


## CVE-2021-24884
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/S1lkys/CVE-2021-24884](https://github.com/S1lkys/CVE-2021-24884) :  ![starts](https://img.shields.io/github/stars/S1lkys/CVE-2021-24884.svg) ![forks](https://img.shields.io/github/forks/S1lkys/CVE-2021-24884.svg)


## CVE-2021-22893
 Pulse Connect Secure 9.0R3/9.1R1 and higher is vulnerable to an authentication bypass vulnerability exposed by the Windows File Share Browser and Pulse Secure Collaboration features of Pulse Connect Secure that can allow an unauthenticated user to perform remote arbitrary code execution on the Pulse Connect Secure gateway. This vulnerability has been exploited in the wild.

- [https://github.com/ZephrFish/CVE-2021-22893_HoneyPoC2](https://github.com/ZephrFish/CVE-2021-22893_HoneyPoC2) :  ![starts](https://img.shields.io/github/stars/ZephrFish/CVE-2021-22893_HoneyPoC2.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/CVE-2021-22893_HoneyPoC2.svg)


## CVE-2020-13933
 Apache Shiro before 1.6.0, when using Apache Shiro, a specially crafted HTTP request may cause an authentication bypass.

- [https://github.com/kunFeng1998/CVE-2020-13933Project](https://github.com/kunFeng1998/CVE-2020-13933Project) :  ![starts](https://img.shields.io/github/stars/kunFeng1998/CVE-2020-13933Project.svg) ![forks](https://img.shields.io/github/forks/kunFeng1998/CVE-2020-13933Project.svg)


## CVE-2020-1350
 A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.

- [https://github.com/ZephrFish/CVE-2020-1350_HoneyPoC](https://github.com/ZephrFish/CVE-2020-1350_HoneyPoC) :  ![starts](https://img.shields.io/github/stars/ZephrFish/CVE-2020-1350_HoneyPoC.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/CVE-2020-1350_HoneyPoC.svg)


## CVE-2019-3980
 The Solarwinds Dameware Mini Remote Client agent v12.1.0.89 supports smart card authentication which can allow a user to upload an executable to be executed on the DWRCS.exe host. An unauthenticated, remote attacker can request smart card login and upload and execute an arbitrary executable run under the Local System account.

- [https://github.com/Barbarisch/CVE-2019-3980](https://github.com/Barbarisch/CVE-2019-3980) :  ![starts](https://img.shields.io/github/stars/Barbarisch/CVE-2019-3980.svg) ![forks](https://img.shields.io/github/forks/Barbarisch/CVE-2019-3980.svg)


## CVE-2019-1040
 A tampering vulnerability exists in Microsoft Windows when a man-in-the-middle attacker is able to successfully bypass the NTLM MIC (Message Integrity Check) protection, aka 'Windows NTLM Tampering Vulnerability'.

- [https://github.com/fox-it/cve-2019-1040-scanner](https://github.com/fox-it/cve-2019-1040-scanner) :  ![starts](https://img.shields.io/github/stars/fox-it/cve-2019-1040-scanner.svg) ![forks](https://img.shields.io/github/forks/fox-it/cve-2019-1040-scanner.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/ItsFadinG/CVE-2018-6574](https://github.com/ItsFadinG/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/ItsFadinG/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/ItsFadinG/CVE-2018-6574.svg)


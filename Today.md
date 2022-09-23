# Update 2022-09-23
## CVE-2022-39197
 An XSS (Cross Site Scripting) vulnerability was found in HelpSystems Cobalt Strike through 4.7 that allowed a remote attacker to execute HTML on the Cobalt Strike teamserver. To exploit the vulnerability, one must first inspect a Cobalt Strike payload, and then modify the username field in the payload (or create a new payload with the extracted information and then modify that username field to be malformed).

- [https://github.com/lovechoudoufu/cobaltstrike4.5_cdf](https://github.com/lovechoudoufu/cobaltstrike4.5_cdf) :  ![starts](https://img.shields.io/github/stars/lovechoudoufu/cobaltstrike4.5_cdf.svg) ![forks](https://img.shields.io/github/forks/lovechoudoufu/cobaltstrike4.5_cdf.svg)
- [https://github.com/burpheart/CS_mock](https://github.com/burpheart/CS_mock) :  ![starts](https://img.shields.io/github/stars/burpheart/CS_mock.svg) ![forks](https://img.shields.io/github/forks/burpheart/CS_mock.svg)
- [https://github.com/safe3s/CVE-2022-39197](https://github.com/safe3s/CVE-2022-39197) :  ![starts](https://img.shields.io/github/stars/safe3s/CVE-2022-39197.svg) ![forks](https://img.shields.io/github/forks/safe3s/CVE-2022-39197.svg)


## CVE-2022-36804
 Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request. This vulnerability was reported via our Bug Bounty Program by TheGrandPew.

- [https://github.com/kljunowsky/CVE-2022-36804-POC](https://github.com/kljunowsky/CVE-2022-36804-POC) :  ![starts](https://img.shields.io/github/stars/kljunowsky/CVE-2022-36804-POC.svg) ![forks](https://img.shields.io/github/forks/kljunowsky/CVE-2022-36804-POC.svg)


## CVE-2022-34265
 An issue was discovered in Django 3.2 before 3.2.14 and 4.0 before 4.0.6. The Trunc() and Extract() database functions are subject to SQL injection if untrusted data is used as a kind/lookup_name value. Applications that constrain the lookup name and kind choice to a known safe list are unaffected.

- [https://github.com/coco0x0a/CTF_Django_CVE-2022-34265](https://github.com/coco0x0a/CTF_Django_CVE-2022-34265) :  ![starts](https://img.shields.io/github/stars/coco0x0a/CTF_Django_CVE-2022-34265.svg) ![forks](https://img.shields.io/github/forks/coco0x0a/CTF_Django_CVE-2022-34265.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)
- [https://github.com/hab1b0x/CVE-2021-41773](https://github.com/hab1b0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/hab1b0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/hab1b0x/CVE-2021-41773.svg)


## CVE-2020-7246
 A remote code execution (RCE) vulnerability exists in qdPM 9.1 and earlier. An attacker can upload a malicious PHP code file via the profile photo functionality, by leveraging a path traversal vulnerability in the users['photop_preview'] delete photo feature, allowing bypass of .htaccess protection. NOTE: this issue exists because of an incomplete fix for CVE-2015-3884.

- [https://github.com/pswalia2u/CVE-2020-7246](https://github.com/pswalia2u/CVE-2020-7246) :  ![starts](https://img.shields.io/github/stars/pswalia2u/CVE-2020-7246.svg) ![forks](https://img.shields.io/github/forks/pswalia2u/CVE-2020-7246.svg)


## CVE-2019-16374
 Pega Platform 8.2.1 allows LDAP injection because a username can contain a * character and can be of unlimited length. An attacker can specify four characters of a username, followed by the * character, to bypass access control.

- [https://github.com/IAG0110/CVE-2019-16374](https://github.com/IAG0110/CVE-2019-16374) :  ![starts](https://img.shields.io/github/stars/IAG0110/CVE-2019-16374.svg) ![forks](https://img.shields.io/github/forks/IAG0110/CVE-2019-16374.svg)


## CVE-2019-1205
 A remote code execution vulnerability exists in Microsoft Word software when it fails to properly handle objects in memory, aka 'Microsoft Word Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-1201.

- [https://github.com/info4mationprivate8tools/CVE-2019-1205](https://github.com/info4mationprivate8tools/CVE-2019-1205) :  ![starts](https://img.shields.io/github/stars/info4mationprivate8tools/CVE-2019-1205.svg) ![forks](https://img.shields.io/github/forks/info4mationprivate8tools/CVE-2019-1205.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/moorada/goGetRCE](https://github.com/moorada/goGetRCE) :  ![starts](https://img.shields.io/github/stars/moorada/goGetRCE.svg) ![forks](https://img.shields.io/github/forks/moorada/goGetRCE.svg)


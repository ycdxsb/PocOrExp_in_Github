# Update 2023-07-06
## CVE-2023-33246
 For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .

- [https://github.com/Devil0ll/CVE-2023-33246](https://github.com/Devil0ll/CVE-2023-33246) :  ![starts](https://img.shields.io/github/stars/Devil0ll/CVE-2023-33246.svg) ![forks](https://img.shields.io/github/forks/Devil0ll/CVE-2023-33246.svg)


## CVE-2023-24488
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/securitycipher/CVE-2023-24488](https://github.com/securitycipher/CVE-2023-24488) :  ![starts](https://img.shields.io/github/stars/securitycipher/CVE-2023-24488.svg) ![forks](https://img.shields.io/github/forks/securitycipher/CVE-2023-24488.svg)


## CVE-2022-46080
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/yerodin/CVE-2022-46080](https://github.com/yerodin/CVE-2022-46080) :  ![starts](https://img.shields.io/github/stars/yerodin/CVE-2022-46080.svg) ![forks](https://img.shields.io/github/forks/yerodin/CVE-2022-46080.svg)


## CVE-2022-28454
 Limbas 4.3.36.1319 is vulnerable to Cross Site Scripting (XSS).

- [https://github.com/YavuzSahbaz/Limbas-4.3.36.1319-is-vulnerable-to-Cross-Site-Scripting-XSS-](https://github.com/YavuzSahbaz/Limbas-4.3.36.1319-is-vulnerable-to-Cross-Site-Scripting-XSS-) :  ![starts](https://img.shields.io/github/stars/YavuzSahbaz/Limbas-4.3.36.1319-is-vulnerable-to-Cross-Site-Scripting-XSS-.svg) ![forks](https://img.shields.io/github/forks/YavuzSahbaz/Limbas-4.3.36.1319-is-vulnerable-to-Cross-Site-Scripting-XSS-.svg)


## CVE-2022-23614
 Twig is an open source template language for PHP. When in a sandbox mode, the `arrow` parameter of the `sort` filter must be a closure to avoid attackers being able to run arbitrary PHP functions. In affected versions this constraint was not properly enforced and could lead to code injection of arbitrary PHP code. Patched versions now disallow calling non Closure in the `sort` filter as is the case for some other filters. Users are advised to upgrade.

- [https://github.com/4rtamis/CVE-2022-23614](https://github.com/4rtamis/CVE-2022-23614) :  ![starts](https://img.shields.io/github/stars/4rtamis/CVE-2022-23614.svg) ![forks](https://img.shields.io/github/forks/4rtamis/CVE-2022-23614.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/0dayNinja/CVE-2021-3560](https://github.com/0dayNinja/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/0dayNinja/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/0dayNinja/CVE-2021-3560.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/krypton612/hikivision](https://github.com/krypton612/hikivision) :  ![starts](https://img.shields.io/github/stars/krypton612/hikivision.svg) ![forks](https://img.shields.io/github/forks/krypton612/hikivision.svg)


## CVE-2015-5477
 named in ISC BIND 9.x before 9.9.7-P2 and 9.10.x before 9.10.2-P3 allows remote attackers to cause a denial of service (REQUIRE assertion failure and daemon exit) via TKEY queries.

- [https://github.com/knqyf263/cve-2015-5477](https://github.com/knqyf263/cve-2015-5477) :  ![starts](https://img.shields.io/github/stars/knqyf263/cve-2015-5477.svg) ![forks](https://img.shields.io/github/forks/knqyf263/cve-2015-5477.svg)


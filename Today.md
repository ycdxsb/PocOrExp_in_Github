# Update 2023-10-01
## CVE-2023-42793
 In JetBrains TeamCity before 2023.05.4 authentication bypass leading to RCE on TeamCity Server was possible

- [https://github.com/H454NSec/CVE-2023-42793](https://github.com/H454NSec/CVE-2023-42793) :  ![starts](https://img.shields.io/github/stars/H454NSec/CVE-2023-42793.svg) ![forks](https://img.shields.io/github/forks/H454NSec/CVE-2023-42793.svg)


## CVE-2023-24538
 Templates do not properly consider backticks (`) as Javascript string delimiters, and do not escape them as expected. Backticks are used, since ES6, for JS template literals. If a template contains a Go template action within a Javascript template literal, the contents of the action can be used to terminate the literal, injecting arbitrary Javascript code into the Go template. As ES6 template literals are rather complex, and themselves can do string interpolation, the decision was made to simply disallow Go template actions from being used inside of them (e.g. &quot;var a = {{.}}&quot;), since there is no obviously safe way to allow this behavior. This takes the same approach as github.com/google/safehtml. With fix, Template.Parse returns an Error when it encounters templates like this, with an ErrorCode of value 12. This ErrorCode is currently unexported, but will be exported in the release of Go 1.21. Users who rely on the previous behavior can re-enable it using the GODEBUG flag jstmpllitinterp=1, with the caveat that backticks will now be escaped. This should be used with caution.

- [https://github.com/skulkarni-mv/goIssue_dunfell](https://github.com/skulkarni-mv/goIssue_dunfell) :  ![starts](https://img.shields.io/github/stars/skulkarni-mv/goIssue_dunfell.svg) ![forks](https://img.shields.io/github/forks/skulkarni-mv/goIssue_dunfell.svg)


## CVE-2023-5129
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority. Duplicate of CVE-2023-4863.

- [https://github.com/GTGalaxi/ElectronVulnerableVersion](https://github.com/GTGalaxi/ElectronVulnerableVersion) :  ![starts](https://img.shields.io/github/stars/GTGalaxi/ElectronVulnerableVersion.svg) ![forks](https://img.shields.io/github/forks/GTGalaxi/ElectronVulnerableVersion.svg)


## CVE-2023-5074
 Use of a static key to protect a JWT token used in user authentication can allow an for an authentication bypass in D-Link D-View 8 v2.0.1.28

- [https://github.com/codeb0ss/CVE-2023-5074-PoC](https://github.com/codeb0ss/CVE-2023-5074-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2023-5074-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2023-5074-PoC.svg)


## CVE-2023-4863
 Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/GTGalaxi/ElectronVulnerableVersion](https://github.com/GTGalaxi/ElectronVulnerableVersion) :  ![starts](https://img.shields.io/github/stars/GTGalaxi/ElectronVulnerableVersion.svg) ![forks](https://img.shields.io/github/forks/GTGalaxi/ElectronVulnerableVersion.svg)


## CVE-2023-3450
 A vulnerability was found in Ruijie RG-BCR860 2.5.13 and classified as critical. This issue affects some unknown processing of the component Network Diagnostic Page. The manipulation leads to os command injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-232547. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/caopengyan/CVE-2023-3450](https://github.com/caopengyan/CVE-2023-3450) :  ![starts](https://img.shields.io/github/stars/caopengyan/CVE-2023-3450.svg) ![forks](https://img.shields.io/github/forks/caopengyan/CVE-2023-3450.svg)


## CVE-2022-3452
 A vulnerability was found in SourceCodester Book Store Management System 1.0. It has been declared as problematic. This vulnerability affects unknown code of the file /category.php. The manipulation of the argument category_name leads to cross site scripting. The attack can be initiated remotely. The identifier of this vulnerability is VDB-210436.

- [https://github.com/kenyon-wong/cve-2022-3452](https://github.com/kenyon-wong/cve-2022-3452) :  ![starts](https://img.shields.io/github/stars/kenyon-wong/cve-2022-3452.svg) ![forks](https://img.shields.io/github/forks/kenyon-wong/cve-2022-3452.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/ab0x90/CVE-2021-44228_PoC](https://github.com/ab0x90/CVE-2021-44228_PoC) :  ![starts](https://img.shields.io/github/stars/ab0x90/CVE-2021-44228_PoC.svg) ![forks](https://img.shields.io/github/forks/ab0x90/CVE-2021-44228_PoC.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/GGyao/CVE-2020-14882_POC](https://github.com/GGyao/CVE-2020-14882_POC) :  ![starts](https://img.shields.io/github/stars/GGyao/CVE-2020-14882_POC.svg) ![forks](https://img.shields.io/github/forks/GGyao/CVE-2020-14882_POC.svg)


## CVE-2020-0096
 In startActivities of ActivityStartController.java, there is a possible escalation of privilege due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9Android ID: A-145669109

- [https://github.com/liuyun201990/StrandHogg2](https://github.com/liuyun201990/StrandHogg2) :  ![starts](https://img.shields.io/github/stars/liuyun201990/StrandHogg2.svg) ![forks](https://img.shields.io/github/forks/liuyun201990/StrandHogg2.svg)


## CVE-2019-19633
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/jra89/CVE-2019-19633](https://github.com/jra89/CVE-2019-19633) :  ![starts](https://img.shields.io/github/stars/jra89/CVE-2019-19633.svg) ![forks](https://img.shields.io/github/forks/jra89/CVE-2019-19633.svg)


## CVE-2018-1235
 Dell EMC RecoverPoint versions prior to 5.1.2 and RecoverPoint for VMs versions prior to 5.1.1.3, contain a command injection vulnerability. An unauthenticated remote attacker may potentially exploit this vulnerability to execute arbitrary commands on the affected system with root privilege.

- [https://github.com/AbsoZed/CVE-2018-1235](https://github.com/AbsoZed/CVE-2018-1235) :  ![starts](https://img.shields.io/github/stars/AbsoZed/CVE-2018-1235.svg) ![forks](https://img.shields.io/github/forks/AbsoZed/CVE-2018-1235.svg)


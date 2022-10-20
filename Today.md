# Update 2022-10-20
## CVE-2022-42899
 Bentley MicroStation and MicroStation-based applications may be affected by out-of-bounds read and stack overflow issues when opening crafted SKP files. Exploiting these issues could lead to information disclosure and code execution. The fixed versions are 10.17.01.58* for MicroStation and 10.17.01.19* for Bentley View.

- [https://github.com/iamsanjay/CVE-2022-42899](https://github.com/iamsanjay/CVE-2022-42899) :  ![starts](https://img.shields.io/github/stars/iamsanjay/CVE-2022-42899.svg) ![forks](https://img.shields.io/github/forks/iamsanjay/CVE-2022-42899.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/karthikuj/cve-2022-42889-text4shell-docker](https://github.com/karthikuj/cve-2022-42889-text4shell-docker) :  ![starts](https://img.shields.io/github/stars/karthikuj/cve-2022-42889-text4shell-docker.svg) ![forks](https://img.shields.io/github/forks/karthikuj/cve-2022-42889-text4shell-docker.svg)
- [https://github.com/Goss1TheDog/CVE-2022-42889-RCE-POC](https://github.com/Goss1TheDog/CVE-2022-42889-RCE-POC) :  ![starts](https://img.shields.io/github/stars/Goss1TheDog/CVE-2022-42889-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/Goss1TheDog/CVE-2022-42889-RCE-POC.svg)
- [https://github.com/chainguard-dev/text4shell-policy](https://github.com/chainguard-dev/text4shell-policy) :  ![starts](https://img.shields.io/github/stars/chainguard-dev/text4shell-policy.svg) ![forks](https://img.shields.io/github/forks/chainguard-dev/text4shell-policy.svg)
- [https://github.com/korteke/CVE-2022-42889-POC](https://github.com/korteke/CVE-2022-42889-POC) :  ![starts](https://img.shields.io/github/stars/korteke/CVE-2022-42889-POC.svg) ![forks](https://img.shields.io/github/forks/korteke/CVE-2022-42889-POC.svg)
- [https://github.com/ClickCyber/cve-2022-42889](https://github.com/ClickCyber/cve-2022-42889) :  ![starts](https://img.shields.io/github/stars/ClickCyber/cve-2022-42889.svg) ![forks](https://img.shields.io/github/forks/ClickCyber/cve-2022-42889.svg)
- [https://github.com/tulhan/commons-text-goat](https://github.com/tulhan/commons-text-goat) :  ![starts](https://img.shields.io/github/stars/tulhan/commons-text-goat.svg) ![forks](https://img.shields.io/github/forks/tulhan/commons-text-goat.svg)


## CVE-2022-41541
 TP-Link AX10v1 V1_211117 allows attackers to execute a replay attack by using a previously transmitted encrypted authentication message and valid authentication token. Attackers are able to login to the web application as an admin user.

- [https://github.com/efchatz/easy-exploits](https://github.com/efchatz/easy-exploits) :  ![starts](https://img.shields.io/github/stars/efchatz/easy-exploits.svg) ![forks](https://img.shields.io/github/forks/efchatz/easy-exploits.svg)


## CVE-2022-41540
 The web app client of TP-Link AX10v1 V1_211117 uses hard-coded cryptographic keys when communicating with the router. Attackers who are able to intercept the communications between the web client and router through a man-in-the-middle attack can then obtain the sequence key via a brute-force attack, and access sensitive information.

- [https://github.com/efchatz/easy-exploits](https://github.com/efchatz/easy-exploits) :  ![starts](https://img.shields.io/github/stars/efchatz/easy-exploits.svg) ![forks](https://img.shields.io/github/forks/efchatz/easy-exploits.svg)


## CVE-2022-40684
 An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

- [https://github.com/mohamedbenchikh/CVE-2022-40684](https://github.com/mohamedbenchikh/CVE-2022-40684) :  ![starts](https://img.shields.io/github/stars/mohamedbenchikh/CVE-2022-40684.svg) ![forks](https://img.shields.io/github/forks/mohamedbenchikh/CVE-2022-40684.svg)


## CVE-2022-27502
 RealVNC VNC Server 6.9.0 through 5.1.0 for Windows allows local privilege escalation because an installer repair operation executes %TEMP% files as SYSTEM.

- [https://github.com/alirezac0/CVE-2022-27502](https://github.com/alirezac0/CVE-2022-27502) :  ![starts](https://img.shields.io/github/stars/alirezac0/CVE-2022-27502.svg) ![forks](https://img.shields.io/github/forks/alirezac0/CVE-2022-27502.svg)


## CVE-2022-3368
 A vulnerability within the Software Updater functionality of Avira Security for Windows allowed an attacker with write access to the filesystem, to escalate his privileges in certain scenarios. The issue was fixed with Avira Security version 1.1.72.30556.

- [https://github.com/Wh04m1001/CVE-2022-3368](https://github.com/Wh04m1001/CVE-2022-3368) :  ![starts](https://img.shields.io/github/stars/Wh04m1001/CVE-2022-3368.svg) ![forks](https://img.shields.io/github/forks/Wh04m1001/CVE-2022-3368.svg)


## CVE-2021-26885
 Windows WalletService Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-26871.

- [https://github.com/1n7erface/PocList](https://github.com/1n7erface/PocList) :  ![starts](https://img.shields.io/github/stars/1n7erface/PocList.svg) ![forks](https://img.shields.io/github/forks/1n7erface/PocList.svg)


## CVE-2021-25646
 Apache Druid includes the ability to execute user-provided JavaScript code embedded in various types of requests. This functionality is intended for use in high-trust environments, and is disabled by default. However, in Druid 0.20.0 and earlier, it is possible for an authenticated user to send a specially-crafted request that forces Druid to run user-provided JavaScript code for that request, regardless of server configuration. This can be leveraged to execute code on the target machine with the privileges of the Druid server process.

- [https://github.com/1n7erface/PocList](https://github.com/1n7erface/PocList) :  ![starts](https://img.shields.io/github/stars/1n7erface/PocList.svg) ![forks](https://img.shields.io/github/forks/1n7erface/PocList.svg)


## CVE-2021-22986
 On BIG-IP versions 16.0.x before 16.0.1.1, 15.1.x before 15.1.2.1, 14.1.x before 14.1.4, 13.1.x before 13.1.3.6, and 12.1.x before 12.1.5.3 amd BIG-IQ 7.1.0.x before 7.1.0.3 and 7.0.0.x before 7.0.0.2, the iControl REST interface has an unauthenticated remote command execution vulnerability. Note: Software versions which have reached End of Software Development (EoSD) are not evaluated.

- [https://github.com/1n7erface/PocList](https://github.com/1n7erface/PocList) :  ![starts](https://img.shields.io/github/stars/1n7erface/PocList.svg) ![forks](https://img.shields.io/github/forks/1n7erface/PocList.svg)


## CVE-2021-2109
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/1n7erface/PocList](https://github.com/1n7erface/PocList) :  ![starts](https://img.shields.io/github/stars/1n7erface/PocList.svg) ![forks](https://img.shields.io/github/forks/1n7erface/PocList.svg)


## CVE-2020-25078
 An issue was discovered on D-Link DCS-2530L before 1.06.01 Hotfix and DCS-2670L through 2.02 devices. The unauthenticated /config/getuser endpoint allows for remote administrator password disclosure.

- [https://github.com/1n7erface/PocList](https://github.com/1n7erface/PocList) :  ![starts](https://img.shields.io/github/stars/1n7erface/PocList.svg) ![forks](https://img.shields.io/github/forks/1n7erface/PocList.svg)


## CVE-2020-14883
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 7.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/1n7erface/PocList](https://github.com/1n7erface/PocList) :  ![starts](https://img.shields.io/github/stars/1n7erface/PocList.svg) ![forks](https://img.shields.io/github/forks/1n7erface/PocList.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/1n7erface/PocList](https://github.com/1n7erface/PocList) :  ![starts](https://img.shields.io/github/stars/1n7erface/PocList.svg) ![forks](https://img.shields.io/github/forks/1n7erface/PocList.svg)


## CVE-2020-13937
 Apache Kylin 2.0.0, 2.1.0, 2.2.0, 2.3.0, 2.3.1, 2.3.2, 2.4.0, 2.4.1, 2.5.0, 2.5.1, 2.5.2, 2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 3.0.0-alpha, 3.0.0-alpha2, 3.0.0-beta, 3.0.0, 3.0.1, 3.0.2, 3.1.0, 4.0.0-alpha has one restful api which exposed Kylin's configuration information without any authentication, so it is dangerous because some confidential information entries will be disclosed to everyone.

- [https://github.com/kailing0220/CVE-2020-13937](https://github.com/kailing0220/CVE-2020-13937) :  ![starts](https://img.shields.io/github/stars/kailing0220/CVE-2020-13937.svg) ![forks](https://img.shields.io/github/forks/kailing0220/CVE-2020-13937.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/inj3ction/CVE-2017-7921-EXP](https://github.com/inj3ction/CVE-2017-7921-EXP) :  ![starts](https://img.shields.io/github/stars/inj3ction/CVE-2017-7921-EXP.svg) ![forks](https://img.shields.io/github/forks/inj3ction/CVE-2017-7921-EXP.svg)


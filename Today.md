# Update 2024-01-05
## CVE-2023-51385
 In ssh in OpenSSH before 9.6, OS command injection might occur if a user name or host name has shell metacharacters, and this name is referenced by an expansion token in certain situations. For example, an untrusted Git repository can have a submodule with shell metacharacters in a user name or host name.

- [https://github.com/julienbrs/exploit-CVE-2023-51385](https://github.com/julienbrs/exploit-CVE-2023-51385) :  ![starts](https://img.shields.io/github/stars/julienbrs/exploit-CVE-2023-51385.svg) ![forks](https://img.shields.io/github/forks/julienbrs/exploit-CVE-2023-51385.svg)
- [https://github.com/julienbrs/malicious-exploit-CVE-2023-51385](https://github.com/julienbrs/malicious-exploit-CVE-2023-51385) :  ![starts](https://img.shields.io/github/stars/julienbrs/malicious-exploit-CVE-2023-51385.svg) ![forks](https://img.shields.io/github/forks/julienbrs/malicious-exploit-CVE-2023-51385.svg)


## CVE-2023-48864
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/f3lze3/CVE-2023-48864](https://github.com/f3lze3/CVE-2023-48864) :  ![starts](https://img.shields.io/github/stars/f3lze3/CVE-2023-48864.svg) ![forks](https://img.shields.io/github/forks/f3lze3/CVE-2023-48864.svg)


## CVE-2022-20229
 In bta_hf_client_handle_cind_list_item of bta_hf_client_at.cc, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-224536184

- [https://github.com/ShaikUsaf/system_bt_AOSP10_r33_CVE-2022-20229](https://github.com/ShaikUsaf/system_bt_AOSP10_r33_CVE-2022-20229) :  ![starts](https://img.shields.io/github/stars/ShaikUsaf/system_bt_AOSP10_r33_CVE-2022-20229.svg) ![forks](https://img.shields.io/github/forks/ShaikUsaf/system_bt_AOSP10_r33_CVE-2022-20229.svg)


## CVE-2022-3786
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed a malicious certificate or for an application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects.

- [https://github.com/NCSC-NL/OpenSSL-2022](https://github.com/NCSC-NL/OpenSSL-2022) :  ![starts](https://img.shields.io/github/stars/NCSC-NL/OpenSSL-2022.svg) ![forks](https://img.shields.io/github/forks/NCSC-NL/OpenSSL-2022.svg)
- [https://github.com/hi-artem/find-spooky-prismacloud](https://github.com/hi-artem/find-spooky-prismacloud) :  ![starts](https://img.shields.io/github/stars/hi-artem/find-spooky-prismacloud.svg) ![forks](https://img.shields.io/github/forks/hi-artem/find-spooky-prismacloud.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/nvk0x/CVE-2022-1388-exploit](https://github.com/nvk0x/CVE-2022-1388-exploit) :  ![starts](https://img.shields.io/github/stars/nvk0x/CVE-2022-1388-exploit.svg) ![forks](https://img.shields.io/github/forks/nvk0x/CVE-2022-1388-exploit.svg)


## CVE-2022-0995
 An out-of-bounds (OOB) memory write flaw was found in the Linux kernel&#8217;s watch_queue event notification subsystem. This flaw can overwrite parts of the kernel state, potentially allowing a local user to gain privileged access or cause a denial of service on the system.

- [https://github.com/1nzag/CVE-2022-0995](https://github.com/1nzag/CVE-2022-0995) :  ![starts](https://img.shields.io/github/stars/1nzag/CVE-2022-0995.svg) ![forks](https://img.shields.io/github/forks/1nzag/CVE-2022-0995.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/12345qwert123456/CVE-2021-41773](https://github.com/12345qwert123456/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/12345qwert123456/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/12345qwert123456/CVE-2021-41773.svg)
- [https://github.com/mightysai1997/cve-2021-41773-v-](https://github.com/mightysai1997/cve-2021-41773-v-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773-v-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773-v-.svg)


## CVE-2020-3580
 Multiple vulnerabilities in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct cross-site scripting (XSS) attacks against a user of the web services interface of an affected device. The vulnerabilities are due to insufficient validation of user-supplied input by the web services interface of an affected device. An attacker could exploit these vulnerabilities by persuading a user of the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or allow the attacker to access sensitive, browser-based information. Note: These vulnerabilities affect only specific AnyConnect and WebVPN configurations. For more information, see the Vulnerable Products section.

- [https://github.com/cruxN3T/CVE-2020-3580](https://github.com/cruxN3T/CVE-2020-3580) :  ![starts](https://img.shields.io/github/stars/cruxN3T/CVE-2020-3580.svg) ![forks](https://img.shields.io/github/forks/cruxN3T/CVE-2020-3580.svg)


## CVE-2020-1362
 An elevation of privilege vulnerability exists in the way that the Windows WalletService handles objects in memory, aka 'Windows WalletService Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1344, CVE-2020-1369.

- [https://github.com/Q4n/CVE-2020-1362](https://github.com/Q4n/CVE-2020-1362) :  ![starts](https://img.shields.io/github/stars/Q4n/CVE-2020-1362.svg) ![forks](https://img.shields.io/github/forks/Q4n/CVE-2020-1362.svg)


## CVE-2019-9153
 Improper Verification of a Cryptographic Signature in OpenPGP.js &lt;=4.1.2 allows an attacker to forge signed messages by replacing its signatures with a &quot;standalone&quot; or &quot;timestamp&quot; signature.

- [https://github.com/ZenyWay/opgp-service-cve-2019-9153](https://github.com/ZenyWay/opgp-service-cve-2019-9153) :  ![starts](https://img.shields.io/github/stars/ZenyWay/opgp-service-cve-2019-9153.svg) ![forks](https://img.shields.io/github/forks/ZenyWay/opgp-service-cve-2019-9153.svg)


## CVE-2019-1181
 A remote code execution vulnerability exists in Remote Desktop Services &#8364;&#8220; formerly known as Terminal Services &#8364;&#8220; when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2019-1182, CVE-2019-1222, CVE-2019-1226.

- [https://github.com/major203/cve-2019-1181](https://github.com/major203/cve-2019-1181) :  ![starts](https://img.shields.io/github/stars/major203/cve-2019-1181.svg) ![forks](https://img.shields.io/github/forks/major203/cve-2019-1181.svg)


## CVE-2018-1297
 When using Distributed Test only (RMI based), Apache JMeter 2.x and 3.x uses an unsecured RMI connection. This could allow an attacker to get Access to JMeterEngine and send unauthorized code.

- [https://github.com/48484848484848/Jmeter-CVE-2018-1297-](https://github.com/48484848484848/Jmeter-CVE-2018-1297-) :  ![starts](https://img.shields.io/github/stars/48484848484848/Jmeter-CVE-2018-1297-.svg) ![forks](https://img.shields.io/github/forks/48484848484848/Jmeter-CVE-2018-1297-.svg)


## CVE-2018-1273
 Spring Data Commons, versions prior to 1.13 to 1.13.10, 2.0 to 2.0.5, and older unsupported versions, contain a property binder vulnerability caused by improper neutralization of special elements. An unauthenticated remote malicious user (or attacker) can supply specially crafted request parameters against Spring Data REST backed HTTP resources or using Spring Data's projection-based request payload binding hat can lead to a remote code execution attack.

- [https://github.com/wearearima/poc-cve-2018-1273](https://github.com/wearearima/poc-cve-2018-1273) :  ![starts](https://img.shields.io/github/stars/wearearima/poc-cve-2018-1273.svg) ![forks](https://img.shields.io/github/forks/wearearima/poc-cve-2018-1273.svg)


## CVE-2015-3636
 The ping_unhash function in net/ipv4/ping.c in the Linux kernel before 4.0.3 does not initialize a certain list data structure during an unhash operation, which allows local users to gain privileges or cause a denial of service (use-after-free and system crash) by leveraging the ability to make a SOCK_DGRAM socket system call for the IPPROTO_ICMP or IPPROTO_ICMPV6 protocol, and then making a connect system call after a disconnect.

- [https://github.com/betalphafai/cve-2015-3636_crash](https://github.com/betalphafai/cve-2015-3636_crash) :  ![starts](https://img.shields.io/github/stars/betalphafai/cve-2015-3636_crash.svg) ![forks](https://img.shields.io/github/forks/betalphafai/cve-2015-3636_crash.svg)


## CVE-2014-3120
 The default configuration in Elasticsearch before 1.2 enables dynamic scripting, which allows remote attackers to execute arbitrary MVEL expressions and Java code via the source parameter to _search.  NOTE: this only violates the vendor's intended security policy if the user does not run Elasticsearch in its own independent virtual machine.

- [https://github.com/jeffgeiger/es_inject](https://github.com/jeffgeiger/es_inject) :  ![starts](https://img.shields.io/github/stars/jeffgeiger/es_inject.svg) ![forks](https://img.shields.io/github/forks/jeffgeiger/es_inject.svg)
- [https://github.com/xpgdgit/CVE-2014-3120](https://github.com/xpgdgit/CVE-2014-3120) :  ![starts](https://img.shields.io/github/stars/xpgdgit/CVE-2014-3120.svg) ![forks](https://img.shields.io/github/forks/xpgdgit/CVE-2014-3120.svg)


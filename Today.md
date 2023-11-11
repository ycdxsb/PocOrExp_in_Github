# Update 2023-11-11
## CVE-2023-46604
 Apache ActiveMQ is vulnerable to Remote Code Execution.The vulnerability may allow a remote attacker with network access to a broker to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to cause the broker to instantiate any class on the classpath. Users are recommended to upgrade to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3, which fixes this issue.

- [https://github.com/h3x3h0g/ActiveMQ-RCE-CVE-2023-46604-Write-up](https://github.com/h3x3h0g/ActiveMQ-RCE-CVE-2023-46604-Write-up) :  ![starts](https://img.shields.io/github/stars/h3x3h0g/ActiveMQ-RCE-CVE-2023-46604-Write-up.svg) ![forks](https://img.shields.io/github/forks/h3x3h0g/ActiveMQ-RCE-CVE-2023-46604-Write-up.svg)


## CVE-2023-38646
 Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation. The other fixed versions are 0.45.4.1, 1.45.4.1, 0.44.7.1, 1.44.7.1, 0.43.7.2, and 1.43.7.2.

- [https://github.com/j0yb0y0h/CVE-2023-38646](https://github.com/j0yb0y0h/CVE-2023-38646) :  ![starts](https://img.shields.io/github/stars/j0yb0y0h/CVE-2023-38646.svg) ![forks](https://img.shields.io/github/forks/j0yb0y0h/CVE-2023-38646.svg)


## CVE-2023-32629
 Local privilege escalation vulnerability in Ubuntu Kernels overlayfs ovl_copy_up_meta_inode_data skip permission checks when calling ovl_do_setxattr on Ubuntu kernels

- [https://github.com/ThrynSec/CVE-2023-32629-CVE-2023-2640---POC-Escalation](https://github.com/ThrynSec/CVE-2023-32629-CVE-2023-2640---POC-Escalation) :  ![starts](https://img.shields.io/github/stars/ThrynSec/CVE-2023-32629-CVE-2023-2640---POC-Escalation.svg) ![forks](https://img.shields.io/github/forks/ThrynSec/CVE-2023-32629-CVE-2023-2640---POC-Escalation.svg)


## CVE-2023-22518
 All versions of Confluence Data Center and Server are affected by this unexploited vulnerability. This Improper Authorization vulnerability allows an unauthenticated attacker to reset Confluence and create a Confluence instance administrator account. Using this account, an attacker can then perform all administrative actions that are available to Confluence instance administrator leading to - but not limited to - full loss of confidentiality, integrity and availability. Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue.

- [https://github.com/0x0d3ad/CVE-2023-22518](https://github.com/0x0d3ad/CVE-2023-22518) :  ![starts](https://img.shields.io/github/stars/0x0d3ad/CVE-2023-22518.svg) ![forks](https://img.shields.io/github/forks/0x0d3ad/CVE-2023-22518.svg)


## CVE-2023-22515
 Atlassian has been made aware of an issue reported by a handful of customers where external attackers may have exploited a previously unknown vulnerability in publicly accessible Confluence Data Center and Server instances to create unauthorized Confluence administrator accounts and access Confluence instances. Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue.

- [https://github.com/aaaademo/Confluence-EvilJar](https://github.com/aaaademo/Confluence-EvilJar) :  ![starts](https://img.shields.io/github/stars/aaaademo/Confluence-EvilJar.svg) ![forks](https://img.shields.io/github/forks/aaaademo/Confluence-EvilJar.svg)


## CVE-2023-2640
 On Ubuntu kernels carrying both c914c0e27eb0 and &quot;UBUNTU: SAUCE: overlayfs: Skip permission checking for trusted.overlayfs.* xattrs&quot;, an unprivileged user may set privileged extended attributes on the mounted files, leading them to be set on the upper files without the appropriate security checks.

- [https://github.com/ThrynSec/CVE-2023-32629-CVE-2023-2640---POC-Escalation](https://github.com/ThrynSec/CVE-2023-32629-CVE-2023-2640---POC-Escalation) :  ![starts](https://img.shields.io/github/stars/ThrynSec/CVE-2023-32629-CVE-2023-2640---POC-Escalation.svg) ![forks](https://img.shields.io/github/forks/ThrynSec/CVE-2023-32629-CVE-2023-2640---POC-Escalation.svg)


## CVE-2022-32250
 net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to a use-after-free.

- [https://github.com/Decstor5/2022-32250LPE](https://github.com/Decstor5/2022-32250LPE) :  ![starts](https://img.shields.io/github/stars/Decstor5/2022-32250LPE.svg) ![forks](https://img.shields.io/github/forks/Decstor5/2022-32250LPE.svg)


## CVE-2020-3580
 Multiple vulnerabilities in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct cross-site scripting (XSS) attacks against a user of the web services interface of an affected device. The vulnerabilities are due to insufficient validation of user-supplied input by the web services interface of an affected device. An attacker could exploit these vulnerabilities by persuading a user of the interface to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script code in the context of the interface or allow the attacker to access sensitive, browser-based information. Note: These vulnerabilities affect only specific AnyConnect and WebVPN configurations. For more information, see the Vulnerable Products section.

- [https://github.com/cruxN3T/CVE-2020-3580](https://github.com/cruxN3T/CVE-2020-3580) :  ![starts](https://img.shields.io/github/stars/cruxN3T/CVE-2020-3580.svg) ![forks](https://img.shields.io/github/forks/cruxN3T/CVE-2020-3580.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/aamfrk/Webmin-CVE2019-15107](https://github.com/aamfrk/Webmin-CVE2019-15107) :  ![starts](https://img.shields.io/github/stars/aamfrk/Webmin-CVE2019-15107.svg) ![forks](https://img.shields.io/github/forks/aamfrk/Webmin-CVE2019-15107.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor](https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor) :  ![starts](https://img.shields.io/github/stars/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor.svg) ![forks](https://img.shields.io/github/forks/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor.svg)


## CVE-2016-0705
 Double free vulnerability in the dsa_priv_decode function in crypto/dsa/dsa_ameth.c in OpenSSL 1.0.1 before 1.0.1s and 1.0.2 before 1.0.2g allows remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via a malformed DSA private key.

- [https://github.com/nidhi7598/OPENSSL_1.0.1g_CVE-2016-0705](https://github.com/nidhi7598/OPENSSL_1.0.1g_CVE-2016-0705) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.0.1g_CVE-2016-0705.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.0.1g_CVE-2016-0705.svg)


## CVE-2014-3507
 Memory leak in d1_both.c in the DTLS implementation in OpenSSL 0.9.8 before 0.9.8zb, 1.0.0 before 1.0.0n, and 1.0.1 before 1.0.1i allows remote attackers to cause a denial of service (memory consumption) via zero-length DTLS fragments that trigger improper handling of the return value of a certain insert function.

- [https://github.com/nidhi7598/OPENSSL_1.0.1g_CVE-2014-3507](https://github.com/nidhi7598/OPENSSL_1.0.1g_CVE-2014-3507) :  ![starts](https://img.shields.io/github/stars/nidhi7598/OPENSSL_1.0.1g_CVE-2014-3507.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/OPENSSL_1.0.1g_CVE-2014-3507.svg)


## CVE-2008-5161
 Error handling in the SSH protocol in (1) SSH Tectia Client and Server and Connector 4.0 through 4.4.11, 5.0 through 5.2.4, and 5.3 through 5.3.8; Client and Server and ConnectSecure 6.0 through 6.0.4; Server for Linux on IBM System z 6.0.4; Server for IBM z/OS 5.5.1 and earlier, 6.0.0, and 6.0.1; and Client 4.0-J through 4.3.3-J and 4.0-K through 4.3.10-K; and (2) OpenSSH 4.7p1 and possibly other versions, when using a block cipher algorithm in Cipher Block Chaining (CBC) mode, makes it easier for remote attackers to recover certain plaintext data from an arbitrary block of ciphertext in an SSH session via unknown vectors.

- [https://github.com/dev-doom/OpenSSH_4.7p1](https://github.com/dev-doom/OpenSSH_4.7p1) :  ![starts](https://img.shields.io/github/stars/dev-doom/OpenSSH_4.7p1.svg) ![forks](https://img.shields.io/github/forks/dev-doom/OpenSSH_4.7p1.svg)


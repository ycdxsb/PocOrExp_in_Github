# Update 2025-02-23
## CVE-2025-26465
 A vulnerability was found in OpenSSH when the VerifyHostKeyDNS option is enabled. A machine-in-the-middle attack can be performed by a malicious machine impersonating a legit server. This issue occurs due to how OpenSSH mishandles error codes in specific conditions when verifying the host key. For an attack to be considered successful, the attacker needs to manage to exhaust the client's memory resource first, turning the attack complexity high.

- [https://github.com/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466](https://github.com/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466) :  ![starts](https://img.shields.io/github/stars/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466.svg) ![forks](https://img.shields.io/github/forks/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466.svg)


## CVE-2024-43583
 Winlogon Elevation of Privilege Vulnerability

- [https://github.com/Kvngtheta/CVE-2024-43583-PoC](https://github.com/Kvngtheta/CVE-2024-43583-PoC) :  ![starts](https://img.shields.io/github/stars/Kvngtheta/CVE-2024-43583-PoC.svg) ![forks](https://img.shields.io/github/forks/Kvngtheta/CVE-2024-43583-PoC.svg)


## CVE-2024-31903
 IBM Sterling B2B Integrator Standard Edition 6.0.0.0 through 6.1.2.5 and 6.2.0.0 through 6.2.0.2 allow an attacker on the local network to execute arbitrary code on the system, caused by the deserialization of untrusted data.

- [https://github.com/WithSecureLabs/ibm-sterling-b2b-integrator-poc](https://github.com/WithSecureLabs/ibm-sterling-b2b-integrator-poc) :  ![starts](https://img.shields.io/github/stars/WithSecureLabs/ibm-sterling-b2b-integrator-poc.svg) ![forks](https://img.shields.io/github/forks/WithSecureLabs/ibm-sterling-b2b-integrator-poc.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/funixone/CVE-2024-24919---Exploit-Script](https://github.com/funixone/CVE-2024-24919---Exploit-Script) :  ![starts](https://img.shields.io/github/stars/funixone/CVE-2024-24919---Exploit-Script.svg) ![forks](https://img.shields.io/github/forks/funixone/CVE-2024-24919---Exploit-Script.svg)


## CVE-2024-22243
 Applications that use UriComponentsBuilder to parse an externally provided URL (e.g. through a query parameter) AND perform validation checks on the host of the parsed URL may be vulnerable to a  open redirect https://cwe.mitre.org/data/definitions/601.html  attack or to a SSRF attack if the URL is used after passing validation checks.

- [https://github.com/Reivap/CVE-2024-22243](https://github.com/Reivap/CVE-2024-22243) :  ![starts](https://img.shields.io/github/stars/Reivap/CVE-2024-22243.svg) ![forks](https://img.shields.io/github/forks/Reivap/CVE-2024-22243.svg)


## CVE-2024-9047
 The WordPress File Upload plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 4.24.11 via wfu_file_downloader.php. This makes it possible for unauthenticated attackers to read or delete files outside of the originally intended directory. Successful exploitation requires the targeted WordPress installation to be using PHP 7.4 or earlier.

- [https://github.com/peiqiF4ck/WebFrameworkTools-5.1-main](https://github.com/peiqiF4ck/WebFrameworkTools-5.1-main) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/WebFrameworkTools-5.1-main.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/WebFrameworkTools-5.1-main.svg)


## CVE-2023-1698
 In multiple products of WAGO a vulnerability allows an unauthenticated, remote attacker to create new users and change the device configuration which can result in unintended behaviour, Denial of Service and full system compromise.

- [https://github.com/X3RX3SSec/CVE-2023-1698](https://github.com/X3RX3SSec/CVE-2023-1698) :  ![starts](https://img.shields.io/github/stars/X3RX3SSec/CVE-2023-1698.svg) ![forks](https://img.shields.io/github/forks/X3RX3SSec/CVE-2023-1698.svg)


## CVE-2022-22659
 A logic issue was addressed with improved state management. This issue is fixed in iOS 15.4 and iPadOS 15.4. An attacker in a privileged network position may be able to leak sensitive user information.

- [https://github.com/geo-chen/iOS](https://github.com/geo-chen/iOS) :  ![starts](https://img.shields.io/github/stars/geo-chen/iOS.svg) ![forks](https://img.shields.io/github/forks/geo-chen/iOS.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Taldrid1/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Taldrid1/cve-2021-41773.svg)


## CVE-2018-9338
 In ResStringPool::setTo of ResourceTypes.cpp, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Pazhanivelmani/frameworks_base_Android_6.0.1_r22_CVE-2018-9338](https://github.com/Pazhanivelmani/frameworks_base_Android_6.0.1_r22_CVE-2018-9338) :  ![starts](https://img.shields.io/github/stars/Pazhanivelmani/frameworks_base_Android_6.0.1_r22_CVE-2018-9338.svg) ![forks](https://img.shields.io/github/forks/Pazhanivelmani/frameworks_base_Android_6.0.1_r22_CVE-2018-9338.svg)


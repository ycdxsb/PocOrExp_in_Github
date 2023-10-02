# Update 2023-10-02
## CVE-2023-36845
 A PHP External Variable Modification vulnerability in J-Web of Juniper Networks Junos OS on EX Series and SRX Series allows an unauthenticated, network-based attacker to remotely execute code. Using a crafted request which sets the variable PHPRC an attacker is able to modify the PHP execution environment allowing the injection und execution of code. This issue affects Juniper Networks Junos OS on EX Series and SRX Series: * All versions prior to 20.4R3-S9; * 21.1 versions 21.1R1 and later; * 21.2 versions prior to 21.2R3-S7; * 21.3 versions prior to 21.3R3-S5; * 21.4 versions prior to 21.4R3-S5; * 22.1 versions prior to 22.1R3-S4; * 22.2 versions prior to 22.2R3-S2; * 22.3 versions prior to 22.3R2-S2, 22.3R3-S1; * 22.4 versions prior to 22.4R2-S1, 22.4R3; * 23.2 versions prior to 23.2R1-S1, 23.2R2.

- [https://github.com/simrotion13/CVE-2023-36845](https://github.com/simrotion13/CVE-2023-36845) :  ![starts](https://img.shields.io/github/stars/simrotion13/CVE-2023-36845.svg) ![forks](https://img.shields.io/github/forks/simrotion13/CVE-2023-36845.svg)


## CVE-2023-29357
 Microsoft SharePoint Server Elevation of Privilege Vulnerability

- [https://github.com/LuemmelSec/CVE-2023-29357](https://github.com/LuemmelSec/CVE-2023-29357) :  ![starts](https://img.shields.io/github/stars/LuemmelSec/CVE-2023-29357.svg) ![forks](https://img.shields.io/github/forks/LuemmelSec/CVE-2023-29357.svg)


## CVE-2023-3567
 A use-after-free flaw was found in vcs_read in drivers/tty/vt/vc_screen.c in vc_screen in the Linux Kernel. This issue may allow an attacker with local user access to cause a system crash or leak internal kernel information.

- [https://github.com/nidhi7598/linux-4.1.15_CVE-2023-3567](https://github.com/nidhi7598/linux-4.1.15_CVE-2023-3567) :  ![starts](https://img.shields.io/github/stars/nidhi7598/linux-4.1.15_CVE-2023-3567.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/linux-4.1.15_CVE-2023-3567.svg)
- [https://github.com/nidhi7598/linux-4.19.72_CVE-2023-3567](https://github.com/nidhi7598/linux-4.19.72_CVE-2023-3567) :  ![starts](https://img.shields.io/github/stars/nidhi7598/linux-4.19.72_CVE-2023-3567.svg) ![forks](https://img.shields.io/github/forks/nidhi7598/linux-4.19.72_CVE-2023-3567.svg)


## CVE-2022-25012
 Argus Surveillance DVR v4.0 employs weak password encryption.

- [https://github.com/deathflash1411/cve-2022-25012](https://github.com/deathflash1411/cve-2022-25012) :  ![starts](https://img.shields.io/github/stars/deathflash1411/cve-2022-25012.svg) ![forks](https://img.shields.io/github/forks/deathflash1411/cve-2022-25012.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2021-34621
 A vulnerability in the user registration component found in the ~/src/Classes/RegistrationAuth.php file of the ProfilePress WordPress plugin made it possible for users to register on sites as an administrator. This issue affects versions 3.0.0 - 3.1.3. .

- [https://github.com/navreet1425/CVE-2021-34621](https://github.com/navreet1425/CVE-2021-34621) :  ![starts](https://img.shields.io/github/stars/navreet1425/CVE-2021-34621.svg) ![forks](https://img.shields.io/github/forks/navreet1425/CVE-2021-34621.svg)


## CVE-2021-3572
 A flaw was found in python-pip in the way it handled Unicode separators in git references. A remote attacker could possibly use this issue to install a different revision on a repository. The highest threat from this vulnerability is to data integrity. This is fixed in python-pip version 21.1.

- [https://github.com/frenzymadness/CVE-2021-3572](https://github.com/frenzymadness/CVE-2021-3572) :  ![starts](https://img.shields.io/github/stars/frenzymadness/CVE-2021-3572.svg) ![forks](https://img.shields.io/github/forks/frenzymadness/CVE-2021-3572.svg)


## CVE-2019-1653
 A vulnerability in the web-based management interface of Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an unauthenticated, remote attacker to retrieve sensitive information. The vulnerability is due to improper access controls for URLs. An attacker could exploit this vulnerability by connecting to an affected device via HTTP or HTTPS and requesting specific URLs. A successful exploit could allow the attacker to download the router configuration or detailed diagnostic information. Cisco has released firmware updates that address this vulnerability.

- [https://github.com/0x27/CiscoRV320Dump](https://github.com/0x27/CiscoRV320Dump) :  ![starts](https://img.shields.io/github/stars/0x27/CiscoRV320Dump.svg) ![forks](https://img.shields.io/github/forks/0x27/CiscoRV320Dump.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/moTorky/CVE-2018-6574-POC](https://github.com/moTorky/CVE-2018-6574-POC) :  ![starts](https://img.shields.io/github/stars/moTorky/CVE-2018-6574-POC.svg) ![forks](https://img.shields.io/github/forks/moTorky/CVE-2018-6574-POC.svg)


## CVE-2017-10274
 Vulnerability in the Java SE component of Oracle Java SE (subcomponent: Smart Card IO). Supported versions that are affected are Java SE: 6u161, 7u151, 8u144 and 9. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE. Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Java SE accessible data as well as unauthorized access to critical data or complete access to all Java SE accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.0 Base Score 6.8 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N).

- [https://github.com/5l1v3r1/CVE-2017-10274](https://github.com/5l1v3r1/CVE-2017-10274) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2017-10274.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2017-10274.svg)


## CVE-2017-10271
 Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/5l1v3r1/CVE-2017-10274](https://github.com/5l1v3r1/CVE-2017-10274) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2017-10274.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2017-10274.svg)


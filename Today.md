# Update 2025-06-04
## CVE-2025-22224
 VMware ESXi, and Workstation contain a TOCTOU (Time-of-Check Time-of-Use) vulnerability that leads to an out-of-bounds write. A malicious actor with local administrative privileges on a virtual machine may exploit this issue to execute code as the virtual machine's VMX process running on the host.

- [https://github.com/voyagken/CVE-2025-22224-PoC](https://github.com/voyagken/CVE-2025-22224-PoC) :  ![starts](https://img.shields.io/github/stars/voyagken/CVE-2025-22224-PoC.svg) ![forks](https://img.shields.io/github/forks/voyagken/CVE-2025-22224-PoC.svg)


## CVE-2025-5280
 Out of bounds write in V8 in Google Chrome prior to 137.0.7151.55 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/voyagken/CVE-2025-5280-V8-OOB](https://github.com/voyagken/CVE-2025-5280-V8-OOB) :  ![starts](https://img.shields.io/github/stars/voyagken/CVE-2025-5280-V8-OOB.svg) ![forks](https://img.shields.io/github/forks/voyagken/CVE-2025-5280-V8-OOB.svg)


## CVE-2024-47176
 CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing functionality including, but not limited to, auto-discovering print services and shared printers. `cups-browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the `Get-Printer-Attributes` IPP request to an attacker controlled URL. When combined with other vulnerabilities, such as CVE-2024-47076, CVE-2024-47175, and CVE-2024-47177, an attacker can execute arbitrary commands remotely on the target machine without authentication when a malicious printer is printed to.

- [https://github.com/l0n3m4n/CVE-2024-47176](https://github.com/l0n3m4n/CVE-2024-47176) :  ![starts](https://img.shields.io/github/stars/l0n3m4n/CVE-2024-47176.svg) ![forks](https://img.shields.io/github/forks/l0n3m4n/CVE-2024-47176.svg)


## CVE-2024-39924
 An issue was discovered in Vaultwarden (formerly Bitwarden_RS) 1.30.3. A vulnerability has been identified in the authentication and authorization process of the endpoint responsible for altering the metadata of an emergency access. It permits an attacker with granted emergency access to escalate their privileges by changing the access level and modifying the wait time. Consequently, the attacker can gain full control over the vault (when only intended to have read access) while bypassing the necessary wait period.

- [https://github.com/l4rm4nd/PoC-CVE-2024-39924](https://github.com/l4rm4nd/PoC-CVE-2024-39924) :  ![starts](https://img.shields.io/github/stars/l4rm4nd/PoC-CVE-2024-39924.svg) ![forks](https://img.shields.io/github/forks/l4rm4nd/PoC-CVE-2024-39924.svg)


## CVE-2024-28784
 IBM QRadar SIEM 7.5 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session.  IBM X-Force ID:  285893.

- [https://github.com/CainSoulless/CVE-2024-28784](https://github.com/CainSoulless/CVE-2024-28784) :  ![starts](https://img.shields.io/github/stars/CainSoulless/CVE-2024-28784.svg) ![forks](https://img.shields.io/github/forks/CainSoulless/CVE-2024-28784.svg)


## CVE-2024-22274
 The vCenter Server contains an authenticated remote code execution vulnerability. A malicious actor with administrative privileges on the vCenter appliance shell may exploit this issue to run arbitrary commands on the underlying operating system.

- [https://github.com/l0n3m4n/CVE-2024-22274-RCE](https://github.com/l0n3m4n/CVE-2024-22274-RCE) :  ![starts](https://img.shields.io/github/stars/l0n3m4n/CVE-2024-22274-RCE.svg) ![forks](https://img.shields.io/github/forks/l0n3m4n/CVE-2024-22274-RCE.svg)


## CVE-2024-8353
 The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.16.1 via deserialization of untrusted input via several parameters like 'give_title' and 'card_address'. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to delete arbitrary files and achieve remote code execution. This is essentially the same vulnerability as CVE-2024-5932, however, it was discovered the the presence of stripslashes_deep on user_info allows the is_serialized check to be bypassed. This issue was mostly patched in 3.16.1, but further hardening was added in 3.16.2.

- [https://github.com/0xb0mb3r/CVE-2024-8353-PoC](https://github.com/0xb0mb3r/CVE-2024-8353-PoC) :  ![starts](https://img.shields.io/github/stars/0xb0mb3r/CVE-2024-8353-PoC.svg) ![forks](https://img.shields.io/github/forks/0xb0mb3r/CVE-2024-8353-PoC.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/l0n3m4n/CVE-2024-6387](https://github.com/l0n3m4n/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/l0n3m4n/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/l0n3m4n/CVE-2024-6387.svg)


## CVE-2024-5932
 The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.14.1 via deserialization of untrusted input from the 'give_title' parameter. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to execute code remotely, and to delete arbitrary files.

- [https://github.com/0xb0mb3r/CVE-2024-8353-PoC](https://github.com/0xb0mb3r/CVE-2024-8353-PoC) :  ![starts](https://img.shields.io/github/stars/0xb0mb3r/CVE-2024-8353-PoC.svg) ![forks](https://img.shields.io/github/forks/0xb0mb3r/CVE-2024-8353-PoC.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/l0n3m4n/CVE-2024-4577-RCE](https://github.com/l0n3m4n/CVE-2024-4577-RCE) :  ![starts](https://img.shields.io/github/stars/l0n3m4n/CVE-2024-4577-RCE.svg) ![forks](https://img.shields.io/github/forks/l0n3m4n/CVE-2024-4577-RCE.svg)


## CVE-2023-28293
 Windows Kernel Elevation of Privilege Vulnerability

- [https://github.com/HexilionLabs/CVE-2023-28293](https://github.com/HexilionLabs/CVE-2023-28293) :  ![starts](https://img.shields.io/github/stars/HexilionLabs/CVE-2023-28293.svg) ![forks](https://img.shields.io/github/forks/HexilionLabs/CVE-2023-28293.svg)


## CVE-2022-29078
 The ejs (aka Embedded JavaScript templates) package 3.1.6 for Node.js allows server-side template injection in settings[view options][outputFunctionName]. This is parsed as an internal option, and overwrites the outputFunctionName option with an arbitrary OS command (which is executed upon template compilation).

- [https://github.com/l0n3m4n/CVE-2022-29078](https://github.com/l0n3m4n/CVE-2022-29078) :  ![starts](https://img.shields.io/github/stars/l0n3m4n/CVE-2022-29078.svg) ![forks](https://img.shields.io/github/forks/l0n3m4n/CVE-2022-29078.svg)


## CVE-2014-4688
 pfSense before 2.1.4 allows remote authenticated users to execute arbitrary commands via (1) the hostname value to diag_dns.php in a Create Alias action, (2) the smartmonemail value to diag_smart.php, or (3) the database value to status_rrd_graph_img.php.

- [https://github.com/fenix0499/CVE-2014-4688-NodeJs-Exploit](https://github.com/fenix0499/CVE-2014-4688-NodeJs-Exploit) :  ![starts](https://img.shields.io/github/stars/fenix0499/CVE-2014-4688-NodeJs-Exploit.svg) ![forks](https://img.shields.io/github/forks/fenix0499/CVE-2014-4688-NodeJs-Exploit.svg)


## CVE-2014-0291
 DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: The CNA or individual who requested this candidate did not associate it with any vulnerability during 2014. Notes: none

- [https://github.com/niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204](https://github.com/niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204) :  ![starts](https://img.shields.io/github/stars/niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204.svg) ![forks](https://img.shields.io/github/forks/niccoX/patch-openssl-CVE-2014-0291_CVE-2015-0204.svg)


## CVE-2008-4250
 The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2, Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary code via a crafted RPC request that triggers the overflow during path canonicalization, as exploited in the wild by Gimmiv.A in October 2008, aka "Server Service Vulnerability."

- [https://github.com/NoTrustedx/Exploit_MS08-067](https://github.com/NoTrustedx/Exploit_MS08-067) :  ![starts](https://img.shields.io/github/stars/NoTrustedx/Exploit_MS08-067.svg) ![forks](https://img.shields.io/github/forks/NoTrustedx/Exploit_MS08-067.svg)


# Update 2022-03-16
## CVE-2022-24122
 kernel/ucount.c in the Linux kernel 5.14 through 5.16.4, when unprivileged user namespaces are enabled, allows a use-after-free and privilege escalation because a ucounts object can outlive its namespace.

- [https://github.com/meowmeowxw/CVE-2022-24122](https://github.com/meowmeowxw/CVE-2022-24122) :  ![starts](https://img.shields.io/github/stars/meowmeowxw/CVE-2022-24122.svg) ![forks](https://img.shields.io/github/forks/meowmeowxw/CVE-2022-24122.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/Bin4xin/bin4xin.github.io](https://github.com/Bin4xin/bin4xin.github.io) :  ![starts](https://img.shields.io/github/stars/Bin4xin/bin4xin.github.io.svg) ![forks](https://img.shields.io/github/forks/Bin4xin/bin4xin.github.io.svg)


## CVE-2022-22909
 HotelDruid v3.0.3 was discovered to contain a remote code execution (RCE) vulnerability which is exploited via an attacker inserting a crafted payload into the name field under the Create New Room module.

- [https://github.com/kaal18/CVE-2022-22909](https://github.com/kaal18/CVE-2022-22909) :  ![starts](https://img.shields.io/github/stars/kaal18/CVE-2022-22909.svg) ![forks](https://img.shields.io/github/forks/kaal18/CVE-2022-22909.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/CYB3RK1D/CVE-2022-0847-POC](https://github.com/CYB3RK1D/CVE-2022-0847-POC) :  ![starts](https://img.shields.io/github/stars/CYB3RK1D/CVE-2022-0847-POC.svg) ![forks](https://img.shields.io/github/forks/CYB3RK1D/CVE-2022-0847-POC.svg)
- [https://github.com/breachnix/dirty-pipe-poc](https://github.com/breachnix/dirty-pipe-poc) :  ![starts](https://img.shields.io/github/stars/breachnix/dirty-pipe-poc.svg) ![forks](https://img.shields.io/github/forks/breachnix/dirty-pipe-poc.svg)
- [https://github.com/Shotokhan/cve_2022_0847_shellcode](https://github.com/Shotokhan/cve_2022_0847_shellcode) :  ![starts](https://img.shields.io/github/stars/Shotokhan/cve_2022_0847_shellcode.svg) ![forks](https://img.shields.io/github/forks/Shotokhan/cve_2022_0847_shellcode.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)


## CVE-2021-33193
 A crafted method sent through HTTP/2 will bypass validation and be forwarded by mod_proxy, which can lead to request splitting or cache poisoning. This issue affects Apache HTTP Server 2.4.17 to 2.4.48.

- [https://github.com/jeremy-cxf/CVE-2021-33193](https://github.com/jeremy-cxf/CVE-2021-33193) :  ![starts](https://img.shields.io/github/stars/jeremy-cxf/CVE-2021-33193.svg) ![forks](https://img.shields.io/github/forks/jeremy-cxf/CVE-2021-33193.svg)


## CVE-2021-30955
 A race condition was addressed with improved state handling. This issue is fixed in macOS Monterey 12.1, watchOS 8.3, iOS 15.2 and iPadOS 15.2, tvOS 15.2. A malicious application may be able to execute arbitrary code with kernel privileges.

- [https://github.com/markie-dev/desc_race_A15](https://github.com/markie-dev/desc_race_A15) :  ![starts](https://img.shields.io/github/stars/markie-dev/desc_race_A15.svg) ![forks](https://img.shields.io/github/forks/markie-dev/desc_race_A15.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/nel0x/pwnkit-vulnerability](https://github.com/nel0x/pwnkit-vulnerability) :  ![starts](https://img.shields.io/github/stars/nel0x/pwnkit-vulnerability.svg) ![forks](https://img.shields.io/github/forks/nel0x/pwnkit-vulnerability.svg)
- [https://github.com/TomSgn/CVE-2021-4034](https://github.com/TomSgn/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/TomSgn/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/TomSgn/CVE-2021-4034.svg)
- [https://github.com/defhacks/cve-2021-4034](https://github.com/defhacks/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/defhacks/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/defhacks/cve-2021-4034.svg)
- [https://github.com/4n0nym0u5dk/CVE-2021-4034](https://github.com/4n0nym0u5dk/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/4n0nym0u5dk/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/4n0nym0u5dk/CVE-2021-4034.svg)


## CVE-2020-2021
 When Security Assertion Markup Language (SAML) authentication is enabled and the 'Validate Identity Provider Certificate' option is disabled (unchecked), improper verification of signatures in PAN-OS SAML authentication enables an unauthenticated network-based attacker to access protected resources. The attacker must have network access to the vulnerable server to exploit this vulnerability. This issue affects PAN-OS 9.1 versions earlier than PAN-OS 9.1.3; PAN-OS 9.0 versions earlier than PAN-OS 9.0.9; PAN-OS 8.1 versions earlier than PAN-OS 8.1.15, and all versions of PAN-OS 8.0 (EOL). This issue does not affect PAN-OS 7.1. This issue cannot be exploited if SAML is not used for authentication. This issue cannot be exploited if the 'Validate Identity Provider Certificate' option is enabled (checked) in the SAML Identity Provider Server Profile. Resources that can be protected by SAML-based single sign-on (SSO) authentication are: GlobalProtect Gateway, GlobalProtect Portal, GlobalProtect Clientless VPN, Authentication and Captive Portal, PAN-OS next-generation firewalls (PA-Series, VM-Series) and Panorama web interfaces, Prisma Access In the case of GlobalProtect Gateways, GlobalProtect Portal, Clientless VPN, Captive Portal, and Prisma Access, an unauthenticated attacker with network access to the affected servers can gain access to protected resources if allowed by configured authentication and Security policies. There is no impact on the integrity and availability of the gateway, portal or VPN server. An attacker cannot inspect or tamper with sessions of regular users. In the worst case, this is a critical severity vulnerability with a CVSS Base Score of 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N). In the case of PAN-OS and Panorama web interfaces, this issue allows an unauthenticated attacker with network access to the PAN-OS or Panorama web interfaces to log in as an administrator and perform administrative actions. In the worst-case scenario, this is a critical severity vulnerability with a CVSS Base Score of 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H). If the web interfaces are only accessible to a restricted management network, then the issue is lowered to a CVSS Base Score of 9.6 (CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H). Palo Alto Networks is not aware of any malicious attempts to exploit this vulnerability.

- [https://github.com/mr-r3b00t/CVE-2020-2021](https://github.com/mr-r3b00t/CVE-2020-2021) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2020-2021.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2020-2021.svg)


## CVE-2020-1054
 An elevation of privilege vulnerability exists in Windows when the Windows kernel-mode driver fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1143.

- [https://github.com/Al1ex/WindowsElevation](https://github.com/Al1ex/WindowsElevation) :  ![starts](https://img.shields.io/github/stars/Al1ex/WindowsElevation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/WindowsElevation.svg)


## CVE-2020-0443
 In LocaleList of LocaleList.java, there is a possible forced reboot due to an uncaught exception. This could lead to local denial of service requiring factory reset to restore with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-152410253

- [https://github.com/Supersonic/CVE-2020-0443](https://github.com/Supersonic/CVE-2020-0443) :  ![starts](https://img.shields.io/github/stars/Supersonic/CVE-2020-0443.svg) ![forks](https://img.shields.io/github/forks/Supersonic/CVE-2020-0443.svg)


## CVE-2019-5420
 A remote code execution vulnerability in development mode Rails &lt;5.2.2.1, &lt;6.0.0.beta3 can allow an attacker to guess the automatically generated development mode secret token. This secret token can be used in combination with other Rails internals to escalate to a remote code execution exploit.

- [https://github.com/trickstersec/CVE-2019-5420](https://github.com/trickstersec/CVE-2019-5420) :  ![starts](https://img.shields.io/github/stars/trickstersec/CVE-2019-5420.svg) ![forks](https://img.shields.io/github/forks/trickstersec/CVE-2019-5420.svg)


## CVE-2018-17418
 Monstra CMS 3.0.4 allows remote attackers to execute arbitrary PHP code via a mixed-case file extension, as demonstrated by the 123.PhP filename, because plugins\box\filesmanager\filesmanager.admin.php mishandles the forbidden_types variable.

- [https://github.com/Jx0n0/monstra_cms-3.0.4--getshell](https://github.com/Jx0n0/monstra_cms-3.0.4--getshell) :  ![starts](https://img.shields.io/github/stars/Jx0n0/monstra_cms-3.0.4--getshell.svg) ![forks](https://img.shields.io/github/forks/Jx0n0/monstra_cms-3.0.4--getshell.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/PrestaDZ/vsftpd-2.3.4](https://github.com/PrestaDZ/vsftpd-2.3.4) :  ![starts](https://img.shields.io/github/stars/PrestaDZ/vsftpd-2.3.4.svg) ![forks](https://img.shields.io/github/forks/PrestaDZ/vsftpd-2.3.4.svg)


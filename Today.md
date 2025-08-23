# Update 2025-08-23
## CVE-2025-55287
 Genealogy is a family tree PHP application. Prior to 4.4.0, Authenticated Stored Cross-Site Scripting (XSS) vulnerability was identified in the Genealogy application. Authenticated attackers could run arbitrary JavaScript in another user’s session, leading to session hijacking, data theft, and UI manipulation. This vulnerability is fixed in 4.4.0.

- [https://github.com/Eternalvalhalla/CVE-2025-55287-POC](https://github.com/Eternalvalhalla/CVE-2025-55287-POC) :  ![starts](https://img.shields.io/github/stars/Eternalvalhalla/CVE-2025-55287-POC.svg) ![forks](https://img.shields.io/github/forks/Eternalvalhalla/CVE-2025-55287-POC.svg)


## CVE-2025-53786
 On April 18th 2025, Microsoft announced Exchange Server Security Changes for Hybrid Deployments and accompanying non-security Hot Fix. Microsoft made these changes in the general interest of improving the security of hybrid Exchange deployments. Following further investigation, Microsoft identified specific security implications tied to the guidance and configuration steps outlined in the April announcement. Microsoft is issuing CVE-2025-53786 to document a vulnerability that is addressed by taking the steps documented with the April 18th announcement. Microsoft strongly recommends reading the information, installing the April 2025 (or later) Hot Fix and implementing the changes in your Exchange Server and hybrid environment.

- [https://github.com/vincentdthe/CVE-2025-53786](https://github.com/vincentdthe/CVE-2025-53786) :  ![starts](https://img.shields.io/github/stars/vincentdthe/CVE-2025-53786.svg) ![forks](https://img.shields.io/github/forks/vincentdthe/CVE-2025-53786.svg)


## CVE-2025-43300
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in macOS Sonoma 14.7.8, macOS Ventura 13.7.8, iPadOS 17.7.10, macOS Sequoia 15.6.1, iOS 18.6.2 and iPadOS 18.6.2. Processing a malicious image file may result in memory corruption. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals.

- [https://github.com/h4xnz/CVE-2025-43300](https://github.com/h4xnz/CVE-2025-43300) :  ![starts](https://img.shields.io/github/stars/h4xnz/CVE-2025-43300.svg) ![forks](https://img.shields.io/github/forks/h4xnz/CVE-2025-43300.svg)


## CVE-2025-25256
 An improper neutralization of special elements used in an OS command ('OS Command Injection') vulnerability [CWE-78] in Fortinet FortiSIEM version 7.3.0 through 7.3.1, 7.2.0 through 7.2.5, 7.1.0 through 7.1.7, 7.0.0 through 7.0.3 and before 6.7.9 allows an unauthenticated attacker to execute unauthorized code or commands via crafted CLI requests.

- [https://github.com/JMS-Security/CVE-2025-25256-PoC](https://github.com/JMS-Security/CVE-2025-25256-PoC) :  ![starts](https://img.shields.io/github/stars/JMS-Security/CVE-2025-25256-PoC.svg) ![forks](https://img.shields.io/github/forks/JMS-Security/CVE-2025-25256-PoC.svg)


## CVE-2025-22235
  *  Your application does not handle requests to /null or this path does not need protection

- [https://github.com/idealzh/cve-2025-22235-demo](https://github.com/idealzh/cve-2025-22235-demo) :  ![starts](https://img.shields.io/github/stars/idealzh/cve-2025-22235-demo.svg) ![forks](https://img.shields.io/github/forks/idealzh/cve-2025-22235-demo.svg)


## CVE-2025-9132
 Out of bounds write in V8 in Google Chrome prior to 139.0.7258.138 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/barbaraeivyu/CVE-2025-9132](https://github.com/barbaraeivyu/CVE-2025-9132) :  ![starts](https://img.shields.io/github/stars/barbaraeivyu/CVE-2025-9132.svg) ![forks](https://img.shields.io/github/forks/barbaraeivyu/CVE-2025-9132.svg)


## CVE-2025-8671
 A mismatch caused by client-triggered server-sent stream resets between HTTP/2 specifications and the internal architectures of some HTTP/2 implementations may result in excessive server resource consumption leading to denial-of-service (DoS).  By opening streams and then rapidly triggering the server to reset them—using malformed frames or flow control errors—an attacker can exploit incorrect stream accounting. Streams reset by the server are considered closed at the protocol level, even though backend processing continues. This allows a client to cause the server to handle an unbounded number of concurrent streams on a single connection. This CVE will be updated as affected product details are released.

- [https://github.com/mateusm1403/PoC-CVE-2025-8671-MadeYouReset-HTTP-2](https://github.com/mateusm1403/PoC-CVE-2025-8671-MadeYouReset-HTTP-2) :  ![starts](https://img.shields.io/github/stars/mateusm1403/PoC-CVE-2025-8671-MadeYouReset-HTTP-2.svg) ![forks](https://img.shields.io/github/forks/mateusm1403/PoC-CVE-2025-8671-MadeYouReset-HTTP-2.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/ghostn4444/CVE-2025-8088](https://github.com/ghostn4444/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/ghostn4444/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/ghostn4444/CVE-2025-8088.svg)
- [https://github.com/amel-62/WinRAR-CVE-2025-8088-PoC-RAR](https://github.com/amel-62/WinRAR-CVE-2025-8088-PoC-RAR) :  ![starts](https://img.shields.io/github/stars/amel-62/WinRAR-CVE-2025-8088-PoC-RAR.svg) ![forks](https://img.shields.io/github/forks/amel-62/WinRAR-CVE-2025-8088-PoC-RAR.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/mistrustt/PAM-UDisks-PrivEsc-Metasploit](https://github.com/mistrustt/PAM-UDisks-PrivEsc-Metasploit) :  ![starts](https://img.shields.io/github/stars/mistrustt/PAM-UDisks-PrivEsc-Metasploit.svg) ![forks](https://img.shields.io/github/forks/mistrustt/PAM-UDisks-PrivEsc-Metasploit.svg)


## CVE-2025-6018
 A Local Privilege Escalation (LPE) vulnerability has been discovered in pam-config within Linux Pluggable Authentication Modules (PAM). This flaw allows an unprivileged local attacker (for example, a user logged in via SSH) to obtain the elevated privileges normally reserved for a physically present, "allow_active" user. The highest risk is that the attacker can then perform all allow_active yes Polkit actions, which are typically restricted to console users, potentially gaining unauthorized control over system configurations, services, or other sensitive operations.

- [https://github.com/mistrustt/PAM-UDisks-PrivEsc-Metasploit](https://github.com/mistrustt/PAM-UDisks-PrivEsc-Metasploit) :  ![starts](https://img.shields.io/github/stars/mistrustt/PAM-UDisks-PrivEsc-Metasploit.svg) ![forks](https://img.shields.io/github/forks/mistrustt/PAM-UDisks-PrivEsc-Metasploit.svg)


## CVE-2024-2961
 The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.

- [https://github.com/scriptSails/glibcs](https://github.com/scriptSails/glibcs) :  ![starts](https://img.shields.io/github/stars/scriptSails/glibcs.svg) ![forks](https://img.shields.io/github/forks/scriptSails/glibcs.svg)


## CVE-2023-41892
 Craft CMS is a platform for creating digital experiences. This is a high-impact, low-complexity attack vector. Users running Craft installations before 4.4.15 are encouraged to update to at least that version to mitigate the issue. This issue has been fixed in Craft CMS 4.4.15.

- [https://github.com/user01-1/CVE-2023-41892_poc](https://github.com/user01-1/CVE-2023-41892_poc) :  ![starts](https://img.shields.io/github/stars/user01-1/CVE-2023-41892_poc.svg) ![forks](https://img.shields.io/github/forks/user01-1/CVE-2023-41892_poc.svg)


## CVE-2023-25813
 Sequelize is a Node.js ORM tool. In versions prior to 6.19.1 a SQL injection exploit exists related to replacements. Parameters which are passed through replacements are not properly escaped which can lead to arbitrary SQL injection depending on the specific queries in use. The issue has been fixed in Sequelize 6.19.1. Users are advised to upgrade. Users unable to upgrade should not use the `replacements` and the `where` option in the same query.

- [https://github.com/SOONHO-21/curd_CVE_2023_25813](https://github.com/SOONHO-21/curd_CVE_2023_25813) :  ![starts](https://img.shields.io/github/stars/SOONHO-21/curd_CVE_2023_25813.svg) ![forks](https://img.shields.io/github/forks/SOONHO-21/curd_CVE_2023_25813.svg)


## CVE-2022-32532
 Apache Shiro before 1.9.1, A RegexRequestMatcher can be misconfigured to be bypassed on some servlet containers. Applications using RegExPatternMatcher with `.` in the regular expression are possibly vulnerable to an authorization bypass.

- [https://github.com/my0113/shiro-cve-2022-32532](https://github.com/my0113/shiro-cve-2022-32532) :  ![starts](https://img.shields.io/github/stars/my0113/shiro-cve-2022-32532.svg) ![forks](https://img.shields.io/github/forks/my0113/shiro-cve-2022-32532.svg)


## CVE-2022-4244
 A flaw was found in codeplex-codehaus. A directory traversal attack (also known as path traversal) aims to access files and directories stored outside the intended folder. By manipulating files with "dot-dot-slash (../)" sequences and their variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on the file system, including application source code, configuration, and other critical system files.

- [https://github.com/shoucheng3/codehaus-plexus__plexus-utils_CVE-2022-4244_3-0-23](https://github.com/shoucheng3/codehaus-plexus__plexus-utils_CVE-2022-4244_3-0-23) :  ![starts](https://img.shields.io/github/stars/shoucheng3/codehaus-plexus__plexus-utils_CVE-2022-4244_3-0-23.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/codehaus-plexus__plexus-utils_CVE-2022-4244_3-0-23.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/jxpsx/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/jxpsx/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/jxpsx/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/jxpsx/CVE-2022-0847-DirtyPipe-Exploits.svg)
- [https://github.com/ayushx007/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/ayushx007/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/ayushx007/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/ayushx007/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2021-4428
 A vulnerability has been found in what3words Autosuggest Plugin up to 4.0.0 on WordPress and classified as problematic. Affected by this vulnerability is the function enqueue_scripts of the file w3w-autosuggest/public/class-w3w-autosuggest-public.php of the component Setting Handler. The manipulation leads to information disclosure. The attack can be launched remotely. Upgrading to version 4.0.1 is able to address this issue. The patch is named dd59cbac5f86057d6a73b87007c08b8bfa0c32ac. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-234247.

- [https://github.com/lov3r/cve-2021-44228-log4j-exploits](https://github.com/lov3r/cve-2021-44228-log4j-exploits) :  ![starts](https://img.shields.io/github/stars/lov3r/cve-2021-44228-log4j-exploits.svg) ![forks](https://img.shields.io/github/forks/lov3r/cve-2021-44228-log4j-exploits.svg)
- [https://github.com/Grupo-Kapa-7/CVE-2021-44228-Log4j-PoC-RCE](https://github.com/Grupo-Kapa-7/CVE-2021-44228-Log4j-PoC-RCE) :  ![starts](https://img.shields.io/github/stars/Grupo-Kapa-7/CVE-2021-44228-Log4j-PoC-RCE.svg) ![forks](https://img.shields.io/github/forks/Grupo-Kapa-7/CVE-2021-44228-Log4j-PoC-RCE.svg)
- [https://github.com/CERT-hr/Log4Shell](https://github.com/CERT-hr/Log4Shell) :  ![starts](https://img.shields.io/github/stars/CERT-hr/Log4Shell.svg) ![forks](https://img.shields.io/github/forks/CERT-hr/Log4Shell.svg)


## CVE-2021-4104
 JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration. The attacker can provide TopicBindingName and TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2 when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/NCSC-NL/log4shell](https://github.com/NCSC-NL/log4shell) :  ![starts](https://img.shields.io/github/stars/NCSC-NL/log4shell.svg) ![forks](https://img.shields.io/github/forks/NCSC-NL/log4shell.svg)
- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)
- [https://github.com/Qualys/log4jscanwin](https://github.com/Qualys/log4jscanwin) :  ![starts](https://img.shields.io/github/stars/Qualys/log4jscanwin.svg) ![forks](https://img.shields.io/github/forks/Qualys/log4jscanwin.svg)
- [https://github.com/HynekPetrak/log4shell-finder](https://github.com/HynekPetrak/log4shell-finder) :  ![starts](https://img.shields.io/github/stars/HynekPetrak/log4shell-finder.svg) ![forks](https://img.shields.io/github/forks/HynekPetrak/log4shell-finder.svg)
- [https://github.com/cckuailong/log4shell_1.x](https://github.com/cckuailong/log4shell_1.x) :  ![starts](https://img.shields.io/github/stars/cckuailong/log4shell_1.x.svg) ![forks](https://img.shields.io/github/forks/cckuailong/log4shell_1.x.svg)
- [https://github.com/thl-cmk/CVE-log4j-check_mk-plugin](https://github.com/thl-cmk/CVE-log4j-check_mk-plugin) :  ![starts](https://img.shields.io/github/stars/thl-cmk/CVE-log4j-check_mk-plugin.svg) ![forks](https://img.shields.io/github/forks/thl-cmk/CVE-log4j-check_mk-plugin.svg)
- [https://github.com/TheInterception/Log4J-Simulation-Tool](https://github.com/TheInterception/Log4J-Simulation-Tool) :  ![starts](https://img.shields.io/github/stars/TheInterception/Log4J-Simulation-Tool.svg) ![forks](https://img.shields.io/github/forks/TheInterception/Log4J-Simulation-Tool.svg)
- [https://github.com/cuijiung/log4j-CVE-2021-4104](https://github.com/cuijiung/log4j-CVE-2021-4104) :  ![starts](https://img.shields.io/github/stars/cuijiung/log4j-CVE-2021-4104.svg) ![forks](https://img.shields.io/github/forks/cuijiung/log4j-CVE-2021-4104.svg)
- [https://github.com/open-AIMS/log4j](https://github.com/open-AIMS/log4j) :  ![starts](https://img.shields.io/github/stars/open-AIMS/log4j.svg) ![forks](https://img.shields.io/github/forks/open-AIMS/log4j.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/berdav/CVE-2021-4034](https://github.com/berdav/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/berdav/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/berdav/CVE-2021-4034.svg)
- [https://github.com/jm33-m0/emp3r0r](https://github.com/jm33-m0/emp3r0r) :  ![starts](https://img.shields.io/github/stars/jm33-m0/emp3r0r.svg) ![forks](https://img.shields.io/github/forks/jm33-m0/emp3r0r.svg)
- [https://github.com/ly4k/PwnKit](https://github.com/ly4k/PwnKit) :  ![starts](https://img.shields.io/github/stars/ly4k/PwnKit.svg) ![forks](https://img.shields.io/github/forks/ly4k/PwnKit.svg)
- [https://github.com/arthepsy/CVE-2021-4034](https://github.com/arthepsy/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/arthepsy/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/arthepsy/CVE-2021-4034.svg)
- [https://github.com/Al1ex/LinuxEelvation](https://github.com/Al1ex/LinuxEelvation) :  ![starts](https://img.shields.io/github/stars/Al1ex/LinuxEelvation.svg) ![forks](https://img.shields.io/github/forks/Al1ex/LinuxEelvation.svg)
- [https://github.com/PwnFunction/CVE-2021-4034](https://github.com/PwnFunction/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/PwnFunction/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/PwnFunction/CVE-2021-4034.svg)
- [https://github.com/joeammond/CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/joeammond/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/joeammond/CVE-2021-4034.svg)
- [https://github.com/dzonerzy/poc-cve-2021-4034](https://github.com/dzonerzy/poc-cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/dzonerzy/poc-cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/dzonerzy/poc-cve-2021-4034.svg)
- [https://github.com/Rvn0xsy/CVE-2021-4034](https://github.com/Rvn0xsy/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Rvn0xsy/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Rvn0xsy/CVE-2021-4034.svg)
- [https://github.com/luijait/PwnKit-Exploit](https://github.com/luijait/PwnKit-Exploit) :  ![starts](https://img.shields.io/github/stars/luijait/PwnKit-Exploit.svg) ![forks](https://img.shields.io/github/forks/luijait/PwnKit-Exploit.svg)
- [https://github.com/Ayrx/CVE-2021-4034](https://github.com/Ayrx/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Ayrx/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Ayrx/CVE-2021-4034.svg)
- [https://github.com/Nickguitar/YAPS](https://github.com/Nickguitar/YAPS) :  ![starts](https://img.shields.io/github/stars/Nickguitar/YAPS.svg) ![forks](https://img.shields.io/github/forks/Nickguitar/YAPS.svg)
- [https://github.com/EstamelGG/CVE-2021-4034-NoGCC](https://github.com/EstamelGG/CVE-2021-4034-NoGCC) :  ![starts](https://img.shields.io/github/stars/EstamelGG/CVE-2021-4034-NoGCC.svg) ![forks](https://img.shields.io/github/forks/EstamelGG/CVE-2021-4034-NoGCC.svg)
- [https://github.com/ryaagard/CVE-2021-4034](https://github.com/ryaagard/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ryaagard/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ryaagard/CVE-2021-4034.svg)
- [https://github.com/nikaiw/CVE-2021-4034](https://github.com/nikaiw/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/nikaiw/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/nikaiw/CVE-2021-4034.svg)
- [https://github.com/jm33-m0/go-lpe](https://github.com/jm33-m0/go-lpe) :  ![starts](https://img.shields.io/github/stars/jm33-m0/go-lpe.svg) ![forks](https://img.shields.io/github/forks/jm33-m0/go-lpe.svg)
- [https://github.com/khulnasoft-lab/awesome-security](https://github.com/khulnasoft-lab/awesome-security) :  ![starts](https://img.shields.io/github/stars/khulnasoft-lab/awesome-security.svg) ![forks](https://img.shields.io/github/forks/khulnasoft-lab/awesome-security.svg)
- [https://github.com/zhzyker/CVE-2021-4034](https://github.com/zhzyker/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/zhzyker/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/zhzyker/CVE-2021-4034.svg)
- [https://github.com/PeterGottesman/pwnkit-exploit](https://github.com/PeterGottesman/pwnkit-exploit) :  ![starts](https://img.shields.io/github/stars/PeterGottesman/pwnkit-exploit.svg) ![forks](https://img.shields.io/github/forks/PeterGottesman/pwnkit-exploit.svg)
- [https://github.com/DanaEpp/pwncat_pwnkit](https://github.com/DanaEpp/pwncat_pwnkit) :  ![starts](https://img.shields.io/github/stars/DanaEpp/pwncat_pwnkit.svg) ![forks](https://img.shields.io/github/forks/DanaEpp/pwncat_pwnkit.svg)
- [https://github.com/mebeim/CVE-2021-4034](https://github.com/mebeim/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/mebeim/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/mebeim/CVE-2021-4034.svg)
- [https://github.com/ck00004/CVE-2021-4034](https://github.com/ck00004/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ck00004/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ck00004/CVE-2021-4034.svg)
- [https://github.com/c3c/CVE-2021-4034](https://github.com/c3c/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/c3c/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/c3c/CVE-2021-4034.svg)
- [https://github.com/c3l3si4n/pwnkit](https://github.com/c3l3si4n/pwnkit) :  ![starts](https://img.shields.io/github/stars/c3l3si4n/pwnkit.svg) ![forks](https://img.shields.io/github/forks/c3l3si4n/pwnkit.svg)
- [https://github.com/Almorabea/pkexec-exploit](https://github.com/Almorabea/pkexec-exploit) :  ![starts](https://img.shields.io/github/stars/Almorabea/pkexec-exploit.svg) ![forks](https://img.shields.io/github/forks/Almorabea/pkexec-exploit.svg)
- [https://github.com/kimusan/pkwner](https://github.com/kimusan/pkwner) :  ![starts](https://img.shields.io/github/stars/kimusan/pkwner.svg) ![forks](https://img.shields.io/github/forks/kimusan/pkwner.svg)
- [https://github.com/evdenis/lsm_bpf_check_argc0](https://github.com/evdenis/lsm_bpf_check_argc0) :  ![starts](https://img.shields.io/github/stars/evdenis/lsm_bpf_check_argc0.svg) ![forks](https://img.shields.io/github/forks/evdenis/lsm_bpf_check_argc0.svg)
- [https://github.com/dadvlingd/CVE-2021-4034](https://github.com/dadvlingd/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/dadvlingd/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/dadvlingd/CVE-2021-4034.svg)
- [https://github.com/NeonWhiteRabbit/CVE-2021-4034](https://github.com/NeonWhiteRabbit/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/NeonWhiteRabbit/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/NeonWhiteRabbit/CVE-2021-4034.svg)
- [https://github.com/JohnHammond/CVE-2021-4034](https://github.com/JohnHammond/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/JohnHammond/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/JohnHammond/CVE-2021-4034.svg)
- [https://github.com/An00bRektn/CVE-2021-4034](https://github.com/An00bRektn/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/An00bRektn/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/An00bRektn/CVE-2021-4034.svg)
- [https://github.com/chenaotian/CVE-2021-4034](https://github.com/chenaotian/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2021-4034.svg)
- [https://github.com/Bin4xin/bin4xin.github.io](https://github.com/Bin4xin/bin4xin.github.io) :  ![starts](https://img.shields.io/github/stars/Bin4xin/bin4xin.github.io.svg) ![forks](https://img.shields.io/github/forks/Bin4xin/bin4xin.github.io.svg)
- [https://github.com/wudicainiao/cve-2021-4034](https://github.com/wudicainiao/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/wudicainiao/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/wudicainiao/cve-2021-4034.svg)
- [https://github.com/drapl0n/pwnKit](https://github.com/drapl0n/pwnKit) :  ![starts](https://img.shields.io/github/stars/drapl0n/pwnKit.svg) ![forks](https://img.shields.io/github/forks/drapl0n/pwnKit.svg)
- [https://github.com/Audiobahn/CVE-2021-4034](https://github.com/Audiobahn/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Audiobahn/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Audiobahn/CVE-2021-4034.svg)
- [https://github.com/rvizx/CVE-2021-4034](https://github.com/rvizx/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/rvizx/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/rvizx/CVE-2021-4034.svg)
- [https://github.com/OXDBXKXO/ez-pwnkit](https://github.com/OXDBXKXO/ez-pwnkit) :  ![starts](https://img.shields.io/github/stars/OXDBXKXO/ez-pwnkit.svg) ![forks](https://img.shields.io/github/forks/OXDBXKXO/ez-pwnkit.svg)
- [https://github.com/sofire/polkit-0.96-CVE-2021-4034](https://github.com/sofire/polkit-0.96-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/sofire/polkit-0.96-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/sofire/polkit-0.96-CVE-2021-4034.svg)
- [https://github.com/jpmcb/pwnkit-go](https://github.com/jpmcb/pwnkit-go) :  ![starts](https://img.shields.io/github/stars/jpmcb/pwnkit-go.svg) ![forks](https://img.shields.io/github/forks/jpmcb/pwnkit-go.svg)
- [https://github.com/Kirill89/CVE-2021-4034](https://github.com/Kirill89/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Kirill89/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Kirill89/CVE-2021-4034.svg)
- [https://github.com/clubby789/CVE-2021-4034](https://github.com/clubby789/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/clubby789/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/clubby789/CVE-2021-4034.svg)
- [https://github.com/navisec/CVE-2021-4034-PwnKit](https://github.com/navisec/CVE-2021-4034-PwnKit) :  ![starts](https://img.shields.io/github/stars/navisec/CVE-2021-4034-PwnKit.svg) ![forks](https://img.shields.io/github/forks/navisec/CVE-2021-4034-PwnKit.svg)
- [https://github.com/Yakumwamba/POC-CVE-2021-4034](https://github.com/Yakumwamba/POC-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Yakumwamba/POC-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Yakumwamba/POC-CVE-2021-4034.svg)
- [https://github.com/Y3A/CVE-2021-4034](https://github.com/Y3A/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Y3A/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Y3A/CVE-2021-4034.svg)
- [https://github.com/Al1ex/CVE-2021-4034](https://github.com/Al1ex/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2021-4034.svg)
- [https://github.com/callrbx/pkexec-lpe-poc](https://github.com/callrbx/pkexec-lpe-poc) :  ![starts](https://img.shields.io/github/stars/callrbx/pkexec-lpe-poc.svg) ![forks](https://img.shields.io/github/forks/callrbx/pkexec-lpe-poc.svg)
- [https://github.com/whokilleddb/CVE-2021-4034](https://github.com/whokilleddb/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/whokilleddb/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/whokilleddb/CVE-2021-4034.svg)
- [https://github.com/TheJoyOfHacking/berdav-CVE-2021-4034](https://github.com/TheJoyOfHacking/berdav-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/TheJoyOfHacking/berdav-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/TheJoyOfHacking/berdav-CVE-2021-4034.svg)
- [https://github.com/tahaafarooq/poppy](https://github.com/tahaafarooq/poppy) :  ![starts](https://img.shields.io/github/stars/tahaafarooq/poppy.svg) ![forks](https://img.shields.io/github/forks/tahaafarooq/poppy.svg)
- [https://github.com/FDlucifer/Pwnkit-go](https://github.com/FDlucifer/Pwnkit-go) :  ![starts](https://img.shields.io/github/stars/FDlucifer/Pwnkit-go.svg) ![forks](https://img.shields.io/github/forks/FDlucifer/Pwnkit-go.svg)
- [https://github.com/artemis-mike/cve-2021-4034](https://github.com/artemis-mike/cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/artemis-mike/cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/artemis-mike/cve-2021-4034.svg)
- [https://github.com/x04000/CVE-2021-4034](https://github.com/x04000/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/x04000/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/x04000/CVE-2021-4034.svg)
- [https://github.com/hohn/codeql-sample-polkit](https://github.com/hohn/codeql-sample-polkit) :  ![starts](https://img.shields.io/github/stars/hohn/codeql-sample-polkit.svg) ![forks](https://img.shields.io/github/forks/hohn/codeql-sample-polkit.svg)
- [https://github.com/mutur4/Hacking-Scripts](https://github.com/mutur4/Hacking-Scripts) :  ![starts](https://img.shields.io/github/stars/mutur4/Hacking-Scripts.svg) ![forks](https://img.shields.io/github/forks/mutur4/Hacking-Scripts.svg)
- [https://github.com/codiobert/pwnkit-scanner](https://github.com/codiobert/pwnkit-scanner) :  ![starts](https://img.shields.io/github/stars/codiobert/pwnkit-scanner.svg) ![forks](https://img.shields.io/github/forks/codiobert/pwnkit-scanner.svg)
- [https://github.com/locksec/CVE-2021-4034](https://github.com/locksec/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/locksec/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/locksec/CVE-2021-4034.svg)
- [https://github.com/LJP-TW/CVE-2021-4034](https://github.com/LJP-TW/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/LJP-TW/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/LJP-TW/CVE-2021-4034.svg)
- [https://github.com/thatstraw/CVE-2021-4034](https://github.com/thatstraw/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/thatstraw/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/thatstraw/CVE-2021-4034.svg)
- [https://github.com/Anonymous-Family/CVE-2021-4034](https://github.com/Anonymous-Family/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Anonymous-Family/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Anonymous-Family/CVE-2021-4034.svg)
- [https://github.com/gbrsh/CVE-2021-4034](https://github.com/gbrsh/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/gbrsh/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/gbrsh/CVE-2021-4034.svg)
- [https://github.com/Pixailz/CVE-2021-4034](https://github.com/Pixailz/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Pixailz/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Pixailz/CVE-2021-4034.svg)
- [https://github.com/cd80-ctf/CVE-2021-4034](https://github.com/cd80-ctf/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/cd80-ctf/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/cd80-ctf/CVE-2021-4034.svg)
- [https://github.com/deoxykev/CVE-2021-4034-Rust](https://github.com/deoxykev/CVE-2021-4034-Rust) :  ![starts](https://img.shields.io/github/stars/deoxykev/CVE-2021-4034-Rust.svg) ![forks](https://img.shields.io/github/forks/deoxykev/CVE-2021-4034-Rust.svg)
- [https://github.com/wechicken456/CVE-2021-4034-CTF-writeup](https://github.com/wechicken456/CVE-2021-4034-CTF-writeup) :  ![starts](https://img.shields.io/github/stars/wechicken456/CVE-2021-4034-CTF-writeup.svg) ![forks](https://img.shields.io/github/forks/wechicken456/CVE-2021-4034-CTF-writeup.svg)
- [https://github.com/x04000/AutoPwnkit](https://github.com/x04000/AutoPwnkit) :  ![starts](https://img.shields.io/github/stars/x04000/AutoPwnkit.svg) ![forks](https://img.shields.io/github/forks/x04000/AutoPwnkit.svg)
- [https://github.com/Nosferatuvjr/PwnKit](https://github.com/Nosferatuvjr/PwnKit) :  ![starts](https://img.shields.io/github/stars/Nosferatuvjr/PwnKit.svg) ![forks](https://img.shields.io/github/forks/Nosferatuvjr/PwnKit.svg)
- [https://github.com/NiS3x/CVE-2021-4034](https://github.com/NiS3x/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/NiS3x/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/NiS3x/CVE-2021-4034.svg)
- [https://github.com/oreosec/pwnkit](https://github.com/oreosec/pwnkit) :  ![starts](https://img.shields.io/github/stars/oreosec/pwnkit.svg) ![forks](https://img.shields.io/github/forks/oreosec/pwnkit.svg)
- [https://github.com/moldabekov/CVE-2021-4034](https://github.com/moldabekov/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/moldabekov/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/moldabekov/CVE-2021-4034.svg)
- [https://github.com/0x01-sec/CVE-2021-4034-](https://github.com/0x01-sec/CVE-2021-4034-) :  ![starts](https://img.shields.io/github/stars/0x01-sec/CVE-2021-4034-.svg) ![forks](https://img.shields.io/github/forks/0x01-sec/CVE-2021-4034-.svg)
- [https://github.com/vilasboasph/CVE-2021-4034](https://github.com/vilasboasph/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/vilasboasph/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/vilasboasph/CVE-2021-4034.svg)
- [https://github.com/LukeGix/CVE-2021-4034](https://github.com/LukeGix/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/LukeGix/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/LukeGix/CVE-2021-4034.svg)
- [https://github.com/Tanmay-N/CVE-2021-4034](https://github.com/Tanmay-N/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Tanmay-N/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Tanmay-N/CVE-2021-4034.svg)
- [https://github.com/deep-know/CVE-2021-4034](https://github.com/deep-know/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/deep-know/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/deep-know/CVE-2021-4034.svg)
- [https://github.com/ayypril/CVE-2021-4034](https://github.com/ayypril/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ayypril/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ayypril/CVE-2021-4034.svg)
- [https://github.com/HrishitJoshi/CVE-2021-4034](https://github.com/HrishitJoshi/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/HrishitJoshi/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/HrishitJoshi/CVE-2021-4034.svg)
- [https://github.com/mutur4/CVE-2021-4034](https://github.com/mutur4/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/mutur4/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/mutur4/CVE-2021-4034.svg)
- [https://github.com/A1vinSmith/CVE-2021-4034](https://github.com/A1vinSmith/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/A1vinSmith/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/A1vinSmith/CVE-2021-4034.svg)
- [https://github.com/JoyGhoshs/CVE-2021-4034](https://github.com/JoyGhoshs/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/JoyGhoshs/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/JoyGhoshs/CVE-2021-4034.svg)
- [https://github.com/hahaleyile/CVE-2021-4034](https://github.com/hahaleyile/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/hahaleyile/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/hahaleyile/CVE-2021-4034.svg)
- [https://github.com/wongwaituck/CVE-2021-4034](https://github.com/wongwaituck/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/wongwaituck/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/wongwaituck/CVE-2021-4034.svg)
- [https://github.com/Immersive-Labs-Sec/CVE-2021-4034](https://github.com/Immersive-Labs-Sec/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/CVE-2021-4034.svg)
- [https://github.com/CYB3RK1D/CVE-2021-4034-POC](https://github.com/CYB3RK1D/CVE-2021-4034-POC) :  ![starts](https://img.shields.io/github/stars/CYB3RK1D/CVE-2021-4034-POC.svg) ![forks](https://img.shields.io/github/forks/CYB3RK1D/CVE-2021-4034-POC.svg)
- [https://github.com/fnknda/CVE-2021-4034_POC](https://github.com/fnknda/CVE-2021-4034_POC) :  ![starts](https://img.shields.io/github/stars/fnknda/CVE-2021-4034_POC.svg) ![forks](https://img.shields.io/github/forks/fnknda/CVE-2021-4034_POC.svg)
- [https://github.com/jehovah2002/CVE-2021-4034-pwnkit](https://github.com/jehovah2002/CVE-2021-4034-pwnkit) :  ![starts](https://img.shields.io/github/stars/jehovah2002/CVE-2021-4034-pwnkit.svg) ![forks](https://img.shields.io/github/forks/jehovah2002/CVE-2021-4034-pwnkit.svg)
- [https://github.com/cdxiaodong/CVE-2021-4034-touch](https://github.com/cdxiaodong/CVE-2021-4034-touch) :  ![starts](https://img.shields.io/github/stars/cdxiaodong/CVE-2021-4034-touch.svg) ![forks](https://img.shields.io/github/forks/cdxiaodong/CVE-2021-4034-touch.svg)
- [https://github.com/0xalwayslucky/log4j-polkit-poc](https://github.com/0xalwayslucky/log4j-polkit-poc) :  ![starts](https://img.shields.io/github/stars/0xalwayslucky/log4j-polkit-poc.svg) ![forks](https://img.shields.io/github/forks/0xalwayslucky/log4j-polkit-poc.svg)
- [https://github.com/jcatala/f_poc_cve-2021-4034](https://github.com/jcatala/f_poc_cve-2021-4034) :  ![starts](https://img.shields.io/github/stars/jcatala/f_poc_cve-2021-4034.svg) ![forks](https://img.shields.io/github/forks/jcatala/f_poc_cve-2021-4034.svg)
- [https://github.com/xcanwin/CVE-2021-4034-UniontechOS](https://github.com/xcanwin/CVE-2021-4034-UniontechOS) :  ![starts](https://img.shields.io/github/stars/xcanwin/CVE-2021-4034-UniontechOS.svg) ![forks](https://img.shields.io/github/forks/xcanwin/CVE-2021-4034-UniontechOS.svg)
- [https://github.com/h3x0v3rl0rd/CVE-2021-4034_Python3](https://github.com/h3x0v3rl0rd/CVE-2021-4034_Python3) :  ![starts](https://img.shields.io/github/stars/h3x0v3rl0rd/CVE-2021-4034_Python3.svg) ![forks](https://img.shields.io/github/forks/h3x0v3rl0rd/CVE-2021-4034_Python3.svg)
- [https://github.com/sentryCyberSec/sentryCyberSec.github.io](https://github.com/sentryCyberSec/sentryCyberSec.github.io) :  ![starts](https://img.shields.io/github/stars/sentryCyberSec/sentryCyberSec.github.io.svg) ![forks](https://img.shields.io/github/forks/sentryCyberSec/sentryCyberSec.github.io.svg)
- [https://github.com/DanielFEXKEX/CVE-Scanner](https://github.com/DanielFEXKEX/CVE-Scanner) :  ![starts](https://img.shields.io/github/stars/DanielFEXKEX/CVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/DanielFEXKEX/CVE-Scanner.svg)
- [https://github.com/Fato07/Pwnkit-exploit](https://github.com/Fato07/Pwnkit-exploit) :  ![starts](https://img.shields.io/github/stars/Fato07/Pwnkit-exploit.svg) ![forks](https://img.shields.io/github/forks/Fato07/Pwnkit-exploit.svg)
- [https://github.com/nobelh/CVE-2021-4034](https://github.com/nobelh/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/nobelh/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/nobelh/CVE-2021-4034.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a "Cookie: uid=admin" header, as demonstrated by a device.rsp?opt=user&cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/tausifzaman/cctv-hack](https://github.com/tausifzaman/cctv-hack) :  ![starts](https://img.shields.io/github/stars/tausifzaman/cctv-hack.svg) ![forks](https://img.shields.io/github/forks/tausifzaman/cctv-hack.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/MarioAlejos-Cs/dirtycow-lab](https://github.com/MarioAlejos-Cs/dirtycow-lab) :  ![starts](https://img.shields.io/github/stars/MarioAlejos-Cs/dirtycow-lab.svg) ![forks](https://img.shields.io/github/forks/MarioAlejos-Cs/dirtycow-lab.svg)


## CVE-2015-8351
 PHP remote file inclusion vulnerability in the Gwolle Guestbook plugin before 1.5.4 for WordPress, when allow_url_include is enabled, allows remote authenticated users to execute arbitrary PHP code via a URL in the abspath parameter to frontend/captcha/ajaxresponse.php.  NOTE: this can also be leveraged to include and execute arbitrary local files via directory traversal sequences regardless of whether allow_url_include is enabled.

- [https://github.com/Philip-Otter/CVE-2015-8351_Otter_Remix](https://github.com/Philip-Otter/CVE-2015-8351_Otter_Remix) :  ![starts](https://img.shields.io/github/stars/Philip-Otter/CVE-2015-8351_Otter_Remix.svg) ![forks](https://img.shields.io/github/forks/Philip-Otter/CVE-2015-8351_Otter_Remix.svg)


## CVE-2008-1447
 The DNS protocol, as implemented in (1) BIND 8 and 9 before 9.5.0-P1, 9.4.2-P1, and 9.3.5-P1; (2) Microsoft DNS in Windows 2000 SP4, XP SP2 and SP3, and Server 2003 SP1 and SP2; and other implementations allow remote attackers to spoof DNS traffic via a birthday attack that uses in-bailiwick referrals to conduct cache poisoning against recursive resolvers, related to insufficient randomness of DNS transaction IDs and source ports, aka "DNS Insufficient Socket Entropy Vulnerability" or "the Kaminsky bug."

- [https://github.com/hamlasiraj/metasploit-bailiwicked_domain-fix](https://github.com/hamlasiraj/metasploit-bailiwicked_domain-fix) :  ![starts](https://img.shields.io/github/stars/hamlasiraj/metasploit-bailiwicked_domain-fix.svg) ![forks](https://img.shields.io/github/forks/hamlasiraj/metasploit-bailiwicked_domain-fix.svg)


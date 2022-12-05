# Update 2022-12-05
## CVE-2022-43097
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/nibin-m/CVE-2022-43097](https://github.com/nibin-m/CVE-2022-43097) :  ![starts](https://img.shields.io/github/stars/nibin-m/CVE-2022-43097.svg) ![forks](https://img.shields.io/github/forks/nibin-m/CVE-2022-43097.svg)


## CVE-2022-24112
 An attacker can abuse the batch-requests plugin to send requests to bypass the IP restriction of Admin API. A default configuration of Apache APISIX (with default API key) is vulnerable to remote code execution. When the admin key was changed or the port of Admin API was changed to a port different from the data panel, the impact is lower. But there is still a risk to bypass the IP restriction of Apache APISIX's data panel. There is a check in the batch-requests plugin which overrides the client IP with its real remote IP. But due to a bug in the code, this check can be bypassed.

- [https://github.com/Acczdy/CVE-2022-24112_POC](https://github.com/Acczdy/CVE-2022-24112_POC) :  ![starts](https://img.shields.io/github/stars/Acczdy/CVE-2022-24112_POC.svg) ![forks](https://img.shields.io/github/forks/Acczdy/CVE-2022-24112_POC.svg)


## CVE-2022-3699
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/alfarom256/CVE-2022-3699](https://github.com/alfarom256/CVE-2022-3699) :  ![starts](https://img.shields.io/github/stars/alfarom256/CVE-2022-3699.svg) ![forks](https://img.shields.io/github/forks/alfarom256/CVE-2022-3699.svg)


## CVE-2022-2639
 An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size() function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/EkamSinghWalia/Detection-and-Mitigation-for-CVE-2022-2639](https://github.com/EkamSinghWalia/Detection-and-Mitigation-for-CVE-2022-2639) :  ![starts](https://img.shields.io/github/stars/EkamSinghWalia/Detection-and-Mitigation-for-CVE-2022-2639.svg) ![forks](https://img.shields.io/github/forks/EkamSinghWalia/Detection-and-Mitigation-for-CVE-2022-2639.svg)


## CVE-2021-44521
 When running Apache Cassandra with the following configuration: enable_user_defined_functions: true enable_scripted_user_defined_functions: true enable_user_defined_functions_threads: false it is possible for an attacker to execute arbitrary code on the host. The attacker would need to have enough permissions to create user defined functions in the cluster to be able to exploit this. Note that this configuration is documented as unsafe, and will continue to be considered unsafe after this CVE.

- [https://github.com/Yeyvo/poc-CVE-2021-44521](https://github.com/Yeyvo/poc-CVE-2021-44521) :  ![starts](https://img.shields.io/github/stars/Yeyvo/poc-CVE-2021-44521.svg) ![forks](https://img.shields.io/github/forks/Yeyvo/poc-CVE-2021-44521.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)
- [https://github.com/hab1b0x/CVE-2021-41773](https://github.com/hab1b0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/hab1b0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/hab1b0x/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/NiS3x/CVE-2021-4034](https://github.com/NiS3x/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/NiS3x/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/NiS3x/CVE-2021-4034.svg)


## CVE-2020-5752
 Relative path traversal in Druva inSync Windows Client 6.6.3 allows a local, unauthenticated attacker to execute arbitrary operating system commands with SYSTEM privileges.

- [https://github.com/yevh/CVE-2020-5752-Druva-inSync-Windows-Client-6.6.3---Local-Privilege-Escalation-PowerShell-](https://github.com/yevh/CVE-2020-5752-Druva-inSync-Windows-Client-6.6.3---Local-Privilege-Escalation-PowerShell-) :  ![starts](https://img.shields.io/github/stars/yevh/CVE-2020-5752-Druva-inSync-Windows-Client-6.6.3---Local-Privilege-Escalation-PowerShell-.svg) ![forks](https://img.shields.io/github/forks/yevh/CVE-2020-5752-Druva-inSync-Windows-Client-6.6.3---Local-Privilege-Escalation-PowerShell-.svg)


## CVE-2019-15231
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2019-15107. Reason: This candidate is a duplicate of CVE-2019-15107. Notes: All CVE users should reference CVE-2019-15107 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.

- [https://github.com/lolminerxmrig/CVE-2019-15107](https://github.com/lolminerxmrig/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/lolminerxmrig/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/lolminerxmrig/CVE-2019-15107.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/lolminerxmrig/CVE-2019-15107](https://github.com/lolminerxmrig/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/lolminerxmrig/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/lolminerxmrig/CVE-2019-15107.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow &quot;go get&quot; remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/mux0x/CVE-2018-6574](https://github.com/mux0x/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/mux0x/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/mux0x/CVE-2018-6574.svg)


## CVE-2016-0728
 The join_session_keyring function in security/keys/process_keys.c in the Linux kernel before 4.4.1 mishandles object references in a certain error case, which allows local users to gain privileges or cause a denial of service (integer overflow and use-after-free) via crafted keyctl commands.

- [https://github.com/sidrk01/cve-2016-0728](https://github.com/sidrk01/cve-2016-0728) :  ![starts](https://img.shields.io/github/stars/sidrk01/cve-2016-0728.svg) ![forks](https://img.shields.io/github/forks/sidrk01/cve-2016-0728.svg)


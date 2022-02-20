# Update 2022-02-20
## CVE-2022-24354
 This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of TP-Link AC1750 prior to 1.1.4 Build 20211022 rel.59103(5553) routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the NetUSB.ko module. The issue results from the lack of proper validation of user-supplied data, which can result in an integer overflow before allocating a buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-15835.

- [https://github.com/0vercl0k/zenith](https://github.com/0vercl0k/zenith) :  ![starts](https://img.shields.io/github/stars/0vercl0k/zenith.svg) ![forks](https://img.shields.io/github/forks/0vercl0k/zenith.svg)


## CVE-2022-23131
 In the case of instances where the SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor, because a user login stored in the session was not verified. Malicious unauthenticated actor may exploit this issue to escalate privileges and gain admin access to Zabbix Frontend. To perform the attack, SAML authentication is required to be enabled and the actor has to know the username of Zabbix user (or use the guest account, which is disabled by default).

- [https://github.com/jweny/zabbix-saml-bypass-exp](https://github.com/jweny/zabbix-saml-bypass-exp) :  ![starts](https://img.shields.io/github/stars/jweny/zabbix-saml-bypass-exp.svg) ![forks](https://img.shields.io/github/forks/jweny/zabbix-saml-bypass-exp.svg)
- [https://github.com/Mr-xn/cve-2022-23131](https://github.com/Mr-xn/cve-2022-23131) :  ![starts](https://img.shields.io/github/stars/Mr-xn/cve-2022-23131.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/cve-2022-23131.svg)
- [https://github.com/1mxml/CVE-2022-23131](https://github.com/1mxml/CVE-2022-23131) :  ![starts](https://img.shields.io/github/stars/1mxml/CVE-2022-23131.svg) ![forks](https://img.shields.io/github/forks/1mxml/CVE-2022-23131.svg)


## CVE-2022-0185
 A heap-based buffer overflow flaw was found in the way the legacy_parse_param function in the Filesystem Context functionality of the Linux kernel verified the supplied parameters length. An unprivileged (in case of unprivileged user namespaces enabled, otherwise needs namespaced CAP_SYS_ADMIN privilege) local user able to open a filesystem that does not support the Filesystem Context API (and thus fallbacks to legacy handling) could use this flaw to escalate their privileges on the system.

- [https://github.com/chenaotian/CVE-2022-0185](https://github.com/chenaotian/CVE-2022-0185) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2022-0185.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2022-0185.svg)


## CVE-2021-33045
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.

- [https://github.com/bp2008/DahuaLoginBypass](https://github.com/bp2008/DahuaLoginBypass) :  ![starts](https://img.shields.io/github/stars/bp2008/DahuaLoginBypass.svg) ![forks](https://img.shields.io/github/forks/bp2008/DahuaLoginBypass.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/LJP-TW/CVE-2021-4034](https://github.com/LJP-TW/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/LJP-TW/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/LJP-TW/CVE-2021-4034.svg)


## CVE-2021-1965
 Possible buffer overflow due to lack of parameter length check during MBSSID scan IE parse in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Mobile, Snapdragon Wired Infrastructure and Networking

- [https://github.com/parsdefense/CVE-2021-1965](https://github.com/parsdefense/CVE-2021-1965) :  ![starts](https://img.shields.io/github/stars/parsdefense/CVE-2021-1965.svg) ![forks](https://img.shields.io/github/forks/parsdefense/CVE-2021-1965.svg)


## CVE-2020-0674
 A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka 'Scripting Engine Memory Corruption Vulnerability'. This CVE ID is unique from CVE-2020-0673, CVE-2020-0710, CVE-2020-0711, CVE-2020-0712, CVE-2020-0713, CVE-2020-0767.

- [https://github.com/Neko-chanQwQ/CVE-2020-0674-PoC](https://github.com/Neko-chanQwQ/CVE-2020-0674-PoC) :  ![starts](https://img.shields.io/github/stars/Neko-chanQwQ/CVE-2020-0674-PoC.svg) ![forks](https://img.shields.io/github/forks/Neko-chanQwQ/CVE-2020-0674-PoC.svg)


# Update 2022-06-24
## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/electr0lulz/Mass-exploit-CVE-2022-29464](https://github.com/electr0lulz/Mass-exploit-CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/electr0lulz/Mass-exploit-CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/electr0lulz/Mass-exploit-CVE-2022-29464.svg)


## CVE-2022-22980
 A Spring Data MongoDB application is vulnerable to SpEL Injection when using @Query or @Aggregation-annotated query methods with SpEL expressions that contain query parameter placeholders for value binding if the input is not sanitized.

- [https://github.com/li8u99/Spring-Data-Mongodb-Demo](https://github.com/li8u99/Spring-Data-Mongodb-Demo) :  ![starts](https://img.shields.io/github/stars/li8u99/Spring-Data-Mongodb-Demo.svg) ![forks](https://img.shields.io/github/forks/li8u99/Spring-Data-Mongodb-Demo.svg)
- [https://github.com/jweny/cve-2022-22980-exp](https://github.com/jweny/cve-2022-22980-exp) :  ![starts](https://img.shields.io/github/stars/jweny/cve-2022-22980-exp.svg) ![forks](https://img.shields.io/github/forks/jweny/cve-2022-22980-exp.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/ih3na/debian11-dirty_pipe-patcher](https://github.com/ih3na/debian11-dirty_pipe-patcher) :  ![starts](https://img.shields.io/github/stars/ih3na/debian11-dirty_pipe-patcher.svg) ![forks](https://img.shields.io/github/forks/ih3na/debian11-dirty_pipe-patcher.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/PentesterSoham/CVE-2021-4034-exploit](https://github.com/PentesterSoham/CVE-2021-4034-exploit) :  ![starts](https://img.shields.io/github/stars/PentesterSoham/CVE-2021-4034-exploit.svg) ![forks](https://img.shields.io/github/forks/PentesterSoham/CVE-2021-4034-exploit.svg)


## CVE-2020-2551
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: WLS Core Components). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/hktalent/CVE-2020-2551](https://github.com/hktalent/CVE-2020-2551) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE-2020-2551.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE-2020-2551.svg)
- [https://github.com/jas502n/CVE-2020-2551](https://github.com/jas502n/CVE-2020-2551) :  ![starts](https://img.shields.io/github/stars/jas502n/CVE-2020-2551.svg) ![forks](https://img.shields.io/github/forks/jas502n/CVE-2020-2551.svg)
- [https://github.com/DSO-Lab/defvul](https://github.com/DSO-Lab/defvul) :  ![starts](https://img.shields.io/github/stars/DSO-Lab/defvul.svg) ![forks](https://img.shields.io/github/forks/DSO-Lab/defvul.svg)
- [https://github.com/zzwlpx/weblogicPoc](https://github.com/zzwlpx/weblogicPoc) :  ![starts](https://img.shields.io/github/stars/zzwlpx/weblogicPoc.svg) ![forks](https://img.shields.io/github/forks/zzwlpx/weblogicPoc.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/NAXG/CVE-2020-1472](https://github.com/NAXG/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/NAXG/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/NAXG/CVE-2020-1472.svg)
- [https://github.com/Fa1c0n35/CVE-2020-1472](https://github.com/Fa1c0n35/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2020-1472.svg)
- [https://github.com/Nekoox/zerologon](https://github.com/Nekoox/zerologon) :  ![starts](https://img.shields.io/github/stars/Nekoox/zerologon.svg) ![forks](https://img.shields.io/github/forks/Nekoox/zerologon.svg)
- [https://github.com/t31m0/CVE-2020-1472](https://github.com/t31m0/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/t31m0/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/t31m0/CVE-2020-1472.svg)
- [https://github.com/Exploitspacks/CVE-2020-1472](https://github.com/Exploitspacks/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/Exploitspacks/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/Exploitspacks/CVE-2020-1472.svg)
- [https://github.com/lele8/CVE-2020-1472](https://github.com/lele8/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/lele8/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/lele8/CVE-2020-1472.svg)
- [https://github.com/hell-moon/ZeroLogon-Exploit](https://github.com/hell-moon/ZeroLogon-Exploit) :  ![starts](https://img.shields.io/github/stars/hell-moon/ZeroLogon-Exploit.svg) ![forks](https://img.shields.io/github/forks/hell-moon/ZeroLogon-Exploit.svg)


## CVE-2018-1160
 Netatalk before 3.1.12 is vulnerable to an out of bounds write in dsi_opensess.c. This is due to lack of bounds checking on attacker controlled data. A remote unauthenticated attacker can leverage this vulnerability to achieve arbitrary code execution.

- [https://github.com/SachinThanushka/CVE-2018-1160](https://github.com/SachinThanushka/CVE-2018-1160) :  ![starts](https://img.shields.io/github/stars/SachinThanushka/CVE-2018-1160.svg) ![forks](https://img.shields.io/github/forks/SachinThanushka/CVE-2018-1160.svg)


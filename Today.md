# Update 2022-10-12
## CVE-2022-41352
 An issue was discovered in Zimbra Collaboration (ZCS) 8.8.15 and 9.0. An attacker can upload arbitrary files through amavisd via a cpio loophole (extraction to /opt/zimbra/jetty/webapps/zimbra/public) that can lead to incorrect access to any other user accounts. Zimbra recommends pax over cpio. Also, pax is in the prerequisites of Zimbra on Ubuntu; however, pax is no longer part of a default Red Hat installation after RHEL 6 (or CentOS 6). Once pax is installed, amavisd automatically prefers it over cpio.

- [https://github.com/segfault-it/cve-2022-41352](https://github.com/segfault-it/cve-2022-41352) :  ![starts](https://img.shields.io/github/stars/segfault-it/cve-2022-41352.svg) ![forks](https://img.shields.io/github/forks/segfault-it/cve-2022-41352.svg)


## CVE-2022-41082
 Microsoft Exchange Server Remote Code Execution Vulnerability.

- [https://github.com/t0mby/CVE-2022-41082-MASS-RCE](https://github.com/t0mby/CVE-2022-41082-MASS-RCE) :  ![starts](https://img.shields.io/github/stars/t0mby/CVE-2022-41082-MASS-RCE.svg) ![forks](https://img.shields.io/github/forks/t0mby/CVE-2022-41082-MASS-RCE.svg)


## CVE-2022-34718
 Windows TCP/IP Remote Code Execution Vulnerability.

- [https://github.com/SecLabResearchBV/CVE-2022-34718-PoC](https://github.com/SecLabResearchBV/CVE-2022-34718-PoC) :  ![starts](https://img.shields.io/github/stars/SecLabResearchBV/CVE-2022-34718-PoC.svg) ![forks](https://img.shields.io/github/forks/SecLabResearchBV/CVE-2022-34718-PoC.svg)


## CVE-2022-22972
 VMware Workspace ONE Access, Identity Manager and vRealize Automation contain an authentication bypass vulnerability affecting local domain users. A malicious actor with network access to the UI may be able to obtain administrative access without the need to authenticate.

- [https://github.com/Schira4396/VcenterKiller](https://github.com/Schira4396/VcenterKiller) :  ![starts](https://img.shields.io/github/stars/Schira4396/VcenterKiller.svg) ![forks](https://img.shields.io/github/forks/Schira4396/VcenterKiller.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/Schira4396/VcenterKiller](https://github.com/Schira4396/VcenterKiller) :  ![starts](https://img.shields.io/github/stars/Schira4396/VcenterKiller.svg) ![forks](https://img.shields.io/github/forks/Schira4396/VcenterKiller.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/Pixailz/CVE-2021-4034](https://github.com/Pixailz/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/Pixailz/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/Pixailz/CVE-2021-4034.svg)


## CVE-2021-2021
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.22 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/TheCryingGame/CVE-2021-2021good](https://github.com/TheCryingGame/CVE-2021-2021good) :  ![starts](https://img.shields.io/github/stars/TheCryingGame/CVE-2021-2021good.svg) ![forks](https://img.shields.io/github/forks/TheCryingGame/CVE-2021-2021good.svg)


## CVE-2019-19781
 An issue was discovered in Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0. They allow Directory Traversal.

- [https://github.com/x1sec/CVE-2019-19781](https://github.com/x1sec/CVE-2019-19781) :  ![starts](https://img.shields.io/github/stars/x1sec/CVE-2019-19781.svg) ![forks](https://img.shields.io/github/forks/x1sec/CVE-2019-19781.svg)
- [https://github.com/x1sec/citrixmash_scanner](https://github.com/x1sec/citrixmash_scanner) :  ![starts](https://img.shields.io/github/stars/x1sec/citrixmash_scanner.svg) ![forks](https://img.shields.io/github/forks/x1sec/citrixmash_scanner.svg)
- [https://github.com/x1sec/citrix-honeypot](https://github.com/x1sec/citrix-honeypot) :  ![starts](https://img.shields.io/github/stars/x1sec/citrix-honeypot.svg) ![forks](https://img.shields.io/github/forks/x1sec/citrix-honeypot.svg)


## CVE-2018-16156
 In PaperStream IP (TWAIN) 1.42.0.5685 (Service Update 7), the FJTWSVIC service running with SYSTEM privilege processes unauthenticated messages received over the FjtwMkic_Fjicube_32 named pipe. One of these message processing functions attempts to dynamically load the UninOldIS.dll library and executes an exported function named ChangeUninstallString. The default install does not contain this library and therefore if any DLL with that name exists in any directory listed in the PATH variable, it can be used to escalate to SYSTEM level privilege.

- [https://github.com/securifera/CVE-2018-16156-Exploit](https://github.com/securifera/CVE-2018-16156-Exploit) :  ![starts](https://img.shields.io/github/stars/securifera/CVE-2018-16156-Exploit.svg) ![forks](https://img.shields.io/github/forks/securifera/CVE-2018-16156-Exploit.svg)


## CVE-2017-5689
 An unprivileged network attacker could gain system privileges to provisioned Intel manageability SKUs: Intel Active Management Technology (AMT) and Intel Standard Manageability (ISM). An unprivileged local attacker could provision manageability features gaining unprivileged network or local system privileges on Intel manageability SKUs: Intel Active Management Technology (AMT), Intel Standard Manageability (ISM), and Intel Small Business Technology (SBT).

- [https://github.com/x1sec/amthoneypot](https://github.com/x1sec/amthoneypot) :  ![starts](https://img.shields.io/github/stars/x1sec/amthoneypot.svg) ![forks](https://img.shields.io/github/forks/x1sec/amthoneypot.svg)


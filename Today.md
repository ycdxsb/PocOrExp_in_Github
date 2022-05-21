# Update 2022-05-21
## CVE-2022-30525
 A OS command injection vulnerability in the CGI program of Zyxel USG FLEX 100(W) firmware versions 5.00 through 5.21 Patch 1, USG FLEX 200 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 500 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 700 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 50(W) firmware versions 5.10 through 5.21 Patch 1, USG20(W)-VPN firmware versions 5.10 through 5.21 Patch 1, ATP series firmware versions 5.10 through 5.21 Patch 1, VPN series firmware versions 4.60 through 5.21 Patch 1, which could allow an attacker to modify specific files and then execute some OS commands on a vulnerable device.

- [https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0](https://github.com/Anonymous-ghost/AttackWebFrameworkTools-5.0) :  ![starts](https://img.shields.io/github/stars/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg) ![forks](https://img.shields.io/github/forks/Anonymous-ghost/AttackWebFrameworkTools-5.0.svg)
- [https://github.com/160Team/CVE-2022-30525](https://github.com/160Team/CVE-2022-30525) :  ![starts](https://img.shields.io/github/stars/160Team/CVE-2022-30525.svg) ![forks](https://img.shields.io/github/forks/160Team/CVE-2022-30525.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 and above through 4.0.0; WSO2 Identity Server 5.2.0 and above through 5.11.0; WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0, and 5.6.0; WSO2 Identity Server as Key Manager 5.3.0 and above through 5.10.0; and WSO2 Enterprise Integrator 6.2.0 and above through 6.6.0.

- [https://github.com/trhacknon/CVE-2022-29464](https://github.com/trhacknon/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2022-29464.svg)


## CVE-2022-28590
 A Remote Code Execution (RCE) vulnerability exists in Pixelimity 1.0 via admin/admin-ajax.php?action=install_theme.

- [https://github.com/trhacknon/CVE-2022-28590](https://github.com/trhacknon/CVE-2022-28590) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2022-28590.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2022-28590.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/cxzero/CVE-2022-22965-spring4shell](https://github.com/cxzero/CVE-2022-22965-spring4shell) :  ![starts](https://img.shields.io/github/stars/cxzero/CVE-2022-22965-spring4shell.svg) ![forks](https://img.shields.io/github/forks/cxzero/CVE-2022-22965-spring4shell.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/corelight/cve-2022-22954](https://github.com/corelight/cve-2022-22954) :  ![starts](https://img.shields.io/github/stars/corelight/cve-2022-22954.svg) ![forks](https://img.shields.io/github/forks/corelight/cve-2022-22954.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/anansec/CVE-2022-22947_EXP](https://github.com/anansec/CVE-2022-22947_EXP) :  ![starts](https://img.shields.io/github/stars/anansec/CVE-2022-22947_EXP.svg) ![forks](https://img.shields.io/github/forks/anansec/CVE-2022-22947_EXP.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/r1is/CVE-2022-0847](https://github.com/r1is/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/r1is/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/r1is/CVE-2022-0847.svg)
- [https://github.com/VinuKalana/DirtyPipe-CVE-2022-0847](https://github.com/VinuKalana/DirtyPipe-CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/VinuKalana/DirtyPipe-CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/VinuKalana/DirtyPipe-CVE-2022-0847.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/pengalaman-1t/CVE-2021-4034](https://github.com/pengalaman-1t/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/pengalaman-1t/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/pengalaman-1t/CVE-2021-4034.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/cerodah/overlayFS-CVE-2021-3493](https://github.com/cerodah/overlayFS-CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/cerodah/overlayFS-CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/cerodah/overlayFS-CVE-2021-3493.svg)


## CVE-2020-1350
 A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.

- [https://github.com/connormcgarr/CVE-2020-1350](https://github.com/connormcgarr/CVE-2020-1350) :  ![starts](https://img.shields.io/github/stars/connormcgarr/CVE-2020-1350.svg) ![forks](https://img.shields.io/github/forks/connormcgarr/CVE-2020-1350.svg)
- [https://github.com/graph-inc/CVE-2020-1350](https://github.com/graph-inc/CVE-2020-1350) :  ![starts](https://img.shields.io/github/stars/graph-inc/CVE-2020-1350.svg) ![forks](https://img.shields.io/github/forks/graph-inc/CVE-2020-1350.svg)


## CVE-2018-1010
 A remote code execution vulnerability exists when the Windows font library improperly handles specially crafted embedded fonts, aka &quot;Microsoft Graphics Remote Code Execution Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers. This CVE ID is unique from CVE-2018-1012, CVE-2018-1013, CVE-2018-1015, CVE-2018-1016.

- [https://github.com/ymgh96/Detecting-the-patch-of-CVE-2018-1010](https://github.com/ymgh96/Detecting-the-patch-of-CVE-2018-1010) :  ![starts](https://img.shields.io/github/stars/ymgh96/Detecting-the-patch-of-CVE-2018-1010.svg) ![forks](https://img.shields.io/github/forks/ymgh96/Detecting-the-patch-of-CVE-2018-1010.svg)


## CVE-2017-1000486
 Primetek Primefaces 5.x is vulnerable to a weak encryption flaw resulting in remote code execution

- [https://github.com/prok3z/Nuclei-Template-Primefaces-RCE](https://github.com/prok3z/Nuclei-Template-Primefaces-RCE) :  ![starts](https://img.shields.io/github/stars/prok3z/Nuclei-Template-Primefaces-RCE.svg) ![forks](https://img.shields.io/github/forks/prok3z/Nuclei-Template-Primefaces-RCE.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;

- [https://github.com/r1is/CVE-2022-0847](https://github.com/r1is/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/r1is/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/r1is/CVE-2022-0847.svg)


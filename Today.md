# Update 2024-07-04
## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/AmbroseCdMeng/CVE-2024-32002](https://github.com/AmbroseCdMeng/CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/AmbroseCdMeng/CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/AmbroseCdMeng/CVE-2024-32002.svg)
- [https://github.com/EQSTSeminar/git_rce](https://github.com/EQSTSeminar/git_rce) :  ![starts](https://img.shields.io/github/stars/EQSTSeminar/git_rce.svg) ![forks](https://img.shields.io/github/forks/EQSTSeminar/git_rce.svg)


## CVE-2024-21006
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/lightr3d/CVE-2024-21006_jar](https://github.com/lightr3d/CVE-2024-21006_jar) :  ![starts](https://img.shields.io/github/stars/lightr3d/CVE-2024-21006_jar.svg) ![forks](https://img.shields.io/github/forks/lightr3d/CVE-2024-21006_jar.svg)


## CVE-2024-20399
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Blootus/CVE-2024-20399-Cisco-RCE](https://github.com/Blootus/CVE-2024-20399-Cisco-RCE) :  ![starts](https://img.shields.io/github/stars/Blootus/CVE-2024-20399-Cisco-RCE.svg) ![forks](https://img.shields.io/github/forks/Blootus/CVE-2024-20399-Cisco-RCE.svg)


## CVE-2024-5084
 The Hash Form &#8211; Drag &amp; Drop Form Builder plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'file_upload_action' function in all versions up to, and including, 1.1.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/WOOOOONG/CVE-2024-5084](https://github.com/WOOOOONG/CVE-2024-5084) :  ![starts](https://img.shields.io/github/stars/WOOOOONG/CVE-2024-5084.svg) ![forks](https://img.shields.io/github/forks/WOOOOONG/CVE-2024-5084.svg)


## CVE-2024-4836
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/sleep46/CVE-2024-4836_Check](https://github.com/sleep46/CVE-2024-4836_Check) :  ![starts](https://img.shields.io/github/stars/sleep46/CVE-2024-4836_Check.svg) ![forks](https://img.shields.io/github/forks/sleep46/CVE-2024-4836_Check.svg)


## CVE-2023-43654
 TorchServe is a tool for serving and scaling PyTorch models in production. TorchServe default configuration lacks proper input validation, enabling third parties to invoke remote HTTP download requests and write files to the disk. This issue could be taken advantage of to compromise the integrity of the system and sensitive data. This issue is present in versions 0.1.0 to 0.8.1. A user is able to load the model of their choice from any URL that they would like to use. The user of TorchServe is responsible for configuring both the allowed_urls and specifying the model URL to be used. A pull request to warn the user when the default value for allowed_urls is used has been merged in PR #2534. TorchServe release 0.8.2 includes this change. Users are advised to upgrade. There are no known workarounds for this issue.

- [https://github.com/OligoCyberSecurity/CVE-2023-43654](https://github.com/OligoCyberSecurity/CVE-2023-43654) :  ![starts](https://img.shields.io/github/stars/OligoCyberSecurity/CVE-2023-43654.svg) ![forks](https://img.shields.io/github/forks/OligoCyberSecurity/CVE-2023-43654.svg)


## CVE-2023-35985
 An arbitrary file creation vulnerability exists in the Javascript exportDataObject API of Foxit Reader 12.1.3.15356 due to a failure to properly validate a dangerous extension. A specially crafted malicious file can create files at arbitrary locations, which can lead to arbitrary code execution. An attacker needs to trick the user into opening the malicious file to trigger this vulnerability. Exploitation is also possible if a user visits a specially-crafted malicious site if the browser plugin extension is enabled.

- [https://github.com/N00BIER/CVE-2023-35985](https://github.com/N00BIER/CVE-2023-35985) :  ![starts](https://img.shields.io/github/stars/N00BIER/CVE-2023-35985.svg) ![forks](https://img.shields.io/github/forks/N00BIER/CVE-2023-35985.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/0x0jr/HTB-Devvortex-CVE-2023-2375-PoC](https://github.com/0x0jr/HTB-Devvortex-CVE-2023-2375-PoC) :  ![starts](https://img.shields.io/github/stars/0x0jr/HTB-Devvortex-CVE-2023-2375-PoC.svg) ![forks](https://img.shields.io/github/forks/0x0jr/HTB-Devvortex-CVE-2023-2375-PoC.svg)


## CVE-2023-3881
 A vulnerability classified as critical was found in Campcodes Beauty Salon Management System 1.0. Affected by this vulnerability is an unknown functionality of the file /admin/forgot-password.php. The manipulation of the argument contactno leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-235243.

- [https://github.com/AnugiArrawwala/CVE-Research](https://github.com/AnugiArrawwala/CVE-Research) :  ![starts](https://img.shields.io/github/stars/AnugiArrawwala/CVE-Research.svg) ![forks](https://img.shields.io/github/forks/AnugiArrawwala/CVE-Research.svg)


## CVE-2022-30525
 A OS command injection vulnerability in the CGI program of Zyxel USG FLEX 100(W) firmware versions 5.00 through 5.21 Patch 1, USG FLEX 200 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 500 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 700 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 50(W) firmware versions 5.10 through 5.21 Patch 1, USG20(W)-VPN firmware versions 5.10 through 5.21 Patch 1, ATP series firmware versions 5.10 through 5.21 Patch 1, VPN series firmware versions 4.60 through 5.21 Patch 1, which could allow an attacker to modify specific files and then execute some OS commands on a vulnerable device.

- [https://github.com/5l1v3r1/CVE-2022-30525-Reverse-Shell](https://github.com/5l1v3r1/CVE-2022-30525-Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2022-30525-Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2022-30525-Reverse-Shell.svg)


## CVE-2018-14714
 System command injection in appGet.cgi on ASUS RT-AC3200 version 3.0.0.4.382.50010 allows attackers to execute system commands via the &quot;load_script&quot; URL parameter.

- [https://github.com/BTtea/CVE-2018-14714-RCE_exploit](https://github.com/BTtea/CVE-2018-14714-RCE_exploit) :  ![starts](https://img.shields.io/github/stars/BTtea/CVE-2018-14714-RCE_exploit.svg) ![forks](https://img.shields.io/github/forks/BTtea/CVE-2018-14714-RCE_exploit.svg)


## CVE-2017-1000251
 The native Bluetooth stack in the Linux Kernel (BlueZ), starting at the Linux kernel version 2.6.32 and up to and including 4.13.1, are vulnerable to a stack overflow vulnerability in the processing of L2CAP configuration responses resulting in Remote code execution in kernel space.

- [https://github.com/sgxgsx/blueborne-CVE-2017-1000251](https://github.com/sgxgsx/blueborne-CVE-2017-1000251) :  ![starts](https://img.shields.io/github/stars/sgxgsx/blueborne-CVE-2017-1000251.svg) ![forks](https://img.shields.io/github/forks/sgxgsx/blueborne-CVE-2017-1000251.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka &quot;Windows SMB Remote Code Execution Vulnerability.&quot; This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/AnugiArrawwala/CVE-Research](https://github.com/AnugiArrawwala/CVE-Research) :  ![starts](https://img.shields.io/github/stars/AnugiArrawwala/CVE-Research.svg) ![forks](https://img.shields.io/github/forks/AnugiArrawwala/CVE-Research.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/AnugiArrawwala/CVE-Research](https://github.com/AnugiArrawwala/CVE-Research) :  ![starts](https://img.shields.io/github/stars/AnugiArrawwala/CVE-Research.svg) ![forks](https://img.shields.io/github/forks/AnugiArrawwala/CVE-Research.svg)


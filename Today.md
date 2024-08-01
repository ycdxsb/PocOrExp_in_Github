# Update 2024-08-01
## CVE-2024-36401
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Chocapikk/CVE-2024-36401](https://github.com/Chocapikk/CVE-2024-36401) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-36401.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-36401.svg)


## CVE-2024-34693
 Improper Input Validation vulnerability in Apache Superset, allows for an authenticated attacker to create a MariaDB connection with local_infile enabled. If both the MariaDB server (off by default) and the local mysql client on the web server are set to allow for local infile, it's possible for the attacker to execute a specific MySQL/MariaDB SQL command that is able to read files from the server and insert their content on a MariaDB database table.This issue affects Apache Superset: before 3.1.3 and version 4.0.0 Users are recommended to upgrade to version 4.0.1 or 3.1.3, which fixes the issue.

- [https://github.com/Mr-r00t11/CVE-2024-34693](https://github.com/Mr-r00t11/CVE-2024-34693) :  ![starts](https://img.shields.io/github/stars/Mr-r00t11/CVE-2024-34693.svg) ![forks](https://img.shields.io/github/forks/Mr-r00t11/CVE-2024-34693.svg)


## CVE-2024-34102
 Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.

- [https://github.com/etx-Arn/CVE-2024-34102-RCE](https://github.com/etx-Arn/CVE-2024-34102-RCE) :  ![starts](https://img.shields.io/github/stars/etx-Arn/CVE-2024-34102-RCE.svg) ![forks](https://img.shields.io/github/forks/etx-Arn/CVE-2024-34102-RCE.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/NishanthAnand21/CVE-2024-32002-PoC](https://github.com/NishanthAnand21/CVE-2024-32002-PoC) :  ![starts](https://img.shields.io/github/stars/NishanthAnand21/CVE-2024-32002-PoC.svg) ![forks](https://img.shields.io/github/forks/NishanthAnand21/CVE-2024-32002-PoC.svg)
- [https://github.com/tiyeume25112004/CVE-2024-32002](https://github.com/tiyeume25112004/CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/tiyeume25112004/CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/tiyeume25112004/CVE-2024-32002.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/KaSooMi0228/CVE-2024-25600-Bricks-Builder-WordPress](https://github.com/KaSooMi0228/CVE-2024-25600-Bricks-Builder-WordPress) :  ![starts](https://img.shields.io/github/stars/KaSooMi0228/CVE-2024-25600-Bricks-Builder-WordPress.svg) ![forks](https://img.shields.io/github/forks/KaSooMi0228/CVE-2024-25600-Bricks-Builder-WordPress.svg)


## CVE-2024-4130
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/patrickdeanramos/CVE-2024-41302-Bookea-tu-Mesa-is-vulnerable-to-SQL-Injection](https://github.com/patrickdeanramos/CVE-2024-41302-Bookea-tu-Mesa-is-vulnerable-to-SQL-Injection) :  ![starts](https://img.shields.io/github/stars/patrickdeanramos/CVE-2024-41302-Bookea-tu-Mesa-is-vulnerable-to-SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/patrickdeanramos/CVE-2024-41302-Bookea-tu-Mesa-is-vulnerable-to-SQL-Injection.svg)
- [https://github.com/patrickdeanramos/CVE-2024-41301-Bookea-tu-Mesa-is-vulnerable-to-Stored-Cross-Site-Scripting](https://github.com/patrickdeanramos/CVE-2024-41301-Bookea-tu-Mesa-is-vulnerable-to-Stored-Cross-Site-Scripting) :  ![starts](https://img.shields.io/github/stars/patrickdeanramos/CVE-2024-41301-Bookea-tu-Mesa-is-vulnerable-to-Stored-Cross-Site-Scripting.svg) ![forks](https://img.shields.io/github/forks/patrickdeanramos/CVE-2024-41301-Bookea-tu-Mesa-is-vulnerable-to-Stored-Cross-Site-Scripting.svg)


## CVE-2024-4061
 The Survey Maker WordPress plugin before 4.2.9 does not sanitise and escape some of its settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup)

- [https://github.com/KyssK00L/CVE-2024-40617](https://github.com/KyssK00L/CVE-2024-40617) :  ![starts](https://img.shields.io/github/stars/KyssK00L/CVE-2024-40617.svg) ![forks](https://img.shields.io/github/forks/KyssK00L/CVE-2024-40617.svg)


## CVE-2023-43040
 IBM Spectrum Fusion HCI 2.5.2 through 2.7.2 could allow an attacker to perform unauthorized actions in RGW for Ceph due to improper bucket access. IBM X-Force ID: 266807.

- [https://github.com/riza/CVE-2023-43040](https://github.com/riza/CVE-2023-43040) :  ![starts](https://img.shields.io/github/stars/riza/CVE-2023-43040.svg) ![forks](https://img.shields.io/github/forks/riza/CVE-2023-43040.svg)


## CVE-2023-33592
 Lost and Found Information System v1.0 was discovered to contain a SQL injection vulnerability via the component /php-lfis/admin/?page=system_info/contact_information.

- [https://github.com/ChineseOldboy/CVE-2023-33592](https://github.com/ChineseOldboy/CVE-2023-33592) :  ![starts](https://img.shields.io/github/stars/ChineseOldboy/CVE-2023-33592.svg) ![forks](https://img.shields.io/github/forks/ChineseOldboy/CVE-2023-33592.svg)


## CVE-2023-31606
 A Regular Expression Denial of Service (ReDoS) issue was discovered in the sanitize_html function of redcloth gem v4.0.0. This vulnerability allows attackers to cause a Denial of Service (DoS) via supplying a crafted payload.

- [https://github.com/merbinr/CVE-2023-31606](https://github.com/merbinr/CVE-2023-31606) :  ![starts](https://img.shields.io/github/stars/merbinr/CVE-2023-31606.svg) ![forks](https://img.shields.io/github/forks/merbinr/CVE-2023-31606.svg)


## CVE-2022-40146
 Server-Side Request Forgery (SSRF) vulnerability in Batik of Apache XML Graphics allows an attacker to access files using a Jar url. This issue affects Apache XML Graphics Batik 1.14.

- [https://github.com/soulfoodisgood/CVE-2022-40146](https://github.com/soulfoodisgood/CVE-2022-40146) :  ![starts](https://img.shields.io/github/stars/soulfoodisgood/CVE-2022-40146.svg) ![forks](https://img.shields.io/github/forks/soulfoodisgood/CVE-2022-40146.svg)


## CVE-2022-2590
 A race condition was found in the way the Linux kernel's memory subsystem handled the copy-on-write (COW) breakage of private read-only shared memory mappings. This flaw allows an unprivileged, local user to gain write access to read-only memory mappings, increasing their privileges on the system.

- [https://github.com/hyeonjun17/CVE-2022-2590-analysis](https://github.com/hyeonjun17/CVE-2022-2590-analysis) :  ![starts](https://img.shields.io/github/stars/hyeonjun17/CVE-2022-2590-analysis.svg) ![forks](https://img.shields.io/github/forks/hyeonjun17/CVE-2022-2590-analysis.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/bananoname/cve-2021-42013](https://github.com/bananoname/cve-2021-42013) :  ![starts](https://img.shields.io/github/stars/bananoname/cve-2021-42013.svg) ![forks](https://img.shields.io/github/forks/bananoname/cve-2021-42013.svg)


## CVE-2021-33699
 Task Hijacking is a vulnerability that affects the applications running on Android devices due to a misconfiguration in their AndroidManifest.xml with their Task Control features. This allows an unauthorized attacker or malware to takeover legitimate apps and to steal user's sensitive information.

- [https://github.com/naroSEC/CVE-2021-33699_Task_Hijacking](https://github.com/naroSEC/CVE-2021-33699_Task_Hijacking) :  ![starts](https://img.shields.io/github/stars/naroSEC/CVE-2021-33699_Task_Hijacking.svg) ![forks](https://img.shields.io/github/forks/naroSEC/CVE-2021-33699_Task_Hijacking.svg)


## CVE-2021-29442
 Nacos is a platform designed for dynamic service discovery and configuration and service management. In Nacos before version 1.4.1, the ConfigOpsController lets the user perform management operations like querying the database or even wiping it out. While the /data/remove endpoint is properly protected with the @Secured annotation, the /derby endpoint is not protected and can be openly accessed by unauthenticated users. These endpoints are only valid when using embedded storage (derby DB) so this issue should not affect those installations using external storage (e.g. mysql)

- [https://github.com/VictorShem/QVD-2024-26473](https://github.com/VictorShem/QVD-2024-26473) :  ![starts](https://img.shields.io/github/stars/VictorShem/QVD-2024-26473.svg) ![forks](https://img.shields.io/github/forks/VictorShem/QVD-2024-26473.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/fnknda/CVE-2021-4034_POC](https://github.com/fnknda/CVE-2021-4034_POC) :  ![starts](https://img.shields.io/github/stars/fnknda/CVE-2021-4034_POC.svg) ![forks](https://img.shields.io/github/forks/fnknda/CVE-2021-4034_POC.svg)


## CVE-2019-1698
 A vulnerability in the web-based user interface of Cisco Internet of Things Field Network Director (IoT-FND) Software could allow an authenticated, remote attacker to gain read access to information that is stored on an affected system. The vulnerability is due to improper handling of XML External Entity (XXE) entries when parsing certain XML files. An attacker could exploit this vulnerability by importing a crafted XML file with malicious entries, which could allow the attacker to read files within the affected application. Versions prior to 4.4(0.26) are affected.

- [https://github.com/raytran54/CVE-2019-1698](https://github.com/raytran54/CVE-2019-1698) :  ![starts](https://img.shields.io/github/stars/raytran54/CVE-2019-1698.svg) ![forks](https://img.shields.io/github/forks/raytran54/CVE-2019-1698.svg)


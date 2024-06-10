# Update 2024-06-10
## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/Hector65432/cve-2024-32002-1](https://github.com/Hector65432/cve-2024-32002-1) :  ![starts](https://img.shields.io/github/stars/Hector65432/cve-2024-32002-1.svg) ![forks](https://img.shields.io/github/forks/Hector65432/cve-2024-32002-1.svg)
- [https://github.com/Hector65432/cve-2024-32002-2](https://github.com/Hector65432/cve-2024-32002-2) :  ![starts](https://img.shields.io/github/stars/Hector65432/cve-2024-32002-2.svg) ![forks](https://img.shields.io/github/forks/Hector65432/cve-2024-32002-2.svg)


## CVE-2024-29269
 An issue discovered in Telesquare TLR-2005Ksh 1.0.0 and 1.1.4 allows attackers to run arbitrary system commands via the Cmd parameter.

- [https://github.com/Jhonsonwannaa/CVE-2024-29269](https://github.com/Jhonsonwannaa/CVE-2024-29269) :  ![starts](https://img.shields.io/github/stars/Jhonsonwannaa/CVE-2024-29269.svg) ![forks](https://img.shields.io/github/forks/Jhonsonwannaa/CVE-2024-29269.svg)


## CVE-2024-25600
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ivanbg2004/0BL1V10N-CVE-2024-25600-Bricks-Builder-plugin-for-WordPress](https://github.com/ivanbg2004/0BL1V10N-CVE-2024-25600-Bricks-Builder-plugin-for-WordPress) :  ![starts](https://img.shields.io/github/stars/ivanbg2004/0BL1V10N-CVE-2024-25600-Bricks-Builder-plugin-for-WordPress.svg) ![forks](https://img.shields.io/github/forks/ivanbg2004/0BL1V10N-CVE-2024-25600-Bricks-Builder-plugin-for-WordPress.svg)


## CVE-2024-24919
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/satchhacker/cve-2024-24919](https://github.com/satchhacker/cve-2024-24919) :  ![starts](https://img.shields.io/github/stars/satchhacker/cve-2024-24919.svg) ![forks](https://img.shields.io/github/forks/satchhacker/cve-2024-24919.svg)


## CVE-2024-4577
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/xcanwin/CVE-2024-4577-PHP-RCE](https://github.com/xcanwin/CVE-2024-4577-PHP-RCE) :  ![starts](https://img.shields.io/github/stars/xcanwin/CVE-2024-4577-PHP-RCE.svg) ![forks](https://img.shields.io/github/forks/xcanwin/CVE-2024-4577-PHP-RCE.svg)
- [https://github.com/zomasec/CVE-2024-4577](https://github.com/zomasec/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/zomasec/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/zomasec/CVE-2024-4577.svg)
- [https://github.com/ZephrFish/CVE-2024-4577-PHP-RCE](https://github.com/ZephrFish/CVE-2024-4577-PHP-RCE) :  ![starts](https://img.shields.io/github/stars/ZephrFish/CVE-2024-4577-PHP-RCE.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/CVE-2024-4577-PHP-RCE.svg)


## CVE-2023-22515
 Atlassian has been made aware of an issue reported by a handful of customers where external attackers may have exploited a previously unknown vulnerability in publicly accessible Confluence Data Center and Server instances to create unauthorized Confluence administrator accounts and access Confluence instances. Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue.

- [https://github.com/xorbbo/cve-2023-22515](https://github.com/xorbbo/cve-2023-22515) :  ![starts](https://img.shields.io/github/stars/xorbbo/cve-2023-22515.svg) ![forks](https://img.shields.io/github/forks/xorbbo/cve-2023-22515.svg)


## CVE-2022-21500
 Vulnerability in Oracle E-Business Suite (component: Manage Proxies). The supported version that is affected is 12.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle E-Business Suite. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle E-Business Suite accessible data. Note: Authentication is required for successful attack, however the user may be self-registered. &lt;br&gt; &lt;br&gt;Oracle E-Business Suite 12.1 is not impacted by this vulnerability. Customers should refer to the Patch Availability Document for details. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/Cappricio-Securities/CVE-2022-21500](https://github.com/Cappricio-Securities/CVE-2022-21500) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2022-21500.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2022-21500.svg)


## CVE-2022-4510
 A path traversal vulnerability was identified in ReFirm Labs binwalk from version 2.1.2b through 2.3.3 included. By crafting a malicious PFS filesystem file, an attacker can get binwalk's PFS extractor to extract files at arbitrary locations when binwalk is run in extraction mode (-e option). Remote code execution can be achieved by building a PFS filesystem that, upon extraction, would extract a malicious binwalk module into the folder .config/binwalk/plugins. This vulnerability is associated with program files src/binwalk/plugins/unpfs.py. This issue affects binwalk from 2.1.2b through 2.3.3 included.

- [https://github.com/Kalagious/BadPfs-CVE-2022-4510](https://github.com/Kalagious/BadPfs-CVE-2022-4510) :  ![starts](https://img.shields.io/github/stars/Kalagious/BadPfs-CVE-2022-4510.svg) ![forks](https://img.shields.io/github/forks/Kalagious/BadPfs-CVE-2022-4510.svg)


## CVE-2020-13958
 A vulnerability in Apache OpenOffice scripting events allows an attacker to construct documents containing hyperlinks pointing to an executable on the target users file system. These hyperlinks can be triggered unconditionally. In fixed versions no internal protocol may be called from the document event handler and other hyperlinks require a control-click.

- [https://github.com/Grey-Junior/CVE-2020-13958](https://github.com/Grey-Junior/CVE-2020-13958) :  ![starts](https://img.shields.io/github/stars/Grey-Junior/CVE-2020-13958.svg) ![forks](https://img.shields.io/github/forks/Grey-Junior/CVE-2020-13958.svg)


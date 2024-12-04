# Update 2024-12-04
## CVE-2024-38816
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Anthony1078/App-vulnerable](https://github.com/Anthony1078/App-vulnerable) :  ![starts](https://img.shields.io/github/stars/Anthony1078/App-vulnerable.svg) ![forks](https://img.shields.io/github/forks/Anthony1078/App-vulnerable.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/SpycioKon/CVE-2024-32002](https://github.com/SpycioKon/CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/SpycioKon/CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/SpycioKon/CVE-2024-32002.svg)


## CVE-2024-4899
 The SEOPress WordPress plugin before 7.8 does not sanitise and escape some of its Post settings, which could allow high privilege users such as contributor to perform Stored Cross-Site Scripting attacks.

- [https://github.com/r0xdeadbeef/CVE-2024-48990](https://github.com/r0xdeadbeef/CVE-2024-48990) :  ![starts](https://img.shields.io/github/stars/r0xdeadbeef/CVE-2024-48990.svg) ![forks](https://img.shields.io/github/forks/r0xdeadbeef/CVE-2024-48990.svg)


## CVE-2024-4521
 A vulnerability classified as problematic has been found in Campcodes Complete Web-Based School Management System 1.0. Affected is an unknown function of the file /view/teacher_salary_details2.php. The manipulation of the argument index leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-263124.

- [https://github.com/congdong007/CVE-2024-45216-Poc](https://github.com/congdong007/CVE-2024-45216-Poc) :  ![starts](https://img.shields.io/github/stars/congdong007/CVE-2024-45216-Poc.svg) ![forks](https://img.shields.io/github/forks/congdong007/CVE-2024-45216-Poc.svg)


## CVE-2024-1041
 The WP Radio &#8211; Worldwide Online Radio Stations Directory for WordPress plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's settings in all versions up to, and including, 3.1.9 due to insufficient input sanitization and output escaping as well as insufficient access control on the settings. This makes it possible for authenticated attackers, with subscriber access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/K1nakoo/CVE-2024-10410](https://github.com/K1nakoo/CVE-2024-10410) :  ![starts](https://img.shields.io/github/stars/K1nakoo/CVE-2024-10410.svg) ![forks](https://img.shields.io/github/forks/K1nakoo/CVE-2024-10410.svg)


## CVE-2024-1035
 A vulnerability has been found in openBI up to 1.0.8 and classified as critical. This vulnerability affects the function uploadIcon of the file /application/index/controller/Icon.php. The manipulation of the argument image leads to unrestricted upload. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-252310 is the identifier assigned to this vulnerability.

- [https://github.com/K1nakoo/CVE-2024-10355](https://github.com/K1nakoo/CVE-2024-10355) :  ![starts](https://img.shields.io/github/stars/K1nakoo/CVE-2024-10355.svg) ![forks](https://img.shields.io/github/forks/K1nakoo/CVE-2024-10355.svg)
- [https://github.com/K1nakoo/CVE-2024-10354](https://github.com/K1nakoo/CVE-2024-10354) :  ![starts](https://img.shields.io/github/stars/K1nakoo/CVE-2024-10354.svg) ![forks](https://img.shields.io/github/forks/K1nakoo/CVE-2024-10354.svg)


## CVE-2023-41425
 Cross Site Scripting vulnerability in Wonder CMS v.3.2.0 thru v.3.4.2 allows a remote attacker to execute arbitrary code via a crafted script uploaded to the installModule component.

- [https://github.com/SpycioKon/CVE-2023-41425](https://github.com/SpycioKon/CVE-2023-41425) :  ![starts](https://img.shields.io/github/stars/SpycioKon/CVE-2023-41425.svg) ![forks](https://img.shields.io/github/forks/SpycioKon/CVE-2023-41425.svg)


## CVE-2023-1177
 Path Traversal: '\..\filename' in GitHub repository mlflow/mlflow prior to 2.2.1.

- [https://github.com/SpycioKon/CVE-2023-1177-rebuild](https://github.com/SpycioKon/CVE-2023-1177-rebuild) :  ![starts](https://img.shields.io/github/stars/SpycioKon/CVE-2023-1177-rebuild.svg) ![forks](https://img.shields.io/github/forks/SpycioKon/CVE-2023-1177-rebuild.svg)


## CVE-2022-33891
 The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1.

- [https://github.com/nanaao/CVE-2022-33891](https://github.com/nanaao/CVE-2022-33891) :  ![starts](https://img.shields.io/github/stars/nanaao/CVE-2022-33891.svg) ![forks](https://img.shields.io/github/forks/nanaao/CVE-2022-33891.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/CatAnnaDev/CVE-2022-26134](https://github.com/CatAnnaDev/CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/CatAnnaDev/CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/CatAnnaDev/CVE-2022-26134.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/Sebastianbedoya25/CVE-2021-3156](https://github.com/Sebastianbedoya25/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/Sebastianbedoya25/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/Sebastianbedoya25/CVE-2021-3156.svg)


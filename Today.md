# Update 2022-08-15
## CVE-2022-33891
 The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1.

- [https://github.com/DrLinuxOfficial/CVE-2022-33891](https://github.com/DrLinuxOfficial/CVE-2022-33891) :  ![starts](https://img.shields.io/github/stars/DrLinuxOfficial/CVE-2022-33891.svg) ![forks](https://img.shields.io/github/forks/DrLinuxOfficial/CVE-2022-33891.svg)


## CVE-2022-29778
 ** UNSUPPORTED WHEN ASSIGNED ** D-Link DIR-890L 1.20b01 allows attackers to execute arbitrary code due to the hardcoded option Wake-On-Lan for the parameter 'descriptor' at SetVirtualServerSettings.php.

- [https://github.com/TyeYeah/DIR-890L-1.20-RCE](https://github.com/TyeYeah/DIR-890L-1.20-RCE) :  ![starts](https://img.shields.io/github/stars/TyeYeah/DIR-890L-1.20-RCE.svg) ![forks](https://img.shields.io/github/forks/TyeYeah/DIR-890L-1.20-RCE.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/whoami0622/CVE-2022-22965-POC](https://github.com/whoami0622/CVE-2022-22965-POC) :  ![starts](https://img.shields.io/github/stars/whoami0622/CVE-2022-22965-POC.svg) ![forks](https://img.shields.io/github/forks/whoami0622/CVE-2022-22965-POC.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/EagleTube/CVE-2022-0847](https://github.com/EagleTube/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/EagleTube/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/EagleTube/CVE-2022-0847.svg)


## CVE-2021-21300
 Git is an open-source distributed revision control system. In affected versions of Git a specially crafted repository that contains symbolic links as well as files using a clean/smudge filter such as Git LFS, may cause just-checked out script to be executed while cloning onto a case-insensitive file system such as NTFS, HFS+ or APFS (i.e. the default file systems on Windows and macOS). Note that clean/smudge filters have to be configured for that. Git for Windows configures Git LFS by default, and is therefore vulnerable. The problem has been patched in the versions published on Tuesday, March 9th, 2021. As a workaound, if symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. Likewise, if no clean/smudge filters such as Git LFS are configured globally (i.e. _before_ cloning), the attack is foiled. As always, it is best to avoid cloning repositories from untrusted sources. The earliest impacted version is 2.14.2. The fix versions are: 2.30.1, 2.29.3, 2.28.1, 2.27.1, 2.26.3, 2.25.5, 2.24.4, 2.23.4, 2.22.5, 2.21.4, 2.20.5, 2.19.6, 2.18.5, 2.17.62.17.6.

- [https://github.com/Roboterh/CVE-2021-21300](https://github.com/Roboterh/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/Roboterh/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/Roboterh/CVE-2021-21300.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/TomMalvoRiddle/CVE-2021-3560](https://github.com/TomMalvoRiddle/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/TomMalvoRiddle/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/TomMalvoRiddle/CVE-2021-3560.svg)


## CVE-2020-9006
 The Popup Builder plugin 2.2.8 through 2.6.7.6 for WordPress is vulnerable to SQL injection (in the sgImportPopups function in sg_popup_ajax.php) via PHP Deserialization on attacker-controlled data with the attachmentUrl POST variable. This allows creation of an arbitrary WordPress Administrator account, leading to possible Remote Code Execution because Administrators can run PHP code on Wordpress instances. (This issue has been fixed in the 3.x branch of popup-builder.)

- [https://github.com/mich3s/cve-2020-9006](https://github.com/mich3s/cve-2020-9006) :  ![starts](https://img.shields.io/github/stars/mich3s/cve-2020-9006.svg) ![forks](https://img.shields.io/github/forks/mich3s/cve-2020-9006.svg)


## CVE-2019-13623
 In NSA Ghidra before 9.1, path traversal can occur in RestoreTask.java (from the package ghidra.app.plugin.core.archive) via an archive with an executable file that has an initial ../ in its filename. This allows attackers to overwrite arbitrary files in scenarios where an intermediate analysis result is archived for sharing with other persons. To achieve arbitrary code execution, one approach is to overwrite some critical Ghidra modules, e.g., the decompile module.

- [https://github.com/TeamPhoneix/exploits](https://github.com/TeamPhoneix/exploits) :  ![starts](https://img.shields.io/github/stars/TeamPhoneix/exploits.svg) ![forks](https://img.shields.io/github/forks/TeamPhoneix/exploits.svg)


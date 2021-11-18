# Update 2021-11-18
## CVE-2021-21300
 Git is an open-source distributed revision control system. In affected versions of Git a specially crafted repository that contains symbolic links as well as files using a clean/smudge filter such as Git LFS, may cause just-checked out script to be executed while cloning onto a case-insensitive file system such as NTFS, HFS+ or APFS (i.e. the default file systems on Windows and macOS). Note that clean/smudge filters have to be configured for that. Git for Windows configures Git LFS by default, and is therefore vulnerable. The problem has been patched in the versions published on Tuesday, March 9th, 2021. As a workaound, if symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. Likewise, if no clean/smudge filters such as Git LFS are configured globally (i.e. _before_ cloning), the attack is foiled. As always, it is best to avoid cloning repositories from untrusted sources. The earliest impacted version is 2.14.2. The fix versions are: 2.30.1, 2.29.3, 2.28.1, 2.27.1, 2.26.3, 2.25.5, 2.24.4, 2.23.4, 2.22.5, 2.21.4, 2.20.5, 2.19.6, 2.18.5, 2.17.62.17.6.

- [https://github.com/fengzhouc/CVE-2021-21300](https://github.com/fengzhouc/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/fengzhouc/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/fengzhouc/CVE-2021-21300.svg)


## CVE-2020-35314
 A remote code execution vulnerability in the installUpdateThemePluginAction function in index.php in WonderCMS 3.1.3, allows remote attackers to upload a custom plugin which can contain arbitrary code and obtain a webshell via the theme/plugin installer.

- [https://github.com/ybdegit2020/wonderplugin](https://github.com/ybdegit2020/wonderplugin) :  ![starts](https://img.shields.io/github/stars/ybdegit2020/wonderplugin.svg) ![forks](https://img.shields.io/github/forks/ybdegit2020/wonderplugin.svg)


## CVE-2020-28032
 WordPress before 5.5.2 mishandles deserialization requests in wp-includes/Requests/Utility/FilteredIterator.php.

- [https://github.com/nth347/CVE-2020-28032_PoC](https://github.com/nth347/CVE-2020-28032_PoC) :  ![starts](https://img.shields.io/github/stars/nth347/CVE-2020-28032_PoC.svg) ![forks](https://img.shields.io/github/forks/nth347/CVE-2020-28032_PoC.svg)


## CVE-2020-0787
 An elevation of privilege vulnerability exists when the Windows Background Intelligent Transfer Service (BITS) improperly handles symbolic links, aka 'Windows Background Intelligent Transfer Service Elevation of Privilege Vulnerability'.

- [https://github.com/yanghaoi/CVE-2020-0787](https://github.com/yanghaoi/CVE-2020-0787) :  ![starts](https://img.shields.io/github/stars/yanghaoi/CVE-2020-0787.svg) ![forks](https://img.shields.io/github/forks/yanghaoi/CVE-2020-0787.svg)


## CVE-2019-1388
 An elevation of privilege vulnerability exists in the Windows Certificate Dialog when it does not properly enforce user privileges, aka 'Windows Certificate Dialog Elevation of Privilege Vulnerability'.

- [https://github.com/sv3nbeast/CVE-2019-1388](https://github.com/sv3nbeast/CVE-2019-1388) :  ![starts](https://img.shields.io/github/stars/sv3nbeast/CVE-2019-1388.svg) ![forks](https://img.shields.io/github/forks/sv3nbeast/CVE-2019-1388.svg)


## CVE-2018-19571
 GitLab CE/EE, versions 8.18 up to 11.x before 11.3.11, 11.4 before 11.4.8, and 11.5 before 11.5.1, are vulnerable to an SSRF vulnerability in webhooks.

- [https://github.com/CS4239-U6/gitlab-ssrf](https://github.com/CS4239-U6/gitlab-ssrf) :  ![starts](https://img.shields.io/github/stars/CS4239-U6/gitlab-ssrf.svg) ![forks](https://img.shields.io/github/forks/CS4239-U6/gitlab-ssrf.svg)


# Update 2024-07-21
## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/TSY244/CVE-2024-32002-git-rce](https://github.com/TSY244/CVE-2024-32002-git-rce) :  ![starts](https://img.shields.io/github/stars/TSY244/CVE-2024-32002-git-rce.svg) ![forks](https://img.shields.io/github/forks/TSY244/CVE-2024-32002-git-rce.svg)
- [https://github.com/TSY244/CVE-2024-32002-git-rce-father-poc](https://github.com/TSY244/CVE-2024-32002-git-rce-father-poc) :  ![starts](https://img.shields.io/github/stars/TSY244/CVE-2024-32002-git-rce-father-poc.svg) ![forks](https://img.shields.io/github/forks/TSY244/CVE-2024-32002-git-rce-father-poc.svg)


## CVE-2022-37706
 enlightenment_sys in Enlightenment before 0.25.4 allows local users to gain privileges because it is setuid root, and the system library function mishandles pathnames that begin with a /dev/.. substring.

- [https://github.com/TACTICAL-HACK/CVE-2022-37706-SUID](https://github.com/TACTICAL-HACK/CVE-2022-37706-SUID) :  ![starts](https://img.shields.io/github/stars/TACTICAL-HACK/CVE-2022-37706-SUID.svg) ![forks](https://img.shields.io/github/forks/TACTICAL-HACK/CVE-2022-37706-SUID.svg)


## CVE-2021-3831
 gnuboard5 is vulnerable to Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

- [https://github.com/aratane/CVE-2021-3831](https://github.com/aratane/CVE-2021-3831) :  ![starts](https://img.shields.io/github/stars/aratane/CVE-2021-3831.svg) ![forks](https://img.shields.io/github/forks/aratane/CVE-2021-3831.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/Fatalitysec/CVE-2012-1823](https://github.com/Fatalitysec/CVE-2012-1823) :  ![starts](https://img.shields.io/github/stars/Fatalitysec/CVE-2012-1823.svg) ![forks](https://img.shields.io/github/forks/Fatalitysec/CVE-2012-1823.svg)


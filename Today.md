# Update 2022-10-29
## CVE-2022-40684
 An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

- [https://github.com/TaroballzChen/CVE-2022-40684-metasploit-scanner](https://github.com/TaroballzChen/CVE-2022-40684-metasploit-scanner) :  ![starts](https://img.shields.io/github/stars/TaroballzChen/CVE-2022-40684-metasploit-scanner.svg) ![forks](https://img.shields.io/github/forks/TaroballzChen/CVE-2022-40684-metasploit-scanner.svg)
- [https://github.com/gustavorobertux/gotigate](https://github.com/gustavorobertux/gotigate) :  ![starts](https://img.shields.io/github/stars/gustavorobertux/gotigate.svg) ![forks](https://img.shields.io/github/forks/gustavorobertux/gotigate.svg)
- [https://github.com/hughink/CVE-2022-40684](https://github.com/hughink/CVE-2022-40684) :  ![starts](https://img.shields.io/github/stars/hughink/CVE-2022-40684.svg) ![forks](https://img.shields.io/github/forks/hughink/CVE-2022-40684.svg)


## CVE-2021-43890
 Windows AppX Installer Spoofing Vulnerability

- [https://github.com/yonggui-li/CVE-2021-43890_poc](https://github.com/yonggui-li/CVE-2021-43890_poc) :  ![starts](https://img.shields.io/github/stars/yonggui-li/CVE-2021-43890_poc.svg) ![forks](https://img.shields.io/github/forks/yonggui-li/CVE-2021-43890_poc.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/ly4k/PwnKit](https://github.com/ly4k/PwnKit) :  ![starts](https://img.shields.io/github/stars/ly4k/PwnKit.svg) ![forks](https://img.shields.io/github/forks/ly4k/PwnKit.svg)
- [https://github.com/T3slaa/pwnkit-pwn](https://github.com/T3slaa/pwnkit-pwn) :  ![starts](https://img.shields.io/github/stars/T3slaa/pwnkit-pwn.svg) ![forks](https://img.shields.io/github/forks/T3slaa/pwnkit-pwn.svg)
- [https://github.com/gbrsh/CVE-2021-4034](https://github.com/gbrsh/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/gbrsh/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/gbrsh/CVE-2021-4034.svg)
- [https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux](https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux) :  ![starts](https://img.shields.io/github/stars/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg) ![forks](https://img.shields.io/github/forks/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg)


## CVE-2021-3138
 In Discourse 2.7.0 through beta1, a rate-limit bypass leads to a bypass of the 2FA requirement for certain forms.

- [https://github.com/Mesh3l911/CVE-2021-3138](https://github.com/Mesh3l911/CVE-2021-3138) :  ![starts](https://img.shields.io/github/stars/Mesh3l911/CVE-2021-3138.svg) ![forks](https://img.shields.io/github/forks/Mesh3l911/CVE-2021-3138.svg)


## CVE-2020-26233
 Git Credential Manager Core (GCM Core) is a secure Git credential helper built on .NET Core that runs on Windows and macOS. In Git Credential Manager Core before version 2.0.289, when recursively cloning a Git repository on Windows with submodules, Git will first clone the top-level repository and then recursively clone all submodules by starting new Git processes from the top-level working directory. If a malicious git.exe executable is present in the top-level repository then this binary will be started by Git Credential Manager Core when attempting to read configuration, and not git.exe as found on the %PATH%. This only affects GCM Core on Windows, not macOS or Linux-based distributions. GCM Core version 2.0.289 contains the fix for this vulnerability, and is available from the project's GitHub releases page. GCM Core 2.0.289 is also bundled in the latest Git for Windows release; version 2.29.2(3). As a workaround, users should avoid recursively cloning untrusted repositories with the --recurse-submodules option.

- [https://github.com/an1p3lg5/CVE-2020-26233](https://github.com/an1p3lg5/CVE-2020-26233) :  ![starts](https://img.shields.io/github/stars/an1p3lg5/CVE-2020-26233.svg) ![forks](https://img.shields.io/github/forks/an1p3lg5/CVE-2020-26233.svg)


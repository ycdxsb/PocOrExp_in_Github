# Update 2025-09-13
## CVE-2025-42944
 Due to a deserialization vulnerability in SAP NetWeaver, an unauthenticated attacker could exploit the system through the RMI-P4 module by submitting malicious payload to an open port. The deserialization of such untrusted Java objects could lead to arbitrary OS command execution, posing a high impact to the application's confidentiality, integrity, and availability.

- [https://github.com/rxerium/CVE-2025-42944](https://github.com/rxerium/CVE-2025-42944) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-42944.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-42944.svg)


## CVE-2025-31258
 This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Sequoia 15.5. An app may be able to break out of its sandbox.

- [https://github.com/sureshkumarsat/CVE-2025-31258-PoC](https://github.com/sureshkumarsat/CVE-2025-31258-PoC) :  ![starts](https://img.shields.io/github/stars/sureshkumarsat/CVE-2025-31258-PoC.svg) ![forks](https://img.shields.io/github/forks/sureshkumarsat/CVE-2025-31258-PoC.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/MKIRAHMET/CVE-2025-29927-PoC](https://github.com/MKIRAHMET/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/MKIRAHMET/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/MKIRAHMET/CVE-2025-29927-PoC.svg)


## CVE-2025-8570
 The BeyondCart Connector plugin for WordPress is vulnerable to Privilege Escalation due to improper JWT secret management and authorization within the determine_current_user filter in versions 1.4.2 through 2.1.0. This makes it possible for unauthenticated attackers to craft valid tokens and assume any user’s identity.

- [https://github.com/Nxploited/CVE-2025-8570](https://github.com/Nxploited/CVE-2025-8570) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-8570.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-8570.svg)


## CVE-2025-5589
 The StreamWeasels Kick Integration plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘status-classic-offline-text’ parameter in all versions up to, and including, 1.1.3 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/terribledactyl/CVE-2025-55891](https://github.com/terribledactyl/CVE-2025-55891) :  ![starts](https://img.shields.io/github/stars/terribledactyl/CVE-2025-55891.svg) ![forks](https://img.shields.io/github/forks/terribledactyl/CVE-2025-55891.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/mrk336/CVE-2024-3094](https://github.com/mrk336/CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/mrk336/CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/mrk336/CVE-2024-3094.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Shadow-Spinner/CVE-2022-0847](https://github.com/Shadow-Spinner/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/Shadow-Spinner/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/Shadow-Spinner/CVE-2022-0847.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/dr4xp/pwnkit-helper](https://github.com/dr4xp/pwnkit-helper) :  ![starts](https://img.shields.io/github/stars/dr4xp/pwnkit-helper.svg) ![forks](https://img.shields.io/github/forks/dr4xp/pwnkit-helper.svg)


## CVE-2019-18935
 Progress Telerik UI for ASP.NET AJAX through 2019.3.1023 contains a .NET deserialization vulnerability in the RadAsyncUpload function. This is exploitable when the encryption keys are known due to the presence of CVE-2017-11317 or CVE-2017-11357, or other means. Exploitation can result in remote code execution. (As of 2020.1.114, a default setting prevents the exploit. In 2019.3.1023, but not earlier versions, a non-default setting can prevent exploitation.)

- [https://github.com/quyt0/CVE-2019-18935-exploit-study](https://github.com/quyt0/CVE-2019-18935-exploit-study) :  ![starts](https://img.shields.io/github/stars/quyt0/CVE-2019-18935-exploit-study.svg) ![forks](https://img.shields.io/github/forks/quyt0/CVE-2019-18935-exploit-study.svg)


## CVE-2017-1000117
 A malicious third-party can give a crafted "ssh://..." URL to an unsuspecting victim, and an attempt to visit the URL can result in any program that exists on the victim's machine being executed. Such a URL could be placed in the .gitmodules file of a malicious project, and an unsuspecting victim could be tricked into running "git clone --recurse-submodules" to trigger the vulnerability.

- [https://github.com/chu1337/CVE-2017-1000117](https://github.com/chu1337/CVE-2017-1000117) :  ![starts](https://img.shields.io/github/stars/chu1337/CVE-2017-1000117.svg) ![forks](https://img.shields.io/github/forks/chu1337/CVE-2017-1000117.svg)


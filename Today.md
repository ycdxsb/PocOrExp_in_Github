# Update 2025-03-03
## CVE-2025-25296
 Label Studio is an open source data labeling tool. Prior to version 1.16.0, Label Studio's `/projects/upload-example` endpoint allows injection of arbitrary HTML through a `GET` request with an appropriately crafted `label_config` query parameter. By crafting a specially formatted XML label config with inline task data containing malicious HTML/JavaScript, an attacker can achieve Cross-Site Scripting (XSS). While the application has a Content Security Policy (CSP), it is only set in report-only mode, making it ineffective at preventing script execution. The vulnerability exists because the upload-example endpoint renders user-provided HTML content without proper sanitization on a GET request. This allows attackers to inject and execute arbitrary JavaScript in victims' browsers by getting them to visit a maliciously crafted URL. This is considered vulnerable because it enables attackers to execute JavaScript in victims' contexts, potentially allowing theft of sensitive data, session hijacking, or other malicious actions. Version 1.16.0 contains a patch for the issue.

- [https://github.com/math-x-io/CVE-2025-25296-POC](https://github.com/math-x-io/CVE-2025-25296-POC) :  ![starts](https://img.shields.io/github/stars/math-x-io/CVE-2025-25296-POC.svg) ![forks](https://img.shields.io/github/forks/math-x-io/CVE-2025-25296-POC.svg)


## CVE-2023-32434
 An integer overflow was addressed with improved input validation. This issue is fixed in watchOS 9.5.2, macOS Big Sur 11.7.8, iOS 15.7.7 and iPadOS 15.7.7, macOS Monterey 12.6.7, watchOS 8.8.1, iOS 16.5.1 and iPadOS 16.5.1, macOS Ventura 13.4.1. An app may be able to execute arbitrary code with kernel privileges. Apple is aware of a report that this issue may have been actively exploited against versions of iOS released before iOS 15.7.

- [https://github.com/alfiecg24/Trigon](https://github.com/alfiecg24/Trigon) :  ![starts](https://img.shields.io/github/stars/alfiecg24/Trigon.svg) ![forks](https://img.shields.io/github/forks/alfiecg24/Trigon.svg)


## CVE-2023-4911
 A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

- [https://github.com/dungNHVhust/CVE-2023-4911](https://github.com/dungNHVhust/CVE-2023-4911) :  ![starts](https://img.shields.io/github/stars/dungNHVhust/CVE-2023-4911.svg) ![forks](https://img.shields.io/github/forks/dungNHVhust/CVE-2023-4911.svg)


## CVE-2023-1545
 SQL Injection in GitHub repository nilsteampassnet/teampass prior to 3.0.0.23.

- [https://github.com/sternstundes/CVE-2023-1545-POC-python](https://github.com/sternstundes/CVE-2023-1545-POC-python) :  ![starts](https://img.shields.io/github/stars/sternstundes/CVE-2023-1545-POC-python.svg) ![forks](https://img.shields.io/github/forks/sternstundes/CVE-2023-1545-POC-python.svg)


## CVE-2022-38532
 Micro-Star International Co., Ltd MSI Center 1.0.50.0 was discovered to contain a vulnerability in the component C_Features of MSI.CentralServer.exe. This vulnerability allows attackers to escalate privileges via running a crafted executable.

- [https://github.com/nam3lum/msi-central_privesc](https://github.com/nam3lum/msi-central_privesc) :  ![starts](https://img.shields.io/github/stars/nam3lum/msi-central_privesc.svg) ![forks](https://img.shields.io/github/forks/nam3lum/msi-central_privesc.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe](https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/osungjinwoo/CVE-2021-22205-gitlab](https://github.com/osungjinwoo/CVE-2021-22205-gitlab) :  ![starts](https://img.shields.io/github/stars/osungjinwoo/CVE-2021-22205-gitlab.svg) ![forks](https://img.shields.io/github/forks/osungjinwoo/CVE-2021-22205-gitlab.svg)


## CVE-2019-9194
 elFinder before 2.1.48 has a command injection vulnerability in the PHP connector.

- [https://github.com/cyvorsec/TryHackMe](https://github.com/cyvorsec/TryHackMe) :  ![starts](https://img.shields.io/github/stars/cyvorsec/TryHackMe.svg) ![forks](https://img.shields.io/github/forks/cyvorsec/TryHackMe.svg)


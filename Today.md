# Update 2025-02-02
## CVE-2025-24659
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in WordPress Download Manager Premium Packages allows Blind SQL Injection. This issue affects Premium Packages: from n/a through 5.9.6.

- [https://github.com/DoTTak/CVE-2025-24659](https://github.com/DoTTak/CVE-2025-24659) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-24659.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-24659.svg)


## CVE-2025-24587
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in I Thirteen Web Solution Email Subscription Popup allows Blind SQL Injection. This issue affects Email Subscription Popup: from n/a through 1.2.23.

- [https://github.com/DoTTak/CVE-2025-24587](https://github.com/DoTTak/CVE-2025-24587) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-24587.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-24587.svg)


## CVE-2025-24118
 The issue was addressed with improved memory handling. This issue is fixed in iPadOS 17.7.4, macOS Sequoia 15.3, macOS Sonoma 14.7.3. An app may be able to cause unexpected system termination or write kernel memory.

- [https://github.com/jprx/CVE-2025-24118](https://github.com/jprx/CVE-2025-24118) :  ![starts](https://img.shields.io/github/stars/jprx/CVE-2025-24118.svg) ![forks](https://img.shields.io/github/forks/jprx/CVE-2025-24118.svg)


## CVE-2025-23040
 GitHub Desktop is an open-source Electron-based GitHub app designed for git development. An attacker convincing a user to clone a repository directly or through a submodule can allow the attacker access to the user's credentials through the use of maliciously crafted remote URL. GitHub Desktop relies on Git to perform all network related operations (such as cloning, fetching, and pushing). When a user attempts to clone a repository GitHub Desktop will invoke `git clone` and when Git encounters a remote which requires authentication it will request the credentials for that remote host from GitHub Desktop using the git-credential protocol. Using a maliciously crafted URL it's possible to cause the credential request coming from Git to be misinterpreted by Github Desktop such that it will send credentials for a different host than the host that Git is currently communicating with thereby allowing for secret exfiltration. GitHub username and OAuth token, or credentials for other Git remote hosts stored in GitHub Desktop could be improperly transmitted to an unrelated host. Users should update to GitHub Desktop 3.4.12 or greater which fixes this vulnerability. Users who suspect they may be affected should revoke any relevant credentials.

- [https://github.com/GabrieleDattile/CVE-2025-23040](https://github.com/GabrieleDattile/CVE-2025-23040) :  ![starts](https://img.shields.io/github/stars/GabrieleDattile/CVE-2025-23040.svg) ![forks](https://img.shields.io/github/forks/GabrieleDattile/CVE-2025-23040.svg)


## CVE-2024-5717
The specific flaw exists within the implementation of the HTTP API. The issue results from the lack of proper validation of a user-supplied string before using it to execute a system call. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-24165.

- [https://github.com/Ajmal101/CVE-2024-57175](https://github.com/Ajmal101/CVE-2024-57175) :  ![starts](https://img.shields.io/github/stars/Ajmal101/CVE-2024-57175.svg) ![forks](https://img.shields.io/github/forks/Ajmal101/CVE-2024-57175.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)


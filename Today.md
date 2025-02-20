# Update 2025-02-20
## CVE-2025-26465
 A vulnerability was found in OpenSSH when the VerifyHostKeyDNS option is enabled. A machine-in-the-middle attack can be performed by a malicious machine impersonating a legit server. This issue occurs due to how OpenSSH mishandles error codes in specific conditions when verifying the host key. For an attack to be considered successful, the attacker needs to manage to exhaust the client's memory resource first, turning the attack complexity high.

- [https://github.com/rxerium/CVE-2025-26465](https://github.com/rxerium/CVE-2025-26465) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-26465.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-26465.svg)


## CVE-2025-25163
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in Zach Swetz Plugin A/B Image Optimizer allows Path Traversal. This issue affects Plugin A/B Image Optimizer: from n/a through 3.3.

- [https://github.com/RandomRobbieBF/CVE-2025-25163](https://github.com/RandomRobbieBF/CVE-2025-25163) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-25163.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-25163.svg)


## CVE-2025-0108
This issue does not affect Cloud NGFW or Prisma Access software.

- [https://github.com/fr4nc1stein/CVE-2025-0108-SCAN](https://github.com/fr4nc1stein/CVE-2025-0108-SCAN) :  ![starts](https://img.shields.io/github/stars/fr4nc1stein/CVE-2025-0108-SCAN.svg) ![forks](https://img.shields.io/github/forks/fr4nc1stein/CVE-2025-0108-SCAN.svg)


## CVE-2024-56883
 Sage DPW before 2024_12_001 is vulnerable to Incorrect Access Control. The implemented role-based access controls are not always enforced on the server side. Low-privileged Sage users with employee role privileges can create external courses for other employees, even though they do not have the option to do so in the user interface. To do this, a valid request to create a course simply needs to be modified, so that the current user ID in the "id" parameter is replaced with the ID of another user.

- [https://github.com/trustcves/CVE-2024-56883](https://github.com/trustcves/CVE-2024-56883) :  ![starts](https://img.shields.io/github/stars/trustcves/CVE-2024-56883.svg) ![forks](https://img.shields.io/github/forks/trustcves/CVE-2024-56883.svg)


## CVE-2024-56882
 Sage DPW before 2024_12_000 is vulnerable to Cross Site Scripting (XSS). Low-privileged Sage users with employee role privileges can permanently store JavaScript code in the Kurstitel and Kurzinfo input fields. The injected payload is executed for each authenticated user who views and interacts with the modified data elements.

- [https://github.com/trustcves/CVE-2024-56882](https://github.com/trustcves/CVE-2024-56882) :  ![starts](https://img.shields.io/github/stars/trustcves/CVE-2024-56882.svg) ![forks](https://img.shields.io/github/forks/trustcves/CVE-2024-56882.svg)


## CVE-2024-43088
 In multiple functions in AppInfoBase.java, there is a possible way to manipulate app permission settings belonging to another user on the device due to a missing permission check. This could lead to local escalation of privilege across user boundaries with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/nidhihcl75/packages_apps_Settings_AOSP10_r33_CVE-2024-43088](https://github.com/nidhihcl75/packages_apps_Settings_AOSP10_r33_CVE-2024-43088) :  ![starts](https://img.shields.io/github/stars/nidhihcl75/packages_apps_Settings_AOSP10_r33_CVE-2024-43088.svg) ![forks](https://img.shields.io/github/forks/nidhihcl75/packages_apps_Settings_AOSP10_r33_CVE-2024-43088.svg)


## CVE-2024-38526
 pdoc provides API Documentation for Python Projects. Documentation generated with `pdoc --math` linked to JavaScript files from polyfill.io. The polyfill.io CDN has been sold and now serves malicious code. This issue has been fixed in pdoc 14.5.1.

- [https://github.com/padayali-JD/pollyscan](https://github.com/padayali-JD/pollyscan) :  ![starts](https://img.shields.io/github/stars/padayali-JD/pollyscan.svg) ![forks](https://img.shields.io/github/forks/padayali-JD/pollyscan.svg)


## CVE-2023-4911
 A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

- [https://github.com/Billar42/CVE-2023-4911](https://github.com/Billar42/CVE-2023-4911) :  ![starts](https://img.shields.io/github/stars/Billar42/CVE-2023-4911.svg) ![forks](https://img.shields.io/github/forks/Billar42/CVE-2023-4911.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/arcslash/exploit_CVE-2021-3560](https://github.com/arcslash/exploit_CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/arcslash/exploit_CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/arcslash/exploit_CVE-2021-3560.svg)


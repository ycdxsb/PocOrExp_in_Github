# Update 2025-01-30
## CVE-2025-24085
 A use after free issue was addressed with improved memory management. This issue is fixed in visionOS 2.3, iOS 18.3 and iPadOS 18.3, macOS Sequoia 15.3, watchOS 11.3, tvOS 18.3. A malicious application may be able to elevate privileges. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 17.2.

- [https://github.com/clidanc/CVE-2025-24085](https://github.com/clidanc/CVE-2025-24085) :  ![starts](https://img.shields.io/github/stars/clidanc/CVE-2025-24085.svg) ![forks](https://img.shields.io/github/forks/clidanc/CVE-2025-24085.svg)


## CVE-2025-0282
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/AdaniKamal/CVE-2025-0282](https://github.com/AdaniKamal/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/AdaniKamal/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/AdaniKamal/CVE-2025-0282.svg)


## CVE-2024-55968
 An issue was discovered in DTEX DEC-M (DTEX Forwarder) 6.1.1. The com.dtexsystems.helper service, responsible for handling privileged operations within the macOS DTEX Event Forwarder agent, fails to implement critical client validation during XPC interprocess communication (IPC). Specifically, the service does not verify the code requirements, entitlements, security flags, or version of any client attempting to establish a connection. This lack of proper logic validation allows malicious actors to exploit the service's methods via unauthorized client connections, and escalate privileges to root by abusing the DTConnectionHelperProtocol protocol's submitQuery method over an unauthorized XPC connection.

- [https://github.com/Wi1DN00B/CVE-2024-55968](https://github.com/Wi1DN00B/CVE-2024-55968) :  ![starts](https://img.shields.io/github/stars/Wi1DN00B/CVE-2024-55968.svg) ![forks](https://img.shields.io/github/forks/Wi1DN00B/CVE-2024-55968.svg)
- [https://github.com/null-event/CVE-2024-55968](https://github.com/null-event/CVE-2024-55968) :  ![starts](https://img.shields.io/github/stars/null-event/CVE-2024-55968.svg) ![forks](https://img.shields.io/github/forks/null-event/CVE-2024-55968.svg)


## CVE-2024-40676
 In checkKeyIntent of AccountManagerService.java, there is a possible way to bypass intent security check and install an unknown app due to a confused deputy. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Aakashmom/accounts_CVE-2024-40676-](https://github.com/Aakashmom/accounts_CVE-2024-40676-) :  ![starts](https://img.shields.io/github/stars/Aakashmom/accounts_CVE-2024-40676-.svg) ![forks](https://img.shields.io/github/forks/Aakashmom/accounts_CVE-2024-40676-.svg)
- [https://github.com/Aakashmom/frameworks_base_accounts_CVE-2024-40676](https://github.com/Aakashmom/frameworks_base_accounts_CVE-2024-40676) :  ![starts](https://img.shields.io/github/stars/Aakashmom/frameworks_base_accounts_CVE-2024-40676.svg) ![forks](https://img.shields.io/github/forks/Aakashmom/frameworks_base_accounts_CVE-2024-40676.svg)


## CVE-2024-40675
 In parseUriInternal of Intent.java, there is a possible infinite loop due to improper input validation. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Aakashmom/intent_CVE-2024-40675](https://github.com/Aakashmom/intent_CVE-2024-40675) :  ![starts](https://img.shields.io/github/stars/Aakashmom/intent_CVE-2024-40675.svg) ![forks](https://img.shields.io/github/forks/Aakashmom/intent_CVE-2024-40675.svg)


## CVE-2024-40673
 In Source of ZipFile.java, there is a possible way for an attacker to execute arbitrary code by manipulating Dynamic Code Loading due to improper input validation. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Aakashmom/G3_libcore_native_CVE-2024-40673](https://github.com/Aakashmom/G3_libcore_native_CVE-2024-40673) :  ![starts](https://img.shields.io/github/stars/Aakashmom/G3_libcore_native_CVE-2024-40673.svg) ![forks](https://img.shields.io/github/forks/Aakashmom/G3_libcore_native_CVE-2024-40673.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/nobelh/CVE-2021-4034](https://github.com/nobelh/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/nobelh/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/nobelh/CVE-2021-4034.svg)


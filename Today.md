# Update 2024-08-23
## CVE-2024-36598
 An arbitrary file upload vulnerability in Aegon Life v1.0 allows attackers to execute arbitrary code via uploading a crafted image file.

- [https://github.com/keruenn/PoC-CVE-2024-36598](https://github.com/keruenn/PoC-CVE-2024-36598) :  ![starts](https://img.shields.io/github/stars/keruenn/PoC-CVE-2024-36598.svg) ![forks](https://img.shields.io/github/forks/keruenn/PoC-CVE-2024-36598.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/sanan2004/CVE-2024-32002](https://github.com/sanan2004/CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/sanan2004/CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/sanan2004/CVE-2024-32002.svg)


## CVE-2024-27088
 es5-ext contains ECMAScript 5 extensions. Passing functions with very long names or complex default argument names into `function#copy` or `function#toStringTokens` may cause the script to stall. The vulnerability is patched in v0.10.63.

- [https://github.com/200101WhoAmI/CVE-2024-27088](https://github.com/200101WhoAmI/CVE-2024-27088) :  ![starts](https://img.shields.io/github/stars/200101WhoAmI/CVE-2024-27088.svg) ![forks](https://img.shields.io/github/forks/200101WhoAmI/CVE-2024-27088.svg)


## CVE-2024-23339
 hoolock is a suite of lightweight utilities designed to maintain a small footprint when bundled. Starting in version 2.0.0 and prior to version 2.2.1, utility functions related to object paths (`get`, `set`, and `update`) did not block attempts to access or alter object prototypes. Starting in version 2.2.1, the `get`, `set` and `update` functions throw a `TypeError` when a user attempts to access or alter inherited properties.

- [https://github.com/200101WhoAmI/CVE-2024-23339](https://github.com/200101WhoAmI/CVE-2024-23339) :  ![starts](https://img.shields.io/github/stars/200101WhoAmI/CVE-2024-23339.svg) ![forks](https://img.shields.io/github/forks/200101WhoAmI/CVE-2024-23339.svg)


## CVE-2024-22526
 Buffer Overflow vulnerability in bandisoft bandiview v7.0, allows local attackers to cause a denial of service (DoS) via exr image file.

- [https://github.com/200101WhoAmI/CVE-2024-22526](https://github.com/200101WhoAmI/CVE-2024-22526) :  ![starts](https://img.shields.io/github/stars/200101WhoAmI/CVE-2024-22526.svg) ![forks](https://img.shields.io/github/forks/200101WhoAmI/CVE-2024-22526.svg)


## CVE-2024-22263
 Spring Cloud Data Flow is a microservices-based Streaming and Batch data processing in Cloud Foundry and Kubernetes. The Skipper server has the ability to receive upload package requests. However, due to improper sanitization for upload path, a malicious user who has access to skipper server api can use a crafted upload request to write arbitrary file to any location on file system, may even compromises the server.

- [https://github.com/securelayer7/CVE-2024-22263_Scanner](https://github.com/securelayer7/CVE-2024-22263_Scanner) :  ![starts](https://img.shields.io/github/stars/securelayer7/CVE-2024-22263_Scanner.svg) ![forks](https://img.shields.io/github/forks/securelayer7/CVE-2024-22263_Scanner.svg)


## CVE-2024-20746
 Premiere Pro versions 24.1, 23.6.2 and earlier are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/200101WhoAmI/CVE-2024-20746](https://github.com/200101WhoAmI/CVE-2024-20746) :  ![starts](https://img.shields.io/github/stars/200101WhoAmI/CVE-2024-20746.svg) ![forks](https://img.shields.io/github/forks/200101WhoAmI/CVE-2024-20746.svg)


## CVE-2024-5932
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/0xb0mb3r/CVE-2024-5932-PoC](https://github.com/0xb0mb3r/CVE-2024-5932-PoC) :  ![starts](https://img.shields.io/github/stars/0xb0mb3r/CVE-2024-5932-PoC.svg) ![forks](https://img.shields.io/github/forks/0xb0mb3r/CVE-2024-5932-PoC.svg)


## CVE-2023-50245
 OpenEXR-viewer is a viewer for OpenEXR files with detailed metadata probing. Versions prior to 0.6.1 have a memory overflow vulnerability. This issue is fixed in version 0.6.1.

- [https://github.com/200101WhoAmI/CVE-2023-50245](https://github.com/200101WhoAmI/CVE-2023-50245) :  ![starts](https://img.shields.io/github/stars/200101WhoAmI/CVE-2023-50245.svg) ![forks](https://img.shields.io/github/forks/200101WhoAmI/CVE-2023-50245.svg)


## CVE-2023-45827
 Dot diver is a lightweight, powerful, and dependency-free TypeScript utility library that provides types and functions to work with object paths in dot notation. In versions prior to 1.0.2 there is a Prototype Pollution vulnerability in the `setByPath` function which can leads to remote code execution (RCE). This issue has been addressed in commit `98daf567` which has been included in release 1.0.2. Users are advised to upgrade. There are no known workarounds to this vulnerability.

- [https://github.com/200101WhoAmI/CVE-2023-45827](https://github.com/200101WhoAmI/CVE-2023-45827) :  ![starts](https://img.shields.io/github/stars/200101WhoAmI/CVE-2023-45827.svg) ![forks](https://img.shields.io/github/forks/200101WhoAmI/CVE-2023-45827.svg)


## CVE-2023-43646
 get-func-name is a module to retrieve a function's name securely and consistently both in NodeJS and the browser. Versions prior to 2.0.1 are subject to a regular expression denial of service (redos) vulnerability which may lead to a denial of service when parsing malicious input. This vulnerability can be exploited when there is an imbalance in parentheses, which results in excessive backtracking and subsequently increases the CPU load and processing time significantly. This vulnerability can be triggered using the following input: '\t'.repeat(54773) + '\t/function/i'. This issue has been addressed in commit `f934b228b` which has been included in releases from 2.0.1. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/200101WhoAmI/CVE-2023-43646](https://github.com/200101WhoAmI/CVE-2023-43646) :  ![starts](https://img.shields.io/github/stars/200101WhoAmI/CVE-2023-43646.svg) ![forks](https://img.shields.io/github/forks/200101WhoAmI/CVE-2023-43646.svg)


## CVE-2023-43494
 Jenkins 2.50 through 2.423 (both inclusive), LTS 2.60.1 through 2.414.1 (both inclusive) does not exclude sensitive build variables (e.g., password parameter values) from the search in the build history widget, allowing attackers with Item/Read permission to obtain values of sensitive variables used in builds by iteratively testing different characters until the correct sequence is discovered.

- [https://github.com/mqxmm/CVE-2023-43494](https://github.com/mqxmm/CVE-2023-43494) :  ![starts](https://img.shields.io/github/stars/mqxmm/CVE-2023-43494.svg) ![forks](https://img.shields.io/github/forks/mqxmm/CVE-2023-43494.svg)


## CVE-2023-32235
 Ghost before 5.42.1 allows remote attackers to read arbitrary files within the active theme's folder via /assets/built%2F..%2F..%2F/ directory traversal. This occurs in frontend/web/middleware/static-theme.js.

- [https://github.com/AXRoux/Ghost-Path-Traversal-CVE-2023-32235-](https://github.com/AXRoux/Ghost-Path-Traversal-CVE-2023-32235-) :  ![starts](https://img.shields.io/github/stars/AXRoux/Ghost-Path-Traversal-CVE-2023-32235-.svg) ![forks](https://img.shields.io/github/forks/AXRoux/Ghost-Path-Traversal-CVE-2023-32235-.svg)


## CVE-2023-1177
 Path Traversal: '\..\filename' in GitHub repository mlflow/mlflow prior to 2.2.1.

- [https://github.com/saimahmed/MLflow-Vuln](https://github.com/saimahmed/MLflow-Vuln) :  ![starts](https://img.shields.io/github/stars/saimahmed/MLflow-Vuln.svg) ![forks](https://img.shields.io/github/forks/saimahmed/MLflow-Vuln.svg)


## CVE-2022-37706
 enlightenment_sys in Enlightenment before 0.25.4 allows local users to gain privileges because it is setuid root, and the system library function mishandles pathnames that begin with a /dev/.. substring.

- [https://github.com/sanan2004/CVE-2022-37706](https://github.com/sanan2004/CVE-2022-37706) :  ![starts](https://img.shields.io/github/stars/sanan2004/CVE-2022-37706.svg) ![forks](https://img.shields.io/github/forks/sanan2004/CVE-2022-37706.svg)


## CVE-2022-30136
 Windows Network File System Remote Code Execution Vulnerability

- [https://github.com/AXRoux/CVE-2022-30136](https://github.com/AXRoux/CVE-2022-30136) :  ![starts](https://img.shields.io/github/stars/AXRoux/CVE-2022-30136.svg) ![forks](https://img.shields.io/github/forks/AXRoux/CVE-2022-30136.svg)


## CVE-2022-27925
 Zimbra Collaboration (aka ZCS) 8.8.15 and 9.0 has mboximport functionality that receives a ZIP archive and extracts files from it. An authenticated user with administrator rights has the ability to upload arbitrary files to the system, leading to directory traversal.

- [https://github.com/sanan2004/CVE-2022-27925](https://github.com/sanan2004/CVE-2022-27925) :  ![starts](https://img.shields.io/github/stars/sanan2004/CVE-2022-27925.svg) ![forks](https://img.shields.io/github/forks/sanan2004/CVE-2022-27925.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)


## CVE-2021-3449
 An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL pointer dereference will result, leading to a crash and a denial of service attack. A server is only vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j).

- [https://github.com/riptl/cve-2021-3449](https://github.com/riptl/cve-2021-3449) :  ![starts](https://img.shields.io/github/stars/riptl/cve-2021-3449.svg) ![forks](https://img.shields.io/github/forks/riptl/cve-2021-3449.svg)


## CVE-2019-11447
 An issue was discovered in CutePHP CuteNews 2.1.2. An attacker can infiltrate the server through the avatar upload process in the profile area via the avatar_file field to index.php?mod=main&amp;opt=personal. There is no effective control of $imgsize in /core/modules/dashboard.php. The header content of a file can be changed and the control can be bypassed for code execution. (An attacker can use the GIF header for this.)

- [https://github.com/ojo5/CVE-2019-11447.c](https://github.com/ojo5/CVE-2019-11447.c) :  ![starts](https://img.shields.io/github/stars/ojo5/CVE-2019-11447.c.svg) ![forks](https://img.shields.io/github/forks/ojo5/CVE-2019-11447.c.svg)


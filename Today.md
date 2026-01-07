# Update 2026-01-07
## CVE-2026-21440
 AdonisJS is a TypeScript-first web framework. A Path Traversal vulnerability in AdonisJS multipart file handling may allow a remote attacker to write arbitrary files to arbitrary locations on the server filesystem. This impacts @adonisjs/bodyparser through version 10.1.1 and 11.x prerelease versions prior to 11.0.0-next.6. This issue has been patched in @adonisjs/bodyparser versions 10.1.2 and 11.0.0-next.6.

- [https://github.com/Ashwesker/Ashwesker-CVE-2026-21440](https://github.com/Ashwesker/Ashwesker-CVE-2026-21440) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-21440.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-21440.svg)
- [https://github.com/you-ssef9/CVE-2026-21440](https://github.com/you-ssef9/CVE-2026-21440) :  ![starts](https://img.shields.io/github/stars/you-ssef9/CVE-2026-21440.svg) ![forks](https://img.shields.io/github/forks/you-ssef9/CVE-2026-21440.svg)


## CVE-2025-68926
 RustFS is a distributed object storage system built in Rust. In versions prior to 1.0.0-alpha.78, RustFS implements gRPC authentication using a hardcoded static token `"rustfs rpc"` that is publicly exposed in the source code repository, hardcoded on both client and server sides, non-configurable with no mechanism for token rotation, and universally valid across all RustFS deployments. Any attacker with network access to the gRPC port can authenticate using this publicly known token and execute privileged operations including data destruction, policy manipulation, and cluster configuration changes. Version 1.0.0-alpha.78 contains a fix for the issue.

- [https://github.com/Arcueld/CVE-2025-68926](https://github.com/Arcueld/CVE-2025-68926) :  ![starts](https://img.shields.io/github/stars/Arcueld/CVE-2025-68926.svg) ![forks](https://img.shields.io/github/forks/Arcueld/CVE-2025-68926.svg)


## CVE-2025-67315
 Cross Site Request Forgery vulnerability in Employee Leave Management System v.2.1 allows a remote attacker to escalate privileges via the manage-employee.php component

- [https://github.com/r-pradyun/CVE-2025-67315](https://github.com/r-pradyun/CVE-2025-67315) :  ![starts](https://img.shields.io/github/stars/r-pradyun/CVE-2025-67315.svg) ![forks](https://img.shields.io/github/forks/r-pradyun/CVE-2025-67315.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/lincemorado97/CVE-2025-55182_CVE-2025-66478](https://github.com/lincemorado97/CVE-2025-55182_CVE-2025-66478) :  ![starts](https://img.shields.io/github/stars/lincemorado97/CVE-2025-55182_CVE-2025-66478.svg) ![forks](https://img.shields.io/github/forks/lincemorado97/CVE-2025-55182_CVE-2025-66478.svg)


## CVE-2025-52691
 Successful exploitation of the vulnerability could allow an unauthenticated attacker to upload arbitrary files to any location on the mail server, potentially enabling remote code execution.

- [https://github.com/nxgn-kd01/smartermail-cve-scanner](https://github.com/nxgn-kd01/smartermail-cve-scanner) :  ![starts](https://img.shields.io/github/stars/nxgn-kd01/smartermail-cve-scanner.svg) ![forks](https://img.shields.io/github/forks/nxgn-kd01/smartermail-cve-scanner.svg)


## CVE-2025-43529
 A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 26.2, Safari 26.2, iOS 18.7.3 and iPadOS 18.7.3, iOS 26.2 and iPadOS 26.2, macOS Tahoe 26.2, visionOS 26.2, tvOS 26.2. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 was also issued in response to this report.

- [https://github.com/jir4vv1t/CVE-2025-43529](https://github.com/jir4vv1t/CVE-2025-43529) :  ![starts](https://img.shields.io/github/stars/jir4vv1t/CVE-2025-43529.svg) ![forks](https://img.shields.io/github/forks/jir4vv1t/CVE-2025-43529.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/jehovahsays/mev](https://github.com/jehovahsays/mev) :  ![starts](https://img.shields.io/github/stars/jehovahsays/mev.svg) ![forks](https://img.shields.io/github/forks/jehovahsays/mev.svg)


## CVE-2025-14998
 The Branda plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 3.4.24. This is due to the plugin not properly validating a user's identity prior to updating their password. This makes it possible for unauthenticated attackers to change arbitrary user's passwords, including administrators, and leverage that to gain access to their account.

- [https://github.com/KTN1990/CVE-2025-14998](https://github.com/KTN1990/CVE-2025-14998) :  ![starts](https://img.shields.io/github/stars/KTN1990/CVE-2025-14998.svg) ![forks](https://img.shields.io/github/forks/KTN1990/CVE-2025-14998.svg)


## CVE-2025-13390
 The WP Directory Kit plugin for WordPress is vulnerable to authentication bypass in all versions up to, and including, 1.4.4 due to incorrect implementation of the authentication algorithm in the "wdk_generate_auto_login_link" function. This is due to the feature using a cryptographically weak token generation mechanism. This makes it possible for unauthenticated attackers to gain administrative access and achieve full site takeover via the auto-login endpoint with a predictable token.

- [https://github.com/Nxploited/CVE-2025-13390](https://github.com/Nxploited/CVE-2025-13390) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-13390.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-13390.svg)


## CVE-2025-12674
 The KiotViet Sync plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the create_media() function in all versions up to, and including, 1.8.5. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Nxploited/CVE-2025-12674](https://github.com/Nxploited/CVE-2025-12674) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-12674.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-12674.svg)


## CVE-2025-6124
 A vulnerability was found in code-projects Restaurant Order System 1.0 and classified as critical. This issue affects some unknown processing of the file /tablelow.php. The manipulation of the argument ID leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/hackergovind/CVE-2025-61246](https://github.com/hackergovind/CVE-2025-61246) :  ![starts](https://img.shields.io/github/stars/hackergovind/CVE-2025-61246.svg) ![forks](https://img.shields.io/github/forks/hackergovind/CVE-2025-61246.svg)


## CVE-2025-2011
 The Slider & Popup Builder by Depicter plugin for WordPress is vulnerable to generic SQL Injection via the ‘s' parameter in all versions up to, and including, 3.6.1 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/zsy107u/CVE-2025-2011-poc](https://github.com/zsy107u/CVE-2025-2011-poc) :  ![starts](https://img.shields.io/github/stars/zsy107u/CVE-2025-2011-poc.svg) ![forks](https://img.shields.io/github/forks/zsy107u/CVE-2025-2011-poc.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/ReGeLePuMa/HTTP-2-Rapid-Reset-DDos](https://github.com/ReGeLePuMa/HTTP-2-Rapid-Reset-DDos) :  ![starts](https://img.shields.io/github/stars/ReGeLePuMa/HTTP-2-Rapid-Reset-DDos.svg) ![forks](https://img.shields.io/github/forks/ReGeLePuMa/HTTP-2-Rapid-Reset-DDos.svg)


## CVE-2023-42793
 In JetBrains TeamCity before 2023.05.4 authentication bypass leading to RCE on TeamCity Server was possible

- [https://github.com/DDestinys/CVE-2023-42793](https://github.com/DDestinys/CVE-2023-42793) :  ![starts](https://img.shields.io/github/stars/DDestinys/CVE-2023-42793.svg) ![forks](https://img.shields.io/github/forks/DDestinys/CVE-2023-42793.svg)


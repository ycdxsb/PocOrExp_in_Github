# Update 2025-03-23
## CVE-2025-30144
 fast-jwt provides fast JSON Web Token (JWT) implementation. Prior to 5.0.6, the fast-jwt library does not properly validate the iss claim based on the RFC 7519. The iss (issuer) claim validation within the fast-jwt library permits an array of strings as a valid iss value. This design flaw enables a potential attack where a malicious actor crafts a JWT with an iss claim structured as ['https://attacker-domain/', 'https://valid-iss']. Due to the permissive validation, the JWT will be deemed valid. Furthermore, if the application relies on external libraries like get-jwks that do not independently validate the iss claim, the attacker can leverage this vulnerability to forge a JWT that will be accepted by the victim application. Essentially, the attacker can insert their own domain into the iss array, alongside the legitimate issuer, and bypass the intended security checks. This issue is fixed in 5.0.6.

- [https://github.com/tibrn/CVE-2025-30144](https://github.com/tibrn/CVE-2025-30144) :  ![starts](https://img.shields.io/github/stars/tibrn/CVE-2025-30144.svg) ![forks](https://img.shields.io/github/forks/tibrn/CVE-2025-30144.svg)


## CVE-2025-29814
 Improper authorization in Microsoft Partner Center allows an authorized attacker to elevate privileges over a network.

- [https://github.com/SatiresHashi/CVE-2025-29814](https://github.com/SatiresHashi/CVE-2025-29814) :  ![starts](https://img.shields.io/github/stars/SatiresHashi/CVE-2025-29814.svg) ![forks](https://img.shields.io/github/forks/SatiresHashi/CVE-2025-29814.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/MuhammadWaseem29/CVE-2025-24813](https://github.com/MuhammadWaseem29/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/CVE-2025-24813.svg)
- [https://github.com/Alaatk/CVE-2025-24813-POC](https://github.com/Alaatk/CVE-2025-24813-POC) :  ![starts](https://img.shields.io/github/stars/Alaatk/CVE-2025-24813-POC.svg) ![forks](https://img.shields.io/github/forks/Alaatk/CVE-2025-24813-POC.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/shacojx/CVE-2025-24071-Exploit](https://github.com/shacojx/CVE-2025-24071-Exploit) :  ![starts](https://img.shields.io/github/stars/shacojx/CVE-2025-24071-Exploit.svg) ![forks](https://img.shields.io/github/forks/shacojx/CVE-2025-24071-Exploit.svg)


## CVE-2025-24011
 Umbraco is a free and open source .NET content management system. Starting in version 14.0.0 and prior to versions 14.3.2 and 15.1.2, it's possible to determine whether an account exists based on an analysis of response codes and timing of Umbraco management API responses. Versions 14.3.2 and 15.1.2 contain a patch. No known workarounds are available.

- [https://github.com/Puben/CVE-2025-24011-PoC](https://github.com/Puben/CVE-2025-24011-PoC) :  ![starts](https://img.shields.io/github/stars/Puben/CVE-2025-24011-PoC.svg) ![forks](https://img.shields.io/github/forks/Puben/CVE-2025-24011-PoC.svg)


## CVE-2025-23922
 Cross-Site Request Forgery (CSRF) vulnerability in Harsh iSpring Embedder allows Upload a Web Shell to a Web Server.This issue affects iSpring Embedder: from n/a through 1.0.

- [https://github.com/Nxploited/CVE-2025-23922](https://github.com/Nxploited/CVE-2025-23922) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-23922.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-23922.svg)


## CVE-2024-56337
Tomcat 11.0.3, 10.1.35 and 9.0.99 onwards will include checks that sun.io.useCanonCaches is set appropriately before allowing the default servlet to be write enabled on a case insensitive file system. Tomcat will also set sun.io.useCanonCaches to false by default where it can.

- [https://github.com/carefreegarb/CVE-2024-50379](https://github.com/carefreegarb/CVE-2024-50379) :  ![starts](https://img.shields.io/github/stars/carefreegarb/CVE-2024-50379.svg) ![forks](https://img.shields.io/github/forks/carefreegarb/CVE-2024-50379.svg)


## CVE-2024-52375
 Unrestricted Upload of File with Dangerous Type vulnerability in Arttia Creative Datasets Manager by Arttia Creative.This issue affects Datasets Manager by Arttia Creative: from n/a through 1.5.

- [https://github.com/Nxploited/CVE-2024-52375](https://github.com/Nxploited/CVE-2024-52375) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-52375.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-52375.svg)


## CVE-2024-50379
Users are recommended to upgrade to version 11.0.2, 10.1.34 or 9.0.98, which fixes the issue.

- [https://github.com/carefreegarb/CVE-2024-50379](https://github.com/carefreegarb/CVE-2024-50379) :  ![starts](https://img.shields.io/github/stars/carefreegarb/CVE-2024-50379.svg) ![forks](https://img.shields.io/github/forks/carefreegarb/CVE-2024-50379.svg)


## CVE-2024-46981
 Redis is an open source, in-memory database that persists on disk. An authenticated user may use a specially crafted Lua script to manipulate the garbage collector and potentially lead to remote code execution. The problem is fixed in 7.4.2, 7.2.7, and 6.2.17. An additional workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/xsshk/CVE-2024-46981](https://github.com/xsshk/CVE-2024-46981) :  ![starts](https://img.shields.io/github/stars/xsshk/CVE-2024-46981.svg) ![forks](https://img.shields.io/github/forks/xsshk/CVE-2024-46981.svg)


## CVE-2024-11042
 In invoke-ai/invokeai version v5.0.2, the web API `POST /api/v1/images/delete` is vulnerable to Arbitrary File Deletion. This vulnerability allows unauthorized attackers to delete arbitrary files on the server, potentially including critical or sensitive system files such as SSH keys, SQLite databases, and configuration files. This can impact the integrity and availability of applications relying on these files.

- [https://github.com/gothburz/CVE-2024-11042](https://github.com/gothburz/CVE-2024-11042) :  ![starts](https://img.shields.io/github/stars/gothburz/CVE-2024-11042.svg) ![forks](https://img.shields.io/github/forks/gothburz/CVE-2024-11042.svg)


## CVE-2024-11040
 vllm-project vllm version 0.5.2.2 is vulnerable to Denial of Service attacks. The issue occurs in the 'POST /v1/completions' and 'POST /v1/embeddings' endpoints. For 'POST /v1/completions', enabling 'use_beam_search' and setting 'best_of' to a high value causes the HTTP connection to time out, with vllm ceasing effective work and the request remaining in a 'pending' state, blocking new completion requests. For 'POST /v1/embeddings', supplying invalid inputs to the JSON object causes an issue in the background loop, resulting in all further completion requests returning a 500 HTTP error code ('Internal Server Error') until vllm is restarted.

- [https://github.com/gothburz/CVE-2024-11040](https://github.com/gothburz/CVE-2024-11040) :  ![starts](https://img.shields.io/github/stars/gothburz/CVE-2024-11040.svg) ![forks](https://img.shields.io/github/forks/gothburz/CVE-2024-11040.svg)


## CVE-2024-9474
Cloud NGFW and Prisma Access are not impacted by this vulnerability.

- [https://github.com/experiencedt/CVE-2024-9474](https://github.com/experiencedt/CVE-2024-9474) :  ![starts](https://img.shields.io/github/stars/experiencedt/CVE-2024-9474.svg) ![forks](https://img.shields.io/github/forks/experiencedt/CVE-2024-9474.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/mistakes1337/CVE-2024-4577](https://github.com/mistakes1337/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/mistakes1337/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/mistakes1337/CVE-2024-4577.svg)


## CVE-2023-21839
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and  14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/illegalbrea/CVE-2023-21839](https://github.com/illegalbrea/CVE-2023-21839) :  ![starts](https://img.shields.io/github/stars/illegalbrea/CVE-2023-21839.svg) ![forks](https://img.shields.io/github/forks/illegalbrea/CVE-2023-21839.svg)


## CVE-2023-6241
 Use After Free vulnerability in Arm Ltd Midgard GPU Kernel Driver, Arm Ltd Bifrost GPU Kernel Driver, Arm Ltd Valhall GPU Kernel Driver, Arm Ltd Arm 5th Gen GPU Architecture Kernel Driver allows a local non-privileged user to exploit a software race condition to perform improper memory processing operations. If the system’s memory is carefully prepared by the user, then this in turn cause a use-after-free.This issue affects Midgard GPU Kernel Driver: from r13p0 through r32p0; Bifrost GPU Kernel Driver: from r11p0 through r25p0; Valhall GPU Kernel Driver: from r19p0 through r25p0, from r29p0 through r46p0; Arm 5th Gen GPU Architecture Kernel Driver: from r41p0 through r46p0.

- [https://github.com/ilGobbo00/CVE-2023-6241-Pixel7_Adaptation](https://github.com/ilGobbo00/CVE-2023-6241-Pixel7_Adaptation) :  ![starts](https://img.shields.io/github/stars/ilGobbo00/CVE-2023-6241-Pixel7_Adaptation.svg) ![forks](https://img.shields.io/github/forks/ilGobbo00/CVE-2023-6241-Pixel7_Adaptation.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/LiEnby/PSSRoot](https://github.com/LiEnby/PSSRoot) :  ![starts](https://img.shields.io/github/stars/LiEnby/PSSRoot.svg) ![forks](https://img.shields.io/github/forks/LiEnby/PSSRoot.svg)


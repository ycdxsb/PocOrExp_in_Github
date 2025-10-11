# Update 2025-10-11
## CVE-2025-60375
 The authentication mechanism in Perfex CRM before 3.3.1 allows attackers to bypass login credentials due to insufficient server-side validation. By sending empty username and password parameters in the login request, an attacker can gain unauthorized access to user accounts, including administrative accounts, without providing valid credentials.

- [https://github.com/AhamedYaseen03/CVE-2025-60375](https://github.com/AhamedYaseen03/CVE-2025-60375) :  ![starts](https://img.shields.io/github/stars/AhamedYaseen03/CVE-2025-60375.svg) ![forks](https://img.shields.io/github/forks/AhamedYaseen03/CVE-2025-60375.svg)


## CVE-2025-54135
 Cursor is a code editor built for programming with AI. Cursor allows writing in-workspace files with no user approval in versions below 1.3.9, If the file is a dotfile, editing it requires approval but creating a new one doesn't. Hence, if sensitive MCP files, such as the .cursor/mcp.json file don't already exist in the workspace, an attacker can chain a indirect prompt injection vulnerability to hijack the context to write to the settings file and trigger RCE on the victim without user approval. This is fixed in version 1.3.9.

- [https://github.com/hn1e13/test-mcp](https://github.com/hn1e13/test-mcp) :  ![starts](https://img.shields.io/github/stars/hn1e13/test-mcp.svg) ![forks](https://img.shields.io/github/forks/hn1e13/test-mcp.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/Yuri08loveElaina/CVE-2025-49844](https://github.com/Yuri08loveElaina/CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-49844.svg)
- [https://github.com/YuanBenSir/CVE-2025-49844_POC](https://github.com/YuanBenSir/CVE-2025-49844_POC) :  ![starts](https://img.shields.io/github/stars/YuanBenSir/CVE-2025-49844_POC.svg) ![forks](https://img.shields.io/github/forks/YuanBenSir/CVE-2025-49844_POC.svg)
- [https://github.com/Mufti22/CVE-2025-49844-RediShell-Vulnerability-Scanner](https://github.com/Mufti22/CVE-2025-49844-RediShell-Vulnerability-Scanner) :  ![starts](https://img.shields.io/github/stars/Mufti22/CVE-2025-49844-RediShell-Vulnerability-Scanner.svg) ![forks](https://img.shields.io/github/forks/Mufti22/CVE-2025-49844-RediShell-Vulnerability-Scanner.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/shazed-x/CVE-2025-32463](https://github.com/shazed-x/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/shazed-x/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/shazed-x/CVE-2025-32463.svg)
- [https://github.com/ricardomaia/CVE-2025-32463](https://github.com/ricardomaia/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/ricardomaia/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/ricardomaia/CVE-2025-32463.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/adjscent/vulnerable-nextjs-14-CVE-2025-29927](https://github.com/adjscent/vulnerable-nextjs-14-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/adjscent/vulnerable-nextjs-14-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/adjscent/vulnerable-nextjs-14-CVE-2025-29927.svg)
- [https://github.com/pickovven/vulnerable-nextjs-14-CVE-2025-29927](https://github.com/pickovven/vulnerable-nextjs-14-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/pickovven/vulnerable-nextjs-14-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/pickovven/vulnerable-nextjs-14-CVE-2025-29927.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/tookATE/CVE-2025-8088](https://github.com/tookATE/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/tookATE/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/tookATE/CVE-2025-8088.svg)


## CVE-2025-6131
 A vulnerability, which was classified as problematic, was found in CodeAstro Food Ordering System 1.0. Affected is an unknown function of the file /admin/store/edit/ of the component POST Request Parameter Handler. The manipulation of the argument Restaurant Name/Address leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/AmalJafarzade/CVE-2025-61319](https://github.com/AmalJafarzade/CVE-2025-61319) :  ![starts](https://img.shields.io/github/stars/AmalJafarzade/CVE-2025-61319.svg) ![forks](https://img.shields.io/github/forks/AmalJafarzade/CVE-2025-61319.svg)


## CVE-2025-6037
 Vault and Vault Enterprise (“Vault”) TLS certificate auth method did not correctly validate client certificates when configured with a non-CA certificate as [+trusted certificate+|https://developer.hashicorp.com/vault/api-docs/auth/cert#certificate]. In this configuration, an attacker may be able to craft a malicious certificate that could be used to impersonate another user. Fixed in Vault Community Edition 1.20.1 and Vault Enterprise 1.20.1, 1.19.7, 1.18.12, and 1.16.23.

- [https://github.com/ajansha/CVE-2025-60378](https://github.com/ajansha/CVE-2025-60378) :  ![starts](https://img.shields.io/github/stars/ajansha/CVE-2025-60378.svg) ![forks](https://img.shields.io/github/forks/ajansha/CVE-2025-60378.svg)


## CVE-2025-5590
 The Owl carousel responsive plugin for WordPress is vulnerable to time-based SQL Injection via the ‘id’ parameter in all versions up to, and including, 1.9 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for authenticated attackers, with Contributor-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/ajansha/CVE-2025-55903](https://github.com/ajansha/CVE-2025-55903) :  ![starts](https://img.shields.io/github/stars/ajansha/CVE-2025-55903.svg) ![forks](https://img.shields.io/github/forks/ajansha/CVE-2025-55903.svg)


## CVE-2025-4614
Cloud NGFW and Prisma® Access are not affected by this vulnerability.

- [https://github.com/AugustusSploits/CVE-2025-46142](https://github.com/AugustusSploits/CVE-2025-46142) :  ![starts](https://img.shields.io/github/stars/AugustusSploits/CVE-2025-46142.svg) ![forks](https://img.shields.io/github/forks/AugustusSploits/CVE-2025-46142.svg)


## CVE-2025-4476
 A denial-of-service vulnerability has been identified in the libsoup HTTP client library. This flaw can be triggered when a libsoup client receives a 401 (Unauthorized) HTTP response containing a specifically crafted domain parameter within the WWW-Authenticate header. Processing this malformed header can lead to a crash of the client application using libsoup. An attacker could exploit this by setting up a malicious HTTP server. If a user's application using the vulnerable libsoup library connects to this malicious server, it could result in a denial-of-service. Successful exploitation requires tricking a user's client application into connecting to the attacker's malicious server.

- [https://github.com/soltanali0/CVE-2025-4476-Exploit](https://github.com/soltanali0/CVE-2025-4476-Exploit) :  ![starts](https://img.shields.io/github/stars/soltanali0/CVE-2025-4476-Exploit.svg) ![forks](https://img.shields.io/github/forks/soltanali0/CVE-2025-4476-Exploit.svg)


## CVE-2024-38856
Unauthenticated endpoints could allow execution of screen rendering code of screens if some preconditions are met (such as when the screen definitions don't explicitly check user's permissions because they rely on the configuration of their endpoints).

- [https://github.com/Hex00-0x4/CVE-2024-38856-Apache-OFBiz](https://github.com/Hex00-0x4/CVE-2024-38856-Apache-OFBiz) :  ![starts](https://img.shields.io/github/stars/Hex00-0x4/CVE-2024-38856-Apache-OFBiz.svg) ![forks](https://img.shields.io/github/forks/Hex00-0x4/CVE-2024-38856-Apache-OFBiz.svg)


## CVE-2024-32113
Users are recommended to upgrade to version 18.12.13, which fixes the issue.

- [https://github.com/luizgaf/CVE-2024-32113-Exploit](https://github.com/luizgaf/CVE-2024-32113-Exploit) :  ![starts](https://img.shields.io/github/stars/luizgaf/CVE-2024-32113-Exploit.svg) ![forks](https://img.shields.io/github/forks/luizgaf/CVE-2024-32113-Exploit.svg)


## CVE-2024-0044
 In createSessionInternal of PackageInstallerService.java, there is a possible run-as any app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/l1ackerronin/CVE-2024-0044](https://github.com/l1ackerronin/CVE-2024-0044) :  ![starts](https://img.shields.io/github/stars/l1ackerronin/CVE-2024-0044.svg) ![forks](https://img.shields.io/github/forks/l1ackerronin/CVE-2024-0044.svg)


## CVE-2023-50164
Users are recommended to upgrade to versions Struts 2.5.33 or Struts 6.3.0.2 or greater to fix this issue.

- [https://github.com/hybinn/CVE-2023-50164](https://github.com/hybinn/CVE-2023-50164) :  ![starts](https://img.shields.io/github/stars/hybinn/CVE-2023-50164.svg) ![forks](https://img.shields.io/github/forks/hybinn/CVE-2023-50164.svg)


## CVE-2023-42793
 In JetBrains TeamCity before 2023.05.4 authentication bypass leading to RCE on TeamCity Server was possible

- [https://github.com/syorik/CVE-2023-42793](https://github.com/syorik/CVE-2023-42793) :  ![starts](https://img.shields.io/github/stars/syorik/CVE-2023-42793.svg) ![forks](https://img.shields.io/github/forks/syorik/CVE-2023-42793.svg)


## CVE-2023-21554
 Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability

- [https://github.com/shootweb/CVE-2023-21554](https://github.com/shootweb/CVE-2023-21554) :  ![starts](https://img.shields.io/github/stars/shootweb/CVE-2023-21554.svg) ![forks](https://img.shields.io/github/forks/shootweb/CVE-2023-21554.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/Enceka/cve-2019-2215-3.18](https://github.com/Enceka/cve-2019-2215-3.18) :  ![starts](https://img.shields.io/github/stars/Enceka/cve-2019-2215-3.18.svg) ![forks](https://img.shields.io/github/forks/Enceka/cve-2019-2215-3.18.svg)


## CVE-2017-10412
 Vulnerability in the Oracle Knowledge Management component of Oracle E-Business Suite (subcomponent: User Interface). Supported versions that are affected are 12.1.1, 12.1.2, 12.1.3, 12.2.3, 12.2.4, 12.2.5, 12.2.6 and 12.2.7. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Knowledge Management. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Knowledge Management, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle Knowledge Management accessible data as well as unauthorized update, insert or delete access to some of Oracle Knowledge Management accessible data. CVSS 3.0 Base Score 8.2 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N).

- [https://github.com/vah13/OracleCVE](https://github.com/vah13/OracleCVE) :  ![starts](https://img.shields.io/github/stars/vah13/OracleCVE.svg) ![forks](https://img.shields.io/github/forks/vah13/OracleCVE.svg)


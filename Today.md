# Update 2026-10-13
## CVE-2026-107406
  *  NetScaler ADC 13.1-FIPS before13.1-NDcPP 13.1-37.279

- [https://github.com/ctroy999/CVE-2026-107406](https://github.com/ctroy999/CVE-2026-107406) :  ![starts](https://img.shields.io/github/stars/ctroy999/CVE-2026-107406.svg) ![forks](https://img.shields.io/github/forks/ctroy999/CVE-2026-107406.svg)


## CVE-2026-105306
 A flaw was found in the Dynamic Client Registration flow of the Keycloak identity and access management server. The issue occurs because the registration process fails to filter security-sensitive client attributes when a new client is created. An attacker with a valid Initial Access Token can register a client that bypasses audience checks during token introspection. This allows the attacker to view sensitive identity information, roles, and session details from access tokens belonging to other applications in the same realm.

- [https://github.com/Dungsocool/CVE-2026-105306](https://github.com/Dungsocool/CVE-2026-105306) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2026-105306.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2026-105306.svg)


## CVE-2026-104335
 IBM Langflow OSS 1.0.0 through 1.12.2 could allow a remote authenticated attacker to execute arbitrary code due to improper access control.

- [https://github.com/Farih123/CVE-2026-104335](https://github.com/Farih123/CVE-2026-104335) :  ![starts](https://img.shields.io/github/stars/Farih123/CVE-2026-104335.svg) ![forks](https://img.shields.io/github/forks/Farih123/CVE-2026-104335.svg)


## CVE-2026-104286
 An improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiMail 8.0.0 through 8.0.1, FortiMail 7.6.0 through 7.6.6, FortiMail 7.4.0 through 7.4.8, FortiMail 7.2.0 through 7.2.9 may allow an unauthenticated attacker to write arbitrary files on the underlying system via crafted HTTP or HTTPS requests.

- [https://github.com/0xREBYTE/CVE-2026-104286-PoC](https://github.com/0xREBYTE/CVE-2026-104286-PoC) :  ![starts](https://img.shields.io/github/stars/0xREBYTE/CVE-2026-104286-PoC.svg) ![forks](https://img.shields.io/github/forks/0xREBYTE/CVE-2026-104286-PoC.svg)


## CVE-2026-102489
 Zammad versions 6.3.0 to 6.5.4 are vulnerable a session hijack vulnerability that leads to remote code execution as the zammad user. The bug is also present in version 7.0.0 to version 7.1.2, but not exploitable due to changes in the underlying framework.

- [https://github.com/1xPwn/CVE-2026-102489](https://github.com/1xPwn/CVE-2026-102489) :  ![starts](https://img.shields.io/github/stars/1xPwn/CVE-2026-102489.svg) ![forks](https://img.shields.io/github/forks/1xPwn/CVE-2026-102489.svg)


## CVE-2026-72898
 Metabase allows a remote, unauthenticated attacker to inject arbitrary SQL via the '/reset_password' database endpoint and gain administrator access to the connected Metabase instance.

- [https://github.com/Riftweld/metabase-cve-2026-72898](https://github.com/Riftweld/metabase-cve-2026-72898) :  ![starts](https://img.shields.io/github/stars/Riftweld/metabase-cve-2026-72898.svg) ![forks](https://img.shields.io/github/forks/Riftweld/metabase-cve-2026-72898.svg)


## CVE-2026-43805
 A race condition was addressed with improved state handling. This issue is fixed in iOS 26.6 and iPadOS 26.6, macOS Sequoia 15.7.8, macOS Sonoma 14.8.8, macOS Tahoe 26.6, watchOS 26.6. An app may be able to cause unexpected system termination or write kernel memory.

- [https://github.com/whysocscs/CVE-2026-43805](https://github.com/whysocscs/CVE-2026-43805) :  ![starts](https://img.shields.io/github/stars/whysocscs/CVE-2026-43805.svg) ![forks](https://img.shields.io/github/forks/whysocscs/CVE-2026-43805.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/ctn-Qvo/CVE-2026-43499-so-build](https://github.com/ctn-Qvo/CVE-2026-43499-so-build) :  ![starts](https://img.shields.io/github/stars/ctn-Qvo/CVE-2026-43499-so-build.svg) ![forks](https://img.shields.io/github/forks/ctn-Qvo/CVE-2026-43499-so-build.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/rune42/ElasticRift](https://github.com/rune42/ElasticRift) :  ![starts](https://img.shields.io/github/stars/rune42/ElasticRift.svg) ![forks](https://img.shields.io/github/forks/rune42/ElasticRift.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/sakidekin/CVE-2026-41940-PoC](https://github.com/sakidekin/CVE-2026-41940-PoC) :  ![starts](https://img.shields.io/github/stars/sakidekin/CVE-2026-41940-PoC.svg) ![forks](https://img.shields.io/github/forks/sakidekin/CVE-2026-41940-PoC.svg)


## CVE-2026-40224
 In systemd 259 before 260, there is local privilege escalation in systemd-machined because varlink can be used to reach the root namespace.

- [https://github.com/0xparad0x/Exploit-CVE-2026-40224](https://github.com/0xparad0x/Exploit-CVE-2026-40224) :  ![starts](https://img.shields.io/github/stars/0xparad0x/Exploit-CVE-2026-40224.svg) ![forks](https://img.shields.io/github/forks/0xparad0x/Exploit-CVE-2026-40224.svg)


## CVE-2026-38812
 RuoYi v4.8.2 is vulnerable to SQL Injection via the /tool/gen/createTable endpoint. The issue affects the code generation module and may allow an authenticated attacker with administrative privileges to access sensitive database information.

- [https://github.com/YYF1337/RuoYi-CVE-2026-38812-UNFIX](https://github.com/YYF1337/RuoYi-CVE-2026-38812-UNFIX) :  ![starts](https://img.shields.io/github/stars/YYF1337/RuoYi-CVE-2026-38812-UNFIX.svg) ![forks](https://img.shields.io/github/forks/YYF1337/RuoYi-CVE-2026-38812-UNFIX.svg)


## CVE-2026-29000
 pac4j-jwt versions prior to 4.5.9, 5.7.9, and 6.3.3 contain an authentication bypass vulnerability in JwtAuthenticator when processing encrypted JWTs that allows remote attackers to forge authentication tokens. Attackers who possess the server's RSA public key can create a JWE-wrapped PlainJWT with arbitrary subject and role claims, bypassing signature verification to authenticate as any user including administrators.

- [https://github.com/Erikgavs/CVE-2026-29000](https://github.com/Erikgavs/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/Erikgavs/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/Erikgavs/CVE-2026-29000.svg)


## CVE-2026-27626
 OliveTin gives access to predefined shell commands from a web interface. In versions up to and including 3000.10.0, OliveTin's shell mode safety check (`checkShellArgumentSafety`) blocks several dangerous argument types but not `password`. A user supplying a `password`-typed argument can inject shell metacharacters that execute arbitrary OS commands. A second independent vector allows unauthenticated RCE via webhook-extracted JSON values that skip type safety checks entirely before reaching `sh -c`. When exploiting vector 1, any authenticated user (registration enabled by default, `authType: none` by default) can execute arbitrary OS commands on the OliveTin host with the permissions of the OliveTin process. When exploiting vector 2, an unauthenticated attacker can achieve the same if the instance receives webhooks from external sources, which is a primary OliveTin use case. When an attacker exploits both vectors, this results in unauthenticated RCE on any OliveTin instance using Shell mode with webhook-triggered actions. As of time of publication, a patched version is not available.

- [https://github.com/Shisones/CVE-2026-27626](https://github.com/Shisones/CVE-2026-27626) :  ![starts](https://img.shields.io/github/stars/Shisones/CVE-2026-27626.svg) ![forks](https://img.shields.io/github/forks/Shisones/CVE-2026-27626.svg)


## CVE-2026-15748
 The Forminator Forms plugin for WordPress is vulnerable to Arbitrary File Upload in all versions up to, and including, 1.56.1 via the handle_file_upload function. This is due to insufficient file type validation in handle_file_upload, where the dangerous-extension blocklist performs exact-key matching that is bypassed by pipe-alternative MIME type keys, combined with a public submission handler that trusts attacker-controlled upload field configuration injected via a forged Select field value. This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.

- [https://github.com/0x4cr/CVE-2026-15748](https://github.com/0x4cr/CVE-2026-15748) :  ![starts](https://img.shields.io/github/stars/0x4cr/CVE-2026-15748.svg) ![forks](https://img.shields.io/github/forks/0x4cr/CVE-2026-15748.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/fusiondrive/CVE-2026-43499-A36](https://github.com/fusiondrive/CVE-2026-43499-A36) :  ![starts](https://img.shields.io/github/stars/fusiondrive/CVE-2026-43499-A36.svg) ![forks](https://img.shields.io/github/forks/fusiondrive/CVE-2026-43499-A36.svg)
- [https://github.com/villager1314/CVE-2026-43499-Analysis](https://github.com/villager1314/CVE-2026-43499-Analysis) :  ![starts](https://img.shields.io/github/stars/villager1314/CVE-2026-43499-Analysis.svg) ![forks](https://img.shields.io/github/forks/villager1314/CVE-2026-43499-Analysis.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/Wayang1337/CVE-2025-57819](https://github.com/Wayang1337/CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/Wayang1337/CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/Wayang1337/CVE-2025-57819.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC](https://github.com/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/pkrasulia/CVE-2025-55182-NextJS-RCE-PoC.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/toyplan/cve-2025-24813](https://github.com/toyplan/cve-2025-24813) :  ![starts](https://img.shields.io/github/stars/toyplan/cve-2025-24813.svg) ![forks](https://img.shields.io/github/forks/toyplan/cve-2025-24813.svg)


## CVE-2025-20730
 In preloader, there is a possible escalation of privilege due to an insecure default value. This could lead to local escalation of privilege if a malicious actor has already obtained the System privilege. User interaction is not needed for exploitation. Patch ID: ALPS10068463; Issue ID: MSV-4141.

- [https://github.com/ELF-RC/mtk_logo_toolkit](https://github.com/ELF-RC/mtk_logo_toolkit) :  ![starts](https://img.shields.io/github/stars/ELF-RC/mtk_logo_toolkit.svg) ![forks](https://img.shields.io/github/forks/ELF-RC/mtk_logo_toolkit.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-5518
This issue affects BILGER: before 2.4.6.

- [https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182](https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg)


## CVE-2023-5536
 A feature in LXD (LP#1829071), affects the default configuration of Ubuntu Server which allows privileged users in the lxd group to escalate their privilege to root without requiring a sudo password.

- [https://github.com/karthikparambil/lxd2root](https://github.com/karthikparambil/lxd2root) :  ![starts](https://img.shields.io/github/stars/karthikparambil/lxd2root.svg) ![forks](https://img.shields.io/github/forks/karthikparambil/lxd2root.svg)


# Update 2026-08-18
## CVE-2026-73678
 MindsDB Minds Platform version 26.1.0 and earlier contains an unauthenticated remote code execution vulnerability that allows unauthenticated attackers to execute arbitrary OS commands by submitting crafted prompts to the unprotected POST /api/v1/responses/ endpoint, which reaches the Anton agent's scratchpad tool that calls exec() on attacker-influenced Python source without sandboxing. Attackers can first configure their own LLM API key through the unauthenticated PUT /api/v1/settings/ endpoint, then POST a prompt directing the agent to invoke the scratchpad tool with arbitrary Python code, achieving full OS command execution as the user running the desktop application and enabling access to SSH keys, stored credentials, and environment secrets.

- [https://github.com/Boreas37/CVE-2026-73678-PoC](https://github.com/Boreas37/CVE-2026-73678-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-73678-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-73678-PoC.svg)


## CVE-2026-73633
Users are recommended to upgrade to version 6.11.0 or 7.3.0, which fixes the issue.

- [https://github.com/CuteeCat/CVE-2026-73633](https://github.com/CuteeCat/CVE-2026-73633) :  ![starts](https://img.shields.io/github/stars/CuteeCat/CVE-2026-73633.svg) ![forks](https://img.shields.io/github/forks/CuteeCat/CVE-2026-73633.svg)


## CVE-2026-72898
 Metabase allows a remote, unauthenticated attacker to inject arbitrary SQL via the '/reset_password' database endpoint and gain administrator access to the connected Metabase instance.

- [https://github.com/Franc-Zar/CVE-2026-72898-safe-detection](https://github.com/Franc-Zar/CVE-2026-72898-safe-detection) :  ![starts](https://img.shields.io/github/stars/Franc-Zar/CVE-2026-72898-safe-detection.svg) ![forks](https://img.shields.io/github/forks/Franc-Zar/CVE-2026-72898-safe-detection.svg)


## CVE-2026-72585
 An authorization bypass vulnerability in Grafana through 13.2.0 allows an Editor-role user to delete protected contact points (receivers) without the required alert.notifications.receivers.protected:write permission.

- [https://github.com/Nel-droid/CVE-2026-72585-PoC](https://github.com/Nel-droid/CVE-2026-72585-PoC) :  ![starts](https://img.shields.io/github/stars/Nel-droid/CVE-2026-72585-PoC.svg) ![forks](https://img.shields.io/github/forks/Nel-droid/CVE-2026-72585-PoC.svg)


## CVE-2026-71206
 Shiori's CheckToken function (internal/domains/auth.go) validates only the JWT's HMAC signature and returns the embedded claims.Account object unmodified, never re-fetching the account from the database. No session store or token-revocation mechanism exists in the codebase.

- [https://github.com/Nel-droid/CVE-2026-71206-PoC](https://github.com/Nel-droid/CVE-2026-71206-PoC) :  ![starts](https://img.shields.io/github/stars/Nel-droid/CVE-2026-71206-PoC.svg) ![forks](https://img.shields.io/github/forks/Nel-droid/CVE-2026-71206-PoC.svg)


## CVE-2026-71205
 changedetection.io's /login route checks the submitted password against a single PBKDF2-HMAC-SHA256 hash with no per-IP or per-session rate limiting, failed-attempt counter, or lockout (no rate-limiting library is present in requirements.txt).

- [https://github.com/Nel-droid/CVE-2026-71205-PoC](https://github.com/Nel-droid/CVE-2026-71205-PoC) :  ![starts](https://img.shields.io/github/stars/Nel-droid/CVE-2026-71205-PoC.svg) ![forks](https://img.shields.io/github/forks/Nel-droid/CVE-2026-71205-PoC.svg)


## CVE-2026-71204
 changedetection.io's /settings save handler builds an update dict from form.data['application'] and blind-merges it into the stored application settings via .update.

- [https://github.com/Nel-droid/CVE-2026-71204-PoC](https://github.com/Nel-droid/CVE-2026-71204-PoC) :  ![starts](https://img.shields.io/github/stars/Nel-droid/CVE-2026-71204-PoC.svg) ![forks](https://img.shields.io/github/forks/Nel-droid/CVE-2026-71204-PoC.svg)


## CVE-2026-71203
 changedetection.io's REST API resources are protected by an @auth.check_token decorator validating the caller's x-api-key header, except the Spec resource registered at /api/v1/full-spec (changedetectionio/api/Spec.py), whose get method carries neither @auth.check_token nor @validate_openapi_request.

- [https://github.com/Nel-droid/CVE-2026-71203-PoC](https://github.com/Nel-droid/CVE-2026-71203-PoC) :  ![starts](https://img.shields.io/github/stars/Nel-droid/CVE-2026-71203-PoC.svg) ![forks](https://img.shields.io/github/forks/Nel-droid/CVE-2026-71203-PoC.svg)


## CVE-2026-64638
Discovered and responsibly disclosed by [the team at pwn.ai](https://pwn.ai/).

- [https://github.com/SanaullahAmanullah/xss2shell-check](https://github.com/SanaullahAmanullah/xss2shell-check) :  ![starts](https://img.shields.io/github/stars/SanaullahAmanullah/xss2shell-check.svg) ![forks](https://img.shields.io/github/forks/SanaullahAmanullah/xss2shell-check.svg)


## CVE-2026-50656
 Microsoft is aware of an elevation of privilege in the Microsoft Malware Protection Engine in Microsoft Defender publicly referred to as &quot;RoguePlanet &quot;.

- [https://github.com/eh-amish/Windows-Defender-Security-Auditor-CVE-2026-50656-](https://github.com/eh-amish/Windows-Defender-Security-Auditor-CVE-2026-50656-) :  ![starts](https://img.shields.io/github/stars/eh-amish/Windows-Defender-Security-Auditor-CVE-2026-50656-.svg) ![forks](https://img.shields.io/github/forks/eh-amish/Windows-Defender-Security-Auditor-CVE-2026-50656-.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/NanoTurtle1145/root-my-s9280](https://github.com/NanoTurtle1145/root-my-s9280) :  ![starts](https://img.shields.io/github/stars/NanoTurtle1145/root-my-s9280.svg) ![forks](https://img.shields.io/github/forks/NanoTurtle1145/root-my-s9280.svg)


## CVE-2026-26119
 Improper authentication in Windows Admin Center allows an authorized attacker to elevate privileges over a network.

- [https://github.com/abdelaaziz0/WACJack](https://github.com/abdelaaziz0/WACJack) :  ![starts](https://img.shields.io/github/stars/abdelaaziz0/WACJack.svg) ![forks](https://img.shields.io/github/forks/abdelaaziz0/WACJack.svg)


## CVE-2026-18366
 The Events Manager  WordPress plugin before 7.4.1 does not properly scope its capability mapping, discarding the access control decisions WordPress already made for unrelated privileged actions, which allows unauthenticated users to change the password of, escalate to Administrator, or delete any account whose user ID happens to match the ID of one of the Events Manager  WordPress plugin before 7.4.1's own posts.

- [https://github.com/Nxploited/CVE-2026-18366](https://github.com/Nxploited/CVE-2026-18366) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-18366.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-18366.svg)


## CVE-2026-8508
 An improper authentication vulnerability in the "social_login.cgi" CGI program in Zyxel WAX650S firmware versions through 7.10(ABRM.4)C0 could allow an attacker on the WLAN to bypass captive portal authentication.

- [https://github.com/minanagehsalalma/zyxel-social-login-bypass-cve-2026-8508](https://github.com/minanagehsalalma/zyxel-social-login-bypass-cve-2026-8508) :  ![starts](https://img.shields.io/github/stars/minanagehsalalma/zyxel-social-login-bypass-cve-2026-8508.svg) ![forks](https://img.shields.io/github/forks/minanagehsalalma/zyxel-social-login-bypass-cve-2026-8508.svg)


## CVE-2026-6837
 A post-authentication command injection vulnerability in the "export-cgi" CGI program in Zyxel WAX650S firmware versions through 7.10(ABRM.4)C0 could allow an authenticated attacker with administrator privileges to execute OS commands on an affected device.

- [https://github.com/minanagehsalalma/CVE-2026-6837-zyxel-export-cgi-command-injection](https://github.com/minanagehsalalma/CVE-2026-6837-zyxel-export-cgi-command-injection) :  ![starts](https://img.shields.io/github/stars/minanagehsalalma/CVE-2026-6837-zyxel-export-cgi-command-injection.svg) ![forks](https://img.shields.io/github/forks/minanagehsalalma/CVE-2026-6837-zyxel-export-cgi-command-injection.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)


## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/aleewyy/CVE-2025-49132](https://github.com/aleewyy/CVE-2025-49132) :  ![starts](https://img.shields.io/github/stars/aleewyy/CVE-2025-49132.svg) ![forks](https://img.shields.io/github/forks/aleewyy/CVE-2025-49132.svg)


## CVE-2025-11740
 The wpForo Forum plugin for WordPress is vulnerable to SQL Injection via the Subscriptions Manager in all versions up to, and including, 2.4.9 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for authenticated attackers, with Subscriber-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/Alixploit22/CVE-2025-11740](https://github.com/Alixploit22/CVE-2025-11740) :  ![starts](https://img.shields.io/github/stars/Alixploit22/CVE-2025-11740.svg) ![forks](https://img.shields.io/github/forks/Alixploit22/CVE-2025-11740.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)


## CVE-2023-4863
 Heap buffer overflow in libwebp in Google Chrome prior to 116.0.5845.187 and libwebp 1.3.2 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/jpsbern/CVE-2023-4863](https://github.com/jpsbern/CVE-2023-4863) :  ![starts](https://img.shields.io/github/stars/jpsbern/CVE-2023-4863.svg) ![forks](https://img.shields.io/github/forks/jpsbern/CVE-2023-4863.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/Park123r/CVE-2021-41773](https://github.com/Park123r/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Park123r/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Park123r/CVE-2021-41773.svg)
- [https://github.com/gunzf0x/CVE-2021-41773](https://github.com/gunzf0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2021-41773.svg)


## CVE-2018-8611
 An elevation of privilege vulnerability exists when the Windows kernel fails to properly handle objects in memory, aka "Windows Kernel Elevation of Privilege Vulnerability." This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2019, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers.

- [https://github.com/ahm3dgg/cve-2018-8611](https://github.com/ahm3dgg/cve-2018-8611) :  ![starts](https://img.shields.io/github/stars/ahm3dgg/cve-2018-8611.svg) ![forks](https://img.shields.io/github/forks/ahm3dgg/cve-2018-8611.svg)


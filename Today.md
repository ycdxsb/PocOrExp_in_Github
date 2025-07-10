# Update 2025-07-10
## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/0xtensho/CVE-2025-49132-poc](https://github.com/0xtensho/CVE-2025-49132-poc) :  ![starts](https://img.shields.io/github/stars/0xtensho/CVE-2025-49132-poc.svg) ![forks](https://img.shields.io/github/forks/0xtensho/CVE-2025-49132-poc.svg)


## CVE-2025-48903
Impact: Successful exploitation of this vulnerability may affect availability.

- [https://github.com/susancodes55/CVE-2025-48903-discord-poc](https://github.com/susancodes55/CVE-2025-48903-discord-poc) :  ![starts](https://img.shields.io/github/stars/susancodes55/CVE-2025-48903-discord-poc.svg) ![forks](https://img.shields.io/github/forks/susancodes55/CVE-2025-48903-discord-poc.svg)


## CVE-2025-48799
 Improper link resolution before file access ('link following') in Windows Update Service allows an authorized attacker to elevate privileges locally.

- [https://github.com/Wh04m1001/CVE-2025-48799](https://github.com/Wh04m1001/CVE-2025-48799) :  ![starts](https://img.shields.io/github/stars/Wh04m1001/CVE-2025-48799.svg) ![forks](https://img.shields.io/github/forks/Wh04m1001/CVE-2025-48799.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/acheong08/CVE-2025-48384](https://github.com/acheong08/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/acheong08/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/acheong08/CVE-2025-48384.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/susancodes55/CVE-2025-32463-sudo-poc](https://github.com/susancodes55/CVE-2025-32463-sudo-poc) :  ![starts](https://img.shields.io/github/stars/susancodes55/CVE-2025-32463-sudo-poc.svg) ![forks](https://img.shields.io/github/forks/susancodes55/CVE-2025-32463-sudo-poc.svg)
- [https://github.com/SpongeBob-369/cve-2025-32463](https://github.com/SpongeBob-369/cve-2025-32463) :  ![starts](https://img.shields.io/github/stars/SpongeBob-369/cve-2025-32463.svg) ![forks](https://img.shields.io/github/forks/SpongeBob-369/cve-2025-32463.svg)
- [https://github.com/lowercasenumbers/CVE-2025-32463_sudo_chroot](https://github.com/lowercasenumbers/CVE-2025-32463_sudo_chroot) :  ![starts](https://img.shields.io/github/stars/lowercasenumbers/CVE-2025-32463_sudo_chroot.svg) ![forks](https://img.shields.io/github/forks/lowercasenumbers/CVE-2025-32463_sudo_chroot.svg)
- [https://github.com/abrewer251/CVE-2025-32463_Sudo_PoC](https://github.com/abrewer251/CVE-2025-32463_Sudo_PoC) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2025-32463_Sudo_PoC.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2025-32463_Sudo_PoC.svg)


## CVE-2025-20682
 In wlan AP driver, there is a possible out of bounds write due to an incorrect bounds check. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation. Patch ID: WCNCR00416937; Issue ID: MSV-3445.

- [https://github.com/Caztemaz/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk](https://github.com/Caztemaz/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk) :  ![starts](https://img.shields.io/github/stars/Caztemaz/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk.svg) ![forks](https://img.shields.io/github/forks/Caztemaz/Phantom-Registy-Exploit-Cve2025-20682-Runtime-Fud-Lnk.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/win3zz/CVE-2025-5777](https://github.com/win3zz/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/win3zz/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/win3zz/CVE-2025-5777.svg)
- [https://github.com/Chocapikk/CVE-2025-5777](https://github.com/Chocapikk/CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2025-5777.svg)


## CVE-2025-4866
 A vulnerability was found in weibocom rill-flow 0.1.18. It has been classified as critical. Affected is an unknown function of the component Management Console. The manipulation leads to code injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/bloodcode-spasov/ble-cve2025-attack-new-version](https://github.com/bloodcode-spasov/ble-cve2025-attack-new-version) :  ![starts](https://img.shields.io/github/stars/bloodcode-spasov/ble-cve2025-attack-new-version.svg) ![forks](https://img.shields.io/github/forks/bloodcode-spasov/ble-cve2025-attack-new-version.svg)


## CVE-2025-4562
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

- [https://github.com/weedl/CVE-2025-45620](https://github.com/weedl/CVE-2025-45620) :  ![starts](https://img.shields.io/github/stars/weedl/CVE-2025-45620.svg) ![forks](https://img.shields.io/github/forks/weedl/CVE-2025-45620.svg)


## CVE-2025-4561
 The KFOX from KingFor has an Arbitrary File Upload vulnerability, allowing remote attackers with regular privilege to upload and execute web shell backdoors, thereby enabling arbitrary code execution on the server.

- [https://github.com/weedl/CVE-2025-45619](https://github.com/weedl/CVE-2025-45619) :  ![starts](https://img.shields.io/github/stars/weedl/CVE-2025-45619.svg) ![forks](https://img.shields.io/github/forks/weedl/CVE-2025-45619.svg)


## CVE-2025-2945
This issue affects pgAdmin 4: before 9.2.

- [https://github.com/abrewer251/CVE-2025-2945_PgAdmin_PoC](https://github.com/abrewer251/CVE-2025-2945_PgAdmin_PoC) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2025-2945_PgAdmin_PoC.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2025-2945_PgAdmin_PoC.svg)


## CVE-2024-9014
 pgAdmin versions 8.11 and earlier are vulnerable to a security flaw in OAuth2 authentication. This vulnerability allows an attacker to potentially obtain the client ID and secret, leading to unauthorized access to user data.

- [https://github.com/r0otk3r/CVE-2024-9014](https://github.com/r0otk3r/CVE-2024-9014) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2024-9014.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2024-9014.svg)


## CVE-2024-7954
 The porte_plume plugin used by SPIP before 4.30-alpha2, 4.2.13, and 4.1.16 is vulnerable to an arbitrary code execution vulnerability. A remote and unauthenticated attacker can execute arbitrary PHP as the SPIP user by sending a crafted HTTP request.

- [https://github.com/r0otk3r/CVE-2024-7954](https://github.com/r0otk3r/CVE-2024-7954) :  ![starts](https://img.shields.io/github/stars/r0otk3r/CVE-2024-7954.svg) ![forks](https://img.shields.io/github/forks/r0otk3r/CVE-2024-7954.svg)


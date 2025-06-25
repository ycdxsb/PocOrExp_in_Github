# Update 2025-06-25
## CVE-2025-49132
 Pterodactyl is a free, open-source game server management panel. Prior to version 1.11.11, using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated. With the ability to execute arbitrary code it could be used to gain access to the Panel's server, read credentials from the Panel's config, extract sensitive information from the database, access files of servers managed by the panel, etc. This issue has been patched in version 1.11.11. There are no software workarounds for this vulnerability, but use of an external Web Application Firewall (WAF) could help mitigate this attack.

- [https://github.com/qiaojojo/CVE-2025-49132_poc](https://github.com/qiaojojo/CVE-2025-49132_poc) :  ![starts](https://img.shields.io/github/stars/qiaojojo/CVE-2025-49132_poc.svg) ![forks](https://img.shields.io/github/forks/qiaojojo/CVE-2025-49132_poc.svg)


## CVE-2025-48988
Users are recommended to upgrade to version 11.0.8, 10.1.42 or 9.0.106, which fix the issue.

- [https://github.com/nankuo/CVE-2025-48976_CVE-2025-48988](https://github.com/nankuo/CVE-2025-48976_CVE-2025-48988) :  ![starts](https://img.shields.io/github/stars/nankuo/CVE-2025-48976_CVE-2025-48988.svg) ![forks](https://img.shields.io/github/forks/nankuo/CVE-2025-48976_CVE-2025-48988.svg)


## CVE-2025-48976
Users are recommended to upgrade to versions 1.6 or 2.0.0-M4, which fix the issue.

- [https://github.com/nankuo/CVE-2025-48976_CVE-2025-48988](https://github.com/nankuo/CVE-2025-48976_CVE-2025-48988) :  ![starts](https://img.shields.io/github/stars/nankuo/CVE-2025-48976_CVE-2025-48988.svg) ![forks](https://img.shields.io/github/forks/nankuo/CVE-2025-48976_CVE-2025-48988.svg)


## CVE-2025-26466
 A flaw was found in the OpenSSH package. For each ping packet the SSH server receives, a pong packet is allocated in a memory buffer and stored in a queue of packages. It is only freed when the server/client key exchange has finished. A malicious client may keep sending such packages, leading to an uncontrolled increase in memory consumption on the server side. Consequently, the server may become unavailable, resulting in a denial of service attack.

- [https://github.com/mrowkoob/CVE-2025-26466-msf](https://github.com/mrowkoob/CVE-2025-26466-msf) :  ![starts](https://img.shields.io/github/stars/mrowkoob/CVE-2025-26466-msf.svg) ![forks](https://img.shields.io/github/forks/mrowkoob/CVE-2025-26466-msf.svg)


## CVE-2025-4571
 The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to unauthorized view and modification of data due to an insufficient capability check on the permissionsCheck functions in all versions up to, and including, 4.3.0. This makes it possible for authenticated attackers, with Contributor-level access and above, to view or delete fundraising campaigns, view donors' data, modify campaign events, etc.

- [https://github.com/partywavesec/CVE-2025-45710](https://github.com/partywavesec/CVE-2025-45710) :  ![starts](https://img.shields.io/github/stars/partywavesec/CVE-2025-45710.svg) ![forks](https://img.shields.io/github/forks/partywavesec/CVE-2025-45710.svg)


## CVE-2025-4322
 The Motors theme for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 5.6.67. This is due to the theme not properly validating a user's identity prior to updating their password. This makes it possible for unauthenticated attackers to change arbitrary user passwords, including those of administrators, and leverage that to gain access to their account.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-4322](https://github.com/B1ack4sh/Blackash-CVE-2025-4322) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-4322.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-4322.svg)


## CVE-2025-3248
code.

- [https://github.com/0-d3y/langflow-rce-exploit](https://github.com/0-d3y/langflow-rce-exploit) :  ![starts](https://img.shields.io/github/stars/0-d3y/langflow-rce-exploit.svg) ![forks](https://img.shields.io/github/forks/0-d3y/langflow-rce-exploit.svg)
- [https://github.com/dennisec/Mass-CVE-2025-3248](https://github.com/dennisec/Mass-CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/dennisec/Mass-CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/dennisec/Mass-CVE-2025-3248.svg)
- [https://github.com/dennisec/CVE-2025-3248](https://github.com/dennisec/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/dennisec/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/dennisec/CVE-2025-3248.svg)


## CVE-2025-1094
 Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to achieve SQL injection in certain usage patterns.  Specifically, SQL injection requires the application to use the function result to construct input to psql, the PostgreSQL interactive terminal.  Similarly, improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source of command line arguments to achieve SQL injection when client_encoding is BIG5 and server_encoding is one of EUC_TW or MULE_INTERNAL.  Versions before PostgreSQL 17.3, 16.7, 15.11, 14.16, and 13.19 are affected.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-1094](https://github.com/B1ack4sh/Blackash-CVE-2025-1094) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-1094.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-1094.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/O-Carneiro/cve_2024_32002_hook](https://github.com/O-Carneiro/cve_2024_32002_hook) :  ![starts](https://img.shields.io/github/stars/O-Carneiro/cve_2024_32002_hook.svg) ![forks](https://img.shields.io/github/forks/O-Carneiro/cve_2024_32002_hook.svg)
- [https://github.com/O-Carneiro/cve_2024_32002_rce](https://github.com/O-Carneiro/cve_2024_32002_rce) :  ![starts](https://img.shields.io/github/stars/O-Carneiro/cve_2024_32002_rce.svg) ![forks](https://img.shields.io/github/forks/O-Carneiro/cve_2024_32002_rce.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/byteReaper77/CVE-2024-4577](https://github.com/byteReaper77/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2024-4577.svg)


## CVE-2023-37273
 Auto-GPT is an experimental open-source application showcasing the capabilities of the GPT-4 language model. Running Auto-GPT version prior to 0.4.3 by cloning the git repo and executing `docker compose run auto-gpt` in the repo root uses a different docker-compose.yml file from the one suggested in the official docker set up instructions. The docker-compose.yml file located in the repo root mounts itself into the docker container without write protection. This means that if malicious custom python code is executed via the `execute_python_file` and `execute_python_code` commands, it can overwrite the docker-compose.yml file and abuse it to gain control of the host system the next time Auto-GPT is started. The issue has been patched in version 0.4.3.

- [https://github.com/gdesantis01/instructions-summarizing](https://github.com/gdesantis01/instructions-summarizing) :  ![starts](https://img.shields.io/github/stars/gdesantis01/instructions-summarizing.svg) ![forks](https://img.shields.io/github/forks/gdesantis01/instructions-summarizing.svg)


## CVE-2023-33538
 TP-Link TL-WR940N V2/V4, TL-WR841N V8/V10, and TL-WR740N V1/V2 was discovered to contain a command injection vulnerability via the component /userRpm/WlanNetworkRpm .

- [https://github.com/mrowkoob/CVE-2023-33538-msf](https://github.com/mrowkoob/CVE-2023-33538-msf) :  ![starts](https://img.shields.io/github/stars/mrowkoob/CVE-2023-33538-msf.svg) ![forks](https://img.shields.io/github/forks/mrowkoob/CVE-2023-33538-msf.svg)


## CVE-2021-31630
 Command Injection in Open PLC Webserver v3 allows remote attackers to execute arbitrary code via the "Hardware Layer Code Box" component on the "/hardware" page of the application.

- [https://github.com/machevalia/OpenPLC-CVE-2021-31630-RCE](https://github.com/machevalia/OpenPLC-CVE-2021-31630-RCE) :  ![starts](https://img.shields.io/github/stars/machevalia/OpenPLC-CVE-2021-31630-RCE.svg) ![forks](https://img.shields.io/github/forks/machevalia/OpenPLC-CVE-2021-31630-RCE.svg)


## CVE-2020-1048
 An elevation of privilege vulnerability exists when the Windows Print Spooler service improperly allows arbitrary writing to the file system, aka 'Windows Print Spooler Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1070.

- [https://github.com/talsim/printDemon2system](https://github.com/talsim/printDemon2system) :  ![starts](https://img.shields.io/github/stars/talsim/printDemon2system.svg) ![forks](https://img.shields.io/github/forks/talsim/printDemon2system.svg)


## CVE-2015-6967
 Unrestricted file upload vulnerability in the My Image plugin in Nibbleblog before 4.0.5 allows remote administrators to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in content/private/plugins/my_image/image.php.

- [https://github.com/cuerv0x/CVE-2015-6967](https://github.com/cuerv0x/CVE-2015-6967) :  ![starts](https://img.shields.io/github/stars/cuerv0x/CVE-2015-6967.svg) ![forks](https://img.shields.io/github/forks/cuerv0x/CVE-2015-6967.svg)


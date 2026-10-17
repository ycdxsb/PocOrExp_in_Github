# Update 2026-10-17
## CVE-2026-110958
 A vulnerability was found in Wavlink WN530HG4B M30HG4B_V260724. The impacted element is an unknown function of the file api.cgi. The manipulation results in heap-based buffer overflow. It is possible to launch the attack remotely. The exploit has been made public and could be used. Upgrading to version 2026-09-24-841a51c6d5_tclinux.bin is sufficient to resolve this issue. The affected component should be upgraded. The vendor confirms: "We confirm the finding, and it has already been addressed. In the current firmware the api=info&client=app handler no longer builds a shell command: the login script is now invoked through an argument vector (execvp) instead of system(), and the client address is length-limited and null-checked."

- [https://github.com/shlln/CVE-2026-110958](https://github.com/shlln/CVE-2026-110958) :  ![starts](https://img.shields.io/github/stars/shlln/CVE-2026-110958.svg) ![forks](https://img.shields.io/github/forks/shlln/CVE-2026-110958.svg)


## CVE-2026-110912
 In DragonFly BSD through 6.4.2 before 4bb22ff, the ARP input handlers arpintr() and in_arpinput() (sys/netinet/if_ether.c) do not validate the hardware address length (ar_hln) and protocol address length (ar_pln) fields of incoming ARP packets. in_arpreply() then uses these attacker-controlled values as memcpy lengths when copying from kernel buffers that are only 6 and 4 bytes long, resulting in an out-of-bounds read of kernel heap and stack memory that is copied into the ARP reply sent back to the requester. An unauthenticated attacker on the adjacent network can use a single crafted ARP request to disclose up to roughly 250 bytes of each type of kernel memory, including kernel pointers. This is expected to be fixed in the 6.6 stable release when that is available.

- [https://github.com/0xBlackash/CVE-2026-110912](https://github.com/0xBlackash/CVE-2026-110912) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-110912.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-110912.svg)
- [https://github.com/dreamfast/CVE-2026-110912](https://github.com/dreamfast/CVE-2026-110912) :  ![starts](https://img.shields.io/github/stars/dreamfast/CVE-2026-110912.svg) ![forks](https://img.shields.io/github/forks/dreamfast/CVE-2026-110912.svg)


## CVE-2026-110447
 Collabora Online Built-in CODE Server before 26.4.303 (richdocumentscode), a Nextcloud app, allows remote code execution, as exploited in the wild in September and October 2026, a different vulnerability than CVE-2025-66208. This is an OS command injection in proxy.php when the CODE server isn't running (e.g., the product was recently restarted). The vulnerability is not present in standalone Collabora Online servers; only this deployment with CODE Server is affected.

- [https://github.com/Iceman2050/cve-2026-110447-checker](https://github.com/Iceman2050/cve-2026-110447-checker) :  ![starts](https://img.shields.io/github/stars/Iceman2050/cve-2026-110447-checker.svg) ![forks](https://img.shields.io/github/forks/Iceman2050/cve-2026-110447-checker.svg)


## CVE-2026-108578
 A vulnerability was identified in Neterbit NW-431F 20250715. Impacted is an unknown function of the file /sms.json of the component Embedded Web Server. Such manipulation leads to information disclosure. The attack may be launched remotely. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/KernelDotDLL/CVE-2026-108578](https://github.com/KernelDotDLL/CVE-2026-108578) :  ![starts](https://img.shields.io/github/stars/KernelDotDLL/CVE-2026-108578.svg) ![forks](https://img.shields.io/github/forks/KernelDotDLL/CVE-2026-108578.svg)


## CVE-2026-104935
 Authentication bypass by spoofing in ICS before version 25.1.3.0 allows a remote unauthenticated attacker to execute arbitrary commands. This does not impact ICS version 22.7R2.14 or prior.

- [https://github.com/0x45dd/ivanti-cve-2026-104935-check](https://github.com/0x45dd/ivanti-cve-2026-104935-check) :  ![starts](https://img.shields.io/github/stars/0x45dd/ivanti-cve-2026-104935-check.svg) ![forks](https://img.shields.io/github/forks/0x45dd/ivanti-cve-2026-104935-check.svg)


## CVE-2026-104711
Users are recommended to upgrade to version 6.12.0 or 7.4.0, which fixes the issue.

- [https://github.com/uday952/CVE-2026-104711-POC-NEW-VARIANT](https://github.com/uday952/CVE-2026-104711-POC-NEW-VARIANT) :  ![starts](https://img.shields.io/github/stars/uday952/CVE-2026-104711-POC-NEW-VARIANT.svg) ![forks](https://img.shields.io/github/forks/uday952/CVE-2026-104711-POC-NEW-VARIANT.svg)


## CVE-2026-104586
 AUTOM8N (WHM/cPanel plugin) through commit 82821f7 contains an OS Command Injection in borg_restore.cgi.

- [https://github.com/AmalJafarzade/CVE-2026-104586](https://github.com/AmalJafarzade/CVE-2026-104586) :  ![starts](https://img.shields.io/github/stars/AmalJafarzade/CVE-2026-104586.svg) ![forks](https://img.shields.io/github/forks/AmalJafarzade/CVE-2026-104586.svg)


## CVE-2026-102697
 Ollama versions 0.14.0 before 0.31.2 contain an incorrect authorization vulnerability in the experimental agent mode Bash tool approval mechanism that fails to properly parse shell syntax. Attackers who can influence model output through prompt injection can execute additional shell commands by appending control operators like semicolons or logical operators to approved commands, bypassing the session approval requirement.

- [https://github.com/akinerkisa/blindllama-cve-2026-102697](https://github.com/akinerkisa/blindllama-cve-2026-102697) :  ![starts](https://img.shields.io/github/stars/akinerkisa/blindllama-cve-2026-102697.svg) ![forks](https://img.shields.io/github/forks/akinerkisa/blindllama-cve-2026-102697.svg)


## CVE-2026-99999
A more complete validation at input is forthcoming, but needs more work.

- [https://github.com/24520597-blip/CVE-2026-999999](https://github.com/24520597-blip/CVE-2026-999999) :  ![starts](https://img.shields.io/github/stars/24520597-blip/CVE-2026-999999.svg) ![forks](https://img.shields.io/github/forks/24520597-blip/CVE-2026-999999.svg)


## CVE-2026-97205
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/suominen/CVE-2026-97205](https://github.com/suominen/CVE-2026-97205) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-97205.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-97205.svg)


## CVE-2026-85097
 The Bricksforge plugin for WordPress is vulnerable to unauthenticated arbitrary file upload in versions up to, and including, 3.1.8.9. This is due to insufficient validation of the attacker-controlled URL field in the 'temporaryFileUploads' parameter during form submission. An unauthenticated attacker can first obtain a valid nonce via the bricksforge_regenerate_nonce AJAX endpoint, then upload a GIF/PHP polyglot file to the temporary upload directory where MIME type validation is correctly performed. Subsequently, the attacker can submit a form with a crafted 'temporaryFileUploads' parameter where the server-side file path points to the validated GIF file, but the attacker-controlled url field ends with a .php extension. This makes it possible for unauthenticated attackers to upload and execute arbitrary PHP code on the server.

- [https://github.com/BlackHatExploitation/CVE-2026-85097](https://github.com/BlackHatExploitation/CVE-2026-85097) :  ![starts](https://img.shields.io/github/stars/BlackHatExploitation/CVE-2026-85097.svg) ![forks](https://img.shields.io/github/forks/BlackHatExploitation/CVE-2026-85097.svg)


## CVE-2026-78851
 Directory Traversal vulnerability in Grav CMS 2.0.3 through 2.0.6 allows a remote attacker to obtain sensitive information via the GravExtension.php and the mediaDirFunc method.

- [https://github.com/SLO-CYBER-SEC/CVE-2026-78851](https://github.com/SLO-CYBER-SEC/CVE-2026-78851) :  ![starts](https://img.shields.io/github/stars/SLO-CYBER-SEC/CVE-2026-78851.svg) ![forks](https://img.shields.io/github/forks/SLO-CYBER-SEC/CVE-2026-78851.svg)


## CVE-2026-78850
 An issue in Matomo v.5.11.2 allows a remote attacker to obtain sensitive information via the SiteContentDetector / SitesManager component

- [https://github.com/SLO-CYBER-SEC/CVE-2026-78850](https://github.com/SLO-CYBER-SEC/CVE-2026-78850) :  ![starts](https://img.shields.io/github/stars/SLO-CYBER-SEC/CVE-2026-78850.svg) ![forks](https://img.shields.io/github/forks/SLO-CYBER-SEC/CVE-2026-78850.svg)


## CVE-2026-77521
 MaxKB is an open-source AI assistant for enterprise. Prior to version 2.10.5-lts, assistants with a tool, MCP tool, skill, or sub-application use SandboxShellBackend, which exposes an execute shell tool without excluding it and omits execute from interrupt_on, so human approval is not required. Untrusted chat or ingested content can therefore cause command execution; source deployments with MAXKB_SANDBOX disabled run commands directly as the application user, while the official root container's string-based gosu wrapper allowed shell metacharacters to execute outside the intended sandbox. This issue is fixed in version 2.10.5-lts.

- [https://github.com/InertFluid/cve-2026-77521-lab](https://github.com/InertFluid/cve-2026-77521-lab) :  ![starts](https://img.shields.io/github/stars/InertFluid/cve-2026-77521-lab.svg) ![forks](https://img.shields.io/github/forks/InertFluid/cve-2026-77521-lab.svg)


## CVE-2026-76519
This vulnerability is due to improper handling of email attachments when the file reputation service is enabled. An attacker could exploit this vulnerability by sending an email that contains a crafted attachment through an affected device. A successful exploit could allow the attacker to write arbitrary files and execute commands with&nbsp;root privileges on the underlying operating system.

- [https://github.com/Mickysalivan/CVE-2026-76519-Proof-of-concept](https://github.com/Mickysalivan/CVE-2026-76519-Proof-of-concept) :  ![starts](https://img.shields.io/github/stars/Mickysalivan/CVE-2026-76519-Proof-of-concept.svg) ![forks](https://img.shields.io/github/forks/Mickysalivan/CVE-2026-76519-Proof-of-concept.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/feiguang-ai/plz110-6.12.69-cve-2026-64560-ksu](https://github.com/feiguang-ai/plz110-6.12.69-cve-2026-64560-ksu) :  ![starts](https://img.shields.io/github/stars/feiguang-ai/plz110-6.12.69-cve-2026-64560-ksu.svg) ![forks](https://img.shields.io/github/forks/feiguang-ai/plz110-6.12.69-cve-2026-64560-ksu.svg)


## CVE-2026-64507
under CONFIG_BPF_JIT so that bugs.c still builds with CONFIG_BPF_JIT=n.

- [https://github.com/manalejandro/CVE-2026-64507](https://github.com/manalejandro/CVE-2026-64507) :  ![starts](https://img.shields.io/github/stars/manalejandro/CVE-2026-64507.svg) ![forks](https://img.shields.io/github/forks/manalejandro/CVE-2026-64507.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/gichirimaku/wp2shell-PoC](https://github.com/gichirimaku/wp2shell-PoC) :  ![starts](https://img.shields.io/github/stars/gichirimaku/wp2shell-PoC.svg) ![forks](https://img.shields.io/github/forks/gichirimaku/wp2shell-PoC.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/gichirimaku/wp2shell-PoC](https://github.com/gichirimaku/wp2shell-PoC) :  ![starts](https://img.shields.io/github/stars/gichirimaku/wp2shell-PoC.svg) ![forks](https://img.shields.io/github/forks/gichirimaku/wp2shell-PoC.svg)


## CVE-2026-59310
 VMware vCenter contains a directory traversal vulnerability in the Syslog server. A malicious actor with network access to vCenter may exploit this issue to execute arbitrary code.

- [https://github.com/zgsfsec/CVE-2026-59310-POC](https://github.com/zgsfsec/CVE-2026-59310-POC) :  ![starts](https://img.shields.io/github/stars/zgsfsec/CVE-2026-59310-POC.svg) ![forks](https://img.shields.io/github/forks/zgsfsec/CVE-2026-59310-POC.svg)


## CVE-2026-57155
 OPNsense is a FreeBSD based firewall and routing platform. Prior to version 26.1.11, the Firewall Alias GeoIP importer's process_zip() and process_gzip() paths in src/opnsense/scripts/filter/lib/alias/geoip.py use an unvalidated CSV country_code value to construct output filenames below /usr/local/share/GeoIP/alias. A user with Firewall Alias Edit privilege can configure an attacker-controlled GeoIP source URL and supply an archive whose country code traverses into another existing directory, causing attacker-controlled content to be written as root with an -IPv4 or -IPv6 suffix. A crafted newsyslog fragment and oversized log file can use the default hourly root cron job to execute commands as root, resulting in complete firewall compromise. This issue is fixed in version 26.1.11.

- [https://github.com/babyshen/CVE-2026-57155](https://github.com/babyshen/CVE-2026-57155) :  ![starts](https://img.shields.io/github/stars/babyshen/CVE-2026-57155.svg) ![forks](https://img.shields.io/github/forks/babyshen/CVE-2026-57155.svg)


## CVE-2026-53582
 OPNsense is a FreeBSD based firewall and routing platform. Prior to version 26.1.10, the Trust module stores attacker-controlled certificate authority and certificate refid values and interpolates them into XPath expressions in src/opnsense/mvc/app/models/OPNsense/Trust/FieldTypes/CAsField.php and src/opnsense/mvc/app/models/OPNsense/Trust/FieldTypes/CertificatesField.php. A user with CA Manager or Certificate Manager privileges can submit a crafted refid and repeatedly retrieve the object to obtain a boolean refcount oracle, allowing values in config.xml to be recovered character by character. Exposed values can include password hashes, API credentials, certificate private keys, VPN key material, and high-availability credentials, enabling privilege escalation and compromise of other security domains. This issue is fixed in version 26.1.10.

- [https://github.com/eev4n/CVE-2026-53582](https://github.com/eev4n/CVE-2026-53582) :  ![starts](https://img.shields.io/github/stars/eev4n/CVE-2026-53582.svg) ![forks](https://img.shields.io/github/forks/eev4n/CVE-2026-53582.svg)


## CVE-2026-53365
but was pre-existing.

- [https://github.com/hoodoer/VsockDrop-Adapted-CVE-2026-53365](https://github.com/hoodoer/VsockDrop-Adapted-CVE-2026-53365) :  ![starts](https://img.shields.io/github/stars/hoodoer/VsockDrop-Adapted-CVE-2026-53365.svg) ![forks](https://img.shields.io/github/forks/hoodoer/VsockDrop-Adapted-CVE-2026-53365.svg)


## CVE-2026-47644
 Improper neutralization of special elements in output used by a downstream component ('injection') in Copilot Chat (Microsoft Edge) allows an unauthorized attacker to disclose information over a network.

- [https://github.com/songjianyang/CVE-2026-47644](https://github.com/songjianyang/CVE-2026-47644) :  ![starts](https://img.shields.io/github/stars/songjianyang/CVE-2026-47644.svg) ![forks](https://img.shields.io/github/forks/songjianyang/CVE-2026-47644.svg)


## CVE-2026-44825
  *  Clusters where template users have been assigned strong passwords after bootstrap

- [https://github.com/q0524/CVE-2026-44825_CTF](https://github.com/q0524/CVE-2026-44825_CTF) :  ![starts](https://img.shields.io/github/stars/q0524/CVE-2026-44825_CTF.svg) ![forks](https://img.shields.io/github/forks/q0524/CVE-2026-44825_CTF.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/ymh001/meizu21-ghostlock-root](https://github.com/ymh001/meizu21-ghostlock-root) :  ![starts](https://img.shields.io/github/stars/ymh001/meizu21-ghostlock-root.svg) ![forks](https://img.shields.io/github/forks/ymh001/meizu21-ghostlock-root.svg)
- [https://github.com/tingao/debian-on-s23-ultra](https://github.com/tingao/debian-on-s23-ultra) :  ![starts](https://img.shields.io/github/stars/tingao/debian-on-s23-ultra.svg) ![forks](https://img.shields.io/github/forks/tingao/debian-on-s23-ultra.svg)


## CVE-2026-36436
 An issue in Trisolutions BRPerfX version 1.4.4.0 exposes LDAP credentials in plaintext within the administrative configuration interface. An authenticated administrator can inspect the client-side code to retrieve the credential.

- [https://github.com/vtrmK/CVE-2026-36436-Public-Reference-Pack](https://github.com/vtrmK/CVE-2026-36436-Public-Reference-Pack) :  ![starts](https://img.shields.io/github/stars/vtrmK/CVE-2026-36436-Public-Reference-Pack.svg) ![forks](https://img.shields.io/github/forks/vtrmK/CVE-2026-36436-Public-Reference-Pack.svg)


## CVE-2026-20896
 Gitea Docker image versions up to and including 1.26.2 use REVERSE_PROXY_TRUSTED_PROXIES=* by default, allowing any source IP to impersonate a user when reverse-proxy authentication headers such as X-WEBAUTH-USER are enabled.

- [https://github.com/Raincombat/CVE-2026-20896-Gitea-CTF](https://github.com/Raincombat/CVE-2026-20896-Gitea-CTF) :  ![starts](https://img.shields.io/github/stars/Raincombat/CVE-2026-20896-Gitea-CTF.svg) ![forks](https://img.shields.io/github/forks/Raincombat/CVE-2026-20896-Gitea-CTF.svg)


## CVE-2026-20329
The vulnerabilities tracked by CVE-2026-20329 are related to issues concerning improper handling of exceptional conditions that are grouped under the Common Weakness Enumeration (CWE) Pillar CWE-703.

- [https://github.com/ekacs/predicted-CVE-2026-20329](https://github.com/ekacs/predicted-CVE-2026-20329) :  ![starts](https://img.shields.io/github/stars/ekacs/predicted-CVE-2026-20329.svg) ![forks](https://img.shields.io/github/forks/ekacs/predicted-CVE-2026-20329.svg)


## CVE-2026-18963
 A flaw was found in the reset-credentials flow of the keycloak-services component, which is the core engine for identity and access management in Red Hat Build of Keycloak. The issue allows an unauthenticated attacker to force the password reset process for any user without needing to click the required email verification link. This can result in the attacker gaining full control over target user accounts by directly setting new credentials.

- [https://github.com/orevim/CVE-2026-18963-PoC](https://github.com/orevim/CVE-2026-18963-PoC) :  ![starts](https://img.shields.io/github/stars/orevim/CVE-2026-18963-PoC.svg) ![forks](https://img.shields.io/github/forks/orevim/CVE-2026-18963-PoC.svg)


## CVE-2026-17001
 The Import and export users and customers plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Custom Column User Meta Profile Fields in all versions up to, and including, 2.4.5 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with custom-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/llaytynher/CVE-2026-17001](https://github.com/llaytynher/CVE-2026-17001) :  ![starts](https://img.shields.io/github/stars/llaytynher/CVE-2026-17001.svg) ![forks](https://img.shields.io/github/forks/llaytynher/CVE-2026-17001.svg)


## CVE-2026-12118
 IBM webMethods Integration (on prem) 10.15, 10.11 could allow an unauthenticated remote attacker to execute arbitrary code on the system due to the deserialization of untrusted data.

- [https://github.com/uday952/CVE-2026-12118-POC-](https://github.com/uday952/CVE-2026-12118-POC-) :  ![starts](https://img.shields.io/github/stars/uday952/CVE-2026-12118-POC-.svg) ![forks](https://img.shields.io/github/forks/uday952/CVE-2026-12118-POC-.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/onesmiledx/CVE-2026-43499](https://github.com/onesmiledx/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/onesmiledx/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/onesmiledx/CVE-2026-43499.svg)
- [https://github.com/dorlow/hazel-cve-2026-43499](https://github.com/dorlow/hazel-cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/dorlow/hazel-cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/dorlow/hazel-cve-2026-43499.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/pulentoski/CVE-2026-31431](https://github.com/pulentoski/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/pulentoski/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/pulentoski/CVE-2026-31431.svg)


## CVE-2026-1047
 The salavat counter Plugin plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'image_url' parameter in all versions up to, and including, 0.9.5 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/M3aCulpa/CVE-2026-104715](https://github.com/M3aCulpa/CVE-2026-104715) :  ![starts](https://img.shields.io/github/stars/M3aCulpa/CVE-2026-104715.svg) ![forks](https://img.shields.io/github/forks/M3aCulpa/CVE-2026-104715.svg)


## CVE-2026-0322
Cloud NGFW and Prisma® Access are not impacted by this vulnerability.

- [https://github.com/Ife-ella/CVE-vulnerability](https://github.com/Ife-ella/CVE-vulnerability) :  ![starts](https://img.shields.io/github/stars/Ife-ella/CVE-vulnerability.svg) ![forks](https://img.shields.io/github/forks/Ife-ella/CVE-vulnerability.svg)


## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/bijoumj/cve-2025-68613-ctf](https://github.com/bijoumj/cve-2025-68613-ctf) :  ![starts](https://img.shields.io/github/stars/bijoumj/cve-2025-68613-ctf.svg) ![forks](https://img.shields.io/github/forks/bijoumj/cve-2025-68613-ctf.svg)


## CVE-2025-66645
 NiceGUI is a Python-based UI framework. Versions 3.3.1 and below are vulnerable to  directory traversal through the App.add_media_files() function, which allows a remote attacker to read arbitrary files on the server filesystem. This issue is fixed in version 3.4.0.

- [https://github.com/prokeon5991-wq/cve-2025-66645](https://github.com/prokeon5991-wq/cve-2025-66645) :  ![starts](https://img.shields.io/github/stars/prokeon5991-wq/cve-2025-66645.svg) ![forks](https://img.shields.io/github/forks/prokeon5991-wq/cve-2025-66645.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/begzodxasanboev/Driftnet](https://github.com/begzodxasanboev/Driftnet) :  ![starts](https://img.shields.io/github/stars/begzodxasanboev/Driftnet.svg) ![forks](https://img.shields.io/github/forks/begzodxasanboev/Driftnet.svg)


## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

- [https://github.com/sefafl77/CVE-2025-27591-PoC](https://github.com/sefafl77/CVE-2025-27591-PoC) :  ![starts](https://img.shields.io/github/stars/sefafl77/CVE-2025-27591-PoC.svg) ![forks](https://img.shields.io/github/forks/sefafl77/CVE-2025-27591-PoC.svg)


## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present.  Disabling follow_symlinks and using a reverse proxy are encouraged mitigations.  Version 3.9.2 fixes this issue.

- [https://github.com/begzodxasanboev/Driftnet](https://github.com/begzodxasanboev/Driftnet) :  ![starts](https://img.shields.io/github/stars/begzodxasanboev/Driftnet.svg) ![forks](https://img.shields.io/github/forks/begzodxasanboev/Driftnet.svg)


## CVE-2024-6648
 Absolute Path Traversal vulnerability in AP Page Builder versions prior to 4.0.0 could allow an unauthenticated remote user to modify the 'product_item_path' within the 'config' JSON file, allowing them to read any file on the system.

- [https://github.com/alexb616/CVE-2024-6648-RCE](https://github.com/alexb616/CVE-2024-6648-RCE) :  ![starts](https://img.shields.io/github/stars/alexb616/CVE-2024-6648-RCE.svg) ![forks](https://img.shields.io/github/forks/alexb616/CVE-2024-6648-RCE.svg)


## CVE-2024-2961
 The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.

- [https://github.com/Sib1110/cve-2024-2961](https://github.com/Sib1110/cve-2024-2961) :  ![starts](https://img.shields.io/github/stars/Sib1110/cve-2024-2961.svg) ![forks](https://img.shields.io/github/forks/Sib1110/cve-2024-2961.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)


## CVE-2021-42574
 An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through 14.0. It permits the visual reordering of characters via control sequences, which can be used to craft source code that renders different logic than the logical ordering of tokens ingested by compilers and interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such that targeted vulnerabilities are introduced invisibly to human reviewers. NOTE: the Unicode Consortium offers the following alternative approach to presenting this concern. An issue is noted in the nature of international text that can affect applications that implement support for The Unicode Standard and the Unicode Bidirectional Algorithm (all versions). Due to text display behavior when text includes left-to-right and right-to-left characters, the visual order of tokens may be different from their logical order. Additionally, control characters needed to fully support the requirements of bidirectional text can further obfuscate the logical order of tokens. Unless mitigated, an adversary could craft source code such that the ordering of tokens perceived by human reviewers does not match what will be processed by a compiler/interpreter/etc. The Unicode Consortium has documented this class of vulnerability in its document, Unicode Technical Report #36, Unicode Security Considerations. The Unicode Consortium also provides guidance on mitigations for this class of issues in Unicode Technical Standard #39, Unicode Security Mechanisms, and in Unicode Standard Annex #31, Unicode Identifier and Pattern Syntax. Also, the BIDI specification allows applications to tailor the implementation in ways that can mitigate misleading visual reordering in program text; see HL4 in Unicode Standard Annex #9, Unicode Bidirectional Algorithm.

- [https://github.com/gitstq/GlyphGuard](https://github.com/gitstq/GlyphGuard) :  ![starts](https://img.shields.io/github/stars/gitstq/GlyphGuard.svg) ![forks](https://img.shields.io/github/forks/gitstq/GlyphGuard.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


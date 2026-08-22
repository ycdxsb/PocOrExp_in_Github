# Update 2026-08-22
## CVE-2026-77113
 Path traversal in apport-unpack in Canonical Apport before 2.36.0, 2.34.2, and 2.28.4 on Linux allows an attacker to create or overwrite arbitrary files with the privileges of the executing user via an attacker controlled key names in crash report files.

- [https://github.com/0xROI/CVE-2026-77113](https://github.com/0xROI/CVE-2026-77113) :  ![starts](https://img.shields.io/github/stars/0xROI/CVE-2026-77113.svg) ![forks](https://img.shields.io/github/forks/0xROI/CVE-2026-77113.svg)


## CVE-2026-71960
 Cudy WR3000 2.0 running firmware before 2.5.24 contains a hard-coded JWT HMAC signing secret vulnerability in the Mosquitto MQTT broker's authentication plugin that allows unauthenticated attackers to forge valid JWT tokens by extracting the secret from the firmware image. Attackers can use the extracted secret to craft arbitrary JWT tokens and authenticate to the MQTT broker without legitimate credentials, gaining unauthorized access to the device's mesh networking interface.

- [https://github.com/Hunt-Benito/the-same-key-opens-every-box-cve-2026-71960-hard-coded-jwt-secret-in-cudy-wr3000-mesh-mqtt](https://github.com/Hunt-Benito/the-same-key-opens-every-box-cve-2026-71960-hard-coded-jwt-secret-in-cudy-wr3000-mesh-mqtt) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/the-same-key-opens-every-box-cve-2026-71960-hard-coded-jwt-secret-in-cudy-wr3000-mesh-mqtt.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/the-same-key-opens-every-box-cve-2026-71960-hard-coded-jwt-secret-in-cudy-wr3000-mesh-mqtt.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/mhassani97/cve-2026-63030-lab](https://github.com/mhassani97/cve-2026-63030-lab) :  ![starts](https://img.shields.io/github/stars/mhassani97/cve-2026-63030-lab.svg) ![forks](https://img.shields.io/github/forks/mhassani97/cve-2026-63030-lab.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/mhassani97/cve-2026-63030-lab](https://github.com/mhassani97/cve-2026-63030-lab) :  ![starts](https://img.shields.io/github/stars/mhassani97/cve-2026-63030-lab.svg) ![forks](https://img.shields.io/github/forks/mhassani97/cve-2026-63030-lab.svg)


## CVE-2026-53587
 libgit2 is a portable C implementation of the Git core methods provided as a linkable library with a solid API, allowing to build Git functionality into your application. Prior to 1.8.6 and 1.9.5, libgit2 performs a fixed-size strncmp in set_data in src/libgit2/transports/smart_pkt.c without first verifying that the smart-protocol pkt-line capability buffer contains 14 bytes. A malicious Git server can make bytes after the pkt-line complete object-format=, causing format_str to advance beyond the pkt-line and the following memchr length calculation to underflow. The resulting heap out-of-bounds walk can crash a client during the first refs-advertisement packet over HTTP, HTTPS, SSH, or the Git protocol. This issue is fixed in versions 1.8.6 and 1.9.5.

- [https://github.com/Alixploit22/CVE-2026-53587](https://github.com/Alixploit22/CVE-2026-53587) :  ![starts](https://img.shields.io/github/stars/Alixploit22/CVE-2026-53587.svg) ![forks](https://img.shields.io/github/forks/Alixploit22/CVE-2026-53587.svg)


## CVE-2026-46242
READ_ONCE(epi-dying) fast-path bailout stays.

- [https://github.com/BinaryMasc/CVE-2026-46242](https://github.com/BinaryMasc/CVE-2026-46242) :  ![starts](https://img.shields.io/github/stars/BinaryMasc/CVE-2026-46242.svg) ![forks](https://img.shields.io/github/forks/BinaryMasc/CVE-2026-46242.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/NanoTurtle1145/root-my-s24](https://github.com/NanoTurtle1145/root-my-s24) :  ![starts](https://img.shields.io/github/stars/NanoTurtle1145/root-my-s24.svg) ![forks](https://img.shields.io/github/forks/NanoTurtle1145/root-my-s24.svg)
- [https://github.com/Cxyofficial/k50g-pocof4gt-cve-2026-43499-test](https://github.com/Cxyofficial/k50g-pocof4gt-cve-2026-43499-test) :  ![starts](https://img.shields.io/github/stars/Cxyofficial/k50g-pocof4gt-cve-2026-43499-test.svg) ![forks](https://img.shields.io/github/forks/Cxyofficial/k50g-pocof4gt-cve-2026-43499-test.svg)
- [https://github.com/SetsuNeko/GhostLock_MT6983V_5.10](https://github.com/SetsuNeko/GhostLock_MT6983V_5.10) :  ![starts](https://img.shields.io/github/stars/SetsuNeko/GhostLock_MT6983V_5.10.svg) ![forks](https://img.shields.io/github/forks/SetsuNeko/GhostLock_MT6983V_5.10.svg)


## CVE-2026-40345
 deepmerge-ts is a typescript library providing functionality to deep merging of javascript objects. Prior to 8.0.0, the deepmerge, deepmergeCustom, deepmergeInto, and deepmergeIntoCustom APIs do not track visited objects or object pairs when recursively merging records. When two input values contain self-references at the same property path, the merge logic repeatedly revisits the same pair until Node.js raises RangeError: Maximum call stack size exceeded. Applications that merge attacker-controlled recursive object graphs can synchronously crash the affected process or cause repeated worker restarts. Plain JSON input alone cannot create the recursive graph required to trigger the issue. This issue is fixed in version 8.0.0.

- [https://github.com/Jvr2022/CVE-2026-40345](https://github.com/Jvr2022/CVE-2026-40345) :  ![starts](https://img.shields.io/github/stars/Jvr2022/CVE-2026-40345.svg) ![forks](https://img.shields.io/github/forks/Jvr2022/CVE-2026-40345.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/dodeepsink/CVE-2026-39987.py](https://github.com/dodeepsink/CVE-2026-39987.py) :  ![starts](https://img.shields.io/github/stars/dodeepsink/CVE-2026-39987.py.svg) ![forks](https://img.shields.io/github/forks/dodeepsink/CVE-2026-39987.py.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/st4rburn/RootRemover](https://github.com/st4rburn/RootRemover) :  ![starts](https://img.shields.io/github/stars/st4rburn/RootRemover.svg) ![forks](https://img.shields.io/github/forks/st4rburn/RootRemover.svg)


## CVE-2026-28134
 Improper Control of Generation of Code ('Code Injection') vulnerability in Crocoblock JetEngine jet-engine allows Remote Code Inclusion.This issue affects JetEngine: from n/a through = 3.7.2.

- [https://github.com/RandomRobbieBF/CVE-2026-28134](https://github.com/RandomRobbieBF/CVE-2026-28134) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2026-28134.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2026-28134.svg)


## CVE-2026-24301
 Improper neutralization of special elements used in a command ('command injection') in Microsoft Copilot allows an unauthorized attacker to disclose information over a network.

- [https://github.com/CSOAI-ORG/memory-poisoning-axis](https://github.com/CSOAI-ORG/memory-poisoning-axis) :  ![starts](https://img.shields.io/github/stars/CSOAI-ORG/memory-poisoning-axis.svg) ![forks](https://img.shields.io/github/forks/CSOAI-ORG/memory-poisoning-axis.svg)


## CVE-2026-21048
 Out-of-bounds write in parsing DNG format in libimagecodec.media.quram.so prior to SMR Jul-2026 Release 1 allows remote attackers to write out-of-bounds memory.

- [https://github.com/Pealeap/CVE-2026-21045_and_CVE-2026-21048](https://github.com/Pealeap/CVE-2026-21045_and_CVE-2026-21048) :  ![starts](https://img.shields.io/github/stars/Pealeap/CVE-2026-21045_and_CVE-2026-21048.svg) ![forks](https://img.shields.io/github/forks/Pealeap/CVE-2026-21045_and_CVE-2026-21048.svg)


## CVE-2026-21045
 Out-of-bounds write in parsing TIFF format in libimagecodec.media.quram.so prior to SMR Jul-2026 Release 1 allows remote attackers to write out-of-bounds memory.

- [https://github.com/Pealeap/CVE-2026-21045_and_CVE-2026-21048](https://github.com/Pealeap/CVE-2026-21045_and_CVE-2026-21048) :  ![starts](https://img.shields.io/github/stars/Pealeap/CVE-2026-21045_and_CVE-2026-21048.svg) ![forks](https://img.shields.io/github/forks/Pealeap/CVE-2026-21045_and_CVE-2026-21048.svg)


## CVE-2026-21018
 Out-of-bounds write in SveService prior to SMR May-2026 Release 1 allows local privileged attackers to execute arbitrary code.

- [https://github.com/Pealeap/CVE-2026-21018](https://github.com/Pealeap/CVE-2026-21018) :  ![starts](https://img.shields.io/github/stars/Pealeap/CVE-2026-21018.svg) ![forks](https://img.shields.io/github/forks/Pealeap/CVE-2026-21018.svg)


## CVE-2026-19478
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 18.2 before 18.11.11, 19.0 before 19.0.8, 19.1 before 19.1.6, and 19.2 before 19.2.4 that under certain conditions could allow an unauthenticated user to remotely modify or delete public projects and user data via a GraphQL directive.

- [https://github.com/n0xdaemon/cve-2026-19478](https://github.com/n0xdaemon/cve-2026-19478) :  ![starts](https://img.shields.io/github/stars/n0xdaemon/cve-2026-19478.svg) ![forks](https://img.shields.io/github/forks/n0xdaemon/cve-2026-19478.svg)


## CVE-2026-18963
 A flaw was found in the reset-credentials flow of the keycloak-services component, which is the core engine for identity and access management in Red Hat Build of Keycloak. The issue allows an unauthenticated attacker to force the password reset process for any user without needing to click the required email verification link. This can result in the attacker gaining full control over target user accounts by directly setting new credentials.

- [https://github.com/kyos-public/keycloak-cve-2026-18963-hunt](https://github.com/kyos-public/keycloak-cve-2026-18963-hunt) :  ![starts](https://img.shields.io/github/stars/kyos-public/keycloak-cve-2026-18963-hunt.svg) ![forks](https://img.shields.io/github/forks/kyos-public/keycloak-cve-2026-18963-hunt.svg)
- [https://github.com/Snizi/CVE-2026-18963-Exploit](https://github.com/Snizi/CVE-2026-18963-Exploit) :  ![starts](https://img.shields.io/github/stars/Snizi/CVE-2026-18963-Exploit.svg) ![forks](https://img.shields.io/github/forks/Snizi/CVE-2026-18963-Exploit.svg)


## CVE-2026-18366
 The Events Manager  WordPress plugin before 7.4.1 does not properly scope its capability mapping, discarding the access control decisions WordPress already made for unrelated privileged actions, which allows unauthenticated users to change the password of, escalate to Administrator, or delete any account whose user ID happens to match the ID of one of the Events Manager  WordPress plugin before 7.4.1's own posts.

- [https://github.com/ghostpels/CVE-2026-18366](https://github.com/ghostpels/CVE-2026-18366) :  ![starts](https://img.shields.io/github/stars/ghostpels/CVE-2026-18366.svg) ![forks](https://img.shields.io/github/forks/ghostpels/CVE-2026-18366.svg)


## CVE-2026-18315
 The TrueBooker – Appointment Booking and Scheduler System plugin for WordPress is vulnerable to Authorization Bypass Through User-Controlled Key leading to Account Takeover in all versions up to, and including, 1.2.6. This is due to the admin_user_create_cus AJAX handler lacking any authentication or capability check before passing the attacker-supplied truebooker_wp_user_id parameter directly to wp_update_user. This makes it possible for unauthenticated attackers to overwrite the email address of any WordPress user — including an administrator — and then complete the standard WordPress lost-password flow to fully take over the targeted account.

- [https://github.com/nastar-id/CVE-2026-18315-PoC](https://github.com/nastar-id/CVE-2026-18315-PoC) :  ![starts](https://img.shields.io/github/stars/nastar-id/CVE-2026-18315-PoC.svg) ![forks](https://img.shields.io/github/forks/nastar-id/CVE-2026-18315-PoC.svg)


## CVE-2026-15706
This issue affects Baylan Smart Meter Management Application (BMS): before v1.1.10.142.

- [https://github.com/musana/CVE-2026-15706](https://github.com/musana/CVE-2026-15706) :  ![starts](https://img.shields.io/github/stars/musana/CVE-2026-15706.svg) ![forks](https://img.shields.io/github/forks/musana/CVE-2026-15706.svg)


## CVE-2026-8181
 The Burst Statistics – Privacy-Friendly WordPress Analytics (Google Analytics Alternative) plugin for WordPress is vulnerable to Authentication Bypass in versions 3.4.0 to 3.4.1.1. This is due to incorrect return-value handling in the `is_mainwp_authenticated()` function when validating application passwords from the Authorization header. This makes it possible for unauthenticated attackers, with knowledge of an administrator username, to impersonate that administrator for the duration of the request by supplying any random Basic Authentication password achieving privilege escalation.

- [https://github.com/0xTerror/CVE-2026-8181](https://github.com/0xTerror/CVE-2026-8181) :  ![starts](https://img.shields.io/github/stars/0xTerror/CVE-2026-8181.svg) ![forks](https://img.shields.io/github/forks/0xTerror/CVE-2026-8181.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/OneDemobird/copy-fail-CVE-2026-31431-pythonlower3.10](https://github.com/OneDemobird/copy-fail-CVE-2026-31431-pythonlower3.10) :  ![starts](https://img.shields.io/github/stars/OneDemobird/copy-fail-CVE-2026-31431-pythonlower3.10.svg) ![forks](https://img.shields.io/github/forks/OneDemobird/copy-fail-CVE-2026-31431-pythonlower3.10.svg)


## CVE-2026-2796
 JIT miscompilation in the JavaScript: WebAssembly component. This vulnerability was fixed in Firefox 148 and Thunderbird 148.

- [https://github.com/SneakyNachos/CVE-2026-2796-escape-wasm-by-using-wasm](https://github.com/SneakyNachos/CVE-2026-2796-escape-wasm-by-using-wasm) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-2796-escape-wasm-by-using-wasm.svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-2796-escape-wasm-by-using-wasm.svg)
- [https://github.com/SneakyNachos/CVE-2026-2796-and-CVE-2026-2768-escape-the-wasm-box](https://github.com/SneakyNachos/CVE-2026-2796-and-CVE-2026-2768-escape-the-wasm-box) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-2796-and-CVE-2026-2768-escape-the-wasm-box.svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-2796-and-CVE-2026-2768-escape-the-wasm-box.svg)


## CVE-2026-2768
 Sandbox escape in the Storage: IndexedDB component. This vulnerability was fixed in Firefox 148, Firefox ESR 140.8, Thunderbird 148, and Thunderbird 140.8.

- [https://github.com/SneakyNachos/CVE-2026-2796-and-CVE-2026-2768-escape-the-wasm-box](https://github.com/SneakyNachos/CVE-2026-2796-and-CVE-2026-2768-escape-the-wasm-box) :  ![starts](https://img.shields.io/github/stars/SneakyNachos/CVE-2026-2796-and-CVE-2026-2768-escape-the-wasm-box.svg) ![forks](https://img.shields.io/github/forks/SneakyNachos/CVE-2026-2796-and-CVE-2026-2768-escape-the-wasm-box.svg)


## CVE-2026-2413
 The Ally – Web Accessibility & Usability plugin for WordPress is vulnerable to SQL Injection via the URL path in all versions up to, and including, 4.0.3. This is due to insufficient escaping on the user-supplied URL parameter in the `get_global_remediations()` method, where it is directly concatenated into an SQL JOIN clause without proper sanitization for SQL context. While `esc_url_raw()` is applied for URL safety, it does not prevent SQL metacharacters (single quotes, parentheses) from being injected. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database via time-based blind SQL injection techniques. The Remediation module must be active, which requires the plugin to be connected to an Elementor account.

- [https://github.com/RandomRobbieBF/CVE-2026-2413](https://github.com/RandomRobbieBF/CVE-2026-2413) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2026-2413.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2026-2413.svg)


## CVE-2026-0300
Prisma Access, Cloud NGFW and Panorama appliances are not impacted by this vulnerability.

- [https://github.com/matad0r-maghribi/CVE-2026-0300-PANOS](https://github.com/matad0r-maghribi/CVE-2026-0300-PANOS) :  ![starts](https://img.shields.io/github/stars/matad0r-maghribi/CVE-2026-0300-PANOS.svg) ![forks](https://img.shields.io/github/forks/matad0r-maghribi/CVE-2026-0300-PANOS.svg)


## CVE-2025-68999
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in HappyMonster Happy Addons for Elementor happy-elementor-addons allows Blind SQL Injection.This issue affects Happy Addons for Elementor: from n/a through = 3.20.4.

- [https://github.com/pipo-cyber/CVE-2025-68999-POC](https://github.com/pipo-cyber/CVE-2025-68999-POC) :  ![starts](https://img.shields.io/github/stars/pipo-cyber/CVE-2025-68999-POC.svg) ![forks](https://img.shields.io/github/forks/pipo-cyber/CVE-2025-68999-POC.svg)


## CVE-2025-67923
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Crocoblock JetEngine jet-engine allows Reflected XSS.This issue affects JetEngine: from n/a through = 3.7.7.

- [https://github.com/RandomRobbieBF/CVE-2025-67923](https://github.com/RandomRobbieBF/CVE-2025-67923) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-67923.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-67923.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/anxs3c/GhostlinkWriteup](https://github.com/anxs3c/GhostlinkWriteup) :  ![starts](https://img.shields.io/github/stars/anxs3c/GhostlinkWriteup.svg) ![forks](https://img.shields.io/github/forks/anxs3c/GhostlinkWriteup.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)


## CVE-2024-4947
 Type Confusion in V8 in Google Chrome prior to 125.0.6422.60 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/l1m3syc/CVE-2024-4947-PoC](https://github.com/l1m3syc/CVE-2024-4947-PoC) :  ![starts](https://img.shields.io/github/stars/l1m3syc/CVE-2024-4947-PoC.svg) ![forks](https://img.shields.io/github/forks/l1m3syc/CVE-2024-4947-PoC.svg)


## CVE-2023-35788
 An issue was discovered in fl_set_geneve_opt in net/sched/cls_flower.c in the Linux kernel before 6.3.7. It allows an out-of-bounds write in the flower classifier code via TCA_FLOWER_KEY_ENC_OPTS_GENEVE packets. This may result in denial of service or privilege escalation.

- [https://github.com/lanleft/cve-2023-35788](https://github.com/lanleft/cve-2023-35788) :  ![starts](https://img.shields.io/github/stars/lanleft/cve-2023-35788.svg) ![forks](https://img.shields.io/github/forks/lanleft/cve-2023-35788.svg)


## CVE-2023-1281
This issue affects Linux Kernel: from 4.14 before git commit ee059170b1f7e94e55fa6cadee544e176a6e59c2.

- [https://github.com/lanleft/CVE-2023-1281](https://github.com/lanleft/CVE-2023-1281) :  ![starts](https://img.shields.io/github/stars/lanleft/CVE-2023-1281.svg) ![forks](https://img.shields.io/github/forks/lanleft/CVE-2023-1281.svg)


## CVE-2022-36804
 Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request. This vulnerability was reported via our Bug Bounty Program by TheGrandPew.

- [https://github.com/Junohea/cve-2022-36804](https://github.com/Junohea/cve-2022-36804) :  ![starts](https://img.shields.io/github/stars/Junohea/cve-2022-36804.svg) ![forks](https://img.shields.io/github/forks/Junohea/cve-2022-36804.svg)


## CVE-2022-2586
 It was discovered that a nft object or expression could reference a nft set on a different nft table, leading to a use-after-free once that table was deleted.

- [https://github.com/lanleft/CVE-2022-2586](https://github.com/lanleft/CVE-2022-2586) :  ![starts](https://img.shields.io/github/stars/lanleft/CVE-2022-2586.svg) ![forks](https://img.shields.io/github/forks/lanleft/CVE-2022-2586.svg)


## CVE-2022-0824
 Improper Access Control to Remote Code Execution in GitHub repository webmin/webmin prior to 1.990.

- [https://github.com/raviprajapati-it/internal-network-penetration-testing](https://github.com/raviprajapati-it/internal-network-penetration-testing) :  ![starts](https://img.shields.io/github/stars/raviprajapati-it/internal-network-penetration-testing.svg) ![forks](https://img.shields.io/github/forks/raviprajapati-it/internal-network-penetration-testing.svg)


## CVE-2021-41733
 Oppia 3.1.4 does not verify that certain URLs are valid before navigating to them.

- [https://github.com/nehaka02/564-Final-Project](https://github.com/nehaka02/564-Final-Project) :  ![starts](https://img.shields.io/github/stars/nehaka02/564-Final-Project.svg) ![forks](https://img.shields.io/github/forks/nehaka02/564-Final-Project.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)
- [https://github.com/Super-Binary/cve-2021-44228](https://github.com/Super-Binary/cve-2021-44228) :  ![starts](https://img.shields.io/github/stars/Super-Binary/cve-2021-44228.svg) ![forks](https://img.shields.io/github/forks/Super-Binary/cve-2021-44228.svg)


## CVE-2018-7600
 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations.

- [https://github.com/elkhaoudari/CVE-2018-7600-PoC](https://github.com/elkhaoudari/CVE-2018-7600-PoC) :  ![starts](https://img.shields.io/github/stars/elkhaoudari/CVE-2018-7600-PoC.svg) ![forks](https://img.shields.io/github/forks/elkhaoudari/CVE-2018-7600-PoC.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Stacyy-Were/CVE-2011-2523](https://github.com/Stacyy-Were/CVE-2011-2523) :  ![starts](https://img.shields.io/github/stars/Stacyy-Were/CVE-2011-2523.svg) ![forks](https://img.shields.io/github/forks/Stacyy-Were/CVE-2011-2523.svg)


## CVE-2010-2075
 UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.

- [https://github.com/Elazab2005/unrealircd-backdoor-pentest-report](https://github.com/Elazab2005/unrealircd-backdoor-pentest-report) :  ![starts](https://img.shields.io/github/stars/Elazab2005/unrealircd-backdoor-pentest-report.svg) ![forks](https://img.shields.io/github/forks/Elazab2005/unrealircd-backdoor-pentest-report.svg)


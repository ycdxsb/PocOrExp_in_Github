# Update 2026-11-12
## CVE-2026-125757
 mailcow: dockerized before 2026-11 contains a server-side template injection vulnerability that allows domain administrators to execute commands in the shared rspamd container by storing a malicious domain-wide footer. Attackers can embed a Jinja macro with an os.execute default value, rendered by the rspamd MOO_FOOTER prefilter, to read or inject mail for every tenant and disable filtering.

- [https://github.com/Faceless0x7/CVE-2026-125757](https://github.com/Faceless0x7/CVE-2026-125757) :  ![starts](https://img.shields.io/github/stars/Faceless0x7/CVE-2026-125757.svg) ![forks](https://img.shields.io/github/forks/Faceless0x7/CVE-2026-125757.svg)


## CVE-2026-125399
 Fluxion before 6.39 contains an OS command injection vulnerability in the fluxion.sh target scanner, which decodes access point ESSIDs with eval after escaping only single quotes. Attackers within Wi-Fi range can broadcast an access point with a crafted SSID to execute commands as root when the operator scans or selects it.

- [https://github.com/VulnSVNC/CVE-2026-125399](https://github.com/VulnSVNC/CVE-2026-125399) :  ![starts](https://img.shields.io/github/stars/VulnSVNC/CVE-2026-125399.svg) ![forks](https://img.shields.io/github/forks/VulnSVNC/CVE-2026-125399.svg)


## CVE-2026-125394
 FreeRDP before 3.33.0 contains a heap use-after-free vulnerability in update_gdi_patblt(), update_gdi_polygon_cb() and update_gdi_mem3blt() that retain stale brush cache pointers. A malicious RDP server can resend CACHE_BRUSH to the same slot then send PATBLT, causing clients to read freed heap memory, disclosing data or crashing.

- [https://github.com/D7EAD/CVE-2026-125394](https://github.com/D7EAD/CVE-2026-125394) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-125394.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-125394.svg)


## CVE-2026-125350
 Use after free in XML in Google Chrome prior to 157.0.8103.50 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/ashrafzaryouh/CVE-2026-125350](https://github.com/ashrafzaryouh/CVE-2026-125350) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-125350.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-125350.svg)
- [https://github.com/Frostmoon39206/CVE-2026-125350-PoC](https://github.com/Frostmoon39206/CVE-2026-125350-PoC) :  ![starts](https://img.shields.io/github/stars/Frostmoon39206/CVE-2026-125350-PoC.svg) ![forks](https://img.shields.io/github/forks/Frostmoon39206/CVE-2026-125350-PoC.svg)


## CVE-2026-123218
 IBM Aspera Faspex 5.0.0 through 5.0.19 could allow an authorized user to craft a specific message to bypass user authorization and gain full administrative privileges.

- [https://github.com/foxcornlab/faspex-scanner](https://github.com/foxcornlab/faspex-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/faspex-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/faspex-scanner.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/pablocerdeira1/CVE-2026-123158](https://github.com/pablocerdeira1/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/pablocerdeira1/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/pablocerdeira1/CVE-2026-123158.svg)
- [https://github.com/Certbn/CVE-2026-123158-OpenSSH-sshd-SSHhole-sshole-](https://github.com/Certbn/CVE-2026-123158-OpenSSH-sshd-SSHhole-sshole-) :  ![starts](https://img.shields.io/github/stars/Certbn/CVE-2026-123158-OpenSSH-sshd-SSHhole-sshole-.svg) ![forks](https://img.shields.io/github/forks/Certbn/CVE-2026-123158-OpenSSH-sshd-SSHhole-sshole-.svg)


## CVE-2026-119977
 WordPress Core is vulnerable to Remote Code Execution in versions 4.7 through 7.1.3. This is due to predictable, web-accessible staging paths used during full-package core upgrades. This makes it possible for unauthenticated attackers to execute code on the server during the upgrade window.

- [https://github.com/BlackHatExploitation/CVE-2026-119977](https://github.com/BlackHatExploitation/CVE-2026-119977) :  ![starts](https://img.shields.io/github/stars/BlackHatExploitation/CVE-2026-119977.svg) ![forks](https://img.shields.io/github/forks/BlackHatExploitation/CVE-2026-119977.svg)


## CVE-2026-119905
 Improper input validation in Windows DNS allows an authorized attacker to perform spoofing over a network.

- [https://github.com/overgrowncarrot1/CVE-2026-119905-DNS-Log-Poisoning-UNC-Path](https://github.com/overgrowncarrot1/CVE-2026-119905-DNS-Log-Poisoning-UNC-Path) :  ![starts](https://img.shields.io/github/stars/overgrowncarrot1/CVE-2026-119905-DNS-Log-Poisoning-UNC-Path.svg) ![forks](https://img.shields.io/github/forks/overgrowncarrot1/CVE-2026-119905-DNS-Log-Poisoning-UNC-Path.svg)


## CVE-2026-116714
 Incorrect authorization in Windows AppX Deployment Service allows an authorized attacker to elevate privileges locally.

- [https://github.com/heluhule/sound-of-system](https://github.com/heluhule/sound-of-system) :  ![starts](https://img.shields.io/github/stars/heluhule/sound-of-system.svg) ![forks](https://img.shields.io/github/forks/heluhule/sound-of-system.svg)


## CVE-2026-116111
 A vulnerability was determined in 2K Games Civilization V 1.0.3.144. Impacted is the function loadstring of the component Lua Sandbox. Executing a manipulation can lead to type confusion. The attack may be performed from remote. The exploit has been publicly disclosed and may be utilized. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/drbloop2000/Sid-Meier-s-Civilization-V-RCE](https://github.com/drbloop2000/Sid-Meier-s-Civilization-V-RCE) :  ![starts](https://img.shields.io/github/stars/drbloop2000/Sid-Meier-s-Civilization-V-RCE.svg) ![forks](https://img.shields.io/github/forks/drbloop2000/Sid-Meier-s-Civilization-V-RCE.svg)


## CVE-2026-114656
 Traefik before 2.11.58 and 3.7.13 contains an authentication bypass vulnerability that allows unauthenticated clients to skip client-certificate checks because negated Host matchers are counted as served domains. Attackers can reach backends protected by RequireAndVerifyClientCert when a router rule with !Host() creates a TLS options conflict that falls back to the default options.

- [https://github.com/fixedbyreboot/CVE-2026-114656-POC](https://github.com/fixedbyreboot/CVE-2026-114656-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-114656-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-114656-POC.svg)


## CVE-2026-110469
This issue has been fixed in version 2.5.

- [https://github.com/im0xfay/CVE-2026-110468-110469-WIDZIALNI](https://github.com/im0xfay/CVE-2026-110468-110469-WIDZIALNI) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-110468-110469-WIDZIALNI.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-110468-110469-WIDZIALNI.svg)


## CVE-2026-110468
This issue has been fixed in version 2.5.

- [https://github.com/im0xfay/CVE-2026-110468-110469-WIDZIALNI](https://github.com/im0xfay/CVE-2026-110468-110469-WIDZIALNI) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-110468-110469-WIDZIALNI.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-110468-110469-WIDZIALNI.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/Galeax/PHP2Shell-Mitigations](https://github.com/Galeax/PHP2Shell-Mitigations) :  ![starts](https://img.shields.io/github/stars/Galeax/PHP2Shell-Mitigations.svg) ![forks](https://img.shields.io/github/forks/Galeax/PHP2Shell-Mitigations.svg)


## CVE-2026-105761
 Dify is an open-source LLM app development platform. Prior to 1.16.0, the PUT /console/api/apps/&lt;app_id&gt;/server endpoint in api/controllers/console/app/mcp_server.py used AppMCPServerController.put() to retrieve an AppMCPServer by the client-supplied server ID without verifying that the server belonged to the requested application and tenant. An authenticated workspace member could therefore change another application's MCP server status and parameters, potentially redirecting data or disabling the service. This issue is fixed in version 1.16.0.

- [https://github.com/JHC56/CVE-2026-105761](https://github.com/JHC56/CVE-2026-105761) :  ![starts](https://img.shields.io/github/stars/JHC56/CVE-2026-105761.svg) ![forks](https://img.shields.io/github/forks/JHC56/CVE-2026-105761.svg)


## CVE-2026-104711
Users are recommended to upgrade to version 6.12.0 or 7.4.0, which fixes the issue.

- [https://github.com/fixedbyreboot/CVE-2026-104711-POC](https://github.com/fixedbyreboot/CVE-2026-104711-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-104711-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-104711-POC.svg)


## CVE-2026-100204
 Use after free in HEIF Image Extensions allows an unauthorized attacker to execute code locally.

- [https://github.com/OntologicallyGood/property-damage](https://github.com/OntologicallyGood/property-damage) :  ![starts](https://img.shields.io/github/stars/OntologicallyGood/property-damage.svg) ![forks](https://img.shields.io/github/forks/OntologicallyGood/property-damage.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/ylh440104/cve-2026-98432-chain](https://github.com/ylh440104/cve-2026-98432-chain) :  ![starts](https://img.shields.io/github/stars/ylh440104/cve-2026-98432-chain.svg) ![forks](https://img.shields.io/github/forks/ylh440104/cve-2026-98432-chain.svg)
- [https://github.com/zake1god/CVE-2026-98432](https://github.com/zake1god/CVE-2026-98432) :  ![starts](https://img.shields.io/github/stars/zake1god/CVE-2026-98432.svg) ![forks](https://img.shields.io/github/forks/zake1god/CVE-2026-98432.svg)


## CVE-2026-98276
to keep the common case lockless.

- [https://github.com/ahamedr08/CVE-2026-98276-Linux-kernel-UDP-socket-flaw-](https://github.com/ahamedr08/CVE-2026-98276-Linux-kernel-UDP-socket-flaw-) :  ![starts](https://img.shields.io/github/stars/ahamedr08/CVE-2026-98276-Linux-kernel-UDP-socket-flaw-.svg) ![forks](https://img.shields.io/github/forks/ahamedr08/CVE-2026-98276-Linux-kernel-UDP-socket-flaw-.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/AwesomeHyper/HyperBreak](https://github.com/AwesomeHyper/HyperBreak) :  ![starts](https://img.shields.io/github/stars/AwesomeHyper/HyperBreak.svg) ![forks](https://img.shields.io/github/forks/AwesomeHyper/HyperBreak.svg)
- [https://github.com/jonrazta89/timertest](https://github.com/jonrazta89/timertest) :  ![starts](https://img.shields.io/github/stars/jonrazta89/timertest.svg) ![forks](https://img.shields.io/github/forks/jonrazta89/timertest.svg)
- [https://github.com/orumanayurpanjayat-ux/SamTimer](https://github.com/orumanayurpanjayat-ux/SamTimer) :  ![starts](https://img.shields.io/github/stars/orumanayurpanjayat-ux/SamTimer.svg) ![forks](https://img.shields.io/github/forks/orumanayurpanjayat-ux/SamTimer.svg)


## CVE-2026-97799
 Improper verification of cryptographic signature in Windows Audio Service allows an authorized attacker to elevate privileges locally.

- [https://github.com/heluhule/sound-of-system](https://github.com/heluhule/sound-of-system) :  ![starts](https://img.shields.io/github/stars/heluhule/sound-of-system.svg) ![forks](https://img.shields.io/github/forks/heluhule/sound-of-system.svg)


## CVE-2026-96652
 Plex Media Server before 1.43.3.10861 allows SSRF via '/player/timeline'. An attacker using any X-Plex-Token value can include a full URL in the 'protocol' parameter and force the Plex server to POST to the attacker's chosen destination.

- [https://github.com/SHIFox8/plex2shell-audit](https://github.com/SHIFox8/plex2shell-audit) :  ![starts](https://img.shields.io/github/stars/SHIFox8/plex2shell-audit.svg) ![forks](https://img.shields.io/github/forks/SHIFox8/plex2shell-audit.svg)


## CVE-2026-92414
Users are recommended to upgrade to versions 2.23.6, 2.22.5, or 2.20.18 which fix the issue.

- [https://github.com/fixedbyreboot/CVE-2026-92414-POC](https://github.com/fixedbyreboot/CVE-2026-92414-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-92414-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-92414-POC.svg)


## CVE-2026-90436
As Axis 1 has been EOL we recommend you migrate to a different SOAP engine, such as Apache Axis 2/Java. Alternatively you could use a build of Axis with the patch from https://github.com/apache/axis-axis1-java/commit/41f3b4e8d04e310ca81f86b92630ab2c11d608bd applied. The Apache Axis project does not expect to create an Axis 1.x release fixing this problem.

- [https://github.com/fixedbyreboot/CVE-2026-90436-POC](https://github.com/fixedbyreboot/CVE-2026-90436-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-90436-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-90436-POC.svg)


## CVE-2026-89052
Successful exploitation may allow unauthorized disclosure of sensitive information, including administrative credentials.

- [https://github.com/sergioamsilva/CVE-2026-89052-archer-c6-aes](https://github.com/sergioamsilva/CVE-2026-89052-archer-c6-aes) :  ![starts](https://img.shields.io/github/stars/sergioamsilva/CVE-2026-89052-archer-c6-aes.svg) ![forks](https://img.shields.io/github/forks/sergioamsilva/CVE-2026-89052-archer-c6-aes.svg)


## CVE-2026-86829
 Apache Airflow's scheduler fully deserializes XCom values written by task code while evaluating task dependencies. A Dag author, who controls what a task writes to XCom, therefore controls data that is deserialized inside the scheduler process - a context the Airflow security model reserves for code installed by the Deployment Manager, above the worker-scoped execution capability a Dag author is documented to have. Deployments that treat Dag authors as less trusted than Deployment Managers are affected, and the scheduler must be evaluating a task dependency that reads a task-written XCom value. Users of apache-airflow are recommended to upgrade to version 3.4.0 or later, which restricts dependency evaluation to primitive XCom values.

- [https://github.com/googlesky/CVE-2026-86829](https://github.com/googlesky/CVE-2026-86829) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-86829.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-86829.svg)


## CVE-2026-81963
 Improper link resolution before file access ('link following') in Windows Update Stack allows an authorized attacker to elevate privileges locally.

- [https://github.com/BarwSirati/CVE-2026-81963-TrustedDpx](https://github.com/BarwSirati/CVE-2026-81963-TrustedDpx) :  ![starts](https://img.shields.io/github/stars/BarwSirati/CVE-2026-81963-TrustedDpx.svg) ![forks](https://img.shields.io/github/forks/BarwSirati/CVE-2026-81963-TrustedDpx.svg)


## CVE-2026-76844
 zlib 1.2.11 through 1.3.2 contains a heap buffer overflow: after an underlying write() fails, gz_write() returns without resetting strm.next_in, leaving it pointed at the caller's buffer. A later gz* write call then derives a position from the stale pointer and writes past a heap allocation; any write() failure reaches it, including EPIPE on a blocking descriptor, and in versions before 1.3.1.2 the failed write must be followed by a gzclearerr() call.

- [https://github.com/perplexedyawdie/cve-2026-76844-lab](https://github.com/perplexedyawdie/cve-2026-76844-lab) :  ![starts](https://img.shields.io/github/stars/perplexedyawdie/cve-2026-76844-lab.svg) ![forks](https://img.shields.io/github/forks/perplexedyawdie/cve-2026-76844-lab.svg)


## CVE-2026-73665
 FreePBX is an open source IP PBX. Prior to 17.0.9, the UCP Node server on ports 8001 and 8003 uses io.use(checkAuth) in node/lib/server.js, but Socket.IO version 4 applies that middleware only to the default namespace. An unauthenticated client can connect to custom namespaces that do not consistently invoke checkAuth in node/lib/auth.js and send crafted event values containing carriage-return or newline characters through the Asterisk Manager Interface action path patched by node/lib/asterisk-manager-patch.js, allowing arbitrary commands to execute as the asterisk service user. This issue is fixed in version 17.0.9.

- [https://github.com/fixedbyreboot/CVE-2026-73665-POC](https://github.com/fixedbyreboot/CVE-2026-73665-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-73665-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-73665-POC.svg)


## CVE-2026-73663
 FreePBX is an open source IP PBX. From 16.0.0 until 16.0.11 and 17.0.4, the FreePBX missedcall module places the inbound Caller ID name from crafted SIP From headers into the missedcalllog INSERT in agi-bin/missedcallnotify.php without escaping or bound parameters. An unauthenticated caller can inject SQL when a monitored extension goes unanswered, corrupting the database and modifying FreePBX administrator accounts to obtain unauthorized remote access. This issue is fixed in versions 16.0.11 and 17.0.4.

- [https://github.com/fixedbyreboot/CVE-2026-73663-POC](https://github.com/fixedbyreboot/CVE-2026-73663-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-73663-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-73663-POC.svg)


## CVE-2026-73373
 Joomla! Core - [20260810] - Unrestricted uploads of SHTML files in Joomla 1.0.0-5.4.7, 6.0.0-6.1.2 - The default list of dangerous files did not include SHTML files. On servers that executed these files, that could lead to code execution.

- [https://github.com/fixedbyreboot/CVE-2026-73373-POC](https://github.com/fixedbyreboot/CVE-2026-73373-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-73373-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-73373-POC.svg)


## CVE-2026-68524
Users are recommended to upgrade to version 24.09.08, which fixes the issue.

- [https://github.com/fixedbyreboot/CVE-2026-68524-POC](https://github.com/fixedbyreboot/CVE-2026-68524-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-68524-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-68524-POC.svg)


## CVE-2026-66738
 SPIP before 4.4.18 contains a code injection vulnerability in SQLite-backed installations. The navigation menu endpoint improperly handles array-typed user input, which bypasses input sanitization and allows the value to break out of an internal quoted string context when evaluated as PHP. An authenticated attacker with at minimum editor (redacteur) privileges can submit a single crafted GET request to /ecrire/?exec=navigation to execute arbitrary OS commands in the web server process. MySQL-backed installations are not affected.

- [https://github.com/fixedbyreboot/CVE-2026-66738-POC](https://github.com/fixedbyreboot/CVE-2026-66738-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-66738-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-66738-POC.svg)


## CVE-2026-66613
 Unauthenticated Remote Code Execution (RCE) in JetEngine = 3.8.14 versions.

- [https://github.com/aramosf/CVE-2026-66613](https://github.com/aramosf/CVE-2026-66613) :  ![starts](https://img.shields.io/github/stars/aramosf/CVE-2026-66613.svg) ![forks](https://img.shields.io/github/forks/aramosf/CVE-2026-66613.svg)


## CVE-2026-65400
 An authentication issue was addressed with improved state management. This issue is fixed in macOS Golden Gate 27, macOS Sequoia 15.7.9, macOS Sonoma 14.8.9, macOS Tahoe 26.6.1, macOS Tahoe 26.7. An attacker on the network may be able to authenticate to Screen Sharing without valid credentials.

- [https://github.com/mrraylau321/cve-2026-65400-mac-check](https://github.com/mrraylau321/cve-2026-65400-mac-check) :  ![starts](https://img.shields.io/github/stars/mrraylau321/cve-2026-65400-mac-check.svg) ![forks](https://img.shields.io/github/forks/mrraylau321/cve-2026-65400-mac-check.svg)


## CVE-2026-58882
 In decodeWapPdu of WapPushOverSms.java, there is a possible out of bounds read due to an integer overflow. This could lead to a remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/januththedev/SMS-Of-Death-CVE-2026-58882-Fix](https://github.com/januththedev/SMS-Of-Death-CVE-2026-58882-Fix) :  ![starts](https://img.shields.io/github/stars/januththedev/SMS-Of-Death-CVE-2026-58882-Fix.svg) ![forks](https://img.shields.io/github/forks/januththedev/SMS-Of-Death-CVE-2026-58882-Fix.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/q181555/pd2232-dirtyfrag](https://github.com/q181555/pd2232-dirtyfrag) :  ![starts](https://img.shields.io/github/stars/q181555/pd2232-dirtyfrag.svg) ![forks](https://img.shields.io/github/forks/q181555/pd2232-dirtyfrag.svg)


## CVE-2026-32475
This issue affects Elementor Pro: from n/a through 4.2.1.

- [https://github.com/tenderacer-lgtm/cve-32475-lab](https://github.com/tenderacer-lgtm/cve-32475-lab) :  ![starts](https://img.shields.io/github/stars/tenderacer-lgtm/cve-32475-lab.svg) ![forks](https://img.shields.io/github/forks/tenderacer-lgtm/cve-32475-lab.svg)


## CVE-2026-26119
 Improper authentication in Windows Admin Center allows an authorized attacker to elevate privileges over a network.

- [https://github.com/csdovah/vuln-cve-2026-26119](https://github.com/csdovah/vuln-cve-2026-26119) :  ![starts](https://img.shields.io/github/stars/csdovah/vuln-cve-2026-26119.svg) ![forks](https://img.shields.io/github/forks/csdovah/vuln-cve-2026-26119.svg)


## CVE-2026-11800
 A flaw was found in Keycloak. This JWT algorithm confusion vulnerability in the JWT Authorization Grant flow allows an attacker with valid client credentials to bypass signature verification. By forging an assertion, the attacker can create unauthorized access tokens. This enables the attacker to impersonate any federated user linked to the affected Identity Provider, leading to unauthorized access and potential privilege escalation.

- [https://github.com/sickwell/CVE-2026-11800](https://github.com/sickwell/CVE-2026-11800) :  ![starts](https://img.shields.io/github/stars/sickwell/CVE-2026-11800.svg) ![forks](https://img.shields.io/github/forks/sickwell/CVE-2026-11800.svg)
- [https://github.com/fixedbyreboot/CVE-2026-11800-POC](https://github.com/fixedbyreboot/CVE-2026-11800-POC) :  ![starts](https://img.shields.io/github/stars/fixedbyreboot/CVE-2026-11800-POC.svg) ![forks](https://img.shields.io/github/forks/fixedbyreboot/CVE-2026-11800-POC.svg)


## CVE-2026-11701
 Inappropriate implementation in Guest View in Google Chrome prior to 149.0.7827.103 allowed a remote attacker to perform UI spoofing via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/esecforte/PoC_CVE-2026-117017](https://github.com/esecforte/PoC_CVE-2026-117017) :  ![starts](https://img.shields.io/github/stars/esecforte/PoC_CVE-2026-117017.svg) ![forks](https://img.shields.io/github/forks/esecforte/PoC_CVE-2026-117017.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619](https://github.com/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/xaviware/go-php2shell-scanner-CVE-2026-109618-CVE-2026-109619.svg)
- [https://github.com/axon003/php-legacy-cve-2026-109618](https://github.com/axon003/php-legacy-cve-2026-109618) :  ![starts](https://img.shields.io/github/stars/axon003/php-legacy-cve-2026-109618.svg) ![forks](https://img.shields.io/github/forks/axon003/php-legacy-cve-2026-109618.svg)
- [https://github.com/tarasik1000-7/sybersecProject_cve2026.109618](https://github.com/tarasik1000-7/sybersecProject_cve2026.109618) :  ![starts](https://img.shields.io/github/stars/tarasik1000-7/sybersecProject_cve2026.109618.svg) ![forks](https://img.shields.io/github/forks/tarasik1000-7/sybersecProject_cve2026.109618.svg)
- [https://github.com/zhaoboy9692/CVE-2026-109618](https://github.com/zhaoboy9692/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/zhaoboy9692/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/zhaoboy9692/CVE-2026-109618.svg)


## CVE-2026-6735
 In PHP versions 8.2.* before 8.2.31, 8.3.* before 8.3.31, 8.4.* before 8.4.21, 8.5.* before 8.5.6, due to improper sanitation of user data, it allows an attacker to compose an URL, which will cause the target to execute arbitrary JavaScript code (XSS) on the target's machine when the target is viewing the PHP-FPM status page.

- [https://github.com/Mkathe/Php-vulnerability-CVE-2026-6735](https://github.com/Mkathe/Php-vulnerability-CVE-2026-6735) :  ![starts](https://img.shields.io/github/stars/Mkathe/Php-vulnerability-CVE-2026-6735.svg) ![forks](https://img.shields.io/github/forks/Mkathe/Php-vulnerability-CVE-2026-6735.svg)


## CVE-2026-1254
 The Modula Image Gallery – Photo Grid & Video Gallery plugin for WordPress is vulnerable to authorization bypass in all versions up to, and including, 2.13.6. This is due to the plugin not properly verifying that a user is authorized to modify specific posts before updating them via the REST API. This makes it possible for authenticated attackers, with contributor level access and above, to update the title, excerpt, and content of arbitrary posts by passing post IDs in the modulaImages field when editing a gallery.

- [https://github.com/kanokwut/CVE-2026-125439-poc](https://github.com/kanokwut/CVE-2026-125439-poc) :  ![starts](https://img.shields.io/github/stars/kanokwut/CVE-2026-125439-poc.svg) ![forks](https://img.shields.io/github/forks/kanokwut/CVE-2026-125439-poc.svg)


## CVE-2026-1210
 The Happy Addons for Elementor plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the '_elementor_data' meta field in all versions up to, and including, 3.20.7 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/elmobp/finder2fullsend-cve-1970-01](https://github.com/elmobp/finder2fullsend-cve-1970-01) :  ![starts](https://img.shields.io/github/stars/elmobp/finder2fullsend-cve-1970-01.svg) ![forks](https://img.shields.io/github/forks/elmobp/finder2fullsend-cve-1970-01.svg)
- [https://github.com/elmobp/cmd2pshell-cve-2026-1210](https://github.com/elmobp/cmd2pshell-cve-2026-1210) :  ![starts](https://img.shields.io/github/stars/elmobp/cmd2pshell-cve-2026-1210.svg) ![forks](https://img.shields.io/github/forks/elmobp/cmd2pshell-cve-2026-1210.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/MorphingYU/CVE-2026-109618](https://github.com/MorphingYU/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/MorphingYU/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/MorphingYU/CVE-2026-109618.svg)
- [https://github.com/santihabib/CVE-2026-109619](https://github.com/santihabib/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/santihabib/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/santihabib/CVE-2026-109619.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)


## CVE-2025-54136
 Cursor is a code editor built for programming with AI. In versions 1.2.4 and below, attackers can achieve remote and persistent code execution by modifying an already trusted MCP configuration file inside a shared GitHub repository or editing the file locally on the target's machine. Once a collaborator accepts a harmless MCP, the attacker can silently swap it for a malicious command (e.g., calc.exe) without triggering any warning or re-prompt. If an attacker has write permissions on a user's active branches of a source repository that contains existing MCP servers the user has previously approved, or allows an attacker has arbitrary file-write locally, the attacker can achieve arbitrary code execution. This is fixed in version 1.3.

- [https://github.com/glebgorelikov-droid/agentgate](https://github.com/glebgorelikov-droid/agentgate) :  ![starts](https://img.shields.io/github/stars/glebgorelikov-droid/agentgate.svg) ![forks](https://img.shields.io/github/forks/glebgorelikov-droid/agentgate.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/elkhaoudari/CVE-2025-29927-Python](https://github.com/elkhaoudari/CVE-2025-29927-Python) :  ![starts](https://img.shields.io/github/stars/elkhaoudari/CVE-2025-29927-Python.svg) ![forks](https://img.shields.io/github/forks/elkhaoudari/CVE-2025-29927-Python.svg)


## CVE-2025-10891
 Integer overflow in V8 in Google Chrome prior to 140.0.7339.207 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/hakaioffsec/cve-2025-10891-samsung-uxss](https://github.com/hakaioffsec/cve-2025-10891-samsung-uxss) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/cve-2025-10891-samsung-uxss.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/cve-2025-10891-samsung-uxss.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)


## CVE-2025-6020
 A flaw was found in linux-pam. The module pam_namespace may use access user-controlled paths without proper protection, allowing local users to elevate their privileges to root via multiple symlink attacks and race conditions.

- [https://github.com/knoxoxen/CVE-2025-6020-upstream-fix](https://github.com/knoxoxen/CVE-2025-6020-upstream-fix) :  ![starts](https://img.shields.io/github/stars/knoxoxen/CVE-2025-6020-upstream-fix.svg) ![forks](https://img.shields.io/github/forks/knoxoxen/CVE-2025-6020-upstream-fix.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/ticofookfook/poc-nextjs-CVE-2025-29927](https://github.com/ticofookfook/poc-nextjs-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/ticofookfook/poc-nextjs-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/ticofookfook/poc-nextjs-CVE-2025-29927.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/dundun93/cve_2025_1974_poc](https://github.com/dundun93/cve_2025_1974_poc) :  ![starts](https://img.shields.io/github/stars/dundun93/cve_2025_1974_poc.svg) ![forks](https://img.shields.io/github/forks/dundun93/cve_2025_1974_poc.svg)


## CVE-2024-42327
 A non-admin user account on the Zabbix frontend with the default User role, or with any other role that gives API access can exploit this vulnerability. An SQLi exists in the CUser class in the addRelatedObjects function, this function is being called from the CUser.get function which is available for every user who has API access.

- [https://github.com/TheCyberGeek/CVE-2024-42327](https://github.com/TheCyberGeek/CVE-2024-42327) :  ![starts](https://img.shields.io/github/stars/TheCyberGeek/CVE-2024-42327.svg) ![forks](https://img.shields.io/github/forks/TheCyberGeek/CVE-2024-42327.svg)


## CVE-2022-38181
 The Arm Mali GPU kernel driver allows unprivileged users to access freed memory because GPU memory operations are mishandled. This affects Bifrost r0p0 through r38p1, and r39p0; Valhall r19p0 through r38p1, and r39p0; and Midgard r4p0 through r32p0.

- [https://github.com/sber-portal/sberportal-root](https://github.com/sber-portal/sberportal-root) :  ![starts](https://img.shields.io/github/stars/sber-portal/sberportal-root.svg) ![forks](https://img.shields.io/github/forks/sber-portal/sberportal-root.svg)


## CVE-2022-23131
 In the case of instances where the SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor, because a user login stored in the session was not verified. Malicious unauthenticated actor may exploit this issue to escalate privileges and gain admin access to Zabbix Frontend. To perform the attack, SAML authentication is required to be enabled and the actor has to know the username of Zabbix user (or use the guest account, which is disabled by default).

- [https://github.com/0xbara/cve-2022-23131](https://github.com/0xbara/cve-2022-23131) :  ![starts](https://img.shields.io/github/stars/0xbara/cve-2022-23131.svg) ![forks](https://img.shields.io/github/forks/0xbara/cve-2022-23131.svg)


## CVE-2022-3653
 Heap buffer overflow in Vulkan in Google Chrome prior to 107.0.5304.62 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/SpiralBL0CK/VULKAN-RCE-cve-2022-3653](https://github.com/SpiralBL0CK/VULKAN-RCE-cve-2022-3653) :  ![starts](https://img.shields.io/github/stars/SpiralBL0CK/VULKAN-RCE-cve-2022-3653.svg) ![forks](https://img.shields.io/github/forks/SpiralBL0CK/VULKAN-RCE-cve-2022-3653.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/d4ytox/CVE-2021-22205](https://github.com/d4ytox/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/d4ytox/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/d4ytox/CVE-2021-22205.svg)


## CVE-2021-22204
 Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

- [https://github.com/d4ytox/CVE-2021-22205](https://github.com/d4ytox/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/d4ytox/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/d4ytox/CVE-2021-22205.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/zer0qs/CVE-2021-41773](https://github.com/zer0qs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/zer0qs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/zer0qs/CVE-2021-41773.svg)
- [https://github.com/gunzf0x/CVE-2021-41773](https://github.com/gunzf0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2021-41773.svg)


## CVE-2020-13671
 Drupal core does not properly sanitize certain filenames on uploaded files, which can lead to files being interpreted as the incorrect extension and served as the wrong MIME type or executed as PHP for certain hosting configurations. This issue affects: Drupal Drupal Core 9.0 versions prior to 9.0.8, 8.9 versions prior to 8.9.9, 8.8 versions prior to 8.8.11, and 7 versions prior to 7.74.

- [https://github.com/d4ytox/CVE-2020-13671](https://github.com/d4ytox/CVE-2020-13671) :  ![starts](https://img.shields.io/github/stars/d4ytox/CVE-2020-13671.svg) ![forks](https://img.shields.io/github/forks/d4ytox/CVE-2020-13671.svg)


## CVE-2019-13139
 In Docker before 18.09.4, an attacker who is capable of supplying or manipulating the build path for the "docker build" command would be able to gain command execution. An issue exists in the way "docker build" processes remote git URLs, and results in command injection into the underlying "git clone" command, leading to code execution in the context of the user executing the "docker build" command. This occurs because git ref can be misinterpreted as a flag.

- [https://github.com/hakaii59/CVE-2019-13139](https://github.com/hakaii59/CVE-2019-13139) :  ![starts](https://img.shields.io/github/stars/hakaii59/CVE-2019-13139.svg) ![forks](https://img.shields.io/github/forks/hakaii59/CVE-2019-13139.svg)


## CVE-2018-7602
 A remote code execution vulnerability exists within multiple subsystems of Drupal 7.x and 8.x. This potentially allows attackers to exploit multiple attack vectors on a Drupal site, which could result in the site being compromised. This vulnerability is related to Drupal core - Highly critical - Remote Code Execution - SA-CORE-2018-002. Both SA-CORE-2018-002 and this vulnerability are being exploited in the wild.

- [https://github.com/d4ytox/CVE-2018-7602](https://github.com/d4ytox/CVE-2018-7602) :  ![starts](https://img.shields.io/github/stars/d4ytox/CVE-2018-7602.svg) ![forks](https://img.shields.io/github/forks/d4ytox/CVE-2018-7602.svg)


## CVE-2007-2447
 The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

- [https://github.com/xsmorl/samba-usermap-script-exploit](https://github.com/xsmorl/samba-usermap-script-exploit) :  ![starts](https://img.shields.io/github/stars/xsmorl/samba-usermap-script-exploit.svg) ![forks](https://img.shields.io/github/forks/xsmorl/samba-usermap-script-exploit.svg)


# Update 2026-06-05
## CVE-2026-49943
 CZ.NIC BIRD Internet Routing Daemon through 2.19.0 contains a stack-based buffer overflow in the BGP AS_PATH mask matching implementation in nest/a-path.c. The as_path_match() function uses a fixed-size stack array of 2048 + 1 pm_pos entries, while parse_path() expands AS_PATH segments from a received BGP UPDATE without enforcing a corresponding capacity limit. When RFC 8654 BGP Extended Messages are enabled and a BIRD filter evaluates an AS path mask expression such as "bgp_path ~ [= ... =]", an established BGP peer can send a long AS_PATH containing more than 2048 expanded ASNs. This causes parse_path()/as_path_match() to write beyond the fixed stack buffer, resulting in a crash of the daemon. NOTE: reportedly, the Supplier's position is that a fix is not being prioritized because all network operators should already be rejecting routes with unusually long attributes.

- [https://github.com/9Bakabaka/CVE-2026-49943-PoC](https://github.com/9Bakabaka/CVE-2026-49943-PoC) :  ![starts](https://img.shields.io/github/stars/9Bakabaka/CVE-2026-49943-PoC.svg) ![forks](https://img.shields.io/github/forks/9Bakabaka/CVE-2026-49943-PoC.svg)


## CVE-2026-46333
set), and require a proper CAP_SYS_PTRACE capability to override.

- [https://github.com/cumakurt/linuxpi](https://github.com/cumakurt/linuxpi) :  ![starts](https://img.shields.io/github/stars/cumakurt/linuxpi.svg) ![forks](https://img.shields.io/github/forks/cumakurt/linuxpi.svg)


## CVE-2026-46300
bytes into @to's linear data rather than transferring frag descriptors.

- [https://github.com/cumakurt/linuxpi](https://github.com/cumakurt/linuxpi) :  ![starts](https://img.shields.io/github/stars/cumakurt/linuxpi.svg) ![forks](https://img.shields.io/github/forks/cumakurt/linuxpi.svg)
- [https://github.com/1neptune/Fragnesia](https://github.com/1neptune/Fragnesia) :  ![starts](https://img.shields.io/github/stars/1neptune/Fragnesia.svg) ![forks](https://img.shields.io/github/forks/1neptune/Fragnesia.svg)


## CVE-2026-46243
spnego_cred to request the key.

- [https://github.com/cumakurt/linuxpi](https://github.com/cumakurt/linuxpi) :  ![starts](https://img.shields.io/github/stars/cumakurt/linuxpi.svg) ![forks](https://img.shields.io/github/forks/cumakurt/linuxpi.svg)


## CVE-2026-45498
 Microsoft Defender Denial of Service Vulnerability

- [https://github.com/ridhinva/defender-privilege-escalation-scanner](https://github.com/ridhinva/defender-privilege-escalation-scanner) :  ![starts](https://img.shields.io/github/stars/ridhinva/defender-privilege-escalation-scanner.svg) ![forks](https://img.shields.io/github/forks/ridhinva/defender-privilege-escalation-scanner.svg)


## CVE-2026-43500
page_pool RX, GRO).  The OOM/trace handling already in place is reused.

- [https://github.com/cumakurt/linuxpi](https://github.com/cumakurt/linuxpi) :  ![starts](https://img.shields.io/github/stars/cumakurt/linuxpi.svg) ![forks](https://img.shields.io/github/forks/cumakurt/linuxpi.svg)
- [https://github.com/1neptune/DirtyFrag](https://github.com/1neptune/DirtyFrag) :  ![starts](https://img.shields.io/github/stars/1neptune/DirtyFrag.svg) ![forks](https://img.shields.io/github/forks/1neptune/DirtyFrag.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/cumakurt/linuxpi](https://github.com/cumakurt/linuxpi) :  ![starts](https://img.shields.io/github/stars/cumakurt/linuxpi.svg) ![forks](https://img.shields.io/github/forks/cumakurt/linuxpi.svg)
- [https://github.com/1neptune/DirtyFrag](https://github.com/1neptune/DirtyFrag) :  ![starts](https://img.shields.io/github/stars/1neptune/DirtyFrag.svg) ![forks](https://img.shields.io/github/forks/1neptune/DirtyFrag.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, attackers can execute code on systems with Address Space Layout Randomization (ASLR) disabled or when the attacker can bypass ASLR.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/strivepan/Nginx_cve-2026-42945-scanner-gui](https://github.com/strivepan/Nginx_cve-2026-42945-scanner-gui) :  ![starts](https://img.shields.io/github/stars/strivepan/Nginx_cve-2026-42945-scanner-gui.svg) ![forks](https://img.shields.io/github/forks/strivepan/Nginx_cve-2026-42945-scanner-gui.svg)
- [https://github.com/lowilol/CVE-2026-42945-NGINX-Rift-Check-Script](https://github.com/lowilol/CVE-2026-42945-NGINX-Rift-Check-Script) :  ![starts](https://img.shields.io/github/stars/lowilol/CVE-2026-42945-NGINX-Rift-Check-Script.svg) ![forks](https://img.shields.io/github/forks/lowilol/CVE-2026-42945-NGINX-Rift-Check-Script.svg)


## CVE-2026-42208
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From version 1.81.16 to before version 1.83.7, a database query used during proxy API key checks mixed the caller-supplied key value into the query text instead of passing it as a separate parameter. An unauthenticated attacker could send a specially crafted Authorization header to any LLM API route (for example POST /chat/completions) and reach this query through the proxy's error-handling path. An attacker could read data from the proxy's database and may be able to modify it, leading to unauthorised access to the proxy and the credentials it manages. This issue has been patched in version 1.83.7.

- [https://github.com/ridhinva/litellm-sqli-scanner](https://github.com/ridhinva/litellm-sqli-scanner) :  ![starts](https://img.shields.io/github/stars/ridhinva/litellm-sqli-scanner.svg) ![forks](https://img.shields.io/github/forks/ridhinva/litellm-sqli-scanner.svg)


## CVE-2026-41651
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.

- [https://github.com/cumakurt/linuxpi](https://github.com/cumakurt/linuxpi) :  ![starts](https://img.shields.io/github/stars/cumakurt/linuxpi.svg) ![forks](https://img.shields.io/github/forks/cumakurt/linuxpi.svg)


## CVE-2026-41091
 Improper link resolution before file access ('link following') in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/ridhinva/defender-privilege-escalation-scanner](https://github.com/ridhinva/defender-privilege-escalation-scanner) :  ![starts](https://img.shields.io/github/stars/ridhinva/defender-privilege-escalation-scanner.svg) ![forks](https://img.shields.io/github/forks/ridhinva/defender-privilege-escalation-scanner.svg)


## CVE-2026-41089
 Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.

- [https://github.com/hnytgl/CVE-2026-41089](https://github.com/hnytgl/CVE-2026-41089) :  ![starts](https://img.shields.io/github/stars/hnytgl/CVE-2026-41089.svg) ![forks](https://img.shields.io/github/forks/hnytgl/CVE-2026-41089.svg)
- [https://github.com/ADScanPro/CVE-2026-41089-LongLogon](https://github.com/ADScanPro/CVE-2026-41089-LongLogon) :  ![starts](https://img.shields.io/github/stars/ADScanPro/CVE-2026-41089-LongLogon.svg) ![forks](https://img.shields.io/github/forks/ADScanPro/CVE-2026-41089-LongLogon.svg)


## CVE-2026-39107
 A Cross Site Scripting vulnerability exists in the Kimi AI v1.0 web interface's 'Preview' feature. The application fails to properly sanitize or encode HTML/JavaScript payloads generated by the AI model. When a user switches to the 'Preview' tab to view AI-generated code, the malicious payload is rendered directly into the DOM, leading to arbitrary JavaScript execution in the victim's browser session.

- [https://github.com/MGTx2/CVE-2026-39107](https://github.com/MGTx2/CVE-2026-39107) :  ![starts](https://img.shields.io/github/stars/MGTx2/CVE-2026-39107.svg) ![forks](https://img.shields.io/github/forks/MGTx2/CVE-2026-39107.svg)


## CVE-2026-36748
 RockRMS v16.13 and before v.17.7.0 is vulnerable to Cross Site Scripting (XSS) via Social Media links in user profile.

- [https://github.com/rufflabs/CVE-2026-36748](https://github.com/rufflabs/CVE-2026-36748) :  ![starts](https://img.shields.io/github/stars/rufflabs/CVE-2026-36748.svg) ![forks](https://img.shields.io/github/forks/rufflabs/CVE-2026-36748.svg)


## CVE-2026-31802
 node-tar is a full-featured Tar for Node.js. Prior to version 7.5.11, tar (npm) can be tricked into creating a symlink that points outside the extraction directory by using a drive-relative symlink target such as C:../../../target.txt, which enables file overwrite outside cwd during normal tar.x() extraction. This vulnerability is fixed in 7.5.11.

- [https://github.com/ridhinva/npm-tar-path-traversal-scanner](https://github.com/ridhinva/npm-tar-path-traversal-scanner) :  ![starts](https://img.shields.io/github/stars/ridhinva/npm-tar-path-traversal-scanner.svg) ![forks](https://img.shields.io/github/forks/ridhinva/npm-tar-path-traversal-scanner.svg)


## CVE-2026-31635
Reject authenticator lengths that exceed the remaining packet payload.

- [https://github.com/cumakurt/linuxpi](https://github.com/cumakurt/linuxpi) :  ![starts](https://img.shields.io/github/stars/cumakurt/linuxpi.svg) ![forks](https://img.shields.io/github/forks/cumakurt/linuxpi.svg)


## CVE-2026-29198
 In Rocket.Chat 8.3.0, 8.2.1, 8.1.2, 8.0.3, 7.13.5, 7.12.6, 7.11.6, and 7.10.9, a NoSQL injection vulnerability can lead to account takeover of the first user with a generated token when an OAuth app is configured.

- [https://github.com/hieuminhnv/CVE-2026-29198-POC](https://github.com/hieuminhnv/CVE-2026-29198-POC) :  ![starts](https://img.shields.io/github/stars/hieuminhnv/CVE-2026-29198-POC.svg) ![forks](https://img.shields.io/github/forks/hieuminhnv/CVE-2026-29198-POC.svg)


## CVE-2026-28990
 The issue was addressed with improved memory handling. This issue is fixed in iOS 26.5 and iPadOS 26.5, macOS Sequoia 15.7.7, macOS Sonoma 14.8.7, macOS Tahoe 26.5, tvOS 26.5, visionOS 26.5, watchOS 26.5. Processing a maliciously crafted image may corrupt process memory.

- [https://github.com/Billy-Ellis/exr-imageio-poc](https://github.com/Billy-Ellis/exr-imageio-poc) :  ![starts](https://img.shields.io/github/stars/Billy-Ellis/exr-imageio-poc.svg) ![forks](https://img.shields.io/github/forks/Billy-Ellis/exr-imageio-poc.svg)


## CVE-2026-27145
 (*x509.Certificate).VerifyHostname previously called matchHostnames in a loop over all DNS Subject Alternative Name (SAN) entries. This caused strings.Split(host, ".") to execute repeatedly on the same input hostname. With a large DNS SAN list, verification costs scaled quadratically based on the number of SAN entries multiplied by the hostname's label count. Because x509.Verify validates hostnames before building the certificate chain, this overhead occurred even for untrusted certificates.

- [https://github.com/HORKimhab/CVE-2026-27145](https://github.com/HORKimhab/CVE-2026-27145) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-27145.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-27145.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/jf-gondim/mcp-pwn](https://github.com/jf-gondim/mcp-pwn) :  ![starts](https://img.shields.io/github/stars/jf-gondim/mcp-pwn.svg) ![forks](https://img.shields.io/github/forks/jf-gondim/mcp-pwn.svg)


## CVE-2026-10187
 A vulnerability was detected in Totolink N300RH 6.1c.1353_B20190305. Affected by this issue is the function setWiFiBasicConfig of the file wireless.so of the component Web Management Interface. Performing a manipulation of the argument KeyStr results in stack-based buffer overflow. The attack is possible to be carried out remotely. The exploit is now public and may be used.

- [https://github.com/passwa11/CVE-2026-10187](https://github.com/passwa11/CVE-2026-10187) :  ![starts](https://img.shields.io/github/stars/passwa11/CVE-2026-10187.svg) ![forks](https://img.shields.io/github/forks/passwa11/CVE-2026-10187.svg)


## CVE-2026-9256
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/06-ux/CVE-2026-9256-POC](https://github.com/06-ux/CVE-2026-9256-POC) :  ![starts](https://img.shields.io/github/stars/06-ux/CVE-2026-9256-POC.svg) ![forks](https://img.shields.io/github/forks/06-ux/CVE-2026-9256-POC.svg)


## CVE-2026-4997
 A security flaw has been discovered in Sinaptik AI PandasAI up to 3.0.0. This affects the function is_sql_query_safe of the file pandasai/helpers/sql_sanitizer.py. Performing a manipulation results in path traversal. The attack may be initiated remotely. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/fevar54/Proof-of-Concept-POC---CVE-2026-49975-HTTP-2-Bomb-](https://github.com/fevar54/Proof-of-Concept-POC---CVE-2026-49975-HTTP-2-Bomb-) :  ![starts](https://img.shields.io/github/stars/fevar54/Proof-of-Concept-POC---CVE-2026-49975-HTTP-2-Bomb-.svg) ![forks](https://img.shields.io/github/forks/fevar54/Proof-of-Concept-POC---CVE-2026-49975-HTTP-2-Bomb-.svg)


## CVE-2026-4392
 A vulnerability was detected in TeamSpeak 3 Server up to 3.13.7. This issue affects some unknown processing of the component clientek Handshake Handler. Performing a manipulation of the argument proof results in reachable assertion. Remote exploitation of the attack is possible. Upgrading to version 3.13.8 is capable of addressing this issue. Upgrading the affected component is recommended.

- [https://github.com/born0monday/teamspeak3-vulnerabilities](https://github.com/born0monday/teamspeak3-vulnerabilities) :  ![starts](https://img.shields.io/github/stars/born0monday/teamspeak3-vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/born0monday/teamspeak3-vulnerabilities.svg)


## CVE-2026-4391
 A security vulnerability has been detected in TeamSpeak 3 Server up to 3.13.7. This vulnerability affects unknown code of the component ECC Key Parser. Such manipulation leads to heap-based buffer overflow. The attack may be launched remotely. Upgrading to version 3.13.8 is able to resolve this issue. It is suggested to upgrade the affected component.

- [https://github.com/born0monday/teamspeak3-vulnerabilities](https://github.com/born0monday/teamspeak3-vulnerabilities) :  ![starts](https://img.shields.io/github/stars/born0monday/teamspeak3-vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/born0monday/teamspeak3-vulnerabilities.svg)


## CVE-2026-4390
 A weakness has been identified in TeamSpeak 3 Server up to 3.13.7. This affects the function process_resend_queue of the component Connection State Management. This manipulation causes use after free. The attack may be initiated remotely. Upgrading to version 3.13.8 is able to mitigate this issue. The affected component should be upgraded.

- [https://github.com/born0monday/teamspeak3-vulnerabilities](https://github.com/born0monday/teamspeak3-vulnerabilities) :  ![starts](https://img.shields.io/github/stars/born0monday/teamspeak3-vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/born0monday/teamspeak3-vulnerabilities.svg)


## CVE-2026-2689
 A vulnerability was detected in itsourcecode Event Management System 1.0. Affected is an unknown function of the file /admin/manage_booking.php. The manipulation of the argument ID results in sql injection. The attack may be performed from remote. The exploit is now public and may be used.

- [https://github.com/iwallplace/CVE-2026-26899-OpenWrt-Exploit](https://github.com/iwallplace/CVE-2026-26899-OpenWrt-Exploit) :  ![starts](https://img.shields.io/github/stars/iwallplace/CVE-2026-26899-OpenWrt-Exploit.svg) ![forks](https://img.shields.io/github/forks/iwallplace/CVE-2026-26899-OpenWrt-Exploit.svg)
- [https://github.com/iwallplace/CVE-2026-26897-EcoOnline-DeepLink](https://github.com/iwallplace/CVE-2026-26897-EcoOnline-DeepLink) :  ![starts](https://img.shields.io/github/stars/iwallplace/CVE-2026-26897-EcoOnline-DeepLink.svg) ![forks](https://img.shields.io/github/forks/iwallplace/CVE-2026-26897-EcoOnline-DeepLink.svg)
- [https://github.com/iwallplace/CVE-2026-26898-Xiaomi-SSRF-HostHeaderInjection](https://github.com/iwallplace/CVE-2026-26898-Xiaomi-SSRF-HostHeaderInjection) :  ![starts](https://img.shields.io/github/stars/iwallplace/CVE-2026-26898-Xiaomi-SSRF-HostHeaderInjection.svg) ![forks](https://img.shields.io/github/forks/iwallplace/CVE-2026-26898-Xiaomi-SSRF-HostHeaderInjection.svg)


## CVE-2026-2256
 A command injection vulnerability in ModelScope's ms-agent versions v1.6.0rc1 and earlier exists, allowing an attacker to execute arbitrary operating system commands through crafted prompt-derived input.

- [https://github.com/melbratic/CVE-2026-2256-Threat-Model----ms-agent-Command-Injection](https://github.com/melbratic/CVE-2026-2256-Threat-Model----ms-agent-Command-Injection) :  ![starts](https://img.shields.io/github/stars/melbratic/CVE-2026-2256-Threat-Model----ms-agent-Command-Injection.svg) ![forks](https://img.shields.io/github/forks/melbratic/CVE-2026-2256-Threat-Model----ms-agent-Command-Injection.svg)


## CVE-2026-0257
Panorama and Cloud NGFW are not impacted by these issues.

- [https://github.com/tushargurav28/CVE-2026-0257](https://github.com/tushargurav28/CVE-2026-0257) :  ![starts](https://img.shields.io/github/stars/tushargurav28/CVE-2026-0257.svg) ![forks](https://img.shields.io/github/forks/tushargurav28/CVE-2026-0257.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)


## CVE-2025-63389
 A critical authentication bypass vulnerability exists in Ollama platform's API endpoints in versions prior to and including v0.12.3. The platform exposes multiple API endpoints without requiring authentication, enabling remote attackers to perform unauthorized model management operations.

- [https://github.com/nuclide-research/VisorGoose](https://github.com/nuclide-research/VisorGoose) :  ![starts](https://img.shields.io/github/stars/nuclide-research/VisorGoose.svg) ![forks](https://img.shields.io/github/forks/nuclide-research/VisorGoose.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/leehunkoo/hk_CVE-2025-32433](https://github.com/leehunkoo/hk_CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/leehunkoo/hk_CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/leehunkoo/hk_CVE-2025-32433.svg)


## CVE-2024-49375
 Open source machine learning framework. A vulnerability has been identified in Rasa that enables an attacker who has the ability to load a maliciously crafted model remotely into a Rasa instance to achieve Remote Code Execution. The prerequisites for this are: 1. The HTTP API must be enabled on the Rasa instance eg with `--enable-api`. This is not the default configuration. 2. For unauthenticated RCE to be exploitable, the user must not have configured any authentication or other security controls recommended in our documentation. 3. For authenticated RCE, the attacker must posses a valid authentication token or JWT to interact with the Rasa API. This issue has been addressed in rasa version 3.6.21 and all users are advised to upgrade. Users unable to upgrade should ensure that they require authentication and that only trusted users are given access.

- [https://github.com/lierbushiwo/Rasa-cve-exp](https://github.com/lierbushiwo/Rasa-cve-exp) :  ![starts](https://img.shields.io/github/stars/lierbushiwo/Rasa-cve-exp.svg) ![forks](https://img.shields.io/github/forks/lierbushiwo/Rasa-cve-exp.svg)


## CVE-2024-48910
 DOMPurify is a DOM-only, super-fast, uber-tolerant XSS sanitizer for HTML, MathML and SVG. DOMPurify was vulnerable to prototype pollution. This vulnerability is fixed in 2.4.2.

- [https://github.com/Galaxy-sc/CVE-2024-48910-dompurify-xss-detector](https://github.com/Galaxy-sc/CVE-2024-48910-dompurify-xss-detector) :  ![starts](https://img.shields.io/github/stars/Galaxy-sc/CVE-2024-48910-dompurify-xss-detector.svg) ![forks](https://img.shields.io/github/forks/Galaxy-sc/CVE-2024-48910-dompurify-xss-detector.svg)


## CVE-2024-46987
 Camaleon CMS is a dynamic and advanced content management system based on Ruby on Rails. A path traversal vulnerability accessible via MediaController's download_private_file method allows authenticated users to download any file on the web server Camaleon CMS is running on (depending on the file permissions). This issue may lead to Information Disclosure. This issue has been addressed in release version 2.8.2. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/SuriyaBoon/HackTheBox-Facts](https://github.com/SuriyaBoon/HackTheBox-Facts) :  ![starts](https://img.shields.io/github/stars/SuriyaBoon/HackTheBox-Facts.svg) ![forks](https://img.shields.io/github/forks/SuriyaBoon/HackTheBox-Facts.svg)


## CVE-2024-36401
Versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/DanieleGiovanardi2408/cve-2024-36401-geoserver-rce](https://github.com/DanieleGiovanardi2408/cve-2024-36401-geoserver-rce) :  ![starts](https://img.shields.io/github/stars/DanieleGiovanardi2408/cve-2024-36401-geoserver-rce.svg) ![forks](https://img.shields.io/github/forks/DanieleGiovanardi2408/cve-2024-36401-geoserver-rce.svg)


## CVE-2023-32784
 In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, there is different API usage and/or random string insertion for mitigation.

- [https://github.com/areebashoaib42/KeePass-CVE-2023-32784-Exploitation-and-Defense](https://github.com/areebashoaib42/KeePass-CVE-2023-32784-Exploitation-and-Defense) :  ![starts](https://img.shields.io/github/stars/areebashoaib42/KeePass-CVE-2023-32784-Exploitation-and-Defense.svg) ![forks](https://img.shields.io/github/forks/areebashoaib42/KeePass-CVE-2023-32784-Exploitation-and-Defense.svg)


## CVE-2021-42556
 Rasa X before 0.42.4 allows Directory Traversal during archive extraction. In the functionality that allows a user to load a trained model archive, an attacker has arbitrary write capability within specific directories via a crafted archive file.

- [https://github.com/lierbushiwo/Rasa-cve-exp](https://github.com/lierbushiwo/Rasa-cve-exp) :  ![starts](https://img.shields.io/github/stars/lierbushiwo/Rasa-cve-exp.svg) ![forks](https://img.shields.io/github/forks/lierbushiwo/Rasa-cve-exp.svg)


## CVE-2021-41127
 Rasa is an open source machine learning framework to automate text-and voice-based conversations. In affected versions a vulnerability exists in the functionality that loads a trained model `tar.gz` file which allows a malicious actor to craft a `model.tar.gz` file which can overwrite or replace bot files in the bot directory. The vulnerability is fixed in Rasa 2.8.10. For users unable to update ensure that users do not upload untrusted model files, and restrict CLI or API endpoint access where a malicious actor could target a deployed Rasa instance.

- [https://github.com/lierbushiwo/Rasa-cve-exp](https://github.com/lierbushiwo/Rasa-cve-exp) :  ![starts](https://img.shields.io/github/stars/lierbushiwo/Rasa-cve-exp.svg) ![forks](https://img.shields.io/github/forks/lierbushiwo/Rasa-cve-exp.svg)


## CVE-2020-17103
 Windows Cloud Files Mini Filter Driver Elevation of Privilege Vulnerability

- [https://github.com/rfranca777/miniplasma-advisory](https://github.com/rfranca777/miniplasma-advisory) :  ![starts](https://img.shields.io/github/stars/rfranca777/miniplasma-advisory.svg) ![forks](https://img.shields.io/github/forks/rfranca777/miniplasma-advisory.svg)


## CVE-2020-10204
 Sonatype Nexus Repository before 3.21.2 allows Remote Code Execution.

- [https://github.com/am-hotstuff819/cve-watch](https://github.com/am-hotstuff819/cve-watch) :  ![starts](https://img.shields.io/github/stars/am-hotstuff819/cve-watch.svg) ![forks](https://img.shields.io/github/forks/am-hotstuff819/cve-watch.svg)


## CVE-2020-10199
 Sonatype Nexus Repository before 3.21.2 allows JavaEL Injection (issue 1 of 2).

- [https://github.com/am-hotstuff819/cve-watch](https://github.com/am-hotstuff819/cve-watch) :  ![starts](https://img.shields.io/github/stars/am-hotstuff819/cve-watch.svg) ![forks](https://img.shields.io/github/forks/am-hotstuff819/cve-watch.svg)


## CVE-2019-14234
 An issue was discovered in Django 1.11.x before 1.11.23, 2.1.x before 2.1.11, and 2.2.x before 2.2.4. Due to an error in shallow key transformation, key and index lookups for django.contrib.postgres.fields.JSONField, and key lookups for django.contrib.postgres.fields.HStoreField, were subject to SQL injection. This could, for example, be exploited via crafted use of "OR 1=1" in a key or index name to return all records, using a suitably crafted dictionary, with dictionary expansion, as the **kwargs passed to the QuerySet.filter() function.

- [https://github.com/giuliodamico/CVE-2019-14234](https://github.com/giuliodamico/CVE-2019-14234) :  ![starts](https://img.shields.io/github/stars/giuliodamico/CVE-2019-14234.svg) ![forks](https://img.shields.io/github/forks/giuliodamico/CVE-2019-14234.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/Reflyzal106/Cve-2014-Error-What-Is-The-Cve-2014-6271-Bash-Vulnerability](https://github.com/Reflyzal106/Cve-2014-Error-What-Is-The-Cve-2014-6271-Bash-Vulnerability) :  ![starts](https://img.shields.io/github/stars/Reflyzal106/Cve-2014-Error-What-Is-The-Cve-2014-6271-Bash-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/Reflyzal106/Cve-2014-Error-What-Is-The-Cve-2014-6271-Bash-Vulnerability.svg)


## CVE-2013-6117
 Dahua DVR 2.608.0000.0 and 2.608.GV00.0 allows remote attackers to bypass authentication and obtain sensitive information including user credentials, change user passwords, clear log files, and perform other actions via a request to TCP port 37777.

- [https://github.com/fsn4k3/dahua-dvr-metasploit](https://github.com/fsn4k3/dahua-dvr-metasploit) :  ![starts](https://img.shields.io/github/stars/fsn4k3/dahua-dvr-metasploit.svg) ![forks](https://img.shields.io/github/forks/fsn4k3/dahua-dvr-metasploit.svg)


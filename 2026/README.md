## CVE-2026-25546
 Godot MCP is a Model Context Protocol (MCP) server for interacting with the Godot game engine. Prior to version 0.1.1, a command injection vulnerability in godot-mcp allows remote code execution. The executeOperation function passed user-controlled input (e.g., projectPath) directly to exec(), which spawns a shell. An attacker could inject shell metacharacters like $(command) or &calc to execute arbitrary commands with the privileges of the MCP server process. This affects any tool that accepts projectPath, including create_scene, add_node, load_sprite, and others. This issue has been patched in version 0.1.1.



- [https://github.com/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection](https://github.com/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection.svg)

## CVE-2026-25512
 Group-Office is an enterprise customer relationship management and groupware tool. Prior to versions 6.8.150, 25.0.82, and 26.0.5, there is a remote code execution (RCE) vulnerability in Group-Office. The endpoint email/message/tnefAttachmentFromTempFile directly concatenates the user-controlled parameter tmp_file into an exec() call. By injecting shell metacharacters into tmp_file, an authenticated attacker can execute arbitrary system commands on the server. This issue has been patched in versions 6.8.150, 25.0.82, and 26.0.5.



- [https://github.com/NumberOreo1/CVE-2026-25512](https://github.com/NumberOreo1/CVE-2026-25512) :  ![starts](https://img.shields.io/github/stars/NumberOreo1/CVE-2026-25512.svg) ![forks](https://img.shields.io/github/forks/NumberOreo1/CVE-2026-25512.svg)

- [https://github.com/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE](https://github.com/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE.svg)

## CVE-2026-25253
 OpenClaw (aka clawdbot or Moltbot) before 2026.1.29 obtains a gatewayUrl value from a query string and automatically makes a WebSocket connection without prompting, sending a token value.



- [https://github.com/ethiack/moltbot-1click-rce](https://github.com/ethiack/moltbot-1click-rce) :  ![starts](https://img.shields.io/github/stars/ethiack/moltbot-1click-rce.svg) ![forks](https://img.shields.io/github/forks/ethiack/moltbot-1click-rce.svg)

- [https://github.com/adibirzu/openclaw-security-monitor](https://github.com/adibirzu/openclaw-security-monitor) :  ![starts](https://img.shields.io/github/stars/adibirzu/openclaw-security-monitor.svg) ![forks](https://img.shields.io/github/forks/adibirzu/openclaw-security-monitor.svg)

## CVE-2026-25211
 Llama Stack (aka llama-stack) before 0.4.0rc3 does not censor the pgvector password in the initialization log.



- [https://github.com/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211](https://github.com/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211) :  ![starts](https://img.shields.io/github/stars/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211.svg)

## CVE-2026-25130
 Cybersecurity AI (CAI) is a framework for AI Security. In versions up to and including 0.5.10, the CAI (Cybersecurity AI) framework contains multiple argument injection vulnerabilities in its function tools. User-controlled input is passed directly to shell commands via `subprocess.Popen()` with `shell=True`, allowing attackers to execute arbitrary commands on the host system. The `find_file()` tool executes without requiring user approval because find is considered a "safe" pre-approved command. This means an attacker can achieve Remote Code Execution (RCE) by injecting malicious arguments (like -exec) into the args parameter, completely bypassing any human-in-the-loop safety mechanisms. Commit e22a1220f764e2d7cf9da6d6144926f53ca01cde contains a fix.



- [https://github.com/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10](https://github.com/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10.svg)

## CVE-2026-25126
 PolarLearn is a free and open-source learning program. Prior to version 0-PRERELEASE-15, the vote API route (`POST /api/v1/forum/vote`) trusts the JSON body’s `direction` value without runtime validation. TypeScript types are not enforced at runtime, so an attacker can send arbitrary strings (e.g., `"x"`) as `direction`. Downstream (`VoteServer`) treats any non-`"up"` and non-`null` value as a downvote and persists the invalid value in `votes_data`. This can be exploited to bypass intended business logic. Version 0-PRERELEASE-15 fixes the vulnerability.



- [https://github.com/Jvr2022/CVE-2026-25126](https://github.com/Jvr2022/CVE-2026-25126) :  ![starts](https://img.shields.io/github/stars/Jvr2022/CVE-2026-25126.svg) ![forks](https://img.shields.io/github/forks/Jvr2022/CVE-2026-25126.svg)

## CVE-2026-25047
 deepHas provides a test for the existence of a nested object key and optionally returns that key. A prototype pollution vulnerability exists in version 1.0.7 of the deephas npm package that allows an attacker to modify global object behavior. This issue was fixed in version 1.0.8.



- [https://github.com/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-](https://github.com/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-) :  ![starts](https://img.shields.io/github/stars/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-.svg)

## CVE-2026-24858
 An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] vulnerability in Fortinet FortiAnalyzer 7.6.0 through 7.6.5, FortiAnalyzer 7.4.0 through 7.4.9, FortiAnalyzer 7.2.0 through 7.2.11, FortiAnalyzer 7.0.0 through 7.0.15, FortiManager 7.6.0 through 7.6.5, FortiManager 7.4.0 through 7.4.9, FortiManager 7.2.0 through 7.2.11, FortiManager 7.0.0 through 7.0.15, FortiOS 7.6.0 through 7.6.5, FortiOS 7.4.0 through 7.4.10, FortiOS 7.2.0 through 7.2.12, FortiOS 7.0.0 through 7.0.18, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4.0 through 7.4.12, FortiProxy 7.2.0 through 7.2.15, FortiProxy 7.0.0 through 7.0.22, FortiWeb 8.0.0 through 8.0.3, FortiWeb 7.6.0 through 7.6.6, FortiWeb 7.4.0 through 7.4.11 may allow an attacker with a FortiCloud account and a registered device to log into other devices registered to other accounts, if FortiCloud SSO authentication is enabled on those devices.



- [https://github.com/absholi7ly/CVE-2026-24858-FortiCloud-SSO-Authentication-Bypass](https://github.com/absholi7ly/CVE-2026-24858-FortiCloud-SSO-Authentication-Bypass) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2026-24858-FortiCloud-SSO-Authentication-Bypass.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2026-24858-FortiCloud-SSO-Authentication-Bypass.svg)

- [https://github.com/m0d0ri205/CVE-2026-24858](https://github.com/m0d0ri205/CVE-2026-24858) :  ![starts](https://img.shields.io/github/stars/m0d0ri205/CVE-2026-24858.svg) ![forks](https://img.shields.io/github/forks/m0d0ri205/CVE-2026-24858.svg)

- [https://github.com/b1gchoi/CVE-2026-24858](https://github.com/b1gchoi/CVE-2026-24858) :  ![starts](https://img.shields.io/github/stars/b1gchoi/CVE-2026-24858.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/CVE-2026-24858.svg)

- [https://github.com/SimoesCTT/-CTT-NSP-Convergent-Time-Theory---Network-Stack-Projection-CVE-2026-24858-](https://github.com/SimoesCTT/-CTT-NSP-Convergent-Time-Theory---Network-Stack-Projection-CVE-2026-24858-) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/-CTT-NSP-Convergent-Time-Theory---Network-Stack-Projection-CVE-2026-24858-.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/-CTT-NSP-Convergent-Time-Theory---Network-Stack-Projection-CVE-2026-24858-.svg)

- [https://github.com/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity](https://github.com/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity.svg)

## CVE-2026-24854
 ChurchCRM is an open-source church management system. A SQL Injection vulnerability exists in endpoint `/PaddleNumEditor.php` in ChurchCRM prior to version 6.7.2. Any authenticated user, including one with zero assigned permissions, can exploit SQL injection through the `PerID` parameter. Version 6.7.2 contains a patch for the issue.



- [https://github.com/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection](https://github.com/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection.svg)

## CVE-2026-24841
 Dokploy is a free, self-hostable Platform as a Service (PaaS). In versions prior to 0.26.6, a critical command injection vulnerability exists in Dokploy's WebSocket endpoint `/docker-container-terminal`. The `containerId` and `activeWay` parameters are directly interpolated into shell commands without sanitization, allowing authenticated attackers to execute arbitrary commands on the host server. Version 0.26.6 fixes the issue.



- [https://github.com/otakuliu/CVE-2026-24841_Range](https://github.com/otakuliu/CVE-2026-24841_Range) :  ![starts](https://img.shields.io/github/stars/otakuliu/CVE-2026-24841_Range.svg) ![forks](https://img.shields.io/github/forks/otakuliu/CVE-2026-24841_Range.svg)

## CVE-2026-24688
 pypdf is a free and open-source pure-python PDF library. An attacker who uses an infinite loop vulnerability that is present in versions prior to 6.6.2 can craft a PDF which leads to an infinite loop. This requires accessing the outlines/bookmarks. This has been fixed in pypdf 6.6.2. If projects cannot upgrade yet, consider applying the changes from PR #3610 manually.



- [https://github.com/JoakimBulow/CVE-2026-24688](https://github.com/JoakimBulow/CVE-2026-24688) :  ![starts](https://img.shields.io/github/stars/JoakimBulow/CVE-2026-24688.svg) ![forks](https://img.shields.io/github/forks/JoakimBulow/CVE-2026-24688.svg)

## CVE-2026-24423
 SmarterTools SmarterMail versions prior to build 9511 contain an unauthenticated remote code execution vulnerability in the ConnectToHub API method. The attacker could point the SmarterMail to the malicious HTTP server, which serves the malicious OS command. This command will be executed by the vulnerable application.



- [https://github.com/aavamin/CVE-2026-24423](https://github.com/aavamin/CVE-2026-24423) :  ![starts](https://img.shields.io/github/stars/aavamin/CVE-2026-24423.svg) ![forks](https://img.shields.io/github/forks/aavamin/CVE-2026-24423.svg)

## CVE-2026-24306
 Improper access control in Azure Front Door (AFD) allows an unauthorized attacker to elevate privileges over a network.



- [https://github.com/ExploreUnknowed/CVE-2026-24306](https://github.com/ExploreUnknowed/CVE-2026-24306) :  ![starts](https://img.shields.io/github/stars/ExploreUnknowed/CVE-2026-24306.svg) ![forks](https://img.shields.io/github/forks/ExploreUnknowed/CVE-2026-24306.svg)

## CVE-2026-24134
 StudioCMS is a server-side-rendered, Astro native, headless content management system. Versions prior to 0.2.0 contain a Broken Object Level Authorization (BOLA) vulnerability in the Content Management feature that allows users with the "Visitor" role to access draft content created by Editor/Admin/Owner users. Version 0.2.0 patches the issue.



- [https://github.com/FilipeGaudard/CVE-2026-24134-PoC](https://github.com/FilipeGaudard/CVE-2026-24134-PoC) :  ![starts](https://img.shields.io/github/stars/FilipeGaudard/CVE-2026-24134-PoC.svg) ![forks](https://img.shields.io/github/forks/FilipeGaudard/CVE-2026-24134-PoC.svg)

## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.



- [https://github.com/SafeBreach-Labs/CVE-2026-24061](https://github.com/SafeBreach-Labs/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/SafeBreach-Labs/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/SafeBreach-Labs/CVE-2026-24061.svg)

- [https://github.com/JayGLXR/CVE-2026-24061-POC](https://github.com/JayGLXR/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/JayGLXR/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/JayGLXR/CVE-2026-24061-POC.svg)

- [https://github.com/parameciumzhang/Tell-Me-Root](https://github.com/parameciumzhang/Tell-Me-Root) :  ![starts](https://img.shields.io/github/stars/parameciumzhang/Tell-Me-Root.svg) ![forks](https://img.shields.io/github/forks/parameciumzhang/Tell-Me-Root.svg)

- [https://github.com/Lingzesec/CVE-2026-24061-GUI](https://github.com/Lingzesec/CVE-2026-24061-GUI) :  ![starts](https://img.shields.io/github/stars/Lingzesec/CVE-2026-24061-GUI.svg) ![forks](https://img.shields.io/github/forks/Lingzesec/CVE-2026-24061-GUI.svg)

- [https://github.com/h3athen/CVE-2026-24061](https://github.com/h3athen/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/h3athen/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/h3athen/CVE-2026-24061.svg)

- [https://github.com/TryA9ain/CVE-2026-24061](https://github.com/TryA9ain/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/TryA9ain/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/TryA9ain/CVE-2026-24061.svg)

- [https://github.com/leonjza/inetutils-telnetd-auth-bypass](https://github.com/leonjza/inetutils-telnetd-auth-bypass) :  ![starts](https://img.shields.io/github/stars/leonjza/inetutils-telnetd-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/leonjza/inetutils-telnetd-auth-bypass.svg)

- [https://github.com/ibrahmsql/CVE-2026-24061-PoC](https://github.com/ibrahmsql/CVE-2026-24061-PoC) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2026-24061-PoC.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2026-24061-PoC.svg)

- [https://github.com/DeadlyHollows/CVE-2026-24061-setup](https://github.com/DeadlyHollows/CVE-2026-24061-setup) :  ![starts](https://img.shields.io/github/stars/DeadlyHollows/CVE-2026-24061-setup.svg) ![forks](https://img.shields.io/github/forks/DeadlyHollows/CVE-2026-24061-setup.svg)

- [https://github.com/Chocapikk/CVE-2026-24061](https://github.com/Chocapikk/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2026-24061.svg)

- [https://github.com/yanxinwu946/CVE-2026-24061--telnetd](https://github.com/yanxinwu946/CVE-2026-24061--telnetd) :  ![starts](https://img.shields.io/github/stars/yanxinwu946/CVE-2026-24061--telnetd.svg) ![forks](https://img.shields.io/github/forks/yanxinwu946/CVE-2026-24061--telnetd.svg)

- [https://github.com/cyberpoul/CVE-2026-24061-POC](https://github.com/cyberpoul/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/cyberpoul/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/cyberpoul/CVE-2026-24061-POC.svg)

- [https://github.com/duy-31/CVE-2026-24061---telnetd](https://github.com/duy-31/CVE-2026-24061---telnetd) :  ![starts](https://img.shields.io/github/stars/duy-31/CVE-2026-24061---telnetd.svg) ![forks](https://img.shields.io/github/forks/duy-31/CVE-2026-24061---telnetd.svg)

- [https://github.com/infat0x/CVE-2026-24061](https://github.com/infat0x/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/infat0x/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/infat0x/CVE-2026-24061.svg)

- [https://github.com/dotelpenguin/telnetd_CVE-2026-24061_tester](https://github.com/dotelpenguin/telnetd_CVE-2026-24061_tester) :  ![starts](https://img.shields.io/github/stars/dotelpenguin/telnetd_CVE-2026-24061_tester.svg) ![forks](https://img.shields.io/github/forks/dotelpenguin/telnetd_CVE-2026-24061_tester.svg)

- [https://github.com/xuemian168/CVE-2026-24061](https://github.com/xuemian168/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/xuemian168/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/xuemian168/CVE-2026-24061.svg)

- [https://github.com/SystemVll/CVE-2026-24061](https://github.com/SystemVll/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/SystemVll/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/SystemVll/CVE-2026-24061.svg)

- [https://github.com/X-croot/CVE-2026-24061_POC](https://github.com/X-croot/CVE-2026-24061_POC) :  ![starts](https://img.shields.io/github/stars/X-croot/CVE-2026-24061_POC.svg) ![forks](https://img.shields.io/github/forks/X-croot/CVE-2026-24061_POC.svg)

- [https://github.com/franckferman/CVE_2026_24061_PoC](https://github.com/franckferman/CVE_2026_24061_PoC) :  ![starts](https://img.shields.io/github/stars/franckferman/CVE_2026_24061_PoC.svg) ![forks](https://img.shields.io/github/forks/franckferman/CVE_2026_24061_PoC.svg)

- [https://github.com/madfxr/Twenty-Three-Scanner](https://github.com/madfxr/Twenty-Three-Scanner) :  ![starts](https://img.shields.io/github/stars/madfxr/Twenty-Three-Scanner.svg) ![forks](https://img.shields.io/github/forks/madfxr/Twenty-Three-Scanner.svg)

- [https://github.com/FurkanKAYAPINAR/CVE-2026-24061-telnet2root](https://github.com/FurkanKAYAPINAR/CVE-2026-24061-telnet2root) :  ![starts](https://img.shields.io/github/stars/FurkanKAYAPINAR/CVE-2026-24061-telnet2root.svg) ![forks](https://img.shields.io/github/forks/FurkanKAYAPINAR/CVE-2026-24061-telnet2root.svg)

- [https://github.com/ridpath/Terrminus-CVE-2026-2406](https://github.com/ridpath/Terrminus-CVE-2026-2406) :  ![starts](https://img.shields.io/github/stars/ridpath/Terrminus-CVE-2026-2406.svg) ![forks](https://img.shields.io/github/forks/ridpath/Terrminus-CVE-2026-2406.svg)

- [https://github.com/Ali-brarou/telnest](https://github.com/Ali-brarou/telnest) :  ![starts](https://img.shields.io/github/stars/Ali-brarou/telnest.svg) ![forks](https://img.shields.io/github/forks/Ali-brarou/telnest.svg)

- [https://github.com/Mefhika120/Ashwesker-CVE-2026-24061](https://github.com/Mefhika120/Ashwesker-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/Mefhika120/Ashwesker-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/Mefhika120/Ashwesker-CVE-2026-24061.svg)

- [https://github.com/novitahk/Exploit-CVE-2026-24061](https://github.com/novitahk/Exploit-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/novitahk/Exploit-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/novitahk/Exploit-CVE-2026-24061.svg)

- [https://github.com/r00tuser111/CVE-2026-24061](https://github.com/r00tuser111/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/r00tuser111/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/r00tuser111/CVE-2026-24061.svg)

- [https://github.com/buzz075/CVE-2026-24061](https://github.com/buzz075/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/buzz075/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/buzz075/CVE-2026-24061.svg)

- [https://github.com/Mr-Zapi/CVE-2026-24061](https://github.com/Mr-Zapi/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/Mr-Zapi/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/Mr-Zapi/CVE-2026-24061.svg)

- [https://github.com/XsanFlip/CVE-2026-24061-Scanner](https://github.com/XsanFlip/CVE-2026-24061-Scanner) :  ![starts](https://img.shields.io/github/stars/XsanFlip/CVE-2026-24061-Scanner.svg) ![forks](https://img.shields.io/github/forks/XsanFlip/CVE-2026-24061-Scanner.svg)

- [https://github.com/LucasPDiniz/CVE-2026-24061](https://github.com/LucasPDiniz/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/LucasPDiniz/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/LucasPDiniz/CVE-2026-24061.svg)

- [https://github.com/Gabs-hub/CVE-2026-24061_Lab](https://github.com/Gabs-hub/CVE-2026-24061_Lab) :  ![starts](https://img.shields.io/github/stars/Gabs-hub/CVE-2026-24061_Lab.svg) ![forks](https://img.shields.io/github/forks/Gabs-hub/CVE-2026-24061_Lab.svg)

- [https://github.com/Parad0x7e/CVE-2026-24061](https://github.com/Parad0x7e/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/Parad0x7e/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/Parad0x7e/CVE-2026-24061.svg)

- [https://github.com/z3n70/CVE-2026-24061](https://github.com/z3n70/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/z3n70/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/z3n70/CVE-2026-24061.svg)

- [https://github.com/obrunolima1910/CVE-2026-24061](https://github.com/obrunolima1910/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/obrunolima1910/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/obrunolima1910/CVE-2026-24061.svg)

- [https://github.com/monstertsl/CVE-2026-24061](https://github.com/monstertsl/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/monstertsl/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/monstertsl/CVE-2026-24061.svg)

- [https://github.com/BrainBob/CVE-2026-24061](https://github.com/BrainBob/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/BrainBob/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/BrainBob/CVE-2026-24061.svg)

- [https://github.com/SeptembersEND/CVE--2026-24061](https://github.com/SeptembersEND/CVE--2026-24061) :  ![starts](https://img.shields.io/github/stars/SeptembersEND/CVE--2026-24061.svg) ![forks](https://img.shields.io/github/forks/SeptembersEND/CVE--2026-24061.svg)

- [https://github.com/balgan/CVE-2026-24061](https://github.com/balgan/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/balgan/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/balgan/CVE-2026-24061.svg)

- [https://github.com/typeconfused/CVE-2026-24061](https://github.com/typeconfused/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/typeconfused/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/typeconfused/CVE-2026-24061.svg)

- [https://github.com/0x7556/CVE-2026-24061](https://github.com/0x7556/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/0x7556/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/0x7556/CVE-2026-24061.svg)

- [https://github.com/midox008/CVE-2026-24061](https://github.com/midox008/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/midox008/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/midox008/CVE-2026-24061.svg)

- [https://github.com/hilwa24/CVE-2026-24061](https://github.com/hilwa24/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/hilwa24/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/hilwa24/CVE-2026-24061.svg)

- [https://github.com/killsystema/scan-cve-2026-24061](https://github.com/killsystema/scan-cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/killsystema/scan-cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/killsystema/scan-cve-2026-24061.svg)

- [https://github.com/lavabyte/telnet-CVE-2026-24061](https://github.com/lavabyte/telnet-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/lavabyte/telnet-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/lavabyte/telnet-CVE-2026-24061.svg)

- [https://github.com/ms0x08-dev/CVE-2026-24061-POC](https://github.com/ms0x08-dev/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/ms0x08-dev/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/ms0x08-dev/CVE-2026-24061-POC.svg)

- [https://github.com/Good123321-bot/CVE-2026-24061-POC](https://github.com/Good123321-bot/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/Good123321-bot/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/Good123321-bot/CVE-2026-24061-POC.svg)

- [https://github.com/m3ngx1ng/cve_2026_24061_cli](https://github.com/m3ngx1ng/cve_2026_24061_cli) :  ![starts](https://img.shields.io/github/stars/m3ngx1ng/cve_2026_24061_cli.svg) ![forks](https://img.shields.io/github/forks/m3ngx1ng/cve_2026_24061_cli.svg)

- [https://github.com/Alter-N0X/CVE-2026-24061-POC](https://github.com/Alter-N0X/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/Alter-N0X/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/Alter-N0X/CVE-2026-24061-POC.svg)

- [https://github.com/punitdarji/telnetd-cve-2026-24061](https://github.com/punitdarji/telnetd-cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/punitdarji/telnetd-cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/punitdarji/telnetd-cve-2026-24061.svg)

- [https://github.com/canpilayda/inetutils-telnetd-cve-2026-24061](https://github.com/canpilayda/inetutils-telnetd-cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/canpilayda/inetutils-telnetd-cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/canpilayda/inetutils-telnetd-cve-2026-24061.svg)

- [https://github.com/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-](https://github.com/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-) :  ![starts](https://img.shields.io/github/stars/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-.svg) ![forks](https://img.shields.io/github/forks/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-.svg)

- [https://github.com/BrainBob/Telnet-TestVuln-CVE-2026-24061](https://github.com/BrainBob/Telnet-TestVuln-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/BrainBob/Telnet-TestVuln-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/BrainBob/Telnet-TestVuln-CVE-2026-24061.svg)

- [https://github.com/androidteacher/CVE-2026-24061-PoC-Telnetd](https://github.com/androidteacher/CVE-2026-24061-PoC-Telnetd) :  ![starts](https://img.shields.io/github/stars/androidteacher/CVE-2026-24061-PoC-Telnetd.svg) ![forks](https://img.shields.io/github/forks/androidteacher/CVE-2026-24061-PoC-Telnetd.svg)

- [https://github.com/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061](https://github.com/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061.svg)

- [https://github.com/Good123321-bot/good123321-bot.github.io](https://github.com/Good123321-bot/good123321-bot.github.io) :  ![starts](https://img.shields.io/github/stars/Good123321-bot/good123321-bot.github.io.svg) ![forks](https://img.shields.io/github/forks/Good123321-bot/good123321-bot.github.io.svg)

- [https://github.com/Moxxic1/Tell-Me-Root](https://github.com/Moxxic1/Tell-Me-Root) :  ![starts](https://img.shields.io/github/stars/Moxxic1/Tell-Me-Root.svg) ![forks](https://img.shields.io/github/forks/Moxxic1/Tell-Me-Root.svg)

- [https://github.com/cumakurt/tscan](https://github.com/cumakurt/tscan) :  ![starts](https://img.shields.io/github/stars/cumakurt/tscan.svg) ![forks](https://img.shields.io/github/forks/cumakurt/tscan.svg)

- [https://github.com/obrunolima1910/obrunolima1910.github.io](https://github.com/obrunolima1910/obrunolima1910.github.io) :  ![starts](https://img.shields.io/github/stars/obrunolima1910/obrunolima1910.github.io.svg) ![forks](https://img.shields.io/github/forks/obrunolima1910/obrunolima1910.github.io.svg)

- [https://github.com/Moxxic1/moxxic1.github.io](https://github.com/Moxxic1/moxxic1.github.io) :  ![starts](https://img.shields.io/github/stars/Moxxic1/moxxic1.github.io.svg) ![forks](https://img.shields.io/github/forks/Moxxic1/moxxic1.github.io.svg)

- [https://github.com/hackingyseguridad/root](https://github.com/hackingyseguridad/root) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/root.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/root.svg)

## CVE-2026-24049
 wheel is a command line tool for manipulating Python wheel files, as defined in PEP 427. In versions 0.40.0 through 0.46.1, the unpack function is vulnerable to file permission modification through mishandling of file permissions after extraction. The logic blindly trusts the filename from the archive header for the chmod operation, even though the extraction process itself might have sanitized the path. Attackers can craft a malicious wheel file that, when unpacked, changes the permissions of critical system files (e.g., /etc/passwd, SSH keys, config files), allowing for Privilege Escalation or arbitrary code execution by modifying now-writable scripts. This issue has been fixed in version 0.46.2.



- [https://github.com/kriskimmerle/wheelaudit](https://github.com/kriskimmerle/wheelaudit) :  ![starts](https://img.shields.io/github/stars/kriskimmerle/wheelaudit.svg) ![forks](https://img.shields.io/github/forks/kriskimmerle/wheelaudit.svg)

## CVE-2026-23947
 Orval generates type-safe JS clients (TypeScript) from any valid OpenAPI v3 or Swagger v2 specification. Versions prior to 7.19.0 until 8.0.2 are vulnerable to arbitrary code execution in environments consuming generated clients. This issue is similar in nature to CVE-2026-22785, but affects a different code path in @orval/core that was not addressed by CVE-2026-22785's fix. The vulnerability allows untrusted OpenAPI specifications to inject arbitrary TypeScript/JavaScript code into generated clients via the x-enumDescriptions field, which is embedded without proper escaping in getEnumImplementation(). I have confirmed that the injection occurs during const enum generation and results in executable code within the generated schema files. Orval 7.19.0 and 8.0.2 contain a fix for the issue.



- [https://github.com/boroeurnprach/CVE-2026-23947-PoC](https://github.com/boroeurnprach/CVE-2026-23947-PoC) :  ![starts](https://img.shields.io/github/stars/boroeurnprach/CVE-2026-23947-PoC.svg) ![forks](https://img.shields.io/github/forks/boroeurnprach/CVE-2026-23947-PoC.svg)

## CVE-2026-23885
 Alchemy is an open source content management system engine written in Ruby on Rails. Prior to versions 7.4.12 and 8.0.3, the application uses the Ruby `eval()` function to dynamically execute a string provided by the `resource_handler.engine_name` attribute in `Alchemy::ResourcesHelper#resource_url_proxy`. The vulnerability exists in `app/helpers/alchemy/resources_helper.rb` at line 28. The code explicitly bypasses security linting with `# rubocop:disable Security/Eval`, indicating that the use of a dangerous function was known but not properly mitigated. Since `engine_name` is sourced from module definitions that can be influenced by administrative configurations, it allows an authenticated attacker to escape the Ruby sandbox and execute arbitrary system commands on the host OS. Versions 7.4.12 and 8.0.3 fix the issue by replacing `eval()` with `send()`.



- [https://github.com/TheDeepOpc/CVE-2026-23885](https://github.com/TheDeepOpc/CVE-2026-23885) :  ![starts](https://img.shields.io/github/stars/TheDeepOpc/CVE-2026-23885.svg) ![forks](https://img.shields.io/github/forks/TheDeepOpc/CVE-2026-23885.svg)

## CVE-2026-23829
 Mailpit is an email testing tool and API for developers. Prior to version 1.28.3, Mailpit's SMTP server is vulnerable to Header Injection due to an insufficient Regular Expression used to validate `RCPT TO` and `MAIL FROM` addresses. An attacker can inject arbitrary SMTP headers (or corrupt existing ones) by including carriage return characters (`\r`) in the email address. This header injection occurs because the regex intended to filter control characters fails to exclude `\r` and `\n` when used inside a character class. Version 1.28.3 fixes this issue.



- [https://github.com/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover](https://github.com/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover.svg)

## CVE-2026-23760
 SmarterTools SmarterMail versions prior to build 9511 contain an authentication bypass vulnerability in the password reset API. The force-reset-password endpoint permits anonymous requests and fails to verify the existing password or a reset token when resetting system administrator accounts. An unauthenticated attacker can supply a target administrator username and a new password to reset the account, resulting in full administrative compromise of the SmarterMail instance. NOTE: SmarterMail system administrator privileges grant the ability to execute operating system commands via built-in management functionality, effectively providing administrative (SYSTEM or root) access on the underlying host.



- [https://github.com/hilwa24/CVE-2026-23760_SmarterMail-Auth-Bypass-and-RCE](https://github.com/hilwa24/CVE-2026-23760_SmarterMail-Auth-Bypass-and-RCE) :  ![starts](https://img.shields.io/github/stars/hilwa24/CVE-2026-23760_SmarterMail-Auth-Bypass-and-RCE.svg) ![forks](https://img.shields.io/github/forks/hilwa24/CVE-2026-23760_SmarterMail-Auth-Bypass-and-RCE.svg)

- [https://github.com/MaxMnMl/smartermail-CVE-2026-23760-poc](https://github.com/MaxMnMl/smartermail-CVE-2026-23760-poc) :  ![starts](https://img.shields.io/github/stars/MaxMnMl/smartermail-CVE-2026-23760-poc.svg) ![forks](https://img.shields.io/github/forks/MaxMnMl/smartermail-CVE-2026-23760-poc.svg)

## CVE-2026-23745
 node-tar is a Tar for Node.js. The node-tar library (= 7.5.2) fails to sanitize the linkpath of Link (hardlink) and SymbolicLink entries when preservePaths is false (the default secure behavior). This allows malicious archives to bypass the extraction root restriction, leading to Arbitrary File Overwrite via hardlinks and Symlink Poisoning via absolute symlink targets. This vulnerability is fixed in 7.5.3.



- [https://github.com/Jvr2022/CVE-2026-23745](https://github.com/Jvr2022/CVE-2026-23745) :  ![starts](https://img.shields.io/github/stars/Jvr2022/CVE-2026-23745.svg) ![forks](https://img.shields.io/github/forks/Jvr2022/CVE-2026-23745.svg)

## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.



- [https://github.com/boroeurnprach/CVE-2026-23744-PoC](https://github.com/boroeurnprach/CVE-2026-23744-PoC) :  ![starts](https://img.shields.io/github/stars/boroeurnprach/CVE-2026-23744-PoC.svg) ![forks](https://img.shields.io/github/forks/boroeurnprach/CVE-2026-23744-PoC.svg)

## CVE-2026-23550
 Incorrect Privilege Assignment vulnerability in Modular DS allows Privilege Escalation.This issue affects Modular DS: from n/a through 2.5.1.



- [https://github.com/TheTorjanCaptain/CVE-2026-23550-PoC](https://github.com/TheTorjanCaptain/CVE-2026-23550-PoC) :  ![starts](https://img.shields.io/github/stars/TheTorjanCaptain/CVE-2026-23550-PoC.svg) ![forks](https://img.shields.io/github/forks/TheTorjanCaptain/CVE-2026-23550-PoC.svg)

- [https://github.com/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector) :  ![starts](https://img.shields.io/github/stars/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector.svg) ![forks](https://img.shields.io/github/forks/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector.svg)

- [https://github.com/O99099O/By-Poloss..-..CVE-2026-23550](https://github.com/O99099O/By-Poloss..-..CVE-2026-23550) :  ![starts](https://img.shields.io/github/stars/O99099O/By-Poloss..-..CVE-2026-23550.svg) ![forks](https://img.shields.io/github/forks/O99099O/By-Poloss..-..CVE-2026-23550.svg)

## CVE-2026-22862
 go-ethereum (geth) is a golang execution layer implementation of the Ethereum protocol. A vulnerable node can be forced to shutdown/crash using a specially crafted message. This vulnerability is fixed in 1.16.8.



- [https://github.com/qzhodl/CVE-2026-22862](https://github.com/qzhodl/CVE-2026-22862) :  ![starts](https://img.shields.io/github/stars/qzhodl/CVE-2026-22862.svg) ![forks](https://img.shields.io/github/forks/qzhodl/CVE-2026-22862.svg)

## CVE-2026-22812
 OpenCode is an open source AI coding agent. Prior to 1.0.216, OpenCode automatically starts an unauthenticated HTTP server that allows any local process (or any website via permissive CORS) to execute arbitrary shell commands with the user's privileges. This vulnerability is fixed in 1.0.216.



- [https://github.com/rohmatariow/CVE-2026-22812-exploit](https://github.com/rohmatariow/CVE-2026-22812-exploit) :  ![starts](https://img.shields.io/github/stars/rohmatariow/CVE-2026-22812-exploit.svg) ![forks](https://img.shields.io/github/forks/rohmatariow/CVE-2026-22812-exploit.svg)

- [https://github.com/Udyz/CVE-2026-22812-Exp](https://github.com/Udyz/CVE-2026-22812-Exp) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2026-22812-Exp.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2026-22812-Exp.svg)

- [https://github.com/0xgh057r3c0n/CVE-2026-22812](https://github.com/0xgh057r3c0n/CVE-2026-22812) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2026-22812.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2026-22812.svg)

- [https://github.com/mad12wader/CVE-2026-22812](https://github.com/mad12wader/CVE-2026-22812) :  ![starts](https://img.shields.io/github/stars/mad12wader/CVE-2026-22812.svg) ![forks](https://img.shields.io/github/forks/mad12wader/CVE-2026-22812.svg)

- [https://github.com/CayberMods/CVE-2026-22812-POC](https://github.com/CayberMods/CVE-2026-22812-POC) :  ![starts](https://img.shields.io/github/stars/CayberMods/CVE-2026-22812-POC.svg) ![forks](https://img.shields.io/github/forks/CayberMods/CVE-2026-22812-POC.svg)

- [https://github.com/barrersoftware/opencode-secure](https://github.com/barrersoftware/opencode-secure) :  ![starts](https://img.shields.io/github/stars/barrersoftware/opencode-secure.svg) ![forks](https://img.shields.io/github/forks/barrersoftware/opencode-secure.svg)

## CVE-2026-22807
 vLLM is an inference and serving engine for large language models (LLMs). Starting in version 0.10.1 and prior to version 0.14.0, vLLM loads Hugging Face `auto_map` dynamic modules during model resolution without gating on `trust_remote_code`, allowing attacker-controlled Python code in a model repo/path to execute at server startup. An attacker who can influence the model repo/path (local directory or remote Hugging Face repo) can achieve arbitrary code execution on the vLLM host during model load. This happens before any request handling and does not require API access. Version 0.14.0 fixes the issue.



- [https://github.com/otakuliu/CVE-2026-22807_Range](https://github.com/otakuliu/CVE-2026-22807_Range) :  ![starts](https://img.shields.io/github/stars/otakuliu/CVE-2026-22807_Range.svg) ![forks](https://img.shields.io/github/forks/otakuliu/CVE-2026-22807_Range.svg)

## CVE-2026-22804
 Termix is a web-based server management platform with SSH terminal, tunneling, and file editing capabilities. From 1.7.0 to 1.9.0, Stored Cross-Site Scripting (XSS) vulnerability exists in the Termix File Manager component. The application fails to sanitize SVG file content before rendering it. This allows an attacker who has compromised a managed SSH server to plant a malicious file, which, when previewed by the Termix user, executes arbitrary JavaScript in the context of the application. The vulnerability is located in src/ui/desktop/apps/file-manager/components/FileViewer.tsx. This vulnerability is fixed in 1.10.0.



- [https://github.com/ThemeHackers/CVE-2026-22804](https://github.com/ThemeHackers/CVE-2026-22804) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2026-22804.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2026-22804.svg)

## CVE-2026-22794
 Appsmith is a platform to build admin panels, internal tools, and dashboards. Prior to 1.93, the server uses the Origin value from the request headers as the email link baseUrl without validation. If an attacker controls the Origin, password reset / email verification links in emails can be generated pointing to the attacker’s domain, causing authentication tokens to be exposed and potentially leading to account takeover. This vulnerability is fixed in 1.93.



- [https://github.com/MalikHamza7/CVE-2026-22794-POC](https://github.com/MalikHamza7/CVE-2026-22794-POC) :  ![starts](https://img.shields.io/github/stars/MalikHamza7/CVE-2026-22794-POC.svg) ![forks](https://img.shields.io/github/forks/MalikHamza7/CVE-2026-22794-POC.svg)

## CVE-2026-22785
 orval generates type-safe JS clients (TypeScript) from any valid OpenAPI v3 or Swagger v2 specification. Prior to 7.18.0, the MCP server generation logic relies on string manipulation that incorporates the summary field from the OpenAPI specification without proper validation or escaping. This allows an attacker to "break out" of the string literal and inject arbitrary code. This vulnerability is fixed in 7.18.0.



- [https://github.com/langbyyi/CVE-2026-22785](https://github.com/langbyyi/CVE-2026-22785) :  ![starts](https://img.shields.io/github/stars/langbyyi/CVE-2026-22785.svg) ![forks](https://img.shields.io/github/forks/langbyyi/CVE-2026-22785.svg)

## CVE-2026-22686
 Enclave is a secure JavaScript sandbox designed for safe AI agent code execution. Prior to 2.7.0, there is a critical sandbox escape vulnerability in enclave-vm that allows untrusted, sandboxed JavaScript code to execute arbitrary code in the host Node.js runtime. When a tool invocation fails, enclave-vm exposes a host-side Error object to sandboxed code. This Error object retains its host realm prototype chain, which can be traversed to reach the host Function constructor. An attacker can intentionally trigger a host error, then climb the prototype chain. Using the host Function constructor, arbitrary JavaScript can be compiled and executed in the host context, fully bypassing the sandbox and granting access to sensitive resources such as process.env, filesystem, and network. This breaks enclave-vm’s core security guarantee of isolating untrusted code. This vulnerability is fixed in 2.7.0.



- [https://github.com/amusedx/CVE-2026-22686](https://github.com/amusedx/CVE-2026-22686) :  ![starts](https://img.shields.io/github/stars/amusedx/CVE-2026-22686.svg) ![forks](https://img.shields.io/github/forks/amusedx/CVE-2026-22686.svg)

## CVE-2026-22610
 Angular is a development platform for building mobile and desktop web applications using TypeScript/JavaScript and other languages. Prior to versions 19.2.18, 20.3.16, 21.0.7, and 21.1.0-rc.0, a cross-site scripting (XSS) vulnerability has been identified in the Angular Template Compiler. The vulnerability exists because Angular’s internal sanitization schema fails to recognize the href and xlink:href attributes of SVG script elements as a Resource URL context. This issue has been patched in versions 19.2.18, 20.3.16, 21.0.7, and 21.1.0-rc.0.



- [https://github.com/ashizZz/CVE-2026-22610](https://github.com/ashizZz/CVE-2026-22610) :  ![starts](https://img.shields.io/github/stars/ashizZz/CVE-2026-22610.svg) ![forks](https://img.shields.io/github/forks/ashizZz/CVE-2026-22610.svg)

## CVE-2026-22444
 The "create core" API of Apache Solr 8.6 through 9.10.0 lacks sufficient input validation on some API parameters, which can cause Solr to check the existence of and attempt to read file-system paths that should be disallowed by Solr's  "allowPaths" security setting https://https://solr.apache.org/guide/solr/latest/configuration-guide/configuring-solr-xml.html#the-solr-element .  These read-only accesses can allow users to create cores using unexpected configsets if any are accessible via the filesystem.  On Windows systems configured to allow UNC paths this can additionally cause disclosure of NTLM "user" hashes. 

Solr deployments are subject to this vulnerability if they meet the following criteria:
  *  Solr is running in its "standalone" mode.
  *  Solr's "allowPath" setting is being used to restrict file access to certain directories.
  *  Solr's "create core" API is exposed and accessible to untrusted users.  This can happen if Solr's  RuleBasedAuthorizationPlugin https://solr.apache.org/guide/solr/latest/deployment-guide/rule-based-authorization-plugin.html  is disabled, or if it is enabled but the "core-admin-edit" predefined permission (or an equivalent custom permission) is given to low-trust (i.e. non-admin) user roles.

Users can mitigate this by enabling Solr's RuleBasedAuthorizationPlugin (if disabled) and configuring a permission-list that prevents untrusted users from creating new Solr cores.  Users should also upgrade to Apache Solr 9.10.1 or greater, which contain fixes for this issue.



- [https://github.com/dptsec/CVE-2026-22444](https://github.com/dptsec/CVE-2026-22444) :  ![starts](https://img.shields.io/github/stars/dptsec/CVE-2026-22444.svg) ![forks](https://img.shields.io/github/forks/dptsec/CVE-2026-22444.svg)

- [https://github.com/bfdfhdsfdd-crypto/CVE-2026-22444](https://github.com/bfdfhdsfdd-crypto/CVE-2026-22444) :  ![starts](https://img.shields.io/github/stars/bfdfhdsfdd-crypto/CVE-2026-22444.svg) ![forks](https://img.shields.io/github/forks/bfdfhdsfdd-crypto/CVE-2026-22444.svg)

## CVE-2026-22241
 The Open eClass platform (formerly known as GUnet eClass) is a complete course management system. Prior to version 4.2, an arbitrary file upload vulnerability in the theme import functionality enables an attacker with administrative privileges to upload arbitrary files on the server's file system. The main cause of the issue is that no validation or sanitization of the file's present inside the zip archive. This leads to remote code execution on the web server. Version 4.2 patches the issue.



- [https://github.com/Ashifcoder/CVE-2026-22241](https://github.com/Ashifcoder/CVE-2026-22241) :  ![starts](https://img.shields.io/github/stars/Ashifcoder/CVE-2026-22241.svg) ![forks](https://img.shields.io/github/forks/Ashifcoder/CVE-2026-22241.svg)

## CVE-2026-22200
 Enhancesoft osTicket versions 1.18.x prior to 1.18.3 and 1.17.x prior to 1.17.7 contain an arbitrary file read vulnerability in the ticket PDF export functionality. A remote attacker can submit a ticket containing crafted rich-text HTML that includes PHP filter expressions which are insufficiently sanitized before being processed by the mPDF PDF generator during export. When the attacker exports the ticket to PDF, the generated PDF can embed the contents of attacker-selected files from the server filesystem as bitmap images, allowing disclosure of sensitive local files in the context of the osTicket application user. This issue is exploitable in default configurations where guests may create tickets and access ticket status, or where self-registration is enabled.



- [https://github.com/horizon3ai/CVE-2026-22200](https://github.com/horizon3ai/CVE-2026-22200) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2026-22200.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2026-22200.svg)

## CVE-2026-21962
 Vulnerability in the Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in product of Oracle Fusion Middleware (component: Weblogic Server Proxy Plug-in for Apache HTTP Server, Weblogic Server Proxy Plug-in for IIS).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0 and  14.1.2.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in.  While the vulnerability is in Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data. Note: Affected version for Weblogic Server Proxy Plug-in for IIS is 12.2.1.4.0 only. CVSS 3.1 Base Score 10.0 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).



- [https://github.com/samael0x4/CVE-2026-21962](https://github.com/samael0x4/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/samael0x4/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/samael0x4/CVE-2026-21962.svg)

- [https://github.com/boroeurnprach/Ashwesker-CVE-2026-21962](https://github.com/boroeurnprach/Ashwesker-CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/boroeurnprach/Ashwesker-CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/boroeurnprach/Ashwesker-CVE-2026-21962.svg)

- [https://github.com/ThumpBo/CVE-2026-21962](https://github.com/ThumpBo/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/ThumpBo/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/ThumpBo/CVE-2026-21962.svg)

- [https://github.com/gregk4sec/CVE-2026-21962](https://github.com/gregk4sec/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2026-21962.svg)

- [https://github.com/gglessner/cve_2026_21962_scanner](https://github.com/gglessner/cve_2026_21962_scanner) :  ![starts](https://img.shields.io/github/stars/gglessner/cve_2026_21962_scanner.svg) ![forks](https://img.shields.io/github/forks/gglessner/cve_2026_21962_scanner.svg)

## CVE-2026-21876
 The OWASP core rule set (CRS) is a set of generic attack detection rules for use with compatible web application firewalls. Prior to versions 4.22.0 and 3.3.8, the current rule 922110 has a bug when processing multipart requests with multiple parts. When the first rule in a chain iterates over a collection (like `MULTIPART_PART_HEADERS`), the capture variables (`TX:0`, `TX:1`) get overwritten with each iteration. Only the last captured value is available to the chained rule, which means malicious charsets in earlier parts can be missed if a later part has a legitimate charset. Versions 4.22.0 and 3.3.8 patch the issue.



- [https://github.com/daytriftnewgen/CVE-2026-21876](https://github.com/daytriftnewgen/CVE-2026-21876) :  ![starts](https://img.shields.io/github/stars/daytriftnewgen/CVE-2026-21876.svg) ![forks](https://img.shields.io/github/forks/daytriftnewgen/CVE-2026-21876.svg)

## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.



- [https://github.com/Chocapikk/CVE-2026-21858](https://github.com/Chocapikk/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2026-21858.svg)

- [https://github.com/SystemVll/CVE-2026-21858](https://github.com/SystemVll/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/SystemVll/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/SystemVll/CVE-2026-21858.svg)

- [https://github.com/bgarz929/Ashwesker-CVE-2026-21858](https://github.com/bgarz929/Ashwesker-CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/bgarz929/Ashwesker-CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/bgarz929/Ashwesker-CVE-2026-21858.svg)

- [https://github.com/Alhakim88/CVE-2026-21858](https://github.com/Alhakim88/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/Alhakim88/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/Alhakim88/CVE-2026-21858.svg)

- [https://github.com/sec-dojo-com/CVE-2026-21858](https://github.com/sec-dojo-com/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/sec-dojo-com/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/sec-dojo-com/CVE-2026-21858.svg)

- [https://github.com/MOGMUNI/CVE-2026-21858](https://github.com/MOGMUNI/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/MOGMUNI/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/MOGMUNI/CVE-2026-21858.svg)

- [https://github.com/sastraadiwiguna-purpleeliteteaming/SASTRA-ADI-WIGUNA-CVE-2026-21858-Holistic-Audit](https://github.com/sastraadiwiguna-purpleeliteteaming/SASTRA-ADI-WIGUNA-CVE-2026-21858-Holistic-Audit) :  ![starts](https://img.shields.io/github/stars/sastraadiwiguna-purpleeliteteaming/SASTRA-ADI-WIGUNA-CVE-2026-21858-Holistic-Audit.svg) ![forks](https://img.shields.io/github/forks/sastraadiwiguna-purpleeliteteaming/SASTRA-ADI-WIGUNA-CVE-2026-21858-Holistic-Audit.svg)

- [https://github.com/MOGMUNI/mogmuni.github.io](https://github.com/MOGMUNI/mogmuni.github.io) :  ![starts](https://img.shields.io/github/stars/MOGMUNI/mogmuni.github.io.svg) ![forks](https://img.shields.io/github/forks/MOGMUNI/mogmuni.github.io.svg)

- [https://github.com/cropnet/ni8mare-scanner](https://github.com/cropnet/ni8mare-scanner) :  ![starts](https://img.shields.io/github/stars/cropnet/ni8mare-scanner.svg) ![forks](https://img.shields.io/github/forks/cropnet/ni8mare-scanner.svg)

## CVE-2026-21721
 The dashboard permissions API does not verify the target dashboard scope and only checks the dashboards.permissions:* action. As a result, a user who has permission management rights on one dashboard can read and modify permissions on other dashboards. This is an organization‑internal privilege escalation.



- [https://github.com/Leonideath/Exploit-LPE-CVE-2026-21721](https://github.com/Leonideath/Exploit-LPE-CVE-2026-21721) :  ![starts](https://img.shields.io/github/stars/Leonideath/Exploit-LPE-CVE-2026-21721.svg) ![forks](https://img.shields.io/github/forks/Leonideath/Exploit-LPE-CVE-2026-21721.svg)

## CVE-2026-21509
 Reliance on untrusted inputs in a security decision in Microsoft Office allows an unauthorized attacker to bypass a security feature locally.



- [https://github.com/kimstars/Ashwesker-CVE-2026-21509](https://github.com/kimstars/Ashwesker-CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/kimstars/Ashwesker-CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/kimstars/Ashwesker-CVE-2026-21509.svg)

- [https://github.com/gavz/CVE-2026-21509-PoC](https://github.com/gavz/CVE-2026-21509-PoC) :  ![starts](https://img.shields.io/github/stars/gavz/CVE-2026-21509-PoC.svg) ![forks](https://img.shields.io/github/forks/gavz/CVE-2026-21509-PoC.svg)

- [https://github.com/SimoesCTT/CTT-NFS-Vortex-RCE](https://github.com/SimoesCTT/CTT-NFS-Vortex-RCE) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-NFS-Vortex-RCE.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-NFS-Vortex-RCE.svg)

- [https://github.com/decalage2/detect_CVE-2026-21509](https://github.com/decalage2/detect_CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/decalage2/detect_CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/decalage2/detect_CVE-2026-21509.svg)

- [https://github.com/ksk-itdk/KSK-ITDK-CVE-2026-21509-Mitigation](https://github.com/ksk-itdk/KSK-ITDK-CVE-2026-21509-Mitigation) :  ![starts](https://img.shields.io/github/stars/ksk-itdk/KSK-ITDK-CVE-2026-21509-Mitigation.svg) ![forks](https://img.shields.io/github/forks/ksk-itdk/KSK-ITDK-CVE-2026-21509-Mitigation.svg)

- [https://github.com/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-](https://github.com/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-.svg)

- [https://github.com/kaizensecurity/CVE-2026-21509](https://github.com/kaizensecurity/CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/kaizensecurity/CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/kaizensecurity/CVE-2026-21509.svg)

- [https://github.com/SimoesCTT/CTT-MICROSOFT-OFFICE-OLE-MANIFOLD-BYPASS-CVE-2026-21509](https://github.com/SimoesCTT/CTT-MICROSOFT-OFFICE-OLE-MANIFOLD-BYPASS-CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-MICROSOFT-OFFICE-OLE-MANIFOLD-BYPASS-CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-MICROSOFT-OFFICE-OLE-MANIFOLD-BYPASS-CVE-2026-21509.svg)

## CVE-2026-21445
 Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to version 1.7.0.dev45, multiple critical API endpoints in Langflow are missing authentication controls. The issue allows any unauthenticated user to access sensitive user conversation data, transaction histories, and perform destructive operations including message deletion. This affects endpoints handling personal data and system operations that should require proper authorization. Version 1.7.0.dev45 contains a patch.



- [https://github.com/chinaxploiter/CVE-2026-21445-PoC](https://github.com/chinaxploiter/CVE-2026-21445-PoC) :  ![starts](https://img.shields.io/github/stars/chinaxploiter/CVE-2026-21445-PoC.svg) ![forks](https://img.shields.io/github/forks/chinaxploiter/CVE-2026-21445-PoC.svg)

## CVE-2026-21440
 AdonisJS is a TypeScript-first web framework. A Path Traversal vulnerability in AdonisJS multipart file handling may allow a remote attacker to write arbitrary files to arbitrary locations on the server filesystem. This impacts @adonisjs/bodyparser through version 10.1.1 and 11.x prerelease versions prior to 11.0.0-next.6. This issue has been patched in @adonisjs/bodyparser versions 10.1.2 and 11.0.0-next.6.



- [https://github.com/k0nnect/cve-2026-21440-writeup-poc](https://github.com/k0nnect/cve-2026-21440-writeup-poc) :  ![starts](https://img.shields.io/github/stars/k0nnect/cve-2026-21440-writeup-poc.svg) ![forks](https://img.shields.io/github/forks/k0nnect/cve-2026-21440-writeup-poc.svg)

- [https://github.com/you-ssef9/CVE-2026-21440](https://github.com/you-ssef9/CVE-2026-21440) :  ![starts](https://img.shields.io/github/stars/you-ssef9/CVE-2026-21440.svg) ![forks](https://img.shields.io/github/forks/you-ssef9/CVE-2026-21440.svg)

- [https://github.com/redpack-kr/Ashwesker-CVE-2026-21440](https://github.com/redpack-kr/Ashwesker-CVE-2026-21440) :  ![starts](https://img.shields.io/github/stars/redpack-kr/Ashwesker-CVE-2026-21440.svg) ![forks](https://img.shields.io/github/forks/redpack-kr/Ashwesker-CVE-2026-21440.svg)

- [https://github.com/TibbersV6/CVE-2026-21440-POC-EXP](https://github.com/TibbersV6/CVE-2026-21440-POC-EXP) :  ![starts](https://img.shields.io/github/stars/TibbersV6/CVE-2026-21440-POC-EXP.svg) ![forks](https://img.shields.io/github/forks/TibbersV6/CVE-2026-21440-POC-EXP.svg)

## CVE-2026-21437
 eopkg is a Solus package manager implemented in python3. In versions prior to 4.4.0, a malicious package could include files that are not tracked by `eopkg`. This requires the installation of a package from a malicious or compromised source. Files in such packages would not be shown by `lseopkg` and related tools. The issue has been fixed in v4.4.0. Users only installing packages from the Solus repositories are not affected.



- [https://github.com/osmancanvural/CVE-2026-21437](https://github.com/osmancanvural/CVE-2026-21437) :  ![starts](https://img.shields.io/github/stars/osmancanvural/CVE-2026-21437.svg) ![forks](https://img.shields.io/github/forks/osmancanvural/CVE-2026-21437.svg)

## CVE-2026-21436
 eopkg is a Solus package manager implemented in python3. In versions prior to 4.4.0, a malicious package could escape the directory set by `--destdir`. This requires the installation of a package from a malicious or compromised source. Files in such packages would not be installed in the path given by `--destdir`, but on a different location on the host. The issue has been fixed in v4.4.0. Users only installing packages from the Solus repositories are not affected.



- [https://github.com/osmancanvural/CVE-2026-21436](https://github.com/osmancanvural/CVE-2026-21436) :  ![starts](https://img.shields.io/github/stars/osmancanvural/CVE-2026-21436.svg) ![forks](https://img.shields.io/github/forks/osmancanvural/CVE-2026-21436.svg)

## CVE-2026-20871
 Use after free in Desktop Windows Manager allows an authorized attacker to elevate privileges locally.



- [https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)

- [https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)

## CVE-2026-20805
 Exposure of sensitive information to an unauthorized actor in Desktop Windows Manager allows an authorized attacker to disclose information locally.



- [https://github.com/fevar54/CVE-2026-20805-POC](https://github.com/fevar54/CVE-2026-20805-POC) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-20805-POC.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-20805-POC.svg)

- [https://github.com/Uzair-Baig0900/CVE-2026-20805-PoC](https://github.com/Uzair-Baig0900/CVE-2026-20805-PoC) :  ![starts](https://img.shields.io/github/stars/Uzair-Baig0900/CVE-2026-20805-PoC.svg) ![forks](https://img.shields.io/github/forks/Uzair-Baig0900/CVE-2026-20805-PoC.svg)

- [https://github.com/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data](https://github.com/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data) :  ![starts](https://img.shields.io/github/stars/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data.svg) ![forks](https://img.shields.io/github/forks/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data.svg)

- [https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)

- [https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)

## CVE-2026-20045
 A vulnerability in Cisco Unified Communications Manager (Unified CM), Cisco Unified Communications Manager Session Management Edition (Unified CM SME), Cisco Unified Communications Manager IM &amp; Presence Service (Unified CM IM&amp;P), Cisco Unity Connection, and Cisco Webex Calling Dedicated Instance could allow an unauthenticated, remote attacker&nbsp;to execute arbitrary commands on the underlying operating system of an affected device.&nbsp;

This vulnerability is due to improper validation of user-supplied input in HTTP requests. An attacker could exploit this vulnerability by sending a sequence of crafted HTTP requests to the web-based management interface of an affected device. A successful exploit could allow the attacker to obtain user-level access to the underlying operating system and then elevate privileges to root.
Note: Cisco has assigned this security advisory a Security Impact Rating (SIR) of Critical rather than High as the score indicates. The reason is that exploitation of this vulnerability could result in an attacker elevating privileges to root.



- [https://github.com/dkstar11q/Ashwesker-CVE-2026-20045](https://github.com/dkstar11q/Ashwesker-CVE-2026-20045) :  ![starts](https://img.shields.io/github/stars/dkstar11q/Ashwesker-CVE-2026-20045.svg) ![forks](https://img.shields.io/github/forks/dkstar11q/Ashwesker-CVE-2026-20045.svg)

## CVE-2026-1953
 Nukegraphic CMS v3.1.2 contains a stored cross-site scripting (XSS) vulnerability in the user profile edit functionality at /ngc-cms/user-edit-profile.php. The application fails to properly sanitize user input in the name field before storing it in the database and rendering it across multiple CMS pages. An authenticated attacker with low privileges can inject malicious JavaScript payloads through the profile edit request, which are then executed site-wide whenever the affected user's name is displayed. This allows the attacker to execute arbitrary JavaScript in the context of other users' sessions, potentially leading to session hijacking, credential theft, or unauthorized actions performed on behalf of victims.



- [https://github.com/carlosbudiman/CVE-2026-1953-Disclosure](https://github.com/carlosbudiman/CVE-2026-1953-Disclosure) :  ![starts](https://img.shields.io/github/stars/carlosbudiman/CVE-2026-1953-Disclosure.svg) ![forks](https://img.shields.io/github/forks/carlosbudiman/CVE-2026-1953-Disclosure.svg)

## CVE-2026-1457
 An authenticated buffer handling flaw in TP-Link VIGI C385 V1 Web API lacking input sanitization, may allow memory corruption leading to remote code execution. Authenticated attackers may trigger buffer overflow and potentially execute arbitrary code with elevated privileges.



- [https://github.com/ii4gsp/CVE-2026-1457](https://github.com/ii4gsp/CVE-2026-1457) :  ![starts](https://img.shields.io/github/stars/ii4gsp/CVE-2026-1457.svg) ![forks](https://img.shields.io/github/forks/ii4gsp/CVE-2026-1457.svg)

## CVE-2026-1208
 The Friendly Functions for Welcart plugin for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 1.2.5. This is due to missing or incorrect nonce validation on the settings page. This makes it possible for unauthenticated attackers to update plugin settings via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.



- [https://github.com/SnailSploit/CVE-2026-1208](https://github.com/SnailSploit/CVE-2026-1208) :  ![starts](https://img.shields.io/github/stars/SnailSploit/CVE-2026-1208.svg) ![forks](https://img.shields.io/github/forks/SnailSploit/CVE-2026-1208.svg)

## CVE-2026-1107
 A weakness has been identified in EyouCMS up to 1.7.1/5.0. Impacted is the function check_userinfo of the file Diyajax.php of the component Member Avatar Handler. Executing a manipulation of the argument viewfile can lead to unrestricted upload. The attack may be performed from remote. The exploit has been made available to the public and could be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/Iniivan13/CVE-2026-1107](https://github.com/Iniivan13/CVE-2026-1107) :  ![starts](https://img.shields.io/github/stars/Iniivan13/CVE-2026-1107.svg) ![forks](https://img.shields.io/github/forks/Iniivan13/CVE-2026-1107.svg)

## CVE-2026-1056
 The Snow Monkey Forms plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation in the 'generate_user_dirpath' function in all versions up to, and including, 12.0.3. This makes it possible for unauthenticated attackers to delete arbitrary files on the server, which can easily lead to remote code execution when the right file is deleted (such as wp-config.php).



- [https://github.com/ch4r0nn/CVE-2026-1056-POC](https://github.com/ch4r0nn/CVE-2026-1056-POC) :  ![starts](https://img.shields.io/github/stars/ch4r0nn/CVE-2026-1056-POC.svg) ![forks](https://img.shields.io/github/forks/ch4r0nn/CVE-2026-1056-POC.svg)

## CVE-2026-0920
 The LA-Studio Element Kit for Elementor plugin for WordPress is vulnerable to Administrative User Creation in all versions up to, and including, 1.5.6.3. This is due to the 'ajax_register_handle' function not restricting what user roles a user can register with. This makes it possible for unauthenticated attackers to supply the 'lakit_bkrole' parameter during registration and gain administrator access to the site.



- [https://github.com/John-doe-code-a11/CVE-2026-0920](https://github.com/John-doe-code-a11/CVE-2026-0920) :  ![starts](https://img.shields.io/github/stars/John-doe-code-a11/CVE-2026-0920.svg) ![forks](https://img.shields.io/github/forks/John-doe-code-a11/CVE-2026-0920.svg)

- [https://github.com/O99099O/By-Poloss..-..CVE-2026-0920](https://github.com/O99099O/By-Poloss..-..CVE-2026-0920) :  ![starts](https://img.shields.io/github/stars/O99099O/By-Poloss..-..CVE-2026-0920.svg) ![forks](https://img.shields.io/github/forks/O99099O/By-Poloss..-..CVE-2026-0920.svg)

- [https://github.com/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit](https://github.com/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit) :  ![starts](https://img.shields.io/github/stars/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit.svg) ![forks](https://img.shields.io/github/forks/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit.svg)

## CVE-2026-0842
 A flaw has been found in Flycatcher Toys smART Sketcher up to 2.0. This affects an unknown part of the component Bluetooth Low Energy Interface. This manipulation causes missing authentication. The attack can only be done within the local network. The exploit has been published and may be used. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/davidrxchester/smart-sketcher-upload](https://github.com/davidrxchester/smart-sketcher-upload) :  ![starts](https://img.shields.io/github/stars/davidrxchester/smart-sketcher-upload.svg) ![forks](https://img.shields.io/github/forks/davidrxchester/smart-sketcher-upload.svg)

## CVE-2026-0834
 Logic vulnerability in TP-Link Archer C20 v6.0 and Archer AX53 v1.0 (TDDP module) allows unauthenticated adjacent attackers to execute administrative commands including factory reset and device reboot without credentials. Attackers on the adjacent network can remotely trigger factory resets and reboots without credentials, causing configuration loss and interruption of device availability.This issue affects Archer C20 v6.0  V6_251031.


Archer AX53 v1.0  

V1_251215



- [https://github.com/mattgsys/CVE-2026-0834](https://github.com/mattgsys/CVE-2026-0834) :  ![starts](https://img.shields.io/github/stars/mattgsys/CVE-2026-0834.svg) ![forks](https://img.shields.io/github/forks/mattgsys/CVE-2026-0834.svg)

## CVE-2026-0628
 Insufficient policy enforcement in WebView tag in Google Chrome prior to 143.0.7499.192 allowed an attacker who convinced a user to install a malicious extension to inject scripts or HTML into a privileged page via a crafted Chrome Extension. (Chromium security severity: High)



- [https://github.com/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation](https://github.com/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation.svg)

- [https://github.com/fevar54/CVE-2026-0628-POC](https://github.com/fevar54/CVE-2026-0628-POC) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-0628-POC.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-0628-POC.svg)

## CVE-2026-0622
 Open 5GS WebUI uses a hard-coded JWT signing key (change-me) whenever the environment variable JWT_SECRET_KEY is unset



- [https://github.com/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor) :  ![starts](https://img.shields.io/github/stars/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor.svg) ![forks](https://img.shields.io/github/forks/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor.svg)

## CVE-2026-0594
 The List Site Contributors plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the 'alpha' parameter in versions up to, and including, 1.1.8 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link.



- [https://github.com/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit](https://github.com/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit) :  ![starts](https://img.shields.io/github/stars/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit.svg) ![forks](https://img.shields.io/github/forks/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit.svg)

## CVE-2026-0547
 A vulnerability was found in PHPGurukul Online Course Registration up to 3.1. This issue affects some unknown processing of the file /admin/edit-student-profile.php of the component Student Registration Page. The manipulation of the argument photo results in unrestricted upload. The attack may be launched remotely. The exploit has been made public and could be used.



- [https://github.com/rsecroot/CVE-2026-0547](https://github.com/rsecroot/CVE-2026-0547) :  ![starts](https://img.shields.io/github/stars/rsecroot/CVE-2026-0547.svg) ![forks](https://img.shields.io/github/forks/rsecroot/CVE-2026-0547.svg)

## CVE-2026-0227
 A vulnerability in Palo Alto Networks PAN-OS software enables an unauthenticated attacker to cause a denial of service (DoS) to the firewall. Repeated attempts to trigger this issue results in the firewall entering into maintenance mode.



- [https://github.com/CkAbhijit/CVE-2026-0227-Advanced-Scanner](https://github.com/CkAbhijit/CVE-2026-0227-Advanced-Scanner) :  ![starts](https://img.shields.io/github/stars/CkAbhijit/CVE-2026-0227-Advanced-Scanner.svg) ![forks](https://img.shields.io/github/forks/CkAbhijit/CVE-2026-0227-Advanced-Scanner.svg)

- [https://github.com/TeeyaR/CVE-2026-0227-Palo-Alto](https://github.com/TeeyaR/CVE-2026-0227-Palo-Alto) :  ![starts](https://img.shields.io/github/stars/TeeyaR/CVE-2026-0227-Palo-Alto.svg) ![forks](https://img.shields.io/github/forks/TeeyaR/CVE-2026-0227-Palo-Alto.svg)

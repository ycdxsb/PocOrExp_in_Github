# Update 2025-04-20
## CVE-2025-32682
 Unrestricted Upload of File with Dangerous Type vulnerability in RomanCode MapSVG Lite allows Upload a Web Shell to a Web Server. This issue affects MapSVG Lite: from n/a through 8.5.34.

- [https://github.com/Nxploited/CVE-2025-32682](https://github.com/Nxploited/CVE-2025-32682) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-32682.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-32682.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/ProDefense/CVE-2025-32433](https://github.com/ProDefense/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/ProDefense/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/ProDefense/CVE-2025-32433.svg)
- [https://github.com/LemieOne/CVE-2025-32433](https://github.com/LemieOne/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/LemieOne/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/LemieOne/CVE-2025-32433.svg)
- [https://github.com/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC](https://github.com/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC.svg)
- [https://github.com/darses/CVE-2025-32433](https://github.com/darses/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/darses/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/darses/CVE-2025-32433.svg)
- [https://github.com/teamtopkarl/CVE-2025-32433](https://github.com/teamtopkarl/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/teamtopkarl/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/teamtopkarl/CVE-2025-32433.svg)
- [https://github.com/Epivalent/CVE-2025-32433-detection](https://github.com/Epivalent/CVE-2025-32433-detection) :  ![starts](https://img.shields.io/github/stars/Epivalent/CVE-2025-32433-detection.svg) ![forks](https://img.shields.io/github/forks/Epivalent/CVE-2025-32433-detection.svg)
- [https://github.com/exa-offsec/ssh_erlangotp_rce](https://github.com/exa-offsec/ssh_erlangotp_rce) :  ![starts](https://img.shields.io/github/stars/exa-offsec/ssh_erlangotp_rce.svg) ![forks](https://img.shields.io/github/forks/exa-offsec/ssh_erlangotp_rce.svg)
- [https://github.com/m0usem0use/erl_mouse](https://github.com/m0usem0use/erl_mouse) :  ![starts](https://img.shields.io/github/stars/m0usem0use/erl_mouse.svg) ![forks](https://img.shields.io/github/forks/m0usem0use/erl_mouse.svg)


## CVE-2025-32395
 Vite is a frontend tooling framework for javascript. Prior to 6.2.6, 6.1.5, 6.0.15, 5.4.18, and 4.5.13, the contents of arbitrary files can be returned to the browser if the dev server is running on Node or Bun. HTTP 1.1 spec (RFC 9112) does not allow # in request-target. Although an attacker can send such a request. For those requests with an invalid request-line (it includes request-target), the spec recommends to reject them with 400 or 301. The same can be said for HTTP 2. On Node and Bun, those requests are not rejected internally and is passed to the user land. For those requests, the value of http.IncomingMessage.url contains #. Vite assumed req.url won't contain # when checking server.fs.deny, allowing those kinds of requests to bypass the check. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) and running the Vite dev server on runtimes that are not Deno (e.g. Node, Bun) are affected. This vulnerability is fixed in 6.2.6, 6.1.5, 6.0.15, 5.4.18, and 4.5.13.

- [https://github.com/ruiwenya/CVE-2025-32395](https://github.com/ruiwenya/CVE-2025-32395) :  ![starts](https://img.shields.io/github/stars/ruiwenya/CVE-2025-32395.svg) ![forks](https://img.shields.io/github/forks/ruiwenya/CVE-2025-32395.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg)


## CVE-2025-28355
 Volmarg Personal Management System 1.4.65 is vulnerable to Cross Site Request Forgery (CSRF) allowing attackers to execute arbitrary code and obtain sensitive information via the SameSite cookie attribute defaults value set to none

- [https://github.com/abbisQQ/CVE-2025-28355](https://github.com/abbisQQ/CVE-2025-28355) :  ![starts](https://img.shields.io/github/stars/abbisQQ/CVE-2025-28355.svg) ![forks](https://img.shields.io/github/forks/abbisQQ/CVE-2025-28355.svg)


## CVE-2025-25427
 A Stored cross-site scripting (XSS) vulnerability in upnp page of the web Interface in TP-Link WR841N v14/v14.6/v14.8 = Build 231119 Rel.67074n allows adjacent attackers to inject arbitrary JavaScript code via the port mapping description. This leads to an execution of the JavaScript payload when the upnp page is loaded.

- [https://github.com/slin99/2025-25427](https://github.com/slin99/2025-25427) :  ![starts](https://img.shields.io/github/stars/slin99/2025-25427.svg) ![forks](https://img.shields.io/github/forks/slin99/2025-25427.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/Erosion2020/CVE-2025-24813-vulhub](https://github.com/Erosion2020/CVE-2025-24813-vulhub) :  ![starts](https://img.shields.io/github/stars/Erosion2020/CVE-2025-24813-vulhub.svg) ![forks](https://img.shields.io/github/forks/Erosion2020/CVE-2025-24813-vulhub.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/xigney/CVE-2025-24054_PoC](https://github.com/xigney/CVE-2025-24054_PoC) :  ![starts](https://img.shields.io/github/stars/xigney/CVE-2025-24054_PoC.svg) ![forks](https://img.shields.io/github/forks/xigney/CVE-2025-24054_PoC.svg)


## CVE-2025-24054
 External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/xigney/CVE-2025-24054_PoC](https://github.com/xigney/CVE-2025-24054_PoC) :  ![starts](https://img.shields.io/github/stars/xigney/CVE-2025-24054_PoC.svg) ![forks](https://img.shields.io/github/forks/xigney/CVE-2025-24054_PoC.svg)


## CVE-2025-21756
 entry_SYSCALL_64_after_hwframe+0x76/0x7e

- [https://github.com/hoefler02/CVE-2025-21756](https://github.com/hoefler02/CVE-2025-21756) :  ![starts](https://img.shields.io/github/stars/hoefler02/CVE-2025-21756.svg) ![forks](https://img.shields.io/github/forks/hoefler02/CVE-2025-21756.svg)


## CVE-2024-53924
 Pycel through 1.0b30, when operating on an untrusted spreadsheet, allows code execution via a crafted formula in a cell, such as one beginning with the =IF(A1=200, eval("__import__('os').system( substring.

- [https://github.com/aelmosalamy/CVE-2024-53924](https://github.com/aelmosalamy/CVE-2024-53924) :  ![starts](https://img.shields.io/github/stars/aelmosalamy/CVE-2024-53924.svg) ![forks](https://img.shields.io/github/forks/aelmosalamy/CVE-2024-53924.svg)


## CVE-2024-53591
 An issue in the login page of Seclore v3.27.5.0 allows attackers to bypass authentication via a brute force attack.

- [https://github.com/aljoharasubaie/CVE-2024-53591](https://github.com/aljoharasubaie/CVE-2024-53591) :  ![starts](https://img.shields.io/github/stars/aljoharasubaie/CVE-2024-53591.svg) ![forks](https://img.shields.io/github/forks/aljoharasubaie/CVE-2024-53591.svg)


## CVE-2024-46713
this patch.

- [https://github.com/enlist12/CVE-2024-46713](https://github.com/enlist12/CVE-2024-46713) :  ![starts](https://img.shields.io/github/stars/enlist12/CVE-2024-46713.svg) ![forks](https://img.shields.io/github/forks/enlist12/CVE-2024-46713.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/Gill-Singh-A/CVE-2024-4577-Exploit](https://github.com/Gill-Singh-A/CVE-2024-4577-Exploit) :  ![starts](https://img.shields.io/github/stars/Gill-Singh-A/CVE-2024-4577-Exploit.svg) ![forks](https://img.shields.io/github/forks/Gill-Singh-A/CVE-2024-4577-Exploit.svg)


## CVE-2024-0044
 In createSessionInternal of PackageInstallerService.java, there is a possible run-as any app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/sridhar-sec/EvilDroid](https://github.com/sridhar-sec/EvilDroid) :  ![starts](https://img.shields.io/github/stars/sridhar-sec/EvilDroid.svg) ![forks](https://img.shields.io/github/forks/sridhar-sec/EvilDroid.svg)


## CVE-2023-27997
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS version 7.2.4 and below, version 7.0.11 and below, version 6.4.12 and below, version 6.0.16 and below and FortiProxy version 7.2.3 and below, version 7.0.9 and below, version 2.0.12 and below, version 1.2 all versions, version 1.1 all versions SSL-VPN may allow a remote attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/onurkerembozkurt/fgt-cve-2023-27997-exploit](https://github.com/onurkerembozkurt/fgt-cve-2023-27997-exploit) :  ![starts](https://img.shields.io/github/stars/onurkerembozkurt/fgt-cve-2023-27997-exploit.svg) ![forks](https://img.shields.io/github/forks/onurkerembozkurt/fgt-cve-2023-27997-exploit.svg)


## CVE-2021-44967
 A Remote Code Execution (RCE) vulnerabilty exists in LimeSurvey 5.2.4 via the upload and install plugins function, which could let a remote malicious user upload an arbitrary PHP code file. NOTE: the Supplier's position is that plugins intentionally can contain arbitrary PHP code, and can only be installed by a superadmin, and therefore the security model is not violated by this finding.

- [https://github.com/monke443/CVE-2021-44967](https://github.com/monke443/CVE-2021-44967) :  ![starts](https://img.shields.io/github/stars/monke443/CVE-2021-44967.svg) ![forks](https://img.shields.io/github/forks/monke443/CVE-2021-44967.svg)


## CVE-2021-25646
 Apache Druid includes the ability to execute user-provided JavaScript code embedded in various types of requests. This functionality is intended for use in high-trust environments, and is disabled by default. However, in Druid 0.20.0 and earlier, it is possible for an authenticated user to send a specially-crafted request that forces Druid to run user-provided JavaScript code for that request, regardless of server configuration. This can be leveraged to execute code on the target machine with the privileges of the Druid server process.

- [https://github.com/k7pro/CVE-2021-25646-exp](https://github.com/k7pro/CVE-2021-25646-exp) :  ![starts](https://img.shields.io/github/stars/k7pro/CVE-2021-25646-exp.svg) ![forks](https://img.shields.io/github/forks/k7pro/CVE-2021-25646-exp.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/madanokr001/CVE-2020-0796](https://github.com/madanokr001/CVE-2020-0796) :  ![starts](https://img.shields.io/github/stars/madanokr001/CVE-2020-0796.svg) ![forks](https://img.shields.io/github/forks/madanokr001/CVE-2020-0796.svg)


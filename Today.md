# Update 2026-08-02
## CVE-2026-66066
 Action Pack is a framework for handling and responding to web requests. In versions prior to 7.2.3.2, 8.0.5.1 and 8.1.3.1, Active Storage does not disable libvips operations marked unsafe for untrusted content, allowing a crafted upload to invoke such an operation. Consuming applications are affected when configured to use libvips and accept image uploads from untrusted users. An unauthenticated attacker may exploit this behavior to read arbitrary files accessible to the Rails process, including environment variables and application secrets. Exposure of credentials such as secret_key_base or external-service tokens may enable remote code execution or lateral movement. This issue has been fixed in versions 7.2.3.2, 8.0.5.1 and 8.1.3.1.

- [https://github.com/0xsha/KindaRails2Shell](https://github.com/0xsha/KindaRails2Shell) :  ![starts](https://img.shields.io/github/stars/0xsha/KindaRails2Shell.svg) ![forks](https://img.shields.io/github/forks/0xsha/KindaRails2Shell.svg)


## CVE-2026-64531
ownership and truncates on close failure.

- [https://github.com/mahfuzreham/OVSwrap-CVE-2026-64531-Mitigation-Tool](https://github.com/mahfuzreham/OVSwrap-CVE-2026-64531-Mitigation-Tool) :  ![starts](https://img.shields.io/github/stars/mahfuzreham/OVSwrap-CVE-2026-64531-Mitigation-Tool.svg) ![forks](https://img.shields.io/github/forks/mahfuzreham/OVSwrap-CVE-2026-64531-Mitigation-Tool.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/KrakenEU/CVE-2026-54121-CertiGhost](https://github.com/KrakenEU/CVE-2026-54121-CertiGhost) :  ![starts](https://img.shields.io/github/stars/KrakenEU/CVE-2026-54121-CertiGhost.svg) ![forks](https://img.shields.io/github/forks/KrakenEU/CVE-2026-54121-CertiGhost.svg)
- [https://github.com/nafiez/Metasploit-CVE-2026-54121-Certighost](https://github.com/nafiez/Metasploit-CVE-2026-54121-Certighost) :  ![starts](https://img.shields.io/github/stars/nafiez/Metasploit-CVE-2026-54121-Certighost.svg) ![forks](https://img.shields.io/github/forks/nafiez/Metasploit-CVE-2026-54121-Certighost.svg)


## CVE-2026-52134
 An issue in the parseGoosePayload() function (/goose/goose_receiver.c) of libiec61850 v1.6 allows attackers to bypass authentication via a captured GOOSE frame.

- [https://github.com/if-forget/CVE-2026-52134-libiec61850](https://github.com/if-forget/CVE-2026-52134-libiec61850) :  ![starts](https://img.shields.io/github/stars/if-forget/CVE-2026-52134-libiec61850.svg) ![forks](https://img.shields.io/github/forks/if-forget/CVE-2026-52134-libiec61850.svg)


## CVE-2026-47668
 DbGate is cross-platform database manager. In versions 7.1.8 and prior, DbGate's JSON script runner (`POST /runners/start`) allows remote code execution via code injection in the `functionName` parameter of JSON script `assign` commands. The `functionName` value is interpolated directly into dynamically generated JavaScript source code via string concatenation. The generated code is then executed in a forked Node.js child process. Version 7.1.9 contains a patch.

- [https://github.com/s-vx/CVE-2026-47668](https://github.com/s-vx/CVE-2026-47668) :  ![starts](https://img.shields.io/github/stars/s-vx/CVE-2026-47668.svg) ![forks](https://img.shields.io/github/forks/s-vx/CVE-2026-47668.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/LuZe0y/pd2425-cve-2026-43499-config](https://github.com/LuZe0y/pd2425-cve-2026-43499-config) :  ![starts](https://img.shields.io/github/stars/LuZe0y/pd2425-cve-2026-43499-config.svg) ![forks](https://img.shields.io/github/forks/LuZe0y/pd2425-cve-2026-43499-config.svg)
- [https://github.com/datfooldive/ghostlock-emerald](https://github.com/datfooldive/ghostlock-emerald) :  ![starts](https://img.shields.io/github/stars/datfooldive/ghostlock-emerald.svg) ![forks](https://img.shields.io/github/forks/datfooldive/ghostlock-emerald.svg)
- [https://github.com/NothingFumo/ghostlock-aresin](https://github.com/NothingFumo/ghostlock-aresin) :  ![starts](https://img.shields.io/github/stars/NothingFumo/ghostlock-aresin.svg) ![forks](https://img.shields.io/github/forks/NothingFumo/ghostlock-aresin.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/AadityaKandel/CVE-2026-43284](https://github.com/AadityaKandel/CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/AadityaKandel/CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/AadityaKandel/CVE-2026-43284.svg)
- [https://github.com/nabhan-mohy/Dirty-Frag-Research-CVE-2026-43284-](https://github.com/nabhan-mohy/Dirty-Frag-Research-CVE-2026-43284-) :  ![starts](https://img.shields.io/github/stars/nabhan-mohy/Dirty-Frag-Research-CVE-2026-43284-.svg) ![forks](https://img.shields.io/github/forks/nabhan-mohy/Dirty-Frag-Research-CVE-2026-43284-.svg)


## CVE-2026-41889
 pgx is a PostgreSQL driver and toolkit for Go. Prior to version 5.9.2, SQL injection can occur when the non-default simple protocol is used, a dollar quoted string literal is used in the SQL query, that string literal contains text that would be would be interpreted as a placeholder outside of a string literal, and the value of that placeholder is controllable by the attacker. This issue has been patched in version 5.9.2.

- [https://github.com/slashid/baton-retool](https://github.com/slashid/baton-retool) :  ![starts](https://img.shields.io/github/stars/slashid/baton-retool.svg) ![forks](https://img.shields.io/github/forks/slashid/baton-retool.svg)


## CVE-2026-32286
 The DataRow.Decode function fails to properly validate field lengths. A malicious or compromised PostgreSQL server can send a DataRow message with a negative field length, causing a slice bounds out of range panic.

- [https://github.com/slashid/baton-retool](https://github.com/slashid/baton-retool) :  ![starts](https://img.shields.io/github/stars/slashid/baton-retool.svg) ![forks](https://img.shields.io/github/forks/slashid/baton-retool.svg)


## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/Giangdurian/CVE-2026-21858-and-CVE-2025-68613](https://github.com/Giangdurian/CVE-2026-21858-and-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/Giangdurian/CVE-2026-21858-and-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/Giangdurian/CVE-2026-21858-and-CVE-2025-68613.svg)


## CVE-2026-17351
This issue affects pgAdmin 4: from 9.13 before 9.17.

- [https://github.com/Hunt-Benito/pgadmin-ai-assistant-sql-injection-cve-2026-17351-lexer-differential-bypass](https://github.com/Hunt-Benito/pgadmin-ai-assistant-sql-injection-cve-2026-17351-lexer-differential-bypass) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/pgadmin-ai-assistant-sql-injection-cve-2026-17351-lexer-differential-bypass.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/pgadmin-ai-assistant-sql-injection-cve-2026-17351-lexer-differential-bypass.svg)


## CVE-2026-16723
 A remote code execution (RCE) vulnerability exists in fastjson 1.2.68 through 1.2.83. This vulnerability is exploitable under fastjson's stock default configuration — no AutoType enablement required, no classpath gadget required.

- [https://github.com/1xPwn/CVE-2026-16723](https://github.com/1xPwn/CVE-2026-16723) :  ![starts](https://img.shields.io/github/stars/1xPwn/CVE-2026-16723.svg) ![forks](https://img.shields.io/github/forks/1xPwn/CVE-2026-16723.svg)
- [https://github.com/fazilbaig1/CVE-2026-16723](https://github.com/fazilbaig1/CVE-2026-16723) :  ![starts](https://img.shields.io/github/stars/fazilbaig1/CVE-2026-16723.svg) ![forks](https://img.shields.io/github/forks/fazilbaig1/CVE-2026-16723.svg)


## CVE-2026-8347
 Concrete CMS 9.5.0 and below is vulnerable to IDOR + wrong-authorization-level in the Express association Reorder dialog.  This can cause Cross-entity state tampering with view-only permission on one entry. To be affected, a website has to be using express and relying on express entity ordering. The Concrete CMS security team gave this vulnerability a CVSS v.4.0 score of 2.3 with vector CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N. Thanks Winston Crooker for reporting.

- [https://github.com/aj2108/CVE-2026-8347](https://github.com/aj2108/CVE-2026-8347) :  ![starts](https://img.shields.io/github/stars/aj2108/CVE-2026-8347.svg) ![forks](https://img.shields.io/github/forks/aj2108/CVE-2026-8347.svg)
- [https://github.com/aj2108/CVE-2026-8337](https://github.com/aj2108/CVE-2026-8337) :  ![starts](https://img.shields.io/github/stars/aj2108/CVE-2026-8337.svg) ![forks](https://img.shields.io/github/forks/aj2108/CVE-2026-8337.svg)


## CVE-2026-8337
 Concrete CMS 9.5.0 and below is vulnerable to IDOR in surveys. To be vulnerable, a site would have to be configured in such a way that both public and private surveys are present on the site. An unauthenticated attacker can vote in the restricted survey by submitting the restricted optionID through the public survey’s endpoint. The Concrete CMS security team gave this vulnerability a CVSS v.4.0 score of 6.3 with vector CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N. Thanks  Zer0daySec https://github.com/Zee99y  for reporting

- [https://github.com/aj2108/CVE-2026-8337](https://github.com/aj2108/CVE-2026-8337) :  ![starts](https://img.shields.io/github/stars/aj2108/CVE-2026-8337.svg) ![forks](https://img.shields.io/github/forks/aj2108/CVE-2026-8337.svg)


## CVE-2026-6759
 Use-after-free in the Widget: Cocoa component. This vulnerability was fixed in Firefox 150, Firefox ESR 140.10, Thunderbird 150, and Thunderbird 140.10.

- [https://github.com/LazyTitan33/CVE-2026-67599_ClearOS_RCE](https://github.com/LazyTitan33/CVE-2026-67599_ClearOS_RCE) :  ![starts](https://img.shields.io/github/stars/LazyTitan33/CVE-2026-67599_ClearOS_RCE.svg) ![forks](https://img.shields.io/github/forks/LazyTitan33/CVE-2026-67599_ClearOS_RCE.svg)


## CVE-2026-6356
 A vulnerability in the web application allows standard users to escalate their privileges to those of a super administrator through parameter manipulation, enabling them to access and modify sensitive information.

- [https://github.com/redr0nin/CVE-2026-63563](https://github.com/redr0nin/CVE-2026-63563) :  ![starts](https://img.shields.io/github/stars/redr0nin/CVE-2026-63563.svg) ![forks](https://img.shields.io/github/forks/redr0nin/CVE-2026-63563.svg)


## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/Giangdurian/CVE-2026-21858-and-CVE-2025-68613](https://github.com/Giangdurian/CVE-2026-21858-and-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/Giangdurian/CVE-2026-21858-and-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/Giangdurian/CVE-2026-21858-and-CVE-2025-68613.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)


## CVE-2025-60595
 SPH Engineering UgCS 5.13.0 is vulnerable to Arbitary code execution.

- [https://github.com/bilalclicksafe/CVE-2025-60595](https://github.com/bilalclicksafe/CVE-2025-60595) :  ![starts](https://img.shields.io/github/stars/bilalclicksafe/CVE-2025-60595.svg) ![forks](https://img.shields.io/github/forks/bilalclicksafe/CVE-2025-60595.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/1xPwn/CVE-2025-32463](https://github.com/1xPwn/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/1xPwn/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/1xPwn/CVE-2025-32463.svg)


## CVE-2025-15001
 The FS Registration Password plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 1.0.1. This is due to the plugin not properly validating a user's identity prior to updating their password. This makes it possible for unauthenticated attackers to change arbitrary user's passwords, including administrators, and leverage that to gain access to their account.

- [https://github.com/r00thex/CVE-2025-15001-Exploit](https://github.com/r00thex/CVE-2025-15001-Exploit) :  ![starts](https://img.shields.io/github/stars/r00thex/CVE-2025-15001-Exploit.svg) ![forks](https://img.shields.io/github/forks/r00thex/CVE-2025-15001-Exploit.svg)


## CVE-2025-7384
 The Database for Contact Form 7, WPforms, Elementor forms plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 1.4.3 via deserialization of untrusted input in the get_lead_detail function. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain in the Contact Form 7 plugin, which is likely to be used alongside, allows attackers to delete arbitrary files, leading to a denial of service or remote code execution when the wp-config.php file is deleted.

- [https://github.com/Dungsocool/CVE-2025-7384](https://github.com/Dungsocool/CVE-2025-7384) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2025-7384.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2025-7384.svg)


## CVE-2025-7029
 A vulnerability in the Software SMI handler (SwSmiInputValue 0xB2) allows a local attacker to control the RBX register, which is used to derive pointers (OcHeader, OcData) passed into power and thermal configuration logic. These buffers are not validated before performing multiple structured memory writes based on OcSetup NVRAM values, enabling arbitrary SMRAM corruption and potential SMM privilege escalation.

- [https://github.com/ARES-SYS/uefi_bootkit_softlanding](https://github.com/ARES-SYS/uefi_bootkit_softlanding) :  ![starts](https://img.shields.io/github/stars/ARES-SYS/uefi_bootkit_softlanding.svg) ![forks](https://img.shields.io/github/forks/ARES-SYS/uefi_bootkit_softlanding.svg)


## CVE-2024-27198
 In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible

- [https://github.com/abiral-timalsina/Cyber-Defenders-lab-](https://github.com/abiral-timalsina/Cyber-Defenders-lab-) :  ![starts](https://img.shields.io/github/stars/abiral-timalsina/Cyber-Defenders-lab-.svg) ![forks](https://img.shields.io/github/forks/abiral-timalsina/Cyber-Defenders-lab-.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/Zedocun/Incident-Analysis-Response-Check-Point-Security-Gateway-CVE-2024-24919-LFI-Exploitation](https://github.com/Zedocun/Incident-Analysis-Response-Check-Point-Security-Gateway-CVE-2024-24919-LFI-Exploitation) :  ![starts](https://img.shields.io/github/stars/Zedocun/Incident-Analysis-Response-Check-Point-Security-Gateway-CVE-2024-24919-LFI-Exploitation.svg) ![forks](https://img.shields.io/github/forks/Zedocun/Incident-Analysis-Response-Check-Point-Security-Gateway-CVE-2024-24919-LFI-Exploitation.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox  126, Firefox ESR  115.11, and Thunderbird  115.11.

- [https://github.com/AnomalousVectors/cve-2024-4367-poc](https://github.com/AnomalousVectors/cve-2024-4367-poc) :  ![starts](https://img.shields.io/github/stars/AnomalousVectors/cve-2024-4367-poc.svg) ![forks](https://img.shields.io/github/forks/AnomalousVectors/cve-2024-4367-poc.svg)


## CVE-2023-0386
 A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel’s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

- [https://github.com/huovnn/CVE-2023-0386-go-poc](https://github.com/huovnn/CVE-2023-0386-go-poc) :  ![starts](https://img.shields.io/github/stars/huovnn/CVE-2023-0386-go-poc.svg) ![forks](https://img.shields.io/github/forks/huovnn/CVE-2023-0386-go-poc.svg)
- [https://github.com/anxs3c/TwoMillion-Machine-Writeup](https://github.com/anxs3c/TwoMillion-Machine-Writeup) :  ![starts](https://img.shields.io/github/stars/anxs3c/TwoMillion-Machine-Writeup.svg) ![forks](https://img.shields.io/github/forks/anxs3c/TwoMillion-Machine-Writeup.svg)


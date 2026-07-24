# Update 2026-07-24
## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/mcipekci/wp2shell](https://github.com/mcipekci/wp2shell) :  ![starts](https://img.shields.io/github/stars/mcipekci/wp2shell.svg) ![forks](https://img.shields.io/github/forks/mcipekci/wp2shell.svg)
- [https://github.com/gagaltotal/CVE-2026-63030-CVE-2026-60137-wp2shell-poc](https://github.com/gagaltotal/CVE-2026-63030-CVE-2026-60137-wp2shell-poc) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-63030-CVE-2026-60137-wp2shell-poc.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-63030-CVE-2026-60137-wp2shell-poc.svg)
- [https://github.com/wn-iqbal/wp2shell](https://github.com/wn-iqbal/wp2shell) :  ![starts](https://img.shields.io/github/stars/wn-iqbal/wp2shell.svg) ![forks](https://img.shields.io/github/forks/wn-iqbal/wp2shell.svg)
- [https://github.com/raphy76/wp2shell-poc-fulljs](https://github.com/raphy76/wp2shell-poc-fulljs) :  ![starts](https://img.shields.io/github/stars/raphy76/wp2shell-poc-fulljs.svg) ![forks](https://img.shields.io/github/forks/raphy76/wp2shell-poc-fulljs.svg)
- [https://github.com/Adrees-Basheer/wp2shell-vulnerability-scanner](https://github.com/Adrees-Basheer/wp2shell-vulnerability-scanner) :  ![starts](https://img.shields.io/github/stars/Adrees-Basheer/wp2shell-vulnerability-scanner.svg) ![forks](https://img.shields.io/github/forks/Adrees-Basheer/wp2shell-vulnerability-scanner.svg)


## CVE-2026-62145
 A vulnerability in Check Point Gaia Portal allows an authenticated attacker with read-only Gaia Portal privileges to execute commands with root privileges.

- [https://github.com/WadesWeaponShed/Check-Point-Trusted-Access-Review](https://github.com/WadesWeaponShed/Check-Point-Trusted-Access-Review) :  ![starts](https://img.shields.io/github/stars/WadesWeaponShed/Check-Point-Trusted-Access-Review.svg) ![forks](https://img.shields.io/github/forks/WadesWeaponShed/Check-Point-Trusted-Access-Review.svg)


## CVE-2026-62144
 An authentication bypass vulnerability in Check Point Security Management and Multi-Domain Security Management allows an unauthenticated remote attacker to execute administrative commands on the Management Server. Successful exploitation may also allow command execution on managed Security Gateways. Exploitation requires network access to the Management Server without firewall protection or a configuration that does not restrict Trusted Clients.

- [https://github.com/WadesWeaponShed/Check-Point-Trusted-Access-Review](https://github.com/WadesWeaponShed/Check-Point-Trusted-Access-Review) :  ![starts](https://img.shields.io/github/stars/WadesWeaponShed/Check-Point-Trusted-Access-Review.svg) ![forks](https://img.shields.io/github/forks/WadesWeaponShed/Check-Point-Trusted-Access-Review.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/mcipekci/wp2shell](https://github.com/mcipekci/wp2shell) :  ![starts](https://img.shields.io/github/stars/mcipekci/wp2shell.svg) ![forks](https://img.shields.io/github/forks/mcipekci/wp2shell.svg)
- [https://github.com/gagaltotal/CVE-2026-63030-CVE-2026-60137-wp2shell-poc](https://github.com/gagaltotal/CVE-2026-63030-CVE-2026-60137-wp2shell-poc) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-63030-CVE-2026-60137-wp2shell-poc.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-63030-CVE-2026-60137-wp2shell-poc.svg)
- [https://github.com/wn-iqbal/wp2shell](https://github.com/wn-iqbal/wp2shell) :  ![starts](https://img.shields.io/github/stars/wn-iqbal/wp2shell.svg) ![forks](https://img.shields.io/github/forks/wn-iqbal/wp2shell.svg)
- [https://github.com/Adrees-Basheer/wp2shell-vulnerability-scanner](https://github.com/Adrees-Basheer/wp2shell-vulnerability-scanner) :  ![starts](https://img.shields.io/github/stars/Adrees-Basheer/wp2shell-vulnerability-scanner.svg) ![forks](https://img.shields.io/github/forks/Adrees-Basheer/wp2shell-vulnerability-scanner.svg)


## CVE-2026-58138
 Orkes Conductor 3.21.21 before 3.30.2 contains an unauthenticated remote code execution vulnerability that allows remote attackers to execute arbitrary OS commands by submitting inline workflow definitions containing malicious JavaScript or Python expressions to the workflow API endpoint prior to authentication. Attackers can exploit unsandboxed GraalVM evaluators configured with HostAccess.ALL or allowAllAccess(true) through INLINE, LAMBDA, DO_WHILE, and SWITCH task types to invoke arbitrary system commands via Java reflection or direct subprocess calls.

- [https://github.com/0xgh057r3c0n/CVE-2026-58138](https://github.com/0xgh057r3c0n/CVE-2026-58138) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2026-58138.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2026-58138.svg)


## CVE-2026-56139
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. For deployments that cannot upgrade immediately, set muteException=true explicitly on the camel-undertow consumer (for example undertow: http://0.0.0.0:8080/api?muteException=true , or globally via the camel.component.undertow.mute-exception=true property), so that processing errors no longer return the stack trace to the client; note that on affected releases this workaround does not cover Rest DSL consumers, whose binding ignores the option until the fix is applied.

- [https://github.com/oscerd/CVE-2026-56139](https://github.com/oscerd/CVE-2026-56139) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-56139.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-56139.svg)


## CVE-2026-55994
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. The fix adds a dedicated IggyHeaderFilterStrategy (and a headerFilterStrategy endpoint option) that filters the Camel header namespace case-insensitively on inbound mapping, so externally-supplied Camel* / camel* headers are no longer copied into the Exchange. For deployments that cannot upgrade immediately, strip the Camel control headers from the inbound message before they reach any downstream producer (for example removeHeaders('Camel*') and removeHeaders('camel*') at the start of the route), restrict who can publish to the consumed Iggy stream/topic, and avoid bridging an untrusted consumer directly into an HTTP producer whose target URI can be driven from message headers.

- [https://github.com/oscerd/CVE-2026-55994](https://github.com/oscerd/CVE-2026-55994) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-55994.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-55994.svg)


## CVE-2026-55993
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. The fix makes the consumer apply the HeaderFilterStrategy it already inherits from the HTTP/servlet stack, filtering the Camel header namespace case-insensitively on inbound mapping, so externally-supplied Camel* / camel* headers are no longer copied into the Exchange. For deployments that cannot upgrade immediately, strip the Camel control headers from the inbound message before they reach any downstream producer (for example removeHeaders('Camel*') and removeHeaders('camel*') at the start of the route), require authentication on the WebSocket endpoint, and avoid bridging an untrusted consumer directly into an HTTP producer whose target URI can be driven from message headers.

- [https://github.com/oscerd/CVE-2026-55993](https://github.com/oscerd/CVE-2026-55993) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-55993.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-55993.svg)


## CVE-2026-45729
 Thor Vector Graphics (ThorVG) is a production-ready vector graphics engine. Prior to version 1.0.5, a null pointer dereference in SvgLoader::run() allows any caller that passes untrusted SVG data to Picture::load() to crash the process with a 6-byte payload. This issue has been patched in version 1.0.5.

- [https://github.com/yeahhbean/CVE-2026-45729](https://github.com/yeahhbean/CVE-2026-45729) :  ![starts](https://img.shields.io/github/stars/yeahhbean/CVE-2026-45729.svg) ![forks](https://img.shields.io/github/forks/yeahhbean/CVE-2026-45729.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/gagaltotal/CVE-2026-43499-PoC-Scanner](https://github.com/gagaltotal/CVE-2026-43499-PoC-Scanner) :  ![starts](https://img.shields.io/github/stars/gagaltotal/CVE-2026-43499-PoC-Scanner.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/CVE-2026-43499-PoC-Scanner.svg)


## CVE-2026-42533
 Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/seguridadentrerios/CVE-2026-42533](https://github.com/seguridadentrerios/CVE-2026-42533) :  ![starts](https://img.shields.io/github/stars/seguridadentrerios/CVE-2026-42533.svg) ![forks](https://img.shields.io/github/forks/seguridadentrerios/CVE-2026-42533.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/razureink/cve-2026-41940-cpanel_authbypass_reproduction](https://github.com/razureink/cve-2026-41940-cpanel_authbypass_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2026-41940-cpanel_authbypass_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2026-41940-cpanel_authbypass_reproduction.svg)


## CVE-2026-41089
 Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.

- [https://github.com/opensource-arrozconpollo191/CVE-2026-41089-Netlogon-RCE](https://github.com/opensource-arrozconpollo191/CVE-2026-41089-Netlogon-RCE) :  ![starts](https://img.shields.io/github/stars/opensource-arrozconpollo191/CVE-2026-41089-Netlogon-RCE.svg) ![forks](https://img.shields.io/github/forks/opensource-arrozconpollo191/CVE-2026-41089-Netlogon-RCE.svg)


## CVE-2026-38766
 An issue in Unistal Systems Pvt. Ltd.Protegent 360 v2.0.0.4 allows a local attacker to escalate privileges via the sub_186f4 function

- [https://github.com/D7EAD/CVE-2026-38766](https://github.com/D7EAD/CVE-2026-38766) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-38766.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-38766.svg)


## CVE-2026-38765
 An issue in Unistal Systems Pvt. Ltd.Protegent 360 v2.0.0.4 allows a local attacker to escalate privileges via the kernel driver pgsecdl.sys

- [https://github.com/D7EAD/CVE-2026-38765](https://github.com/D7EAD/CVE-2026-38765) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-38765.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-38765.svg)


## CVE-2026-38763
 An issue in Unistal Systems Pvt. Ltd.Protegent 360 v2.0.0.4 allows a local attacker to cause a denial of service via the function sub_13828

- [https://github.com/D7EAD/CVE-2026-38763](https://github.com/D7EAD/CVE-2026-38763) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-38763.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-38763.svg)


## CVE-2026-38526
 An authenticated arbitrary file upload vulnerability in the /admin/tinymce/upload endpoint of Webkul Krayin CRM v2.2.x allows attackers to execute arbitrary code via uploading a crafted PHP file.

- [https://github.com/Industri4l-H3ll-Xpl0it3rs/CVE-2026-38526-KrayinCRM-RCE](https://github.com/Industri4l-H3ll-Xpl0it3rs/CVE-2026-38526-KrayinCRM-RCE) :  ![starts](https://img.shields.io/github/stars/Industri4l-H3ll-Xpl0it3rs/CVE-2026-38526-KrayinCRM-RCE.svg) ![forks](https://img.shields.io/github/forks/Industri4l-H3ll-Xpl0it3rs/CVE-2026-38526-KrayinCRM-RCE.svg)


## CVE-2026-34486
Users are recommended to upgrade to version 11.0.21, 10.1.54 or 9.0.117, which fix the issue.

- [https://github.com/razureink/cve-2026-34486-tomcat_encrypt_bypass_reproduction](https://github.com/razureink/cve-2026-34486-tomcat_encrypt_bypass_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2026-34486-tomcat_encrypt_bypass_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2026-34486-tomcat_encrypt_bypass_reproduction.svg)


## CVE-2026-29145
Users are recommended to upgrade to version Tomcat Native 1.3.7 or 2.0.14 and Tomcat 11.0.20, 10.1.53 and 9.0.116, which fix the issue.

- [https://github.com/sancliffe/CVE-2026-29145-Tester](https://github.com/sancliffe/CVE-2026-29145-Tester) :  ![starts](https://img.shields.io/github/stars/sancliffe/CVE-2026-29145-Tester.svg) ![forks](https://img.shields.io/github/forks/sancliffe/CVE-2026-29145-Tester.svg)


## CVE-2026-22226
Build 20260430.

- [https://github.com/LucasVanHaaren/CVE-2026-22226](https://github.com/LucasVanHaaren/CVE-2026-22226) :  ![starts](https://img.shields.io/github/stars/LucasVanHaaren/CVE-2026-22226.svg) ![forks](https://img.shields.io/github/forks/LucasVanHaaren/CVE-2026-22226.svg)


## CVE-2026-16232
 An authentication bypass vulnerability in the Check Point SmartConsole login process allows an unauthenticated remote attacker to obtain an application login token and use it to authenticate with full administrative privileges. Successful exploitation allows the attacker to modify security policies and security configurations. Remote exploitation requires internet access to the Management Server IP address and a configuration that does not restrict Trusted Clients. Check Point is aware that this vulnerability is being exploited and has affected a very small number of customers.

- [https://github.com/WadesWeaponShed/Check-Point-Trusted-Access-Review](https://github.com/WadesWeaponShed/Check-Point-Trusted-Access-Review) :  ![starts](https://img.shields.io/github/stars/WadesWeaponShed/Check-Point-Trusted-Access-Review.svg) ![forks](https://img.shields.io/github/forks/WadesWeaponShed/Check-Point-Trusted-Access-Review.svg)


## CVE-2026-5005
This issue affects OKRs & Goals: from 28220 before 28398.

- [https://github.com/HORKimhab/CVE-2026-50055](https://github.com/HORKimhab/CVE-2026-50055) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-50055.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-50055.svg)


## CVE-2026-2406
This issue affects Online Registration and Workflow Management System: through 12022026.

- [https://github.com/SimoesCTT/CTT-Sovereign-Vortex](https://github.com/SimoesCTT/CTT-Sovereign-Vortex) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-Sovereign-Vortex.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-Sovereign-Vortex.svg)


## CVE-2026-2395
This issue affects No Code Platform: from 4.3.1.0 through 20260722. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/open-flaw/CVE-2026-2395](https://github.com/open-flaw/CVE-2026-2395) :  ![starts](https://img.shields.io/github/stars/open-flaw/CVE-2026-2395.svg) ![forks](https://img.shields.io/github/forks/open-flaw/CVE-2026-2395.svg)


## CVE-2026-1654
 The Peter's Date Countdown plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the `$_SERVER['PHP_SELF']` parameter in all versions up to, and including, 2.0.0 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link.

- [https://github.com/huseyn0vs/CVE-2026-16540-SimplyScheduleAppointments](https://github.com/huseyn0vs/CVE-2026-16540-SimplyScheduleAppointments) :  ![starts](https://img.shields.io/github/stars/huseyn0vs/CVE-2026-16540-SimplyScheduleAppointments.svg) ![forks](https://img.shields.io/github/forks/huseyn0vs/CVE-2026-16540-SimplyScheduleAppointments.svg)


## CVE-2026-1426
 The Advanced AJAX Product Filters plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.1.9.6 via deserialization of untrusted input in the shortcode_check function within the Live Composer compatibility layer. This makes it possible for authenticated attackers, with Author-level access and above, to inject a PHP Object. No known POP chain is present in the vulnerable software, which means this vulnerability has no impact unless another plugin or theme containing a POP chain is installed on the site. If a POP chain is present via an additional plugin or theme installed on the target system, it may allow the attacker to perform actions like delete arbitrary files, retrieve sensitive data, or execute code depending on the POP chain present. Note: This vulnerability requires the Live Composer plugin to also be installed and active.

- [https://github.com/4minx/CVE-2026-14266](https://github.com/4minx/CVE-2026-14266) :  ![starts](https://img.shields.io/github/stars/4minx/CVE-2026-14266.svg) ![forks](https://img.shields.io/github/forks/4minx/CVE-2026-14266.svg)


## CVE-2025-69421
OpenSSL 3.6, 3.5, 3.4, 3.3, 3.0, 1.1.1 and 1.0.2 are vulnerable to this issue.

- [https://github.com/Kha-Beleh/PoC-CVE-2025-69421](https://github.com/Kha-Beleh/PoC-CVE-2025-69421) :  ![starts](https://img.shields.io/github/stars/Kha-Beleh/PoC-CVE-2025-69421.svg) ![forks](https://img.shields.io/github/forks/Kha-Beleh/PoC-CVE-2025-69421.svg)


## CVE-2025-69420
OpenSSL 1.0.2 is not affected by this issue.

- [https://github.com/Kha-Beleh/PoC-CVE-2025-69420](https://github.com/Kha-Beleh/PoC-CVE-2025-69420) :  ![starts](https://img.shields.io/github/stars/Kha-Beleh/PoC-CVE-2025-69420.svg) ![forks](https://img.shields.io/github/forks/Kha-Beleh/PoC-CVE-2025-69420.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)


## CVE-2025-64512
 Pdfminer.six is a community maintained fork of the original PDFMiner, a tool for extracting information from PDF documents. Prior to version 20251107, pdfminer.six will execute arbitrary code from a malicious pickle file if provided with a malicious PDF file. The `CMapDB._load_data()` function in pdfminer.six uses `pickle.loads()` to deserialize pickle files. These pickle files are supposed to be part of the pdfminer.six distribution stored in the `cmap/` directory, but a malicious PDF can specify an alternative directory and filename as long as the filename ends in `.pickle.gz`. A malicious, zipped pickle file can then contain code which will automatically execute when the PDF is processed. Version 20251107 fixes the issue.

- [https://github.com/stoic-crawler/CVE-2025-64512](https://github.com/stoic-crawler/CVE-2025-64512) :  ![starts](https://img.shields.io/github/stars/stoic-crawler/CVE-2025-64512.svg) ![forks](https://img.shields.io/github/forks/stoic-crawler/CVE-2025-64512.svg)
- [https://github.com/Cosm3No1de/Bedside.htb_solved](https://github.com/Cosm3No1de/Bedside.htb_solved) :  ![starts](https://img.shields.io/github/stars/Cosm3No1de/Bedside.htb_solved.svg) ![forks](https://img.shields.io/github/forks/Cosm3No1de/Bedside.htb_solved.svg)


## CVE-2025-61882
 Vulnerability in the Oracle Concurrent Processing product of Oracle E-Business Suite (component: BI Publisher Integration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Concurrent Processing.  Successful attacks of this vulnerability can result in takeover of Oracle Concurrent Processing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/razureink/cve-2025-61882-oracle_ebs_rce_reproduction](https://github.com/razureink/cve-2025-61882-oracle_ebs_rce_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2025-61882-oracle_ebs_rce_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2025-61882-oracle_ebs_rce_reproduction.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/owaset55-crypto/CVE-2025-59287](https://github.com/owaset55-crypto/CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/owaset55-crypto/CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/owaset55-crypto/CVE-2025-59287.svg)


## CVE-2025-24472
 An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS 7.0.0 through 7.0.16 and FortiProxy 7.2.0 through 7.2.12, 7.0.0 through 7.0.19 may allow a remote unauthenticated attacker with prior knowledge of upstream and downstream devices serial numbers to gain super-admin privileges on the downstream device, if the Security Fabric is enabled, via crafted CSF proxy requests.

- [https://github.com/razureink/cve-2025-24472-fortinet_authbypass_reproduction](https://github.com/razureink/cve-2025-24472-fortinet_authbypass_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2025-24472-fortinet_authbypass_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2025-24472-fortinet_authbypass_reproduction.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/razureink/cve-2025-5777-citrixbleed2_reproduction](https://github.com/razureink/cve-2025-5777-citrixbleed2_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2025-5777-citrixbleed2_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2025-5777-citrixbleed2_reproduction.svg)


## CVE-2025-2783
 Incorrect handle provided in unspecified circumstances in Mojo in Google Chrome on Windows prior to 134.0.6998.177 allowed a remote attacker to perform a sandbox escape via a malicious file. (Chromium security severity: High)

- [https://github.com/razureink/cve-2025-2783-chrome_sandbox_escape_reproduction](https://github.com/razureink/cve-2025-2783-chrome_sandbox_escape_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2025-2783-chrome_sandbox_escape_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2025-2783-chrome_sandbox_escape_reproduction.svg)


## CVE-2024-50330
 SQL injection in Ivanti Endpoint Manager before 2024 November Security Update or 2022 SU6 November Security Update allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/razureink/cve-2024-50330-ivanti_epm_sqli_reproduction](https://github.com/razureink/cve-2024-50330-ivanti_epm_sqli_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2024-50330-ivanti_epm_sqli_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2024-50330-ivanti_epm_sqli_reproduction.svg)


## CVE-2024-49039
 Windows Task Scheduler Elevation of Privilege Vulnerability

- [https://github.com/razureink/cve-2024-49039-task_scheduler_eop_reproduction](https://github.com/razureink/cve-2024-49039-task_scheduler_eop_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2024-49039-task_scheduler_eop_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2024-49039-task_scheduler_eop_reproduction.svg)


## CVE-2024-43451
 NTLM Hash Disclosure Spoofing Vulnerability

- [https://github.com/razureink/cve-2024-43451-ntlm_hash_disclosure_reproduction](https://github.com/razureink/cve-2024-43451-ntlm_hash_disclosure_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2024-43451-ntlm_hash_disclosure_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2024-43451-ntlm_hash_disclosure_reproduction.svg)


## CVE-2024-38077
 Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability

- [https://github.com/razureink/cve-2024-38077-madlicense_reproduction](https://github.com/razureink/cve-2024-38077-madlicense_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2024-38077-madlicense_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2024-38077-madlicense_reproduction.svg)


## CVE-2024-37054
 Deserialization of untrusted data can occur in versions of the MLflow platform running version 0.9.0 or newer, enabling a maliciously uploaded PyFunc model to run arbitrary code on an end user’s system when interacted with.

- [https://github.com/Cosm3No1de/SmartHire---Hack-The-Box-WriteUp](https://github.com/Cosm3No1de/SmartHire---Hack-The-Box-WriteUp) :  ![starts](https://img.shields.io/github/stars/Cosm3No1de/SmartHire---Hack-The-Box-WriteUp.svg) ![forks](https://img.shields.io/github/forks/Cosm3No1de/SmartHire---Hack-The-Box-WriteUp.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/razureink/cve-2024-4577-phpcgi_rce_reproduction](https://github.com/razureink/cve-2024-4577-phpcgi_rce_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2024-4577-phpcgi_rce_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2024-4577-phpcgi_rce_reproduction.svg)


## CVE-2024-0012
Cloud NGFW and Prisma Access are not impacted by this vulnerability.

- [https://github.com/razureink/cve-2024-0012_9474-panos_authbypass_reproduction](https://github.com/razureink/cve-2024-0012_9474-panos_authbypass_reproduction) :  ![starts](https://img.shields.io/github/stars/razureink/cve-2024-0012_9474-panos_authbypass_reproduction.svg) ![forks](https://img.shields.io/github/forks/razureink/cve-2024-0012_9474-panos_authbypass_reproduction.svg)


## CVE-2023-32629
 Local privilege escalation vulnerability in Ubuntu Kernels overlayfs ovl_copy_up_meta_inode_data skip permission checks when calling ovl_do_setxattr on Ubuntu kernels

- [https://github.com/WhatsWrongAndWhy/CVE-2023-2640-CVE-2023-32629](https://github.com/WhatsWrongAndWhy/CVE-2023-2640-CVE-2023-32629) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2023-2640-CVE-2023-32629.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2023-2640-CVE-2023-32629.svg)


## CVE-2023-2640
 On Ubuntu kernels carrying both c914c0e27eb0 and "UBUNTU: SAUCE: overlayfs: Skip permission checking for trusted.overlayfs.* xattrs", an unprivileged user may set privileged extended attributes on the mounted files, leading them to be set on the upper files without the appropriate security checks.

- [https://github.com/WhatsWrongAndWhy/CVE-2023-2640-CVE-2023-32629](https://github.com/WhatsWrongAndWhy/CVE-2023-2640-CVE-2023-32629) :  ![starts](https://img.shields.io/github/stars/WhatsWrongAndWhy/CVE-2023-2640-CVE-2023-32629.svg) ![forks](https://img.shields.io/github/forks/WhatsWrongAndWhy/CVE-2023-2640-CVE-2023-32629.svg)


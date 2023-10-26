# Update 2023-10-26
## CVE-2023-37478
 pnpm is a package manager. It is possible to construct a tarball that, when installed via npm or parsed by the registry is safe, but when installed via pnpm is malicious, due to how pnpm parses tar archives. This can result in a package that appears safe on the npm registry or when installed via npm being replaced with a compromised or malicious version when installed via pnpm. This issue has been patched in version(s) 7.33.4 and 8.6.8.

- [https://github.com/TrevorGKann/CVE-2023-37478_npm_vs_pnpm](https://github.com/TrevorGKann/CVE-2023-37478_npm_vs_pnpm) :  ![starts](https://img.shields.io/github/stars/TrevorGKann/CVE-2023-37478_npm_vs_pnpm.svg) ![forks](https://img.shields.io/github/forks/TrevorGKann/CVE-2023-37478_npm_vs_pnpm.svg)


## CVE-2023-20198
 Cisco is aware of active exploitation of a previously unknown vulnerability in the web UI feature of Cisco IOS XE Software when exposed to the internet or to untrusted networks. This vulnerability allows a remote, unauthenticated attacker to create an account on an affected system with privilege level 15 access. The attacker can then use that account to gain control of the affected system. For steps to close the attack vector for this vulnerability, see the Recommendations section of this advisory Cisco will provide updates on the status of this investigation and when a software patch is available.

- [https://github.com/kacem-expereo/CVE-2023-20198](https://github.com/kacem-expereo/CVE-2023-20198) :  ![starts](https://img.shields.io/github/stars/kacem-expereo/CVE-2023-20198.svg) ![forks](https://img.shields.io/github/forks/kacem-expereo/CVE-2023-20198.svg)


## CVE-2023-4966
 Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server.

- [https://github.com/Chocapikk/CVE-2023-4966](https://github.com/Chocapikk/CVE-2023-4966) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2023-4966.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2023-4966.svg)
- [https://github.com/dinosn/citrix_cve-2023-4966](https://github.com/dinosn/citrix_cve-2023-4966) :  ![starts](https://img.shields.io/github/stars/dinosn/citrix_cve-2023-4966.svg) ![forks](https://img.shields.io/github/forks/dinosn/citrix_cve-2023-4966.svg)


## CVE-2023-4911
 A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

- [https://github.com/KernelKrise/Looney-Tunables-LPE-workshop-CVE-2023-4911-](https://github.com/KernelKrise/Looney-Tunables-LPE-workshop-CVE-2023-4911-) :  ![starts](https://img.shields.io/github/stars/KernelKrise/Looney-Tunables-LPE-workshop-CVE-2023-4911-.svg) ![forks](https://img.shields.io/github/forks/KernelKrise/Looney-Tunables-LPE-workshop-CVE-2023-4911-.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 up to 4.0.0, WSO2 Identity Server 5.2.0 up to 5.11.0, WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0 and 5.6.0, WSO2 Identity Server as Key Manager 5.3.0 up to 5.11.0, WSO2 Enterprise Integrator 6.2.0 up to 6.6.0, WSO2 Open Banking AM 1.4.0 up to 2.0.0 and WSO2 Open Banking KM 1.4.0, up to 2.0.0.

- [https://github.com/Pushkarup/CVE-2022-29464](https://github.com/Pushkarup/CVE-2022-29464) :  ![starts](https://img.shields.io/github/stars/Pushkarup/CVE-2022-29464.svg) ![forks](https://img.shields.io/github/forks/Pushkarup/CVE-2022-29464.svg)


## CVE-2022-23131
 In the case of instances where the SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor, because a user login stored in the session was not verified. Malicious unauthenticated actor may exploit this issue to escalate privileges and gain admin access to Zabbix Frontend. To perform the attack, SAML authentication is required to be enabled and the actor has to know the username of Zabbix user (or use the guest account, which is disabled by default).

- [https://github.com/r10lab/CVE-2022-23131](https://github.com/r10lab/CVE-2022-23131) :  ![starts](https://img.shields.io/github/stars/r10lab/CVE-2022-23131.svg) ![forks](https://img.shields.io/github/forks/r10lab/CVE-2022-23131.svg)


## CVE-2022-22274
 A Stack-based buffer overflow vulnerability in the SonicOS via HTTP request allows a remote unauthenticated attacker to cause Denial of Service (DoS) or potentially results in code execution in the firewall.

- [https://github.com/4lucardSec/Sonic_CVE-2022-22274_poc](https://github.com/4lucardSec/Sonic_CVE-2022-22274_poc) :  ![starts](https://img.shields.io/github/stars/4lucardSec/Sonic_CVE-2022-22274_poc.svg) ![forks](https://img.shields.io/github/forks/4lucardSec/Sonic_CVE-2022-22274_poc.svg)


## CVE-2021-27198
 An issue was discovered in Visualware MyConnection Server before v11.1a. Unauthenticated Remote Code Execution can occur via Arbitrary File Upload in the web service when using a myspeed/sf?filename= URI. This application is written in Java and is thus cross-platform. The Windows installation runs as SYSTEM, which means that exploitation gives one Administrator privileges on the target system.

- [https://github.com/rwincey/CVE-2021-27198](https://github.com/rwincey/CVE-2021-27198) :  ![starts](https://img.shields.io/github/stars/rwincey/CVE-2021-27198.svg) ![forks](https://img.shields.io/github/forks/rwincey/CVE-2021-27198.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/abdullah098/CVE-2020-0796-Scanner](https://github.com/abdullah098/CVE-2020-0796-Scanner) :  ![starts](https://img.shields.io/github/stars/abdullah098/CVE-2020-0796-Scanner.svg) ![forks](https://img.shields.io/github/forks/abdullah098/CVE-2020-0796-Scanner.svg)


## CVE-2019-10149
 A flaw was found in Exim versions 4.87 to 4.91 (inclusive). Improper validation of recipient address in deliver_message() function in /src/deliver.c may lead to remote command execution.

- [https://github.com/hyim0810/CVE-2019-10149](https://github.com/hyim0810/CVE-2019-10149) :  ![starts](https://img.shields.io/github/stars/hyim0810/CVE-2019-10149.svg) ![forks](https://img.shields.io/github/forks/hyim0810/CVE-2019-10149.svg)


## CVE-2018-7848
 A CWE-200: Information Exposure vulnerability exists in all versions of the Modicon M580, Modicon M340, Modicon Quantum, and Modicon Premium which could cause the disclosure of SNMP information when reading files from the controller over Modbus

- [https://github.com/yanissec/CVE-2018-7848](https://github.com/yanissec/CVE-2018-7848) :  ![starts](https://img.shields.io/github/stars/yanissec/CVE-2018-7848.svg) ![forks](https://img.shields.io/github/forks/yanissec/CVE-2018-7848.svg)


## CVE-2016-3861
 LibUtils in Android 4.x before 4.4.4, 5.0.x before 5.0.2, 5.1.x before 5.1.1, 6.x before 2016-09-01, and 7.0 before 2016-09-01 mishandles conversions between Unicode character encodings with different encoding widths, which allows remote attackers to execute arbitrary code or cause a denial of service (heap-based buffer overflow) via a crafted file, aka internal bug 29250543.

- [https://github.com/xencyborg/CVE-2016-3861](https://github.com/xencyborg/CVE-2016-3861) :  ![starts](https://img.shields.io/github/stars/xencyborg/CVE-2016-3861.svg) ![forks](https://img.shields.io/github/forks/xencyborg/CVE-2016-3861.svg)


## CVE-2010-4180
 OpenSSL before 0.9.8q, and 1.0.x before 1.0.0c, when SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG is enabled, does not properly prevent modification of the ciphersuite in the session cache, which allows remote attackers to force the downgrade to an unintended cipher via vectors involving sniffing network traffic to discover a session identifier.

- [https://github.com/protonnegativo/CVE-2010-4180-by-ChatGPT](https://github.com/protonnegativo/CVE-2010-4180-by-ChatGPT) :  ![starts](https://img.shields.io/github/stars/protonnegativo/CVE-2010-4180-by-ChatGPT.svg) ![forks](https://img.shields.io/github/forks/protonnegativo/CVE-2010-4180-by-ChatGPT.svg)


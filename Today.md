# Update 2025-05-01
## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/abrewer251/CVE-2025-32433_Erlang-OTP](https://github.com/abrewer251/CVE-2025-32433_Erlang-OTP) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2025-32433_Erlang-OTP.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2025-32433_Erlang-OTP.svg)
- [https://github.com/C9b3rD3vi1/Erlang-OTP-SSH-CVE-2025-32433](https://github.com/C9b3rD3vi1/Erlang-OTP-SSH-CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/C9b3rD3vi1/Erlang-OTP-SSH-CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/C9b3rD3vi1/Erlang-OTP-SSH-CVE-2025-32433.svg)
- [https://github.com/ODST-Forge/CVE-2025-32433_PoC](https://github.com/ODST-Forge/CVE-2025-32433_PoC) :  ![starts](https://img.shields.io/github/stars/ODST-Forge/CVE-2025-32433_PoC.svg) ![forks](https://img.shields.io/github/forks/ODST-Forge/CVE-2025-32433_PoC.svg)


## CVE-2025-31324
 SAP NetWeaver Visual Composer Metadata Uploader is not protected with a proper authorization, allowing unauthenticated agent to upload potentially malicious executable binaries that could severely harm the host system. This could significantly affect the confidentiality, integrity, and availability of the targeted system.

- [https://github.com/Pengrey/CVE-2025-31324](https://github.com/Pengrey/CVE-2025-31324) :  ![starts](https://img.shields.io/github/stars/Pengrey/CVE-2025-31324.svg) ![forks](https://img.shields.io/github/forks/Pengrey/CVE-2025-31324.svg)
- [https://github.com/abrewer251/CVE-2025-31324_PoC_SAP](https://github.com/abrewer251/CVE-2025-31324_PoC_SAP) :  ![starts](https://img.shields.io/github/stars/abrewer251/CVE-2025-31324_PoC_SAP.svg) ![forks](https://img.shields.io/github/forks/abrewer251/CVE-2025-31324_PoC_SAP.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/HoumanPashaei/CVE-2025-29927](https://github.com/HoumanPashaei/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/HoumanPashaei/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/HoumanPashaei/CVE-2025-29927.svg)
- [https://github.com/rubbxalc/CVE-2025-29927](https://github.com/rubbxalc/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/rubbxalc/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/rubbxalc/CVE-2025-29927.svg)


## CVE-2025-29775
 xml-crypto is an XML digital signature and encryption library for Node.js. An attacker may be able to exploit a vulnerability in versions prior to 6.0.1, 3.2.1, and 2.1.6 to bypass authentication or authorization mechanisms in systems that rely on xml-crypto for verifying signed XML documents. The vulnerability allows an attacker to modify a valid signed XML message in a way that still passes signature verification checks. For example, it could be used to alter critical identity or access control attributes, enabling an attacker to escalate privileges or impersonate another user. Users of versions 6.0.0 and prior should upgrade to version 6.0.1 to receive a fix. Those who are still using v2.x or v3.x should upgrade to patched versions 2.1.6 or 3.2.1, respectively.

- [https://github.com/twypsy/cve-2025-29775](https://github.com/twypsy/cve-2025-29775) :  ![starts](https://img.shields.io/github/stars/twypsy/cve-2025-29775.svg) ![forks](https://img.shields.io/github/forks/twypsy/cve-2025-29775.svg)


## CVE-2025-26014
 A Remote Code Execution (RCE) vulnerability in Loggrove v.1.0 allows a remote attacker to execute arbitrary code via the path parameter.

- [https://github.com/vigilante-1337/CVE-2025-26014](https://github.com/vigilante-1337/CVE-2025-26014) :  ![starts](https://img.shields.io/github/stars/vigilante-1337/CVE-2025-26014.svg) ![forks](https://img.shields.io/github/forks/vigilante-1337/CVE-2025-26014.svg)


## CVE-2025-24801
 GLPI is a free asset and IT management software package. An authenticated user can upload and force the execution of *.php files located on the GLPI server. This vulnerability is fixed in 10.0.18.

- [https://github.com/r1beirin/CVE-2025-24801](https://github.com/r1beirin/CVE-2025-24801) :  ![starts](https://img.shields.io/github/stars/r1beirin/CVE-2025-24801.svg) ![forks](https://img.shields.io/github/forks/r1beirin/CVE-2025-24801.svg)


## CVE-2025-24252
 A use-after-free issue was addressed with improved memory management. This issue is fixed in macOS Sequoia 15.4, tvOS 18.4, macOS Ventura 13.7.5, iPadOS 17.7.6, macOS Sonoma 14.7.5, iOS 18.4 and iPadOS 18.4, visionOS 2.4. An attacker on the local network may be able to corrupt process memory.

- [https://github.com/ekomsSavior/AirBorne-PoC](https://github.com/ekomsSavior/AirBorne-PoC) :  ![starts](https://img.shields.io/github/stars/ekomsSavior/AirBorne-PoC.svg) ![forks](https://img.shields.io/github/forks/ekomsSavior/AirBorne-PoC.svg)


## CVE-2025-0401
 A vulnerability classified as critical has been found in 1902756969 reggie 1.0. Affected is the function download of the file src/main/java/com/itheima/reggie/controller/CommonController.java. The manipulation of the argument name leads to path traversal. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Darabium/Gombruc](https://github.com/Darabium/Gombruc) :  ![starts](https://img.shields.io/github/stars/Darabium/Gombruc.svg) ![forks](https://img.shields.io/github/forks/Darabium/Gombruc.svg)


## CVE-2024-12342
 A vulnerability was found in TP-Link VN020 F3v(T) TT_V6.2.1021. It has been rated as critical. This issue affects some unknown processing of the file /control/WANIPConnection of the component Incomplete SOAP Request Handler. The manipulation leads to denial of service. The attack can only be initiated within the local network. The exploit has been disclosed to the public and may be used.

- [https://github.com/becrevex/TPLink-VN020-DoS](https://github.com/becrevex/TPLink-VN020-DoS) :  ![starts](https://img.shields.io/github/stars/becrevex/TPLink-VN020-DoS.svg) ![forks](https://img.shields.io/github/forks/becrevex/TPLink-VN020-DoS.svg)


## CVE-2024-3400
Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.

- [https://github.com/CyprianAtsyor/letsdefend-cve2024-3400-case-study](https://github.com/CyprianAtsyor/letsdefend-cve2024-3400-case-study) :  ![starts](https://img.shields.io/github/stars/CyprianAtsyor/letsdefend-cve2024-3400-case-study.svg) ![forks](https://img.shields.io/github/forks/CyprianAtsyor/letsdefend-cve2024-3400-case-study.svg)


## CVE-2023-32243
 Improper Authentication vulnerability in WPDeveloper Essential Addons for Elementor allows Privilege Escalation. This issue affects Essential Addons for Elementor: from 5.4.0 through 5.7.1.

- [https://github.com/dev0558/CVE-2023-32243-Detection-and-Mitigation-in-WordPress](https://github.com/dev0558/CVE-2023-32243-Detection-and-Mitigation-in-WordPress) :  ![starts](https://img.shields.io/github/stars/dev0558/CVE-2023-32243-Detection-and-Mitigation-in-WordPress.svg) ![forks](https://img.shields.io/github/forks/dev0558/CVE-2023-32243-Detection-and-Mitigation-in-WordPress.svg)


## CVE-2022-23302
 JMSSink in all versions of Log4j 1.x is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration or if the configuration references an LDAP service the attacker has access to. The attacker can provide a TopicConnectionFactoryBindingName configuration causing JMSSink to perform JNDI requests that result in remote code execution in a similar fashion to CVE-2021-4104. Note this issue only affects Log4j 1.x when specifically configured to use JMSSink, which is not the default. Apache Log4j 1.2 reached end of life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the previous versions.

- [https://github.com/Chrisync/CVE-Scanner](https://github.com/Chrisync/CVE-Scanner) :  ![starts](https://img.shields.io/github/stars/Chrisync/CVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/Chrisync/CVE-Scanner.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/Chrisync/CVE-Scanner](https://github.com/Chrisync/CVE-Scanner) :  ![starts](https://img.shields.io/github/stars/Chrisync/CVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/Chrisync/CVE-Scanner.svg)


## CVE-2021-44832
 Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is fixed by limiting JNDI data source names to the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2.

- [https://github.com/Chrisync/CVE-Scanner](https://github.com/Chrisync/CVE-Scanner) :  ![starts](https://img.shields.io/github/stars/Chrisync/CVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/Chrisync/CVE-Scanner.svg)


## CVE-2021-42287
 Active Directory Domain Services Elevation of Privilege Vulnerability

- [https://github.com/Chrisync/CVE-Scanner](https://github.com/Chrisync/CVE-Scanner) :  ![starts](https://img.shields.io/github/stars/Chrisync/CVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/Chrisync/CVE-Scanner.svg)


## CVE-2021-42278
 Active Directory Domain Services Elevation of Privilege Vulnerability

- [https://github.com/Chrisync/CVE-Scanner](https://github.com/Chrisync/CVE-Scanner) :  ![starts](https://img.shields.io/github/stars/Chrisync/CVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/Chrisync/CVE-Scanner.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/Chrisync/CVE-Scanner](https://github.com/Chrisync/CVE-Scanner) :  ![starts](https://img.shields.io/github/stars/Chrisync/CVE-Scanner.svg) ![forks](https://img.shields.io/github/forks/Chrisync/CVE-Scanner.svg)


## CVE-2018-7250
 An issue was discovered in secdrv.sys as shipped in Microsoft Windows Vista, Windows 7, Windows 8, and Windows 8.1 before KB3086255, and as shipped in Macrovision SafeDisc. An uninitialized kernel pool allocation in IOCTL 0xCA002813 allows a local unprivileged attacker to leak 16 bits of uninitialized kernel PagedPool data.

- [https://github.com/alonhr/SecDrvPoolLeak](https://github.com/alonhr/SecDrvPoolLeak) :  ![starts](https://img.shields.io/github/stars/alonhr/SecDrvPoolLeak.svg) ![forks](https://img.shields.io/github/forks/alonhr/SecDrvPoolLeak.svg)


## CVE-2018-7249
 An issue was discovered in secdrv.sys as shipped in Microsoft Windows Vista, Windows 7, Windows 8, and Windows 8.1 before KB3086255, and as shipped in Macrovision SafeDisc. Two carefully timed calls to IOCTL 0xCA002813 can cause a race condition that leads to a use-after-free. When exploited, an unprivileged attacker can run arbitrary code in the kernel.

- [https://github.com/alonhr/NotSecDrv](https://github.com/alonhr/NotSecDrv) :  ![starts](https://img.shields.io/github/stars/alonhr/NotSecDrv.svg) ![forks](https://img.shields.io/github/forks/alonhr/NotSecDrv.svg)


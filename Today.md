# Update 2026-09-04
## CVE-2026-84361
 Composer is a dependency Manager for the PHP language. From 1.0 until 2.2.30 and 2.10.3, a malicious dependency package from a custom Composer repository or an untrusted composer.lock file could set source.type to perforce and source.url to an rsh: or jsh: P4PORT value. When the Perforce p4 client was installed and Composer installed the package from source through composer install or composer update, including --prefer-source, Composer\Util\Perforce passed the address to p4 without validation, causing p4 to run a local command with the privileges of the user or CI account. Packagist.org does not permit Perforce source metadata. This issue is fixed in versions 2.2.30 and 2.10.3.

- [https://github.com/Saku0512/CVE-2026-84361-poc](https://github.com/Saku0512/CVE-2026-84361-poc) :  ![starts](https://img.shields.io/github/stars/Saku0512/CVE-2026-84361-poc.svg) ![forks](https://img.shields.io/github/forks/Saku0512/CVE-2026-84361-poc.svg)


## CVE-2026-82329
 JFrog Artifactory contains an authentication weakness that, under default configuration, may allow an unauthenticated attacker with network access to obtain administrative privileges.

- [https://github.com/ynsmroztas/CVE-2026-82329-JFrog-Artifactory-Auth-Bypass](https://github.com/ynsmroztas/CVE-2026-82329-JFrog-Artifactory-Auth-Bypass) :  ![starts](https://img.shields.io/github/stars/ynsmroztas/CVE-2026-82329-JFrog-Artifactory-Auth-Bypass.svg) ![forks](https://img.shields.io/github/forks/ynsmroztas/CVE-2026-82329-JFrog-Artifactory-Auth-Bypass.svg)
- [https://github.com/realalexandergeorgiev/artifactory-CVE-2026-82329-poc.py](https://github.com/realalexandergeorgiev/artifactory-CVE-2026-82329-poc.py) :  ![starts](https://img.shields.io/github/stars/realalexandergeorgiev/artifactory-CVE-2026-82329-poc.py.svg) ![forks](https://img.shields.io/github/forks/realalexandergeorgiev/artifactory-CVE-2026-82329-poc.py.svg)


## CVE-2026-73570
 A remote code execution vulnerability exists in Zimbra Collaboration (ZCS) before 10.1.20 when the optional zimbra-snmp package is installed and SNMP notifications are enabled. Due to improper sanitization of untrusted input during SNMP notification processing, an unauthenticated attacker can send specially crafted SMTP requests that may result in execution of arbitrary operating system commands as the Zimbra user.

- [https://github.com/byt3l0rd/CVE-2026-73570](https://github.com/byt3l0rd/CVE-2026-73570) :  ![starts](https://img.shields.io/github/stars/byt3l0rd/CVE-2026-73570.svg) ![forks](https://img.shields.io/github/forks/byt3l0rd/CVE-2026-73570.svg)


## CVE-2026-73296
 Microsoft UFO open-source framework for intelligent automation across devices and platforms. Prior to 3.0.8, create_mobile_data_collection_server and create_mobile_action_server in ufo/client/mcp/http_servers/mobile_mcp_server.py exposed Streamable HTTP MCP services on TCP ports 8020 and 8021 without authentication, allowing an unauthenticated remote attacker to invoke capture_screenshot, get_ui_tree, tap, swipe, type_text, launch_app, press_key, and click_control against an ADB-connected Android device, disclose screen and device data, and modify device state. This issue is fixed in version 3.0.8.

- [https://github.com/0xBlackash/CVE-2026-73296](https://github.com/0xBlackash/CVE-2026-73296) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-73296.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-73296.svg)


## CVE-2026-71981
 Cypht before 2.12.2 contains a PHP object injection vulnerability that allows authenticated attackers to execute arbitrary operating system commands by supplying a crafted PHP object graph in the back_query GET parameter of the logout handler. Attackers can pass a base64-encoded serialized payload through this parameter, which is decoded and passed directly to unserialize() without an allow-list, signature check, or type restriction, enabling gadget-chain exploitation to achieve remote code execution as the web server process.

- [https://github.com/lyn4r/CVE-2026-71981](https://github.com/lyn4r/CVE-2026-71981) :  ![starts](https://img.shields.io/github/stars/lyn4r/CVE-2026-71981.svg) ![forks](https://img.shields.io/github/forks/lyn4r/CVE-2026-71981.svg)


## CVE-2026-65905
Users are recommended to upgrade to version 11.0.25, 10.1.58 or 9.0.121, which fix the issue.

- [https://github.com/xiaoqiMikko/spring-cvss-check](https://github.com/xiaoqiMikko/spring-cvss-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/spring-cvss-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/spring-cvss-check.svg)


## CVE-2026-65637
Users are recommended to upgrade to version 11.0.25, 10.1.58 or 9.0.121, which fix the issue.

- [https://github.com/xiaoqiMikko/spring-cvss-check](https://github.com/xiaoqiMikko/spring-cvss-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/spring-cvss-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/spring-cvss-check.svg)


## CVE-2026-65349
 An out-of-bounds read was addressed with improved input validation. This issue is fixed in iOS 26.6.1 and iPadOS 26.6.1, macOS Tahoe 26.6.2. An app may be able to cause unexpected system termination or read kernel memory.

- [https://github.com/ByteV0rtex/CVE-2026-65349](https://github.com/ByteV0rtex/CVE-2026-65349) :  ![starts](https://img.shields.io/github/stars/ByteV0rtex/CVE-2026-65349.svg) ![forks](https://img.shields.io/github/forks/ByteV0rtex/CVE-2026-65349.svg)


## CVE-2026-65343
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 26.6.1 and iPadOS 26.6.1, macOS Tahoe 26.6.2. A remote attacker may be able to cause unexpected system termination.

- [https://github.com/ByteV0rtex/CVE-2026-65343](https://github.com/ByteV0rtex/CVE-2026-65343) :  ![starts](https://img.shields.io/github/stars/ByteV0rtex/CVE-2026-65343.svg) ![forks](https://img.shields.io/github/forks/ByteV0rtex/CVE-2026-65343.svg)


## CVE-2026-65330
 The issue was addressed with improved memory handling. This issue is fixed in iOS 26.6.1 and iPadOS 26.6.1, macOS Tahoe 26.6.2. An app may be able to cause unexpected system termination or corrupt kernel memory.

- [https://github.com/ByteV0rtex/CVE-2026-65330](https://github.com/ByteV0rtex/CVE-2026-65330) :  ![starts](https://img.shields.io/github/stars/ByteV0rtex/CVE-2026-65330.svg) ![forks](https://img.shields.io/github/forks/ByteV0rtex/CVE-2026-65330.svg)


## CVE-2026-64788
 The issue was addressed with improved memory handling. This issue is fixed in iOS 26.6.1 and iPadOS 26.6.1, macOS Tahoe 26.6.2. Processing maliciously crafted web content may lead to memory corruption.

- [https://github.com/ByteV0rtex/CVE-2026-64788](https://github.com/ByteV0rtex/CVE-2026-64788) :  ![starts](https://img.shields.io/github/stars/ByteV0rtex/CVE-2026-64788.svg) ![forks](https://img.shields.io/github/forks/ByteV0rtex/CVE-2026-64788.svg)


## CVE-2026-63828
cover MPTCP fast open, so the SOCK_STREAM/IPPROTO_MPTCP arm is explicit.

- [https://github.com/4n4s4zi/tfo-connect-bypass](https://github.com/4n4s4zi/tfo-connect-bypass) :  ![starts](https://img.shields.io/github/stars/4n4s4zi/tfo-connect-bypass.svg) ![forks](https://img.shields.io/github/forks/4n4s4zi/tfo-connect-bypass.svg)


## CVE-2026-63077
 In JetBrains TeamCity before 2026.1.3, 2025.11.7 unauthenticated remote code execution was possible via the agent polling protocol

- [https://github.com/bakos-sandor-nx/teamcity-cve-2026-63077-remediation](https://github.com/bakos-sandor-nx/teamcity-cve-2026-63077-remediation) :  ![starts](https://img.shields.io/github/stars/bakos-sandor-nx/teamcity-cve-2026-63077-remediation.svg) ![forks](https://img.shields.io/github/forks/bakos-sandor-nx/teamcity-cve-2026-63077-remediation.svg)


## CVE-2026-59313
Spring Framework 5.3.0 - 5.3.49

- [https://github.com/xiaoqiMikko/spring-cvss-check](https://github.com/xiaoqiMikko/spring-cvss-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/spring-cvss-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/spring-cvss-check.svg)


## CVE-2026-59283
Spring Framework 5.2.25.RELEASE and earlier

- [https://github.com/xiaoqiMikko/spring-cvss-check](https://github.com/xiaoqiMikko/spring-cvss-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/spring-cvss-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/spring-cvss-check.svg)


## CVE-2026-59270
Spring Security 5.7.0 - 5.7.25

- [https://github.com/xiaoqiMikko/spring-cvss-check](https://github.com/xiaoqiMikko/spring-cvss-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/spring-cvss-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/spring-cvss-check.svg)


## CVE-2026-58231
availability of the application.

- [https://github.com/SAP-system-update/CVE-2026-58231](https://github.com/SAP-system-update/CVE-2026-58231) :  ![starts](https://img.shields.io/github/stars/SAP-system-update/CVE-2026-58231.svg) ![forks](https://img.shields.io/github/forks/SAP-system-update/CVE-2026-58231.svg)


## CVE-2026-52832
 Nuclio is a "Serverless" framework for Real-Time Events and Data Processing. Prior to version 1.16.5, Nuclio Dashboard exposes POST /api/functions without authentication by default (NOP auth mode). The spec.handler field (e.g., mymodule:myfunction) is parsed by functionconfig.ParseHandler() which splits on : only — no path validation is applied to the module portion. This issue has been patched in version 1.16.5.

- [https://github.com/mdvpat/CVE-2026-52832-PoC-exploit-nuclio-dashboard](https://github.com/mdvpat/CVE-2026-52832-PoC-exploit-nuclio-dashboard) :  ![starts](https://img.shields.io/github/stars/mdvpat/CVE-2026-52832-PoC-exploit-nuclio-dashboard.svg) ![forks](https://img.shields.io/github/forks/mdvpat/CVE-2026-52832-PoC-exploit-nuclio-dashboard.svg)


## CVE-2026-48611
 Improper authentication checks in the OAuth implementation allow account hijacking even when OAuth is not configured or enabled leading to unauthorized access in default installations.

- [https://github.com/R4Wbytes/phpbb-cve-2026-48611-scanner](https://github.com/R4Wbytes/phpbb-cve-2026-48611-scanner) :  ![starts](https://img.shields.io/github/stars/R4Wbytes/phpbb-cve-2026-48611-scanner.svg) ![forks](https://img.shields.io/github/forks/R4Wbytes/phpbb-cve-2026-48611-scanner.svg)


## CVE-2026-47892
Spring Framework 5.2.5.RELEASE - 5.2.25.RELEASE

- [https://github.com/xiaoqiMikko/spring-cvss-check](https://github.com/xiaoqiMikko/spring-cvss-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/spring-cvss-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/spring-cvss-check.svg)


## CVE-2026-47891
Spring Framework 5.2.25.RELEASE and earlier

- [https://github.com/xiaoqiMikko/spring-cvss-check](https://github.com/xiaoqiMikko/spring-cvss-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/spring-cvss-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/spring-cvss-check.svg)


## CVE-2026-47890
Spring Framework 6.2.0 - 6.2.19

- [https://github.com/xiaoqiMikko/spring-cvss-check](https://github.com/xiaoqiMikko/spring-cvss-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/spring-cvss-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/spring-cvss-check.svg)


## CVE-2026-47884
Spring Framework 5.2.25.RELEASE and earlier

- [https://github.com/xiaoqiMikko/spring-cvss-check](https://github.com/xiaoqiMikko/spring-cvss-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/spring-cvss-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/spring-cvss-check.svg)


## CVE-2026-41853
Spring Framework 7.0.0 through 7.0.7; 6.2.0 through 6.2.18; 6.1.0 through 6.1.27; 5.3.0 through 5.3.48.

- [https://github.com/xiaoqiMikko/spring-cvss-check](https://github.com/xiaoqiMikko/spring-cvss-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/spring-cvss-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/spring-cvss-check.svg)


## CVE-2026-41848
Spring Framework 7.0.0 through 7.0.7; 6.2.0 through 6.2.18; 6.1.0 through 6.1.27; 5.3.0 through 5.3.48.

- [https://github.com/xiaoqiMikko/spring-cvss-check](https://github.com/xiaoqiMikko/spring-cvss-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/spring-cvss-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/spring-cvss-check.svg)


## CVE-2026-41846
Spring Framework 7.0.0 through 7.0.7; 6.2.0 through 6.2.18; 6.1.0 through 6.1.27; 5.3.0 through 5.3.48.

- [https://github.com/xiaoqiMikko/spring-cvss-check](https://github.com/xiaoqiMikko/spring-cvss-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/spring-cvss-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/spring-cvss-check.svg)


## CVE-2026-41844
Spring Framework 7.0.0 through 7.0.7; 6.2.0 through 6.2.18; 6.1.0 through 6.1.27; 5.3.0 through 5.3.48.

- [https://github.com/xiaoqiMikko/spring-cvss-check](https://github.com/xiaoqiMikko/spring-cvss-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/spring-cvss-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/spring-cvss-check.svg)


## CVE-2026-41843
Spring Framework 7.0.0 through 7.0.7; 6.2.0 through 6.2.18; 6.1.0 through 6.1.27; 5.3.0 through 5.3.48.

- [https://github.com/xiaoqiMikko/spring-cvss-check](https://github.com/xiaoqiMikko/spring-cvss-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/spring-cvss-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/spring-cvss-check.svg)


## CVE-2026-38577
 Insecure hardcoded credentials in the Admin account of Tenda HG21 V4.0.0-260302 allows attackers to gain root access.

- [https://github.com/poxsky/CVE-2026-38577-by-deepak-Anmol](https://github.com/poxsky/CVE-2026-38577-by-deepak-Anmol) :  ![starts](https://img.shields.io/github/stars/poxsky/CVE-2026-38577-by-deepak-Anmol.svg) ![forks](https://img.shields.io/github/forks/poxsky/CVE-2026-38577-by-deepak-Anmol.svg)


## CVE-2026-24423
 SmarterTools SmarterMail versions prior to build 9511 contain an unauthenticated remote code execution vulnerability in the ConnectToHub API method. The attacker could point the SmarterMail to the malicious HTTP server, which serves the malicious OS command. This command will be executed by the vulnerable application.

- [https://github.com/CyberAlp0/SmarterMail-CVE-2026-24423](https://github.com/CyberAlp0/SmarterMail-CVE-2026-24423) :  ![starts](https://img.shields.io/github/stars/CyberAlp0/SmarterMail-CVE-2026-24423.svg) ![forks](https://img.shields.io/github/forks/CyberAlp0/SmarterMail-CVE-2026-24423.svg)


## CVE-2026-19490
This issue affects ADC: from 14.1 through 73.32 and from 13.1 through 63.21; Gateway: from 14.1 through 73.32 and from 13.1 through 63.21.

- [https://github.com/TarPeg007/CVE-2026-19490](https://github.com/TarPeg007/CVE-2026-19490) :  ![starts](https://img.shields.io/github/stars/TarPeg007/CVE-2026-19490.svg) ![forks](https://img.shields.io/github/forks/TarPeg007/CVE-2026-19490.svg)


## CVE-2026-9586
 An unauthenticated SQL injection vulnerability exists in Sangoma Switchvox SMB Edition 8.3 (104997). The /pa endpoint processes XML content beginning with PolycomIPPhone and directly concatenates the user-controlled PhoneIP value into PostgreSQL queries without sanitization or parameterization. An unauthenticated remote attacker can execute arbitrary SQL statements against the backend PostgreSQL database using a single crafted request, including database operations and remote code execution.

- [https://github.com/HORKimhab/CVE-2026-9586](https://github.com/HORKimhab/CVE-2026-9586) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-9586.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-9586.svg)


## CVE-2026-9335
 A vulnerability in keras-team/keras versions = 3.14.0 allows arbitrary local HDF5 file content disclosure due to improper handling of HDF5 ExternalLinks. The `KerasFileEditor` and `keras.saving.load_weights` functions bypass the `safe_get_h5_group` and `safe_get_h5_dataset` helpers, which are designed to reject ExternalLinks and SoftLinks. This results in automatic dereferencing of links to external HDF5 files, enabling attackers to disclose sensitive data from the victim's local filesystem. Specifically, `KerasFileEditor` extracts attributes and datasets from linked files into its internal structures, while `keras.saving.load_weights` loads weights from linked files into the user's model. This issue can be exploited by providing a malicious `.h5`, `.weights.h5`, or `.keras` file containing ExternalLinks.

- [https://github.com/paparojonathan/CVE-2026-9335-keras-hdf5-externallink](https://github.com/paparojonathan/CVE-2026-9335-keras-hdf5-externallink) :  ![starts](https://img.shields.io/github/stars/paparojonathan/CVE-2026-9335-keras-hdf5-externallink.svg) ![forks](https://img.shields.io/github/forks/paparojonathan/CVE-2026-9335-keras-hdf5-externallink.svg)


## CVE-2026-9055
 The Booking for Appointments and Events Calendar – Amelia (Premium) plugin for WordPress is vulnerable to Privilege Escalation in versions 8.0 - 9.6.2. This is due to insufficient validation of the attacker-controlled 'type' parameter in the customer update endpoint, which allows customers to set their role to 'manager' and trigger creation of a WordPress user with the wpamelia-manager role when the 'externalId' parameter is set to 0. This makes it possible for unauthenticated attackers to escalate their privileges to administrator by first elevating to the manager role, then creating a provider entity linked to an administrator user ID and overwriting that administrator's password.

- [https://github.com/EXEcution-py/CVE-2026-9055](https://github.com/EXEcution-py/CVE-2026-9055) :  ![starts](https://img.shields.io/github/stars/EXEcution-py/CVE-2026-9055.svg) ![forks](https://img.shields.io/github/forks/EXEcution-py/CVE-2026-9055.svg)


## CVE-2026-7899
 Out of bounds read and write in V8 in Google Chrome prior to 148.0.7778.96 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/HORKimhab/CVE-2026-7899](https://github.com/HORKimhab/CVE-2026-7899) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-7899.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-7899.svg)


## CVE-2026-5027
 The 'POST /api/v2/files' endpoint does not sanitize the 'filename' parameter from the multipart form data, allowing an attacker to write files to arbitrary locations on the filesystem using path traversal sequences ('../').

- [https://github.com/rmhowe425/POC-CVE-2026-5027](https://github.com/rmhowe425/POC-CVE-2026-5027) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-5027.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-5027.svg)


## CVE-2026-5006
This vulnerability, CVE-2026-5006, was fixed in Vault Community Edition 2.0.4 and Vault Enterprise 2.0.4, 1.21.9, 1.20.14, and 1.19.20.

- [https://github.com/tcollins-hashicorp/vault-cve-2026-5006-audit](https://github.com/tcollins-hashicorp/vault-cve-2026-5006-audit) :  ![starts](https://img.shields.io/github/stars/tcollins-hashicorp/vault-cve-2026-5006-audit.svg) ![forks](https://img.shields.io/github/forks/tcollins-hashicorp/vault-cve-2026-5006-audit.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC](https://github.com/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC) :  ![starts](https://img.shields.io/github/stars/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC.svg) ![forks](https://img.shields.io/github/forks/Cxyofficial/K50G-POCOF4GT-CVE-2026-43499-PoC.svg)


## CVE-2026-1555
 The WebStack theme for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the io_img_upload() function in all versions up to, and including, 1.2024. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/katranSefa/CVE-2026-1555](https://github.com/katranSefa/CVE-2026-1555) :  ![starts](https://img.shields.io/github/stars/katranSefa/CVE-2026-1555.svg) ![forks](https://img.shields.io/github/forks/katranSefa/CVE-2026-1555.svg)


## CVE-2026-0920
 The LA-Studio Element Kit for Elementor plugin for WordPress is vulnerable to Administrative User Creation in all versions up to, and including, 1.5.6.3. This is due to the 'ajax_register_handle' function not restricting what user roles a user can register with. This makes it possible for unauthenticated attackers to supply the 'lakit_bkrole' parameter during registration and gain administrator access to the site.

- [https://github.com/katranSefa/CVE-2026-0920](https://github.com/katranSefa/CVE-2026-0920) :  ![starts](https://img.shields.io/github/stars/katranSefa/CVE-2026-0920.svg) ![forks](https://img.shields.io/github/forks/katranSefa/CVE-2026-0920.svg)


## CVE-2026-0828
 Kernel driver ProcessMonitorDriver.sys in Safetica's endpoint client x64 , versions 10.5.75.0 and 11.11.4.0, allows unprivileged user to abuse IOCTL path and terminate protected system processes.

- [https://github.com/ximerag/dast](https://github.com/ximerag/dast) :  ![starts](https://img.shields.io/github/stars/ximerag/dast.svg) ![forks](https://img.shields.io/github/forks/ximerag/dast.svg)


## CVE-2026-0769
The specific flaw exists within the implementation of eval_custom_component_code function. The issue results from the lack of proper validation of a user-supplied string before using it to execute python code. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26972.

- [https://github.com/rmhowe425/POC-CVE-2026-0769](https://github.com/rmhowe425/POC-CVE-2026-0769) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-0769.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-0769.svg)


## CVE-2026-0768
. Was ZDI-CAN-27322.

- [https://github.com/rmhowe425/POC-CVE-2026-0768](https://github.com/rmhowe425/POC-CVE-2026-0768) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-0768.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-0768.svg)


## CVE-2025-41249
This CVE is published in conjunction with  CVE-2025-41248 https://spring.io/security/cve-2025-41248 .

- [https://github.com/xiaoqiMikko/spring-cvss-check](https://github.com/xiaoqiMikko/spring-cvss-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/spring-cvss-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/spring-cvss-check.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/lucaschanzx/CVE-2025-29927-PoC](https://github.com/lucaschanzx/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/lucaschanzx/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/lucaschanzx/CVE-2025-29927-PoC.svg)


## CVE-2025-29009
 Unrestricted Upload of File with Dangerous Type vulnerability in Webkul Medical Prescription Attachment Plugin for WooCommerce medical-prescription-attachment-plugin-for-woocommerce allows Upload a Web Shell to a Web Server.This issue affects Medical Prescription Attachment Plugin for WooCommerce: from n/a through = 1.2.3.

- [https://github.com/katranSefa/CVE-2025-29009](https://github.com/katranSefa/CVE-2025-29009) :  ![starts](https://img.shields.io/github/stars/katranSefa/CVE-2025-29009.svg) ![forks](https://img.shields.io/github/forks/katranSefa/CVE-2025-29009.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/buffertrychar/CVE-2025-24071-POC](https://github.com/buffertrychar/CVE-2025-24071-POC) :  ![starts](https://img.shields.io/github/stars/buffertrychar/CVE-2025-24071-POC.svg) ![forks](https://img.shields.io/github/forks/buffertrychar/CVE-2025-24071-POC.svg)


## CVE-2025-15617
 Wazuh version 4.12.0 contains an exposure vulnerability in GitHub Actions workflow artifacts that allows attackers to extract the GITHUB_TOKEN from uploaded artifacts. Attackers can use the exposed token within a limited time window to perform unauthorized actions such as pushing malicious commits or altering release tags.

- [https://github.com/pvharmo2/gha-lab-becf103a54](https://github.com/pvharmo2/gha-lab-becf103a54) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-becf103a54.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-becf103a54.svg)


## CVE-2025-10894
 Malicious code was inserted into the Nx (build system) package and several related plugins. The tampered package was published to the npm software registry, via a supply-chain attack. Affected versions contain code that scans the file system, collects credentials, and posts them to GitHub as a repo under user's accounts.

- [https://github.com/pvharmo2/gha-lab-23db52563c](https://github.com/pvharmo2/gha-lab-23db52563c) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-23db52563c.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-23db52563c.svg)


## CVE-2025-9974
 The unified WEBUI application of the ONT/Beacon device contains an input handling flaw that allows authenticated users to trigger unintended system-level command execution. Due to insufficient validation of user-supplied data, a low-privileged authenticated attacker may be able to execute arbitrary commands on the underlying ONT/Beacon operating system, potentially impacting the confidentiality, integrity, and availability of the device.

- [https://github.com/Rajdave69/CVE-2025-9974](https://github.com/Rajdave69/CVE-2025-9974) :  ![starts](https://img.shields.io/github/stars/Rajdave69/CVE-2025-9974.svg) ![forks](https://img.shields.io/github/forks/Rajdave69/CVE-2025-9974.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/all3njk/NextJS_CVE-2025-29927](https://github.com/all3njk/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/all3njk/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/all3njk/NextJS_CVE-2025-29927.svg)


## CVE-2024-47179
 RSSHub is an RSS network. Prior to commit 64e00e7, RSSHub's `docker-test-cont.yml` workflow is vulnerable to Artifact Poisoning, which could have lead to a full repository takeover. Downstream users of RSSHub are not vulnerable to this issue, and commit 64e00e7 fixed the underlying issue and made the repository no longer vulnerable. The `docker-test-cont.yml` workflow gets triggered when the `PR - Docker build test` workflow completes successfully. It then collects some information about the Pull Request that triggered the triggering workflow and set some labels depending on the PR body and sender. If the PR also contains a `routes` markdown block, it will set the `TEST_CONTINUE` environment variable to `true`. The workflow then downloads and extracts an artifact uploaded by the triggering workflow which is expected to contain a single `rsshub.tar.zst` file. However, prior to commit 64e00e7, it did not validate and the contents were extracted in the root of the workspace overriding any existing files. Since the contents of the artifact were not validated, it is possible for a malicious actor to send a Pull Request which uploads, not just the `rsshub.tar.zst` compressed docker image, but also a malicious `package.json` file with a script to run arbitrary code in the context of the privileged workflow. As of commit 64e00e7, this scenario has been addressed and the RSSHub repository is no longer vulnerable.

- [https://github.com/pvharmo2/gha-lab-d9fd584b12](https://github.com/pvharmo2/gha-lab-d9fd584b12) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-d9fd584b12.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-d9fd584b12.svg)


## CVE-2024-45798
 arduino-esp32 is an Arduino core for the ESP32, ESP32-S2, ESP32-S3, ESP32-C3, ESP32-C6 and ESP32-H2 microcontrollers. The `arduino-esp32` CI is vulnerable to multiple Poisoned Pipeline Execution (PPE) vulnerabilities. Code injection in `tests_results.yml` workflow (`GHSL-2024-169`) and environment Variable injection (`GHSL-2024-170`). These issue have been addressed but users are advised to verify the contents of the downloaded artifacts.

- [https://github.com/pvharmo2/gha-lab-6ab39df295](https://github.com/pvharmo2/gha-lab-6ab39df295) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-6ab39df295.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-6ab39df295.svg)


## CVE-2024-4254
 The 'deploy-website.yml' workflow in the gradio-app/gradio repository, specifically in the 'main' branch, is vulnerable to secrets exfiltration due to improper authorization. The vulnerability arises from the workflow's explicit checkout and execution of code from a fork, which is unsafe as it allows the running of untrusted code in an environment with access to push to the base repository and access secrets. This flaw could lead to the exfiltration of sensitive secrets such as GITHUB_TOKEN, HF_TOKEN, VERCEL_ORG_ID, VERCEL_PROJECT_ID, COMMENT_TOKEN, AWSACCESSKEYID, AWSSECRETKEY, and VERCEL_TOKEN. The vulnerability is present in the workflow file located at https://github.com/gradio-app/gradio/blob/72f4ca88ab569aae47941b3fb0609e57f2e13a27/.github/workflows/deploy-website.yml.

- [https://github.com/pvharmo2/gha-lab-40e23db109](https://github.com/pvharmo2/gha-lab-40e23db109) :  ![starts](https://img.shields.io/github/stars/pvharmo2/gha-lab-40e23db109.svg) ![forks](https://img.shields.io/github/forks/pvharmo2/gha-lab-40e23db109.svg)


## CVE-2022-25765
 The package pdfkit from 0.0.0 are vulnerable to Command Injection where the URL is not properly sanitized.

- [https://github.com/innocentx0/CVE-2022-25765](https://github.com/innocentx0/CVE-2022-25765) :  ![starts](https://img.shields.io/github/stars/innocentx0/CVE-2022-25765.svg) ![forks](https://img.shields.io/github/forks/innocentx0/CVE-2022-25765.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe](https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/GU-007/struts2-tool](https://github.com/GU-007/struts2-tool) :  ![starts](https://img.shields.io/github/stars/GU-007/struts2-tool.svg) ![forks](https://img.shields.io/github/forks/GU-007/struts2-tool.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/JUN41DS2709/vsFTPd-2.3.4-Exploit](https://github.com/JUN41DS2709/vsFTPd-2.3.4-Exploit) :  ![starts](https://img.shields.io/github/stars/JUN41DS2709/vsFTPd-2.3.4-Exploit.svg) ![forks](https://img.shields.io/github/forks/JUN41DS2709/vsFTPd-2.3.4-Exploit.svg)
- [https://github.com/aboubacar70/LAB1-metasploitable](https://github.com/aboubacar70/LAB1-metasploitable) :  ![starts](https://img.shields.io/github/stars/aboubacar70/LAB1-metasploitable.svg) ![forks](https://img.shields.io/github/forks/aboubacar70/LAB1-metasploitable.svg)


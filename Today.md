# Update 2025-12-19
## CVE-2025-68434
 Open Source Point of Sale (opensourcepos) is a web based point of sale application written in PHP using CodeIgniter framework. Starting in version 3.4.0 and prior to version 3.4.2, a Cross-Site Request Forgery (CSRF) vulnerability exists in the application's filter configuration. The CSRF protection mechanism was **explicitly disabled**, allowing the application to process state-changing requests (POST) without verifying a valid CSRF token. An unauthenticated remote attacker can exploit this by hosting a malicious web page. If a logged-in administrator visits this page, their browser is forced to send unauthorized requests to the application. A successful exploit allows the attacker to silently create a new Administrator account with full privileges, leading to a complete takeover of the system and loss of confidentiality, integrity, and availability. The vulnerability has been patched in version 3.4.2. The fix re-enables the CSRF filter in `app/Config/Filters.php` and resolves associated AJAX race conditions by adjusting token regeneration settings. As a workaround, administrators can manually re-enable the CSRF filter in `app/Config/Filters.php` by uncommenting the protection line. However, this is not recommended without applying the full patch, as it may cause functionality breakage in the Sales module due to token synchronization issues.

- [https://github.com/Nixon-H/CVE-2025-68434-OSPOS-CSRF-Unauthorized-Administrator-Creation](https://github.com/Nixon-H/CVE-2025-68434-OSPOS-CSRF-Unauthorized-Administrator-Creation) :  ![starts](https://img.shields.io/github/stars/Nixon-H/CVE-2025-68434-OSPOS-CSRF-Unauthorized-Administrator-Creation.svg) ![forks](https://img.shields.io/github/forks/Nixon-H/CVE-2025-68434-OSPOS-CSRF-Unauthorized-Administrator-Creation.svg)


## CVE-2025-68147
 Open Source Point of Sale (opensourcepos) is a web based point of sale application written in PHP using CodeIgniter framework. Starting in version 3.4.0 and prior to version 3.4.2, a Stored Cross-Site Scripting (XSS) vulnerability exists in the "Return Policy" configuration field. The application does not properly sanitize user input before saving it to the database or displaying it on receipts. An attacker with access to the "Store Configuration" (such as a rogue administrator or an account compromised via the separate CSRF vulnerability) can inject malicious JavaScript payloads into this field. These payloads are executed in the browser of any user (including other administrators and sales staff) whenever they view a receipt or complete a transaction. This can lead to session hijacking, theft of sensitive data, or unauthorized actions performed on behalf of the victim. The vulnerability has been patched in version 3.4.2 by ensuring the output is escaped using the `esc()` function in the receipt template. As a temporary mitigation, administrators should ensure the "Return Policy" field contains only plain text and strictly avoid entering any HTML tags. There is no code-based workaround other than applying the patch.

- [https://github.com/Nixon-H/CVE-2025-68147-OSPOS-Stored-XSS](https://github.com/Nixon-H/CVE-2025-68147-OSPOS-Stored-XSS) :  ![starts](https://img.shields.io/github/stars/Nixon-H/CVE-2025-68147-OSPOS-Stored-XSS.svg) ![forks](https://img.shields.io/github/forks/Nixon-H/CVE-2025-68147-OSPOS-Stored-XSS.svg)


## CVE-2025-67779
 It was found that the fix addressing CVE-2025-55184 in React Server Components was incomplete and does not prevent a denial of service attack in a specific case. React Server Components versions 19.0.2, 19.1.3 and 19.2.2 are affected, allowing unsafe deserialization of payloads from HTTP requests to Server Function endpoints. This can cause an infinite loop that hangs the server process and may prevent future HTTP requests from being served.

- [https://github.com/theori-io/reactguard](https://github.com/theori-io/reactguard) :  ![starts](https://img.shields.io/github/stars/theori-io/reactguard.svg) ![forks](https://img.shields.io/github/forks/theori-io/reactguard.svg)


## CVE-2025-66516
Second, the original report failed to mention that in the 1.x Tika releases, the PDFParser was in the "org.apache.tika:tika-parsers" module.

- [https://github.com/sid6224/CVE-2025-66516-POC](https://github.com/sid6224/CVE-2025-66516-POC) :  ![starts](https://img.shields.io/github/stars/sid6224/CVE-2025-66516-POC.svg) ![forks](https://img.shields.io/github/forks/sid6224/CVE-2025-66516-POC.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/mio-qwq/nextjs-cve-2025-66478-ctf](https://github.com/mio-qwq/nextjs-cve-2025-66478-ctf) :  ![starts](https://img.shields.io/github/stars/mio-qwq/nextjs-cve-2025-66478-ctf.svg) ![forks](https://img.shields.io/github/forks/mio-qwq/nextjs-cve-2025-66478-ctf.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg)


## CVE-2025-66224
 OrangeHRM is a comprehensive human resource management (HRM) system. From version 5.0 to 5.7, the application contains an input-neutralization flaw in its mail configuration and delivery workflow that allows user-controlled values to flow directly into the system’s sendmail command. Because these values are not sanitized or constrained before being incorporated into the command execution path, certain sendmail behaviors can be unintentionally invoked during email processing. This makes it possible for the application to write files on the server as part of the mail-handling routine, and in deployments where those files end up in web-accessible locations, the behavior can be leveraged to achieve execution of attacker-controlled content. The issue stems entirely from constructing OS-level command strings using unsanitized input within the mail-sending logic. This issue has been patched in version 5.8.

- [https://github.com/richard-natan/PoC-CVE-2025-66224](https://github.com/richard-natan/PoC-CVE-2025-66224) :  ![starts](https://img.shields.io/github/stars/richard-natan/PoC-CVE-2025-66224.svg) ![forks](https://img.shields.io/github/forks/richard-natan/PoC-CVE-2025-66224.svg)


## CVE-2025-65945
 auth0/node-jws is a JSON Web Signature implementation for Node.js. In versions 3.2.2 and earlier and version 4.0.0, auth0/node-jws has an improper signature verification vulnerability when using the HS256 algorithm under specific conditions. Applications are affected when they use the jws.createVerify() function for HMAC algorithms and use user-provided data from the JSON Web Signature protected header or payload in HMAC secret lookup routines, which can allow attackers to bypass signature verification. This issue has been patched in versions 3.2.3 and 4.0.1.

- [https://github.com/jedisct1/CVE-2025-65945-poc](https://github.com/jedisct1/CVE-2025-65945-poc) :  ![starts](https://img.shields.io/github/stars/jedisct1/CVE-2025-65945-poc.svg) ![forks](https://img.shields.io/github/forks/jedisct1/CVE-2025-65945-poc.svg)


## CVE-2025-65855
 The OTA firmware update mechanism in Netun Solutions HelpFlash IoT (firmware v18_178_221102_ASCII_PRO_1R5_50) uses hard-coded WiFi credentials identical across all devices and does not authenticate update servers or validate firmware signatures. An attacker with brief physical access can activate OTA mode (8-second button press), create a malicious WiFi AP using the known credentials, and serve malicious firmware via unauthenticated HTTP to achieve arbitrary code execution on this safety-critical emergency signaling device.

- [https://github.com/LuisMirandaAcebedo/CVE-2025-65855](https://github.com/LuisMirandaAcebedo/CVE-2025-65855) :  ![starts](https://img.shields.io/github/stars/LuisMirandaAcebedo/CVE-2025-65855.svg) ![forks](https://img.shields.io/github/forks/LuisMirandaAcebedo/CVE-2025-65855.svg)


## CVE-2025-59718
 A improper verification of cryptographic signature vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2.0 through 7.2.11, FortiOS 7.0.0 through 7.0.17, FortiProxy 7.6.0 through 7.6.3, FortiProxy 7.4.0 through 7.4.10, FortiProxy 7.2.0 through 7.2.14, FortiProxy 7.0.0 through 7.0.21, FortiSwitchManager 7.2.0 through 7.2.6, FortiSwitchManager 7.0.0 through 7.0.5 allows an unauthenticated attacker to bypass the FortiCloud SSO login authentication via a crafted SAML response message.

- [https://github.com/exfil0/CVE-2025-59718-PoC](https://github.com/exfil0/CVE-2025-59718-PoC) :  ![starts](https://img.shields.io/github/stars/exfil0/CVE-2025-59718-PoC.svg) ![forks](https://img.shields.io/github/forks/exfil0/CVE-2025-59718-PoC.svg)


## CVE-2025-55184
 A pre-authentication denial of service vulnerability exists in React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints, which can cause an infinite loop that hangs the server process and may prevent future HTTP requests from being served.

- [https://github.com/theori-io/reactguard](https://github.com/theori-io/reactguard) :  ![starts](https://img.shields.io/github/stars/theori-io/reactguard.svg) ![forks](https://img.shields.io/github/forks/theori-io/reactguard.svg)


## CVE-2025-55183
 An information leak vulnerability exists in specific configurations of React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. A specifically crafted HTTP request sent to a vulnerable Server Function may unsafely return the source code of any Server Function. Exploitation requires the existence of a Server Function which explicitly or implicitly exposes a stringified argument.

- [https://github.com/theori-io/reactguard](https://github.com/theori-io/reactguard) :  ![starts](https://img.shields.io/github/stars/theori-io/reactguard.svg) ![forks](https://img.shields.io/github/forks/theori-io/reactguard.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/websecuritylabs/React2Shell-Library](https://github.com/websecuritylabs/React2Shell-Library) :  ![starts](https://img.shields.io/github/stars/websecuritylabs/React2Shell-Library.svg) ![forks](https://img.shields.io/github/forks/websecuritylabs/React2Shell-Library.svg)
- [https://github.com/hidden-investigations/react2shell-scanner](https://github.com/hidden-investigations/react2shell-scanner) :  ![starts](https://img.shields.io/github/stars/hidden-investigations/react2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/hidden-investigations/react2shell-scanner.svg)


## CVE-2025-54988
Users are recommended to upgrade to version 3.2.2, which fixes this issue.

- [https://github.com/galoryber/cve-2025-54988-VulnTikaProject](https://github.com/galoryber/cve-2025-54988-VulnTikaProject) :  ![starts](https://img.shields.io/github/stars/galoryber/cve-2025-54988-VulnTikaProject.svg) ![forks](https://img.shields.io/github/forks/galoryber/cve-2025-54988-VulnTikaProject.svg)


## CVE-2025-24201
 An out-of-bounds write issue was addressed with improved checks to prevent unauthorized actions. This issue is fixed in visionOS 2.3.2, iOS 18.3.2 and iPadOS 18.3.2, macOS Sequoia 15.3.2, Safari 18.3.1, watchOS 11.4, iPadOS 17.7.6, iOS 16.7.11 and iPadOS 16.7.11, iOS 15.8.4 and iPadOS 15.8.4. Maliciously crafted web content may be able to break out of Web Content sandbox. This is a supplementary fix for an attack that was blocked in iOS 17.2. (Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 17.2.).

- [https://github.com/The-Maxu/CVE-2025-24201-WebKit-Vulnerability-Detector-PoC-](https://github.com/The-Maxu/CVE-2025-24201-WebKit-Vulnerability-Detector-PoC-) :  ![starts](https://img.shields.io/github/stars/The-Maxu/CVE-2025-24201-WebKit-Vulnerability-Detector-PoC-.svg) ![forks](https://img.shields.io/github/forks/The-Maxu/CVE-2025-24201-WebKit-Vulnerability-Detector-PoC-.svg)


## CVE-2025-24016
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations, even by a compromised agent. Version 4.9.1 contains a fix.

- [https://github.com/celsius026/poc_CVE-2025-24016](https://github.com/celsius026/poc_CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/celsius026/poc_CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/celsius026/poc_CVE-2025-24016.svg)


## CVE-2025-23419
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/harley-ghostie/safe-check-CVE-2025-23419](https://github.com/harley-ghostie/safe-check-CVE-2025-23419) :  ![starts](https://img.shields.io/github/stars/harley-ghostie/safe-check-CVE-2025-23419.svg) ![forks](https://img.shields.io/github/forks/harley-ghostie/safe-check-CVE-2025-23419.svg)


## CVE-2025-21628
 Chatwoot is a customer engagement suite. Prior to 3.16.0, conversation and contact filters endpoints did not sanitize the input of query_operator passed from the frontend or the API. This provided any actor who is authenticated, an attack vector to run arbitrary SQL within the filter query by adding a tautological WHERE clause. This issue is patched with v3.16.0.

- [https://github.com/elahehasanpour/chatwoot-cve-2025-21628](https://github.com/elahehasanpour/chatwoot-cve-2025-21628) :  ![starts](https://img.shields.io/github/stars/elahehasanpour/chatwoot-cve-2025-21628.svg) ![forks](https://img.shields.io/github/forks/elahehasanpour/chatwoot-cve-2025-21628.svg)


## CVE-2025-14700
 An input neutralization vulnerability in the Webhook Template component of Crafty Controller allows a remote, authenticated attacker to perform remote code execution via Server Side Template Injection.

- [https://github.com/Nosiume/CVE-2025-14700-poc](https://github.com/Nosiume/CVE-2025-14700-poc) :  ![starts](https://img.shields.io/github/stars/Nosiume/CVE-2025-14700-poc.svg) ![forks](https://img.shields.io/github/forks/Nosiume/CVE-2025-14700-poc.svg)


## CVE-2025-13780
 pgAdmin versions up to 9.10 are affected by a Remote Code Execution (RCE) vulnerability that occurs when running in server mode and performing restores from PLAIN-format dump files. This issue allows attackers to inject and execute arbitrary commands on the server hosting pgAdmin, posing a critical risk to the integrity and security of the database management system and underlying data.

- [https://github.com/ThemeHackers/CVE-2025-13780](https://github.com/ThemeHackers/CVE-2025-13780) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2025-13780.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2025-13780.svg)


## CVE-2025-6585
 The WP JobHunt plugin for WordPress is vulnerable to Insecure Direct Object Reference in all versions up to, and including, 7.2 via the cs_remove_profile_callback() function due to missing validation on a user controlled key. This makes it possible for authenticated attackers, with Subscriber-level access and above, to delete accounts of other users including admins.

- [https://github.com/LuisMirandaAcebedo/CVE-2025-65856](https://github.com/LuisMirandaAcebedo/CVE-2025-65856) :  ![starts](https://img.shields.io/github/stars/LuisMirandaAcebedo/CVE-2025-65856.svg) ![forks](https://img.shields.io/github/forks/LuisMirandaAcebedo/CVE-2025-65856.svg)
- [https://github.com/LuisMirandaAcebedo/CVE-2025-65857](https://github.com/LuisMirandaAcebedo/CVE-2025-65857) :  ![starts](https://img.shields.io/github/stars/LuisMirandaAcebedo/CVE-2025-65857.svg) ![forks](https://img.shields.io/github/forks/LuisMirandaAcebedo/CVE-2025-65857.svg)


## CVE-2025-1426
 Heap buffer overflow in GPU in Google Chrome on Android prior to 133.0.6943.126 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/r0binak/CVE-2025-14269](https://github.com/r0binak/CVE-2025-14269) :  ![starts](https://img.shields.io/github/stars/r0binak/CVE-2025-14269.svg) ![forks](https://img.shields.io/github/forks/r0binak/CVE-2025-14269.svg)


## CVE-2024-30804
 An issue discovered in the DeviceIoControl component in ASUS Fan_Xpert before v.10013 allows an attacker to execute arbitrary code via crafted IOCTL requests.

- [https://github.com/ekfkawl/CVE-2024-30804](https://github.com/ekfkawl/CVE-2024-30804) :  ![starts](https://img.shields.io/github/stars/ekfkawl/CVE-2024-30804.svg) ![forks](https://img.shields.io/github/forks/ekfkawl/CVE-2024-30804.svg)


## CVE-2024-29973
The command injection vulnerability in the “setCookie” parameter in Zyxel NAS326 firmware versions before V5.21(AAZF.17)C0 and NAS542 firmware versions before V5.21(ABAG.14)C0 could allow an unauthenticated attacker to execute some operating system (OS) commands by sending a crafted HTTP POST request.

- [https://github.com/0zerobyte/CVE-2024-29973](https://github.com/0zerobyte/CVE-2024-29973) :  ![starts](https://img.shields.io/github/stars/0zerobyte/CVE-2024-29973.svg) ![forks](https://img.shields.io/github/forks/0zerobyte/CVE-2024-29973.svg)


## CVE-2024-27198
 In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible

- [https://github.com/EynaExp/CVE-2024-27198-POC](https://github.com/EynaExp/CVE-2024-27198-POC) :  ![starts](https://img.shields.io/github/stars/EynaExp/CVE-2024-27198-POC.svg) ![forks](https://img.shields.io/github/forks/EynaExp/CVE-2024-27198-POC.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/0zerobyte/CVE-2024-24919](https://github.com/0zerobyte/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/0zerobyte/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/0zerobyte/CVE-2024-24919.svg)


## CVE-2024-7593
 Incorrect implementation of an authentication algorithm in Ivanti vTM other than versions 22.2R1 or 22.7R2 allows a remote unauthenticated attacker to bypass authentication of the admin panel.

- [https://github.com/0zerobyte/CVE-2024-7593](https://github.com/0zerobyte/CVE-2024-7593) :  ![starts](https://img.shields.io/github/stars/0zerobyte/CVE-2024-7593.svg) ![forks](https://img.shields.io/github/forks/0zerobyte/CVE-2024-7593.svg)


## CVE-2024-2876
 The Email Subscribers by Icegram Express – Email Marketing, Newsletters, Automation for WordPress & WooCommerce plugin for WordPress is vulnerable to SQL Injection via the 'run' function of the 'IG_ES_Subscribers_Query' class in all versions up to, and including, 5.7.14 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/0zerobyte/CVE-2024-2876](https://github.com/0zerobyte/CVE-2024-2876) :  ![starts](https://img.shields.io/github/stars/0zerobyte/CVE-2024-2876.svg) ![forks](https://img.shields.io/github/forks/0zerobyte/CVE-2024-2876.svg)


## CVE-2024-2404
 The Better Comments WordPress plugin before 1.5.6 does not sanitise and escape some of its settings, which could allow low privilege users such as Subscribers to perform Stored Cross-Site Scripting attacks.

- [https://github.com/mihwuan/CVE2024-24048_Likeshop_Fix](https://github.com/mihwuan/CVE2024-24048_Likeshop_Fix) :  ![starts](https://img.shields.io/github/stars/mihwuan/CVE2024-24048_Likeshop_Fix.svg) ![forks](https://img.shields.io/github/forks/mihwuan/CVE2024-24048_Likeshop_Fix.svg)


## CVE-2023-22527
Most recent supported versions of Confluence Data Center and Server are not affected by this vulnerability as it was ultimately mitigated during regular version updates. However, Atlassian recommends that customers take care to install the latest version to protect their instances from non-critical vulnerabilities outlined in Atlassian’s January Security Bulletin.

- [https://github.com/anonymous-echo/CVE-2023-22527](https://github.com/anonymous-echo/CVE-2023-22527) :  ![starts](https://img.shields.io/github/stars/anonymous-echo/CVE-2023-22527.svg) ![forks](https://img.shields.io/github/forks/anonymous-echo/CVE-2023-22527.svg)


## CVE-2022-3218
 Due to a reliance on client-side authentication, the WiFi Mouse (Mouse Server) from Necta LLC's authentication mechanism is trivially bypassed, which can result in remote code execution.

- [https://github.com/MoisesTapia/cve-2022-3218](https://github.com/MoisesTapia/cve-2022-3218) :  ![starts](https://img.shields.io/github/stars/MoisesTapia/cve-2022-3218.svg) ![forks](https://img.shields.io/github/forks/MoisesTapia/cve-2022-3218.svg)


## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.

- [https://github.com/davids52/cve-2021-29447_auto-script](https://github.com/davids52/cve-2021-29447_auto-script) :  ![starts](https://img.shields.io/github/stars/davids52/cve-2021-29447_auto-script.svg) ![forks](https://img.shields.io/github/forks/davids52/cve-2021-29447_auto-script.svg)


## CVE-2021-3560
 It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

- [https://github.com/m4lk3rnel/CVE-2021-3560](https://github.com/m4lk3rnel/CVE-2021-3560) :  ![starts](https://img.shields.io/github/stars/m4lk3rnel/CVE-2021-3560.svg) ![forks](https://img.shields.io/github/forks/m4lk3rnel/CVE-2021-3560.svg)


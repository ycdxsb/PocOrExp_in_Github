# Update 2026-05-29
## CVE-2026-48710
 Starlette is a lightweight ASGI framework/toolkit. Prior to version 1.0.1, the HTTP `Host` request header was not validated before being used to reconstruct `request.url`. Because the routing algorithm relies on the raw HTTP path while `request.url` is rebuilt from the `Host` header, a malformed header could make `request.url.path` differ from the path that was actually requested. Middleware and endpoints that apply security restrictions based on `request.url` (rather than the raw `scope` path) could therefore be bypassed. Users should upgrade to a version greater than or equal to version 1.0.1, which validates the `Host` header against the grammar of RFC 9112 §3.2 / RFC 3986 §3.2.2 when constructing `request.url` and falls back to `scope["server"]` for malformed values.

- [https://github.com/eris-ths/supply-chain-guard](https://github.com/eris-ths/supply-chain-guard) :  ![starts](https://img.shields.io/github/stars/eris-ths/supply-chain-guard.svg) ![forks](https://img.shields.io/github/forks/eris-ths/supply-chain-guard.svg)
- [https://github.com/xtremebeing/starlette-host-header-lab](https://github.com/xtremebeing/starlette-host-header-lab) :  ![starts](https://img.shields.io/github/stars/xtremebeing/starlette-host-header-lab.svg) ![forks](https://img.shields.io/github/forks/xtremebeing/starlette-host-header-lab.svg)


## CVE-2026-46586
Users are recommended to upgrade to version 24.09.06, which fixes the issue.

- [https://github.com/lwd3c/CVE-2026-46586](https://github.com/lwd3c/CVE-2026-46586) :  ![starts](https://img.shields.io/github/stars/lwd3c/CVE-2026-46586.svg) ![forks](https://img.shields.io/github/forks/lwd3c/CVE-2026-46586.svg)


## CVE-2026-45659
 Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized attacker to execute code over a network.

- [https://github.com/HORKimhab/CVE-2026-45659](https://github.com/HORKimhab/CVE-2026-45659) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-45659.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-45659.svg)
- [https://github.com/mistbarbarianspot/CVE-2026-45659-SharePoint-RCE](https://github.com/mistbarbarianspot/CVE-2026-45659-SharePoint-RCE) :  ![starts](https://img.shields.io/github/stars/mistbarbarianspot/CVE-2026-45659-SharePoint-RCE.svg) ![forks](https://img.shields.io/github/forks/mistbarbarianspot/CVE-2026-45659-SharePoint-RCE.svg)


## CVE-2026-44590
 Sherlock hunts down social media accounts by username across social networks. Prior to 0.16.1, the GitHub Actions workflow validate_modified_targets.yml is vulnerable to command injection via the pull_request_target trigger. Any GitHub user can execute arbitrary commands on the CI runner and exfiltrate the GITHUB_TOKEN by opening a pull request. No approval, review, or merge is required. This vulnerability is fixed in 0.16.1.

- [https://github.com/Astaruf/CVE-2026-44590](https://github.com/Astaruf/CVE-2026-44590) :  ![starts](https://img.shields.io/github/stars/Astaruf/CVE-2026-44590.svg) ![forks](https://img.shields.io/github/forks/Astaruf/CVE-2026-44590.svg)


## CVE-2026-42879
 FacturaScripts is an open source accounting and invoicing software. In 2025.81 and earlier, an authenticated unrestricted file upload vulnerability exists in FacturaScripts' product image upload functionality. An attacker with valid credentials can upload a PHP file disguised as a GIF image (using a GIF89a header), bypassing MIME type validation. The file is stored with its original extension, including executable extensions such as .php. The vulnerability exists the addImageAction() method of Core/Lib/ExtendedController/ProductImagesTrait.php.

- [https://github.com/guzrex/CVE-2026-42879](https://github.com/guzrex/CVE-2026-42879) :  ![starts](https://img.shields.io/github/stars/guzrex/CVE-2026-42879.svg) ![forks](https://img.shields.io/github/forks/guzrex/CVE-2026-42879.svg)


## CVE-2026-38945
 Command injection in Raynet rvia version 12.6 Update 8 and previous versions allows adversaries to execute arbitrary code via a crafted path that matches the improperly terminated search criteria of rvia's Java search using the find command.

- [https://github.com/Wise-Security/CVE-2026-38945](https://github.com/Wise-Security/CVE-2026-38945) :  ![starts](https://img.shields.io/github/stars/Wise-Security/CVE-2026-38945.svg) ![forks](https://img.shields.io/github/forks/Wise-Security/CVE-2026-38945.svg)


## CVE-2026-38427
 An issue in fetch_jpg() in xdrv_10_scripter.ino in Tasmota through 15.3.0.3 allows a remote attacker to cause heap buffer overflow. The Content-Length from a JPEG stream is stored in a uint16_t variable; values above 65535 wrap around, causing allocation of a smaller buffer than the data actually read.

- [https://github.com/sermikr0/CVE-2026-38427](https://github.com/sermikr0/CVE-2026-38427) :  ![starts](https://img.shields.io/github/stars/sermikr0/CVE-2026-38427.svg) ![forks](https://img.shields.io/github/forks/sermikr0/CVE-2026-38427.svg)


## CVE-2026-38426
 Buffer Overflow vulnerability in arendst Tasmota v.15.3.0.3 and before allows a remote attacker to execute arbitrary code via the xdrv_10_scripter.ino, fetch_jpg(), jpg_task.boundary[40], strcpy() function.

- [https://github.com/sermikr0/CVE-2026-38426](https://github.com/sermikr0/CVE-2026-38426) :  ![starts](https://img.shields.io/github/stars/sermikr0/CVE-2026-38426.svg) ![forks](https://img.shields.io/github/forks/sermikr0/CVE-2026-38426.svg)


## CVE-2026-38422
 Buffer Overflow vulnerability in arendst Tasmota v.15.3.0.3 and before allows a remote attacker to execute arbitrary code via the tasmota/tasmota_xdrv_driver/xdrv_10_scripter.ino, fetch_jpg() function.

- [https://github.com/sermikr0/CVE-2026-38422](https://github.com/sermikr0/CVE-2026-38422) :  ![starts](https://img.shields.io/github/stars/sermikr0/CVE-2026-38422.svg) ![forks](https://img.shields.io/github/forks/sermikr0/CVE-2026-38422.svg)


## CVE-2026-31266
 Craft CMS 5.9.5 and earlier contains a Missing Authorization vulnerability in the migrate endpoint (/actions/app/migrate).

- [https://github.com/0xrixet/Craftcms-PoC-CVE-2026-31266](https://github.com/0xrixet/Craftcms-PoC-CVE-2026-31266) :  ![starts](https://img.shields.io/github/stars/0xrixet/Craftcms-PoC-CVE-2026-31266.svg) ![forks](https://img.shields.io/github/forks/0xrixet/Craftcms-PoC-CVE-2026-31266.svg)


## CVE-2026-30498
 A Cross-Site Request Forgery (CSRF) vulnerability was discovered in the delete.php endpoint of Jason2605 AdminPanel 4.0.

- [https://github.com/Mehdi-Ben-Hamou/CVE-2026-30498](https://github.com/Mehdi-Ben-Hamou/CVE-2026-30498) :  ![starts](https://img.shields.io/github/stars/Mehdi-Ben-Hamou/CVE-2026-30498.svg) ![forks](https://img.shields.io/github/forks/Mehdi-Ben-Hamou/CVE-2026-30498.svg)


## CVE-2026-26980
 Ghost is a Node.js content management system. Versions 3.24.0 through 6.19.0 allow unauthenticated attackers to perform arbitrary reads from the database. This issue has been fixed in version 6.19.1.

- [https://github.com/EQSTLab/CVE-2026-26980](https://github.com/EQSTLab/CVE-2026-26980) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-26980.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-26980.svg)


## CVE-2026-9256
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/friparia/NGINX_RIFT_SCAN_CVE_2026_42945](https://github.com/friparia/NGINX_RIFT_SCAN_CVE_2026_42945) :  ![starts](https://img.shields.io/github/stars/friparia/NGINX_RIFT_SCAN_CVE_2026_42945.svg) ![forks](https://img.shields.io/github/forks/friparia/NGINX_RIFT_SCAN_CVE_2026_42945.svg)


## CVE-2026-9082
This issue affects Drupal core: from 8.9.0 before 10.4.10, from 10.5.0 before 10.5.10, from 10.6.0 before 10.6.9, from 11.0.0 before 11.1.10, from 11.2.0 before 11.2.12, from 11.3.0 before 11.3.10.

- [https://github.com/strobelpierre/CVE-2026-9082](https://github.com/strobelpierre/CVE-2026-9082) :  ![starts](https://img.shields.io/github/stars/strobelpierre/CVE-2026-9082.svg) ![forks](https://img.shields.io/github/forks/strobelpierre/CVE-2026-9082.svg)
- [https://github.com/thinhap/CVE-2026-9082-PoC](https://github.com/thinhap/CVE-2026-9082-PoC) :  ![starts](https://img.shields.io/github/stars/thinhap/CVE-2026-9082-PoC.svg) ![forks](https://img.shields.io/github/forks/thinhap/CVE-2026-9082-PoC.svg)


## CVE-2026-5172
 A buffer overflow in dnsmasq’s extract_addresses() function allows an attacker to trigger a heap out-of-bounds read and crash by exploiting a malformed DNS response, enabling extract_name() to advance the pointer past the record’s end.

- [https://github.com/lottiedeyan/CVE20265172poc](https://github.com/lottiedeyan/CVE20265172poc) :  ![starts](https://img.shields.io/github/stars/lottiedeyan/CVE20265172poc.svg) ![forks](https://img.shields.io/github/forks/lottiedeyan/CVE20265172poc.svg)


## CVE-2026-4893
 An information disclosure vulnerability in dnsmasq allows remote attackers to bypass source checks via a crafted DNS packet with RFC 7871 client subnet information.

- [https://github.com/lottiedeyan/CVE20264893poc](https://github.com/lottiedeyan/CVE20264893poc) :  ![starts](https://img.shields.io/github/stars/lottiedeyan/CVE20264893poc.svg) ![forks](https://img.shields.io/github/forks/lottiedeyan/CVE20264893poc.svg)


## CVE-2026-3069
 A security vulnerability has been detected in itsourcecode Document Management System 1.0. Affected is an unknown function of the file /edtlbls.php. The manipulation of the argument field1 leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed publicly and may be used.

- [https://github.com/walidriouah/CVE-2026-30690](https://github.com/walidriouah/CVE-2026-30690) :  ![starts](https://img.shields.io/github/stars/walidriouah/CVE-2026-30690.svg) ![forks](https://img.shields.io/github/forks/walidriouah/CVE-2026-30690.svg)


## CVE-2026-2777
 Privilege escalation in the Messaging System component. This vulnerability was fixed in Firefox 148, Firefox ESR 115.33, Firefox ESR 140.8, Thunderbird 148, and Thunderbird 140.8.

- [https://github.com/portbuster1337/CVE-2026-27771](https://github.com/portbuster1337/CVE-2026-27771) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-27771.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-27771.svg)
- [https://github.com/HORKimhab/CVE-2026-27771](https://github.com/HORKimhab/CVE-2026-27771) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-27771.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-27771.svg)


## CVE-2025-69600
 Command injection in Raynet rvia 12.6.4392.49-amd64.deb allows adversaries to execute commands via getconfig, and upload through the URL argument, and oracle through the -o flag The Supplier's perspective is that this is caused by Argument Injection in the find command query in rvia 12.6.4392.49. This in an arbitrary code execution flaw caused by an incorrectly constructed find command. The application actively searches for a Java executable by using search criteria that is not properly terminated or sanitized. By constructing a crafted directory path that satisfies the malformed search criteria, an attacker can trick the application into executing arbitrary Java code. This differs from standard PATH manipulation because it stems from the application's internal search logic. Specifically, a local attacker can create a crafted directory structure and path that satisfies an improperly terminated find query used by the application to locate a Java runtime.

- [https://github.com/Wise-Security/CVE-2025-69600](https://github.com/Wise-Security/CVE-2025-69600) :  ![starts](https://img.shields.io/github/stars/Wise-Security/CVE-2025-69600.svg) ![forks](https://img.shields.io/github/forks/Wise-Security/CVE-2025-69600.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/jensnesten/React2Shell-PoC](https://github.com/jensnesten/React2Shell-PoC) :  ![starts](https://img.shields.io/github/stars/jensnesten/React2Shell-PoC.svg) ![forks](https://img.shields.io/github/forks/jensnesten/React2Shell-PoC.svg)


## CVE-2025-54123
 Hoverfly is an open source API simulation tool. In versions 1.11.3 and prior, the middleware functionality in Hoverfly is vulnerable to command injection vulnerability at `/api/v2/hoverfly/middleware` endpoint due to insufficient validation and sanitization in user input. The vulnerability exists in the middleware management API endpoint `/api/v2/hoverfly/middleware`. This issue is born due to combination of three code level flaws: Insufficient Input Validation in middleware.go line 94-96; Unsafe Command Execution in local_middleware.go line 14-19; and Immediate Execution During Testing in hoverfly_service.go line 173. This allows an attacker to gain remote code execution (RCE) on any system running the vulnerable Hoverfly service. Since the input is directly passed to system commands without proper checks, an attacker can upload a malicious payload or directly execute arbitrary commands (including reverse shells) on the host server with the privileges of the Hoverfly process. Commit 17e60a9bc78826deb4b782dca1c1abd3dbe60d40 in version 1.12.0 disables the set middleware API by default, and subsequent changes to documentation make users aware of the security changes of exposing the set middleware API.

- [https://github.com/0x00phantom-hat/Hoverfly-1.11.3-RCE-CVE-2025-54123-Exploit](https://github.com/0x00phantom-hat/Hoverfly-1.11.3-RCE-CVE-2025-54123-Exploit) :  ![starts](https://img.shields.io/github/stars/0x00phantom-hat/Hoverfly-1.11.3-RCE-CVE-2025-54123-Exploit.svg) ![forks](https://img.shields.io/github/forks/0x00phantom-hat/Hoverfly-1.11.3-RCE-CVE-2025-54123-Exploit.svg)


## CVE-2025-36911
 In key-based pairing, there is a possible ID due to a logic error in the code. This could lead to remote (proximal/adjacent) information disclosure of user's conversations and location with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/KULeuven-COSIC/WhisperPair](https://github.com/KULeuven-COSIC/WhisperPair) :  ![starts](https://img.shields.io/github/stars/KULeuven-COSIC/WhisperPair.svg) ![forks](https://img.shields.io/github/forks/KULeuven-COSIC/WhisperPair.svg)


## CVE-2025-33073
 Improper access control in Windows SMB allows an authorized attacker to elevate privileges over a network.

- [https://github.com/SFRDevelopment/windows-smb-vulnerability-framework-cve-2025-33073](https://github.com/SFRDevelopment/windows-smb-vulnerability-framework-cve-2025-33073) :  ![starts](https://img.shields.io/github/stars/SFRDevelopment/windows-smb-vulnerability-framework-cve-2025-33073.svg) ![forks](https://img.shields.io/github/forks/SFRDevelopment/windows-smb-vulnerability-framework-cve-2025-33073.svg)


## CVE-2025-21298
 Windows OLE Remote Code Execution Vulnerability

- [https://github.com/abc1230940/SOC336-Windows-OLE-Zero-Click-RCE-Exploitation-Detected-CVE-2025-21298](https://github.com/abc1230940/SOC336-Windows-OLE-Zero-Click-RCE-Exploitation-Detected-CVE-2025-21298) :  ![starts](https://img.shields.io/github/stars/abc1230940/SOC336-Windows-OLE-Zero-Click-RCE-Exploitation-Detected-CVE-2025-21298.svg) ![forks](https://img.shields.io/github/forks/abc1230940/SOC336-Windows-OLE-Zero-Click-RCE-Exploitation-Detected-CVE-2025-21298.svg)


## CVE-2024-38063
 Windows TCP/IP Remote Code Execution Vulnerability

- [https://github.com/artemgarkusenko919-design/Kill-System](https://github.com/artemgarkusenko919-design/Kill-System) :  ![starts](https://img.shields.io/github/stars/artemgarkusenko919-design/Kill-System.svg) ![forks](https://img.shields.io/github/forks/artemgarkusenko919-design/Kill-System.svg)


## CVE-2024-4309
 SQL injection vulnerability in HubBank affecting version 1.0.2. This vulnerability could allow an attacker to send a specially crafted SQL query to the database through different endpoints (/user/transaction.php?id=1, /user/credit-debit_transaction.php?id=1,/user/view_transaction. php?id=1 and  /user/viewloantrans.php?id=1, id parameter) and retrieve the information stored in the database.

- [https://github.com/Winslowe/CVE-2024-4309-Analysis](https://github.com/Winslowe/CVE-2024-4309-Analysis) :  ![starts](https://img.shields.io/github/stars/Winslowe/CVE-2024-4309-Analysis.svg) ![forks](https://img.shields.io/github/forks/Winslowe/CVE-2024-4309-Analysis.svg)


## CVE-2023-35813
 Multiple Sitecore products allow remote code execution. This affects Experience Manager, Experience Platform, and Experience Commerce through 10.3.

- [https://github.com/nmlz/CVE-2023-35813_PoC](https://github.com/nmlz/CVE-2023-35813_PoC) :  ![starts](https://img.shields.io/github/stars/nmlz/CVE-2023-35813_PoC.svg) ![forks](https://img.shields.io/github/forks/nmlz/CVE-2023-35813_PoC.svg)


## CVE-2023-26083
 Memory leak vulnerability in Mali GPU Kernel Driver in Midgard GPU Kernel Driver all versions from r6p0 - r32p0, Bifrost GPU Kernel Driver all versions from r0p0 - r42p0, Valhall GPU Kernel Driver all versions from r19p0 - r42p0, and Avalon GPU Kernel Driver all versions from r41p0 - r42p0 allows a non-privileged user to make valid GPU processing operations that expose sensitive kernel metadata.

- [https://github.com/Noverisp3/CVE-2023-26083-Mali-InfoLeak-PoC](https://github.com/Noverisp3/CVE-2023-26083-Mali-InfoLeak-PoC) :  ![starts](https://img.shields.io/github/stars/Noverisp3/CVE-2023-26083-Mali-InfoLeak-PoC.svg) ![forks](https://img.shields.io/github/forks/Noverisp3/CVE-2023-26083-Mali-InfoLeak-PoC.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/march0n/PoC-CVE-2022-22965-Spring4Shell](https://github.com/march0n/PoC-CVE-2022-22965-Spring4Shell) :  ![starts](https://img.shields.io/github/stars/march0n/PoC-CVE-2022-22965-Spring4Shell.svg) ![forks](https://img.shields.io/github/forks/march0n/PoC-CVE-2022-22965-Spring4Shell.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/Robblackcatchai/porfolio-Baron-Samedit](https://github.com/Robblackcatchai/porfolio-Baron-Samedit) :  ![starts](https://img.shields.io/github/stars/Robblackcatchai/porfolio-Baron-Samedit.svg) ![forks](https://img.shields.io/github/forks/Robblackcatchai/porfolio-Baron-Samedit.svg)


## CVE-2019-20933
 InfluxDB before 1.7.6 has an authentication bypass vulnerability in the authenticate function in services/httpd/handler.go because a JWT token may have an empty SharedSecret (aka shared secret).

- [https://github.com/Dungsocool/CVE-2019-20933](https://github.com/Dungsocool/CVE-2019-20933) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2019-20933.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2019-20933.svg)


## CVE-2017-11610
 The XML-RPC server in supervisor before 3.0.1, 3.1.x before 3.1.4, 3.2.x before 3.2.4, and 3.3.x before 3.3.3 allows remote authenticated users to execute arbitrary commands via a crafted XML-RPC request, related to nested supervisord namespace lookups.

- [https://github.com/Dungsocool/CVE-2017-11610](https://github.com/Dungsocool/CVE-2017-11610) :  ![starts](https://img.shields.io/github/stars/Dungsocool/CVE-2017-11610.svg) ![forks](https://img.shields.io/github/forks/Dungsocool/CVE-2017-11610.svg)


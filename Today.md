# Update 2025-12-24
## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/rxerium/CVE-2025-68613](https://github.com/rxerium/CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-68613.svg)
- [https://github.com/Ashwesker/Blackash-CVE-2025-68613](https://github.com/Ashwesker/Blackash-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Blackash-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Blackash-CVE-2025-68613.svg)
- [https://github.com/TheStingR/CVE-2025-68613-POC](https://github.com/TheStingR/CVE-2025-68613-POC) :  ![starts](https://img.shields.io/github/stars/TheStingR/CVE-2025-68613-POC.svg) ![forks](https://img.shields.io/github/forks/TheStingR/CVE-2025-68613-POC.svg)
- [https://github.com/wioui/n8n-CVE-2025-68613-exploit](https://github.com/wioui/n8n-CVE-2025-68613-exploit) :  ![starts](https://img.shields.io/github/stars/wioui/n8n-CVE-2025-68613-exploit.svg) ![forks](https://img.shields.io/github/forks/wioui/n8n-CVE-2025-68613-exploit.svg)


## CVE-2025-68461
 Roundcube Webmail before 1.5.12 and 1.6 before 1.6.12 is prone to a Cross-Site-Scripting (XSS) vulnerability via the animate tag in an SVG document.

- [https://github.com/gotr00t0day/CVE-2025-68461](https://github.com/gotr00t0day/CVE-2025-68461) :  ![starts](https://img.shields.io/github/stars/gotr00t0day/CVE-2025-68461.svg) ![forks](https://img.shields.io/github/forks/gotr00t0day/CVE-2025-68461.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-no-lockfile](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-no-lockfile) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-no-lockfile.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-no-lockfile.svg)


## CVE-2025-65857
 An issue was discovered in Xiongmai XM530 IP cameras on firmware V5.00.R02.000807D8.10010.346624.S.ONVIF 21.06. The GetStreamUri exposes RTSP URIs containing hardcoded credentials enabling direct unauthorized video stream access.

- [https://github.com/LuisMirandaAcebedo/CVE-2025-65857](https://github.com/LuisMirandaAcebedo/CVE-2025-65857) :  ![starts](https://img.shields.io/github/stars/LuisMirandaAcebedo/CVE-2025-65857.svg) ![forks](https://img.shields.io/github/forks/LuisMirandaAcebedo/CVE-2025-65857.svg)


## CVE-2025-65856
 Authentication bypass vulnerability in Xiongmai XM530 IP cameras on Firmware V5.00.R02.000807D8.10010.346624.S.ONVIF 21.06 allows unauthenticated remote attackers to access sensitive device information and live video streams. The ONVIF implementation fails to enforce authentication on 31 critical endpoints, enabling direct unauthorized video stream access.

- [https://github.com/LuisMirandaAcebedo/CVE-2025-65856](https://github.com/LuisMirandaAcebedo/CVE-2025-65856) :  ![starts](https://img.shields.io/github/stars/LuisMirandaAcebedo/CVE-2025-65856.svg) ![forks](https://img.shields.io/github/forks/LuisMirandaAcebedo/CVE-2025-65856.svg)


## CVE-2025-65817
 LSC Smart Connect Indoor IP Camera 1.4.13 contains a RCE vulnerability in start_app.sh.

- [https://github.com/Istaarkk/CVE-2025-65817](https://github.com/Istaarkk/CVE-2025-65817) :  ![starts](https://img.shields.io/github/stars/Istaarkk/CVE-2025-65817.svg) ![forks](https://img.shields.io/github/forks/Istaarkk/CVE-2025-65817.svg)


## CVE-2025-65790
 A reflected cross-site scripting (XSS) vulnerability exists in FuguHub 8.1 when serving SVG files through the /fs/ file manager interface. FuguHub does not sanitize or restrict script execution inside SVG content. When a victim opens a crafted SVG containing an inline script element, the browser executes the attacker-controlled JavaScript.

- [https://github.com/hunterxxx/FuguHub-8.1-Reflected-SVG-XSS-CVE-2025-65790](https://github.com/hunterxxx/FuguHub-8.1-Reflected-SVG-XSS-CVE-2025-65790) :  ![starts](https://img.shields.io/github/stars/hunterxxx/FuguHub-8.1-Reflected-SVG-XSS-CVE-2025-65790.svg) ![forks](https://img.shields.io/github/forks/hunterxxx/FuguHub-8.1-Reflected-SVG-XSS-CVE-2025-65790.svg)


## CVE-2025-65270
 Reflected cross-site scripting (XSS) vulnerability in ClinCapture EDC 3.0 and 2.2.3, allowing an unauthenticated remote attacker to execute JavaScript code in the context of the victim's browser.

- [https://github.com/xh4vm/CVE-2025-65270](https://github.com/xh4vm/CVE-2025-65270) :  ![starts](https://img.shields.io/github/stars/xh4vm/CVE-2025-65270.svg) ![forks](https://img.shields.io/github/forks/xh4vm/CVE-2025-65270.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/TrixSec/CVE-2025-55182-Scanner](https://github.com/TrixSec/CVE-2025-55182-Scanner) :  ![starts](https://img.shields.io/github/stars/TrixSec/CVE-2025-55182-Scanner.svg) ![forks](https://img.shields.io/github/forks/TrixSec/CVE-2025-55182-Scanner.svg)


## CVE-2025-14733
 An Out-of-bounds Write vulnerability in WatchGuard Fireware OS may allow a remote unauthenticated attacker to execute arbitrary code. This vulnerability affects both the Mobile User VPN with IKEv2 and the Branch Office VPN using IKEv2 when configured with a dynamic gateway peer.This vulnerability affects Fireware OS 11.10.2 up to and including 11.12.4_Update1, 12.0 up to and including 12.11.5 and 2025.1 up to and including 2025.1.3.

- [https://github.com/b1gchoi/CVE-2025-14733](https://github.com/b1gchoi/CVE-2025-14733) :  ![starts](https://img.shields.io/github/stars/b1gchoi/CVE-2025-14733.svg) ![forks](https://img.shields.io/github/forks/b1gchoi/CVE-2025-14733.svg)


## CVE-2025-9074
This can lead to execution of a wide range of privileged commands to the engine API, including controlling other containers, creating new ones, managing images etc. In some circumstances (e.g. Docker Desktop for Windows with WSL backend) it also allows mounting the host drive with the same privileges as the user running Docker Desktop.

- [https://github.com/zaydbf/CVE-2025-9074-Poc](https://github.com/zaydbf/CVE-2025-9074-Poc) :  ![starts](https://img.shields.io/github/stars/zaydbf/CVE-2025-9074-Poc.svg) ![forks](https://img.shields.io/github/forks/zaydbf/CVE-2025-9074-Poc.svg)


## CVE-2025-6620
 A vulnerability was found in TOTOLINK CA300-PoE 6.2c.884. It has been rated as critical. Affected by this issue is the function setUpgradeUboot of the file upgrade.so. The manipulation of the argument FileName leads to os command injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/0xrakan/coolify-cve-2025-66209-66213](https://github.com/0xrakan/coolify-cve-2025-66209-66213) :  ![starts](https://img.shields.io/github/stars/0xrakan/coolify-cve-2025-66209-66213.svg) ![forks](https://img.shields.io/github/forks/0xrakan/coolify-cve-2025-66209-66213.svg)


## CVE-2025-6544
 A deserialization vulnerability exists in h2oai/h2o-3 versions = 3.46.0.8, allowing attackers to read arbitrary system files and execute arbitrary code. The vulnerability arises from improper handling of JDBC connection parameters, which can be exploited by bypassing regular expression checks and using double URL encoding. This issue impacts all users of the affected versions.

- [https://github.com/zero-day348/CVE-2025-65442-DOM-based-Cross-Site-Scripting-XSS-Vulnerability-in-novel-V3.5.0-CWE-79-](https://github.com/zero-day348/CVE-2025-65442-DOM-based-Cross-Site-Scripting-XSS-Vulnerability-in-novel-V3.5.0-CWE-79-) :  ![starts](https://img.shields.io/github/stars/zero-day348/CVE-2025-65442-DOM-based-Cross-Site-Scripting-XSS-Vulnerability-in-novel-V3.5.0-CWE-79-.svg) ![forks](https://img.shields.io/github/forks/zero-day348/CVE-2025-65442-DOM-based-Cross-Site-Scripting-XSS-Vulnerability-in-novel-V3.5.0-CWE-79-.svg)


## CVE-2025-4917
 A vulnerability classified as critical has been found in PHPGurukul Auto Taxi Stand Management System 1.0. Affected is an unknown function of the file /admin/new-autoortaxi-entry-form.php. The manipulation of the argument drivername leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well.

- [https://github.com/aliyabuz25/cve-2025-49173-macos-mavericks-10.9-local-root-privesc-auth-services](https://github.com/aliyabuz25/cve-2025-49173-macos-mavericks-10.9-local-root-privesc-auth-services) :  ![starts](https://img.shields.io/github/stars/aliyabuz25/cve-2025-49173-macos-mavericks-10.9-local-root-privesc-auth-services.svg) ![forks](https://img.shields.io/github/forks/aliyabuz25/cve-2025-49173-macos-mavericks-10.9-local-root-privesc-auth-services.svg)


## CVE-2024-48990
 Qualys discovered that needrestart, before version 3.8, allows local attackers to execute arbitrary code as root by tricking needrestart into running the Python interpreter with an attacker-controlled PYTHONPATH environment variable.

- [https://github.com/grecosamuel/CVE-2024-48990](https://github.com/grecosamuel/CVE-2024-48990) :  ![starts](https://img.shields.io/github/stars/grecosamuel/CVE-2024-48990.svg) ![forks](https://img.shields.io/github/forks/grecosamuel/CVE-2024-48990.svg)


## CVE-2024-39205
 An issue in pyload-ng v0.5.0b3.dev85 running under python3.11 or below allows attackers to execute arbitrary code via a crafted HTTP request.

- [https://github.com/btar1gan/exploit_CVE-2024-39205](https://github.com/btar1gan/exploit_CVE-2024-39205) :  ![starts](https://img.shields.io/github/stars/btar1gan/exploit_CVE-2024-39205.svg) ![forks](https://img.shields.io/github/forks/btar1gan/exploit_CVE-2024-39205.svg)


## CVE-2024-5752
 A path traversal vulnerability exists in stitionai/devika, specifically in the project creation functionality. In the affected version beacf6edaa205a5a5370525407a6db45137873b3, the project name is not validated, allowing an attacker to create a project with a crafted name that traverses directories. This can lead to arbitrary file overwrite when the application generates code and saves it to the specified project directory, potentially resulting in remote code execution.

- [https://github.com/mrlihd/CVE-2024-57521-SQL-Injection-PoC](https://github.com/mrlihd/CVE-2024-57521-SQL-Injection-PoC) :  ![starts](https://img.shields.io/github/stars/mrlihd/CVE-2024-57521-SQL-Injection-PoC.svg) ![forks](https://img.shields.io/github/forks/mrlihd/CVE-2024-57521-SQL-Injection-PoC.svg)


## CVE-2024-3408
 man-group/dtale version 3.10.0 is vulnerable to an authentication bypass and remote code execution (RCE) due to improper input validation. The vulnerability arises from a hardcoded `SECRET_KEY` in the flask configuration, allowing attackers to forge a session cookie if authentication is enabled. Additionally, the application fails to properly restrict custom filter queries, enabling attackers to execute arbitrary code on the server by bypassing the restriction on the `/update-settings` endpoint, even when `enable_custom_filters` is not enabled. This vulnerability allows attackers to bypass authentication mechanisms and execute remote code on the server.

- [https://github.com/flame-11/CVE-2024-3408-dtale](https://github.com/flame-11/CVE-2024-3408-dtale) :  ![starts](https://img.shields.io/github/stars/flame-11/CVE-2024-3408-dtale.svg) ![forks](https://img.shields.io/github/forks/flame-11/CVE-2024-3408-dtale.svg)


## CVE-2023-25813
 Sequelize is a Node.js ORM tool. In versions prior to 6.19.1 a SQL injection exploit exists related to replacements. Parameters which are passed through replacements are not properly escaped which can lead to arbitrary SQL injection depending on the specific queries in use. The issue has been fixed in Sequelize 6.19.1. Users are advised to upgrade. Users unable to upgrade should not use the `replacements` and the `where` option in the same query.

- [https://github.com/numbbvi/CVE-2023-25813](https://github.com/numbbvi/CVE-2023-25813) :  ![starts](https://img.shields.io/github/stars/numbbvi/CVE-2023-25813.svg) ![forks](https://img.shields.io/github/forks/numbbvi/CVE-2023-25813.svg)


## CVE-2022-29464
 Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 up to 4.0.0, WSO2 Identity Server 5.2.0 up to 5.11.0, WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0 and 5.6.0, WSO2 Identity Server as Key Manager 5.3.0 up to 5.11.0, WSO2 Enterprise Integrator 6.2.0 up to 6.6.0, WSO2 Open Banking AM 1.4.0 up to 2.0.0 and WSO2 Open Banking KM 1.4.0, up to 2.0.0.

- [https://github.com/0xdsm/WSOB](https://github.com/0xdsm/WSOB) :  ![starts](https://img.shields.io/github/stars/0xdsm/WSOB.svg) ![forks](https://img.shields.io/github/forks/0xdsm/WSOB.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/Anon2Fear/CVE-2022-26134](https://github.com/Anon2Fear/CVE-2022-26134) :  ![starts](https://img.shields.io/github/stars/Anon2Fear/CVE-2022-26134.svg) ![forks](https://img.shields.io/github/forks/Anon2Fear/CVE-2022-26134.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/Anon2Fear/CVE-2022-22965](https://github.com/Anon2Fear/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/Anon2Fear/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/Anon2Fear/CVE-2022-22965.svg)


## CVE-2022-1026
 Kyocera multifunction printers running vulnerable versions of Net View unintentionally expose sensitive user information, including usernames and passwords, through an insufficiently protected address book export function.

- [https://github.com/h4po0n/kyocera-cve-2022-1026_SOAP1.1](https://github.com/h4po0n/kyocera-cve-2022-1026_SOAP1.1) :  ![starts](https://img.shields.io/github/stars/h4po0n/kyocera-cve-2022-1026_SOAP1.1.svg) ![forks](https://img.shields.io/github/forks/h4po0n/kyocera-cve-2022-1026_SOAP1.1.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/strikoder/Grafana-Password-Decryptor](https://github.com/strikoder/Grafana-Password-Decryptor) :  ![starts](https://img.shields.io/github/stars/strikoder/Grafana-Password-Decryptor.svg) ![forks](https://img.shields.io/github/forks/strikoder/Grafana-Password-Decryptor.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/JIYUN02/cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/JIYUN02/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/JIYUN02/cve-2021-41773.svg)
- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2021-27514
 EyesOfNetwork 5.3-10 uses an integer of between 8 and 10 digits for the session ID, which might be leveraged for brute-force authentication bypass (such as in CVE-2021-27513 exploitation).

- [https://github.com/ArianeBlow/CVE-2021-27513-CVE-2021-27514](https://github.com/ArianeBlow/CVE-2021-27513-CVE-2021-27514) :  ![starts](https://img.shields.io/github/stars/ArianeBlow/CVE-2021-27513-CVE-2021-27514.svg) ![forks](https://img.shields.io/github/forks/ArianeBlow/CVE-2021-27513-CVE-2021-27514.svg)


## CVE-2021-27248
 This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of D-Link DAP-2020 v1.01rc001 Wi-Fi access points. Authentication is not required to exploit this vulnerability. The specific flaw exists within the processing of CGI scripts. When parsing the getpage parameter, the process does not properly validate the length of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-10932.

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/George-Yanni/DeepRoot](https://github.com/George-Yanni/DeepRoot) :  ![starts](https://img.shields.io/github/stars/George-Yanni/DeepRoot.svg) ![forks](https://img.shields.io/github/forks/George-Yanni/DeepRoot.svg)


## CVE-2020-1472
When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications.

- [https://github.com/JeNilSE/CVE-2020-1472-ZeroLogon-Analysis](https://github.com/JeNilSE/CVE-2020-1472-ZeroLogon-Analysis) :  ![starts](https://img.shields.io/github/stars/JeNilSE/CVE-2020-1472-ZeroLogon-Analysis.svg) ![forks](https://img.shields.io/github/forks/JeNilSE/CVE-2020-1472-ZeroLogon-Analysis.svg)


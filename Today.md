# Update 2025-03-01
## CVE-2025-26264
 GeoVision GV-ASWeb with the version 6.1.2.0 or less, contains a Remote Code Execution (RCE) vulnerability within its Notification Settings feature. An authenticated attacker with "System Settings" privileges in ASWeb can exploit this flaw to execute arbitrary commands on the server, leading to a full system compromise.

- [https://github.com/DRAGOWN/CVE-2025-26264](https://github.com/DRAGOWN/CVE-2025-26264) :  ![starts](https://img.shields.io/github/stars/DRAGOWN/CVE-2025-26264.svg) ![forks](https://img.shields.io/github/forks/DRAGOWN/CVE-2025-26264.svg)


## CVE-2025-21333
 Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege Vulnerability

- [https://github.com/MrAle98/CVE-2025-21333-POC](https://github.com/MrAle98/CVE-2025-21333-POC) :  ![starts](https://img.shields.io/github/stars/MrAle98/CVE-2025-21333-POC.svg) ![forks](https://img.shields.io/github/forks/MrAle98/CVE-2025-21333-POC.svg)


## CVE-2025-1094
 Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to achieve SQL injection in certain usage patterns.  Specifically, SQL injection requires the application to use the function result to construct input to psql, the PostgreSQL interactive terminal.  Similarly, improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source of command line arguments to achieve SQL injection when client_encoding is BIG5 and server_encoding is one of EUC_TW or MULE_INTERNAL.  Versions before PostgreSQL 17.3, 16.7, 15.11, 14.16, and 13.19 are affected.

- [https://github.com/soltanali0/CVE-2025-1094-Exploit](https://github.com/soltanali0/CVE-2025-1094-Exploit) :  ![starts](https://img.shields.io/github/stars/soltanali0/CVE-2025-1094-Exploit.svg) ![forks](https://img.shields.io/github/forks/soltanali0/CVE-2025-1094-Exploit.svg)


## CVE-2025-0364
 BigAntSoft BigAnt Server, up to and including version 5.6.06, is vulnerable to unauthenticated remote code execution via account registration. An unauthenticated remote attacker can create an administrative user through the default exposed SaaS registration mechanism. Once an administrator, the attacker can upload and execute arbitrary PHP code using the "Cloud Storage Addin," leading to unauthenticated code execution.

- [https://github.com/vulncheck-oss/cve-2025-0364](https://github.com/vulncheck-oss/cve-2025-0364) :  ![starts](https://img.shields.io/github/stars/vulncheck-oss/cve-2025-0364.svg) ![forks](https://img.shields.io/github/forks/vulncheck-oss/cve-2025-0364.svg)


## CVE-2024-56264
 Unrestricted Upload of File with Dangerous Type vulnerability in Beee ACF City Selector allows Upload a Web Shell to a Web Server.This issue affects ACF City Selector: from n/a through 1.14.0.

- [https://github.com/dpakmrya/CVE-2024-56264](https://github.com/dpakmrya/CVE-2024-56264) :  ![starts](https://img.shields.io/github/stars/dpakmrya/CVE-2024-56264.svg) ![forks](https://img.shields.io/github/forks/dpakmrya/CVE-2024-56264.svg)


## CVE-2024-36401
Versions 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/wingedmicroph/CVE-2024-36401](https://github.com/wingedmicroph/CVE-2024-36401) :  ![starts](https://img.shields.io/github/stars/wingedmicroph/CVE-2024-36401.svg) ![forks](https://img.shields.io/github/forks/wingedmicroph/CVE-2024-36401.svg)


## CVE-2024-20671
 Microsoft Defender Security Feature Bypass Vulnerability

- [https://github.com/ig-labs/EDR-ALPC-Block-POC](https://github.com/ig-labs/EDR-ALPC-Block-POC) :  ![starts](https://img.shields.io/github/stars/ig-labs/EDR-ALPC-Block-POC.svg) ![forks](https://img.shields.io/github/forks/ig-labs/EDR-ALPC-Block-POC.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/Karmakstylez/CVE-2024-6387](https://github.com/Karmakstylez/CVE-2024-6387) :  ![starts](https://img.shields.io/github/stars/Karmakstylez/CVE-2024-6387.svg) ![forks](https://img.shields.io/github/forks/Karmakstylez/CVE-2024-6387.svg)


## CVE-2024-5909
 A problem with a protection mechanism in the Palo Alto Networks Cortex XDR agent on Windows devices allows a low privileged local Windows user to disable the agent. This issue may be leveraged by malware to disable the Cortex XDR agent and then to perform malicious activity.

- [https://github.com/ig-labs/EDR-ALPC-Block-POC](https://github.com/ig-labs/EDR-ALPC-Block-POC) :  ![starts](https://img.shields.io/github/stars/ig-labs/EDR-ALPC-Block-POC.svg) ![forks](https://img.shields.io/github/forks/ig-labs/EDR-ALPC-Block-POC.svg)


## CVE-2023-26049
 Jetty is a java based web server and servlet engine. Nonstandard cookie parsing in Jetty may allow an attacker to smuggle cookies within other cookies, or otherwise perform unintended behavior by tampering with the cookie parsing mechanism. If Jetty sees a cookie VALUE that starts with `"` (double quote), it will continue to read the cookie string until it sees a closing quote -- even if a semicolon is encountered. So, a cookie header such as: `DISPLAY_LANGUAGE="b; JSESSIONID=1337; c=d"` will be parsed as one cookie, with the name DISPLAY_LANGUAGE and a value of b; JSESSIONID=1337; c=d instead of 3 separate cookies. This has security implications because if, say, JSESSIONID is an HttpOnly cookie, and the DISPLAY_LANGUAGE cookie value is rendered on the page, an attacker can smuggle the JSESSIONID cookie into the DISPLAY_LANGUAGE cookie and thereby exfiltrate it. This is significant when an intermediary is enacting some policy based on cookies, so a smuggled cookie can bypass that policy yet still be seen by the Jetty server or its logging system. This issue has been addressed in versions 9.4.51, 10.0.14, 11.0.14, and 12.0.0.beta0 and users are advised to upgrade. There are no known workarounds for this issue.

- [https://github.com/nidhihcl75/jetty-9.4.31.v20200723_G3_CVE-2023-26049](https://github.com/nidhihcl75/jetty-9.4.31.v20200723_G3_CVE-2023-26049) :  ![starts](https://img.shields.io/github/stars/nidhihcl75/jetty-9.4.31.v20200723_G3_CVE-2023-26049.svg) ![forks](https://img.shields.io/github/forks/nidhihcl75/jetty-9.4.31.v20200723_G3_CVE-2023-26049.svg)


## CVE-2023-20198
 Cisco is providing an update for the ongoing investigation into observed exploitation of the web UI feature in Cisco IOS XE Software. We are updating the list of fixed releases and adding the Software Checker. Our investigation has determined that the actors exploited two previously unknown issues. The attacker first exploited CVE-2023-20198 to gain initial access and issued a privilege 15 command to create a local user and password combination. This allowed the user to log in with normal user access. The attacker then exploited another component of the web UI feature, leveraging the new local user to elevate privilege to root and write the implant to the file system. Cisco has assigned CVE-2023-20273 to this issue. CVE-2023-20198 has been assigned a CVSS Score of 10.0. CVE-2023-20273 has been assigned a CVSS Score of 7.2. Both of these CVEs are being tracked by CSCwh87343.

- [https://github.com/unsightlyabol/cisco-ios-xe-implant-scanner](https://github.com/unsightlyabol/cisco-ios-xe-implant-scanner) :  ![starts](https://img.shields.io/github/stars/unsightlyabol/cisco-ios-xe-implant-scanner.svg) ![forks](https://img.shields.io/github/forks/unsightlyabol/cisco-ios-xe-implant-scanner.svg)


## CVE-2023-4357
 Insufficient validation of untrusted input in XML in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to bypass file access restrictions via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/xcanwin/CVE-2023-4357-Chrome-XXE](https://github.com/xcanwin/CVE-2023-4357-Chrome-XXE) :  ![starts](https://img.shields.io/github/stars/xcanwin/CVE-2023-4357-Chrome-XXE.svg) ![forks](https://img.shields.io/github/forks/xcanwin/CVE-2023-4357-Chrome-XXE.svg)
- [https://github.com/lon5948/CVE-2023-4357-Exploitation](https://github.com/lon5948/CVE-2023-4357-Exploitation) :  ![starts](https://img.shields.io/github/stars/lon5948/CVE-2023-4357-Exploitation.svg) ![forks](https://img.shields.io/github/forks/lon5948/CVE-2023-4357-Exploitation.svg)
- [https://github.com/sunu11/chrome-CVE-2023-4357](https://github.com/sunu11/chrome-CVE-2023-4357) :  ![starts](https://img.shields.io/github/stars/sunu11/chrome-CVE-2023-4357.svg) ![forks](https://img.shields.io/github/forks/sunu11/chrome-CVE-2023-4357.svg)
- [https://github.com/WinnieZy/CVE-2023-4357](https://github.com/WinnieZy/CVE-2023-4357) :  ![starts](https://img.shields.io/github/stars/WinnieZy/CVE-2023-4357.svg) ![forks](https://img.shields.io/github/forks/WinnieZy/CVE-2023-4357.svg)
- [https://github.com/CamillaFranceschini/CVE-2023-4357](https://github.com/CamillaFranceschini/CVE-2023-4357) :  ![starts](https://img.shields.io/github/stars/CamillaFranceschini/CVE-2023-4357.svg) ![forks](https://img.shields.io/github/forks/CamillaFranceschini/CVE-2023-4357.svg)
- [https://github.com/passwa11/CVE-2023-4357-APT-Style-exploitation](https://github.com/passwa11/CVE-2023-4357-APT-Style-exploitation) :  ![starts](https://img.shields.io/github/stars/passwa11/CVE-2023-4357-APT-Style-exploitation.svg) ![forks](https://img.shields.io/github/forks/passwa11/CVE-2023-4357-APT-Style-exploitation.svg)


## CVE-2023-3280
 A problem with a protection mechanism in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local user to disable the agent.

- [https://github.com/ig-labs/EDR-ALPC-Block-POC](https://github.com/ig-labs/EDR-ALPC-Block-POC) :  ![starts](https://img.shields.io/github/stars/ig-labs/EDR-ALPC-Block-POC.svg) ![forks](https://img.shields.io/github/forks/ig-labs/EDR-ALPC-Block-POC.svg)


## CVE-2022-35978
 Minetest is a free open-source voxel game engine with easy modding and game creation. In **single player**, a mod can set a global setting that controls the Lua script loaded to display the main menu. The script is then loaded as soon as the game session is exited. The Lua environment the menu runs in is not sandboxed and can directly interfere with the user's system. There are currently no known workarounds.

- [https://github.com/CanVo/CVE-2022-35978-POC](https://github.com/CanVo/CVE-2022-35978-POC) :  ![starts](https://img.shields.io/github/stars/CanVo/CVE-2022-35978-POC.svg) ![forks](https://img.shields.io/github/forks/CanVo/CVE-2022-35978-POC.svg)


## CVE-2020-27223
 In Eclipse Jetty 9.4.6.v20170531 to 9.4.36.v20210114 (inclusive), 10.0.0, and 11.0.0 when Jetty handles a request containing multiple Accept headers with a large number of “quality” (i.e. q) parameters, the server may enter a denial of service (DoS) state due to high CPU usage processing those quality values, resulting in minutes of CPU time exhausted processing those quality values.

- [https://github.com/Mahesh-970/G3_Jetty.project_CVE-2020-27223](https://github.com/Mahesh-970/G3_Jetty.project_CVE-2020-27223) :  ![starts](https://img.shields.io/github/stars/Mahesh-970/G3_Jetty.project_CVE-2020-27223.svg) ![forks](https://img.shields.io/github/forks/Mahesh-970/G3_Jetty.project_CVE-2020-27223.svg)


## CVE-2015-9238
 secure-compare 3.0.0 and below do not actually compare two strings properly. compare was actually comparing the first argument with itself, meaning the check passed for any two strings of the same length.

- [https://github.com/JamesDarf/wargame-turkey_in_2](https://github.com/JamesDarf/wargame-turkey_in_2) :  ![starts](https://img.shields.io/github/stars/JamesDarf/wargame-turkey_in_2.svg) ![forks](https://img.shields.io/github/forks/JamesDarf/wargame-turkey_in_2.svg)


## CVE-2010-2075
 UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.

- [https://github.com/abhinavcybersec/PenTest-Lab](https://github.com/abhinavcybersec/PenTest-Lab) :  ![starts](https://img.shields.io/github/stars/abhinavcybersec/PenTest-Lab.svg) ![forks](https://img.shields.io/github/forks/abhinavcybersec/PenTest-Lab.svg)


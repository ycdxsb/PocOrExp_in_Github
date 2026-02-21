# Update 2026-02-21
## CVE-2026-27180
 MajorDoMo (aka Major Domestic Module) is vulnerable to unauthenticated remote code execution through supply chain compromise via update URL poisoning. The saverestore module exposes its admin() method through the /objects/?module=saverestore endpoint without authentication because it uses gr('mode') (which reads directly from $_REQUEST) instead of the framework's $this-mode. An attacker can poison the system update URL via the auto_update_settings mode handler, then trigger the force_update handler to initiate the update chain. The autoUpdateSystem() method fetches an Atom feed from the attacker-controlled URL with trivial validation, downloads a tarball via curl with TLS verification disabled (CURLOPT_SSL_VERIFYPEER set to FALSE), extracts it using exec('tar xzvf ...'), and copies all extracted files to the document root using copyTree(). This allows an attacker to deploy arbitrary PHP files, including webshells, to the webroot with two GET requests.

- [https://github.com/mbanyamer/CVE-2026-27180-MajorDoMo-unauthenticated-RCE](https://github.com/mbanyamer/CVE-2026-27180-MajorDoMo-unauthenticated-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-27180-MajorDoMo-unauthenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-27180-MajorDoMo-unauthenticated-RCE.svg)


## CVE-2026-26744
 A user enumeration vulnerability exists in FormaLMS 4.1.18 and below in the password recovery functionality accessible via the /lostpwd endpoint. The application returns different error messages for valid and invalid usernames allowing an unauthenticated attacker to determine which usernames are registered in the system through observable response discrepancy.

- [https://github.com/lorenzobruno7/CVE-2026-26744](https://github.com/lorenzobruno7/CVE-2026-26744) :  ![starts](https://img.shields.io/github/stars/lorenzobruno7/CVE-2026-26744.svg) ![forks](https://img.shields.io/github/forks/lorenzobruno7/CVE-2026-26744.svg)


## CVE-2026-25890
 File Browser provides a file managing interface within a specified directory and it can be used to upload, delete, preview, rename and edit files. Prior to 2.57.1, an authenticated user can bypass the application's "Disallow" file path rules by modifying the request URL. By adding multiple slashes (e.g., //private/) to the path, the authorization check fails to match the rule, while the underlying filesystem resolves the path correctly, granting unauthorized access to restricted files. This vulnerability is fixed in 2.57.1.

- [https://github.com/mbanyamer/CVE-2026-25890-FileBrowser-Access-Control-Bypass](https://github.com/mbanyamer/CVE-2026-25890-FileBrowser-Access-Control-Bypass) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25890-FileBrowser-Access-Control-Bypass.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25890-FileBrowser-Access-Control-Bypass.svg)


## CVE-2026-25242
 Gogs is an open source self-hosted Git service. Versions 0.13.4 and below expose unauthenticated file upload endpoints by default. When the global RequireSigninView setting is disabled (default), any remote user can upload arbitrary files to the server via /releases/attachments and /issues/attachments. This enables the instance to be abused as a public file host, potentially leading to disk exhaustion, content hosting, or delivery of malware. CSRF tokens do not mitigate this attack due to same-origin cookie issuance. This issue has been fixed in version 0.14.1.

- [https://github.com/mindkernel/CVE-2026-25242](https://github.com/mindkernel/CVE-2026-25242) :  ![starts](https://img.shields.io/github/stars/mindkernel/CVE-2026-25242.svg) ![forks](https://img.shields.io/github/forks/mindkernel/CVE-2026-25242.svg)


## CVE-2026-23829
 Mailpit is an email testing tool and API for developers. Prior to version 1.28.3, Mailpit's SMTP server is vulnerable to Header Injection due to an insufficient Regular Expression used to validate `RCPT TO` and `MAIL FROM` addresses. An attacker can inject arbitrary SMTP headers (or corrupt existing ones) by including carriage return characters (`\r`) in the email address. This header injection occurs because the regex intended to filter control characters fails to exclude `\r` and `\n` when used inside a character class. Version 1.28.3 fixes this issue.

- [https://github.com/SimoesCTT/-CVE-2026-23829-CTT-Mailpit-phase-reconstruction-](https://github.com/SimoesCTT/-CVE-2026-23829-CTT-Mailpit-phase-reconstruction-) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/-CVE-2026-23829-CTT-Mailpit-phase-reconstruction-.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/-CVE-2026-23829-CTT-Mailpit-phase-reconstruction-.svg)


## CVE-2026-2441
 Use after free in CSS in Google Chrome prior to 145.0.7632.75 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/theemperorspath/CVE-2026-2441-PoC](https://github.com/theemperorspath/CVE-2026-2441-PoC) :  ![starts](https://img.shields.io/github/stars/theemperorspath/CVE-2026-2441-PoC.svg) ![forks](https://img.shields.io/github/forks/theemperorspath/CVE-2026-2441-PoC.svg)


## CVE-2026-1340
 A code injection in Ivanti Endpoint Manager Mobile allowing attackers to achieve unauthenticated remote code execution.

- [https://github.com/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE](https://github.com/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE) :  ![starts](https://img.shields.io/github/stars/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE.svg) ![forks](https://img.shields.io/github/forks/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE.svg)


## CVE-2026-1281
 A code injection in Ivanti Endpoint Manager Mobile allowing attackers to achieve unauthenticated remote code execution.

- [https://github.com/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE](https://github.com/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE) :  ![starts](https://img.shields.io/github/stars/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE.svg) ![forks](https://img.shields.io/github/forks/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE.svg)


## CVE-2025-71243
 The 'Saisies pour formulaire' (Saisies) plugin for SPIP versions 5.4.0 through 5.11.0 contains a critical Remote Code Execution (RCE) vulnerability. An attacker can exploit this vulnerability to execute arbitrary code on the server. Users should immediately update to version 5.11.1 or later.

- [https://github.com/Chocapikk/CVE-2025-71243](https://github.com/Chocapikk/CVE-2025-71243) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2025-71243.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2025-71243.svg)


## CVE-2025-68937
 Forgejo before 13.0.2 allows attackers to write to unintended files, and possibly obtain server shell access, because of mishandling of out-of-repository symlink destinations for template repositories. This is also fixed for 11 LTS in 11.0.7 and later.

- [https://github.com/ClemaX/Gitea-Forgejo-CVE-2025-68937](https://github.com/ClemaX/Gitea-Forgejo-CVE-2025-68937) :  ![starts](https://img.shields.io/github/stars/ClemaX/Gitea-Forgejo-CVE-2025-68937.svg) ![forks](https://img.shields.io/github/forks/ClemaX/Gitea-Forgejo-CVE-2025-68937.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/imad457/NextJS-RCE-Root-Takeover](https://github.com/imad457/NextJS-RCE-Root-Takeover) :  ![starts](https://img.shields.io/github/stars/imad457/NextJS-RCE-Root-Takeover.svg) ![forks](https://img.shields.io/github/forks/imad457/NextJS-RCE-Root-Takeover.svg)
- [https://github.com/phornnato/CVE-2025-55182](https://github.com/phornnato/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/phornnato/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/phornnato/CVE-2025-55182.svg)


## CVE-2025-65717
 An issue in Visual Studio Code Extensions Live Server v5.7.9 allows attackers to exfiltrate files via user interaction with a crafted HTML page.

- [https://github.com/natsuki-engr/live-server-evil-crawler](https://github.com/natsuki-engr/live-server-evil-crawler) :  ![starts](https://img.shields.io/github/stars/natsuki-engr/live-server-evil-crawler.svg) ![forks](https://img.shields.io/github/forks/natsuki-engr/live-server-evil-crawler.svg)


## CVE-2025-55853
 SoftVision webPDF before 10.0.2 is vulnerable to Server-Side Request Forgery (SSRF). The PDF converter function does not check if internal or external resources are requested in the uploaded files and allows for protocols such as http:// and file:///. This allows an attacker to upload an XML or HTML file in the application, which when rendered to a PDF allows for internal port scanning and Local File Inclusion (LFI).

- [https://github.com/Vivz13/CVE-2025-55853](https://github.com/Vivz13/CVE-2025-55853) :  ![starts](https://img.shields.io/github/stars/Vivz13/CVE-2025-55853.svg) ![forks](https://img.shields.io/github/forks/Vivz13/CVE-2025-55853.svg)


## CVE-2025-54795
 Claude Code is an agentic coding tool. In versions below 1.0.20, an error in command parsing makes it possible to bypass the Claude Code confirmation prompt to trigger execution of an untrusted command. Reliably exploiting this requires the ability to add untrusted content into a Claude Code context window. This is fixed in version 1.0.20.

- [https://github.com/alonisser/ralph](https://github.com/alonisser/ralph) :  ![starts](https://img.shields.io/github/stars/alonisser/ralph.svg) ![forks](https://img.shields.io/github/forks/alonisser/ralph.svg)


## CVE-2025-47812
 In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.

- [https://github.com/estebanzarate/CVE-2025-47812-Wing-FTP-Server-7.4.3-Unauthenticated-RCE-PoC](https://github.com/estebanzarate/CVE-2025-47812-Wing-FTP-Server-7.4.3-Unauthenticated-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/estebanzarate/CVE-2025-47812-Wing-FTP-Server-7.4.3-Unauthenticated-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/estebanzarate/CVE-2025-47812-Wing-FTP-Server-7.4.3-Unauthenticated-RCE-PoC.svg)


## CVE-2025-36911
 In key-based pairing, there is a possible ID due to a logic error in the code. This could lead to remote (proximal/adjacent) information disclosure of user's conversations and location with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Athexhacker/BLUE-SPY](https://github.com/Athexhacker/BLUE-SPY) :  ![starts](https://img.shields.io/github/stars/Athexhacker/BLUE-SPY.svg) ![forks](https://img.shields.io/github/forks/Athexhacker/BLUE-SPY.svg)


## CVE-2025-29969
 Time-of-check time-of-use (toctou) race condition in Windows Fundamentals allows an authorized attacker to execute code over a network.

- [https://github.com/SafeBreach-Labs/EventLogin-CVE-2025-29969](https://github.com/SafeBreach-Labs/EventLogin-CVE-2025-29969) :  ![starts](https://img.shields.io/github/stars/SafeBreach-Labs/EventLogin-CVE-2025-29969.svg) ![forks](https://img.shields.io/github/forks/SafeBreach-Labs/EventLogin-CVE-2025-29969.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Si-Ni/CVE-2025-29927-Proof-of-Concept](https://github.com/Si-Ni/CVE-2025-29927-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/Si-Ni/CVE-2025-29927-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/Si-Ni/CVE-2025-29927-Proof-of-Concept.svg)


## CVE-2025-27152
 axios is a promise based HTTP client for the browser and node.js. The issue occurs when passing absolute URLs rather than protocol-relative URLs to axios. Even if ⁠baseURL is set, axios sends the request to the specified absolute URL, potentially causing SSRF and credential leakage. This issue impacts both server-side and client-side usage of axios. This issue is fixed in 1.8.2.

- [https://github.com/WillFortMadeTech/axiosVulnExample](https://github.com/WillFortMadeTech/axiosVulnExample) :  ![starts](https://img.shields.io/github/stars/WillFortMadeTech/axiosVulnExample.svg) ![forks](https://img.shields.io/github/forks/WillFortMadeTech/axiosVulnExample.svg)


## CVE-2025-4517
Note that none of these vulnerabilities significantly affect the installation of source distributions which are tar archives as source distributions already allow arbitrary code execution during the build process. However when evaluating source distributions it's important to avoid installing source distributions with suspicious links.

- [https://github.com/estebanzarate/CVE-2025-4517-Python-tarfile-filter-data-Bypass-PoC](https://github.com/estebanzarate/CVE-2025-4517-Python-tarfile-filter-data-Bypass-PoC) :  ![starts](https://img.shields.io/github/stars/estebanzarate/CVE-2025-4517-Python-tarfile-filter-data-Bypass-PoC.svg) ![forks](https://img.shields.io/github/forks/estebanzarate/CVE-2025-4517-Python-tarfile-filter-data-Bypass-PoC.svg)


## CVE-2024-22363
 SheetJS Community Edition before 0.20.2 is vulnerable.to Regular Expression Denial of Service (ReDoS).

- [https://github.com/weareu/xlsx](https://github.com/weareu/xlsx) :  ![starts](https://img.shields.io/github/stars/weareu/xlsx.svg) ![forks](https://img.shields.io/github/forks/weareu/xlsx.svg)


## CVE-2024-5243
The specific flaw exists within the handling of DNS names. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-22523.

- [https://github.com/redpack-kr/CVE-2024-5243-pwn2own-toronto-2023](https://github.com/redpack-kr/CVE-2024-5243-pwn2own-toronto-2023) :  ![starts](https://img.shields.io/github/stars/redpack-kr/CVE-2024-5243-pwn2own-toronto-2023.svg) ![forks](https://img.shields.io/github/forks/redpack-kr/CVE-2024-5243-pwn2own-toronto-2023.svg)


## CVE-2023-30533
 SheetJS Community Edition before 0.19.3 allows Prototype Pollution via a crafted file. In other words. 0.19.2 and earlier are affected, whereas 0.19.3 and later are unaffected.

- [https://github.com/weareu/xlsx](https://github.com/weareu/xlsx) :  ![starts](https://img.shields.io/github/stars/weareu/xlsx.svg) ![forks](https://img.shields.io/github/forks/weareu/xlsx.svg)


## CVE-2022-37969
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/uname1able/CVE-2022-37969](https://github.com/uname1able/CVE-2022-37969) :  ![starts](https://img.shields.io/github/stars/uname1able/CVE-2022-37969.svg) ![forks](https://img.shields.io/github/forks/uname1able/CVE-2022-37969.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/soufiane-benchahyd/vulhub-struts2](https://github.com/soufiane-benchahyd/vulhub-struts2) :  ![starts](https://img.shields.io/github/stars/soufiane-benchahyd/vulhub-struts2.svg) ![forks](https://img.shields.io/github/forks/soufiane-benchahyd/vulhub-struts2.svg)


## CVE-2014-9222
 AllegroSoft RomPager 4.34 and earlier, as used in Huawei Home Gateway products and other vendors and products, allows remote attackers to gain privileges via a crafted cookie that triggers memory corruption, aka the "Misfortune Cookie" vulnerability.

- [https://github.com/mercul1ninna/MIPS-CVE-2014-9222](https://github.com/mercul1ninna/MIPS-CVE-2014-9222) :  ![starts](https://img.shields.io/github/stars/mercul1ninna/MIPS-CVE-2014-9222.svg) ![forks](https://img.shields.io/github/forks/mercul1ninna/MIPS-CVE-2014-9222.svg)


## CVE-2011-4862
 Buffer overflow in libtelnet/encrypt.c in telnetd in FreeBSD 7.3 through 9.0, MIT Kerberos Version 5 Applications (aka krb5-appl) 1.0.2 and earlier, Heimdal 1.5.1 and earlier, GNU inetutils, and possibly other products allows remote attackers to execute arbitrary code via a long encryption key, as exploited in the wild in December 2011.

- [https://github.com/appsecrani/CVE-2011-4862](https://github.com/appsecrani/CVE-2011-4862) :  ![starts](https://img.shields.io/github/stars/appsecrani/CVE-2011-4862.svg) ![forks](https://img.shields.io/github/forks/appsecrani/CVE-2011-4862.svg)


# Update 2026-01-11
## CVE-2025-69194
 A security issue was discovered in GNU Wget2 when handling Metalink documents. The application fails to properly validate file paths provided in Metalink file name elements. An attacker can abuse this behavior to write files to unintended locations on the system. This can lead to data loss or potentially allow further compromise of the user’s environment.

- [https://github.com/secdongle/POC_CVE-2025-69194](https://github.com/secdongle/POC_CVE-2025-69194) :  ![starts](https://img.shields.io/github/stars/secdongle/POC_CVE-2025-69194.svg) ![forks](https://img.shields.io/github/forks/secdongle/POC_CVE-2025-69194.svg)


## CVE-2025-67303
 An issue in ComfyUI-Manager prior to version 3.38 allowed remote attackers to potentially manipulate its configuration and critical data. This was due to the application storing its files in an insufficiently protected location that was accessible via the web interface

- [https://github.com/joker-xiaoyan/CVE-2025-67303](https://github.com/joker-xiaoyan/CVE-2025-67303) :  ![starts](https://img.shields.io/github/stars/joker-xiaoyan/CVE-2025-67303.svg) ![forks](https://img.shields.io/github/forks/joker-xiaoyan/CVE-2025-67303.svg)


## CVE-2025-67070
 A vulnerability exists in Intelbras CFTV IP NVD 9032 R Ftd V2.800.00IB00C.0.T, which allows an unauthenticated attacker to bypass the multi-factor authentication (MFA) mechanism during the password recovery process. This results in the ability to change the admin password and gain full access to the administrative panel.

- [https://github.com/teteco/CVE-2025-67070-Intelbras-CFTV-MFA-Bypass](https://github.com/teteco/CVE-2025-67070-Intelbras-CFTV-MFA-Bypass) :  ![starts](https://img.shields.io/github/stars/teteco/CVE-2025-67070-Intelbras-CFTV-MFA-Bypass.svg) ![forks](https://img.shields.io/github/forks/teteco/CVE-2025-67070-Intelbras-CFTV-MFA-Bypass.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/khadafigans/React2Shell](https://github.com/khadafigans/React2Shell) :  ![starts](https://img.shields.io/github/stars/khadafigans/React2Shell.svg) ![forks](https://img.shields.io/github/forks/khadafigans/React2Shell.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg)


## CVE-2025-65964
 n8n is an open source workflow automation platform. Versions 0.123.1 through 1.119.1 do not have adequate protections to prevent RCE through the project's pre-commit hooks. The Add Config operation allows workflows to set arbitrary Git configuration values, including core.hooksPath, which can point to a malicious Git hook that executes arbitrary commands on the n8n host during subsequent Git operations. Exploitation requires the ability to create or modify an n8n workflow using the Git node. This issue is fixed in version 1.119.2. Workarounds include excluding the Git Node (Docs) and avoiding cloning or interacting with untrusted repositories using the Git Node.

- [https://github.com/nn0nkey/repo](https://github.com/nn0nkey/repo) :  ![starts](https://img.shields.io/github/stars/nn0nkey/repo.svg) ![forks](https://img.shields.io/github/forks/nn0nkey/repo.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927](https://github.com/sn1p3rt3s7/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/sn1p3rt3s7/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/sn1p3rt3s7/NextJS_CVE-2025-29927.svg)
- [https://github.com/enochgitgamefied/NextJS-CVE-2025-29927](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/enochgitgamefied/NextJS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/enochgitgamefied/NextJS-CVE-2025-29927.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/TomKingori/xwiki-cve-2025-24893-exploit](https://github.com/TomKingori/xwiki-cve-2025-24893-exploit) :  ![starts](https://img.shields.io/github/stars/TomKingori/xwiki-cve-2025-24893-exploit.svg) ![forks](https://img.shields.io/github/forks/TomKingori/xwiki-cve-2025-24893-exploit.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/AdolfBharath/mongobleed](https://github.com/AdolfBharath/mongobleed) :  ![starts](https://img.shields.io/github/stars/AdolfBharath/mongobleed.svg) ![forks](https://img.shields.io/github/forks/AdolfBharath/mongobleed.svg)


## CVE-2025-14736
 The Frontend Admin by DynamiApps plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 3.28.25. This is due to insufficient validation of user-supplied role values in the 'validate_value', 'pre_update_value', and 'get_fields_display' functions. This makes it possible for unauthenticated attackers to register as administrators and gain complete control of the site, granted they can access a user registration form containing a Role field.

- [https://github.com/hyunchiya/CVE-2025-14736](https://github.com/hyunchiya/CVE-2025-14736) :  ![starts](https://img.shields.io/github/stars/hyunchiya/CVE-2025-14736.svg) ![forks](https://img.shields.io/github/forks/hyunchiya/CVE-2025-14736.svg)


## CVE-2025-14598
 BeeS Software Solutions BET Portal contains an SQL injection vulnerability in the login functionality of affected sites. The vulnerability enables arbitrary SQL commands to be executed on the backend database.

- [https://github.com/Afnaan-Ahmed/CVE-2025-14598](https://github.com/Afnaan-Ahmed/CVE-2025-14598) :  ![starts](https://img.shields.io/github/stars/Afnaan-Ahmed/CVE-2025-14598.svg) ![forks](https://img.shields.io/github/forks/Afnaan-Ahmed/CVE-2025-14598.svg)


## CVE-2025-14221
 A vulnerability was detected in SourceCodester Online Banking System 1.0. This impacts an unknown function of the file /?page=user. The manipulation of the argument First Name/Last Name results in cross site scripting. The attack can be launched remotely. The exploit is now public and may be used.

- [https://github.com/fatmatrabelsi17/CVE-2025-14221](https://github.com/fatmatrabelsi17/CVE-2025-14221) :  ![starts](https://img.shields.io/github/stars/fatmatrabelsi17/CVE-2025-14221.svg) ![forks](https://img.shields.io/github/forks/fatmatrabelsi17/CVE-2025-14221.svg)


## CVE-2025-14124
 The Team  WordPress plugin before 5.0.11 does not properly sanitize and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to a SQL injection.

- [https://github.com/hyunchiya/CVE-2025-14124](https://github.com/hyunchiya/CVE-2025-14124) :  ![starts](https://img.shields.io/github/stars/hyunchiya/CVE-2025-14124.svg) ![forks](https://img.shields.io/github/forks/hyunchiya/CVE-2025-14124.svg)


## CVE-2025-5546
 A vulnerability classified as critical was found in PHPGurukul Daily Expense Tracker System 1.1. This vulnerability affects unknown code of the file /expense-reports-detailed.php. The manipulation of the argument fromdate/todate leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/sibikrish001/CVE-2025-55462](https://github.com/sibikrish001/CVE-2025-55462) :  ![starts](https://img.shields.io/github/stars/sibikrish001/CVE-2025-55462.svg) ![forks](https://img.shields.io/github/forks/sibikrish001/CVE-2025-55462.svg)


## CVE-2025-2025
 The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability check on the give_reports_earnings() function in all versions up to, and including, 3.22.0. This makes it possible for unauthenticated attackers to disclose sensitive information included within earnings reports.

- [https://github.com/SuJing-cy/CVE-2025-2025-52691-SmarterMail-Exp](https://github.com/SuJing-cy/CVE-2025-2025-52691-SmarterMail-Exp) :  ![starts](https://img.shields.io/github/stars/SuJing-cy/CVE-2025-2025-52691-SmarterMail-Exp.svg) ![forks](https://img.shields.io/github/forks/SuJing-cy/CVE-2025-2025-52691-SmarterMail-Exp.svg)


## CVE-2024-41577
 An arbitrary file upload vulnerability in the Ueditor component of productinfoquick v1.0 allows attackers to execute arbitrary code via uploading a crafted PNG file.

- [https://github.com/0dinox/CVE-2024-415770-ssrf-rce](https://github.com/0dinox/CVE-2024-415770-ssrf-rce) :  ![starts](https://img.shields.io/github/stars/0dinox/CVE-2024-415770-ssrf-rce.svg) ![forks](https://img.shields.io/github/forks/0dinox/CVE-2024-415770-ssrf-rce.svg)


## CVE-2024-0044
 In createSessionInternal of PackageInstallerService.java, there is a possible run-as any app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/JackTekno/Chrome-Forensic_CVE-2024-0044](https://github.com/JackTekno/Chrome-Forensic_CVE-2024-0044) :  ![starts](https://img.shields.io/github/stars/JackTekno/Chrome-Forensic_CVE-2024-0044.svg) ![forks](https://img.shields.io/github/forks/JackTekno/Chrome-Forensic_CVE-2024-0044.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/mishra0230/CVE-2023-38831](https://github.com/mishra0230/CVE-2023-38831) :  ![starts](https://img.shields.io/github/stars/mishra0230/CVE-2023-38831.svg) ![forks](https://img.shields.io/github/forks/mishra0230/CVE-2023-38831.svg)
- [https://github.com/ImagineNotChetng/WinRAR-Exploit-Builder](https://github.com/ImagineNotChetng/WinRAR-Exploit-Builder) :  ![starts](https://img.shields.io/github/stars/ImagineNotChetng/WinRAR-Exploit-Builder.svg) ![forks](https://img.shields.io/github/forks/ImagineNotChetng/WinRAR-Exploit-Builder.svg)


## CVE-2023-29689
 PyroCMS 3.9 contains a remote code execution (RCE) vulnerability that can be exploited through a server-side template injection (SSTI) flaw. This vulnerability allows a malicious attacker to send customized commands to the server and execute arbitrary code on the affected system.

- [https://github.com/YSaxon/pyrocms-ssti-fix](https://github.com/YSaxon/pyrocms-ssti-fix) :  ![starts](https://img.shields.io/github/stars/YSaxon/pyrocms-ssti-fix.svg) ![forks](https://img.shields.io/github/forks/YSaxon/pyrocms-ssti-fix.svg)


## CVE-2023-1773
 A vulnerability was found in Rockoa 2.3.2. It has been declared as critical. This vulnerability affects unknown code of the file webmainConfig.php of the component Configuration File Handler. The manipulation leads to code injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-224674 is the identifier assigned to this vulnerability.

- [https://github.com/C1oudfL0w0/CVE-2023-1773-Exploit](https://github.com/C1oudfL0w0/CVE-2023-1773-Exploit) :  ![starts](https://img.shields.io/github/stars/C1oudfL0w0/CVE-2023-1773-Exploit.svg) ![forks](https://img.shields.io/github/forks/C1oudfL0w0/CVE-2023-1773-Exploit.svg)


## CVE-2022-23779
 Zoho ManageEngine Desktop Central before 10.1.2137.8 exposes the installed server name to anyone. The internal hostname can be discovered by reading HTTP redirect responses.

- [https://github.com/Rishi-kaul/CVE-2022-23779](https://github.com/Rishi-kaul/CVE-2022-23779) :  ![starts](https://img.shields.io/github/stars/Rishi-kaul/CVE-2022-23779.svg) ![forks](https://img.shields.io/github/forks/Rishi-kaul/CVE-2022-23779.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/honeyvig/CVE-2022-0847-DirtyPipe-Exploit](https://github.com/honeyvig/CVE-2022-0847-DirtyPipe-Exploit) :  ![starts](https://img.shields.io/github/stars/honeyvig/CVE-2022-0847-DirtyPipe-Exploit.svg) ![forks](https://img.shields.io/github/forks/honeyvig/CVE-2022-0847-DirtyPipe-Exploit.svg)


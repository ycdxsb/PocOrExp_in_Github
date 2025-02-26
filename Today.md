# Update 2025-02-26
## CVE-2025-25460
 A stored Cross-Site Scripting (XSS) vulnerability was identified in FlatPress 1.3.1 within the "Add Entry" feature. This vulnerability allows authenticated attackers to inject malicious JavaScript payloads into blog posts, which are executed when other users view the posts. The issue arises due to improper input sanitization of the "TextArea" field in the blog entry submission form.

- [https://github.com/RoNiXxCybSeC0101/CVE-2025-25460](https://github.com/RoNiXxCybSeC0101/CVE-2025-25460) :  ![starts](https://img.shields.io/github/stars/RoNiXxCybSeC0101/CVE-2025-25460.svg) ![forks](https://img.shields.io/github/forks/RoNiXxCybSeC0101/CVE-2025-25460.svg)


## CVE-2025-25279
 Mattermost versions 10.4.x = 10.4.1, 9.11.x = 9.11.7, 10.3.x = 10.3.2, 10.2.x = 10.2.2 fail to properly validate board blocks when importing boards which allows an attacker could read any arbitrary file on the system via importing and exporting a specially crafted import archive in Boards.

- [https://github.com/numanturle/CVE-2025-25279](https://github.com/numanturle/CVE-2025-25279) :  ![starts](https://img.shields.io/github/stars/numanturle/CVE-2025-25279.svg) ![forks](https://img.shields.io/github/forks/numanturle/CVE-2025-25279.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/sug4r-wr41th/CVE-2025-24893](https://github.com/sug4r-wr41th/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/sug4r-wr41th/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/sug4r-wr41th/CVE-2025-24893.svg)


## CVE-2025-22785
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in ComMotion Course Booking System allows SQL Injection.This issue affects Course Booking System: from n/a through 6.0.5.

- [https://github.com/RandomRobbieBF/CVE-2025-22785](https://github.com/RandomRobbieBF/CVE-2025-22785) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-22785.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-22785.svg)


## CVE-2024-56897
 Improper access control in the HTTP server in YI Car Dashcam v3.88 allows unrestricted file downloads, uploads, and API commands. API commands can also be made to make unauthorized modifications to the device settings, such as disabling recording, disabling sounds, factory reset.

- [https://github.com/geo-chen/YI-Smart-Dashcam](https://github.com/geo-chen/YI-Smart-Dashcam) :  ![starts](https://img.shields.io/github/stars/geo-chen/YI-Smart-Dashcam.svg) ![forks](https://img.shields.io/github/forks/geo-chen/YI-Smart-Dashcam.svg)


## CVE-2024-56264
 Unrestricted Upload of File with Dangerous Type vulnerability in Beee ACF City Selector allows Upload a Web Shell to a Web Server.This issue affects ACF City Selector: from n/a through 1.14.0.

- [https://github.com/Nxploited/CVE-2024-56264](https://github.com/Nxploited/CVE-2024-56264) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-56264.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-56264.svg)


## CVE-2024-54951
 Monica 4.1.2 is vulnerable to Cross Site Scripting (XSS). A malicious user can create a malformed contact and use that contact in the "HOW YOU MET" customization options to trigger the XSS.

- [https://github.com/Allevon412/CVE-2024-54951](https://github.com/Allevon412/CVE-2024-54951) :  ![starts](https://img.shields.io/github/stars/Allevon412/CVE-2024-54951.svg) ![forks](https://img.shields.io/github/forks/Allevon412/CVE-2024-54951.svg)


## CVE-2024-54820
 XOne Web Monitor v02.10.2024.530 framework 1.0.4.9 was discovered to contain a SQL injection vulnerability in the login page. This vulnerability allows attackers to extract all usernames and passwords via a crafted input.

- [https://github.com/jcarabantes/CVE-2024-54820](https://github.com/jcarabantes/CVE-2024-54820) :  ![starts](https://img.shields.io/github/stars/jcarabantes/CVE-2024-54820.svg) ![forks](https://img.shields.io/github/forks/jcarabantes/CVE-2024-54820.svg)


## CVE-2024-54239
 Missing Authorization vulnerability in dugudlabs Eyewear prescription form allows Privilege Escalation.This issue affects Eyewear prescription form: from n/a through 4.0.18.

- [https://github.com/RandomRobbieBF/CVE-2024-54239](https://github.com/RandomRobbieBF/CVE-2024-54239) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-54239.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-54239.svg)


## CVE-2024-53677
You can find more details in  https://cwiki.apache.org/confluence/display/WW/S2-067

- [https://github.com/shishirghimir/CVE-2024-53677-Exploit](https://github.com/shishirghimir/CVE-2024-53677-Exploit) :  ![starts](https://img.shields.io/github/stars/shishirghimir/CVE-2024-53677-Exploit.svg) ![forks](https://img.shields.io/github/forks/shishirghimir/CVE-2024-53677-Exploit.svg)


## CVE-2024-11848
 The NitroPack plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'nitropack_dismiss_notice_forever' AJAX action in all versions up to, and including, 1.17.0. This makes it possible for authenticated attackers, with subscriber-level access and above, to update arbitrary options to a fixed value of '1' which can activate certain options (e.g., enable user registration) or modify certain options in a way that leads to a denial of service condition.

- [https://github.com/RandomRobbieBF/CVE-2024-11848](https://github.com/RandomRobbieBF/CVE-2024-11848) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-11848.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-11848.svg)


## CVE-2024-9698
 The Crafthemes Demo Import plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'process_uploaded_files' function in all versions up to, and including, 3.3. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Nxploited/CVE-2024-9698](https://github.com/Nxploited/CVE-2024-9698) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-9698.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-9698.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/internalwhel/rapidresetclient](https://github.com/internalwhel/rapidresetclient) :  ![starts](https://img.shields.io/github/stars/internalwhel/rapidresetclient.svg) ![forks](https://img.shields.io/github/forks/internalwhel/rapidresetclient.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/Ben1B3astt/CVE-2023-38831_ReverseShell_Winrar](https://github.com/Ben1B3astt/CVE-2023-38831_ReverseShell_Winrar) :  ![starts](https://img.shields.io/github/stars/Ben1B3astt/CVE-2023-38831_ReverseShell_Winrar.svg) ![forks](https://img.shields.io/github/forks/Ben1B3astt/CVE-2023-38831_ReverseShell_Winrar.svg)


## CVE-2023-22515
Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue. 

- [https://github.com/vivigotnotime/CVE-2023-22515-Exploit-Script](https://github.com/vivigotnotime/CVE-2023-22515-Exploit-Script) :  ![starts](https://img.shields.io/github/stars/vivigotnotime/CVE-2023-22515-Exploit-Script.svg) ![forks](https://img.shields.io/github/forks/vivigotnotime/CVE-2023-22515-Exploit-Script.svg)


## CVE-2023-21839
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and  14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/outgoingcon/CVE-2023-21839](https://github.com/outgoingcon/CVE-2023-21839) :  ![starts](https://img.shields.io/github/stars/outgoingcon/CVE-2023-21839.svg) ![forks](https://img.shields.io/github/forks/outgoingcon/CVE-2023-21839.svg)


## CVE-2023-4903
 Inappropriate implementation in Custom Mobile Tabs in Google Chrome on Android prior to 117.0.5938.62 allowed a remote attacker to spoof security UI via a crafted HTML page. (Chromium security severity: Medium)

- [https://github.com/Yoshik0xF6/CVE-2023-49031](https://github.com/Yoshik0xF6/CVE-2023-49031) :  ![starts](https://img.shields.io/github/stars/Yoshik0xF6/CVE-2023-49031.svg) ![forks](https://img.shields.io/github/forks/Yoshik0xF6/CVE-2023-49031.svg)


## CVE-2023-1545
 SQL Injection in GitHub repository nilsteampassnet/teampass prior to 3.0.0.23.

- [https://github.com/zer0-dave/CVE-2023-1545-POC](https://github.com/zer0-dave/CVE-2023-1545-POC) :  ![starts](https://img.shields.io/github/stars/zer0-dave/CVE-2023-1545-POC.svg) ![forks](https://img.shields.io/github/forks/zer0-dave/CVE-2023-1545-POC.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is "${prefix:name}", where "prefix" is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - "script" - execute expressions using the JVM script execution engine (javax.script) - "dns" - resolve dns records - "url" - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/808ale/CVE-2022-42889-Text4Shell-POC](https://github.com/808ale/CVE-2022-42889-Text4Shell-POC) :  ![starts](https://img.shields.io/github/stars/808ale/CVE-2022-42889-Text4Shell-POC.svg) ![forks](https://img.shields.io/github/forks/808ale/CVE-2022-42889-Text4Shell-POC.svg)


## CVE-2021-27365
 An issue was discovered in the Linux kernel through 5.11.3. Certain iSCSI data structures do not have appropriate length constraints or checks, and can exceed the PAGE_SIZE value. An unprivileged user can send a Netlink message that is associated with iSCSI, and has a length up to the maximum length of a Netlink message.

- [https://github.com/Iweisc/Kernel-CVE-2021-27365-hotfix](https://github.com/Iweisc/Kernel-CVE-2021-27365-hotfix) :  ![starts](https://img.shields.io/github/stars/Iweisc/Kernel-CVE-2021-27365-hotfix.svg) ![forks](https://img.shields.io/github/forks/Iweisc/Kernel-CVE-2021-27365-hotfix.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/erickrr-bd/Apache-Tomcat-Ghostcat-Vulnerability](https://github.com/erickrr-bd/Apache-Tomcat-Ghostcat-Vulnerability) :  ![starts](https://img.shields.io/github/stars/erickrr-bd/Apache-Tomcat-Ghostcat-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/erickrr-bd/Apache-Tomcat-Ghostcat-Vulnerability.svg)


## CVE-2019-13292
 A SQL Injection issue was discovered in webERP 4.15. Payments.php accepts payment data in base64 format. After this is decoded, it is deserialized. Then, this deserialized data goes directly into a SQL query, with no sanitizing checks.

- [https://github.com/808ale/CVE-2019-13292-WebERP_4.15](https://github.com/808ale/CVE-2019-13292-WebERP_4.15) :  ![starts](https://img.shields.io/github/stars/808ale/CVE-2019-13292-WebERP_4.15.svg) ![forks](https://img.shields.io/github/forks/808ale/CVE-2019-13292-WebERP_4.15.svg)


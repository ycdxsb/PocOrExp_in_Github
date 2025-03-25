# Update 2025-03-25
## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Prior to 14.2.25 and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 14.2.25 and 15.2.3.

- [https://github.com/6mile/nextjs-CVE-2025-29927](https://github.com/6mile/nextjs-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/6mile/nextjs-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/6mile/nextjs-CVE-2025-29927.svg)
- [https://github.com/azu/nextjs-cve-2025-29927-poc](https://github.com/azu/nextjs-cve-2025-29927-poc) :  ![starts](https://img.shields.io/github/stars/azu/nextjs-cve-2025-29927-poc.svg) ![forks](https://img.shields.io/github/forks/azu/nextjs-cve-2025-29927-poc.svg)
- [https://github.com/Neoxs/nextjs-middleware-vuln-poc](https://github.com/Neoxs/nextjs-middleware-vuln-poc) :  ![starts](https://img.shields.io/github/stars/Neoxs/nextjs-middleware-vuln-poc.svg) ![forks](https://img.shields.io/github/forks/Neoxs/nextjs-middleware-vuln-poc.svg)
- [https://github.com/aydinnyunus/CVE-2025-29927](https://github.com/aydinnyunus/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/aydinnyunus/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/aydinnyunus/CVE-2025-29927.svg)
- [https://github.com/MuhammadWaseem29/CVE-2025-29927-POC](https://github.com/MuhammadWaseem29/CVE-2025-29927-POC) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/CVE-2025-29927-POC.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/CVE-2025-29927-POC.svg)
- [https://github.com/t3tra-dev/cve-2025-29927-demo](https://github.com/t3tra-dev/cve-2025-29927-demo) :  ![starts](https://img.shields.io/github/stars/t3tra-dev/cve-2025-29927-demo.svg) ![forks](https://img.shields.io/github/forks/t3tra-dev/cve-2025-29927-demo.svg)
- [https://github.com/websecnl/CVE-2025-29927-PoC-Exploit](https://github.com/websecnl/CVE-2025-29927-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/websecnl/CVE-2025-29927-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/websecnl/CVE-2025-29927-PoC-Exploit.svg)
- [https://github.com/ticofookfook/poc-nextjs-CVE-2025-29927](https://github.com/ticofookfook/poc-nextjs-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/ticofookfook/poc-nextjs-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/ticofookfook/poc-nextjs-CVE-2025-29927.svg)
- [https://github.com/lirantal/vulnerable-nextjs-14-CVE-2025-29927](https://github.com/lirantal/vulnerable-nextjs-14-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/lirantal/vulnerable-nextjs-14-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/lirantal/vulnerable-nextjs-14-CVE-2025-29927.svg)


## CVE-2025-27363
 An out of bounds write exists in FreeType versions 2.13.0 and below (newer versions of FreeType are not vulnerable) when attempting to parse font subglyph structures related to TrueType GX and variable font files. The vulnerable code assigns a signed short value to an unsigned long and then adds a static value causing it to wrap around and allocate too small of a heap buffer. The code then writes up to 6 signed long integers out of bounds relative to this buffer. This may result in arbitrary code execution. This vulnerability may have been exploited in the wild.

- [https://github.com/zhuowei/CVE-2025-27363-proof-of-concept](https://github.com/zhuowei/CVE-2025-27363-proof-of-concept) :  ![starts](https://img.shields.io/github/stars/zhuowei/CVE-2025-27363-proof-of-concept.svg) ![forks](https://img.shields.io/github/forks/zhuowei/CVE-2025-27363-proof-of-concept.svg)


## CVE-2025-2641
 A vulnerability, which was classified as critical, has been found in PHPGurukul Art Gallery Management System 1.0. Affected by this issue is some unknown functionality of the file /admin/edit-artist-detail.php?editid=1. The manipulation of the argument Name leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/uthrasri/CVE-2025-26417](https://github.com/uthrasri/CVE-2025-26417) :  ![starts](https://img.shields.io/github/stars/uthrasri/CVE-2025-26417.svg) ![forks](https://img.shields.io/github/forks/uthrasri/CVE-2025-26417.svg)


## CVE-2024-54525
 A logic issue was addressed with improved file handling. This issue is fixed in visionOS 2.2, watchOS 11.2, tvOS 18.2, macOS Sequoia 15.2, iOS 18.2 and iPadOS 18.2. Restoring a maliciously crafted backup file may lead to modification of protected system files.

- [https://github.com/skadz108/MyBallsItch](https://github.com/skadz108/MyBallsItch) :  ![starts](https://img.shields.io/github/stars/skadz108/MyBallsItch.svg) ![forks](https://img.shields.io/github/forks/skadz108/MyBallsItch.svg)


## CVE-2024-51793
 Unrestricted Upload of File with Dangerous Type vulnerability in Webful Creations Computer Repair Shop allows Upload a Web Shell to a Web Server.This issue affects Computer Repair Shop: from n/a through 3.8115.

- [https://github.com/Nxploited/CVE-2024-51793](https://github.com/Nxploited/CVE-2024-51793) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-51793.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-51793.svg)


## CVE-2024-46981
 Redis is an open source, in-memory database that persists on disk. An authenticated user may use a specially crafted Lua script to manipulate the garbage collector and potentially lead to remote code execution. The problem is fixed in 7.4.2, 7.2.7, and 6.2.17. An additional workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/publicqi/CVE-2024-46981](https://github.com/publicqi/CVE-2024-46981) :  ![starts](https://img.shields.io/github/stars/publicqi/CVE-2024-46981.svg) ![forks](https://img.shields.io/github/forks/publicqi/CVE-2024-46981.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/slytechroot/CVE-2024-23897](https://github.com/slytechroot/CVE-2024-23897) :  ![starts](https://img.shields.io/github/stars/slytechroot/CVE-2024-23897.svg) ![forks](https://img.shields.io/github/forks/slytechroot/CVE-2024-23897.svg)


## CVE-2024-10578
 The Pubnews theme for WordPress is vulnerable to unauthorized arbitrary plugin installation due to a missing capability check on the pubnews_importer_plugin_action_for_notice() function in all versions up to, and including, 1.0.7. This makes it possible for authenticated attackers, with Subscriber-level access and above, to install arbitrary plugins that can be leveraged to exploit other vulnerabilities.

- [https://github.com/Nxploited/CVE-2024-10578](https://github.com/Nxploited/CVE-2024-10578) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2024-10578.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2024-10578.svg)


## CVE-2024-9474
Cloud NGFW and Prisma Access are not impacted by this vulnerability.

- [https://github.com/stupidgossi/CVE-2024-9474](https://github.com/stupidgossi/CVE-2024-9474) :  ![starts](https://img.shields.io/github/stars/stupidgossi/CVE-2024-9474.svg) ![forks](https://img.shields.io/github/forks/stupidgossi/CVE-2024-9474.svg)


## CVE-2024-5535
become available.

- [https://github.com/websecnl/CVE-2024-5535](https://github.com/websecnl/CVE-2024-5535) :  ![starts](https://img.shields.io/github/stars/websecnl/CVE-2024-5535.svg) ![forks](https://img.shields.io/github/forks/websecnl/CVE-2024-5535.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/creamylegum/CVE-2024-4577-PHP-RCE](https://github.com/creamylegum/CVE-2024-4577-PHP-RCE) :  ![starts](https://img.shields.io/github/stars/creamylegum/CVE-2024-4577-PHP-RCE.svg) ![forks](https://img.shields.io/github/forks/creamylegum/CVE-2024-4577-PHP-RCE.svg)


## CVE-2023-48292
 The XWiki Admin Tools Application provides tools to help the administration of XWiki. Starting in version 4.4 and prior to version 4.5.1, a cross site request forgery vulnerability in the admin tool for executing shell commands on the server allows an attacker to execute arbitrary shell commands by tricking an admin into loading the URL with the shell command. A very simple possibility for an attack are comments. When the attacker can leave a comment on any page in the wiki it is sufficient to include an image with an URL like  `/xwiki/bin/view/Admin/RunShellCommand?command=touch%20/tmp/attacked` in the comment. When an admin views the comment, the file `/tmp/attacked` will be created on the server. The output of the command is also vulnerable to XWiki syntax injection which offers a simple way to execute Groovy in the context of the XWiki installation and thus an even easier way to compromise the integrity and confidentiality of the whole XWiki installation. This has been patched by adding a form token check in version 4.5.1 of the admin tools. Some workarounds are available. The patch can be applied manually to the affected wiki pages. Alternatively, the document `Admin.RunShellCommand` can also be deleted if the possibility to run shell commands isn't needed.

- [https://github.com/Mehran-Seifalinia/CVE-2023-48292](https://github.com/Mehran-Seifalinia/CVE-2023-48292) :  ![starts](https://img.shields.io/github/stars/Mehran-Seifalinia/CVE-2023-48292.svg) ![forks](https://img.shields.io/github/forks/Mehran-Seifalinia/CVE-2023-48292.svg)


## CVE-2023-42793
 In JetBrains TeamCity before 2023.05.4 authentication bypass leading to RCE on TeamCity Server was possible

- [https://github.com/B4l3rI0n/CVE-2023-42793](https://github.com/B4l3rI0n/CVE-2023-42793) :  ![starts](https://img.shields.io/github/stars/B4l3rI0n/CVE-2023-42793.svg) ![forks](https://img.shields.io/github/forks/B4l3rI0n/CVE-2023-42793.svg)


## CVE-2022-36804
 Multiple API endpoints in Atlassian Bitbucket Server and Data Center 7.0.0 before version 7.6.17, from version 7.7.0 before version 7.17.10, from version 7.18.0 before version 7.21.4, from version 8.0.0 before version 8.0.3, from version 8.1.0 before version 8.1.3, and from version 8.2.0 before version 8.2.2, and from version 8.3.0 before 8.3.1 allows remote attackers with read permissions to a public or private Bitbucket repository to execute arbitrary code by sending a malicious HTTP request. This vulnerability was reported via our Bug Bounty Program by TheGrandPew.

- [https://github.com/ui-bootstrap/CVE-2022-36804](https://github.com/ui-bootstrap/CVE-2022-36804) :  ![starts](https://img.shields.io/github/stars/ui-bootstrap/CVE-2022-36804.svg) ![forks](https://img.shields.io/github/forks/ui-bootstrap/CVE-2022-36804.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/Plunder283/CVE-2021-41773](https://github.com/Plunder283/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Plunder283/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Plunder283/CVE-2021-41773.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/saccles/CVE_2018_16763_Proof_of_Concept](https://github.com/saccles/CVE_2018_16763_Proof_of_Concept) :  ![starts](https://img.shields.io/github/stars/saccles/CVE_2018_16763_Proof_of_Concept.svg) ![forks](https://img.shields.io/github/forks/saccles/CVE_2018_16763_Proof_of_Concept.svg)


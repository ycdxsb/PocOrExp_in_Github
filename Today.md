# Update 2025-06-17
## CVE-2025-49619
 Skyvern through 0.1.85 has a Jinja runtime leak in sdk/workflow/models/block.py.

- [https://github.com/cristibtz/CVE-2025-49619](https://github.com/cristibtz/CVE-2025-49619) :  ![starts](https://img.shields.io/github/stars/cristibtz/CVE-2025-49619.svg) ![forks](https://img.shields.io/github/forks/cristibtz/CVE-2025-49619.svg)


## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/Yuri08loveElaina/CVE-2025-49113](https://github.com/Yuri08loveElaina/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-49113.svg)


## CVE-2025-33073
 Improper access control in Windows SMB allows an authorized attacker to elevate privileges over a network.

- [https://github.com/joaozixx/CVE-2025-33073](https://github.com/joaozixx/CVE-2025-33073) :  ![starts](https://img.shields.io/github/stars/joaozixx/CVE-2025-33073.svg) ![forks](https://img.shields.io/github/forks/joaozixx/CVE-2025-33073.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/Yuri08loveElaina/CVE_2025_32433_exploit](https://github.com/Yuri08loveElaina/CVE_2025_32433_exploit) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2025_32433_exploit.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2025_32433_exploit.svg)
- [https://github.com/Yuri08loveElaina/CVE-2025-32433-Erlang-OTP-SSH-Pre-Auth-RCE-exploit](https://github.com/Yuri08loveElaina/CVE-2025-32433-Erlang-OTP-SSH-Pre-Auth-RCE-exploit) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE-2025-32433-Erlang-OTP-SSH-Pre-Auth-RCE-exploit.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE-2025-32433-Erlang-OTP-SSH-Pre-Auth-RCE-exploit.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/ibrahmsql/CVE-2025-31161](https://github.com/ibrahmsql/CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2025-31161.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/KamalideenAK/poc-cve-2025-29927](https://github.com/KamalideenAK/poc-cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/KamalideenAK/poc-cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/KamalideenAK/poc-cve-2025-29927.svg)


## CVE-2025-6083
 In ExtremeCloud Universal ZTNA, a syntax error in the 'searchKeyword' condition caused queries to bypass the owner_id filter. This issue may allow users to search data across the entire table instead of being restricted to their specific owner_id.

- [https://github.com/Yuri08loveElaina/CVE_2025_6083](https://github.com/Yuri08loveElaina/CVE_2025_6083) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2025_6083.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2025_6083.svg)


## CVE-2025-6070
 The Restrict File Access plugin for WordPress is vulnerable to Directory Traversal in all versions up to, and including, 1.1.2 via the output() function. This makes it possible for authenticated attackers, with Subscriber-level access and above, to read the contents of arbitrary files on the server, which can contain sensitive information.

- [https://github.com/Yuri08loveElaina/CVE_2025_6070](https://github.com/Yuri08loveElaina/CVE_2025_6070) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2025_6070.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2025_6070.svg)


## CVE-2025-6065
 The Image Resizer On The Fly plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation in the 'delete' task in all versions up to, and including, 1.1. This makes it possible for unauthenticated attackers to delete arbitrary files on the server, which can easily lead to remote code execution when the right file is deleted (such as wp-config.php).

- [https://github.com/Yuri08loveElaina/CVE_2025_6065](https://github.com/Yuri08loveElaina/CVE_2025_6065) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/CVE_2025_6065.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/CVE_2025_6065.svg)


## CVE-2025-2783
 Incorrect handle provided in unspecified circumstances in Mojo in Google Chrome on Windows prior to 134.0.6998.177 allowed a remote attacker to perform a sandbox escape via a malicious file. (Chromium security severity: High)

- [https://github.com/byteReaper77/CVE-2025-2783-SandboxEscape](https://github.com/byteReaper77/CVE-2025-2783-SandboxEscape) :  ![starts](https://img.shields.io/github/stars/byteReaper77/CVE-2025-2783-SandboxEscape.svg) ![forks](https://img.shields.io/github/forks/byteReaper77/CVE-2025-2783-SandboxEscape.svg)


## CVE-2024-28995
SolarWinds Serv-U was susceptible to a directory transversal vulnerability that would allow access to read sensitive files on the host machine.    

- [https://github.com/ibrahmsql/CVE-2024-28995](https://github.com/ibrahmsql/CVE-2024-28995) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2024-28995.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2024-28995.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/ibrahmsql/CVE-2024-4577](https://github.com/ibrahmsql/CVE-2024-4577) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2024-4577.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2024-4577.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/gensecaihq/CVE-2024-3094-Vulnerability-Checker-Fixer](https://github.com/gensecaihq/CVE-2024-3094-Vulnerability-Checker-Fixer) :  ![starts](https://img.shields.io/github/stars/gensecaihq/CVE-2024-3094-Vulnerability-Checker-Fixer.svg) ![forks](https://img.shields.io/github/forks/gensecaihq/CVE-2024-3094-Vulnerability-Checker-Fixer.svg)


## CVE-2024-0204
 Authentication bypass in Fortra's GoAnywhere MFT prior to 7.4.1 allows an unauthorized user to create an admin user via the administration portal.

- [https://github.com/ibrahmsql/CVE-2024-0204](https://github.com/ibrahmsql/CVE-2024-0204) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2024-0204.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2024-0204.svg)


## CVE-2023-1698
 In multiple products of WAGO a vulnerability allows an unauthenticated, remote attacker to create new users and change the device configuration which can result in unintended behaviour, Denial of Service and full system compromise.

- [https://github.com/ibrahmsql/CVE-2023-1698](https://github.com/ibrahmsql/CVE-2023-1698) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2023-1698.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2023-1698.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/RizqiSec/CVE-2021-41773](https://github.com/RizqiSec/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/RizqiSec/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/RizqiSec/CVE-2021-41773.svg)


## CVE-2021-40724
 Acrobat Reader for Android versions 21.8.0 (and earlier) are affected by a Path traversal vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/tinopreter/DocViewerExploitApp](https://github.com/tinopreter/DocViewerExploitApp) :  ![starts](https://img.shields.io/github/stars/tinopreter/DocViewerExploitApp.svg) ![forks](https://img.shields.io/github/forks/tinopreter/DocViewerExploitApp.svg)


## CVE-2021-36934
pAfter installing this security update, you emmust/em manually delete all shadow copies of system files, including the SAM database, to fully mitigate this vulnerabilty. strongSimply installing this security update will not fully mitigate this vulnerability./strong See a href="https://support.microsoft.com/topic/1ceaa637-aaa3-4b58-a48b-baf72a2fa9e7"KB5005357- Delete Volume Shadow Copies/a./p

- [https://github.com/Blu3L33t/Nightmare](https://github.com/Blu3L33t/Nightmare) :  ![starts](https://img.shields.io/github/stars/Blu3L33t/Nightmare.svg) ![forks](https://img.shields.io/github/forks/Blu3L33t/Nightmare.svg)


## CVE-2019-14811
 A flaw was found in, ghostscript versions prior to 9.50, in the .pdf_hook_DSC_Creator procedure where it did not properly secure its privileged calls, enabling scripts to bypass `-dSAFER` restrictions. A specially crafted PostScript file could disable security protection and then have access to the file system, or execute arbitrary commands.

- [https://github.com/matejsmycka/CVE-2019-14811-in-pdf-exploit](https://github.com/matejsmycka/CVE-2019-14811-in-pdf-exploit) :  ![starts](https://img.shields.io/github/stars/matejsmycka/CVE-2019-14811-in-pdf-exploit.svg) ![forks](https://img.shields.io/github/forks/matejsmycka/CVE-2019-14811-in-pdf-exploit.svg)


## CVE-2016-3088
 The Fileserver web application in Apache ActiveMQ 5.x before 5.14.0 allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request.

- [https://github.com/HeArtE4t3r/CVE-2016-3088](https://github.com/HeArtE4t3r/CVE-2016-3088) :  ![starts](https://img.shields.io/github/stars/HeArtE4t3r/CVE-2016-3088.svg) ![forks](https://img.shields.io/github/forks/HeArtE4t3r/CVE-2016-3088.svg)


## CVE-2015-9238
 secure-compare 3.0.0 and below do not actually compare two strings properly. compare was actually comparing the first argument with itself, meaning the check passed for any two strings of the same length.

- [https://github.com/m0d0ri205/wargame-turkey_in_2](https://github.com/m0d0ri205/wargame-turkey_in_2) :  ![starts](https://img.shields.io/github/stars/m0d0ri205/wargame-turkey_in_2.svg) ![forks](https://img.shields.io/github/forks/m0d0ri205/wargame-turkey_in_2.svg)


## CVE-2007-4559
 Directory traversal vulnerability in the (1) extract and (2) extractall functions in the tarfile module in Python allows user-assisted remote attackers to overwrite arbitrary files via a .. (dot dot) sequence in filenames in a TAR archive, a related issue to CVE-2001-1267.

- [https://github.com/m0d0ri205/wargame-tarpioka](https://github.com/m0d0ri205/wargame-tarpioka) :  ![starts](https://img.shields.io/github/stars/m0d0ri205/wargame-tarpioka.svg) ![forks](https://img.shields.io/github/forks/m0d0ri205/wargame-tarpioka.svg)


# Update 2025-11-13
## CVE-2025-58179
 Astro is a web framework for content-driven websites. Versions 11.0.3 through 12.6.5 are vulnerable to SSRF when using Astro's Cloudflare adapter. When configured with output: 'server' while using the default imageService: 'compile', the generated image optimization endpoint doesn't check the URLs it receives, allowing content from unauthorized third-party domains to be served. a A bug in impacted versions of the @astrojs/cloudflare adapter for deployment on Cloudflare’s infrastructure, allows an attacker to bypass the third-party domain restrictions and serve any content from the vulnerable origin. This issue is fixed in version 12.6.6.

- [https://github.com/shitodcy/CVE-2025-58179-Check](https://github.com/shitodcy/CVE-2025-58179-Check) :  ![starts](https://img.shields.io/github/stars/shitodcy/CVE-2025-58179-Check.svg) ![forks](https://img.shields.io/github/forks/shitodcy/CVE-2025-58179-Check.svg)


## CVE-2025-56764
 Trivision NC-227WF firmware 5.80 (build 20141010) login mechanism reveals whether a username exists or not by returning different error messages ("Unknown user" vs. "Wrong password"), allowing an attacker to enumerate valid usernames.

- [https://github.com/Remenis/CVE-2025-56764](https://github.com/Remenis/CVE-2025-56764) :  ![starts](https://img.shields.io/github/stars/Remenis/CVE-2025-56764.svg) ![forks](https://img.shields.io/github/forks/Remenis/CVE-2025-56764.svg)


## CVE-2025-55315
 Inconsistent interpretation of http requests ('http request/response smuggling') in ASP.NET Core allows an authorized attacker to bypass a security feature over a network.

- [https://github.com/ZemarKhos/CVE-2025-55315-PoC-Exploit](https://github.com/ZemarKhos/CVE-2025-55315-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/ZemarKhos/CVE-2025-55315-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/ZemarKhos/CVE-2025-55315-PoC-Exploit.svg)


## CVE-2025-52881
 runc is a CLI tool for spawning and running containers according to the OCI specification. In versions 1.2.7, 1.3.2 and 1.4.0-rc.2, an attacker can trick runc into misdirecting writes to /proc to other procfs files through the use of a racing container with shared mounts (we have also verified this attack is possible to exploit using a standard Dockerfile with docker buildx build as that also permits triggering parallel execution of containers with custom shared mounts configured). This redirect could be through symbolic links in a tmpfs or theoretically other methods such as regular bind-mounts. While similar, the mitigation applied for the related CVE, CVE-2019-19921, was fairly limited and effectively only caused runc to verify that when LSM labels are written they are actually procfs files. This issue is fixed in versions 1.2.8, 1.3.3, and 1.4.0-rc.3.

- [https://github.com/jq6l43d1/proxmox-lxc-docker-fix](https://github.com/jq6l43d1/proxmox-lxc-docker-fix) :  ![starts](https://img.shields.io/github/stars/jq6l43d1/proxmox-lxc-docker-fix.svg) ![forks](https://img.shields.io/github/forks/jq6l43d1/proxmox-lxc-docker-fix.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/Network-Sec/CVE-2025-49844-RediShell-AI-made-Revshell](https://github.com/Network-Sec/CVE-2025-49844-RediShell-AI-made-Revshell) :  ![starts](https://img.shields.io/github/stars/Network-Sec/CVE-2025-49844-RediShell-AI-made-Revshell.svg) ![forks](https://img.shields.io/github/forks/Network-Sec/CVE-2025-49844-RediShell-AI-made-Revshell.svg)


## CVE-2025-48703
 CWP (aka Control Web Panel or CentOS Web Panel) before 0.9.8.1205 allows unauthenticated remote code execution via shell metacharacters in the t_total parameter in a filemanager changePerm request. A valid non-root username must be known.

- [https://github.com/137f/PoC-CVE-2025-48703](https://github.com/137f/PoC-CVE-2025-48703) :  ![starts](https://img.shields.io/github/stars/137f/PoC-CVE-2025-48703.svg) ![forks](https://img.shields.io/github/forks/137f/PoC-CVE-2025-48703.svg)


## CVE-2025-41244
 VMware Aria Operations and VMware Tools contain a local privilege escalation vulnerability. A malicious local actor with non-administrative privileges having access to a VM with VMware Tools installed and managed by Aria Operations with SDMP enabled may exploit this vulnerability to escalate privileges to root on the same VM.

- [https://github.com/IBO-ATTACKS/CVE-2025-41244](https://github.com/IBO-ATTACKS/CVE-2025-41244) :  ![starts](https://img.shields.io/github/stars/IBO-ATTACKS/CVE-2025-41244.svg) ![forks](https://img.shields.io/github/forks/IBO-ATTACKS/CVE-2025-41244.svg)


## CVE-2025-34299
 Monsta FTP versions 2.11 and earlier contain a vulnerability that allows unauthenticated arbitrary file uploads. This flaw enables attackers to execute arbitrary code by uploading a specially crafted file from a malicious (S)FTP server.

- [https://github.com/rxerium/CVE-2025-34299](https://github.com/rxerium/CVE-2025-34299) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-34299.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-34299.svg)


## CVE-2025-31931
 Uncontrolled search path for the Instrumentation and Tracing Technology API (ITT API) software before version 3.25.4 within Ring 3: User Applications may allow an escalation of privilege. Unprivileged software adversary with an authenticated user combined with a high complexity attack may enable escalation of privilege. This result may potentially occur via local access when attack requirements are present without special internal knowledge and requires active user interaction. The potential vulnerability may impact the confidentiality (high), integrity (high) and availability (high) of the vulnerable system, resulting in subsequent system confidentiality (none), integrity (none) and availability (none) impacts.

- [https://github.com/yohanes/POC-CVE-2025-31931](https://github.com/yohanes/POC-CVE-2025-31931) :  ![starts](https://img.shields.io/github/stars/yohanes/POC-CVE-2025-31931.svg) ![forks](https://img.shields.io/github/forks/yohanes/POC-CVE-2025-31931.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg)


## CVE-2025-25257
 An improper neutralization of special elements used in an SQL command ('SQL Injection') vulnerability [CWE-89] in Fortinet FortiWeb version 7.6.0 through 7.6.3, 7.4.0 through 7.4.7, 7.2.0 through 7.2.10 and below 7.0.10 allows an unauthenticated attacker to execute unauthorized SQL code or commands via crafted HTTP or HTTPs requests.

- [https://github.com/mr-r3b00t/CVE-2025-25257](https://github.com/mr-r3b00t/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2025-25257.svg)


## CVE-2025-12539
 The TNC Toolbox: Web Performance plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 1.4.2. This is due to the plugin storing cPanel API credentials (hostname, username, and API key) in files within the web-accessible wp-content directory without adequate protection in the "Tnc_Wp_Toolbox_Settings::save_settings" function. This makes it possible for unauthenticated attackers to retrieve these credentials and use them to interact with the cPanel API, which can lead to arbitrary file uploads, remote code execution, and full compromise of the hosting environment.

- [https://github.com/Nxploited/CVE-2025-12539](https://github.com/Nxploited/CVE-2025-12539) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-12539.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-12539.svg)


## CVE-2025-11170
 The WP移行専用プラグイン for CPI plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the Cpiwm_Import_Controller::import function in all versions up to, and including, 1.0.2. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Nxploited/CVE-2025-11170](https://github.com/Nxploited/CVE-2025-11170) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-11170.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-11170.svg)


## CVE-2025-10161
 Improper Restriction of Excessive Authentication Attempts, Client-Side Enforcement of Server-Side Security, Reliance on Untrusted Inputs in a Security Decision vulnerability in Turkguven Software Technologies Inc. Perfektive allows Brute Force, Authentication Bypass, Functionality Bypass.This issue affects Perfektive: before Version: 12574 Build: 2701.

- [https://github.com/FeZqq/CVE-2025-10161](https://github.com/FeZqq/CVE-2025-10161) :  ![starts](https://img.shields.io/github/stars/FeZqq/CVE-2025-10161.svg) ![forks](https://img.shields.io/github/forks/FeZqq/CVE-2025-10161.svg)


## CVE-2025-9223
 Zohocorp ManageEngine Applications Manager versions 178100 and below are vulnerable to authenticated command injection vulnerability due to the improper configuration in the execute program action feature.

- [https://github.com/networkkiller/CVE-2025-9223](https://github.com/networkkiller/CVE-2025-9223) :  ![starts](https://img.shields.io/github/stars/networkkiller/CVE-2025-9223.svg) ![forks](https://img.shields.io/github/forks/networkkiller/CVE-2025-9223.svg)


## CVE-2025-6366
 The Event List plugin for WordPress is vulnerable to privilege escalation in all versions up to, and including, 2.0.4. This is due to the plugin not properly validating a user's capabilities prior to updating their profile in the el_update_profile() function. This makes it possible for authenticated attackers, with Subscriber-level access and above, to change their capabilities to those of an administrator.

- [https://github.com/Remenis/CVE-2025-63666](https://github.com/Remenis/CVE-2025-63666) :  ![starts](https://img.shields.io/github/stars/Remenis/CVE-2025-63666.svg) ![forks](https://img.shields.io/github/forks/Remenis/CVE-2025-63666.svg)
- [https://github.com/Remenis/CVE-2025-63667](https://github.com/Remenis/CVE-2025-63667) :  ![starts](https://img.shields.io/github/stars/Remenis/CVE-2025-63667.svg) ![forks](https://img.shields.io/github/forks/Remenis/CVE-2025-63667.svg)


## CVE-2025-5544
 A vulnerability was found in aaluoxiang oa_system up to 5b445a6227b51cee287bd0c7c33ed94b801a82a5. It has been rated as problematic. Affected by this issue is the function image of the file src/main/java/cn/gson/oasys/controller/user/UserpanelController.java. The manipulation leads to path traversal. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. Continious delivery with rolling releases is used by this product. Therefore, no version details of affected nor updated releases are available.

- [https://github.com/Marven11/CVE-2025-55449-AstrBot-RCE](https://github.com/Marven11/CVE-2025-55449-AstrBot-RCE) :  ![starts](https://img.shields.io/github/stars/Marven11/CVE-2025-55449-AstrBot-RCE.svg) ![forks](https://img.shields.io/github/forks/Marven11/CVE-2025-55449-AstrBot-RCE.svg)


## CVE-2025-4859
 A vulnerability was found in D-Link DAP-2695 120b36r137_ALL_en_20210528. It has been rated as problematic. This issue affects some unknown processing of the file /adv_macbypass.php of the component MAC Bypass Settings Page. The manipulation of the argument f_mac leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/GiladLeef/CVE-2025-48593](https://github.com/GiladLeef/CVE-2025-48593) :  ![starts](https://img.shields.io/github/stars/GiladLeef/CVE-2025-48593.svg) ![forks](https://img.shields.io/github/forks/GiladLeef/CVE-2025-48593.svg)


## CVE-2025-2945
This issue affects pgAdmin 4: before 9.2.

- [https://github.com/I3r1h0n/pgAdminOpendoor](https://github.com/I3r1h0n/pgAdminOpendoor) :  ![starts](https://img.shields.io/github/stars/I3r1h0n/pgAdminOpendoor.svg) ![forks](https://img.shields.io/github/forks/I3r1h0n/pgAdminOpendoor.svg)


## CVE-2024-51378
 getresetstatus in dns/views.py and ftp/views.py in CyberPanel (aka Cyber Panel) before 1c0c6cb allows remote attackers to bypass authentication and execute arbitrary commands via /dns/getresetstatus or /ftp/getresetstatus by bypassing secMiddleware (which is only for a POST request) and using shell metacharacters in the statusfile property, as exploited in the wild in October 2024 by PSAUX. Versions through 2.3.6 and (unpatched) 2.3.7 are affected.

- [https://github.com/rimbadirgantara/CVE-2024-51378](https://github.com/rimbadirgantara/CVE-2024-51378) :  ![starts](https://img.shields.io/github/stars/rimbadirgantara/CVE-2024-51378.svg) ![forks](https://img.shields.io/github/forks/rimbadirgantara/CVE-2024-51378.svg)


## CVE-2024-31982
 XWiki Platform is a generic wiki platform. Starting in version 2.4-milestone-1 and prior to versions 4.10.20, 15.5.4, and 15.10-rc-1, XWiki's database search allows remote code execution through the search text. This allows remote code execution for any visitor of a public wiki or user of a closed wiki as the database search is by default accessible for all users. This impacts the confidentiality, integrity and availability of the whole XWiki installation. This vulnerability has been patched in XWiki 14.10.20, 15.5.4 and 15.10RC1. As a workaround, one may manually apply the patch to the page `Main.DatabaseSearch`. Alternatively, unless database search is explicitly used by users, this page can be deleted as this is not the default search interface of XWiki.

- [https://github.com/raishin1/CVE-2024-31982](https://github.com/raishin1/CVE-2024-31982) :  ![starts](https://img.shields.io/github/stars/raishin1/CVE-2024-31982.svg) ![forks](https://img.shields.io/github/forks/raishin1/CVE-2024-31982.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/harekrishnarai/CVE-2024-23897-test-windows](https://github.com/harekrishnarai/CVE-2024-23897-test-windows) :  ![starts](https://img.shields.io/github/stars/harekrishnarai/CVE-2024-23897-test-windows.svg) ![forks](https://img.shields.io/github/forks/harekrishnarai/CVE-2024-23897-test-windows.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/aavamin/cve-2024-4577](https://github.com/aavamin/cve-2024-4577) :  ![starts](https://img.shields.io/github/stars/aavamin/cve-2024-4577.svg) ![forks](https://img.shields.io/github/forks/aavamin/cve-2024-4577.svg)


## CVE-2023-35813
 Multiple Sitecore products allow remote code execution. This affects Experience Manager, Experience Platform, and Experience Commerce through 10.3.

- [https://github.com/her3ticAVI/CVE-2023-35813](https://github.com/her3ticAVI/CVE-2023-35813) :  ![starts](https://img.shields.io/github/stars/her3ticAVI/CVE-2023-35813.svg) ![forks](https://img.shields.io/github/forks/her3ticAVI/CVE-2023-35813.svg)


## CVE-2021-4449
 The ZoomSounds plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'savepng.php' file in versions up to, and including, 5.96. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/0xnemian/CVE-2021-4449](https://github.com/0xnemian/CVE-2021-4449) :  ![starts](https://img.shields.io/github/stars/0xnemian/CVE-2021-4449.svg) ![forks](https://img.shields.io/github/forks/0xnemian/CVE-2021-4449.svg)


## CVE-2020-2883
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/zhzyker/exphub](https://github.com/zhzyker/exphub) :  ![starts](https://img.shields.io/github/stars/zhzyker/exphub.svg) ![forks](https://img.shields.io/github/forks/zhzyker/exphub.svg)
- [https://github.com/zhzyker/vulmap](https://github.com/zhzyker/vulmap) :  ![starts](https://img.shields.io/github/stars/zhzyker/vulmap.svg) ![forks](https://img.shields.io/github/forks/zhzyker/vulmap.svg)
- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)
- [https://github.com/Y4er/WebLogic-Shiro-shell](https://github.com/Y4er/WebLogic-Shiro-shell) :  ![starts](https://img.shields.io/github/stars/Y4er/WebLogic-Shiro-shell.svg) ![forks](https://img.shields.io/github/forks/Y4er/WebLogic-Shiro-shell.svg)
- [https://github.com/Y4er/CVE-2020-2883](https://github.com/Y4er/CVE-2020-2883) :  ![starts](https://img.shields.io/github/stars/Y4er/CVE-2020-2883.svg) ![forks](https://img.shields.io/github/forks/Y4er/CVE-2020-2883.svg)
- [https://github.com/hktalent/CVE_2020_2546](https://github.com/hktalent/CVE_2020_2546) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE_2020_2546.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE_2020_2546.svg)
- [https://github.com/zzwlpx/weblogicPoc](https://github.com/zzwlpx/weblogicPoc) :  ![starts](https://img.shields.io/github/stars/zzwlpx/weblogicPoc.svg) ![forks](https://img.shields.io/github/forks/zzwlpx/weblogicPoc.svg)
- [https://github.com/MagicZer0/Weblogic_CVE-2020-2883_POC](https://github.com/MagicZer0/Weblogic_CVE-2020-2883_POC) :  ![starts](https://img.shields.io/github/stars/MagicZer0/Weblogic_CVE-2020-2883_POC.svg) ![forks](https://img.shields.io/github/forks/MagicZer0/Weblogic_CVE-2020-2883_POC.svg)
- [https://github.com/Al1ex/CVE-2020-2883](https://github.com/Al1ex/CVE-2020-2883) :  ![starts](https://img.shields.io/github/stars/Al1ex/CVE-2020-2883.svg) ![forks](https://img.shields.io/github/forks/Al1ex/CVE-2020-2883.svg)
- [https://github.com/FancyDoesSecurity/CVE-2020-2883](https://github.com/FancyDoesSecurity/CVE-2020-2883) :  ![starts](https://img.shields.io/github/stars/FancyDoesSecurity/CVE-2020-2883.svg) ![forks](https://img.shields.io/github/forks/FancyDoesSecurity/CVE-2020-2883.svg)
- [https://github.com/Qynklee/POC_CVE-2020-2883](https://github.com/Qynklee/POC_CVE-2020-2883) :  ![starts](https://img.shields.io/github/stars/Qynklee/POC_CVE-2020-2883.svg) ![forks](https://img.shields.io/github/forks/Qynklee/POC_CVE-2020-2883.svg)
- [https://github.com/ZZZWD/CVE-2020-2883](https://github.com/ZZZWD/CVE-2020-2883) :  ![starts](https://img.shields.io/github/stars/ZZZWD/CVE-2020-2883.svg) ![forks](https://img.shields.io/github/forks/ZZZWD/CVE-2020-2883.svg)


## CVE-2020-2814
 Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are affected are 5.6.47 and prior, 5.7.28 and prior and 8.0.18 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).

- [https://github.com/fengchenzxc/CVE-2020-28148](https://github.com/fengchenzxc/CVE-2020-28148) :  ![starts](https://img.shields.io/github/stars/fengchenzxc/CVE-2020-28148.svg) ![forks](https://img.shields.io/github/forks/fengchenzxc/CVE-2020-28148.svg)


## CVE-2020-2719
 Vulnerability in the Oracle Banking Corporate Lending product of Oracle Financial Services Applications (component: Core). Supported versions that are affected are 12.3.0-12.4.0 and 14.0.0-14.3.0. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Banking Corporate Lending. Successful attacks of this vulnerability can result in unauthorized read access to a subset of Oracle Banking Corporate Lending accessible data. CVSS 3.0 Base Score 4.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N).

- [https://github.com/qlh831/x-CVE-2020-27190](https://github.com/qlh831/x-CVE-2020-27190) :  ![starts](https://img.shields.io/github/stars/qlh831/x-CVE-2020-27190.svg) ![forks](https://img.shields.io/github/forks/qlh831/x-CVE-2020-27190.svg)


## CVE-2020-2576
 Vulnerability in the Oracle Outside In Technology product of Oracle Fusion Middleware (component: Outside In Filters). The supported version that is affected is 8.5.4. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Outside In Technology. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Outside In Technology accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Outside In Technology. Note: Outside In Technology is a suite of software development kits (SDKs). The protocol and CVSS score depend on the software that uses the Outside In Technology code. The CVSS score assumes that the software passes data received over a network directly to Outside In Technology code, but if data is not received over a network the CVSS score may be lower. CVSS 3.0 Base Score 6.5 (Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L).

- [https://github.com/defrancescojp/CVE-2020-25769](https://github.com/defrancescojp/CVE-2020-25769) :  ![starts](https://img.shields.io/github/stars/defrancescojp/CVE-2020-25769.svg) ![forks](https://img.shields.io/github/forks/defrancescojp/CVE-2020-25769.svg)


## CVE-2020-2555
 Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching,CacheStore,Invocation). Supported versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3 to compromise Oracle Coherence. Successful attacks of this vulnerability can result in takeover of Oracle Coherence. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/zhzyker/exphub](https://github.com/zhzyker/exphub) :  ![starts](https://img.shields.io/github/stars/zhzyker/exphub.svg) ![forks](https://img.shields.io/github/forks/zhzyker/exphub.svg)
- [https://github.com/zhzyker/vulmap](https://github.com/zhzyker/vulmap) :  ![starts](https://img.shields.io/github/stars/zhzyker/vulmap.svg) ![forks](https://img.shields.io/github/forks/zhzyker/vulmap.svg)
- [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) :  ![starts](https://img.shields.io/github/stars/0xn0ne/weblogicScanner.svg) ![forks](https://img.shields.io/github/forks/0xn0ne/weblogicScanner.svg)
- [https://github.com/Y4er/CVE-2020-2555](https://github.com/Y4er/CVE-2020-2555) :  ![starts](https://img.shields.io/github/stars/Y4er/CVE-2020-2555.svg) ![forks](https://img.shields.io/github/forks/Y4er/CVE-2020-2555.svg)
- [https://github.com/zzwlpx/weblogicPoc](https://github.com/zzwlpx/weblogicPoc) :  ![starts](https://img.shields.io/github/stars/zzwlpx/weblogicPoc.svg) ![forks](https://img.shields.io/github/forks/zzwlpx/weblogicPoc.svg)
- [https://github.com/feihong-cs/Attacking_Shiro_with_CVE_2020_2555](https://github.com/feihong-cs/Attacking_Shiro_with_CVE_2020_2555) :  ![starts](https://img.shields.io/github/stars/feihong-cs/Attacking_Shiro_with_CVE_2020_2555.svg) ![forks](https://img.shields.io/github/forks/feihong-cs/Attacking_Shiro_with_CVE_2020_2555.svg)
- [https://github.com/wsfengfan/CVE-2020-2555](https://github.com/wsfengfan/CVE-2020-2555) :  ![starts](https://img.shields.io/github/stars/wsfengfan/CVE-2020-2555.svg) ![forks](https://img.shields.io/github/forks/wsfengfan/CVE-2020-2555.svg)
- [https://github.com/Maskhe/cve-2020-2555](https://github.com/Maskhe/cve-2020-2555) :  ![starts](https://img.shields.io/github/stars/Maskhe/cve-2020-2555.svg) ![forks](https://img.shields.io/github/forks/Maskhe/cve-2020-2555.svg)
- [https://github.com/adm1in/CodeTest](https://github.com/adm1in/CodeTest) :  ![starts](https://img.shields.io/github/stars/adm1in/CodeTest.svg) ![forks](https://img.shields.io/github/forks/adm1in/CodeTest.svg)
- [https://github.com/Hu3sky/CVE-2020-2555](https://github.com/Hu3sky/CVE-2020-2555) :  ![starts](https://img.shields.io/github/stars/Hu3sky/CVE-2020-2555.svg) ![forks](https://img.shields.io/github/forks/Hu3sky/CVE-2020-2555.svg)
- [https://github.com/Qynklee/POC_CVE-2020-2555](https://github.com/Qynklee/POC_CVE-2020-2555) :  ![starts](https://img.shields.io/github/stars/Qynklee/POC_CVE-2020-2555.svg) ![forks](https://img.shields.io/github/forks/Qynklee/POC_CVE-2020-2555.svg)


## CVE-2020-2547
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle WebLogic Server, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle WebLogic Server accessible data as well as unauthorized read access to a subset of Oracle WebLogic Server accessible data. CVSS 3.0 Base Score 4.8 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N).

- [https://github.com/santokum/CVE-2020-25478--ASUS-RT-AC87U-TFTP-is-vulnerable-to-Denial-of-Service-DoS-attack](https://github.com/santokum/CVE-2020-25478--ASUS-RT-AC87U-TFTP-is-vulnerable-to-Denial-of-Service-DoS-attack) :  ![starts](https://img.shields.io/github/stars/santokum/CVE-2020-25478--ASUS-RT-AC87U-TFTP-is-vulnerable-to-Denial-of-Service-DoS-attack.svg) ![forks](https://img.shields.io/github/forks/santokum/CVE-2020-25478--ASUS-RT-AC87U-TFTP-is-vulnerable-to-Denial-of-Service-DoS-attack.svg)


## CVE-2020-2509
 A command injection vulnerability has been reported to affect QTS and QuTS hero. If exploited, this vulnerability allows attackers to execute arbitrary commands in a compromised application. We have already fixed this vulnerability in the following versions: QTS 4.5.2.1566 Build 20210202 and later QTS 4.5.1.1495 Build 20201123 and later QTS 4.3.6.1620 Build 20210322 and later QTS 4.3.4.1632 Build 20210324 and later QTS 4.3.3.1624 Build 20210416 and later QTS 4.2.6 Build 20210327 and later QuTS hero h4.5.1.1491 build 20201119 and later

- [https://github.com/jbaines-r7/overkill](https://github.com/jbaines-r7/overkill) :  ![starts](https://img.shields.io/github/stars/jbaines-r7/overkill.svg) ![forks](https://img.shields.io/github/forks/jbaines-r7/overkill.svg)


## CVE-2020-2501
 A stack-based buffer overflow vulnerability has been reported to affect QNAP NAS devices running Surveillance Station. If exploited, this vulnerability allows attackers to execute arbitrary code. QNAP have already fixed this vulnerability in the following versions: Surveillance Station 5.1.5.4.3 (and later) for ARM CPU NAS (64bit OS) and x86 CPU NAS (64bit OS) Surveillance Station 5.1.5.3.3 (and later) for ARM CPU NAS (32bit OS) and x86 CPU NAS (32bit OS)

- [https://github.com/Alonzozzz/alonzzzo](https://github.com/Alonzozzz/alonzzzo) :  ![starts](https://img.shields.io/github/stars/Alonzozzz/alonzzzo.svg) ![forks](https://img.shields.io/github/forks/Alonzozzz/alonzzzo.svg)


## CVE-2020-2025
 Kata Containers before 1.11.0 on Cloud Hypervisor persists guest filesystem changes to the underlying image file on the host. A malicious guest can overwrite the image file to gain control of all subsequent guest VMs. Since Kata Containers uses the same VM image file with all VMMs, this issue may also affect QEMU and Firecracker based guests.

- [https://github.com/arojit/model-training-with-sft](https://github.com/arojit/model-training-with-sft) :  ![starts](https://img.shields.io/github/stars/arojit/model-training-with-sft.svg) ![forks](https://img.shields.io/github/forks/arojit/model-training-with-sft.svg)


## CVE-2020-2023
 Kata Containers doesn't restrict containers from accessing the guest's root filesystem device. Malicious containers can exploit this to gain code execution on the guest and masquerade as the kata-agent. This issue affects Kata Containers 1.11 versions earlier than 1.11.1; Kata Containers 1.10 versions earlier than 1.10.5; and Kata Containers 1.9 and earlier versions.

- [https://github.com/ssst0n3/kata-cve-2020-2023-poc](https://github.com/ssst0n3/kata-cve-2020-2023-poc) :  ![starts](https://img.shields.io/github/stars/ssst0n3/kata-cve-2020-2023-poc.svg) ![forks](https://img.shields.io/github/forks/ssst0n3/kata-cve-2020-2023-poc.svg)


## CVE-2020-2021
 When Security Assertion Markup Language (SAML) authentication is enabled and the 'Validate Identity Provider Certificate' option is disabled (unchecked), improper verification of signatures in PAN-OS SAML authentication enables an unauthenticated network-based attacker to access protected resources. The attacker must have network access to the vulnerable server to exploit this vulnerability. This issue affects PAN-OS 9.1 versions earlier than PAN-OS 9.1.3; PAN-OS 9.0 versions earlier than PAN-OS 9.0.9; PAN-OS 8.1 versions earlier than PAN-OS 8.1.15, and all versions of PAN-OS 8.0 (EOL). This issue does not affect PAN-OS 7.1. This issue cannot be exploited if SAML is not used for authentication. This issue cannot be exploited if the 'Validate Identity Provider Certificate' option is enabled (checked) in the SAML Identity Provider Server Profile. Resources that can be protected by SAML-based single sign-on (SSO) authentication are: GlobalProtect Gateway, GlobalProtect Portal, GlobalProtect Clientless VPN, Authentication and Captive Portal, PAN-OS next-generation firewalls (PA-Series, VM-Series) and Panorama web interfaces, Prisma Access In the case of GlobalProtect Gateways, GlobalProtect Portal, Clientless VPN, Captive Portal, and Prisma Access, an unauthenticated attacker with network access to the affected servers can gain access to protected resources if allowed by configured authentication and Security policies. There is no impact on the integrity and availability of the gateway, portal or VPN server. An attacker cannot inspect or tamper with sessions of regular users. In the worst case, this is a critical severity vulnerability with a CVSS Base Score of 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N). In the case of PAN-OS and Panorama web interfaces, this issue allows an unauthenticated attacker with network access to the PAN-OS or Panorama web interfaces to log in as an administrator and perform administrative actions. In the worst-case scenario, this is a critical severity vulnerability with a CVSS Base Score of 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H). If the web interfaces are only accessible to a restricted management network, then the issue is lowered to a CVSS Base Score of 9.6 (CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H). Palo Alto Networks is not aware of any malicious attempts to exploit this vulnerability.

- [https://github.com/mr-r3b00t/CVE-2020-2021](https://github.com/mr-r3b00t/CVE-2020-2021) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2020-2021.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2020-2021.svg)


## CVE-2020-0192
 In ih264d_decode_slice_thread of ih264d_thread_parse_decode.c, there is a possible out of bounds read due to improper input validation. This could lead to remote information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-144687080

- [https://github.com/himanshu67111/CVE-2020-0192](https://github.com/himanshu67111/CVE-2020-0192) :  ![starts](https://img.shields.io/github/stars/himanshu67111/CVE-2020-0192.svg) ![forks](https://img.shields.io/github/forks/himanshu67111/CVE-2020-0192.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/6iroc/CVE-2019-9053](https://github.com/6iroc/CVE-2019-9053) :  ![starts](https://img.shields.io/github/stars/6iroc/CVE-2019-9053.svg) ![forks](https://img.shields.io/github/forks/6iroc/CVE-2019-9053.svg)


## CVE-2018-19207
 The Van Ons WP GDPR Compliance (aka wp-gdpr-compliance) plugin before 1.4.3 for WordPress allows remote attackers to execute arbitrary code because $wpdb-prepare() input is mishandled, as exploited in the wild in November 2018.

- [https://github.com/Pwdnx1337/CVE-2018-19207](https://github.com/Pwdnx1337/CVE-2018-19207) :  ![starts](https://img.shields.io/github/stars/Pwdnx1337/CVE-2018-19207.svg) ![forks](https://img.shields.io/github/forks/Pwdnx1337/CVE-2018-19207.svg)


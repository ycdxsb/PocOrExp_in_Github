# Update 2026-01-09
## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/Chocapikk/CVE-2026-21858](https://github.com/Chocapikk/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2026-21858.svg)
- [https://github.com/eduardorossi84/CVE-2026-21858-POC](https://github.com/eduardorossi84/CVE-2026-21858-POC) :  ![starts](https://img.shields.io/github/stars/eduardorossi84/CVE-2026-21858-POC.svg) ![forks](https://img.shields.io/github/forks/eduardorossi84/CVE-2026-21858-POC.svg)
- [https://github.com/Ashwesker/Ashwesker-CVE-2026-21858](https://github.com/Ashwesker/Ashwesker-CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2026-21858.svg)


## CVE-2026-0628
 Insufficient policy enforcement in WebView tag in Google Chrome prior to 143.0.7499.192 allowed an attacker who convinced a user to install a malicious extension to inject scripts or HTML into a privileged page via a crafted Chrome Extension. (Chromium security severity: High)

- [https://github.com/fevar54/CVE-2026-0628-POC](https://github.com/fevar54/CVE-2026-0628-POC) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-0628-POC.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-0628-POC.svg)


## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/shibaaa204/CVE-2025-68613](https://github.com/shibaaa204/CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/shibaaa204/CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/shibaaa204/CVE-2025-68613.svg)


## CVE-2025-66838
 In Aris v10.0.23.0.3587512 and before, the file upload functionality does not enforce any rate limiting or throttling, allowing users to upload files at an unrestricted rate. An attacker can exploit this behavior to rapidly upload a large volume of files, potentially leading to resource exhaustion such as disk space depletion, increased server load, or degraded performance

- [https://github.com/saykino/CVE-2025-66838](https://github.com/saykino/CVE-2025-66838) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-66838.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-66838.svg)


## CVE-2025-66837
 A file upload vulnerability in ARIS 10.0.23.0.3587512 allows attackers to execute arbitrary code via uploading a crafted PDF file/Malware

- [https://github.com/saykino/CVE-2025-66837](https://github.com/saykino/CVE-2025-66837) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-66837.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-66837.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg)


## CVE-2025-65354
 Improper input handling in /Grocery/search_products_itname.php inPuneethReddyHC event-management 1.0 permits SQL injection via the sitem_name POST parameter. Crafted payloads can alter query logic and disclose database contents. Exploitation may result in sensitive data disclosure and backend compromise.

- [https://github.com/EarthAngel666/CVE-2025-65354](https://github.com/EarthAngel666/CVE-2025-65354) :  ![starts](https://img.shields.io/github/stars/EarthAngel666/CVE-2025-65354.svg) ![forks](https://img.shields.io/github/forks/EarthAngel666/CVE-2025-65354.svg)


## CVE-2025-60188
 Insertion of Sensitive Information Into Sent Data vulnerability in Vito Peleg Atarim atarim-visual-collaboration allows Retrieve Embedded Sensitive Data.This issue affects Atarim: from n/a through = 4.2.

- [https://github.com/m4sh-wacker/CVE-2025-60188-Atarim-Plugin-Exploit](https://github.com/m4sh-wacker/CVE-2025-60188-Atarim-Plugin-Exploit) :  ![starts](https://img.shields.io/github/stars/m4sh-wacker/CVE-2025-60188-Atarim-Plugin-Exploit.svg) ![forks](https://img.shields.io/github/forks/m4sh-wacker/CVE-2025-60188-Atarim-Plugin-Exploit.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/vrx7men2/RSC-Detect-CVE-2025-55182](https://github.com/vrx7men2/RSC-Detect-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/vrx7men2/RSC-Detect-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/vrx7men2/RSC-Detect-CVE-2025-55182.svg)
- [https://github.com/alfazhossain/CVE-2025-55182-Exploiter](https://github.com/alfazhossain/CVE-2025-55182-Exploiter) :  ![starts](https://img.shields.io/github/stars/alfazhossain/CVE-2025-55182-Exploiter.svg) ![forks](https://img.shields.io/github/forks/alfazhossain/CVE-2025-55182-Exploiter.svg)


## CVE-2025-49071
 Unrestricted Upload of File with Dangerous Type vulnerability in NasaTheme Flozen allows Upload a Web Shell to a Web Server. This issue affects Flozen: from n/a through n/a.

- [https://github.com/xShadow-Here/CVE-2025-49071](https://github.com/xShadow-Here/CVE-2025-49071) :  ![starts](https://img.shields.io/github/stars/xShadow-Here/CVE-2025-49071.svg) ![forks](https://img.shields.io/github/forks/xShadow-Here/CVE-2025-49071.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/wvverez/CVE-2025-32463](https://github.com/wvverez/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/wvverez/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/wvverez/CVE-2025-32463.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/maronnjapan/claude-create-CVE-2025-29927](https://github.com/maronnjapan/claude-create-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/maronnjapan/claude-create-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/maronnjapan/claude-create-CVE-2025-29927.svg)
- [https://github.com/0xPThree/next.js_cve-2025-29927](https://github.com/0xPThree/next.js_cve-2025-29927) :  ![starts](https://img.shields.io/github/stars/0xPThree/next.js_cve-2025-29927.svg) ![forks](https://img.shields.io/github/forks/0xPThree/next.js_cve-2025-29927.svg)
- [https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927](https://github.com/Grand-Moomin/Vuln-Next.js-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Grand-Moomin/Vuln-Next.js-CVE-2025-29927.svg)


## CVE-2025-29306
 An issue in FoxCMS v.1.2.5 allows a remote attacker to execute arbitrary code via the case display page in the index.html component.

- [https://github.com/mantanhacker/Mass-CVE-2025-29306](https://github.com/mantanhacker/Mass-CVE-2025-29306) :  ![starts](https://img.shields.io/github/stars/mantanhacker/Mass-CVE-2025-29306.svg) ![forks](https://img.shields.io/github/forks/mantanhacker/Mass-CVE-2025-29306.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/achnouri/Editor-CTF-writre-up](https://github.com/achnouri/Editor-CTF-writre-up) :  ![starts](https://img.shields.io/github/stars/achnouri/Editor-CTF-writre-up.svg) ![forks](https://img.shields.io/github/forks/achnouri/Editor-CTF-writre-up.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/CadGoose/MongoBleed-CVE-2025-14847-Fully-Automated-scanner](https://github.com/CadGoose/MongoBleed-CVE-2025-14847-Fully-Automated-scanner) :  ![starts](https://img.shields.io/github/stars/CadGoose/MongoBleed-CVE-2025-14847-Fully-Automated-scanner.svg) ![forks](https://img.shields.io/github/forks/CadGoose/MongoBleed-CVE-2025-14847-Fully-Automated-scanner.svg)


## CVE-2025-12030
 The ACF to REST API plugin for WordPress is vulnerable to Insecure Direct Object Reference in all versions up to, and including, 3.3.4. This is due to insufficient capability checks in the update_item_permissions_check() method, which only verifies that the current user has the edit_posts capability without checking object-specific permissions (e.g., edit_post($id), edit_user($id), manage_options). This makes it possible for authenticated attackers, with Contributor-level access and above, to modify ACF fields on posts they do not own, any user account, comments, taxonomy terms, and even the global options page via the /wp-json/acf/v3/{type}/{id} endpoints, granted they can authenticate to the site.

- [https://github.com/SnailSploit/CVE-2025-12030](https://github.com/SnailSploit/CVE-2025-12030) :  ![starts](https://img.shields.io/github/stars/SnailSploit/CVE-2025-12030.svg) ![forks](https://img.shields.io/github/forks/SnailSploit/CVE-2025-12030.svg)


## CVE-2025-6919
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Cats Information Technology Software Development Technologies Aykome License Tracking System allows SQL Injection.This issue affects Aykome License Tracking System: before Version dated 06.10.2025.

- [https://github.com/secdongle/POC_CVE-2025-69194](https://github.com/secdongle/POC_CVE-2025-69194) :  ![starts](https://img.shields.io/github/stars/secdongle/POC_CVE-2025-69194.svg) ![forks](https://img.shields.io/github/forks/secdongle/POC_CVE-2025-69194.svg)


## CVE-2025-3243
 A vulnerability was found in code-projects Patient Record Management System 1.0 and classified as critical. This issue affects some unknown processing of the file /dental_form.php. The manipulation of the argument itr_no/dental_no leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/ladosudeste/CVE-2025-3243](https://github.com/ladosudeste/CVE-2025-3243) :  ![starts](https://img.shields.io/github/stars/ladosudeste/CVE-2025-3243.svg) ![forks](https://img.shields.io/github/forks/ladosudeste/CVE-2025-3243.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/BoianEduard/CVE-2025-1974](https://github.com/BoianEduard/CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/BoianEduard/CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/BoianEduard/CVE-2025-1974.svg)


## CVE-2025-1910
Client is installed.This issue affects the Mobile VPN with SSL Client 12.0 up to and including 12.11.2.

- [https://github.com/lutrasecurity/CVE-2025-1910-WatchGuard-Privilege-Escalation](https://github.com/lutrasecurity/CVE-2025-1910-WatchGuard-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/lutrasecurity/CVE-2025-1910-WatchGuard-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/lutrasecurity/CVE-2025-1910-WatchGuard-Privilege-Escalation.svg)


## CVE-2024-4542
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2024-3548. Reason: This candidate was issued in error. Please use CVE-2024-3548 instead.

- [https://github.com/MHamdy24/CVE-2024-45427-Exploit](https://github.com/MHamdy24/CVE-2024-45427-Exploit) :  ![starts](https://img.shields.io/github/stars/MHamdy24/CVE-2024-45427-Exploit.svg) ![forks](https://img.shields.io/github/forks/MHamdy24/CVE-2024-45427-Exploit.svg)


## CVE-2024-0670
 Privilege escalation in windows agent plugin in Checkmk before 2.2.0p23, 2.1.0p40 and 2.0.0 (EOL) allows local user to escalate privileges

- [https://github.com/Nikopmpm/Fsociety-CVE-2024-0670-CheckMK-LPE](https://github.com/Nikopmpm/Fsociety-CVE-2024-0670-CheckMK-LPE) :  ![starts](https://img.shields.io/github/stars/Nikopmpm/Fsociety-CVE-2024-0670-CheckMK-LPE.svg) ![forks](https://img.shields.io/github/forks/Nikopmpm/Fsociety-CVE-2024-0670-CheckMK-LPE.svg)
- [https://github.com/Nikopmpm/nikopmpm.github.io](https://github.com/Nikopmpm/nikopmpm.github.io) :  ![starts](https://img.shields.io/github/stars/Nikopmpm/nikopmpm.github.io.svg) ![forks](https://img.shields.io/github/forks/Nikopmpm/nikopmpm.github.io.svg)


## CVE-2023-39910
 The cryptocurrency wallet entropy seeding mechanism used in Libbitcoin Explorer 3.0.0 through 3.6.0 is weak, aka the Milk Sad issue. The use of an mt19937 Mersenne Twister PRNG restricts the internal entropy to 32 bits regardless of settings. This allows remote attackers to recover any wallet private keys generated from "bx seed" entropy output and steal funds. (Affected users need to move funds to a secure new cryptocurrency wallet.) NOTE: the vendor's position is that there was sufficient documentation advising against "bx seed" but others disagree. NOTE: this was exploited in the wild in June and July 2023.

- [https://github.com/Hitplus/hitplus.github.io](https://github.com/Hitplus/hitplus.github.io) :  ![starts](https://img.shields.io/github/stars/Hitplus/hitplus.github.io.svg) ![forks](https://img.shields.io/github/forks/Hitplus/hitplus.github.io.svg)
- [https://github.com/Hitplus/RingSide-Replay-Attack](https://github.com/Hitplus/RingSide-Replay-Attack) :  ![starts](https://img.shields.io/github/stars/Hitplus/RingSide-Replay-Attack.svg) ![forks](https://img.shields.io/github/forks/Hitplus/RingSide-Replay-Attack.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/xiaoLvChen/CVE-2022-0847](https://github.com/xiaoLvChen/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/xiaoLvChen/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/xiaoLvChen/CVE-2022-0847.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/rikdek/CVE-2021-41773](https://github.com/rikdek/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/rikdek/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/rikdek/CVE-2021-41773.svg)
- [https://github.com/puckiestyle/CVE-2021-41773](https://github.com/puckiestyle/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/puckiestyle/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/puckiestyle/CVE-2021-41773.svg)
- [https://github.com/JIYUN02/cve-2021-41773](https://github.com/JIYUN02/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/JIYUN02/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/JIYUN02/cve-2021-41773.svg)
- [https://github.com/AzkOsDev/CVE-2021-41773](https://github.com/AzkOsDev/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/AzkOsDev/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/AzkOsDev/CVE-2021-41773.svg)
- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2019-18634
 In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS; however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.

- [https://github.com/CyrusRazavi/CVE-2019-18634-](https://github.com/CyrusRazavi/CVE-2019-18634-) :  ![starts](https://img.shields.io/github/stars/CyrusRazavi/CVE-2019-18634-.svg) ![forks](https://img.shields.io/github/forks/CyrusRazavi/CVE-2019-18634-.svg)


## CVE-2019-9624
 Webmin 1.900 allows remote attackers to execute arbitrary code by leveraging the "Java file manager" and "Upload and Download" privileges to upload a crafted .cgi file via the /updown/upload.cgi URI.

- [https://github.com/x0rbeexd/CVE-2019-9624](https://github.com/x0rbeexd/CVE-2019-9624) :  ![starts](https://img.shields.io/github/stars/x0rbeexd/CVE-2019-9624.svg) ![forks](https://img.shields.io/github/forks/x0rbeexd/CVE-2019-9624.svg)


## CVE-2015-3839
 The updateMessageStatus function in Android 5.1.1 and earlier allows local users to cause a denial of service (NULL pointer exception and process crash).

- [https://github.com/Cecilia-newbie/cve-2015-3839_PoC](https://github.com/Cecilia-newbie/cve-2015-3839_PoC) :  ![starts](https://img.shields.io/github/stars/Cecilia-newbie/cve-2015-3839_PoC.svg) ![forks](https://img.shields.io/github/forks/Cecilia-newbie/cve-2015-3839_PoC.svg)


## CVE-2014-7912
 The get_option function in dhcp.c in dhcpcd before 6.2.0, as used in dhcpcd 5.x in Android before 5.1 and other products, does not validate the relationship between length fields and the amount of data, which allows remote DHCP servers to execute arbitrary code or cause a denial of service (memory corruption) via a large length value of an option in a DHCPACK message.

- [https://github.com/vaginessa/cve-2014-7912](https://github.com/vaginessa/cve-2014-7912) :  ![starts](https://img.shields.io/github/stars/vaginessa/cve-2014-7912.svg) ![forks](https://img.shields.io/github/forks/vaginessa/cve-2014-7912.svg)


## CVE-2014-7911
 luni/src/main/java/java/io/ObjectInputStream.java in the java.io.ObjectInputStream implementation in Android before 5.0.0 does not verify that deserialization will result in an object that met the requirements for serialization, which allows attackers to execute arbitrary code via a crafted finalize method for a serialized object in an ArrayMap Parcel within an intent sent to system_service, as demonstrated by the finalize method of android.os.BinderProxy, aka Bug 15874291.

- [https://github.com/vaginessa/cve-2014-7912](https://github.com/vaginessa/cve-2014-7912) :  ![starts](https://img.shields.io/github/stars/vaginessa/cve-2014-7912.svg) ![forks](https://img.shields.io/github/forks/vaginessa/cve-2014-7912.svg)


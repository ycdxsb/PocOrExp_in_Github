# Update 2025-07-31
## CVE-2025-54381
 BentoML is a Python library for building online serving systems optimized for AI apps and model inference. In versions 1.4.0 until 1.4.19, the file upload processing system contains an SSRF vulnerability that allows unauthenticated remote attackers to force the server to make arbitrary HTTP requests. The vulnerability stems from the multipart form data and JSON request handlers, which automatically download files from user-provided URLs without validating whether those URLs point to internal network addresses, cloud metadata endpoints, or other restricted resources. The documentation explicitly promotes this URL-based file upload feature, making it an intended design that exposes all deployed services to SSRF attacks by default. Version 1.4.19 contains a patch for the issue.

- [https://github.com/rockmelodies/bentoml_CVE-2025-54381](https://github.com/rockmelodies/bentoml_CVE-2025-54381) :  ![starts](https://img.shields.io/github/stars/rockmelodies/bentoml_CVE-2025-54381.svg) ![forks](https://img.shields.io/github/forks/rockmelodies/bentoml_CVE-2025-54381.svg)


## CVE-2025-54352
 WordPress 3.5 through 6.8.2 allows remote attackers to guess titles of private and draft posts via pingback.ping XML-RPC requests. NOTE: the Supplier is not changing this behavior.

- [https://github.com/yohannslm/CVE-2025-54352](https://github.com/yohannslm/CVE-2025-54352) :  ![starts](https://img.shields.io/github/stars/yohannslm/CVE-2025-54352.svg) ![forks](https://img.shields.io/github/forks/yohannslm/CVE-2025-54352.svg)


## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/Immersive-Labs-Sec/SharePoint-CVE-2025-53770-POC](https://github.com/Immersive-Labs-Sec/SharePoint-CVE-2025-53770-POC) :  ![starts](https://img.shields.io/github/stars/Immersive-Labs-Sec/SharePoint-CVE-2025-53770-POC.svg) ![forks](https://img.shields.io/github/forks/Immersive-Labs-Sec/SharePoint-CVE-2025-53770-POC.svg)


## CVE-2025-51970
 A SQL Injection vulnerability exists in the action.php endpoint of PuneethReddyHC Online Shopping System Advanced 1.0 due to improper sanitization of user-supplied input in the keyword POST parameter.

- [https://github.com/M4xIq/CVE-2025-51970](https://github.com/M4xIq/CVE-2025-51970) :  ![starts](https://img.shields.io/github/stars/M4xIq/CVE-2025-51970.svg) ![forks](https://img.shields.io/github/forks/M4xIq/CVE-2025-51970.svg)


## CVE-2025-47227
 In the Production Environment extension in Netmake ScriptCase through 9.12.006 (23), the Administrator password reset mechanism is mishandled. Making both a GET and a POST request to login.php.is sufficient. An unauthenticated attacker can then bypass authentication via administrator account takeover.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-47227](https://github.com/B1ack4sh/Blackash-CVE-2025-47227) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-47227.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-47227.svg)


## CVE-2025-44137
 MapTiler Tileserver-php v2.0 is vulnerable to Directory Traversal. The renderTile function within tileserver.php is responsible for delivering tiles that are stored as files on the server via web request. Creating the path to a file allows the insertion of "../" and thus read any file on the web server. Affected GET parameters are "TileMatrix", "TileRow", "TileCol" and "Format"

- [https://github.com/mheranco/CVE-2025-44137](https://github.com/mheranco/CVE-2025-44137) :  ![starts](https://img.shields.io/github/stars/mheranco/CVE-2025-44137.svg) ![forks](https://img.shields.io/github/forks/mheranco/CVE-2025-44137.svg)


## CVE-2025-44136
 MapTiler Tileserver-php v2.0 is vulnerable to Cross Site Scripting (XSS). The GET parameter "layer" is reflected in an error message without html encoding. This leads to XSS and allows an unauthenticated attacker to execute arbitrary HTML or JavaScript code on a victim's browser.

- [https://github.com/mheranco/CVE-2025-44136](https://github.com/mheranco/CVE-2025-44136) :  ![starts](https://img.shields.io/github/stars/mheranco/CVE-2025-44136.svg) ![forks](https://img.shields.io/github/forks/mheranco/CVE-2025-44136.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/KaiHT-Ladiant/CVE-2025-32463](https://github.com/KaiHT-Ladiant/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/KaiHT-Ladiant/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/KaiHT-Ladiant/CVE-2025-32463.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/b4sh0xf/PoC-CVE-2025-29927](https://github.com/b4sh0xf/PoC-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/b4sh0xf/PoC-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/b4sh0xf/PoC-CVE-2025-29927.svg)
- [https://github.com/newweshi/CVE-2025-29927](https://github.com/newweshi/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/newweshi/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/newweshi/CVE-2025-29927.svg)


## CVE-2025-24203
 The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.7.5, iPadOS 17.7.6, macOS Sequoia 15.4, macOS Sonoma 14.7.5. An app may be able to modify protected parts of the file system.

- [https://github.com/aokumo21/iOS-CVE-2025-24203-Paths](https://github.com/aokumo21/iOS-CVE-2025-24203-Paths) :  ![starts](https://img.shields.io/github/stars/aokumo21/iOS-CVE-2025-24203-Paths.svg) ![forks](https://img.shields.io/github/forks/aokumo21/iOS-CVE-2025-24203-Paths.svg)


## CVE-2025-5228
 A vulnerability was found in D-Link DI-8100 up to 20250523. It has been classified as critical. Affected is the function httpd_get_parm of the file /login.cgi of the component jhttpd. The manipulation of the argument notify leads to stack-based buffer overflow. The attack can only be initiated within the local network. The exploit has been disclosed to the public and may be used.

- [https://github.com/Madhav-Bhardwaj/CVE-2025-52289](https://github.com/Madhav-Bhardwaj/CVE-2025-52289) :  ![starts](https://img.shields.io/github/stars/Madhav-Bhardwaj/CVE-2025-52289.svg) ![forks](https://img.shields.io/github/forks/Madhav-Bhardwaj/CVE-2025-52289.svg)


## CVE-2025-2828
 A Server-Side Request Forgery (SSRF) vulnerability exists in the RequestsToolkit component of the langchain-community package (specifically, langchain_community.agent_toolkits.openapi.toolkit.RequestsToolkit) in langchain-ai/langchain version 0.0.27. This vulnerability occurs because the toolkit does not enforce restrictions on requests to remote internet addresses, allowing it to also access local addresses. As a result, an attacker could exploit this flaw to perform port scans, access local services, retrieve instance metadata from cloud environments (e.g., Azure, AWS), and interact with servers on the local network. This issue has been fixed in version 0.0.28.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-2828](https://github.com/B1ack4sh/Blackash-CVE-2025-2828) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-2828.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-2828.svg)


## CVE-2025-2533
 IBM Db2 for Linux 12.1.0, 12.1.1, and 12.1.2 is vulnerable to a denial of service as the server may crash under certain conditions with a specially crafted query.

- [https://github.com/l00neyhacker/CVE-2025-25338](https://github.com/l00neyhacker/CVE-2025-25338) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2025-25338.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2025-25338.svg)
- [https://github.com/l00neyhacker/CVE-2025-25335](https://github.com/l00neyhacker/CVE-2025-25335) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2025-25335.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2025-25335.svg)
- [https://github.com/l00neyhacker/CVE-2025-25337](https://github.com/l00neyhacker/CVE-2025-25337) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2025-25337.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2025-25337.svg)
- [https://github.com/l00neyhacker/CVE-2025-25339](https://github.com/l00neyhacker/CVE-2025-25339) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2025-25339.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2025-25339.svg)


## CVE-2024-45200
 In Nintendo Mario Kart 8 Deluxe before 3.0.3, the LAN/LDN local multiplayer implementation allows a remote attacker to exploit a stack-based buffer overflow upon deserialization of session information via a malformed browse-reply packet, aka KartLANPwn. The victim is not required to join a game session with an attacker. The victim must open the "Wireless Play" (or "LAN Play") menu from the game's title screen, and an attacker nearby (LDN) or on the same LAN network as the victim can send a crafted reply packet to the victim's console. This enables a remote attacker to obtain complete denial-of-service on the game's process, or potentially, remote code execution on the victim's console. The issue is caused by incorrect use of the Nintendo Pia library,

- [https://github.com/regginator/kartlanpwn](https://github.com/regginator/kartlanpwn) :  ![starts](https://img.shields.io/github/stars/regginator/kartlanpwn.svg) ![forks](https://img.shields.io/github/forks/regginator/kartlanpwn.svg)


## CVE-2024-43018
 Piwigo 13.8.0 and below is vulnerable to SQL Injection in the parameters max_level and min_register. These parameters are used in ws_user_gerList function from file include\ws_functions\pwg.users.php and this same function is called by ws.php file at some point can be used for searching users in advanced way in /admin.php?page=user_list.

- [https://github.com/joaosilva21/CVE-2024-43018](https://github.com/joaosilva21/CVE-2024-43018) :  ![starts](https://img.shields.io/github/stars/joaosilva21/CVE-2024-43018.svg) ![forks](https://img.shields.io/github/forks/joaosilva21/CVE-2024-43018.svg)


## CVE-2022-24713
 regex is an implementation of regular expressions for the Rust language. The regex crate features built-in mitigations to prevent denial of service attacks caused by untrusted regexes, or untrusted input matched by trusted regexes. Those (tunable) mitigations already provide sane defaults to prevent attacks. This guarantee is documented and it's considered part of the crate's API. Unfortunately a bug was discovered in the mitigations designed to prevent untrusted regexes to take an arbitrary amount of time during parsing, and it's possible to craft regexes that bypass such mitigations. This makes it possible to perform denial of service attacks by sending specially crafted regexes to services accepting user-controlled, untrusted regexes. All versions of the regex crate before or equal to 1.5.4 are affected by this issue. The fix is include starting from regex 1.5.5. All users accepting user-controlled regexes are recommended to upgrade immediately to the latest version of the regex crate. Unfortunately there is no fixed set of problematic regexes, as there are practically infinite regexes that could be crafted to exploit this vulnerability. Because of this, it us not recommend to deny known problematic regexes.

- [https://github.com/JPeisach/CVE-2022-24713-POC](https://github.com/JPeisach/CVE-2022-24713-POC) :  ![starts](https://img.shields.io/github/stars/JPeisach/CVE-2022-24713-POC.svg) ![forks](https://img.shields.io/github/forks/JPeisach/CVE-2022-24713-POC.svg)


## CVE-2022-22947
 In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

- [https://github.com/kkx600/Burp_VulPscan](https://github.com/kkx600/Burp_VulPscan) :  ![starts](https://img.shields.io/github/stars/kkx600/Burp_VulPscan.svg) ![forks](https://img.shields.io/github/forks/kkx600/Burp_VulPscan.svg)


## CVE-2021-43857
 Gerapy is a distributed crawler management framework. Gerapy prior to version 0.9.8 is vulnerable to remote code execution, and this issue is patched in version 0.9.8.

- [https://github.com/ProwlSec/gerapy-cve-2021-43857](https://github.com/ProwlSec/gerapy-cve-2021-43857) :  ![starts](https://img.shields.io/github/stars/ProwlSec/gerapy-cve-2021-43857.svg) ![forks](https://img.shields.io/github/forks/ProwlSec/gerapy-cve-2021-43857.svg)


## CVE-2021-1675
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/DLL00P/CVE-2021-1675](https://github.com/DLL00P/CVE-2021-1675) :  ![starts](https://img.shields.io/github/stars/DLL00P/CVE-2021-1675.svg) ![forks](https://img.shields.io/github/forks/DLL00P/CVE-2021-1675.svg)


## CVE-2018-1049
 In systemd prior to 234 a race condition exists between .mount and .automount units such that automount requests from kernel may not be serviced by systemd resulting in kernel holding the mountpoint and any processes that try to use said mount will hang. A race condition like this may lead to denial of service, until mount points are unmounted.

- [https://github.com/lukehebe/CVE-2018-1049](https://github.com/lukehebe/CVE-2018-1049) :  ![starts](https://img.shields.io/github/stars/lukehebe/CVE-2018-1049.svg) ![forks](https://img.shields.io/github/forks/lukehebe/CVE-2018-1049.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/joidiego/Detection-struts-cve-2017-5638-detector](https://github.com/joidiego/Detection-struts-cve-2017-5638-detector) :  ![starts](https://img.shields.io/github/stars/joidiego/Detection-struts-cve-2017-5638-detector.svg) ![forks](https://img.shields.io/github/forks/joidiego/Detection-struts-cve-2017-5638-detector.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/Dmitri131313/CVE-2012-1823-exploit-for-https-user-password-web](https://github.com/Dmitri131313/CVE-2012-1823-exploit-for-https-user-password-web) :  ![starts](https://img.shields.io/github/stars/Dmitri131313/CVE-2012-1823-exploit-for-https-user-password-web.svg) ![forks](https://img.shields.io/github/forks/Dmitri131313/CVE-2012-1823-exploit-for-https-user-password-web.svg)


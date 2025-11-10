# Update 2025-11-10
## CVE-2025-61922
 PrestaShop Checkout is the PrestaShop official payment module in partnership with PayPal. Starting in version 1.3.0 and prior to versions 4.4.1 and 5.0.5, missing validation on the Express Checkout feature allows silent login, enabling account takeover via email. The vulnerability is fixed in versions 4.4.1 and 5.0.5. No known workarounds exist.

- [https://github.com/captaincookie34/Vulnerability-Playground-CVE-2025-61922](https://github.com/captaincookie34/Vulnerability-Playground-CVE-2025-61922) :  ![starts](https://img.shields.io/github/stars/captaincookie34/Vulnerability-Playground-CVE-2025-61922.svg) ![forks](https://img.shields.io/github/forks/captaincookie34/Vulnerability-Playground-CVE-2025-61922.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/bummie/CVE-2025-48384](https://github.com/bummie/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/bummie/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/bummie/CVE-2025-48384.svg)
- [https://github.com/bummie/CVE-2025-48384-submodule](https://github.com/bummie/CVE-2025-48384-submodule) :  ![starts](https://img.shields.io/github/stars/bummie/CVE-2025-48384-submodule.svg) ![forks](https://img.shields.io/github/forks/bummie/CVE-2025-48384-submodule.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/l1nuxkid/CVE-2025-32433-exploit](https://github.com/l1nuxkid/CVE-2025-32433-exploit) :  ![starts](https://img.shields.io/github/stars/l1nuxkid/CVE-2025-32433-exploit.svg) ![forks](https://img.shields.io/github/forks/l1nuxkid/CVE-2025-32433-exploit.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/KaztoRay/CVE-2025-29927-Research](https://github.com/KaztoRay/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2025-29927-Research.svg)
- [https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927](https://github.com/rgvillanueva28/vulnbox-easy-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/rgvillanueva28/vulnbox-easy-CVE-2025-29927.svg)


## CVE-2025-21042
 Out-of-bounds write in libimagecodec.quram.so prior to SMR Apr-2025 Release 1 allows remote attackers to execute arbitrary code.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-21042](https://github.com/B1ack4sh/Blackash-CVE-2025-21042) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-21042.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-21042.svg)
- [https://github.com/usjnx72726w/CVE-2025-21042](https://github.com/usjnx72726w/CVE-2025-21042) :  ![starts](https://img.shields.io/github/stars/usjnx72726w/CVE-2025-21042.svg) ![forks](https://img.shields.io/github/forks/usjnx72726w/CVE-2025-21042.svg)


## CVE-2025-12907
 Insufficient validation of untrusted input in Devtools in Google Chrome prior to 140.0.7339.80 allowed a remote attacker to execute arbitrary code via user action in Devtools. (Chromium security severity: Low)

- [https://github.com/DExplo1ted/CVE-2025-12907-Exploit](https://github.com/DExplo1ted/CVE-2025-12907-Exploit) :  ![starts](https://img.shields.io/github/stars/DExplo1ted/CVE-2025-12907-Exploit.svg) ![forks](https://img.shields.io/github/forks/DExplo1ted/CVE-2025-12907-Exploit.svg)


## CVE-2025-12399
 The Alex Reservations: Smart Restaurant Booking plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the /wp-json/srr/v1/app/upload/file REST endpoint in all versions up to, and including, 2.2.3. This makes it possible for authenticated attackers, with Administrator-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/d0n601/CVE-2025-12399](https://github.com/d0n601/CVE-2025-12399) :  ![starts](https://img.shields.io/github/stars/d0n601/CVE-2025-12399.svg) ![forks](https://img.shields.io/github/forks/d0n601/CVE-2025-12399.svg)


## CVE-2025-11749
 The AI Engine plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 3.1.3 via the /mcp/v1/ REST API endpoint that exposes the 'Bearer Token' value when 'No-Auth URL' is enabled. This makes it possible for unauthenticated attackers to extract the bearer token, which can be used to gain access to a valid session and perform many actions like creating a new administrator account, leading to privilege escalation.

- [https://github.com/Nxploited/CVE-2025-11749](https://github.com/Nxploited/CVE-2025-11749) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-11749.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-11749.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/shourout/CVE-2025-8088](https://github.com/shourout/CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/shourout/CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/shourout/CVE-2025-8088.svg)


## CVE-2025-5731
 A flaw was found in Infinispan CLI. A sensitive password, decoded from a Base64-encoded Kubernetes secret, is processed in plaintext and included in a command string that may expose the data in an error message when a command is not found.

- [https://github.com/MMAKINGDOM/CVE-2025-57310](https://github.com/MMAKINGDOM/CVE-2025-57310) :  ![starts](https://img.shields.io/github/stars/MMAKINGDOM/CVE-2025-57310.svg) ![forks](https://img.shields.io/github/forks/MMAKINGDOM/CVE-2025-57310.svg)


## CVE-2025-4859
 A vulnerability was found in D-Link DAP-2695 120b36r137_ALL_en_20210528. It has been rated as problematic. This issue affects some unknown processing of the file /adv_macbypass.php of the component MAC Bypass Settings Page. The manipulation of the argument f_mac leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. Other parameters might be affected as well. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/logesh-GIT001/CVE-2025-48593](https://github.com/logesh-GIT001/CVE-2025-48593) :  ![starts](https://img.shields.io/github/stars/logesh-GIT001/CVE-2025-48593.svg) ![forks](https://img.shields.io/github/forks/logesh-GIT001/CVE-2025-48593.svg)


## CVE-2023-45612
 In JetBrains Ktor before 2.3.5 default configuration of ContentNegotiation with XML format was vulnerable to XXE

- [https://github.com/razvanclaudiu/Ktor-XXE-PoC](https://github.com/razvanclaudiu/Ktor-XXE-PoC) :  ![starts](https://img.shields.io/github/stars/razvanclaudiu/Ktor-XXE-PoC.svg) ![forks](https://img.shields.io/github/forks/razvanclaudiu/Ktor-XXE-PoC.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/jxpsx/CVE-2022-0847-DirtyPipe-Exploits](https://github.com/jxpsx/CVE-2022-0847-DirtyPipe-Exploits) :  ![starts](https://img.shields.io/github/stars/jxpsx/CVE-2022-0847-DirtyPipe-Exploits.svg) ![forks](https://img.shields.io/github/forks/jxpsx/CVE-2022-0847-DirtyPipe-Exploits.svg)


## CVE-2022-0324
Discovered by Eugene Lim of GovTech Singapore.

- [https://github.com/ngtuonghung/cve-2022-0324](https://github.com/ngtuonghung/cve-2022-0324) :  ![starts](https://img.shields.io/github/stars/ngtuonghung/cve-2022-0324.svg) ![forks](https://img.shields.io/github/forks/ngtuonghung/cve-2022-0324.svg)


## CVE-2021-40438
 A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the remote user. This issue affects Apache HTTP Server 2.4.48 and earlier.

- [https://github.com/n0m-d/CVE-2021-40438-POC](https://github.com/n0m-d/CVE-2021-40438-POC) :  ![starts](https://img.shields.io/github/stars/n0m-d/CVE-2021-40438-POC.svg) ![forks](https://img.shields.io/github/forks/n0m-d/CVE-2021-40438-POC.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/0nion1/CVE-2021-3129](https://github.com/0nion1/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/0nion1/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/0nion1/CVE-2021-3129.svg)


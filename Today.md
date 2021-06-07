# Update 2021-06-07
## CVE-2021-33623
 The trim-newlines package before 3.0.1 and 4.x before 4.0.1 for Node.js has an issue related to regular expression denial-of-service (ReDoS) for the .end() method.

- [https://github.com/JamesGeeee/CVE-2021-33623](https://github.com/JamesGeeee/CVE-2021-33623) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-33623.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-33623.svg)


## CVE-2021-33587
 The css-what package before 5.0.1 for Node.js does not ensure that attribute parsing has Linear Time Complexity relative to the size of the input.

- [https://github.com/JamesGeeee/CVE-2021-33587](https://github.com/JamesGeeee/CVE-2021-33587) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-33587.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-33587.svg)


## CVE-2021-33558
 Boa 0.94.13 allows remote attackers to obtain sensitive information via a misconfiguration involving backup.html, preview.html, js/log.js, log.html, email.html, online-users.html, and config.js.

- [https://github.com/JamesGeeee/CVE-2021-33558](https://github.com/JamesGeeee/CVE-2021-33558) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-33558.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-33558.svg)


## CVE-2021-32641
 auth0-lock is Auth0's signin solution. Versions of nauth0-lock before and including `11.30.0` are vulnerable to reflected XSS. An attacker can execute arbitrary code when the library's `flashMessage` feature is utilized and user input or data from URL parameters is incorporated into the `flashMessage` or the library's `languageDictionary` feature is utilized and user input or data from URL parameters is incorporated into the `languageDictionary`. The vulnerability is patched in version 11.30.1.

- [https://github.com/JamesGeeee/CVE-2021-32641](https://github.com/JamesGeeee/CVE-2021-32641) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-32641.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-32641.svg)


## CVE-2021-32638
 Github's CodeQL action is provided to run CodeQL-based code scanning on non-GitHub CI/CD systems and requires a GitHub access token to connect to a GitHub repository. The runner and its documentation previously suggested passing the GitHub token as a command-line parameter to the process instead of reading it from a file, standard input, or an environment variable. This approach made the token visible to other processes on the same machine, for example in the output of the `ps` command. If the CI system publicly exposes the output of `ps`, for example by logging the output, then the GitHub access token can be exposed beyond the scope intended. Users of the CodeQL runner on 3rd-party systems, who are passing a GitHub token via the `--github-auth` flag, are affected. This applies to both GitHub.com and GitHub Enterprise users. Users of the CodeQL Action on GitHub Actions are not affected. The `--github-auth` flag is now considered insecure and deprecated. The undocumented `--external-repository-token` flag has been removed. To securely provide a GitHub access token to the CodeQL runner, users should **do one of the following instead**: Use the `--github-auth-stdin` flag and pass the token on the command line via standard input OR set the `GITHUB_TOKEN` environment variable to contain the token, then call the command without passing in the token. The old flag remains present for backwards compatibility with existing workflows. If the user tries to specify an access token using the `--github-auth` flag, there is a deprecation warning printed to the terminal that directs the user to one of the above options. All CodeQL runner releases codeql-bundle-20210304 onwards contain the patches. We recommend updating to a recent version of the CodeQL runner, storing a token in your CI system's secret storage mechanism, and passing the token to the CodeQL runner using `--github-auth-stdin` or the `GITHUB_TOKEN` environment variable. If still using the old flag, ensure that process output, such as from `ps`, is not persisted in CI logs.

- [https://github.com/JamesGeeee/CVE-2021-32638](https://github.com/JamesGeeee/CVE-2021-32638) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-32638.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-32638.svg)


## CVE-2021-31252
 An open redirect vulnerability exists in BF-630, BF-450M, BF-430, BF-431, BF631-W, BF830-W, Webpass, and SEMAC devices from CHIYU Technology that can be exploited by sending a link that has a specially crafted URL to convince the user to click on it.

- [https://github.com/JamesGeeee/CVE-2021-31252](https://github.com/JamesGeeee/CVE-2021-31252) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-31252.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-31252.svg)


## CVE-2021-31251
 An authentication bypass in telnet server in BF-430 and BF431 232/422 TCP/IP Converter, BF-450M and SEMAC from CHIYU Technology Inc allows obtaining a privileged connection with the target device by supplying a specially malformed request and an attacker may force the remote telnet server to believe that the user has already authenticated.

- [https://github.com/JamesGeeee/CVE-2021-31251](https://github.com/JamesGeeee/CVE-2021-31251) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-31251.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-31251.svg)


## CVE-2021-31250
 Multiple storage XSS vulnerabilities were discovered on BF-430, BF-431 and BF-450M TCP/IP Converter devices from CHIYU Technology Inc due to a lack of sanitization of the input on the components man.cgi, if.cgi, dhcpc.cgi, ppp.cgi.

- [https://github.com/JamesGeeee/CVE-2021-31250](https://github.com/JamesGeeee/CVE-2021-31250) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-31250.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-31250.svg)


## CVE-2021-31249
 A CRLF injection vulnerability was found on BF-430, BF-431, and BF-450M TCP/IP Converter devices from CHIYU Technology Inc due to a lack of validation on the parameter redirect= available on multiple CGI components.

- [https://github.com/JamesGeeee/CVE-2021-31249](https://github.com/JamesGeeee/CVE-2021-31249) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-31249.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-31249.svg)


## CVE-2021-30513
 Type confusion in V8 in Google Chrome prior to 90.0.4430.212 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30513](https://github.com/JamesGeeee/CVE-2021-30513) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30513.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30513.svg)


## CVE-2021-30510
 Use after free in Aura in Google Chrome prior to 90.0.4430.212 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30510](https://github.com/JamesGeeee/CVE-2021-30510) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30510.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30510.svg)


## CVE-2021-30178
 An issue was discovered in the Linux kernel through 5.11.11. synic_get in arch/x86/kvm/hyperv.c has a NULL pointer dereference for certain accesses to the SynIC Hyper-V context, aka CID-919f4ebc5987.

- [https://github.com/JamesGeeee/CVE-2021-30178](https://github.com/JamesGeeee/CVE-2021-30178) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30178.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30178.svg)


## CVE-2021-30159
 An issue was discovered in MediaWiki before 1.31.12 and 1.32.x through 1.35.x before 1.35.2. Users can bypass intended restrictions on deleting pages in certain &quot;fast double move&quot; situations. MovePage::isValidMoveTarget() uses FOR UPDATE, but it's only called if Title::getArticleID() returns non-zero with no special flags. Next, MovePage::moveToInternal() will delete the page if getArticleID(READ_LATEST) is non-zero. Therefore, if the page is missing in the replica DB, isValidMove() will return true, and then moveToInternal() will unconditionally delete the page if it can be found in the master.

- [https://github.com/JamesGeeee/CVE-2021-30159](https://github.com/JamesGeeee/CVE-2021-30159) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30159.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30159.svg)


## CVE-2021-30123
 FFmpeg &lt;=4.3 contains a buffer overflow vulnerability in libavcodec through a crafted file that may lead to remote code execution.

- [https://github.com/JamesGeeee/CVE-2021-30123](https://github.com/JamesGeeee/CVE-2021-30123) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30123.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30123.svg)


## CVE-2021-29642
 GistPad before 0.2.7 allows a crafted workspace folder to change the URL for the Gist API, which leads to leakage of GitHub access tokens.

- [https://github.com/JamesGeeee/CVE-2021-29642](https://github.com/JamesGeeee/CVE-2021-29642) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-29642.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-29642.svg)


## CVE-2021-29500
 bubble fireworks is an open source java package relating to Spring Framework. In bubble fireworks before version 2021.BUILD-SNAPSHOT there is a vulnerability in which the package did not properly verify the signature of JSON Web Tokens. This allows to forgery of valid JWTs.

- [https://github.com/JamesGeeee/CVE-2021-29500](https://github.com/JamesGeeee/CVE-2021-29500) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-29500.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-29500.svg)


## CVE-2021-29440
 Grav is a file based Web-platform. Twig processing of static pages can be enabled in the front matter by any administrative user allowed to create or edit pages. As the Twig processor runs unsandboxed, this behavior can be used to gain arbitrary code execution and elevate privileges on the instance. The issue was addressed in version 1.7.11.

- [https://github.com/CsEnox/CVE-2021-29440](https://github.com/CsEnox/CVE-2021-29440) :  ![starts](https://img.shields.io/github/stars/CsEnox/CVE-2021-29440.svg) ![forks](https://img.shields.io/github/forks/CsEnox/CVE-2021-29440.svg)


## CVE-2021-29417
 gitjacker before 0.1.0 allows remote attackers to execute arbitrary code via a crafted .git directory because of directory traversal.

- [https://github.com/JamesGeeee/CVE-2021-29417](https://github.com/JamesGeeee/CVE-2021-29417) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-29417.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-29417.svg)


## CVE-2021-29272
 bluemonday before 1.0.5 allows XSS because certain Go lowercasing converts an uppercase Cyrillic character, defeating a protection mechanism against the &quot;script&quot; string.

- [https://github.com/JamesGeeee/CVE-2021-29272](https://github.com/JamesGeeee/CVE-2021-29272) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-29272.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-29272.svg)


## CVE-2021-29271
 remark42 before 1.6.1 allows XSS, as demonstrated by &quot;Locator: Locator{URL:&quot; followed by an XSS payload. This is related to backend/app/store/comment.go and backend/app/store/service/service.go.

- [https://github.com/JamesGeeee/CVE-2021-29271](https://github.com/JamesGeeee/CVE-2021-29271) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-29271.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-29271.svg)


## CVE-2021-28453
 Microsoft Word Remote Code Execution Vulnerability

- [https://github.com/JamesGeeee/CVE-2021-28453](https://github.com/JamesGeeee/CVE-2021-28453) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-28453.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-28453.svg)


## CVE-2021-28326
 Windows AppX Deployment Server Denial of Service Vulnerability

- [https://github.com/JamesGeeee/CVE-2021-28326](https://github.com/JamesGeeee/CVE-2021-28326) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-28326.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-28326.svg)


## CVE-2021-28242
 SQL Injection in the &quot;evoadm.php&quot; component of b2evolution v7.2.2-stable allows remote attackers to obtain sensitive database information by injecting SQL commands into the &quot;cf_name&quot; parameter when creating a new filter under the &quot;Collections&quot; tab.

- [https://github.com/JamesGeeee/CVE-2021-28242](https://github.com/JamesGeeee/CVE-2021-28242) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-28242.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-28242.svg)


## CVE-2021-26928
 ** DISPUTED ** BIRD through 2.0.7 does not provide functionality for password authentication of BGP peers. Because of this, products that use BIRD (which may, for example, include Tigera products in some configurations, as well as products of other vendors) may have been susceptible to route redirection for Denial of Service and/or Information Disclosure. NOTE: a researcher has asserted that the behavior is within Tigera&#8217;s area of responsibility; however, Tigera disagrees.

- [https://github.com/JamesGeeee/CVE-2021-26928](https://github.com/JamesGeeee/CVE-2021-26928) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-26928.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-26928.svg)


## CVE-2021-25328
 Skyworth Digital Technology RN510 V.3.1.0.4 RN510 V.3.1.0.4 contains a buffer overflow vulnerability in /cgi-bin/app-staticIP.asp. An authenticated attacker can send a specially crafted request to endpoint which can lead to a denial of service (DoS) or possible code execution on the device.

- [https://github.com/JamesGeeee/CVE-2021-25328](https://github.com/JamesGeeee/CVE-2021-25328) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-25328.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-25328.svg)


## CVE-2021-25327
 Skyworth Digital Technology RN510 V.3.1.0.4 contains a cross-site request forgery (CSRF) vulnerability in /cgi-bin/net-routeadd.asp and /cgi-bin/sec-urlfilter.asp. Missing CSRF protection in devices can lead to XSRF, as the above pages are vulnerable to cross-site scripting (XSS).

- [https://github.com/JamesGeeee/CVE-2021-25327](https://github.com/JamesGeeee/CVE-2021-25327) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-25327.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-25327.svg)


## CVE-2021-25326
 Skyworth Digital Technology RN510 V.3.1.0.4 is affected by an incorrect access control vulnerability in/cgi-bin/test_version.asp. If Wi-Fi is connected but an unauthenticated user visits a URL, the SSID password and web UI password may be disclosed.

- [https://github.com/JamesGeeee/CVE-2021-25326](https://github.com/JamesGeeee/CVE-2021-25326) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-25326.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-25326.svg)


## CVE-2021-25217
 In ISC DHCP 4.1-ESV-R1 -&gt; 4.1-ESV-R16, ISC DHCP 4.4.0 -&gt; 4.4.2 (Other branches of ISC DHCP (i.e., releases in the 4.0.x series or lower and releases in the 4.3.x series) are beyond their End-of-Life (EOL) and no longer supported by ISC. From inspection it is clear that the defect is also present in releases from those series, but they have not been officially tested for the vulnerability), The outcome of encountering the defect while reading a lease that will trigger it varies, according to: the component being affected (i.e., dhclient or dhcpd) whether the package was built as a 32-bit or 64-bit binary whether the compiler flag -fstack-protection-strong was used when compiling In dhclient, ISC has not successfully reproduced the error on a 64-bit system. However, on a 32-bit system it is possible to cause dhclient to crash when reading an improper lease, which could cause network connectivity problems for an affected system due to the absence of a running DHCP client process. In dhcpd, when run in DHCPv4 or DHCPv6 mode: if the dhcpd server binary was built for a 32-bit architecture AND the -fstack-protection-strong flag was specified to the compiler, dhcpd may exit while parsing a lease file containing an objectionable lease, resulting in lack of service to clients. Additionally, the offending lease and the lease immediately following it in the lease database may be improperly deleted. if the dhcpd server binary was built for a 64-bit architecture OR if the -fstack-protection-strong compiler flag was NOT specified, the crash will not occur, but it is possible for the offending lease and the lease which immediately followed it to be improperly deleted.

- [https://github.com/JamesGeeee/CVE-2021-25217](https://github.com/JamesGeeee/CVE-2021-25217) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-25217.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-25217.svg)


## CVE-2021-23987
 Mozilla developers and community members reported memory safety bugs present in Firefox 86 and Firefox ESR 78.8. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox ESR &lt; 78.9, Thunderbird &lt; 78.9, and Firefox &lt; 87.

- [https://github.com/JamesGeeee/CVE-2021-23987](https://github.com/JamesGeeee/CVE-2021-23987) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-23987.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-23987.svg)


## CVE-2021-23986
 A malicious extension with the 'search' permission could have installed a new search engine whose favicon referenced a cross-origin URL. The response to this cross-origin request could have been read by the extension, allowing a same-origin policy bypass by the extension, which should not have cross-origin permissions. This cross-origin request was made without cookies, so the sensitive information disclosed by the violation was limited to local-network resources or resources that perform IP-based authentication. This vulnerability affects Firefox &lt; 87.

- [https://github.com/JamesGeeee/CVE-2021-23986](https://github.com/JamesGeeee/CVE-2021-23986) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-23986.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-23986.svg)


## CVE-2021-23985
 If an attacker is able to alter specific about:config values (for example malware running on the user's computer), the Devtools remote debugging feature could have been enabled in a way that was unnoticable to the user. This would have allowed a remote attacker (able to make a direct network connection to the victim) to monitor the user's browsing activity and (plaintext) network traffic. This was addressed by providing a visual cue when Devtools has an open network socket. This vulnerability affects Firefox &lt; 87.

- [https://github.com/JamesGeeee/CVE-2021-23985](https://github.com/JamesGeeee/CVE-2021-23985) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-23985.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-23985.svg)


## CVE-2021-23984
 A malicious extension could have opened a popup window lacking an address bar. The title of the popup lacking an address bar should not be fully controllable, but in this situation was. This could have been used to spoof a website and attempt to trick the user into providing credentials. This vulnerability affects Firefox ESR &lt; 78.9, Thunderbird &lt; 78.9, and Firefox &lt; 87.

- [https://github.com/JamesGeeee/CVE-2021-23984](https://github.com/JamesGeeee/CVE-2021-23984) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-23984.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-23984.svg)


## CVE-2021-23983
 By causing a transition on a parent node by removing a CSS rule, an invalid property for a marker could have been applied, resulting in memory corruption and a potentially exploitable crash. This vulnerability affects Firefox &lt; 87.

- [https://github.com/JamesGeeee/CVE-2021-23983](https://github.com/JamesGeeee/CVE-2021-23983) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-23983.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-23983.svg)


## CVE-2021-22911
 A improper input sanitization vulnerability exists in Rocket.Chat server 3.11, 3.12 &amp; 3.13 that could lead to unauthenticated NoSQL injection, resulting potentially in RCE.

- [https://github.com/CsEnox/CVE-2021-22911](https://github.com/CsEnox/CVE-2021-22911) :  ![starts](https://img.shields.io/github/stars/CsEnox/CVE-2021-22911.svg) ![forks](https://img.shields.io/github/forks/CsEnox/CVE-2021-22911.svg)


## CVE-2021-22900
 A vulnerability allowed multiple unrestricted uploads in Pulse Connect Secure before 9.1R11.4 that could lead to an authenticated administrator to perform a file write via a maliciously crafted archive upload in the administrator web interface.

- [https://github.com/JamesGeeee/CVE-2021-22900](https://github.com/JamesGeeee/CVE-2021-22900) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-22900.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-22900.svg)


## CVE-2021-22359
 There is a denial of service vulnerability in the verisions V200R005C00SPC500 of S5700 and V200R005C00SPC500 of S6700. An attacker could exploit this vulnerability by sending specific message to a targeted device. Due to insufficient input validation, successful exploit can cause the service abnormal.

- [https://github.com/JamesGeeee/CVE-2021-22359](https://github.com/JamesGeeee/CVE-2021-22359) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-22359.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-22359.svg)


## CVE-2021-22358
 There is an insufficient input validation vulnerability in FusionCompute 8.0.0. Due to the input validation is insufficient, an attacker can exploit this vulnerability to upload any files to the device. Successful exploit may cause the service abnormal.

- [https://github.com/JamesGeeee/CVE-2021-22358](https://github.com/JamesGeeee/CVE-2021-22358) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-22358.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-22358.svg)


## CVE-2021-22207
 Excessive memory consumption in MS-WSP dissector in Wireshark 3.4.0 to 3.4.4 and 3.2.0 to 3.2.12 allows denial of service via packet injection or crafted capture file

- [https://github.com/JamesGeeee/CVE-2021-22207](https://github.com/JamesGeeee/CVE-2021-22207) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-22207.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-22207.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/mr-r3bot/Gitlab-CVE-2021-22205](https://github.com/mr-r3bot/Gitlab-CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/mr-r3bot/Gitlab-CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/mr-r3bot/Gitlab-CVE-2021-22205.svg)


## CVE-2021-22160
 If Apache Pulsar is configured to authenticate clients using tokens based on JSON Web Tokens (JWT), the signature of the token is not validated if the algorithm of the presented token is set to &quot;none&quot;. This allows an attacker to connect to Pulsar instances as any user (incl. admins).

- [https://github.com/JamesGeeee/CVE-2021-22160](https://github.com/JamesGeeee/CVE-2021-22160) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-22160.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-22160.svg)


## CVE-2021-21989
 VMware Workstation (16.x prior to 16.1.2) and Horizon Client for Windows (5.x prior to 5.5.2) contain out-of-bounds read vulnerability in the Cortado ThinPrint component (TTC Parser). A malicious actor with access to a virtual machine or remote desktop may be able to exploit these issues leading to information disclosure from the TPView process running on the system where Workstation or Horizon Client for Windows is installed.

- [https://github.com/JamesGeeee/CVE-2021-21989](https://github.com/JamesGeeee/CVE-2021-21989) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-21989.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-21989.svg)


## CVE-2021-21988
 VMware Workstation (16.x prior to 16.1.2) and Horizon Client for Windows (5.x prior to 5.5.2) contain out-of-bounds read vulnerability in the Cortado ThinPrint component (JPEG2000 Parser). A malicious actor with access to a virtual machine or remote desktop may be able to exploit these issues leading to information disclosure from the TPView process running on the system where Workstation or Horizon Client for Windows is installed.

- [https://github.com/JamesGeeee/CVE-2021-21988](https://github.com/JamesGeeee/CVE-2021-21988) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-21988.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-21988.svg)


## CVE-2021-21987
 VMware Workstation (16.x prior to 16.1.2) and Horizon Client for Windows (5.x prior to 5.5.2) contain out-of-bounds read vulnerability in the Cortado ThinPrint component (TTC Parser). A malicious actor with access to a virtual machine or remote desktop may be able to exploit these issues leading to information disclosure from the TPView process running on the system where Workstation or Horizon Client for Windows is installed.

- [https://github.com/JamesGeeee/CVE-2021-21987](https://github.com/JamesGeeee/CVE-2021-21987) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-21987.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-21987.svg)


## CVE-2021-21985
 The vSphere Client (HTML5) contains a remote code execution vulnerability due to lack of input validation in the Virtual SAN Health Check plug-in which is enabled by default in vCenter Server. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server.

- [https://github.com/testanull/Project_CVE-2021-21985_PoC](https://github.com/testanull/Project_CVE-2021-21985_PoC) :  ![starts](https://img.shields.io/github/stars/testanull/Project_CVE-2021-21985_PoC.svg) ![forks](https://img.shields.io/github/forks/testanull/Project_CVE-2021-21985_PoC.svg)


## CVE-2021-20585
 IBM Security Verify Access 20.07 could disclose sensitive information in HTTP server headers that could be used in further attacks against the system. IBM X-Force ID: 199398.

- [https://github.com/JamesGeeee/CVE-2021-20585](https://github.com/JamesGeeee/CVE-2021-20585) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-20585.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-20585.svg)


## CVE-2021-3448
 A flaw was found in dnsmasq in versions before 2.85. When configured to use a specific server for a given network interface, dnsmasq uses a fixed port while forwarding queries. An attacker on the network, able to find the outgoing port used by dnsmasq, only needs to guess the random transmission ID to forge a reply and get it accepted by dnsmasq. This flaw makes a DNS Cache Poisoning attack much easier. The highest threat from this vulnerability is to data integrity.

- [https://github.com/JamesGeeee/CVE-2021-3448](https://github.com/JamesGeeee/CVE-2021-3448) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-3448.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-3448.svg)


## CVE-2021-3393
 An information leak was discovered in postgresql in versions before 13.2, before 12.6 and before 11.11. A user having UPDATE permission but not SELECT permission to a particular column could craft queries which, under some circumstances, might disclose values from that column in error messages. An attacker could use this flaw to obtain information stored in a column they are allowed to write but not read.

- [https://github.com/JamesGeeee/CVE-2021-3393](https://github.com/JamesGeeee/CVE-2021-3393) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-3393.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-3393.svg)


## CVE-2020-29324
 The DLink Router DIR-895L MFC v1.21b05 is vulnerable to credentials disclosure in telnet service through decompilation of firmware, that allows an unauthenticated attacker to gain access to the firmware and to extract sensitive data.

- [https://github.com/JamesGeeee/CVE-2020-29324](https://github.com/JamesGeeee/CVE-2020-29324) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-29324.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-29324.svg)


## CVE-2020-29323
 The D-link router DIR-885L-MFC 1.15b02, v1.21b05 is vulnerable to credentials disclosure in telnet service through decompilation of firmware, that allows an unauthenticated attacker to gain access to the firmware and to extract sensitive data.

- [https://github.com/JamesGeeee/CVE-2020-29323](https://github.com/JamesGeeee/CVE-2020-29323) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-29323.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-29323.svg)


## CVE-2020-29322
 The D-Link router DIR-880L 1.07 is vulnerable to credentials disclosure in telnet service through decompilation of firmware, that allows an unauthenticated attacker to gain access to the firmware and to extract sensitive data.

- [https://github.com/JamesGeeee/CVE-2020-29322](https://github.com/JamesGeeee/CVE-2020-29322) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-29322.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-29322.svg)


## CVE-2020-29321
 The D-Link router DIR-868L 3.01 is vulnerable to credentials disclosure in telnet service through decompilation of firmware, that allows an unauthenticated attacker to gain access to the firmware and to extract sensitive data.

- [https://github.com/JamesGeeee/CVE-2020-29321](https://github.com/JamesGeeee/CVE-2020-29321) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-29321.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-29321.svg)


## CVE-2020-14882
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/xwuyi/CVE-2020-14882](https://github.com/xwuyi/CVE-2020-14882) :  ![starts](https://img.shields.io/github/stars/xwuyi/CVE-2020-14882.svg) ![forks](https://img.shields.io/github/forks/xwuyi/CVE-2020-14882.svg)


## CVE-2020-13956
 Apache HttpClient versions prior to version 4.5.13 and 5.0.3 can misinterpret malformed authority component in request URIs passed to the library as java.net.URI object and pick the wrong target host for request execution.

- [https://github.com/JamesGeeee/CVE-2020-13956](https://github.com/JamesGeeee/CVE-2020-13956) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-13956.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-13956.svg)


## CVE-2020-13558
 A code execution vulnerability exists in the AudioSourceProviderGStreamer functionality of Webkit WebKitGTK 2.30.1. A specially crafted web page can lead to a use after free.

- [https://github.com/JamesGeeee/CVE-2020-13558](https://github.com/JamesGeeee/CVE-2020-13558) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-13558.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-13558.svg)


## CVE-2019-11932
 A double free vulnerability in the DDGifSlurp function in decoding.c in the android-gif-drawable library before version 1.2.18, as used in WhatsApp for Android before version 2.19.244 and many other Android applications, allows remote attackers to execute arbitrary code or cause a denial of service when the library is used to parse a specially crafted GIF image.

- [https://github.com/alexanderstonec/CVE-2019-11932](https://github.com/alexanderstonec/CVE-2019-11932) :  ![starts](https://img.shields.io/github/stars/alexanderstonec/CVE-2019-11932.svg) ![forks](https://img.shields.io/github/forks/alexanderstonec/CVE-2019-11932.svg)


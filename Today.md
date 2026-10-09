# Update 2026-10-09
## CVE-2026-105844
 Payload is a free and open source headless content management system. In versions from 3.0.0 before 3.88.0 and canary versions before 4.0.0-canary.27, an unauthenticated user can submit prototype-sensitive field paths when @payloadcms/plugin-import-export is enabled, causing unintended application behavior that can lead to remote code execution. This issue is fixed in versions 3.88.0 and 4.0.0-canary.27.

- [https://github.com/murrez/CVE-2026-105844](https://github.com/murrez/CVE-2026-105844) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-105844.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-105844.svg)


## CVE-2026-102782
 Joomla Extension - ordasoft.com - Unauthenticated SQL injection in OrdaSoft Simple Membership  7.4.0 - site/simplemembership.php dispatches task=checkLoginPass with no authentication or access control check of any kind. The handler reads a login request parameter through Joomla’s generic, non-sanitizing input filter, which strips HTML/script tags but never touches quotes or SQL syntax, and concatenates it directly into a query string with no escaping or parameterization:

- [https://github.com/murrez/CVE-2026-102782](https://github.com/murrez/CVE-2026-102782) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-102782.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-102782.svg)


## CVE-2026-102489
 Zammad versions 6.3.0 to 6.5.4 are vulnerable a session hijack vulnerability that leads to remote code execution as the zammad user. The bug is also present in version 7.0.0 to version 7.1.2, but not exploitable due to changes in the underlying framework.

- [https://github.com/horizon3ai/CVE-2026-102489](https://github.com/horizon3ai/CVE-2026-102489) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2026-102489.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2026-102489.svg)
- [https://github.com/Hunt-Benito/the-cookie-in-the-error-message-cve-2026-102489-zammad-session-hijack-to-rce](https://github.com/Hunt-Benito/the-cookie-in-the-error-message-cve-2026-102489-zammad-session-hijack-to-rce) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/the-cookie-in-the-error-message-cve-2026-102489-zammad-session-hijack-to-rce.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/the-cookie-in-the-error-message-cve-2026-102489-zammad-session-hijack-to-rce.svg)


## CVE-2026-102422
 shell-quote's `quote()` function emits a `{ comment }` token as `#` followed by its text, which comments out the rest of the shell line, including the opening quote of any later string token. A line terminator (\n, \r, U+2028, U+2029) in that later string therefore ends the comment, and the rest of the string is parsed as shell input: `quote(['echo', 'ok', { comment: 'x' }, 'a\nid;#'])` runs `id` in sh, bash, dash, ksh and zsh. `parse()` emits a comment token for a `#` in the middle of a word (for example `http://example.com/#frag`), so callers that combine `parse()` output with another untrusted string, such as `quote(parse(untrustedCommand).concat(untrustedArg))`, are affected. The fix for CVE-2026-9277 rejected line terminators in the comment's own text, but not in the tokens after it. Fixed in 1.11.0: `quote()` throws a `TypeError` when a string after a `{ comment }` token contains a line terminator.

- [https://github.com/DevVaibhav07/CVE-2026-102422](https://github.com/DevVaibhav07/CVE-2026-102422) :  ![starts](https://img.shields.io/github/stars/DevVaibhav07/CVE-2026-102422.svg) ![forks](https://img.shields.io/github/forks/DevVaibhav07/CVE-2026-102422.svg)


## CVE-2026-102253
 iperf3 versions prior to 3.22 contains a denial of service vulnerability that allows unauthenticated remote attackers to crash-loop the server's UDP receive worker into an unrecoverable infinite loop by sending a single crafted control-channel parameter message followed by one 16-byte UDP datagram. Attackers can permanently pin the affected per-stream receive thread at approximately 100% CPU usage, rendering the server unusable until forcibly killed with SIGKILL, as the process does not respond to normal control-channel closure.

- [https://github.com/Ravi-lk/CVE-2026-102253-POC](https://github.com/Ravi-lk/CVE-2026-102253-POC) :  ![starts](https://img.shields.io/github/stars/Ravi-lk/CVE-2026-102253-POC.svg) ![forks](https://img.shields.io/github/forks/Ravi-lk/CVE-2026-102253-POC.svg)


## CVE-2026-101162
 The WP Ultimate Review WordPress plugin before 2.4.4 does not escape some of its review overview settings before outputting them in posts, which could allow users with a role as low as author to perform Stored Cross-Site Scripting attacks, when author reviews are enabled.

- [https://github.com/Hasyros/CVE-2026-101162-xss-wp-ultimate-review](https://github.com/Hasyros/CVE-2026-101162-xss-wp-ultimate-review) :  ![starts](https://img.shields.io/github/stars/Hasyros/CVE-2026-101162-xss-wp-ultimate-review.svg) ![forks](https://img.shields.io/github/forks/Hasyros/CVE-2026-101162-xss-wp-ultimate-review.svg)


## CVE-2026-101161
 The WP Ultimate Review WordPress plugin before 2.4.4 does not prevent unauthenticated users from storing crafted review content that makes the reviewed page fail with a fatal error on every subsequent visit, resulting in a persistent denial of service when the WP Ultimate Review WordPress plugin before 2.4.4's review display settings have never been saved.

- [https://github.com/Hasyros/CVE-2026-101161-dos-wp-ultimate-review-shortcode](https://github.com/Hasyros/CVE-2026-101161-dos-wp-ultimate-review-shortcode) :  ![starts](https://img.shields.io/github/stars/Hasyros/CVE-2026-101161-dos-wp-ultimate-review-shortcode.svg) ![forks](https://img.shields.io/github/forks/Hasyros/CVE-2026-101161-dos-wp-ultimate-review-shortcode.svg)


## CVE-2026-101160
 The WP Ultimate Review WordPress plugin before 2.4.4 does not validate that a submitted review rating is numeric before storing it and later using it in numeric operations when rendering reviews, allowing unauthenticated users to make the reviewed content fail with a fatal error for all visitors until the review is removed (a persistent denial of service), when user reviews are enabled.

- [https://github.com/Hasyros/CVE-2026-101160-dos-wp-ultimate-review-rating](https://github.com/Hasyros/CVE-2026-101160-dos-wp-ultimate-review-rating) :  ![starts](https://img.shields.io/github/stars/Hasyros/CVE-2026-101160-dos-wp-ultimate-review-rating.svg) ![forks](https://img.shields.io/github/forks/Hasyros/CVE-2026-101160-dos-wp-ultimate-review-rating.svg)


## CVE-2026-97332
 The User Private Files  WordPress plugin before 2.2.0 does not properly protect its stored private files on multisite installations, where the rewrite rule it relies on to route file requests through its access check is never reached, allowing unauthenticated users to retrieve other users' private files directly.

- [https://github.com/Kolya080808/CVE-2026-97332-PoC](https://github.com/Kolya080808/CVE-2026-97332-PoC) :  ![starts](https://img.shields.io/github/stars/Kolya080808/CVE-2026-97332-PoC.svg) ![forks](https://img.shields.io/github/forks/Kolya080808/CVE-2026-97332-PoC.svg)


## CVE-2026-96451
 Authorization Bypass Through User-Controlled Key vulnerability in Ultimate Member Ultimate Member ultimate-member allows Privilege Escalation.This issue affects Ultimate Member: from n/a through 2.13.1.

- [https://github.com/MRdark-ops/wpexploit-CVE-2026-96451](https://github.com/MRdark-ops/wpexploit-CVE-2026-96451) :  ![starts](https://img.shields.io/github/stars/MRdark-ops/wpexploit-CVE-2026-96451.svg) ![forks](https://img.shields.io/github/forks/MRdark-ops/wpexploit-CVE-2026-96451.svg)


## CVE-2026-93674
 IBM Langflow OSS 1.0.0 through 1.12.2 could allow a remote attacker to execute arbitrary code due to improper neutralization of special elements used in an OS command.

- [https://github.com/rmhowe425/POC-CVE-2026-93674](https://github.com/rmhowe425/POC-CVE-2026-93674) :  ![starts](https://img.shields.io/github/stars/rmhowe425/POC-CVE-2026-93674.svg) ![forks](https://img.shields.io/github/forks/rmhowe425/POC-CVE-2026-93674.svg)


## CVE-2026-93661
 The Events Manager  WordPress plugin before 7.4.5 does not stop a ticket-update request from replacing the identifiers of the ticket it was authorized against, letting a user who can manage one event's tickets overwrite and reassign any ticket on the site to their own event.

- [https://github.com/Hasyros/CVE-2026-93661-idor-events-manager](https://github.com/Hasyros/CVE-2026-93661-idor-events-manager) :  ![starts](https://img.shields.io/github/stars/Hasyros/CVE-2026-93661-idor-events-manager.svg) ![forks](https://img.shields.io/github/forks/Hasyros/CVE-2026-93661-idor-events-manager.svg)


## CVE-2026-93355
 LiteLLM contains a weak authentication vulnerability that allows an attacker holding a valid JWT from the configured identity provider to authenticate as any existing user by exploiting an email-based fallback lookup in the JWT authentication flow without verifying the email_verified claim. Attackers can present a token with an unverified email address matching a victim's account to inherit the victim's role, including proxy_admin privileges, and permanently overwrite the victim's stored identity binding to retain persistent unauthorized access to administrative endpoints exposing API keys and user management.

- [https://github.com/InertFluid/cve-2026-93355-lab](https://github.com/InertFluid/cve-2026-93355-lab) :  ![starts](https://img.shields.io/github/stars/InertFluid/cve-2026-93355-lab.svg) ![forks](https://img.shields.io/github/forks/InertFluid/cve-2026-93355-lab.svg)


## CVE-2026-90977
 The Clean Login WordPress plugin before 1.19 does not verify its registration CAPTCHA when the stored session value is empty, allowing unauthenticated users to bypass the anti-automation control on the registration form and create accounts without solving it.

- [https://github.com/aminquliyev057/CVE-2026-90977](https://github.com/aminquliyev057/CVE-2026-90977) :  ![starts](https://img.shields.io/github/stars/aminquliyev057/CVE-2026-90977.svg) ![forks](https://img.shields.io/github/forks/aminquliyev057/CVE-2026-90977.svg)


## CVE-2026-88778
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23.

- [https://github.com/grupooruss/netscaler-defensive-checker](https://github.com/grupooruss/netscaler-defensive-checker) :  ![starts](https://img.shields.io/github/stars/grupooruss/netscaler-defensive-checker.svg) ![forks](https://img.shields.io/github/forks/grupooruss/netscaler-defensive-checker.svg)


## CVE-2026-88771
This issue affects ADC: before 14.1-73.37, before 13.1-64.23, before 14.1-73.37 FIPS, and before 13.1.37.279 FIPS and NDcPP; Gateway: before 14.1-73.37 and before 13.1-64.23 leading to an unauthenticated attacker to execute arbitrary commands.

- [https://github.com/grupooruss/netscaler-defensive-checker](https://github.com/grupooruss/netscaler-defensive-checker) :  ![starts](https://img.shields.io/github/stars/grupooruss/netscaler-defensive-checker.svg) ![forks](https://img.shields.io/github/forks/grupooruss/netscaler-defensive-checker.svg)
- [https://github.com/watchtowrlabs/citrix-netscaler-cve-2026-88771-iocs](https://github.com/watchtowrlabs/citrix-netscaler-cve-2026-88771-iocs) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/citrix-netscaler-cve-2026-88771-iocs.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/citrix-netscaler-cve-2026-88771-iocs.svg)


## CVE-2026-87902
 An unauthenticated attacker can make `get_page_template()` page-template resolution include a chosen readable local `.php` file outside the active theme directories. If relevant pre-conditions for both the server and the active theme are met, this can lead to RCE.

- [https://github.com/xiaxiu555/cve-2026-87902](https://github.com/xiaxiu555/cve-2026-87902) :  ![starts](https://img.shields.io/github/stars/xiaxiu555/cve-2026-87902.svg) ![forks](https://img.shields.io/github/forks/xiaxiu555/cve-2026-87902.svg)


## CVE-2026-85102
 Improper certificate trust validation during VPN negotiation in Check Point Quantum Security Gateway may allow an unauthenticated remote attacker to execute arbitrary code on the Gateway.

- [https://github.com/aduli198/CVE-2026-85102](https://github.com/aduli198/CVE-2026-85102) :  ![starts](https://img.shields.io/github/stars/aduli198/CVE-2026-85102.svg) ![forks](https://img.shields.io/github/forks/aduli198/CVE-2026-85102.svg)


## CVE-2026-82531
 Smarty before 4.5.8 and 5.x before 5.8.5 contains a code injection vulnerability where the top-level nocache_hash is never restored during extends:/multi-component template inheritance, leaving it null. Attackers can supply assigned data containing a forged SmartyNocache marker that is copied verbatim into the regenerated PHP cache file, executing arbitrary PHP on include for remote code execution.

- [https://github.com/murrez/CVE-2026-82531](https://github.com/murrez/CVE-2026-82531) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-82531.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-82531.svg)


## CVE-2026-81780
 Unauthenticated Arbitrary File Upload in Hash Form = 1.4.2 versions.

- [https://github.com/0xCyp1337/CVE-2026-81780](https://github.com/0xCyp1337/CVE-2026-81780) :  ![starts](https://img.shields.io/github/stars/0xCyp1337/CVE-2026-81780.svg) ![forks](https://img.shields.io/github/forks/0xCyp1337/CVE-2026-81780.svg)


## CVE-2026-76555
 The WP Import Export Lite WordPress plugin before 3.9.33 does not validate a user-supplied file path before reading it and copying it into a publicly accessible directory, allowing any user whose role an administrator has granted the WP Import Export Lite WordPress plugin before 3.9.33's import permission to disclose sensitive files from the server, including files located outside the web root. The same code path also relaxes the file-system permissions of any path it is given, whether or not the copy succeeds.

- [https://github.com/Hasyros/CVE-2026-76555-path-traversal-wp-import-export-lite](https://github.com/Hasyros/CVE-2026-76555-path-traversal-wp-import-export-lite) :  ![starts](https://img.shields.io/github/stars/Hasyros/CVE-2026-76555-path-traversal-wp-import-export-lite.svg) ![forks](https://img.shields.io/github/forks/Hasyros/CVE-2026-76555-path-traversal-wp-import-export-lite.svg)


## CVE-2026-72898
 Metabase allows a remote, unauthenticated attacker to inject arbitrary SQL via the '/reset_password' database endpoint and gain administrator access to the connected Metabase instance.

- [https://github.com/amier-ge/CVE-2026-72898](https://github.com/amier-ge/CVE-2026-72898) :  ![starts](https://img.shields.io/github/stars/amier-ge/CVE-2026-72898.svg) ![forks](https://img.shields.io/github/forks/amier-ge/CVE-2026-72898.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/manpisetsu/wp2shell](https://github.com/manpisetsu/wp2shell) :  ![starts](https://img.shields.io/github/stars/manpisetsu/wp2shell.svg) ![forks](https://img.shields.io/github/forks/manpisetsu/wp2shell.svg)


## CVE-2026-62911
 Authentication bypass by capture-replay in Microsoft Exchange Server allows an authorized attacker to elevate privileges over a network.

- [https://github.com/bhavik08-gone/CVE-2026-62911-info](https://github.com/bhavik08-gone/CVE-2026-62911-info) :  ![starts](https://img.shields.io/github/stars/bhavik08-gone/CVE-2026-62911-info.svg) ![forks](https://img.shields.io/github/forks/bhavik08-gone/CVE-2026-62911-info.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/manpisetsu/wp2shell](https://github.com/manpisetsu/wp2shell) :  ![starts](https://img.shields.io/github/stars/manpisetsu/wp2shell.svg) ![forks](https://img.shields.io/github/forks/manpisetsu/wp2shell.svg)


## CVE-2026-59358
Exploitation requires a valid user access token (the attacker’s own) for a client that is configured to support both a public, user-facing authorization flow and the client_credentials grant type on the same client_id — a non-default combination. Practical impact scales with the authorities assigned to that client.

- [https://github.com/abraxas/CVE-2026-59358](https://github.com/abraxas/CVE-2026-59358) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-59358.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-59358.svg)


## CVE-2026-59346
- VMware Fusion: 25H2, 26H1 (fixed in 26H1u1)

- [https://github.com/0xCyberstan/CVE-2026-59346-POC](https://github.com/0xCyberstan/CVE-2026-59346-POC) :  ![starts](https://img.shields.io/github/stars/0xCyberstan/CVE-2026-59346-POC.svg) ![forks](https://img.shields.io/github/forks/0xCyberstan/CVE-2026-59346-POC.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/HirokiAkihiko/dirtyfrag-research](https://github.com/HirokiAkihiko/dirtyfrag-research) :  ![starts](https://img.shields.io/github/stars/HirokiAkihiko/dirtyfrag-research.svg) ![forks](https://img.shields.io/github/forks/HirokiAkihiko/dirtyfrag-research.svg)


## CVE-2026-33439
 Open Access Management (OpenAM) is an access management solution. Prior to 16.0.6, OpenIdentityPlatform OpenAM is vulnerable to pre-authentication Remote Code Execution (RCE) via unsafe Java deserialization of the jato.clientSession HTTP parameter. This bypasses the WhitelistObjectInputStream mitigation that was applied to the jato.pageSession parameter after CVE-2021-35464. An unauthenticated attacker can achieve arbitrary command execution on the server by sending a crafted serialized Java object as the jato.clientSession GET/POST parameter to any JATO ViewBean endpoint whose JSP contains jato:form tags (e.g., the Password Reset pages). This vulnerability is fixed in 16.0.6.

- [https://github.com/amis13/openam-clean](https://github.com/amis13/openam-clean) :  ![starts](https://img.shields.io/github/stars/amis13/openam-clean.svg) ![forks](https://img.shields.io/github/forks/amis13/openam-clean.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/Yoksulcvt/CVE-2026-24061-Telnet-Authentication-Bypass](https://github.com/Yoksulcvt/CVE-2026-24061-Telnet-Authentication-Bypass) :  ![starts](https://img.shields.io/github/stars/Yoksulcvt/CVE-2026-24061-Telnet-Authentication-Bypass.svg) ![forks](https://img.shields.io/github/forks/Yoksulcvt/CVE-2026-24061-Telnet-Authentication-Bypass.svg)


## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.

- [https://github.com/01xJB/CVE-2026-23744-POC](https://github.com/01xJB/CVE-2026-23744-POC) :  ![starts](https://img.shields.io/github/stars/01xJB/CVE-2026-23744-POC.svg) ![forks](https://img.shields.io/github/forks/01xJB/CVE-2026-23744-POC.svg)


## CVE-2026-21589
 This is a vulnerability in Bitbucket Data Center, Confluence Data Center, Jira Service Management Data Center, Jira Software Data Center, Bamboo Data Center. Crowd Data Center, Crucible and Fisheye. This Arbitrary File Access vulnerability allows an unauthenticated attacker to access specific files within the web application root directory in affected versions. Exploitation requires prior knowledge of the target file's exact name and path; this vulnerability does not allow attackers to enumerate or list directory contents. In some configurations, there may be some sensitive files that make this highly severe. This vulnerability allows an unauthenticated remote attacker to access specific files within the web application root directory in affected versions. The vulnerability must be addressed for affected versions of: -- Bitbucket Data Center, introduced in version = 4.6.0, fix versions: 9.4.26, 10.2.8, 10.5.1 -- Confluence Data Center, introduced in version = 5.10.0, fix versions 9.2.26, 10.2.19 -- Crowd Data Center, introduced in version = 2.11.0, fix versions 6.3.7, 7.0.3, 7.1.7, 7.2.4 -- Jira Software Data Center, introduced in version = 7.1.0, fix versions 9.12.40, 10.3.26, 11.3.12 -- Jira Service Management Data Center, introduced in version = 3.1.0, fix versions 5.12.40, 10.3.26, 11.3.12 -- Bamboo Data Center = 7.0.1, fix versions 10.2.24, 12.1.12 -- Crucible, fix versions 4.9.15 -- Fisheye, fix version 4.9.15 -- Exploitation requires prior knowledge of the target file's exact name and path. The vulnerability does not include the capability to enumerate or list directory contents.

- [https://github.com/ynsmroztas/AtlasSniper](https://github.com/ynsmroztas/AtlasSniper) :  ![starts](https://img.shields.io/github/stars/ynsmroztas/AtlasSniper.svg) ![forks](https://img.shields.io/github/forks/ynsmroztas/AtlasSniper.svg)
- [https://github.com/0xBlackash/CVE-2026-21589](https://github.com/0xBlackash/CVE-2026-21589) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-21589.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-21589.svg)
- [https://github.com/BimBoxH4/CVE-2026-21589](https://github.com/BimBoxH4/CVE-2026-21589) :  ![starts](https://img.shields.io/github/stars/BimBoxH4/CVE-2026-21589.svg) ![forks](https://img.shields.io/github/forks/BimBoxH4/CVE-2026-21589.svg)
- [https://github.com/aduli198/CVE-2026-21589](https://github.com/aduli198/CVE-2026-21589) :  ![starts](https://img.shields.io/github/stars/aduli198/CVE-2026-21589.svg) ![forks](https://img.shields.io/github/forks/aduli198/CVE-2026-21589.svg)


## CVE-2026-13043
 A missing authentication vulnerability in the Kernel Memory Access Driver (PSKMAD) used by WatchGuard endpoint security products allows a local, authenticated attacker to bypass the driver's access-control handshake and issue arbitrary privileged commands to the driver, resulting in disclosure of kernel and process memory.

- [https://github.com/TheMalwareGuardian/CVE-2026-13043](https://github.com/TheMalwareGuardian/CVE-2026-13043) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2026-13043.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2026-13043.svg)


## CVE-2026-10520
 An OS Command Injection vulnerability in Ivanti Sentry before the R10.5.2, R10.6.2 and R10.7.1 versions allows a remote unauthenticated user to achieve root-level remote code execution

- [https://github.com/01xJB/CVE-2026-10520-POC](https://github.com/01xJB/CVE-2026-10520-POC) :  ![starts](https://img.shields.io/github/stars/01xJB/CVE-2026-10520-POC.svg) ![forks](https://img.shields.io/github/forks/01xJB/CVE-2026-10520-POC.svg)


## CVE-2026-5430
Successful exploitation of this vulnerability may result in unauthorized access to the system, including the potential compromise of administrative accounts and full account takeover. The CVSS score is adjusted to 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) in single-tenant deployments, reflecting that the impact is contained within a single security authority boundary.

- [https://github.com/davidvrns/CVE-2026-5430-WSO2](https://github.com/davidvrns/CVE-2026-5430-WSO2) :  ![starts](https://img.shields.io/github/stars/davidvrns/CVE-2026-5430-WSO2.svg) ![forks](https://img.shields.io/github/forks/davidvrns/CVE-2026-5430-WSO2.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/tematemaru/CVE-2026-31431-simple-test](https://github.com/tematemaru/CVE-2026-31431-simple-test) :  ![starts](https://img.shields.io/github/stars/tematemaru/CVE-2026-31431-simple-test.svg) ![forks](https://img.shields.io/github/forks/tematemaru/CVE-2026-31431-simple-test.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)


## CVE-2025-58226
 Insertion of Sensitive Information Into Sent Data vulnerability in iberezansky 3D FlipBook – PDF Flipbook Viewer, Flipbook Image Gallery interactive-3d-flipbook-powered-physics-engine allows Retrieve Embedded Sensitive Data.This issue affects 3D FlipBook – PDF Flipbook Viewer, Flipbook Image Gallery: from n/a through = 1.16.16.

- [https://github.com/QASIM1401/CVE-2025-58226-PoC](https://github.com/QASIM1401/CVE-2025-58226-PoC) :  ![starts](https://img.shields.io/github/stars/QASIM1401/CVE-2025-58226-PoC.svg) ![forks](https://img.shields.io/github/forks/QASIM1401/CVE-2025-58226-PoC.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/sungue1/CVE-2025-29927](https://github.com/sungue1/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/sungue1/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/sungue1/CVE-2025-29927.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)


## CVE-2024-38063
 Windows TCP/IP Remote Code Execution Vulnerability

- [https://github.com/ntru0/CVE_2024_38063_homelab](https://github.com/ntru0/CVE_2024_38063_homelab) :  ![starts](https://img.shields.io/github/stars/ntru0/CVE_2024_38063_homelab.svg) ![forks](https://img.shields.io/github/forks/ntru0/CVE_2024_38063_homelab.svg)


## CVE-2024-23652
 BuildKit is a toolkit for converting source code to build artifacts in an efficient, expressive and repeatable manner. A malicious BuildKit frontend or Dockerfile using RUN --mount could trick the feature that removes empty files created for the mountpoints into removing a file outside the container, from the host system. The issue has been fixed in v0.12.5. Workarounds include avoiding using BuildKit frontends from an untrusted source or building an untrusted Dockerfile containing RUN --mount feature.

- [https://github.com/hgyc/CVE-stand](https://github.com/hgyc/CVE-stand) :  ![starts](https://img.shields.io/github/stars/hgyc/CVE-stand.svg) ![forks](https://img.shields.io/github/forks/hgyc/CVE-stand.svg)


## CVE-2024-14027
a71874379ec8 ("xattr: switch to CLASS(fd)").

- [https://github.com/lcfr-hax/CVE-2024-14027_slop](https://github.com/lcfr-hax/CVE-2024-14027_slop) :  ![starts](https://img.shields.io/github/stars/lcfr-hax/CVE-2024-14027_slop.svg) ![forks](https://img.shields.io/github/forks/lcfr-hax/CVE-2024-14027_slop.svg)


## CVE-2024-7971
 Type confusion in V8 in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/pepoc3/cve-2024-7971-poc](https://github.com/pepoc3/cve-2024-7971-poc) :  ![starts](https://img.shields.io/github/stars/pepoc3/cve-2024-7971-poc.svg) ![forks](https://img.shields.io/github/forks/pepoc3/cve-2024-7971-poc.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/osungjinwoo/CVE-2022-22965](https://github.com/osungjinwoo/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/osungjinwoo/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/osungjinwoo/CVE-2022-22965.svg)


## CVE-2022-2296
 Use after free in Chrome OS Shell in Google Chrome on Chrome OS prior to 103.0.5060.114 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via direct UI interactions.

- [https://github.com/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE](https://github.com/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE) :  ![starts](https://img.shields.io/github/stars/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE.svg) ![forks](https://img.shields.io/github/forks/shoucheng3/spring-projects__spring-framework_CVE-2022-22965_5-2-19-RELEASE.svg)


## CVE-2022-0492
 A vulnerability was found in the Linux kernel’s cgroup_release_agent_write in the kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.

- [https://github.com/hgyc/CVE-stand](https://github.com/hgyc/CVE-stand) :  ![starts](https://img.shields.io/github/stars/hgyc/CVE-stand.svg) ![forks](https://img.shields.io/github/forks/hgyc/CVE-stand.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/0xrogg/CVE-2021-41773](https://github.com/0xrogg/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/0xrogg/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/0xrogg/CVE-2021-41773.svg)


## CVE-2021-38759
 Raspberry Pi OS through 5.10 has the raspberry default password for the pi account. If not changed, attackers can gain administrator privileges.

- [https://github.com/Hu2ie/CVE-2021-38759](https://github.com/Hu2ie/CVE-2021-38759) :  ![starts](https://img.shields.io/github/stars/Hu2ie/CVE-2021-38759.svg) ![forks](https://img.shields.io/github/forks/Hu2ie/CVE-2021-38759.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/osungjinwoo/CVE-2021-22205-gitlab](https://github.com/osungjinwoo/CVE-2021-22205-gitlab) :  ![starts](https://img.shields.io/github/stars/osungjinwoo/CVE-2021-22205-gitlab.svg) ![forks](https://img.shields.io/github/forks/osungjinwoo/CVE-2021-22205-gitlab.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/mightysai1997/cve-2021-41773](https://github.com/mightysai1997/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/mightysai1997/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/cve-2021-41773.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/WJNKAC/cve-2019-2215-oppo-a77t](https://github.com/WJNKAC/cve-2019-2215-oppo-a77t) :  ![starts](https://img.shields.io/github/stars/WJNKAC/cve-2019-2215-oppo-a77t.svg) ![forks](https://img.shields.io/github/forks/WJNKAC/cve-2019-2215-oppo-a77t.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/diceverick/vulnerability-assessment-lab](https://github.com/diceverick/vulnerability-assessment-lab) :  ![starts](https://img.shields.io/github/stars/diceverick/vulnerability-assessment-lab.svg) ![forks](https://img.shields.io/github/forks/diceverick/vulnerability-assessment-lab.svg)


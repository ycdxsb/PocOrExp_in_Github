# Update 2026-09-14
## CVE-2026-83991
 Missing authentication for critical function in Windows Cloud Files Mini Filter Driver allows an authorized attacker to perform tampering locally.

- [https://github.com/karollooool/CVE-2026-83991-writeup-and-poc](https://github.com/karollooool/CVE-2026-83991-writeup-and-poc) :  ![starts](https://img.shields.io/github/stars/karollooool/CVE-2026-83991-writeup-and-poc.svg) ![forks](https://img.shields.io/github/forks/karollooool/CVE-2026-83991-writeup-and-poc.svg)


## CVE-2026-79617
This issue affects Pardus LightDM Greeter: before 0.4.15.

- [https://github.com/alpernae/CVE-2026-79617](https://github.com/alpernae/CVE-2026-79617) :  ![starts](https://img.shields.io/github/stars/alpernae/CVE-2026-79617.svg) ![forks](https://img.shields.io/github/forks/alpernae/CVE-2026-79617.svg)


## CVE-2026-79387
 SQL injection vulnerability in PbootCMS versions 3.2.0 through 3.2.5 allows an authenticated user to modify arbitrary user account fields (including passwords and roles) via crafted parameters to the User/mod interface, enabling account takeover.

- [https://github.com/jhli07/CVE-2026-79387-PbootCMS-SQL-Injection](https://github.com/jhli07/CVE-2026-79387-PbootCMS-SQL-Injection) :  ![starts](https://img.shields.io/github/stars/jhli07/CVE-2026-79387-PbootCMS-SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/jhli07/CVE-2026-79387-PbootCMS-SQL-Injection.svg)


## CVE-2026-76578
 A flaw was found in FreeIPA. The self-managed OTP token ACI does not require authentication and does not restrict which attributes may be added alongside the token entry. An unauthenticated LDAP client can exploit this, combined with a related flaw in the underlying directory server's ACI evaluation (tracked separately), to create an arbitrary attacker-controlled Kerberos principal and have it added to the administrators group. This allows a remote, unauthenticated attacker to obtain genuine FreeIPA administrator-group membership and perform administrative operations against the directory and, on SID-enabled deployments, other IdM services.

- [https://github.com/BrainBob/CVE-2026-76578](https://github.com/BrainBob/CVE-2026-76578) :  ![starts](https://img.shields.io/github/stars/BrainBob/CVE-2026-76578.svg) ![forks](https://img.shields.io/github/forks/BrainBob/CVE-2026-76578.svg)


## CVE-2026-75650
 Adobe Commerce is affected by an Improper Neutralization of Special Elements Used in a Template Engine vulnerability that could result in arbitrary code execution in the context of the current user. An attacker could exploit this vulnerability to execute arbitrary code. Exploitation of this issue does not require user interaction. Scope is changed.

- [https://github.com/jithinkrishnanrs/stylesmuggler-ioc-toolkit](https://github.com/jithinkrishnanrs/stylesmuggler-ioc-toolkit) :  ![starts](https://img.shields.io/github/stars/jithinkrishnanrs/stylesmuggler-ioc-toolkit.svg) ![forks](https://img.shields.io/github/forks/jithinkrishnanrs/stylesmuggler-ioc-toolkit.svg)


## CVE-2026-74586
create the HEARTBEAT.

- [https://github.com/TarPeg007/CVE-2026-74586](https://github.com/TarPeg007/CVE-2026-74586) :  ![starts](https://img.shields.io/github/stars/TarPeg007/CVE-2026-74586.svg) ![forks](https://img.shields.io/github/forks/TarPeg007/CVE-2026-74586.svg)


## CVE-2026-73570
 A remote code execution vulnerability exists in Zimbra Collaboration (ZCS) before 10.1.20 when the optional zimbra-snmp package is installed and SNMP notifications are enabled. Due to improper sanitization of untrusted input during SNMP notification processing, an unauthenticated attacker can send specially crafted SMTP requests that may result in execution of arbitrary operating system commands as the Zimbra user.

- [https://github.com/hainhc/CVE-2026-73570](https://github.com/hainhc/CVE-2026-73570) :  ![starts](https://img.shields.io/github/stars/hainhc/CVE-2026-73570.svg) ![forks](https://img.shields.io/github/forks/hainhc/CVE-2026-73570.svg)


## CVE-2026-72815
 go-chi chi versions = 5.2.1 and before 5.3.0 contain an IP spoofing vulnerability in the RealIP middleware, which blindly trusts the first (leftmost) value of the X-Forwarded-For HTTP header. A remote attacker can bypass IP-based access control lists and rate-limiting mechanisms, and forge log entries, by supplying a spoofed IP address in the X-Forwarded-For header. The issue is fixed in version 5.3.0.

- [https://github.com/Saku0512/CVE-2026-72815-poc](https://github.com/Saku0512/CVE-2026-72815-poc) :  ![starts](https://img.shields.io/github/stars/Saku0512/CVE-2026-72815-poc.svg) ![forks](https://img.shields.io/github/forks/Saku0512/CVE-2026-72815-poc.svg)


## CVE-2026-67401
 A vulnerability in cPanel allows a mail-enabled account to achieve remote code execution as root through SQLi in EmailTrack component

- [https://github.com/axedos/CVE-2026-67401](https://github.com/axedos/CVE-2026-67401) :  ![starts](https://img.shields.io/github/stars/axedos/CVE-2026-67401.svg) ![forks](https://img.shields.io/github/forks/axedos/CVE-2026-67401.svg)
- [https://github.com/HORKimhab/CVE-2026-67401](https://github.com/HORKimhab/CVE-2026-67401) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-67401.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-67401.svg)
- [https://github.com/jithinkrishnanrs/CVE-2026-67401-cPanel-EmailTrack-SQLi](https://github.com/jithinkrishnanrs/CVE-2026-67401-cPanel-EmailTrack-SQLi) :  ![starts](https://img.shields.io/github/stars/jithinkrishnanrs/CVE-2026-67401-cPanel-EmailTrack-SQLi.svg) ![forks](https://img.shields.io/github/forks/jithinkrishnanrs/CVE-2026-67401-cPanel-EmailTrack-SQLi.svg)


## CVE-2026-67276
 RouterOS does not compare the complete RSA public key when matching an SSH authentication request to an authorized user key, checking the key type and modulus but omitting the exponent. Because signature verification uses the client-supplied key, an attacker knowing an authorized RSA modulus can supply a key with exponent one, forge a valid signature, and open an SSH command channel as the target user without the private key.This issue affects only 7.x branch was fixed in versions: 7.23.4 (Long-term) and 7.24.2 (Stable)

- [https://github.com/4rt-Net/Mikrotrick_POC](https://github.com/4rt-Net/Mikrotrick_POC) :  ![starts](https://img.shields.io/github/stars/4rt-Net/Mikrotrick_POC.svg) ![forks](https://img.shields.io/github/forks/4rt-Net/Mikrotrick_POC.svg)


## CVE-2026-66066
 Action Pack is a framework for handling and responding to web requests. In versions prior to 7.2.3.2, 8.0.5.1 and 8.1.3.1, Active Storage does not disable libvips operations marked unsafe for untrusted content, allowing a crafted upload to invoke such an operation. Consuming applications are affected when configured to use libvips and accept image uploads from untrusted users. An unauthenticated attacker may exploit this behavior to read arbitrary files accessible to the Rails process, including environment variables and application secrets. Exposure of credentials such as secret_key_base or external-service tokens may enable remote code execution or lateral movement. This issue has been fixed in versions 7.2.3.2, 8.0.5.1 and 8.1.3.1.

- [https://github.com/ivanesk315/CVE-2026-66066](https://github.com/ivanesk315/CVE-2026-66066) :  ![starts](https://img.shields.io/github/stars/ivanesk315/CVE-2026-66066.svg) ![forks](https://img.shields.io/github/forks/ivanesk315/CVE-2026-66066.svg)


## CVE-2026-62201
 OpenClaw versions before 2026.6.6 contain a network policy bypass vulnerability in the sandbox exec-server that allows lower-trust callers to reach internal network destinations blocked by OpenClaw policy. Attackers can send HTTP requests through the exec-server to access network resources that should have been restricted by configured policies.

- [https://github.com/diedromeo/CVE-2026-62201-OpenClaw-SSRF](https://github.com/diedromeo/CVE-2026-62201-OpenClaw-SSRF) :  ![starts](https://img.shields.io/github/stars/diedromeo/CVE-2026-62201-OpenClaw-SSRF.svg) ![forks](https://img.shields.io/github/forks/diedromeo/CVE-2026-62201-OpenClaw-SSRF.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/TryA9ain/Certighost_CVE-2026-54121](https://github.com/TryA9ain/Certighost_CVE-2026-54121) :  ![starts](https://img.shields.io/github/stars/TryA9ain/Certighost_CVE-2026-54121.svg) ![forks](https://img.shields.io/github/forks/TryA9ain/Certighost_CVE-2026-54121.svg)


## CVE-2026-51376
 An issue in BitChat for iOS v1.15.0 allows a remote attacker to cause a denial of service via an unauthenticated MESSAGE packet into the mesh gossip cache

- [https://github.com/BARGHEST-ngo/CVE-2026-51376](https://github.com/BARGHEST-ngo/CVE-2026-51376) :  ![starts](https://img.shields.io/github/stars/BARGHEST-ngo/CVE-2026-51376.svg) ![forks](https://img.shields.io/github/forks/BARGHEST-ngo/CVE-2026-51376.svg)


## CVE-2026-49881
 In serviceClassExists of InCallController.java, there is a possible arbitrary code execution due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/LSPosed/LSPromise](https://github.com/LSPosed/LSPromise) :  ![starts](https://img.shields.io/github/stars/LSPosed/LSPromise.svg) ![forks](https://img.shields.io/github/forks/LSPosed/LSPromise.svg)
- [https://github.com/Supersonic/TLPE](https://github.com/Supersonic/TLPE) :  ![starts](https://img.shields.io/github/stars/Supersonic/TLPE.svg) ![forks](https://img.shields.io/github/forks/Supersonic/TLPE.svg)


## CVE-2026-43500
page_pool RX, GRO).  The OOM/trace handling already in place is reused.

- [https://github.com/TeamN4C/SG-2026-0024](https://github.com/TeamN4C/SG-2026-0024) :  ![starts](https://img.shields.io/github/stars/TeamN4C/SG-2026-0024.svg) ![forks](https://img.shields.io/github/forks/TeamN4C/SG-2026-0024.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/LSPosed/LSPromise](https://github.com/LSPosed/LSPromise) :  ![starts](https://img.shields.io/github/stars/LSPosed/LSPromise.svg) ![forks](https://img.shields.io/github/forks/LSPosed/LSPromise.svg)
- [https://github.com/TeamN4C/SG-2026-0024](https://github.com/TeamN4C/SG-2026-0024) :  ![starts](https://img.shields.io/github/stars/TeamN4C/SG-2026-0024.svg) ![forks](https://img.shields.io/github/forks/TeamN4C/SG-2026-0024.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/Xrzmodz444/cve-2026-41940-PoC-Linux](https://github.com/Xrzmodz444/cve-2026-41940-PoC-Linux) :  ![starts](https://img.shields.io/github/stars/Xrzmodz444/cve-2026-41940-PoC-Linux.svg) ![forks](https://img.shields.io/github/forks/Xrzmodz444/cve-2026-41940-PoC-Linux.svg)


## CVE-2026-34159
 llama.cpp is an inference of several LLM models in C/C++. Prior to version b8492, the RPC backend's deserialize_tensor() skips all bounds validation when a tensor's buffer field is 0. An unauthenticated attacker can read and write arbitrary process memory via crafted GRAPH_COMPUTE messages. Combined with pointer leaks from ALLOC_BUFFER/BUFFER_GET_BASE, this gives full ASLR bypass and remote code execution. No authentication required, just TCP access to the RPC server port. This issue has been patched in version b8492.

- [https://github.com/TeamN4C/SG-2026-0021](https://github.com/TeamN4C/SG-2026-0021) :  ![starts](https://img.shields.io/github/stars/TeamN4C/SG-2026-0021.svg) ![forks](https://img.shields.io/github/forks/TeamN4C/SG-2026-0021.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/sudoytang/copyfail-arm64](https://github.com/sudoytang/copyfail-arm64) :  ![starts](https://img.shields.io/github/stars/sudoytang/copyfail-arm64.svg) ![forks](https://img.shields.io/github/forks/sudoytang/copyfail-arm64.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/skyejacobson/CyberhawksLab-telnetCVE](https://github.com/skyejacobson/CyberhawksLab-telnetCVE) :  ![starts](https://img.shields.io/github/stars/skyejacobson/CyberhawksLab-telnetCVE.svg) ![forks](https://img.shields.io/github/forks/skyejacobson/CyberhawksLab-telnetCVE.svg)


## CVE-2026-19089
 The Product Input Fields for WooCommerce WordPress plugin before 2.0.2 does not validate uploaded file types when its accepted-types setting is left empty, which its own documentation advertises as accepting all files, allowing unauthenticated attackers to upload arbitrary files and achieve remote code execution on servers that do not honour the directory's access rules.

- [https://github.com/abraxas/CVE-2026-19089-WooCommerce-Tyche](https://github.com/abraxas/CVE-2026-19089-WooCommerce-Tyche) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-19089-WooCommerce-Tyche.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-19089-WooCommerce-Tyche.svg)


## CVE-2026-11387
 The SMS Alert – SMS & OTP for WooCommerce, Order Notifications & Abandoned Cart Recovery plugin for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 3.9.5. This is due to the plugin not properly validating a user's identity prior to updating their details like reset the password of any user account, including administrators, and gain full access to those accounts. This makes it possible for unauthenticated attackers to change arbitrary user's email addresses, including administrators, and leverage that to reset the user's password and gain access to their account. This is only vulnerable on sites with OTP verification for password resets enabled, and where the administrator (or other user) has set a phone number for OTP verification.

- [https://github.com/abraxas/CVE-2026-11387-WooCommerce-SMS-OTP](https://github.com/abraxas/CVE-2026-11387-WooCommerce-SMS-OTP) :  ![starts](https://img.shields.io/github/stars/abraxas/CVE-2026-11387-WooCommerce-SMS-OTP.svg) ![forks](https://img.shields.io/github/forks/abraxas/CVE-2026-11387-WooCommerce-SMS-OTP.svg)


## CVE-2026-7930
 Is not a vulnerability, is a feature bug.

- [https://github.com/4ybrick/CVE-2026-79303](https://github.com/4ybrick/CVE-2026-79303) :  ![starts](https://img.shields.io/github/stars/4ybrick/CVE-2026-79303.svg) ![forks](https://img.shields.io/github/forks/4ybrick/CVE-2026-79303.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/0xer0/CVE-2026-31431-Copy-Fail-add-arm64](https://github.com/0xer0/CVE-2026-31431-Copy-Fail-add-arm64) :  ![starts](https://img.shields.io/github/stars/0xer0/CVE-2026-31431-Copy-Fail-add-arm64.svg) ![forks](https://img.shields.io/github/forks/0xer0/CVE-2026-31431-Copy-Fail-add-arm64.svg)
- [https://github.com/abdelkabirouadoukou/CVE-2026-31431-Analysis-and-Fix](https://github.com/abdelkabirouadoukou/CVE-2026-31431-Analysis-and-Fix) :  ![starts](https://img.shields.io/github/stars/abdelkabirouadoukou/CVE-2026-31431-Analysis-and-Fix.svg) ![forks](https://img.shields.io/github/forks/abdelkabirouadoukou/CVE-2026-31431-Analysis-and-Fix.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)


## CVE-2025-54352
 WordPress 3.5 through 6.8.2 allows remote attackers to guess titles of private and draft posts via pingback.ping XML-RPC requests. NOTE: the Supplier is not changing this behavior.

- [https://github.com/mufasa-noir/XMLRPC-Pingback-vulnerability-POC](https://github.com/mufasa-noir/XMLRPC-Pingback-vulnerability-POC) :  ![starts](https://img.shields.io/github/stars/mufasa-noir/XMLRPC-Pingback-vulnerability-POC.svg) ![forks](https://img.shields.io/github/forks/mufasa-noir/XMLRPC-Pingback-vulnerability-POC.svg)


## CVE-2025-33073
 Improper access control in Windows SMB allows an authorized attacker to elevate privileges over a network.

- [https://github.com/starscow/CVE-2025-33073](https://github.com/starscow/CVE-2025-33073) :  ![starts](https://img.shields.io/github/stars/starscow/CVE-2025-33073.svg) ![forks](https://img.shields.io/github/forks/starscow/CVE-2025-33073.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/lucaschanzx/CVE-2025-29927-PoC](https://github.com/lucaschanzx/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/lucaschanzx/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/lucaschanzx/CVE-2025-29927-PoC.svg)


## CVE-2025-27636
Mitigation: You can easily work around this in your Camel applications by removing the headers in your Camel routes. There are many ways of doing this, also globally or per route. This means you could use the removeHeaders EIP, to filter out anything like "cAmel, cAMEL" etc, or in general everything not starting with "Camel", "camel" or "org.apache.camel.".

- [https://github.com/AC8999/CVE-2025-27636-RCE-in-Apache-Camel](https://github.com/AC8999/CVE-2025-27636-RCE-in-Apache-Camel) :  ![starts](https://img.shields.io/github/stars/AC8999/CVE-2025-27636-RCE-in-Apache-Camel.svg) ![forks](https://img.shields.io/github/forks/AC8999/CVE-2025-27636-RCE-in-Apache-Camel.svg)
- [https://github.com/AC8999/CVE-2025-27636-RCE](https://github.com/AC8999/CVE-2025-27636-RCE) :  ![starts](https://img.shields.io/github/stars/AC8999/CVE-2025-27636-RCE.svg) ![forks](https://img.shields.io/github/forks/AC8999/CVE-2025-27636-RCE.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-15x.svg)


## CVE-2025-3248
code.

- [https://github.com/zoly-zoly/CVE-2025-3248](https://github.com/zoly-zoly/CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/zoly-zoly/CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/zoly-zoly/CVE-2025-3248.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/all3njk/NextJS_CVE-2025-29927](https://github.com/all3njk/NextJS_CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/all3njk/NextJS_CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/all3njk/NextJS_CVE-2025-29927.svg)


## CVE-2024-44625
 Gogs =0.13.0 is vulnerable to Directory Traversal via the editFilePost function of internal/route/repo/editor.go.

- [https://github.com/batj44/CVE-2024-44625-Gogs-RCE-0.13.0](https://github.com/batj44/CVE-2024-44625-Gogs-RCE-0.13.0) :  ![starts](https://img.shields.io/github/stars/batj44/CVE-2024-44625-Gogs-RCE-0.13.0.svg) ![forks](https://img.shields.io/github/forks/batj44/CVE-2024-44625-Gogs-RCE-0.13.0.svg)


## CVE-2024-38077
 Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability

- [https://github.com/starscow/CVE-2024-38077-POC](https://github.com/starscow/CVE-2024-38077-POC) :  ![starts](https://img.shields.io/github/stars/starscow/CVE-2024-38077-POC.svg) ![forks](https://img.shields.io/github/forks/starscow/CVE-2024-38077-POC.svg)


## CVE-2024-37890
 ws is an open source WebSocket client and server for Node.js. A request with a number of headers exceeding theserver.maxHeadersCount threshold could be used to crash a ws server. The vulnerability was fixed in ws@8.17.1 (e55e510) and backported to ws@7.5.10 (22c2876), ws@6.2.3 (eeb76d3), and ws@5.2.4 (4abd8f6). In vulnerable versions of ws, the issue can be mitigated in the following ways: 1. Reduce the maximum allowed length of the request headers using the --max-http-header-size=size and/or the maxHeaderSize options so that no more headers than the server.maxHeadersCount limit can be sent. 2. Set server.maxHeadersCount to 0 so that no limit is applied.

- [https://github.com/RazdoruNET/OMG_KILLER](https://github.com/RazdoruNET/OMG_KILLER) :  ![starts](https://img.shields.io/github/stars/RazdoruNET/OMG_KILLER.svg) ![forks](https://img.shields.io/github/forks/RazdoruNET/OMG_KILLER.svg)


## CVE-2024-20154
 In Modem, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution, if a UE has connected to a rogue base station controlled by the attacker, with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: MOLY00720348; Issue ID: MSV-2392.

- [https://github.com/HarbingerSe7en/CVE-2024-20154](https://github.com/HarbingerSe7en/CVE-2024-20154) :  ![starts](https://img.shields.io/github/stars/HarbingerSe7en/CVE-2024-20154.svg) ![forks](https://img.shields.io/github/forks/HarbingerSe7en/CVE-2024-20154.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/yeee3642/edu-recon](https://github.com/yeee3642/edu-recon) :  ![starts](https://img.shields.io/github/stars/yeee3642/edu-recon.svg) ![forks](https://img.shields.io/github/forks/yeee3642/edu-recon.svg)


## CVE-2024-2961
 The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.

- [https://github.com/qinglove777/CVE-2024-2961-XXE-Exploit](https://github.com/qinglove777/CVE-2024-2961-XXE-Exploit) :  ![starts](https://img.shields.io/github/stars/qinglove777/CVE-2024-2961-XXE-Exploit.svg) ![forks](https://img.shields.io/github/forks/qinglove777/CVE-2024-2961-XXE-Exploit.svg)


## CVE-2023-34468
You are recommended to upgrade to version 1.22.0 or later which fixes this issue.

- [https://github.com/luiskrnr/HTB_Helix_CVE-2023-34468](https://github.com/luiskrnr/HTB_Helix_CVE-2023-34468) :  ![starts](https://img.shields.io/github/stars/luiskrnr/HTB_Helix_CVE-2023-34468.svg) ![forks](https://img.shields.io/github/forks/luiskrnr/HTB_Helix_CVE-2023-34468.svg)


## CVE-2023-25157
 GeoServer is an open source software server written in Java that allows users to share and edit geospatial data. GeoServer includes support for the OGC Filter expression language and the OGC Common Query Language (CQL) as part of the Web Feature Service (WFS) and Web Map Service (WMS) protocols.  CQL is also supported through the Web Coverage Service (WCS) protocol for ImageMosaic coverages. Users are advised to upgrade to either version 2.21.4, or version 2.22.2 to resolve this issue. Users unable to upgrade should disable the PostGIS Datastore *encode functions* setting to mitigate ``strEndsWith``, ``strStartsWith`` and ``PropertyIsLike `` misuse and enable the PostGIS DataStore *preparedStatements* setting to mitigate the ``FeatureId`` misuse.

- [https://github.com/ivanesk315/CVE-2023-25157](https://github.com/ivanesk315/CVE-2023-25157) :  ![starts](https://img.shields.io/github/stars/ivanesk315/CVE-2023-25157.svg) ![forks](https://img.shields.io/github/forks/ivanesk315/CVE-2023-25157.svg)


## CVE-2023-6063
 The WP Fastest Cache WordPress plugin before 1.2.2 does not properly sanitise and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by unauthenticated users.

- [https://github.com/zhairiazzeddine/Exploit-CVE-2023-6063-PoC-Vuln](https://github.com/zhairiazzeddine/Exploit-CVE-2023-6063-PoC-Vuln) :  ![starts](https://img.shields.io/github/stars/zhairiazzeddine/Exploit-CVE-2023-6063-PoC-Vuln.svg) ![forks](https://img.shields.io/github/forks/zhairiazzeddine/Exploit-CVE-2023-6063-PoC-Vuln.svg)


## CVE-2022-29900
 Mis-trained branch predictions for return instructions may allow arbitrary speculative code execution under certain microarchitecture-dependent conditions.

- [https://github.com/abdul-kalam2000/retbleed-speculative-execution-poc](https://github.com/abdul-kalam2000/retbleed-speculative-execution-poc) :  ![starts](https://img.shields.io/github/stars/abdul-kalam2000/retbleed-speculative-execution-poc.svg) ![forks](https://img.shields.io/github/forks/abdul-kalam2000/retbleed-speculative-execution-poc.svg)


## CVE-2022-24637
 Open Web Analytics (OWA) before 1.7.4 allows an unauthenticated remote attacker to obtain sensitive user information, which can be used to gain admin privileges by leveraging cache hashes. This occurs because files generated with '?php (instead of the intended "?php sequence) aren't handled by the PHP interpreter.

- [https://github.com/PrinceAikinsBaidoo/CVE-2022-24637](https://github.com/PrinceAikinsBaidoo/CVE-2022-24637) :  ![starts](https://img.shields.io/github/stars/PrinceAikinsBaidoo/CVE-2022-24637.svg) ![forks](https://img.shields.io/github/forks/PrinceAikinsBaidoo/CVE-2022-24637.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/vudangducminh/CVE-2022-0847](https://github.com/vudangducminh/CVE-2022-0847) :  ![starts](https://img.shields.io/github/stars/vudangducminh/CVE-2022-0847.svg) ![forks](https://img.shields.io/github/forks/vudangducminh/CVE-2022-0847.svg)


## CVE-2021-32675
 Redis is an open source, in-memory database that persists on disk. When parsing an incoming Redis Standard Protocol (RESP) request, Redis allocates memory according to user-specified values which determine the number of elements (in the multi-bulk header) and size of each element (in the bulk header). An attacker delivering specially crafted requests over multiple connections can cause the server to allocate significant amount of memory. Because the same parsing mechanism is used to handle authentication requests, this vulnerability can also be exploited by unauthenticated users. The problem is fixed in Redis versions 6.2.6, 6.0.16 and 5.0.14. An additional workaround to mitigate this problem without patching the redis-server executable is to block access to prevent unauthenticated users from connecting to Redis. This can be done in different ways: Using network access control tools like firewalls, iptables, security groups, etc. or Enabling TLS and requiring users to authenticate using client side certificates.

- [https://github.com/rubbxalc/CVE-2021-32675](https://github.com/rubbxalc/CVE-2021-32675) :  ![starts](https://img.shields.io/github/stars/rubbxalc/CVE-2021-32675.svg) ![forks](https://img.shields.io/github/forks/rubbxalc/CVE-2021-32675.svg)


## CVE-2021-4422
 The POST SMTP Mailer plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.20. This is due to missing or incorrect nonce validation on the handleCsvExport() function. This makes it possible for unauthenticated attackers to trigger a CSV export via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/asd58584388/CVE-2021-44228](https://github.com/asd58584388/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/asd58584388/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/asd58584388/CVE-2021-44228.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/shiomiyan/CVE-2021-41773](https://github.com/shiomiyan/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/shiomiyan/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/shiomiyan/CVE-2021-41773.svg)


## CVE-2020-24656
 Maltego before 4.2.12 allows XXE attacks.

- [https://github.com/mattia-maria-scivoletto/Internet-Security-Project](https://github.com/mattia-maria-scivoletto/Internet-Security-Project) :  ![starts](https://img.shields.io/github/stars/mattia-maria-scivoletto/Internet-Security-Project.svg) ![forks](https://img.shields.io/github/forks/mattia-maria-scivoletto/Internet-Security-Project.svg)


## CVE-2020-13671
 Drupal core does not properly sanitize certain filenames on uploaded files, which can lead to files being interpreted as the incorrect extension and served as the wrong MIME type or executed as PHP for certain hosting configurations. This issue affects: Drupal Drupal Core 9.0 versions prior to 9.0.8, 8.9 versions prior to 8.9.9, 8.8 versions prior to 8.8.11, and 7 versions prior to 7.74.

- [https://github.com/ivanesk315/CVE-2020-13671](https://github.com/ivanesk315/CVE-2020-13671) :  ![starts](https://img.shields.io/github/stars/ivanesk315/CVE-2020-13671.svg) ![forks](https://img.shields.io/github/forks/ivanesk315/CVE-2020-13671.svg)


## CVE-2020-0022
 In reassemble_and_dispatch of packet_fragmenter.cc, there is possible out of bounds write due to an incorrect bounds calculation. This could lead to remote code execution over Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-143894715

- [https://github.com/idkwim/CVE-2020-0022](https://github.com/idkwim/CVE-2020-0022) :  ![starts](https://img.shields.io/github/stars/idkwim/CVE-2020-0022.svg) ![forks](https://img.shields.io/github/forks/idkwim/CVE-2020-0022.svg)


## CVE-2019-18394
 A Server Side Request Forgery (SSRF) vulnerability in FaviconServlet.java in Ignite Realtime Openfire through 4.4.2 allows attackers to send arbitrary HTTP GET requests.

- [https://github.com/l0lsec/openfire-ssrf-cve-2019-18394](https://github.com/l0lsec/openfire-ssrf-cve-2019-18394) :  ![starts](https://img.shields.io/github/stars/l0lsec/openfire-ssrf-cve-2019-18394.svg) ![forks](https://img.shields.io/github/forks/l0lsec/openfire-ssrf-cve-2019-18394.svg)


## CVE-2018-20062
 An issue was discovered in NoneCms V1.3. thinkphp/library/think/App.php allows remote attackers to execute arbitrary PHP code via crafted use of the filter parameter, as demonstrated by the s=index/\think\Request/input&filter=phpinfo&data=1 query string.

- [https://github.com/Jasper2018/CVE-2018-20062](https://github.com/Jasper2018/CVE-2018-20062) :  ![starts](https://img.shields.io/github/stars/Jasper2018/CVE-2018-20062.svg) ![forks](https://img.shields.io/github/forks/Jasper2018/CVE-2018-20062.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/quincyomoruyi6-lang/BLUE-WRITEUP-CVE-2017-0144](https://github.com/quincyomoruyi6-lang/BLUE-WRITEUP-CVE-2017-0144) :  ![starts](https://img.shields.io/github/stars/quincyomoruyi6-lang/BLUE-WRITEUP-CVE-2017-0144.svg) ![forks](https://img.shields.io/github/forks/quincyomoruyi6-lang/BLUE-WRITEUP-CVE-2017-0144.svg)
- [https://github.com/porcumarcooo/TryHackMe-Blue-MS17-010](https://github.com/porcumarcooo/TryHackMe-Blue-MS17-010) :  ![starts](https://img.shields.io/github/stars/porcumarcooo/TryHackMe-Blue-MS17-010.svg) ![forks](https://img.shields.io/github/forks/porcumarcooo/TryHackMe-Blue-MS17-010.svg)


## CVE-2016-3223
 Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold and 1511 mishandle LDAP authentication, which allows man-in-the-middle attackers to gain privileges by modifying group-policy update data within a domain-controller data stream, aka "Group Policy Elevation of Privilege Vulnerability."

- [https://github.com/HORKimhab/CVE-2016-3223](https://github.com/HORKimhab/CVE-2016-3223) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2016-3223.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2016-3223.svg)


## CVE-2015-5736
 The Fortishield.sys driver in Fortinet FortiClient before 5.2.4 allows local users to execute arbitrary code with kernel privileges by setting the callback function in a (1) 0x220024 or (2) 0x220028 ioctl call.

- [https://github.com/RainbowDynamix/FortiLOL](https://github.com/RainbowDynamix/FortiLOL) :  ![starts](https://img.shields.io/github/stars/RainbowDynamix/FortiLOL.svg) ![forks](https://img.shields.io/github/forks/RainbowDynamix/FortiLOL.svg)


## CVE-2013-2028
 The ngx_http_parse_chunked function in http/ngx_http_parse.c in nginx 1.3.9 through 1.4.0 allows remote attackers to cause a denial of service (crash) and execute arbitrary code via a chunked Transfer-Encoding request with a large chunk size, which triggers an integer signedness error and a stack-based buffer overflow.

- [https://github.com/vanivamshi/CVE-2013-2028-Exploit](https://github.com/vanivamshi/CVE-2013-2028-Exploit) :  ![starts](https://img.shields.io/github/stars/vanivamshi/CVE-2013-2028-Exploit.svg) ![forks](https://img.shields.io/github/forks/vanivamshi/CVE-2013-2028-Exploit.svg)


## CVE-2010-2075
 UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.

- [https://github.com/rhimavanth32-max/Metasploitable2-Reconnaissance-and-UnrealIRCd-Backdoor-Exploitation](https://github.com/rhimavanth32-max/Metasploitable2-Reconnaissance-and-UnrealIRCd-Backdoor-Exploitation) :  ![starts](https://img.shields.io/github/stars/rhimavanth32-max/Metasploitable2-Reconnaissance-and-UnrealIRCd-Backdoor-Exploitation.svg) ![forks](https://img.shields.io/github/forks/rhimavanth32-max/Metasploitable2-Reconnaissance-and-UnrealIRCd-Backdoor-Exploitation.svg)


## CVE-2008-0166
 OpenSSL 0.9.8c-1 up to versions before 0.9.8g-9 on Debian-based operating systems uses a random number generator that generates predictable numbers, which makes it easier for remote attackers to conduct brute force guessing attacks against cryptographic keys.

- [https://github.com/ethicbrudhack/CVE-2008-0166-BTC-satoshi-mining-wallets](https://github.com/ethicbrudhack/CVE-2008-0166-BTC-satoshi-mining-wallets) :  ![starts](https://img.shields.io/github/stars/ethicbrudhack/CVE-2008-0166-BTC-satoshi-mining-wallets.svg) ![forks](https://img.shields.io/github/forks/ethicbrudhack/CVE-2008-0166-BTC-satoshi-mining-wallets.svg)


## CVE-2004-2687
 distcc 2.x, as used in XCode 1.5 and others, when not configured to restrict access to the server port, allows remote attackers to execute arbitrary commands via compilation jobs, which are executed by the server without authorization checks.

- [https://github.com/germarr93/CyberSecurity-Pentest-Lab](https://github.com/germarr93/CyberSecurity-Pentest-Lab) :  ![starts](https://img.shields.io/github/stars/germarr93/CyberSecurity-Pentest-Lab.svg) ![forks](https://img.shields.io/github/forks/germarr93/CyberSecurity-Pentest-Lab.svg)


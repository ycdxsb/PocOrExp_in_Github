# Update 2026-09-25
## CVE-2026-94504
 Ninja Forms 3.15.3 stores an anonymous non-RTE textarea value and renders it without safe HTML encoding in the legacy submission editor. An attacker can break out of the textarea with stored script. When an Administrator opens the attacker-known direct submission URL, the script runs in the WordPress admin origin.

- [https://github.com/cflowsec/cve-2026-94504](https://github.com/cflowsec/cve-2026-94504) :  ![starts](https://img.shields.io/github/stars/cflowsec/cve-2026-94504.svg) ![forks](https://img.shields.io/github/forks/cflowsec/cve-2026-94504.svg)


## CVE-2026-94127
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/FurkanKAYAPINAR/CVE-2026-94127](https://github.com/FurkanKAYAPINAR/CVE-2026-94127) :  ![starts](https://img.shields.io/github/stars/FurkanKAYAPINAR/CVE-2026-94127.svg) ![forks](https://img.shields.io/github/forks/FurkanKAYAPINAR/CVE-2026-94127.svg)


## CVE-2026-93616
 A directory traversal and file upload vulnerability allows an unauthenticated attacker to upload and execute arbitrary scripts on Check Point Management Server.

- [https://github.com/Nebula-Consulting-Limited/CVE-2026-93616-PoC](https://github.com/Nebula-Consulting-Limited/CVE-2026-93616-PoC) :  ![starts](https://img.shields.io/github/stars/Nebula-Consulting-Limited/CVE-2026-93616-PoC.svg) ![forks](https://img.shields.io/github/forks/Nebula-Consulting-Limited/CVE-2026-93616-PoC.svg)


## CVE-2026-93528
 The NP Quote Request for WooCommerce WordPress plugin before 2.4.16 does not verify order ownership before rendering an order's details, allowing unauthenticated attackers to view another customer's order using the order's key.

- [https://github.com/muradislamzada/CVE-2026-93528](https://github.com/muradislamzada/CVE-2026-93528) :  ![starts](https://img.shields.io/github/stars/muradislamzada/CVE-2026-93528.svg) ![forks](https://img.shields.io/github/forks/muradislamzada/CVE-2026-93528.svg)


## CVE-2026-93349
 Frictionless through 5.20.0rc1 contains an OS command injection vulnerability in the explore console command that allows an attacker who supplies a crafted Data Package descriptor to execute arbitrary operating system commands as the user who explores it. Attackers can place shell metacharacters in resource path values within a datapackage.json descriptor, which are passed unsanitized to os.system through a shell, causing arbitrary command execution in the victim's security context when they run the explore command against the untrusted package.

- [https://github.com/SaiTeja-Erukude/CVE-2026-93349-frictionless-command-injection](https://github.com/SaiTeja-Erukude/CVE-2026-93349-frictionless-command-injection) :  ![starts](https://img.shields.io/github/stars/SaiTeja-Erukude/CVE-2026-93349-frictionless-command-injection.svg) ![forks](https://img.shields.io/github/forks/SaiTeja-Erukude/CVE-2026-93349-frictionless-command-injection.svg)


## CVE-2026-90847
 A vulnerability was determined in EFM ipTIME C200E 1.094. The impacted element is an unknown function of the file iux_set.cgi of the component System Setup. This manipulation causes os command injection. It is possible to initiate the attack remotely. The exploit has been publicly disclosed and may be utilized.

- [https://github.com/shlln/CVE-2026-90847](https://github.com/shlln/CVE-2026-90847) :  ![starts](https://img.shields.io/github/stars/shlln/CVE-2026-90847.svg) ![forks](https://img.shields.io/github/forks/shlln/CVE-2026-90847.svg)


## CVE-2026-89274
 The WP Recipe Maker plugin for WordPress is vulnerable to Arbitrary Shortcode Execution in all versions up to, and including, 10.8.1. The vulnerability exists because `WPRM_Metadata::sanitize_metadata()` recursively calls `do_shortcode()` on every scalar field of the recipe's structured metadata array — including the `reviewBody` field, which is populated verbatim from the `comment_content` of approved `wprm-comment-rating` comments — without sanitizing or stripping shortcode tokens before execution; the subsequent `wp_strip_all_tags()` and `strip_shortcodes()` calls operate only on the output string after execution has already fully occurred, providing no protection against server-side shortcode invocation. This makes it possible for unauthenticated attackers to execute arbitrary registered WordPress shortcodes server-side on every recipe page render, causing shortcode output — such as attachment captions, private post fields, or other data exposed by installed shortcodes — to be embedded in the page's JSON-LD `reviewBody` metadata and disclosed to all visitors who load the recipe page. Successful exploitation requires the attacker's rated comment to pass the site's comment approval threshold, either via auto-approval or moderator action, before the injected shortcode begins executing on page loads.

- [https://github.com/Hassham1/CVE-2026-89274-wp-recipe-maker-poc](https://github.com/Hassham1/CVE-2026-89274-wp-recipe-maker-poc) :  ![starts](https://img.shields.io/github/stars/Hassham1/CVE-2026-89274-wp-recipe-maker-poc.svg) ![forks](https://img.shields.io/github/forks/Hassham1/CVE-2026-89274-wp-recipe-maker-poc.svg)


## CVE-2026-88997
 The JSM Show Post Metadata WordPress plugin before 4.9.1 does not properly escape a post meta key before outputting it into an inline event-handler attribute in an admin-facing meta box, allowing users with contributor-level access and above to inject arbitrary JavaScript that executes in the session of a higher-privileged user who reviews the affected post.

- [https://github.com/pervinzahidli/CVE-2026-88997](https://github.com/pervinzahidli/CVE-2026-88997) :  ![starts](https://img.shields.io/github/stars/pervinzahidli/CVE-2026-88997.svg) ![forks](https://img.shields.io/github/forks/pervinzahidli/CVE-2026-88997.svg)


## CVE-2026-87902
 An unauthenticated attacker can make `get_page_template()` page-template resolution include a chosen readable local `.php` file outside the active theme directories. If relevant pre-conditions for both the server and the active theme are met, this can lead to RCE.

- [https://github.com/dinosn/cve-2026-87902-wordpress-lfi-lab](https://github.com/dinosn/cve-2026-87902-wordpress-lfi-lab) :  ![starts](https://img.shields.io/github/stars/dinosn/cve-2026-87902-wordpress-lfi-lab.svg) ![forks](https://img.shields.io/github/forks/dinosn/cve-2026-87902-wordpress-lfi-lab.svg)
- [https://github.com/oliveiralimajr/CVE_2026_87902](https://github.com/oliveiralimajr/CVE_2026_87902) :  ![starts](https://img.shields.io/github/stars/oliveiralimajr/CVE_2026_87902.svg) ![forks](https://img.shields.io/github/forks/oliveiralimajr/CVE_2026_87902.svg)
- [https://github.com/Hassham1/CVE-2026-87902](https://github.com/Hassham1/CVE-2026-87902) :  ![starts](https://img.shields.io/github/stars/Hassham1/CVE-2026-87902.svg) ![forks](https://img.shields.io/github/forks/Hassham1/CVE-2026-87902.svg)
- [https://github.com/tc4dy/CVE-2026-87902-Toolkit](https://github.com/tc4dy/CVE-2026-87902-Toolkit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-87902-Toolkit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-87902-Toolkit.svg)
- [https://github.com/ynsmroztas/WPSniper](https://github.com/ynsmroztas/WPSniper) :  ![starts](https://img.shields.io/github/stars/ynsmroztas/WPSniper.svg) ![forks](https://img.shields.io/github/forks/ynsmroztas/WPSniper.svg)
- [https://github.com/Lutfifakee-Project/CVE-2026-87902](https://github.com/Lutfifakee-Project/CVE-2026-87902) :  ![starts](https://img.shields.io/github/stars/Lutfifakee-Project/CVE-2026-87902.svg) ![forks](https://img.shields.io/github/forks/Lutfifakee-Project/CVE-2026-87902.svg)
- [https://github.com/bhideki/CVE-2026-87902](https://github.com/bhideki/CVE-2026-87902) :  ![starts](https://img.shields.io/github/stars/bhideki/CVE-2026-87902.svg) ![forks](https://img.shields.io/github/forks/bhideki/CVE-2026-87902.svg)
- [https://github.com/zer0dayf/CVE-2026-87902](https://github.com/zer0dayf/CVE-2026-87902) :  ![starts](https://img.shields.io/github/stars/zer0dayf/CVE-2026-87902.svg) ![forks](https://img.shields.io/github/forks/zer0dayf/CVE-2026-87902.svg)
- [https://github.com/nextco/wordpress-cve-2026-87902](https://github.com/nextco/wordpress-cve-2026-87902) :  ![starts](https://img.shields.io/github/stars/nextco/wordpress-cve-2026-87902.svg) ![forks](https://img.shields.io/github/forks/nextco/wordpress-cve-2026-87902.svg)
- [https://github.com/rabakuku/CVE-2026-87902-A-working-PoC-for-WordPress-s-critical-path-traversal](https://github.com/rabakuku/CVE-2026-87902-A-working-PoC-for-WordPress-s-critical-path-traversal) :  ![starts](https://img.shields.io/github/stars/rabakuku/CVE-2026-87902-A-working-PoC-for-WordPress-s-critical-path-traversal.svg) ![forks](https://img.shields.io/github/forks/rabakuku/CVE-2026-87902-A-working-PoC-for-WordPress-s-critical-path-traversal.svg)


## CVE-2026-86218
 N-central is vulnerable to a pre-auth remote code execution This issue affects N-central: before 2026.3.1.14.

- [https://github.com/super-meuw/CVE-2026-86218](https://github.com/super-meuw/CVE-2026-86218) :  ![starts](https://img.shields.io/github/stars/super-meuw/CVE-2026-86218.svg) ![forks](https://img.shields.io/github/forks/super-meuw/CVE-2026-86218.svg)


## CVE-2026-86060
path involving usernames that begin with a prohibited character, allowing for the trusted RouterOS policy mask to be changed, leading to privilege escalation. Exploitation requires an unauthenticated SSH session to reach the RouterOS login helper.This issue was fixed in versions: 6.49.21 (Long-term), 7.23.4 (Long-term) and 7.24.2 (Stable)

- [https://github.com/digiprosec/MicroTrick](https://github.com/digiprosec/MicroTrick) :  ![starts](https://img.shields.io/github/stars/digiprosec/MicroTrick.svg) ![forks](https://img.shields.io/github/forks/digiprosec/MicroTrick.svg)


## CVE-2026-50369
 Use after free in Windows Remote Desktop Services allows an authorized attacker to elevate privileges over a network.

- [https://github.com/Mofarthim/CVE-2026-50369](https://github.com/Mofarthim/CVE-2026-50369) :  ![starts](https://img.shields.io/github/stars/Mofarthim/CVE-2026-50369.svg) ![forks](https://img.shields.io/github/forks/Mofarthim/CVE-2026-50369.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/dorlow/hazel-cve-2026-43499](https://github.com/dorlow/hazel-cve-2026-43499) :  ![starts](https://img.shields.io/github/stars/dorlow/hazel-cve-2026-43499.svg) ![forks](https://img.shields.io/github/forks/dorlow/hazel-cve-2026-43499.svg)


## CVE-2026-27626
 OliveTin gives access to predefined shell commands from a web interface. In versions up to and including 3000.10.0, OliveTin's shell mode safety check (`checkShellArgumentSafety`) blocks several dangerous argument types but not `password`. A user supplying a `password`-typed argument can inject shell metacharacters that execute arbitrary OS commands. A second independent vector allows unauthenticated RCE via webhook-extracted JSON values that skip type safety checks entirely before reaching `sh -c`. When exploiting vector 1, any authenticated user (registration enabled by default, `authType: none` by default) can execute arbitrary OS commands on the OliveTin host with the permissions of the OliveTin process. When exploiting vector 2, an unauthenticated attacker can achieve the same if the instance receives webhooks from external sources, which is a primary OliveTin use case. When an attacker exploits both vectors, this results in unauthenticated RCE on any OliveTin instance using Shell mode with webhook-triggered actions. As of time of publication, a patched version is not available.

- [https://github.com/abdelhakimgaferNetworkSec/Enigm-Writeup](https://github.com/abdelhakimgaferNetworkSec/Enigm-Writeup) :  ![starts](https://img.shields.io/github/stars/abdelhakimgaferNetworkSec/Enigm-Writeup.svg) ![forks](https://img.shields.io/github/forks/abdelhakimgaferNetworkSec/Enigm-Writeup.svg)


## CVE-2026-19125
 The EthPress – Web3 Login plugin for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 2.3.5. This is due to the verify_login() function in app/Login.php containing a missing return statement in the signature verification failure branch — when Signature::verify2() reports a mismatch, the function only assigns a WP_Error to a local variable and continues executing, causing unconditional fall-through to the login block where Address::log_in() calls wp_set_auth_cookie() regardless of whether the submitted signature is valid. This makes it possible for unauthenticated attackers to log in as any WordPress user who has a linked wallet address — including administrators — by submitting that user's public wallet address alongside an arbitrary well-formed signature, enabling full site takeover.

- [https://github.com/Polosss/By-Poloss..-..CVE-2026-19125](https://github.com/Polosss/By-Poloss..-..CVE-2026-19125) :  ![starts](https://img.shields.io/github/stars/Polosss/By-Poloss..-..CVE-2026-19125.svg) ![forks](https://img.shields.io/github/forks/Polosss/By-Poloss..-..CVE-2026-19125.svg)


## CVE-2026-9454
 A flaw has been found in Totolink A8000RU 7.1cu.643_b20200521. This vulnerability affects the function setOpenVpnCertGenerationCfg of the file /cgi-bin/cstecgi.cgi of the component Web Management Interface. Executing a manipulation of the argument servername can lead to os command injection. The attack may be launched remotely. The exploit has been published and may be used.

- [https://github.com/HORKimhab/CVE-2026-94545](https://github.com/HORKimhab/CVE-2026-94545) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-94545.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-94545.svg)
- [https://github.com/Hassham1/CVE-2026-94545-nextjs-og-poc](https://github.com/Hassham1/CVE-2026-94545-nextjs-og-poc) :  ![starts](https://img.shields.io/github/stars/Hassham1/CVE-2026-94545-nextjs-og-poc.svg) ![forks](https://img.shields.io/github/forks/Hassham1/CVE-2026-94545-nextjs-og-poc.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/krish-foren6/CVE-2026-31431-Report-Copy-fail-Vulnerability-](https://github.com/krish-foren6/CVE-2026-31431-Report-Copy-fail-Vulnerability-) :  ![starts](https://img.shields.io/github/stars/krish-foren6/CVE-2026-31431-Report-Copy-fail-Vulnerability-.svg) ![forks](https://img.shields.io/github/forks/krish-foren6/CVE-2026-31431-Report-Copy-fail-Vulnerability-.svg)


## CVE-2026-1769
upgrading Xerox® CentreWare Web® to v7.2.2.25 via the software available on Xerox.com

- [https://github.com/Leox48/CVE-2026-1769-WriteUp](https://github.com/Leox48/CVE-2026-1769-WriteUp) :  ![starts](https://img.shields.io/github/stars/Leox48/CVE-2026-1769-WriteUp.svg) ![forks](https://img.shields.io/github/forks/Leox48/CVE-2026-1769-WriteUp.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-packagemanager-field.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)


## CVE-2025-22457
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.6, Ivanti Policy Secure before version 22.7R1.4, and Ivanti ZTA Gateways before version 22.8R2.2 allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/donofly/CVE-2025-22457-vulnserver-lab](https://github.com/donofly/CVE-2025-22457-vulnserver-lab) :  ![starts](https://img.shields.io/github/stars/donofly/CVE-2025-22457-vulnserver-lab.svg) ![forks](https://img.shields.io/github/forks/donofly/CVE-2025-22457-vulnserver-lab.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/lucaschanzx/CVE-2025-29927-PoC](https://github.com/lucaschanzx/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/lucaschanzx/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/lucaschanzx/CVE-2025-29927-PoC.svg)


## CVE-2024-49138
 Windows Common Log File System Driver Elevation of Privilege Vulnerability

- [https://github.com/mohamedbrek/SOC335-CVE-2024-49138-Exploitation-Detected](https://github.com/mohamedbrek/SOC335-CVE-2024-49138-Exploitation-Detected) :  ![starts](https://img.shields.io/github/stars/mohamedbrek/SOC335-CVE-2024-49138-Exploitation-Detected.svg) ![forks](https://img.shields.io/github/forks/mohamedbrek/SOC335-CVE-2024-49138-Exploitation-Detected.svg)


## CVE-2024-37054
 Deserialization of untrusted data can occur in versions of the MLflow platform running version 0.9.0 or newer, enabling a maliciously uploaded PyFunc model to run arbitrary code on an end user’s system when interacted with.

- [https://github.com/BardLaudian/CVE-2024-37054](https://github.com/BardLaudian/CVE-2024-37054) :  ![starts](https://img.shields.io/github/stars/BardLaudian/CVE-2024-37054.svg) ![forks](https://img.shields.io/github/forks/BardLaudian/CVE-2024-37054.svg)


## CVE-2023-32233
 In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users can obtain root privileges. This occurs because anonymous sets are mishandled.

- [https://github.com/adeadukagi/CVE-2023-32233-reproduction](https://github.com/adeadukagi/CVE-2023-32233-reproduction) :  ![starts](https://img.shields.io/github/stars/adeadukagi/CVE-2023-32233-reproduction.svg) ![forks](https://img.shields.io/github/forks/adeadukagi/CVE-2023-32233-reproduction.svg)


## CVE-2022-40769
 profanity through 1.60 has only four billion possible RNG initializations. Thus, attackers can recover private keys from Ethereum vanity addresses and steal cryptocurrency, as exploited in the wild in June 2022.

- [https://github.com/artsbykriss/profanity-verifier](https://github.com/artsbykriss/profanity-verifier) :  ![starts](https://img.shields.io/github/stars/artsbykriss/profanity-verifier.svg) ![forks](https://img.shields.io/github/forks/artsbykriss/profanity-verifier.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe](https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg)
- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe.svg)


## CVE-2021-40444
UPDATE September 14, 2021: Microsoft has released security updates to address this vulnerability. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. Please see the FAQ for important information about which updates are applicable to your system.

- [https://github.com/rankthree/SOC-Detection-T1003.001-CVE-2021-40444](https://github.com/rankthree/SOC-Detection-T1003.001-CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/rankthree/SOC-Detection-T1003.001-CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/rankthree/SOC-Detection-T1003.001-CVE-2021-40444.svg)


## CVE-2020-15368
 AsrDrv103.sys in the ASRock RGB Driver does not properly restrict access from user space, as demonstrated by triggering a triple fault via a request to zero CR3.

- [https://github.com/egorrsp/CVE-2020-15368-AsrDrv103-research](https://github.com/egorrsp/CVE-2020-15368-AsrDrv103-research) :  ![starts](https://img.shields.io/github/stars/egorrsp/CVE-2020-15368-AsrDrv103-research.svg) ![forks](https://img.shields.io/github/forks/egorrsp/CVE-2020-15368-AsrDrv103-research.svg)


## CVE-2020-14645
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/jlvsjp/Weblogic_CVE-2020-14645](https://github.com/jlvsjp/Weblogic_CVE-2020-14645) :  ![starts](https://img.shields.io/github/stars/jlvsjp/Weblogic_CVE-2020-14645.svg) ![forks](https://img.shields.io/github/forks/jlvsjp/Weblogic_CVE-2020-14645.svg)


## CVE-2020-10257
 The ThemeREX Addons plugin before 2020-03-09 for WordPress lacks access control on the /trx_addons/v2/get/sc_layout REST API endpoint, allowing for PHP functions to be executed by any users, because includes/plugin.rest-api.php calls trx_addons_rest_get_sc_layout with an unsafe sc parameter.

- [https://github.com/Darkcast/CVE-2020-10257](https://github.com/Darkcast/CVE-2020-10257) :  ![starts](https://img.shields.io/github/stars/Darkcast/CVE-2020-10257.svg) ![forks](https://img.shields.io/github/forks/Darkcast/CVE-2020-10257.svg)


# Update 2023-01-07
## CVE-2023-22626
 PgHero before 3.1.0 allows Information Disclosure via EXPLAIN because query results may be present in an error message. (Depending on database user privileges, this may only be information from the database, or may be information from file contents on the database server.)

- [https://github.com/Live-Hack-CVE/CVE-2023-22626](https://github.com/Live-Hack-CVE/CVE-2023-22626) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22626.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22626.svg)


## CVE-2023-22454
 Discourse is an option source discussion platform. Prior to version 2.8.14 on the `stable` branch and version 3.0.0.beta16 on the `beta` and `tests-passed` branches, pending post titles can be used for cross-site scripting attacks. Pending posts can be created by unprivileged users when a category has the &quot;require moderator approval of all new topics&quot; setting set. This vulnerability can lead to a full XSS on sites which have modified or disabled Discourse&#8217;s default Content Security Policy. A patch is available in versions 2.8.14 and 3.0.0.beta16.

- [https://github.com/Live-Hack-CVE/CVE-2023-22454](https://github.com/Live-Hack-CVE/CVE-2023-22454) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22454.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22454.svg)


## CVE-2023-22453
 Discourse is an option source discussion platform. Prior to version 2.8.14 on the `stable` branch and version 3.0.0.beta16 on the `beta` and `tests-passed` branches, the number of times a user posted in an arbitrary topic is exposed to unauthorized users through the `/u/username.json` endpoint. The issue is patched in version 2.8.14 and 3.0.0.beta16. There is no known workaround.

- [https://github.com/Live-Hack-CVE/CVE-2023-22453](https://github.com/Live-Hack-CVE/CVE-2023-22453) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22453.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22453.svg)


## CVE-2023-0088
 The Swifty Page Manager plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 3.0.1. This is due to missing or incorrect nonce validation on several AJAX actions handling page creation and deletion among other things. This makes it possible for unauthenticated attackers to invoke those functions, via forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Live-Hack-CVE/CVE-2023-0088](https://github.com/Live-Hack-CVE/CVE-2023-0088) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0088.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0088.svg)


## CVE-2023-0087
 The Swifty Page Manager plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the &#8216;spm_plugin_options_page_tree_max_width&#8217; parameter in versions up to, and including, 3.0.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.

- [https://github.com/Live-Hack-CVE/CVE-2023-0087](https://github.com/Live-Hack-CVE/CVE-2023-0087) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0087.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0087.svg)


## CVE-2023-0086
 The JetWidgets for Elementor plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 1.0.12. This is due to missing nonce validation on the save() function. This makes it possible for unauthenticated attackers to to modify the plugin's settings via a forged request granted they can trick a site administrator into performing an action such as clicking on a link. This can be used to enable SVG uploads that could make Cross-Site Scripting possible.

- [https://github.com/Live-Hack-CVE/CVE-2023-0086](https://github.com/Live-Hack-CVE/CVE-2023-0086) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0086.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0086.svg)


## CVE-2023-0077
 Integer overflow or wraparound vulnerability in CGI component in Synology Router Manager (SRM) before 1.2.5-8227-6 and 1.3.1-9346-3 allows remote attackers to overflow buffers via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2023-0077](https://github.com/Live-Hack-CVE/CVE-2023-0077) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0077.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0077.svg)


## CVE-2022-47663
 GPAC MP4box 2.1-DEV-rev649-ga8f438d20 is vulnerable to buffer overflow in h263dmx_process filters/reframe_h263.c:609

- [https://github.com/Live-Hack-CVE/CVE-2022-47663](https://github.com/Live-Hack-CVE/CVE-2022-47663) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47663.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47663.svg)


## CVE-2022-47662
 GPAC MP4Box 2.1-DEV-rev649-ga8f438d20 has a segment fault (/stack overflow) due to infinite recursion in Media_GetSample isomedia/media.c:662

- [https://github.com/Live-Hack-CVE/CVE-2022-47662](https://github.com/Live-Hack-CVE/CVE-2022-47662) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47662.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47662.svg)


## CVE-2022-47661
 GPAC MP4Box 2.1-DEV-rev649-ga8f438d20 is vulnerable to Buffer Overflow via media_tools/av_parsers.c:4988 in gf_media_nalu_add_emulation_bytes

- [https://github.com/Live-Hack-CVE/CVE-2022-47661](https://github.com/Live-Hack-CVE/CVE-2022-47661) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47661.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47661.svg)


## CVE-2022-47660
 GPAC MP4Box 2.1-DEV-rev644-g5c4df2a67 is has an integer overflow in isomedia/isom_write.c

- [https://github.com/Live-Hack-CVE/CVE-2022-47660](https://github.com/Live-Hack-CVE/CVE-2022-47660) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47660.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47660.svg)


## CVE-2022-47659
 GPAC MP4box 2.1-DEV-rev644-g5c4df2a67 is vulnerable to Buffer Overflow in gf_bs_read_data

- [https://github.com/Live-Hack-CVE/CVE-2022-47659](https://github.com/Live-Hack-CVE/CVE-2022-47659) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47659.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47659.svg)


## CVE-2022-47658
 GPAC MP4Box 2.1-DEV-rev644-g5c4df2a67 is vulnerable to buffer overflow in function gf_hevc_read_vps_bs_internal of media_tools/av_parsers.c:8039

- [https://github.com/Live-Hack-CVE/CVE-2022-47658](https://github.com/Live-Hack-CVE/CVE-2022-47658) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47658.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47658.svg)


## CVE-2022-47657
 GPAC MP4Box 2.1-DEV-rev644-g5c4df2a67 is vulnerable to buffer overflow in function hevc_parse_vps_extension of media_tools/av_parsers.c:7662

- [https://github.com/Live-Hack-CVE/CVE-2022-47657](https://github.com/Live-Hack-CVE/CVE-2022-47657) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47657.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47657.svg)


## CVE-2022-47656
 GPAC MP4box 2.1-DEV-rev617-g85ce76efd is vulnerable to Buffer Overflow in gf_hevc_read_sps_bs_internal function of media_tools/av_parsers.c:8273

- [https://github.com/Live-Hack-CVE/CVE-2022-47656](https://github.com/Live-Hack-CVE/CVE-2022-47656) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47656.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47656.svg)


## CVE-2022-47655
 Libde265 1.0.9 is vulnerable to Buffer Overflow in function void put_qpel_fallback&lt;unsigned short&gt;

- [https://github.com/Live-Hack-CVE/CVE-2022-47655](https://github.com/Live-Hack-CVE/CVE-2022-47655) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47655.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47655.svg)


## CVE-2022-47654
 GPAC MP4box 2.1-DEV-rev593-g007bf61a0 is vulnerable to Buffer Overflow in gf_hevc_read_sps_bs_internal function of media_tools/av_parsers.c:8261

- [https://github.com/Live-Hack-CVE/CVE-2022-47654](https://github.com/Live-Hack-CVE/CVE-2022-47654) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47654.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47654.svg)


## CVE-2022-47653
 GPAC MP4box 2.1-DEV-rev593-g007bf61a0 is vulnerable to Buffer Overflow in eac3_update_channels function of media_tools/av_parsers.c:9113

- [https://github.com/Live-Hack-CVE/CVE-2022-47653](https://github.com/Live-Hack-CVE/CVE-2022-47653) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47653.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47653.svg)


## CVE-2022-47523
 Zoho ManageEngine Access Manager Plus before 4309, Password Manager Pro before 12210, and PAM360 before 5801 are vulnerable to SQL Injection.

- [https://github.com/Live-Hack-CVE/CVE-2022-47523](https://github.com/Live-Hack-CVE/CVE-2022-47523) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47523.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47523.svg)


## CVE-2022-46740
 There is a denial of service vulnerability in the Wi-Fi module of the HUAWEI WS7100-20 Smart WiFi Router.Successful exploit could cause a denial of service (DoS) condition.

- [https://github.com/Live-Hack-CVE/CVE-2022-46740](https://github.com/Live-Hack-CVE/CVE-2022-46740) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46740.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46740.svg)


## CVE-2022-46442
 dedecms &lt;=V5.7.102 is vulnerable to SQL Injection. In sys_ sql_ n query.php there are no restrictions on the sql query.

- [https://github.com/Live-Hack-CVE/CVE-2022-46442](https://github.com/Live-Hack-CVE/CVE-2022-46442) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46442.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46442.svg)


## CVE-2022-46177
 Discourse is an option source discussion platform. Prior to version 2.8.14 on the `stable` branch and version 3.0.0.beta16 on the `beta` and `tests-passed` branches, when a user requests for a password reset link email, then changes their primary email, the old reset email is still valid. When the old reset email is used to reset the password, the Discourse account's primary email would be re-linked to the old email. If the old email address is compromised or has transferred ownership, this leads to an account takeover. This is however mitigated by the SiteSetting `email_token_valid_hours` which is currently 48 hours. Users should upgrade to versions 2.8.14 or 3.0.0.beta15 to receive a patch. As a workaround, lower `email_token_valid_hours ` as needed.

- [https://github.com/Live-Hack-CVE/CVE-2022-46177](https://github.com/Live-Hack-CVE/CVE-2022-46177) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46177.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46177.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/sAsPeCt488/CVE-2022-46169](https://github.com/sAsPeCt488/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/sAsPeCt488/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/sAsPeCt488/CVE-2022-46169.svg)


## CVE-2022-46168
 Discourse is an option source discussion platform. Prior to version 2.8.14 on the `stable` branch and version 2.9.0.beta15 on the `beta` and `tests-passed` branches, recipients of a group SMTP email could see the email addresses of all other users inside the group SMTP topic. Most of the time this is not an issue as they are likely already familiar with one another's email addresses. This issue is patched in versions 2.8.14 and 2.9.0.beta15. The fix is that someone sending emails out via group SMTP to non-staged users masks those emails with blind carbon copy (BCC). Staged users are ones that have likely only interacted with the group via email, and will likely include other people who were CC'd on the original email to the group. As a workaround, disable group SMTP for any groups that have it enabled.

- [https://github.com/Live-Hack-CVE/CVE-2022-46168](https://github.com/Live-Hack-CVE/CVE-2022-46168) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46168.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46168.svg)


## CVE-2022-45995
 There is an unauthorized buffer overflow vulnerability in Tenda AX12 v22.03.01.21 _ cn. This vulnerability can cause the web service not to restart or even execute arbitrary code. It is a different vulnerability from CVE-2022-2414.

- [https://github.com/Live-Hack-CVE/CVE-2022-45995](https://github.com/Live-Hack-CVE/CVE-2022-45995) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45995.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45995.svg)


## CVE-2022-45874
 Huawei Aslan Children's Watch has an improper authorization vulnerability. Successful exploit could allow the attacker to access certain file.

- [https://github.com/Live-Hack-CVE/CVE-2022-45874](https://github.com/Live-Hack-CVE/CVE-2022-45874) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45874.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45874.svg)


## CVE-2022-45857
 An incorrect user management vulnerability [CWE-286] in the FortiManager version 6.4.6 and below VDOM creation component may allow an attacker to access a FortiGate without a password via newly created VDOMs after the super_admin account is deleted.

- [https://github.com/Live-Hack-CVE/CVE-2022-45857](https://github.com/Live-Hack-CVE/CVE-2022-45857) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45857.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45857.svg)


## CVE-2022-44877
 RESERVED An issue in the /login/index.php component of Centos Web Panel 7 before v0.9.8.1147 allows unauthenticated attackers to execute arbitrary system commands via crafted HTTP requests.

- [https://github.com/numanturle/CVE-2022-44877](https://github.com/numanturle/CVE-2022-44877) :  ![starts](https://img.shields.io/github/stars/numanturle/CVE-2022-44877.svg) ![forks](https://img.shields.io/github/forks/numanturle/CVE-2022-44877.svg)
- [https://github.com/Live-Hack-CVE/CVE-2022-44877](https://github.com/Live-Hack-CVE/CVE-2022-44877) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44877.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44877.svg)


## CVE-2022-44870
 A reflected cross-site scripting (XSS) vulnerability in maccms10 v2022.1000.3032 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the Name parameter under the AD Management module.

- [https://github.com/Live-Hack-CVE/CVE-2022-44870](https://github.com/Live-Hack-CVE/CVE-2022-44870) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44870.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44870.svg)


## CVE-2022-44564
 Huawei Aslan Children's Watch has a path traversal vulnerability. Successful exploitation may allow attackers to access or modify protected system resources.

- [https://github.com/Live-Hack-CVE/CVE-2022-44564](https://github.com/Live-Hack-CVE/CVE-2022-44564) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44564.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44564.svg)


## CVE-2022-44541
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2022-44541](https://github.com/Live-Hack-CVE/CVE-2022-44541) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44541.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44541.svg)


## CVE-2022-44540
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2022-44540](https://github.com/Live-Hack-CVE/CVE-2022-44540) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44540.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44540.svg)


## CVE-2022-44539
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2022-44539](https://github.com/Live-Hack-CVE/CVE-2022-44539) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44539.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44539.svg)


## CVE-2022-44538
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2022-44538](https://github.com/Live-Hack-CVE/CVE-2022-44538) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44538.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44538.svg)


## CVE-2022-44537
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2022-44537](https://github.com/Live-Hack-CVE/CVE-2022-44537) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44537.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44537.svg)


## CVE-2022-44536
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2022-44536](https://github.com/Live-Hack-CVE/CVE-2022-44536) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44536.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44536.svg)


## CVE-2022-43932
 Improper neutralization of special elements in output used by a downstream component ('Injection') vulnerability in CGI component in Synology Router Manager (SRM) before 1.2.5-8227-6 and 1.3.1-9346-3 allows remote attackers to read arbitrary files via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2022-43932](https://github.com/Live-Hack-CVE/CVE-2022-43932) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43932.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43932.svg)


## CVE-2022-43844
 IBM Robotic Process Automation for Cloud Pak 20.12 through 21.0.3 is vulnerable to broken access control. A user is not correctly redirected to the platform log out screen when logging out of IBM RPA for Cloud Pak. IBM X-Force ID: 239081.

- [https://github.com/Live-Hack-CVE/CVE-2022-43844](https://github.com/Live-Hack-CVE/CVE-2022-43844) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43844.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43844.svg)


## CVE-2022-43573
 IBM Robotic Process Automation 20.12 through 21.0.6 is vulnerable to exposure of the name and email for the creator/modifier of platform level objects. IBM X-Force ID: 238678.

- [https://github.com/Live-Hack-CVE/CVE-2022-43573](https://github.com/Live-Hack-CVE/CVE-2022-43573) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43573.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43573.svg)


## CVE-2022-43533
 A vulnerability in the ClearPass OnGuard macOS agent could allow malicious users on a macOS instance to elevate their user privileges. A successful exploit could allow these users to execute arbitrary code with root level privileges on the macOS instance in Aruba ClearPass Policy Manager version(s): ClearPass Policy Manager 6.10.x: 6.10.7 and below and ClearPass Policy Manager 6.9.x: 6.9.12 and below.

- [https://github.com/Live-Hack-CVE/CVE-2022-43533](https://github.com/Live-Hack-CVE/CVE-2022-43533) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43533.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43533.svg)


## CVE-2022-43532
 A vulnerability in the web-based management interface of ClearPass Policy Manager could allow an authenticated remote attacker to conduct a stored cross-site scripting (XSS) attack against an administrative user of the interface. A successful exploit allows an attacker to execute arbitrary script code in a victim's browser in the context of the affected interface in Aruba ClearPass Policy Manager version(s): ClearPass Policy Manager 6.10.x: 6.10.7 and below and ClearPass Policy Manager 6.9.x: 6.9.12 and below.

- [https://github.com/Live-Hack-CVE/CVE-2022-43532](https://github.com/Live-Hack-CVE/CVE-2022-43532) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43532.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43532.svg)


## CVE-2022-43529
 A vulnerability in the web-based management interface of Aruba EdgeConnect Enterprise Orchestrator could allow an remote attacker to persist a session after a password reset or similar session clearing event. Successful exploitation of this vulnerability could allow an authenticated attacker to remain on the system with the permissions of their current session after the session should be invalidated in Aruba EdgeConnect Enterprise Orchestration Software version(s): Aruba EdgeConnect Enterprise Orchestrator (on-premises), Aruba EdgeConnect Enterprise Orchestrator-as-a-Service, Aruba EdgeConnect Enterprise Orchestrator-SP and Aruba EdgeConnect Enterprise Orchestrator Global Enterprise Tenant Orchestrators - Orchestrator 9.2.1.40179 and below, - Orchestrator 9.1.4.40436 and below, - Orchestrator 9.0.7.40110 and below, - Orchestrator 8.10.23.40015 and below, - Any older branches of Orchestrator not specifically mentioned.

- [https://github.com/Live-Hack-CVE/CVE-2022-43529](https://github.com/Live-Hack-CVE/CVE-2022-43529) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43529.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43529.svg)


## CVE-2022-43522
 Multiple vulnerabilities in the web-based management interface of Aruba EdgeConnect Enterprise Orchestrator could allow an authenticated remote attacker to conduct SQL injection attacks against the Aruba EdgeConnect Enterprise Orchestrator instance. An attacker could exploit these vulnerabilities to obtain and modify sensitive information in the underlying database potentially leading to complete compromise of the Aruba EdgeConnect Enterprise Orchestrator host in Aruba EdgeConnect Enterprise Orchestration Software version(s): Aruba EdgeConnect Enterprise Orchestrator (on-premises), Aruba EdgeConnect Enterprise Orchestrator-as-a-Service, Aruba EdgeConnect Enterprise Orchestrator-SP and Aruba EdgeConnect Enterprise Orchestrator Global Enterprise Tenant Orchestrators - Orchestrator 9.2.1.40179 and below, - Orchestrator 9.1.4.40436 and below, - Orchestrator 9.0.7.40110 and below, - Orchestrator 8.10.23.40015 and below, - Any older branches of Orchestrator not specifically mentioned.

- [https://github.com/Live-Hack-CVE/CVE-2022-43522](https://github.com/Live-Hack-CVE/CVE-2022-43522) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43522.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43522.svg)


## CVE-2022-43143
 A cross-site scripting (XSS) vulnerability in Beekeeper Studio v3.6.6 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the error modal container.

- [https://github.com/goseungduk/beekeeper](https://github.com/goseungduk/beekeeper) :  ![starts](https://img.shields.io/github/stars/goseungduk/beekeeper.svg) ![forks](https://img.shields.io/github/forks/goseungduk/beekeeper.svg)


## CVE-2022-42979
 Information disclosure due to an insecure hostname validation in the RYDE application 5.8.43 for Android and iOS allows attackers to take over an account via a deep link.

- [https://github.com/Live-Hack-CVE/CVE-2022-42979](https://github.com/Live-Hack-CVE/CVE-2022-42979) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42979.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42979.svg)


## CVE-2022-42259
 NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where an integer overflow may lead to denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2022-42259](https://github.com/Live-Hack-CVE/CVE-2022-42259) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42259.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42259.svg)


## CVE-2022-42258
 NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where an integer overflow may lead to denial of service, data tampering, or information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2022-42258](https://github.com/Live-Hack-CVE/CVE-2022-42258) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42258.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42258.svg)


## CVE-2022-42257
 NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where an integer overflow may lead to information disclosure, data tampering or denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2022-42257](https://github.com/Live-Hack-CVE/CVE-2022-42257) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42257.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42257.svg)


## CVE-2022-41966
 XStream serializes Java objects to XML and back again. Versions prior to 1.4.20 may allow a remote attacker to terminate the application with a stack overflow error, resulting in a denial of service only via manipulation the processed input stream. The attack uses the hash code implementation for collections and maps to force recursive hash calculation causing a stack overflow. This issue is patched in version 1.4.20 which handles the stack overflow and raises an InputManipulationException instead. A potential workaround for users who only use HashMap or HashSet and whose XML refers these only as default map or set, is to change the default implementation of java.util.Map and java.util per the code example in the referenced advisory. However, this implies that your application does not care about the implementation of the map and all elements are comparable.

- [https://github.com/111ddea/Xstream_cve-2022-41966](https://github.com/111ddea/Xstream_cve-2022-41966) :  ![starts](https://img.shields.io/github/stars/111ddea/Xstream_cve-2022-41966.svg) ![forks](https://img.shields.io/github/forks/111ddea/Xstream_cve-2022-41966.svg)


## CVE-2022-41740
 IBM Robotic Process Automation 20.12 through 21.0.6 could allow an attacker with physical access to the system to obtain highly sensitive information from system memory. IBM X-Force ID: 238053.

- [https://github.com/Live-Hack-CVE/CVE-2022-41740](https://github.com/Live-Hack-CVE/CVE-2022-41740) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41740.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41740.svg)


## CVE-2022-41579
 There is an insufficient authentication vulnerability in some Huawei band products. Successful exploit could allow the attacker to spoof then connect to the band.

- [https://github.com/Live-Hack-CVE/CVE-2022-41579](https://github.com/Live-Hack-CVE/CVE-2022-41579) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41579.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41579.svg)


## CVE-2022-40049
 SQL injection vulnerability in sourcecodester Theme Park Ticketing System 1.0 allows remote attackers to view sensitive information via the id parameter to the /tpts/manage_user.php page.

- [https://github.com/Live-Hack-CVE/CVE-2022-40049](https://github.com/Live-Hack-CVE/CVE-2022-40049) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40049.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40049.svg)


## CVE-2022-39012
 Huawei Aslan Children's Watch has an improper input validation vulnerability. Successful exploitation may cause the watch's application service abnormal.

- [https://github.com/Live-Hack-CVE/CVE-2022-39012](https://github.com/Live-Hack-CVE/CVE-2022-39012) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39012.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39012.svg)


## CVE-2022-38209
 There is a reflected XSS vulnerability in Esri Portal for ArcGIS versions 10.9.1 and below which may allow a remote, unauthenticated attacker to create a crafted link which when clicked could execute arbitrary JavaScript code in the victim&#8217;s browser.

- [https://github.com/Live-Hack-CVE/CVE-2022-38209](https://github.com/Live-Hack-CVE/CVE-2022-38209) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38209.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38209.svg)


## CVE-2022-38207
 There is a reflected XSS vulnerability in Esri Portal for ArcGIS versions 10.8.1 and 10.7.1 which may allow a remote remote, unauthenticated attacker to create a crafted link which when clicked which could execute arbitrary JavaScript code in the victim&#8217;s browser.

- [https://github.com/Live-Hack-CVE/CVE-2022-38207](https://github.com/Live-Hack-CVE/CVE-2022-38207) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38207.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38207.svg)


## CVE-2022-38206
 There is a reflected XSS vulnerability in Esri Portal for ArcGIS versions 10.9.1 and below which may allow a remote remote, unauthenticated attacker to create a crafted link which when clicked could execute arbitrary JavaScript code in the victim&#8217;s browser.

- [https://github.com/Live-Hack-CVE/CVE-2022-38206](https://github.com/Live-Hack-CVE/CVE-2022-38206) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38206.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38206.svg)


## CVE-2022-38205
 In some non-default installations of Esri Portal for ArcGIS versions 10.9.1 and below, a directory traversal issue may allow a remote, unauthenticated attacker to traverse the file system and lead to the disclosure of sensitive data (not customer-published content).

- [https://github.com/Live-Hack-CVE/CVE-2022-38205](https://github.com/Live-Hack-CVE/CVE-2022-38205) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38205.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38205.svg)


## CVE-2022-38204
 There is a reflected XSS vulnerability in Esri Portal for ArcGIS versions 10.8.1 and 10.7.1 which may allow a remote, unauthenticated attacker to create a crafted link which when clicked could potentially execute arbitrary JavaScript code in the victim&#8217;s browser.

- [https://github.com/Live-Hack-CVE/CVE-2022-38204](https://github.com/Live-Hack-CVE/CVE-2022-38204) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38204.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38204.svg)


## CVE-2022-34680
 NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an integer truncation can lead to an out-of-bounds read, which may lead to denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2022-34680](https://github.com/Live-Hack-CVE/CVE-2022-34680) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34680.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34680.svg)


## CVE-2022-29455
 DOM-based Reflected Cross-Site Scripting (XSS) vulnerability in Elementor's Elementor Website Builder plugin &lt;= 3.5.5 versions.

- [https://github.com/yaudahbanh/CVE-2022-29455](https://github.com/yaudahbanh/CVE-2022-29455) :  ![starts](https://img.shields.io/github/stars/yaudahbanh/CVE-2022-29455.svg) ![forks](https://img.shields.io/github/forks/yaudahbanh/CVE-2022-29455.svg)


## CVE-2022-23549
 Discourse is an option source discussion platform. Prior to version 2.8.14 on the `stable` branch and version 2.9.0.beta16 on the `beta` and `tests-passed` branches, users can create posts with raw body longer than the `max_length` site setting by including html comments that are not counted toward the character limit. This issue is patched in versions 2.8.14 and 2.9.0.beta16. There are no known workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2022-23549](https://github.com/Live-Hack-CVE/CVE-2022-23549) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23549.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23549.svg)


## CVE-2022-23548
 Discourse is an option source discussion platform. Prior to version 2.8.14 on the `stable` branch and version 2.9.0.beta16 on the `beta` and `tests-passed` branches, parsing posts can be susceptible to XSS attacks. This issue is patched in versions 2.8.14 and 2.9.0.beta16. There are no known workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2022-23548](https://github.com/Live-Hack-CVE/CVE-2022-23548) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23548.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23548.svg)


## CVE-2022-23546
 In version 2.9.0.beta14 of Discourse, an open-source discussion platform, maliciously embedded urls can leak an admin's digest of recent topics, possibly exposing private information. A patch is available for version 2.9.0.beta15. There are no known workarounds for this issue.

- [https://github.com/Live-Hack-CVE/CVE-2022-23546](https://github.com/Live-Hack-CVE/CVE-2022-23546) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23546.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23546.svg)


## CVE-2022-23544
 MeterSphere is a one-stop open source continuous testing platform, covering test management, interface testing, UI testing and performance testing. Versions prior to 2.5.0 are subject to a Server-Side Request Forgery that leads to Cross-Site Scripting. A Server-Side request forgery in `IssueProxyResourceService::getMdImageByUrl` allows an attacker to access internal resources, as well as executing JavaScript code in the context of Metersphere's origin by a victim of a reflected XSS. This vulnerability has been fixed in v2.5.0. There are no known workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2022-23544](https://github.com/Live-Hack-CVE/CVE-2022-23544) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23544.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23544.svg)


## CVE-2022-22371
 IBM Sterling B2B Integrator Standard Edition 6.0.0.0 through 6.1.2.1 does not invalidate session after a password change which could allow an authenticated user to impersonate another user on the system. IBM X-Force ID: 221195.

- [https://github.com/Live-Hack-CVE/CVE-2022-22371](https://github.com/Live-Hack-CVE/CVE-2022-22371) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-22371.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-22371.svg)


## CVE-2022-4877
 A vulnerability has been found in snoyberg keter up to 1.8.1 and classified as problematic. This vulnerability affects unknown code of the file Keter/Proxy.hs. The manipulation of the argument host leads to cross site scripting. The attack can be initiated remotely. Upgrading to version 1.8.2 is able to address this issue. The name of the patch is d41f3697926b231782a3ad8050f5af1ce5cc40b7. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-217444.

- [https://github.com/Live-Hack-CVE/CVE-2022-4877](https://github.com/Live-Hack-CVE/CVE-2022-4877) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4877.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4877.svg)


## CVE-2022-4869
 A vulnerability was found in Evolution Events Artaxerxes. It has been declared as problematic. This vulnerability affects unknown code of the file arta/common/middleware.py of the component POST Parameter Handler. The manipulation of the argument password leads to information disclosure. The attack can be initiated remotely. The name of the patch is 022111407d34815c16c6eada2de69ca34084dc0d. It is recommended to apply a patch to fix this issue. VDB-217438 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4869](https://github.com/Live-Hack-CVE/CVE-2022-4869) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4869.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4869.svg)


## CVE-2022-4822
 A vulnerability, which was classified as problematic, has been found in FlatPress. This issue affects some unknown processing of the file setup/lib/main.lib.php of the component Setup. The manipulation leads to cross site scripting. The attack may be initiated remotely. The name of the patch is 5f23b4c2eac294cc0ba5e541f83a6f8a26f9fed1. It is recommended to apply a patch to fix this issue. The identifier VDB-217001 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4822](https://github.com/Live-Hack-CVE/CVE-2022-4822) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4822.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4822.svg)


## CVE-2022-4821
 A vulnerability classified as problematic was found in FlatPress. This vulnerability affects the function onupload of the file admin/panels/uploader/admin.uploader.php of the component XML File Handler/MD File Handler. The manipulation leads to cross site scripting. The attack can be initiated remotely. The name of the patch is 3cc223dec5260e533a84b5cf5780d3a4fbf21241. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217000.

- [https://github.com/Live-Hack-CVE/CVE-2022-4821](https://github.com/Live-Hack-CVE/CVE-2022-4821) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4821.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4821.svg)


## CVE-2022-4820
 A vulnerability classified as problematic has been found in FlatPress. This affects an unknown part of the file admin/panels/entry/admin.entry.list.php of the component Admin Area. The manipulation leads to cross site scripting. It is possible to initiate the attack remotely. The name of the patch is 229752b51025e678370298284d42f8ebb231f67f. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-216999.

- [https://github.com/Live-Hack-CVE/CVE-2022-4820](https://github.com/Live-Hack-CVE/CVE-2022-4820) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4820.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4820.svg)


## CVE-2022-4819
 A vulnerability was found in HotCRP. It has been rated as problematic. Affected by this issue is some unknown functionality. The manipulation leads to cross site scripting. The attack may be launched remotely. The name of the patch is d4ffdb0ef806453c54ddca7fdda3e5c60356285c. It is recommended to apply a patch to fix this issue. VDB-216998 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4819](https://github.com/Live-Hack-CVE/CVE-2022-4819) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4819.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4819.svg)


## CVE-2022-4814
 Improper Access Control in GitHub repository usememos/memos prior to 0.9.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-4814](https://github.com/Live-Hack-CVE/CVE-2022-4814) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4814.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4814.svg)


## CVE-2022-4813
 Insufficient Granularity of Access Control in GitHub repository usememos/memos prior to 0.9.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-4813](https://github.com/Live-Hack-CVE/CVE-2022-4813) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4813.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4813.svg)


## CVE-2022-4812
 Comparison of Object References Instead of Object Contents in GitHub repository usememos/memos prior to 0.9.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-4812](https://github.com/Live-Hack-CVE/CVE-2022-4812) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4812.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4812.svg)


## CVE-2022-4811
 Improper Authorization in GitHub repository usememos/memos prior to 0.9.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-4811](https://github.com/Live-Hack-CVE/CVE-2022-4811) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4811.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4811.svg)


## CVE-2022-4810
 Improper Access Control in GitHub repository usememos/memos prior to 0.9.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-4810](https://github.com/Live-Hack-CVE/CVE-2022-4810) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4810.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4810.svg)


## CVE-2022-4809
 Improper Access Control in GitHub repository usememos/memos prior to 0.9.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-4809](https://github.com/Live-Hack-CVE/CVE-2022-4809) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4809.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4809.svg)


## CVE-2022-4808
 Improper Privilege Management in GitHub repository usememos/memos prior to 0.9.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-4808](https://github.com/Live-Hack-CVE/CVE-2022-4808) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4808.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4808.svg)


## CVE-2022-4807
 Improper Access Control in GitHub repository usememos/memos prior to 0.9.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-4807](https://github.com/Live-Hack-CVE/CVE-2022-4807) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4807.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4807.svg)


## CVE-2022-4806
 Improper Access Control in GitHub repository usememos/memos prior to 0.9.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-4806](https://github.com/Live-Hack-CVE/CVE-2022-4806) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4806.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4806.svg)


## CVE-2022-4805
 Incorrect Use of Privileged APIs in GitHub repository usememos/memos prior to 0.9.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-4805](https://github.com/Live-Hack-CVE/CVE-2022-4805) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4805.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4805.svg)


## CVE-2022-4803
 Improper Access Control in GitHub repository usememos/memos prior to 0.9.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-4803](https://github.com/Live-Hack-CVE/CVE-2022-4803) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4803.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4803.svg)


## CVE-2022-4802
 Improper Authorization in GitHub repository usememos/memos prior to 0.9.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-4802](https://github.com/Live-Hack-CVE/CVE-2022-4802) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4802.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4802.svg)


## CVE-2022-4801
 Insufficient Granularity of Access Control in GitHub repository usememos/memos prior to 0.9.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-4801](https://github.com/Live-Hack-CVE/CVE-2022-4801) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4801.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4801.svg)


## CVE-2022-4800
 Improper Verification of Source of a Communication Channel in GitHub repository usememos/memos prior to 0.9.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-4800](https://github.com/Live-Hack-CVE/CVE-2022-4800) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4800.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4800.svg)


## CVE-2022-4733
 Cross-site Scripting (XSS) - Stored in GitHub repository openemr/openemr prior to 7.0.0.2.

- [https://github.com/Live-Hack-CVE/CVE-2022-4733](https://github.com/Live-Hack-CVE/CVE-2022-4733) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4733.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4733.svg)


## CVE-2022-4730
 A vulnerability was found in Graphite Web. It has been classified as problematic. Affected is an unknown function of the component Absolute Time Range Handler. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The name of the patch is 2f178f490e10efc03cd1d27c72f64ecab224eb23. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-216744.

- [https://github.com/Live-Hack-CVE/CVE-2022-4730](https://github.com/Live-Hack-CVE/CVE-2022-4730) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4730.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4730.svg)


## CVE-2022-4724
 Improper Access Control in GitHub repository ikus060/rdiffweb prior to 2.5.5.

- [https://github.com/Live-Hack-CVE/CVE-2022-4724](https://github.com/Live-Hack-CVE/CVE-2022-4724) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4724.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4724.svg)


## CVE-2022-4723
 Allocation of Resources Without Limits or Throttling in GitHub repository ikus060/rdiffweb prior to 2.5.5.

- [https://github.com/Live-Hack-CVE/CVE-2022-4723](https://github.com/Live-Hack-CVE/CVE-2022-4723) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4723.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4723.svg)


## CVE-2022-4722
 Authentication Bypass by Primary Weakness in GitHub repository ikus060/rdiffweb prior to 2.5.5.

- [https://github.com/Live-Hack-CVE/CVE-2022-4722](https://github.com/Live-Hack-CVE/CVE-2022-4722) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4722.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4722.svg)


## CVE-2022-4721
 Failure to Sanitize Special Elements into a Different Plane (Special Element Injection) in GitHub repository ikus060/rdiffweb prior to 2.5.5.

- [https://github.com/Live-Hack-CVE/CVE-2022-4721](https://github.com/Live-Hack-CVE/CVE-2022-4721) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4721.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4721.svg)


## CVE-2022-4720
 Open Redirect in GitHub repository ikus060/rdiffweb prior to 2.5.5.

- [https://github.com/Live-Hack-CVE/CVE-2022-4720](https://github.com/Live-Hack-CVE/CVE-2022-4720) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4720.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4720.svg)


## CVE-2022-4719
 Business Logic Errors in GitHub repository ikus060/rdiffweb prior to 2.5.5.

- [https://github.com/Live-Hack-CVE/CVE-2022-4719](https://github.com/Live-Hack-CVE/CVE-2022-4719) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4719.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4719.svg)


## CVE-2022-4695
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.9.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-4695](https://github.com/Live-Hack-CVE/CVE-2022-4695) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4695.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4695.svg)


## CVE-2022-4694
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.9.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-4694](https://github.com/Live-Hack-CVE/CVE-2022-4694) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4694.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4694.svg)


## CVE-2022-4691
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.9.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-4691](https://github.com/Live-Hack-CVE/CVE-2022-4691) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4691.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4691.svg)


## CVE-2022-4435
 A buffer over-read vulnerability was reported in the ThinkPadX13s BIOS LenovoRemoteConfigUpdateDxe driver that could allow a local attacker with elevated privileges to cause information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2022-4435](https://github.com/Live-Hack-CVE/CVE-2022-4435) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4435.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4435.svg)


## CVE-2022-4434
 A buffer over-read vulnerability was reported in the ThinkPadX13s BIOS driver that could allow a local attacker with elevated privileges to cause information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2022-4434](https://github.com/Live-Hack-CVE/CVE-2022-4434) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4434.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4434.svg)


## CVE-2022-4433
 A buffer over-read vulnerability was reported in the ThinkPadX13s BIOS LenovoSetupConfigDxe driver that could allow a local attacker with elevated privileges to cause information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2022-4433](https://github.com/Live-Hack-CVE/CVE-2022-4433) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4433.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4433.svg)


## CVE-2022-4432
 A buffer over-read vulnerability was reported in the ThinkPadX13s BIOS PersistenceConfigDxe driver that could allow a local attacker with elevated privileges to cause information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2022-4432](https://github.com/Live-Hack-CVE/CVE-2022-4432) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4432.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4432.svg)


## CVE-2022-4402
 A vulnerability classified as critical has been found in RainyGao DocSys 2.02.37. This affects an unknown part of the component ZIP File Decompression Handler. The manipulation leads to path traversal: '../filedir'. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-215271.

- [https://github.com/Live-Hack-CVE/CVE-2022-4402](https://github.com/Live-Hack-CVE/CVE-2022-4402) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4402.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4402.svg)


## CVE-2022-4378
 A stack overflow flaw was found in the Linux kernel's SYSCTL subsystem in how a user changes certain kernel parameters and variables. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/Live-Hack-CVE/CVE-2022-4378](https://github.com/Live-Hack-CVE/CVE-2022-4378) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4378.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4378.svg)


## CVE-2022-4055
 When xdg-mail is configured to use thunderbird for mailto URLs, improper parsing of the URL can lead to additional headers being passed to thunderbird that should not be included per RFC 2368. An attacker can use this method to create a mailto URL that looks safe to users, but will actually attach files when clicked.

- [https://github.com/Live-Hack-CVE/CVE-2022-4055](https://github.com/Live-Hack-CVE/CVE-2022-4055) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4055.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4055.svg)


## CVE-2022-3929
 Communication between the client and the server application of the affected products is partially done using CORBA (Common Object Request Broker Architecture) over TCP/IP. This protocol is not encrypted and allows tracing of internal messages. This issue affects * FOXMAN-UN product: FOXMAN-UN R15B, FOXMAN-UN R15A, FOXMAN-UN R14B, FOXMAN-UN R14A, FOXMAN-UN R11B, FOXMAN-UN R11A, FOXMAN-UN R10C, FOXMAN-UN R9C; * UNEM product: UNEM R15B, UNEM R15A, UNEM R14B, UNEM R14A, UNEM R11B, UNEM R11A, UNEM R10C, UNEM R9C. List of CPEs: * cpe:2.3:a:hitachienergy:foxman-un:R15B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R15A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R14B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R14A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R11B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R11A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R10C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R9C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R15B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R15A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R14B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R14A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R11B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R11A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R10C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R9C:*:*:*:*:*:*:*

- [https://github.com/Live-Hack-CVE/CVE-2022-3929](https://github.com/Live-Hack-CVE/CVE-2022-3929) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3929.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3929.svg)


## CVE-2022-3928
 Hardcoded credential is found in affected products' message queue. An attacker that manages to exploit this vulnerability will be able to access data to the internal message queue. This issue affects * FOXMAN-UN product: FOXMAN-UN R15B, FOXMAN-UN R15A, FOXMAN-UN R14B, FOXMAN-UN R14A, FOXMAN-UN R11B, FOXMAN-UN R11A, FOXMAN-UN R10C, FOXMAN-UN R9C; * UNEM product: UNEM R15B, UNEM R15A, UNEM R14B, UNEM R14A, UNEM R11B, UNEM R11A, UNEM R10C, UNEM R9C. List of CPEs: * cpe:2.3:a:hitachienergy:foxman-un:R15B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R15A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R14B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R14A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R11B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R11A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R10C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R9C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R15B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R15A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R14B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R14A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R11B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R11A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R10C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R9C:*:*:*:*:*:*:*

- [https://github.com/Live-Hack-CVE/CVE-2022-3928](https://github.com/Live-Hack-CVE/CVE-2022-3928) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3928.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3928.svg)


## CVE-2022-3927
 The affected products store both public and private key that are used to sign and protect Custom Parameter Set (CPS) file from modification. An attacker that manages to exploit this vulnerability will be able to change the CPS file, sign it so that it is trusted as the legitimate CPS file. This issue affects * FOXMAN-UN product: FOXMAN-UN R15B, FOXMAN-UN R15A, FOXMAN-UN R14B, FOXMAN-UN R14A, FOXMAN-UN R11B, FOXMAN-UN R11A, FOXMAN-UN R10C, FOXMAN-UN R9C; * UNEM product: UNEM R15B, UNEM R15A, UNEM R14B, UNEM R14A, UNEM R11B, UNEM R11A, UNEM R10C, UNEM R9C. List of CPEs: * cpe:2.3:a:hitachienergy:foxman-un:R15B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R15A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R14B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R14A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R11B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R11A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R10C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R9C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R15B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R15A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R14B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R14A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R11B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R11A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R10C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R9C:*:*:*:*:*:*:*

- [https://github.com/Live-Hack-CVE/CVE-2022-3927](https://github.com/Live-Hack-CVE/CVE-2022-3927) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3927.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3927.svg)


## CVE-2022-3222
 Uncontrolled Recursion in GitHub repository gpac/gpac prior to 2.1.0-DEV.

- [https://github.com/Live-Hack-CVE/CVE-2022-3222](https://github.com/Live-Hack-CVE/CVE-2022-3222) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3222.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3222.svg)


## CVE-2022-2583
 A race condition can cause incorrect HTTP request routing.

- [https://github.com/Live-Hack-CVE/CVE-2022-2583](https://github.com/Live-Hack-CVE/CVE-2022-2583) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2583.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2583.svg)


## CVE-2022-2582
 The AWS S3 Crypto SDK sends an unencrypted hash of the plaintext alongside the ciphertext as a metadata field. This hash can be used to brute force the plaintext, if the hash is readable to the attacker. AWS now blocks this metadata field, but older SDK versions still send it.

- [https://github.com/Live-Hack-CVE/CVE-2022-2582](https://github.com/Live-Hack-CVE/CVE-2022-2582) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2582.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2582.svg)


## CVE-2022-2447
 A flaw was found in Keystone. There is a time lag (up to one hour in a default configuration) between when security policy says a token should be revoked from when it is actually revoked. This could allow a remote administrator to secretly maintain access for longer than expected.

- [https://github.com/Live-Hack-CVE/CVE-2022-2447](https://github.com/Live-Hack-CVE/CVE-2022-2447) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2447.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2447.svg)


## CVE-2022-2414
 Access to external entities when parsing XML documents can lead to XML external entity (XXE) attacks. This flaw allows a remote attacker to potentially retrieve the content of arbitrary files by sending specially crafted HTTP requests.

- [https://github.com/Live-Hack-CVE/CVE-2022-45995](https://github.com/Live-Hack-CVE/CVE-2022-45995) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45995.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45995.svg)


## CVE-2022-2285
 Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-2285](https://github.com/Live-Hack-CVE/CVE-2022-2285) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2285.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2285.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/vida003/Scanner-CVE-2021-41773](https://github.com/vida003/Scanner-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/vida003/Scanner-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vida003/Scanner-CVE-2021-41773.svg)


## CVE-2021-41010
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2021-41010](https://github.com/Live-Hack-CVE/CVE-2021-41010) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41010.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41010.svg)


## CVE-2021-41009
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2021-41009](https://github.com/Live-Hack-CVE/CVE-2021-41009) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41009.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41009.svg)


## CVE-2021-41008
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2021-41008](https://github.com/Live-Hack-CVE/CVE-2021-41008) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41008.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41008.svg)


## CVE-2021-41007
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2021-41007](https://github.com/Live-Hack-CVE/CVE-2021-41007) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41007.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41007.svg)


## CVE-2021-41006
 CVE was unused by HPE.

- [https://github.com/Live-Hack-CVE/CVE-2021-41006](https://github.com/Live-Hack-CVE/CVE-2021-41006) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41006.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41006.svg)


## CVE-2021-40342
 In the DES implementation, the affected product versions use a default key for encryption. Successful exploitation allows an attacker to obtain sensitive information and gain access to the network elements that are managed by the affected products versions. This issue affects * FOXMAN-UN product: FOXMAN-UN R16A, FOXMAN-UN R15B, FOXMAN-UN R15A, FOXMAN-UN R14B, FOXMAN-UN R14A, FOXMAN-UN R11B, FOXMAN-UN R11A, FOXMAN-UN R10C, FOXMAN-UN R9C; * UNEM product: UNEM R16A, UNEM R15B, UNEM R15A, UNEM R14B, UNEM R14A, UNEM R11B, UNEM R11A, UNEM R10C, UNEM R9C. List of CPEs: * cpe:2.3:a:hitachienergy:foxman-un:R16A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R15B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R15A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R14B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R14A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R11B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R11A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R10C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R9C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R16A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R15B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R15A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R14B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R14A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R11B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R11A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R10C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R9C:*:*:*:*:*:*:*

- [https://github.com/Live-Hack-CVE/CVE-2021-40342](https://github.com/Live-Hack-CVE/CVE-2021-40342) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-40342.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-40342.svg)


## CVE-2021-40341
 DES cipher, which has inadequate encryption strength, is used Hitachi Energy FOXMAN-UN to encrypt user credentials used to access the Network Elements. Successful exploitation allows sensitive information to be decrypted easily. This issue affects * FOXMAN-UN product: FOXMAN-UN R16A, FOXMAN-UN R15B, FOXMAN-UN R15A, FOXMAN-UN R14B, FOXMAN-UN R14A, FOXMAN-UN R11B, FOXMAN-UN R11A, FOXMAN-UN R10C, FOXMAN-UN R9C; * UNEM product: UNEM R16A, UNEM R15B, UNEM R15A, UNEM R14B, UNEM R14A, UNEM R11B, UNEM R11A, UNEM R10C, UNEM R9C. List of CPEs: * cpe:2.3:a:hitachienergy:foxman-un:R16A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R15B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R15A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R14B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R14A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R11B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R11A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R10C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R9C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R16A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R15B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R15A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R14B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R14A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R11B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R11A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R10C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R9C:*:*:*:*:*:*:*

- [https://github.com/Live-Hack-CVE/CVE-2021-40341](https://github.com/Live-Hack-CVE/CVE-2021-40341) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-40341.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-40341.svg)


## CVE-2021-37678
 TensorFlow is an end-to-end open source platform for machine learning. In affected versions TensorFlow and Keras can be tricked to perform arbitrary code execution when deserializing a Keras model from YAML format. The [implementation](https://github.com/tensorflow/tensorflow/blob/460e000de3a83278fb00b61a16d161b1964f15f4/tensorflow/python/keras/saving/model_config.py#L66-L104) uses `yaml.unsafe_load` which can perform arbitrary code execution on the input. Given that YAML format support requires a significant amount of work, we have removed it for now. We have patched the issue in GitHub commit 23d6383eb6c14084a8fc3bdf164043b974818012. The fix will be included in TensorFlow 2.6.0. We will also cherrypick this commit on TensorFlow 2.5.1, TensorFlow 2.4.3, and TensorFlow 2.3.4, as these are also affected and still in supported range.

- [https://github.com/fran-CICS/ExploitTensorflowCVE-2021-37678](https://github.com/fran-CICS/ExploitTensorflowCVE-2021-37678) :  ![starts](https://img.shields.io/github/stars/fran-CICS/ExploitTensorflowCVE-2021-37678.svg) ![forks](https://img.shields.io/github/forks/fran-CICS/ExploitTensorflowCVE-2021-37678.svg)


## CVE-2021-36394
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/lavclash75/CVE-2021-36394-Pre-Auth-RCE-in-Moodle](https://github.com/lavclash75/CVE-2021-36394-Pre-Auth-RCE-in-Moodle) :  ![starts](https://img.shields.io/github/stars/lavclash75/CVE-2021-36394-Pre-Auth-RCE-in-Moodle.svg) ![forks](https://img.shields.io/github/forks/lavclash75/CVE-2021-36394-Pre-Auth-RCE-in-Moodle.svg)


## CVE-2021-32828
 The Nuxeo Platform is an open source content management platform for building business applications. In version 11.5.109, the `oauth2` REST API is vulnerable to Reflected Cross-Site Scripting (XSS). This XSS can be escalated to Remote Code Execution (RCE) by levering the automation API.

- [https://github.com/Live-Hack-CVE/CVE-2021-32828](https://github.com/Live-Hack-CVE/CVE-2021-32828) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-32828.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-32828.svg)


## CVE-2021-32563
 An issue was discovered in Thunar before 4.16.7 and 4.17.x before 4.17.2. When called with a regular file as a command-line argument, it delegates to a different program (based on the file type) without user confirmation. This could be used to achieve code execution.

- [https://github.com/Live-Hack-CVE/CVE-2021-32563](https://github.com/Live-Hack-CVE/CVE-2021-32563) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-32563.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-32563.svg)


## CVE-2021-25223
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-25223](https://github.com/Live-Hack-CVE/CVE-2021-25223) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-25223.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-25223.svg)


## CVE-2021-25222
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2021-25222](https://github.com/Live-Hack-CVE/CVE-2021-25222) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-25222.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-25222.svg)


## CVE-2021-4305
 A vulnerability was found in Woorank robots-txt-guard. It has been rated as problematic. Affected by this issue is the function makePathPattern of the file lib/patterns.js. The manipulation of the argument pattern leads to inefficient regular expression complexity. The exploit has been disclosed to the public and may be used. The name of the patch is c03827cd2f9933619c23894ce7c98401ea824020. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217448.

- [https://github.com/Live-Hack-CVE/CVE-2021-4305](https://github.com/Live-Hack-CVE/CVE-2021-4305) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4305.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4305.svg)


## CVE-2021-4304
 A vulnerability was found in eprintsug ulcc-core. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file cgi/toolbox/toolbox. The manipulation of the argument password leads to command injection. The attack can be launched remotely. The name of the patch is 811edaae81eb044891594f00062a828f51b22cb1. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217447.

- [https://github.com/Live-Hack-CVE/CVE-2021-4304](https://github.com/Live-Hack-CVE/CVE-2021-4304) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4304.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4304.svg)


## CVE-2021-4303
 A vulnerability, which was classified as problematic, has been found in shannah Xataface up to 2.x. Affected by this issue is the function testftp of the file install/install_form.js.php of the component Installer. The manipulation leads to cross site scripting. The attack may be launched remotely. Upgrading to version 3.0.0 is able to address this issue. The name of the patch is 94143a4299e386f33bf582139cd4702571d93bde. It is recommended to upgrade the affected component. VDB-217442 is the identifier assigned to this vulnerability. NOTE: Installer is disabled by default.

- [https://github.com/Live-Hack-CVE/CVE-2021-4303](https://github.com/Live-Hack-CVE/CVE-2021-4303) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4303.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4303.svg)


## CVE-2021-4291
 A vulnerability was found in OpenMRS Admin UI Module up to 1.5.x. It has been declared as problematic. This vulnerability affects unknown code of the file omod/src/main/webapp/pages/metadata/locations/location.gsp. The manipulation leads to cross site scripting. The attack can be initiated remotely. Upgrading to version 1.6.0 is able to address this issue. The name of the patch is a7eefb5f69f6c50a3bffcb138bb8ea57cb41a9b6. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-216916.

- [https://github.com/Live-Hack-CVE/CVE-2021-4291](https://github.com/Live-Hack-CVE/CVE-2021-4291) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4291.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4291.svg)


## CVE-2021-4239
 The Noise protocol implementation suffers from weakened cryptographic security after encrypting 2^64 messages, and a potential denial of service attack. After 2^64 (~18.4 quintillion) messages are encrypted with the Encrypt function, the nonce counter will wrap around, causing multiple messages to be encrypted with the same key and nonce. In a separate issue, the Decrypt function increments the nonce state even when it fails to decrypt a message. If an attacker can provide an invalid input to the Decrypt function, this will cause the nonce state to desynchronize between the peers, resulting in a failure to encrypt all subsequent messages.

- [https://github.com/Live-Hack-CVE/CVE-2021-4239](https://github.com/Live-Hack-CVE/CVE-2021-4239) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4239.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4239.svg)


## CVE-2021-4235
 Due to unbounded alias chasing, a maliciously crafted YAML file can cause the system to consume significant system resources. If parsing user input, this may be used as a denial of service vector.

- [https://github.com/Live-Hack-CVE/CVE-2021-4235](https://github.com/Live-Hack-CVE/CVE-2021-4235) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4235.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4235.svg)


## CVE-2020-36641
 A vulnerability classified as problematic was found in gturri aXMLRPC up to 1.12.0. This vulnerability affects the function ResponseParser of the file src/main/java/de/timroes/axmlrpc/ResponseParser.java. The manipulation leads to xml external entity reference. Upgrading to version 1.12.1 is able to address this issue. The name of the patch is ad6615b3ec41353e614f6ea5fdd5b046442a832b. It is recommended to upgrade the affected component. VDB-217450 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2020-36641](https://github.com/Live-Hack-CVE/CVE-2020-36641) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36641.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36641.svg)


## CVE-2020-36636
 A vulnerability classified as problematic has been found in OpenMRS Admin UI Module up to 1.4.x. Affected is the function sendErrorMessage of the file omod/src/main/java/org/openmrs/module/adminui/page/controller/systemadmin/accounts/AccountPageController.java of the component Account Setup Handler. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 1.5.0 is able to address this issue. The name of the patch is 702fbfdac7c4418f23bb5f6452482b4a88020061. It is recommended to upgrade the affected component. VDB-216918 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2020-36636](https://github.com/Live-Hack-CVE/CVE-2020-36636) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36636.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36636.svg)


## CVE-2020-36634
 A vulnerability classified as problematic has been found in Indeed Engineering util up to 1.0.33. Affected is the function visit/appendTo of the file varexport/src/main/java/com/indeed/util/varexport/servlet/ViewExportedVariablesServlet.java. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 1.0.34 is able to address this issue. The name of the patch is c0952a9db51a880e9544d9fac2a2218a6bfc9c63. It is recommended to upgrade the affected component. VDB-216882 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2020-36634](https://github.com/Live-Hack-CVE/CVE-2020-36634) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36634.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36634.svg)


## CVE-2020-36633
 A vulnerability was found in moodle-block_sitenews 1.0. It has been classified as problematic. This affects the function get_content of the file block_sitenews.php. The manipulation leads to cross-site request forgery. It is possible to initiate the attack remotely. Upgrading to version 1.1 is able to address this issue. The name of the patch is cd18d8b1afe464ae6626832496f4e070bac4c58f. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-216879.

- [https://github.com/Live-Hack-CVE/CVE-2020-36633](https://github.com/Live-Hack-CVE/CVE-2020-36633) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36633.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36633.svg)


## CVE-2020-36569
 Authentication is globally bypassed in github.com/nanobox-io/golang-nanoauth between v0.0.0-20160722212129-ac0cc4484ad4 and v0.0.0-20200131131040-063a3fb69896 if ListenAndServe is called with an empty token.

- [https://github.com/Live-Hack-CVE/CVE-2020-36569](https://github.com/Live-Hack-CVE/CVE-2020-36569) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36569.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36569.svg)


## CVE-2020-36564
 Due to improper validation of caller input, validation is silently disabled if the provided expected token is malformed, causing any user supplied token to be considered valid.

- [https://github.com/Live-Hack-CVE/CVE-2020-36564](https://github.com/Live-Hack-CVE/CVE-2020-36564) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36564.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36564.svg)


## CVE-2020-36561
 Due to improper path santization, archives containing relative file paths can cause files to be written (or overwritten) outside of the target directory.

- [https://github.com/Live-Hack-CVE/CVE-2020-36561](https://github.com/Live-Hack-CVE/CVE-2020-36561) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36561.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36561.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/NAXG/CVE-2020-1472](https://github.com/NAXG/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/NAXG/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/NAXG/CVE-2020-1472.svg)
- [https://github.com/Fa1c0n35/CVE-2020-1472](https://github.com/Fa1c0n35/CVE-2020-1472) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2020-1472.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2020-1472.svg)
- [https://github.com/Nekoox/zerologon](https://github.com/Nekoox/zerologon) :  ![starts](https://img.shields.io/github/stars/Nekoox/zerologon.svg) ![forks](https://img.shields.io/github/forks/Nekoox/zerologon.svg)
- [https://github.com/hell-moon/ZeroLogon-Exploit](https://github.com/hell-moon/ZeroLogon-Exploit) :  ![starts](https://img.shields.io/github/stars/hell-moon/ZeroLogon-Exploit.svg) ![forks](https://img.shields.io/github/forks/hell-moon/ZeroLogon-Exploit.svg)


## CVE-2019-25090
 A vulnerability was found in FreePBX arimanager up to 13.0.5.3 and classified as problematic. Affected by this issue is some unknown functionality of the component Views Handler. The manipulation of the argument dataurl leads to cross site scripting. The attack may be launched remotely. Upgrading to version 13.0.5.4 is able to address this issue. The name of the patch is 199dea7cc7020d3c469a86a39fbd80f5edd3c5ab. It is recommended to upgrade the affected component. VDB-216878 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2019-25090](https://github.com/Live-Hack-CVE/CVE-2019-25090) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25090.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25090.svg)


## CVE-2019-5418
 There is a File Content Disclosure vulnerability in Action View &lt;5.2.2.1, &lt;5.1.6.2, &lt;5.0.7.2, &lt;4.2.11.1 and v3 where specially crafted accept headers can cause contents of arbitrary files on the target system's filesystem to be exposed.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)


## CVE-2018-25066
 A vulnerability was found in PeterMu nodebatis up to 2.1.x. It has been classified as critical. Affected is an unknown function. The manipulation leads to sql injection. Upgrading to version 2.2.0 is able to address this issue. The name of the patch is 6629ff5b7e3d62ad8319007a54589ec1f62c7c35. It is recommended to upgrade the affected component. VDB-217554 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-25066](https://github.com/Live-Hack-CVE/CVE-2018-25066) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25066.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25066.svg)


## CVE-2018-25057
 A vulnerability was found in simple_php_link_shortener. It has been classified as critical. Affected is an unknown function of the file index.php. The manipulation of the argument $link[&quot;id&quot;] leads to sql injection. The name of the patch is b26ac6480761635ed94ccb0222ba6b732de6e53f. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-216996.

- [https://github.com/Live-Hack-CVE/CVE-2018-25057](https://github.com/Live-Hack-CVE/CVE-2018-25057) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25057.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25057.svg)


## CVE-2018-25031
 Swagger UI before 4.1.3 could allow a remote attacker to conduct spoofing attacks. By persuading a victim to open a crafted URL, an attacker could exploit this vulnerability to display remote OpenAPI definitions.

- [https://github.com/kriso4os/CVE-2018-25031](https://github.com/kriso4os/CVE-2018-25031) :  ![starts](https://img.shields.io/github/stars/kriso4os/CVE-2018-25031.svg) ![forks](https://img.shields.io/github/forks/kriso4os/CVE-2018-25031.svg)


## CVE-2017-20163
 A vulnerability has been found in Red Snapper NView and classified as critical. This vulnerability affects the function mutate of the file src/Session.php. The manipulation of the argument session leads to sql injection. The name of the patch is cbd255f55d476b29e5680f66f48c73ddb3d416a8. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217516.

- [https://github.com/Live-Hack-CVE/CVE-2017-20163](https://github.com/Live-Hack-CVE/CVE-2017-20163) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-20163.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-20163.svg)


## CVE-2017-20146
 Usage of the CORS handler may apply improper CORS headers, allowing the requester to explicitly control the value of the Access-Control-Allow-Origin header, which bypasses the expected behavior of the Same Origin Policy.

- [https://github.com/Live-Hack-CVE/CVE-2017-20146](https://github.com/Live-Hack-CVE/CVE-2017-20146) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-20146.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-20146.svg)


## CVE-2017-10661
 Race condition in fs/timerfd.c in the Linux kernel before 4.10.15 allows local users to gain privileges or cause a denial of service (list corruption or use-after-free) via simultaneous file-descriptor operations that leverage improper might_cancel queueing.

- [https://github.com/GeneBlue/CVE-2017-10661_POC](https://github.com/GeneBlue/CVE-2017-10661_POC) :  ![starts](https://img.shields.io/github/stars/GeneBlue/CVE-2017-10661_POC.svg) ![forks](https://img.shields.io/github/forks/GeneBlue/CVE-2017-10661_POC.svg)


## CVE-2016-15011
 A vulnerability classified as problematic was found in e-Contract dssp up to 1.3.1. Affected by this vulnerability is the function checkSignResponse of the file dssp-client/src/main/java/be/e_contract/dssp/client/SignResponseVerifier.java. The manipulation leads to xml external entity reference. Upgrading to version 1.3.2 is able to address this issue. The name of the patch is ec4238349691ec66dd30b416ec6eaab02d722302. It is recommended to upgrade the affected component. The identifier VDB-217549 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2016-15011](https://github.com/Live-Hack-CVE/CVE-2016-15011) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-15011.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-15011.svg)


## CVE-2016-15005
 CSRF tokens are generated using math/rand, which is not a cryptographically secure rander number generation, making predicting their values relatively trivial and allowing an attacker to bypass CSRF protections which relatively few requests.

- [https://github.com/Live-Hack-CVE/CVE-2016-15005](https://github.com/Live-Hack-CVE/CVE-2016-15005) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-15005.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-15005.svg)


## CVE-2015-10018
 A vulnerability has been found in DBRisinajumi d2files and classified as critical. Affected by this vulnerability is the function actionUpload/actionDownloadFile of the file controllers/D2filesController.php. The manipulation leads to sql injection. Upgrading to version 1.0.0 is able to address this issue. The name of the patch is b5767f2ec9d0f3cbfda7f13c84740e2179c90574. It is recommended to upgrade the affected component. The identifier VDB-217561 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2015-10018](https://github.com/Live-Hack-CVE/CVE-2015-10018) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10018.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10018.svg)


## CVE-2015-10017
 A vulnerability has been found in HPI-Information-Systems ProLOD and classified as critical. This vulnerability affects unknown code. The manipulation of the argument this leads to sql injection. The name of the patch is 3f710905458d49c77530bd3cbcd8960457566b73. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217552.

- [https://github.com/Live-Hack-CVE/CVE-2015-10017](https://github.com/Live-Hack-CVE/CVE-2015-10017) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10017.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10017.svg)


## CVE-2015-10016
 A vulnerability, which was classified as critical, has been found in jeff-kelley opensim-utils. Affected by this issue is the function DatabaseForRegion of the file regionscrits.php. The manipulation of the argument region leads to sql injection. The name of the patch is c29e5c729a833a29dbf5b1e505a0553fe154575e. It is recommended to apply a patch to fix this issue. VDB-217550 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2015-10016](https://github.com/Live-Hack-CVE/CVE-2015-10016) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10016.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10016.svg)


## CVE-2015-5521
 Cross-site scripting (XSS) vulnerability in BlackCat CMS 1.1.2 allows remote attackers to inject arbitrary web script or HTML via the name in a new group to backend/groups/index.php.

- [https://github.com/Live-Hack-CVE/CVE-2015-5521](https://github.com/Live-Hack-CVE/CVE-2015-5521) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-5521.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-5521.svg)


## CVE-2014-125051
 A vulnerability was found in himiklab yii2-jqgrid-widget up to 1.0.7. It has been declared as critical. This vulnerability affects the function addSearchOptionsRecursively of the file JqGridAction.php. The manipulation leads to sql injection. Upgrading to version 1.0.8 is able to address this issue. The name of the patch is a117e0f2df729e3ff726968794d9a5ac40e660b9. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-217564.

- [https://github.com/Live-Hack-CVE/CVE-2014-125051](https://github.com/Live-Hack-CVE/CVE-2014-125051) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125051.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125051.svg)


## CVE-2014-125050
 A vulnerability was found in ScottTZhang voter-js and classified as critical. Affected by this issue is some unknown functionality of the file main.js. The manipulation leads to sql injection. The name of the patch is 6317c67a56061aeeaeed3cf9ec665fd9983d8044. It is recommended to apply a patch to fix this issue. VDB-217562 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125050](https://github.com/Live-Hack-CVE/CVE-2014-125050) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125050.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125050.svg)


## CVE-2014-125049
 ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability, which was classified as critical, was found in typcn Blogile. Affected is the function getNav of the file server.js. The manipulation of the argument query leads to sql injection. The name of the patch is cfec31043b562ffefe29fe01af6d3c5ed1bf8f7d. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-217560. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Live-Hack-CVE/CVE-2014-125049](https://github.com/Live-Hack-CVE/CVE-2014-125049) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125049.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125049.svg)


## CVE-2014-125048
 A vulnerability, which was classified as critical, has been found in kassi xingwall. This issue affects some unknown processing of the file app/controllers/oauth.js. The manipulation leads to session fixiation. The name of the patch is e9f0d509e1408743048e29d9c099d36e0e1f6ae7. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217559.

- [https://github.com/Live-Hack-CVE/CVE-2014-125048](https://github.com/Live-Hack-CVE/CVE-2014-125048) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125048.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125048.svg)


## CVE-2014-125047
 A vulnerability classified as critical has been found in tbezman school-store. This affects an unknown part. The manipulation leads to sql injection. The name of the patch is 2957fc97054216d3a393f1775efd01ae2b072001. It is recommended to apply a patch to fix this issue. The identifier VDB-217557 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125047](https://github.com/Live-Hack-CVE/CVE-2014-125047) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125047.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125047.svg)


## CVE-2014-125046
 A vulnerability, which was classified as critical, was found in Seiji42 cub-scout-tracker. This affects an unknown part of the file databaseAccessFunctions.js. The manipulation leads to sql injection. The name of the patch is b4bc1a328b1f59437db159f9d136d9ed15707e31. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217551.

- [https://github.com/Live-Hack-CVE/CVE-2014-125046](https://github.com/Live-Hack-CVE/CVE-2014-125046) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125046.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125046.svg)


## CVE-2014-125045
 A vulnerability has been found in meol1 and classified as critical. Affected by this vulnerability is the function GetAnimal of the file opdracht4/index.php. The manipulation of the argument where leads to sql injection. The name of the patch is 82441e413f87920d1e8f866e8ef9d7f353a7c583. It is recommended to apply a patch to fix this issue. The identifier VDB-217525 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125045](https://github.com/Live-Hack-CVE/CVE-2014-125045) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125045.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125045.svg)


## CVE-2014-125044
 A vulnerability, which was classified as critical, was found in soshtolsus wing-tight. This affects an unknown part of the file index.php. The manipulation of the argument p leads to file inclusion. It is possible to initiate the attack remotely. Upgrading to version 1.0.0 is able to address this issue. The name of the patch is 567bc33e6ed82b0d0179c9add707ac2b257aeaf2. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-217515.

- [https://github.com/Live-Hack-CVE/CVE-2014-125044](https://github.com/Live-Hack-CVE/CVE-2014-125044) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125044.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125044.svg)


## CVE-2014-125043
 A vulnerability, which was classified as problematic, has been found in vicamo NetworkManager. Affected by this issue is the function send_arps of the file src/devices/nm-device.c. The manipulation leads to unchecked return value. The name of the patch is 4da19b89815cbf6e063e39bc33c04fe4b3f789df. It is recommended to apply a patch to fix this issue. VDB-217514 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125043](https://github.com/Live-Hack-CVE/CVE-2014-125043) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125043.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125043.svg)


## CVE-2014-125042
 A vulnerability classified as problematic was found in vicamo NetworkManager. Affected by this vulnerability is the function nm_setting_vlan_add_priority_str/nm_utils_rsa_key_encrypt/nm_setting_vlan_add_priority_str. The manipulation leads to missing release of resource. The name of the patch is afb0e2c53c4c17dfdb89d63b39db5101cc864704. It is recommended to apply a patch to fix this issue. The identifier VDB-217513 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125042](https://github.com/Live-Hack-CVE/CVE-2014-125042) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125042.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125042.svg)


## CVE-2013-10005
 The RemoteAddr and LocalAddr methods on the returned net.Conn may call themselves, leading to an infinite loop which will crash the program due to a stack overflow.

- [https://github.com/Live-Hack-CVE/CVE-2013-10005](https://github.com/Live-Hack-CVE/CVE-2013-10005) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2013-10005.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2013-10005.svg)


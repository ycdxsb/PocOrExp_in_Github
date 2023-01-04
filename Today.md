# Update 2023-01-04
## CVE-2023-22452
 kenny2automate is a Discord bot. In the web interface for server settings, form elements were generated with Discord channel IDs as part of input names. Prior to commit a947d7c, no validation was performed to ensure that the channel IDs submitted actually belonged to the server being configured. Thus anyone who has access to the channel ID they wish to change settings for and the server settings panel for any server could change settings for the requested channel no matter which server it belonged to. Commit a947d7c resolves the issue and has been deployed to the official instance of the bot. The only workaround that exists is to disable the web config entirely by changing it to run on localhost. Note that a workaround is only necessary for those who run their own instance of the bot.

- [https://github.com/Live-Hack-CVE/CVE-2023-22452](https://github.com/Live-Hack-CVE/CVE-2023-22452) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22452.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22452.svg)


## CVE-2023-22451
 Kiwi TCMS is an open source test management system. In version 11.6 and prior, when users register new accounts and/or change passwords, there is no validation in place which would prevent them from picking an easy to guess password. This issue is resolved by providing defaults for the `AUTH_PASSWORD_VALIDATORS` configuration setting. As of version 11.7, the password can&#8217;t be too similar to other personal information, must contain at least 10 characters, can&#8217;t be a commonly used password, and can&#8217;t be entirely numeric. As a workaround, an administrator may reset all passwords in Kiwi TCMS if they think a weak password may have been chosen.

- [https://github.com/Live-Hack-CVE/CVE-2023-22451](https://github.com/Live-Hack-CVE/CVE-2023-22451) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22451.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22451.svg)


## CVE-2022-48197
 ** UNSUPPORTED WHEN ASSIGNED ** Reflected cross-site scripting (XSS) exists in the TreeView of YUI2 through 2800: up.php sam.php renderhidden.php removechildren.php removeall.php readd.php overflow.php newnode2.php newnode.php. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/ryan412/CVE-2022-48197](https://github.com/ryan412/CVE-2022-48197) :  ![starts](https://img.shields.io/github/stars/ryan412/CVE-2022-48197.svg) ![forks](https://img.shields.io/github/forks/ryan412/CVE-2022-48197.svg)
- [https://github.com/Live-Hack-CVE/CVE-2022-48197](https://github.com/Live-Hack-CVE/CVE-2022-48197) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48197.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48197.svg)


## CVE-2022-47908
 Stack-based buffer overflow vulnerability in V-Server v4.0.12.0 and earlier allows a local attacker to obtain the information and/or execute arbitrary code by having a user to open a specially crafted project file.

- [https://github.com/Live-Hack-CVE/CVE-2022-47908](https://github.com/Live-Hack-CVE/CVE-2022-47908) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47908.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47908.svg)


## CVE-2022-47618
 Merit LILIN AH55B04 &amp; AH55B08 DVR firm has hard-coded administrator credentials. An unauthenticated remote attacker can use these credentials to log in administrator page, to manipulate system or disrupt service.

- [https://github.com/Live-Hack-CVE/CVE-2022-47618](https://github.com/Live-Hack-CVE/CVE-2022-47618) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47618.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47618.svg)


## CVE-2022-47317
 Out-of-bounds write vulnerability in V-Server v4.0.12.0 and earlier allows a local attacker to obtain the information and/or execute arbitrary code by having a user to open a specially crafted project file.

- [https://github.com/Live-Hack-CVE/CVE-2022-47317](https://github.com/Live-Hack-CVE/CVE-2022-47317) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47317.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47317.svg)


## CVE-2022-46689
 A race condition was addressed with additional validation. This issue is fixed in tvOS 16.2, macOS Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/ginsudev/WDBFontOverwrite](https://github.com/ginsudev/WDBFontOverwrite) :  ![starts](https://img.shields.io/github/stars/ginsudev/WDBFontOverwrite.svg) ![forks](https://img.shields.io/github/forks/ginsudev/WDBFontOverwrite.svg)


## CVE-2022-46366
 ** UNSUPPORTED WHEN ASSIGNED ** Apache Tapestry 3.x allows deserialization of untrusted data, leading to remote code execution. This issue is similar to but distinct from CVE-2020-17531, which applies the the (also unsupported) 4.x version line. NOTE: This vulnerability only affects Apache Tapestry version line 3.x, which is no longer supported by the maintainer. Users are recommended to upgrade to a supported version line of Apache Tapestry.

- [https://github.com/wh-gov/CVE-2022-46366](https://github.com/wh-gov/CVE-2022-46366) :  ![starts](https://img.shields.io/github/stars/wh-gov/CVE-2022-46366.svg) ![forks](https://img.shields.io/github/forks/wh-gov/CVE-2022-46366.svg)


## CVE-2022-46360
 Out-of-bounds read vulnerability in V-SFT v6.1.7.0 and earlier and TELLUS v4.0.12.0 and earlier allows a local attacker to obtain the information and/or execute arbitrary code by having a user to open a specially crafted image file.

- [https://github.com/Live-Hack-CVE/CVE-2022-46360](https://github.com/Live-Hack-CVE/CVE-2022-46360) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46360.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46360.svg)


## CVE-2022-46309
 Vitals ESP upload function has a path traversal vulnerability. A remote attacker with general user privilege can exploit this vulnerability to access arbitrary system files.

- [https://github.com/Live-Hack-CVE/CVE-2022-46309](https://github.com/Live-Hack-CVE/CVE-2022-46309) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46309.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46309.svg)


## CVE-2022-46306
 ChangingTec ServiSign component has a path traversal vulnerability due to insufficient filtering for special characters in the DLL file path. An unauthenticated remote attacker can host a malicious website for the component user to access, which triggers the component to load malicious DLL files under arbitrary file path and allows the attacker to perform arbitrary system operation and disrupt of service.

- [https://github.com/Live-Hack-CVE/CVE-2022-46306](https://github.com/Live-Hack-CVE/CVE-2022-46306) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46306.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46306.svg)


## CVE-2022-46305
 ChangingTec ServiSign component has a path traversal vulnerability. An unauthenticated LAN attacker can exploit this vulnerability to bypass authentication and access arbitrary system files.

- [https://github.com/Live-Hack-CVE/CVE-2022-46305](https://github.com/Live-Hack-CVE/CVE-2022-46305) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46305.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46305.svg)


## CVE-2022-46304
 ChangingTec ServiSign component has insufficient filtering for special characters in the connection response parameter. An unauthenticated remote attacker can host a malicious website for the component user to access, which triggers command injection and allows the attacker to execute arbitrary system command to perform arbitrary system operation or disrupt service.

- [https://github.com/Live-Hack-CVE/CVE-2022-46304](https://github.com/Live-Hack-CVE/CVE-2022-46304) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46304.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46304.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/Inplex-sys/CVE-2022-46169](https://github.com/Inplex-sys/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/Inplex-sys/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/Inplex-sys/CVE-2022-46169.svg)


## CVE-2022-43931
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-43931](https://github.com/Live-Hack-CVE/CVE-2022-43931) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43931.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43931.svg)


## CVE-2022-43448
 Out-of-bounds write vulnerability in V-SFT v6.1.7.0 and earlier and TELLUS v4.0.12.0 and earlier allows a local attacker to obtain the information and/or execute arbitrary code by having a user to open a specially crafted image file.

- [https://github.com/Live-Hack-CVE/CVE-2022-43448](https://github.com/Live-Hack-CVE/CVE-2022-43448) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43448.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43448.svg)


## CVE-2022-43438
 The Administrator function of EasyTest has an Incorrect Authorization vulnerability. A remote attacker authenticated as a general user can exploit this vulnerability to bypass the intended access restrictions, to make API functions calls, manipulate system and terminate service.

- [https://github.com/Live-Hack-CVE/CVE-2022-43438](https://github.com/Live-Hack-CVE/CVE-2022-43438) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43438.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43438.svg)


## CVE-2022-43437
 The Download function&#8217;s parameter of EasyTest has insufficient validation for user input. A remote attacker authenticated as a general user can inject arbitrary SQL command to access, modify or delete database.

- [https://github.com/Live-Hack-CVE/CVE-2022-43437](https://github.com/Live-Hack-CVE/CVE-2022-43437) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43437.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43437.svg)


## CVE-2022-43436
 The File Upload function of EasyTest has insufficient filtering for special characters and file type. A remote attacker authenticated as a general user can upload and execute arbitrary files, to manipulate system or disrupt service.

- [https://github.com/Live-Hack-CVE/CVE-2022-43436](https://github.com/Live-Hack-CVE/CVE-2022-43436) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43436.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43436.svg)


## CVE-2022-42475
 A heap-based buffer overflow vulnerability [CWE-122] in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through 7.0.8, 6.4.0 through 6.4.10, 6.2.0 through 6.2.11, 6.0.15 and earlier and FortiProxy SSL-VPN 7.2.0 through 7.2.1, 7.0.7 and earlier may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.

- [https://github.com/Live-Hack-CVE/CVE-2022-42475](https://github.com/Live-Hack-CVE/CVE-2022-42475) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42475.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42475.svg)


## CVE-2022-41898
 TensorFlow is an open source platform for machine learning. If `SparseFillEmptyRowsGrad` is given empty inputs, TensorFlow will crash. We have patched the issue in GitHub commit af4a6a3c8b95022c351edae94560acc61253a1b8. The fix will be included in TensorFlow 2.11. We will also cherrypick this commit on TensorFlow 2.10.1, 2.9.3, and TensorFlow 2.8.4, as these are also affected and still in supported range.

- [https://github.com/Live-Hack-CVE/CVE-2022-41898](https://github.com/Live-Hack-CVE/CVE-2022-41898) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41898.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41898.svg)


## CVE-2022-41645
 Out-of-bounds read vulnerability in V-Server v4.0.12.0 and earlier allows a local attacker to obtain the information and/or execute arbitrary code by having a user to open a specially crafted project file.

- [https://github.com/Live-Hack-CVE/CVE-2022-41645](https://github.com/Live-Hack-CVE/CVE-2022-41645) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41645.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41645.svg)


## CVE-2022-40740
 Realtek GPON router has insufficient filtering for special characters. A remote attacker authenticated as an administrator can exploit this vulnerability to perform command injection attacks, to execute arbitrary system command, manipulate system or disrupt service.

- [https://github.com/Live-Hack-CVE/CVE-2022-40740](https://github.com/Live-Hack-CVE/CVE-2022-40740) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40740.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40740.svg)


## CVE-2022-39042
 aEnrich a+HRD has improper validation for login function. An unauthenticated remote attacker can exploit this vulnerability to bypass authentication and access API function to perform arbitrary system command or disrupt service.

- [https://github.com/Live-Hack-CVE/CVE-2022-39042](https://github.com/Live-Hack-CVE/CVE-2022-39042) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39042.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39042.svg)


## CVE-2022-39041
 aEnrich a+HRD has insufficient user input validation for specific API parameter. An unauthenticated remote attacker can exploit this vulnerability to inject arbitrary SQL commands to access, modify and delete database.

- [https://github.com/Live-Hack-CVE/CVE-2022-39041](https://github.com/Live-Hack-CVE/CVE-2022-39041) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39041.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39041.svg)


## CVE-2022-39040
 aEnrich a+HRD log read function has a path traversal vulnerability. An unauthenticated remote attacker can exploit this vulnerability to bypass authentication and download arbitrary system files.

- [https://github.com/Live-Hack-CVE/CVE-2022-39040](https://github.com/Live-Hack-CVE/CVE-2022-39040) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39040.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39040.svg)


## CVE-2022-39039
 aEnrich&#8217;s a+HRD has inadequate filtering for specific URL parameter. An unauthenticated remote attacker can exploit this vulnerability to send arbitrary HTTP(s) request to launch Server-Side Request Forgery (SSRF) attack, to perform arbitrary system command or disrupt service.

- [https://github.com/Live-Hack-CVE/CVE-2022-39039](https://github.com/Live-Hack-CVE/CVE-2022-39039) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39039.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39039.svg)


## CVE-2022-35698
 Adobe Commerce versions 2.4.4-p1 (and earlier) and 2.4.5 (and earlier) are affected by a Stored Cross-site Scripting vulnerability. Exploitation of this issue does not require user interaction and could result in a post-authentication arbitrary code execution.

- [https://github.com/EmicoEcommerce/Magento-APSB22-48-Security-Patches](https://github.com/EmicoEcommerce/Magento-APSB22-48-Security-Patches) :  ![starts](https://img.shields.io/github/stars/EmicoEcommerce/Magento-APSB22-48-Security-Patches.svg) ![forks](https://img.shields.io/github/forks/EmicoEcommerce/Magento-APSB22-48-Security-Patches.svg)


## CVE-2022-32598
 In widevine, there is a possible out of bounds write due to an incorrect bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07446228; Issue ID: ALPS07446228.

- [https://github.com/Live-Hack-CVE/CVE-2022-32598](https://github.com/Live-Hack-CVE/CVE-2022-32598) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32598.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32598.svg)


## CVE-2022-31707
 vRealize Operations (vROps) contains a privilege escalation vulnerability. VMware has evaluated the severity of this issue to be in the Important severity range with a maximum CVSSv3 base score of 7.2.

- [https://github.com/Live-Hack-CVE/CVE-2022-31707](https://github.com/Live-Hack-CVE/CVE-2022-31707) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-31707.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-31707.svg)


## CVE-2022-23046
 PhpIPAM v1.4.4 allows an authenticated admin user to inject SQL sentences in the &quot;subnet&quot; parameter while searching a subnet via app/admin/routing/edit-bgp-mapping-search.php

- [https://github.com/hadrian3689/phpipam_1.4.4](https://github.com/hadrian3689/phpipam_1.4.4) :  ![starts](https://img.shields.io/github/stars/hadrian3689/phpipam_1.4.4.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/phpipam_1.4.4.svg)


## CVE-2022-20470
 In bindRemoteViewsService of AppWidgetServiceImpl.java, there is a possible way to bypass background activity launch due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-234013191

- [https://github.com/Trinadh465/frameworks_base_AOSP10_r33_CVE-2022-20470](https://github.com/Trinadh465/frameworks_base_AOSP10_r33_CVE-2022-20470) :  ![starts](https://img.shields.io/github/stars/Trinadh465/frameworks_base_AOSP10_r33_CVE-2022-20470.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/frameworks_base_AOSP10_r33_CVE-2022-20470.svg)


## CVE-2022-4336
 In BAOTA linux panel there exists a stored xss vulnerability attackers can use to obtain sensitive information via the log analysis feature.

- [https://github.com/Live-Hack-CVE/CVE-2022-4336](https://github.com/Live-Hack-CVE/CVE-2022-4336) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4336.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4336.svg)


## CVE-2022-4324
 The Custom Field Template WordPress plugin before 2.5.8 unserialises the content of an imported file, which could lead to PHP object injections issues when a high privilege user import (intentionally or not) a malicious Customizer Styling file and a suitable gadget chain is present on the blog.

- [https://github.com/Live-Hack-CVE/CVE-2022-4324](https://github.com/Live-Hack-CVE/CVE-2022-4324) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4324.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4324.svg)


## CVE-2022-4302
 The White Label CMS WordPress plugin before 2.5 unserializes user input provided via the settings, which could allow high-privilege users such as admin to perform PHP Object Injection when a suitable gadget is present.

- [https://github.com/Live-Hack-CVE/CVE-2022-4302](https://github.com/Live-Hack-CVE/CVE-2022-4302) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4302.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4302.svg)


## CVE-2022-4298
 The Wholesale Market WordPress plugin before 2.2.1 does not have authorisation check, as well as does not validate user input used to generate system path, allowing unauthenticated attackers to download arbitrary file from the server.

- [https://github.com/Live-Hack-CVE/CVE-2022-4298](https://github.com/Live-Hack-CVE/CVE-2022-4298) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4298.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4298.svg)


## CVE-2022-4297
 The WP AutoComplete Search WordPress plugin through 1.0.4 does not sanitise and escape a parameter before using it in a SQL statement via an AJAX available to unauthenticated users, leading to an unauthenticated SQL injection

- [https://github.com/Live-Hack-CVE/CVE-2022-4297](https://github.com/Live-Hack-CVE/CVE-2022-4297) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4297.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4297.svg)


## CVE-2022-4260
 The WP-Ban WordPress plugin before 1.69.1 does not sanitise and escape some of its settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup).

- [https://github.com/Live-Hack-CVE/CVE-2022-4260](https://github.com/Live-Hack-CVE/CVE-2022-4260) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4260.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4260.svg)


## CVE-2022-4256
 The All-in-One Addons for Elementor WordPress plugin before 2.4.4 does not sanitise and escape some of its settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup)

- [https://github.com/Live-Hack-CVE/CVE-2022-4256](https://github.com/Live-Hack-CVE/CVE-2022-4256) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4256.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4256.svg)


## CVE-2022-4237
 The Welcart e-Commerce WordPress plugin before 2.8.6 does not validate user input before using it in file_exist() functions via various AJAX actions available to any authenticated users, which could allow users with a role as low as subscriber to perform PHAR deserialisation when they can upload a file and a suitable gadget chain is present on the blog

- [https://github.com/Live-Hack-CVE/CVE-2022-4237](https://github.com/Live-Hack-CVE/CVE-2022-4237) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4237.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4237.svg)


## CVE-2022-4236
 The Welcart e-Commerce WordPress plugin before 2.8.5 does not validate user input before using it to output the content of a file via an AJAX action available to any authenticated users, which could allow users with a role as low as subscriber to read arbitrary files on the server.

- [https://github.com/Live-Hack-CVE/CVE-2022-4236](https://github.com/Live-Hack-CVE/CVE-2022-4236) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4236.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4236.svg)


## CVE-2022-4200
 The Login with Cognito WordPress plugin through 1.4.8 does not sanitise and escape some of its settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup).

- [https://github.com/Live-Hack-CVE/CVE-2022-4200](https://github.com/Live-Hack-CVE/CVE-2022-4200) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4200.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4200.svg)


## CVE-2022-4198
 The WP Social Sharing WordPress plugin through 2.2 does not sanitise and escape some of its settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup).

- [https://github.com/Live-Hack-CVE/CVE-2022-4198](https://github.com/Live-Hack-CVE/CVE-2022-4198) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4198.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4198.svg)


## CVE-2022-4142
 The WordPress Filter Gallery Plugin WordPress plugin before 0.1.6 does not properly escape the filters passed in the ufg_gallery_filters ajax action before outputting them on the page, allowing a high privileged user such as an administrator to inject HTML or javascript to the plugin settings page, even when the unfiltered_html capability is disabled.

- [https://github.com/Live-Hack-CVE/CVE-2022-4142](https://github.com/Live-Hack-CVE/CVE-2022-4142) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4142.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4142.svg)


## CVE-2022-4140
 The Welcart e-Commerce WordPress plugin before 2.8.5 does not validate user input before using it to output the content of a file, which could allow unauthenticated attacker to read arbitrary files on the server

- [https://github.com/Live-Hack-CVE/CVE-2022-4140](https://github.com/Live-Hack-CVE/CVE-2022-4140) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4140.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4140.svg)


## CVE-2022-4119
 The Image Optimizer, Resizer and CDN WordPress plugin before 6.8.1 does not sanitise and escape some of its settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup).

- [https://github.com/Live-Hack-CVE/CVE-2022-4119](https://github.com/Live-Hack-CVE/CVE-2022-4119) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4119.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4119.svg)


## CVE-2022-4114
 The Superio WordPress theme does not sanitise and escape some parameters, which could allow users with a role as low as a subscriber to perform Cross-Site Scripting attacks.

- [https://github.com/Live-Hack-CVE/CVE-2022-4114](https://github.com/Live-Hack-CVE/CVE-2022-4114) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4114.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4114.svg)


## CVE-2022-4109
 The Wholesale Market for WooCommerce WordPress plugin before 2.0.0 does not validate user input against path traversal attacks, allowing high privilege users such as admin to download arbitrary logs from the server even when they should not be able to (for example in multisite)

- [https://github.com/Live-Hack-CVE/CVE-2022-4109](https://github.com/Live-Hack-CVE/CVE-2022-4109) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4109.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4109.svg)


## CVE-2022-4099
 The Joy Of Text Lite WordPress plugin before 2.3.1 does not properly sanitise and escape some parameters before using them in SQL statements accessible to unauthenticated users, leading to unauthenticated SQL injection

- [https://github.com/Live-Hack-CVE/CVE-2022-4099](https://github.com/Live-Hack-CVE/CVE-2022-4099) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4099.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4099.svg)


## CVE-2022-4059
 The Cryptocurrency Widgets Pack WordPress plugin through 1.8.1 does not sanitise and escape some parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to a SQL injection.

- [https://github.com/Live-Hack-CVE/CVE-2022-4059](https://github.com/Live-Hack-CVE/CVE-2022-4059) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4059.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4059.svg)


## CVE-2022-4057
 The Autoptimize WordPress plugin before 3.1.0 uses an easily guessable path to store plugin's exported settings and logs.

- [https://github.com/Live-Hack-CVE/CVE-2022-4057](https://github.com/Live-Hack-CVE/CVE-2022-4057) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4057.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4057.svg)


## CVE-2022-4049
 The WP User WordPress plugin through 7.0 does not properly sanitize and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by unauthenticated users.

- [https://github.com/Live-Hack-CVE/CVE-2022-4049](https://github.com/Live-Hack-CVE/CVE-2022-4049) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4049.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4049.svg)


## CVE-2022-4025
 Inappropriate implementation in Paint in Google Chrome prior to 98.0.4758.80 allowed a remote attacker to leak cross-origin data outside an iframe via a crafted HTML page. (Chrome security severity: Low)

- [https://github.com/Live-Hack-CVE/CVE-2022-4025](https://github.com/Live-Hack-CVE/CVE-2022-4025) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4025.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4025.svg)


## CVE-2022-3994
 The Authenticator WordPress plugin before 1.3.1 does not prevent subscribers from updating a site's feed access token, which may deny other users access to the functionality in certain configurations.

- [https://github.com/Live-Hack-CVE/CVE-2022-3994](https://github.com/Live-Hack-CVE/CVE-2022-3994) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3994.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3994.svg)


## CVE-2022-3936
 The Team Members WordPress plugin before 5.2.1 does not sanitize and escapes some of its settings, which could allow high-privilege users such as editors to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example, in a multisite setup).

- [https://github.com/Live-Hack-CVE/CVE-2022-3936](https://github.com/Live-Hack-CVE/CVE-2022-3936) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3936.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3936.svg)


## CVE-2022-3911
 The iubenda | All-in-one Compliance for GDPR / CCPA Cookie Consent + more WordPress plugin before 3.3.3 does does not have authorisation and CSRF in an AJAX action, and does not ensure that the options to be updated belong to the plugin as long as they are arrays. As a result, any authenticated users, such as subscriber can grant themselves any privileges, such as edit_plugins etc

- [https://github.com/Live-Hack-CVE/CVE-2022-3911](https://github.com/Live-Hack-CVE/CVE-2022-3911) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3911.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3911.svg)


## CVE-2022-3863
 Use after free in Browser History in Google Chrome prior to 100.0.4896.75 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chrome security severity: High)

- [https://github.com/Live-Hack-CVE/CVE-2022-3863](https://github.com/Live-Hack-CVE/CVE-2022-3863) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3863.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3863.svg)


## CVE-2022-3860
 The Visual Email Designer for WooCommerce WordPress plugin before 1.7.2 does not properly sanitise and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by users with a role as low as author.

- [https://github.com/Live-Hack-CVE/CVE-2022-3860](https://github.com/Live-Hack-CVE/CVE-2022-3860) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3860.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3860.svg)


## CVE-2022-3842
 Use after free in Passwords in Google Chrome prior to 105.0.5195.125 allowed a remote attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Live-Hack-CVE/CVE-2022-3842](https://github.com/Live-Hack-CVE/CVE-2022-3842) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3842.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3842.svg)


## CVE-2022-3460
 In affected versions of Octopus Deploy it is possible for certain types of sensitive variables to inadvertently become unmasked when viewed in variable preview.

- [https://github.com/Live-Hack-CVE/CVE-2022-3460](https://github.com/Live-Hack-CVE/CVE-2022-3460) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3460.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3460.svg)


## CVE-2022-3241
 The Build App Online WordPress plugin before 1.0.19 does not properly sanitise and escape some parameters before using them in a SQL statement via an AJAX action available to unauthenticated users, leading to a SQL injection

- [https://github.com/Live-Hack-CVE/CVE-2022-3241](https://github.com/Live-Hack-CVE/CVE-2022-3241) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3241.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3241.svg)


## CVE-2022-2743
 Integer overflow in Window Manager in Google Chrome on Chrome OS and Lacros prior to 104.0.5112.79 allowed a remote attacker who convinced a user to engage in specific UI interactions to perform an out of bounds memory write via crafted UI interactions. (Chrome security severity: High)

- [https://github.com/Live-Hack-CVE/CVE-2022-2743](https://github.com/Live-Hack-CVE/CVE-2022-2743) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2743.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2743.svg)


## CVE-2022-2742
 Use after free in Exosphere in Google Chrome on Chrome OS and Lacros prior to 104.0.5112.79 allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption via crafted UI interactions. (Chrome security severity: High)

- [https://github.com/Live-Hack-CVE/CVE-2022-2742](https://github.com/Live-Hack-CVE/CVE-2022-2742) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2742.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2742.svg)


## CVE-2022-2637
 Incorrect Privilege Assignment vulnerability in Hitachi Storage Plug-in for VMware vCenter allows remote authenticated users to cause privilege escalation. This issue affects: Hitachi Storage Plug-in for VMware vCenter 04.8.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-2637](https://github.com/Live-Hack-CVE/CVE-2022-2637) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2637.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2637.svg)


## CVE-2022-2463
 Rockwell Automation ISaGRAF Workbench software versions 6.0 through 6.6.9 are affected by a Path Traversal vulnerability. A crafted malicious .7z exchange file may allow an attacker to gain the privileges of the ISaGRAF Workbench software when opened. If the software is running at the SYSTEM level, then the attacker will gain admin level privileges. User interaction is required for this exploit to be successful.

- [https://github.com/Live-Hack-CVE/CVE-2022-2463](https://github.com/Live-Hack-CVE/CVE-2022-2463) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2463.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2463.svg)


## CVE-2022-0801
 Inappropriate implementation in HTML parser in Google Chrome prior to 99.0.4844.51 allowed a remote attacker to bypass XSS preventions via a crafted HTML page. (Chrome security severity: Medium)

- [https://github.com/Live-Hack-CVE/CVE-2022-0801](https://github.com/Live-Hack-CVE/CVE-2022-0801) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0801.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0801.svg)


## CVE-2022-0739
 The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied POST data before it is used in a dynamically constructed SQL query via the bookingpress_front_get_category_services AJAX action (available to unauthenticated users), leading to an unauthenticated SQL Injection

- [https://github.com/hadrian3689/wp_bookingpress_1.0.11](https://github.com/hadrian3689/wp_bookingpress_1.0.11) :  ![starts](https://img.shields.io/github/stars/hadrian3689/wp_bookingpress_1.0.11.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/wp_bookingpress_1.0.11.svg)


## CVE-2022-0337
 Inappropriate implementation in File System API in Google Chrome on Windows prior to 97.0.4692.71 allowed a remote attacker to obtain potentially sensitive information via a crafted HTML page. (Chrome security severity: High)

- [https://github.com/Live-Hack-CVE/CVE-2022-0337](https://github.com/Live-Hack-CVE/CVE-2022-0337) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0337.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0337.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/hadrian3689/apache_2.4.50](https://github.com/hadrian3689/apache_2.4.50) :  ![starts](https://img.shields.io/github/stars/hadrian3689/apache_2.4.50.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/apache_2.4.50.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/DoTuan1/Reserch-CVE-2021-41773](https://github.com/DoTuan1/Reserch-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/DoTuan1/Reserch-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/DoTuan1/Reserch-CVE-2021-41773.svg)
- [https://github.com/mightysai1997/CVE-2021-41773-i-](https://github.com/mightysai1997/CVE-2021-41773-i-) :  ![starts](https://img.shields.io/github/stars/mightysai1997/CVE-2021-41773-i-.svg) ![forks](https://img.shields.io/github/forks/mightysai1997/CVE-2021-41773-i-.svg)
- [https://github.com/wolf1892/CVE-2021-41773](https://github.com/wolf1892/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/wolf1892/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/wolf1892/CVE-2021-41773.svg)
- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2021-39174
 Cachet is an open source status page system. Prior to version 2.5.1, authenticated users, regardless of their privileges (User or Admin), can leak the value of any configuration entry of the dotenv file, e.g. the application secret (`APP_KEY`) and various passwords (email, database, etc). This issue was addressed in version 2.5.1 by improving `UpdateConfigCommandHandler` and preventing the use of nested variables in the resulting dotenv configuration file. As a workaround, only allow trusted source IP addresses to access to the administration dashboard.

- [https://github.com/hadrian3689/cachet_2.4.0-dev](https://github.com/hadrian3689/cachet_2.4.0-dev) :  ![starts](https://img.shields.io/github/stars/hadrian3689/cachet_2.4.0-dev.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/cachet_2.4.0-dev.svg)


## CVE-2021-35576
 Vulnerability in the Oracle Database Enterprise Edition Unified Audit component of Oracle Database Server. Supported versions that are affected are 12.1.0.2, 12.2.0.1 and 19c. Easily exploitable vulnerability allows high privileged attacker having Local Logon privilege with network access via Oracle Net to compromise Oracle Database Enterprise Edition Unified Audit. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Database Enterprise Edition Unified Audit accessible data. CVSS 3.1 Base Score 2.7 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2021-35576](https://github.com/Live-Hack-CVE/CVE-2021-35576) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-35576.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-35576.svg)


## CVE-2021-30558
 Insufficient policy enforcement in content security policy in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to bypass content security policy via a crafted HTML page. (Chrome security severity: Medium)

- [https://github.com/Live-Hack-CVE/CVE-2021-30558](https://github.com/Live-Hack-CVE/CVE-2021-30558) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-30558.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-30558.svg)


## CVE-2021-21200
 Out of bounds read in WebUI Settings in Google Chrome prior to 89.0.4389.72 allowed a remote attacker to perform an out of bounds memory read via a crafted HTML page. (Chrome security severity: Low)

- [https://github.com/Live-Hack-CVE/CVE-2021-21200](https://github.com/Live-Hack-CVE/CVE-2021-21200) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-21200.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-21200.svg)


## CVE-2021-4299
 A vulnerability classified as problematic was found in cronvel string-kit up to 0.12.7. This vulnerability affects the function naturalSort of the file lib/naturalSort.js. The manipulation leads to inefficient regular expression complexity. The attack can be initiated remotely. Upgrading to version 0.12.8 is able to address this issue. The name of the patch is 9cac4c298ee92c1695b0695951f1488884a7ca73. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-217180.

- [https://github.com/Live-Hack-CVE/CVE-2021-4299](https://github.com/Live-Hack-CVE/CVE-2021-4299) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4299.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4299.svg)


## CVE-2021-4298
 A vulnerability classified as critical has been found in Hesburgh Libraries of Notre Dame Sipity. This affects the function SearchCriteriaForWorksParameter of the file app/parameters/sipity/parameters/search_criteria_for_works_parameter.rb. The manipulation leads to sql injection. Upgrading to version 2021.8 is able to address this issue. The name of the patch is d1704c7363b899ffce65be03a796a0ee5fdbfbdc. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-217179.

- [https://github.com/Live-Hack-CVE/CVE-2021-4298](https://github.com/Live-Hack-CVE/CVE-2021-4298) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4298.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4298.svg)


## CVE-2021-3007
 ** DISPUTED ** Laminas Project laminas-http before 2.14.2, and Zend Framework 3.0.0, has a deserialization vulnerability that can lead to remote code execution if the content is controllable, related to the __destruct method of the Zend\Http\Response\Stream class in Stream.php. NOTE: Zend Framework is no longer supported by the maintainer. NOTE: the laminas-http vendor considers this a &quot;vulnerability in the PHP language itself&quot; but has added certain type checking as a way to prevent exploitation in (unrecommended) use cases where attacker-supplied data can be deserialized.

- [https://github.com/Vulnmachines/ZF3_CVE-2021-3007](https://github.com/Vulnmachines/ZF3_CVE-2021-3007) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/ZF3_CVE-2021-3007.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/ZF3_CVE-2021-3007.svg)


## CVE-2020-14295
 A SQL injection issue in color.php in Cacti 1.2.12 allows an admin to inject SQL via the filter parameter. This can lead to remote command execution because the product accepts stacked queries.

- [https://github.com/hadrian3689/cacti_1.2.12](https://github.com/hadrian3689/cacti_1.2.12) :  ![starts](https://img.shields.io/github/stars/hadrian3689/cacti_1.2.12.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/cacti_1.2.12.svg)


## CVE-2020-13851
 Artica Pandora FMS 7.44 allows remote command execution via the events feature.

- [https://github.com/hadrian3689/pandorafms_7.44](https://github.com/hadrian3689/pandorafms_7.44) :  ![starts](https://img.shields.io/github/stars/hadrian3689/pandorafms_7.44.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/pandorafms_7.44.svg)


## CVE-2019-18818
 strapi before 3.0.0-beta.17.5 mishandles password resets within packages/strapi-admin/controllers/Auth.js and packages/strapi-plugin-users-permissions/controllers/Auth.js.

- [https://github.com/hadrian3689/strapi_cms_3.0.0-beta.17.7](https://github.com/hadrian3689/strapi_cms_3.0.0-beta.17.7) :  ![starts](https://img.shields.io/github/stars/hadrian3689/strapi_cms_3.0.0-beta.17.7.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/strapi_cms_3.0.0-beta.17.7.svg)


## CVE-2019-15949
 Nagios XI before 5.6.6 allows remote command execution as root. The exploit requires access to the server as the nagios user, or access as the admin user via the web interface. The getprofile.sh script, invoked by downloading a system profile (profile.php?cmd=download), is executed as root via a passwordless sudo entry; the script executes check_plugin, which is owned by the nagios user. A user logged into Nagios XI with permissions to modify plugins, or the nagios user on the server, can modify the check_plugin executable and insert malicious commands to execute as root.

- [https://github.com/hadrian3689/nagiosxi_5.6.6](https://github.com/hadrian3689/nagiosxi_5.6.6) :  ![starts](https://img.shields.io/github/stars/hadrian3689/nagiosxi_5.6.6.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/nagiosxi_5.6.6.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/hadrian3689/webmin_1.920](https://github.com/hadrian3689/webmin_1.920) :  ![starts](https://img.shields.io/github/stars/hadrian3689/webmin_1.920.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/webmin_1.920.svg)


## CVE-2019-15062
 An issue was discovered in Dolibarr 11.0.0-alpha. A user can store an IFRAME element (containing a user/card.php CSRF request) in his Linked Files settings page. When visited by the admin, this could completely take over the admin account. (The protection mechanism for CSRF is to check the Referer header; however, because the attack is from one of the application's own settings pages, this mechanism is bypassed.)

- [https://github.com/Live-Hack-CVE/CVE-2019-15062](https://github.com/Live-Hack-CVE/CVE-2019-15062) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-15062.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-15062.svg)


## CVE-2019-13768
 Use after free in FileAPI in Google Chrome prior to 72.0.3626.81 allowed a remote attacker to potentially perform a sandbox escape via a crafted HTML page. (Chrome security severity: High)

- [https://github.com/Live-Hack-CVE/CVE-2019-13768](https://github.com/Live-Hack-CVE/CVE-2019-13768) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-13768.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-13768.svg)


## CVE-2019-8943
 WordPress through 5.0.3 allows Path Traversal in wp_crop_image(). An attacker (who has privileges to crop an image) can write the output image to an arbitrary directory via a filename containing two image extensions and ../ sequences, such as a filename ending with the .jpg?/../../file.jpg substring.

- [https://github.com/hadrian3689/wordpress_cropimage](https://github.com/hadrian3689/wordpress_cropimage) :  ![starts](https://img.shields.io/github/stars/hadrian3689/wordpress_cropimage.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/wordpress_cropimage.svg)


## CVE-2019-5736
 runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a command as root within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.

- [https://github.com/batuhan-dilek99/CVE-2019-5736](https://github.com/batuhan-dilek99/CVE-2019-5736) :  ![starts](https://img.shields.io/github/stars/batuhan-dilek99/CVE-2019-5736.svg) ![forks](https://img.shields.io/github/forks/batuhan-dilek99/CVE-2019-5736.svg)


## CVE-2016-15007
 A vulnerability was found in Centralized-Salesforce-Dev-Framework. It has been declared as problematic. Affected by this vulnerability is the function SObjectService of the file src/classes/SObjectService.cls of the component SOQL Handler. The manipulation of the argument orderDirection leads to injection. The name of the patch is db03ac5b8a9d830095991b529c067a030a0ccf7b. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217195.

- [https://github.com/Live-Hack-CVE/CVE-2016-15007](https://github.com/Live-Hack-CVE/CVE-2016-15007) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-15007.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-15007.svg)


## CVE-2015-10012
 ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability was found in sumocoders FrameworkUserBundle up to 1.3.x. It has been rated as problematic. Affected by this issue is some unknown functionality of the file Resources/views/Security/login.html.twig. The manipulation leads to information exposure through error message. Upgrading to version 1.4.0 is able to address this issue. The name of the patch is abe4993390ba9bd7821ab12678270556645f94c8. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-217268. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Live-Hack-CVE/CVE-2015-10012](https://github.com/Live-Hack-CVE/CVE-2015-10012) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10012.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10012.svg)


## CVE-2015-10011
 A vulnerability classified as problematic has been found in OpenDNS OpenResolve. This affects an unknown part of the file resolverapi/endpoints.py. The manipulation leads to improper output neutralization for logs. The name of the patch is 9eba6ba5abd89d0e36a008921eb307fcef8c5311. It is recommended to apply a patch to fix this issue. The identifier VDB-217197 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2015-10011](https://github.com/Live-Hack-CVE/CVE-2015-10011) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10011.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10011.svg)


## CVE-2015-6967
 Unrestricted file upload vulnerability in the My Image plugin in Nibbleblog before 4.0.5 allows remote administrators to execute arbitrary code by uploading a file with an executable extension, then accessing it via a direct request to the file in content/private/plugins/my_image/image.php.

- [https://github.com/hadrian3689/nibbleblog_4.0.3](https://github.com/hadrian3689/nibbleblog_4.0.3) :  ![starts](https://img.shields.io/github/stars/hadrian3689/nibbleblog_4.0.3.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/nibbleblog_4.0.3.svg)


## CVE-2014-125036
 A vulnerability, which was classified as problematic, has been found in drybjed ansible-ntp. Affected by this issue is some unknown functionality of the file meta/main.yml. The manipulation leads to insufficient control of network message volume. The attack can only be done within the local network. The name of the patch is ed4ca2cf012677973c220cdba36b5c60bfa0260b. It is recommended to apply a patch to fix this issue. VDB-217190 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125036](https://github.com/Live-Hack-CVE/CVE-2014-125036) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125036.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125036.svg)


## CVE-2014-6287
 The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aks HFS or HttpFileServer) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

- [https://github.com/hadrian3689/rejetto_hfs_rce](https://github.com/hadrian3689/rejetto_hfs_rce) :  ![starts](https://img.shields.io/github/stars/hadrian3689/rejetto_hfs_rce.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/rejetto_hfs_rce.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/hadrian3689/shellshock](https://github.com/hadrian3689/shellshock) :  ![starts](https://img.shields.io/github/stars/hadrian3689/shellshock.svg) ![forks](https://img.shields.io/github/forks/hadrian3689/shellshock.svg)


## CVE-2013-10007
 A vulnerability classified as problematic has been found in ethitter WP-Print-Friendly up to 0.5.2. This affects an unknown part of the file wp-print-friendly.php. The manipulation leads to information disclosure. It is possible to initiate the attack remotely. Upgrading to version 0.5.3 is able to address this issue. The name of the patch is 437787292670c20b4abe20160ebbe8428187f2b4. It is recommended to upgrade the affected component. The identifier VDB-217269 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2013-10007](https://github.com/Live-Hack-CVE/CVE-2013-10007) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2013-10007.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2013-10007.svg)


## CVE-2012-10003
 A vulnerability, which was classified as problematic, has been found in ahmyi RivetTracker. This issue affects some unknown processing. The manipulation of the argument $_SERVER['PHP_SELF'] leads to cross site scripting. The attack may be initiated remotely. The name of the patch is f053c5cc2bc44269b0496b5f275e349928a92ef9. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217271.

- [https://github.com/Live-Hack-CVE/CVE-2012-10003](https://github.com/Live-Hack-CVE/CVE-2012-10003) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-10003.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-10003.svg)


## CVE-2012-10002
 A vulnerability was found in ahmyi RivetTracker. It has been declared as problematic. Affected by this vulnerability is the function changeColor of the file css.php. The manipulation of the argument set_css leads to cross site scripting. The attack can be launched remotely. The name of the patch is 45a0f33876d58cb7e4a0f17da149e58fc893b858. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217267.

- [https://github.com/Live-Hack-CVE/CVE-2012-10002](https://github.com/Live-Hack-CVE/CVE-2012-10002) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-10002.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-10002.svg)


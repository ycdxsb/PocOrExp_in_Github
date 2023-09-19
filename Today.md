# Update 2023-09-19
## CVE-2023-42471
 The wave.ai.browser application through 1.0.35 for Android allows a remote attacker to execute arbitrary JavaScript code via a crafted intent. It contains a manifest entry that exports the wave.ai.browser.ui.splash.SplashScreen activity. This activity uses a WebView component to display web content and doesn't adequately validate or sanitize the URI or any extra data passed in the intent by a third party application (with no permissions).

- [https://github.com/actuator/cve](https://github.com/actuator/cve) :  ![starts](https://img.shields.io/github/stars/actuator/cve.svg) ![forks](https://img.shields.io/github/forks/actuator/cve.svg)


## CVE-2023-42470
 The Imou Life com.mm.android.smartlifeiot application through 6.8.0 for Android allows Remote Code Execution via a crafted intent to an exported component. This relates to the com.mm.android.easy4ip.MainActivity activity. JavaScript execution is enabled in the WebView, and direct web content loading occurs.

- [https://github.com/actuator/cve](https://github.com/actuator/cve) :  ![starts](https://img.shields.io/github/stars/actuator/cve.svg) ![forks](https://img.shields.io/github/forks/actuator/cve.svg)


## CVE-2023-42469
 The com.full.dialer.top.secure.encrypted application through 1.0.1 for Android enables any installed application (with no permissions) to place phone calls without user interaction by sending a crafted intent via the com.full.dialer.top.secure.encrypted.activities.DialerActivity component.

- [https://github.com/actuator/cve](https://github.com/actuator/cve) :  ![starts](https://img.shields.io/github/stars/actuator/cve.svg) ![forks](https://img.shields.io/github/forks/actuator/cve.svg)


## CVE-2023-42468
 The com.cutestudio.colordialer application through 2.1.8-2 for Android allows a remote attacker to initiate phone calls without user consent, because of improper export of the com.cutestudio.dialer.activities.DialerActivity component. A third-party application (without any permissions) can craft an intent targeting com.cutestudio.dialer.activities.DialerActivity via the android.intent.action.CALL action in conjunction with a tel: URI, thereby placing a phone call.

- [https://github.com/actuator/cve](https://github.com/actuator/cve) :  ![starts](https://img.shields.io/github/stars/actuator/cve.svg) ![forks](https://img.shields.io/github/forks/actuator/cve.svg)


## CVE-2023-40040
 An issue was discovered in the MyCrops HiGrade &quot;THC Testing &amp; Cannabi&quot; application 1.0.337 for Android. A remote attacker can start the camera feed via the com.cordovaplugincamerapreview.CameraActivity component in some situations. NOTE: this is only exploitable on Android versions that lack runtime permission checks, and of those only Android SDK 5.1.1 API 22 is consistent with the manifest. Thus, this applies only to Android Lollipop, affecting less than five percent of Android devices as of 2023.

- [https://github.com/actuator/cve](https://github.com/actuator/cve) :  ![starts](https://img.shields.io/github/stars/actuator/cve.svg) ![forks](https://img.shields.io/github/forks/actuator/cve.svg)


## CVE-2023-32784
 In KeePass 2.x before 2.54, it is possible to recover the cleartext master password from a memory dump, even when a workspace is locked or no longer running. The memory dump can be a KeePass process dump, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. The first character cannot be recovered. In 2.54, there is different API usage and/or random string insertion for mitigation.

- [https://github.com/dawnl3ss/CVE-2023-32784](https://github.com/dawnl3ss/CVE-2023-32784) :  ![starts](https://img.shields.io/github/stars/dawnl3ss/CVE-2023-32784.svg) ![forks](https://img.shields.io/github/forks/dawnl3ss/CVE-2023-32784.svg)


## CVE-2023-32629
 Local privilege escalation vulnerability in Ubuntu Kernels overlayfs ovl_copy_up_meta_inode_data skip permission checks when calling ovl_do_setxattr on Ubuntu kernels

- [https://github.com/luanoliveira350/GameOverlayFS](https://github.com/luanoliveira350/GameOverlayFS) :  ![starts](https://img.shields.io/github/stars/luanoliveira350/GameOverlayFS.svg) ![forks](https://img.shields.io/github/forks/luanoliveira350/GameOverlayFS.svg)


## CVE-2023-2640
 On Ubuntu kernels carrying both c914c0e27eb0 and &quot;UBUNTU: SAUCE: overlayfs: Skip permission checking for trusted.overlayfs.* xattrs&quot;, an unprivileged user may set privileged extended attributes on the mounted files, leading them to be set on the upper files without the appropriate security checks.

- [https://github.com/luanoliveira350/GameOverlayFS](https://github.com/luanoliveira350/GameOverlayFS) :  ![starts](https://img.shields.io/github/stars/luanoliveira350/GameOverlayFS.svg) ![forks](https://img.shields.io/github/forks/luanoliveira350/GameOverlayFS.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/dawnl3ss/CVE-2022-46169](https://github.com/dawnl3ss/CVE-2022-46169) :  ![starts](https://img.shields.io/github/stars/dawnl3ss/CVE-2022-46169.svg) ![forks](https://img.shields.io/github/forks/dawnl3ss/CVE-2022-46169.svg)


## CVE-2022-32947
 The issue was addressed with improved memory handling. This issue is fixed in iOS 16.1 and iPadOS 16, macOS Ventura 13, watchOS 9.1. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/asahilina/agx-exploit](https://github.com/asahilina/agx-exploit) :  ![starts](https://img.shields.io/github/stars/asahilina/agx-exploit.svg) ![forks](https://img.shields.io/github/forks/asahilina/agx-exploit.svg)


## CVE-2022-2588
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ASkyeye/2022-LPE-UAF](https://github.com/ASkyeye/2022-LPE-UAF) :  ![starts](https://img.shields.io/github/stars/ASkyeye/2022-LPE-UAF.svg) ![forks](https://img.shields.io/github/forks/ASkyeye/2022-LPE-UAF.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/pashayogi/DirtyPipe](https://github.com/pashayogi/DirtyPipe) :  ![starts](https://img.shields.io/github/stars/pashayogi/DirtyPipe.svg) ![forks](https://img.shields.io/github/forks/pashayogi/DirtyPipe.svg)


## CVE-2021-38699
 TastyIgniter 3.0.7 allows XSS via /account, /reservation, /admin/dashboard, and /admin/system_logs.

- [https://github.com/Justin-1993/CVE-2021-38699](https://github.com/Justin-1993/CVE-2021-38699) :  ![starts](https://img.shields.io/github/stars/Justin-1993/CVE-2021-38699.svg) ![forks](https://img.shields.io/github/forks/Justin-1993/CVE-2021-38699.svg)


## CVE-2021-34621
 A vulnerability in the user registration component found in the ~/src/Classes/RegistrationAuth.php file of the ProfilePress WordPress plugin made it possible for users to register on sites as an administrator. This issue affects versions 3.0.0 - 3.1.3. .

- [https://github.com/RandomRobbieBF/CVE-2021-34621](https://github.com/RandomRobbieBF/CVE-2021-34621) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2021-34621.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2021-34621.svg)


## CVE-2020-5847
 Unraid through 6.8.0 allows Remote Code Execution.

- [https://github.com/1Gould/CVE-2020-5847-exploit](https://github.com/1Gould/CVE-2020-5847-exploit) :  ![starts](https://img.shields.io/github/stars/1Gould/CVE-2020-5847-exploit.svg) ![forks](https://img.shields.io/github/forks/1Gould/CVE-2020-5847-exploit.svg)


## CVE-2018-15473
 OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

- [https://github.com/mrblue12-byte/CVE-2018-15473](https://github.com/mrblue12-byte/CVE-2018-15473) :  ![starts](https://img.shields.io/github/stars/mrblue12-byte/CVE-2018-15473.svg) ![forks](https://img.shields.io/github/forks/mrblue12-byte/CVE-2018-15473.svg)


## CVE-2018-6389
 In WordPress through 4.9.2, unauthenticated attackers can cause a denial of service (resource consumption) by using the large list of registered .js files (from wp-includes/script-loader.php) to construct a series of requests to load every file many times.

- [https://github.com/safebuffer/CVE-2018-6389](https://github.com/safebuffer/CVE-2018-6389) :  ![starts](https://img.shields.io/github/stars/safebuffer/CVE-2018-6389.svg) ![forks](https://img.shields.io/github/forks/safebuffer/CVE-2018-6389.svg)


## CVE-2014-9301
 Server-side request forgery (SSRF) vulnerability in the proxy servlet in Alfresco Community Edition before 5.0.a allows remote attackers to trigger outbound requests to intranet servers, conduct port scans, and read arbitrary files via a crafted URI in the endpoint parameter.

- [https://github.com/ottimo/burp-alfresco-referer-proxy-cve-2014-9301](https://github.com/ottimo/burp-alfresco-referer-proxy-cve-2014-9301) :  ![starts](https://img.shields.io/github/stars/ottimo/burp-alfresco-referer-proxy-cve-2014-9301.svg) ![forks](https://img.shields.io/github/forks/ottimo/burp-alfresco-referer-proxy-cve-2014-9301.svg)


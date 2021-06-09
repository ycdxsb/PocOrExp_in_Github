# Update 2021-06-09
## CVE-2021-33904
 In Accela Civic Platform through 21.1, the security/hostSignon.do parameter servProvCode is vulnerable to XSS.

- [https://github.com/JamesGeeee/CVE-2021-33904](https://github.com/JamesGeeee/CVE-2021-33904) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-33904.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-33904.svg)


## CVE-2021-33896
 Dino before 0.1.2 and 0.2.x before 0.2.1 allows Directory Traversal (only for creation of new files) via URI-encoded path separators.

- [https://github.com/JamesGeeee/CVE-2021-33896](https://github.com/JamesGeeee/CVE-2021-33896) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-33896.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-33896.svg)


## CVE-2021-33840
 The server in Luca through 1.1.14 allows remote attackers to cause a denial of service (insertion of many fake records related to COVID-19) because Phone Number data lacks a digital signature.

- [https://github.com/JamesGeeee/CVE-2021-33840](https://github.com/JamesGeeee/CVE-2021-33840) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-33840.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-33840.svg)


## CVE-2021-33839
 Luca through 1.7.4 on Android allows remote attackers to obtain sensitive information about COVID-19 tracking because the QR code of a Public Location can be intentionally confused with the QR code of a Private Meeting.

- [https://github.com/JamesGeeee/CVE-2021-33839](https://github.com/JamesGeeee/CVE-2021-33839) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-33839.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-33839.svg)


## CVE-2021-33838
 Luca through 1.7.4 on Android allows remote attackers to obtain sensitive information about COVID-19 tracking because requests related to Check-In State occur shortly after requests for Phone Number Registration.

- [https://github.com/JamesGeeee/CVE-2021-33838](https://github.com/JamesGeeee/CVE-2021-33838) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-33838.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-33838.svg)


## CVE-2021-33194
 Go through 1.15.12 and 1.16.x through 1.16.4 has a golang.org/x/net/html infinite loop via crafted ParseFragment input.

- [https://github.com/JamesGeeee/CVE-2021-33194](https://github.com/JamesGeeee/CVE-2021-33194) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-33194.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-33194.svg)


## CVE-2021-32671
 Flarum is a forum software for building communities. Flarum's translation system allowed for string inputs to be converted into HTML DOM nodes when rendered. This change was made after v0.1.0-beta.16 (our last beta before v1.0.0) and was not noticed or documented. This allowed for any user to type malicious HTML markup within certain user input fields and have this execute on client browsers. The example which led to the discovery of this vulnerability was in the forum search box. Entering faux-malicious HTML markup, such as &lt;script&gt;alert('test')&lt;/script&gt; resulted in an alert box appearing on the forum. This attack could also be modified to perform AJAX requests on behalf of a user, possibly deleting discussions, modifying their settings or profile, or even modifying settings on the Admin panel if the attack was targetted towards a privileged user. All Flarum communities that run flarum v1.0.0 or v1.0.1 are impacted. The vulnerability has been fixed and published as flarum/core v1.0.2. All communities running Flarum v1.0 have to upgrade as soon as possible to v1.0.2.

- [https://github.com/JamesGeeee/CVE-2021-32671](https://github.com/JamesGeeee/CVE-2021-32671) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-32671.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-32671.svg)


## CVE-2021-32670
 Datasette is an open source multi-tool for exploring and publishing data. The `?_trace=1` debugging feature in Datasette does not correctly escape generated HTML, resulting in a [reflected cross-site scripting](https://owasp.org/www-community/attacks/xss/#reflected-xss-attacks) vulnerability. This vulnerability is particularly relevant if your Datasette installation includes authenticated features using plugins such as [datasette-auth-passwords](https://datasette.io/plugins/datasette-auth-passwords) as an attacker could use the vulnerability to access protected data. Datasette 0.57 and 0.56.1 both include patches for this issue. If you run Datasette behind a proxy you can workaround this issue by rejecting any incoming requests with `?_trace=` or `&amp;_trace=` in their query string parameters.

- [https://github.com/JamesGeeee/CVE-2021-32670](https://github.com/JamesGeeee/CVE-2021-32670) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-32670.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-32670.svg)


## CVE-2021-32458
 Trend Micro Home Network Security version 6.6.604 and earlier is vulnerable to an iotcl stack-based buffer overflow vulnerability which could allow an attacker to issue a specially crafted iotcl which could lead to code execution on affected devices. An attacker must first obtain the ability to execute low-privileged code on the target device in order to exploit this vulnerability.

- [https://github.com/JamesGeeee/CVE-2021-32458](https://github.com/JamesGeeee/CVE-2021-32458) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-32458.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-32458.svg)


## CVE-2021-31920
 Istio before 1.8.6 and 1.9.x before 1.9.5 has a remotely exploitable vulnerability where an HTTP request path with multiple slashes or escaped slash characters (%2F or %5C) could potentially bypass an Istio authorization policy when path based authorization rules are used.

- [https://github.com/JamesGeeee/CVE-2021-31920](https://github.com/JamesGeeee/CVE-2021-31920) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-31920.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-31920.svg)


## CVE-2021-31155
 Failure to normalize the umask in please before 0.4 allows a local attacker to gain full root privileges if they are allowed to execute at least one command.

- [https://github.com/JamesGeeee/CVE-2021-31155](https://github.com/JamesGeeee/CVE-2021-31155) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-31155.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-31155.svg)


## CVE-2021-31154
 pleaseedit in please before 0.4 uses predictable temporary filenames in /tmp and the target directory. This allows a local attacker to gain full root privileges by staging a symlink attack.

- [https://github.com/JamesGeeee/CVE-2021-31154](https://github.com/JamesGeeee/CVE-2021-31154) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-31154.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-31154.svg)


## CVE-2021-31153
 please before 0.4 allows a local unprivileged attacker to gain knowledge about the existence of files or directories in privileged locations via the search_path function, the --check option, or the -d option.

- [https://github.com/JamesGeeee/CVE-2021-31153](https://github.com/JamesGeeee/CVE-2021-31153) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-31153.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-31153.svg)


## CVE-2021-30543
 Use after free in Tab Strip in Google Chrome prior to 91.0.4472.77 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30543](https://github.com/JamesGeeee/CVE-2021-30543) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30543.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30543.svg)


## CVE-2021-30542
 Use after free in Tab Strip in Google Chrome prior to 91.0.4472.77 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30542](https://github.com/JamesGeeee/CVE-2021-30542) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30542.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30542.svg)


## CVE-2021-30540
 Incorrect security UI in payments in Google Chrome on Android prior to 91.0.4472.77 allowed a remote attacker to perform domain spoofing via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30540](https://github.com/JamesGeeee/CVE-2021-30540) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30540.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30540.svg)


## CVE-2021-30539
 Insufficient policy enforcement in content security policy in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to bypass content security policy via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30539](https://github.com/JamesGeeee/CVE-2021-30539) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30539.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30539.svg)


## CVE-2021-30538
 Insufficient policy enforcement in content security policy in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to bypass content security policy via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30538](https://github.com/JamesGeeee/CVE-2021-30538) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30538.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30538.svg)


## CVE-2021-30537
 Insufficient policy enforcement in cookies in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to bypass cookie policy via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30537](https://github.com/JamesGeeee/CVE-2021-30537) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30537.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30537.svg)


## CVE-2021-30536
 Out of bounds read in V8 in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to potentially exploit stack corruption via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30536](https://github.com/JamesGeeee/CVE-2021-30536) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30536.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30536.svg)


## CVE-2021-30535
 Double free in ICU in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30535](https://github.com/JamesGeeee/CVE-2021-30535) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30535.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30535.svg)


## CVE-2021-30534
 Insufficient policy enforcement in iFrameSandbox in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to bypass navigation restrictions via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30534](https://github.com/JamesGeeee/CVE-2021-30534) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30534.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30534.svg)


## CVE-2021-30533
 Insufficient policy enforcement in PopupBlocker in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to bypass navigation restrictions via a crafted iframe.

- [https://github.com/JamesGeeee/CVE-2021-30533](https://github.com/JamesGeeee/CVE-2021-30533) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30533.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30533.svg)


## CVE-2021-30532
 Insufficient policy enforcement in Content Security Policy in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to bypass content security policy via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30532](https://github.com/JamesGeeee/CVE-2021-30532) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30532.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30532.svg)


## CVE-2021-30531
 Insufficient policy enforcement in Content Security Policy in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to bypass content security policy via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30531](https://github.com/JamesGeeee/CVE-2021-30531) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30531.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30531.svg)


## CVE-2021-30530
 Out of bounds memory access in WebAudio in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30530](https://github.com/JamesGeeee/CVE-2021-30530) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30530.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30530.svg)


## CVE-2021-30529
 Use after free in Bookmarks in Google Chrome prior to 91.0.4472.77 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30529](https://github.com/JamesGeeee/CVE-2021-30529) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30529.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30529.svg)


## CVE-2021-30528
 Use after free in WebAuthentication in Google Chrome on Android prior to 91.0.4472.77 allowed a remote attacker who had compromised the renderer process of a user who had saved a credit card in their Google account to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30528](https://github.com/JamesGeeee/CVE-2021-30528) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30528.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30528.svg)


## CVE-2021-30527
 Use after free in WebUI in Google Chrome prior to 91.0.4472.77 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30527](https://github.com/JamesGeeee/CVE-2021-30527) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30527.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30527.svg)


## CVE-2021-30526
 Out of bounds write in TabStrip in Google Chrome prior to 91.0.4472.77 allowed an attacker who convinced a user to install a malicious extension to perform an out of bounds memory write via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30526](https://github.com/JamesGeeee/CVE-2021-30526) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30526.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30526.svg)


## CVE-2021-30525
 Use after free in TabGroups in Google Chrome prior to 91.0.4472.77 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30525](https://github.com/JamesGeeee/CVE-2021-30525) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30525.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30525.svg)


## CVE-2021-30524
 Use after free in TabStrip in Google Chrome prior to 91.0.4472.77 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30524](https://github.com/JamesGeeee/CVE-2021-30524) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30524.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30524.svg)


## CVE-2021-30523
 Use after free in WebRTC in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to potentially exploit heap corruption via a crafted SCTP packet.

- [https://github.com/JamesGeeee/CVE-2021-30523](https://github.com/JamesGeeee/CVE-2021-30523) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30523.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30523.svg)


## CVE-2021-30522
 Use after free in WebAudio in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30522](https://github.com/JamesGeeee/CVE-2021-30522) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30522.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30522.svg)


## CVE-2021-30521
 Heap buffer overflow in Autofill in Google Chrome on Android prior to 91.0.4472.77 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-30521](https://github.com/JamesGeeee/CVE-2021-30521) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30521.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30521.svg)


## CVE-2021-30465
 runc before 1.0.0-rc95 allows a Container Filesystem Breakout via Directory Traversal. To exploit the vulnerability, an attacker must be able to create multiple containers with a fairly specific mount configuration. The problem occurs via a symlink-exchange attack that relies on a race condition.

- [https://github.com/JamesGeeee/CVE-2021-30465](https://github.com/JamesGeeee/CVE-2021-30465) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-30465.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-30465.svg)


## CVE-2021-29740
 IBM Spectrum Scale 5.0.0 through 5.0.5.6 and 5.1.0 through 5.1.0.3 system core component is affected by a format string security vulnerability. An attacker could execute arbitrary code in the context of process memory, potentially escalating their system privileges and taking control over the entire system with root access. IBM X-Force ID: 201474.

- [https://github.com/JamesGeeee/CVE-2021-29740](https://github.com/JamesGeeee/CVE-2021-29740) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-29740.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-29740.svg)


## CVE-2021-29670
 IBM Jazz Foundation and IBM Engineering products are vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 199408.

- [https://github.com/JamesGeeee/CVE-2021-29670](https://github.com/JamesGeeee/CVE-2021-29670) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-29670.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-29670.svg)


## CVE-2021-29668
 IBM Jazz Foundation and IBM Engineering products are vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 199406.

- [https://github.com/JamesGeeee/CVE-2021-29668](https://github.com/JamesGeeee/CVE-2021-29668) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-29668.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-29668.svg)


## CVE-2021-29665
 IBM Security Verify Access 20.07 is vulnerable to a stack based buffer overflow, caused by improper bounds checking which could allow a local attacker to execute arbitrary code on the system with elevated privileges.

- [https://github.com/JamesGeeee/CVE-2021-29665](https://github.com/JamesGeeee/CVE-2021-29665) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-29665.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-29665.svg)


## CVE-2021-29621
 Flask-AppBuilder is a development framework, built on top of Flask. User enumeration in database authentication in Flask-AppBuilder &lt;= 3.2.3. Allows for a non authenticated user to enumerate existing accounts by timing the response time from the server when you are logging in. Upgrade to version 3.3.0 or higher to resolve.

- [https://github.com/JamesGeeee/CVE-2021-29621](https://github.com/JamesGeeee/CVE-2021-29621) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-29621.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-29621.svg)


## CVE-2021-29505
 XStream is software for serializing Java objects to XML and back again. A vulnerability in XStream versions prior to 1.4.17 may allow a remote attacker has sufficient rights to execute commands of the host only by manipulating the processed input stream. No user who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types is affected. The vulnerability is patched in version 1.4.17.

- [https://github.com/MyBlackManba/CVE-2021-29505](https://github.com/MyBlackManba/CVE-2021-29505) :  ![starts](https://img.shields.io/github/stars/MyBlackManba/CVE-2021-29505.svg) ![forks](https://img.shields.io/github/forks/MyBlackManba/CVE-2021-29505.svg)


## CVE-2021-29504
 WP-CLI is the command-line interface for WordPress. An improper error handling in HTTPS requests management in WP-CLI version 0.12.0 and later allows remote attackers able to intercept the communication to remotely disable the certificate verification on WP-CLI side, gaining full control over the communication content, including the ability to impersonate update servers and push malicious updates towards WordPress instances controlled by the vulnerable WP-CLI agent, or push malicious updates toward WP-CLI itself. The vulnerability stems from the fact that the default behavior of `WP_CLI\Utils\http_request()` when encountering a TLS handshake error is to disable certificate validation and retry the same request. The default behavior has been changed with version 2.5.0 of WP-CLI and the `wp-cli/wp-cli` framework (via https://github.com/wp-cli/wp-cli/pull/5523) so that the `WP_CLI\Utils\http_request()` method accepts an `$insecure` option that is `false` by default and consequently that a TLS handshake failure is a hard error by default. This new default is a breaking change and ripples through to all consumers of `WP_CLI\Utils\http_request()`, including those in separate WP-CLI bundled or third-party packages. https://github.com/wp-cli/wp-cli/pull/5523 has also added an `--insecure` flag to the `cli update` command to counter this breaking change. There is no direct workaround for the default insecure behavior of `wp-cli/wp-cli` versions before 2.5.0. The workaround for dealing with the breaking change in the commands directly affected by the new secure default behavior is to add the `--insecure` flag to manually opt-in to the previous insecure behavior.

- [https://github.com/JamesGeeee/CVE-2021-29504](https://github.com/JamesGeeee/CVE-2021-29504) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-29504.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-29504.svg)


## CVE-2021-29099
 A SQL injection vulnerability exists in some configurations of ArcGIS Server versions 10.8.1 and earlier. Specially crafted web requests can expose information that is not intended to be disclosed (not customer datasets). Web Services that use file based data sources (file Geodatabase or Shape Files or tile cached services) are unaffected by this issue.

- [https://github.com/JamesGeeee/CVE-2021-29099](https://github.com/JamesGeeee/CVE-2021-29099) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-29099.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-29099.svg)


## CVE-2021-26080
 EditworkflowScheme.jspa in Jira Server and Jira Data Center before version 8.5.14, and from version 8.6.0 before version 8.13.6, and from 8.14.0 before 8.16.1 allows remote attackers to inject arbitrary HTML or JavaScript via a cross site scripting (XSS) vulnerability.

- [https://github.com/JamesGeeee/CVE-2021-26080](https://github.com/JamesGeeee/CVE-2021-26080) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-26080.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-26080.svg)


## CVE-2021-26079
 The CardLayoutConfigTable component in Jira Server and Jira Data Center before version 8.5.15, and from version 8.6.0 before version 8.13.7, and from version 8.14.0 before 8.17.0 allows remote attackers to inject arbitrary HTML or JavaScript via a cross site scripting (XSS) vulnerability.

- [https://github.com/JamesGeeee/CVE-2021-26079](https://github.com/JamesGeeee/CVE-2021-26079) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-26079.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-26079.svg)


## CVE-2021-26078
 The number range searcher component in Jira Server and Jira Data Center before version 8.5.14, from version 8.6.0 before version 8.13.6, and from version 8.14.0 before version 8.16.1 allows remote attackers inject arbitrary HTML or JavaScript via a cross site scripting (XSS) vulnerability.

- [https://github.com/JamesGeeee/CVE-2021-26078](https://github.com/JamesGeeee/CVE-2021-26078) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-26078.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-26078.svg)


## CVE-2021-23391
 This affects all versions of package calipso. It is possible for a malicious module to overwrite files on an arbitrary file system through the module install functionality.

- [https://github.com/JamesGeeee/CVE-2021-23391](https://github.com/JamesGeeee/CVE-2021-23391) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-23391.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-23391.svg)


## CVE-2021-23362
 The package hosted-git-info before 3.0.8 are vulnerable to Regular Expression Denial of Service (ReDoS) via regular expression shortcutMatch in the fromUrl function in index.js. The affected regular expression exhibits polynomial worst-case time complexity.

- [https://github.com/JamesGeeee/CVE-2021-23362](https://github.com/JamesGeeee/CVE-2021-23362) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-23362.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-23362.svg)


## CVE-2021-22911
 A improper input sanitization vulnerability exists in Rocket.Chat server 3.11, 3.12 &amp; 3.13 that could lead to unauthenticated NoSQL injection, resulting potentially in RCE.

- [https://github.com/JamesGeeee/CVE-2021-22911](https://github.com/JamesGeeee/CVE-2021-22911) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-22911.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-22911.svg)


## CVE-2021-22705
 Improper Restriction of Operations within the Bounds of a Memory Buffer vulnerability exists that could cause denial of service or unauthorized access to system information when interacting directly with a driver installed by Vijeo Designer or EcoStruxure Machine Expert

- [https://github.com/JamesGeeee/CVE-2021-22705](https://github.com/JamesGeeee/CVE-2021-22705) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-22705.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-22705.svg)


## CVE-2021-22543
 An issue was discovered in Linux: KVM through Improper handling of VM_IO|VM_PFNMAP vmas in KVM can bypass RO checks and can lead to pages being freed while still accessible by the VMM and guest. This allows users with the ability to start and control a VM to read/write random pages of memory and can result in local privilege escalation.

- [https://github.com/JamesGeeee/CVE-2021-22543](https://github.com/JamesGeeee/CVE-2021-22543) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-22543.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-22543.svg)


## CVE-2021-22222
 Infinite loop in DVB-S2-BB dissector in Wireshark 3.4.0 to 3.4.5 allows denial of service via packet injection or crafted capture file

- [https://github.com/JamesGeeee/CVE-2021-22222](https://github.com/JamesGeeee/CVE-2021-22222) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-22222.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-22222.svg)


## CVE-2021-22118
 In Spring Framework, versions 5.2.x prior to 5.2.15 and versions 5.3.x prior to 5.3.7, a WebFlux application is vulnerable to a privilege escalation: by (re)creating the temporary storage directory, a locally authenticated malicious user can read or modify files that have been uploaded to the WebFlux application, or overwrite arbitrary files with multipart request data.

- [https://github.com/JamesGeeee/CVE-2021-22118](https://github.com/JamesGeeee/CVE-2021-22118) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-22118.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-22118.svg)


## CVE-2021-21198
 Out of bounds read in IPC in Google Chrome prior to 89.0.4389.114 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.

- [https://github.com/JamesGeeee/CVE-2021-21198](https://github.com/JamesGeeee/CVE-2021-21198) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-21198.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-21198.svg)


## CVE-2021-20699
 Sharp NEC Displays (UN462A R1.300 and prior to it, UN462VA R1.300 and prior to it, UN492S R1.300 and prior to it, UN492VS R1.300 and prior to it, UN552A R1.300 and prior to it, UN552S R1.300 and prior to it, UN552VS R1.300 and prior to it, UN552 R1.300 and prior to it, UN552V R1.300 and prior to it, UX552S R1.300 and prior to it, UN552 R1.300 and prior to it, V864Q R2.000 and prior to it, C861Q R2.000 and prior to it, P754Q R2.000 and prior to it, V754Q R2.000 and prior to it, C751Q R2.000 and prior to it, V964Q R2.000 and prior to it, C961Q R2.000 and prior to it, P654Q R2.000 and prior to it, V654Q R2.000 and prior to it, C651Q R2.000 and prior to it, V554Q R2.000 and prior to it) allows an attacker a buffer overflow and to execute remote code by sending long parameters that contains specific characters in http request.

- [https://github.com/JamesGeeee/CVE-2021-20699](https://github.com/JamesGeeee/CVE-2021-20699) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-20699.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-20699.svg)


## CVE-2021-20698
 Sharp NEC Displays (UN462A R1.300 and prior to it, UN462VA R1.300 and prior to it, UN492S R1.300 and prior to it, UN492VS R1.300 and prior to it, UN552A R1.300 and prior to it, UN552S R1.300 and prior to it, UN552VS R1.300 and prior to it, UN552 R1.300 and prior to it, UN552V R1.300 and prior to it, UX552S R1.300 and prior to it, UN552 R1.300 and prior to it, V864Q R2.000 and prior to it, C861Q R2.000 and prior to it, P754Q R2.000 and prior to it, V754Q R2.000 and prior to it, C751Q R2.000 and prior to it, V964Q R2.000 and prior to it, C961Q R2.000 and prior to it, P654Q R2.000 and prior to it, V654Q R2.000 and prior to it, C651Q R2.000 and prior to it, V554Q R2.000 and prior to it) allows an attacker to obtain root privileges and execute remote code by sending unintended parameters that contain specific characters in http request.

- [https://github.com/JamesGeeee/CVE-2021-20698](https://github.com/JamesGeeee/CVE-2021-20698) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-20698.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-20698.svg)


## CVE-2021-20517
 IBM WebSphere Application Server Network Deployment 8.5 and 9.0 could allow a remote authenticated attacker to traverse directories. An attacker could send a specially-crafted URL request containing &quot;dot dot&quot; sequences (/../) to read and delete arbitrary files on the system. IBM X-Force ID: 198435.

- [https://github.com/JamesGeeee/CVE-2021-20517](https://github.com/JamesGeeee/CVE-2021-20517) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-20517.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-20517.svg)


## CVE-2021-20371
 IBM Jazz Foundation and IBM Engineering products could allow a remote attacker to obtain sensitive information when an error message is returned in the browser. This information could be used in further attacks against the system. IBM X-Force ID: 195516.

- [https://github.com/JamesGeeee/CVE-2021-20371](https://github.com/JamesGeeee/CVE-2021-20371) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-20371.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-20371.svg)


## CVE-2021-20348
 IBM Jazz Foundation and IBM Engineering products are vulnerable to server-side request forgery (SSRF). This may allow an authenticated attacker to send unauthorized requests from the system, potentially leading to network enumeration or facilitating other attacks. IBM X-ForceID: 194597.

- [https://github.com/JamesGeeee/CVE-2021-20348](https://github.com/JamesGeeee/CVE-2021-20348) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-20348.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-20348.svg)


## CVE-2021-20347
 IBM Jazz Foundation and IBM Engineering products are vulnerable to server-side request forgery (SSRF). This may allow an authenticated attacker to send unauthorized requests from the system, potentially leading to network enumeration or facilitating other attacks. IBM X-Force ID: 194596.

- [https://github.com/JamesGeeee/CVE-2021-20347](https://github.com/JamesGeeee/CVE-2021-20347) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-20347.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-20347.svg)


## CVE-2021-20346
 IBM Jazz Foundation and IBM Engineering products are vulnerable to server-side request forgery (SSRF). This may allow an authenticated attacker to send unauthorized requests from the system, potentially leading to network enumeration or facilitating other attacks. IBM X-Force ID: 194595.

- [https://github.com/JamesGeeee/CVE-2021-20346](https://github.com/JamesGeeee/CVE-2021-20346) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-20346.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-20346.svg)


## CVE-2021-20345
 IBM Jazz Foundation and IBM Engineering products are vulnerable to server-side request forgery (SSRF). This may allow an authenticated attacker to send unauthorized requests from the system, potentially leading to network enumeration or facilitating other attacks. IBM X-Force ID: 194594.

- [https://github.com/JamesGeeee/CVE-2021-20345](https://github.com/JamesGeeee/CVE-2021-20345) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-20345.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-20345.svg)


## CVE-2021-20343
 IBM Jazz Foundation and IBM Engineering products are vulnerable to server-side request forgery (SSRF). This may allow an authenticated attacker to send unauthorized requests from the system, potentially leading to network enumeration or facilitating other attacks. IBM X-Force ID: 194593.

- [https://github.com/JamesGeeee/CVE-2021-20343](https://github.com/JamesGeeee/CVE-2021-20343) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-20343.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-20343.svg)


## CVE-2021-20338
 IBM Jazz Foundation and IBM Engineering products are vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 194449.

- [https://github.com/JamesGeeee/CVE-2021-20338](https://github.com/JamesGeeee/CVE-2021-20338) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-20338.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-20338.svg)


## CVE-2021-20259
 A flaw was found in the Foreman project. The Proxmox compute resource exposes the password through the API to an authenticated local attacker with view_hosts permission. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability. Versions before foreman_fog_proxmox 0.13.1 are affected

- [https://github.com/JamesGeeee/CVE-2021-20259](https://github.com/JamesGeeee/CVE-2021-20259) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-20259.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-20259.svg)


## CVE-2021-3572
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/frenzymadness/CVE-2021-3572](https://github.com/frenzymadness/CVE-2021-3572) :  ![starts](https://img.shields.io/github/stars/frenzymadness/CVE-2021-3572.svg) ![forks](https://img.shields.io/github/forks/frenzymadness/CVE-2021-3572.svg)


## CVE-2021-3277
 Nagios XI 5.7.5 and earlier allows authenticated admins to upload arbitrary files due to improper validation of the rename functionality in custom-includes component, which leads to remote code execution by uploading php files.

- [https://github.com/JamesGeeee/CVE-2021-3277](https://github.com/JamesGeeee/CVE-2021-3277) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-3277.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-3277.svg)


## CVE-2021-1498
 Multiple vulnerabilities in the web-based management interface of Cisco HyperFlex HX could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device. For more information about these vulnerabilities, see the Details section of this advisory.

- [https://github.com/JamesGeeee/CVE-2021-1498](https://github.com/JamesGeeee/CVE-2021-1498) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-1498.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-1498.svg)


## CVE-2021-1497
 Multiple vulnerabilities in the web-based management interface of Cisco HyperFlex HX could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device. For more information about these vulnerabilities, see the Details section of this advisory.

- [https://github.com/JamesGeeee/CVE-2021-1497](https://github.com/JamesGeeee/CVE-2021-1497) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2021-1497.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2021-1497.svg)


## CVE-2020-36387
 An issue was discovered in the Linux kernel before 5.8.2. fs/io_uring.c has a use-after-free related to io_async_task_func and ctx reference holding, aka CID-6d816e088c35.

- [https://github.com/JamesGeeee/CVE-2020-36387](https://github.com/JamesGeeee/CVE-2020-36387) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-36387.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-36387.svg)


## CVE-2020-36386
 An issue was discovered in the Linux kernel before 5.8.1. net/bluetooth/hci_event.c has a slab out-of-bounds read in hci_extended_inquiry_result_evt, aka CID-51c19bf3d5cf.

- [https://github.com/JamesGeeee/CVE-2020-36386](https://github.com/JamesGeeee/CVE-2020-36386) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-36386.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-36386.svg)


## CVE-2020-36385
 An issue was discovered in the Linux kernel before 5.10. drivers/infiniband/core/ucma.c has a use-after-free because the ctx is reached via the ctx_list in some ucma_migrate_id situations where ucma_close is called, aka CID-f5449e74802c.

- [https://github.com/JamesGeeee/CVE-2020-36385](https://github.com/JamesGeeee/CVE-2020-36385) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-36385.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-36385.svg)


## CVE-2020-36313
 An issue was discovered in the Linux kernel before 5.7. The KVM subsystem allows out-of-range access to memslots after a deletion, aka CID-0774a964ef56. This affects arch/s390/kvm/kvm-s390.c, include/linux/kvm_host.h, and virt/kvm/kvm_main.c.

- [https://github.com/JamesGeeee/CVE-2020-36313](https://github.com/JamesGeeee/CVE-2020-36313) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-36313.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-36313.svg)


## CVE-2020-36007
 AppCMS 2.0.101 in /admin/template/tpl_app.php has a cross site scripting attack vulnerability which allows the attacker to obtain sensitive information of other users.

- [https://github.com/JamesGeeee/CVE-2020-36007](https://github.com/JamesGeeee/CVE-2020-36007) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-36007.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-36007.svg)


## CVE-2020-28328
 SuiteCRM before 7.11.17 is vulnerable to remote code execution via the system settings Log File Name setting. In certain circumstances involving admin account takeover, logger_file_name can refer to an attacker-controlled .php file under the web root.

- [https://github.com/JamesGeeee/CVE-2020-28328](https://github.com/JamesGeeee/CVE-2020-28328) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-28328.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-28328.svg)


## CVE-2020-26142
 An issue was discovered in the kernel in OpenBSD 6.6. The WEP, WPA, WPA2, and WPA3 implementations treat fragmented frames as full frames. An adversary can abuse this to inject arbitrary network packets, independent of the network configuration.

- [https://github.com/JamesGeeee/CVE-2020-26142](https://github.com/JamesGeeee/CVE-2020-26142) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-26142.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-26142.svg)


## CVE-2020-25716
 A flaw was found in Cloudforms. A role-based privileges escalation flaw where export or import of administrator files is possible. An attacker with a specific group can perform actions restricted only to system administrator. This is the affect of an incomplete fix for CVE-2020-10783. The highest threat from this vulnerability is to data confidentiality and integrity. Versions before cfme 5.11.10.1 are affected

- [https://github.com/JamesGeeee/CVE-2020-25716](https://github.com/JamesGeeee/CVE-2020-25716) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-25716.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-25716.svg)


## CVE-2020-18268
 Open Redirect in Z-BlogPHP v1.5.2 and earlier allows remote attackers to obtain sensitive information via the &quot;redirect&quot; parameter in the component &quot;zb_system/cmd.php.&quot;

- [https://github.com/JamesGeeee/CVE-2020-18268](https://github.com/JamesGeeee/CVE-2020-18268) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-18268.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-18268.svg)


## CVE-2020-18265
 Cross Site Request Forgery (CSRF) in Simple-Log v1.6 allows remote attackers to gain privilege and execute arbitrary code via the component &quot;Simple-Log/admin/admin.php?act=act_add_member&quot;.

- [https://github.com/JamesGeeee/CVE-2020-18265](https://github.com/JamesGeeee/CVE-2020-18265) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-18265.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-18265.svg)


## CVE-2020-18264
 Cross Site Request Forgery (CSRF) in Simple-Log v1.6 allows remote attackers to gain privilege and execute arbitrary code via the component &quot;Simple-Log/admin/admin.php?act=act_edit_member&quot;.

- [https://github.com/JamesGeeee/CVE-2020-18264](https://github.com/JamesGeeee/CVE-2020-18264) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-18264.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-18264.svg)


## CVE-2020-17514
 Apache Fineract prior to 1.5.0 disables HTTPS hostname verification in ProcessorHelper in the configureClient method. Under typical deployments, a man in the middle attack could be successful.

- [https://github.com/JamesGeeee/CVE-2020-17514](https://github.com/JamesGeeee/CVE-2020-17514) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-17514.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-17514.svg)


## CVE-2020-15225
 django-filter is a generic system for filtering Django QuerySets based on user selections. In django-filter before version 2.4.0, automatically generated `NumberFilter` instances, whose value was later converted to an integer, were subject to potential DoS from maliciously input using exponential format with sufficiently large exponents. Version 2.4.0+ applies a `MaxValueValidator` with a a default `limit_value` of 1e50 to the form field used by `NumberFilter` instances. In addition, `NumberFilter` implements the new `get_max_validator()` which should return a configured validator instance to customise the limit, or else `None` to disable the additional validation. Users may manually apply an equivalent validator if they are not able to upgrade.

- [https://github.com/JamesGeeee/CVE-2020-15225](https://github.com/JamesGeeee/CVE-2020-15225) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-15225.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-15225.svg)


## CVE-2020-14329
 A data exposure flaw was found in Ansible Tower in versions before 3.7.2, where sensitive data can be exposed from the /api/v2/labels/ endpoint. This flaw allows users from other organizations in the system to retrieve any label from the organization and also disclose organization names. The highest threat from this vulnerability is to confidentiality.

- [https://github.com/JamesGeeee/CVE-2020-14329](https://github.com/JamesGeeee/CVE-2020-14329) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-14329.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-14329.svg)


## CVE-2020-14328
 A flaw was found in Ansible Tower in versions before 3.7.2. A Server Side Request Forgery flaw can be abused by supplying a URL which could lead to the server processing it connecting to internal services or exposing additional internal services and more particularly retrieving full details in case of error. The highest threat from this vulnerability is to data confidentiality.

- [https://github.com/JamesGeeee/CVE-2020-14328](https://github.com/JamesGeeee/CVE-2020-14328) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-14328.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-14328.svg)


## CVE-2020-14327
 A Server-side request forgery (SSRF) flaw was found in Ansible Tower in versions before 3.6.5 and before 3.7.2. Functionality on the Tower server is abused by supplying a URL that could lead to the server processing it. This flaw leads to the connection to internal services or the exposure of additional internal services by abusing the test feature of lookup credentials to forge HTTP/HTTPS requests from the server and retrieving the results of the response.

- [https://github.com/JamesGeeee/CVE-2020-14327](https://github.com/JamesGeeee/CVE-2020-14327) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-14327.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-14327.svg)


## CVE-2020-10729
 A flaw was found in the use of insufficiently random values in Ansible. Two random password lookups of the same length generate the equal value as the template caching action for the same file since no re-evaluation happens. The highest threat from this vulnerability would be that all passwords are exposed at once for the file. This flaw affects Ansible Engine versions before 2.9.6.

- [https://github.com/JamesGeeee/CVE-2020-10729](https://github.com/JamesGeeee/CVE-2020-10729) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-10729.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-10729.svg)


## CVE-2020-10698
 A flaw was found in Ansible Tower when running jobs. This flaw allows an attacker to access the stdout of the executed jobs which are run from other organizations. Some sensible data can be disclosed. However, critical data should not be disclosed, as it should be protected by the no_log flag when debugging is enabled. This flaw affects Ansible Tower versions before 3.6.4, Ansible Tower versions before 3.5.6 and Ansible Tower versions before 3.4.6.

- [https://github.com/JamesGeeee/CVE-2020-10698](https://github.com/JamesGeeee/CVE-2020-10698) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-10698.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-10698.svg)


## CVE-2020-5030
 IBM Jazz Foundation and IBM Engineering products are vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 193737.

- [https://github.com/JamesGeeee/CVE-2020-5030](https://github.com/JamesGeeee/CVE-2020-5030) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-5030.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-5030.svg)


## CVE-2020-5008
 IBM DataPower Gateway 10.0.0.0 through 10.0.1.0 and 2018.4.1.0 through 2018.4.1.14 stores sensitive information in GET request parameters. This may lead to information disclosure if unauthorized parties have access to the URLs via server logs, referrer header or browser history. IBM X-Force ID: 193033.

- [https://github.com/JamesGeeee/CVE-2020-5008](https://github.com/JamesGeeee/CVE-2020-5008) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-5008.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-5008.svg)


## CVE-2020-4977
 IBM Engineering Lifecycle Optimization - Publishing is vulnerable to stored cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 192470.

- [https://github.com/JamesGeeee/CVE-2020-4977](https://github.com/JamesGeeee/CVE-2020-4977) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-4977.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-4977.svg)


## CVE-2020-4732
 IBM Jazz Foundation and IBM Engineering products could allow an authenticated user to obtain sensitive information due to lack of security restrictions. IBM X-Force ID: 188126.

- [https://github.com/JamesGeeee/CVE-2020-4732](https://github.com/JamesGeeee/CVE-2020-4732) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-4732.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-4732.svg)


## CVE-2020-4495
 IBM Jazz Foundation and IBM Engineering products could allow a remote attacker to bypass security restrictions, caused by improper access control. By sending a specially-crafted request to the REST API, an attacker could exploit this vulnerability to bypass access restrictions, and execute arbitrary actions with administrative privileges. IBM X-Force ID: 182114.

- [https://github.com/JamesGeeee/CVE-2020-4495](https://github.com/JamesGeeee/CVE-2020-4495) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-4495.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-4495.svg)


## CVE-2020-1750
 A flaw was found in the machine-config-operator that causes an OpenShift node to become unresponsive when a container consumes a large amount of memory. An attacker could use this flaw to deny access to schedule new pods in the OpenShift cluster. This was fixed in openshift/machine-config-operator 4.4.3, openshift/machine-config-operator 4.3.25, openshift/machine-config-operator 4.2.36.

- [https://github.com/JamesGeeee/CVE-2020-1750](https://github.com/JamesGeeee/CVE-2020-1750) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-1750.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-1750.svg)


## CVE-2020-1742
 An insecure modification vulnerability flaw was found in containers using nmstate/kubernetes-nmstate-handler. An attacker with access to the container could use this flaw to modify /etc/passwd and escalate their privileges. Versions before kubernetes-nmstate-handler-container-v2.3.0-30 are affected.

- [https://github.com/JamesGeeee/CVE-2020-1742](https://github.com/JamesGeeee/CVE-2020-1742) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-1742.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-1742.svg)


## CVE-2020-1719
 A flaw was found in wildfly. The EJBContext principle is not popped back after invoking another EJB using a different Security Domain. The highest threat from this vulnerability is to data confidentiality and integrity. Versions before wildfly 20.0.0.Final are affected.

- [https://github.com/JamesGeeee/CVE-2020-1719](https://github.com/JamesGeeee/CVE-2020-1719) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-1719.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-1719.svg)


## CVE-2020-1690
 An improper authorization flaw was discovered in openstack-selinux's applied policy where it does not prevent a non-root user in a container from privilege escalation. A non-root attacker in one or more Red Hat OpenStack (RHOSP) containers could send messages to the dbus. With access to the dbus, the attacker could start or stop services, possibly causing a denial of service. Versions before openstack-selinux 0.8.24 are affected.

- [https://github.com/JamesGeeee/CVE-2020-1690](https://github.com/JamesGeeee/CVE-2020-1690) :  ![starts](https://img.shields.io/github/stars/JamesGeeee/CVE-2020-1690.svg) ![forks](https://img.shields.io/github/forks/JamesGeeee/CVE-2020-1690.svg)


## CVE-2020-0041
 In binder_transaction of binder.c, there is a possible out of bounds write due to an incorrect bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-145988638References: Upstream kernel

- [https://github.com/Byte-Master-101/CVE_2020_0041](https://github.com/Byte-Master-101/CVE_2020_0041) :  ![starts](https://img.shields.io/github/stars/Byte-Master-101/CVE_2020_0041.svg) ![forks](https://img.shields.io/github/forks/Byte-Master-101/CVE_2020_0041.svg)


## CVE-2019-17240
 bl-kernel/security.class.php in Bludit 3.9.2 allows attackers to bypass a brute-force protection mechanism by using many different forged X-Forwarded-For or Client-IP HTTP headers.

- [https://github.com/brusergio/bloodit](https://github.com/brusergio/bloodit) :  ![starts](https://img.shields.io/github/stars/brusergio/bloodit.svg) ![forks](https://img.shields.io/github/forks/brusergio/bloodit.svg)


## CVE-2019-1388
 An elevation of privilege vulnerability exists in the Windows Certificate Dialog when it does not properly enforce user privileges, aka 'Windows Certificate Dialog Elevation of Privilege Vulnerability'.

- [https://github.com/suprise4u/CVE-2019-1388](https://github.com/suprise4u/CVE-2019-1388) :  ![starts](https://img.shields.io/github/stars/suprise4u/CVE-2019-1388.svg) ![forks](https://img.shields.io/github/forks/suprise4u/CVE-2019-1388.svg)


## CVE-2018-0114
 A vulnerability in the Cisco node-jose open source library before 0.11.0 could allow an unauthenticated, remote attacker to re-sign tokens using a key that is embedded within the token. The vulnerability is due to node-jose following the JSON Web Signature (JWS) standard for JSON Web Tokens (JWTs). This standard specifies that a JSON Web Key (JWK) representing a public key can be embedded within the header of a JWS. This public key is then trusted for verification. An attacker could exploit this by forging valid JWS objects by removing the original signature, adding a new public key to the header, and then signing the object using the (attacker-owned) private key associated with the public key embedded in that JWS header.

- [https://github.com/adityathebe/POC-CVE-2018-0114](https://github.com/adityathebe/POC-CVE-2018-0114) :  ![starts](https://img.shields.io/github/stars/adityathebe/POC-CVE-2018-0114.svg) ![forks](https://img.shields.io/github/forks/adityathebe/POC-CVE-2018-0114.svg)
- [https://github.com/Logeirs/CVE-2018-0114](https://github.com/Logeirs/CVE-2018-0114) :  ![starts](https://img.shields.io/github/stars/Logeirs/CVE-2018-0114.svg) ![forks](https://img.shields.io/github/forks/Logeirs/CVE-2018-0114.svg)


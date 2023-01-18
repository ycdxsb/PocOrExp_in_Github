# Update 2023-01-18
## CVE-2023-0327
 A vulnerability was found in saemorris TheRadSystem. It has been classified as problematic. Affected is an unknown function of the file users.php. The manipulation of the argument q leads to cross site scripting. It is possible to launch the attack remotely. VDB-218454 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0327](https://github.com/Live-Hack-CVE/CVE-2023-0327) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0327.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0327.svg)


## CVE-2023-0316
 Path Traversal: '\..\filename' in GitHub repository froxlor/froxlor prior to 2.0.0.

- [https://github.com/Live-Hack-CVE/CVE-2023-0316](https://github.com/Live-Hack-CVE/CVE-2023-0316) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0316.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0316.svg)


## CVE-2023-0315
 Command Injection in GitHub repository froxlor/froxlor prior to 2.0.8.

- [https://github.com/Live-Hack-CVE/CVE-2023-0315](https://github.com/Live-Hack-CVE/CVE-2023-0315) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0315.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0315.svg)


## CVE-2022-47630
 Trusted Firmware-A through 2.8 has an out-of-bounds read in the X.509 parser for parsing boot certificates. This affects downstream use of get_ext and auth_nvctr. Attackers might be able to trigger dangerous read side effects or obtain sensitive information about microarchitectural state.

- [https://github.com/Live-Hack-CVE/CVE-2022-47630](https://github.com/Live-Hack-CVE/CVE-2022-47630) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47630.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47630.svg)


## CVE-2022-46463
 An access control issue in Harbor v1.X.X to v2.5.3 allows attackers to access public and private image repositories without authentication.

- [https://github.com/peiqiF4ck/AttackWebFrameworkTools-5.1-main](https://github.com/peiqiF4ck/AttackWebFrameworkTools-5.1-main) :  ![starts](https://img.shields.io/github/stars/peiqiF4ck/AttackWebFrameworkTools-5.1-main.svg) ![forks](https://img.shields.io/github/forks/peiqiF4ck/AttackWebFrameworkTools-5.1-main.svg)


## CVE-2022-46169
 Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: &lt;TARGETIP&gt;`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

- [https://github.com/N1arut/CVE-2022-46169_POC](https://github.com/N1arut/CVE-2022-46169_POC) :  ![starts](https://img.shields.io/github/stars/N1arut/CVE-2022-46169_POC.svg) ![forks](https://img.shields.io/github/forks/N1arut/CVE-2022-46169_POC.svg)


## CVE-2022-45440
 A vulnerability exists in the FTP server of the Zyxel AX7501-B0 firmware prior to V5.17(ABPC.3)C0, which processes symbolic links on external storage media. A local authenticated attacker with administrator privileges could abuse this vulnerability to access the root file system by creating a symbolic link on external storage media, such as a USB flash drive, and then logging into the FTP server on a vulnerable device.

- [https://github.com/Live-Hack-CVE/CVE-2022-45440](https://github.com/Live-Hack-CVE/CVE-2022-45440) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45440.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45440.svg)


## CVE-2022-45439
 A pair of spare WiFi credentials is stored in the configuration file of the Zyxel AX7501-B0 firmware prior to V5.17(ABPC.3)C0 in cleartext. An unauthenticated attacker could use the credentials to access the WLAN service if the configuration file has been retrieved from the device by leveraging another known vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-45439](https://github.com/Live-Hack-CVE/CVE-2022-45439) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45439.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45439.svg)


## CVE-2022-45438
 When explicitly enabling the feature flag DASHBOARD_CACHE (disabled by default), the system allowed for an unauthenticated user to access dashboard configuration metadata using a REST API Get endpoint. This issue affects Apache Superset version 1.5.2 and prior versions and version 2.0.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-45438](https://github.com/Live-Hack-CVE/CVE-2022-45438) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45438.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45438.svg)


## CVE-2022-43721
 An authenticated attacker with update datasets permission could change a dataset link to an untrusted site, users could be redirected to this site when clicking on that specific dataset. This issue affects Apache Superset version 1.5.2 and prior versions and version 2.0.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-43721](https://github.com/Live-Hack-CVE/CVE-2022-43721) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43721.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43721.svg)


## CVE-2022-43720
 An authenticated attacker with write CSS template permissions can create a record with specific HTML tags that will not get properly escaped by the toast message displayed when a user deletes that specific CSS template record. This issue affects Apache Superset version 1.5.2 and prior versions and version 2.0.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-43720](https://github.com/Live-Hack-CVE/CVE-2022-43720) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43720.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43720.svg)


## CVE-2022-43719
 Two legacy REST API endpoints for approval and request access are vulnerable to cross site request forgery. This issue affects Apache Superset version 1.5.2 and prior versions and version 2.0.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-43719](https://github.com/Live-Hack-CVE/CVE-2022-43719) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43719.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43719.svg)


## CVE-2022-43718
 Upload data forms do not correctly render user input leading to possible XSS attack vectors that can be performed by authenticated users with database connection update permissions. This issue affects Apache Superset version 1.5.2 and prior versions and version 2.0.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-43718](https://github.com/Live-Hack-CVE/CVE-2022-43718) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43718.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43718.svg)


## CVE-2022-43717
 Dashboard rendering does not sufficiently sanitize the content of markdown components leading to possible XSS attack vectors that can be performed by authenticated users with create dashboard permissions. This issue affects Apache Superset version 1.5.2 and prior versions and version 2.0.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-43717](https://github.com/Live-Hack-CVE/CVE-2022-43717) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43717.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43717.svg)


## CVE-2022-43462
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-43462](https://github.com/Live-Hack-CVE/CVE-2022-43462) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43462.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43462.svg)


## CVE-2022-42462
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-42462](https://github.com/Live-Hack-CVE/CVE-2022-42462) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42462.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42462.svg)


## CVE-2022-41703
 A vulnerability in the SQL Alchemy connector of Apache Superset allows an authenticated user with read access to a specific database to add subqueries to the WHERE and HAVING fields referencing tables on the same database that the user should not have access to, despite the user having the feature flag &quot;ALLOW_ADHOC_SUBQUERY&quot; disabled (default value). This issue affects Apache Superset version 1.5.2 and prior versions and version 2.0.0.

- [https://github.com/Live-Hack-CVE/CVE-2022-41703](https://github.com/Live-Hack-CVE/CVE-2022-41703) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41703.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41703.svg)


## CVE-2022-34169
 The Apache Xalan Java XSLT library is vulnerable to an integer truncation issue when processing malicious XSLT stylesheets. This can be used to corrupt Java class files generated by the internal XSLTC compiler and execute arbitrary Java bytecode. The Apache Xalan Java project is dormant and in the process of being retired. No future releases of Apache Xalan Java to address this issue are expected. Note: Java runtimes (such as OpenJDK) include repackaged copies of Xalan.

- [https://github.com/flowerwind/AutoGenerateXalanPayload](https://github.com/flowerwind/AutoGenerateXalanPayload) :  ![starts](https://img.shields.io/github/stars/flowerwind/AutoGenerateXalanPayload.svg) ![forks](https://img.shields.io/github/forks/flowerwind/AutoGenerateXalanPayload.svg)


## CVE-2022-30773
 DMA attacks on the parameter buffer used by the IhisiSmm driver could change the contents after parameter values have been checked but before they are used (a TOCTOU attack). DMA attacks on the parameter buffer used by the IhisiSmm driver could change the contents after parameter values have been checked but before they are used (a TOCTOU attack). This issue was discovered by Insyde engineering. This issue is fixed in Kernel 5.4: 05.44.23 and Kernel 5.5: 05.52.23. CWE-367

- [https://github.com/Live-Hack-CVE/CVE-2022-30773](https://github.com/Live-Hack-CVE/CVE-2022-30773) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-30773.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-30773.svg)


## CVE-2022-27499
 Premature release of resource during expected lifetime in the Intel(R) SGX SDK software may allow a privileged user to potentially enable information disclosure via local access.

- [https://github.com/StanPlatinum/snapshot-demo](https://github.com/StanPlatinum/snapshot-demo) :  ![starts](https://img.shields.io/github/stars/StanPlatinum/snapshot-demo.svg) ![forks](https://img.shields.io/github/forks/StanPlatinum/snapshot-demo.svg)


## CVE-2022-22963
 In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

- [https://github.com/iliass-dahman/CVE-2022-22963-POC](https://github.com/iliass-dahman/CVE-2022-22963-POC) :  ![starts](https://img.shields.io/github/stars/iliass-dahman/CVE-2022-22963-POC.svg) ![forks](https://img.shields.io/github/forks/iliass-dahman/CVE-2022-22963-POC.svg)


## CVE-2022-4658
 The RSSImport WordPress plugin through 4.6.1 does not validate and escape one of its shortcode attributes, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attack.

- [https://github.com/Live-Hack-CVE/CVE-2022-4658](https://github.com/Live-Hack-CVE/CVE-2022-4658) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4658.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4658.svg)


## CVE-2022-4655
 The Welcart e-Commerce WordPress plugin before 2.8.9 does not validate and escapes one of its shortcode attributes, which could allow users with a role as low as a contributor to perform a Stored Cross-Site Scripting attack.

- [https://github.com/Live-Hack-CVE/CVE-2022-4655](https://github.com/Live-Hack-CVE/CVE-2022-4655) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4655.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4655.svg)


## CVE-2022-4653
 The Greenshift WordPress plugin before 4.8.9 does not validate and escape one of its shortcode attributes, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attack.

- [https://github.com/Live-Hack-CVE/CVE-2022-4653](https://github.com/Live-Hack-CVE/CVE-2022-4653) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4653.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4653.svg)


## CVE-2022-4648
 The Real Testimonials WordPress plugin before 2.6.0 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4648](https://github.com/Live-Hack-CVE/CVE-2022-4648) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4648.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4648.svg)


## CVE-2022-4578
 The Video Conferencing with Zoom WordPress plugin before 4.0.10 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4578](https://github.com/Live-Hack-CVE/CVE-2022-4578) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4578.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4578.svg)


## CVE-2022-4571
 The Seriously Simple Podcasting WordPress plugin before 2.19.1 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4571](https://github.com/Live-Hack-CVE/CVE-2022-4571) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4571.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4571.svg)


## CVE-2022-4549
 The Tickera WordPress plugin before 3.5.1.0 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged-in admin change them via a CSRF attack.

- [https://github.com/Live-Hack-CVE/CVE-2022-4549](https://github.com/Live-Hack-CVE/CVE-2022-4549) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4549.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4549.svg)


## CVE-2022-4547
 The Conditional Payment Methods for WooCommerce WordPress plugin through 1.0 does not properly sanitise and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by [high privilege users such as admin|users with a role as low as admin.

- [https://github.com/Live-Hack-CVE/CVE-2022-4547](https://github.com/Live-Hack-CVE/CVE-2022-4547) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4547.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4547.svg)


## CVE-2022-4544
 The MashShare WordPress plugin before 3.8.7 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4544](https://github.com/Live-Hack-CVE/CVE-2022-4544) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4544.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4544.svg)


## CVE-2022-4508
 The ConvertKit WordPress plugin before 2.0.5 does not validate and escapes some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as a contributor to perform Stored Cross-Site Scripting attacks, which could be used against high-privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4508](https://github.com/Live-Hack-CVE/CVE-2022-4508) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4508.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4508.svg)


## CVE-2022-4507
 The Real Cookie Banner WordPress plugin before 3.4.10 does not validate and escapes some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as a contributor to perform Stored Cross-Site Scripting attacks against logged-in admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4507](https://github.com/Live-Hack-CVE/CVE-2022-4507) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4507.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4507.svg)


## CVE-2022-4487
 The Easy Accordion WordPress plugin before 2.2.0 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4487](https://github.com/Live-Hack-CVE/CVE-2022-4487) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4487.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4487.svg)


## CVE-2022-4486
 The Meteor Slides WordPress plugin through 1.5.6 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4486](https://github.com/Live-Hack-CVE/CVE-2022-4486) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4486.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4486.svg)


## CVE-2022-4484
 The Social Share, Social Login and Social Comments Plugin WordPress plugin before 7.13.44 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4484](https://github.com/Live-Hack-CVE/CVE-2022-4484) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4484.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4484.svg)


## CVE-2022-4483
 The Insert Pages WordPress plugin before 3.7.5 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4483](https://github.com/Live-Hack-CVE/CVE-2022-4483) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4483.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4483.svg)


## CVE-2022-4482
 The Carousel, Slider, Gallery by WP Carousel WordPress plugin before 2.5.3 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4482](https://github.com/Live-Hack-CVE/CVE-2022-4482) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4482.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4482.svg)


## CVE-2022-4481
 The Mesmerize Companion WordPress plugin before 1.6.135 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4481](https://github.com/Live-Hack-CVE/CVE-2022-4481) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4481.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4481.svg)


## CVE-2022-4480
 The Click to Chat WordPress plugin before 3.18.1 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4480](https://github.com/Live-Hack-CVE/CVE-2022-4480) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4480.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4480.svg)


## CVE-2022-4478
 The Font Awesome WordPress plugin before 4.3.2 does not validate and escapes some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as a contributor to perform Stored Cross-Site Scripting attacks against logged-in admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4478](https://github.com/Live-Hack-CVE/CVE-2022-4478) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4478.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4478.svg)


## CVE-2022-4477
 The Smash Balloon Social Post Feed WordPress plugin before 4.1.6 does not validate and escapes some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as a contributor to perform Stored Cross-Site Scripting attacks against logged-in admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4477](https://github.com/Live-Hack-CVE/CVE-2022-4477) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4477.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4477.svg)


## CVE-2022-4476
 The Download Manager WordPress plugin before 3.2.62 does not validate and escapes some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as a contributor to perform Stored Cross-Site Scripting attacks against logged-in admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4476](https://github.com/Live-Hack-CVE/CVE-2022-4476) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4476.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4476.svg)


## CVE-2022-4469
 The Simple Membership WordPress plugin before 4.2.2 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admin.

- [https://github.com/Live-Hack-CVE/CVE-2022-4469](https://github.com/Live-Hack-CVE/CVE-2022-4469) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4469.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4469.svg)


## CVE-2022-4464
 Themify Portfolio Post WordPress plugin before 1.2.1 does not validate and escapes some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as a contributor to perform Stored Cross-Site Scripting attacks, which could be used against high privileged users such as admin.

- [https://github.com/Live-Hack-CVE/CVE-2022-4464](https://github.com/Live-Hack-CVE/CVE-2022-4464) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4464.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4464.svg)


## CVE-2022-4453
 The 3D FlipBook WordPress plugin through 1.13.2 does not validate or escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as Contributor to perform Stored Cross-Site Scripting attacks against high privilege users like administrators.

- [https://github.com/Live-Hack-CVE/CVE-2022-4453](https://github.com/Live-Hack-CVE/CVE-2022-4453) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4453.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4453.svg)


## CVE-2022-4258
 In multiple versions of HIMA PC based Software an unquoted Windows search path vulnerability might allow local users to gain privileges via a malicious .exe file and gain full access to the system.

- [https://github.com/Live-Hack-CVE/CVE-2022-4258](https://github.com/Live-Hack-CVE/CVE-2022-4258) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4258.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4258.svg)


## CVE-2022-4167
 Incorrect Authorization check affecting all versions of GitLab EE from 13.11 prior to 15.5.7, 15.6 prior to 15.6.4, and 15.7 prior to 15.7.2 allows group access tokens to continue working even after the group owner loses the ability to revoke them.

- [https://github.com/Live-Hack-CVE/CVE-2022-4167](https://github.com/Live-Hack-CVE/CVE-2022-4167) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4167.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4167.svg)


## CVE-2022-3904
 The MonsterInsights WordPress plugin before 8.9.1 does not sanitize or escape page titles in the top posts/pages section, allowing an unauthenticated attacker to inject arbitrary web scripts into the titles by spoofing requests to google analytics.

- [https://github.com/Live-Hack-CVE/CVE-2022-3904](https://github.com/Live-Hack-CVE/CVE-2022-3904) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3904.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3904.svg)


## CVE-2022-3677
 The Advanced Import WordPress plugin before 1.3.8 does not have CSRF check when installing and activating plugins, which could allow attackers to make a logged in admin install arbitrary plugins from WordPress.org, and activate arbitrary ones from the blog via CSRF attacks

- [https://github.com/Live-Hack-CVE/CVE-2022-3677](https://github.com/Live-Hack-CVE/CVE-2022-3677) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3677.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3677.svg)


## CVE-2022-3480
 A remote, unauthenticated attacker could cause a denial-of-service of PHOENIX CONTACT FL MGUARD and TC MGUARD devices below version 8.9.0 by sending a larger number of unauthenticated HTTPS connections originating from different source IP&#8217;s. Configuring firewall limits for incoming connections cannot prevent the issue.

- [https://github.com/Live-Hack-CVE/CVE-2022-3480](https://github.com/Live-Hack-CVE/CVE-2022-3480) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3480.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3480.svg)


## CVE-2022-3087
 Fuji Electric Tellus Lite V-Simulator versions 4.0.12.0 and prior are vulnerable to an out-of-bounds write which may allow an attacker to execute arbitrary code.

- [https://github.com/Live-Hack-CVE/CVE-2022-3087](https://github.com/Live-Hack-CVE/CVE-2022-3087) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3087.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3087.svg)


## CVE-2021-4313
 A vulnerability was found in NethServer phonenehome. It has been rated as critical. This issue affects the function get_info/get_country_coor of the file server/index.php. The manipulation leads to sql injection. The name of the patch is 759c30b0ddd7d493836bbdf695cf71624b377391. It is recommended to apply a patch to fix this issue. The identifier VDB-218393 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2021-4313](https://github.com/Live-Hack-CVE/CVE-2021-4313) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4313.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4313.svg)


## CVE-2021-3481
 A flaw was found in Qt. An out-of-bounds read vulnerability was found in QRadialFetchSimd in qt/qtbase/src/gui/painting/qdrawhelper_p.h in Qt/Qtbase. While rendering and displaying a crafted Scalable Vector Graphics (SVG) file this flaw may lead to an unauthorized memory access. The highest threat from this vulnerability is to data confidentiality and the application availability.

- [https://github.com/Live-Hack-CVE/CVE-2021-3481](https://github.com/Live-Hack-CVE/CVE-2021-3481) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3481.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3481.svg)


## CVE-2020-36611
 Incorrect Default Permissions vulnerability in Hitachi Tuning Manager on Linux (Hitachi Tuning Manager server, Hitachi Tuning Manager - Agent for RAID, Hitachi Tuning Manager - Agent for NAS, Hitachi Tuning Manager - Agent for SAN Switch components) allows local users to read and write specific files.This issue affects Hitachi Tuning Manager: before 8.8.5-00.

- [https://github.com/Live-Hack-CVE/CVE-2020-36611](https://github.com/Live-Hack-CVE/CVE-2020-36611) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36611.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36611.svg)


## CVE-2020-28478
 This affects the package gsap before 3.6.0.

- [https://github.com/NetJBS/CVE-2020-28478--PoC](https://github.com/NetJBS/CVE-2020-28478--PoC) :  ![starts](https://img.shields.io/github/stars/NetJBS/CVE-2020-28478--PoC.svg) ![forks](https://img.shields.io/github/forks/NetJBS/CVE-2020-28478--PoC.svg)


## CVE-2017-20170
 A vulnerability was found in ollpu parontalli. It has been classified as critical. Affected is an unknown function of the file httpdocs/index.php. The manipulation of the argument s leads to sql injection. The name of the patch is 6891bb2dec57dca6daabc15a6d2808c8896620e5. It is recommended to apply a patch to fix this issue. VDB-218418 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2017-20170](https://github.com/Live-Hack-CVE/CVE-2017-20170) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-20170.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-20170.svg)


## CVE-2017-8917
 SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers to execute arbitrary SQL commands via unspecified vectors.

- [https://github.com/xeno-john/joomla_CVE-2017-8917](https://github.com/xeno-john/joomla_CVE-2017-8917) :  ![starts](https://img.shields.io/github/stars/xeno-john/joomla_CVE-2017-8917.svg) ![forks](https://img.shields.io/github/forks/xeno-john/joomla_CVE-2017-8917.svg)


## CVE-2017-0055
 Microsoft Internet Information Server (IIS) in Windows Vista SP2; Windows Server 2008 SP2 and R2; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to perform cross-site scripting and run script with local user privileges via a crafted request, aka &quot;Microsoft IIS Server XSS Elevation of Privilege Vulnerability.&quot;

- [https://github.com/NetJBS/CVE-2017-0055-PoC](https://github.com/NetJBS/CVE-2017-0055-PoC) :  ![starts](https://img.shields.io/github/stars/NetJBS/CVE-2017-0055-PoC.svg) ![forks](https://img.shields.io/github/forks/NetJBS/CVE-2017-0055-PoC.svg)


## CVE-2016-15021
 A vulnerability was found in nickzren alsdb. It has been rated as critical. This issue affects some unknown processing. The manipulation leads to sql injection. Upgrading to version v2 is able to address this issue. The name of the patch is cbc79a68145e845f951113d184b4de207c341599. It is recommended to upgrade the affected component. The identifier VDB-218429 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2016-15021](https://github.com/Live-Hack-CVE/CVE-2016-15021) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2016-15021.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2016-15021.svg)


## CVE-2015-10061
 A vulnerability was found in evandro-machado Trabalho-Web2. It has been classified as critical. This affects an unknown part of the file src/java/br/com/magazine/dao/ClienteDAO.java. The manipulation leads to sql injection. The name of the patch is f59ac954625d0a4f6d34f069a2e26686a7a20aeb. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-218427.

- [https://github.com/Live-Hack-CVE/CVE-2015-10061](https://github.com/Live-Hack-CVE/CVE-2015-10061) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10061.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10061.svg)


## CVE-2015-10057
 A vulnerability was found in Little Apps Little Software Stats. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file inc/class.securelogin.php of the component Password Reset Handler. The manipulation leads to improper access controls. Upgrading to version 0.2 is able to address this issue. The name of the patch is 07ba8273a9311d1383f3686ac7cb32f20770ab1e. It is recommended to upgrade the affected component. The identifier VDB-218401 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2015-10057](https://github.com/Live-Hack-CVE/CVE-2015-10057) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10057.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10057.svg)


## CVE-2015-10056
 A vulnerability was found in 2071174A vinylmap. It has been classified as critical. Affected is the function contact of the file recordstoreapp/views.py. The manipulation leads to sql injection. The name of the patch is b07b79a1e92cc62574ba0492cce000ef4a7bd25f. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-218400.

- [https://github.com/Live-Hack-CVE/CVE-2015-10056](https://github.com/Live-Hack-CVE/CVE-2015-10056) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10056.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10056.svg)


## CVE-2015-10055
 A vulnerability was found in PictureThisWebServer and classified as critical. This issue affects the function router.post of the file routes/user.js. The manipulation of the argument username/password leads to sql injection. The name of the patch is 68b9dc346e88b494df00d88c7d058e96820e1479. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-218399.

- [https://github.com/Live-Hack-CVE/CVE-2015-10055](https://github.com/Live-Hack-CVE/CVE-2015-10055) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10055.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10055.svg)


## CVE-2015-10054
 A vulnerability, which was classified as critical, was found in githuis P2Manage. This affects the function Execute of the file PTwoManage/Database.cs. The manipulation of the argument sql leads to sql injection. The name of the patch is 717380aba80002414f82d93c770035198b7858cc. It is recommended to apply a patch to fix this issue. The identifier VDB-218397 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2015-10054](https://github.com/Live-Hack-CVE/CVE-2015-10054) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10054.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10054.svg)


## CVE-2014-5460
 Unrestricted file upload vulnerability in the Tribulant Slideshow Gallery plugin before 1.4.7 for WordPress allows remote authenticated users to execute arbitrary code by uploading a PHP file, then accessing it via a direct request to the file in wp-content/uploads/slideshow-gallery/.

- [https://github.com/brookeses69/CVE-2014-5460](https://github.com/brookeses69/CVE-2014-5460) :  ![starts](https://img.shields.io/github/stars/brookeses69/CVE-2014-5460.svg) ![forks](https://img.shields.io/github/forks/brookeses69/CVE-2014-5460.svg)


## CVE-2013-10013
 A vulnerability was found in Bricco Authenticator Plugin. It has been declared as critical. This vulnerability affects the function authenticate/compare of the file src/java/talentum/escenic/plugins/authenticator/authenticators/DBAuthenticator.java. The manipulation leads to sql injection. Upgrading to version 1.39 is able to address this issue. The name of the patch is a5456633ff75e8f13705974c7ed1ce77f3f142d5. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-218428.

- [https://github.com/Live-Hack-CVE/CVE-2013-10013](https://github.com/Live-Hack-CVE/CVE-2013-10013) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2013-10013.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2013-10013.svg)


## CVE-2010-10008
 ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability was found in simplesamlphp simplesamlphp-module-openidprovider up to 0.8.x. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the file templates/trust.tpl.php. The manipulation of the argument StateID leads to cross site scripting. The attack can be launched remotely. Upgrading to version 0.9.0 is able to address this issue. The name of the patch is 8365d48c863cf06ccf1465cc0a161cefae29d69d. It is recommended to upgrade the affected component. The identifier VDB-218473 was assigned to this vulnerability. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Live-Hack-CVE/CVE-2010-10008](https://github.com/Live-Hack-CVE/CVE-2010-10008) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2010-10008.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2010-10008.svg)


## CVE-2006-20001
 A carefully crafted If: request header can cause a memory read, or write of a single zero byte, in a pool (heap) memory location beyond the header value sent. This could cause the process to crash. This issue affects Apache HTTP Server 2.4.54 and earlier.

- [https://github.com/Live-Hack-CVE/CVE-2006-20001](https://github.com/Live-Hack-CVE/CVE-2006-20001) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2006-20001.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2006-20001.svg)


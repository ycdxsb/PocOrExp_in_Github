# Update 2023-01-29
## CVE-2023-24060
 Haven 5d15944 allows Server-Side Request Forgery (SSRF) via the feed[url]= Feeds functionality. Authenticated users with the ability to create new RSS Feeds or add RSS Feeds can supply an arbitrary hostname (or even the hostname of the Haven server itself). NOTE: this product has significant usage but does not have numbered releases; ordinary end users may typically use the master branch.

- [https://github.com/Live-Hack-CVE/CVE-2023-24060](https://github.com/Live-Hack-CVE/CVE-2023-24060) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24060.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24060.svg)


## CVE-2023-23627
 Sanitize is an allowlist-based HTML and CSS sanitizer. Versions 5.0.0 and later, prior to 6.0.1, are vulnerable to Cross-site Scripting. When Sanitize is configured with a custom allowlist that allows `noscript` elements, attackers are able to include arbitrary HTML, resulting in XSS (cross-site scripting) or other undesired behavior when that HTML is rendered in a browser. The default configurations do not allow `noscript` elements and are not vulnerable. This issue only affects users who are using a custom config that adds `noscript` to the element allowlist. This issue has been patched in version 6.0.1. Users who are unable to upgrade can prevent this issue by using one of Sanitize's default configs or by ensuring that their custom config does not include `noscript` in the element allowlist.

- [https://github.com/Live-Hack-CVE/CVE-2023-23627](https://github.com/Live-Hack-CVE/CVE-2023-23627) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23627.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23627.svg)


## CVE-2023-23624
 Discourse is an open-source discussion platform. Prior to version 3.0.1 on the `stable` branch and version 3.1.0.beta2 on the `beta` and `tests-passed` branches, someone can use the `exclude_tag param` to filter out topics and deduce which ones were using a specific hidden tag. This affects any Discourse site using hidden tags in public categories. This issue is patched in version 3.0.1 on the `stable` branch and version 3.1.0.beta2 on the `beta` and `tests-passed` branches. As a workaround, secure any categories that are using hidden tags, change any existing hidden tags to not include private data, or remove any hidden tags currently in use.

- [https://github.com/Live-Hack-CVE/CVE-2023-23624](https://github.com/Live-Hack-CVE/CVE-2023-23624) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23624.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23624.svg)


## CVE-2023-23621
 Discourse is an open-source discussion platform. Prior to version 3.0.1 on the `stable` branch and version 3.1.0.beta2 on the `beta` and `tests-passed` branches, a malicious user can cause a regular expression denial of service using a carefully crafted user agent. This issue is patched in version 3.0.1 on the `stable` branch and version 3.1.0.beta2 on the `beta` and `tests-passed` branches. There are no known workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2023-23621](https://github.com/Live-Hack-CVE/CVE-2023-23621) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23621.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23621.svg)


## CVE-2023-23620
 Discourse is an open-source discussion platform. Prior to version 3.0.1 on the `stable` branch and 3.1.0.beta2 on the `beta` and `tests-passed` branches, the contents of latest/top routes for restricted tags can be accessed by unauthorized users. This issue is patched in version 3.0.1 on the `stable` branch and 3.1.0.beta2 on the `beta` and `tests-passed` branches. There are no known workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2023-23620](https://github.com/Live-Hack-CVE/CVE-2023-23620) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23620.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23620.svg)


## CVE-2023-23617
 OpenMage LTS is an e-commerce platform. Versions prior to 19.4.22 and 20.0.19 contain an infinite loop in malicious code filter in certain conditions. Versions 19.4.22 and 20.0.19 have a fix for this issue. There are no known workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2023-23617](https://github.com/Live-Hack-CVE/CVE-2023-23617) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23617.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23617.svg)


## CVE-2023-23616
 Discourse is an open-source discussion platform. Prior to version 3.0.1 on the `stable` branch and 3.1.0.beta2 on the `beta` and `tests-passed` branches, when submitting a membership request, there is no character limit for the reason provided with the request. This could potentially allow a user to flood the database with a large amount of data. However it is unlikely this could be used as part of a DoS attack, as the paths reading back the reasons are only available to administrators. Starting in version 3.0.1 on the `stable` branch and 3.1.0.beta2 on the `beta` and `tests-passed` branches, a limit of 280 characters has been introduced for membership requests.

- [https://github.com/Live-Hack-CVE/CVE-2023-23616](https://github.com/Live-Hack-CVE/CVE-2023-23616) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23616.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23616.svg)


## CVE-2023-23492
 The Login with Phone Number WordPress Plugin, version &lt; 1.4.2, is affected by an authenticated SQL injection vulnerability in the 'ID' parameter of its 'lwp_forgot_password' action.

- [https://github.com/Live-Hack-CVE/CVE-2023-23492](https://github.com/Live-Hack-CVE/CVE-2023-23492) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23492.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23492.svg)


## CVE-2023-22740
 Discourse is an open source platform for community discussion. Versions prior to 3.1.0.beta1 (beta) (tests-passed) are vulnerable to Allocation of Resources Without Limits. Users can create chat drafts of an unlimited length, which can cause a denial of service by generating an excessive load on the server. Additionally, an unlimited number of drafts were loaded when loading the user. This issue has been patched in version 2.1.0.beta1 (beta) and (tests-passed). Users should upgrade to the latest version where a limit has been introduced. There are no workarounds available.

- [https://github.com/Live-Hack-CVE/CVE-2023-22740](https://github.com/Live-Hack-CVE/CVE-2023-22740) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22740.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22740.svg)


## CVE-2023-22737
 wire-server provides back end services for Wire, a team communication and collaboration platform. Prior to version 2022-12-09, every member of a Conversation can remove a Bot from a Conversation due to a missing permissions check. Only Conversation admins should be able to remove Bots. Regular Conversations are not allowed to do so. The issue is fixed in wire-server 2022-12-09 and is already deployed on all Wire managed services. On-premise instances of wire-server need to be updated to 2022-12-09/Chart 4.29.0, so that their backends are no longer affected. There are no known workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2023-22737](https://github.com/Live-Hack-CVE/CVE-2023-22737) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22737.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22737.svg)


## CVE-2023-0558
 The ContentStudio plugin for WordPress is vulnerable to authorization bypass due to an unsecure token check that is susceptible to type juggling in versions up to, and including, 1.2.5. This makes it possible for unauthenticated attackers to execute functions intended for use by users with proper API keys.

- [https://github.com/Live-Hack-CVE/CVE-2023-0558](https://github.com/Live-Hack-CVE/CVE-2023-0558) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0558.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0558.svg)


## CVE-2023-0557
 The ContentStudio plugin for WordPress is vulnerable to Sensitive Information Exposure in versions up to, and including, 1.2.5. This could allow unauthenticated attackers to obtain a nonce needed for the creation of posts.

- [https://github.com/Live-Hack-CVE/CVE-2023-0557](https://github.com/Live-Hack-CVE/CVE-2023-0557) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0557.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0557.svg)


## CVE-2023-0556
 The ContentStudio plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on several functions in versions up to, and including, 1.2.5. This makes it possible for unauthenticated attackers to obtain the blog metadata (via the function cstu_get_metadata) that includes the plugin's contentstudio_token. Knowing this token allows for other interactions with the plugin such as creating posts in versions prior to 1.2.5, which added other requirements to posting and updating.

- [https://github.com/Live-Hack-CVE/CVE-2023-0556](https://github.com/Live-Hack-CVE/CVE-2023-0556) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0556.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0556.svg)


## CVE-2023-0555
 The Quick Restaurant Menu plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on its AJAX actions in versions up to, and including, 2.0.2. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke those actions intended for administrator use. Actions include menu item creation, update and deletion and other menu management functions. Since the plugin does not verify that a post ID passed to one of its AJAX actions belongs to a menu item, this can lead to arbitrary post deletion/alteration.

- [https://github.com/Live-Hack-CVE/CVE-2023-0555](https://github.com/Live-Hack-CVE/CVE-2023-0555) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0555.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0555.svg)


## CVE-2023-0554
 The Quick Restaurant Menu plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.0.2. This is due to missing or incorrect nonce validation on its AJAX actions. This makes it possible for unauthenticated attackers to update menu items, via forged request granted they can trick a site administrator into performing an action such as clicking on a link.

- [https://github.com/Live-Hack-CVE/CVE-2023-0554](https://github.com/Live-Hack-CVE/CVE-2023-0554) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0554.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0554.svg)


## CVE-2023-0553
 The Quick Restaurant Menu plugin for WordPress is vulnerable to Stored Cross-Site Scripting via its settings parameters in versions up to, and including, 2.0.2 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/Live-Hack-CVE/CVE-2023-0553](https://github.com/Live-Hack-CVE/CVE-2023-0553) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0553.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0553.svg)


## CVE-2023-0550
 The Quick Restaurant Menu plugin for WordPress is vulnerable to Insecure Direct Object Reference in versions up to, and including, 2.0.2. This is due to the fact that during menu item deletion/modification, the plugin does not verify that the post ID provided to the AJAX action is indeed a menu item. This makes it possible for authenticated attackers, with subscriber-level access or higher, to modify or delete arbitrary posts.

- [https://github.com/Live-Hack-CVE/CVE-2023-0550](https://github.com/Live-Hack-CVE/CVE-2023-0550) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0550.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0550.svg)


## CVE-2023-0534
 A vulnerability, which was classified as critical, was found in SourceCodester Online Tours &amp; Travels Management System 1.0. This affects an unknown part of the file admin/expense_report.php. The manipulation of the argument to_date leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-219603.

- [https://github.com/Live-Hack-CVE/CVE-2023-0534](https://github.com/Live-Hack-CVE/CVE-2023-0534) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0534.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0534.svg)


## CVE-2023-0533
 A vulnerability, which was classified as critical, has been found in SourceCodester Online Tours &amp; Travels Management System 1.0. Affected by this issue is some unknown functionality of the file admin/expense_report.php. The manipulation of the argument from_date leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. VDB-219602 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0533](https://github.com/Live-Hack-CVE/CVE-2023-0533) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0533.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0533.svg)


## CVE-2023-0532
 A vulnerability classified as critical was found in SourceCodester Online Tours &amp; Travels Management System 1.0. Affected by this vulnerability is an unknown functionality of the file admin/disapprove_user.php. The manipulation of the argument id leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-219601 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0532](https://github.com/Live-Hack-CVE/CVE-2023-0532) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0532.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0532.svg)


## CVE-2023-0531
 A vulnerability classified as critical has been found in SourceCodester Online Tours &amp; Travels Management System 1.0. Affected is an unknown function of the file admin/booking_report.php. The manipulation of the argument to_date leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-219600.

- [https://github.com/Live-Hack-CVE/CVE-2023-0531](https://github.com/Live-Hack-CVE/CVE-2023-0531) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0531.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0531.svg)


## CVE-2023-0530
 A vulnerability was found in SourceCodester Online Tours &amp; Travels Management System 1.0. It has been rated as critical. This issue affects some unknown processing of the file admin/approve_user.php. The manipulation of the argument id leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-219599.

- [https://github.com/Live-Hack-CVE/CVE-2023-0530](https://github.com/Live-Hack-CVE/CVE-2023-0530) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0530.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0530.svg)


## CVE-2023-0529
 A vulnerability was found in SourceCodester Online Tours &amp; Travels Management System 1.0. It has been declared as critical. This vulnerability affects unknown code of the file admin/add_payment.php. The manipulation of the argument id leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-219598 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0529](https://github.com/Live-Hack-CVE/CVE-2023-0529) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0529.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0529.svg)


## CVE-2023-0528
 A vulnerability was found in SourceCodester Online Tours &amp; Travels Management System 1.0. It has been classified as critical. This affects an unknown part of the file admin/abc.php. The manipulation of the argument id leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-219597 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0528](https://github.com/Live-Hack-CVE/CVE-2023-0528) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0528.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0528.svg)


## CVE-2023-0527
 A vulnerability was found in PHPGurukul Online Security Guards Hiring System 1.0 and classified as problematic. Affected by this issue is some unknown functionality of the file search-request.php. The manipulation of the argument searchdata with the input &quot;&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt; leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-219596.

- [https://github.com/Live-Hack-CVE/CVE-2023-0527](https://github.com/Live-Hack-CVE/CVE-2023-0527) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0527.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0527.svg)


## CVE-2023-0047
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool that was not assigned to any issues during 2023. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2023-0047](https://github.com/Live-Hack-CVE/CVE-2023-0047) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0047.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0047.svg)


## CVE-2022-48152
 SQL Injection vulnerability in RemoteClinic 2.0 allows attackers to execute arbitrary commands and gain sensitive information via the id parameter to /medicines/profile.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-48152](https://github.com/Live-Hack-CVE/CVE-2022-48152) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48152.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48152.svg)


## CVE-2022-48120
 SQL Injection vulnerability in kishan0725 Hospital Management System thru commit 4770d740f2512693ef8fd9aa10a8d17f79fad9bd (on March 13, 2021), allows attackers to execute arbitrary commands via the contact and doctor parameters to /search.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-48120](https://github.com/Live-Hack-CVE/CVE-2022-48120) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48120.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48120.svg)


## CVE-2022-48116
 AyaCMS v3.1.2 was discovered to contain a remote code execution (RCE) vulnerability via the component /admin/tpl_edit.inc.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-48116](https://github.com/Live-Hack-CVE/CVE-2022-48116) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48116.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48116.svg)


## CVE-2022-48108
 D-Link DIR_878_FW1.30B08 was discovered to contain a command injection vulnerability via the component /SetNetworkSettings/SubnetMask. This vulnerability allows attackers to escalate privileges to root via a crafted payload.

- [https://github.com/Live-Hack-CVE/CVE-2022-48108](https://github.com/Live-Hack-CVE/CVE-2022-48108) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48108.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48108.svg)


## CVE-2022-48107
 D-Link DIR_878_FW1.30B08 was discovered to contain a command injection vulnerability via the component /setnetworksettings/IPAddress. This vulnerability allows attackers to escalate privileges to root via a crafted payload.

- [https://github.com/Live-Hack-CVE/CVE-2022-48107](https://github.com/Live-Hack-CVE/CVE-2022-48107) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48107.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48107.svg)


## CVE-2022-48073
 Phicomm K2 v22.6.534.263 was discovered to store the root and admin passwords in plaintext.

- [https://github.com/Live-Hack-CVE/CVE-2022-48073](https://github.com/Live-Hack-CVE/CVE-2022-48073) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48073.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48073.svg)


## CVE-2022-48072
 Phicomm K2G v22.6.3.20 was discovered to contain a command injection vulnerability via the autoUpTime parameter in the automatic upgrade function.

- [https://github.com/Live-Hack-CVE/CVE-2022-48072](https://github.com/Live-Hack-CVE/CVE-2022-48072) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48072.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48072.svg)


## CVE-2022-48071
 Phicomm K2 v22.6.534.263 was discovered to store the root and admin passwords in plaintext.

- [https://github.com/Live-Hack-CVE/CVE-2022-48071](https://github.com/Live-Hack-CVE/CVE-2022-48071) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48071.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48071.svg)


## CVE-2022-48070
 Phicomm K2 v22.6.534.263 was discovered to contain a command injection vulnerability via the autoUpTime parameter in the automatic upgrade function.

- [https://github.com/Live-Hack-CVE/CVE-2022-48070](https://github.com/Live-Hack-CVE/CVE-2022-48070) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48070.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48070.svg)


## CVE-2022-48069
 Totolink A830R V4.1.2cu.5182 was discovered to contain a command injection vulnerability via the QUERY_STRING parameter.

- [https://github.com/Live-Hack-CVE/CVE-2022-48069](https://github.com/Live-Hack-CVE/CVE-2022-48069) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48069.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48069.svg)


## CVE-2022-48067
 An information disclosure vulnerability in Totolink A830R V4.1.2cu.5182 allows attackers to obtain the root password via a brute-force attack.

- [https://github.com/Live-Hack-CVE/CVE-2022-48067](https://github.com/Live-Hack-CVE/CVE-2022-48067) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48067.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48067.svg)


## CVE-2022-48066
 An issue in the component global.so of Totolink A830R V4.1.2cu.5182 allows attackers to bypass authentication via a crafted cookie.

- [https://github.com/Live-Hack-CVE/CVE-2022-48066](https://github.com/Live-Hack-CVE/CVE-2022-48066) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48066.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48066.svg)


## CVE-2022-47873
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/waspthebughunter/CVE-2022-47873](https://github.com/waspthebughunter/CVE-2022-47873) :  ![starts](https://img.shields.io/github/stars/waspthebughunter/CVE-2022-47873.svg) ![forks](https://img.shields.io/github/forks/waspthebughunter/CVE-2022-47873.svg)


## CVE-2022-47747
 kraken &lt;= 0.1.4 has an arbitrary file read vulnerability via the component testfs.

- [https://github.com/Live-Hack-CVE/CVE-2022-47747](https://github.com/Live-Hack-CVE/CVE-2022-47747) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47747.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47747.svg)


## CVE-2022-47632
 Razer Synapse before 3.7.0830.081906 allows privilege escalation due to an unsafe installation path, improper privilege management, and improper certificate validation. Attackers can place malicious DLLs into %PROGRAMDATA%\Razer\Synapse3\Service\bin if they do so before the service is installed and if they deny write access for the SYSTEM user. Although the service will not start if the malicious DLLs are unsigned, it suffices to use self-signed DLLs. The validity of the DLL signatures is not checked. As a result, local Windows users can abuse the Razer driver installer to obtain administrative privileges on Windows.

- [https://github.com/Live-Hack-CVE/CVE-2022-47632](https://github.com/Live-Hack-CVE/CVE-2022-47632) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47632.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47632.svg)


## CVE-2022-47024
 A null pointer dereference issue was discovered in function gui_x11_create_blank_mouse in gui_x11.c in vim 8.1.2269 thru 9.0.0339 allows attackers to cause denial of service or other unspecified impacts.

- [https://github.com/Live-Hack-CVE/CVE-2022-47024](https://github.com/Live-Hack-CVE/CVE-2022-47024) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47024.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47024.svg)


## CVE-2022-47021
 A null pointer dereference issue was discovered in functions op_get_data and op_open1 in opusfile.c in xiph opusfile 0.9 thru 0.12 allows attackers to cause denial of service or other unspecified impacts.

- [https://github.com/Live-Hack-CVE/CVE-2022-47021](https://github.com/Live-Hack-CVE/CVE-2022-47021) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47021.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47021.svg)


## CVE-2022-47016
 A null pointer dereference issue was discovered in function window_pane_set_event in window.c in tmux 3.0 thru 3.3 and later, allows attackers to cause denial of service or other unspecified impacts.

- [https://github.com/Live-Hack-CVE/CVE-2022-47016](https://github.com/Live-Hack-CVE/CVE-2022-47016) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47016.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47016.svg)


## CVE-2022-47015
 MariaDB Server before 10.3.34 thru 10.9.3 is vulnerable to Denial of Service. It is possible for function spider_db_mbase::print_warnings to dereference a null pointer.

- [https://github.com/Live-Hack-CVE/CVE-2022-47015](https://github.com/Live-Hack-CVE/CVE-2022-47015) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47015.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47015.svg)


## CVE-2022-47012
 Use of uninitialized variable in function gen_eth_recv in GNS3 dynamips 0.2.21.

- [https://github.com/Live-Hack-CVE/CVE-2022-47012](https://github.com/Live-Hack-CVE/CVE-2022-47012) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47012.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47012.svg)


## CVE-2022-46968
 A stored cross-site scripting (XSS) vulnerability in /index.php?page=help of Revenue Collection System v1.0 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into sent messages.

- [https://github.com/Live-Hack-CVE/CVE-2022-46968](https://github.com/Live-Hack-CVE/CVE-2022-46968) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46968.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46968.svg)


## CVE-2022-45748
 An issue was discovered with assimp 5.1.4, a use after free occurred in function ColladaParser::ExtractDataObjectFromChannel in file /code/AssetLib/Collada/ColladaParser.cpp.

- [https://github.com/Live-Hack-CVE/CVE-2022-45748](https://github.com/Live-Hack-CVE/CVE-2022-45748) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45748.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45748.svg)


## CVE-2022-44718
 An issue was discovered in NetScout nGeniusONE 6.3.2 build 904. Open Redirection can occur (issue 2 of 2). After successful login, an attacker must visit the vulnerable parameter and inject a crafted payload to successfully redirect to an unknown host. The attack vector is Network, and the Attack Complexity required is High. Privileges required are administrator, User Interaction is required, and Scope is unchanged. The user must visit the vulnerable parameter and inject a crafted payload to successfully redirect to an unknown host.

- [https://github.com/Live-Hack-CVE/CVE-2022-44718](https://github.com/Live-Hack-CVE/CVE-2022-44718) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44718.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44718.svg)


## CVE-2022-44717
 An issue was discovered in NetScout nGeniusONE 6.3.2 build 904. Open Redirection can occur (issue 1 of 2). After successful login, an attacker must visit the vulnerable parameter and inject a crafted payload to successfully redirect to an unknown host. The attack vector is Network, and the Attack Complexity required is High. Privileges required are administrator, User Interaction is required, and Scope is unchanged. The user must visit the vulnerable parameter and inject a crafted payload to successfully redirect to an unknown host.

- [https://github.com/Live-Hack-CVE/CVE-2022-44717](https://github.com/Live-Hack-CVE/CVE-2022-44717) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44717.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44717.svg)


## CVE-2022-44715
 Improper File Permissions in NetScout nGeniusONE 6.3.2 build 904 allows authenticated remote users to gain permissions via a crafted payload.

- [https://github.com/Live-Hack-CVE/CVE-2022-44715](https://github.com/Live-Hack-CVE/CVE-2022-44715) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44715.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44715.svg)


## CVE-2022-44298
 SiteServer CMS 7.1.3 is vulnerable to SQL Injection.

- [https://github.com/Live-Hack-CVE/CVE-2022-44298](https://github.com/Live-Hack-CVE/CVE-2022-44298) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44298.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44298.svg)


## CVE-2022-44029
 An issue was discovered in NetScout nGeniusONE 6.3.2 before P10. It allows Reflected Cross-Site Scripting (XSS), issue 6 of 6.

- [https://github.com/Live-Hack-CVE/CVE-2022-44029](https://github.com/Live-Hack-CVE/CVE-2022-44029) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44029.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44029.svg)


## CVE-2022-44028
 An issue was discovered in NetScout nGeniusONE 6.3.2 before P10. It allows Reflected Cross-Site Scripting (XSS), issue 5 of 6.

- [https://github.com/Live-Hack-CVE/CVE-2022-44028](https://github.com/Live-Hack-CVE/CVE-2022-44028) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44028.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44028.svg)


## CVE-2022-44027
 An issue was discovered in NetScout nGeniusONE 6.3.2 before P10. It allows Reflected Cross-Site Scripting (XSS), issue 4 of 6.

- [https://github.com/Live-Hack-CVE/CVE-2022-44027](https://github.com/Live-Hack-CVE/CVE-2022-44027) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44027.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44027.svg)


## CVE-2022-44026
 An issue was discovered in NetScout nGeniusONE 6.3.2 before P10. It allows Reflected Cross-Site Scripting (XSS), issue 3 of 6.

- [https://github.com/Live-Hack-CVE/CVE-2022-44026](https://github.com/Live-Hack-CVE/CVE-2022-44026) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44026.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44026.svg)


## CVE-2022-44025
 An issue was discovered in NetScout nGeniusONE 6.3.2 before P10. It allows Reflected Cross-Site Scripting (XSS), issue 2 of 6.

- [https://github.com/Live-Hack-CVE/CVE-2022-44025](https://github.com/Live-Hack-CVE/CVE-2022-44025) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44025.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44025.svg)


## CVE-2022-44024
 An issue was discovered in NetScout nGeniusONE 6.3.2 before P10. It allows Reflected Cross-Site Scripting (XSS), issue 1 of 6.

- [https://github.com/Live-Hack-CVE/CVE-2022-44024](https://github.com/Live-Hack-CVE/CVE-2022-44024) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44024.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44024.svg)


## CVE-2022-43980
 There is a stored cross-site scripting vulnerability in Pandora FMS v765 in the network maps editing functionality. An attacker could modify a network map, including on purpose the name of an XSS payload. Once created, if a user with admin privileges clicks on the edited network maps, the XSS payload will be executed. The exploitation of this vulnerability could allow an atacker to steal the value of the admin users cookie.

- [https://github.com/Live-Hack-CVE/CVE-2022-43980](https://github.com/Live-Hack-CVE/CVE-2022-43980) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43980.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43980.svg)


## CVE-2022-43979
 There is a Path Traversal that leads to a Local File Inclusion in Pandora FMS v764. A function is called to check that the parameter that the user has inserted does not contain malicious characteres, but this check is insufficient. An attacker could insert an absolute path to overcome the heck, thus being able to incluse any PHP file that resides on the disk. The exploitation of this vulnerability could lead to a remote code execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-43979](https://github.com/Live-Hack-CVE/CVE-2022-43979) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43979.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43979.svg)


## CVE-2022-43978
 There is an improper authentication vulnerability in Pandora FMS v764. The application verifies that the user has a valid session when he is not trying to do a login. Since the secret is static in generatePublicHash function, an attacker with knowledge of a valid session can abuse this in order to pass the authentication check.

- [https://github.com/Live-Hack-CVE/CVE-2022-43978](https://github.com/Live-Hack-CVE/CVE-2022-43978) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43978.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43978.svg)


## CVE-2022-43494
 An unauthorized user could be able to read any file on the system, potentially exposing sensitive information.

- [https://github.com/Live-Hack-CVE/CVE-2022-43494](https://github.com/Live-Hack-CVE/CVE-2022-43494) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43494.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43494.svg)


## CVE-2022-42423
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of TIF files. Crafted data in a TIF file can trigger a write past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18716.

- [https://github.com/Live-Hack-CVE/CVE-2022-42423](https://github.com/Live-Hack-CVE/CVE-2022-42423) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42423.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42423.svg)


## CVE-2022-42421
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of TIF files. Crafted data in a TIF file can trigger a write past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18703.

- [https://github.com/Live-Hack-CVE/CVE-2022-42421](https://github.com/Live-Hack-CVE/CVE-2022-42421) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42421.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42421.svg)


## CVE-2022-42420
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of TIF files. Crafted data in a TIF file can trigger a write past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18686.

- [https://github.com/Live-Hack-CVE/CVE-2022-42420](https://github.com/Live-Hack-CVE/CVE-2022-42420) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42420.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42420.svg)


## CVE-2022-42419
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of TIF files. Crafted data in a TIF file can trigger a write past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18700.

- [https://github.com/Live-Hack-CVE/CVE-2022-42419](https://github.com/Live-Hack-CVE/CVE-2022-42419) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42419.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42419.svg)


## CVE-2022-42418
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of TIF files. The issue results from the lack of proper validation of a user-supplied value prior to dereferencing it as a pointer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18677.

- [https://github.com/Live-Hack-CVE/CVE-2022-42418](https://github.com/Live-Hack-CVE/CVE-2022-42418) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42418.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42418.svg)


## CVE-2022-42417
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of TIF files. Crafted data in a TIF file can trigger a read past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18676.

- [https://github.com/Live-Hack-CVE/CVE-2022-42417](https://github.com/Live-Hack-CVE/CVE-2022-42417) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42417.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42417.svg)


## CVE-2022-42416
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of TIF files. Crafted data in a TIF file can trigger a write past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18673.

- [https://github.com/Live-Hack-CVE/CVE-2022-42416](https://github.com/Live-Hack-CVE/CVE-2022-42416) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42416.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42416.svg)


## CVE-2022-42415
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of JP2 files. Crafted data in a JP2 file can trigger a write past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18366.

- [https://github.com/Live-Hack-CVE/CVE-2022-42415](https://github.com/Live-Hack-CVE/CVE-2022-42415) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42415.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42415.svg)


## CVE-2022-42414
 This vulnerability allows remote attackers to disclose sensitive information on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of PDF files. The issue results from the lack of validating the existence of an object prior to performing operations on the object. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code in the context of the current process. Was ZDI-CAN-18326.

- [https://github.com/Live-Hack-CVE/CVE-2022-42414](https://github.com/Live-Hack-CVE/CVE-2022-42414) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42414.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42414.svg)


## CVE-2022-42410
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of PGM files. Crafted data in a PGM file can trigger a write past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18365.

- [https://github.com/Live-Hack-CVE/CVE-2022-42410](https://github.com/Live-Hack-CVE/CVE-2022-42410) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42410.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42410.svg)


## CVE-2022-42409
 This vulnerability allows remote attackers to disclose sensitive information on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of PDF files. Crafted data in a PDF file can trigger a read past the end of an allocated buffer. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code in the context of the current process. Was ZDI-CAN-18315.

- [https://github.com/Live-Hack-CVE/CVE-2022-42409](https://github.com/Live-Hack-CVE/CVE-2022-42409) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42409.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42409.svg)


## CVE-2022-42407
 This vulnerability allows remote attackers to disclose sensitive information on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of EMF files. Crafted data in an EMF file can trigger a read past the end of an allocated buffer. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code in the context of the current process. Was ZDI-CAN-18542.

- [https://github.com/Live-Hack-CVE/CVE-2022-42407](https://github.com/Live-Hack-CVE/CVE-2022-42407) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42407.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42407.svg)


## CVE-2022-42406
 This vulnerability allows remote attackers to disclose sensitive information on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of EMF files. Crafted data in an EMF file can trigger a read past the end of an allocated buffer. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code in the context of the current process. Was ZDI-CAN-18369.

- [https://github.com/Live-Hack-CVE/CVE-2022-42406](https://github.com/Live-Hack-CVE/CVE-2022-42406) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42406.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42406.svg)


## CVE-2022-42405
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of EMF files. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a fixed-length heap-based buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18367.

- [https://github.com/Live-Hack-CVE/CVE-2022-42405](https://github.com/Live-Hack-CVE/CVE-2022-42405) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42405.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42405.svg)


## CVE-2022-42403
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of PDF files. The issue results from the lack of proper validation of the length of user-supplied data prior to copying it to a fixed-length heap-based buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18892.

- [https://github.com/Live-Hack-CVE/CVE-2022-42403](https://github.com/Live-Hack-CVE/CVE-2022-42403) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42403.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42403.svg)


## CVE-2022-42400
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of PDF files. Crafted data in a PDF file can trigger a write past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18328.

- [https://github.com/Live-Hack-CVE/CVE-2022-42400](https://github.com/Live-Hack-CVE/CVE-2022-42400) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42400.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42400.svg)


## CVE-2022-42399
 This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of PDF files. Crafted data in a PDF file can trigger a read past the end of an allocated buffer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18327.

- [https://github.com/Live-Hack-CVE/CVE-2022-42399](https://github.com/Live-Hack-CVE/CVE-2022-42399) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42399.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42399.svg)


## CVE-2022-41947
 DHIS 2 is an open source information system for data capture, management, validation, analytics and visualization. Through various features of DHIS2, an authenticated user may be able to upload a file which includes embedded javascript. The user could then potentially trick another authenticated user to open the malicious file in a browser which would trigger the javascript code, resulting in a cross-site scripting (XSS) attack. DHIS2 administrators should upgrade to the following hotfix releases: 2.36.12.1, 2.37.8.1, 2.38.2.1, 2.39.0.1. Users unable to upgrade may add the following simple CSP rule in your web proxy to the vulnerable endpoints: `script-src 'none'`. This workaround will prevent all javascript from running on those endpoints.

- [https://github.com/Live-Hack-CVE/CVE-2022-41947](https://github.com/Live-Hack-CVE/CVE-2022-41947) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41947.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41947.svg)


## CVE-2022-41225
 Jenkins Anchore Container Image Scanner Plugin 1.0.24 and earlier does not escape content provided by the Anchore engine API, resulting in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able to control API responses by Anchore engine.

- [https://github.com/Live-Hack-CVE/CVE-2022-41225](https://github.com/Live-Hack-CVE/CVE-2022-41225) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41225.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41225.svg)


## CVE-2022-39813
 Italtel NetMatch-S CI 5.2.0-20211008 allows Multiple Reflected/Stored XSS issues under NMSCIWebGui/j_security_check via the j_username parameter, or NMSCIWebGui/actloglineview.jsp via the name or actLine parameter. An attacker leveraging this vulnerability could inject arbitrary JavaScript. The payload would then be triggered every time an authenticated user browses the page containing it.

- [https://github.com/Live-Hack-CVE/CVE-2022-39813](https://github.com/Live-Hack-CVE/CVE-2022-39813) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39813.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39813.svg)


## CVE-2022-39812
 Italtel NetMatch-S CI 5.2.0-20211008 allows Absolute Path Traversal under NMSCI-WebGui/SaveFileUploader. An unauthenticated user can upload files to an arbitrary path. An attacker can change the uploadDir parameter in a POST request (not possible using the GUI) to an arbitrary directory. Because the application does not check in which directory a file will be uploaded, an attacker can perform a variety of attacks that can result in unauthorized access to the server.

- [https://github.com/Live-Hack-CVE/CVE-2022-39812](https://github.com/Live-Hack-CVE/CVE-2022-39812) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39812.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39812.svg)


## CVE-2022-39811
 Italtel NetMatch-S CI 5.2.0-20211008 has incorrect Access Control under NMSCI-WebGui/advancedsettings.jsp and NMSCIWebGui/SaveFileUploader. By not verifying permissions for access to resources, it allows an attacker to view pages that are not allowed, and modify the system configuration, bypassing all controls (without checking for user identity).

- [https://github.com/Live-Hack-CVE/CVE-2022-39811](https://github.com/Live-Hack-CVE/CVE-2022-39811) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39811.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39811.svg)


## CVE-2022-39380
 Wire web-app is part of Wire communications. Versions prior to 2022-11-02 are subject to Improper Handling of Exceptional Conditions. In the wire-webapp, certain combinations of Markdown formatting can trigger an unhandled error in the conversion to HTML representation. The error makes it impossible to display the affected chat history, other conversations are not affected. The issue has been fixed in version 2022-11-02 and is already deployed on all Wire managed services. On-premise instances of wire-webapp need to be updated to docker tag 2022-11-02-production.0-v0.31.9-0-337e400 or wire-server 2022-11-03 (chart/4.26.0), so that their applications are no longer affected. As a workaround, you may use an iOS or Android client and delete the corresponding message from the history OR write 30 or more messages into the affected conversation to prevent the client from further rendering of the corresponding message. When attempting to retrieve messages from the conversation history, the error will continue to occur once the malformed message is part of the result.

- [https://github.com/Live-Hack-CVE/CVE-2022-39380](https://github.com/Live-Hack-CVE/CVE-2022-39380) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39380.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39380.svg)


## CVE-2022-39324
 Grafana is an open-source platform for monitoring and observability. Prior to versions 8.5.16 and 9.2.8, malicious user can create a snapshot and arbitrarily choose the `originalUrl` parameter by editing the query, thanks to a web proxy. When another user opens the URL of the snapshot, they will be presented with the regular web interface delivered by the trusted Grafana server. The `Open original dashboard` button no longer points to the to the real original dashboard but to the attacker&#8217;s injected URL. This issue is fixed in versions 8.5.16 and 9.2.8.

- [https://github.com/Live-Hack-CVE/CVE-2022-39324](https://github.com/Live-Hack-CVE/CVE-2022-39324) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-39324.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-39324.svg)


## CVE-2022-32952
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2022-32952](https://github.com/Live-Hack-CVE/CVE-2022-32952) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32952.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32952.svg)


## CVE-2022-32472
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by its CNA. Further investigation showed that it was not a security issue. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2022-32472](https://github.com/Live-Hack-CVE/CVE-2022-32472) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-32472.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-32472.svg)


## CVE-2022-32250
 net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to a use-after-free.

- [https://github.com/ysanatomic/CVE-2022-32250-LPE](https://github.com/ysanatomic/CVE-2022-32250-LPE) :  ![starts](https://img.shields.io/github/stars/ysanatomic/CVE-2022-32250-LPE.svg) ![forks](https://img.shields.io/github/forks/ysanatomic/CVE-2022-32250-LPE.svg)


## CVE-2022-30190
 Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability.

- [https://github.com/0xAbbarhSF/FollinaXploit](https://github.com/0xAbbarhSF/FollinaXploit) :  ![starts](https://img.shields.io/github/stars/0xAbbarhSF/FollinaXploit.svg) ![forks](https://img.shields.io/github/forks/0xAbbarhSF/FollinaXploit.svg)
- [https://github.com/droidrzrlover/CVE-2022-30190](https://github.com/droidrzrlover/CVE-2022-30190) :  ![starts](https://img.shields.io/github/stars/droidrzrlover/CVE-2022-30190.svg) ![forks](https://img.shields.io/github/forks/droidrzrlover/CVE-2022-30190.svg)
- [https://github.com/ITMarcin2211/CVE-2022-30190](https://github.com/ITMarcin2211/CVE-2022-30190) :  ![starts](https://img.shields.io/github/stars/ITMarcin2211/CVE-2022-30190.svg) ![forks](https://img.shields.io/github/forks/ITMarcin2211/CVE-2022-30190.svg)
- [https://github.com/SrCroqueta/CVE-2022-30190_Temporary_Fix](https://github.com/SrCroqueta/CVE-2022-30190_Temporary_Fix) :  ![starts](https://img.shields.io/github/stars/SrCroqueta/CVE-2022-30190_Temporary_Fix.svg) ![forks](https://img.shields.io/github/forks/SrCroqueta/CVE-2022-30190_Temporary_Fix.svg)
- [https://github.com/Imeneallouche/Follina-attack-CVE-2022-30190-](https://github.com/Imeneallouche/Follina-attack-CVE-2022-30190-) :  ![starts](https://img.shields.io/github/stars/Imeneallouche/Follina-attack-CVE-2022-30190-.svg) ![forks](https://img.shields.io/github/forks/Imeneallouche/Follina-attack-CVE-2022-30190-.svg)


## CVE-2022-23552
 Grafana is an open-source platform for monitoring and observability. Starting with the 8.1 branch and prior to versions 8.5.16, 9.2.10, and 9.3.4, Grafana had a stored XSS vulnerability affecting the core plugin GeoMap. The stored XSS vulnerability was possible because SVG files weren't properly sanitized and allowed arbitrary JavaScript to be executed in the context of the currently authorized user of the Grafana instance. An attacker needs to have the Editor role in order to change a panel to include either an external URL to a SVG-file containing JavaScript, or use the `data:` scheme to load an inline SVG-file containing JavaScript. This means that vertical privilege escalation is possible, where a user with Editor role can change to a known password for a user having Admin role if the user with Admin role executes malicious JavaScript viewing a dashboard. Users may upgrade to version 8.5.16, 9.2.10, or 9.3.4 to receive a fix.

- [https://github.com/Live-Hack-CVE/CVE-2022-23552](https://github.com/Live-Hack-CVE/CVE-2022-23552) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23552.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23552.svg)


## CVE-2022-4205
 In Gitlab EE/CE before 15.6.1, 15.5.5 and 15.4.6 using a branch with a hexadecimal name could override an existing hash.

- [https://github.com/Live-Hack-CVE/CVE-2022-4205](https://github.com/Live-Hack-CVE/CVE-2022-4205) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4205.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4205.svg)


## CVE-2022-4201
 A blind SSRF in GitLab CE/EE affecting all from 11.3 prior to 15.4.6, 15.5 prior to 15.5.5, and 15.6 prior to 15.6.1 allows an attacker to connect to local addresses when configuring a malicious GitLab Runner.

- [https://github.com/Live-Hack-CVE/CVE-2022-4201](https://github.com/Live-Hack-CVE/CVE-2022-4201) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4201.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4201.svg)


## CVE-2022-3888
 Use after free in WebCodecs in Google Chrome prior to 107.0.5304.106 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Live-Hack-CVE/CVE-2022-3888](https://github.com/Live-Hack-CVE/CVE-2022-3888) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3888.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3888.svg)


## CVE-2022-3671
 A vulnerability classified as critical was found in SourceCodester eLearning System 1.0. This vulnerability affects unknown code of the file /admin/students/manage.php. The manipulation of the argument id leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-212014 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-3671](https://github.com/Live-Hack-CVE/CVE-2022-3671) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3671.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3671.svg)


## CVE-2022-3641
 Elevation of privilege in the Azure SQL Data Source in Devolutions Remote Desktop Manager 2022.3.13 to 2022.3.24 allows an authenticated user to spoof a privileged account.

- [https://github.com/Live-Hack-CVE/CVE-2022-3641](https://github.com/Live-Hack-CVE/CVE-2022-3641) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3641.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3641.svg)


## CVE-2022-3452
 A vulnerability was found in SourceCodester Book Store Management System 1.0. It has been declared as problematic. This vulnerability affects unknown code of the file /category.php. The manipulation of the argument category_name leads to cross site scripting. The attack can be initiated remotely. The identifier of this vulnerability is VDB-210436.

- [https://github.com/Live-Hack-CVE/CVE-2022-3452](https://github.com/Live-Hack-CVE/CVE-2022-3452) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3452.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3452.svg)


## CVE-2022-2712
 In Eclipse GlassFish versions 5.1.0 to 6.2.5, there is a vulnerability in relative path traversal because it does not filter request path starting with './'. Successful exploitation could allow an remote unauthenticated attacker to access critical data, such as configuration files and deployed application source code.

- [https://github.com/Live-Hack-CVE/CVE-2022-2712](https://github.com/Live-Hack-CVE/CVE-2022-2712) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2712.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2712.svg)


## CVE-2022-2563
 The Tutor LMS WordPress plugin before 2.0.10 does not escape some course parameters, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup)

- [https://github.com/Live-Hack-CVE/CVE-2022-2563](https://github.com/Live-Hack-CVE/CVE-2022-2563) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2563.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2563.svg)


## CVE-2021-44226
 Razer Synapse before 3.7.0228.022817 allows privilege escalation because it relies on %PROGRAMDATA%\Razer\Synapse3\Service\bin even if %PROGRAMDATA%\Razer has been created by any unprivileged user before Synapse is installed. The unprivileged user may have placed Trojan horse DLLs there.

- [https://github.com/Live-Hack-CVE/CVE-2021-44226](https://github.com/Live-Hack-CVE/CVE-2021-44226) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-44226.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-44226.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/mauricelambert/LabAutomationCVE-2021-43798](https://github.com/mauricelambert/LabAutomationCVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/mauricelambert/LabAutomationCVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/mauricelambert/LabAutomationCVE-2021-43798.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/McSl0vv/CVE-2021-41773](https://github.com/McSl0vv/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/McSl0vv/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/McSl0vv/CVE-2021-41773.svg)
- [https://github.com/m96dg/CVE-2021-41773-exercise](https://github.com/m96dg/CVE-2021-41773-exercise) :  ![starts](https://img.shields.io/github/stars/m96dg/CVE-2021-41773-exercise.svg) ![forks](https://img.shields.io/github/forks/m96dg/CVE-2021-41773-exercise.svg)
- [https://github.com/12345qwert123456/CVE-2021-41773](https://github.com/12345qwert123456/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/12345qwert123456/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/12345qwert123456/CVE-2021-41773.svg)


## CVE-2021-21395
 Magneto LTS (Long Term Support) is a community developed alternative to the Magento CE official releases. Versions prior to 19.4.22 and 20.0.19 are vulnerable to Cross-Site Request Forgery. The password reset form is vulnerable to CSRF between the time the reset password link is clicked and user submits new password. This issue is patched in versions 19.4.22 and 20.0.19. There are no workarounds.

- [https://github.com/Live-Hack-CVE/CVE-2021-21395](https://github.com/Live-Hack-CVE/CVE-2021-21395) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-21395.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-21395.svg)


## CVE-2021-4067
 Use after free in window manager in Google Chrome on ChromeOS prior to 96.0.4664.93 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2021-4067](https://github.com/Live-Hack-CVE/CVE-2021-4067) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-4067.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-4067.svg)


## CVE-2020-24371
 lgc.c in Lua 5.4.0 mishandles the interaction between barriers and the sweep phase, leading to a memory access violation involving collectgarbage.

- [https://github.com/Live-Hack-CVE/CVE-2020-24371](https://github.com/Live-Hack-CVE/CVE-2020-24371) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-24371.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-24371.svg)


## CVE-2020-17446
 asyncpg before 0.21.0 allows a malicious PostgreSQL server to trigger a crash or execute arbitrary code (on a database client) via a crafted server response, because of access to an uninitialized pointer in the array data decoder.

- [https://github.com/Live-Hack-CVE/CVE-2020-17446](https://github.com/Live-Hack-CVE/CVE-2020-17446) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-17446.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-17446.svg)


## CVE-2020-17366
 An issue was discovered in NLnet Labs Routinator 0.1.0 through 0.7.1. It allows remote attackers to bypass intended access restrictions or to cause a denial of service on dependent routing systems by strategically withholding RPKI Route Origin Authorisation &quot;.roa&quot; files or X509 Certificate Revocation List files from the RPKI relying party's view.

- [https://github.com/Live-Hack-CVE/CVE-2020-17366](https://github.com/Live-Hack-CVE/CVE-2020-17366) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-17366.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-17366.svg)


## CVE-2020-16207
 Advantech WebAccess HMI Designer, Versions 2.1.9.31 and prior. Multiple heap-based buffer overflow vulnerabilities may be exploited by opening specially crafted project files that may overflow the heap, which may allow remote code execution, disclosure/modification of information, or cause the application to crash.

- [https://github.com/Live-Hack-CVE/CVE-2020-16207](https://github.com/Live-Hack-CVE/CVE-2020-16207) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-16207.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-16207.svg)


## CVE-2020-15689
 Appweb before 7.2.2 and 8.x before 8.1.0, when built with CGI support, mishandles an HTTP request with a Range header that lacks an exact range. This may result in a NULL pointer dereference and cause a denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2020-15689](https://github.com/Live-Hack-CVE/CVE-2020-15689) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-15689.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-15689.svg)


## CVE-2020-14983
 The server in Chocolate Doom 3.0.0 and Crispy Doom 5.8.0 doesn't validate the user-controlled num_players value, leading to a buffer overflow. A malicious user can overwrite the server's stack.

- [https://github.com/Live-Hack-CVE/CVE-2020-14983](https://github.com/Live-Hack-CVE/CVE-2020-14983) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-14983.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-14983.svg)


## CVE-2020-14981
 The ThreatTrack VIPRE Password Vault app through 1.100.1090 for iOS has Missing SSL Certificate Validation.

- [https://github.com/Live-Hack-CVE/CVE-2020-14981](https://github.com/Live-Hack-CVE/CVE-2020-14981) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-14981.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-14981.svg)


## CVE-2020-14980
 The Sophos Secure Email application through 3.9.4 for Android has Missing SSL Certificate Validation.

- [https://github.com/Live-Hack-CVE/CVE-2020-14980](https://github.com/Live-Hack-CVE/CVE-2020-14980) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-14980.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-14980.svg)


## CVE-2020-14968
 An issue was discovered in the jsrsasign package before 8.0.17 for Node.js. Its RSASSA-PSS (RSA-PSS) implementation does not detect signature manipulation/modification by prepending '\0' bytes to a signature (it accepts these modified signatures as valid). An attacker can abuse this behavior in an application by creating multiple valid signatures where only one signature should exist. Also, an attacker might prepend these bytes with the goal of triggering memory corruption issues.

- [https://github.com/Live-Hack-CVE/CVE-2020-14968](https://github.com/Live-Hack-CVE/CVE-2020-14968) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-14968.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-14968.svg)


## CVE-2020-14967
 An issue was discovered in the jsrsasign package before 8.0.18 for Node.js. Its RSA PKCS1 v1.5 decryption implementation does not detect ciphertext modification by prepending '\0' bytes to ciphertexts (it decrypts modified ciphertexts without error). An attacker might prepend these bytes with the goal of triggering memory corruption issues.

- [https://github.com/Live-Hack-CVE/CVE-2020-14967](https://github.com/Live-Hack-CVE/CVE-2020-14967) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-14967.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-14967.svg)


## CVE-2020-14966
 An issue was discovered in the jsrsasign package through 8.0.18 for Node.js. It allows a malleability in ECDSA signatures by not checking overflows in the length of a sequence and '0' characters appended or prepended to an integer. The modified signatures are verified as valid. This could have a security-relevant impact if an application relied on a single canonical signature.

- [https://github.com/Live-Hack-CVE/CVE-2020-14966](https://github.com/Live-Hack-CVE/CVE-2020-14966) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-14966.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-14966.svg)


## CVE-2020-14947
 OCS Inventory NG 2.7 allows Remote Command Execution via shell metacharacters to require/commandLine/CommandLine.php because mib_file in plugins/main_sections/ms_config/ms_snmp_config.php is mishandled in get_mib_oid.

- [https://github.com/Live-Hack-CVE/CVE-2020-14947](https://github.com/Live-Hack-CVE/CVE-2020-14947) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-14947.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-14947.svg)


## CVE-2020-14943
 The Firstname and Lastname parameters in Global RADAR BSA Radar 1.6.7234.24750 and earlier are vulnerable to stored cross-site scripting (XSS) via Update User Profile.

- [https://github.com/Live-Hack-CVE/CVE-2020-14943](https://github.com/Live-Hack-CVE/CVE-2020-14943) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-14943.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-14943.svg)


## CVE-2020-14461
 Zyxel Armor X1 WAP6806 1.00(ABAL.6)C0 devices allow Directory Traversal via the images/eaZy/ URI.

- [https://github.com/Live-Hack-CVE/CVE-2020-14461](https://github.com/Live-Hack-CVE/CVE-2020-14461) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-14461.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-14461.svg)


## CVE-2020-14148
 The Server-Server protocol implementation in ngIRCd before 26~rc2 allows an out-of-bounds access, as demonstrated by the IRC_NJOIN() function.

- [https://github.com/Live-Hack-CVE/CVE-2020-14148](https://github.com/Live-Hack-CVE/CVE-2020-14148) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-14148.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-14148.svg)


## CVE-2020-14073
 XSS exists in PRTG Network Monitor 20.1.56.1574 via crafted map properties. An attacker with Read/Write privileges can create a map, and then use the Map Designer Properties screen to insert JavaScript code. This can be exploited against any user with View Maps or Edit Maps access.

- [https://github.com/Live-Hack-CVE/CVE-2020-14073](https://github.com/Live-Hack-CVE/CVE-2020-14073) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-14073.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-14073.svg)


## CVE-2020-13999
 ScaleViewPortExtEx in libemf.cpp in libEMF (aka ECMA-234 Metafile Library) 1.0.12 allows an integer overflow and denial of service via a crafted EMF file.

- [https://github.com/Live-Hack-CVE/CVE-2020-13999](https://github.com/Live-Hack-CVE/CVE-2020-13999) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-13999.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-13999.svg)


## CVE-2020-13775
 ZNC 1.8.0 up to 1.8.1-rc1 allows authenticated users to trigger an application crash (with a NULL pointer dereference) if echo-message is not enabled and there is no network.

- [https://github.com/Live-Hack-CVE/CVE-2020-13775](https://github.com/Live-Hack-CVE/CVE-2020-13775) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-13775.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-13775.svg)


## CVE-2020-13640
 A SQL injection issue in the gVectors wpDiscuz plugin 5.3.5 and earlier for WordPress allows remote attackers to execute arbitrary SQL commands via the order parameter of a wpdLoadMoreComments request. (No 7.x versions are affected.)

- [https://github.com/Live-Hack-CVE/CVE-2020-13640](https://github.com/Live-Hack-CVE/CVE-2020-13640) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-13640.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-13640.svg)


## CVE-2020-13112
 An issue was discovered in libexif before 0.6.22. Several buffer over-reads in EXIF MakerNote handling could lead to information disclosure and crashes. This is different from CVE-2020-0093.

- [https://github.com/Live-Hack-CVE/CVE-2020-13112](https://github.com/Live-Hack-CVE/CVE-2020-13112) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-13112.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-13112.svg)


## CVE-2020-12823
 OpenConnect 8.09 has a buffer overflow, causing a denial of service (application crash) or possibly unspecified other impact, via crafted certificate data to get_cert_name in gnutls.c.

- [https://github.com/Live-Hack-CVE/CVE-2020-12823](https://github.com/Live-Hack-CVE/CVE-2020-12823) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-12823.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-12823.svg)


## CVE-2020-12767
 exif_entry_get_value in exif-entry.c in libexif 0.6.21 has a divide-by-zero error.

- [https://github.com/Live-Hack-CVE/CVE-2020-12767](https://github.com/Live-Hack-CVE/CVE-2020-12767) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-12767.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-12767.svg)


## CVE-2020-12424
 When constructing a permission prompt for WebRTC, a URI was supplied from the content process. This URI was untrusted, and could have been the URI of an origin that was previously granted permission; bypassing the prompt. This vulnerability affects Firefox &lt; 78.

- [https://github.com/Live-Hack-CVE/CVE-2020-12424](https://github.com/Live-Hack-CVE/CVE-2020-12424) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-12424.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-12424.svg)


## CVE-2020-12418
 Manipulating individual parts of a URL object could have caused an out-of-bounds read, leaking process memory to malicious JavaScript. This vulnerability affects Firefox ESR &lt; 68.10, Firefox &lt; 78, and Thunderbird &lt; 68.10.0.

- [https://github.com/Live-Hack-CVE/CVE-2020-12418](https://github.com/Live-Hack-CVE/CVE-2020-12418) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-12418.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-12418.svg)


## CVE-2020-12415
 When &quot;%2F&quot; was present in a manifest URL, Firefox's AppCache behavior may have become confused and allowed a manifest to be served from a subdirectory. This could cause the appcache to be used to service requests for the top level directory. This vulnerability affects Firefox &lt; 78.

- [https://github.com/Live-Hack-CVE/CVE-2020-12415](https://github.com/Live-Hack-CVE/CVE-2020-12415) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-12415.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-12415.svg)


## CVE-2020-12406
 Mozilla Developer Iain Ireland discovered a missing type check during unboxed objects removal, resulting in a crash. We presume that with enough effort that it could be exploited to run arbitrary code. This vulnerability affects Thunderbird &lt; 68.9.0, Firefox &lt; 77, and Firefox ESR &lt; 68.9.

- [https://github.com/Live-Hack-CVE/CVE-2020-12406](https://github.com/Live-Hack-CVE/CVE-2020-12406) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-12406.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-12406.svg)


## CVE-2020-12267
 setMarkdown in Qt before 5.14.2 has a use-after-free related to QTextMarkdownImporter::insertBlock.

- [https://github.com/Live-Hack-CVE/CVE-2020-12267](https://github.com/Live-Hack-CVE/CVE-2020-12267) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-12267.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-12267.svg)


## CVE-2020-11958
 re2c 1.3 has a heap-based buffer overflow in Scanner::fill in parse/scanner.cc via a long lexeme.

- [https://github.com/Live-Hack-CVE/CVE-2020-11958](https://github.com/Live-Hack-CVE/CVE-2020-11958) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-11958.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-11958.svg)


## CVE-2020-11074
 In PrestaShop from version 1.5.3.0 and before version 1.7.6.6, there is a stored XSS when using the name of a quick access item. The problem is fixed in 1.7.6.6.

- [https://github.com/Live-Hack-CVE/CVE-2020-11074](https://github.com/Live-Hack-CVE/CVE-2020-11074) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-11074.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-11074.svg)


## CVE-2020-11019
 In FreeRDP less than or equal to 2.0.0, when running with logger set to &quot;WLOG_TRACE&quot;, a possible crash of application could occur due to a read of an invalid array index. Data could be printed as string to local terminal. This has been fixed in 2.1.0.

- [https://github.com/Live-Hack-CVE/CVE-2020-11019](https://github.com/Live-Hack-CVE/CVE-2020-11019) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-11019.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-11019.svg)


## CVE-2020-11018
 In FreeRDP less than or equal to 2.0.0, a possible resource exhaustion vulnerability can be performed. Malicious clients could trigger out of bound reads causing memory allocation with random size. This has been fixed in 2.1.0.

- [https://github.com/Live-Hack-CVE/CVE-2020-11018](https://github.com/Live-Hack-CVE/CVE-2020-11018) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-11018.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-11018.svg)


## CVE-2020-11017
 In FreeRDP less than or equal to 2.0.0, by providing manipulated input a malicious client can create a double free condition and crash the server. This is fixed in version 2.1.0.

- [https://github.com/Live-Hack-CVE/CVE-2020-11017](https://github.com/Live-Hack-CVE/CVE-2020-11017) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-11017.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-11017.svg)


## CVE-2020-10702
 A flaw was found in QEMU in the implementation of the Pointer Authentication (PAuth) support for ARM introduced in version 4.0 and fixed in version 5.0.0. A general failure of the signature generation process caused every PAuth-enforced pointer to be signed with the same signature. A local attacker could obtain the signature of a protected pointer and abuse this flaw to bypass PAuth protection for all programs running on QEMU.

- [https://github.com/Live-Hack-CVE/CVE-2020-10702](https://github.com/Live-Hack-CVE/CVE-2020-10702) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-10702.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-10702.svg)


## CVE-2020-8559
 The Kubernetes kube-apiserver in versions v1.6-v1.15, and versions prior to v1.16.13, v1.17.9 and v1.18.6 are vulnerable to an unvalidated redirect on proxied upgrade requests that could allow an attacker to escalate privileges from a node compromise to a full cluster compromise.

- [https://github.com/Live-Hack-CVE/CVE-2020-8559](https://github.com/Live-Hack-CVE/CVE-2020-8559) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-8559.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-8559.svg)


## CVE-2020-8557
 The Kubernetes kubelet component in versions 1.1-1.16.12, 1.17.0-1.17.8 and 1.18.0-1.18.5 do not account for disk usage by a pod which writes to its own /etc/hosts file. The /etc/hosts file mounted in a pod by kubelet is not included by the kubelet eviction manager when calculating ephemeral storage usage by a pod. If a pod writes a large amount of data to the /etc/hosts file, it could fill the storage space of the node and cause the node to fail.

- [https://github.com/Live-Hack-CVE/CVE-2020-8557](https://github.com/Live-Hack-CVE/CVE-2020-8557) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-8557.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-8557.svg)


## CVE-2020-7115
 The ClearPass Policy Manager web interface is affected by a vulnerability that leads to authentication bypass. Upon successful bypass an attacker could then execute an exploit that would allow to remote command execution in the underlying operating system. Resolution: Fixed in 6.7.13-HF, 6.8.5-HF, 6.8.6, 6.9.1 and higher.

- [https://github.com/Live-Hack-CVE/CVE-2020-7115](https://github.com/Live-Hack-CVE/CVE-2020-7115) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-7115.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-7115.svg)


## CVE-2020-7019
 In Elasticsearch before 7.9.0 and 6.8.12 a field disclosure flaw was found when running a scrolling search with Field Level Security. If a user runs the same query another more privileged user recently ran, the scrolling search can leak fields that should be hidden. This could result in an attacker gaining additional permissions against a restricted index.

- [https://github.com/Live-Hack-CVE/CVE-2020-7019](https://github.com/Live-Hack-CVE/CVE-2020-7019) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-7019.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-7019.svg)


## CVE-2020-5906
 In versions 13.1.0-13.1.3.3, 12.1.0-12.1.5.2, and 11.6.1-11.6.5.2, the BIG-IP system does not properly enforce the access controls for the scp.blacklist files. This allows Admin and Resource Admin users with Secure Copy (SCP) protocol access to read and overwrite blacklisted files via SCP.

- [https://github.com/Live-Hack-CVE/CVE-2020-5906](https://github.com/Live-Hack-CVE/CVE-2020-5906) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-5906.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-5906.svg)


## CVE-2020-5903
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, a Cross-Site Scripting (XSS) vulnerability exists in an undisclosed page of the BIG-IP Configuration utility.

- [https://github.com/Live-Hack-CVE/CVE-2020-5903](https://github.com/Live-Hack-CVE/CVE-2020-5903) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-5903.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-5903.svg)


## CVE-2020-4074
 In PrestaShop from version 1.5.0.0 and before version 1.7.6.6, the authentication system is malformed and an attacker is able to forge requests and execute admin commands. The problem is fixed in 1.7.6.6.

- [https://github.com/Live-Hack-CVE/CVE-2020-4074](https://github.com/Live-Hack-CVE/CVE-2020-4074) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-4074.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-4074.svg)


## CVE-2020-4046
 In affected versions of WordPress, users with low privileges (like contributors and authors) can use the embed block in a certain way to inject unfiltered HTML in the block editor. When affected posts are viewed by a higher privileged user, this could lead to script execution in the editor/wp-admin. This has been patched in version 5.4.2, along with all the previously affected versions via a minor release (5.3.4, 5.2.7, 5.1.6, 5.0.10, 4.9.15, 4.8.14, 4.7.18, 4.6.19, 4.5.22, 4.4.23, 4.3.24, 4.2.28, 4.1.31, 4.0.31, 3.9.32, 3.8.34, 3.7.34).

- [https://github.com/Live-Hack-CVE/CVE-2020-4046](https://github.com/Live-Hack-CVE/CVE-2020-4046) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-4046.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-4046.svg)


## CVE-2020-3963
 VMware ESXi (7.0 before ESXi_7.0.0-1.20.16321839, 6.7 before ESXi670-202006401-SG and 6.5 before ESXi650-202005401-SG), Workstation (15.x before 15.5.2), and Fusion (11.x before 11.5.2) contain a use-after-free vulnerability in PVNVRAM. A malicious actor with local access to a virtual machine may be able to read privileged information contained in physical memory.

- [https://github.com/Live-Hack-CVE/CVE-2020-3963](https://github.com/Live-Hack-CVE/CVE-2020-3963) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-3963.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-3963.svg)


## CVE-2020-1983
 A use after free vulnerability in ip_reass() in ip_input.c of libslirp 4.2.0 and prior releases allows crafted packets to cause a denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2020-1983](https://github.com/Live-Hack-CVE/CVE-2020-1983) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-1983.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-1983.svg)


## CVE-2020-1751
 An out-of-bounds write vulnerability was found in glibc before 2.31 when handling signal trampolines on PowerPC. Specifically, the backtrace function did not properly check the array bounds when storing the frame address, resulting in a denial of service or potential code execution. The highest threat from this vulnerability is to system availability.

- [https://github.com/Live-Hack-CVE/CVE-2020-1751](https://github.com/Live-Hack-CVE/CVE-2020-1751) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-1751.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-1751.svg)


## CVE-2020-0093
 In exif_data_save_data_entry of exif-data.c, there is a possible out of bounds read due to a missing bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-148705132

- [https://github.com/Live-Hack-CVE/CVE-2020-13112](https://github.com/Live-Hack-CVE/CVE-2020-13112) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-13112.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-13112.svg)


## CVE-2019-25053
 A path traversal vulnerability exists in Sage FRP 1000 before November 2019. This allows remote unauthenticated attackers to access files outside of the web tree via a crafted URL.

- [https://github.com/Live-Hack-CVE/CVE-2019-25053](https://github.com/Live-Hack-CVE/CVE-2019-25053) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-25053.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-25053.svg)


## CVE-2019-19740
 Octeth Oempro 4.7 and 4.8 allow SQL injection. The parameter CampaignID in Campaign.Get is vulnerable.

- [https://github.com/Live-Hack-CVE/CVE-2019-19740](https://github.com/Live-Hack-CVE/CVE-2019-19740) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-19740.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-19740.svg)


## CVE-2019-17637
 In all versions of Eclipse Web Tools Platform through release 3.18 (2020-06), XML and DTD files referring to external entities could be exploited to send the contents of local files to a remote server when edited or validated, even when external entity resolution is disabled in the user preferences.

- [https://github.com/Live-Hack-CVE/CVE-2019-17637](https://github.com/Live-Hack-CVE/CVE-2019-17637) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-17637.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-17637.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/Pichuuuuu/verbose_happiness](https://github.com/Pichuuuuu/verbose_happiness) :  ![starts](https://img.shields.io/github/stars/Pichuuuuu/verbose_happiness.svg) ![forks](https://img.shields.io/github/forks/Pichuuuuu/verbose_happiness.svg)


## CVE-2019-13033
 In CISOfy Lynis 2.x through 2.7.5, the license key can be obtained by looking at the process list when a data upload is being performed. This license can be used to upload data to a central Lynis server. Although no data can be extracted by knowing the license key, it may be possible to upload the data of additional scans.

- [https://github.com/Live-Hack-CVE/CVE-2019-13033](https://github.com/Live-Hack-CVE/CVE-2019-13033) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-13033.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-13033.svg)


## CVE-2019-11165
 Improper conditions check in the Linux kernel driver for the Intel(R) FPGA SDK for OpenCL(TM) Pro Edition before version 19.4 may allow an authenticated user to potentially enable denial of service via local access.

- [https://github.com/Live-Hack-CVE/CVE-2019-11165](https://github.com/Live-Hack-CVE/CVE-2019-11165) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-11165.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-11165.svg)


## CVE-2019-10695
 When using the cd4pe::root_configuration task to configure a Continuous Delivery for PE installation, the root user&#8217;s username and password were exposed in the job&#8217;s Job Details pane in the PE console. These issues have been resolved in version 1.2.1 of the puppetlabs/cd4pe module.

- [https://github.com/Live-Hack-CVE/CVE-2019-10695](https://github.com/Live-Hack-CVE/CVE-2019-10695) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-10695.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-10695.svg)


## CVE-2018-6703
 Use After Free in Remote logging (which is disabled by default) in McAfee McAfee Agent (MA) 5.x prior to 5.6.0 allows remote unauthenticated attackers to cause a Denial of Service and potentially a remote code execution via a specially crafted HTTP header sent to the logging service.

- [https://github.com/Live-Hack-CVE/CVE-2018-6703](https://github.com/Live-Hack-CVE/CVE-2018-6703) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-6703.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-6703.svg)


## CVE-2018-6700
 DLL Search Order Hijacking vulnerability in Microsoft Windows Client in McAfee True Key (TK) before 5.1.165 allows local users to execute arbitrary code via specially crafted malware.

- [https://github.com/Live-Hack-CVE/CVE-2018-6700](https://github.com/Live-Hack-CVE/CVE-2018-6700) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-6700.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-6700.svg)


## CVE-2018-6693
 An unprivileged user can delete arbitrary files on a Linux system running ENSLTP 10.5.1, 10.5.0, and 10.2.3 Hotfix 1246778 and earlier. By exploiting a time of check to time of use (TOCTOU) race condition during a specific scanning sequence, the unprivileged user is able to perform a privilege escalation to delete arbitrary files.

- [https://github.com/Live-Hack-CVE/CVE-2018-6693](https://github.com/Live-Hack-CVE/CVE-2018-6693) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-6693.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-6693.svg)


## CVE-2018-6692
 Stack-based Buffer Overflow vulnerability in libUPnPHndlr.so in Belkin Wemo Insight Smart Plug allows remote attackers to bypass local security protection via a crafted HTTP post packet.

- [https://github.com/Live-Hack-CVE/CVE-2018-6692](https://github.com/Live-Hack-CVE/CVE-2018-6692) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-6692.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-6692.svg)


## CVE-2018-6690
 Accessing, modifying, or executing executable files vulnerability in Microsoft Windows client in McAfee Application and Change Control (MACC) 8.0.0 Hotfix 4 and earlier allows authenticated users to execute arbitrary code via file transfer from external system.

- [https://github.com/Live-Hack-CVE/CVE-2018-6690](https://github.com/Live-Hack-CVE/CVE-2018-6690) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-6690.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-6690.svg)


## CVE-2018-6689
 Authentication Bypass vulnerability in McAfee Data Loss Prevention Endpoint (DLPe) 10.0.x earlier than 10.0.510, and 11.0.x earlier than 11.0.600 allows attackers to bypass local security protection via specific conditions.

- [https://github.com/Live-Hack-CVE/CVE-2018-6689](https://github.com/Live-Hack-CVE/CVE-2018-6689) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-6689.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-6689.svg)


## CVE-2018-6686
 Authentication Bypass vulnerability in TPM autoboot in McAfee Drive Encryption (MDE) 7.1.0 and above allows physically proximate attackers to bypass local security protection via specific set of circumstances.

- [https://github.com/Live-Hack-CVE/CVE-2018-6686](https://github.com/Live-Hack-CVE/CVE-2018-6686) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-6686.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-6686.svg)


## CVE-2018-6677
 Directory Traversal vulnerability in the administrative user interface in McAfee Web Gateway (MWG) MWG 7.8.1.x allows authenticated administrator users to gain elevated privileges via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2018-6677](https://github.com/Live-Hack-CVE/CVE-2018-6677) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-6677.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-6677.svg)


## CVE-2018-6590
 CA API Developer Portal 4.x, prior to v4.2.5.3 and v4.2.7.1, has an unspecified reflected cross-site scripting vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-6590](https://github.com/Live-Hack-CVE/CVE-2018-6590) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-6590.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-6590.svg)


## CVE-2018-4920
 Adobe Flash Player versions 28.0.0.161 and earlier have an exploitable type confusion vulnerability. Successful exploitation could lead to arbitrary code execution in the context of the current user.

- [https://github.com/Live-Hack-CVE/CVE-2018-4920](https://github.com/Live-Hack-CVE/CVE-2018-4920) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-4920.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-4920.svg)


## CVE-2017-14448
 An exploitable code execution vulnerability exists in the XCF image rendering functionality of SDL2_image-2.0.2. A specially crafted XCF image can cause a heap overflow resulting in code execution. An attacker can display a specially crafted image to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2017-14448](https://github.com/Live-Hack-CVE/CVE-2017-14448) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-14448.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-14448.svg)


## CVE-2017-9476
 The Comcast firmware on Cisco DPC3939 (firmware version dpc3939-P20-18-v303r20421733-160420a-CMCST); Cisco DPC3939 (firmware version dpc3939-P20-18-v303r20421746-170221a-CMCST); and Arris TG1682G (eMTA&amp;DOCSIS version 10.0.132.SIP.PC20.CT, software version TG1682_2.2p7s2_PROD_sey) devices makes it easy for remote attackers to determine the hidden SSID and passphrase for a Home Security Wi-Fi network.

- [https://github.com/wiire-a/CVE-2017-9476](https://github.com/wiire-a/CVE-2017-9476) :  ![starts](https://img.shields.io/github/stars/wiire-a/CVE-2017-9476.svg) ![forks](https://img.shields.io/github/forks/wiire-a/CVE-2017-9476.svg)


## CVE-2017-2820
 An exploitable integer overflow vulnerability exists in the JPEG 2000 image parsing functionality of freedesktop.org Poppler 0.53.0. A specially crafted PDF file can lead to an integer overflow causing out of bounds memory overwrite on the heap resulting in potential arbitrary code execution. To trigger this vulnerability, a victim must open the malicious PDF in an application using this library.

- [https://github.com/Live-Hack-CVE/CVE-2017-2820](https://github.com/Live-Hack-CVE/CVE-2017-2820) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-2820.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-2820.svg)


## CVE-2017-2788
 A buffer overflows exists in the psnotifyd application of the Pharos PopUp printer client version 9.0. A specially crafted packet can be sent to the victim's computer and can lead to a heap based buffer overflow resulting in potential remote code execution. This client is always listening, has root privileges, and requires no user interaction to exploit.

- [https://github.com/Live-Hack-CVE/CVE-2017-2788](https://github.com/Live-Hack-CVE/CVE-2017-2788) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-2788.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-2788.svg)


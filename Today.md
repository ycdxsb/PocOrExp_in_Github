# Update 2023-01-13
## CVE-2023-22959
 WebChess through 0.9.0 and 1.0.0.rc2 allows SQL injection: mainmenu.php, chess.php, and opponentspassword.php (txtFirstName, txtLastName).

- [https://github.com/Live-Hack-CVE/CVE-2023-22959](https://github.com/Live-Hack-CVE/CVE-2023-22959) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22959.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22959.svg)


## CVE-2023-22958
 The Syracom Secure Login plugin before 3.1.1.0 for Jira may allow spoofing of 2FA PIN validation via the plugins/servlet/twofactor/public/pinvalidation target parameter.

- [https://github.com/Live-Hack-CVE/CVE-2023-22958](https://github.com/Live-Hack-CVE/CVE-2023-22958) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22958.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22958.svg)


## CVE-2023-22952
 In SugarCRM before 12.0. Hotfix 91155, a crafted request can inject custom PHP code through the EmailTemplates because of missing input validation.

- [https://github.com/Live-Hack-CVE/CVE-2023-22952](https://github.com/Live-Hack-CVE/CVE-2023-22952) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22952.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22952.svg)


## CVE-2023-22885
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2023-22885](https://github.com/Live-Hack-CVE/CVE-2023-22885) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22885.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22885.svg)


## CVE-2023-22622
 WordPress through 6.1.1 depends on unpredictable client visits to cause wp-cron.php execution and the resulting security updates, and the source code describes &quot;the scenario where a site may not receive enough visits to execute scheduled tasks in a timely manner,&quot; but neither the installation guide nor the security guide mentions this default behavior, or alerts the user about security risks on installations with very few visits.

- [https://github.com/Live-Hack-CVE/CVE-2023-22622](https://github.com/Live-Hack-CVE/CVE-2023-22622) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22622.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22622.svg)


## CVE-2023-22492
 ZITADEL is a combination of Auth0 and Keycloak. RefreshTokens is an OAuth 2.0 feature that allows applications to retrieve new access tokens and refresh the user's session without the need for interacting with a UI. RefreshTokens were not invalidated when a user was locked or deactivated. The deactivated or locked user was able to obtain a valid access token only through a refresh token grant. When the locked or deactivated user&#8217;s session was already terminated (&#8220;logged out&#8221;) then it was not possible to create a new session. Renewal of access token through a refresh token grant is limited to the configured amount of time (RefreshTokenExpiration). As a workaround, ensure the RefreshTokenExpiration in the OIDC settings of your instance is set according to your security requirements. This issue has been patched in versions 2.17.3 and 2.16.4.

- [https://github.com/Live-Hack-CVE/CVE-2023-22492](https://github.com/Live-Hack-CVE/CVE-2023-22492) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22492.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22492.svg)


## CVE-2023-22487
 Flarum is a forum software for building communities. Using the mentions feature provided by the flarum/mentions extension, users can mention any post ID on the forum with the special `@&quot;&lt;username&gt;&quot;#p&lt;id&gt;` syntax. The following behavior never changes no matter if the actor should be able to read the mentioned post or not: A URL to the mentioned post is inserted into the actor post HTML, leaking its discussion ID and post number. The `mentionsPosts` relationship included in the `POST /api/posts` and `PATCH /api/posts/&lt;id&gt;` JSON responses leaks the full JSON:API payload of all mentioned posts without any access control. This includes the content, date, number and attributes added by other extensions. An attacker only needs the ability to create new posts on the forum to exploit the vulnerability. This works even if new posts require approval. If they have the ability to edit posts, the attack can be performed even more discreetly by using a single post to scan any size of database and hiding the attack post content afterward. The attack allows the leaking of all posts in the forum database, including posts awaiting approval, posts in tags the user has no access to, and private discussions created by other extensions like FriendsOfFlarum Byobu. This also includes non-comment posts like tag changes or renaming events. The discussion payload is not leaked but using the mention HTML payload it's possible to extract the discussion ID of all posts and combine all posts back together into their original discussions even if the discussion title remains unknown. All Flarum versions prior to 1.6.3 are affected. The vulnerability has been fixed and published as flarum/core v1.6.3. As a workaround, user can disable the mentions extension.

- [https://github.com/Live-Hack-CVE/CVE-2023-22487](https://github.com/Live-Hack-CVE/CVE-2023-22487) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22487.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22487.svg)


## CVE-2023-22464
 ViewVC is a browser interface for CVS and Subversion version control repositories. Versions prior to 1.2.3 and 1.1.30 are vulnerable to cross-site scripting. The impact of this vulnerability is mitigated by the need for an attacker to have commit privileges to a Subversion repository exposed by an otherwise trusted ViewVC instance. The attack vector involves files with unsafe names (names that, when embedded into an HTML stream, would cause the browser to run unwanted code), which themselves can be challenging to create. Users should update to at least version 1.2.3 (if they are using a 1.2.x version of ViewVC) or 1.1.30 (if they are using a 1.1.x version). ViewVC 1.0.x is no longer supported, so users of that release lineage should implement one of the following workarounds. Users can edit their ViewVC EZT view templates to manually HTML-escape changed path &quot;copyfrom paths&quot; during rendering. Locate in your template set's `revision.ezt` file references to those changed paths, and wrap them with `[format &quot;html&quot;]` and `[end]`. For most users, that means that references to `[changes.copy_path]` will become `[format &quot;html&quot;][changes.copy_path][end]`. (This workaround should be reverted after upgrading to a patched version of ViewVC, else &quot;copyfrom path&quot; names will be doubly escaped.)

- [https://github.com/Live-Hack-CVE/CVE-2023-22464](https://github.com/Live-Hack-CVE/CVE-2023-22464) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22464.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22464.svg)


## CVE-2023-21752
 Windows Backup Service Elevation of Privilege Vulnerability.

- [https://github.com/Wh04m1001/CVE-2023-21752](https://github.com/Wh04m1001/CVE-2023-21752) :  ![starts](https://img.shields.io/github/stars/Wh04m1001/CVE-2023-21752.svg) ![forks](https://img.shields.io/github/forks/Wh04m1001/CVE-2023-21752.svg)


## CVE-2023-20532
 Insufficient input validation in the SMU may allow an attacker to improperly lock resources, potentially resulting in a denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2023-20532](https://github.com/Live-Hack-CVE/CVE-2023-20532) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20532.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20532.svg)


## CVE-2023-20531
 Insufficient bound checks in the SMU may allow an attacker to update the SRAM from/to address space to an invalid value potentially resulting in a denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2023-20531](https://github.com/Live-Hack-CVE/CVE-2023-20531) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20531.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20531.svg)


## CVE-2023-20530
 Insufficient input validation of BIOS mailbox messages in SMU may result in out-of-bounds memory reads potentially resulting in a denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2023-20530](https://github.com/Live-Hack-CVE/CVE-2023-20530) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20530.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20530.svg)


## CVE-2023-20529
 Insufficient bound checks in the SMU may allow an attacker to update the from/to address space to an invalid value potentially resulting in a denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2023-20529](https://github.com/Live-Hack-CVE/CVE-2023-20529) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20529.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20529.svg)


## CVE-2023-20528
 Insufficient input validation in the SMU may allow a physical attacker to exfiltrate SMU memory contents over the I2C bus potentially leading to a loss of confidentiality.

- [https://github.com/Live-Hack-CVE/CVE-2023-20528](https://github.com/Live-Hack-CVE/CVE-2023-20528) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20528.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20528.svg)


## CVE-2023-20527
 Improper syscall input validation in the ASP Bootloader may allow a privileged attacker to read memory out-of-bounds, potentially leading to a denial-of-service.

- [https://github.com/Live-Hack-CVE/CVE-2023-20527](https://github.com/Live-Hack-CVE/CVE-2023-20527) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20527.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20527.svg)


## CVE-2023-20525
 Insufficient syscall input validation in the ASP Bootloader may allow a privileged attacker to read memory outside the bounds of a mapped register potentially leading to a denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2023-20525](https://github.com/Live-Hack-CVE/CVE-2023-20525) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20525.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20525.svg)


## CVE-2023-20523
 TOCTOU in the ASP may allow a physical attacker to write beyond the buffer bounds, potentially leading to a loss of integrity or denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2023-20523](https://github.com/Live-Hack-CVE/CVE-2023-20523) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20523.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20523.svg)


## CVE-2023-0161
 ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.

- [https://github.com/Live-Hack-CVE/CVE-2023-0161](https://github.com/Live-Hack-CVE/CVE-2023-0161) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0161.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0161.svg)


## CVE-2023-0110
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.

- [https://github.com/emotest1/cve_2023_0110](https://github.com/emotest1/cve_2023_0110) :  ![starts](https://img.shields.io/github/stars/emotest1/cve_2023_0110.svg) ![forks](https://img.shields.io/github/forks/emotest1/cve_2023_0110.svg)


## CVE-2023-0057
 Improper Restriction of Rendered UI Layers or Frames in GitHub repository pyload/pyload prior to 0.5.0b3.dev33.

- [https://github.com/Live-Hack-CVE/CVE-2023-0057](https://github.com/Live-Hack-CVE/CVE-2023-0057) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0057.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0057.svg)


## CVE-2022-47866
 Lead management system v1.0 is vulnerable to SQL Injection via the id parameter in removeBrand.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-47866](https://github.com/Live-Hack-CVE/CVE-2022-47866) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47866.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47866.svg)


## CVE-2022-47865
 Lead Management System v1.0 is vulnerable to SQL Injection via the id parameter in removeOrder.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-47865](https://github.com/Live-Hack-CVE/CVE-2022-47865) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47865.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47865.svg)


## CVE-2022-47095
 GPAC MP4box 2.1-DEV-rev574-g9d5bb184b is vulnerable to Buffer overflow in hevc_parse_vps_extension function of media_tools/av_parsers.c

- [https://github.com/Live-Hack-CVE/CVE-2022-47095](https://github.com/Live-Hack-CVE/CVE-2022-47095) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47095.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47095.svg)


## CVE-2022-47094
 GPAC MP4box 2.1-DEV-rev574-g9d5bb184b is vulnerable to Null pointer dereference via filters/dmx_m2ts.c:343 in m2tsdmx_declare_pid

- [https://github.com/Live-Hack-CVE/CVE-2022-47094](https://github.com/Live-Hack-CVE/CVE-2022-47094) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47094.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47094.svg)


## CVE-2022-47087
 GPAC MP4box 2.1-DEV-rev574-g9d5bb184b has a Buffer overflow in gf_vvc_read_pps_bs_internal function of media_tools/av_parsers.c

- [https://github.com/Live-Hack-CVE/CVE-2022-47087](https://github.com/Live-Hack-CVE/CVE-2022-47087) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47087.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47087.svg)


## CVE-2022-46689
 A race condition was addressed with additional validation. This issue is fixed in tvOS 16.2, macOS Monterey 12.6.2, macOS Ventura 13.1, macOS Big Sur 11.7.2, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.2 and iPadOS 16.2, watchOS 9.2. An app may be able to execute arbitrary code with kernel privileges.

- [https://github.com/staturnzz/sw1tch](https://github.com/staturnzz/sw1tch) :  ![starts](https://img.shields.io/github/stars/staturnzz/sw1tch.svg) ![forks](https://img.shields.io/github/forks/staturnzz/sw1tch.svg)


## CVE-2022-46485
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/WodenSec/CVE-2022-46485](https://github.com/WodenSec/CVE-2022-46485) :  ![starts](https://img.shields.io/github/stars/WodenSec/CVE-2022-46485.svg) ![forks](https://img.shields.io/github/forks/WodenSec/CVE-2022-46485.svg)


## CVE-2022-46484
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/WodenSec/CVE-2022-46484](https://github.com/WodenSec/CVE-2022-46484) :  ![starts](https://img.shields.io/github/stars/WodenSec/CVE-2022-46484.svg) ![forks](https://img.shields.io/github/forks/WodenSec/CVE-2022-46484.svg)


## CVE-2022-46175
 JSON5 is an extension to the popular JSON file format that aims to be easier to write and maintain by hand (e.g. for config files). The `parse` method of the JSON5 library before and including versions 1.0.1 and 2.2.1 does not restrict parsing of keys named `__proto__`, allowing specially crafted strings to pollute the prototype of the resulting object. This vulnerability pollutes the prototype of the object returned by `JSON5.parse` and not the global Object prototype, which is the commonly understood definition of Prototype Pollution. However, polluting the prototype of a single object can have significant security impact for an application if the object is later used in trusted operations. This vulnerability could allow an attacker to set arbitrary and unexpected keys on the object returned from `JSON5.parse`. The actual impact will depend on how applications utilize the returned object and how they filter unwanted keys, but could include denial of service, cross-site scripting, elevation of privilege, and in extreme cases, remote code execution. `JSON5.parse` should restrict parsing of `__proto__` keys when parsing JSON strings to objects. As a point of reference, the `JSON.parse` method included in JavaScript ignores `__proto__` keys. Simply changing `JSON5.parse` to `JSON.parse` in the examples above mitigates this vulnerability. This vulnerability is patched in json5 versions 1.0.2, 2.2.2, and later.

- [https://github.com/giz-berlin/quasar-app-webpack-json5-vulnerability](https://github.com/giz-berlin/quasar-app-webpack-json5-vulnerability) :  ![starts](https://img.shields.io/github/stars/giz-berlin/quasar-app-webpack-json5-vulnerability.svg) ![forks](https://img.shields.io/github/forks/giz-berlin/quasar-app-webpack-json5-vulnerability.svg)


## CVE-2022-46174
 efs-utils is a set of Utilities for Amazon Elastic File System (EFS). A potential race condition issue exists within the Amazon EFS mount helper in efs-utils versions v1.34.3 and below. When using TLS to mount file systems, the mount helper allocates a local port for stunnel to receive NFS connections prior to applying the TLS tunnel. In affected versions, concurrent mount operations can allocate the same local port, leading to either failed mount operations or an inappropriate mapping from an EFS customer&#8217;s local mount points to that customer&#8217;s EFS file systems. This issue is patched in version v1.34.4. There is no recommended work around. We recommend affected users update the installed version of efs-utils to v1.34.4 or later.

- [https://github.com/Live-Hack-CVE/CVE-2022-46174](https://github.com/Live-Hack-CVE/CVE-2022-46174) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46174.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46174.svg)


## CVE-2022-44535
 A vulnerability in the Aruba EdgeConnect Enterprise Orchestrator web-based management interface allows remote low-privileged authenticated users to escalate their privileges to those of an administrative user. A successful exploit could allow an attacker to achieve administrative privilege on the web-management interface leading to complete system compromise in Aruba EdgeConnect Enterprise Orchestration Software version(s): Aruba EdgeConnect Enterprise Orchestrator (on-premises), Aruba EdgeConnect Enterprise Orchestrator-as-a-Service, Aruba EdgeConnect Enterprise Orchestrator-SP and Aruba EdgeConnect Enterprise Orchestrator Global Enterprise Tenant Orchestrators - Orchestrator 9.2.1.40179 and below, - Orchestrator 9.1.4.40436 and below, - Orchestrator 9.0.7.40110 and below, - Orchestrator 8.10.23.40015 and below, - Any older branches of Orchestrator not specifically mentioned.

- [https://github.com/Live-Hack-CVE/CVE-2022-44535](https://github.com/Live-Hack-CVE/CVE-2022-44535) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44535.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44535.svg)


## CVE-2022-44534
 A vulnerability in the Aruba EdgeConnect Enterprise Orchestrator web-based management interface allows remote authenticated users to run arbitrary commands on the underlying host. A successful exploit could allow an attacker to execute arbitrary commands as root on the underlying operating system leading to complete system compromise in Aruba EdgeConnect Enterprise Orchestration Software version(s): Aruba EdgeConnect Enterprise Orchestrator (on-premises), Aruba EdgeConnect Enterprise Orchestrator-as-a-Service, Aruba EdgeConnect Enterprise Orchestrator-SP and Aruba EdgeConnect Enterprise Orchestrator Global Enterprise Tenant Orchestrators - Orchestrator 9.2.1.40179 and below, - Orchestrator 9.1.4.40436 and below, - Orchestrator 9.0.7.40110 and below, - Orchestrator 8.10.23.40015 and below, - Any older branches of Orchestrator not specifically mentioned.

- [https://github.com/Live-Hack-CVE/CVE-2022-44534](https://github.com/Live-Hack-CVE/CVE-2022-44534) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44534.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44534.svg)


## CVE-2022-43540
 A vulnerability exists in the ClearPass OnGuard macOS agent that allows for an attacker with local macOS instance access to potentially obtain sensitive information. A successful exploit could allow an attacker to retrieve information that is of a sensitive nature in Aruba ClearPass Policy Manager version(s): ClearPass Policy Manager 6.10.x: 6.10.7 and below and ClearPass Policy Manager 6.9.x: 6.9.12 and below.

- [https://github.com/Live-Hack-CVE/CVE-2022-43540](https://github.com/Live-Hack-CVE/CVE-2022-43540) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43540.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43540.svg)


## CVE-2022-43539
 A vulnerability exists in the ClearPass Policy Manager cluster communications that allow for an attacker in a privileged network position to potentially obtain sensitive information. A successful exploit could allow an attacker to retrieve information that allows for unauthorized actions as a privileged user on the ClearPass Policy Manager cluster in Aruba ClearPass Policy Manager version(s): ClearPass Policy Manager 6.10.x: 6.10.7 and below and ClearPass Policy Manager 6.9.x: 6.9.12 and below.

- [https://github.com/Live-Hack-CVE/CVE-2022-43539](https://github.com/Live-Hack-CVE/CVE-2022-43539) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43539.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43539.svg)


## CVE-2022-43538
 Vulnerabilities in the ClearPass Policy Manager web-based management interface allow remote authenticated users to run arbitrary commands on the underlying host. Successful exploits could allow an attacker to execute arbitrary commands as root on the underlying operating system leading to complete system compromise in Aruba ClearPass Policy Manager version(s): ClearPass Policy Manager 6.10.x: 6.10.7 and below and ClearPass Policy Manager 6.9.x: 6.9.12 and below.

- [https://github.com/Live-Hack-CVE/CVE-2022-43538](https://github.com/Live-Hack-CVE/CVE-2022-43538) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43538.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43538.svg)


## CVE-2022-43537
 Vulnerabilities in the ClearPass Policy Manager web-based management interface allow remote authenticated users to run arbitrary commands on the underlying host. Successful exploits could allow an attacker to execute arbitrary commands as root on the underlying operating system leading to complete system compromise in Aruba ClearPass Policy Manager version(s): ClearPass Policy Manager 6.10.x: 6.10.7 and below and ClearPass Policy Manager 6.9.x: 6.9.12 and below.

- [https://github.com/Live-Hack-CVE/CVE-2022-43537](https://github.com/Live-Hack-CVE/CVE-2022-43537) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43537.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43537.svg)


## CVE-2022-43536
 Vulnerabilities in the ClearPass Policy Manager web-based management interface allow remote authenticated users to run arbitrary commands on the underlying host. Successful exploits could allow an attacker to execute arbitrary commands as root on the underlying operating system leading to complete system compromise in Aruba ClearPass Policy Manager version(s): ClearPass Policy Manager 6.10.x: 6.10.7 and below and ClearPass Policy Manager 6.9.x: 6.9.12 and below.

- [https://github.com/Live-Hack-CVE/CVE-2022-43536](https://github.com/Live-Hack-CVE/CVE-2022-43536) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43536.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43536.svg)


## CVE-2022-43535
 A vulnerability in the ClearPass OnGuard Windows agent could allow malicious users on a Windows instance to elevate their user privileges. A successful exploit could allow these users to execute arbitrary code with NT AUTHORITY\SYSTEM level privileges on the Windows instance in Aruba ClearPass Policy Manager version(s): ClearPass Policy Manager 6.10.x: 6.10.7 and below and ClearPass Policy Manager 6.9.x: 6.9.12 and below.

- [https://github.com/Live-Hack-CVE/CVE-2022-43535](https://github.com/Live-Hack-CVE/CVE-2022-43535) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43535.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43535.svg)


## CVE-2022-43534
 A vulnerability in the ClearPass OnGuard Linux agent could allow malicious users on a Linux instance to elevate their user privileges. A successful exploit could allow these users to execute arbitrary code with root level privileges on the Linux instance in Aruba ClearPass Policy Manager version(s): ClearPass Policy Manager 6.10.x: 6.10.7 and below and ClearPass Policy Manager 6.9.x: 6.9.12 and below.

- [https://github.com/Live-Hack-CVE/CVE-2022-43534](https://github.com/Live-Hack-CVE/CVE-2022-43534) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43534.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43534.svg)


## CVE-2022-43530
 Vulnerabilities in the web-based management interface of ClearPass Policy Manager could allow an authenticated remote attacker to conduct SQL injection attacks against the ClearPass Policy Manager instance. An attacker could exploit these vulnerabilities to obtain and modify sensitive information in the underlying database potentially leading to complete compromise of the ClearPass Policy Manager cluster in Aruba ClearPass Policy Manager version(s): ClearPass Policy Manager 6.10.x: 6.10.7 and below and ClearPass Policy Manager 6.9.x: 6.9.12 and below.

- [https://github.com/Live-Hack-CVE/CVE-2022-43530](https://github.com/Live-Hack-CVE/CVE-2022-43530) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43530.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43530.svg)


## CVE-2022-43528
 Under certain configurations, an attacker can login to Aruba EdgeConnect Enterprise Orchestrator without supplying a multi-factor authentication code. Successful exploitation allows an attacker to login using only a username and password and successfully bypass MFA requirements in Aruba EdgeConnect Enterprise Orchestration Software version(s): Aruba EdgeConnect Enterprise Orchestrator (on-premises), Aruba EdgeConnect Enterprise Orchestrator-as-a-Service, Aruba EdgeConnect Enterprise Orchestrator-SP and Aruba EdgeConnect Enterprise Orchestrator Global Enterprise Tenant Orchestrators - Orchestrator 9.2.1.40179 and below, - Orchestrator 9.1.4.40436 and below, - Orchestrator 9.0.7.40110 and below, - Orchestrator 8.10.23.40015 and below, - Any older branches of Orchestrator not specifically mentioned.

- [https://github.com/Live-Hack-CVE/CVE-2022-43528](https://github.com/Live-Hack-CVE/CVE-2022-43528) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43528.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43528.svg)


## CVE-2022-43527
 Multiple vulnerabilities within the web-based management interface of Aruba EdgeConnect Enterprise Orchestrator could allow a remote attacker to conduct a reflected cross-site scripting (XSS) attack against a user of the interface. A successful exploit could allow an attacker to execute arbitrary script code in a victim's browser in the context of the affected interface in Aruba EdgeConnect Enterprise Orchestration Software version(s): Aruba EdgeConnect Enterprise Orchestrator (on-premises), Aruba EdgeConnect Enterprise Orchestrator-as-a-Service, Aruba EdgeConnect Enterprise Orchestrator-SP and Aruba EdgeConnect Enterprise Orchestrator Global Enterprise Tenant Orchestrators - Orchestrator 9.2.1.40179 and below, - Orchestrator 9.1.4.40436 and below, - Orchestrator 9.0.7.40110 and below, - Orchestrator 8.10.23.40015 and below, - Any older branches of Orchestrator not specifically mentioned.

- [https://github.com/Live-Hack-CVE/CVE-2022-43527](https://github.com/Live-Hack-CVE/CVE-2022-43527) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43527.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43527.svg)


## CVE-2022-43523
 Multiple vulnerabilities in the web-based management interface of Aruba EdgeConnect Enterprise Orchestrator could allow an authenticated remote attacker to conduct SQL injection attacks against the Aruba EdgeConnect Enterprise Orchestrator instance. An attacker could exploit these vulnerabilities to obtain and modify sensitive information in the underlying database potentially leading to complete compromise of the Aruba EdgeConnect Enterprise Orchestrator host in Aruba EdgeConnect Enterprise Orchestration Software version(s): Aruba EdgeConnect Enterprise Orchestrator (on-premises), Aruba EdgeConnect Enterprise Orchestrator-as-a-Service, Aruba EdgeConnect Enterprise Orchestrator-SP and Aruba EdgeConnect Enterprise Orchestrator Global Enterprise Tenant Orchestrators - Orchestrator 9.2.1.40179 and below, - Orchestrator 9.1.4.40436 and below, - Orchestrator 9.0.7.40110 and below, - Orchestrator 8.10.23.40015 and below, - Any older branches of Orchestrator not specifically mentioned.

- [https://github.com/Live-Hack-CVE/CVE-2022-43523](https://github.com/Live-Hack-CVE/CVE-2022-43523) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43523.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43523.svg)


## CVE-2022-43521
 Multiple vulnerabilities in the web-based management interface of Aruba EdgeConnect Enterprise Orchestrator could allow an authenticated remote attacker to conduct SQL injection attacks against the Aruba EdgeConnect Enterprise Orchestrator instance. An attacker could exploit these vulnerabilities to obtain and modify sensitive information in the underlying database potentially leading to complete compromise of the Aruba EdgeConnect Enterprise Orchestrator host in Aruba EdgeConnect Enterprise Orchestration Software version(s): Aruba EdgeConnect Enterprise Orchestrator (on-premises), Aruba EdgeConnect Enterprise Orchestrator-as-a-Service, Aruba EdgeConnect Enterprise Orchestrator-SP and Aruba EdgeConnect Enterprise Orchestrator Global Enterprise Tenant Orchestrators - Orchestrator 9.2.1.40179 and below, - Orchestrator 9.1.4.40436 and below, - Orchestrator 9.0.7.40110 and below, - Orchestrator 8.10.23.40015 and below, - Any older branches of Orchestrator not specifically mentioned.

- [https://github.com/Live-Hack-CVE/CVE-2022-43521](https://github.com/Live-Hack-CVE/CVE-2022-43521) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43521.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43521.svg)


## CVE-2022-43520
 Multiple vulnerabilities in the web-based management interface of Aruba EdgeConnect Enterprise Orchestrator could allow an authenticated remote attacker to conduct SQL injection attacks against the Aruba EdgeConnect Enterprise Orchestrator instance. An attacker could exploit these vulnerabilities to obtain and modify sensitive information in the underlying database potentially leading to complete compromise of the Aruba EdgeConnect Enterprise Orchestrator host in Aruba EdgeConnect Enterprise Orchestration Software version(s): Aruba EdgeConnect Enterprise Orchestrator (on-premises), Aruba EdgeConnect Enterprise Orchestrator-as-a-Service, Aruba EdgeConnect Enterprise Orchestrator-SP and Aruba EdgeConnect Enterprise Orchestrator Global Enterprise Tenant Orchestrators - Orchestrator 9.2.1.40179 and below, - Orchestrator 9.1.4.40436 and below, - Orchestrator 9.0.7.40110 and below, - Orchestrator 8.10.23.40015 and below, - Any older branches of Orchestrator not specifically mentioned.

- [https://github.com/Live-Hack-CVE/CVE-2022-43520](https://github.com/Live-Hack-CVE/CVE-2022-43520) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43520.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43520.svg)


## CVE-2022-42967
 Caret is vulnerable to an XSS attack when the user opens a crafted Markdown file when preview mode is enabled. This directly leads to client-side code execution.

- [https://github.com/Live-Hack-CVE/CVE-2022-42967](https://github.com/Live-Hack-CVE/CVE-2022-42967) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42967.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42967.svg)


## CVE-2022-42264
 NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where an unprivileged regular user can cause the use of an out-of-range pointer offset, which may lead to data tampering, data loss, information disclosure, or denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2022-42264](https://github.com/Live-Hack-CVE/CVE-2022-42264) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42264.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42264.svg)


## CVE-2022-42263
 NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an Integer overflow may lead to denial of service or information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2022-42263](https://github.com/Live-Hack-CVE/CVE-2022-42263) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42263.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42263.svg)


## CVE-2022-42262
 NVIDIA vGPU software contains a vulnerability in the Virtual GPU Manager (vGPU plugin), where an input index is not validated, which may lead to buffer overrun, which in turn may cause data tampering, information disclosure, or denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2022-42262](https://github.com/Live-Hack-CVE/CVE-2022-42262) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42262.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42262.svg)


## CVE-2022-42261
 NVIDIA vGPU software contains a vulnerability in the Virtual GPU Manager (vGPU plugin), where an input index is not validated, which may lead to buffer overrun, which in turn may cause data tampering, information disclosure, or denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2022-42261](https://github.com/Live-Hack-CVE/CVE-2022-42261) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42261.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42261.svg)


## CVE-2022-42260
 NVIDIA vGPU Display Driver for Linux guest contains a vulnerability in a D-Bus configuration file, where an unauthorized user in the guest VM can impact protected D-Bus endpoints, which may lead to code execution, denial of service, escalation of privileges, information disclosure, or data tampering.

- [https://github.com/Live-Hack-CVE/CVE-2022-42260](https://github.com/Live-Hack-CVE/CVE-2022-42260) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42260.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42260.svg)


## CVE-2022-42254
 NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where an out-of-bounds array access may lead to denial of service, data tampering, or information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2022-42254](https://github.com/Live-Hack-CVE/CVE-2022-42254) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-42254.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-42254.svg)


## CVE-2022-40615
 IBM Sterling Partner Engagement Manager 6.1, 6.2, and 6.2.1 is vulnerable to SQL injection. A remote attacker could send specially crafted SQL statements, which could allow the attacker to view, add, modify or delete information in the back-end database. IBM X-Force ID: 236208.

- [https://github.com/Live-Hack-CVE/CVE-2022-40615](https://github.com/Live-Hack-CVE/CVE-2022-40615) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40615.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40615.svg)


## CVE-2022-34684
 NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where an off-by-one error may lead to data tampering or information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2022-34684](https://github.com/Live-Hack-CVE/CVE-2022-34684) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34684.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34684.svg)


## CVE-2022-34441
 Dell EMC SCG Policy Manager, versions from 5.10 to 5.12, contain(s) a contain a Hard-coded Cryptographic Key vulnerability. An attacker with the knowledge of the hard-coded sensitive information, could potentially exploit this vulnerability to login to the system to gain admin privileges.

- [https://github.com/Live-Hack-CVE/CVE-2022-34441](https://github.com/Live-Hack-CVE/CVE-2022-34441) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34441.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34441.svg)


## CVE-2022-34440
 Dell EMC SCG Policy Manager, versions from 5.10 to 5.12, contain(s) a contain a Hard-coded Cryptographic Key vulnerability. An attacker with the knowledge of the hard-coded sensitive information, could potentially exploit this vulnerability to login to the system to gain admin privileges.

- [https://github.com/Live-Hack-CVE/CVE-2022-34440](https://github.com/Live-Hack-CVE/CVE-2022-34440) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34440.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34440.svg)


## CVE-2022-34335
 IBM Sterling Partner Engagement Manager 6.1.2, 6.2.0, and 6.2.1 could allow an authenticated user to exhaust server resources which could lead to a denial of service. IBM X-Force ID: 229705.

- [https://github.com/Live-Hack-CVE/CVE-2022-34335](https://github.com/Live-Hack-CVE/CVE-2022-34335) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34335.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34335.svg)


## CVE-2022-34330
 IBM Sterling B2B Integrator Standard Edition 6.0.0.0 through 6.1.2.1 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 229469.

- [https://github.com/Live-Hack-CVE/CVE-2022-34330](https://github.com/Live-Hack-CVE/CVE-2022-34330) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34330.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34330.svg)


## CVE-2022-23814
 Failure to validate addresses provided by software to BIOS commands may result in a potential loss of integrity of guest memory in a confidential compute environment.

- [https://github.com/Live-Hack-CVE/CVE-2022-23814](https://github.com/Live-Hack-CVE/CVE-2022-23814) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23814.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23814.svg)


## CVE-2022-23813
 The software interfaces to ASP and SMU may not enforce the SNP memory security policy resulting in a potential loss of integrity of guest memory in a confidential compute environment.

- [https://github.com/Live-Hack-CVE/CVE-2022-23813](https://github.com/Live-Hack-CVE/CVE-2022-23813) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-23813.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-23813.svg)


## CVE-2022-23529
 node-jsonwebtoken is a JsonWebToken implementation for node.js. For versions `&lt;= 8.5.1` of `jsonwebtoken` library, if a malicious actor has the ability to modify the key retrieval parameter (referring to the `secretOrPublicKey` argument from the readme link of the `jwt.verify()` function, they can write arbitrary files on the host machine. Users are affected only if untrusted entities are allowed to modify the key retrieval parameter of the `jwt.verify()` on a host that you control. This issue has been fixed, please update to version 9.0.0.

- [https://github.com/despossivel/CVE-2022-23529-lab](https://github.com/despossivel/CVE-2022-23529-lab) :  ![starts](https://img.shields.io/github/stars/despossivel/CVE-2022-23529-lab.svg) ![forks](https://img.shields.io/github/forks/despossivel/CVE-2022-23529-lab.svg)


## CVE-2022-4885
 A vulnerability has been found in sviehb jefferson up to 0.3 and classified as critical. This vulnerability affects unknown code of the file src/scripts/jefferson. The manipulation leads to path traversal. The attack can be initiated remotely. Upgrading to version 0.4 is able to address this issue. The name of the patch is 53b3f2fc34af0bb32afbcee29d18213e61471d87. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-218020.

- [https://github.com/Live-Hack-CVE/CVE-2022-4885](https://github.com/Live-Hack-CVE/CVE-2022-4885) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4885.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4885.svg)


## CVE-2022-4696
 There exists a use-after-free vulnerability in the Linux kernel through io_uring and the IORING_OP_SPLICE operation. If IORING_OP_SPLICE is missing the IO_WQ_WORK_FILES flag, which signals that the operation won't use current-&gt;nsproxy, so its reference counter is not increased. This assumption is not always true as calling io_splice on specific files will call the get_uts function which will use current-&gt;nsproxy leading to invalidly decreasing its reference counter later causing the use-after-free vulnerability. We recommend upgrading to version 5.10.160 or above

- [https://github.com/Live-Hack-CVE/CVE-2022-4696](https://github.com/Live-Hack-CVE/CVE-2022-4696) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4696.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4696.svg)


## CVE-2022-4610
 A vulnerability, which was classified as problematic, has been found in Click Studios Passwordstate and Passwordstate Browser Extension Chrome. Affected by this issue is some unknown functionality. The manipulation leads to risky cryptographic algorithm. Local access is required to approach this attack. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-216272.

- [https://github.com/Live-Hack-CVE/CVE-2022-4610](https://github.com/Live-Hack-CVE/CVE-2022-4610) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4610.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4610.svg)


## CVE-2022-4457
 Due to a misconfiguration in the manifest file of the WARP client for Android, it was possible to a perform a task hijacking attack. An attacker could create a malicious mobile application which could hijack legitimate app and steal potentially sensitive information when installed on the victim's device.

- [https://github.com/Live-Hack-CVE/CVE-2022-4457](https://github.com/Live-Hack-CVE/CVE-2022-4457) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4457.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4457.svg)


## CVE-2022-4428
 support_uri parameter in the WARP client local settings file (mdm.xml) lacked proper validation which allowed for privilege escalation and launching an arbitrary executable on the local machine upon clicking on the &quot;Send feedback&quot; option. An attacker with access to the local file system could use a crafted XML config file pointing to a malicious file or set a local path to the executable using Cloudflare Zero Trust Dashboard (for Zero Trust enrolled clients).

- [https://github.com/Live-Hack-CVE/CVE-2022-4428](https://github.com/Live-Hack-CVE/CVE-2022-4428) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4428.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4428.svg)


## CVE-2022-4365
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-4365](https://github.com/Live-Hack-CVE/CVE-2022-4365) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4365.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4365.svg)


## CVE-2022-4345
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-4345](https://github.com/Live-Hack-CVE/CVE-2022-4345) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4345.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4345.svg)


## CVE-2022-4344
 Memory exhaustion in the Kafka protocol dissector in Wireshark 4.0.0 to 4.0.1 and 3.6.0 to 3.6.9 allows denial of service via packet injection or crafted capture file

- [https://github.com/Live-Hack-CVE/CVE-2022-4344](https://github.com/Live-Hack-CVE/CVE-2022-4344) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4344.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4344.svg)


## CVE-2022-4342
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-4342](https://github.com/Live-Hack-CVE/CVE-2022-4342) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4342.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4342.svg)


## CVE-2022-4167
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-4167](https://github.com/Live-Hack-CVE/CVE-2022-4167) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4167.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4167.svg)


## CVE-2022-4131
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-4131](https://github.com/Live-Hack-CVE/CVE-2022-4131) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4131.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4131.svg)


## CVE-2022-4037
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Live-Hack-CVE/CVE-2022-4037](https://github.com/Live-Hack-CVE/CVE-2022-4037) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4037.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4037.svg)


## CVE-2022-4036
 The Appointment Hour Booking plugin for WordPress is vulnerable to CAPTCHA bypass in versions up to, and including, 1.3.72. This is due to the use of insufficiently strong hashing algorithm on the CAPTCHA secret that is also displayed to the user via a cookie.

- [https://github.com/Live-Hack-CVE/CVE-2022-4036](https://github.com/Live-Hack-CVE/CVE-2022-4036) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4036.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4036.svg)


## CVE-2022-4031
 The Simple:Press plugin for WordPress is vulnerable to arbitrary file modifications in versions up to, and including, 6.8 via the 'file' parameter which does not properly restrict files to be edited in the context of the plugin. This makes it possible with attackers, with high-level permissions such as an administrator, to supply paths to arbitrary files on the server that can be modified outside of the intended scope of the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2022-4031](https://github.com/Live-Hack-CVE/CVE-2022-4031) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4031.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4031.svg)


## CVE-2022-3903
 An incorrect read request flaw was found in the Infrared Transceiver USB driver in the Linux kernel. This issue occurs when a user attaches a malicious USB device. A local user could use this flaw to starve the resources, causing denial of service or potentially crashing the system.

- [https://github.com/Live-Hack-CVE/CVE-2022-3903](https://github.com/Live-Hack-CVE/CVE-2022-3903) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3903.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3903.svg)


## CVE-2022-3786
 A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed a malicious certificate or for an application to continue certificate verification despite failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server requests client authentication and a malicious client connects.

- [https://github.com/WhatTheFuzz/openssl-fuzz](https://github.com/WhatTheFuzz/openssl-fuzz) :  ![starts](https://img.shields.io/github/stars/WhatTheFuzz/openssl-fuzz.svg) ![forks](https://img.shields.io/github/forks/WhatTheFuzz/openssl-fuzz.svg)


## CVE-2022-3536
 The Role Based Pricing for WooCommerce WordPress plugin before 1.6.3 does not have authorisation and proper CSRF checks, as well as does not validate path given via user input, allowing any authenticated users like subscriber to perform PHAR deserialization attacks when they can upload a file, and a suitable gadget chain is present on the blog

- [https://github.com/Live-Hack-CVE/CVE-2022-3536](https://github.com/Live-Hack-CVE/CVE-2022-3536) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3536.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3536.svg)


## CVE-2022-3480
 A remote, unauthenticated attacker could cause a denial-of-service of PHOENIX CONTACT FL MGUARD and TC MGUARD devices below version 8.9.0 by sending a larger number of unauthenticated HTTPS connections originating from different source IP&#8217;s. Configuring firewall limits for incoming connections cannot prevent the issue.

- [https://github.com/Live-Hack-CVE/CVE-2022-3480](https://github.com/Live-Hack-CVE/CVE-2022-3480) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3480.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3480.svg)


## CVE-2022-3280
 An open redirect in GitLab CE/EE affecting all versions from 10.1 prior to 15.3.5, 15.4 prior to 15.4.4, and 15.5 prior to 15.5.2 allows an attacker to trick users into visiting a trustworthy URL and being redirected to arbitrary content.

- [https://github.com/Live-Hack-CVE/CVE-2022-3280](https://github.com/Live-Hack-CVE/CVE-2022-3280) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3280.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3280.svg)


## CVE-2022-2473
 The WP-UserOnline plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the &#8216;templates[browsingpage][text]' parameter in versions up to, and including, 2.87.6 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers with administrative capabilities and above to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. The only affects multi-site installations and installations where unfiltered_html is disabled.

- [https://github.com/Live-Hack-CVE/CVE-2022-2473](https://github.com/Live-Hack-CVE/CVE-2022-2473) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2473.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2473.svg)


## CVE-2022-2315
 Database Software Accreditation Tracking/Presentation Module product before version 2 has an unauthenticated SQL Injection vulnerability. This is fixed in version 2.

- [https://github.com/Live-Hack-CVE/CVE-2022-2315](https://github.com/Live-Hack-CVE/CVE-2022-2315) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2315.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2315.svg)


## CVE-2022-0553
 There is no check to see if slot 0 is being uploaded from the device to the host. When using encrypted images this means the unencrypted firmware can be retrieved easily.

- [https://github.com/Live-Hack-CVE/CVE-2022-0553](https://github.com/Live-Hack-CVE/CVE-2022-0553) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0553.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0553.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/Ki11i0n4ir3/CVE-2021-43798](https://github.com/Ki11i0n4ir3/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/Ki11i0n4ir3/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/Ki11i0n4ir3/CVE-2021-43798.svg)


## CVE-2021-43797
 Netty is an asynchronous event-driven network application framework for rapid development of maintainable high performance protocol servers &amp; clients. Netty prior to version 4.1.71.Final skips control chars when they are present at the beginning / end of the header name. It should instead fail fast as these are not allowed by the spec and could lead to HTTP request smuggling. Failing to do the validation might cause netty to &quot;sanitize&quot; header names before it forward these to another remote system when used as proxy. This remote system can't see the invalid usage anymore, and therefore does not do the validation itself. Users should upgrade to version 4.1.71.Final.

- [https://github.com/Live-Hack-CVE/CVE-2021-43797](https://github.com/Live-Hack-CVE/CVE-2021-43797) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-43797.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-43797.svg)


## CVE-2021-41073
 loop_rw_iter in fs/io_uring.c in the Linux kernel 5.10 through 5.14.6 allows local users to gain privileges by using IORING_OP_PROVIDE_BUFFERS to trigger a free of a kernel buffer, as demonstrated by using /proc/&lt;pid&gt;/maps for exploitation.

- [https://github.com/Live-Hack-CVE/CVE-2021-41073](https://github.com/Live-Hack-CVE/CVE-2021-41073) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-41073.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-41073.svg)


## CVE-2021-26403
 Insufficient checks in SEV may lead to a malicious hypervisor disclosing the launch secret potentially resulting in compromise of VM confidentiality.

- [https://github.com/Live-Hack-CVE/CVE-2021-26403](https://github.com/Live-Hack-CVE/CVE-2021-26403) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-26403.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-26403.svg)


## CVE-2021-26402
 Insufficient bounds checking in ASP (AMD Secure Processor) firmware while handling BIOS mailbox commands, may allow an attacker to write partially-controlled data out-of-bounds to SMM or SEV-ES regions which may lead to a potential loss of integrity and availability.

- [https://github.com/Live-Hack-CVE/CVE-2021-26402](https://github.com/Live-Hack-CVE/CVE-2021-26402) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-26402.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-26402.svg)


## CVE-2021-26398
 Insufficient input validation in SYS_KEY_DERIVE system call in a compromised user application or ABL may allow an attacker to corrupt ASP (AMD Secure Processor) OS memory which may lead to potential arbitrary code execution.

- [https://github.com/Live-Hack-CVE/CVE-2021-26398](https://github.com/Live-Hack-CVE/CVE-2021-26398) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-26398.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-26398.svg)


## CVE-2021-26396
 Insufficient validation of address mapping to IO in ASP (AMD Secure Processor) may result in a loss of memory integrity in the SNP guest.

- [https://github.com/Live-Hack-CVE/CVE-2021-26396](https://github.com/Live-Hack-CVE/CVE-2021-26396) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-26396.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-26396.svg)


## CVE-2021-26355
 Insufficient fencing and checks in System Management Unit (SMU) may result in access to invalid message port registers that could result in a potential denial-of-service.

- [https://github.com/Live-Hack-CVE/CVE-2021-26355](https://github.com/Live-Hack-CVE/CVE-2021-26355) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-26355.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-26355.svg)


## CVE-2021-26346
 Failure to validate the integer operand in ASP (AMD Secure Processor) bootloader may allow an attacker to introduce an integer overflow in the L2 directory table in SPI flash resulting in a potential denial of service.

- [https://github.com/Live-Hack-CVE/CVE-2021-26346](https://github.com/Live-Hack-CVE/CVE-2021-26346) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-26346.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-26346.svg)


## CVE-2021-26343
 Insufficient validation in ASP BIOS and DRTM commands may allow malicious supervisor x86 software to disclose the contents of sensitive memory which may result in information disclosure.

- [https://github.com/Live-Hack-CVE/CVE-2021-26343](https://github.com/Live-Hack-CVE/CVE-2021-26343) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-26343.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-26343.svg)


## CVE-2021-26328
 Failure to verify the mode of CPU execution at the time of SNP_INIT may lead to a potential loss of memory integrity for SNP guests.

- [https://github.com/Live-Hack-CVE/CVE-2021-26328](https://github.com/Live-Hack-CVE/CVE-2021-26328) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-26328.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-26328.svg)


## CVE-2021-26316
 Failure to validate the communication buffer and communication service in the BIOS may allow an attacker to tamper with the buffer resulting in potential SMM (System Management Mode) arbitrary code execution.

- [https://github.com/Live-Hack-CVE/CVE-2021-26316](https://github.com/Live-Hack-CVE/CVE-2021-26316) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-26316.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-26316.svg)


## CVE-2021-3709
 Function check_attachment_for_errors() in file data/general-hooks/ubuntu.py could be tricked into exposing private data via a constructed crash file. This issue affects: apport 2.14.1 versions prior to 2.14.1-0ubuntu3.29+esm8; 2.20.1 versions prior to 2.20.1-0ubuntu2.30+esm2; 2.20.9 versions prior to 2.20.9-0ubuntu7.26; 2.20.11 versions prior to 2.20.11-0ubuntu27.20; 2.20.11 versions prior to 2.20.11-0ubuntu65.3;

- [https://github.com/Live-Hack-CVE/CVE-2021-3709](https://github.com/Live-Hack-CVE/CVE-2021-3709) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3709.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3709.svg)


## CVE-2021-2297
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The supported version that is affected is Prior to 6.1.20. Difficult to exploit vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 5.3 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:N).

- [https://github.com/Live-Hack-CVE/CVE-2021-2297](https://github.com/Live-Hack-CVE/CVE-2021-2297) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-2297.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-2297.svg)


## CVE-2020-36650
 A vulnerability, which was classified as critical, was found in IonicaBizau node-gry up to 5.x. This affects an unknown part. The manipulation leads to command injection. Upgrading to version 6.0.0 is able to address this issue. The name of the patch is 5108446c1e23960d65e8b973f1d9486f9f9dbd6c. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-218019.

- [https://github.com/Live-Hack-CVE/CVE-2020-36650](https://github.com/Live-Hack-CVE/CVE-2020-36650) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-36650.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-36650.svg)


## CVE-2020-21601
 libde265 v1.0.4 contains a stack buffer overflow in the put_qpel_fallback function, which can be exploited via a crafted a file.

- [https://github.com/Live-Hack-CVE/CVE-2020-21601](https://github.com/Live-Hack-CVE/CVE-2020-21601) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-21601.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-21601.svg)


## CVE-2020-1631
 A vulnerability in the HTTP/HTTPS service used by J-Web, Web Authentication, Dynamic-VPN (DVPN), Firewall Authentication Pass-Through with Web-Redirect, and Zero Touch Provisioning (ZTP) allows an unauthenticated attacker to perform local file inclusion (LFI) or path traversal. Using this vulnerability, an attacker may be able to inject commands into the httpd.log, read files with 'world' readable permission file or obtain J-Web session tokens. In the case of command injection, as the HTTP service runs as user 'nobody', the impact of this command injection is limited. (CVSS score 5.3, vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) In the case of reading files with 'world' readable permission, in Junos OS 19.3R1 and above, the unauthenticated attacker would be able to read the configuration file. (CVSS score 5.9, vector CVSS:3.1/ AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N) If J-Web is enabled, the attacker could gain the same level of access of anyone actively logged into J-Web. If an administrator is logged in, the attacker could gain administrator access to J-Web. (CVSS score 8.8, vector CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H) This issue only affects Juniper Networks Junos OS devices with HTTP/HTTPS services enabled. Junos OS devices with HTTP/HTTPS services disabled are not affected. If HTTP/HTTPS services are enabled, the following command will show the httpd processes: user@device&gt; show system processes | match http 5260 - S 0:00.13 /usr/sbin/httpd-gk -N 5797 - I 0:00.10 /usr/sbin/httpd --config /jail/var/etc/httpd.conf To summarize: If HTTP/HTTPS services are disabled, there is no impact from this vulnerability. If HTTP/HTTPS services are enabled and J-Web is not in use, this vulnerability has a CVSS score of 5.9 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N). If J-Web is enabled, this vulnerability has a CVSS score of 8.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H). Juniper SIRT has received a single report of this vulnerability being exploited in the wild. Out of an abundance of caution, we are notifying customers so they can take appropriate actions. Indicators of Compromise: The /var/log/httpd.log may have indicators that commands have injected or files being accessed. The device administrator can look for these indicators by searching for the string patterns &quot;=*;*&amp;&quot; or &quot;*%3b*&amp;&quot; in /var/log/httpd.log, using the following command: user@device&gt; show log httpd.log | match &quot;=*;*&amp;|=*%3b*&amp;&quot; If this command returns any output, it might be an indication of malicious attempts or simply scanning activities. Rotated logs should also be reviewed, using the following command: user@device&gt; show log httpd.log.0.gz | match &quot;=*;*&amp;|=*%3b*&amp;&quot; user@device&gt; show log httpd.log.1.gz | match &quot;=*;*&amp;|=*%3b*&amp;&quot; Note that a skilled attacker would likely remove these entries from the local log file, thus effectively eliminating any reliable signature that the device had been attacked. This issue affects Juniper Networks Junos OS 12.3 versions prior to 12.3R12-S16; 12.3X48 versions prior to 12.3X48-D101, 12.3X48-D105; 14.1X53 versions prior to 14.1X53-D54; 15.1 versions prior to 15.1R7-S7; 15.1X49 versions prior to 15.1X49-D211, 15.1X49-D220; 16.1 versions prior to 16.1R7-S8; 17.2 versions prior to 17.2R3-S4; 17.3 versions prior to 17.3R3-S8; 17.4 versions prior to 17.4R2-S11, 17.4R3-S2; 18.1 versions prior to 18.1R3-S10; 18.2 versions prior to 18.2R2-S7, 18.2R3-S4; 18.3 versions prior to 18.3R2-S4, 18.3R3-S2; 18.4 versions prior to 18.4R1-S7, 18.4R3-S2 ; 18.4 version 18.4R2 and later versions; 19.1 versions prior to 19.1R1-S5, 19.1R3-S1; 19.1 version 19.1R2 and later versions; 19.2 versions prior to 19.2R2; 19.3 versions prior to 19.3R2-S3, 19.3R3; 19.4 versions prior to 19.4R1-S2, 19.4R2; 20.1 versions prior to 20.1R1-S1, 20.1R2.

- [https://github.com/Live-Hack-CVE/CVE-2020-1631](https://github.com/Live-Hack-CVE/CVE-2020-1631) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-1631.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-1631.svg)


## CVE-2017-16309
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd sn_exw, at 0x9d01b3d8, the value for the `d` key is copied using `strcpy` to the buffer at `$sp+0x334`.This buffer is 100 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16309](https://github.com/Live-Hack-CVE/CVE-2017-16309) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16309.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16309.svg)


## CVE-2017-16303
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd sn_ex, at 0x9d01addc, the value for the `cmd2` key is copied using `strcpy` to the buffer at `$sp+0x280`.This buffer is 16 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16303](https://github.com/Live-Hack-CVE/CVE-2017-16303) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16303.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16303.svg)


## CVE-2017-16302
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd sn_ex, at 0x9d01ad78, the value for the `cmd1` key is copied using `strcpy` to the buffer at `$sp+0x2d0`.This buffer is 100 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16302](https://github.com/Live-Hack-CVE/CVE-2017-16302) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16302.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16302.svg)


## CVE-2017-16301
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd sn_ex, at 0x9d01ad14, the value for the `flg` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16301](https://github.com/Live-Hack-CVE/CVE-2017-16301) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16301.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16301.svg)


## CVE-2017-16300
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd sn_ex, at 0x9d01ac74, the value for the `id` key is copied using `strcpy` to the buffer at `$sp+0x290`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16300](https://github.com/Live-Hack-CVE/CVE-2017-16300) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16300.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16300.svg)


## CVE-2017-16289
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_utc, at 0x9d0193ac, the value for the `offset` key is copied using `strcpy` to the buffer at `$sp+0x2d0`.This buffer is 100 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16289](https://github.com/Live-Hack-CVE/CVE-2017-16289) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16289.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16289.svg)


## CVE-2017-16286
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_time, at 0x9d018ea0, the value for the `dststart` key is copied using `strcpy` to the buffer at `$sp+0x280`.This buffer is 16 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16286](https://github.com/Live-Hack-CVE/CVE-2017-16286) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16286.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16286.svg)


## CVE-2017-16280
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_net, at 0x9d0181ec, the value for the `gate` key is copied using `strcpy` to the buffer at `$sp+0x290`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16280](https://github.com/Live-Hack-CVE/CVE-2017-16280) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16280.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16280.svg)


## CVE-2017-16279
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_net, at 0x9d0181a4, the value for the `port` key is copied using `strcpy` to the buffer at `$sp+0x280`.This buffer is 16 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16279](https://github.com/Live-Hack-CVE/CVE-2017-16279) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16279.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16279.svg)


## CVE-2017-16277
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd sn_grp, at 0x9d017658, the value for the `gcmd` key is copied using `strcpy` to the buffer at `$sp+0x270`.This buffer is 16 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16277](https://github.com/Live-Hack-CVE/CVE-2017-16277) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16277.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16277.svg)


## CVE-2017-16276
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd sn_grp, at 0x9d0175f4, the value for the `gbt` key is copied using `strcpy` to the buffer at `$sp+0x280`.This buffer is 16 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16276](https://github.com/Live-Hack-CVE/CVE-2017-16276) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16276.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16276.svg)


## CVE-2017-16275
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd sn_grp, at 0x9d01758c, the value for the `grp` key is copied using `strcpy` to the buffer at `$sp+0x1b4`.This buffer is 8 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16275](https://github.com/Live-Hack-CVE/CVE-2017-16275) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16275.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16275.svg)


## CVE-2017-16273
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd e_ml, at 0x9d016fa8, the value for the `grp` key is copied using `strcpy` to the buffer at `$sp+0x1b4`.This buffer is 8 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16273](https://github.com/Live-Hack-CVE/CVE-2017-16273) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16273.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16273.svg)


## CVE-2017-16271
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd e_l, at 0x9d016c94, the value for the `as_c` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16271](https://github.com/Live-Hack-CVE/CVE-2017-16271) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16271.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16271.svg)


## CVE-2017-16270
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_b, at 0x9d01679c, the value for the `s_sonos_cmd` key is copied using `strcpy` to the buffer at `$sp+0x290`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16270](https://github.com/Live-Hack-CVE/CVE-2017-16270) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16270.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16270.svg)


## CVE-2017-16268
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_b, at 0x9d0165c0, the value for the `id` key is copied using `strcpy` to the buffer at `$sp+0x270`.This buffer is 16 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16268](https://github.com/Live-Hack-CVE/CVE-2017-16268) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16268.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16268.svg)


## CVE-2017-16263
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd g_b, at 0x9d015a8c, the value for the `val` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16263](https://github.com/Live-Hack-CVE/CVE-2017-16263) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16263.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16263.svg)


## CVE-2017-16262
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd g_b, at 0x9d015864, the value for the `id` key is copied using `strcpy` to the buffer at `$sp+0x290`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16262](https://github.com/Live-Hack-CVE/CVE-2017-16262) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16262.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16262.svg)


## CVE-2017-16261
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd g_b, at 0x9d015714, the value for the `grp` key is copied using `strcpy` to the buffer at `$sp+0x280`.This buffer is 16 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16261](https://github.com/Live-Hack-CVE/CVE-2017-16261) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16261.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16261.svg)


## CVE-2017-16260
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd s_auth, at 0x9d015478, the value for the `pwd` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16260](https://github.com/Live-Hack-CVE/CVE-2017-16260) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16260.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16260.svg)


## CVE-2017-16258
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd sn_sx, at 0x9d014f7c, the value for the `cmd4` key is copied using `strcpy` to the buffer at `$sp+0x2b0`.This buffer is 32 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16258](https://github.com/Live-Hack-CVE/CVE-2017-16258) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16258.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16258.svg)


## CVE-2017-16256
 Multiple exploitable buffer overflow vulnerabilities exist in the PubNub message handler for the &quot;cc&quot; channel of Insteon Hub running firmware version 1012. Specially crafted commands sent through the PubNub service can cause a stack-based buffer overflow overwriting arbitrary data. An attacker should send an authenticated HTTP request to trigger this vulnerability. In cmd sn_sx, at 0x9d014ebc, the value for the `cmd2` key is copied using `strcpy` to the buffer at `$sp+0x2d0`.This buffer is 100 bytes large, sending anything longer will cause a buffer overflow.

- [https://github.com/Live-Hack-CVE/CVE-2017-16256](https://github.com/Live-Hack-CVE/CVE-2017-16256) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-16256.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-16256.svg)


## CVE-2017-14454
 Multiple exploitable buffer overflow vulnerabilities exists in the PubNub message handler for the &quot;control&quot; channel of Insteon Hub running firmware version 1012. Specially crafted replies received from the PubNub service can cause buffer overflows on a global section overwriting arbitrary data. An attacker should impersonate PubNub and answer an HTTPS GET request to trigger this vulnerability. The `strcpy` at [18] overflows the buffer `insteon_pubnub.channel_al`, which has a size of 16 bytes.

- [https://github.com/Live-Hack-CVE/CVE-2017-14454](https://github.com/Live-Hack-CVE/CVE-2017-14454) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-14454.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-14454.svg)


## CVE-2015-10015
 A vulnerability, which was classified as critical, has been found in glidernet ogn-live. This issue affects some unknown processing. The manipulation leads to sql injection. The name of the patch is bc0f19965f760587645583b7624d66a260946e01. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217487.

- [https://github.com/Live-Hack-CVE/CVE-2015-10015](https://github.com/Live-Hack-CVE/CVE-2015-10015) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10015.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10015.svg)


## CVE-2014-125076
 A vulnerability was found in NoxxieNl Criminals. It has been classified as critical. Affected is an unknown function of the file ingame/roulette.php. The manipulation of the argument gambleMoney leads to sql injection. The name of the patch is 0a60b31271d4cbf8babe4be993d2a3a1617f0897. It is recommended to apply a patch to fix this issue. VDB-218022 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125076](https://github.com/Live-Hack-CVE/CVE-2014-125076) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125076.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125076.svg)


## CVE-2014-125075
 A vulnerability was found in gmail-servlet and classified as critical. This issue affects the function search of the file src/Model.java. The manipulation leads to sql injection. The name of the patch is 5d72753c2e95bb373aa86824939397dc25f679ea. It is recommended to apply a patch to fix this issue. The identifier VDB-218021 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2014-125075](https://github.com/Live-Hack-CVE/CVE-2014-125075) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-125075.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-125075.svg)


## CVE-2013-10011
 A vulnerability was found in aeharding classroom-engagement-system and classified as critical. Affected by this issue is some unknown functionality. The manipulation leads to sql injection. The attack may be launched remotely. The name of the patch is 096de5815c7b414e7339f3439522a446098fb73a. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-218156.

- [https://github.com/Live-Hack-CVE/CVE-2013-10011](https://github.com/Live-Hack-CVE/CVE-2013-10011) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2013-10011.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2013-10011.svg)


## CVE-2012-10005
 A vulnerability has been found in manikandan170890 php-form-builder-class and classified as problematic. Affected by this vulnerability is an unknown functionality of the file PFBC/Element/Textarea.php of the component Textarea Handler. The manipulation of the argument value leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The name of the patch is 74897993818d826595fd5857038e6703456a594a. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-218155.

- [https://github.com/Live-Hack-CVE/CVE-2012-10005](https://github.com/Live-Hack-CVE/CVE-2012-10005) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-10005.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-10005.svg)


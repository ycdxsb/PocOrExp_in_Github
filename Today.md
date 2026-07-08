# Update 2026-07-08
## CVE-2026-54350
 Budibase is an open-source low-code platform. Prior to 3.39.12,  an unauthenticated visitor of any published Budibase app reads every document of the backing MongoDB, CouchDB, Elasticsearch, DynamoDB-PartiQL, or REST-with-JSON-body collection and, where the builder has published a PUBLIC write query, modifies every document of that collection with one HTTP request. enrichContext at packages/server/src/sdk/workspace/queries/queries.ts:121-138 substitutes parameter values into the raw JSON body of a query, then JSON.parses the result. The validator validateQueryInputs at packages/server/src/api/controllers/query/index.ts:61-71 rejects only Handlebars markers ({{, }}) in user input and does not escape JSON metacharacters (", \, }). A parameter value containing a closing quote and additional keys lifts attacker-controlled fields into the parsed filter object. For Mongo find, the parsed filter passes directly to collection.find() (packages/server/src/integrations/mongodb.ts:506-510). Duplicate-key JSON parsing overrides the builder's {name: "..."} with {name: {$exists: true}} and returns every document. The same primitive against an updateMany query (mongodb.ts:577-585) widens the filter scope to the full collection while the builder-controlled $set body runs against every matched document. The authorized middleware at packages/server/src/middleware/authorized.ts:141-148 short-circuits when the query's role is PUBLIC. CSRF is not enforced on this path. POST /api/v2/queries/:queryId (packages/server/src/api/routes/query.ts:63) accepts the call with no session, only an x-budibase-app-id header that is public from the published-app URL. This vulnerability is fixed in 3.39.12.

- [https://github.com/BiiTts/CVE-2026-54350-Budibase-NoSQL-Injection](https://github.com/BiiTts/CVE-2026-54350-Budibase-NoSQL-Injection) :  ![starts](https://img.shields.io/github/stars/BiiTts/CVE-2026-54350-Budibase-NoSQL-Injection.svg) ![forks](https://img.shields.io/github/forks/BiiTts/CVE-2026-54350-Budibase-NoSQL-Injection.svg)


## CVE-2026-53647
 FOSSBilling is a free, open-source billing and client management system. In versions 0.5.3 through 0.7.2, the Guest `serviceapikey/get_info` API endpoint is accessible without authentication. Any caller with a valid API key can retrieve all custom configuration parameters (`custom_*` fields) stored in the key's database record. These custom fields are populated by billing administrators and can contain business-sensitive data such as pricing tiers, feature flags, rate limits, expiry overrides, or access scope data. Version 0.8.0 patches the issue. Some workarounds are available. Administrators can avoid storing sensitive data in `custom_*` API key configuration fields, monitor API logs for suspicious calls to `/api/guest/serviceapikey/get_info`, and/or disable the Serviceapikey module if not in active use.

- [https://github.com/7megaumka7/FOSKiller](https://github.com/7megaumka7/FOSKiller) :  ![starts](https://img.shields.io/github/stars/7megaumka7/FOSKiller.svg) ![forks](https://img.shields.io/github/forks/7megaumka7/FOSKiller.svg)


## CVE-2026-53646
 FOSSBilling is a free, open-source billing and client management system. In versions 0.5.6 through 0.7.2, when a `ClientPasswordReset` record already exists for a client (from a previous unexpired reset request), subsequent calls to the `reset_password` guest API endpoint reuse the existing token instead of generating a new one. The 15-minute validity window is anchored to the first request's `created_at` timestamp, not the time of the most recent email. An attacker who obtained the original reset link remains able to use it even after the victim requests a new reset, because the original token is never invalidated or rotated. Version 0.8.0 patches the issue. Some workarounds are available. Configure a reverse proxy (e.g., Nginx, Apache, Cloudflare) to apply per-IP rate limiting to the `/client/reset-password` endpoint to minimize the window of opportunity, and/or manually clear expired `client_password_reset` records from the database after a client reports a suspected compromise.

- [https://github.com/7megaumka7/FOSKiller](https://github.com/7megaumka7/FOSKiller) :  ![starts](https://img.shields.io/github/stars/7megaumka7/FOSKiller.svg) ![forks](https://img.shields.io/github/forks/7megaumka7/FOSKiller.svg)


## CVE-2026-52806
 Gogs is an open source self-hosted Git service. Prior to 0.14.3, Gogs allows authenticated users to achieve Remote Code Execution (RCE) on the server by creating a pull request with a specially crafted branch name that injects the --exec flag into the git rebase command during the "Rebase before merging" merge operation. This vulnerability is fixed in 0.14.3.

- [https://github.com/portbuster1337/CVE-2026-52806](https://github.com/portbuster1337/CVE-2026-52806) :  ![starts](https://img.shields.io/github/stars/portbuster1337/CVE-2026-52806.svg) ![forks](https://img.shields.io/github/forks/portbuster1337/CVE-2026-52806.svg)


## CVE-2026-48908
 A vulnerability in SP Page Builder for Joomla allows unauthenticated users to upload arbitrary files, ultimately resulting in the upload and execution of PHP code.

- [https://github.com/Jenderal92/CVE-2026-48908](https://github.com/Jenderal92/CVE-2026-48908) :  ![starts](https://img.shields.io/github/stars/Jenderal92/CVE-2026-48908.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/CVE-2026-48908.svg)


## CVE-2026-48282
 ColdFusion versions 2025.9, 2023.20 and earlier are affected by an Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability that could lead to arbitrary code execution in the context of the current user. Exploitation of this issue does not require user interaction. Scope is changed.

- [https://github.com/imbas007/CVE-2026-48282](https://github.com/imbas007/CVE-2026-48282) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2026-48282.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2026-48282.svg)


## CVE-2026-40022
Users are recommended to upgrade to version 4.20.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, they are suggested to upgrade to 4.14.6. If users are on the 4.18.x LTS releases stream, they are suggested to upgrade to 4.18.2.

- [https://github.com/oscerd/CVE-2026-40022](https://github.com/oscerd/CVE-2026-40022) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-40022.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-40022.svg)


## CVE-2026-38526
 An authenticated arbitrary file upload vulnerability in the /admin/tinymce/upload endpoint of Webkul Krayin CRM v2.2.x allows attackers to execute arbitrary code via uploading a crafted PHP file.

- [https://github.com/diamorphine666/CVE-2026-38526-Exploit](https://github.com/diamorphine666/CVE-2026-38526-Exploit) :  ![starts](https://img.shields.io/github/stars/diamorphine666/CVE-2026-38526-Exploit.svg) ![forks](https://img.shields.io/github/forks/diamorphine666/CVE-2026-38526-Exploit.svg)
- [https://github.com/mmoobbeeiidat-design/Hack-The-Box-Nexus-Findings-Report](https://github.com/mmoobbeeiidat-design/Hack-The-Box-Nexus-Findings-Report) :  ![starts](https://img.shields.io/github/stars/mmoobbeeiidat-design/Hack-The-Box-Nexus-Findings-Report.svg) ![forks](https://img.shields.io/github/forks/mmoobbeeiidat-design/Hack-The-Box-Nexus-Findings-Report.svg)


## CVE-2026-34038
 Coolify is an open-source and self-hostable tool for managing servers, applications, and databases. Prior to 4.0.0-beta.469, an authenticated remote command injection vulnerability in application deployment handling allows users with application write permissions to achieve remote code execution and exfiltrate sensitive environment variables through deployment logs via fields such as dockerfile_location and deployment commands. This issue is fixed in version 4.0.0-beta.469.

- [https://github.com/ThemeHackers/CVE-2026-34038](https://github.com/ThemeHackers/CVE-2026-34038) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2026-34038.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2026-34038.svg)


## CVE-2026-33454
Users are recommended to upgrade to version 4.19.0, which fixes the issue. If users are on the 4.18.x LTS releases stream, then they are suggested to upgrade to 4.18.1. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.6.

- [https://github.com/oscerd/CVE-2026-33454](https://github.com/oscerd/CVE-2026-33454) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-33454.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-33454.svg)


## CVE-2026-33453
Users are recommended to upgrade to version 4.18.1 or 4.19.0, fixing the issue.

- [https://github.com/oscerd/CVE-2026-33453](https://github.com/oscerd/CVE-2026-33453) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-33453.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-33453.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/Juguitos/copy-fail](https://github.com/Juguitos/copy-fail) :  ![starts](https://img.shields.io/github/stars/Juguitos/copy-fail.svg) ![forks](https://img.shields.io/github/forks/Juguitos/copy-fail.svg)


## CVE-2026-27172
Users are recommended to upgrade to version 4.19.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.6. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.1.

- [https://github.com/oscerd/CVE-2026-27172](https://github.com/oscerd/CVE-2026-27172) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-27172.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-27172.svg)


## CVE-2026-25555
 OpenBullet2 through version 0.3.2 contains an authentication bypass vulnerability in the API key authentication middleware that allows unauthenticated attackers to gain admin access by supplying an empty X-Api-Key header value. Attackers can exploit the middleware's comparison of the supplied header against an empty AdminApiKey default string to access the admin console and all API endpoints without valid credentials.

- [https://github.com/thecodeb0ss/CVE-2026-25555](https://github.com/thecodeb0ss/CVE-2026-25555) :  ![starts](https://img.shields.io/github/stars/thecodeb0ss/CVE-2026-25555.svg) ![forks](https://img.shields.io/github/forks/thecodeb0ss/CVE-2026-25555.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/harygovind/CVE-2026-24061](https://github.com/harygovind/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/harygovind/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/harygovind/CVE-2026-24061.svg)


## CVE-2026-6421
 A vulnerability has been found in Mobatek MobaXterm Home Edition up to 26.1. This affects an unknown part in the library msimg32.dll. The manipulation leads to uncontrolled search path. An attack has to be approached locally. The attack is considered to have high complexity. It is indicated that the exploitability is difficult. The exploit has been disclosed to the public and may be used. Upgrading to version 26.2 is able to mitigate this issue. It is suggested to upgrade the affected component. The vendor was contacted early, responded in a very professional manner and quickly released a fixed version of the affected product.

- [https://github.com/1neptune/chimera](https://github.com/1neptune/chimera) :  ![starts](https://img.shields.io/github/stars/1neptune/chimera.svg) ![forks](https://img.shields.io/github/forks/1neptune/chimera.svg)


## CVE-2026-4935
 The OttoKit: All-in-One Automation Platform WordPress plugin before 1.1.23 does not properly sanitize user input before using it in a SQL statement, which could allow unauthenticated attackers to perform SQL injection attacks.

- [https://github.com/covepseng/cve-2026-49352-poc](https://github.com/covepseng/cve-2026-49352-poc) :  ![starts](https://img.shields.io/github/stars/covepseng/cve-2026-49352-poc.svg) ![forks](https://img.shields.io/github/forks/covepseng/cve-2026-49352-poc.svg)


## CVE-2026-4480
substitution character without escaping shell meta characters. A remote attacker could exploit this vulnerability by sending a specially crafted print job description that contains unescaped shell characters. This could lead to remote code execution on the affected system.

- [https://github.com/Cosm3No1de/HTB-Abducted-Writeup](https://github.com/Cosm3No1de/HTB-Abducted-Writeup) :  ![starts](https://img.shields.io/github/stars/Cosm3No1de/HTB-Abducted-Writeup.svg) ![forks](https://img.shields.io/github/forks/Cosm3No1de/HTB-Abducted-Writeup.svg)


## CVE-2026-0776
The specific flaw exists within the discord_rpc module. The product loads a file from an unsecured location. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of a target user. Was ZDI-CAN-27057.

- [https://github.com/xsuf/CVE-2026-0776](https://github.com/xsuf/CVE-2026-0776) :  ![starts](https://img.shields.io/github/stars/xsuf/CVE-2026-0776.svg) ![forks](https://img.shields.io/github/forks/xsuf/CVE-2026-0776.svg)
- [https://github.com/OverlayCS/Helix](https://github.com/OverlayCS/Helix) :  ![starts](https://img.shields.io/github/stars/OverlayCS/Helix.svg) ![forks](https://img.shields.io/github/forks/OverlayCS/Helix.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)


## CVE-2025-20700
 In the Airoha Bluetooth audio SDK, there is a possible permission bypass that allows access critical data of RACE protocol through Bluetooth LE GATT service. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/SpiritualMachines/buds-audit](https://github.com/SpiritualMachines/buds-audit) :  ![starts](https://img.shields.io/github/stars/SpiritualMachines/buds-audit.svg) ![forks](https://img.shields.io/github/forks/SpiritualMachines/buds-audit.svg)


## CVE-2024-27766
 An issue in MariaDB v.11.1 allows a remote attacker to execute arbitrary code via the lib_mysqludf_sys.so function. NOTE: this is disputed by the MariaDB Foundation because no privilege boundary is crossed.

- [https://github.com/Hissec/Mysql_CVE-2024-27766](https://github.com/Hissec/Mysql_CVE-2024-27766) :  ![starts](https://img.shields.io/github/stars/Hissec/Mysql_CVE-2024-27766.svg) ![forks](https://img.shields.io/github/forks/Hissec/Mysql_CVE-2024-27766.svg)


## CVE-2024-0519
 Out of bounds memory access in V8 in Google Chrome prior to 120.0.6099.224 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Insaida/cve-2024-0519-rca-research](https://github.com/Insaida/cve-2024-0519-rca-research) :  ![starts](https://img.shields.io/github/stars/Insaida/cve-2024-0519-rca-research.svg) ![forks](https://img.shields.io/github/forks/Insaida/cve-2024-0519-rca-research.svg)


## CVE-2023-22496
 Netdata is an open source option for real-time infrastructure monitoring and troubleshooting. An attacker with the ability to establish a streaming connection can execute arbitrary commands on the targeted Netdata agent. When an alert is triggered, the function `health_alarm_execute` is called. This function performs different checks and then enqueues a command by calling `spawn_enq_cmd`. This command is populated with several arguments that are not sanitized. One of them is the `registry_hostname` of the node for which the alert is raised. By providing a specially crafted `registry_hostname` as part of the health data that is streamed to a Netdata (parent) agent, an attacker can execute arbitrary commands at the remote host as a side-effect of the raised alert. Note that the commands are executed as the user running the Netdata Agent. This user is usually named `netdata`. The ability to run arbitrary commands may allow an attacker to escalate privileges by escalating other vulnerabilities in the system, as that user. The problem has been fixed in: Netdata agent v1.37 (stable) and Netdata agent v1.36.0-409 (nightly). As a workaround, streaming is not enabled by default. If you have previously enabled this, it can be disabled. Limiting access to the port on the recipient Agent to trusted child connections may mitigate the impact of this vulnerability.

- [https://github.com/jstjep00/CVE-2023-22496-PoC](https://github.com/jstjep00/CVE-2023-22496-PoC) :  ![starts](https://img.shields.io/github/stars/jstjep00/CVE-2023-22496-PoC.svg) ![forks](https://img.shields.io/github/forks/jstjep00/CVE-2023-22496-PoC.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/RootEvil333/CVE-2022-22965](https://github.com/RootEvil333/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/RootEvil333/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/RootEvil333/CVE-2022-22965.svg)


## CVE-2021-42287
 Active Directory Domain Services Elevation of Privilege Vulnerability

- [https://github.com/xLTJ/noPac](https://github.com/xLTJ/noPac) :  ![starts](https://img.shields.io/github/stars/xLTJ/noPac.svg) ![forks](https://img.shields.io/github/forks/xLTJ/noPac.svg)


## CVE-2021-42278
 Active Directory Domain Services Elevation of Privilege Vulnerability

- [https://github.com/xLTJ/noPac](https://github.com/xLTJ/noPac) :  ![starts](https://img.shields.io/github/stars/xLTJ/noPac.svg) ![forks](https://img.shields.io/github/forks/xLTJ/noPac.svg)


## CVE-2019-18634
 In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS; however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.

- [https://github.com/Moscvv/thm-cybersec-portfolio](https://github.com/Moscvv/thm-cybersec-portfolio) :  ![starts](https://img.shields.io/github/stars/Moscvv/thm-cybersec-portfolio.svg) ![forks](https://img.shields.io/github/forks/Moscvv/thm-cybersec-portfolio.svg)


## CVE-2016-9079
 A use-after-free vulnerability in SVG Animation has been discovered. An exploit built on this vulnerability has been discovered in the wild targeting Firefox and Tor Browser users on Windows. This vulnerability affects Firefox  50.0.2, Firefox ESR  45.5.1, and Thunderbird  45.5.1.

- [https://github.com/soham23/firefox-rce-nssmil](https://github.com/soham23/firefox-rce-nssmil) :  ![starts](https://img.shields.io/github/stars/soham23/firefox-rce-nssmil.svg) ![forks](https://img.shields.io/github/forks/soham23/firefox-rce-nssmil.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/rauljvc8/Exploit-Dirty-Cow](https://github.com/rauljvc8/Exploit-Dirty-Cow) :  ![starts](https://img.shields.io/github/stars/rauljvc8/Exploit-Dirty-Cow.svg) ![forks](https://img.shields.io/github/forks/rauljvc8/Exploit-Dirty-Cow.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/caverm/Shellshock_CVE-2014-6271](https://github.com/caverm/Shellshock_CVE-2014-6271) :  ![starts](https://img.shields.io/github/stars/caverm/Shellshock_CVE-2014-6271.svg) ![forks](https://img.shields.io/github/forks/caverm/Shellshock_CVE-2014-6271.svg)


## CVE-2012-2122
 sql/password.c in Oracle MySQL 5.1.x before 5.1.63, 5.5.x before 5.5.24, and 5.6.x before 5.6.6, and MariaDB 5.1.x before 5.1.62, 5.2.x before 5.2.12, 5.3.x before 5.3.6, and 5.5.x before 5.5.23, when running in certain environments with certain implementations of the memcmp function, allows remote attackers to bypass authentication by repeatedly authenticating with the same incorrect password, which eventually causes a token comparison to succeed due to an improperly-checked return value.

- [https://github.com/K3ysTr0K3R/CVE-2012-2122](https://github.com/K3ysTr0K3R/CVE-2012-2122) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2012-2122.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2012-2122.svg)


## CVE-2011-3192
 The byterange filter in the Apache HTTP Server 1.3.x, 2.0.x through 2.0.64, and 2.2.x through 2.2.19 allows remote attackers to cause a denial of service (memory and CPU consumption) via a Range header that expresses multiple overlapping ranges, as exploited in the wild in August 2011, a different vulnerability than CVE-2007-0086.

- [https://github.com/bluedragonsecurity/CVE-2011-3192-apache-exploit](https://github.com/bluedragonsecurity/CVE-2011-3192-apache-exploit) :  ![starts](https://img.shields.io/github/stars/bluedragonsecurity/CVE-2011-3192-apache-exploit.svg) ![forks](https://img.shields.io/github/forks/bluedragonsecurity/CVE-2011-3192-apache-exploit.svg)


## CVE-2011-1485
 Race condition in the pkexec utility and polkitd daemon in PolicyKit (aka polkit) 0.96 allows local users to gain privileges by executing a setuid program from pkexec, related to the use of the effective user ID instead of the real user ID.

- [https://github.com/bluedragonsecurity/CVE-2011-1485-pkexec-exploit](https://github.com/bluedragonsecurity/CVE-2011-1485-pkexec-exploit) :  ![starts](https://img.shields.io/github/stars/bluedragonsecurity/CVE-2011-1485-pkexec-exploit.svg) ![forks](https://img.shields.io/github/forks/bluedragonsecurity/CVE-2011-1485-pkexec-exploit.svg)


## CVE-2005-0575
 Buffer overflow in Stormy Studios Knet 1.04c and earlier allows remote attackers to cause a denial of service and possibly execute arbitrary code via a long HTTP GET request.

- [https://github.com/bluedragonsecurity/CVE-2005-0575-knet-exploit](https://github.com/bluedragonsecurity/CVE-2005-0575-knet-exploit) :  ![starts](https://img.shields.io/github/stars/bluedragonsecurity/CVE-2005-0575-knet-exploit.svg) ![forks](https://img.shields.io/github/forks/bluedragonsecurity/CVE-2005-0575-knet-exploit.svg)


# Update 2026-07-23
## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/GhostInExile/CVE-2026-63030-Wp2Shell](https://github.com/GhostInExile/CVE-2026-63030-Wp2Shell) :  ![starts](https://img.shields.io/github/stars/GhostInExile/CVE-2026-63030-Wp2Shell.svg) ![forks](https://img.shields.io/github/forks/GhostInExile/CVE-2026-63030-Wp2Shell.svg)
- [https://github.com/Ch4120N/CVE-2026-63030](https://github.com/Ch4120N/CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/Ch4120N/CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/Ch4120N/CVE-2026-63030.svg)
- [https://github.com/joaovicdev/EXPLOIT-CVE-2026-63030](https://github.com/joaovicdev/EXPLOIT-CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/joaovicdev/EXPLOIT-CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/joaovicdev/EXPLOIT-CVE-2026-63030.svg)
- [https://github.com/0xjessie21/wp2shell-checker](https://github.com/0xjessie21/wp2shell-checker) :  ![starts](https://img.shields.io/github/stars/0xjessie21/wp2shell-checker.svg) ![forks](https://img.shields.io/github/forks/0xjessie21/wp2shell-checker.svg)
- [https://github.com/SentinelXofficial/sxwp2shell](https://github.com/SentinelXofficial/sxwp2shell) :  ![starts](https://img.shields.io/github/stars/SentinelXofficial/sxwp2shell.svg) ![forks](https://img.shields.io/github/forks/SentinelXofficial/sxwp2shell.svg)
- [https://github.com/lucifer0xf/wp2shell-Wordpress-TOWN](https://github.com/lucifer0xf/wp2shell-Wordpress-TOWN) :  ![starts](https://img.shields.io/github/stars/lucifer0xf/wp2shell-Wordpress-TOWN.svg) ![forks](https://img.shields.io/github/forks/lucifer0xf/wp2shell-Wordpress-TOWN.svg)
- [https://github.com/TomorrowX6/CVE-2026-63030-poc](https://github.com/TomorrowX6/CVE-2026-63030-poc) :  ![starts](https://img.shields.io/github/stars/TomorrowX6/CVE-2026-63030-poc.svg) ![forks](https://img.shields.io/github/forks/TomorrowX6/CVE-2026-63030-poc.svg)
- [https://github.com/Bhanunamikaze/WP2Shell-CVE-2026-63030-POC](https://github.com/Bhanunamikaze/WP2Shell-CVE-2026-63030-POC) :  ![starts](https://img.shields.io/github/stars/Bhanunamikaze/WP2Shell-CVE-2026-63030-POC.svg) ![forks](https://img.shields.io/github/forks/Bhanunamikaze/WP2Shell-CVE-2026-63030-POC.svg)
- [https://github.com/mrmtwoj/Fix-CVE-2026-60137-CVE-2026-63030-in-wordpress](https://github.com/mrmtwoj/Fix-CVE-2026-60137-CVE-2026-63030-in-wordpress) :  ![starts](https://img.shields.io/github/stars/mrmtwoj/Fix-CVE-2026-60137-CVE-2026-63030-in-wordpress.svg) ![forks](https://img.shields.io/github/forks/mrmtwoj/Fix-CVE-2026-60137-CVE-2026-63030-in-wordpress.svg)
- [https://github.com/Crypto-Cat/wp2shell](https://github.com/Crypto-Cat/wp2shell) :  ![starts](https://img.shields.io/github/stars/Crypto-Cat/wp2shell.svg) ![forks](https://img.shields.io/github/forks/Crypto-Cat/wp2shell.svg)
- [https://github.com/ASYquan/wp2shell-cf-WAF-bypass](https://github.com/ASYquan/wp2shell-cf-WAF-bypass) :  ![starts](https://img.shields.io/github/stars/ASYquan/wp2shell-cf-WAF-bypass.svg) ![forks](https://img.shields.io/github/forks/ASYquan/wp2shell-cf-WAF-bypass.svg)
- [https://github.com/Colere-Sys/wp2shell-poc](https://github.com/Colere-Sys/wp2shell-poc) :  ![starts](https://img.shields.io/github/stars/Colere-Sys/wp2shell-poc.svg) ![forks](https://img.shields.io/github/forks/Colere-Sys/wp2shell-poc.svg)
- [https://github.com/AkbarWiraN/holy-wp2shell](https://github.com/AkbarWiraN/holy-wp2shell) :  ![starts](https://img.shields.io/github/stars/AkbarWiraN/holy-wp2shell.svg) ![forks](https://img.shields.io/github/forks/AkbarWiraN/holy-wp2shell.svg)


## CVE-2026-62183
Users are recommended to upgrade to version 4.0.7 / 4.1.2, which fix this issue.

- [https://github.com/NicPWNs/CVE-2026-62183](https://github.com/NicPWNs/CVE-2026-62183) :  ![starts](https://img.shields.io/github/stars/NicPWNs/CVE-2026-62183.svg) ![forks](https://img.shields.io/github/forks/NicPWNs/CVE-2026-62183.svg)


## CVE-2026-61498
 Vitec Flamingo 4.12.2 contains an unauthenticated OS command injection vulnerability in the admin/ajax/gen_graphs.php endpoint that allows remote unauthenticated attackers to execute arbitrary commands by supplying shell metacharacters in the start, end, key, or format HTTP GET parameters. Attackers can exploit the lack of input sanitization in the graph generation script, which passes user-supplied values directly to shell commands via passthru(), to execute arbitrary OS commands with root privileges due to the web server context having passwordless sudo access.

- [https://github.com/HORKimhab/CVE-2026-60121-CVE-2026-61498](https://github.com/HORKimhab/CVE-2026-60121-CVE-2026-61498) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-60121-CVE-2026-61498.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-60121-CVE-2026-61498.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/GhostInExile/CVE-2026-63030-Wp2Shell](https://github.com/GhostInExile/CVE-2026-63030-Wp2Shell) :  ![starts](https://img.shields.io/github/stars/GhostInExile/CVE-2026-63030-Wp2Shell.svg) ![forks](https://img.shields.io/github/forks/GhostInExile/CVE-2026-63030-Wp2Shell.svg)
- [https://github.com/0xjessie21/wp2shell-checker](https://github.com/0xjessie21/wp2shell-checker) :  ![starts](https://img.shields.io/github/stars/0xjessie21/wp2shell-checker.svg) ![forks](https://img.shields.io/github/forks/0xjessie21/wp2shell-checker.svg)
- [https://github.com/SentinelXofficial/sxwp2shell](https://github.com/SentinelXofficial/sxwp2shell) :  ![starts](https://img.shields.io/github/stars/SentinelXofficial/sxwp2shell.svg) ![forks](https://img.shields.io/github/forks/SentinelXofficial/sxwp2shell.svg)
- [https://github.com/lucifer0xf/wp2shell-Wordpress-TOWN](https://github.com/lucifer0xf/wp2shell-Wordpress-TOWN) :  ![starts](https://img.shields.io/github/stars/lucifer0xf/wp2shell-Wordpress-TOWN.svg) ![forks](https://img.shields.io/github/forks/lucifer0xf/wp2shell-Wordpress-TOWN.svg)
- [https://github.com/mrmtwoj/Fix-CVE-2026-60137-CVE-2026-63030-in-wordpress](https://github.com/mrmtwoj/Fix-CVE-2026-60137-CVE-2026-63030-in-wordpress) :  ![starts](https://img.shields.io/github/stars/mrmtwoj/Fix-CVE-2026-60137-CVE-2026-63030-in-wordpress.svg) ![forks](https://img.shields.io/github/forks/mrmtwoj/Fix-CVE-2026-60137-CVE-2026-63030-in-wordpress.svg)
- [https://github.com/Crypto-Cat/wp2shell](https://github.com/Crypto-Cat/wp2shell) :  ![starts](https://img.shields.io/github/stars/Crypto-Cat/wp2shell.svg) ![forks](https://img.shields.io/github/forks/Crypto-Cat/wp2shell.svg)
- [https://github.com/Colere-Sys/wp2shell-poc](https://github.com/Colere-Sys/wp2shell-poc) :  ![starts](https://img.shields.io/github/stars/Colere-Sys/wp2shell-poc.svg) ![forks](https://img.shields.io/github/forks/Colere-Sys/wp2shell-poc.svg)
- [https://github.com/Bhanunamikaze/WP2Shell-CVE-2026-63030-POC](https://github.com/Bhanunamikaze/WP2Shell-CVE-2026-63030-POC) :  ![starts](https://img.shields.io/github/stars/Bhanunamikaze/WP2Shell-CVE-2026-63030-POC.svg) ![forks](https://img.shields.io/github/forks/Bhanunamikaze/WP2Shell-CVE-2026-63030-POC.svg)
- [https://github.com/AkbarWiraN/holy-wp2shell](https://github.com/AkbarWiraN/holy-wp2shell) :  ![starts](https://img.shields.io/github/stars/AkbarWiraN/holy-wp2shell.svg) ![forks](https://img.shields.io/github/forks/AkbarWiraN/holy-wp2shell.svg)


## CVE-2026-60121
 Vitec Flamingo 4.12.2 contains an unauthenticated OS command injection vulnerability in the admin/ajax/ping.php endpoint that allows remote attackers to execute arbitrary commands by exploiting a double-evaluation flaw in shell argument handling. The endpoint applies escapeshellarg() to the user-supplied host POST parameter before passing it to a system wrapper, but the wrapper retrieves the decoded value from argv and incorporates it into a second shell_exec() call without escaping, allowing injected commands to execute with root privileges via passwordless sudo.

- [https://github.com/HORKimhab/CVE-2026-60121-CVE-2026-61498](https://github.com/HORKimhab/CVE-2026-60121-CVE-2026-61498) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-60121-CVE-2026-61498.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-60121-CVE-2026-61498.svg)


## CVE-2026-57588
 A SQL injection vulnerability in Nessus allows an attacker to craft a malicious scan result file that, when imported by a privileged user, injects malicious SQL into the scan results database, potentially enabling exfiltration of scan-result data.

- [https://github.com/CerberusMrXi/CVE-2026-57588-Nessus-XML-Import-SQL-Injection-PoC](https://github.com/CerberusMrXi/CVE-2026-57588-Nessus-XML-Import-SQL-Injection-PoC) :  ![starts](https://img.shields.io/github/stars/CerberusMrXi/CVE-2026-57588-Nessus-XML-Import-SQL-Injection-PoC.svg) ![forks](https://img.shields.io/github/forks/CerberusMrXi/CVE-2026-57588-Nessus-XML-Import-SQL-Injection-PoC.svg)


## CVE-2026-53913
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. For deployments that cannot upgrade immediately, configure a non-empty requiredRoles or requiredPermissions on every KeycloakSecurityPolicy so that the token-verification path is exercised, set allowTokenFromHeader to false where the token is not expected from the request header, or perform token verification at the framework layer ahead of the policy.

- [https://github.com/oscerd/CVE-2026-53913](https://github.com/oscerd/CVE-2026-53913) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-53913.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-53913.svg)


## CVE-2026-53595
 FreeScout is a free help desk and shared inbox built with PHP's Laravel framework. Prior to version 1.8.224, the public endpoint `POST /user-setup/{hash}/{invite_sent_at}` (`OpenController@userSetupSave`) selects the target account solely by its `invite_hash` column, then overwrites that account's email and password and logs in as it. No authentication, cookie, or prior session is required. After a user activates, FreeScout sets `invite_hash` to the empty string. On MySQL and MariaDB, `VARCHAR` equality ignores trailing spaces, so a single URL-encoded space (`%20`) matches the stored empty string and selects the lowest-id activated user. The expiry guard decrypts `invite_sent_at` with the target's password hash, but `Helper::decrypt` returns its raw input unchanged when decryption fails. A plaintext numeric value such as `9999999999` therefore passes the time-to-live check without any secret. The result is that an anonymous attacker sets the email and password of the lowest-id activated FreeScout account (a support agent, or an administrator if one was added by invitation) and authenticates as that account. Version 1.8.224 contains a fix.

- [https://github.com/0xdak/CVE-2026-53595_exploit](https://github.com/0xdak/CVE-2026-53595_exploit) :  ![starts](https://img.shields.io/github/stars/0xdak/CVE-2026-53595_exploit.svg) ![forks](https://img.shields.io/github/forks/0xdak/CVE-2026-53595_exploit.svg)


## CVE-2026-52910
---truncated---

- [https://github.com/Dere3046/ScreenOff](https://github.com/Dere3046/ScreenOff) :  ![starts](https://img.shields.io/github/stars/Dere3046/ScreenOff.svg) ![forks](https://img.shields.io/github/forks/Dere3046/ScreenOff.svg)
- [https://github.com/Dere3046/ElevateMe_noLKM](https://github.com/Dere3046/ElevateMe_noLKM) :  ![starts](https://img.shields.io/github/stars/Dere3046/ElevateMe_noLKM.svg) ![forks](https://img.shields.io/github/forks/Dere3046/ElevateMe_noLKM.svg)


## CVE-2026-52813
 Gogs is an open source self-hosted Git service. Prior to 0.14.3, organization names containing path traversal sequences (../) are accepted by Gogs, and repositories under them are written to paths following these path traversals. This allows storing/retrieving data for repositories at arbitrary locations on the filesystem. By creating nested structure of Git repositories, one can overwrite the other's hooks configuration to result in Remote Code Execution (RCE). This vulnerability is fixed in 0.14.3.

- [https://github.com/iqx6889/CVE-2026-52813-Gogs-RCE](https://github.com/iqx6889/CVE-2026-52813-Gogs-RCE) :  ![starts](https://img.shields.io/github/stars/iqx6889/CVE-2026-52813-Gogs-RCE.svg) ![forks](https://img.shields.io/github/forks/iqx6889/CVE-2026-52813-Gogs-RCE.svg)


## CVE-2026-52656
 An issue in SJCAM AllWinner Tech products SJ4000-Air V1.4C and before and Whitelabel based v.1.4C and before allows an attacker to execute arbitrary code via a crafted FEX file

- [https://github.com/keowu/sjcam](https://github.com/keowu/sjcam) :  ![starts](https://img.shields.io/github/stars/keowu/sjcam.svg) ![forks](https://img.shields.io/github/forks/keowu/sjcam.svg)


## CVE-2026-51385
 An issue in safishamsi Open-Source GRAPHIFY v.0.3.2 through v0.4.29 allows a remote attacker to execute arbitrary code via the validate_url, safe_fetch, _build_opener, _fetch_html and _download_binary functions.

- [https://github.com/Arturo0x90/CVE-2026-51385](https://github.com/Arturo0x90/CVE-2026-51385) :  ![starts](https://img.shields.io/github/stars/Arturo0x90/CVE-2026-51385.svg) ![forks](https://img.shields.io/github/forks/Arturo0x90/CVE-2026-51385.svg)


## CVE-2026-50522
 Deserialization of untrusted data in Microsoft Office SharePoint allows an unauthorized attacker to execute code over a network.

- [https://github.com/HORKimhab/CVE-2026-50522](https://github.com/HORKimhab/CVE-2026-50522) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-50522.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-50522.svg)


## CVE-2026-49365
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. For deployments that cannot upgrade immediately, set muteException=true explicitly on the camel-netty-http consumer (for example netty-http: http://0.0.0.0:8080/api?muteException=true , or globally via the camel.component.netty-http.configuration.mute-exception=true property), so that processing errors no longer return the stack trace to the client.

- [https://github.com/oscerd/CVE-2026-49365](https://github.com/oscerd/CVE-2026-49365) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-49365.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-49365.svg)


## CVE-2026-49099
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. After upgrading, routes that set Salesforce operation parameters via the raw header names must use the CamelSalesforce* names (for example CamelSalesforceSObjectQuery and CamelSalesforceApexUrl) instead of the old sObject* / apex* values; the endpoint-option spelling is unchanged. For deployments that cannot upgrade immediately, strip the Salesforce control headers from any untrusted ingress before the salesforce: producer (for example removeHeaders('sObject*') and removeHeaders('apex*') at the start of the route), and set the query, SObject and Apex parameters from a trusted source.

- [https://github.com/oscerd/CVE-2026-49099](https://github.com/oscerd/CVE-2026-49099) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-49099.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-49099.svg)


## CVE-2026-49098
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. After upgrading, routes that set or read Kafka headers via the raw header names must use the CamelKafka* names (for example CamelKafkaOverrideTopic and CamelKafkaTopic) instead of the old kafka.* values. For deployments that cannot upgrade immediately, strip the kafka.* headers from any untrusted ingress before the kafka: producer (for example removeHeaders('kafka.*') at the start of the route), and set the target topic from a trusted source.

- [https://github.com/oscerd/CVE-2026-49098](https://github.com/oscerd/CVE-2026-49098) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-49098.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-49098.svg)


## CVE-2026-49097
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. After upgrading, routes that set IRC headers via the raw header names must use the CamelIrc* names (for example CamelIrcSendTo) instead of the old irc.* values. For deployments that cannot upgrade immediately, strip the irc.* headers from any untrusted ingress before the irc: producer (for example removeHeaders('irc.*') at the start of the route), and set the IRC destination from a trusted source.

- [https://github.com/oscerd/CVE-2026-49097](https://github.com/oscerd/CVE-2026-49097) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-49097.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-49097.svg)


## CVE-2026-49086
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. For deployments that cannot upgrade immediately, remove the CamelDaprPubSubName and CamelDaprTopic headers from the Exchange between the Dapr consumer and any Dapr producer in the route (for example removeHeaders('CamelDaprPubSubName', 'CamelDaprTopic')), and restrict who can publish to the subscribed Dapr Pub/Sub topic so that only trusted producers can send to it.

- [https://github.com/oscerd/CVE-2026-49086](https://github.com/oscerd/CVE-2026-49086) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-49086.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-49086.svg)


## CVE-2026-49042
Users are recommended to upgrade to version 4.18.3, 4.21.0, which fixes the issue.

- [https://github.com/oscerd/CVE-2026-49042](https://github.com/oscerd/CVE-2026-49042) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-49042.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-49042.svg)


## CVE-2026-48206
Users are recommended to upgrade to version 4.21.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.8. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.3. After upgrading, routes that drive JIRA operations via the raw header names must use the CamelJira* names (for example CamelJiraIssueKey) instead of the old values. For deployments that cannot upgrade immediately, strip the camel-jira control headers from any untrusted ingress before the jira: producer (for example removing the IssueKey, ProjectKey, IssueTransitionId and related headers at the start of the route), and set the required JIRA operation parameters from a trusted source.

- [https://github.com/oscerd/CVE-2026-48206](https://github.com/oscerd/CVE-2026-48206) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-48206.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-48206.svg)


## CVE-2026-45585
No, if you are using TPM+PIN the vulnerability is not exploitable.

- [https://github.com/yellowkeys/YellowKey-Bitlocker-CVE-2026-45585](https://github.com/yellowkeys/YellowKey-Bitlocker-CVE-2026-45585) :  ![starts](https://img.shields.io/github/stars/yellowkeys/YellowKey-Bitlocker-CVE-2026-45585.svg) ![forks](https://img.shields.io/github/forks/yellowkeys/YellowKey-Bitlocker-CVE-2026-45585.svg)
- [https://github.com/boobalover7/YellowKey-Bitlocker-CVE-2026-45585](https://github.com/boobalover7/YellowKey-Bitlocker-CVE-2026-45585) :  ![starts](https://img.shields.io/github/stars/boobalover7/YellowKey-Bitlocker-CVE-2026-45585.svg) ![forks](https://img.shields.io/github/forks/boobalover7/YellowKey-Bitlocker-CVE-2026-45585.svg)


## CVE-2026-44680
 MikroORM is a TypeScript ORM for Node.js based on Data Mapper, Unit of Work and Identity Map patterns. Prior to @mikro-orm/knex 6.6.14 and @mikro-orm/sql 7.0.14, MikroORM's identifier-quoting helper (Platform.quoteIdentifier and the postgres/mssql overrides) and its JSON-path emitters (Platform.getSearchJsonPropertyKey, quoteJsonKey) did not properly escape characters that delimit the SQL identifier or string-literal context they emit into. When application code passes attacker-influenced strings to public ORM APIs that expect an identifier or a JSON-property filter, an attacker can break out of the quoted context and inject arbitrary SQL. This vulnerability is fixed in @mikro-orm/knex 6.6.14 and @mikro-orm/sql 7.0.14.

- [https://github.com/CerberusMrXi/CVE-2026-44680-MikroORM-SQL-Injection-Exploit-Framework](https://github.com/CerberusMrXi/CVE-2026-44680-MikroORM-SQL-Injection-Exploit-Framework) :  ![starts](https://img.shields.io/github/stars/CerberusMrXi/CVE-2026-44680-MikroORM-SQL-Injection-Exploit-Framework.svg) ![forks](https://img.shields.io/github/forks/CerberusMrXi/CVE-2026-44680-MikroORM-SQL-Injection-Exploit-Framework.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/geecjdj/CVE-2026-43499](https://github.com/geecjdj/CVE-2026-43499) :  ![starts](https://img.shields.io/github/stars/geecjdj/CVE-2026-43499.svg) ![forks](https://img.shields.io/github/forks/geecjdj/CVE-2026-43499.svg)
- [https://github.com/Petalrain224/CVE-2026-43499-Redmi-Turbo5](https://github.com/Petalrain224/CVE-2026-43499-Redmi-Turbo5) :  ![starts](https://img.shields.io/github/stars/Petalrain224/CVE-2026-43499-Redmi-Turbo5.svg) ![forks](https://img.shields.io/github/forks/Petalrain224/CVE-2026-43499-Redmi-Turbo5.svg)
- [https://github.com/DistrictBlauw/Ace3-GhostLock-Preload](https://github.com/DistrictBlauw/Ace3-GhostLock-Preload) :  ![starts](https://img.shields.io/github/stars/DistrictBlauw/Ace3-GhostLock-Preload.svg) ![forks](https://img.shields.io/github/forks/DistrictBlauw/Ace3-GhostLock-Preload.svg)


## CVE-2026-43449
---truncated---

- [https://github.com/Daniyal48/ghostlock-vagrant-box](https://github.com/Daniyal48/ghostlock-vagrant-box) :  ![starts](https://img.shields.io/github/stars/Daniyal48/ghostlock-vagrant-box.svg) ![forks](https://img.shields.io/github/forks/Daniyal48/ghostlock-vagrant-box.svg)


## CVE-2026-42533
 Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/suominen/CVE-2026-42533](https://github.com/suominen/CVE-2026-42533) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-42533.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-42533.svg)
- [https://github.com/Daniyal48/ghostlock-vagrant-box](https://github.com/Daniyal48/ghostlock-vagrant-box) :  ![starts](https://img.shields.io/github/stars/Daniyal48/ghostlock-vagrant-box.svg) ![forks](https://img.shields.io/github/forks/Daniyal48/ghostlock-vagrant-box.svg)


## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

- [https://github.com/soverineg/cve-2026-41940-PoC](https://github.com/soverineg/cve-2026-41940-PoC) :  ![starts](https://img.shields.io/github/stars/soverineg/cve-2026-41940-PoC.svg) ![forks](https://img.shields.io/github/forks/soverineg/cve-2026-41940-PoC.svg)


## CVE-2026-41089
 Stack-based buffer overflow in Windows Netlogon allows an unauthorized attacker to execute code over a network.

- [https://github.com/HydraSoft/CVE-2026-41089-Netlogon-RCE](https://github.com/HydraSoft/CVE-2026-41089-Netlogon-RCE) :  ![starts](https://img.shields.io/github/stars/HydraSoft/CVE-2026-41089-Netlogon-RCE.svg) ![forks](https://img.shields.io/github/forks/HydraSoft/CVE-2026-41089-Netlogon-RCE.svg)


## CVE-2026-33697
 Cocos AI is a confidential computing system for AI. The current implementation of attested TLS (aTLS) in CoCoS is vulnerable to a relay attack affecting all versions from v0.4.0 through v0.8.2. This vulnerability is present in both the AMD SEV-SNP and Intel TDX deployment targets supported by CoCoS. In the affected design, an attacker may be able to extract the ephemeral TLS private key used during the intra-handshake attestation. Because the attestation evidence is bound to the ephemeral key but not to the TLS channel, possession of that key is sufficient to relay or divert the attested TLS session. A client will accept the connection under false assumptions about the endpoint it is communicating with — the attestation report cannot distinguish the genuine attested service from the attacker's relay. This undermines the intended authentication guarantees of attested TLS. A successful attack may allow an attacker to impersonate an attested CoCoS service and access data or operations that the client intended to send only to the genuine attested endpoint. Exploitation requires the attacker to first extract the ephemeral TLS private key, which is possible through physical access to the server hardware, transient execution attacks, or side-channel attacks. Note that the aTLS implementation was fully redesigned in v0.7.0, but the redesign does not address this vulnerability. The relay attack weakness is architectural and affects all releases in the v0.4.0–v0.8.2 range. This vulnerability class was formally analyzed and demonstrated across multiple attested TLS implementations, including CoCoS, by researchers whose findings were disclosed to the IETF TLS Working Group. Formal verification was conducted using ProVerif. As of time of publication, there is no patch available. No complete workaround is available. The following hardening measures reduce but do not eliminate the risk: Keep TEE firmware and microcode up to date to reduce the key-extraction surface; define strict attestation policies that validate all available report fields, including firmware versions, TCB levels, and platform configuration registers; and/or enable mutual aTLS with CA-signed certificates where deployment architecture permits.

- [https://github.com/pduggusa/dugganusa-ietf](https://github.com/pduggusa/dugganusa-ietf) :  ![starts](https://img.shields.io/github/stars/pduggusa/dugganusa-ietf.svg) ![forks](https://img.shields.io/github/forks/pduggusa/dugganusa-ietf.svg)


## CVE-2026-30623
 LiteLLM 1.18.10 contains a remote code execution vulnerability in its MCP server creation functionality. The application allows users to add MCP servers via a JSON configuration specifying arbitrary command and args values. LiteLLM executes these values on the host without validation, enabling attackers to run arbitrary operating system commands. Successful exploitation may result in remote code execution with the privileges of the LiteLLM process.

- [https://github.com/csinexus/mcpshield](https://github.com/csinexus/mcpshield) :  ![starts](https://img.shields.io/github/stars/csinexus/mcpshield.svg) ![forks](https://img.shields.io/github/forks/csinexus/mcpshield.svg)


## CVE-2026-27971
 Qwik is a performance focused javascript framework. qwik =1.19.0 is vulnerable to RCE due to an unsafe deserialization vulnerability in the server$ RPC mechanism that allows any unauthenticated user to execute arbitrary code on the server with a single HTTP request. Affects any deployment where require() is available at runtime. This vulnerability is fixed in 1.19.1.

- [https://github.com/Ghalendar/CVE-2026-27971_POC](https://github.com/Ghalendar/CVE-2026-27971_POC) :  ![starts](https://img.shields.io/github/stars/Ghalendar/CVE-2026-27971_POC.svg) ![forks](https://img.shields.io/github/forks/Ghalendar/CVE-2026-27971_POC.svg)


## CVE-2026-27654
 NGINX Open Source and NGINX Plus have a vulnerability in the ngx_http_dav_module module that might allow an attacker to trigger a buffer overflow to the NGINX worker process; this vulnerability may result in termination of the NGINX worker process or modification of source or destination file names outside the document root. This issue affects NGINX Open Source and NGINX Plus when the configuration file uses DAV module MOVE or COPY methods, prefix location (nonregular expression location configuration), and alias directives. The integrity impact is constrained because the NGINX worker process user has low privileges and does not have access to the entire system. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/Debajyoti0-0/CVE-2026-27654-PoC](https://github.com/Debajyoti0-0/CVE-2026-27654-PoC) :  ![starts](https://img.shields.io/github/stars/Debajyoti0-0/CVE-2026-27654-PoC.svg) ![forks](https://img.shields.io/github/forks/Debajyoti0-0/CVE-2026-27654-PoC.svg)


## CVE-2026-25632
 EPyT-Flow is a Python package designed for the easy generation of hydraulic and water quality scenario data of water distribution networks. Prior to 0.16.1, EPyT-Flow’s REST API parses attacker-controlled JSON request bodies using a custom deserializer (my_load_from_json) that supports a type field. When type is present, the deserializer dynamically imports an attacker-specified module/class and instantiates it with attacker-supplied arguments. This allows invoking dangerous classes such as subprocess.Popen, which can lead to OS command execution during JSON parsing. This also affects the loading of JSON files. This vulnerability is fixed in 0.16.1.

- [https://github.com/lazarus0x1337/CVE-2026-25632](https://github.com/lazarus0x1337/CVE-2026-25632) :  ![starts](https://img.shields.io/github/stars/lazarus0x1337/CVE-2026-25632.svg) ![forks](https://img.shields.io/github/forks/lazarus0x1337/CVE-2026-25632.svg)


## CVE-2026-23550
 Incorrect Privilege Assignment vulnerability in Modular DS Modular DS modular-connector allows Privilege Escalation.This issue affects Modular DS: from n/a through = 2.5.1.

- [https://github.com/baktistr/cve-2026-23550-poc](https://github.com/baktistr/cve-2026-23550-poc) :  ![starts](https://img.shields.io/github/stars/baktistr/cve-2026-23550-poc.svg) ![forks](https://img.shields.io/github/forks/baktistr/cve-2026-23550-poc.svg)


## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.

- [https://github.com/qianlijaingshan/n8n-cve-2026-21858](https://github.com/qianlijaingshan/n8n-cve-2026-21858) :  ![starts](https://img.shields.io/github/stars/qianlijaingshan/n8n-cve-2026-21858.svg) ![forks](https://img.shields.io/github/forks/qianlijaingshan/n8n-cve-2026-21858.svg)


## CVE-2026-20169
This vulnerability is due to insufficient input validation of user-supplied data. An attacker could exploit this vulnerability by submitting crafted input in the web-based management interface. A successful exploit could allow the attacker to create, read, or delete files and execute limited commands in&nbsp;user EXEC mode on a remote router.

- [https://github.com/gigachadusers/CVE-2026-20169](https://github.com/gigachadusers/CVE-2026-20169) :  ![starts](https://img.shields.io/github/stars/gigachadusers/CVE-2026-20169.svg) ![forks](https://img.shields.io/github/forks/gigachadusers/CVE-2026-20169.svg)


## CVE-2026-16219
 A flaw has been found in Croogo CMS up to 4.0.7. This affects the function FileManager::isEditable of the file FileManager/src/Utility/FileManager.php of the component Admin File Manager. This manipulation causes path traversal. The attack can be initiated remotely. The exploit has been published and may be used. The project was informed of the problem early through an issue report but has not responded yet.

- [https://github.com/HELLBOY3110/cve-2026-16219-croogo-lab](https://github.com/HELLBOY3110/cve-2026-16219-croogo-lab) :  ![starts](https://img.shields.io/github/stars/HELLBOY3110/cve-2026-16219-croogo-lab.svg) ![forks](https://img.shields.io/github/forks/HELLBOY3110/cve-2026-16219-croogo-lab.svg)


## CVE-2026-13233
 Server-Side Request Forgery (SSRF) vulnerability in Drupal OpenAI Provider allows Server Side Request Forgery. This issue affects OpenAI Provider versions: from 0.0.0 to 1.1.1, from 1.2.0 to 1.2.2.

- [https://github.com/KuniNogu/drupal-openai-provider-ssrf-cve-2026-13233](https://github.com/KuniNogu/drupal-openai-provider-ssrf-cve-2026-13233) :  ![starts](https://img.shields.io/github/stars/KuniNogu/drupal-openai-provider-ssrf-cve-2026-13233.svg) ![forks](https://img.shields.io/github/forks/KuniNogu/drupal-openai-provider-ssrf-cve-2026-13233.svg)


## CVE-2026-13156
 The MailerSend  WordPress plugin before 1.0.8 does not perform a nonce check on its configuration-delete action (it verifies the manage_options capability but ignores the nonce), so an attacker can trick a logged-in administrator into visiting a crafted page that wipes the MailerSend  WordPress plugin before 1.0.8's SMTP configuration and deactivates the MailerSend  WordPress plugin before 1.0.8, breaking the site's email delivery.

- [https://github.com/MinhHK68/CVE-2026-13156](https://github.com/MinhHK68/CVE-2026-13156) :  ![starts](https://img.shields.io/github/stars/MinhHK68/CVE-2026-13156.svg) ![forks](https://img.shields.io/github/forks/MinhHK68/CVE-2026-13156.svg)


## CVE-2026-12191
 A vulnerability was found in Comma AI Openpilot 0.11. This issue affects the function pickle.load/pickle.loads of the file selfdrive/modeld/modeld.py of the component Pickle Module. The manipulation results in deserialization. The attack is only possible with local access. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/hakaioffsec/CVE-2026-12191](https://github.com/hakaioffsec/CVE-2026-12191) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/CVE-2026-12191.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/CVE-2026-12191.svg)


## CVE-2026-11374
 by an unauthenticated user, leading to account takeover.

- [https://github.com/BishopFox/CVE-2026-11374-check](https://github.com/BishopFox/CVE-2026-11374-check) :  ![starts](https://img.shields.io/github/stars/BishopFox/CVE-2026-11374-check.svg) ![forks](https://img.shields.io/github/forks/BishopFox/CVE-2026-11374-check.svg)


## CVE-2026-11349
 The Modern Event Calendar Pro WordPress plugin before 7.34.0, Modern Events Calendar Lite WordPress plugin before 7.34.0 do not sanitise and escape a request parameter before using it in a SQL statement, through an AJAX action available to unauthenticated users, leading to an unauthenticated SQL injection vulnerability that allows attackers to extract sensitive data from the database.

- [https://github.com/Hann1bl3L3ct3r/CVE-2026-11349](https://github.com/Hann1bl3L3ct3r/CVE-2026-11349) :  ![starts](https://img.shields.io/github/stars/Hann1bl3L3ct3r/CVE-2026-11349.svg) ![forks](https://img.shields.io/github/forks/Hann1bl3L3ct3r/CVE-2026-11349.svg)


## CVE-2026-9973
 Out of bounds write in V8 in Google Chrome prior to 148.0.7778.216 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/jaf0rk/CVE-2026-9973-exploit](https://github.com/jaf0rk/CVE-2026-9973-exploit) :  ![starts](https://img.shields.io/github/stars/jaf0rk/CVE-2026-9973-exploit.svg) ![forks](https://img.shields.io/github/forks/jaf0rk/CVE-2026-9973-exploit.svg)


## CVE-2026-9789
 A Local Privilege Escalation (LPE) vulnerability affects Acer NitroSense software versions prior to 3.01.3052. The vulnerability stems from the the PSAdminAgent service, which creates a Named Pipe with a weak Access Control List (ACL). This allows any authenticated local user to connect and send commands. Because the service does not check the caller's privileges before running file deletion commands, a low-privileged local user can exploit this to delete arbitrary files with system authority.

- [https://github.com/ugvxb/CVE-2026-9789](https://github.com/ugvxb/CVE-2026-9789) :  ![starts](https://img.shields.io/github/stars/ugvxb/CVE-2026-9789.svg) ![forks](https://img.shields.io/github/forks/ugvxb/CVE-2026-9789.svg)


## CVE-2026-9490
 A security vulnerability has been identified in Acer Care Center where the ACCSvc service creates a Named Pipe with a weak Security Descriptor. This vulnerability allows an authenticated local user to connect and send a specially crafted message (message type 0x03) to the pipe, causing the service to crash with exit code 1067 (ERROR_PROCESS_ABORTED). To mitigate this potential local service disruption, Acer requires users to update the software to the latest version.

- [https://github.com/ugvxb/CVE-2026-9490](https://github.com/ugvxb/CVE-2026-9490) :  ![starts](https://img.shields.io/github/stars/ugvxb/CVE-2026-9490.svg) ![forks](https://img.shields.io/github/forks/ugvxb/CVE-2026-9490.svg)


## CVE-2026-9198
 IBM Langflow OSS 1.0.0 through 1.10.0 allows unauthenticated attackers to chain /api/v1/auto_login (mints SUPERUSER tokens to any network caller) with /api/v1/validate/code (executes user code via exec()) to achieve full RCE on default Langflow deployments

- [https://github.com/0xdak/CVE-2026-9198_exploit](https://github.com/0xdak/CVE-2026-9198_exploit) :  ![starts](https://img.shields.io/github/stars/0xdak/CVE-2026-9198_exploit.svg) ![forks](https://img.shields.io/github/forks/0xdak/CVE-2026-9198_exploit.svg)


## CVE-2026-6875
We recommend customers promptly apply appropriate updates or upgrade to a patched release if they have not already done so.

- [https://github.com/HORKimhab/CVE-2026-6875](https://github.com/HORKimhab/CVE-2026-6875) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-6875.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-6875.svg)
- [https://github.com/tc4dy/CVE-2026-6875-PoC-Exploit](https://github.com/tc4dy/CVE-2026-6875-PoC-Exploit) :  ![starts](https://img.shields.io/github/stars/tc4dy/CVE-2026-6875-PoC-Exploit.svg) ![forks](https://img.shields.io/github/forks/tc4dy/CVE-2026-6875-PoC-Exploit.svg)


## CVE-2026-5141
This issue affects Pardus Software Center: from 1.0.2 before 1.0.3.

- [https://github.com/Renio-wow/CVE-2026-51416](https://github.com/Renio-wow/CVE-2026-51416) :  ![starts](https://img.shields.io/github/stars/Renio-wow/CVE-2026-51416.svg) ![forks](https://img.shields.io/github/forks/Renio-wow/CVE-2026-51416.svg)


## CVE-2026-5029
 A remote code execution vulnerability exists in Code Runner MCP Server when run with the --transport http option, which exposes the /mcp JSON-RPC endpoint without authentication on port 3088. An unauthenticated remote attacker can invoke the run-code MCP tool to supply arbitrary source code and execute it via child_process.exec() using the specified language interpreter. This allows execution of arbitrary code with the privileges of the user running the server. This vulnerability has not been fixed and might affect the project in all versions.

- [https://github.com/0x00phantom-hat/CVE-2026-5029-Exploit](https://github.com/0x00phantom-hat/CVE-2026-5029-Exploit) :  ![starts](https://img.shields.io/github/stars/0x00phantom-hat/CVE-2026-5029-Exploit.svg) ![forks](https://img.shields.io/github/forks/0x00phantom-hat/CVE-2026-5029-Exploit.svg)


## CVE-2026-3576
 The Planyo Online Reservation System plugin for WordPress is vulnerable to Server-Side Request Forgery leading to Local File Inclusion in all versions up to, and including, 3.0. The ulap.php file acts as an AJAX proxy and is directly accessible without WordPress bootstrapping or any authentication. The send_http_post() function validates the host of the provided URL against an allowlist that includes 'localhost', but critically fails to validate the URL scheme/protocol. This makes it possible for unauthenticated attackers to supply a file:// URL (e.g., file://localhost/etc/passwd) which bypasses the host allowlist check because parse_url() returns 'localhost' as the host. The URL is then passed to curl_init() or fopen(), both of which support the file:// protocol, allowing the attacker to read arbitrary local files on the server and have their contents returned in the HTTP response. This can lead to disclosure of sensitive files such as /etc/passwd, wp-config.php (containing database credentials and authentication keys), and other server-side files.

- [https://github.com/anirbala98/CVE-2026-3576](https://github.com/anirbala98/CVE-2026-3576) :  ![starts](https://img.shields.io/github/stars/anirbala98/CVE-2026-3576.svg) ![forks](https://img.shields.io/github/forks/anirbala98/CVE-2026-3576.svg)


## CVE-2026-0776
The specific flaw exists within the discord_rpc module. The product loads a file from an unsecured location. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of a target user. Was ZDI-CAN-27057.

- [https://github.com/whenx/CVE-2026-0776](https://github.com/whenx/CVE-2026-0776) :  ![starts](https://img.shields.io/github/stars/whenx/CVE-2026-0776.svg) ![forks](https://img.shields.io/github/forks/whenx/CVE-2026-0776.svg)


## CVE-2026-0059
 In multiple functions of sdp_discovery.cc, there is a possible way to achieve code execution due to a heap buffer overflow. This could lead to remote (proximal/adjacent) code execution with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/paul-goon/bootlicka-POC](https://github.com/paul-goon/bootlicka-POC) :  ![starts](https://img.shields.io/github/stars/paul-goon/bootlicka-POC.svg) ![forks](https://img.shields.io/github/forks/paul-goon/bootlicka-POC.svg)


## CVE-2025-69419
OpenSSL 1.0.2 is not affected by this issue.

- [https://github.com/Kha-Beleh/PoC-CVE-2025-69419](https://github.com/Kha-Beleh/PoC-CVE-2025-69419) :  ![starts](https://img.shields.io/github/stars/Kha-Beleh/PoC-CVE-2025-69419.svg) ![forks](https://img.shields.io/github/forks/Kha-Beleh/PoC-CVE-2025-69419.svg)


## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/qianlijaingshan/n8n-cve-2026-21858](https://github.com/qianlijaingshan/n8n-cve-2026-21858) :  ![starts](https://img.shields.io/github/stars/qianlijaingshan/n8n-cve-2026-21858.svg) ![forks](https://img.shields.io/github/forks/qianlijaingshan/n8n-cve-2026-21858.svg)


## CVE-2025-64512
 Pdfminer.six is a community maintained fork of the original PDFMiner, a tool for extracting information from PDF documents. Prior to version 20251107, pdfminer.six will execute arbitrary code from a malicious pickle file if provided with a malicious PDF file. The `CMapDB._load_data()` function in pdfminer.six uses `pickle.loads()` to deserialize pickle files. These pickle files are supposed to be part of the pdfminer.six distribution stored in the `cmap/` directory, but a malicious PDF can specify an alternative directory and filename as long as the filename ends in `.pickle.gz`. A malicious, zipped pickle file can then contain code which will automatically execute when the PDF is processed. Version 20251107 fixes the issue.

- [https://github.com/BardLaudian/CVE-2025-64512](https://github.com/BardLaudian/CVE-2025-64512) :  ![starts](https://img.shields.io/github/stars/BardLaudian/CVE-2025-64512.svg) ![forks](https://img.shields.io/github/forks/BardLaudian/CVE-2025-64512.svg)
- [https://github.com/joeack123/PoC-for-CVE-2025-64512](https://github.com/joeack123/PoC-for-CVE-2025-64512) :  ![starts](https://img.shields.io/github/stars/joeack123/PoC-for-CVE-2025-64512.svg) ![forks](https://img.shields.io/github/forks/joeack123/PoC-for-CVE-2025-64512.svg)
- [https://github.com/MehdiChyhab/CVE-2025-64512-exploit](https://github.com/MehdiChyhab/CVE-2025-64512-exploit) :  ![starts](https://img.shields.io/github/stars/MehdiChyhab/CVE-2025-64512-exploit.svg) ![forks](https://img.shields.io/github/forks/MehdiChyhab/CVE-2025-64512-exploit.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/se1zer/Nextjs_Exploit_Tool](https://github.com/se1zer/Nextjs_Exploit_Tool) :  ![starts](https://img.shields.io/github/stars/se1zer/Nextjs_Exploit_Tool.svg) ![forks](https://img.shields.io/github/forks/se1zer/Nextjs_Exploit_Tool.svg)


## CVE-2025-49596
 The MCP inspector is a developer tool for testing and debugging MCP servers. Versions of MCP Inspector below 0.14.1 are vulnerable to remote code execution due to lack of authentication between the Inspector client and proxy, allowing unauthenticated requests to launch MCP commands over stdio. Users should immediately upgrade to version 0.14.1 or later to address these vulnerabilities.

- [https://github.com/RajSidwadkar/UAP-protocol](https://github.com/RajSidwadkar/UAP-protocol) :  ![starts](https://img.shields.io/github/stars/RajSidwadkar/UAP-protocol.svg) ![forks](https://img.shields.io/github/forks/RajSidwadkar/UAP-protocol.svg)


## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

- [https://github.com/c0gnit00/CVE-2025-32432](https://github.com/c0gnit00/CVE-2025-32432) :  ![starts](https://img.shields.io/github/stars/c0gnit00/CVE-2025-32432.svg) ![forks](https://img.shields.io/github/forks/c0gnit00/CVE-2025-32432.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/Loufa0/CVE-2025-24813](https://github.com/Loufa0/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/Loufa0/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/Loufa0/CVE-2025-24813.svg)


## CVE-2025-20352
 Note: This vulnerability affects all versions of SNMP.

- [https://github.com/sentinel-aidefense/CVE-2025-20352](https://github.com/sentinel-aidefense/CVE-2025-20352) :  ![starts](https://img.shields.io/github/stars/sentinel-aidefense/CVE-2025-20352.svg) ![forks](https://img.shields.io/github/forks/sentinel-aidefense/CVE-2025-20352.svg)


## CVE-2025-10725
 A flaw was found in Red Hat Openshift AI Service. A low-privileged attacker with access to an authenticated account, for example as a data scientist using a standard Jupyter notebook, can escalate their privileges to a full cluster administrator. This allows for the complete compromise of the cluster's confidentiality, integrity, and availability. The attacker can steal sensitive data, disrupt all services, and take control of the underlying infrastructure, leading to a total breach of the platform and all applications hosted on it.

- [https://github.com/kaiokmo/cve-2025-10725-eda-demo](https://github.com/kaiokmo/cve-2025-10725-eda-demo) :  ![starts](https://img.shields.io/github/stars/kaiokmo/cve-2025-10725-eda-demo.svg) ![forks](https://img.shields.io/github/forks/kaiokmo/cve-2025-10725-eda-demo.svg)


## CVE-2025-9242
 An Out-of-bounds Write vulnerability in WatchGuard Fireware OS may allow a remote unauthenticated attacker to execute arbitrary code. This vulnerability affects both the Mobile User VPN with IKEv2 and the Branch Office VPN using IKEv2 when configured with a dynamic gateway peer.This vulnerability affects Fireware OS 11.10.2 up to and including 11.12.4_Update1, 12.0 up to and including 12.11.3 and 2025.1.

- [https://github.com/UnusualGiraffe/PoC-Unauthenticated-RCE-in-WatchGuard-Fireware-12.7-Build-640389-CVE-2025-9242](https://github.com/UnusualGiraffe/PoC-Unauthenticated-RCE-in-WatchGuard-Fireware-12.7-Build-640389-CVE-2025-9242) :  ![starts](https://img.shields.io/github/stars/UnusualGiraffe/PoC-Unauthenticated-RCE-in-WatchGuard-Fireware-12.7-Build-640389-CVE-2025-9242.svg) ![forks](https://img.shields.io/github/forks/UnusualGiraffe/PoC-Unauthenticated-RCE-in-WatchGuard-Fireware-12.7-Build-640389-CVE-2025-9242.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/ixZODiAK/CVE-2025-8110](https://github.com/ixZODiAK/CVE-2025-8110) :  ![starts](https://img.shields.io/github/stars/ixZODiAK/CVE-2025-8110.svg) ![forks](https://img.shields.io/github/forks/ixZODiAK/CVE-2025-8110.svg)


## CVE-2024-29973
The command injection vulnerability in the “setCookie” parameter in Zyxel NAS326 firmware versions before V5.21(AAZF.17)C0 and NAS542 firmware versions before V5.21(ABAG.14)C0 could allow an unauthenticated attacker to execute some operating system (OS) commands by sending a crafted HTTP POST request.

- [https://github.com/solo364/CVE-2024-29973](https://github.com/solo364/CVE-2024-29973) :  ![starts](https://img.shields.io/github/stars/solo364/CVE-2024-29973.svg) ![forks](https://img.shields.io/github/forks/solo364/CVE-2024-29973.svg)


## CVE-2024-27867
 An authentication issue was addressed with improved state management. This issue is fixed in AirPods Firmware Update 6A326, AirPods Firmware Update 6F8, and Beats Firmware Update 6F8. When your headphones are seeking a connection request to one of your previously paired devices, an attacker in Bluetooth range might be able to spoof the intended source device and gain access to your headphones.

- [https://github.com/Hirador/pspgo-airpods-802F0130](https://github.com/Hirador/pspgo-airpods-802F0130) :  ![starts](https://img.shields.io/github/stars/Hirador/pspgo-airpods-802F0130.svg) ![forks](https://img.shields.io/github/forks/Hirador/pspgo-airpods-802F0130.svg)


## CVE-2024-26229
 Windows CSC Service Elevation of Privilege Vulnerability

- [https://github.com/shinspace92/cve-2024-26229](https://github.com/shinspace92/cve-2024-26229) :  ![starts](https://img.shields.io/github/stars/shinspace92/cve-2024-26229.svg) ![forks](https://img.shields.io/github/forks/shinspace92/cve-2024-26229.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/solo364/CVE-2024-24919](https://github.com/solo364/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/solo364/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/solo364/CVE-2024-24919.svg)


## CVE-2024-9264
 The SQL Expressions experimental feature of Grafana allows for the evaluation of `duckdb` queries containing user input. These queries are insufficiently sanitized before being passed to `duckdb`, leading to a command injection and local file inclusion vulnerability. Any user with the VIEWER or higher permission is capable of executing this attack.  The `duckdb` binary must be present in Grafana's $PATH for this attack to function; by default, this binary is not installed in Grafana distributions.

- [https://github.com/ozcanpng/CVE-2024-9264](https://github.com/ozcanpng/CVE-2024-9264) :  ![starts](https://img.shields.io/github/stars/ozcanpng/CVE-2024-9264.svg) ![forks](https://img.shields.io/github/forks/ozcanpng/CVE-2024-9264.svg)


## CVE-2024-7593
 Incorrect implementation of an authentication algorithm in Ivanti vTM other than versions 22.2R1 or 22.7R2 allows a remote unauthenticated attacker to bypass authentication of the admin panel.

- [https://github.com/solo364/CVE-2024-7593](https://github.com/solo364/CVE-2024-7593) :  ![starts](https://img.shields.io/github/stars/solo364/CVE-2024-7593.svg) ![forks](https://img.shields.io/github/forks/solo364/CVE-2024-7593.svg)


## CVE-2024-4068
 The NPM package `braces`, versions prior to 3.0.3, fails to limit the number of characters it can handle, which could lead to Memory Exhaustion. In `lib/parse.js,` if a malicious user sends "imbalanced braces" as input, the parsing will enter a loop, which will cause the program to start allocating heap memory without freeing it at any moment of the loop. Eventually, the JavaScript heap limit is reached, and the program will crash.

- [https://github.com/cyeezy08/DoS-Braces-3.03](https://github.com/cyeezy08/DoS-Braces-3.03) :  ![starts](https://img.shields.io/github/stars/cyeezy08/DoS-Braces-3.03.svg) ![forks](https://img.shields.io/github/forks/cyeezy08/DoS-Braces-3.03.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/Preacher98/Report-XZ-Utils-CVE-2024-3094](https://github.com/Preacher98/Report-XZ-Utils-CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/Preacher98/Report-XZ-Utils-CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/Preacher98/Report-XZ-Utils-CVE-2024-3094.svg)
- [https://github.com/x-cmd-build/xz](https://github.com/x-cmd-build/xz) :  ![starts](https://img.shields.io/github/stars/x-cmd-build/xz.svg) ![forks](https://img.shields.io/github/forks/x-cmd-build/xz.svg)


## CVE-2024-2876
 The Email Subscribers by Icegram Express – Email Marketing, Newsletters, Automation for WordPress & WooCommerce plugin for WordPress is vulnerable to SQL Injection via the 'run' function of the 'IG_ES_Subscribers_Query' class in all versions up to, and including, 5.7.14 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/solo364/CVE-2024-2876](https://github.com/solo364/CVE-2024-2876) :  ![starts](https://img.shields.io/github/stars/solo364/CVE-2024-2876.svg) ![forks](https://img.shields.io/github/forks/solo364/CVE-2024-2876.svg)


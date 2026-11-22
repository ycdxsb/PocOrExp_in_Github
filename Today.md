# Update 2026-11-22
## CVE-2026-133626
Affected versions: FlowIntel prior to 4.1.0

- [https://github.com/googlesky/CVE-2026-133626](https://github.com/googlesky/CVE-2026-133626) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133626.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133626.svg)


## CVE-2026-133624
 SCTP protocol dissector heap disclosure in 4.6.0 to 4.6.9 and 4.4.0 to 4.4.19 might enable denial of service or code execution

- [https://github.com/googlesky/CVE-2026-133624](https://github.com/googlesky/CVE-2026-133624) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133624.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133624.svg)


## CVE-2026-133620
Affected: Flowintel versions prior to 4.1.0.

- [https://github.com/googlesky/CVE-2026-133620](https://github.com/googlesky/CVE-2026-133620) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133620.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133620.svg)


## CVE-2026-133481
 In Dolibarr before 24.0.3, /api/index.php/eventattendees discloses attendee and project data regardless of the caller's permissions. Only 22.0.0 and later (where api_eventattendees.class.php exists) are affected. A remote authenticated user can obtain column values one character at a time.

- [https://github.com/googlesky/CVE-2026-133481](https://github.com/googlesky/CVE-2026-133481) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133481.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133481.svg)


## CVE-2026-133430
 A flaw was found in Keycloak. This vulnerability allows an authenticated remote attacker to cause a denial of service by terminating active sessions of arbitrary users. When processing Security Assertion Markup Language (SAML) documents that lack a root signature, Keycloak accepts the request as long as any assertion within the document is signed, without verifying its context or placement. An attacker holding a validly signed assertion can embed it into an unsigned logout request for another user, causing Keycloak to accept the forged request and terminate the victim's session.

- [https://github.com/googlesky/CVE-2026-133430](https://github.com/googlesky/CVE-2026-133430) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133430.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133430.svg)
- [https://github.com/LLCForge/CVE-2026-133430](https://github.com/LLCForge/CVE-2026-133430) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-133430.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-133430.svg)


## CVE-2026-132825
 Ruby before 3.3.14, 3.4.13, and 4.0.10 has a heap-based buffer overflow during case conversion. One byte can be written outside a buffer for, for example, ISO-8859-1 or Windows-1252.

- [https://github.com/genaforvena/mishe-tauftauf2shell](https://github.com/genaforvena/mishe-tauftauf2shell) :  ![starts](https://img.shields.io/github/stars/genaforvena/mishe-tauftauf2shell.svg) ![forks](https://img.shields.io/github/forks/genaforvena/mishe-tauftauf2shell.svg)
- [https://github.com/ashrafzaryouh/CVE-2026-132825](https://github.com/ashrafzaryouh/CVE-2026-132825) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-132825.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-132825.svg)
- [https://github.com/hackpatato/CVE-2026-132825-poc](https://github.com/hackpatato/CVE-2026-132825-poc) :  ![starts](https://img.shields.io/github/stars/hackpatato/CVE-2026-132825-poc.svg) ![forks](https://img.shields.io/github/forks/hackpatato/CVE-2026-132825-poc.svg)
- [https://github.com/techdevfun/ruby2shell](https://github.com/techdevfun/ruby2shell) :  ![starts](https://img.shields.io/github/stars/techdevfun/ruby2shell.svg) ![forks](https://img.shields.io/github/forks/techdevfun/ruby2shell.svg)
- [https://github.com/Mahgal/ruby2shell-check](https://github.com/Mahgal/ruby2shell-check) :  ![starts](https://img.shields.io/github/stars/Mahgal/ruby2shell-check.svg) ![forks](https://img.shields.io/github/forks/Mahgal/ruby2shell-check.svg)


## CVE-2026-132749
 Vtiger CRM through 8.4.0 contains a blind SQL injection vulnerability in ReportRun::generateAdvFilterSql() that allows authenticated low-privileged users to inject SQL via the bw comparator. Attackers can send a crafted advanced_filter parameter containing a single quote to the Reports getRecordsCount action to break out of BETWEEN literals and extract database contents.

- [https://github.com/SHAHID-XT/CVE-2026-132749-Vtiger-CRM-Reports-SQLi](https://github.com/SHAHID-XT/CVE-2026-132749-Vtiger-CRM-Reports-SQLi) :  ![starts](https://img.shields.io/github/stars/SHAHID-XT/CVE-2026-132749-Vtiger-CRM-Reports-SQLi.svg) ![forks](https://img.shields.io/github/forks/SHAHID-XT/CVE-2026-132749-Vtiger-CRM-Reports-SQLi.svg)


## CVE-2026-132748
 Vtiger CRM through 8.4.0 contains a PHP code injection vulnerability that allows authenticated administrators to inject code via the updatedFields parameter into config.inc.php. Attackers can supply a crafted HELPDESK_SUPPORT_EMAIL_ID value that passes email validation but closes the PHP string literal to execute arbitrary operating system commands.

- [https://github.com/SHAHID-XT/CVE-2026-132748-Vtiger-CRM-PHP-Code-Injection](https://github.com/SHAHID-XT/CVE-2026-132748-Vtiger-CRM-PHP-Code-Injection) :  ![starts](https://img.shields.io/github/stars/SHAHID-XT/CVE-2026-132748-Vtiger-CRM-PHP-Code-Injection.svg) ![forks](https://img.shields.io/github/forks/SHAHID-XT/CVE-2026-132748-Vtiger-CRM-PHP-Code-Injection.svg)


## CVE-2026-132747
 Vtiger CRM through 8.4.0 contains an SQL injection vulnerability that allows authenticated users with export access to inject SQL through unvalidated selected_ids values in ExportData.php. Attackers can send a UNION SELECT payload in selected_ids[] to the ExportSelectedRecords mode and read password hashes and access keys from the exported CSV.

- [https://github.com/SHAHID-XT/CVE-2026-132747-Vtiger-CRM-ExportData-SQLi](https://github.com/SHAHID-XT/CVE-2026-132747-Vtiger-CRM-ExportData-SQLi) :  ![starts](https://img.shields.io/github/stars/SHAHID-XT/CVE-2026-132747-Vtiger-CRM-ExportData-SQLi.svg) ![forks](https://img.shields.io/github/forks/SHAHID-XT/CVE-2026-132747-Vtiger-CRM-ExportData-SQLi.svg)


## CVE-2026-132746
 Vtiger CRM through 8.4.0 contains a blind SQL injection vulnerability that allows authenticated low-privileged users to inject SQL via unescaped clientid values in the wsapp_map webservice operation. Attackers can register a sync application with wsapp_register, then send delete-mode entries with quoted clientid values processed by SyncServer.php to extract database contents including administrator access keys.

- [https://github.com/SHAHID-XT/CVE-2026-132746-Vtiger-CRM-WSAPP-SQLi-](https://github.com/SHAHID-XT/CVE-2026-132746-Vtiger-CRM-WSAPP-SQLi-) :  ![starts](https://img.shields.io/github/stars/SHAHID-XT/CVE-2026-132746-Vtiger-CRM-WSAPP-SQLi-.svg) ![forks](https://img.shields.io/github/forks/SHAHID-XT/CVE-2026-132746-Vtiger-CRM-WSAPP-SQLi-.svg)


## CVE-2026-132745
 Vtiger CRM through 8.4.0 contains a blind SQL injection vulnerability that allows authenticated non-administrative users to inject SQL through the k (does not contain) comparator in list view search_params. Attackers can send crafted search_params to the ListAjax getRecordsCount mode, breaking out of the unescaped NOT LIKE clause to extract database contents via boolean or time-based techniques.

- [https://github.com/SHAHID-XT/CVE-2026-132745-Vtiger-CRM-Blind-SQLi](https://github.com/SHAHID-XT/CVE-2026-132745-Vtiger-CRM-Blind-SQLi) :  ![starts](https://img.shields.io/github/stars/SHAHID-XT/CVE-2026-132745-Vtiger-CRM-Blind-SQLi.svg) ![forks](https://img.shields.io/github/forks/SHAHID-XT/CVE-2026-132745-Vtiger-CRM-Blind-SQLi.svg)


## CVE-2026-130176
 aMQTT is an open source MQTT broker and client. From 0.11.0 until 0.12.1, the QoS 2 transaction handler in amqtt/mqtt/protocol/handler.py, _handle_qos2_message_flow(), can retain transaction state and packet identifiers when a client disconnects before the handshake completes, unlike QoS 1 flows that expire after the default five-second timeout. A remote client can repeatedly begin QoS 2 flows and disconnect without maintaining long-lived connections; anonymous clients can do this with the default configuration, while authenticated deployments remain affected when a client may initiate QoS 2 flows. The retained state grows broker memory until resource exhaustion can terminate the process; no confidentiality or integrity impact is identified. This issue is fixed in version 0.12.1.

- [https://github.com/googlesky/CVE-2026-130176](https://github.com/googlesky/CVE-2026-130176) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-130176.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-130176.svg)


## CVE-2026-129496
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/LLCForge/CVE-2026-129496](https://github.com/LLCForge/CVE-2026-129496) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-129496.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-129496.svg)


## CVE-2026-129474
This issue affects PHP versions 8.5.* before 8.5.13.

- [https://github.com/LLCForge/CVE-2026-129474](https://github.com/LLCForge/CVE-2026-129474) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-129474.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-129474.svg)


## CVE-2026-129448
Users who cannot upgrade right away should set "enabledForExtensions" to "false" in WEB-INF/web.xml, or remove the "/roller-services/xmlrpc" servlet mapping, and restart Roller. Disabling XML-RPC in the administration UI is not enough, because older versions deserialize the request before checking that setting.

- [https://github.com/foxcornlab/apache-roller-scanner](https://github.com/foxcornlab/apache-roller-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/apache-roller-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/apache-roller-scanner.svg)


## CVE-2026-129289
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/LLCForge/CVE-2026-129289](https://github.com/LLCForge/CVE-2026-129289) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-129289.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-129289.svg)


## CVE-2026-126714
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/bimajunestifa/phpAfterShell](https://github.com/bimajunestifa/phpAfterShell) :  ![starts](https://img.shields.io/github/stars/bimajunestifa/phpAfterShell.svg) ![forks](https://img.shields.io/github/forks/bimajunestifa/phpAfterShell.svg)
- [https://github.com/ashrafzaryouh/CVE-2026-126714](https://github.com/ashrafzaryouh/CVE-2026-126714) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-126714.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-126714.svg)
- [https://github.com/evenomn/cve-2026-126714-phpAfterShell](https://github.com/evenomn/cve-2026-126714-phpAfterShell) :  ![starts](https://img.shields.io/github/stars/evenomn/cve-2026-126714-phpAfterShell.svg) ![forks](https://img.shields.io/github/forks/evenomn/cve-2026-126714-phpAfterShell.svg)
- [https://github.com/donxud/PHP2Shell-Security-Investigation](https://github.com/donxud/PHP2Shell-Security-Investigation) :  ![starts](https://img.shields.io/github/stars/donxud/PHP2Shell-Security-Investigation.svg) ![forks](https://img.shields.io/github/forks/donxud/PHP2Shell-Security-Investigation.svg)
- [https://github.com/tani2shell/phpaftershell-lab](https://github.com/tani2shell/phpaftershell-lab) :  ![starts](https://img.shields.io/github/stars/tani2shell/phpaftershell-lab.svg) ![forks](https://img.shields.io/github/forks/tani2shell/phpaftershell-lab.svg)
- [https://github.com/VABISMO/PHPAfterShell-poc](https://github.com/VABISMO/PHPAfterShell-poc) :  ![starts](https://img.shields.io/github/stars/VABISMO/PHPAfterShell-poc.svg) ![forks](https://img.shields.io/github/forks/VABISMO/PHPAfterShell-poc.svg)


## CVE-2026-123890
Telco Cloud Platform 3.0, 4.x, 5.0.x, 5.1.x, 5.2 and Telco Cloud Infrastructure 3.0 are also affected (see KB463116).

- [https://github.com/sanMuSec/vcenter-80u3m-patch-download](https://github.com/sanMuSec/vcenter-80u3m-patch-download) :  ![starts](https://img.shields.io/github/stars/sanMuSec/vcenter-80u3m-patch-download.svg) ![forks](https://img.shields.io/github/forks/sanMuSec/vcenter-80u3m-patch-download.svg)
- [https://github.com/LLCForge/CVE-2026-123890](https://github.com/LLCForge/CVE-2026-123890) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-123890.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-123890.svg)
- [https://github.com/Quaerendir/cve-2026-123890-audit](https://github.com/Quaerendir/cve-2026-123890-audit) :  ![starts](https://img.shields.io/github/stars/Quaerendir/cve-2026-123890-audit.svg) ![forks](https://img.shields.io/github/forks/Quaerendir/cve-2026-123890-audit.svg)
- [https://github.com/3tternp/vcenter-cve-2026-123890-check](https://github.com/3tternp/vcenter-cve-2026-123890-check) :  ![starts](https://img.shields.io/github/stars/3tternp/vcenter-cve-2026-123890-check.svg) ![forks](https://img.shields.io/github/forks/3tternp/vcenter-cve-2026-123890-check.svg)


## CVE-2026-123634
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts](https://github.com/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts) :  ![starts](https://img.shields.io/github/stars/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts.svg) ![forks](https://img.shields.io/github/forks/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts.svg)


## CVE-2026-123633
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/federiconbaez/cve-2026-123633-detector](https://github.com/federiconbaez/cve-2026-123633-detector) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cve-2026-123633-detector.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cve-2026-123633-detector.svg)
- [https://github.com/federiconbaez/cve-2026-123633-analysis](https://github.com/federiconbaez/cve-2026-123633-analysis) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cve-2026-123633-analysis.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cve-2026-123633-analysis.svg)
- [https://github.com/avoliomattia/NGINX-CVE-2026-123007-CVE-2026-123633](https://github.com/avoliomattia/NGINX-CVE-2026-123007-CVE-2026-123633) :  ![starts](https://img.shields.io/github/stars/avoliomattia/NGINX-CVE-2026-123007-CVE-2026-123633.svg) ![forks](https://img.shields.io/github/forks/avoliomattia/NGINX-CVE-2026-123007-CVE-2026-123633.svg)
- [https://github.com/federiconbaez/nginx-h2-hardening-audit](https://github.com/federiconbaez/nginx-h2-hardening-audit) :  ![starts](https://img.shields.io/github/stars/federiconbaez/nginx-h2-hardening-audit.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/nginx-h2-hardening-audit.svg)
- [https://github.com/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts](https://github.com/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts) :  ![starts](https://img.shields.io/github/stars/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts.svg) ![forks](https://img.shields.io/github/forks/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/Pauloxc6/CVE-2026-123158](https://github.com/Pauloxc6/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/Pauloxc6/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/Pauloxc6/CVE-2026-123158.svg)
- [https://github.com/unixsvr4/cve-sshole](https://github.com/unixsvr4/cve-sshole) :  ![starts](https://img.shields.io/github/stars/unixsvr4/cve-sshole.svg) ![forks](https://img.shields.io/github/forks/unixsvr4/cve-sshole.svg)
- [https://github.com/TheoCerveraLede/auditoria-ciberseguridad-ypf](https://github.com/TheoCerveraLede/auditoria-ciberseguridad-ypf) :  ![starts](https://img.shields.io/github/stars/TheoCerveraLede/auditoria-ciberseguridad-ypf.svg) ![forks](https://img.shields.io/github/forks/TheoCerveraLede/auditoria-ciberseguridad-ypf.svg)
- [https://github.com/aparnaa19/cve-to-chaos](https://github.com/aparnaa19/cve-to-chaos) :  ![starts](https://img.shields.io/github/stars/aparnaa19/cve-to-chaos.svg) ![forks](https://img.shields.io/github/forks/aparnaa19/cve-to-chaos.svg)


## CVE-2026-123007
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/federiconbaez/cve-2026-123007-detector](https://github.com/federiconbaez/cve-2026-123007-detector) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cve-2026-123007-detector.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cve-2026-123007-detector.svg)
- [https://github.com/federiconbaez/cve-2026-123007-analysis](https://github.com/federiconbaez/cve-2026-123007-analysis) :  ![starts](https://img.shields.io/github/stars/federiconbaez/cve-2026-123007-analysis.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/cve-2026-123007-analysis.svg)
- [https://github.com/avoliomattia/NGINX-CVE-2026-123007-CVE-2026-123633](https://github.com/avoliomattia/NGINX-CVE-2026-123007-CVE-2026-123633) :  ![starts](https://img.shields.io/github/stars/avoliomattia/NGINX-CVE-2026-123007-CVE-2026-123633.svg) ![forks](https://img.shields.io/github/forks/avoliomattia/NGINX-CVE-2026-123007-CVE-2026-123633.svg)
- [https://github.com/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts](https://github.com/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts) :  ![starts](https://img.shields.io/github/stars/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts.svg) ![forks](https://img.shields.io/github/forks/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts.svg)
- [https://github.com/bytevet/h2flowcheck](https://github.com/bytevet/h2flowcheck) :  ![starts](https://img.shields.io/github/stars/bytevet/h2flowcheck.svg) ![forks](https://img.shields.io/github/forks/bytevet/h2flowcheck.svg)
- [https://github.com/eduxcode/nginx2root-lab](https://github.com/eduxcode/nginx2root-lab) :  ![starts](https://img.shields.io/github/stars/eduxcode/nginx2root-lab.svg) ![forks](https://img.shields.io/github/forks/eduxcode/nginx2root-lab.svg)
- [https://github.com/federiconbaez/nginx-h2-hardening-audit](https://github.com/federiconbaez/nginx-h2-hardening-audit) :  ![starts](https://img.shields.io/github/stars/federiconbaez/nginx-h2-hardening-audit.svg) ![forks](https://img.shields.io/github/forks/federiconbaez/nginx-h2-hardening-audit.svg)
- [https://github.com/weitek/nginx2root](https://github.com/weitek/nginx2root) :  ![starts](https://img.shields.io/github/stars/weitek/nginx2root.svg) ![forks](https://img.shields.io/github/forks/weitek/nginx2root.svg)
- [https://github.com/genaforvena/nginx2root](https://github.com/genaforvena/nginx2root) :  ![starts](https://img.shields.io/github/stars/genaforvena/nginx2root.svg) ![forks](https://img.shields.io/github/forks/genaforvena/nginx2root.svg)
- [https://github.com/cyberdesserts/nmap-detections](https://github.com/cyberdesserts/nmap-detections) :  ![starts](https://img.shields.io/github/stars/cyberdesserts/nmap-detections.svg) ![forks](https://img.shields.io/github/forks/cyberdesserts/nmap-detections.svg)
- [https://github.com/kitten443/nginx2root](https://github.com/kitten443/nginx2root) :  ![starts](https://img.shields.io/github/stars/kitten443/nginx2root.svg) ![forks](https://img.shields.io/github/forks/kitten443/nginx2root.svg)


## CVE-2026-121810
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts](https://github.com/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts) :  ![starts](https://img.shields.io/github/stars/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts.svg) ![forks](https://img.shields.io/github/forks/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts.svg)


## CVE-2026-121481
The affected code is outside the FIPS module boundary.

- [https://github.com/Quaerendir/openssl-cve-2026-121481-audit](https://github.com/Quaerendir/openssl-cve-2026-121481-audit) :  ![starts](https://img.shields.io/github/stars/Quaerendir/openssl-cve-2026-121481-audit.svg) ![forks](https://img.shields.io/github/forks/Quaerendir/openssl-cve-2026-121481-audit.svg)


## CVE-2026-119348
 Next.js is a React framework for building full-stack web applications. Prior to 15.5.29 and 16.4.5, self-hosted Next.js App Router route handlers and the fetch cache that return a fetched upstream response unchanged can emit a response whose declared framing does not match the body actually sent. When the application is behind an HTTP/1.1 reverse proxy that permits pipelined response queueing, a crafted upstream response can desynchronize responses between clients. The resulting desynchronization can inject a response into another client's queue or disclose another client's response. This issue is fixed in versions 16.4.5 and 15.5.29.

- [https://github.com/aheybati/CVE-2026-119348](https://github.com/aheybati/CVE-2026-119348) :  ![starts](https://img.shields.io/github/stars/aheybati/CVE-2026-119348.svg) ![forks](https://img.shields.io/github/forks/aheybati/CVE-2026-119348.svg)


## CVE-2026-117517
Note: Tomcat 11.0.28 was not released

- [https://github.com/LLCForge/CVE-2026-117517](https://github.com/LLCForge/CVE-2026-117517) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-117517.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-117517.svg)
- [https://github.com/googlesky/CVE-2026-117517](https://github.com/googlesky/CVE-2026-117517) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-117517.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-117517.svg)


## CVE-2026-115578
 Go-Guerrilla SMTP Daemon is a lightweight SMTP server written in Go. In 1.6.7 and earlier, according to the repository advisory's structured affected range, server.go defines the seven-byte cmdXCLIENT token, but the XCLIENT handler slices input[8:] after matching only that seven-byte verb, so a bare command causes an out-of-bounds panic in handleClient and terminates the daemon because that connection goroutine does not recover the panic. The issue is reachable by an unauthenticated client when the non-default xclient_on setting is enabled; no HELO command is required. The repository fix is present in version 1.6.7-1.

- [https://github.com/googlesky/CVE-2026-115578](https://github.com/googlesky/CVE-2026-115578) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-115578.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-115578.svg)


## CVE-2026-115565
 storyblok-backup is an npx CLI tool to create backups of a Storyblok space and restore individual resources. Prior to 0.7.1, the writeJson function used the editable Storyblok component name field as a filename without path containment. A person with component-management access in a Storyblok space could store a component name containing path traversal sequences; when another user later ran a backup for that space, the stored name escaped the configured backup directory and caused a JSON file to be written outside it on the backup host. Depending on the path chosen and the backup process's permissions, this could overwrite existing files at attacker-chosen locations. The vulnerability is specific to components: stories and datasources use numeric identifiers, and asset names are reduced to a final path segment. This issue is fixed in version 0.7.1.

- [https://github.com/googlesky/CVE-2026-115565](https://github.com/googlesky/CVE-2026-115565) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-115565.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-115565.svg)


## CVE-2026-115463
 Poweradmin is a web-based DNS administration tool for PowerDNS server. From 4.0.0 until 4.2.6, 4.3.5, and 4.4.1, lib/Domain/Service/MfaService.php verifies email second-factor codes through MfaService::verifyCode() without limiting failed attempts, and lib/Application/Controller/MfaVerifyController.php logs failures without throttling them. An attacker who knows the user's password can repeatedly guess the six-digit code during its ten-minute validity period when email MFA is enabled, potentially bypassing the second factor; the advisory notes MFA is disabled by default and that the practical request rate was not measured. This issue is fixed in versions 4.2.6, 4.3.5, and 4.4.1.

- [https://github.com/googlesky/CVE-2026-115463](https://github.com/googlesky/CVE-2026-115463) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-115463.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-115463.svg)


## CVE-2026-114938
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Compiler).  Supported versions that are affected are Oracle Java SE: 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3; Oracle GraalVM for JDK: 17.0.21.0.3 and  21.0.13.0.3; Oracle GraalVM Enterprise Edition: 21.3.20.0.3. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/maxnyakundi23-del/java4shell-exposure-audit](https://github.com/maxnyakundi23-del/java4shell-exposure-audit) :  ![starts](https://img.shields.io/github/stars/maxnyakundi23-del/java4shell-exposure-audit.svg) ![forks](https://img.shields.io/github/forks/maxnyakundi23-del/java4shell-exposure-audit.svg)
- [https://github.com/crash00xd/java2shell-poc](https://github.com/crash00xd/java2shell-poc) :  ![starts](https://img.shields.io/github/stars/crash00xd/java2shell-poc.svg) ![forks](https://img.shields.io/github/forks/crash00xd/java2shell-poc.svg)
- [https://github.com/Luscious8/JVM2Shell](https://github.com/Luscious8/JVM2Shell) :  ![starts](https://img.shields.io/github/stars/Luscious8/JVM2Shell.svg) ![forks](https://img.shields.io/github/forks/Luscious8/JVM2Shell.svg)
- [https://github.com/tomcek42/Omnissa-UAG_CVE-2026-114938-remediation](https://github.com/tomcek42/Omnissa-UAG_CVE-2026-114938-remediation) :  ![starts](https://img.shields.io/github/stars/tomcek42/Omnissa-UAG_CVE-2026-114938-remediation.svg) ![forks](https://img.shields.io/github/forks/tomcek42/Omnissa-UAG_CVE-2026-114938-remediation.svg)
- [https://github.com/carlosmarte/runbook_remediation_verification_cve_2026_114938_java4shell](https://github.com/carlosmarte/runbook_remediation_verification_cve_2026_114938_java4shell) :  ![starts](https://img.shields.io/github/stars/carlosmarte/runbook_remediation_verification_cve_2026_114938_java4shell.svg) ![forks](https://img.shields.io/github/forks/carlosmarte/runbook_remediation_verification_cve_2026_114938_java4shell.svg)
- [https://github.com/Pamircil/Symantec-DLP-25.x-26.x-CVE-2026-114938-Java4Shell-Fixing](https://github.com/Pamircil/Symantec-DLP-25.x-26.x-CVE-2026-114938-Java4Shell-Fixing) :  ![starts](https://img.shields.io/github/stars/Pamircil/Symantec-DLP-25.x-26.x-CVE-2026-114938-Java4Shell-Fixing.svg) ![forks](https://img.shields.io/github/forks/Pamircil/Symantec-DLP-25.x-26.x-CVE-2026-114938-Java4Shell-Fixing.svg)
- [https://github.com/EterNullSec/java4shell-defensive-lab](https://github.com/EterNullSec/java4shell-defensive-lab) :  ![starts](https://img.shields.io/github/stars/EterNullSec/java4shell-defensive-lab.svg) ![forks](https://img.shields.io/github/forks/EterNullSec/java4shell-defensive-lab.svg)
- [https://github.com/tobias-weiss-ai-xr/java-fixed-images](https://github.com/tobias-weiss-ai-xr/java-fixed-images) :  ![starts](https://img.shields.io/github/stars/tobias-weiss-ai-xr/java-fixed-images.svg) ![forks](https://img.shields.io/github/forks/tobias-weiss-ai-xr/java-fixed-images.svg)


## CVE-2026-114516
 Etherpad is a real-time collaborative editor. From 1.8.14 until 3.3.3, the pre-authentication /static/* plugin asset handler in src/node/utils/Minify.ts performs a backslash-to-forward-slash conversion after src/node/utils/sanitizePathname.ts has completed its POSIX path checks. On POSIX systems the sanitizer correctly treats backslashes as ordinary filename bytes, but the later conversion turns encoded backslash-separated parent-directory segments into traversal components without revalidation or containment. The expressPreSession registration and the always-present ep_etherpad-lite core pseudo-plugin make this path reachable without credentials, allowing a remote attacker to read any file available to the Etherpad process. Disclosed configuration or environment secrets can expose administrator credentials, after which the administrator plugin installer can provide in-process code execution and full server compromise. This issue is fixed in version 3.3.3.

- [https://github.com/ynsmroztas/EtherPadSniper](https://github.com/ynsmroztas/EtherPadSniper) :  ![starts](https://img.shields.io/github/stars/ynsmroztas/EtherPadSniper.svg) ![forks](https://img.shields.io/github/forks/ynsmroztas/EtherPadSniper.svg)


## CVE-2026-113425
Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts](https://github.com/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts) :  ![starts](https://img.shields.io/github/stars/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts.svg) ![forks](https://img.shields.io/github/forks/gabriel-shtx/CVE-2026-123007-NGINX2Root-detection-scripts.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/elmati279/http2shell-brotli-impact-review](https://github.com/elmati279/http2shell-brotli-impact-review) :  ![starts](https://img.shields.io/github/stars/elmati279/http2shell-brotli-impact-review.svg) ![forks](https://img.shields.io/github/forks/elmati279/http2shell-brotli-impact-review.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/SwordSec/php2shell-guard](https://github.com/SwordSec/php2shell-guard) :  ![starts](https://img.shields.io/github/stars/SwordSec/php2shell-guard.svg) ![forks](https://img.shields.io/github/forks/SwordSec/php2shell-guard.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/KtebhTeam/php2shell](https://github.com/KtebhTeam/php2shell) :  ![starts](https://img.shields.io/github/stars/KtebhTeam/php2shell.svg) ![forks](https://img.shields.io/github/forks/KtebhTeam/php2shell.svg)


## CVE-2026-105803
 Git LFS is a Git extension for versioning large files. From 1.3.0 until 3.8.1, Git LFS does not correctly filter the limited set of options permitted in a repository's .lfsconfig file when option keys contain certain additional components. Crafted keys can mimic options that configure Git LFS to use a custom command to transfer objects, causing Git LFS to execute an attacker-selected command or binary while fetching objects. This issue is fixed in version 3.8.1.

- [https://github.com/googlesky/CVE-2026-105803](https://github.com/googlesky/CVE-2026-105803) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-105803.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-105803.svg)


## CVE-2026-105802
 Git LFS is a Git extension for versioning large files. From 0.6.0 until 3.8.1, Git LFS reads Git configuration options defined for a submodule without checking certain values for embedded line-ending control characters. A malicious repository can insert control characters such as line feed (LF) into those values to mimic options that cause Git LFS to execute an attacker-controlled command or binary while fetching or adding objects. This issue is fixed in version 3.8.1.

- [https://github.com/googlesky/CVE-2026-105802](https://github.com/googlesky/CVE-2026-105802) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-105802.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-105802.svg)


## CVE-2026-104199
 aMQTT is an open source MQTT broker and client. From 0.11.0 until 0.11.4, add_subscription() in amqtt/broker.py accepts malformed single-level + wildcard placement because it checks substrings instead of validating each slash-delimited level. The _matches() function converts each + into a greedy regular-expression fragment and evaluates it with re.fullmatch(), allowing a filter containing many adjacent + characters to trigger catastrophic backtracking when compared with a topic that partially matches but ultimately fails. Because matching runs synchronously in _run_broadcast(), one subscription followed by a publish can block the broker event loop, stopping message delivery and new connection processing until restart. Anonymous clients can trigger the issue with the default configuration. Any authenticated client permitted to create arbitrary subscriptions and publish messages may still exploit it when authentication is enabled. This issue is fixed in version 0.11.4.

- [https://github.com/googlesky/CVE-2026-104199](https://github.com/googlesky/CVE-2026-104199) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-104199.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-104199.svg)


## CVE-2026-103033
 ALTCHA is a Go library for creating and verifying ALTCHA challenges. Prior to 2.1.0, parseServerSignature can leave ServerSignatureVerificationData.Extra uninitialized when url.ParseQuery returns partial values and an error for a malformed percent escape in VerificationData. A later write of an unknown parsed key to the nil map panics before VerifyServerSignature or VerifyServerSignatureSafe completes signature verification, so an unauthenticated client can abort a request. Standard net/http recovers the request goroutine, while application goroutines or frameworks without recovery can crash the process. This issue is fixed in version 2.1.0.

- [https://github.com/googlesky/CVE-2026-103033](https://github.com/googlesky/CVE-2026-103033) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-103033.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-103033.svg)


## CVE-2026-103025
 bep/imagemeta is a Go library for reading EXIF, IPTC and XMP image meta data from JPEG, TIFF, PNG, and WebP files. Prior to 0.17.3, imagemeta.Decode could exhaust memory when parsing PNG zTXt chunks whose keyword is "Raw profile type iptc": the declared chunk length can drive an allocation far larger than the input file, and the embedded zlib stream is decompressed without an output limit. The advisory reports a 42-byte input causing a 256 MB allocation and a 127 KB input inflating to 460 MB. The oversized-allocation path's memory effect depends on platform overcommit and configured GOMEMLIMIT or cgroup limits, while the decompression path reliably creates resident memory. Applications that decode untrusted PNGs with IPTC metadata processing can therefore suffer denial of service through memory exhaustion. This issue is fixed in 0.17.3.

- [https://github.com/googlesky/CVE-2026-103025](https://github.com/googlesky/CVE-2026-103025) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-103025.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-103025.svg)


## CVE-2026-99491
desynchronization.

- [https://github.com/woshigenm/CVE-2026-99491](https://github.com/woshigenm/CVE-2026-99491) :  ![starts](https://img.shields.io/github/stars/woshigenm/CVE-2026-99491.svg) ![forks](https://img.shields.io/github/forks/woshigenm/CVE-2026-99491.svg)
- [https://github.com/Yunnijian/CVE-2026-99491](https://github.com/Yunnijian/CVE-2026-99491) :  ![starts](https://img.shields.io/github/stars/Yunnijian/CVE-2026-99491.svg) ![forks](https://img.shields.io/github/forks/Yunnijian/CVE-2026-99491.svg)


## CVE-2026-99312
CR0.PG must be '0').

- [https://github.com/jmginer/pve-cve-2026-99312](https://github.com/jmginer/pve-cve-2026-99312) :  ![starts](https://img.shields.io/github/stars/jmginer/pve-cve-2026-99312.svg) ![forks](https://img.shields.io/github/forks/jmginer/pve-cve-2026-99312.svg)


## CVE-2026-98432
will be addressed in a separate patch.

- [https://github.com/Agency-Tool-Company/jetson-cve-2026-98432](https://github.com/Agency-Tool-Company/jetson-cve-2026-98432) :  ![starts](https://img.shields.io/github/stars/Agency-Tool-Company/jetson-cve-2026-98432.svg) ![forks](https://img.shields.io/github/forks/Agency-Tool-Company/jetson-cve-2026-98432.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/zhanghangjie/CVE-2026-98260-CYL1](https://github.com/zhanghangjie/CVE-2026-98260-CYL1) :  ![starts](https://img.shields.io/github/stars/zhanghangjie/CVE-2026-98260-CYL1.svg) ![forks](https://img.shields.io/github/forks/zhanghangjie/CVE-2026-98260-CYL1.svg)
- [https://github.com/nestchao/redmi-pad-se-87-root](https://github.com/nestchao/redmi-pad-se-87-root) :  ![starts](https://img.shields.io/github/stars/nestchao/redmi-pad-se-87-root.svg) ![forks](https://img.shields.io/github/forks/nestchao/redmi-pad-se-87-root.svg)


## CVE-2026-94597
 NukeViet CMS is a multi Content Management System. Prior to 4.5.12 and 4.6.02, an attacker who can reach an image-upload flow can upload a valid image with appended PHP short-tag code and a double-extension filename. NukeViet\Files\Upload::save_file() relied on verify_image(), which missed the ? short-open tag, while filename handling preserved embedded dots, validation inspected only the final extension, and an .htaccess rule blocked PHP extensions only at the end of the URI. On Apache mod_php systems configured with short_open_tag and a PHP extension handler, the stored polyglot can execute as PHP and run operating-system commands as the web-server user; PHP-FPM, nginx, and end-anchored handler configurations are not exposed to the execution step. This issue is fixed in versions 4.5.12 and 4.6.02.

- [https://github.com/canhieu/CVE-2026-94597-poc](https://github.com/canhieu/CVE-2026-94597-poc) :  ![starts](https://img.shields.io/github/stars/canhieu/CVE-2026-94597-poc.svg) ![forks](https://img.shields.io/github/forks/canhieu/CVE-2026-94597-poc.svg)


## CVE-2026-82384
 Deserialization of Untrusted Data in Apache Roller 6.1.5 allows an unauthenticated remote attacker to cause deserialization of attacker-controlled bytes, because the XML-RPC endpoint accepts vendor extension types that are deserialized during request parsing, before authentication. The servlet is mapped unconditionally, so parsing occurs even when the global XML-RPC feature is set to disabled; no non-default configuration is required for this path. This can lead to remote code execution. Users are recommended to upgrade to Apache Roller 6.1.6 or later, which disables the extension types and rejects requests when the XML-RPC feature is disabled.

- [https://github.com/foxcornlab/apache-roller-scanner](https://github.com/foxcornlab/apache-roller-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/apache-roller-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/apache-roller-scanner.svg)


## CVE-2026-77378
 Bolt is a fully open source, adaptable platform for building and running modern websites. Prior to 6.1.4, SQL injection in ListFormatHelper allows authenticated users with upload permission to execute arbitrary SQL queries through /async/select-options and exfiltrate sensitive database contents when general/caching/list_format is enabled. This issue is fixed in version 6.1.4.

- [https://github.com/googlesky/CVE-2026-77378](https://github.com/googlesky/CVE-2026-77378) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77378.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77378.svg)


## CVE-2026-77318
 Jupyter MCP Server is a Model Context Protocol server for Jupyter. Prior to 1.0.3, standalone streamable-http mode can enforce MCP_TOKEN on /mcp while leaving the state-changing /api/connect and /api/stop management routes unauthenticated. An unauthenticated network caller can use /api/connect to replace runtime_url and document_url values and their tokens, reset ServerContext, and start a kernel client against attacker-controlled infrastructure, causing the server to send Jupyter API and WebSocket traffic to that backend. The caller can also use /api/stop to stop the current notebook kernel. This boundary failure does not require explicit insecure no-auth mode and occurs outside normal MCP JSON-RPC tool dispatch. This issue is fixed in version 1.0.3.

- [https://github.com/googlesky/CVE-2026-77318](https://github.com/googlesky/CVE-2026-77318) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77318.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77318.svg)


## CVE-2026-71965
 CyberPanel 2.4.3, fixed in commit eca0c3c, contains an authenticated remote code execution vulnerability in the remote backup feature that allows authenticated attackers to gain root-level SSH access by supplying a malicious remote server address. Attackers can exploit the unverified SSH public key retrieval process to write an attacker-controlled public key directly to /root/.ssh/authorized_keys, granting persistent root access to the host system.

- [https://github.com/duypt02/CVE-2026-71965-PoC](https://github.com/duypt02/CVE-2026-71965-PoC) :  ![starts](https://img.shields.io/github/stars/duypt02/CVE-2026-71965-PoC.svg) ![forks](https://img.shields.io/github/forks/duypt02/CVE-2026-71965-PoC.svg)


## CVE-2026-71319
 Nuxt is an open-source web development framework for Vue.js. Prior to 3.3.1, Nuxt DevTools (development mode only) exposes a bidirectional RPC channel over the Vite HMR WebSocket via the nuxt:devtools:rpc plugin. On affected versions the channel has no authentication: any client that can reach the Vite HMR endpoint (ws://host:port/, subprotocol vite-hmr) can call RPC methods, with no token, handshake, or origin check before the channel is established. The updateOptions(), clearOptions(), and openInEditor() methods do not enforce the ensureDevAuthToken check that the other mutating methods use. openInEditor() reads the persisted behavior.openInEditor value and passes it to the launch-editor package, which spawns it as a child process. That value is settable through the equally unauthenticated updateOptions(). An attacker who can reach the HMR port can therefore chain updateOptions('behavior', { openInEditor: 'command' }) then openInEditor('any-existing-file') to execute an arbitrary program on the developer's machine. This issue is fixed in 3.3.1.

- [https://github.com/TazmiDev/CVE-2026-71319](https://github.com/TazmiDev/CVE-2026-71319) :  ![starts](https://img.shields.io/github/stars/TazmiDev/CVE-2026-71319.svg) ![forks](https://img.shields.io/github/forks/TazmiDev/CVE-2026-71319.svg)


## CVE-2026-70229
 Incorrect authorization in Active Directory Domain Services allows an unauthorized attacker to execute code over a network.

- [https://github.com/oOSH4rpZOo/CVE-2026-70229](https://github.com/oOSH4rpZOo/CVE-2026-70229) :  ![starts](https://img.shields.io/github/stars/oOSH4rpZOo/CVE-2026-70229.svg) ![forks](https://img.shields.io/github/forks/oOSH4rpZOo/CVE-2026-70229.svg)


## CVE-2026-69261
 Git LFS is a Git extension for versioning large files. From 0.5.0 until 3.8.1, Git LFS may forward a Cookie header after an HTTP redirect to a host other than the one for which the header was intended. That unintended host can therefore receive cookies containing credentials or other confidential values. Authorization headers are never forwarded to inappropriate hosts and are not the affected secret in this vulnerability. This issue is fixed in version 3.8.1.

- [https://github.com/googlesky/CVE-2026-69261](https://github.com/googlesky/CVE-2026-69261) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-69261.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-69261.svg)


## CVE-2026-69260
 Git LFS is a Git extension for versioning large files. From 0.5.0 until 3.8.1, Git LFS does not format the SSH URL path component as a single argument when constructing remote object-transfer or authentication commands. Shell metacharacters in the SSH URL can therefore escape the intended path argument and cause arbitrary command execution when the remote Git LFS service passes received commands to a shell without adequate sanitization. Git LFS also incorrectly encodes default HTTPS URLs when an SSH URL is configured and the remote host either does not support Git LFS remote commands over SSH or supports HTTP authentication over SSH but git-lfs-authenticate does not return an explicit HTTP URL. This issue is fixed in version 3.8.1.

- [https://github.com/googlesky/CVE-2026-69260](https://github.com/googlesky/CVE-2026-69260) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-69260.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-69260.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/zhanghangjie/CVE-2026-64560-CYL1](https://github.com/zhanghangjie/CVE-2026-64560-CYL1) :  ![starts](https://img.shields.io/github/stars/zhanghangjie/CVE-2026-64560-CYL1.svg) ![forks](https://img.shields.io/github/forks/zhanghangjie/CVE-2026-64560-CYL1.svg)


## CVE-2026-63386
 js-toml is a TOML parser for JavaScript. Prior to 1.1.3, load() does not bound nesting or dotted-key depth in the recursive parser at src/load/parser.ts or the interpreter at src/load/interpreter.ts, so deeply nested arrays, deeply nested inline tables, or long dotted keys can exhaust the V8 call stack and throw a raw RangeError instead of the documented SyntaxParseError. Applications that parse attacker-controlled TOML and handle only SyntaxParseError can rethrow the unexpected exception, which can terminate a worker or process and cause denial of service. The exception is synchronous and catchable by consumers that handle all exceptions, and the issue does not affect confidentiality or integrity. This issue is fixed in version 1.1.3.

- [https://github.com/googlesky/CVE-2026-63386](https://github.com/googlesky/CVE-2026-63386) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-63386.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-63386.svg)


## CVE-2026-63341
 Aedes is an MQTT broker that can run on any stream server. Prior to 1.1.1, the MQTT broker does not bound topic depth or structural complexity before passing topics through `mqemitter` into `qlobber`. A `PUBLISH`, `SUBSCRIBE`, or registered `Will` message containing an excessively deep topic can reach `qlobber._split_words` in `lib/qlobber.js` and trigger an uncaught `too many words` exception. Calls from `handlers/subscribe.js` and the publishing logic are not protected against that exception, so it escapes to the `Node.js event loop` and terminates the entire broker. The `Will` path is independently reachable when a client disconnects ungracefully: it calls `broker.publish` directly and bypasses the `PUBLISH` handler. An attacker must be able to establish an `MQTT session`, authenticated or unauthenticated according to broker configuration. A successful attack disconnects all legitimate clients and prevents reconnection until the broker process restarts. This issue is fixed in version 1.1.1.

- [https://github.com/googlesky/CVE-2026-63341](https://github.com/googlesky/CVE-2026-63341) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-63341.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-63341.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/SanWRoot/wp2shell-LAB-POC](https://github.com/SanWRoot/wp2shell-LAB-POC) :  ![starts](https://img.shields.io/github/stars/SanWRoot/wp2shell-LAB-POC.svg) ![forks](https://img.shields.io/github/forks/SanWRoot/wp2shell-LAB-POC.svg)


## CVE-2026-63012
 baserCMS is a website development framework. Prior to 5.3.0, getAuthenticationService permits an Api/Admin session authentication fallback based on the Referer header, although operator accounts have an Admin auth prefix and cannot obtain an Api/Admin JWT. An authenticated operator can therefore access /baser/api/admin/ endpoints whose permission.php entries have auth = true, including /baser/api/admin/baser-core/site_configs/view.json, even when the corresponding administrative functionality is restricted. This can disclose administrator-restricted configuration information. This issue is fixed in 5.3.0.

- [https://github.com/googlesky/CVE-2026-63012](https://github.com/googlesky/CVE-2026-63012) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-63012.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-63012.svg)


## CVE-2026-62955
 baserCMS is a website development framework. From 5.2.3 until 5.3.0, BcThemeFileService::getFullpath() in plugins/bc-theme-file/src/Service/BcThemeFileService.php skips its path containment check when realpath() fails for a nonexistent theme subdirectory selected by the type parameter. An authenticated administrator can supply a traversal path through the theme-file API to access locations outside the theme directory. The bypass of the CVE-2026-30940 fix can permit file writes, overwrites or deletion within the PHP process permissions and, where executable PHP can be written, remote code execution. This issue is fixed in 5.3.0.

- [https://github.com/googlesky/CVE-2026-62955](https://github.com/googlesky/CVE-2026-62955) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-62955.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-62955.svg)


## CVE-2026-61725
 sevenz-rust2 is a Rust-native 7z compressor and `decompress`or. Prior to 0.21.1, extracting an attacker-supplied 7z archive can write or overwrite files outside the destination directory. In `src/util/decompress.rs`, `decompress_impl` computes each destination with `dest.join(entry.name())` without normalizing the archive's UTF-16 entry name or verifying containment, and `default_entry_extract_fn` writes to it with `File::create`. Parent-directory components escape the extraction root, and an absolute entry path makes the join discard the destination entirely. The convenience entry points `decompress`, `decompress_file`, `decompress_with_password`, and `decompress_file_with_password` all use this default path. Overwriting writable configuration, startup, cron, or build files can lead to code execution or persistence. The archive bytes are the attacker-controlled trust boundary, including for applications that automatically unpack uploaded or otherwise untrusted archives. This issue is fixed in version 0.21.1.

- [https://github.com/googlesky/CVE-2026-61725](https://github.com/googlesky/CVE-2026-61725) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-61725.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-61725.svg)


## CVE-2026-60137
 WordPress 6.8.x before 6.8.6, 6.9.x before 6.9.5, and 7.0.x before 7.0.2 does not properly sanitise the author__not_in parameter of WP_Query, which could allow SQL Injection when a plugin or theme passes untrusted input to the parameter.

- [https://github.com/SanWRoot/wp2shell-LAB-POC](https://github.com/SanWRoot/wp2shell-LAB-POC) :  ![starts](https://img.shields.io/github/stars/SanWRoot/wp2shell-LAB-POC.svg) ![forks](https://img.shields.io/github/forks/SanWRoot/wp2shell-LAB-POC.svg)


## CVE-2026-58882
 In decodeWapPdu of WapPushOverSms.java, there is a possible out of bounds read due to an integer overflow. This could lead to a remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Lucifer7794/sms-of-death-recovery](https://github.com/Lucifer7794/sms-of-death-recovery) :  ![starts](https://img.shields.io/github/stars/Lucifer7794/sms-of-death-recovery.svg) ![forks](https://img.shields.io/github/forks/Lucifer7794/sms-of-death-recovery.svg)


## CVE-2026-58192
 Appium is a cross-platform automation framework for all kinds of apps, built on top of the W3C WebDriver protocol. Prior to 1.1.6, the Appium storage plugin exposes POST /storage/delete, whose handler passes the user-supplied name value directly into path.join(storageRoot, name) and fs.rimraf() without path sanitization, allowing an unauthenticated remote client to escape the storage root with ../ sequences and recursively delete arbitrary writable files or directories. This issue is fixed in version 1.1.6.

- [https://github.com/googlesky/CVE-2026-58192](https://github.com/googlesky/CVE-2026-58192) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-58192.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-58192.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/soralis0912/CVE-2026-43499-warhol-root](https://github.com/soralis0912/CVE-2026-43499-warhol-root) :  ![starts](https://img.shields.io/github/stars/soralis0912/CVE-2026-43499-warhol-root.svg) ![forks](https://img.shields.io/github/forks/soralis0912/CVE-2026-43499-warhol-root.svg)
- [https://github.com/ReBiliBin/ghostlock-oppo-watch3pro](https://github.com/ReBiliBin/ghostlock-oppo-watch3pro) :  ![starts](https://img.shields.io/github/stars/ReBiliBin/ghostlock-oppo-watch3pro.svg) ![forks](https://img.shields.io/github/forks/ReBiliBin/ghostlock-oppo-watch3pro.svg)


## CVE-2026-30940
 baserCMS is a website development framework. Prior to version 5.2.3, a path traversal vulnerability exists in the theme file management API (/baser/api/admin/bc-theme-file/theme_files/add.json) that allows arbitrary file write. An authenticated administrator can include ../ sequences in the path parameter to create a PHP file in an arbitrary directory outside the theme directory, which may result in remote code execution (RCE). This issue has been patched in version 5.2.3.

- [https://github.com/googlesky/CVE-2026-62955](https://github.com/googlesky/CVE-2026-62955) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-62955.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-62955.svg)


## CVE-2026-27980
 Next.js is a React framework for building full-stack web applications. Starting in version 10.0.0 and prior to version 16.1.7, the default Next.js image optimization disk cache (`/_next/image`) did not have a configurable upper bound, allowing unbounded cache growth. An attacker could generate many unique image-optimization variants and exhaust disk space, causing denial of service. This is fixed in version 16.1.7 by adding an LRU-backed disk cache with `images.maximumDiskCacheSize`, including eviction of least-recently-used entries when the limit is exceeded. Setting `maximumDiskCacheSize: 0` disables disk caching. If upgrading is not immediately possible, periodically clean `.next/cache/images` and/or reduce variant cardinality (e.g., tighten values for `images.localPatterns`, `images.remotePatterns`, and `images.qualities`).

- [https://github.com/aheybati/CVE-2026-27980](https://github.com/aheybati/CVE-2026-27980) :  ![starts](https://img.shields.io/github/stars/aheybati/CVE-2026-27980.svg) ![forks](https://img.shields.io/github/forks/aheybati/CVE-2026-27980.svg)


## CVE-2026-25854
Users are recommended to upgrade to version 11.0.20, 10.1.53 or 9.0.116, which fix the issue.

- [https://github.com/googlesky/CVE-2026-117517](https://github.com/googlesky/CVE-2026-117517) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-117517.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-117517.svg)


## CVE-2026-21385
 Memory corruption while using alignments for memory allocation.

- [https://github.com/zhanghangjie/CVE-2026-21385-CYL1](https://github.com/zhanghangjie/CVE-2026-21385-CYL1) :  ![starts](https://img.shields.io/github/stars/zhanghangjie/CVE-2026-21385-CYL1.svg) ![forks](https://img.shields.io/github/forks/zhanghangjie/CVE-2026-21385-CYL1.svg)


## CVE-2026-20971
 Use After Free in PROCA driver prior to SMR Jan-2026 Release 1 allows local attackers to potentially execute arbitrary code.

- [https://github.com/zhanghangjie/CVE-2026-20971-CYL1](https://github.com/zhanghangjie/CVE-2026-20971-CYL1) :  ![starts](https://img.shields.io/github/stars/zhanghangjie/CVE-2026-20971-CYL1.svg) ![forks](https://img.shields.io/github/forks/zhanghangjie/CVE-2026-20971-CYL1.svg)


## CVE-2026-12853
 The Flamingo plugin for WordPress is vulnerable to authorization bypass in all versions up to, and including, 2.6.2. This is due to the plugin not properly verifying that a user is authorized to perform an action. This makes it possible for authenticated attackers, with contributor-level access and above, to enumerate taxonomy terms including channel names derived from Contact Form 7 form titles that may reveal internal form purposes, department names, or workflow identifiers, as well as submission counts per channel and contact tag names. The plugin's flamingo_map_meta_cap() filter restricts access to Flamingo's admin UI but does not extend to WordPress core APIs such as XML-RPC wp.getTerms and admin-ajax ajax-tag-search.

- [https://github.com/l00neyhacker/CVE-2026-128536](https://github.com/l00neyhacker/CVE-2026-128536) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-128536.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-128536.svg)
- [https://github.com/l00neyhacker/CVE-2026-128531](https://github.com/l00neyhacker/CVE-2026-128531) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-128531.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-128531.svg)
- [https://github.com/l00neyhacker/CVE-2026-128537](https://github.com/l00neyhacker/CVE-2026-128537) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-128537.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-128537.svg)
- [https://github.com/l00neyhacker/CVE-2026-128534](https://github.com/l00neyhacker/CVE-2026-128534) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2026-128534.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2026-128534.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Ethen1212/php2shell-CVE-2026-109618](https://github.com/Ethen1212/php2shell-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/Ethen1212/php2shell-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/Ethen1212/php2shell-CVE-2026-109618.svg)
- [https://github.com/sxyrxyy/php2shell-cve-2026-109618-check](https://github.com/sxyrxyy/php2shell-cve-2026-109618-check) :  ![starts](https://img.shields.io/github/stars/sxyrxyy/php2shell-cve-2026-109618-check.svg) ![forks](https://img.shields.io/github/forks/sxyrxyy/php2shell-cve-2026-109618-check.svg)


## CVE-2026-9082
This issue affects Drupal core: from 8.9.0 before 10.4.10, from 10.5.0 before 10.5.10, from 10.6.0 before 10.6.9, from 11.0.0 before 11.1.10, from 11.2.0 before 11.2.12, from 11.3.0 before 11.3.10.

- [https://github.com/begimher/calix-cve-2026-9082-recovery](https://github.com/begimher/calix-cve-2026-9082-recovery) :  ![starts](https://img.shields.io/github/stars/begimher/calix-cve-2026-9082-recovery.svg) ![forks](https://img.shields.io/github/forks/begimher/calix-cve-2026-9082-recovery.svg)


## CVE-2026-5941
 Parsing logic flaws cause non-signature data to be misidentified as valid signatures when processing malformed form field hierarchies, leading to invalid memory writes and program crashes during internal data structure construction.

- [https://github.com/daehyuh/CVE-2026-59415](https://github.com/daehyuh/CVE-2026-59415) :  ![starts](https://img.shields.io/github/stars/daehyuh/CVE-2026-59415.svg) ![forks](https://img.shields.io/github/forks/daehyuh/CVE-2026-59415.svg)
- [https://github.com/daehyuh/CVE-2026-59417](https://github.com/daehyuh/CVE-2026-59417) :  ![starts](https://img.shields.io/github/stars/daehyuh/CVE-2026-59417.svg) ![forks](https://img.shields.io/github/forks/daehyuh/CVE-2026-59417.svg)


## CVE-2026-5939
 A crafted XFA PDF can trigger a use-after-free condition during calculate event processing, causing the application to crash and resulting in an arbitrary code execution.

- [https://github.com/daehyuh/CVE-2026-59392](https://github.com/daehyuh/CVE-2026-59392) :  ![starts](https://img.shields.io/github/stars/daehyuh/CVE-2026-59392.svg) ![forks](https://img.shields.io/github/forks/daehyuh/CVE-2026-59392.svg)
- [https://github.com/daehyuh/CVE-2026-59398](https://github.com/daehyuh/CVE-2026-59398) :  ![starts](https://img.shields.io/github/stars/daehyuh/CVE-2026-59398.svg) ![forks](https://img.shields.io/github/forks/daehyuh/CVE-2026-59398.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/zhanghangjie/CVE-2026-43499-CYL1](https://github.com/zhanghangjie/CVE-2026-43499-CYL1) :  ![starts](https://img.shields.io/github/stars/zhanghangjie/CVE-2026-43499-CYL1.svg) ![forks](https://img.shields.io/github/forks/zhanghangjie/CVE-2026-43499-CYL1.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/santihabib/CVE-2026-109619](https://github.com/santihabib/CVE-2026-109619) :  ![starts](https://img.shields.io/github/stars/santihabib/CVE-2026-109619.svg) ![forks](https://img.shields.io/github/forks/santihabib/CVE-2026-109619.svg)


## CVE-2025-57833
 An issue was discovered in Django 4.2 before 4.2.24, 5.1 before 5.1.12, and 5.2 before 5.2.6. FilteredRelation is subject to SQL injection in column aliases, using a suitably crafted dictionary, with dictionary expansion, as the **kwargs passed QuerySet.annotate() or QuerySet.alias().

- [https://github.com/Renatata-H/demo-cve-2025-57833](https://github.com/Renatata-H/demo-cve-2025-57833) :  ![starts](https://img.shields.io/github/stars/Renatata-H/demo-cve-2025-57833.svg) ![forks](https://img.shields.io/github/forks/Renatata-H/demo-cve-2025-57833.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/ihhgimhana/React2Shell-CVE-2025-55182-PoC-Reverse-Shell](https://github.com/ihhgimhana/React2Shell-CVE-2025-55182-PoC-Reverse-Shell) :  ![starts](https://img.shields.io/github/stars/ihhgimhana/React2Shell-CVE-2025-55182-PoC-Reverse-Shell.svg) ![forks](https://img.shields.io/github/forks/ihhgimhana/React2Shell-CVE-2025-55182-PoC-Reverse-Shell.svg)


## CVE-2025-38618
to VMADDR_PORT_ANY.

- [https://github.com/nanabingies/cve-2025-38618](https://github.com/nanabingies/cve-2025-38618) :  ![starts](https://img.shields.io/github/stars/nanabingies/cve-2025-38618.svg) ![forks](https://img.shields.io/github/forks/nanabingies/cve-2025-38618.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/jigrit/CVE_Analysis](https://github.com/jigrit/CVE_Analysis) :  ![starts](https://img.shields.io/github/stars/jigrit/CVE_Analysis.svg) ![forks](https://img.shields.io/github/forks/jigrit/CVE_Analysis.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Ghost-Bx1/cve-2025-29927-nextjs-middleware-bypass](https://github.com/Ghost-Bx1/cve-2025-29927-nextjs-middleware-bypass) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2025-29927-nextjs-middleware-bypass.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2025-29927-nextjs-middleware-bypass.svg)
- [https://github.com/shahin-shadow/nextjs-auth-bypass](https://github.com/shahin-shadow/nextjs-auth-bypass) :  ![starts](https://img.shields.io/github/stars/shahin-shadow/nextjs-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/shahin-shadow/nextjs-auth-bypass.svg)
- [https://github.com/l1uk/nextjs-middleware-exploit](https://github.com/l1uk/nextjs-middleware-exploit) :  ![starts](https://img.shields.io/github/stars/l1uk/nextjs-middleware-exploit.svg) ![forks](https://img.shields.io/github/forks/l1uk/nextjs-middleware-exploit.svg)
- [https://github.com/kazuya256/nextjs-auth-bypass-poc](https://github.com/kazuya256/nextjs-auth-bypass-poc) :  ![starts](https://img.shields.io/github/stars/kazuya256/nextjs-auth-bypass-poc.svg) ![forks](https://img.shields.io/github/forks/kazuya256/nextjs-auth-bypass-poc.svg)


## CVE-2025-21756
 entry_SYSCALL_64_after_hwframe+0x76/0x7e

- [https://github.com/zhanghangjie/CVE-2025-21756-VM](https://github.com/zhanghangjie/CVE-2025-21756-VM) :  ![starts](https://img.shields.io/github/stars/zhanghangjie/CVE-2025-21756-VM.svg) ![forks](https://img.shields.io/github/forks/zhanghangjie/CVE-2025-21756-VM.svg)


## CVE-2025-6554
 Type confusion in V8 in Google Chrome prior to 138.0.7204.96 allowed a remote attacker to perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/zhanghangjie/CVE-2025-6554-CYL1](https://github.com/zhanghangjie/CVE-2025-6554-CYL1) :  ![starts](https://img.shields.io/github/stars/zhanghangjie/CVE-2025-6554-CYL1.svg) ![forks](https://img.shields.io/github/forks/zhanghangjie/CVE-2025-6554-CYL1.svg)


## CVE-2025-5518
This issue affects BILGER: before 2.4.6.

- [https://github.com/oways/React2shell-CVE-2025-55182-checker](https://github.com/oways/React2shell-CVE-2025-55182-checker) :  ![starts](https://img.shields.io/github/stars/oways/React2shell-CVE-2025-55182-checker.svg) ![forks](https://img.shields.io/github/forks/oways/React2shell-CVE-2025-55182-checker.svg)


## CVE-2025-2992
 A vulnerability classified as critical was found in Tenda FH1202 1.2.0.14(408). Affected by this vulnerability is an unknown functionality of the file /goform/AdvSetWrlsafeset of the component Web Management Interface. The manipulation leads to improper access controls. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/aleongx/CVE-2025-29927_Scanner](https://github.com/aleongx/CVE-2025-29927_Scanner) :  ![starts](https://img.shields.io/github/stars/aleongx/CVE-2025-29927_Scanner.svg) ![forks](https://img.shields.io/github/forks/aleongx/CVE-2025-29927_Scanner.svg)
- [https://github.com/gitgudKrish/cve-2025-29927-nextjs](https://github.com/gitgudKrish/cve-2025-29927-nextjs) :  ![starts](https://img.shields.io/github/stars/gitgudKrish/cve-2025-29927-nextjs.svg) ![forks](https://img.shields.io/github/forks/gitgudKrish/cve-2025-29927-nextjs.svg)
- [https://github.com/Ritinify/CVE-2025-29927-PoC](https://github.com/Ritinify/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Ritinify/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Ritinify/CVE-2025-29927-PoC.svg)
- [https://github.com/elshaheedy/CVE-2025-29927-Sigma-Rule](https://github.com/elshaheedy/CVE-2025-29927-Sigma-Rule) :  ![starts](https://img.shields.io/github/stars/elshaheedy/CVE-2025-29927-Sigma-Rule.svg) ![forks](https://img.shields.io/github/forks/elshaheedy/CVE-2025-29927-Sigma-Rule.svg)


## CVE-2023-28450
 An issue was discovered in Dnsmasq before 2.90. The default maximum EDNS.0 UDP packet size was set to 4096 but should be 1232 because of DNS Flag Day 2020.

- [https://github.com/vitalelele/CVE-2023-28450-PoC](https://github.com/vitalelele/CVE-2023-28450-PoC) :  ![starts](https://img.shields.io/github/stars/vitalelele/CVE-2023-28450-PoC.svg) ![forks](https://img.shields.io/github/forks/vitalelele/CVE-2023-28450-PoC.svg)


## CVE-2022-38694
 In BootRom, there is a possible unchecked write address. This could lead to local escalation of privilege with no additional execution privileges needed.

- [https://github.com/MissMudan/e5u-root-notes](https://github.com/MissMudan/e5u-root-notes) :  ![starts](https://img.shields.io/github/stars/MissMudan/e5u-root-notes.svg) ![forks](https://img.shields.io/github/forks/MissMudan/e5u-root-notes.svg)


## CVE-2022-22706
 Arm Mali GPU Kernel Driver allows a non-privileged user to achieve write access to read-only memory pages. This affects Midgard r26p0 through r31p0, Bifrost r0p0 through r35p0, and Valhall r19p0 through r35p0.

- [https://github.com/emdzej/sony-bravia-mtk-root](https://github.com/emdzej/sony-bravia-mtk-root) :  ![starts](https://img.shields.io/github/stars/emdzej/sony-bravia-mtk-root.svg) ![forks](https://img.shields.io/github/forks/emdzej/sony-bravia-mtk-root.svg)


## CVE-2021-40444
UPDATE September 14, 2021: Microsoft has released security updates to address this vulnerability. Please see the Security Updates table for the applicable update for your system. We recommend that you install these updates immediately. Please see the FAQ for important information about which updates are applicable to your system.

- [https://github.com/mzn41/CVE-2021-40444-POC](https://github.com/mzn41/CVE-2021-40444-POC) :  ![starts](https://img.shields.io/github/stars/mzn41/CVE-2021-40444-POC.svg) ![forks](https://img.shields.io/github/forks/mzn41/CVE-2021-40444-POC.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/gunzf0x/CVE-2021-41773](https://github.com/gunzf0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2021-41773.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via "sudoedit -s" and a command-line argument that ends with a single backslash character.

- [https://github.com/calonnuotcabe/CVE-2021-3156](https://github.com/calonnuotcabe/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/calonnuotcabe/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/calonnuotcabe/CVE-2021-3156.svg)


## CVE-2020-37281
 Gravitee API Management through 4.12.22 contains an authentication bypass vulnerability that allows unauthenticated remote attackers to impersonate any user by forging JWTs signed with the shipped default jwt.secret. Attackers knowing an existing user ID can sign an HS256 token with that subject and present it as a bearer token to the Management API, impersonating administrators to gain full platform control.

- [https://github.com/l4rm4nd/CVE-2020-37281](https://github.com/l4rm4nd/CVE-2020-37281) :  ![starts](https://img.shields.io/github/stars/l4rm4nd/CVE-2020-37281.svg) ![forks](https://img.shields.io/github/forks/l4rm4nd/CVE-2020-37281.svg)


## CVE-2019-14287
 In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. For example, this allows bypass of !root configuration, and USER= logging, for a "sudo -u \#$((0xffffffff))" command.

- [https://github.com/fantasmakm4/LAB-010-AGENT-SUDO](https://github.com/fantasmakm4/LAB-010-AGENT-SUDO) :  ![starts](https://img.shields.io/github/stars/fantasmakm4/LAB-010-AGENT-SUDO.svg) ![forks](https://img.shields.io/github/forks/fantasmakm4/LAB-010-AGENT-SUDO.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/raisul06/WannaCry_Ransomware_Impact](https://github.com/raisul06/WannaCry_Ransomware_Impact) :  ![starts](https://img.shields.io/github/stars/raisul06/WannaCry_Ransomware_Impact.svg) ![forks](https://img.shields.io/github/forks/raisul06/WannaCry_Ransomware_Impact.svg)


## CVE-2015-2050
 D-Link DAP-1320 Rev Ax with firmware before 1.21b05 allows attackers to execute arbitrary commands via unspecified vectors.

- [https://github.com/nightscry/CVE-2015-2050-DAP-1320](https://github.com/nightscry/CVE-2015-2050-DAP-1320) :  ![starts](https://img.shields.io/github/stars/nightscry/CVE-2015-2050-DAP-1320.svg) ![forks](https://img.shields.io/github/forks/nightscry/CVE-2015-2050-DAP-1320.svg)


## CVE-2009-3103
 Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2, Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location, aka "SMBv2 Negotiation Vulnerability." NOTE: some of these details are obtained from third party information.

- [https://github.com/Zhaoyi-Fan/ms09-050-smb2-manual](https://github.com/Zhaoyi-Fan/ms09-050-smb2-manual) :  ![starts](https://img.shields.io/github/stars/Zhaoyi-Fan/ms09-050-smb2-manual.svg) ![forks](https://img.shields.io/github/forks/Zhaoyi-Fan/ms09-050-smb2-manual.svg)


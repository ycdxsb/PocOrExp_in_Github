## CVE-2025-30066
 tj-actions changed-files before 46 allows remote attackers to discover secrets by reading actions logs. (The tags v1 through v45.0.7 were affected on 2025-03-14 and 2025-03-15 because they were modified by a threat actor to point at commit 0e58ed8, which contained malicious updateFeatures code.)



- [https://github.com/Checkmarx/Checkmarx-CVE-2025-30066-Detection-Tool](https://github.com/Checkmarx/Checkmarx-CVE-2025-30066-Detection-Tool) :  ![starts](https://img.shields.io/github/stars/Checkmarx/Checkmarx-CVE-2025-30066-Detection-Tool.svg) ![forks](https://img.shields.io/github/forks/Checkmarx/Checkmarx-CVE-2025-30066-Detection-Tool.svg)

- [https://github.com/OS-pedrogustavobilro/test-changed-files](https://github.com/OS-pedrogustavobilro/test-changed-files) :  ![starts](https://img.shields.io/github/stars/OS-pedrogustavobilro/test-changed-files.svg) ![forks](https://img.shields.io/github/forks/OS-pedrogustavobilro/test-changed-files.svg)

## CVE-2025-29384
 In Tenda AC9 v1.0 V15.03.05.14_multi, the wanMTU parameter of /goform/AdvSetMacMtuWan has a stack overflow vulnerability, which can lead to remote arbitrary code execution.



- [https://github.com/Otsmane-Ahmed/cve-2025-29384-poc](https://github.com/Otsmane-Ahmed/cve-2025-29384-poc) :  ![starts](https://img.shields.io/github/stars/Otsmane-Ahmed/cve-2025-29384-poc.svg) ![forks](https://img.shields.io/github/forks/Otsmane-Ahmed/cve-2025-29384-poc.svg)

## CVE-2025-28915
 Unrestricted Upload of File with Dangerous Type vulnerability in Theme Egg ThemeEgg ToolKit allows Upload a Web Shell to a Web Server. This issue affects ThemeEgg ToolKit: from n/a through 1.2.9.



- [https://github.com/Nxploited/CVE-2025-28915](https://github.com/Nxploited/CVE-2025-28915) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-28915.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-28915.svg)

- [https://github.com/Pei4AN/CVE-2025-28915](https://github.com/Pei4AN/CVE-2025-28915) :  ![starts](https://img.shields.io/github/stars/Pei4AN/CVE-2025-28915.svg) ![forks](https://img.shields.io/github/forks/Pei4AN/CVE-2025-28915.svg)

## CVE-2025-27893
 In Archer Platform 6 through 6.14.00202.10024, an authenticated user with record creation privileges can manipulate immutable fields, such as the creation date, by intercepting and modifying a Copy request via a GenericContent/Record.aspx?id= URI. This enables unauthorized modification of system-generated metadata, compromising data integrity and potentially impacting auditing, compliance, and security controls.



- [https://github.com/NastyCrow/CVE-2025-27893](https://github.com/NastyCrow/CVE-2025-27893) :  ![starts](https://img.shields.io/github/stars/NastyCrow/CVE-2025-27893.svg) ![forks](https://img.shields.io/github/forks/NastyCrow/CVE-2025-27893.svg)

## CVE-2025-27840
 Espressif ESP32 chips allow 29 hidden HCI commands, such as 0xFC02 (Write memory).



- [https://github.com/em0gi/CVE-2025-27840](https://github.com/em0gi/CVE-2025-27840) :  ![starts](https://img.shields.io/github/stars/em0gi/CVE-2025-27840.svg) ![forks](https://img.shields.io/github/forks/em0gi/CVE-2025-27840.svg)

## CVE-2025-27636
 Bypass/Injection vulnerability in Apache Camel components under particular conditions.

This issue affects Apache Camel: from 4.10.0 through = 4.10.1, from 4.8.0 through = 4.8.4, from 3.10.0 through = 3.22.3.

Users are recommended to upgrade to version 4.10.2 for 4.10.x LTS, 4.8.5 for 4.8.x LTS and 3.22.4 for 3.x releases.



This vulnerability is present in Camel's default incoming header filter, that allows an attacker to include Camel specific

headers that for some Camel components can alter the behaviours such as the camel-bean component, to call another method

on the bean, than was coded in the application. In the camel-jms component, then a malicious header can be used to send

the message to another queue (on the same broker) than was coded in the application. This could also be seen by using the camel-exec component




The attacker would need to inject custom headers, such as HTTP protocols. So if you have Camel applications that are

directly connected to the internet via HTTP, then an attacker could include malicious HTTP headers in the HTTP requests

that are send to the Camel application.




All the known Camel HTTP component such as camel-servlet, camel-jetty, camel-undertow, camel-platform-http, and camel-netty-http would be vulnerable out of the box.

In these conditions an attacker could be able to forge a Camel header name and make the bean component invoking other methods in the same bean.

In terms of usage of the default header filter strategy the list of components using that is: 


  *  camel-activemq
  *  camel-activemq6
  *  camel-amqp
  *  camel-aws2-sqs
  *  camel-azure-servicebus
  *  camel-cxf-rest
  *  camel-cxf-soap
  *  camel-http
  *  camel-jetty
  *  camel-jms
  *  camel-kafka
  *  camel-knative
  *  camel-mail
  *  camel-nats
  *  camel-netty-http
  *  camel-platform-http
  *  camel-rest
  *  camel-sjms
  *  camel-spring-rabbitmq
  *  camel-stomp
  *  camel-tahu
  *  camel-undertow
  *  camel-xmpp






The vulnerability arises due to a bug in the default filtering mechanism that only blocks headers starting with "Camel", "camel", or "org.apache.camel.". 


Mitigation: You can easily work around this in your Camel applications by removing the headers in your Camel routes. There are many ways of doing this, also globally or per route. This means you could use the removeHeaders EIP, to filter out anything like "cAmel, cAMEL" etc, or in general everything not starting with "Camel", "camel" or "org.apache.camel.".



- [https://github.com/akamai/CVE-2025-27636-Apache-Camel-PoC](https://github.com/akamai/CVE-2025-27636-Apache-Camel-PoC) :  ![starts](https://img.shields.io/github/stars/akamai/CVE-2025-27636-Apache-Camel-PoC.svg) ![forks](https://img.shields.io/github/forks/akamai/CVE-2025-27636-Apache-Camel-PoC.svg)

## CVE-2025-27607
 Python JSON Logger is a JSON Formatter for Python Logging. Between 30 December 2024 and 4 March 2025 Python JSON Logger was vulnerable to RCE through a missing dependency. This occurred because msgspec-python313-pre was deleted by the owner leaving the name open to being claimed by a third party. If the package was claimed, it would allow them RCE on any Python JSON Logger user who installed the development dependencies on Python 3.13 (e.g. pip install python-json-logger[dev]). This issue has been resolved with 3.3.0.



- [https://github.com/Barsug/msgspec-python313-pre](https://github.com/Barsug/msgspec-python313-pre) :  ![starts](https://img.shields.io/github/stars/Barsug/msgspec-python313-pre.svg) ![forks](https://img.shields.io/github/forks/Barsug/msgspec-python313-pre.svg)

## CVE-2025-27410
 PwnDoc is a penetration test reporting application. Prior to version 1.2.0, the backup restore functionality is vulnerable to path traversal in the TAR entry's name, allowing an attacker to overwrite any file on the system with their content. By overwriting an included `.js` file and restarting the container, this allows for Remote Code Execution as an administrator. The remote code execution occurs because any user with the `backups:create` and `backups:update` (only administrators by default) is able to overwrite any file on the system. Version 1.2.0 fixes the issue.



- [https://github.com/shreyas-malhotra/CVE-2025-27410](https://github.com/shreyas-malhotra/CVE-2025-27410) :  ![starts](https://img.shields.io/github/stars/shreyas-malhotra/CVE-2025-27410.svg) ![forks](https://img.shields.io/github/forks/shreyas-malhotra/CVE-2025-27410.svg)

## CVE-2025-26794
 Exim 4.98 before 4.98.1, when SQLite hints and ETRN serialization are used, allows remote SQL injection.



- [https://github.com/OscarBataille/CVE-2025-26794](https://github.com/OscarBataille/CVE-2025-26794) :  ![starts](https://img.shields.io/github/stars/OscarBataille/CVE-2025-26794.svg) ![forks](https://img.shields.io/github/forks/OscarBataille/CVE-2025-26794.svg)

- [https://github.com/ishwardeepp/CVE-2025-26794-Exim-Mail-SQLi](https://github.com/ishwardeepp/CVE-2025-26794-Exim-Mail-SQLi) :  ![starts](https://img.shields.io/github/stars/ishwardeepp/CVE-2025-26794-Exim-Mail-SQLi.svg) ![forks](https://img.shields.io/github/forks/ishwardeepp/CVE-2025-26794-Exim-Mail-SQLi.svg)

## CVE-2025-26466
 A flaw was found in the OpenSSH package. For each ping packet the SSH server receives, a pong packet is allocated in a memory buffer and stored in a queue of packages. It is only freed when the server/client key exchange has finished. A malicious client may keep sending such packages, leading to an uncontrolled increase in memory consumption on the server side. Consequently, the server may become unavailable, resulting in a denial of service attack.



- [https://github.com/jhonnybonny/CVE-2025-26466](https://github.com/jhonnybonny/CVE-2025-26466) :  ![starts](https://img.shields.io/github/stars/jhonnybonny/CVE-2025-26466.svg) ![forks](https://img.shields.io/github/forks/jhonnybonny/CVE-2025-26466.svg)

- [https://github.com/rxerium/CVE-2025-26466](https://github.com/rxerium/CVE-2025-26466) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-26466.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-26466.svg)

- [https://github.com/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466](https://github.com/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466) :  ![starts](https://img.shields.io/github/stars/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466.svg) ![forks](https://img.shields.io/github/forks/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466.svg)

## CVE-2025-26465
 A vulnerability was found in OpenSSH when the VerifyHostKeyDNS option is enabled. A machine-in-the-middle attack can be performed by a malicious machine impersonating a legit server. This issue occurs due to how OpenSSH mishandles error codes in specific conditions when verifying the host key. For an attack to be considered successful, the attacker needs to manage to exhaust the client's memory resource first, turning the attack complexity high.



- [https://github.com/rxerium/CVE-2025-26465](https://github.com/rxerium/CVE-2025-26465) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-26465.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-26465.svg)

- [https://github.com/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466](https://github.com/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466) :  ![starts](https://img.shields.io/github/stars/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466.svg) ![forks](https://img.shields.io/github/forks/dolutech/patch-manual-CVE-2025-26465-e-CVE-2025-26466.svg)

## CVE-2025-26326
 A vulnerability was identified in the NVDA Remote (version 2.6.4) and Tele NVDA Remote (version 2025.3.3) remote connection add-ons, which allows an attacker to obtain total control of the remote system by guessing a weak password. The problem occurs because these add-ons accept any password entered by the user and do not have an additional authentication or computer verification mechanism. Tests indicate that more than 1,000 systems use easy-to-guess passwords, many with less than 4 to 6 characters, including common sequences. This allows brute force attacks or trial-and-error attempts by malicious invaders. The vulnerability can be exploited by a remote attacker who knows or can guess the password used in the connection. As a result, the attacker gains complete access to the affected system and can execute commands, modify files, and compromise user security.



- [https://github.com/azurejoga/CVE-2025-26326](https://github.com/azurejoga/CVE-2025-26326) :  ![starts](https://img.shields.io/github/stars/azurejoga/CVE-2025-26326.svg) ![forks](https://img.shields.io/github/forks/azurejoga/CVE-2025-26326.svg)

## CVE-2025-26319
 FlowiseAI Flowise v2.2.6 was discovered to contain an arbitrary file upload vulnerability in /api/v1/attachments.



- [https://github.com/YuoLuo/CVE-2025-26319](https://github.com/YuoLuo/CVE-2025-26319) :  ![starts](https://img.shields.io/github/stars/YuoLuo/CVE-2025-26319.svg) ![forks](https://img.shields.io/github/forks/YuoLuo/CVE-2025-26319.svg)

- [https://github.com/dorattias/CVE-2025-26319](https://github.com/dorattias/CVE-2025-26319) :  ![starts](https://img.shields.io/github/stars/dorattias/CVE-2025-26319.svg) ![forks](https://img.shields.io/github/forks/dorattias/CVE-2025-26319.svg)

## CVE-2025-26318
 hb.exe in TSplus Remote Access before 17.30 2024-10-30 allows remote attackers to retrieve a list of all domain accounts currently connected to the application.



- [https://github.com/Frozenka/CVE-2025-26318](https://github.com/Frozenka/CVE-2025-26318) :  ![starts](https://img.shields.io/github/stars/Frozenka/CVE-2025-26318.svg) ![forks](https://img.shields.io/github/forks/Frozenka/CVE-2025-26318.svg)

## CVE-2025-26264
 GeoVision GV-ASWeb with the version 6.1.2.0 or less (fixed in 6.2.0), contains a Remote Code Execution (RCE) vulnerability within its Notification Settings feature. An authenticated attacker with "System Settings" privileges in ASWeb can exploit this flaw to execute arbitrary commands on the server, leading to a full system compromise.



- [https://github.com/DRAGOWN/CVE-2025-26264](https://github.com/DRAGOWN/CVE-2025-26264) :  ![starts](https://img.shields.io/github/stars/DRAGOWN/CVE-2025-26264.svg) ![forks](https://img.shields.io/github/forks/DRAGOWN/CVE-2025-26264.svg)

## CVE-2025-26263
 GeoVision ASManager Windows desktop application with the version 6.1.2.0 or less (fixed in 6.2.0), is vulnerable to credentials disclosure due to improper memory handling in the ASManagerService.exe process.



- [https://github.com/DRAGOWN/CVE-2025-26263](https://github.com/DRAGOWN/CVE-2025-26263) :  ![starts](https://img.shields.io/github/stars/DRAGOWN/CVE-2025-26263.svg) ![forks](https://img.shields.io/github/forks/DRAGOWN/CVE-2025-26263.svg)

## CVE-2025-26206
 Cross Site Request Forgery vulnerability in sell done storefront v.1.0 allows a remote attacker to escalate privileges via the index.html component



- [https://github.com/xibhi/CVE-2025-26206](https://github.com/xibhi/CVE-2025-26206) :  ![starts](https://img.shields.io/github/stars/xibhi/CVE-2025-26206.svg) ![forks](https://img.shields.io/github/forks/xibhi/CVE-2025-26206.svg)

## CVE-2025-26202
 Cross-Site Scripting (XSS) vulnerability exists in the WPA/WAPI Passphrase field of the Wireless Security settings (2.4GHz & 5GHz bands) in DZS Router Web Interface. An authenticated attacker can inject malicious JavaScript into the passphrase field, which is stored and later executed when an administrator views the passphrase via the "Click here to display" option on the Status page



- [https://github.com/A17-ba/CVE-2025-26202-Details](https://github.com/A17-ba/CVE-2025-26202-Details) :  ![starts](https://img.shields.io/github/stars/A17-ba/CVE-2025-26202-Details.svg) ![forks](https://img.shields.io/github/forks/A17-ba/CVE-2025-26202-Details.svg)

## CVE-2025-26125
 An exposed ioctl in the IMFForceDelete driver of IObit Malware Fighter v12.1.0 allows attackers to arbitrarily delete files and escalate privileges.



- [https://github.com/ZeroMemoryEx/CVE-2025-26125](https://github.com/ZeroMemoryEx/CVE-2025-26125) :  ![starts](https://img.shields.io/github/stars/ZeroMemoryEx/CVE-2025-26125.svg) ![forks](https://img.shields.io/github/forks/ZeroMemoryEx/CVE-2025-26125.svg)

## CVE-2025-25968
 DDSN Interactive cm3 Acora CMS version 10.1.1 contains an improper access control vulnerability. An editor-privileged user can access sensitive information, such as system administrator credentials, by force browsing the endpoint and exploiting the 'file' parameter. By referencing specific files (e.g., cm3.xml), attackers can bypass access controls, leading to account takeover and potential privilege escalation.



- [https://github.com/padayali-JD/CVE-2025-25968](https://github.com/padayali-JD/CVE-2025-25968) :  ![starts](https://img.shields.io/github/stars/padayali-JD/CVE-2025-25968.svg) ![forks](https://img.shields.io/github/forks/padayali-JD/CVE-2025-25968.svg)

## CVE-2025-25967
 Acora CMS version 10.1.1 is vulnerable to Cross-Site Request Forgery (CSRF). This flaw enables attackers to trick authenticated users into performing unauthorized actions, such as account deletion or user creation, by embedding malicious requests in external content. The lack of CSRF protections allows exploitation via crafted requests.



- [https://github.com/padayali-JD/CVE-2025-25967](https://github.com/padayali-JD/CVE-2025-25967) :  ![starts](https://img.shields.io/github/stars/padayali-JD/CVE-2025-25967.svg) ![forks](https://img.shields.io/github/forks/padayali-JD/CVE-2025-25967.svg)

## CVE-2025-25763
 crmeb CRMEB-KY v5.4.0 and before has a SQL Injection vulnerability at getRead() in /system/SystemDatabackupServices.php



- [https://github.com/Oyst3r1ng/CVE-2025-25763](https://github.com/Oyst3r1ng/CVE-2025-25763) :  ![starts](https://img.shields.io/github/stars/Oyst3r1ng/CVE-2025-25763.svg) ![forks](https://img.shields.io/github/forks/Oyst3r1ng/CVE-2025-25763.svg)

## CVE-2025-25749
 An issue in HotelDruid version 3.0.7 and earlier allows users to set weak passwords due to the lack of enforcement of password strength policies.



- [https://github.com/huyvo2910/CVE-2025-25749-Weak-Password-Policy-in-HotelDruid-3.0.7](https://github.com/huyvo2910/CVE-2025-25749-Weak-Password-Policy-in-HotelDruid-3.0.7) :  ![starts](https://img.shields.io/github/stars/huyvo2910/CVE-2025-25749-Weak-Password-Policy-in-HotelDruid-3.0.7.svg) ![forks](https://img.shields.io/github/forks/huyvo2910/CVE-2025-25749-Weak-Password-Policy-in-HotelDruid-3.0.7.svg)

## CVE-2025-25748
 A CSRF vulnerability in the gestione_utenti.php endpoint of HotelDruid 3.0.7 allows attackers to perform unauthorized actions (e.g., modifying user passwords) on behalf of authenticated users by exploiting the lack of origin or referrer validation and the absence of CSRF tokens. NOTE: this is disputed because there is an id_sessione CSRF token.



- [https://github.com/huyvo2910/CVE-2525-25748-Cross-Site-Request-Forgery-CSRF-Vulnerability-in-HotelDruid-3.0.7](https://github.com/huyvo2910/CVE-2525-25748-Cross-Site-Request-Forgery-CSRF-Vulnerability-in-HotelDruid-3.0.7) :  ![starts](https://img.shields.io/github/stars/huyvo2910/CVE-2525-25748-Cross-Site-Request-Forgery-CSRF-Vulnerability-in-HotelDruid-3.0.7.svg) ![forks](https://img.shields.io/github/forks/huyvo2910/CVE-2525-25748-Cross-Site-Request-Forgery-CSRF-Vulnerability-in-HotelDruid-3.0.7.svg)

## CVE-2025-25747
 Cross Site Scripting vulnerability in DigitalDruid HotelDruid v.3.0.7 allows an attacker to execute arbitrary code and obtain sensitive information via the ripristina_backup parameter in the crea_backup.php endpoint



- [https://github.com/huyvo2910/CVE-2025-25747-HotelDruid-3-0-7-Reflected-XSS](https://github.com/huyvo2910/CVE-2025-25747-HotelDruid-3-0-7-Reflected-XSS) :  ![starts](https://img.shields.io/github/stars/huyvo2910/CVE-2025-25747-HotelDruid-3-0-7-Reflected-XSS.svg) ![forks](https://img.shields.io/github/forks/huyvo2910/CVE-2025-25747-HotelDruid-3-0-7-Reflected-XSS.svg)

## CVE-2025-25650
 An issue in the storage of NFC card data in Dorset DG 201 Digital Lock H5_433WBSK_v2.2_220605 allows attackers to produce cloned NFC cards to bypass authentication.



- [https://github.com/AbhijithAJ/Dorset_SmartLock_Vulnerability](https://github.com/AbhijithAJ/Dorset_SmartLock_Vulnerability) :  ![starts](https://img.shields.io/github/stars/AbhijithAJ/Dorset_SmartLock_Vulnerability.svg) ![forks](https://img.shields.io/github/forks/AbhijithAJ/Dorset_SmartLock_Vulnerability.svg)

## CVE-2025-25621
 Unifiedtransform 2.0 is vulnerable to Incorrect Access Control, which allows teachers to take attendance of fellow teachers. This affected endpoint is /courses/teacher/index?teacher_id=2&semester_id=1.



- [https://github.com/armaansidana2003/CVE-2025-25621](https://github.com/armaansidana2003/CVE-2025-25621) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25621.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25621.svg)

## CVE-2025-25620
 Unifiedtransform 2.0 is vulnerable to Cross Site Scripting (XSS) in the Create assignment function.



- [https://github.com/armaansidana2003/CVE-2025-25620](https://github.com/armaansidana2003/CVE-2025-25620) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25620.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25620.svg)

## CVE-2025-25618
 Incorrect Access Control in Unifiedtransform 2.0 leads to Privilege Escalation allowing the change of Section Name and Room Number by Teachers.



- [https://github.com/armaansidana2003/CVE-2025-25618](https://github.com/armaansidana2003/CVE-2025-25618) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25618.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25618.svg)

## CVE-2025-25617
 Incorrect Access Control in Unifiedtransform 2.X leads to Privilege Escalation allowing teachers to create syllabus.



- [https://github.com/armaansidana2003/CVE-2025-25617](https://github.com/armaansidana2003/CVE-2025-25617) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25617.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25617.svg)

## CVE-2025-25616
 Unifiedtransform 2.0 is vulnerable to Incorrect Access Control, which allows students to modify rules for exams. The affected endpoint is /exams/edit-rule?exam_rule_id=1.



- [https://github.com/armaansidana2003/CVE-2025-25616](https://github.com/armaansidana2003/CVE-2025-25616) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25616.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25616.svg)

## CVE-2025-25615
 Unifiedtransform 2.0 is vulnerable to Incorrect Access Control which allows viewing attendance list for all class sections.



- [https://github.com/armaansidana2003/CVE-2025-25615](https://github.com/armaansidana2003/CVE-2025-25615) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25615.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25615.svg)

## CVE-2025-25614
 Incorrect Access Control in Unifiedtransform 2.0 leads to Privilege Escalation, which allows teachers to update the personal data of fellow teachers.



- [https://github.com/armaansidana2003/CVE-2025-25614](https://github.com/armaansidana2003/CVE-2025-25614) :  ![starts](https://img.shields.io/github/stars/armaansidana2003/CVE-2025-25614.svg) ![forks](https://img.shields.io/github/forks/armaansidana2003/CVE-2025-25614.svg)

## CVE-2025-25612
 FS Inc S3150-8T2F prior to version S3150-8T2F_2.2.0D_135103 is vulnerable to Cross Site Scripting (XSS) in the Time Range Configuration functionality of the administration interface. An attacker can inject malicious JavaScript into the "Time Range Name" field, which is improperly sanitized. When this input is saved, it is later executed in the browser of any user accessing the affected page, including administrators, resulting in arbitrary script execution in the user's browser.



- [https://github.com/secmuzz/CVE-2025-25612](https://github.com/secmuzz/CVE-2025-25612) :  ![starts](https://img.shields.io/github/stars/secmuzz/CVE-2025-25612.svg) ![forks](https://img.shields.io/github/forks/secmuzz/CVE-2025-25612.svg)

## CVE-2025-25461
 A Stored Cross-Site Scripting (XSS) vulnerability exists in SeedDMS 6.0.29. A user or rogue admin with the "Add Category" permission can inject a malicious XSS payload into the category name field. When a document is subsequently associated with this category, the payload is stored on the server and rendered without proper sanitization or output encoding. This results in the XSS payload executing in the browser of any user who views the document.



- [https://github.com/RoNiXxCybSeC0101/CVE-2025-25461](https://github.com/RoNiXxCybSeC0101/CVE-2025-25461) :  ![starts](https://img.shields.io/github/stars/RoNiXxCybSeC0101/CVE-2025-25461.svg) ![forks](https://img.shields.io/github/forks/RoNiXxCybSeC0101/CVE-2025-25461.svg)

## CVE-2025-25460
 A stored Cross-Site Scripting (XSS) vulnerability was identified in FlatPress 1.3.1 within the "Add Entry" feature. This vulnerability allows authenticated attackers to inject malicious JavaScript payloads into blog posts, which are executed when other users view the posts. The issue arises due to improper input sanitization of the "TextArea" field in the blog entry submission form.



- [https://github.com/RoNiXxCybSeC0101/CVE-2025-25460](https://github.com/RoNiXxCybSeC0101/CVE-2025-25460) :  ![starts](https://img.shields.io/github/stars/RoNiXxCybSeC0101/CVE-2025-25460.svg) ![forks](https://img.shields.io/github/forks/RoNiXxCybSeC0101/CVE-2025-25460.svg)

## CVE-2025-25296
 Label Studio is an open source data labeling tool. Prior to version 1.16.0, Label Studio's `/projects/upload-example` endpoint allows injection of arbitrary HTML through a `GET` request with an appropriately crafted `label_config` query parameter. By crafting a specially formatted XML label config with inline task data containing malicious HTML/JavaScript, an attacker can achieve Cross-Site Scripting (XSS). While the application has a Content Security Policy (CSP), it is only set in report-only mode, making it ineffective at preventing script execution. The vulnerability exists because the upload-example endpoint renders user-provided HTML content without proper sanitization on a GET request. This allows attackers to inject and execute arbitrary JavaScript in victims' browsers by getting them to visit a maliciously crafted URL. This is considered vulnerable because it enables attackers to execute JavaScript in victims' contexts, potentially allowing theft of sensitive data, session hijacking, or other malicious actions. Version 1.16.0 contains a patch for the issue.



- [https://github.com/math-x-io/CVE-2025-25296-POC](https://github.com/math-x-io/CVE-2025-25296-POC) :  ![starts](https://img.shields.io/github/stars/math-x-io/CVE-2025-25296-POC.svg) ![forks](https://img.shields.io/github/forks/math-x-io/CVE-2025-25296-POC.svg)

## CVE-2025-25279
 Mattermost versions 10.4.x = 10.4.1, 9.11.x = 9.11.7, 10.3.x = 10.3.2, 10.2.x = 10.2.2 fail to properly validate board blocks when importing boards which allows an attacker could read any arbitrary file on the system via importing and exporting a specially crafted import archive in Boards.



- [https://github.com/numanturle/CVE-2025-25279](https://github.com/numanturle/CVE-2025-25279) :  ![starts](https://img.shields.io/github/stars/numanturle/CVE-2025-25279.svg) ![forks](https://img.shields.io/github/forks/numanturle/CVE-2025-25279.svg)

## CVE-2025-25163
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in Zach Swetz Plugin A/B Image Optimizer allows Path Traversal. This issue affects Plugin A/B Image Optimizer: from n/a through 3.3.



- [https://github.com/RandomRobbieBF/CVE-2025-25163](https://github.com/RandomRobbieBF/CVE-2025-25163) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-25163.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-25163.svg)

- [https://github.com/RootHarpy/CVE-2025-25163-Nuclei-Template](https://github.com/RootHarpy/CVE-2025-25163-Nuclei-Template) :  ![starts](https://img.shields.io/github/stars/RootHarpy/CVE-2025-25163-Nuclei-Template.svg) ![forks](https://img.shields.io/github/forks/RootHarpy/CVE-2025-25163-Nuclei-Template.svg)

## CVE-2025-25101
 Cross-Site Request Forgery (CSRF) vulnerability in MetricThemes Munk Sites allows Cross Site Request Forgery. This issue affects Munk Sites: from n/a through 1.0.7.



- [https://github.com/Nxploited/CVE-2025-25101](https://github.com/Nxploited/CVE-2025-25101) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-25101.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-25101.svg)

## CVE-2025-25064
 SQL injection vulnerability in the ZimbraSync Service SOAP endpoint in Zimbra Collaboration 10.0.x before 10.0.12 and 10.1.x before 10.1.4 due to insufficient sanitization of a user-supplied parameter. Authenticated attackers can exploit this vulnerability by manipulating a specific parameter in the request, allowing them to inject arbitrary SQL queries that could retrieve email metadata.



- [https://github.com/yelang123/Zimbra10_SQL_Injection](https://github.com/yelang123/Zimbra10_SQL_Injection) :  ![starts](https://img.shields.io/github/stars/yelang123/Zimbra10_SQL_Injection.svg) ![forks](https://img.shields.io/github/forks/yelang123/Zimbra10_SQL_Injection.svg)

## CVE-2025-25062
 An XSS issue was discovered in Backdrop CMS 1.28.x before 1.28.5 and 1.29.x before 1.29.3. It doesn't sufficiently isolate long text content when the CKEditor 5 rich text editor is used. This allows a potential attacker to craft specialized HTML and JavaScript that may be executed when an administrator attempts to edit a piece of content. This vulnerability is mitigated by the fact that an attacker must have the ability to create long text content (such as through the node or comment forms) and an administrator must edit (not view) the content that contains the malicious content. This problem only exists when using the CKEditor 5 module.



- [https://github.com/rhburt/CVE-2025-25062](https://github.com/rhburt/CVE-2025-25062) :  ![starts](https://img.shields.io/github/stars/rhburt/CVE-2025-25062.svg) ![forks](https://img.shields.io/github/forks/rhburt/CVE-2025-25062.svg)

## CVE-2025-24971
 DumpDrop is a stupid simple file upload application that provides an interface for dragging and dropping files. An OS Command Injection vulnerability was discovered in the DumbDrop application, `/upload/init` endpoint. This vulnerability could allow an attacker to execute arbitrary code remotely when the **Apprise Notification** enabled. This issue has been addressed in commit `4ff8469d` and all users are advised to patch. There are no known workarounds for this vulnerability.



- [https://github.com/be4zad/CVE-2025-24971](https://github.com/be4zad/CVE-2025-24971) :  ![starts](https://img.shields.io/github/stars/be4zad/CVE-2025-24971.svg) ![forks](https://img.shields.io/github/forks/be4zad/CVE-2025-24971.svg)

## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.



- [https://github.com/iSee857/CVE-2025-24893-PoC](https://github.com/iSee857/CVE-2025-24893-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-24893-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-24893-PoC.svg)

## CVE-2025-24813
 Path Equivalence: 'file.Name' (Internal Dot) leading to Remote Code Execution and/or Information disclosure and/or malicious content added to uploaded files via write enabled Default Servlet in Apache Tomcat.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.2, from 10.1.0-M1 through 10.1.34, from 9.0.0.M1 through 9.0.98.

If all of the following were true, a malicious user was able to view       security sensitive files and/or inject content into those files:
- writes enabled for the default servlet (disabled by default)
- support for partial PUT (enabled by default)
- a target URL for security sensitive uploads that was a sub-directory of a target URL for public uploads
- attacker knowledge of the names of security sensitive files being uploaded
- the security sensitive files also being uploaded via partial PUT

If all of the following were true, a malicious user was able to       perform remote code execution:
- writes enabled for the default servlet (disabled by default)
- support for partial PUT (enabled by default)
- application was using Tomcat's file based session persistence with the default storage location
- application included a library that may be leveraged in a deserialization attack

Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.



- [https://github.com/absholi7ly/POC-CVE-2025-24813](https://github.com/absholi7ly/POC-CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/absholi7ly/POC-CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/POC-CVE-2025-24813.svg)

- [https://github.com/iSee857/CVE-2025-24813-PoC](https://github.com/iSee857/CVE-2025-24813-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-24813-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-24813-PoC.svg)

- [https://github.com/FY036/cve-2025-24813_poc](https://github.com/FY036/cve-2025-24813_poc) :  ![starts](https://img.shields.io/github/stars/FY036/cve-2025-24813_poc.svg) ![forks](https://img.shields.io/github/forks/FY036/cve-2025-24813_poc.svg)

- [https://github.com/charis3306/CVE-2025-24813](https://github.com/charis3306/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/charis3306/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/charis3306/CVE-2025-24813.svg)

- [https://github.com/N0c1or/CVE-2025-24813_POC](https://github.com/N0c1or/CVE-2025-24813_POC) :  ![starts](https://img.shields.io/github/stars/N0c1or/CVE-2025-24813_POC.svg) ![forks](https://img.shields.io/github/forks/N0c1or/CVE-2025-24813_POC.svg)

- [https://github.com/imbas007/CVE-2025-24813-apache-tomcat](https://github.com/imbas007/CVE-2025-24813-apache-tomcat) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2025-24813-apache-tomcat.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2025-24813-apache-tomcat.svg)

- [https://github.com/msadeghkarimi/CVE-2025-24813-Exploit](https://github.com/msadeghkarimi/CVE-2025-24813-Exploit) :  ![starts](https://img.shields.io/github/stars/msadeghkarimi/CVE-2025-24813-Exploit.svg) ![forks](https://img.shields.io/github/forks/msadeghkarimi/CVE-2025-24813-Exploit.svg)

- [https://github.com/issamjr/CVE-2025-24813-Scanner](https://github.com/issamjr/CVE-2025-24813-Scanner) :  ![starts](https://img.shields.io/github/stars/issamjr/CVE-2025-24813-Scanner.svg) ![forks](https://img.shields.io/github/forks/issamjr/CVE-2025-24813-Scanner.svg)

- [https://github.com/gregk4sec/CVE-2025-24813](https://github.com/gregk4sec/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2025-24813.svg)

- [https://github.com/ps-interactive/lab-cve-2025-24813](https://github.com/ps-interactive/lab-cve-2025-24813) :  ![starts](https://img.shields.io/github/stars/ps-interactive/lab-cve-2025-24813.svg) ![forks](https://img.shields.io/github/forks/ps-interactive/lab-cve-2025-24813.svg)

- [https://github.com/michael-david-fry/Apache-Tomcat-Vulnerability-POC-CVE-2025-24813](https://github.com/michael-david-fry/Apache-Tomcat-Vulnerability-POC-CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/michael-david-fry/Apache-Tomcat-Vulnerability-POC-CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/michael-david-fry/Apache-Tomcat-Vulnerability-POC-CVE-2025-24813.svg)

- [https://github.com/n0n-zer0/Spring-Boot-Tomcat-CVE-2025-24813](https://github.com/n0n-zer0/Spring-Boot-Tomcat-CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/n0n-zer0/Spring-Boot-Tomcat-CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/n0n-zer0/Spring-Boot-Tomcat-CVE-2025-24813.svg)

## CVE-2025-24659
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in WordPress Download Manager Premium Packages allows Blind SQL Injection. This issue affects Premium Packages: from n/a through 5.9.6.



- [https://github.com/DoTTak/CVE-2025-24659](https://github.com/DoTTak/CVE-2025-24659) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-24659.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-24659.svg)

## CVE-2025-24587
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in I Thirteen Web Solution Email Subscription Popup allows Blind SQL Injection. This issue affects Email Subscription Popup: from n/a through 1.2.23.



- [https://github.com/DoTTak/CVE-2025-24587](https://github.com/DoTTak/CVE-2025-24587) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-24587.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-24587.svg)

## CVE-2025-24200
 An authorization issue was addressed with improved state management. This issue is fixed in iPadOS 17.7.5, iOS 18.3.1 and iPadOS 18.3.1. A physical attack may disable USB Restricted Mode on a locked device. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals.



- [https://github.com/McTavishSue/CVE-2025-24200](https://github.com/McTavishSue/CVE-2025-24200) :  ![starts](https://img.shields.io/github/stars/McTavishSue/CVE-2025-24200.svg) ![forks](https://img.shields.io/github/forks/McTavishSue/CVE-2025-24200.svg)

## CVE-2025-24118
 The issue was addressed with improved memory handling. This issue is fixed in iPadOS 17.7.4, macOS Sequoia 15.3, macOS Sonoma 14.7.3. An app may be able to cause unexpected system termination or write kernel memory.



- [https://github.com/jprx/CVE-2025-24118](https://github.com/jprx/CVE-2025-24118) :  ![starts](https://img.shields.io/github/stars/jprx/CVE-2025-24118.svg) ![forks](https://img.shields.io/github/forks/jprx/CVE-2025-24118.svg)

- [https://github.com/rawtips/-CVE-2025-24118](https://github.com/rawtips/-CVE-2025-24118) :  ![starts](https://img.shields.io/github/stars/rawtips/-CVE-2025-24118.svg) ![forks](https://img.shields.io/github/forks/rawtips/-CVE-2025-24118.svg)

## CVE-2025-24104
 This issue was addressed with improved handling of symlinks. This issue is fixed in iPadOS 17.7.4, iOS 18.3 and iPadOS 18.3. Restoring a maliciously crafted backup file may lead to modification of protected system files.



- [https://github.com/ifpdz/CVE-2025-24104](https://github.com/ifpdz/CVE-2025-24104) :  ![starts](https://img.shields.io/github/stars/ifpdz/CVE-2025-24104.svg) ![forks](https://img.shields.io/github/forks/ifpdz/CVE-2025-24104.svg)

## CVE-2025-24085
 A use after free issue was addressed with improved memory management. This issue is fixed in visionOS 2.3, iOS 18.3 and iPadOS 18.3, macOS Sequoia 15.3, watchOS 11.3, tvOS 18.3. A malicious application may be able to elevate privileges. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 17.2.



- [https://github.com/bronsoneaver/CVE-2025-24085](https://github.com/bronsoneaver/CVE-2025-24085) :  ![starts](https://img.shields.io/github/stars/bronsoneaver/CVE-2025-24085.svg) ![forks](https://img.shields.io/github/forks/bronsoneaver/CVE-2025-24085.svg)

## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.



- [https://github.com/0x6rss/CVE-2025-24071_PoC](https://github.com/0x6rss/CVE-2025-24071_PoC) :  ![starts](https://img.shields.io/github/stars/0x6rss/CVE-2025-24071_PoC.svg) ![forks](https://img.shields.io/github/forks/0x6rss/CVE-2025-24071_PoC.svg)

- [https://github.com/FOLKS-iwd/CVE-2025-24071-msfvenom](https://github.com/FOLKS-iwd/CVE-2025-24071-msfvenom) :  ![starts](https://img.shields.io/github/stars/FOLKS-iwd/CVE-2025-24071-msfvenom.svg) ![forks](https://img.shields.io/github/forks/FOLKS-iwd/CVE-2025-24071-msfvenom.svg)

- [https://github.com/ctabango/CVE-2025-24071_PoCExtra](https://github.com/ctabango/CVE-2025-24071_PoCExtra) :  ![starts](https://img.shields.io/github/stars/ctabango/CVE-2025-24071_PoCExtra.svg) ![forks](https://img.shields.io/github/forks/ctabango/CVE-2025-24071_PoCExtra.svg)

- [https://github.com/aleongx/CVE-2025-24071](https://github.com/aleongx/CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/aleongx/CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/aleongx/CVE-2025-24071.svg)

## CVE-2025-24016
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations, even by a compromised agent. Version 4.9.1 contains a fix.



- [https://github.com/0xjessie21/CVE-2025-24016](https://github.com/0xjessie21/CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/0xjessie21/CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/0xjessie21/CVE-2025-24016.svg)

- [https://github.com/MuhammadWaseem29/CVE-2025-24016](https://github.com/MuhammadWaseem29/CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/CVE-2025-24016.svg)

- [https://github.com/huseyinstif/CVE-2025-24016-Nuclei-Template](https://github.com/huseyinstif/CVE-2025-24016-Nuclei-Template) :  ![starts](https://img.shields.io/github/stars/huseyinstif/CVE-2025-24016-Nuclei-Template.svg) ![forks](https://img.shields.io/github/forks/huseyinstif/CVE-2025-24016-Nuclei-Template.svg)

## CVE-2025-23942
 Unrestricted Upload of File with Dangerous Type vulnerability in NgocCode WP Load Gallery allows Upload a Web Shell to a Web Server. This issue affects WP Load Gallery: from n/a through 2.1.6.



- [https://github.com/Nxploited/CVE-2025-23942-poc](https://github.com/Nxploited/CVE-2025-23942-poc) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-23942-poc.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-23942-poc.svg)

## CVE-2025-23369
 An improper verification of cryptographic signature vulnerability was identified in GitHub Enterprise Server that allowed signature spoofing for unauthorized internal users.  Instances not utilizing SAML single sign-on or where the attacker is not already an existing user were not impacted. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.12.14, 3.13.10, 3.14.7, 3.15.2, and 3.16.0. This vulnerability was reported via the GitHub Bug Bounty program.



- [https://github.com/hakivvi/CVE-2025-23369](https://github.com/hakivvi/CVE-2025-23369) :  ![starts](https://img.shields.io/github/stars/hakivvi/CVE-2025-23369.svg) ![forks](https://img.shields.io/github/forks/hakivvi/CVE-2025-23369.svg)

- [https://github.com/Arian91/CVE-2025-23369_SAML_bypass](https://github.com/Arian91/CVE-2025-23369_SAML_bypass) :  ![starts](https://img.shields.io/github/stars/Arian91/CVE-2025-23369_SAML_bypass.svg) ![forks](https://img.shields.io/github/forks/Arian91/CVE-2025-23369_SAML_bypass.svg)

## CVE-2025-23040
 GitHub Desktop is an open-source Electron-based GitHub app designed for git development. An attacker convincing a user to clone a repository directly or through a submodule can allow the attacker access to the user's credentials through the use of maliciously crafted remote URL. GitHub Desktop relies on Git to perform all network related operations (such as cloning, fetching, and pushing). When a user attempts to clone a repository GitHub Desktop will invoke `git clone` and when Git encounters a remote which requires authentication it will request the credentials for that remote host from GitHub Desktop using the git-credential protocol. Using a maliciously crafted URL it's possible to cause the credential request coming from Git to be misinterpreted by Github Desktop such that it will send credentials for a different host than the host that Git is currently communicating with thereby allowing for secret exfiltration. GitHub username and OAuth token, or credentials for other Git remote hosts stored in GitHub Desktop could be improperly transmitted to an unrelated host. Users should update to GitHub Desktop 3.4.12 or greater which fixes this vulnerability. Users who suspect they may be affected should revoke any relevant credentials.



- [https://github.com/GabrieleDattile/CVE-2025-23040](https://github.com/GabrieleDattile/CVE-2025-23040) :  ![starts](https://img.shields.io/github/stars/GabrieleDattile/CVE-2025-23040.svg) ![forks](https://img.shields.io/github/forks/GabrieleDattile/CVE-2025-23040.svg)

## CVE-2025-22968
 An issue in D-Link DWR-M972V 1.05SSG allows a remote attacker to execute arbitrary code via SSH using root account without restrictions



- [https://github.com/CRUNZEX/CVE-2025-22968](https://github.com/CRUNZEX/CVE-2025-22968) :  ![starts](https://img.shields.io/github/stars/CRUNZEX/CVE-2025-22968.svg) ![forks](https://img.shields.io/github/forks/CRUNZEX/CVE-2025-22968.svg)

## CVE-2025-22964
 DDSN Interactive cm3 Acora CMS version 10.1.1 has an unauthenticated time-based blind SQL Injection vulnerability caused by insufficient input sanitization and validation in the "table" parameter. This flaw allows attackers to inject malicious SQL queries by directly incorporating user-supplied input into database queries without proper escaping or validation. Exploiting this issue enables unauthorized access, manipulation of data, or exposure of sensitive information, posing significant risks to the integrity and confidentiality of the application.



- [https://github.com/padayali-JD/CVE-2025-22964](https://github.com/padayali-JD/CVE-2025-22964) :  ![starts](https://img.shields.io/github/stars/padayali-JD/CVE-2025-22964.svg) ![forks](https://img.shields.io/github/forks/padayali-JD/CVE-2025-22964.svg)

## CVE-2025-22954
 GetLateOrMissingIssues in C4/Serials.pm in Koha before 24.11.02 allows SQL Injection in /serials/lateissues-export.pl via the supplierid or serialid parameter.



- [https://github.com/RandomRobbieBF/CVE-2025-22954](https://github.com/RandomRobbieBF/CVE-2025-22954) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-22954.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-22954.svg)

## CVE-2025-22828
 CloudStack users can add and read comments (annotations) on resources they are authorised to access. 

Due to an access validation issue that affects Apache CloudStack versions from 4.16.0, users who have access, prior access or knowledge of resource UUIDs can list and add comments (annotations) to such resources. 

An attacker with a user-account and access or prior knowledge of resource UUIDs may exploit this issue to read contents of the comments (annotations) or add malicious comments (annotations) to such resources. 

This may cause potential loss of confidentiality of CloudStack environments and resources if the comments (annotations) contain any privileged information. However, guessing or brute-forcing resource UUIDs are generally hard to impossible and access to listing or adding comments isn't same as access to CloudStack resources, making this issue of very low severity and general low impact.


CloudStack admins may also disallow listAnnotations and addAnnotation API access to non-admin roles in their environment as an interim measure.



- [https://github.com/Stolichnayer/CVE-2025-22828](https://github.com/Stolichnayer/CVE-2025-22828) :  ![starts](https://img.shields.io/github/stars/Stolichnayer/CVE-2025-22828.svg) ![forks](https://img.shields.io/github/forks/Stolichnayer/CVE-2025-22828.svg)

## CVE-2025-22785
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in ComMotion Course Booking System allows SQL Injection.This issue affects Course Booking System: from n/a through 6.0.5.



- [https://github.com/RandomRobbieBF/CVE-2025-22785](https://github.com/RandomRobbieBF/CVE-2025-22785) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2025-22785.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2025-22785.svg)

## CVE-2025-22710
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in StoreApps Smart Manager allows Blind SQL Injection. This issue affects Smart Manager: from n/a through 8.52.0.



- [https://github.com/DoTTak/CVE-2025-22710](https://github.com/DoTTak/CVE-2025-22710) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22710.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22710.svg)

## CVE-2025-22620
 gitoxide is an implementation of git written in Rust. Prior to 0.17.0, gix-worktree-state specifies 0777 permissions when checking out executable files, intending that the umask will restrict them appropriately. But one of the strategies it uses to set permissions is not subject to the umask. This causes files in a repository to be world-writable in some situations. This vulnerability is fixed in 0.17.0.



- [https://github.com/EliahKagan/checkout-index](https://github.com/EliahKagan/checkout-index) :  ![starts](https://img.shields.io/github/stars/EliahKagan/checkout-index.svg) ![forks](https://img.shields.io/github/forks/EliahKagan/checkout-index.svg)

## CVE-2025-22604
 Cacti is an open source performance and fault management framework. Due to a flaw in multi-line SNMP result parser, authenticated users can inject malformed OIDs in the response. When processed by ss_net_snmp_disk_io() or ss_net_snmp_disk_bytes(), a part of each OID will be used as a key in an array that is used as part of a system command, causing a command execution vulnerability. This vulnerability is fixed in 1.2.29.



- [https://github.com/ishwardeepp/CVE-2025-22604-Cacti-RCE](https://github.com/ishwardeepp/CVE-2025-22604-Cacti-RCE) :  ![starts](https://img.shields.io/github/stars/ishwardeepp/CVE-2025-22604-Cacti-RCE.svg) ![forks](https://img.shields.io/github/forks/ishwardeepp/CVE-2025-22604-Cacti-RCE.svg)

## CVE-2025-22510
 Deserialization of Untrusted Data vulnerability in Konrad Karpieszuk WC Price History for Omnibus allows Object Injection.This issue affects WC Price History for Omnibus: from n/a through 2.1.4.



- [https://github.com/DoTTak/CVE-2025-22510](https://github.com/DoTTak/CVE-2025-22510) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22510.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22510.svg)

## CVE-2025-22352
 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in ELEXtensions ELEX WooCommerce Advanced Bulk Edit Products, Prices & Attributes allows Blind SQL Injection.This issue affects ELEX WooCommerce Advanced Bulk Edit Products, Prices & Attributes: from n/a through 1.4.8.



- [https://github.com/DoTTak/CVE-2025-22352](https://github.com/DoTTak/CVE-2025-22352) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22352.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22352.svg)

## CVE-2025-21420
 Windows Disk Cleanup Tool Elevation of Privilege Vulnerability



- [https://github.com/Network-Sec/CVE-2025-21420-PoC](https://github.com/Network-Sec/CVE-2025-21420-PoC) :  ![starts](https://img.shields.io/github/stars/Network-Sec/CVE-2025-21420-PoC.svg) ![forks](https://img.shields.io/github/forks/Network-Sec/CVE-2025-21420-PoC.svg)

- [https://github.com/toxy4ny/edge-maradeur](https://github.com/toxy4ny/edge-maradeur) :  ![starts](https://img.shields.io/github/stars/toxy4ny/edge-maradeur.svg) ![forks](https://img.shields.io/github/forks/toxy4ny/edge-maradeur.svg)

## CVE-2025-21401
 Microsoft Edge (Chromium-based) Security Feature Bypass Vulnerability



- [https://github.com/toxy4ny/edge-maradeur](https://github.com/toxy4ny/edge-maradeur) :  ![starts](https://img.shields.io/github/stars/toxy4ny/edge-maradeur.svg) ![forks](https://img.shields.io/github/forks/toxy4ny/edge-maradeur.svg)

## CVE-2025-21385
 A Server-Side Request Forgery (SSRF) vulnerability in Microsoft Purview allows an authorized attacker to disclose information over a network.



- [https://github.com/Pauloxc6/CVE-2025-21385](https://github.com/Pauloxc6/CVE-2025-21385) :  ![starts](https://img.shields.io/github/stars/Pauloxc6/CVE-2025-21385.svg) ![forks](https://img.shields.io/github/forks/Pauloxc6/CVE-2025-21385.svg)

## CVE-2025-21333
 Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege Vulnerability



- [https://github.com/MrAle98/CVE-2025-21333-POC](https://github.com/MrAle98/CVE-2025-21333-POC) :  ![starts](https://img.shields.io/github/stars/MrAle98/CVE-2025-21333-POC.svg) ![forks](https://img.shields.io/github/forks/MrAle98/CVE-2025-21333-POC.svg)

- [https://github.com/aleongx/KQL_sentinel_CVE-2025-21333](https://github.com/aleongx/KQL_sentinel_CVE-2025-21333) :  ![starts](https://img.shields.io/github/stars/aleongx/KQL_sentinel_CVE-2025-21333.svg) ![forks](https://img.shields.io/github/forks/aleongx/KQL_sentinel_CVE-2025-21333.svg)

- [https://github.com/Mukesh-blend/CVE-2025-21333-POC](https://github.com/Mukesh-blend/CVE-2025-21333-POC) :  ![starts](https://img.shields.io/github/stars/Mukesh-blend/CVE-2025-21333-POC.svg) ![forks](https://img.shields.io/github/forks/Mukesh-blend/CVE-2025-21333-POC.svg)

## CVE-2025-21298
 Windows OLE Remote Code Execution Vulnerability



- [https://github.com/ynwarcs/CVE-2025-21298](https://github.com/ynwarcs/CVE-2025-21298) :  ![starts](https://img.shields.io/github/stars/ynwarcs/CVE-2025-21298.svg) ![forks](https://img.shields.io/github/forks/ynwarcs/CVE-2025-21298.svg)

- [https://github.com/Dit-Developers/CVE-2025-21298](https://github.com/Dit-Developers/CVE-2025-21298) :  ![starts](https://img.shields.io/github/stars/Dit-Developers/CVE-2025-21298.svg) ![forks](https://img.shields.io/github/forks/Dit-Developers/CVE-2025-21298.svg)

## CVE-2025-21293
 Active Directory Domain Services Elevation of Privilege Vulnerability



- [https://github.com/ahmedumarehman/CVE-2025-21293](https://github.com/ahmedumarehman/CVE-2025-21293) :  ![starts](https://img.shields.io/github/stars/ahmedumarehman/CVE-2025-21293.svg) ![forks](https://img.shields.io/github/forks/ahmedumarehman/CVE-2025-21293.svg)

## CVE-2025-20029
 Command injection vulnerability exists in iControl REST and BIG-IP TMOS Shell (tmsh) save command, which may allow an authenticated attacker to execute arbitrary system commands.

 


Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/mbadanoiu/CVE-2025-20029](https://github.com/mbadanoiu/CVE-2025-20029) :  ![starts](https://img.shields.io/github/stars/mbadanoiu/CVE-2025-20029.svg) ![forks](https://img.shields.io/github/forks/mbadanoiu/CVE-2025-20029.svg)

## CVE-2025-2536
 Cross-site scripting (XSS) vulnerability on Liferay Portal 7.4.3.82 through 7.4.3.128, and Liferay DXP 2024.Q3.0, 2024.Q2.0 through 2024.Q2.13, 2024.Q1.1 through 2024.Q1.12, 2023.Q4.0 through 2023.Q4.10, 2023.Q3.1 through 2023.Q3.10, 7.4 update 82 through update 92 in the Frontend JS module's layout-taglib/__liferay__/index.js allows remote attackers to inject arbitrary web script or HTML via toastData parameter



- [https://github.com/lkasjkasj/CVE-2025-25369](https://github.com/lkasjkasj/CVE-2025-25369) :  ![starts](https://img.shields.io/github/stars/lkasjkasj/CVE-2025-25369.svg) ![forks](https://img.shields.io/github/forks/lkasjkasj/CVE-2025-25369.svg)

## CVE-2025-2476
 Use after free in Lens in Google Chrome prior to 134.0.6998.117 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)



- [https://github.com/McTavishSue/CVE-2025-2476](https://github.com/McTavishSue/CVE-2025-2476) :  ![starts](https://img.shields.io/github/stars/McTavishSue/CVE-2025-2476.svg) ![forks](https://img.shields.io/github/forks/McTavishSue/CVE-2025-2476.svg)

## CVE-2025-2278
 Improper access control in temporary access requests and checkout requests endpoints in Devolutions Server 2024.3.13 and earlier allows an authenticated user to access information about these requests via a known request ID.



- [https://github.com/DoTTak/CVE-2025-22783](https://github.com/DoTTak/CVE-2025-22783) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22783.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22783.svg)

## CVE-2025-2265
 The password of a web user in "Sante PACS Server.exe" is zero-padded to 0x2000 bytes, SHA1-hashed, base64-encoded, and stored in the USER table in the SQLite database HTTP.db. However, the number of hash bytes encoded and stored is truncated if the hash contains a zero byte



- [https://github.com/DoTTak/CVE-2025-22652](https://github.com/DoTTak/CVE-2025-22652) :  ![starts](https://img.shields.io/github/stars/DoTTak/CVE-2025-22652.svg) ![forks](https://img.shields.io/github/forks/DoTTak/CVE-2025-22652.svg)

## CVE-2025-2233
 Samsung SmartThings Improper Verification of Cryptographic Signature Authentication Bypass Vulnerability. This vulnerability allows network-adjacent attackers to bypass authentication on affected installations of Samsung SmartThings. Authentication is not required to exploit this vulnerability.

The specific flaw exists within the Hub Local API service, which listens on TCP port 8766 by default. The issue results from the lack of proper verification of a cryptographic signature. An attacker can leverage this vulnerability to bypass authentication on the system. Was ZDI-CAN-25615.



- [https://github.com/McTavishSue/CVE-2025-2233](https://github.com/McTavishSue/CVE-2025-2233) :  ![starts](https://img.shields.io/github/stars/McTavishSue/CVE-2025-2233.svg) ![forks](https://img.shields.io/github/forks/McTavishSue/CVE-2025-2233.svg)

## CVE-2025-1716
 picklescan before 0.0.21 does not treat 'pip' as an unsafe global. An attacker could craft a malicious model that uses Pickle to pull in a malicious PyPI package (hosted, for example, on pypi.org or GitHub) via `pip.main()`. Because pip is not a restricted global, the model, when scanned with picklescan, would pass security checks and appear to be safe, when it could instead prove to be problematic.



- [https://github.com/shybu9/poc_CVE-2025-1716](https://github.com/shybu9/poc_CVE-2025-1716) :  ![starts](https://img.shields.io/github/stars/shybu9/poc_CVE-2025-1716.svg) ![forks](https://img.shields.io/github/forks/shybu9/poc_CVE-2025-1716.svg)

## CVE-2025-1661
 The HUSKY – Products Filter Professional for WooCommerce plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 1.3.6.5 via the 'template' parameter of the woof_text_search AJAX action. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.



- [https://github.com/MuhammadWaseem29/CVE-2025-1661](https://github.com/MuhammadWaseem29/CVE-2025-1661) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/CVE-2025-1661.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/CVE-2025-1661.svg)

- [https://github.com/gbrsh/CVE-2025-1661](https://github.com/gbrsh/CVE-2025-1661) :  ![starts](https://img.shields.io/github/stars/gbrsh/CVE-2025-1661.svg) ![forks](https://img.shields.io/github/forks/gbrsh/CVE-2025-1661.svg)

## CVE-2025-1639
 The Animation Addons for Elementor Pro plugin for WordPress is vulnerable to unauthorized arbitrary plugin installation due to a missing capability check on the install_elementor_plugin_handler() function in all versions up to, and including, 1.6. This makes it possible for authenticated attackers, with Subscriber-level access and above, to install and activate arbitrary plugins which can be leveraged to further infect a victim when Elementor is not activated on a vulnerable site.



- [https://github.com/Nxploited/CVE-2025-1639](https://github.com/Nxploited/CVE-2025-1639) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-1639.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-1639.svg)

## CVE-2025-1307
 The Newscrunch theme for WordPress is vulnerable to arbitrary file uploads due to a missing capability check in the newscrunch_install_and_activate_plugin() function in all versions up to, and including, 1.8.4.1. This makes it possible for authenticated attackers, with Subscriber-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Nxploited/CVE-2025-1307](https://github.com/Nxploited/CVE-2025-1307) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-1307.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-1307.svg)

## CVE-2025-1306
 The Newscrunch theme for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 1.8.4. This is due to missing or incorrect nonce validation on the newscrunch_install_and_activate_plugin() function. This makes it possible for unauthenticated attackers to upload arbitrary files via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.



- [https://github.com/Nxploited/CVE-2025-1306](https://github.com/Nxploited/CVE-2025-1306) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-1306.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-1306.svg)

## CVE-2025-1302
 Versions of the package jsonpath-plus before 10.3.0 are vulnerable to Remote Code Execution (RCE) due to improper input sanitization. An attacker can execute aribitrary code on the system by exploiting the unsafe default usage of eval='safe' mode.**Note:**This is caused by an incomplete fix for [CVE-2024-21534](https://security.snyk.io/vuln/SNYK-JS-JSONPATHPLUS-7945884).



- [https://github.com/EQSTLab/CVE-2025-1302](https://github.com/EQSTLab/CVE-2025-1302) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2025-1302.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2025-1302.svg)

## CVE-2025-1094
 Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to achieve SQL injection in certain usage patterns.  Specifically, SQL injection requires the application to use the function result to construct input to psql, the PostgreSQL interactive terminal.  Similarly, improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source of command line arguments to achieve SQL injection when client_encoding is BIG5 and server_encoding is one of EUC_TW or MULE_INTERNAL.  Versions before PostgreSQL 17.3, 16.7, 15.11, 14.16, and 13.19 are affected.



- [https://github.com/soltanali0/CVE-2025-1094-Exploit](https://github.com/soltanali0/CVE-2025-1094-Exploit) :  ![starts](https://img.shields.io/github/stars/soltanali0/CVE-2025-1094-Exploit.svg) ![forks](https://img.shields.io/github/forks/soltanali0/CVE-2025-1094-Exploit.svg)

- [https://github.com/shacojx/CVE-2025-1094-Exploit](https://github.com/shacojx/CVE-2025-1094-Exploit) :  ![starts](https://img.shields.io/github/stars/shacojx/CVE-2025-1094-Exploit.svg) ![forks](https://img.shields.io/github/forks/shacojx/CVE-2025-1094-Exploit.svg)

- [https://github.com/ishwardeepp/CVE-2025-1094-PoC-Postgre-SQLi](https://github.com/ishwardeepp/CVE-2025-1094-PoC-Postgre-SQLi) :  ![starts](https://img.shields.io/github/stars/ishwardeepp/CVE-2025-1094-PoC-Postgre-SQLi.svg) ![forks](https://img.shields.io/github/forks/ishwardeepp/CVE-2025-1094-PoC-Postgre-SQLi.svg)

## CVE-2025-1015
 The Thunderbird Address Book URI fields contained unsanitized links. This could be used by an attacker to create and export an address book containing a malicious payload in a field. For example, in the “Other” field of the Instant Messaging section. If another user imported the address book, clicking on the link could result in opening a web page inside Thunderbird, and that page could execute (unprivileged) JavaScript. This vulnerability affects Thunderbird  128.7 and Thunderbird  135.



- [https://github.com/r3m0t3nu11/CVE-2025-1015](https://github.com/r3m0t3nu11/CVE-2025-1015) :  ![starts](https://img.shields.io/github/stars/r3m0t3nu11/CVE-2025-1015.svg) ![forks](https://img.shields.io/github/forks/r3m0t3nu11/CVE-2025-1015.svg)

## CVE-2025-0994
 Trimble Cityworks versions prior to 15.8.9 and Cityworks with office companion versions prior to 23.10 are vulnerable to a deserialization vulnerability. This could allow an authenticated user to perform a remote code execution attack against a customer’s Microsoft Internet Information Services (IIS) web server.



- [https://github.com/rxerium/CVE-2025-0994](https://github.com/rxerium/CVE-2025-0994) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-0994.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-0994.svg)

## CVE-2025-0924
 The WP Activity Log plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘message’ parameter in all versions up to, and including, 5.2.2 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/skrkcb2/CVE-2025-0924-different](https://github.com/skrkcb2/CVE-2025-0924-different) :  ![starts](https://img.shields.io/github/stars/skrkcb2/CVE-2025-0924-different.svg) ![forks](https://img.shields.io/github/forks/skrkcb2/CVE-2025-0924-different.svg)

## CVE-2025-0851
 A path traversal issue in ZipUtils.unzip and TarUtils.untar in Deep Java Library (DJL) on all platforms allows a bad actor to write files to arbitrary locations.



- [https://github.com/skrkcb2/CVE-2025-0851](https://github.com/skrkcb2/CVE-2025-0851) :  ![starts](https://img.shields.io/github/stars/skrkcb2/CVE-2025-0851.svg) ![forks](https://img.shields.io/github/forks/skrkcb2/CVE-2025-0851.svg)

## CVE-2025-0411
 7-Zip Mark-of-the-Web Bypass Vulnerability. This vulnerability allows remote attackers to bypass the Mark-of-the-Web protection mechanism on affected installations of 7-Zip. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file.

The specific flaw exists within the handling of archived files. When extracting files from a crafted archive that bears the Mark-of-the-Web, 7-Zip does not propagate the Mark-of-the-Web to the extracted files. An attacker can leverage this vulnerability to execute arbitrary code in the context of the current user. Was ZDI-CAN-25456.



- [https://github.com/dhmosfunk/7-Zip-CVE-2025-0411-POC](https://github.com/dhmosfunk/7-Zip-CVE-2025-0411-POC) :  ![starts](https://img.shields.io/github/stars/dhmosfunk/7-Zip-CVE-2025-0411-POC.svg) ![forks](https://img.shields.io/github/forks/dhmosfunk/7-Zip-CVE-2025-0411-POC.svg)

- [https://github.com/iSee857/CVE-2025-0411-PoC](https://github.com/iSee857/CVE-2025-0411-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-0411-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-0411-PoC.svg)

- [https://github.com/cesarbtakeda/7-Zip-CVE-2025-0411-POC](https://github.com/cesarbtakeda/7-Zip-CVE-2025-0411-POC) :  ![starts](https://img.shields.io/github/stars/cesarbtakeda/7-Zip-CVE-2025-0411-POC.svg) ![forks](https://img.shields.io/github/forks/cesarbtakeda/7-Zip-CVE-2025-0411-POC.svg)

- [https://github.com/dpextreme/7-Zip-CVE-2025-0411-POC](https://github.com/dpextreme/7-Zip-CVE-2025-0411-POC) :  ![starts](https://img.shields.io/github/stars/dpextreme/7-Zip-CVE-2025-0411-POC.svg) ![forks](https://img.shields.io/github/forks/dpextreme/7-Zip-CVE-2025-0411-POC.svg)

- [https://github.com/ishwardeepp/CVE-2025-0411-MoTW-PoC](https://github.com/ishwardeepp/CVE-2025-0411-MoTW-PoC) :  ![starts](https://img.shields.io/github/stars/ishwardeepp/CVE-2025-0411-MoTW-PoC.svg) ![forks](https://img.shields.io/github/forks/ishwardeepp/CVE-2025-0411-MoTW-PoC.svg)

## CVE-2025-0364
 BigAntSoft BigAnt Server, up to and including version 5.6.06, is vulnerable to unauthenticated remote code execution via account registration. An unauthenticated remote attacker can create an administrative user through the default exposed SaaS registration mechanism. Once an administrator, the attacker can upload and execute arbitrary PHP code using the "Cloud Storage Addin," leading to unauthenticated code execution.



- [https://github.com/vulncheck-oss/cve-2025-0364](https://github.com/vulncheck-oss/cve-2025-0364) :  ![starts](https://img.shields.io/github/stars/vulncheck-oss/cve-2025-0364.svg) ![forks](https://img.shields.io/github/forks/vulncheck-oss/cve-2025-0364.svg)

## CVE-2025-0282
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution.



- [https://github.com/absholi7ly/CVE-2025-0282-Ivanti-exploit](https://github.com/absholi7ly/CVE-2025-0282-Ivanti-exploit) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2025-0282-Ivanti-exploit.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2025-0282-Ivanti-exploit.svg)

- [https://github.com/sfewer-r7/CVE-2025-0282](https://github.com/sfewer-r7/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/CVE-2025-0282.svg)

- [https://github.com/watchtowrlabs/CVE-2025-0282](https://github.com/watchtowrlabs/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/CVE-2025-0282.svg)

- [https://github.com/AnonStorks/CVE-2025-0282-Full-version](https://github.com/AnonStorks/CVE-2025-0282-Full-version) :  ![starts](https://img.shields.io/github/stars/AnonStorks/CVE-2025-0282-Full-version.svg) ![forks](https://img.shields.io/github/forks/AnonStorks/CVE-2025-0282-Full-version.svg)

- [https://github.com/punitdarji/Ivanti-CVE-2025-0282](https://github.com/punitdarji/Ivanti-CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/punitdarji/Ivanti-CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/punitdarji/Ivanti-CVE-2025-0282.svg)

- [https://github.com/Hexastrike/Ivanti-Connect-Secure-Logs-Parser](https://github.com/Hexastrike/Ivanti-Connect-Secure-Logs-Parser) :  ![starts](https://img.shields.io/github/stars/Hexastrike/Ivanti-Connect-Secure-Logs-Parser.svg) ![forks](https://img.shields.io/github/forks/Hexastrike/Ivanti-Connect-Secure-Logs-Parser.svg)

- [https://github.com/AdaniKamal/CVE-2025-0282](https://github.com/AdaniKamal/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/AdaniKamal/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/AdaniKamal/CVE-2025-0282.svg)

- [https://github.com/rxwx/pulse-meter](https://github.com/rxwx/pulse-meter) :  ![starts](https://img.shields.io/github/stars/rxwx/pulse-meter.svg) ![forks](https://img.shields.io/github/forks/rxwx/pulse-meter.svg)

- [https://github.com/almanatra/CVE-2025-0282](https://github.com/almanatra/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/almanatra/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/almanatra/CVE-2025-0282.svg)

- [https://github.com/44xo/CVE-2025-0282](https://github.com/44xo/CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/44xo/CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/44xo/CVE-2025-0282.svg)

## CVE-2025-0108
 An authentication bypass in the Palo Alto Networks PAN-OS software enables an unauthenticated attacker with network access to the management web interface to bypass the authentication otherwise required by the PAN-OS management web interface and invoke certain PHP scripts. While invoking these PHP scripts does not enable remote code execution, it can negatively impact integrity and confidentiality of PAN-OS.

You can greatly reduce the risk of this issue by restricting access to the management web interface to only trusted internal IP addresses according to our recommended  best practices deployment guidelines https://live.paloaltonetworks.com/t5/community-blogs/tips-amp-tricks-how-to-secure-the-management-access-of-your-palo/ba-p/464431 .

This issue does not affect Cloud NGFW or Prisma Access software.



- [https://github.com/iSee857/CVE-2025-0108-PoC](https://github.com/iSee857/CVE-2025-0108-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-0108-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-0108-PoC.svg)

- [https://github.com/FOLKS-iwd/CVE-2025-0108-PoC](https://github.com/FOLKS-iwd/CVE-2025-0108-PoC) :  ![starts](https://img.shields.io/github/stars/FOLKS-iwd/CVE-2025-0108-PoC.svg) ![forks](https://img.shields.io/github/forks/FOLKS-iwd/CVE-2025-0108-PoC.svg)

- [https://github.com/fr4nc1stein/CVE-2025-0108-SCAN](https://github.com/fr4nc1stein/CVE-2025-0108-SCAN) :  ![starts](https://img.shields.io/github/stars/fr4nc1stein/CVE-2025-0108-SCAN.svg) ![forks](https://img.shields.io/github/forks/fr4nc1stein/CVE-2025-0108-SCAN.svg)

- [https://github.com/sohaibeb/CVE-2025-0108](https://github.com/sohaibeb/CVE-2025-0108) :  ![starts](https://img.shields.io/github/stars/sohaibeb/CVE-2025-0108.svg) ![forks](https://img.shields.io/github/forks/sohaibeb/CVE-2025-0108.svg)

- [https://github.com/becrevex/CVE-2025-0108](https://github.com/becrevex/CVE-2025-0108) :  ![starts](https://img.shields.io/github/stars/becrevex/CVE-2025-0108.svg) ![forks](https://img.shields.io/github/forks/becrevex/CVE-2025-0108.svg)

- [https://github.com/barcrange/CVE-2025-0108-Authentication-Bypass-checker](https://github.com/barcrange/CVE-2025-0108-Authentication-Bypass-checker) :  ![starts](https://img.shields.io/github/stars/barcrange/CVE-2025-0108-Authentication-Bypass-checker.svg) ![forks](https://img.shields.io/github/forks/barcrange/CVE-2025-0108-Authentication-Bypass-checker.svg)

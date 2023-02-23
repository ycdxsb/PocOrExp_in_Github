## CVE-2023-25194
 A possible security vulnerability has been identified in Apache Kafka Connect. This requires access to a Kafka Connect worker, and the ability to create/modify connectors on it with an arbitrary Kafka client SASL JAAS config and a SASL-based security protocol, which has been possible on Kafka Connect clusters since Apache Kafka 2.3.0. When configuring the connector via the Kafka Connect REST API, an authenticated operator can set the `sasl.jaas.config` property for any of the connector's Kafka clients to &quot;com.sun.security.auth.module.JndiLoginModule&quot;, which can be done via the `producer.override.sasl.jaas.config`, `consumer.override.sasl.jaas.config`, or `admin.override.sasl.jaas.config` properties. This will allow the server to connect to the attacker's LDAP server and deserialize the LDAP response, which the attacker can use to execute java deserialization gadget chains on the Kafka connect server. Attacker can cause unrestricted deserialization of untrusted data (or) RCE vulnerability when there are gadgets in the classpath. Since Apache Kafka 3.0.0, users are allowed to specify these properties in connector configurations for Kafka Connect clusters running with out-of-the-box configurations. Before Apache Kafka 3.0.0, users may not specify these properties unless the Kafka Connect cluster has been reconfigured with a connector client override policy that permits them. Since Apache Kafka 3.4.0, we have added a system property (&quot;-Dorg.apache.kafka.disallowed.login.modules&quot;) to disable the problematic login modules usage in SASL JAAS configuration. Also by default &quot;com.sun.security.auth.module.JndiLoginModule&quot; is disabled in Apache Kafka 3.4.0. We advise the Kafka Connect users to validate connector configurations and only allow trusted JNDI configurations. Also examine connector dependencies for vulnerable versions and either upgrade their connectors, upgrading that specific dependency, or removing the connectors as options for remediation. Finally, in addition to leveraging the &quot;org.apache.kafka.disallowed.login.modules&quot; system property, Kafka Connect users can also implement their own connector client config override policy, which can be used to control which Kafka client properties can be overridden directly in a connector config and which cannot.



- [https://github.com/ohnonoyesyes/CVE-2023-25194](https://github.com/ohnonoyesyes/CVE-2023-25194) :  ![starts](https://img.shields.io/github/stars/ohnonoyesyes/CVE-2023-25194.svg) ![forks](https://img.shields.io/github/forks/ohnonoyesyes/CVE-2023-25194.svg)

## CVE-2023-25136
 OpenSSH server (sshd) 9.1 introduced a double-free vulnerability during options.kex_algorithms handling. This is fixed in OpenSSH 9.2. The double free can be leveraged, by an unauthenticated remote attacker in the default configuration, to jump to any location in the sshd address space. One third-party report states &quot;remote code execution is theoretically possible.&quot;



- [https://github.com/jfrog/jfrog-CVE-2023-25136-OpenSSH_Double-Free](https://github.com/jfrog/jfrog-CVE-2023-25136-OpenSSH_Double-Free) :  ![starts](https://img.shields.io/github/stars/jfrog/jfrog-CVE-2023-25136-OpenSSH_Double-Free.svg) ![forks](https://img.shields.io/github/forks/jfrog/jfrog-CVE-2023-25136-OpenSSH_Double-Free.svg)

- [https://github.com/ticofookfook/CVE-2023-25136](https://github.com/ticofookfook/CVE-2023-25136) :  ![starts](https://img.shields.io/github/stars/ticofookfook/CVE-2023-25136.svg) ![forks](https://img.shields.io/github/forks/ticofookfook/CVE-2023-25136.svg)

- [https://github.com/Christbowel/CVE-2023-25136](https://github.com/Christbowel/CVE-2023-25136) :  ![starts](https://img.shields.io/github/stars/Christbowel/CVE-2023-25136.svg) ![forks](https://img.shields.io/github/forks/Christbowel/CVE-2023-25136.svg)

## CVE-2023-24610
 NOSH 4a5cfdb allows remote authenticated users to execute PHP arbitrary code via the &quot;practice logo&quot; upload feature. The client-side checks can be bypassed. This may allow attackers to steal Protected Health Information because the product is for health charting.



- [https://github.com/abbisQQ/CVE-2023-24610](https://github.com/abbisQQ/CVE-2023-24610) :  ![starts](https://img.shields.io/github/stars/abbisQQ/CVE-2023-24610.svg) ![forks](https://img.shields.io/github/forks/abbisQQ/CVE-2023-24610.svg)

## CVE-2023-24059
 Grand Theft Auto V for PC allows attackers to achieve partial remote code execution or modify files on a PC, as exploited in the wild in January 2023.



- [https://github.com/gmh5225/CVE-2023-24059](https://github.com/gmh5225/CVE-2023-24059) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2023-24059.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2023-24059.svg)

## CVE-2023-24055
 ** DISPUTED ** KeePass through 2.53 (in a default installation) allows an attacker, who has write access to the XML configuration file, to obtain the cleartext passwords by adding an export trigger. NOTE: the vendor's position is that the password database is not intended to be secure against an attacker who has that level of access to the local PC.



- [https://github.com/alt3kx/CVE-2023-24055_PoC](https://github.com/alt3kx/CVE-2023-24055_PoC) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2023-24055_PoC.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2023-24055_PoC.svg)

- [https://github.com/deetl/CVE-2023-24055](https://github.com/deetl/CVE-2023-24055) :  ![starts](https://img.shields.io/github/stars/deetl/CVE-2023-24055.svg) ![forks](https://img.shields.io/github/forks/deetl/CVE-2023-24055.svg)

- [https://github.com/ATTACKnDEFEND/CVE-2023-24055](https://github.com/ATTACKnDEFEND/CVE-2023-24055) :  ![starts](https://img.shields.io/github/stars/ATTACKnDEFEND/CVE-2023-24055.svg) ![forks](https://img.shields.io/github/forks/ATTACKnDEFEND/CVE-2023-24055.svg)

- [https://github.com/PyterSmithDarkGhost/CVE-2023-24055-PoC-KeePass-2.5x-](https://github.com/PyterSmithDarkGhost/CVE-2023-24055-PoC-KeePass-2.5x-) :  ![starts](https://img.shields.io/github/stars/PyterSmithDarkGhost/CVE-2023-24055-PoC-KeePass-2.5x-.svg) ![forks](https://img.shields.io/github/forks/PyterSmithDarkGhost/CVE-2023-24055-PoC-KeePass-2.5x-.svg)

- [https://github.com/zwlsix/KeePass-CVE-2023-24055](https://github.com/zwlsix/KeePass-CVE-2023-24055) :  ![starts](https://img.shields.io/github/stars/zwlsix/KeePass-CVE-2023-24055.svg) ![forks](https://img.shields.io/github/forks/zwlsix/KeePass-CVE-2023-24055.svg)

- [https://github.com/julesbozouklian/PoC_CVE-2023-24055](https://github.com/julesbozouklian/PoC_CVE-2023-24055) :  ![starts](https://img.shields.io/github/stars/julesbozouklian/PoC_CVE-2023-24055.svg) ![forks](https://img.shields.io/github/forks/julesbozouklian/PoC_CVE-2023-24055.svg)

- [https://github.com/poppylarrry/firefox-rce-poc](https://github.com/poppylarrry/firefox-rce-poc) :  ![starts](https://img.shields.io/github/stars/poppylarrry/firefox-rce-poc.svg) ![forks](https://img.shields.io/github/forks/poppylarrry/firefox-rce-poc.svg)

- [https://github.com/Cyb3rtus/keepass_CVE-2023-24055_yara_rule](https://github.com/Cyb3rtus/keepass_CVE-2023-24055_yara_rule) :  ![starts](https://img.shields.io/github/stars/Cyb3rtus/keepass_CVE-2023-24055_yara_rule.svg) ![forks](https://img.shields.io/github/forks/Cyb3rtus/keepass_CVE-2023-24055_yara_rule.svg)

- [https://github.com/digital-dev/KeePass-TriggerLess](https://github.com/digital-dev/KeePass-TriggerLess) :  ![starts](https://img.shields.io/github/stars/digital-dev/KeePass-TriggerLess.svg) ![forks](https://img.shields.io/github/forks/digital-dev/KeePass-TriggerLess.svg)

## CVE-2023-23924
 Dompdf is an HTML to PDF converter. The URI validation on dompdf 2.0.1 can be bypassed on SVG parsing by passing `&lt;image&gt;` tags with uppercase letters. This may lead to arbitrary object unserialize on PHP &lt; 8, through the `phar` URL wrapper. An attacker can exploit the vulnerability to call arbitrary URL with arbitrary protocols, if they can provide a SVG file to dompdf. In PHP versions before 8.0.0, it leads to arbitrary unserialize, that will lead to the very least to an arbitrary file deletion and even remote code execution, depending on classes that are available.



- [https://github.com/motikan2010/CVE-2023-23924](https://github.com/motikan2010/CVE-2023-23924) :  ![starts](https://img.shields.io/github/stars/motikan2010/CVE-2023-23924.svg) ![forks](https://img.shields.io/github/forks/motikan2010/CVE-2023-23924.svg)

## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.



- [https://github.com/WhiteOwl-Pub/CVE-2023-23752](https://github.com/WhiteOwl-Pub/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/WhiteOwl-Pub/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/WhiteOwl-Pub/CVE-2023-23752.svg)

- [https://github.com/Saboor-Hakimi/CVE-2023-23752](https://github.com/Saboor-Hakimi/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/Saboor-Hakimi/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/Saboor-Hakimi/CVE-2023-23752.svg)

- [https://github.com/YusinoMy/CVE-2023-23752](https://github.com/YusinoMy/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/YusinoMy/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/YusinoMy/CVE-2023-23752.svg)

- [https://github.com/wangking1/CVE-2023-23752-poc](https://github.com/wangking1/CVE-2023-23752-poc) :  ![starts](https://img.shields.io/github/stars/wangking1/CVE-2023-23752-poc.svg) ![forks](https://img.shields.io/github/forks/wangking1/CVE-2023-23752-poc.svg)

- [https://github.com/Vulnmachines/joomla_CVE-2023-23752](https://github.com/Vulnmachines/joomla_CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/joomla_CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/joomla_CVE-2023-23752.svg)

- [https://github.com/DanielRuf/CVE-2023-23752](https://github.com/DanielRuf/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/DanielRuf/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/DanielRuf/CVE-2023-23752.svg)

- [https://github.com/ibaiw/joomla_CVE-2023-23752](https://github.com/ibaiw/joomla_CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/ibaiw/joomla_CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/ibaiw/joomla_CVE-2023-23752.svg)

## CVE-2023-23488
 The Paid Memberships Pro WordPress Plugin, version &lt; 2.9.8, is affected by an unauthenticated SQL injection vulnerability in the 'code' parameter of the '/pmpro/v1/order' REST route.



- [https://github.com/r3nt0n/CVE-2023-23488-PoC](https://github.com/r3nt0n/CVE-2023-23488-PoC) :  ![starts](https://img.shields.io/github/stars/r3nt0n/CVE-2023-23488-PoC.svg) ![forks](https://img.shields.io/github/forks/r3nt0n/CVE-2023-23488-PoC.svg)

## CVE-2023-23333
 There is a command injection vulnerability in SolarView Compact through 6.00, attackers can execute commands by bypassing internal restrictions through downloader.php.



- [https://github.com/Timorlover/CVE-2023-23333](https://github.com/Timorlover/CVE-2023-23333) :  ![starts](https://img.shields.io/github/stars/Timorlover/CVE-2023-23333.svg) ![forks](https://img.shields.io/github/forks/Timorlover/CVE-2023-23333.svg)

## CVE-2023-23132
 Selfwealth iOS mobile App 3.3.1 is vulnerable to Sensitive key disclosure. The application reveals hardcoded API keys.



- [https://github.com/l00neyhacker/CVE-2023-23132](https://github.com/l00neyhacker/CVE-2023-23132) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2023-23132.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2023-23132.svg)

## CVE-2023-23131
 Selfwealth iOS mobile App 3.3.1 is vulnerable to Insecure App Transport Security (ATS) Settings.



- [https://github.com/l00neyhacker/CVE-2023-23131](https://github.com/l00neyhacker/CVE-2023-23131) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2023-23131.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2023-23131.svg)

## CVE-2023-23130
 ** DISPUTED ** Connectwise Automate 2022.11 is vulnerable to Cleartext authentication. Authentication is being done via HTTP (cleartext) with SSL disabled. OTE: the vendor's position is that, by design, this is controlled by a configuration option in which a customer can choose to use HTTP (rather than HTTPS) during troubleshooting.



- [https://github.com/l00neyhacker/CVE-2023-23130](https://github.com/l00neyhacker/CVE-2023-23130) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2023-23130.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2023-23130.svg)

## CVE-2023-23128
 Connectwise Control 22.8.10013.8329 is vulnerable to Cross Origin Resource Sharing (CORS). The vendor's position is that two endpoints have Access-Control-Allow-Origin wildcarding to support product functionality, and that there is no risk from this behavior. The vulnerability report is thus not valid.



- [https://github.com/l00neyhacker/CVE-2023-23128](https://github.com/l00neyhacker/CVE-2023-23128) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2023-23128.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2023-23128.svg)

## CVE-2023-23127
 In Connectwise Control 22.8.10013.8329, the login page does not implement HSTS headers therefore not enforcing HTTPS. NOTE: the vendor's position is that, by design, this is controlled by a configuration option in which a customer can choose to use HTTP (rather than HTTPS) during troubleshooting.



- [https://github.com/l00neyhacker/CVE-2023-23127](https://github.com/l00neyhacker/CVE-2023-23127) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2023-23127.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2023-23127.svg)

## CVE-2023-23126
 ** DISPUTED ** Connectwise Automate 2022.11 is vulnerable to Clickjacking. The login screen can be iframed and used to manipulate users to perform unintended actions. NOTE: the vendor's position is that a Content-Security-Policy HTTP response header is present to block this attack.



- [https://github.com/l00neyhacker/CVE-2023-23126](https://github.com/l00neyhacker/CVE-2023-23126) :  ![starts](https://img.shields.io/github/stars/l00neyhacker/CVE-2023-23126.svg) ![forks](https://img.shields.io/github/forks/l00neyhacker/CVE-2023-23126.svg)

## CVE-2023-22960
 Lexmark products through 2023-01-10 have Improper Control of Interaction Frequency.



- [https://github.com/t3l3machus/CVE-2023-22960](https://github.com/t3l3machus/CVE-2023-22960) :  ![starts](https://img.shields.io/github/stars/t3l3machus/CVE-2023-22960.svg) ![forks](https://img.shields.io/github/forks/t3l3machus/CVE-2023-22960.svg)

- [https://github.com/manas3c/CVE-2023-22960](https://github.com/manas3c/CVE-2023-22960) :  ![starts](https://img.shields.io/github/stars/manas3c/CVE-2023-22960.svg) ![forks](https://img.shields.io/github/forks/manas3c/CVE-2023-22960.svg)

## CVE-2023-22941
 In Splunk Enterprise versions below 8.1.13, 8.2.10, and 9.0.4, an improperly-formatted &#8216;INGEST_EVAL&#8217; parameter in a [Field Transformation](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Managefieldtransforms) crashes the Splunk daemon (splunkd).



- [https://github.com/eduardosantos1989/CVE-2023-22941](https://github.com/eduardosantos1989/CVE-2023-22941) :  ![starts](https://img.shields.io/github/stars/eduardosantos1989/CVE-2023-22941.svg) ![forks](https://img.shields.io/github/forks/eduardosantos1989/CVE-2023-22941.svg)

## CVE-2023-22855
 Kardex Mlog MCC 5.7.12+0-a203c2a213-master allows remote code execution. It spawns a web interface listening on port 8088. A user-controllable path is handed to a path-concatenation method (Path.Combine from .NET) without proper sanitisation. This yields the possibility of including local files, as well as remote files on SMB shares. If one provides a file with the extension .t4, it is rendered with the .NET templating engine mono/t4, which can execute code.



- [https://github.com/patrickhener/CVE-2023-22855](https://github.com/patrickhener/CVE-2023-22855) :  ![starts](https://img.shields.io/github/stars/patrickhener/CVE-2023-22855.svg) ![forks](https://img.shields.io/github/forks/patrickhener/CVE-2023-22855.svg)

## CVE-2023-22809
 In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a &quot;--&quot; argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.



- [https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc](https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc) :  ![starts](https://img.shields.io/github/stars/n3m1dotsys/CVE-2023-22809-sudoedit-privesc.svg) ![forks](https://img.shields.io/github/forks/n3m1dotsys/CVE-2023-22809-sudoedit-privesc.svg)

- [https://github.com/M4fiaB0y/CVE-2023-22809](https://github.com/M4fiaB0y/CVE-2023-22809) :  ![starts](https://img.shields.io/github/stars/M4fiaB0y/CVE-2023-22809.svg) ![forks](https://img.shields.io/github/forks/M4fiaB0y/CVE-2023-22809.svg)

## CVE-2023-21839
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).



- [https://github.com/DXask88MA/Weblogic-CVE-2023-21839](https://github.com/DXask88MA/Weblogic-CVE-2023-21839) :  ![starts](https://img.shields.io/github/stars/DXask88MA/Weblogic-CVE-2023-21839.svg) ![forks](https://img.shields.io/github/forks/DXask88MA/Weblogic-CVE-2023-21839.svg)

- [https://github.com/dream0x01/weblogic-framework](https://github.com/dream0x01/weblogic-framework) :  ![starts](https://img.shields.io/github/stars/dream0x01/weblogic-framework.svg) ![forks](https://img.shields.io/github/forks/dream0x01/weblogic-framework.svg)

- [https://github.com/fakenews2025/CVE-2023-21839](https://github.com/fakenews2025/CVE-2023-21839) :  ![starts](https://img.shields.io/github/stars/fakenews2025/CVE-2023-21839.svg) ![forks](https://img.shields.io/github/forks/fakenews2025/CVE-2023-21839.svg)

## CVE-2023-21752
 Windows Backup Service Elevation of Privilege Vulnerability.



- [https://github.com/Wh04m1001/CVE-2023-21752](https://github.com/Wh04m1001/CVE-2023-21752) :  ![starts](https://img.shields.io/github/stars/Wh04m1001/CVE-2023-21752.svg) ![forks](https://img.shields.io/github/forks/Wh04m1001/CVE-2023-21752.svg)

## CVE-2023-21739
 Windows Bluetooth Driver Elevation of Privilege Vulnerability.



- [https://github.com/gmh5225/CVE-2023-21739](https://github.com/gmh5225/CVE-2023-21739) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2023-21739.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2023-21739.svg)

## CVE-2023-21608
 Adobe Acrobat Reader versions 22.003.20282 (and earlier), 22.003.20281 (and earlier) and 20.005.30418 (and earlier) are affected by a Use After Free vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/hacksysteam/CVE-2023-21608](https://github.com/hacksysteam/CVE-2023-21608) :  ![starts](https://img.shields.io/github/stars/hacksysteam/CVE-2023-21608.svg) ![forks](https://img.shields.io/github/forks/hacksysteam/CVE-2023-21608.svg)

- [https://github.com/kuckibf/Popular-CVEs](https://github.com/kuckibf/Popular-CVEs) :  ![starts](https://img.shields.io/github/stars/kuckibf/Popular-CVEs.svg) ![forks](https://img.shields.io/github/forks/kuckibf/Popular-CVEs.svg)

- [https://github.com/Malwareman007/CVE-2023-21608](https://github.com/Malwareman007/CVE-2023-21608) :  ![starts](https://img.shields.io/github/stars/Malwareman007/CVE-2023-21608.svg) ![forks](https://img.shields.io/github/forks/Malwareman007/CVE-2023-21608.svg)

- [https://github.com/PyterSmithDarkGhost/CVE-2023-21608-EXPLOIT](https://github.com/PyterSmithDarkGhost/CVE-2023-21608-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/PyterSmithDarkGhost/CVE-2023-21608-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/PyterSmithDarkGhost/CVE-2023-21608-EXPLOIT.svg)

## CVE-2023-0860
 Improper Restriction of Excessive Authentication Attempts in GitHub repository modoboa/modoboa-installer prior to 2.0.4.



- [https://github.com/0xsu3ks/CVE-2023-0860](https://github.com/0xsu3ks/CVE-2023-0860) :  ![starts](https://img.shields.io/github/stars/0xsu3ks/CVE-2023-0860.svg) ![forks](https://img.shields.io/github/forks/0xsu3ks/CVE-2023-0860.svg)

## CVE-2023-0748
 Open Redirect in GitHub repository btcpayserver/btcpayserver prior to 1.7.6.



- [https://github.com/gonzxph/CVE-2023-0748](https://github.com/gonzxph/CVE-2023-0748) :  ![starts](https://img.shields.io/github/stars/gonzxph/CVE-2023-0748.svg) ![forks](https://img.shields.io/github/forks/gonzxph/CVE-2023-0748.svg)

## CVE-2023-0669
 Fortra (formerly, HelpSystems) GoAnywhere MFT suffers from a pre-authentication command injection vulnerability in the License Response Servlet due to deserializing an arbitrary attacker-controlled object. This issue was patched in version 7.1.2.



- [https://github.com/0xf4n9x/CVE-2023-0669](https://github.com/0xf4n9x/CVE-2023-0669) :  ![starts](https://img.shields.io/github/stars/0xf4n9x/CVE-2023-0669.svg) ![forks](https://img.shields.io/github/forks/0xf4n9x/CVE-2023-0669.svg)

- [https://github.com/trhacknon/CVE-2023-0669](https://github.com/trhacknon/CVE-2023-0669) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2023-0669.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2023-0669.svg)

- [https://github.com/yosef0x01/CVE-2023-0669](https://github.com/yosef0x01/CVE-2023-0669) :  ![starts](https://img.shields.io/github/stars/yosef0x01/CVE-2023-0669.svg) ![forks](https://img.shields.io/github/forks/yosef0x01/CVE-2023-0669.svg)

- [https://github.com/cataiovita/CVE-2023-0669](https://github.com/cataiovita/CVE-2023-0669) :  ![starts](https://img.shields.io/github/stars/cataiovita/CVE-2023-0669.svg) ![forks](https://img.shields.io/github/forks/cataiovita/CVE-2023-0669.svg)

- [https://github.com/Griffin-01/CVE-2023-0669](https://github.com/Griffin-01/CVE-2023-0669) :  ![starts](https://img.shields.io/github/stars/Griffin-01/CVE-2023-0669.svg) ![forks](https://img.shields.io/github/forks/Griffin-01/CVE-2023-0669.svg)

## CVE-2023-0315
 Command Injection in GitHub repository froxlor/froxlor prior to 2.0.8.



- [https://github.com/mhaskar/CVE-2023-0315](https://github.com/mhaskar/CVE-2023-0315) :  ![starts](https://img.shields.io/github/stars/mhaskar/CVE-2023-0315.svg) ![forks](https://img.shields.io/github/forks/mhaskar/CVE-2023-0315.svg)

## CVE-2023-0297
 Code Injection in GitHub repository pyload/pyload prior to 0.5.0b3.dev31.



- [https://github.com/b11y/CVE-2023-0297](https://github.com/b11y/CVE-2023-0297) :  ![starts](https://img.shields.io/github/stars/b11y/CVE-2023-0297.svg) ![forks](https://img.shields.io/github/forks/b11y/CVE-2023-0297.svg)

- [https://github.com/Small-ears/CVE-2023-0297](https://github.com/Small-ears/CVE-2023-0297) :  ![starts](https://img.shields.io/github/stars/Small-ears/CVE-2023-0297.svg) ![forks](https://img.shields.io/github/forks/Small-ears/CVE-2023-0297.svg)

## CVE-2023-0179
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/TurtleARM/CVE-2023-0179-PoC](https://github.com/TurtleARM/CVE-2023-0179-PoC) :  ![starts](https://img.shields.io/github/stars/TurtleARM/CVE-2023-0179-PoC.svg) ![forks](https://img.shields.io/github/forks/TurtleARM/CVE-2023-0179-PoC.svg)

## CVE-2023-0110
 Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.



- [https://github.com/emotest1/cve_2023_0110](https://github.com/emotest1/cve_2023_0110) :  ![starts](https://img.shields.io/github/stars/emotest1/cve_2023_0110.svg) ![forks](https://img.shields.io/github/forks/emotest1/cve_2023_0110.svg)

## CVE-2023-0045
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.



- [https://github.com/es0j/CVE-2023-0045](https://github.com/es0j/CVE-2023-0045) :  ![starts](https://img.shields.io/github/stars/es0j/CVE-2023-0045.svg) ![forks](https://img.shields.io/github/forks/es0j/CVE-2023-0045.svg)

- [https://github.com/missyes/CVE-2023-0045](https://github.com/missyes/CVE-2023-0045) :  ![starts](https://img.shields.io/github/stars/missyes/CVE-2023-0045.svg) ![forks](https://img.shields.io/github/forks/missyes/CVE-2023-0045.svg)

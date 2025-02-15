# Update 2025-02-15
## CVE-2025-24016
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations, even by a compromised agent. Version 4.9.1 contains a fix.

- [https://github.com/huseyinstif/CVE-2025-24016-Nuclei-Template](https://github.com/huseyinstif/CVE-2025-24016-Nuclei-Template) :  ![starts](https://img.shields.io/github/stars/huseyinstif/CVE-2025-24016-Nuclei-Template.svg) ![forks](https://img.shields.io/github/forks/huseyinstif/CVE-2025-24016-Nuclei-Template.svg)


## CVE-2025-0108
This issue does not affect Cloud NGFW or Prisma Access software.

- [https://github.com/iSee857/CVE-2025-0108-PoC](https://github.com/iSee857/CVE-2025-0108-PoC) :  ![starts](https://img.shields.io/github/stars/iSee857/CVE-2025-0108-PoC.svg) ![forks](https://img.shields.io/github/forks/iSee857/CVE-2025-0108-PoC.svg)


## CVE-2024-54160
 dashboards-reporting (aka Dashboards Reports) before 2.19.0.0, as shipped in OpenSearch before 2.19, allows XSS because Markdown is not sanitized when previewing a header or footer.

- [https://github.com/Jflye/CVE-2024-54160-Opensearch-HTML-And-Injection-Stored-XSS](https://github.com/Jflye/CVE-2024-54160-Opensearch-HTML-And-Injection-Stored-XSS) :  ![starts](https://img.shields.io/github/stars/Jflye/CVE-2024-54160-Opensearch-HTML-And-Injection-Stored-XSS.svg) ![forks](https://img.shields.io/github/forks/Jflye/CVE-2024-54160-Opensearch-HTML-And-Injection-Stored-XSS.svg)


## CVE-2024-53677
You can find more details in  https://cwiki.apache.org/confluence/display/WW/S2-067

- [https://github.com/hopsypopsy8/CVE-2024-53677-Exploitation](https://github.com/hopsypopsy8/CVE-2024-53677-Exploitation) :  ![starts](https://img.shields.io/github/stars/hopsypopsy8/CVE-2024-53677-Exploitation.svg) ![forks](https://img.shields.io/github/forks/hopsypopsy8/CVE-2024-53677-Exploitation.svg)


## CVE-2024-42010
 mod_css_styles in Roundcube through 1.5.7 and 1.6.x through 1.6.7 insufficiently filters Cascading Style Sheets (CSS) token sequences in rendered e-mail messages, allowing a remote attacker to obtain sensitive information.

- [https://github.com/victoni/Roundcube-CVE-2024-42008-and-CVE-2024-42010-POC](https://github.com/victoni/Roundcube-CVE-2024-42008-and-CVE-2024-42010-POC) :  ![starts](https://img.shields.io/github/stars/victoni/Roundcube-CVE-2024-42008-and-CVE-2024-42010-POC.svg) ![forks](https://img.shields.io/github/forks/victoni/Roundcube-CVE-2024-42008-and-CVE-2024-42010-POC.svg)


## CVE-2024-42009
 A Cross-Site Scripting vulnerability in Roundcube through 1.5.7 and 1.6.x through 1.6.7 allows a remote attacker to steal and send emails of a victim via a crafted e-mail message that abuses a Desanitization issue in message_body() in program/actions/mail/show.php.

- [https://github.com/Bhanunamikaze/CVE-2024-42009](https://github.com/Bhanunamikaze/CVE-2024-42009) :  ![starts](https://img.shields.io/github/stars/Bhanunamikaze/CVE-2024-42009.svg) ![forks](https://img.shields.io/github/forks/Bhanunamikaze/CVE-2024-42009.svg)


## CVE-2024-42008
 A Cross-Site Scripting vulnerability in rcmail_action_mail_get-run() in Roundcube through 1.5.7 and 1.6.x through 1.6.7 allows a remote attacker to steal and send emails of a victim via a malicious e-mail attachment served with a dangerous Content-Type header.

- [https://github.com/victoni/Roundcube-CVE-2024-42008-and-CVE-2024-42010-POC](https://github.com/victoni/Roundcube-CVE-2024-42008-and-CVE-2024-42010-POC) :  ![starts](https://img.shields.io/github/stars/victoni/Roundcube-CVE-2024-42008-and-CVE-2024-42010-POC.svg) ![forks](https://img.shields.io/github/forks/victoni/Roundcube-CVE-2024-42008-and-CVE-2024-42010-POC.svg)


## CVE-2024-38143
 Windows WLAN AutoConfig Service Elevation of Privilege Vulnerability

- [https://github.com/redr0nin/CVE-2024-38143](https://github.com/redr0nin/CVE-2024-38143) :  ![starts](https://img.shields.io/github/stars/redr0nin/CVE-2024-38143.svg) ![forks](https://img.shields.io/github/forks/redr0nin/CVE-2024-38143.svg)


## CVE-2024-5777
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

- [https://github.com/KUK3N4N/CVE-2024-57778](https://github.com/KUK3N4N/CVE-2024-57778) :  ![starts](https://img.shields.io/github/stars/KUK3N4N/CVE-2024-57778.svg) ![forks](https://img.shields.io/github/forks/KUK3N4N/CVE-2024-57778.svg)


## CVE-2024-5772
 A vulnerability, which was classified as critical, has been found in Netentsec NS-ASG Application Security Gateway 6.3. This issue affects some unknown processing of the file /protocol/iscuser/deleteiscuser.php. The manipulation of the argument messagecontent leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-267455. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/pointedsec/CVE-2024-57725](https://github.com/pointedsec/CVE-2024-57725) :  ![starts](https://img.shields.io/github/stars/pointedsec/CVE-2024-57725.svg) ![forks](https://img.shields.io/github/forks/pointedsec/CVE-2024-57725.svg)


## CVE-2021-21551
 Dell dbutil_2_3.sys driver contains an insufficient access control vulnerability which may lead to escalation of privileges, denial of service, or information disclosure. Local authenticated user access is required.

- [https://github.com/luke0x90/CVE-2021-21551](https://github.com/luke0x90/CVE-2021-21551) :  ![starts](https://img.shields.io/github/stars/luke0x90/CVE-2021-21551.svg) ![forks](https://img.shields.io/github/forks/luke0x90/CVE-2021-21551.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/Yzhacker/CVE-2019-9053-CMS46635-python3](https://github.com/Yzhacker/CVE-2019-9053-CMS46635-python3) :  ![starts](https://img.shields.io/github/stars/Yzhacker/CVE-2019-9053-CMS46635-python3.svg) ![forks](https://img.shields.io/github/forks/Yzhacker/CVE-2019-9053-CMS46635-python3.svg)


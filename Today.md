# Update 2025-06-12
## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/BiiTts/Roundcube-CVE-2025-49113](https://github.com/BiiTts/Roundcube-CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/BiiTts/Roundcube-CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/BiiTts/Roundcube-CVE-2025-49113.svg)


## CVE-2025-32720
 Out-of-bounds read in Windows Storage Management Provider allows an authorized attacker to disclose information locally.

- [https://github.com/itssixtyn3in/CVE-2025-3272025](https://github.com/itssixtyn3in/CVE-2025-3272025) :  ![starts](https://img.shields.io/github/stars/itssixtyn3in/CVE-2025-3272025.svg) ![forks](https://img.shields.io/github/forks/itssixtyn3in/CVE-2025-3272025.svg)


## CVE-2025-24016
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations, even by a compromised agent. Version 4.9.1 contains a fix.

- [https://github.com/rxerium/CVE-2025-24016](https://github.com/rxerium/CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-24016.svg)
- [https://github.com/B1ack4sh/Blackash-CVE-2025-24016](https://github.com/B1ack4sh/Blackash-CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-24016.svg)


## CVE-2025-20286
Note: If the Primary Administration node is deployed in the cloud, then Cisco ISE is affected by this vulnerability. If the Primary Administration node is on-premises, then it is not affected.

- [https://github.com/noeneal/CVE-2025-20286](https://github.com/noeneal/CVE-2025-20286) :  ![starts](https://img.shields.io/github/stars/noeneal/CVE-2025-20286.svg) ![forks](https://img.shields.io/github/forks/noeneal/CVE-2025-20286.svg)


## CVE-2025-5419
 Out of bounds read and write in V8 in Google Chrome prior to 137.0.7151.68 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/alegrason/CVE-2025-5419](https://github.com/alegrason/CVE-2025-5419) :  ![starts](https://img.shields.io/github/stars/alegrason/CVE-2025-5419.svg) ![forks](https://img.shields.io/github/forks/alegrason/CVE-2025-5419.svg)


## CVE-2025-4601
 The "RH - Real Estate WordPress Theme" theme for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 4.4.0. This is due to the theme not properly restricting user roles that can be updated as part of the inspiry_update_profile() function. This makes it possible for authenticated attackers, with subscriber-level access and above, to set their role to that of an administrator. The vulnerability was partially patched in version 4.4.0, and fully patched in version 4.4.1.

- [https://github.com/Yucaerin/CVE-2025-4601](https://github.com/Yucaerin/CVE-2025-4601) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2025-4601.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2025-4601.svg)


## CVE-2024-57378
 Wazuh SIEM version 4.8.2 is affected by a broken access control vulnerability. This issue allows the unauthorized creation of internal users without assigning any existing user role, potentially leading to privilege escalation or unauthorized access to sensitive resources.

- [https://github.com/rxerium/CVE-2024-57378](https://github.com/rxerium/CVE-2024-57378) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2024-57378.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2024-57378.svg)


## CVE-2024-41505
 Jetimob Plataforma Imobiliaria 20240627-0 is vulnerable to Cross Site Scripting (XSS) in the "Pessoas" (persons) section via the field "Profisso" (professor).

- [https://github.com/rafaelbaldasso/CVE-2024-41505](https://github.com/rafaelbaldasso/CVE-2024-41505) :  ![starts](https://img.shields.io/github/stars/rafaelbaldasso/CVE-2024-41505.svg) ![forks](https://img.shields.io/github/forks/rafaelbaldasso/CVE-2024-41505.svg)


## CVE-2024-41504
 Jetimob Plataforma Imobiliaria 20240627-0 is vulnerable to Cross Site Scripting (XSS). In the "Oportunidades" (opportunities) section of the application when creating or editing an "Atividade" (activity), the form field "Descrico" allows injection of JavaScript.

- [https://github.com/rafaelbaldasso/CVE-2024-41504](https://github.com/rafaelbaldasso/CVE-2024-41504) :  ![starts](https://img.shields.io/github/stars/rafaelbaldasso/CVE-2024-41504.svg) ![forks](https://img.shields.io/github/forks/rafaelbaldasso/CVE-2024-41504.svg)


## CVE-2024-41503
 Jetimob Plataforma Imobiliaria 20240627-0 is vulnerable to Cross Site Scripting (XSS) in the field "Ttulo" (title) inside the filter Save option in the "Busca" (search) function.

- [https://github.com/rafaelbaldasso/CVE-2024-41503](https://github.com/rafaelbaldasso/CVE-2024-41503) :  ![starts](https://img.shields.io/github/stars/rafaelbaldasso/CVE-2024-41503.svg) ![forks](https://img.shields.io/github/forks/rafaelbaldasso/CVE-2024-41503.svg)


## CVE-2024-41502
 Jetimob Plataforma Imobiliaria 20240627-0 is vulnerable to Cross Site Scripting (XSS) via the form field "Observaces" (observances) in the "Pessoas" (persons) section when creating or editing either a legal or a natural person.

- [https://github.com/rafaelbaldasso/CVE-2024-41502](https://github.com/rafaelbaldasso/CVE-2024-41502) :  ![starts](https://img.shields.io/github/stars/rafaelbaldasso/CVE-2024-41502.svg) ![forks](https://img.shields.io/github/forks/rafaelbaldasso/CVE-2024-41502.svg)


## CVE-2024-22371
Users are recommended to upgrade to version 3.21.4, 3.22.1, 4.0.4 or 4.4.0, which fixes the issue.

- [https://github.com/vishalborkar7/POC_for_-CVE-2024-22371](https://github.com/vishalborkar7/POC_for_-CVE-2024-22371) :  ![starts](https://img.shields.io/github/stars/vishalborkar7/POC_for_-CVE-2024-22371.svg) ![forks](https://img.shields.io/github/forks/vishalborkar7/POC_for_-CVE-2024-22371.svg)


## CVE-2023-39910
 The cryptocurrency wallet entropy seeding mechanism used in Libbitcoin Explorer 3.0.0 through 3.6.0 is weak, aka the Milk Sad issue. The use of an mt19937 Mersenne Twister PRNG restricts the internal entropy to 32 bits regardless of settings. This allows remote attackers to recover any wallet private keys generated from "bx seed" entropy output and steal funds. (Affected users need to move funds to a secure new cryptocurrency wallet.) NOTE: the vendor's position is that there was sufficient documentation advising against "bx seed" but others disagree. NOTE: this was exploited in the wild in June and July 2023.

- [https://github.com/z1ph1us/MilkSad-Mnemonic-Generator](https://github.com/z1ph1us/MilkSad-Mnemonic-Generator) :  ![starts](https://img.shields.io/github/stars/z1ph1us/MilkSad-Mnemonic-Generator.svg) ![forks](https://img.shields.io/github/forks/z1ph1us/MilkSad-Mnemonic-Generator.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is "${prefix:name}", where "prefix" is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - "script" - execute expressions using the JVM script execution engine (javax.script) - "dns" - resolve dns records - "url" - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/Syndicate27/text4shell-exploit](https://github.com/Syndicate27/text4shell-exploit) :  ![starts](https://img.shields.io/github/stars/Syndicate27/text4shell-exploit.svg) ![forks](https://img.shields.io/github/forks/Syndicate27/text4shell-exploit.svg)


## CVE-2019-7304
 Canonical snapd before version 2.37.1 incorrectly performed socket owner validation, allowing an attacker to run arbitrary commands as root. This issue affects: Canonical snapd versions prior to 2.37.1.

- [https://github.com/coby-nguyen/Document-Linux-Privilege-Escalation](https://github.com/coby-nguyen/Document-Linux-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/coby-nguyen/Document-Linux-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/coby-nguyen/Document-Linux-Privilege-Escalation.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a "?php " substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/K3ysTr0K3R/CVE-2017-9841-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-9841-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-9841-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-9841-EXPLOIT.svg)


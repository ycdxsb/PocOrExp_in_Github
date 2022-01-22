# Update 2022-01-22
## CVE-2022-0219
 Improper Restriction of XML External Entity Reference in GitHub repository skylot/jadx prior to 1.3.2.

- [https://github.com/Haxatron/CVE-2022-0219](https://github.com/Haxatron/CVE-2022-0219) :  ![starts](https://img.shields.io/github/stars/Haxatron/CVE-2022-0219.svg) ![forks](https://img.shields.io/github/forks/Haxatron/CVE-2022-0219.svg)


## CVE-2021-44228
 Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

- [https://github.com/Y0-kan/Log4jShell-Scan](https://github.com/Y0-kan/Log4jShell-Scan) :  ![starts](https://img.shields.io/github/stars/Y0-kan/Log4jShell-Scan.svg) ![forks](https://img.shields.io/github/forks/Y0-kan/Log4jShell-Scan.svg)


## CVE-2021-32790
 Woocommerce is an open source eCommerce plugin for WordPress. An SQL injection vulnerability impacts all WooCommerce sites running the WooCommerce plugin between version 3.3.0 and 3.3.6. Malicious actors (already) having admin access, or API keys to the WooCommerce site can exploit vulnerable endpoints of `/wp-json/wc/v3/webhooks`, `/wp-json/wc/v2/webhooks` and other webhook listing API. Read-only SQL queries can be executed using this exploit, while data will not be returned, by carefully crafting `search` parameter information can be disclosed using timing and related attacks. Version 3.3.6 is the earliest version of Woocommerce with a patch for this vulnerability. There are no known workarounds other than upgrading.

- [https://github.com/LazyTitan33/CVE-2021-32790-PoC](https://github.com/LazyTitan33/CVE-2021-32790-PoC) :  ![starts](https://img.shields.io/github/stars/LazyTitan33/CVE-2021-32790-PoC.svg) ![forks](https://img.shields.io/github/forks/LazyTitan33/CVE-2021-32790-PoC.svg)


## CVE-2021-32648
 octobercms in a CMS platform based on the Laravel PHP Framework. In affected versions of the october/system package an attacker can request an account password reset and then gain access to the account using a specially crafted request. The issue has been patched in Build 472 and v1.1.5.

- [https://github.com/daftspunk/CVE-2021-32648](https://github.com/daftspunk/CVE-2021-32648) :  ![starts](https://img.shields.io/github/stars/daftspunk/CVE-2021-32648.svg) ![forks](https://img.shields.io/github/forks/daftspunk/CVE-2021-32648.svg)


## CVE-2021-32099
 A SQL injection vulnerability in the pandora_console component of Artica Pandora FMS 742 allows an unauthenticated attacker to upgrade his unprivileged session via the /include/chart_generator.php session_id parameter, leading to a login bypass.

- [https://github.com/l3eol3eo/CVE-2021-32099_SQLi](https://github.com/l3eol3eo/CVE-2021-32099_SQLi) :  ![starts](https://img.shields.io/github/stars/l3eol3eo/CVE-2021-32099_SQLi.svg) ![forks](https://img.shields.io/github/forks/l3eol3eo/CVE-2021-32099_SQLi.svg)


## CVE-2018-16809
 An issue was discovered in Dolibarr through 7.0.0. expensereport/card.php in the expense reports module allows SQL injection via the integer parameters qty and value_unit.

- [https://github.com/elkassimyhajar/CVE-2018-16809](https://github.com/elkassimyhajar/CVE-2018-16809) :  ![starts](https://img.shields.io/github/stars/elkassimyhajar/CVE-2018-16809.svg) ![forks](https://img.shields.io/github/forks/elkassimyhajar/CVE-2018-16809.svg)


## CVE-2018-1311
 The Apache Xerces-C 3.0.0 to 3.2.3 XML parser contains a use-after-free error triggered during the scanning of external DTDs. This flaw has not been addressed in the maintained version of the library and has no current mitigation other than to disable DTD processing. This can be accomplished via the DOM using a standard parser feature, or via SAX using the XERCES_DISABLE_DTD environment variable.

- [https://github.com/johnjamesmccann/xerces-3.2.3-DTD-hotfix](https://github.com/johnjamesmccann/xerces-3.2.3-DTD-hotfix) :  ![starts](https://img.shields.io/github/stars/johnjamesmccann/xerces-3.2.3-DTD-hotfix.svg) ![forks](https://img.shields.io/github/forks/johnjamesmccann/xerces-3.2.3-DTD-hotfix.svg)


# Update 2022-05-25
## CVE-2022-30778
 Laravel 9.1.8, when processing attacker-controlled data for deserialization, allows Remote Code Execution via an unserialize pop chain in __destruct in Illuminate\Broadcasting\PendingBroadcast.php and dispatch($command) in Illuminate\Bus\QueueingDispatcher.php.

- [https://github.com/kang8/CVE-2022-30778](https://github.com/kang8/CVE-2022-30778) :  ![starts](https://img.shields.io/github/stars/kang8/CVE-2022-30778.svg) ![forks](https://img.shields.io/github/forks/kang8/CVE-2022-30778.svg)


## CVE-2022-30525
 A OS command injection vulnerability in the CGI program of Zyxel USG FLEX 100(W) firmware versions 5.00 through 5.21 Patch 1, USG FLEX 200 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 500 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 700 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 50(W) firmware versions 5.10 through 5.21 Patch 1, USG20(W)-VPN firmware versions 5.10 through 5.21 Patch 1, ATP series firmware versions 5.10 through 5.21 Patch 1, VPN series firmware versions 4.60 through 5.21 Patch 1, which could allow an attacker to modify specific files and then execute some OS commands on a vulnerable device.

- [https://github.com/iveresk/cve-2022-30525](https://github.com/iveresk/cve-2022-30525) :  ![starts](https://img.shields.io/github/stars/iveresk/cve-2022-30525.svg) ![forks](https://img.shields.io/github/forks/iveresk/cve-2022-30525.svg)


## CVE-2022-24087
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/TomArni680/CVE-2022-24086-RCE](https://github.com/TomArni680/CVE-2022-24086-RCE) :  ![starts](https://img.shields.io/github/stars/TomArni680/CVE-2022-24086-RCE.svg) ![forks](https://img.shields.io/github/forks/TomArni680/CVE-2022-24086-RCE.svg)


## CVE-2022-24086
 Adobe Commerce versions 2.4.3-p1 (and earlier) and 2.3.7-p2 (and earlier) are affected by an improper input validation vulnerability during the checkout process. Exploitation of this issue does not require user interaction and could result in arbitrary code execution.

- [https://github.com/TomArni680/CVE-2022-24086-RCE](https://github.com/TomArni680/CVE-2022-24086-RCE) :  ![starts](https://img.shields.io/github/stars/TomArni680/CVE-2022-24086-RCE.svg) ![forks](https://img.shields.io/github/forks/TomArni680/CVE-2022-24086-RCE.svg)


## CVE-2022-23046
 PhpIPAM v1.4.4 allows an authenticated admin user to inject SQL sentences in the &quot;subnet&quot; parameter while searching a subnet via app/admin/routing/edit-bgp-mapping-search.php

- [https://github.com/bernauers/CVE-2022-23046](https://github.com/bernauers/CVE-2022-23046) :  ![starts](https://img.shields.io/github/stars/bernauers/CVE-2022-23046.svg) ![forks](https://img.shields.io/github/forks/bernauers/CVE-2022-23046.svg)


## CVE-2021-33044
 The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.

- [https://github.com/jorhelp/Ingram](https://github.com/jorhelp/Ingram) :  ![starts](https://img.shields.io/github/stars/jorhelp/Ingram.svg) ![forks](https://img.shields.io/github/forks/jorhelp/Ingram.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/GatoGamer1155/CVE-2021-4034](https://github.com/GatoGamer1155/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/GatoGamer1155/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/GatoGamer1155/CVE-2021-4034.svg)


## CVE-2020-11023
 In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing &lt;option&gt; elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.

- [https://github.com/korestreet/https-nj.gov---CVE-2020-11023](https://github.com/korestreet/https-nj.gov---CVE-2020-11023) :  ![starts](https://img.shields.io/github/stars/korestreet/https-nj.gov---CVE-2020-11023.svg) ![forks](https://img.shields.io/github/forks/korestreet/https-nj.gov---CVE-2020-11023.svg)


## CVE-2020-11022
 In jQuery versions greater than or equal to 1.2 and before 3.5.0, passing HTML from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.

- [https://github.com/korestreet/https-nj.gov---CVE-2020-11022](https://github.com/korestreet/https-nj.gov---CVE-2020-11022) :  ![starts](https://img.shields.io/github/stars/korestreet/https-nj.gov---CVE-2020-11022.svg) ![forks](https://img.shields.io/github/forks/korestreet/https-nj.gov---CVE-2020-11022.svg)


## CVE-2019-11358
 jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution. If an unsanitized source object contained an enumerable __proto__ property, it could extend the native Object.prototype.

- [https://github.com/Snorlyd/https-nj.gov---CVE-2019-11358](https://github.com/Snorlyd/https-nj.gov---CVE-2019-11358) :  ![starts](https://img.shields.io/github/stars/Snorlyd/https-nj.gov---CVE-2019-11358.svg) ![forks](https://img.shields.io/github/forks/Snorlyd/https-nj.gov---CVE-2019-11358.svg)


## CVE-2019-8331
 In Bootstrap before 3.4.1 and 4.3.x before 4.3.1, XSS is possible in the tooltip or popover data-template attribute.

- [https://github.com/Snorlyd/https-nj.gov---CVE-2019-8331](https://github.com/Snorlyd/https-nj.gov---CVE-2019-8331) :  ![starts](https://img.shields.io/github/stars/Snorlyd/https-nj.gov---CVE-2019-8331.svg) ![forks](https://img.shields.io/github/forks/Snorlyd/https-nj.gov---CVE-2019-8331.svg)


## CVE-2018-14042
 In Bootstrap before 4.1.2, XSS is possible in the data-container property of tooltip.

- [https://github.com/Snorlyd/https-nj.gov---CVE-2018-14042](https://github.com/Snorlyd/https-nj.gov---CVE-2018-14042) :  ![starts](https://img.shields.io/github/stars/Snorlyd/https-nj.gov---CVE-2018-14042.svg) ![forks](https://img.shields.io/github/forks/Snorlyd/https-nj.gov---CVE-2018-14042.svg)


## CVE-2018-14041
 In Bootstrap before 4.1.2, XSS is possible in the data-target property of scrollspy.

- [https://github.com/Snorlyd/https-nj.gov---CVE-2018-14041](https://github.com/Snorlyd/https-nj.gov---CVE-2018-14041) :  ![starts](https://img.shields.io/github/stars/Snorlyd/https-nj.gov---CVE-2018-14041.svg) ![forks](https://img.shields.io/github/forks/Snorlyd/https-nj.gov---CVE-2018-14041.svg)


## CVE-2018-14040
 In Bootstrap before 4.1.2, XSS is possible in the collapse data-parent attribute.

- [https://github.com/Snorlyd/https-nj.gov---CVE-2018-14040](https://github.com/Snorlyd/https-nj.gov---CVE-2018-14040) :  ![starts](https://img.shields.io/github/stars/Snorlyd/https-nj.gov---CVE-2018-14040.svg) ![forks](https://img.shields.io/github/forks/Snorlyd/https-nj.gov---CVE-2018-14040.svg)


## CVE-2018-11776
 Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then: results are used with no namespace and in same time, its upper package have no or wildcard namespace and similar to results, same possibility when using url tag which doesn't have value and action set and in same time, its upper package have no or wildcard namespace.

- [https://github.com/jiguangsdf/CVE-2018-11776](https://github.com/jiguangsdf/CVE-2018-11776) :  ![starts](https://img.shields.io/github/stars/jiguangsdf/CVE-2018-11776.svg) ![forks](https://img.shields.io/github/forks/jiguangsdf/CVE-2018-11776.svg)


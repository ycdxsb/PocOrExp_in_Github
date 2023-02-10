# Update 2023-02-10
## CVE-2023-25168
 Wings is Pterodactyl's server control plane. This vulnerability can be used to delete files and directories recursively on the host system. This vulnerability can be combined with `GHSA-p8r3-83r8-jwj5` to overwrite files on the host system. In order to use this exploit, an attacker must have an existing &quot;server&quot; allocated and controlled by Wings. This vulnerability has been resolved in version `v1.11.4` of Wings, and has been back-ported to the 1.7 release series in `v1.7.4`. Anyone running `v1.11.x` should upgrade to `v1.11.4` and anyone running `v1.7.x` should upgrade to `v1.7.4`. There are no known workarounds for this issue.

- [https://github.com/Live-Hack-CVE/CVE-2023-25168](https://github.com/Live-Hack-CVE/CVE-2023-25168) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25168.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25168.svg)


## CVE-2023-25163
 Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. All versions of Argo CD starting with v2.6.0-rc1 have an output sanitization bug which leaks repository access credentials in error messages. These error messages are visible to the user, and they are logged. The error message is visible when a user attempts to create or update an Application via the Argo CD API (and therefor the UI or CLI). The user must have `applications, create` or `applications, update` RBAC access to reach the code which may produce the error. The user is not guaranteed to be able to trigger the error message. They may attempt to spam the API with requests to trigger a rate limit error from the upstream repository. If the user has `repositories, update` access, they may edit an existing repository to introduce a URL typo or otherwise force an error message. But if they have that level of access, they are probably intended to have access to the credentials anyway. A patch for this vulnerability has been released in version 2.6.1. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-25163](https://github.com/Live-Hack-CVE/CVE-2023-25163) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25163.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25163.svg)


## CVE-2023-24997
 Deserialization of Untrusted Data vulnerability in Apache Software Foundation Apache InLong.This issue affects Apache InLong: from 1.1.0 through 1.5.0. Users are advised to upgrade to Apache InLong's latest version or cherry-pick https://github.com/apache/inlong/pull/7223 https://github.com/apache/inlong/pull/7223 to solve it.

- [https://github.com/Live-Hack-CVE/CVE-2023-24997](https://github.com/Live-Hack-CVE/CVE-2023-24997) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24997.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24997.svg)


## CVE-2023-24610
 NOSH 4a5cfdb allows remote authenticated users to execute PHP arbitrary code via the &quot;practice logo&quot; upload feature. The client-side checks can be bypassed. This may allow attackers to steal Protected Health Information because the product is for health charting.

- [https://github.com/Live-Hack-CVE/CVE-2023-24610](https://github.com/Live-Hack-CVE/CVE-2023-24610) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24610.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24610.svg)


## CVE-2023-24508
 Baicells Nova 227, Nova 233, and Nova 243 LTE TDD eNodeB and Nova 246 devices with firmware through RTS/RTD 3.6.6 are vulnerable to remote shell code exploitation via HTTP command injections. Commands are executed using pre-login execution and executed with root permissions. The following methods below have been tested and validated by a 3rd party analyst and has been confirmed exploitable special thanks to Rustam Amin for providing the steps to reproduce.

- [https://github.com/Live-Hack-CVE/CVE-2023-24508](https://github.com/Live-Hack-CVE/CVE-2023-24508) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24508.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24508.svg)


## CVE-2023-24055
 ** DISPUTED ** KeePass through 2.53 (in a default installation) allows an attacker, who has write access to the XML configuration file, to obtain the cleartext passwords by adding an export trigger. NOTE: the vendor's position is that the password database is not intended to be secure against an attacker who has that level of access to the local PC.

- [https://github.com/digital-dev/KeePass-TriggerLess](https://github.com/digital-dev/KeePass-TriggerLess) :  ![starts](https://img.shields.io/github/stars/digital-dev/KeePass-TriggerLess.svg) ![forks](https://img.shields.io/github/forks/digital-dev/KeePass-TriggerLess.svg)


## CVE-2023-23692
 Dell EMC prior to version DDOS 7.9 contain(s) an OS command injection Vulnerability. An authenticated non admin attacker could potentially exploit this vulnerability, leading to the execution of arbitrary OS commands on the application's underlying OS, with the privileges of the vulnerable application.

- [https://github.com/Live-Hack-CVE/CVE-2023-23692](https://github.com/Live-Hack-CVE/CVE-2023-23692) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23692.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23692.svg)


## CVE-2023-23136
 lmxcms v1.41 was discovered to contain an arbitrary file deletion vulnerability via BackdbAction.class.php.

- [https://github.com/Live-Hack-CVE/CVE-2023-23136](https://github.com/Live-Hack-CVE/CVE-2023-23136) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23136.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23136.svg)


## CVE-2023-23135
 An arbitrary file upload vulnerability in Ftdms v3.1.6 allows attackers to execute arbitrary code via uploading a crafted JPG file.

- [https://github.com/Live-Hack-CVE/CVE-2023-23135](https://github.com/Live-Hack-CVE/CVE-2023-23135) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23135.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23135.svg)


## CVE-2023-23132
 Selfwealth iOS mobile App 3.3.1 is vulnerable to Sensitive key disclosure. The application reveals hardcoded API keys.

- [https://github.com/Live-Hack-CVE/CVE-2023-23132](https://github.com/Live-Hack-CVE/CVE-2023-23132) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23132.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23132.svg)


## CVE-2023-23131
 Selfwealth iOS mobile App 3.3.1 is vulnerable to Insecure App Transport Security (ATS) Settings.

- [https://github.com/Live-Hack-CVE/CVE-2023-23131](https://github.com/Live-Hack-CVE/CVE-2023-23131) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23131.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23131.svg)


## CVE-2023-23073
 Cross site scripting (XSS) vulnerability in Zoho ManageEngine ServiceDesk Plus 14 via PO in the purchase component.

- [https://github.com/Live-Hack-CVE/CVE-2023-23073](https://github.com/Live-Hack-CVE/CVE-2023-23073) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23073.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23073.svg)


## CVE-2023-22575
 Dell PowerScale OneFS 9.0.0.x - 9.4.0.x contain an insertion of sensitive information into log file vulnerability in celog. A low privileges user could potentially exploit this vulnerability, leading to information disclosure and escalation of privileges.

- [https://github.com/Live-Hack-CVE/CVE-2023-22575](https://github.com/Live-Hack-CVE/CVE-2023-22575) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22575.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22575.svg)


## CVE-2023-22572
 Dell PowerScale OneFS 9.1.0.x-9.4.0.x contain an insertion of sensitive information into log file vulnerability in change password api. A low privilege local attacker could potentially exploit this vulnerability, leading to system takeover.

- [https://github.com/Live-Hack-CVE/CVE-2023-22572](https://github.com/Live-Hack-CVE/CVE-2023-22572) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22572.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22572.svg)


## CVE-2023-0748
 Open Redirect in GitHub repository btcpayserver/btcpayserver prior to 1.7.6.

- [https://github.com/Live-Hack-CVE/CVE-2023-0748](https://github.com/Live-Hack-CVE/CVE-2023-0748) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0748.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0748.svg)


## CVE-2023-0747
 Cross-site Scripting (XSS) - Stored in GitHub repository btcpayserver/btcpayserver prior to 1.7.6.

- [https://github.com/Live-Hack-CVE/CVE-2023-0747](https://github.com/Live-Hack-CVE/CVE-2023-0747) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0747.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0747.svg)


## CVE-2023-0744
 Improper Access Control in GitHub repository answerdev/answer prior to 1.0.4.

- [https://github.com/Live-Hack-CVE/CVE-2023-0744](https://github.com/Live-Hack-CVE/CVE-2023-0744) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0744.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0744.svg)


## CVE-2023-0743
 Cross-site Scripting (XSS) - Generic in GitHub repository answerdev/answer prior to 1.0.4.

- [https://github.com/Live-Hack-CVE/CVE-2023-0743](https://github.com/Live-Hack-CVE/CVE-2023-0743) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0743.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0743.svg)


## CVE-2023-0742
 Cross-site Scripting (XSS) - Stored in GitHub repository answerdev/answer prior to 1.0.4.

- [https://github.com/Live-Hack-CVE/CVE-2023-0742](https://github.com/Live-Hack-CVE/CVE-2023-0742) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0742.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0742.svg)


## CVE-2023-0741
 Cross-site Scripting (XSS) - DOM in GitHub repository answerdev/answer prior to 1.0.4.

- [https://github.com/Live-Hack-CVE/CVE-2023-0741](https://github.com/Live-Hack-CVE/CVE-2023-0741) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0741.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0741.svg)


## CVE-2023-0740
 Cross-site Scripting (XSS) - Stored in GitHub repository answerdev/answer prior to 1.0.4.

- [https://github.com/Live-Hack-CVE/CVE-2023-0740](https://github.com/Live-Hack-CVE/CVE-2023-0740) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0740.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0740.svg)


## CVE-2023-0739
 Race Condition in Switch in GitHub repository answerdev/answer prior to 1.0.4.

- [https://github.com/Live-Hack-CVE/CVE-2023-0739](https://github.com/Live-Hack-CVE/CVE-2023-0739) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0739.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0739.svg)


## CVE-2023-0726
 The Wicked Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.18.16. This is due to missing or incorrect nonce validation on the ajax_edit_folder function. This makes it possible for unauthenticated attackers to invoke this function via forged request granted they can trick a site administrator into performing an action such as clicking on a link leading them to perform actions intended for administrators such as changing the folder structure maintained by the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-0726](https://github.com/Live-Hack-CVE/CVE-2023-0726) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0726.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0726.svg)


## CVE-2023-0725
 The Wicked Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.18.16. This is due to missing or incorrect nonce validation on the ajax_clone_folder function. This makes it possible for unauthenticated attackers to invoke this function via forged request granted they can trick a site administrator into performing an action such as clicking on a link leading them to perform actions intended for administrators such as changing the folder structure maintained by the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-0725](https://github.com/Live-Hack-CVE/CVE-2023-0725) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0725.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0725.svg)


## CVE-2023-0724
 The Wicked Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.18.16. This is due to missing or incorrect nonce validation on the ajax_add_folder function. This makes it possible for unauthenticated attackers to invoke this function via forged request granted they can trick a site administrator into performing an action such as clicking on a link leading them to perform actions intended for administrators such as changing the folder structure maintained by the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-0724](https://github.com/Live-Hack-CVE/CVE-2023-0724) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0724.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0724.svg)


## CVE-2023-0722
 The Wicked Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.18.16. This is due to missing or incorrect nonce validation on the ajax_save_state function. This makes it possible for unauthenticated attackers to invoke this function via forged request granted they can trick a site administrator into performing an action such as clicking on a link leading them to perform actions intended for administrators such as changing the folder structure maintained by the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-0722](https://github.com/Live-Hack-CVE/CVE-2023-0722) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0722.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0722.svg)


## CVE-2023-0720
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_save_folder_order function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-0720](https://github.com/Live-Hack-CVE/CVE-2023-0720) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0720.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0720.svg)


## CVE-2023-0717
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_delete_folder function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-0717](https://github.com/Live-Hack-CVE/CVE-2023-0717) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0717.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0717.svg)


## CVE-2023-0716
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_edit_folder function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-0716](https://github.com/Live-Hack-CVE/CVE-2023-0716) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0716.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0716.svg)


## CVE-2023-0715
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_clone_folder function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the folder structure maintained by the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-0715](https://github.com/Live-Hack-CVE/CVE-2023-0715) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0715.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0715.svg)


## CVE-2023-0711
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_save_state function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as modifying the view state of the folder structure maintained by the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-0711](https://github.com/Live-Hack-CVE/CVE-2023-0711) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0711.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0711.svg)


## CVE-2023-0685
 The Wicked Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.18.16. This is due to missing or incorrect nonce validation on the ajax_unassign_folders function. This makes it possible for unauthenticated attackers to invoke this function via forged request granted they can trick a site administrator into performing an action such as clicking on a link leading them to perform actions intended for administrators such as changing the folder structure maintained by the plugin..

- [https://github.com/Live-Hack-CVE/CVE-2023-0685](https://github.com/Live-Hack-CVE/CVE-2023-0685) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0685.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0685.svg)


## CVE-2023-0684
 The Wicked Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the ajax_unassign_folders function in versions up to, and including, 2.18.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke this function and perform actions intended for administrators such as changing the folder structure maintained by the plugin.

- [https://github.com/Live-Hack-CVE/CVE-2023-0684](https://github.com/Live-Hack-CVE/CVE-2023-0684) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0684.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0684.svg)


## CVE-2023-0669
 Fortra (formerly, HelpSystems) GoAnywhere MFT suffers from a pre-authentication command injection vulnerability in the License Response Servlet due to deserializing an arbitrary attacker-controlled object. This issue was patched in version 7.1.2.

- [https://github.com/Live-Hack-CVE/CVE-2023-0669](https://github.com/Live-Hack-CVE/CVE-2023-0669) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0669.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0669.svg)


## CVE-2023-0618
 A vulnerability was found in TRENDnet TEW-652BRP 3.04B01. It has been declared as critical. This vulnerability affects unknown code of the file cfg_op.ccp of the component Web Service. The manipulation leads to memory corruption. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-219958 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0618](https://github.com/Live-Hack-CVE/CVE-2023-0618) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0618.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0618.svg)


## CVE-2023-0617
 A vulnerability was found in TRENDNet TEW-811DRU 1.0.10.0. It has been classified as critical. This affects an unknown part of the file /wireless/guestnetwork.asp of the component httpd. The manipulation leads to buffer overflow. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-219957 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0617](https://github.com/Live-Hack-CVE/CVE-2023-0617) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0617.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0617.svg)


## CVE-2023-0251
 Delta Electronics DIAScreen versions 1.2.1.23 and prior are vulnerable to a buffer overflow through improper restrictions of operations within memory, which could allow an attacker to remotely execute arbitrary code.

- [https://github.com/Live-Hack-CVE/CVE-2023-0251](https://github.com/Live-Hack-CVE/CVE-2023-0251) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0251.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0251.svg)


## CVE-2023-0250
 Delta Electronics DIAScreen versions 1.2.1.23 and prior are vulnerable to a stack-based buffer overflow, which could allow an attacker to remotely execute arbitrary code.

- [https://github.com/Live-Hack-CVE/CVE-2023-0250](https://github.com/Live-Hack-CVE/CVE-2023-0250) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0250.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0250.svg)


## CVE-2023-0249
 Delta Electronics DIAScreen versions 1.2.1.23 and prior are vulnerable to out-of-bounds write, which may allow an attacker to remotely execute arbitrary code.

- [https://github.com/Live-Hack-CVE/CVE-2023-0249](https://github.com/Live-Hack-CVE/CVE-2023-0249) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0249.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0249.svg)


## CVE-2023-0003
 A file disclosure vulnerability in the Palo Alto Networks Cortex XSOAR server software enables an authenticated user with access to the web interface to read local files from the server.

- [https://github.com/Live-Hack-CVE/CVE-2023-0003](https://github.com/Live-Hack-CVE/CVE-2023-0003) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0003.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0003.svg)


## CVE-2023-0002
 A problem with a protection mechanism in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local user to execute privileged cytool commands that disable or uninstall the agent.

- [https://github.com/Live-Hack-CVE/CVE-2023-0002](https://github.com/Live-Hack-CVE/CVE-2023-0002) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0002.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0002.svg)


## CVE-2023-0001
 An information exposure vulnerability in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local system administrator to disclose the admin password for the agent in cleartext, which bad actors can then use to execute privileged cytool commands that disable or uninstall the agent.

- [https://github.com/Live-Hack-CVE/CVE-2023-0001](https://github.com/Live-Hack-CVE/CVE-2023-0001) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0001.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0001.svg)


## CVE-2022-48094
 lmxcms v1.41 was discovered to contain an arbitrary file read vulnerability via TemplateAction.class.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-48094](https://github.com/Live-Hack-CVE/CVE-2022-48094) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48094.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48094.svg)


## CVE-2022-48093
 Seacms v12.7 was discovered to contain a remote code execution (RCE) vulnerability via the ip parameter at admin_ ip.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-48093](https://github.com/Live-Hack-CVE/CVE-2022-48093) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48093.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48093.svg)


## CVE-2022-47648
 Bosch Security Systems B420 firmware 02.02.0001 employs IP based authorization in its authentication mechanism, allowing attackers to access the device as long as they are on the same network as a legitimate user.

- [https://github.com/Live-Hack-CVE/CVE-2022-47648](https://github.com/Live-Hack-CVE/CVE-2022-47648) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47648.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47648.svg)


## CVE-2022-46842
 Cross-Site Request Forgery (CSRF) vulnerability in JS Help Desk plugin &lt;= 2.7.1 versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-46842](https://github.com/Live-Hack-CVE/CVE-2022-46842) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46842.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46842.svg)


## CVE-2022-46815
 Cross-Site Request Forgery (CSRF) vulnerability in Lauri Karisola / WP Trio Conditional Shipping for WooCommerce plugin &lt;= 2.3.1 versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-46815](https://github.com/Live-Hack-CVE/CVE-2022-46815) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-46815.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-46815.svg)


## CVE-2022-45982
 thinkphp 6.0.0~6.0.13 and 6.1.0~6.1.1 contains a deserialization vulnerability. This vulnerability allows attackers to execute arbitrary code via a crafted payload.

- [https://github.com/Live-Hack-CVE/CVE-2022-45982](https://github.com/Live-Hack-CVE/CVE-2022-45982) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45982.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45982.svg)


## CVE-2022-45807
 Cross-Site Request Forgery (CSRF) in WPVibes WP Mail Log plugin &lt;= 1.0.1 versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-45807](https://github.com/Live-Hack-CVE/CVE-2022-45807) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45807.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45807.svg)


## CVE-2022-45770
 Improper input validation in driver adgnetworkwfpdrv.sys in Adguard For Windows x86 up to version 7.11 allows attacker to gain local privileges escalation.

- [https://github.com/Live-Hack-CVE/CVE-2022-45770](https://github.com/Live-Hack-CVE/CVE-2022-45770) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45770.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45770.svg)


## CVE-2022-44585
 Cross-Site Request Forgery (CSRF) vulnerability in Magneticlab Srl Homepage Pop-up plugin &lt;= 1.2.5 versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-44585](https://github.com/Live-Hack-CVE/CVE-2022-44585) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-44585.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-44585.svg)


## CVE-2022-43765
 B&amp;R APROL versions &lt; R 4.2-07 doesn&#8217;t process correctly specially formatted data packages sent to port 55502/tcp, which may allow a network based attacker to cause an application Denial-of-Service.

- [https://github.com/Live-Hack-CVE/CVE-2022-43765](https://github.com/Live-Hack-CVE/CVE-2022-43765) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43765.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43765.svg)


## CVE-2022-43764
 Insufficient validation of input parameters when changing configuration on Tbase server in B&amp;R APROL versions &lt; R 4.2-07 could result in buffer overflow. This may lead to Denial-of-Service conditions or execution of arbitrary code.

- [https://github.com/Live-Hack-CVE/CVE-2022-43764](https://github.com/Live-Hack-CVE/CVE-2022-43764) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43764.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43764.svg)


## CVE-2022-43763
 Insufficient check of preconditions could lead to Denial of Service conditions when calling commands on the Tbase server of B&amp;R APROL versions &lt; R 4.2-07.

- [https://github.com/Live-Hack-CVE/CVE-2022-43763](https://github.com/Live-Hack-CVE/CVE-2022-43763) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43763.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43763.svg)


## CVE-2022-43762
 Lack of verification in B&amp;R APROL Tbase server versions &lt; R 4.2-07 may lead to memory leaks when receiving messages

- [https://github.com/Live-Hack-CVE/CVE-2022-43762](https://github.com/Live-Hack-CVE/CVE-2022-43762) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43762.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43762.svg)


## CVE-2022-43761
 Missing authentication when creating and managing the B&amp;R APROL database in versions &lt; R 4.2-07 allows reading and changing the system configuration.

- [https://github.com/Live-Hack-CVE/CVE-2022-43761](https://github.com/Live-Hack-CVE/CVE-2022-43761) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43761.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43761.svg)


## CVE-2022-41620
 Cross-Site Request Forgery (CSRF) vulnerability in SeoSamba for WordPress Webmasters plugin &lt;= 1.0.5 versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-41620](https://github.com/Live-Hack-CVE/CVE-2022-41620) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41620.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41620.svg)


## CVE-2022-40692
 Cross-Site Request Forgery (CSRF) vulnerability in WP Sunshine Sunshine Photo Cart plugin &lt;= 2.9.13 versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-40692](https://github.com/Live-Hack-CVE/CVE-2022-40692) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40692.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40692.svg)


## CVE-2022-40035
 File Upload Vulnerability found in Rawchen Blog-ssm v1.0 allowing attackers to execute arbitrary commands and gain escalated privileges via the /uploadFileList component.

- [https://github.com/Live-Hack-CVE/CVE-2022-40035](https://github.com/Live-Hack-CVE/CVE-2022-40035) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40035.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40035.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/doyensec/CVE-2022-39299_PoC_Generator](https://github.com/doyensec/CVE-2022-39299_PoC_Generator) :  ![starts](https://img.shields.io/github/stars/doyensec/CVE-2022-39299_PoC_Generator.svg) ![forks](https://img.shields.io/github/forks/doyensec/CVE-2022-39299_PoC_Generator.svg)


## CVE-2022-38900
 decode-uri-component 0.2.0 is vulnerable to Improper Input Validation resulting in DoS.

- [https://github.com/Live-Hack-CVE/CVE-2022-38778](https://github.com/Live-Hack-CVE/CVE-2022-38778) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38778.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38778.svg)


## CVE-2022-38778
 A flaw (CVE-2022-38900) was discovered in one of Kibana&#8217;s third party dependencies, that could allow an authenticated user to perform a request that crashes the Kibana server process.

- [https://github.com/Live-Hack-CVE/CVE-2022-38778](https://github.com/Live-Hack-CVE/CVE-2022-38778) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38778.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38778.svg)


## CVE-2022-38777
 An issue was discovered in the rollback feature of Elastic Endpoint Security for Windows, which could allow unprivileged users to elevate their privileges to those of the LocalSystem account.

- [https://github.com/Live-Hack-CVE/CVE-2022-38777](https://github.com/Live-Hack-CVE/CVE-2022-38777) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-38777.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-38777.svg)


## CVE-2022-36118
 An issue was discovered in Blue Prism Enterprise 6.0 through 7.01. In a misconfigured environment that exposes the Blue Prism Application server, it is possible for an authenticated user to reverse engineer the Blue Prism software and circumvent access controls for the SetProcessAttributes administrative function. Abusing this function will allow any Blue Prism user to publish, unpublish, or retire processes. Using this function, any logged-in user can change the status of a process, an action allowed only intended for users with the Edit Process permission.

- [https://github.com/Live-Hack-CVE/CVE-2022-36118](https://github.com/Live-Hack-CVE/CVE-2022-36118) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-36118.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-36118.svg)


## CVE-2022-34350
 IBM API Connect 10.0.0.0 through 10.0.5.0, 10.0.1.0 through 10.0.1.7, and 2018.4.1.0 through 2018.4.1.20 is vulnerable to External Service Interaction attack, caused by improper validation of user-supplied input. A remote attacker could exploit this vulnerability to induce the application to perform server-side DNS lookups or HTTP requests to arbitrary domain names. By submitting suitable payloads, an attacker can cause the application server to attack other systems that it can interact with. IBM X-Force ID: 230264.

- [https://github.com/Live-Hack-CVE/CVE-2022-34350](https://github.com/Live-Hack-CVE/CVE-2022-34350) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34350.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34350.svg)


## CVE-2022-26872
 AMI Megarac Password reset interception via API

- [https://github.com/Live-Hack-CVE/CVE-2022-26872](https://github.com/Live-Hack-CVE/CVE-2022-26872) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-26872.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-26872.svg)


## CVE-2022-21661
 WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.

- [https://github.com/daniel616/CVE-2022-21661-Demo](https://github.com/daniel616/CVE-2022-21661-Demo) :  ![starts](https://img.shields.io/github/stars/daniel616/CVE-2022-21661-Demo.svg) ![forks](https://img.shields.io/github/forks/daniel616/CVE-2022-21661-Demo.svg)


## CVE-2022-4869
 A vulnerability was found in Evolution Events Artaxerxes. It has been declared as problematic. This vulnerability affects unknown code of the file arta/common/middleware.py of the component POST Parameter Handler. The manipulation of the argument password leads to information disclosure. The attack can be initiated remotely. The name of the patch is 022111407d34815c16c6eada2de69ca34084dc0d. It is recommended to apply a patch to fix this issue. VDB-217438 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4869](https://github.com/Live-Hack-CVE/CVE-2022-4869) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4869.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4869.svg)


## CVE-2022-4743
 A potential memory leak issue was discovered in SDL2 in GLES_CreateTexture() function in SDL_render_gles.c. The vulnerability allows an attacker to cause a denial of service attack. The vulnerability affects SDL2 v2.0.4 and above. SDL-1.x are not affected.

- [https://github.com/Live-Hack-CVE/CVE-2022-4743](https://github.com/Live-Hack-CVE/CVE-2022-4743) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4743.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4743.svg)


## CVE-2022-4304
 A timing based side channel exists in the OpenSSL RSA Decryption implementation which could be sufficient to recover a plaintext across a network in a Bleichenbacher style attack. To achieve a successful decryption an attacker would have to be able to send a very large number of trial messages for decryption. The vulnerability affects all RSA padding modes: PKCS#1 v1.5, RSA-OEAP and RSASVE. For example, in a TLS connection, RSA is commonly used by a client to send an encrypted pre-master secret to the server. An attacker that had observed a genuine connection between a client and a server could use this flaw to send trial messages to the server and record the time taken to process them. After a sufficiently large number of messages the attacker could recover the pre-master secret used for the original connection and thus be able to decrypt the application data sent over that connection.

- [https://github.com/Live-Hack-CVE/CVE-2022-4304](https://github.com/Live-Hack-CVE/CVE-2022-4304) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4304.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4304.svg)


## CVE-2022-3644
 The collection remote for pulp_ansible stores tokens in plaintext instead of using pulp's encrypted field and exposes them in read/write mode via the API () instead of marking it as write only.

- [https://github.com/Live-Hack-CVE/CVE-2022-3644](https://github.com/Live-Hack-CVE/CVE-2022-3644) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3644.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3644.svg)


## CVE-2022-3203
 On ORing net IAP-420(+) with FW version 2.0m a telnet server is enabled by default and cannot permanently be disabled. You can connect to the device via LAN or WiFi with hardcoded credentials and get an administrative shell. These credentials are reset to defaults with every reboot.

- [https://github.com/Live-Hack-CVE/CVE-2022-3203](https://github.com/Live-Hack-CVE/CVE-2022-3203) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3203.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3203.svg)


## CVE-2022-2775
 The Fast Flow WordPress plugin before 1.2.13 does not sanitise and escape some of its Widget settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup)

- [https://github.com/Live-Hack-CVE/CVE-2022-2775](https://github.com/Live-Hack-CVE/CVE-2022-2775) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2775.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2775.svg)


## CVE-2022-2567
 The Form Builder CP WordPress plugin before 1.2.32 does not sanitise and escape some of its form settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup)

- [https://github.com/Live-Hack-CVE/CVE-2022-2567](https://github.com/Live-Hack-CVE/CVE-2022-2567) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2567.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2567.svg)


## CVE-2022-2094
 The Yellow Yard Searchbar WordPress plugin before 2.8.2 does not escape some URL parameters before outputting them back to the user, leading to Reflected Cross-Site Scripting

- [https://github.com/Live-Hack-CVE/CVE-2022-2094](https://github.com/Live-Hack-CVE/CVE-2022-2094) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2094.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2094.svg)


## CVE-2022-0316
 The WeStand WordPress theme before 2.1, footysquare WordPress theme, aidreform WordPress theme, statfort WordPress theme, club-theme WordPress theme, kingclub-theme WordPress theme, spikes WordPress theme, spikes-black WordPress theme, soundblast WordPress theme, bolster WordPress theme from ChimpStudio and PixFill does not have any authorisation and upload validation in the lang_upload.php file, allowing any unauthenticated attacker to upload arbitrary files to the web server.

- [https://github.com/KTN1990/CVE-2022-0316_wordpress_multiple_themes_exploit](https://github.com/KTN1990/CVE-2022-0316_wordpress_multiple_themes_exploit) :  ![starts](https://img.shields.io/github/stars/KTN1990/CVE-2022-0316_wordpress_multiple_themes_exploit.svg) ![forks](https://img.shields.io/github/forks/KTN1990/CVE-2022-0316_wordpress_multiple_themes_exploit.svg)


## CVE-2021-33657
 There is a heap overflow problem in video/SDL_pixels.c in SDL (Simple DirectMedia Layer) 2.x to 2.0.18 versions. By crafting a malicious .BMP file, an attacker can cause the application using this library to crash, denial of service or Code execution.

- [https://github.com/Live-Hack-CVE/CVE-2021-33657](https://github.com/Live-Hack-CVE/CVE-2021-33657) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-33657.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-33657.svg)


## CVE-2021-25680
 ** UNSUPPORTED WHEN ASSIGNED ** The AdTran Personal Phone Manager software is vulnerable to multiple reflected cross-site scripting (XSS) issues. These issues impact at minimum versions 10.8.1 and below but potentially impact later versions as well since they have not previously been disclosed. Only version 10.8.1 was able to be confirmed during primary research. NOTE: The affected appliances NetVanta 7060 and NetVanta 7100 are considered End of Life and as such this issue will not be patched.

- [https://github.com/3ndG4me/AdTran-Personal-Phone-Manager-Vulns](https://github.com/3ndG4me/AdTran-Personal-Phone-Manager-Vulns) :  ![starts](https://img.shields.io/github/stars/3ndG4me/AdTran-Personal-Phone-Manager-Vulns.svg) ![forks](https://img.shields.io/github/forks/3ndG4me/AdTran-Personal-Phone-Manager-Vulns.svg)


## CVE-2021-25298
 Nagios XI version xi-5.7.5 is affected by OS command injection. The vulnerability exists in the file /usr/local/nagiosxi/html/includes/configwizards/cloud-vm/cloud-vm.inc.php due to improper sanitization of authenticated user-controlled input by a single HTTP request, which can lead to OS command injection on the Nagios XI server.

- [https://github.com/Live-Hack-CVE/CVE-2021-25298](https://github.com/Live-Hack-CVE/CVE-2021-25298) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-25298.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-25298.svg)


## CVE-2021-25297
 Nagios XI version xi-5.7.5 is affected by OS command injection. The vulnerability exists in the file /usr/local/nagiosxi/html/includes/configwizards/switch/switch.inc.php due to improper sanitization of authenticated user-controlled input by a single HTTP request, which can lead to OS command injection on the Nagios XI server.

- [https://github.com/Live-Hack-CVE/CVE-2021-25297](https://github.com/Live-Hack-CVE/CVE-2021-25297) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-25297.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-25297.svg)


## CVE-2021-25296
 Nagios XI version xi-5.7.5 is affected by OS command injection. The vulnerability exists in the file /usr/local/nagiosxi/html/includes/configwizards/windowswmi/windowswmi.inc.php due to improper sanitization of authenticated user-controlled input by a single HTTP request, which can lead to OS command injection on the Nagios XI server.

- [https://github.com/Live-Hack-CVE/CVE-2021-25296](https://github.com/Live-Hack-CVE/CVE-2021-25296) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-25296.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-25296.svg)


## CVE-2021-21974
 OpenSLP as used in ESXi (7.0 before ESXi70U1c-17325551, 6.7 before ESXi670-202102401-SG, 6.5 before ESXi650-202102101-SG) has a heap-overflow vulnerability. A malicious actor residing within the same network segment as ESXi who has access to port 427 may be able to trigger the heap-overflow issue in OpenSLP service resulting in remote code execution.

- [https://github.com/CYBERTHREATANALYSIS/ESXi_ransomware_scanner](https://github.com/CYBERTHREATANALYSIS/ESXi_ransomware_scanner) :  ![starts](https://img.shields.io/github/stars/CYBERTHREATANALYSIS/ESXi_ransomware_scanner.svg) ![forks](https://img.shields.io/github/forks/CYBERTHREATANALYSIS/ESXi_ransomware_scanner.svg)


## CVE-2021-3958
 Improper Handling of Parameters vulnerability in Ipack Automation Systems Ipack SCADA Software allows : Blind SQL Injection.This issue affects Ipack SCADA Software: from unspecified before 1.1.0.

- [https://github.com/Live-Hack-CVE/CVE-2021-3958](https://github.com/Live-Hack-CVE/CVE-2021-3958) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3958.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3958.svg)


## CVE-2021-3948
 An incorrect default permissions vulnerability was found in the mig-controller. Due to an incorrect cluster namespaces handling an attacker may be able to migrate a malicious workload to the target cluster, impacting confidentiality, integrity, and availability of the services located on that cluster.

- [https://github.com/Live-Hack-CVE/CVE-2021-3948](https://github.com/Live-Hack-CVE/CVE-2021-3948) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-3948.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-3948.svg)


## CVE-2020-27068
 Product: AndroidVersions: Android kernelAndroid ID: A-127973231References: Upstream kernel

- [https://github.com/Live-Hack-CVE/CVE-2020-27068](https://github.com/Live-Hack-CVE/CVE-2020-27068) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-27068.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-27068.svg)


## CVE-2020-25659
 python-cryptography 3.2 is vulnerable to Bleichenbacher timing attacks in the RSA decryption API, via timed processing of valid PKCS#1 v1.5 ciphertext.

- [https://github.com/Live-Hack-CVE/CVE-2020-25659](https://github.com/Live-Hack-CVE/CVE-2020-25659) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-25659.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-25659.svg)


## CVE-2020-14410
 SDL (Simple DirectMedia Layer) through 2.0.12 has a heap-based buffer over-read in Blit_3or4_to_3or4__inversed_rgb in video/SDL_blit_N.c via a crafted .BMP file.

- [https://github.com/Live-Hack-CVE/CVE-2020-14410](https://github.com/Live-Hack-CVE/CVE-2020-14410) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-14410.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-14410.svg)


## CVE-2020-8002
 A NULL pointer dereference in vrend_renderer.c in virglrenderer through 0.8.1 allows attackers to cause a denial of service via commands that attempt to launch a grid without previously providing a Compute Shader (CS).

- [https://github.com/Live-Hack-CVE/CVE-2020-8002](https://github.com/Live-Hack-CVE/CVE-2020-8002) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2020-8002.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2020-8002.svg)


## CVE-2020-2883
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/zhzyker/vulmap](https://github.com/zhzyker/vulmap) :  ![starts](https://img.shields.io/github/stars/zhzyker/vulmap.svg) ![forks](https://img.shields.io/github/forks/zhzyker/vulmap.svg)


## CVE-2019-15112
 The wp-slimstat plugin before 4.8.1 for WordPress has XSS.

- [https://github.com/Live-Hack-CVE/CVE-2019-15112](https://github.com/Live-Hack-CVE/CVE-2019-15112) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-15112.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-15112.svg)


## CVE-2019-13626
 SDL (Simple DirectMedia Layer) 2.x through 2.0.9 has a heap-based buffer over-read in Fill_IMA_ADPCM_block, caused by an integer overflow in IMA_ADPCM_decode() in audio/SDL_wave.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-13626](https://github.com/Live-Hack-CVE/CVE-2019-13626) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-13626.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-13626.svg)


## CVE-2019-13616
 SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in BlitNtoN in video/SDL_blit_N.c when called from SDL_SoftBlit in video/SDL_blit.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-13616](https://github.com/Live-Hack-CVE/CVE-2019-13616) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-13616.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-13616.svg)


## CVE-2019-7638
 SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in Map1toN in video/SDL_pixels.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-7638](https://github.com/Live-Hack-CVE/CVE-2019-7638) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-7638.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-7638.svg)


## CVE-2019-7636
 SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in SDL_GetRGB in video/SDL_pixels.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-7636](https://github.com/Live-Hack-CVE/CVE-2019-7636) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-7636.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-7636.svg)


## CVE-2019-7635
 SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in Blit1to4 in video/SDL_blit_1.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-7635](https://github.com/Live-Hack-CVE/CVE-2019-7635) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-7635.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-7635.svg)


## CVE-2019-7578
 SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in InitIMA_ADPCM in audio/SDL_wave.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-7578](https://github.com/Live-Hack-CVE/CVE-2019-7578) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-7578.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-7578.svg)


## CVE-2019-7577
 SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a buffer over-read in SDL_LoadWAV_RW in audio/SDL_wave.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-7577](https://github.com/Live-Hack-CVE/CVE-2019-7577) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-7577.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-7577.svg)


## CVE-2019-7576
 SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in InitMS_ADPCM in audio/SDL_wave.c (outside the wNumCoef loop).

- [https://github.com/Live-Hack-CVE/CVE-2019-7576](https://github.com/Live-Hack-CVE/CVE-2019-7576) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-7576.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-7576.svg)


## CVE-2019-7575
 SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer overflow in MS_ADPCM_decode in audio/SDL_wave.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-7575](https://github.com/Live-Hack-CVE/CVE-2019-7575) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-7575.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-7575.svg)


## CVE-2019-7574
 SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in IMA_ADPCM_decode in audio/SDL_wave.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-7574](https://github.com/Live-Hack-CVE/CVE-2019-7574) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-7574.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-7574.svg)


## CVE-2019-7573
 SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a heap-based buffer over-read in InitMS_ADPCM in audio/SDL_wave.c (inside the wNumCoef loop).

- [https://github.com/Live-Hack-CVE/CVE-2019-7573](https://github.com/Live-Hack-CVE/CVE-2019-7573) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-7573.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-7573.svg)


## CVE-2019-7572
 SDL (Simple DirectMedia Layer) through 1.2.15 and 2.x through 2.0.9 has a buffer over-read in IMA_ADPCM_nibble in audio/SDL_wave.c.

- [https://github.com/Live-Hack-CVE/CVE-2019-7572](https://github.com/Live-Hack-CVE/CVE-2019-7572) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-7572.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-7572.svg)


## CVE-2018-25014
 A use of uninitialized value was found in libwebp in versions before 1.0.1 in ReadSymbol().

- [https://github.com/Live-Hack-CVE/CVE-2018-25014](https://github.com/Live-Hack-CVE/CVE-2018-25014) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25014.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25014.svg)


## CVE-2018-25013
 A heap-based buffer overflow was found in libwebp in versions before 1.0.1 in ShiftBytes().

- [https://github.com/Live-Hack-CVE/CVE-2018-25013](https://github.com/Live-Hack-CVE/CVE-2018-25013) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25013.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25013.svg)


## CVE-2018-25012
 A heap-based buffer overflow was found in libwebp in versions before 1.0.1 in GetLE24().

- [https://github.com/Live-Hack-CVE/CVE-2018-25012](https://github.com/Live-Hack-CVE/CVE-2018-25012) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-25012.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-25012.svg)


## CVE-2018-3982
 An exploitable arbitrary write vulnerability exists in the Word document parser of the Atlantis Word Processor 3.0.2.3 and 3.0.2.5. A specially crafted document can prevent Atlas from adding elements to an array that is indexed by a loop. When reading from this array, the application will use an out-of-bounds index which can result in arbitrary data being read as a pointer. Later, when the application attempts to write to said pointer, an arbitrary write will occur. This can allow an attacker to further corrupt memory, which leads to code execution under the context of the application. An attacker must convince a victim to open a document in order to trigger this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2018-3982](https://github.com/Live-Hack-CVE/CVE-2018-3982) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2018-3982.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2018-3982.svg)


## CVE-2017-18540
 The weblibrarian plugin before 3.4.8.7 for WordPress has XSS via front-end short codes.

- [https://github.com/Live-Hack-CVE/CVE-2017-18540](https://github.com/Live-Hack-CVE/CVE-2017-18540) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-18540.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-18540.svg)


## CVE-2017-18539
 The weblibrarian plugin before 3.4.8.6 for WordPress has XSS via front-end short codes.

- [https://github.com/Live-Hack-CVE/CVE-2017-18539](https://github.com/Live-Hack-CVE/CVE-2017-18539) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-18539.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-18539.svg)


## CVE-2017-18538
 The weblibrarian plugin before 3.4.8.5 for WordPress has XSS via front-end short codes.

- [https://github.com/Live-Hack-CVE/CVE-2017-18538](https://github.com/Live-Hack-CVE/CVE-2017-18538) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-18538.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-18538.svg)


## CVE-2017-15699
 A Denial of Service vulnerability was found in Apache Qpid Dispatch Router versions 0.7.0 and 0.8.0. To exploit this vulnerability, a remote user must be able to establish an AMQP connection to the Qpid Dispatch Router and send a specifically crafted AMQP frame which will cause it to segfault and shut down.

- [https://github.com/Live-Hack-CVE/CVE-2017-15699](https://github.com/Live-Hack-CVE/CVE-2017-15699) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-15699.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-15699.svg)


## CVE-2017-12621
 During Jelly (xml) file parsing with Apache Xerces, if a custom doctype entity is declared with a &quot;SYSTEM&quot; entity with a URL and that entity is used in the body of the Jelly file, during parser instantiation the parser will attempt to connect to said URL. This could lead to XML External Entity (XXE) attacks in Apache Commons Jelly before 1.0.1.

- [https://github.com/Live-Hack-CVE/CVE-2017-12621](https://github.com/Live-Hack-CVE/CVE-2017-12621) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-12621.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-12621.svg)


## CVE-2017-5546
 The freelist-randomization feature in mm/slab.c in the Linux kernel 4.8.x and 4.9.x before 4.9.5 allows local users to cause a denial of service (duplicate freelist entries and system crash) or possibly have unspecified other impact in opportunistic circumstances by leveraging the selection of a large value for a random number.

- [https://github.com/Live-Hack-CVE/CVE-2017-5546](https://github.com/Live-Hack-CVE/CVE-2017-5546) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2017-5546.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2017-5546.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;

- [https://github.com/ireshchaminda1/System-Exploitation-May-2021-](https://github.com/ireshchaminda1/System-Exploitation-May-2021-) :  ![starts](https://img.shields.io/github/stars/ireshchaminda1/System-Exploitation-May-2021-.svg) ![forks](https://img.shields.io/github/forks/ireshchaminda1/System-Exploitation-May-2021-.svg)


## CVE-2015-3864
 Integer underflow in the MPEG4Extractor::parseChunk function in MPEG4Extractor.cpp in libstagefright in mediaserver in Android before 5.1.1 LMY48M allows remote attackers to execute arbitrary code via crafted MPEG-4 data, aka internal bug 23034759.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2015-3824.

- [https://github.com/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864](https://github.com/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864) :  ![starts](https://img.shields.io/github/stars/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864.svg) ![forks](https://img.shields.io/github/forks/Bhathiya404/Exploiting-Stagefright-Vulnerability-CVE-2015-3864.svg)


## CVE-2009-0824
 Elaborate Bytes ElbyCDIO.sys 6.0.2.0 and earlier, as distributed in SlySoft AnyDVD before 6.5.2.6, Virtual CloneDrive 5.4.2.3 and earlier, CloneDVD 2.9.2.0 and earlier, and CloneCD 5.3.1.3 and earlier, uses the METHOD_NEITHER communication method for IOCTLs and does not properly validate a buffer associated with the Irp object, which allows local users to cause a denial of service (system crash) via a crafted IOCTL call.

- [https://github.com/Exploitables/CVE-2009-0824](https://github.com/Exploitables/CVE-2009-0824) :  ![starts](https://img.shields.io/github/stars/Exploitables/CVE-2009-0824.svg) ![forks](https://img.shields.io/github/forks/Exploitables/CVE-2009-0824.svg)


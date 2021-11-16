# Update 2021-11-16
## CVE-2021-43616
 The npm ci command in npm 7.x and 8.x through 8.1.3 proceeds with an installation even if dependency information in package-lock.json differs from package.json. This behavior is inconsistent with the documentation, and makes it easier for attackers to install malware that was supposed to have been blocked by an exact version match requirement in package-lock.json.

- [https://github.com/icatalina/CVE-2021-43616](https://github.com/icatalina/CVE-2021-43616) :  ![starts](https://img.shields.io/github/stars/icatalina/CVE-2021-43616.svg) ![forks](https://img.shields.io/github/forks/icatalina/CVE-2021-43616.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/simon242/CVE-2021-42013](https://github.com/simon242/CVE-2021-42013) :  ![starts](https://img.shields.io/github/stars/simon242/CVE-2021-42013.svg) ![forks](https://img.shields.io/github/forks/simon242/CVE-2021-42013.svg)
- [https://github.com/xMohamed0/CVE-2021-42013-ApacheRCE](https://github.com/xMohamed0/CVE-2021-42013-ApacheRCE) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-42013-ApacheRCE.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-42013-ApacheRCE.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)


## CVE-2021-41351
 Microsoft Edge (Chrome based) Spoofing on IE Mode

- [https://github.com/JaneMandy/CVE-2021-41351-POC](https://github.com/JaneMandy/CVE-2021-41351-POC) :  ![starts](https://img.shields.io/github/stars/JaneMandy/CVE-2021-41351-POC.svg) ![forks](https://img.shields.io/github/forks/JaneMandy/CVE-2021-41351-POC.svg)


## CVE-2021-32724
 check-spelling is a github action which provides CI spell checking. In affected versions and for a repository with the [check-spelling action](https://github.com/marketplace/actions/check-spelling) enabled that triggers on `pull_request_target` (or `schedule`), an attacker can send a crafted Pull Request that causes a `GITHUB_TOKEN` to be exposed. With the `GITHUB_TOKEN`, it's possible to push commits to the repository bypassing standard approval processes. Commits to the repository could then steal any/all secrets available to the repository. As a workaround users may can either: [Disable the workflow](https://docs.github.com/en/actions/managing-workflow-runs/disabling-and-enabling-a-workflow) until you've fixed all branches or Set repository to [Allow specific actions](https://docs.github.com/en/github/administering-a-repository/managing-repository-settings/disabling-or-limiting-github-actions-for-a-repository#allowing-specific-actions-to-run). check-spelling isn't a verified creator and it certainly won't be anytime soon. You could then explicitly add other actions that your repository uses. Set repository [Workflow permissions](https://docs.github.com/en/github/administering-a-repository/managing-repository-settings/disabling-or-limiting-github-actions-for-a-repository#setting-the-permissions-of-the-github_token-for-your-repository) to `Read repository contents permission`. Workflows using `check-spelling/check-spelling@main` will get the fix automatically. Workflows using a pinned sha or tagged version will need to change the affected workflows for all repository branches to the latest version. Users can verify who and which Pull Requests have been running the action by looking up the spelling.yml action in the Actions tab of their repositories, e.g., https://github.com/check-spelling/check-spelling/actions/workflows/spelling.yml - you can filter PRs by adding ?query=event%3Apull_request_target, e.g., https://github.com/check-spelling/check-spelling/actions/workflows/spelling.yml?query=event%3Apull_request_target.

- [https://github.com/MaximeSchlegel/AMUM2-CVE-2021-32724-Target](https://github.com/MaximeSchlegel/AMUM2-CVE-2021-32724-Target) :  ![starts](https://img.shields.io/github/stars/MaximeSchlegel/AMUM2-CVE-2021-32724-Target.svg) ![forks](https://img.shields.io/github/forks/MaximeSchlegel/AMUM2-CVE-2021-32724-Target.svg)


## CVE-2021-24807
 The Support Board WordPress plugin before 3.3.5 allows Authenticated (Agent+) users to perform Cross-Site Scripting attacks by placing a payload in the notes field, when an administrator or any authenticated user go to the chat the XSS will be automatically executed.

- [https://github.com/itsjeffersonli/CVE-2021-24807](https://github.com/itsjeffersonli/CVE-2021-24807) :  ![starts](https://img.shields.io/github/stars/itsjeffersonli/CVE-2021-24807.svg) ![forks](https://img.shields.io/github/forks/itsjeffersonli/CVE-2021-24807.svg)


## CVE-2021-21315
 The System Information Library for Node.JS (npm package &quot;systeminformation&quot;) is an open source collection of functions to retrieve detailed hardware, system and OS information. In systeminformation before version 5.3.1 there is a command injection vulnerability. Problem was fixed in version 5.3.1. As a workaround instead of upgrading, be sure to check or sanitize service parameters that are passed to si.inetLatency(), si.inetChecksite(), si.services(), si.processLoad() ... do only allow strings, reject any arrays. String sanitation works as expected.

- [https://github.com/xMohamed0/CVE-2021-21315-POC](https://github.com/xMohamed0/CVE-2021-21315-POC) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-21315-POC.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-21315-POC.svg)


## CVE-2020-7699
 This affects the package express-fileupload before 1.1.8. If the parseNested option is enabled, sending a corrupt HTTP request can lead to denial of service or arbitrary code execution.

- [https://github.com/hemaoqi-Tom/CVE-2020-7699_reproduce](https://github.com/hemaoqi-Tom/CVE-2020-7699_reproduce) :  ![starts](https://img.shields.io/github/stars/hemaoqi-Tom/CVE-2020-7699_reproduce.svg) ![forks](https://img.shields.io/github/forks/hemaoqi-Tom/CVE-2020-7699_reproduce.svg)


## CVE-2020-5504
 In phpMyAdmin 4 before 4.9.4 and 5 before 5.0.1, SQL injection exists in the user accounts page. A malicious user could inject custom SQL in place of their own username when creating queries to this page. An attacker must have a valid MySQL account to access the server.

- [https://github.com/xMohamed0/CVE-2020-5504-phpMyAdmin](https://github.com/xMohamed0/CVE-2020-5504-phpMyAdmin) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2020-5504-phpMyAdmin.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2020-5504-phpMyAdmin.svg)


## CVE-2020-2884
 Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core). Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle WebLogic Server. Successful attacks of this vulnerability can result in takeover of Oracle WebLogic Server. CVSS 3.0 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/hktalent/CVE_2020_2546](https://github.com/hktalent/CVE_2020_2546) :  ![starts](https://img.shields.io/github/stars/hktalent/CVE_2020_2546.svg) ![forks](https://img.shields.io/github/forks/hktalent/CVE_2020_2546.svg)


## CVE-2018-11776
 Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then: results are used with no namespace and in same time, its upper package have no or wildcard namespace and similar to results, same possibility when using url tag which doesn't have value and action set and in same time, its upper package have no or wildcard namespace.

- [https://github.com/HxDDD/CVE-PoC](https://github.com/HxDDD/CVE-PoC) :  ![starts](https://img.shields.io/github/stars/HxDDD/CVE-PoC.svg) ![forks](https://img.shields.io/github/forks/HxDDD/CVE-PoC.svg)


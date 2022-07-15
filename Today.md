# Update 2022-07-15
## CVE-2022-34265
 An issue was discovered in Django 3.2 before 3.2.14 and 4.0 before 4.0.6. The Trunc() and Extract() database functions are subject to SQL injection if untrusted data is used as a kind/lookup_name value. Applications that constrain the lookup name and kind choice to a known safe list are unaffected.

- [https://github.com/not-xences/CVE-2022-34265](https://github.com/not-xences/CVE-2022-34265) :  ![starts](https://img.shields.io/github/stars/not-xences/CVE-2022-34265.svg) ![forks](https://img.shields.io/github/forks/not-xences/CVE-2022-34265.svg)


## CVE-2022-30525
 A OS command injection vulnerability in the CGI program of Zyxel USG FLEX 100(W) firmware versions 5.00 through 5.21 Patch 1, USG FLEX 200 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 500 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 700 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 50(W) firmware versions 5.10 through 5.21 Patch 1, USG20(W)-VPN firmware versions 5.10 through 5.21 Patch 1, ATP series firmware versions 5.10 through 5.21 Patch 1, VPN series firmware versions 4.60 through 5.21 Patch 1, which could allow an attacker to modify specific files and then execute some OS commands on a vulnerable device.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)


## CVE-2022-29303
 SolarView Compact ver.6.00 was discovered to contain a command injection vulnerability via conf_mail.php.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/twoning/CVE-2022-26134-PoC](https://github.com/twoning/CVE-2022-26134-PoC) :  ![starts](https://img.shields.io/github/stars/twoning/CVE-2022-26134-PoC.svg) ![forks](https://img.shields.io/github/forks/twoning/CVE-2022-26134-PoC.svg)
- [https://github.com/2212970396/CVE_2022_26134](https://github.com/2212970396/CVE_2022_26134) :  ![starts](https://img.shields.io/github/stars/2212970396/CVE_2022_26134.svg) ![forks](https://img.shields.io/github/forks/2212970396/CVE_2022_26134.svg)


## CVE-2022-25078
 TOTOLink A3600R V4.1.2cu.5182_B20201102 was discovered to contain a command injection vulnerability in the &quot;Main&quot; function. This vulnerability allows attackers to execute arbitrary commands via the QUERY_STRING parameter.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)


## CVE-2022-22980
 A Spring Data MongoDB application is vulnerable to SpEL Injection when using @Query or @Aggregation-annotated query methods with SpEL expressions that contain query parameter placeholders for value binding if the input is not sanitized.

- [https://github.com/Vulnmachines/Spring_cve-2022-22980](https://github.com/Vulnmachines/Spring_cve-2022-22980) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/Spring_cve-2022-22980.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/Spring_cve-2022-22980.svg)


## CVE-2022-22978
 In Spring Security versions 5.5.6 and 5.6.3 and older unsupported versions, RegexRequestMatcher can easily be misconfigured to be bypassed on some servlet containers. Applications using RegexRequestMatcher with `.` in the regular expression are possibly vulnerable to an authorization bypass

- [https://github.com/aeifkz/CVE-2022-22978](https://github.com/aeifkz/CVE-2022-22978) :  ![starts](https://img.shields.io/github/stars/aeifkz/CVE-2022-22978.svg) ![forks](https://img.shields.io/github/forks/aeifkz/CVE-2022-22978.svg)


## CVE-2022-22954
 VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)


## CVE-2022-21449
 Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Libraries). Supported versions that are affected are Oracle Java SE: 17.0.2 and 18; Oracle GraalVM Enterprise Edition: 21.3.1 and 22.0.0.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 7.5 (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N).

- [https://github.com/notkmhn/CVE-2022-21449-TLS-PoC](https://github.com/notkmhn/CVE-2022-21449-TLS-PoC) :  ![starts](https://img.shields.io/github/stars/notkmhn/CVE-2022-21449-TLS-PoC.svg) ![forks](https://img.shields.io/github/forks/notkmhn/CVE-2022-21449-TLS-PoC.svg)


## CVE-2022-1119
 The Simple File List WordPress plugin is vulnerable to Arbitrary File Download via the eeFile parameter found in the ~/includes/ee-downloader.php file due to missing controls which makes it possible unauthenticated attackers to supply a path to a file that will subsequently be downloaded, in versions up to and including 3.2.7.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)


## CVE-2021-46422
 Telesquare SDT-CW3B1 1.1.0 is affected by an OS command injection vulnerability that allows a remote attacker to execute OS commands without any authentication.

- [https://github.com/twoning/CVE-2021-46422_PoC](https://github.com/twoning/CVE-2021-46422_PoC) :  ![starts](https://img.shields.io/github/stars/twoning/CVE-2021-46422_PoC.svg) ![forks](https://img.shields.io/github/forks/twoning/CVE-2021-46422_PoC.svg)


## CVE-2021-43734
 kkFileview v4.0.0 has arbitrary file read through a directory traversal vulnerability which may lead to sensitive file leak on related host.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)


## CVE-2021-41652
 Insecure permissions in the file database.sdb of BatFlat CMS v1.3.6 allows attackers to dump the entire database.

- [https://github.com/deathflash1411/CVE-2021-41652](https://github.com/deathflash1411/CVE-2021-41652) :  ![starts](https://img.shields.io/github/stars/deathflash1411/CVE-2021-41652.svg) ![forks](https://img.shields.io/github/forks/deathflash1411/CVE-2021-41652.svg)


## CVE-2021-34473
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-31196, CVE-2021-31206.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)


## CVE-2021-30461
 A remote code execution issue was discovered in the web UI of VoIPmonitor before 24.61. When the recheck option is used, the user-supplied SPOOLDIR value (which might contain PHP code) is injected into config/configuration.php.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)


## CVE-2021-21300
 Git is an open-source distributed revision control system. In affected versions of Git a specially crafted repository that contains symbolic links as well as files using a clean/smudge filter such as Git LFS, may cause just-checked out script to be executed while cloning onto a case-insensitive file system such as NTFS, HFS+ or APFS (i.e. the default file systems on Windows and macOS). Note that clean/smudge filters have to be configured for that. Git for Windows configures Git LFS by default, and is therefore vulnerable. The problem has been patched in the versions published on Tuesday, March 9th, 2021. As a workaound, if symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. Likewise, if no clean/smudge filters such as Git LFS are configured globally (i.e. _before_ cloning), the attack is foiled. As always, it is best to avoid cloning repositories from untrusted sources. The earliest impacted version is 2.14.2. The fix versions are: 2.30.1, 2.29.3, 2.28.1, 2.27.1, 2.26.3, 2.25.5, 2.24.4, 2.23.4, 2.22.5, 2.21.4, 2.20.5, 2.19.6, 2.18.5, 2.17.62.17.6.

- [https://github.com/erranfenech/CVE-2021-21300](https://github.com/erranfenech/CVE-2021-21300) :  ![starts](https://img.shields.io/github/stars/erranfenech/CVE-2021-21300.svg) ![forks](https://img.shields.io/github/forks/erranfenech/CVE-2021-21300.svg)


## CVE-2019-5418
 There is a File Content Disclosure vulnerability in Action View &lt;5.2.2.1, &lt;5.1.6.2, &lt;5.0.7.2, &lt;4.2.11.1 and v3 where specially crafted accept headers can cause contents of arbitrary files on the target system's filesystem to be exposed.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)


## CVE-2018-20250
 In WinRAR versions prior to and including 5.61, There is path traversal vulnerability when crafting the filename field of the ACE format (in UNACEV2.dll). When the filename field is manipulated with specific patterns, the destination (extraction) folder is ignored, thus treating the filename as an absolute path.

- [https://github.com/STP5940/CVE-2018-20250](https://github.com/STP5940/CVE-2018-20250) :  ![starts](https://img.shields.io/github/stars/STP5940/CVE-2018-20250.svg) ![forks](https://img.shields.io/github/forks/STP5940/CVE-2018-20250.svg)
- [https://github.com/eastmountyxz/CVE-2018-20250-WinRAR](https://github.com/eastmountyxz/CVE-2018-20250-WinRAR) :  ![starts](https://img.shields.io/github/stars/eastmountyxz/CVE-2018-20250-WinRAR.svg) ![forks](https://img.shields.io/github/forks/eastmountyxz/CVE-2018-20250-WinRAR.svg)
- [https://github.com/n4r1b/WinAce-POC](https://github.com/n4r1b/WinAce-POC) :  ![starts](https://img.shields.io/github/stars/n4r1b/WinAce-POC.svg) ![forks](https://img.shields.io/github/forks/n4r1b/WinAce-POC.svg)


## CVE-2018-13379
 An Improper Limitation of a Pathname to a Restricted Directory (&quot;Path Traversal&quot;) in Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.3 to 5.6.7 and 5.4.6 to 5.4.12 and FortiProxy 2.0.0, 1.2.0 to 1.2.8, 1.1.0 to 1.1.6, 1.0.0 to 1.0.7 under SSL VPN web portal allows an unauthenticated attacker to download system files via special crafted HTTP resource requests.

- [https://github.com/W01fh4cker/Serein](https://github.com/W01fh4cker/Serein) :  ![starts](https://img.shields.io/github/stars/W01fh4cker/Serein.svg) ![forks](https://img.shields.io/github/forks/W01fh4cker/Serein.svg)


## CVE-2017-16043
 Shout is an IRC client. Because the `/topic` command in messages is unescaped, attackers have the ability to inject HTML scripts that will run in the victim's browser. Affects shout &gt;=0.44.0 &lt;=0.49.3.

- [https://github.com/ossf-cve-benchmark/CVE-2017-16043](https://github.com/ossf-cve-benchmark/CVE-2017-16043) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2017-16043.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2017-16043.svg)


## CVE-2015-3224
 request.rb in Web Console before 2.1.3, as used with Ruby on Rails 3.x and 4.x, does not properly restrict the use of X-Forwarded-For headers in determining a client's IP address, which allows remote attackers to bypass the whitelisted_ips protection mechanism via a crafted request.

- [https://github.com/n000xy/CVE-2015-3224-](https://github.com/n000xy/CVE-2015-3224-) :  ![starts](https://img.shields.io/github/stars/n000xy/CVE-2015-3224-.svg) ![forks](https://img.shields.io/github/forks/n000xy/CVE-2015-3224-.svg)


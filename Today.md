# Update 2022-10-13
## CVE-2022-41082
 Microsoft Exchange Server Remote Code Execution Vulnerability.

- [https://github.com/y4b4n/CVE-2022-41082-RCE-POC](https://github.com/y4b4n/CVE-2022-41082-RCE-POC) :  ![starts](https://img.shields.io/github/stars/y4b4n/CVE-2022-41082-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/y4b4n/CVE-2022-41082-RCE-POC.svg)


## CVE-2022-40684
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/CarlosV1e1ra/CVE-2022-40684-RCE-POC](https://github.com/CarlosV1e1ra/CVE-2022-40684-RCE-POC) :  ![starts](https://img.shields.io/github/stars/CarlosV1e1ra/CVE-2022-40684-RCE-POC.svg) ![forks](https://img.shields.io/github/forks/CarlosV1e1ra/CVE-2022-40684-RCE-POC.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/Pygosce/CVE-2022-22965](https://github.com/Pygosce/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/Pygosce/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/Pygosce/CVE-2022-22965.svg)


## CVE-2022-3452
 A vulnerability was found in SourceCodester Book Store Management System 1.0. It has been declared as problematic. This vulnerability affects unknown code of the file /category.php. The manipulation of the argument category_name leads to cross site scripting. The attack can be initiated remotely. The identifier of this vulnerability is VDB-210436.

- [https://github.com/kenyon-wong/cve-2022-3452](https://github.com/kenyon-wong/cve-2022-3452) :  ![starts](https://img.shields.io/github/stars/kenyon-wong/cve-2022-3452.svg) ![forks](https://img.shields.io/github/forks/kenyon-wong/cve-2022-3452.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/badboy-sft/Dirty-Pipe-Oneshot](https://github.com/badboy-sft/Dirty-Pipe-Oneshot) :  ![starts](https://img.shields.io/github/stars/badboy-sft/Dirty-Pipe-Oneshot.svg) ![forks](https://img.shields.io/github/forks/badboy-sft/Dirty-Pipe-Oneshot.svg)


## CVE-2021-42327
 dp_link_settings_write in drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm_debugfs.c in the Linux kernel through 5.14.14 allows a heap-based buffer overflow by an attacker who can write a string to the AMD GPU display drivers debug filesystem. There are no checks on size within parse_write_buffer_into_params when it uses the size of copy_from_user to copy a userspace buffer into a 40-byte heap buffer.

- [https://github.com/docfate111/CVE-2021-42327](https://github.com/docfate111/CVE-2021-42327) :  ![starts](https://img.shields.io/github/stars/docfate111/CVE-2021-42327.svg) ![forks](https://img.shields.io/github/forks/docfate111/CVE-2021-42327.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/256o/CVE-2021-41773](https://github.com/256o/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/256o/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/256o/CVE-2021-41773.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/256o/CVE-2021-41773](https://github.com/256o/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/256o/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/256o/CVE-2021-41773.svg)


## CVE-2021-3129
 Ignition before 2.5.2, as used in Laravel and other products, allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2.

- [https://github.com/0nion1/CVE-2021-3129](https://github.com/0nion1/CVE-2021-3129) :  ![starts](https://img.shields.io/github/stars/0nion1/CVE-2021-3129.svg) ![forks](https://img.shields.io/github/forks/0nion1/CVE-2021-3129.svg)


## CVE-2018-17207
 An issue was discovered in Snap Creek Duplicator before 1.2.42. By accessing leftover installer files (installer.php and installer-backup.php), an attacker can inject PHP code into wp-config.php during the database setup step, achieving arbitrary code execution.

- [https://github.com/cved-sources/cve-2018-17207](https://github.com/cved-sources/cve-2018-17207) :  ![starts](https://img.shields.io/github/stars/cved-sources/cve-2018-17207.svg) ![forks](https://img.shields.io/github/forks/cved-sources/cve-2018-17207.svg)


## CVE-2018-1010
 A remote code execution vulnerability exists when the Windows font library improperly handles specially crafted embedded fonts, aka &quot;Microsoft Graphics Remote Code Execution Vulnerability.&quot; This affects Windows 7, Windows Server 2012 R2, Windows RT 8.1, Windows Server 2008, Windows Server 2012, Windows 8.1, Windows Server 2016, Windows Server 2008 R2, Windows 10, Windows 10 Servers. This CVE ID is unique from CVE-2018-1012, CVE-2018-1013, CVE-2018-1015, CVE-2018-1016.

- [https://github.com/ymgh96/Detecting-the-patch-of-CVE-2018-1010](https://github.com/ymgh96/Detecting-the-patch-of-CVE-2018-1010) :  ![starts](https://img.shields.io/github/stars/ymgh96/Detecting-the-patch-of-CVE-2018-1010.svg) ![forks](https://img.shields.io/github/forks/ymgh96/Detecting-the-patch-of-CVE-2018-1010.svg)


## CVE-2017-1000353
 Jenkins versions 2.56 and earlier as well as 2.46.1 LTS and earlier are vulnerable to an unauthenticated remote code execution. An unauthenticated remote code execution vulnerability allowed attackers to transfer a serialized Java `SignedObject` object to the Jenkins CLI, that would be deserialized using a new `ObjectInputStream`, bypassing the existing blacklist-based protection mechanism. We're fixing this issue by adding `SignedObject` to the blacklist. We're also backporting the new HTTP CLI protocol from Jenkins 2.54 to LTS 2.46.2, and deprecating the remoting-based (i.e. Java serialization) CLI protocol, disabling it by default.

- [https://github.com/r00t4dm/Jenkins-CVE-2017-1000353](https://github.com/r00t4dm/Jenkins-CVE-2017-1000353) :  ![starts](https://img.shields.io/github/stars/r00t4dm/Jenkins-CVE-2017-1000353.svg) ![forks](https://img.shields.io/github/forks/r00t4dm/Jenkins-CVE-2017-1000353.svg)


## CVE-2016-9299
 The remoting module in Jenkins before 2.32 and LTS before 2.19.3 allows remote attackers to execute arbitrary code via a crafted serialized Java object, which triggers an LDAP query to a third-party server.

- [https://github.com/r00t4dm/Jenkins-CVE-2016-9299](https://github.com/r00t4dm/Jenkins-CVE-2016-9299) :  ![starts](https://img.shields.io/github/stars/r00t4dm/Jenkins-CVE-2016-9299.svg) ![forks](https://img.shields.io/github/forks/r00t4dm/Jenkins-CVE-2016-9299.svg)


## CVE-2015-8103
 The Jenkins CLI subsystem in Jenkins before 1.638 and LTS before 1.625.2 allows remote attackers to execute arbitrary code via a crafted serialized Java object, related to a problematic webapps/ROOT/WEB-INF/lib/commons-collections-*.jar file and the &quot;Groovy variant in 'ysoserial'&quot;.

- [https://github.com/r00t4dm/Jenkins-CVE-2015-8103](https://github.com/r00t4dm/Jenkins-CVE-2015-8103) :  ![starts](https://img.shields.io/github/stars/r00t4dm/Jenkins-CVE-2015-8103.svg) ![forks](https://img.shields.io/github/forks/r00t4dm/Jenkins-CVE-2015-8103.svg)


## CVE-2009-4623
 Multiple PHP remote file inclusion vulnerabilities in Advanced Comment System 1.0 allow remote attackers to execute arbitrary PHP code via a URL in the ACS_path parameter to (1) index.php and (2) admin.php in advanced_comment_system/. NOTE: this might only be a vulnerability when the administrator has not followed installation instructions in install.php. NOTE: this might be the same as CVE-2020-35598.

- [https://github.com/MonsempesSamuel/CVE-2009-4623](https://github.com/MonsempesSamuel/CVE-2009-4623) :  ![starts](https://img.shields.io/github/stars/MonsempesSamuel/CVE-2009-4623.svg) ![forks](https://img.shields.io/github/forks/MonsempesSamuel/CVE-2009-4623.svg)


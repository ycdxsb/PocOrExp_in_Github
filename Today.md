# Update 2022-08-31
## CVE-2022-36200
 In FiberHome VDSL2 Modem HG150-Ub_V3.0, Credentials of Admin are submitted in URL, which can be logged/sniffed.

- [https://github.com/afaq1337/CVE-2022-36200](https://github.com/afaq1337/CVE-2022-36200) :  ![starts](https://img.shields.io/github/stars/afaq1337/CVE-2022-36200.svg) ![forks](https://img.shields.io/github/forks/afaq1337/CVE-2022-36200.svg)


## CVE-2022-33891
 The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1.

- [https://github.com/Vulnmachines/Apache-spark-CVE-2022-33891](https://github.com/Vulnmachines/Apache-spark-CVE-2022-33891) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/Apache-spark-CVE-2022-33891.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/Apache-spark-CVE-2022-33891.svg)


## CVE-2022-28381
 Mediaserver.exe in ALLMediaServer 1.6 has a stack-based buffer overflow that allows remote attackers to execute arbitrary code via a long string to TCP port 888, a related issue to CVE-2017-17932.

- [https://github.com/DShankle/CVE-2022-28381_PoC](https://github.com/DShankle/CVE-2022-28381_PoC) :  ![starts](https://img.shields.io/github/stars/DShankle/CVE-2022-28381_PoC.svg) ![forks](https://img.shields.io/github/forks/DShankle/CVE-2022-28381_PoC.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/iyamroshan/CVE-2022-22965](https://github.com/iyamroshan/CVE-2022-22965) :  ![starts](https://img.shields.io/github/stars/iyamroshan/CVE-2022-22965.svg) ![forks](https://img.shields.io/github/forks/iyamroshan/CVE-2022-22965.svg)


## CVE-2022-22814
 The System Diagnosis service of MyASUS before 3.1.2.0 allows privilege escalation.

- [https://github.com/DShankle/CVE-2022-22814_PoC](https://github.com/DShankle/CVE-2022-22814_PoC) :  ![starts](https://img.shields.io/github/stars/DShankle/CVE-2022-22814_PoC.svg) ![forks](https://img.shields.io/github/forks/DShankle/CVE-2022-22814_PoC.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/jpts/CVE-2022-0847-DirtyPipe-Container-Breakout](https://github.com/jpts/CVE-2022-0847-DirtyPipe-Container-Breakout) :  ![starts](https://img.shields.io/github/stars/jpts/CVE-2022-0847-DirtyPipe-Container-Breakout.svg) ![forks](https://img.shields.io/github/forks/jpts/CVE-2022-0847-DirtyPipe-Container-Breakout.svg)


## CVE-2021-36260
 A command injection vulnerability in the web server of some Hikvision product. Due to the insufficient input validation, attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.

- [https://github.com/TakenoSite/Simple-CVE-2021-36260](https://github.com/TakenoSite/Simple-CVE-2021-36260) :  ![starts](https://img.shields.io/github/stars/TakenoSite/Simple-CVE-2021-36260.svg) ![forks](https://img.shields.io/github/forks/TakenoSite/Simple-CVE-2021-36260.svg)


## CVE-2021-25804
 A NULL-pointer dereference in &quot;Open&quot; in avi.c of VideoLAN VLC Media Player 3.0.11 can a denial of service (DOS) in the application.

- [https://github.com/DShankle/VLC_CVE-2021-25804_Analysis](https://github.com/DShankle/VLC_CVE-2021-25804_Analysis) :  ![starts](https://img.shields.io/github/stars/DShankle/VLC_CVE-2021-25804_Analysis.svg) ![forks](https://img.shields.io/github/forks/DShankle/VLC_CVE-2021-25804_Analysis.svg)


## CVE-2021-25801
 A buffer overflow vulnerability in the __Parse_indx component of VideoLAN VLC Media Player 3.0.11 allows attackers to cause an out-of-bounds read via a crafted .avi file.

- [https://github.com/DShankle/VLC_CVE-2021-25801_Analysis](https://github.com/DShankle/VLC_CVE-2021-25801_Analysis) :  ![starts](https://img.shields.io/github/stars/DShankle/VLC_CVE-2021-25801_Analysis.svg) ![forks](https://img.shields.io/github/forks/DShankle/VLC_CVE-2021-25801_Analysis.svg)


## CVE-2020-9715
 Adobe Acrobat and Reader versions 2020.009.20074 and earlier, 2020.001.30002, 2017.011.30171 and earlier, and 2015.006.30523 and earlier have an use-after-free vulnerability. Successful exploitation could lead to arbitrary code execution .

- [https://github.com/WonjunChun/CVE-2020-9715](https://github.com/WonjunChun/CVE-2020-9715) :  ![starts](https://img.shields.io/github/stars/WonjunChun/CVE-2020-9715.svg) ![forks](https://img.shields.io/github/forks/WonjunChun/CVE-2020-9715.svg)


## CVE-2020-0674
 A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer, aka 'Scripting Engine Memory Corruption Vulnerability'. This CVE ID is unique from CVE-2020-0673, CVE-2020-0710, CVE-2020-0711, CVE-2020-0712, CVE-2020-0713, CVE-2020-0767.

- [https://github.com/suspiciousbytes/CVE-2020-0674](https://github.com/suspiciousbytes/CVE-2020-0674) :  ![starts](https://img.shields.io/github/stars/suspiciousbytes/CVE-2020-0674.svg) ![forks](https://img.shields.io/github/forks/suspiciousbytes/CVE-2020-0674.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/Z-0ne/ScanS2-045-Nmap](https://github.com/Z-0ne/ScanS2-045-Nmap) :  ![starts](https://img.shields.io/github/stars/Z-0ne/ScanS2-045-Nmap.svg) ![forks](https://img.shields.io/github/forks/Z-0ne/ScanS2-045-Nmap.svg)
- [https://github.com/SpiderMate/Stutsfi](https://github.com/SpiderMate/Stutsfi) :  ![starts](https://img.shields.io/github/stars/SpiderMate/Stutsfi.svg) ![forks](https://img.shields.io/github/forks/SpiderMate/Stutsfi.svg)
- [https://github.com/pasannirmana/Aspire](https://github.com/pasannirmana/Aspire) :  ![starts](https://img.shields.io/github/stars/pasannirmana/Aspire.svg) ![forks](https://img.shields.io/github/forks/pasannirmana/Aspire.svg)
- [https://github.com/random-robbie/CVE-2017-5638](https://github.com/random-robbie/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/random-robbie/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/random-robbie/CVE-2017-5638.svg)


## CVE-2013-1965
 Apache Struts Showcase App 2.0.0 through 2.3.13, as used in Struts 2 before 2.3.14.3, allows remote attackers to execute arbitrary OGNL code via a crafted parameter name that is not properly handled when invoking a redirect.

- [https://github.com/cinno/CVE-2013-1965](https://github.com/cinno/CVE-2013-1965) :  ![starts](https://img.shields.io/github/stars/cinno/CVE-2013-1965.svg) ![forks](https://img.shields.io/github/forks/cinno/CVE-2013-1965.svg)


## CVE-2010-2553
 The Cinepak codec in Microsoft Windows XP SP2 and SP3, Windows Vista SP1 and SP2, and Windows 7 does not properly decompress media files, which allows remote attackers to execute arbitrary code via a crafted file, aka &quot;Cinepak Codec Decompression Vulnerability.&quot;

- [https://github.com/Sunqiz/CVE-2010-2553-reproduction](https://github.com/Sunqiz/CVE-2010-2553-reproduction) :  ![starts](https://img.shields.io/github/stars/Sunqiz/CVE-2010-2553-reproduction.svg) ![forks](https://img.shields.io/github/forks/Sunqiz/CVE-2010-2553-reproduction.svg)


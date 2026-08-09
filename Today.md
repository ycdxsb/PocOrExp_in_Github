# Update 2026-08-09
## CVE-2026-71557
 go-git is an extensible git implementation library written in pure Go. Prior to 5.19.2 and 6.0.0-alpha.5, reference names are not sanitized before being used to construct on-disk paths under the reference storage directory, so a maliciously crafted reference name (for example containing directory-traversal sequences) can cause go-git to write files outside the intended reference storage directory. Versions 5.19.2 and 6.0.0-alpha.5 fix the issue.

- [https://github.com/Saku0512/CVE-2026-71557-poc](https://github.com/Saku0512/CVE-2026-71557-poc) :  ![starts](https://img.shields.io/github/stars/Saku0512/CVE-2026-71557-poc.svg) ![forks](https://img.shields.io/github/forks/Saku0512/CVE-2026-71557-poc.svg)


## CVE-2026-71554
 h2 is a pure-Python implementation of a HTTP/2 protocol stack. Versions up to and including 4.4.0 accept request header blocks containing more than one Host header, and forward every Host header to the consuming application. Where the consumer downgrades HTTP/2 to HTTP/1.1, the resulting request carries two Host header lines, providing a request smuggling primitive. This issue is fixed in version 4.4.1.

- [https://github.com/SunandM/poc-h2-CVE-2026-71554](https://github.com/SunandM/poc-h2-CVE-2026-71554) :  ![starts](https://img.shields.io/github/stars/SunandM/poc-h2-CVE-2026-71554.svg) ![forks](https://img.shields.io/github/forks/SunandM/poc-h2-CVE-2026-71554.svg)
- [https://github.com/SunandM/poc-h2-duplicate-host](https://github.com/SunandM/poc-h2-duplicate-host) :  ![starts](https://img.shields.io/github/stars/SunandM/poc-h2-duplicate-host.svg) ![forks](https://img.shields.io/github/forks/SunandM/poc-h2-duplicate-host.svg)


## CVE-2026-70638
 llama.cpp builds b1886 through b7445 contain an integer overflow vulnerability in the LLaMA-Android JNI wrapper where the new_1batch() function multiplies sizeof(llama_seq_id) by an attacker-controlled n_seq_max parameter without overflow validation, causing heap buffer allocation to wrap and allocate insufficient memory. Attackers can exploit this by providing a crafted n_seq_max value through a malicious model file or JNI call to trigger heap corruption and achieve denial of service or arbitrary code execution on Android applications using the LLaMA-Android binding.

- [https://github.com/Hunt-Benito/one-multiply-too-many-cve-2026-70638-llama-cpp-android-jni-integer-overflow](https://github.com/Hunt-Benito/one-multiply-too-many-cve-2026-70638-llama-cpp-android-jni-integer-overflow) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/one-multiply-too-many-cve-2026-70638-llama-cpp-android-jni-integer-overflow.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/one-multiply-too-many-cve-2026-70638-llama-cpp-android-jni-integer-overflow.svg)


## CVE-2026-67822
 Tenda W6-S 1.0.0.4(510) contains a stack-based buffer overflow vulnerability in the /goform/wifiSSIDset endpoint. The function formwrlSSIDset uses sprintf to copy user-controlled 'GO' and 'index' parameters into a 64-byte stack buffer without length restriction, leading to stack overflow.

- [https://github.com/Hunt-Benito/go-without-bounds-cve-2026-67822-stack-overflow-in-tenda-w6-s-wifissidset](https://github.com/Hunt-Benito/go-without-bounds-cve-2026-67822-stack-overflow-in-tenda-w6-s-wifissidset) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/go-without-bounds-cve-2026-67822-stack-overflow-in-tenda-w6-s-wifissidset.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/go-without-bounds-cve-2026-67822-stack-overflow-in-tenda-w6-s-wifissidset.svg)


## CVE-2026-64640
Exploitation requires an authenticated principal with table- or view-registration privileges.

- [https://github.com/oscerd/CVE-2026-64640](https://github.com/oscerd/CVE-2026-64640) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-64640.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-64640.svg)


## CVE-2026-64638
Discovered and responsibly disclosed by [the team at pwn.ai](https://pwn.ai/).

- [https://github.com/5yu4n/CVE-2026-64638](https://github.com/5yu4n/CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/5yu4n/CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/5yu4n/CVE-2026-64638.svg)
- [https://github.com/0xBlackash/CVE-2026-64638](https://github.com/0xBlackash/CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-64638.svg)
- [https://github.com/Boreas37/CVE-2026-64638-PoC](https://github.com/Boreas37/CVE-2026-64638-PoC) :  ![starts](https://img.shields.io/github/stars/Boreas37/CVE-2026-64638-PoC.svg) ![forks](https://img.shields.io/github/forks/Boreas37/CVE-2026-64638-PoC.svg)
- [https://github.com/ZSecur1ty/XSS2Shell-CVE-2026-64638](https://github.com/ZSecur1ty/XSS2Shell-CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/ZSecur1ty/XSS2Shell-CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/ZSecur1ty/XSS2Shell-CVE-2026-64638.svg)
- [https://github.com/Linuxhackingid-official/XSS2Shell-CVE-2026-64638](https://github.com/Linuxhackingid-official/XSS2Shell-CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/Linuxhackingid-official/XSS2Shell-CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/Linuxhackingid-official/XSS2Shell-CVE-2026-64638.svg)
- [https://github.com/686f6c61/POC-WP-XSS2Shell-CVE-2026-64638](https://github.com/686f6c61/POC-WP-XSS2Shell-CVE-2026-64638) :  ![starts](https://img.shields.io/github/stars/686f6c61/POC-WP-XSS2Shell-CVE-2026-64638.svg) ![forks](https://img.shields.io/github/forks/686f6c61/POC-WP-XSS2Shell-CVE-2026-64638.svg)
- [https://github.com/renzi25031469/CVE-2026-64638-WordPress-Core-XSS2Shell](https://github.com/renzi25031469/CVE-2026-64638-WordPress-Core-XSS2Shell) :  ![starts](https://img.shields.io/github/stars/renzi25031469/CVE-2026-64638-WordPress-Core-XSS2Shell.svg) ![forks](https://img.shields.io/github/forks/renzi25031469/CVE-2026-64638-WordPress-Core-XSS2Shell.svg)
- [https://github.com/wordsec/XSS2Shell](https://github.com/wordsec/XSS2Shell) :  ![starts](https://img.shields.io/github/stars/wordsec/XSS2Shell.svg) ![forks](https://img.shields.io/github/forks/wordsec/XSS2Shell.svg)


## CVE-2026-64564
branch can never reuse a freed transport.

- [https://github.com/HackSpeak/CVE-2026-64564](https://github.com/HackSpeak/CVE-2026-64564) :  ![starts](https://img.shields.io/github/stars/HackSpeak/CVE-2026-64564.svg) ![forks](https://img.shields.io/github/forks/HackSpeak/CVE-2026-64564.svg)
- [https://github.com/ethanolgolf/CVE-2026-64564](https://github.com/ethanolgolf/CVE-2026-64564) :  ![starts](https://img.shields.io/github/stars/ethanolgolf/CVE-2026-64564.svg) ![forks](https://img.shields.io/github/forks/ethanolgolf/CVE-2026-64564.svg)


## CVE-2026-64561
far from ideal; that flaw will be addressed separately.

- [https://github.com/HORKimhab/CVE-2026-64561](https://github.com/HORKimhab/CVE-2026-64561) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-64561.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-64561.svg)
- [https://github.com/Aoripus-LTD/Zapscape-Fix](https://github.com/Aoripus-LTD/Zapscape-Fix) :  ![starts](https://img.shields.io/github/stars/Aoripus-LTD/Zapscape-Fix.svg) ![forks](https://img.shields.io/github/forks/Aoripus-LTD/Zapscape-Fix.svg)
- [https://github.com/aarif450/aarif450.github.io](https://github.com/aarif450/aarif450.github.io) :  ![starts](https://img.shields.io/github/stars/aarif450/aarif450.github.io.svg) ![forks](https://img.shields.io/github/forks/aarif450/aarif450.github.io.svg)
- [https://github.com/aarif450/Zapscape](https://github.com/aarif450/Zapscape) :  ![starts](https://img.shields.io/github/stars/aarif450/Zapscape.svg) ![forks](https://img.shields.io/github/forks/aarif450/Zapscape.svg)


## CVE-2026-63077
 In JetBrains TeamCity before 2026.1.3, 2025.11.7 unauthenticated remote code execution was possible via the agent polling protocol

- [https://github.com/sfewer-r7/CVE-2026-63077](https://github.com/sfewer-r7/CVE-2026-63077) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/CVE-2026-63077.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/CVE-2026-63077.svg)
- [https://github.com/BoredHackerBlog/teamcity-CVE-2026-63077-pcap](https://github.com/BoredHackerBlog/teamcity-CVE-2026-63077-pcap) :  ![starts](https://img.shields.io/github/stars/BoredHackerBlog/teamcity-CVE-2026-63077-pcap.svg) ![forks](https://img.shields.io/github/forks/BoredHackerBlog/teamcity-CVE-2026-63077-pcap.svg)


## CVE-2026-59889
 jackson-databind contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor. From 2.18.0 until 2.18.9, 2.21.5, 2.22.1, 3.1.5, and 3.2.1, UnwrappedPropertyHandler.processUnwrapped() replays buffered JSON for a @JsonUnwrapped property and calls prop.deserializeAndSet() without a prop.visibleInView(ctxt.getActiveView()) guard, allowing a property annotated with both @JsonView and @JsonUnwrapped to be written from attacker JSON under a less-privileged active view. This issue is fixed in versions 2.18.9, 2.21.5, 2.22.1, 3.1.5, and 3.2.1.

- [https://github.com/xiaoqiMikko/jackson-check](https://github.com/xiaoqiMikko/jackson-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/jackson-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/jackson-check.svg)


## CVE-2026-59888
 jackson-databind contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor. From 2.15.0 until 2.18.8, 2.21.4, and 3.1.4, Java Records using a PropertyNamingStrategy can bypass @JsonIgnore because POJOPropertiesCollector._removeUnwantedIgnorals() records an ignored component under its original implicit name before _renameUsing() applies the naming strategy, allowing the renamed JSON key to be assigned to the Record constructor parameter. This issue is fixed in versions 2.18.8, 2.21.4, and 3.1.4.

- [https://github.com/xiaoqiMikko/jackson-check](https://github.com/xiaoqiMikko/jackson-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/jackson-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/jackson-check.svg)


## CVE-2026-58644
 Deserialization of untrusted data in Microsoft Office SharePoint allows an unauthorized attacker to execute code over a network.

- [https://github.com/WismanSec/sharepoint-2026-poc](https://github.com/WismanSec/sharepoint-2026-poc) :  ![starts](https://img.shields.io/github/stars/WismanSec/sharepoint-2026-poc.svg) ![forks](https://img.shields.io/github/forks/WismanSec/sharepoint-2026-poc.svg)


## CVE-2026-56164
 Missing authentication for critical function in Microsoft Office SharePoint allows an unauthorized attacker to elevate privileges over a network.

- [https://github.com/WismanSec/sharepoint-2026-poc](https://github.com/WismanSec/sharepoint-2026-poc) :  ![starts](https://img.shields.io/github/stars/WismanSec/sharepoint-2026-poc.svg) ![forks](https://img.shields.io/github/forks/WismanSec/sharepoint-2026-poc.svg)


## CVE-2026-55957
Users are recommended to upgrade to version 11.0.5, 10.1.37 or 9.0.101, which fixes the issue.

- [https://github.com/mdvpat/CVE-2026-55957-PoC](https://github.com/mdvpat/CVE-2026-55957-PoC) :  ![starts](https://img.shields.io/github/stars/mdvpat/CVE-2026-55957-PoC.svg) ![forks](https://img.shields.io/github/forks/mdvpat/CVE-2026-55957-PoC.svg)


## CVE-2026-49844
Users are advised to upgrade to Apache Log4j API 2.25.5 or 2.26.1, both of which emit RFC 8259-compliant JSON for non-finite values.

- [https://github.com/xiaoqiMikko/log4j-check](https://github.com/xiaoqiMikko/log4j-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/log4j-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/log4j-check.svg)


## CVE-2026-45659
 Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized attacker to execute code over a network.

- [https://github.com/WismanSec/sharepoint-2026-poc](https://github.com/WismanSec/sharepoint-2026-poc) :  ![starts](https://img.shields.io/github/stars/WismanSec/sharepoint-2026-poc.svg) ![forks](https://img.shields.io/github/forks/WismanSec/sharepoint-2026-poc.svg)


## CVE-2026-45185
 Exim before 4.99.3, in certain GnuTLS configurations, has a remotely reachable use-after-free in the BDAT body parsing path. It is triggered when a client sends a TLS close_notify mid-body during a CHUNKING transfer, followed by a final cleartext byte on the same TCP connection. This can lead to heap corruption. An unauthenticated network attacker exploiting this vulnerability could execute arbitrary code.

- [https://github.com/0init/CVE-2026-45185](https://github.com/0init/CVE-2026-45185) :  ![starts](https://img.shields.io/github/stars/0init/CVE-2026-45185.svg) ![forks](https://img.shields.io/github/forks/0init/CVE-2026-45185.svg)


## CVE-2026-44613
 Cross-Site Request Forgery (CSRF) vulnerability in Apache Zeppelin. The default CORS configuration allowed cross-origin state-changing requests and accepted text/plain request bodies, allowing an attacker who lures an authenticated user to a                   malicious site to perform actions on the user's behalf through REST and WebSocket endpoints. This issue affects Apache Zeppelin versions 0.6.0 through 0.12.0. Users are recommended to upgrade to version 0.12.1, which fixes this issue.

- [https://github.com/HORKimhab/CVE-2026-44613](https://github.com/HORKimhab/CVE-2026-44613) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-44613.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-44613.svg)


## CVE-2026-43499
  	changelog ]

- [https://github.com/Meowkis/tcp-zerocopy-sm](https://github.com/Meowkis/tcp-zerocopy-sm) :  ![starts](https://img.shields.io/github/stars/Meowkis/tcp-zerocopy-sm.svg) ![forks](https://img.shields.io/github/forks/Meowkis/tcp-zerocopy-sm.svg)


## CVE-2026-41242
 protobufjs compiles protobuf definitions into JavaScript (JS) functions. In versions prior to 8.0.1 and 7.5.5, attackers can inject arbitrary code in the "type" fields of protobuf definitions, which will then execute during object decoding using that definition. Versions 8.0.1 and 7.5.5 patch the issue.

- [https://github.com/Giangdurian/CVE-2026-41242](https://github.com/Giangdurian/CVE-2026-41242) :  ![starts](https://img.shields.io/github/stars/Giangdurian/CVE-2026-41242.svg) ![forks](https://img.shields.io/github/forks/Giangdurian/CVE-2026-41242.svg)


## CVE-2026-34481
Note: The fix released in version 2.25.4 did not cover all affected code paths. CVE-2026-49844 was assigned to the remaining issue, which concerns the MapMessage.asJson() serialization in Apache Log4j API and is fixed in versions 2.25.5 and 2.26.1.

- [https://github.com/xiaoqiMikko/log4j-check](https://github.com/xiaoqiMikko/log4j-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/log4j-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/log4j-check.svg)


## CVE-2026-34480
Users are advised to upgrade to Apache Log4j Core 2.25.4, which corrects this issue by sanitizing forbidden characters before XML output.

- [https://github.com/xiaoqiMikko/log4j-check](https://github.com/xiaoqiMikko/log4j-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/log4j-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/log4j-check.svg)


## CVE-2026-34479
Note: The Apache Log4j 1-to-Log4j 2 bridge is deprecated and will not be present in Log4j 3. Users are encouraged to consult the  Log4j 1 to Log4j 2 migration guide https://logging.apache.org/log4j/2.x/migrate-from-log4j1.html , and specifically the section on eliminating reliance on the bridge.

- [https://github.com/xiaoqiMikko/log4j-check](https://github.com/xiaoqiMikko/log4j-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/log4j-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/log4j-check.svg)


## CVE-2026-34478
Users are advised to upgrade to Apache Log4j Core 2.25.4, which corrects this issue.

- [https://github.com/xiaoqiMikko/log4j-check](https://github.com/xiaoqiMikko/log4j-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/log4j-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/log4j-check.svg)


## CVE-2026-34477
Users are advised to upgrade to Apache Log4j Core 2.25.4, which corrects this issue.

- [https://github.com/xiaoqiMikko/log4j-check](https://github.com/xiaoqiMikko/log4j-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/log4j-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/log4j-check.svg)


## CVE-2026-18953
To remediate this issue, users should upgrade to version 0.1.5 or later.

- [https://github.com/ronamosa/CVE-2026-18953](https://github.com/ronamosa/CVE-2026-18953) :  ![starts](https://img.shields.io/github/stars/ronamosa/CVE-2026-18953.svg) ![forks](https://img.shields.io/github/forks/ronamosa/CVE-2026-18953.svg)


## CVE-2026-9082
This issue affects Drupal core: from 8.9.0 before 10.4.10, from 10.5.0 before 10.5.10, from 10.6.0 before 10.6.9, from 11.0.0 before 11.1.10, from 11.2.0 before 11.2.12, from 11.3.0 before 11.3.10.

- [https://github.com/ridhinva/drupal-jsonapi-sqli-scanner](https://github.com/ridhinva/drupal-jsonapi-sqli-scanner) :  ![starts](https://img.shields.io/github/stars/ridhinva/drupal-jsonapi-sqli-scanner.svg) ![forks](https://img.shields.io/github/forks/ridhinva/drupal-jsonapi-sqli-scanner.svg)


## CVE-2026-5785
 Zohocorp ManageEngine PAM360 versions before 8531 and ManageEngine Password Manager Pro versions from 8600 to 13230 are vulnerable to Authenticated SQL injection in the query report module.

- [https://github.com/zylideum/CVE-2026-57858](https://github.com/zylideum/CVE-2026-57858) :  ![starts](https://img.shields.io/github/stars/zylideum/CVE-2026-57858.svg) ![forks](https://img.shields.io/github/forks/zylideum/CVE-2026-57858.svg)


## CVE-2026-3854
 An improper neutralization of special elements vulnerability was identified in GitHub Enterprise Server that allowed an attacker with push access to a repository to achieve remote code execution on the instance. During a git push operation, user-supplied push option values were not properly sanitized before being included in internal service headers. Because the internal header format used a delimiter character that could also appear in user input, an attacker could inject additional metadata fields through crafted push option values. This vulnerability was reported via the GitHub Bug Bounty program and has been fixed in GitHub Enterprise Server versions 3.14.25, 3.15.20, 3.16.16, 3.17.13, 3.18.7 and 3.19.4.

- [https://github.com/ridhinva/ghe-push-option-rce-scanner](https://github.com/ridhinva/ghe-push-option-rce-scanner) :  ![starts](https://img.shields.io/github/stars/ridhinva/ghe-push-option-rce-scanner.svg) ![forks](https://img.shields.io/github/forks/ridhinva/ghe-push-option-rce-scanner.svg)


## CVE-2026-1731
 BeyondTrust Remote Support (RS) and certain older versions of Privileged Remote Access (PRA) contain a critical pre-authentication remote code execution vulnerability. By sending specially crafted requests, an unauthenticated remote attacker may be able to execute operating system commands in the context of the site user.

- [https://github.com/ridhinva/beyondtrust-rce-scanner](https://github.com/ridhinva/beyondtrust-rce-scanner) :  ![starts](https://img.shields.io/github/stars/ridhinva/beyondtrust-rce-scanner.svg) ![forks](https://img.shields.io/github/forks/ridhinva/beyondtrust-rce-scanner.svg)


## CVE-2026-0300
Prisma Access, Cloud NGFW and Panorama appliances are not impacted by this vulnerability.

- [https://github.com/ridhinva/panos-captive-portal-rce](https://github.com/ridhinva/panos-captive-portal-rce) :  ![starts](https://img.shields.io/github/stars/ridhinva/panos-captive-portal-rce.svg) ![forks](https://img.shields.io/github/forks/ridhinva/panos-captive-portal-rce.svg)


## CVE-2026-0049
 In onHeaderDecoded of LocalImageResolver.java, there is a possible persistent denial of service due to resource exhaustion. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/R3n3r0/CVE-2026-0049](https://github.com/R3n3r0/CVE-2026-0049) :  ![starts](https://img.shields.io/github/stars/R3n3r0/CVE-2026-0049.svg) ![forks](https://img.shields.io/github/forks/R3n3r0/CVE-2026-0049.svg)


## CVE-2025-68645
 A Local File Inclusion (LFI) vulnerability exists in the Webmail Classic UI of Zimbra Collaboration (ZCS) 10.0 and 10.1 because of improper handling of user-supplied request parameters in the RestFilter servlet. An unauthenticated remote attacker can craft requests to the /h/rest endpoint to influence internal request dispatching, allowing inclusion of arbitrary files from the WebRoot directory.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-68645](https://github.com/Ashwesker/Ashwesker-CVE-2025-68645) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-68645.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-68645.svg)


## CVE-2025-68161
As an alternative mitigation, the Socket Appender may be configured to use a private or restricted trust root to limit the set of trusted certificates.

- [https://github.com/xiaoqiMikko/log4j-check](https://github.com/xiaoqiMikko/log4j-check) :  ![starts](https://img.shields.io/github/stars/xiaoqiMikko/log4j-check.svg) ![forks](https://img.shields.io/github/forks/xiaoqiMikko/log4j-check.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-patch-package.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-yarn-workspaces.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-resolutions.svg)


## CVE-2025-34291
 Langflow versions up to and including 1.6.9 contain a chained vulnerability that enables account takeover and remote code execution. An overly permissive CORS configuration (allow_origins='*' with allow_credentials=True) combined with a refresh token cookie configured as SameSite=None allows a malicious webpage to perform cross-origin requests that include credentials and successfully call the refresh endpoint. An attacker-controlled origin can therefore obtain fresh access_token / refresh_token pairs for a victim session. Obtained tokens permit access to authenticated endpoints — including built-in code-execution functionality — allowing the attacker to execute arbitrary code and achieve full system compromise.

- [https://github.com/ridhinva/langflow-cors-scanner](https://github.com/ridhinva/langflow-cors-scanner) :  ![starts](https://img.shields.io/github/stars/ridhinva/langflow-cors-scanner.svg) ![forks](https://img.shields.io/github/forks/ridhinva/langflow-cors-scanner.svg)


## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

- [https://github.com/EzraMansor/CVE-2025-32432-PoC](https://github.com/EzraMansor/CVE-2025-32432-PoC) :  ![starts](https://img.shields.io/github/stars/EzraMansor/CVE-2025-32432-PoC.svg) ![forks](https://img.shields.io/github/forks/EzraMansor/CVE-2025-32432-PoC.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Heimd411/CVE-2025-29927-PoC](https://github.com/Heimd411/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/Heimd411/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/Heimd411/CVE-2025-29927-PoC.svg)


## CVE-2024-23692
 Rejetto HTTP File Server, up to and including version 2.3m, is vulnerable to a template injection vulnerability. This vulnerability allows a remote, unauthenticated attacker to execute arbitrary commands on the affected system by sending a specially crafted HTTP request. As of the CVE assignment date, Rejetto HFS 2.3m is no longer supported.

- [https://github.com/sandimfz/CVE-2024-23692](https://github.com/sandimfz/CVE-2024-23692) :  ![starts](https://img.shields.io/github/stars/sandimfz/CVE-2024-23692.svg) ![forks](https://img.shields.io/github/forks/sandimfz/CVE-2024-23692.svg)


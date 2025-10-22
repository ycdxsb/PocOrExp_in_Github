# Update 2025-10-22
## CVE-2025-61456
 A Cross-Site Scripting (XSS) vulnerability exists in Bhabishya-123 E-commerce 1.0, specifically within the index endpoint. Unsanitized input in the /index parameter is directly reflected back into the response HTML, allowing attackers to execute arbitrary JavaScript in the browser of a user who visits a malicious link or submits a crafted request.

- [https://github.com/tansique-17/CVE-2025-61456](https://github.com/tansique-17/CVE-2025-61456) :  ![starts](https://img.shields.io/github/stars/tansique-17/CVE-2025-61456.svg) ![forks](https://img.shields.io/github/forks/tansique-17/CVE-2025-61456.svg)


## CVE-2025-61455
 SQL Injection vulnerability exists in Bhabishya-123 E-commerce 1.0, specifically within the signup.inc.php endpoint. The application directly incorporates unsanitized user inputs into SQL queries, allowing unauthenticated attackers to bypass authentication and gain full access.

- [https://github.com/tansique-17/CVE-2025-61455](https://github.com/tansique-17/CVE-2025-61455) :  ![starts](https://img.shields.io/github/stars/tansique-17/CVE-2025-61455.svg) ![forks](https://img.shields.io/github/forks/tansique-17/CVE-2025-61455.svg)


## CVE-2025-61454
 A Cross-Site Scripting (XSS) vulnerability exists in Bhabishya-123 E-commerce 1.0, specifically within the search endpoint. Unsanitized input in the /search parameter is directly reflected back into the response HTML, allowing attackers to execute arbitrary JavaScript in the browser of a user who visits a malicious link or submits a crafted request.

- [https://github.com/tansique-17/CVE-2025-61454](https://github.com/tansique-17/CVE-2025-61454) :  ![starts](https://img.shields.io/github/stars/tansique-17/CVE-2025-61454.svg) ![forks](https://img.shields.io/github/forks/tansique-17/CVE-2025-61454.svg)


## CVE-2025-61303
 Hatching Triage Sandbox Windows 10 build 2004 (2025-08-14) and Windows 10 LTSC 2021(2025-08-14) contains a vulnerability in its Windows behavioral analysis engine that allows a submitted malware sample to evade detection and cause denial-of-analysis. The vulnerability is triggered when a sample recursively spawns a large number of child processes, generating high log volume and exhausting system resources. As a result, key malicious behavior, including PowerShell execution and reverse shell activity, may not be recorded or reported, misleading analysts and compromising the integrity and availability of sandboxed analysis results.

- [https://github.com/eGkritsis/CVE-2025-61303](https://github.com/eGkritsis/CVE-2025-61303) :  ![starts](https://img.shields.io/github/stars/eGkritsis/CVE-2025-61303.svg) ![forks](https://img.shields.io/github/forks/eGkritsis/CVE-2025-61303.svg)


## CVE-2025-61301
 Denial-of-analysis in reporting/mongodb.py and reporting/jsondump.py in CAPEv2 (commit 52e4b43, on 2025-05-17) allows attackers who can submit samples to cause incomplete or missing behavioral analysis reports by generating deeply nested or oversized behavior data that trigger MongoDB BSON limits or orjson recursion errors when the sample executes in the sandbox.

- [https://github.com/eGkritsis/CVE-2025-61301](https://github.com/eGkritsis/CVE-2025-61301) :  ![starts](https://img.shields.io/github/stars/eGkritsis/CVE-2025-61301.svg) ![forks](https://img.shields.io/github/forks/eGkritsis/CVE-2025-61301.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/keeganparr1/CVE-2025-59287-hawktrace](https://github.com/keeganparr1/CVE-2025-59287-hawktrace) :  ![starts](https://img.shields.io/github/stars/keeganparr1/CVE-2025-59287-hawktrace.svg) ![forks](https://img.shields.io/github/forks/keeganparr1/CVE-2025-59287-hawktrace.svg)


## CVE-2025-59230
 Improper access control in Windows Remote Access Connection Manager allows an authorized attacker to elevate privileges locally.

- [https://github.com/moegameka/CVE-2025-59230](https://github.com/moegameka/CVE-2025-59230) :  ![starts](https://img.shields.io/github/stars/moegameka/CVE-2025-59230.svg) ![forks](https://img.shields.io/github/forks/moegameka/CVE-2025-59230.svg)


## CVE-2025-56224
 A lack of rate limiting in the One-Time Password (OTP) verification endpoint of SigningHub v8.6.8 allows attackers to bypass verification via a bruteforce attack.

- [https://github.com/saykino/CVE-2025-56224](https://github.com/saykino/CVE-2025-56224) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-56224.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-56224.svg)


## CVE-2025-56223
 A lack of rate limiting in the component /Home/UploadStreamDocument of SigningHub v8.6.8 allows attackers to cause a Denial of Service (DoS) via uploading an excessive number of files.

- [https://github.com/saykino/CVE-2025-56223](https://github.com/saykino/CVE-2025-56223) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-56223.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-56223.svg)


## CVE-2025-56219
 Incorrect access control in SigningHub v8.6.8 allows attackers to arbitrarily add user accounts without any rate limiting. This can lead to a resource exhaustion and a Denial of Service (DoS) when an excessively large number of user accounts are created.

- [https://github.com/saykino/CVE-2025-56219](https://github.com/saykino/CVE-2025-56219) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2025-56219.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2025-56219.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/toshithh/CVE-2025-32433](https://github.com/toshithh/CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/toshithh/CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/toshithh/CVE-2025-32433.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/Lusensec/CVE-2025-30208](https://github.com/Lusensec/CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/Lusensec/CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/Lusensec/CVE-2025-30208.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/achnouri/Editor-CTF-writre-up](https://github.com/achnouri/Editor-CTF-writre-up) :  ![starts](https://img.shields.io/github/stars/achnouri/Editor-CTF-writre-up.svg) ![forks](https://img.shields.io/github/forks/achnouri/Editor-CTF-writre-up.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/pirenga/CVE-2025-24813](https://github.com/pirenga/CVE-2025-24813) :  ![starts](https://img.shields.io/github/stars/pirenga/CVE-2025-24813.svg) ![forks](https://img.shields.io/github/forks/pirenga/CVE-2025-24813.svg)


## CVE-2025-11391
 The PPOM – Product Addons & Custom Fields for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the image cropper functionality in all versions up to, and including, 33.0.15. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. While the vulnerable code is in the free version, this only affected users with the paid version of the software installed and activated.

- [https://github.com/aritlhq/CVE-2025-11391](https://github.com/aritlhq/CVE-2025-11391) :  ![starts](https://img.shields.io/github/stars/aritlhq/CVE-2025-11391.svg) ![forks](https://img.shields.io/github/forks/aritlhq/CVE-2025-11391.svg)


## CVE-2025-10041
 The Flex QR Code Generator plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in thesave_qr_code_to_db() function in all versions up to, and including, 1.2.5. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/DExplo1ted/CVE-2025-10041-POC](https://github.com/DExplo1ted/CVE-2025-10041-POC) :  ![starts](https://img.shields.io/github/stars/DExplo1ted/CVE-2025-10041-POC.svg) ![forks](https://img.shields.io/github/forks/DExplo1ted/CVE-2025-10041-POC.svg)


## CVE-2025-9744
 A weakness has been identified in Campcodes Online Loan Management System 1.0. The affected element is an unknown function of the file /ajax.php?action=login. Executing manipulation of the argument Username can lead to sql injection. The attack can be launched remotely. The exploit has been made available to the public and could be exploited.

- [https://github.com/godfatherofexps/CVE-2025-9744-PoC](https://github.com/godfatherofexps/CVE-2025-9744-PoC) :  ![starts](https://img.shields.io/github/stars/godfatherofexps/CVE-2025-9744-PoC.svg) ![forks](https://img.shields.io/github/forks/godfatherofexps/CVE-2025-9744-PoC.svg)


## CVE-2024-36437
 The com.enflick.android.TextNow (aka TextNow: Call + Text Unlimited) application 24.17.0.2 for Android enables any installed application (with no permissions) to place phone calls without user interaction by sending a crafted intent via the com.enflick.android.TextNow.activities.DialerActivity component.

- [https://github.com/actuator/com.enflick.android.TextNow](https://github.com/actuator/com.enflick.android.TextNow) :  ![starts](https://img.shields.io/github/stars/actuator/com.enflick.android.TextNow.svg) ![forks](https://img.shields.io/github/forks/actuator/com.enflick.android.TextNow.svg)


## CVE-2024-27954
 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in WP Automatic Automatic allows Path Traversal, Server Side Request Forgery.This issue affects Automatic: from n/a through 3.92.0.

- [https://github.com/chsxthwik/CVE-2024-27954](https://github.com/chsxthwik/CVE-2024-27954) :  ![starts](https://img.shields.io/github/stars/chsxthwik/CVE-2024-27954.svg) ![forks](https://img.shields.io/github/forks/chsxthwik/CVE-2024-27954.svg)


## CVE-2024-27564
 pictureproxy.php in the dirk1983 mm1.ltd source code f9f4bbc allows SSRF via the url parameter. NOTE: the references section has an archived copy of pictureproxy.php from its original GitHub location, but the repository name might later change because it is misleading.

- [https://github.com/chsxthwik/CVE-2024-27564](https://github.com/chsxthwik/CVE-2024-27564) :  ![starts](https://img.shields.io/github/stars/chsxthwik/CVE-2024-27564.svg) ![forks](https://img.shields.io/github/forks/chsxthwik/CVE-2024-27564.svg)


## CVE-2024-23729
 The ColorOS Internet Browser com.heytap.browser application 45.10.3.4.1 for Android allows a remote attacker to execute arbitrary JavaScript code via the com.android.browser.RealBrowserActivity component.

- [https://github.com/actuator/com.heytap.browser](https://github.com/actuator/com.heytap.browser) :  ![starts](https://img.shields.io/github/stars/actuator/com.heytap.browser.svg) ![forks](https://img.shields.io/github/forks/actuator/com.heytap.browser.svg)


## CVE-2023-41991
 A certificate validation issue was addressed. This issue is fixed in macOS Ventura 13.6, iOS 16.7 and iPadOS 16.7. A malicious app may be able to bypass signature validation. Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 16.7.

- [https://github.com/itsgiddd/CVE-2023-41991](https://github.com/itsgiddd/CVE-2023-41991) :  ![starts](https://img.shields.io/github/stars/itsgiddd/CVE-2023-41991.svg) ![forks](https://img.shields.io/github/forks/itsgiddd/CVE-2023-41991.svg)


## CVE-2023-38873
 The commit 3730880 (April 2023) and v.0.9-beta1 of gugoan Economizzer is vulnerable to Clickjacking. Clickjacking, also known as a "UI redress attack", is when an attacker uses multiple transparent or opaque layers to trick a user into clicking on a button or link on another page when they were intending to click on the top-level page. Thus, the attacker is "hijacking" clicks meant for their page and routing them to another page, most likely owned by another application, domain, or both.

- [https://github.com/K9-Modz/CVE-2023-38873-G1](https://github.com/K9-Modz/CVE-2023-38873-G1) :  ![starts](https://img.shields.io/github/stars/K9-Modz/CVE-2023-38873-G1.svg) ![forks](https://img.shields.io/github/forks/K9-Modz/CVE-2023-38873-G1.svg)


## CVE-2017-6736
   There are workarounds that address these vulnerabilities.

- [https://github.com/plyrthn/CiscoIOSSNMPToolkit](https://github.com/plyrthn/CiscoIOSSNMPToolkit) :  ![starts](https://img.shields.io/github/stars/plyrthn/CiscoIOSSNMPToolkit.svg) ![forks](https://img.shields.io/github/forks/plyrthn/CiscoIOSSNMPToolkit.svg)
- [https://github.com/plyrthn/CiscoSpectreTakeover](https://github.com/plyrthn/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/plyrthn/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/plyrthn/CiscoSpectreTakeover.svg)


## CVE-2017-5753
 Systems with microprocessors utilizing speculative execution and branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.

- [https://github.com/plyrthn/CiscoSpectreTakeover](https://github.com/plyrthn/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/plyrthn/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/plyrthn/CiscoSpectreTakeover.svg)


## CVE-2017-5715
 Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis.

- [https://github.com/plyrthn/CiscoSpectreTakeover](https://github.com/plyrthn/CiscoSpectreTakeover) :  ![starts](https://img.shields.io/github/stars/plyrthn/CiscoSpectreTakeover.svg) ![forks](https://img.shields.io/github/forks/plyrthn/CiscoSpectreTakeover.svg)


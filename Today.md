# Update 2025-08-11
## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/behnamvanda/CVE-2025-32463](https://github.com/behnamvanda/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/behnamvanda/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/behnamvanda/CVE-2025-32463.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/AventurineJun/CVE-2025-29927-Research](https://github.com/AventurineJun/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/AventurineJun/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/AventurineJun/CVE-2025-29927-Research.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/D3Ext/CVE-2025-24893](https://github.com/D3Ext/CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/D3Ext/CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/D3Ext/CVE-2025-24893.svg)
- [https://github.com/Retro023/CVE-2025-24893-POC](https://github.com/Retro023/CVE-2025-24893-POC) :  ![starts](https://img.shields.io/github/stars/Retro023/CVE-2025-24893-POC.svg) ![forks](https://img.shields.io/github/forks/Retro023/CVE-2025-24893-POC.svg)


## CVE-2025-21298
 Windows OLE Remote Code Execution Vulnerability

- [https://github.com/B1ack4sh/Blackash-CVE-2025-21298](https://github.com/B1ack4sh/Blackash-CVE-2025-21298) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-21298.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-21298.svg)


## CVE-2025-4404
 A privilege escalation from host to domain vulnerability was found in the FreeIPA project. The FreeIPA package fails to validate the uniqueness of the `krbCanonicalName` for the admin account by default, allowing users to create services with the same canonical name as the REALM admin. When a successful attack happens, the user can retrieve a Kerberos ticket in the name of this service, containing the admin@REALM credential. This flaw allows an attacker to perform administrative tasks over the REALM, leading to access to sensitive data and sensitive data exfiltration.

- [https://github.com/Cyxow/CVE-2025-4404-POC](https://github.com/Cyxow/CVE-2025-4404-POC) :  ![starts](https://img.shields.io/github/stars/Cyxow/CVE-2025-4404-POC.svg) ![forks](https://img.shields.io/github/forks/Cyxow/CVE-2025-4404-POC.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/AventurineJun/CVE-2022-39299-Research](https://github.com/AventurineJun/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/AventurineJun/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/AventurineJun/CVE-2022-39299-Research.svg)


## CVE-2021-30809
 A use after free issue was addressed with improved memory management. This issue is fixed in Safari 15, tvOS 15, watchOS 8, iOS 15 and iPadOS 15. Processing maliciously crafted web content may lead to arbitrary code execution.

- [https://github.com/seregonwar/CVE-2021-30809-UAF](https://github.com/seregonwar/CVE-2021-30809-UAF) :  ![starts](https://img.shields.io/github/stars/seregonwar/CVE-2021-30809-UAF.svg) ![forks](https://img.shields.io/github/forks/seregonwar/CVE-2021-30809-UAF.svg)


## CVE-2019-13497
 One Identity Cloud Access Manager before 8.1.4 Hotfix 1 allows CSRF for logout requests.

- [https://github.com/FurqanKhan1/CVE-2019-13497](https://github.com/FurqanKhan1/CVE-2019-13497) :  ![starts](https://img.shields.io/github/stars/FurqanKhan1/CVE-2019-13497.svg) ![forks](https://img.shields.io/github/forks/FurqanKhan1/CVE-2019-13497.svg)


## CVE-2017-5941
 An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the unserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).

- [https://github.com/kylew1004/cve-2017-5941-poc-docker-lab](https://github.com/kylew1004/cve-2017-5941-poc-docker-lab) :  ![starts](https://img.shields.io/github/stars/kylew1004/cve-2017-5941-poc-docker-lab.svg) ![forks](https://img.shields.io/github/forks/kylew1004/cve-2017-5941-poc-docker-lab.svg)


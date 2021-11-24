# Update 2021-11-24
## CVE-2021-43557
 The uri-block plugin in Apache APISIX before 2.10.2 uses $request_uri without verification. The $request_uri is the full original request URI without normalization. This makes it possible to construct a URI to bypass the block list on some occasions. For instance, when the block list contains &quot;^/internal/&quot;, a URI like `//internal/` can be used to bypass it. Some other plugins also have the same issue. And it may affect the developer's custom plugin.

- [https://github.com/xvnpw/k8s-CVE-2021-43557-poc](https://github.com/xvnpw/k8s-CVE-2021-43557-poc) :  ![starts](https://img.shields.io/github/stars/xvnpw/k8s-CVE-2021-43557-poc.svg) ![forks](https://img.shields.io/github/forks/xvnpw/k8s-CVE-2021-43557-poc.svg)


## CVE-2021-42321
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/DarkSprings/CVE-2021-42321](https://github.com/DarkSprings/CVE-2021-42321) :  ![starts](https://img.shields.io/github/stars/DarkSprings/CVE-2021-42321.svg) ![forks](https://img.shields.io/github/forks/DarkSprings/CVE-2021-42321.svg)


## CVE-2021-41277
 Metabase is an open source data analytics platform. In affected versions a security issue has been discovered with the custom GeoJSON map (`admin-&gt;settings-&gt;maps-&gt;custom maps-&gt;add a map`) support and potential local file inclusion (including environment variables). URLs were not validated prior to being loaded. This issue is fixed in a new maintenance release (0.40.5 and 1.40.5), and any subsequent release after that. If you&#8217;re unable to upgrade immediately, you can mitigate this by including rules in your reverse proxy or load balancer or WAF to provide a validation filter before the application.

- [https://github.com/z3n70/CVE-2021-41277](https://github.com/z3n70/CVE-2021-41277) :  ![starts](https://img.shields.io/github/stars/z3n70/CVE-2021-41277.svg) ![forks](https://img.shields.io/github/forks/z3n70/CVE-2021-41277.svg)
- [https://github.com/kap1ush0n/CVE-2021-41277](https://github.com/kap1ush0n/CVE-2021-41277) :  ![starts](https://img.shields.io/github/stars/kap1ush0n/CVE-2021-41277.svg) ![forks](https://img.shields.io/github/forks/kap1ush0n/CVE-2021-41277.svg)
- [https://github.com/kaizensecurity/CVE-2021-41277](https://github.com/kaizensecurity/CVE-2021-41277) :  ![starts](https://img.shields.io/github/stars/kaizensecurity/CVE-2021-41277.svg) ![forks](https://img.shields.io/github/forks/kaizensecurity/CVE-2021-41277.svg)


## CVE-2021-40531
 Sketch before 75 mishandles external library feeds.

- [https://github.com/jonpalmisc/CVE-2021-40531](https://github.com/jonpalmisc/CVE-2021-40531) :  ![starts](https://img.shields.io/github/stars/jonpalmisc/CVE-2021-40531.svg) ![forks](https://img.shields.io/github/forks/jonpalmisc/CVE-2021-40531.svg)


## CVE-2021-40444
 Microsoft MSHTML Remote Code Execution Vulnerability

- [https://github.com/Alexcot25051999/CVE-2021-40444](https://github.com/Alexcot25051999/CVE-2021-40444) :  ![starts](https://img.shields.io/github/stars/Alexcot25051999/CVE-2021-40444.svg) ![forks](https://img.shields.io/github/forks/Alexcot25051999/CVE-2021-40444.svg)


## CVE-2021-34473
 Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-31196, CVE-2021-31206.

- [https://github.com/je6k/CVE-2021-34473-Exchange-ProxyShell](https://github.com/je6k/CVE-2021-34473-Exchange-ProxyShell) :  ![starts](https://img.shields.io/github/stars/je6k/CVE-2021-34473-Exchange-ProxyShell.svg) ![forks](https://img.shields.io/github/forks/je6k/CVE-2021-34473-Exchange-ProxyShell.svg)


## CVE-2021-22053
 Applications using both `spring-cloud-netflix-hystrix-dashboard` and `spring-boot-starter-thymeleaf` expose a way to execute code submitted within the request URI path during the resolution of view templates. When a request is made at `/hystrix/monitor;[user-provided data]`, the path elements following `hystrix/monitor` are being evaluated as SpringEL expressions, which can lead to code execution.

- [https://github.com/Vulnmachines/CVE-2021-22053](https://github.com/Vulnmachines/CVE-2021-22053) :  ![starts](https://img.shields.io/github/stars/Vulnmachines/CVE-2021-22053.svg) ![forks](https://img.shields.io/github/forks/Vulnmachines/CVE-2021-22053.svg)


## CVE-2020-6861
 A flawed protocol design in the Ledger Monero app before 1.5.1 for Ledger Nano and Ledger S devices allows a local attacker to extract the master spending key by sending crafted messages to this app selected on a PIN-entered Ledger connected to a host PC.

- [https://github.com/ph4r05/ledger-app-monero-1.42-vuln](https://github.com/ph4r05/ledger-app-monero-1.42-vuln) :  ![starts](https://img.shields.io/github/stars/ph4r05/ledger-app-monero-1.42-vuln.svg) ![forks](https://img.shields.io/github/forks/ph4r05/ledger-app-monero-1.42-vuln.svg)


## CVE-2019-11043
 In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.

- [https://github.com/hlong12042/CVE_2019_11043](https://github.com/hlong12042/CVE_2019_11043) :  ![starts](https://img.shields.io/github/stars/hlong12042/CVE_2019_11043.svg) ![forks](https://img.shields.io/github/forks/hlong12042/CVE_2019_11043.svg)


## CVE-2018-16763
 FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.

- [https://github.com/SlizBinksman/THM-Vulnerability_Capstone-CVE-2018-16763](https://github.com/SlizBinksman/THM-Vulnerability_Capstone-CVE-2018-16763) :  ![starts](https://img.shields.io/github/stars/SlizBinksman/THM-Vulnerability_Capstone-CVE-2018-16763.svg) ![forks](https://img.shields.io/github/forks/SlizBinksman/THM-Vulnerability_Capstone-CVE-2018-16763.svg)


## CVE-2017-17692
 Samsung Internet Browser 5.4.02.3 allows remote attackers to bypass the Same Origin Policy and obtain sensitive information via crafted JavaScript code that redirects to a child tab and rewrites the innerHTML property.

- [https://github.com/specloli/CVE-2017-17692](https://github.com/specloli/CVE-2017-17692) :  ![starts](https://img.shields.io/github/stars/specloli/CVE-2017-17692.svg) ![forks](https://img.shields.io/github/forks/specloli/CVE-2017-17692.svg)


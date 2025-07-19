# Update 2025-07-19
## CVE-2025-53964
 GoldenDict 1.5.0 and 1.5.1 has an exposed dangerous method that allows reading and modifying files when a user adds a crafted dictionary and then searches for any term included in that dictionary.

- [https://github.com/tigr78/CVE-2025-53964](https://github.com/tigr78/CVE-2025-53964) :  ![starts](https://img.shields.io/github/stars/tigr78/CVE-2025-53964.svg) ![forks](https://img.shields.io/github/forks/tigr78/CVE-2025-53964.svg)


## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/Joelp03/CVE-2025-49113](https://github.com/Joelp03/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/Joelp03/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/Joelp03/CVE-2025-49113.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/admin-ping/CVE-2025-48384-RCE](https://github.com/admin-ping/CVE-2025-48384-RCE) :  ![starts](https://img.shields.io/github/stars/admin-ping/CVE-2025-48384-RCE.svg) ![forks](https://img.shields.io/github/forks/admin-ping/CVE-2025-48384-RCE.svg)
- [https://github.com/simplyfurious/CVE-2025-48384-submodule_test](https://github.com/simplyfurious/CVE-2025-48384-submodule_test) :  ![starts](https://img.shields.io/github/stars/simplyfurious/CVE-2025-48384-submodule_test.svg) ![forks](https://img.shields.io/github/forks/simplyfurious/CVE-2025-48384-submodule_test.svg)


## CVE-2025-47812
 In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-47812](https://github.com/B1ack4sh/Blackash-CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-47812.svg)
- [https://github.com/blindma1den/CVE-2025-47812](https://github.com/blindma1den/CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/blindma1den/CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/blindma1den/CVE-2025-47812.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/Rajneeshkarya/CVE-2025-32463](https://github.com/Rajneeshkarya/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/Rajneeshkarya/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/Rajneeshkarya/CVE-2025-32463.svg)


## CVE-2025-30065
Users are recommended to upgrade to version 1.15.1, which fixes the issue.

- [https://github.com/B1ack4sh/Blackash-CVE-2025-30065](https://github.com/B1ack4sh/Blackash-CVE-2025-30065) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-30065.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-30065.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/AventurineJun/CVE-2025-29927-Research](https://github.com/AventurineJun/CVE-2025-29927-Research) :  ![starts](https://img.shields.io/github/stars/AventurineJun/CVE-2025-29927-Research.svg) ![forks](https://img.shields.io/github/forks/AventurineJun/CVE-2025-29927-Research.svg)


## CVE-2025-27591
 A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

- [https://github.com/alialucas7/CVE-2025-27591_PoC](https://github.com/alialucas7/CVE-2025-27591_PoC) :  ![starts](https://img.shields.io/github/stars/alialucas7/CVE-2025-27591_PoC.svg) ![forks](https://img.shields.io/github/forks/alialucas7/CVE-2025-27591_PoC.svg)


## CVE-2025-25257
 An improper neutralization of special elements used in an SQL command ('SQL Injection') vulnerability [CWE-89] in Fortinet FortiWeb version 7.6.0 through 7.6.3, 7.4.0 through 7.4.7, 7.2.0 through 7.2.10 and below 7.0.10 allows an unauthenticated attacker to execute unauthorized SQL code or commands via crafted HTTP or HTTPs requests.

- [https://github.com/watchtowrlabs/watchTowr-vs-FortiWeb-CVE-2025-25257](https://github.com/watchtowrlabs/watchTowr-vs-FortiWeb-CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-FortiWeb-CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-FortiWeb-CVE-2025-25257.svg)
- [https://github.com/0xbigshaq/CVE-2025-25257](https://github.com/0xbigshaq/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/0xbigshaq/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/0xbigshaq/CVE-2025-25257.svg)
- [https://github.com/B1ack4sh/Blackash-CVE-2025-25257](https://github.com/B1ack4sh/Blackash-CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/B1ack4sh/Blackash-CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/B1ack4sh/Blackash-CVE-2025-25257.svg)
- [https://github.com/imbas007/CVE-2025-25257](https://github.com/imbas007/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/imbas007/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/imbas007/CVE-2025-25257.svg)
- [https://github.com/0xgh057r3c0n/CVE-2025-25257](https://github.com/0xgh057r3c0n/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2025-25257.svg)
- [https://github.com/adilburaksen/CVE-2025-25257-Exploit-Tool](https://github.com/adilburaksen/CVE-2025-25257-Exploit-Tool) :  ![starts](https://img.shields.io/github/stars/adilburaksen/CVE-2025-25257-Exploit-Tool.svg) ![forks](https://img.shields.io/github/forks/adilburaksen/CVE-2025-25257-Exploit-Tool.svg)
- [https://github.com/secwatch92/fortiweb_rce_toolkit](https://github.com/secwatch92/fortiweb_rce_toolkit) :  ![starts](https://img.shields.io/github/stars/secwatch92/fortiweb_rce_toolkit.svg) ![forks](https://img.shields.io/github/forks/secwatch92/fortiweb_rce_toolkit.svg)


## CVE-2025-6558
 Insufficient validation of untrusted input in ANGLE and GPU in Google Chrome prior to 138.0.7204.157 allowed a remote attacker to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/allinsthon/CVE-2025-6558-exp](https://github.com/allinsthon/CVE-2025-6558-exp) :  ![starts](https://img.shields.io/github/stars/allinsthon/CVE-2025-6558-exp.svg) ![forks](https://img.shields.io/github/forks/allinsthon/CVE-2025-6558-exp.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/cyberleelawat/ExploitVeer](https://github.com/cyberleelawat/ExploitVeer) :  ![starts](https://img.shields.io/github/stars/cyberleelawat/ExploitVeer.svg) ![forks](https://img.shields.io/github/forks/cyberleelawat/ExploitVeer.svg)


## CVE-2025-4660
This does not impact Linux or OSX Secure Connector.

- [https://github.com/NetSPI/CVE-2025-4660](https://github.com/NetSPI/CVE-2025-4660) :  ![starts](https://img.shields.io/github/stars/NetSPI/CVE-2025-4660.svg) ![forks](https://img.shields.io/github/forks/NetSPI/CVE-2025-4660.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/AventurineJun/CVE-2022-39299-Research](https://github.com/AventurineJun/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/AventurineJun/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/AventurineJun/CVE-2022-39299-Research.svg)


## CVE-2019-4716
 IBM Planning Analytics 2.0.0 through 2.0.8 is vulnerable to a configuration overwrite that allows an unauthenticated user to login as "admin", and then execute code as root or SYSTEM via TM1 scripting. IBM X-Force ID: 172094.

- [https://github.com/Pranjal6955/CVE-2019-4716-Test-Environment](https://github.com/Pranjal6955/CVE-2019-4716-Test-Environment) :  ![starts](https://img.shields.io/github/stars/Pranjal6955/CVE-2019-4716-Test-Environment.svg) ![forks](https://img.shields.io/github/forks/Pranjal6955/CVE-2019-4716-Test-Environment.svg)


# Update 2021-12-13
## CVE-2021-44228
 Apache Log4j2 &lt;=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. In previous releases (&gt;2.10) this behavior can be mitigated by setting system property &quot;log4j2.formatMsgNoLookups&quot; to &#8220;true&#8221; or by removing the JndiLookup class from the classpath (example: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class). Java 8u121 (see https://www.oracle.com/java/technologies/javase/8u121-relnotes.html) protects against remote code execution by defaulting &quot;com.sun.jndi.rmi.object.trustURLCodebase&quot; and &quot;com.sun.jndi.cosnaming.object.trustURLCodebase&quot; to &quot;false&quot;.

- [https://github.com/CreeperHost/Log4jPatcher](https://github.com/CreeperHost/Log4jPatcher) :  ![starts](https://img.shields.io/github/stars/CreeperHost/Log4jPatcher.svg) ![forks](https://img.shields.io/github/forks/CreeperHost/Log4jPatcher.svg)
- [https://github.com/f0ng/log4j2burpscanner](https://github.com/f0ng/log4j2burpscanner) :  ![starts](https://img.shields.io/github/stars/f0ng/log4j2burpscanner.svg) ![forks](https://img.shields.io/github/forks/f0ng/log4j2burpscanner.svg)
- [https://github.com/adilsoybali/Log4j-RCE-Scanner](https://github.com/adilsoybali/Log4j-RCE-Scanner) :  ![starts](https://img.shields.io/github/stars/adilsoybali/Log4j-RCE-Scanner.svg) ![forks](https://img.shields.io/github/forks/adilsoybali/Log4j-RCE-Scanner.svg)
- [https://github.com/logpresso/CVE-2021-44228-Scanner](https://github.com/logpresso/CVE-2021-44228-Scanner) :  ![starts](https://img.shields.io/github/stars/logpresso/CVE-2021-44228-Scanner.svg) ![forks](https://img.shields.io/github/forks/logpresso/CVE-2021-44228-Scanner.svg)
- [https://github.com/toramanemre/log4j-rce-detect-waf-bypass](https://github.com/toramanemre/log4j-rce-detect-waf-bypass) :  ![starts](https://img.shields.io/github/stars/toramanemre/log4j-rce-detect-waf-bypass.svg) ![forks](https://img.shields.io/github/forks/toramanemre/log4j-rce-detect-waf-bypass.svg)
- [https://github.com/hillu/local-log4j-vuln-scanner](https://github.com/hillu/local-log4j-vuln-scanner) :  ![starts](https://img.shields.io/github/stars/hillu/local-log4j-vuln-scanner.svg) ![forks](https://img.shields.io/github/forks/hillu/local-log4j-vuln-scanner.svg)
- [https://github.com/darkarnium/CVE-2021-44228](https://github.com/darkarnium/CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/darkarnium/CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/darkarnium/CVE-2021-44228.svg)
- [https://github.com/zzzz0317/log4j2-vulnerable-spring-app](https://github.com/zzzz0317/log4j2-vulnerable-spring-app) :  ![starts](https://img.shields.io/github/stars/zzzz0317/log4j2-vulnerable-spring-app.svg) ![forks](https://img.shields.io/github/forks/zzzz0317/log4j2-vulnerable-spring-app.svg)
- [https://github.com/mzlogin/CVE-2021-44228-Demo](https://github.com/mzlogin/CVE-2021-44228-Demo) :  ![starts](https://img.shields.io/github/stars/mzlogin/CVE-2021-44228-Demo.svg) ![forks](https://img.shields.io/github/forks/mzlogin/CVE-2021-44228-Demo.svg)
- [https://github.com/PwnC00re/Log4J_0day_RCE](https://github.com/PwnC00re/Log4J_0day_RCE) :  ![starts](https://img.shields.io/github/stars/PwnC00re/Log4J_0day_RCE.svg) ![forks](https://img.shields.io/github/forks/PwnC00re/Log4J_0day_RCE.svg)
- [https://github.com/saharNooby/log4j-vulnerability-patcher-agent](https://github.com/saharNooby/log4j-vulnerability-patcher-agent) :  ![starts](https://img.shields.io/github/stars/saharNooby/log4j-vulnerability-patcher-agent.svg) ![forks](https://img.shields.io/github/forks/saharNooby/log4j-vulnerability-patcher-agent.svg)
- [https://github.com/RedDrip7/Log4Shell_CVE-2021-44228_related_attacks_IOCs](https://github.com/RedDrip7/Log4Shell_CVE-2021-44228_related_attacks_IOCs) :  ![starts](https://img.shields.io/github/stars/RedDrip7/Log4Shell_CVE-2021-44228_related_attacks_IOCs.svg) ![forks](https://img.shields.io/github/forks/RedDrip7/Log4Shell_CVE-2021-44228_related_attacks_IOCs.svg)
- [https://github.com/corretto/hotpatch-for-apache-log4j2](https://github.com/corretto/hotpatch-for-apache-log4j2) :  ![starts](https://img.shields.io/github/stars/corretto/hotpatch-for-apache-log4j2.svg) ![forks](https://img.shields.io/github/forks/corretto/hotpatch-for-apache-log4j2.svg)
- [https://github.com/alexandre-lavoie/python-log4rce](https://github.com/alexandre-lavoie/python-log4rce) :  ![starts](https://img.shields.io/github/stars/alexandre-lavoie/python-log4rce.svg) ![forks](https://img.shields.io/github/forks/alexandre-lavoie/python-log4rce.svg)
- [https://github.com/leetxyz/CVE-2021-44228-Advisories](https://github.com/leetxyz/CVE-2021-44228-Advisories) :  ![starts](https://img.shields.io/github/stars/leetxyz/CVE-2021-44228-Advisories.svg) ![forks](https://img.shields.io/github/forks/leetxyz/CVE-2021-44228-Advisories.svg)
- [https://github.com/Sh0ckFR/log4j-CVE-2021-44228-Public-IoCs](https://github.com/Sh0ckFR/log4j-CVE-2021-44228-Public-IoCs) :  ![starts](https://img.shields.io/github/stars/Sh0ckFR/log4j-CVE-2021-44228-Public-IoCs.svg) ![forks](https://img.shields.io/github/forks/Sh0ckFR/log4j-CVE-2021-44228-Public-IoCs.svg)
- [https://github.com/lhotari/log4shell-mitigation-tester](https://github.com/lhotari/log4shell-mitigation-tester) :  ![starts](https://img.shields.io/github/stars/lhotari/log4shell-mitigation-tester.svg) ![forks](https://img.shields.io/github/forks/lhotari/log4shell-mitigation-tester.svg)
- [https://github.com/irgoncalves/f5-waf-enforce-sig-CVE-2021-44228](https://github.com/irgoncalves/f5-waf-enforce-sig-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/irgoncalves/f5-waf-enforce-sig-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/irgoncalves/f5-waf-enforce-sig-CVE-2021-44228.svg)
- [https://github.com/Mormoroth/log4j-vulnerable-app-cve-2021-44228-terraform](https://github.com/Mormoroth/log4j-vulnerable-app-cve-2021-44228-terraform) :  ![starts](https://img.shields.io/github/stars/Mormoroth/log4j-vulnerable-app-cve-2021-44228-terraform.svg) ![forks](https://img.shields.io/github/forks/Mormoroth/log4j-vulnerable-app-cve-2021-44228-terraform.svg)
- [https://github.com/byteboycn/CVE-2021-44228-Apache-Log4j-Rce](https://github.com/byteboycn/CVE-2021-44228-Apache-Log4j-Rce) :  ![starts](https://img.shields.io/github/stars/byteboycn/CVE-2021-44228-Apache-Log4j-Rce.svg) ![forks](https://img.shields.io/github/forks/byteboycn/CVE-2021-44228-Apache-Log4j-Rce.svg)
- [https://github.com/M1ngGod/CVE-2021-44228-Log4j-lookup-Rce](https://github.com/M1ngGod/CVE-2021-44228-Log4j-lookup-Rce) :  ![starts](https://img.shields.io/github/stars/M1ngGod/CVE-2021-44228-Log4j-lookup-Rce.svg) ![forks](https://img.shields.io/github/forks/M1ngGod/CVE-2021-44228-Log4j-lookup-Rce.svg)
- [https://github.com/js-on/jndiRep](https://github.com/js-on/jndiRep) :  ![starts](https://img.shields.io/github/stars/js-on/jndiRep.svg) ![forks](https://img.shields.io/github/forks/js-on/jndiRep.svg)
- [https://github.com/chilliwebs/CVE-2021-44228_Example](https://github.com/chilliwebs/CVE-2021-44228_Example) :  ![starts](https://img.shields.io/github/stars/chilliwebs/CVE-2021-44228_Example.svg) ![forks](https://img.shields.io/github/forks/chilliwebs/CVE-2021-44228_Example.svg)
- [https://github.com/Ghost-chu/CVE-2021-44228-quickfix-script](https://github.com/Ghost-chu/CVE-2021-44228-quickfix-script) :  ![starts](https://img.shields.io/github/stars/Ghost-chu/CVE-2021-44228-quickfix-script.svg) ![forks](https://img.shields.io/github/forks/Ghost-chu/CVE-2021-44228-quickfix-script.svg)
- [https://github.com/datadavev/test-44228](https://github.com/datadavev/test-44228) :  ![starts](https://img.shields.io/github/stars/datadavev/test-44228.svg) ![forks](https://img.shields.io/github/forks/datadavev/test-44228.svg)
- [https://github.com/trevalkov/javalogslulz](https://github.com/trevalkov/javalogslulz) :  ![starts](https://img.shields.io/github/stars/trevalkov/javalogslulz.svg) ![forks](https://img.shields.io/github/forks/trevalkov/javalogslulz.svg)
- [https://github.com/vorburger/Log4j_CVE-2021-44228](https://github.com/vorburger/Log4j_CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/vorburger/Log4j_CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/vorburger/Log4j_CVE-2021-44228.svg)
- [https://github.com/zhangxvx/Log4j-Rec-CVE-2021-44228](https://github.com/zhangxvx/Log4j-Rec-CVE-2021-44228) :  ![starts](https://img.shields.io/github/stars/zhangxvx/Log4j-Rec-CVE-2021-44228.svg) ![forks](https://img.shields.io/github/forks/zhangxvx/Log4j-Rec-CVE-2021-44228.svg)
- [https://github.com/blake-fm/vcenter-log4j](https://github.com/blake-fm/vcenter-log4j) :  ![starts](https://img.shields.io/github/stars/blake-fm/vcenter-log4j.svg) ![forks](https://img.shields.io/github/forks/blake-fm/vcenter-log4j.svg)
- [https://github.com/jeffbryner/log4j-docker-vaccine](https://github.com/jeffbryner/log4j-docker-vaccine) :  ![starts](https://img.shields.io/github/stars/jeffbryner/log4j-docker-vaccine.svg) ![forks](https://img.shields.io/github/forks/jeffbryner/log4j-docker-vaccine.svg)
- [https://github.com/gauthamg/log4j2021_vul_test](https://github.com/gauthamg/log4j2021_vul_test) :  ![starts](https://img.shields.io/github/stars/gauthamg/log4j2021_vul_test.svg) ![forks](https://img.shields.io/github/forks/gauthamg/log4j2021_vul_test.svg)
- [https://github.com/cado-security/log4shell](https://github.com/cado-security/log4shell) :  ![starts](https://img.shields.io/github/stars/cado-security/log4shell.svg) ![forks](https://img.shields.io/github/forks/cado-security/log4shell.svg)
- [https://github.com/o7-Fire/Log4Shell](https://github.com/o7-Fire/Log4Shell) :  ![starts](https://img.shields.io/github/stars/o7-Fire/Log4Shell.svg) ![forks](https://img.shields.io/github/forks/o7-Fire/Log4Shell.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798](https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/pedrohavay/exploit-grafana-CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/pedrohavay/exploit-grafana-CVE-2021-43798.svg)
- [https://github.com/LongWayHomie/CVE-2021-43798](https://github.com/LongWayHomie/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/LongWayHomie/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/LongWayHomie/CVE-2021-43798.svg)


## CVE-2021-42574
 An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through 14.0. It permits the visual reordering of characters via control sequences, which can be used to craft source code that renders different logic than the logical ordering of tokens ingested by compilers and interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such that targeted vulnerabilities are introduced invisibly to human reviewers.

- [https://github.com/waseeld/CVE-2021-42574](https://github.com/waseeld/CVE-2021-42574) :  ![starts](https://img.shields.io/github/stars/waseeld/CVE-2021-42574.svg) ![forks](https://img.shields.io/github/forks/waseeld/CVE-2021-42574.svg)


## CVE-2021-42287
 Active Directory Domain Services Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-42278, CVE-2021-42282, CVE-2021-42291.

- [https://github.com/cube0x0/noPac](https://github.com/cube0x0/noPac) :  ![starts](https://img.shields.io/github/stars/cube0x0/noPac.svg) ![forks](https://img.shields.io/github/forks/cube0x0/noPac.svg)
- [https://github.com/WazeHell/sam-the-admin](https://github.com/WazeHell/sam-the-admin) :  ![starts](https://img.shields.io/github/stars/WazeHell/sam-the-admin.svg) ![forks](https://img.shields.io/github/forks/WazeHell/sam-the-admin.svg)


## CVE-2021-42278
 Active Directory Domain Services Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-42282, CVE-2021-42287, CVE-2021-42291.

- [https://github.com/cube0x0/noPac](https://github.com/cube0x0/noPac) :  ![starts](https://img.shields.io/github/stars/cube0x0/noPac.svg) ![forks](https://img.shields.io/github/forks/cube0x0/noPac.svg)
- [https://github.com/WazeHell/sam-the-admin](https://github.com/WazeHell/sam-the-admin) :  ![starts](https://img.shields.io/github/stars/WazeHell/sam-the-admin.svg) ![forks](https://img.shields.io/github/forks/WazeHell/sam-the-admin.svg)


## CVE-2021-41090
 Grafana Agent is a telemetry collector for sending metrics, logs, and trace data to the opinionated Grafana observability stack. Prior to versions 0.20.1 and 0.21.2, inline secrets defined within a metrics instance config are exposed in plaintext over two endpoints: metrics instance configs defined in the base YAML file are exposed at `/-/config` and metrics instance configs defined for the scraping service are exposed at `/agent/api/v1/configs/:key`. Inline secrets will be exposed to anyone being able to reach these endpoints. If HTTPS with client authentication is not configured, these endpoints are accessible to unauthenticated users. Secrets found in these sections are used for delivering metrics to a Prometheus Remote Write system, authenticating against a system for discovering Prometheus targets, and authenticating against a system for collecting metrics. This does not apply for non-inlined secrets, such as `*_file` based secrets. This issue is patched in Grafana Agent versions 0.20.1 and 0.21.2. A few workarounds are available. Users who cannot upgrade should use non-inline secrets where possible. Users may also desire to restrict API access to Grafana Agent with some combination of restricting the network interfaces Grafana Agent listens on through `http_listen_address` in the `server` block, configuring Grafana Agent to use HTTPS with client authentication, and/or using firewall rules to restrict external access to Grafana Agent's API.

- [https://github.com/0xAgun/grafana_lfi](https://github.com/0xAgun/grafana_lfi) :  ![starts](https://img.shields.io/github/stars/0xAgun/grafana_lfi.svg) ![forks](https://img.shields.io/github/forks/0xAgun/grafana_lfi.svg)


## CVE-2021-38666
 Remote Desktop Client Remote Code Execution Vulnerability

- [https://github.com/JaneMandy/CVE-2021-38666](https://github.com/JaneMandy/CVE-2021-38666) :  ![starts](https://img.shields.io/github/stars/JaneMandy/CVE-2021-38666.svg) ![forks](https://img.shields.io/github/forks/JaneMandy/CVE-2021-38666.svg)


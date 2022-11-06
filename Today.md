# Update 2022-11-06
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/cryxnet/CVE-2022-42889-PoC](https://github.com/cryxnet/CVE-2022-42889-PoC) :  ![starts](https://img.shields.io/github/stars/cryxnet/CVE-2022-42889-PoC.svg) ![forks](https://img.shields.io/github/forks/cryxnet/CVE-2022-42889-PoC.svg)


## CVE-2022-31692
 Spring Security, versions 5.7 prior to 5.7.5 and 5.6 prior to 5.6.9 could be susceptible to authorization rules bypass via forward or include dispatcher types. Specifically, an application is vulnerable when all of the following are true: The application expects that Spring Security applies security to forward and include dispatcher types. The application uses the AuthorizationFilter either manually or via the authorizeHttpRequests() method. The application configures the FilterChainProxy to apply to forward and/or include requests (e.g. spring.security.filter.dispatcher-types = request, error, async, forward, include). The application may forward or include the request to a higher privilege-secured endpoint.The application configures Spring Security to apply to every dispatcher type via authorizeHttpRequests().shouldFilterAllDispatcherTypes(true)

- [https://github.com/SpindleSec/cve-2022-31692](https://github.com/SpindleSec/cve-2022-31692) :  ![starts](https://img.shields.io/github/stars/SpindleSec/cve-2022-31692.svg) ![forks](https://img.shields.io/github/forks/SpindleSec/cve-2022-31692.svg)


## CVE-2013-2765
 The ModSecurity module before 2.7.4 for the Apache HTTP Server allows remote attackers to cause a denial of service (NULL pointer dereference, process crash, and disk consumption) via a POST request with a large body and a crafted Content-Type header.

- [https://github.com/yjaaidi/exploits](https://github.com/yjaaidi/exploits) :  ![starts](https://img.shields.io/github/stars/yjaaidi/exploits.svg) ![forks](https://img.shields.io/github/forks/yjaaidi/exploits.svg)


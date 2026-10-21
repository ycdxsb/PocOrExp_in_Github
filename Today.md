# Update 2026-10-21
## CVE-2026-107084
 Slims (Senayan Library Management Systems) 9 Bulian 9.8.0 allows cross-site request forgery (CSRF) against admin/modules/circulation/loan_history_maintenance.php because the action=run GET parameter performs privileged, destructive operations with no CSRF token or POST confirmation, leading to data loss of loan history records.

- [https://github.com/Primandito/CVE-2026-107084](https://github.com/Primandito/CVE-2026-107084) :  ![starts](https://img.shields.io/github/stars/Primandito/CVE-2026-107084.svg) ![forks](https://img.shields.io/github/forks/Primandito/CVE-2026-107084.svg)


## CVE-2026-107083
 SENAYAN Library Management System (SLiMS) Bulian (slims9_bulian) 9.8.0 is vulnerable to SQL Injection in admin/modules/reporting/customs/dl_detail.php via the parameter fileID.

- [https://github.com/Primandito/CVE-2026-107083](https://github.com/Primandito/CVE-2026-107083) :  ![starts](https://img.shields.io/github/stars/Primandito/CVE-2026-107083.svg) ![forks](https://img.shields.io/github/forks/Primandito/CVE-2026-107083.svg)


## CVE-2026-107082
 Slims (Senayan Library Management Systems) 9 Bulian 9.8.0 allows an authenticated staff user to perform SQL injection via the opac_hide and promoted GET parameters of admin/modules/bibliography/index.php, because escape_string() is applied but the values are concatenated into an unquoted numeric SQL context, leading to error-based information disclosure and arbitrary data extraction.

- [https://github.com/Primandito/CVE-2026-107082](https://github.com/Primandito/CVE-2026-107082) :  ![starts](https://img.shields.io/github/stars/Primandito/CVE-2026-107082.svg) ![forks](https://img.shields.io/github/forks/Primandito/CVE-2026-107082.svg)


## CVE-2026-107081
 SQL injection via identifier injection in the tableName and tableFields POST parameters of admin AJAX endpoints (admin/AJAX_lookup_handler.php, admin/AJAX_check_id.php, admin/AJAX_vocabolary_control.php) in SENAYAN Library Management System (SLiMS) Bulian 9.8.0 allows any authenticated staff user to extract arbitrary database contents.

- [https://github.com/Primandito/CVE-2026-107081](https://github.com/Primandito/CVE-2026-107081) :  ![starts](https://img.shields.io/github/stars/Primandito/CVE-2026-107081.svg) ![forks](https://img.shields.io/github/forks/Primandito/CVE-2026-107081.svg)


## CVE-2026-105105
 CWE-306: Missing Authentication for Critical Function in the ait.core.server telemetry and command broker (ait-server) in NASA-AMMOS AIT-Core through 3.1.1 allows an unauthenticated remote attacker with network access to the ZeroMQ message bus to inject spacecraft command data, exfiltrate command and telemetry traffic, inject forged telemetry, or disrupt the command and telemetry bus. The ait-server ZeroMQ broker binds its XSUB and XPUB sockets to all network interfaces by default without authentication or transport security. An attacker able to reach TCP port 5559 can publish messages onto internal topics, including the __commands__ command topic. With the shipped default configuration, command messages are forwarded through command_stream and emitted on the command-uplink UDP path. An attacker able to reach TCP port 5560 can subscribe to command and telemetry traffic on the ground bus. AIT-Core 3.1.2 changes the default ZeroMQ bind addresses to loopback.

- [https://github.com/Mothra-1/CVE-2026-105105](https://github.com/Mothra-1/CVE-2026-105105) :  ![starts](https://img.shields.io/github/stars/Mothra-1/CVE-2026-105105.svg) ![forks](https://img.shields.io/github/forks/Mothra-1/CVE-2026-105105.svg)


## CVE-2026-103663
This issue was fixed in version 0.35.0.

- [https://github.com/striga-ai/CVE-2026-103663](https://github.com/striga-ai/CVE-2026-103663) :  ![starts](https://img.shields.io/github/stars/striga-ai/CVE-2026-103663.svg) ![forks](https://img.shields.io/github/forks/striga-ai/CVE-2026-103663.svg)


## CVE-2026-99999
A more complete validation at input is forthcoming, but needs more work.

- [https://github.com/gandli/CVE-2026-99999-pwnescape](https://github.com/gandli/CVE-2026-99999-pwnescape) :  ![starts](https://img.shields.io/github/stars/gandli/CVE-2026-99999-pwnescape.svg) ![forks](https://img.shields.io/github/forks/gandli/CVE-2026-99999-pwnescape.svg)
- [https://github.com/alvaroguzmancode/CVE-2026-99999](https://github.com/alvaroguzmancode/CVE-2026-99999) :  ![starts](https://img.shields.io/github/stars/alvaroguzmancode/CVE-2026-99999.svg) ![forks](https://img.shields.io/github/forks/alvaroguzmancode/CVE-2026-99999.svg)
- [https://github.com/nsrg-fmlorg/kpatch-rocky-cve-2026-99999](https://github.com/nsrg-fmlorg/kpatch-rocky-cve-2026-99999) :  ![starts](https://img.shields.io/github/stars/nsrg-fmlorg/kpatch-rocky-cve-2026-99999.svg) ![forks](https://img.shields.io/github/forks/nsrg-fmlorg/kpatch-rocky-cve-2026-99999.svg)
- [https://github.com/nsrg-fmlorg/kpatch-alma-cve-2026-99999](https://github.com/nsrg-fmlorg/kpatch-alma-cve-2026-99999) :  ![starts](https://img.shields.io/github/stars/nsrg-fmlorg/kpatch-alma-cve-2026-99999.svg) ![forks](https://img.shields.io/github/forks/nsrg-fmlorg/kpatch-alma-cve-2026-99999.svg)
- [https://github.com/shizuku198411/CVE-2026-99999-KVM-checksum-metadata-non-destructive-PoC](https://github.com/shizuku198411/CVE-2026-99999-KVM-checksum-metadata-non-destructive-PoC) :  ![starts](https://img.shields.io/github/stars/shizuku198411/CVE-2026-99999-KVM-checksum-metadata-non-destructive-PoC.svg) ![forks](https://img.shields.io/github/forks/shizuku198411/CVE-2026-99999-KVM-checksum-metadata-non-destructive-PoC.svg)


## CVE-2026-85880
 Heap-based buffer overflow in Windows ALPC allows an authorized attacker to elevate privileges locally.

- [https://github.com/rsah35404-star/stunning-octo-doodle](https://github.com/rsah35404-star/stunning-octo-doodle) :  ![starts](https://img.shields.io/github/stars/rsah35404-star/stunning-octo-doodle.svg) ![forks](https://img.shields.io/github/forks/rsah35404-star/stunning-octo-doodle.svg)


## CVE-2026-85257
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. A muteException consumer option, defaulting to true, replaces an undeclared route failure with a generic fault carrying no class name, message or stack trace. Faults the contract declares are reported exactly as before. Set muteException=false to restore the previous output. For deployments that cannot upgrade immediately, declare the exceptions the service is allowed to report and map every other failure onto one of them in an onException handler, so no undeclared exception reaches the fault.

- [https://github.com/oscerd/CVE-2026-85257](https://github.com/oscerd/CVE-2026-85257) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85257.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85257.svg)


## CVE-2026-85254
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. Request header names are now compared case insensitively, so the suppression holds regardless of casing and works under HTTP/2. For deployments that cannot upgrade immediately, strip the headers in question in front of the Camel endpoint, or remove them from the response in the route rather than relying on the built-in suppression.

- [https://github.com/oscerd/CVE-2026-85254](https://github.com/oscerd/CVE-2026-85254) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85254.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85254.svg)


## CVE-2026-85251
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. Credentials are now sent only to the authority the endpoint was configured with, and are not re-attached when a redirect crosses to another host. For deployments that cannot upgrade immediately, set followRedirects=false on endpoints that carry credentials, and handle any redirect explicitly in the route so that the destination is chosen by the route rather than by the remote server.

- [https://github.com/oscerd/CVE-2026-85251](https://github.com/oscerd/CVE-2026-85251) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85251.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85251.svg)


## CVE-2026-85250
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. The InputSource document type now goes through the same hardened parser as the default type, so a DOCTYPE is refused. Note that it also shares that type's documented escape hatch: the same DocumentBuilderFactory system properties that relax the default type relax this one, so a deployment that has set them remains unprotected by design. For deployments that cannot upgrade immediately, do not use documentType=InputSource on expressions evaluated over untrusted XML; the default document type already refuses a DOCTYPE.

- [https://github.com/oscerd/CVE-2026-85250](https://github.com/oscerd/CVE-2026-85250) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85250.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85250.svg)


## CVE-2026-85249
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. Parsed document metadata is now filtered through a HeaderFilterStrategy before it is mapped onto the Exchange. A route that was reading a metadata-derived header the filter now blocks will see it missing. For deployments that cannot upgrade immediately, strip the Camel namespace after the Tika producer with removeHeaders("Camel*") before any component that acts on those headers.

- [https://github.com/oscerd/CVE-2026-85249](https://github.com/oscerd/CVE-2026-85249) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85249.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85249.svg)


## CVE-2026-85248
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. The Signature instance is no longer shared across concurrent exchanges. For deployments that cannot upgrade immediately, restrict the affected route to a single concurrent consumer so that no two exchanges use the instance at once.

- [https://github.com/oscerd/CVE-2026-85248](https://github.com/oscerd/CVE-2026-85248) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85248.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85248.svg)


## CVE-2026-85247
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. With no truststore configured the trust options are now left unset so the JVM default trust anchors apply, the same fallback SSLContextParameters and the rest of Camel use. Trusting every certificate is now reached only by asking for it explicitly through the trust.all property, which remains available for development against a cluster with a self-signed certificate. For deployments that cannot upgrade immediately, configure a truststore explicitly wherever SSL is enabled. After upgrading, a deployment that was relying on the implicit trust-all behaviour must either configure a truststore or set the trust.all property deliberately.

- [https://github.com/oscerd/CVE-2026-85247](https://github.com/oscerd/CVE-2026-85247) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85247.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85247.svg)


## CVE-2026-85246
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. A muteException consumer option, defaulting to true, replaces the route exception with a generic one carrying no class name, message or stack trace, while still writing a reply so that a synchronous peer is not left to time out. Set muteException=false to restore the previous behaviour. For deployments that cannot upgrade immediately, add an onException handler that sets the reply body explicitly, so the framework never writes the exception back to the peer.

- [https://github.com/oscerd/CVE-2026-85246](https://github.com/oscerd/CVE-2026-85246) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85246.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85246.svg)


## CVE-2026-85245
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. Unmarshalling now deserializes into a copy, so each exchange gets its own instance and no state carries between messages. For deployments that cannot upgrade immediately, copy the unmarshalled body into a new instance immediately after the data format runs, and do not retain references to the returned object.

- [https://github.com/oscerd/CVE-2026-85245](https://github.com/oscerd/CVE-2026-85245) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85245.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85245.svg)


## CVE-2026-85243
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. A requireIntegrityProtection option, defaulting to true, now rejects a message that is not integrity protected. Note that signatureVerificationOption still defaults to optional, so a message carrying no signature is accepted; the two options together are what give a decrypted message authenticity and not only confidentiality. For deployments that cannot upgrade immediately, reject messages that do not use the integrity protected packet before they reach the data format. Routes that must interoperate with a sender still emitting the legacy packet should set requireIntegrityProtection=false after upgrading, and treat the decrypted content as unauthenticated.

- [https://github.com/oscerd/CVE-2026-85243](https://github.com/oscerd/CVE-2026-85243) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-85243.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-85243.svg)


## CVE-2026-84181
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. The processor now verifies the presented credentials on every exchange rather than accepting a subject already bound to the thread. Setting alwaysReauthenticate=false restores the previous behaviour for deployments that depend on it. For deployments that cannot upgrade immediately, ensure the Shiro subject is cleared from the thread at the end of every exchange so that no subject can be inherited by a later one.

- [https://github.com/oscerd/CVE-2026-84181](https://github.com/oscerd/CVE-2026-84181) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-84181.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-84181.svg)


## CVE-2026-84180
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. The consumer now honours a muteException option that defaults to true, so a route failure returns an empty body with the error status rather than the exception. Set muteException=false to restore the previous output. For deployments that cannot upgrade immediately, add an onException handler that sets the response body explicitly, so that the framework never writes the exception back to the caller.

- [https://github.com/oscerd/CVE-2026-84180](https://github.com/oscerd/CVE-2026-84180) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-84180.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-84180.svg)


## CVE-2026-84178
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. The authorization request now issues a state value bound to the session, and the callback rejects a request whose state is absent or does not match, stopping the route with a 400 response. For deployments that cannot upgrade immediately, terminate the authorization code flow in a component that performs its own state binding rather than relying on the Camel callback. Note that after upgrading, a deployment behind a proxy that drops or rewrites the callback query string will begin to see 400 responses, because the state parameter must survive the round trip.

- [https://github.com/oscerd/CVE-2026-84178](https://github.com/oscerd/CVE-2026-84178) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-84178.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-84178.svg)


## CVE-2026-84176
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. Access-Control-Allow-Credentials is now sent only when the request origin matched an origin the operator actually configured. With no origin list the origin is still reflected, as before, but credentials are not granted, and Vary: Origin is now set whenever the origin is reflected so that a shared cache cannot serve one origin's response to another. For deployments that cannot upgrade immediately, set camel.server.cors.origins to the explicit list of origins that need access rather than leaving it unset.

- [https://github.com/oscerd/CVE-2026-84176](https://github.com/oscerd/CVE-2026-84176) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-84176.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-84176.svg)


## CVE-2026-83531
Users are recommended to upgrade to version 4.23.0, which fixes the issue. If users are on the 4.22.x releases stream, then they are suggested to upgrade to 4.22.1. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.5. The 4.14.x releases stream and earlier reached end of life before this issue was resolved and will not receive a fix, so deployments on those lines must move to a supported release. After upgrading, a control message that carries a predicate expression or an expression language is rejected unless the new allowPredicateFromMessage option is enabled on the dynamic-router-control endpoint; enable it only when every sender of control messages is trusted. For deployments that cannot upgrade immediately, do not forward messages from untrusted or shared transports to a dynamic-router-control endpoint. Where control messages must cross such a transport, authenticate the sender and make sure the predicate and expression language of each subscription are set by the route rather than taken from the incoming message, for example by removing the CamelDynamicRouterPredicate and CamelDynamicRouterExpressionLanguage headers and clearing the predicate and expressionLanguage fields of a DynamicRouterControlMessage before it reaches the endpoint. Removing optional expression languages from the classpath is not a sufficient workaround. As defence in depth, restrict who can send to the transports that feed the control endpoint, and on 4.23.0 and 4.22.1 set the allowedSchemes option of the dynamic-router endpoint to limit which endpoints a subscription's destinationUri may name.

- [https://github.com/oscerd/CVE-2026-83531](https://github.com/oscerd/CVE-2026-83531) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-83531.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-83531.svg)


## CVE-2026-81963
 Improper link resolution before file access ('link following') in Windows Update Stack allows an authorized attacker to elevate privileges locally.

- [https://github.com/rsah35404-star/stunning-octo-doodle](https://github.com/rsah35404-star/stunning-octo-doodle) :  ![starts](https://img.shields.io/github/stars/rsah35404-star/stunning-octo-doodle.svg) ![forks](https://img.shields.io/github/forks/rsah35404-star/stunning-octo-doodle.svg)


## CVE-2026-80344
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. The asynchronous MDN destination is now constrained rather than taken verbatim from the inbound message. For deployments that cannot upgrade immediately, restrict outbound connectivity from the AS2 receiver to the partner endpoints it legitimately delivers receipts to, and do not attach credentials to MDN delivery that are valid for any host other than those partners.

- [https://github.com/oscerd/CVE-2026-80344](https://github.com/oscerd/CVE-2026-80344) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-80344.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-80344.svg)


## CVE-2026-80343
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. The constraint now matches the request path with the same case rules the dispatch uses, so the two can no longer disagree. For deployments that cannot upgrade immediately, place the authorization decision in front of the Camel consumer, for example in a reverse proxy that normalises the request path before forwarding.

- [https://github.com/oscerd/CVE-2026-80343](https://github.com/oscerd/CVE-2026-80343) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-80343.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-80343.svg)


## CVE-2026-80312
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. Users on the 4.22.x LTS releases stream should upgrade to 4.22.1. The processors now stop the exchange and set the appropriate error status whenever an authenticated session cannot be established, so a failed authentication no longer reaches the protected part of the route. For deployments that cannot upgrade immediately, place an explicit authorization check after the OAuth processor rather than relying on it to halt the exchange, and verify that the route stops on failure.

- [https://github.com/oscerd/CVE-2026-80312](https://github.com/oscerd/CVE-2026-80312) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-80312.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-80312.svg)


## CVE-2026-79986
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.22.x releases stream should upgrade to 4.22.1. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. The 4.14.x stream reached end of life and does not receive this fix; users on it should move to a supported releases stream.

- [https://github.com/oscerd/CVE-2026-79986](https://github.com/oscerd/CVE-2026-79986) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-79986.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-79986.svg)


## CVE-2026-79985
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.22.x releases stream should upgrade to 4.22.1. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. The 4.14.x stream reached end of life and does not receive this fix; users on it should move to a supported releases stream.

- [https://github.com/oscerd/CVE-2026-79985](https://github.com/oscerd/CVE-2026-79985) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-79985.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-79985.svg)


## CVE-2026-79984
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.22.x releases stream should upgrade to 4.22.1. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. The 4.14.x stream reached end of life and does not receive this fix; users on it should move to a supported releases stream.

- [https://github.com/oscerd/CVE-2026-79984](https://github.com/oscerd/CVE-2026-79984) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-79984.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-79984.svg)


## CVE-2026-79983
Upgrade to Apache Camel 4.23.0, which fixes the issue. Users on the 4.22.x releases stream should upgrade to 4.22.1. Users on the 4.18.x LTS releases stream should upgrade to 4.18.5. The 4.14.x stream reached end of life and does not receive this fix; users on it should move to a supported releases stream.

- [https://github.com/oscerd/CVE-2026-79983](https://github.com/oscerd/CVE-2026-79983) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-79983.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-79983.svg)
- [https://github.com/oscerd/CVE-2026-79986](https://github.com/oscerd/CVE-2026-79986) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-79986.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-79986.svg)
- [https://github.com/oscerd/CVE-2026-79985](https://github.com/oscerd/CVE-2026-79985) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-79985.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-79985.svg)


## CVE-2026-78165
Users are recommended to upgrade to version 4.23.0, which fixes the issue. If users are on the 4.22.x releases stream, then they are suggested to upgrade to 4.22.1. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.5. The 4.14.x releases stream and earlier reached end of life before this issue was resolved and will not receive a fix, so deployments on those lines must move to a supported release. For deployments that cannot upgrade immediately, set the JVM-wide jdk.serialFilter system property, which the affected code path honours because it reads through a java.io.ObjectInputStream, for example -Djdk.serialFilter=!java.net.**;java.**;javax.**;org.apache.camel.**;!* ; or set the serializer endpoint option to a serializer that does not use Java serialization, such as StringRedisSerializer, noting that this must be set as the serializer option and not only on a custom redisTemplate. As defence in depth, require authentication on the Redis instance and restrict which clients may publish to the subscribed channels, and do not expose a Redis instance consumed by Camel to untrusted networks.

- [https://github.com/oscerd/CVE-2026-78165](https://github.com/oscerd/CVE-2026-78165) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-78165.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-78165.svg)


## CVE-2026-78164
Users should upgrade to version 4.23.0, which fixes the issue. Users on the 4.22.x releases stream should upgrade to 4.22.1. Users on the 4.18.x releases stream should upgrade to 4.18.5. The 4.14.x releases stream and earlier reached end of life before this issue was resolved and will not receive a fix, so deployments on those lines must move to a supported release. For deployments that cannot upgrade immediately, strip the override headers at the trust boundary before the producer with removeHeader("CamelHttpUri") and removeHeader("CamelRestHttpUri"), or set skipControlHeaders=true on camel-http endpoints, which is the only component offering that option. Note that bridgeEndpoint=true is not a workaround: it suppresses the header override when the outbound URL is built but not when the header is re-parsed for the query string. Percent-encoding the placeholder delimiters is likewise not a mitigation for camel-netty-http, whose binding decodes the request path before the value reaches the header, so proxy or WAF rules written against the raw delimiters do not help there. As defence in depth, ensure consumers exposed to untrusted senders apply a strict inbound HeaderFilterStrategy over the Camel namespace, and resolve secrets through a vault rather than through environment variables or system properties that a placeholder can name.

- [https://github.com/oscerd/CVE-2026-78164](https://github.com/oscerd/CVE-2026-78164) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-78164.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-78164.svg)


## CVE-2026-78163
Users are recommended to upgrade to version 4.23.0, which fixes the issue. If users are on the 4.22.x releases stream, then they are suggested to upgrade to 4.22.1. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.5. The 4.14.x releases stream and earlier reached end of life before this issue was resolved and will not receive a fix, so deployments on those lines must move to a supported release. For deployments that cannot upgrade immediately, do not route message bodies that originate outside the deployment into a docling endpoint, and pass the document through a typed body such as File, byte[] or InputStream, or through the CamelDoclingInputFilePath header, so that the body is never subject to prefix interpretation.

- [https://github.com/oscerd/CVE-2026-78163](https://github.com/oscerd/CVE-2026-78163) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-78163.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-78163.svg)


## CVE-2026-78162
Users are recommended to upgrade to version 4.23.0, which fixes the issue. If users are on the 4.22.x releases stream, then they are suggested to upgrade to 4.22.1. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.5. The 4.14.x releases stream and earlier reached end of life before this issue was resolved and will not receive a fix, so deployments on those lines must move to a supported release. For deployments that cannot upgrade immediately, supply an explicit Hazelcast configuration carrying a JavaSerializationFilterConfig, or inject a pre-built HazelcastInstance, since a user-supplied configuration is never overwritten by Camel. Alternatively set the JVM-wide filter -Djdk.serialFilter=!java.net.;java.;javax.;org.apache.camel.;!* and enable Hazelcast cluster authentication and TLS to restrict who can reach the cluster.

- [https://github.com/oscerd/CVE-2026-78162](https://github.com/oscerd/CVE-2026-78162) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-78162.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-78162.svg)


## CVE-2026-75045
2026.2.18112 an unauthenticated attacker could download database backups via shared draft signature

- [https://github.com/LHeiakim/CVE-2026-75045-PoC](https://github.com/LHeiakim/CVE-2026-75045-PoC) :  ![starts](https://img.shields.io/github/stars/LHeiakim/CVE-2026-75045-PoC.svg) ![forks](https://img.shields.io/github/forks/LHeiakim/CVE-2026-75045-PoC.svg)


## CVE-2026-69414
 Microsoft is aware of an elevation of privilege in the Microsoft Malware Protection Engine in Microsoft Defender publicly referred to as &quot;ShieldBreak &quot;.

- [https://github.com/rsah35404-star/stunning-octo-doodle](https://github.com/rsah35404-star/stunning-octo-doodle) :  ![starts](https://img.shields.io/github/stars/rsah35404-star/stunning-octo-doodle.svg) ![forks](https://img.shields.io/github/forks/rsah35404-star/stunning-octo-doodle.svg)


## CVE-2026-64560
---truncated---

- [https://github.com/Feng1586/CVE-2026-64560-public](https://github.com/Feng1586/CVE-2026-64560-public) :  ![starts](https://img.shields.io/github/stars/Feng1586/CVE-2026-64560-public.svg) ![forks](https://img.shields.io/github/forks/Feng1586/CVE-2026-64560-public.svg)
- [https://github.com/Feng1586/CVE-2026-64560-sources](https://github.com/Feng1586/CVE-2026-64560-sources) :  ![starts](https://img.shields.io/github/stars/Feng1586/CVE-2026-64560-sources.svg) ![forks](https://img.shields.io/github/forks/Feng1586/CVE-2026-64560-sources.svg)


## CVE-2026-63030
 WordPress 6.9.x before 6.9.5 and 7.0.x before 7.0.2 is affected by a REST API batch endpoint route confusion issue which, combined with the author__not_in WP_Query SQL Injection (CVE-2026-60137), could allow an attacker to perform SQL Injection and achieve Remote Code Execution.

- [https://github.com/K52-ai/CVE-2026-63030](https://github.com/K52-ai/CVE-2026-63030) :  ![starts](https://img.shields.io/github/stars/K52-ai/CVE-2026-63030.svg) ![forks](https://img.shields.io/github/forks/K52-ai/CVE-2026-63030.svg)


## CVE-2026-58249
 SAP NetWeaver and SAP Web Dispatcher do not properly validate certain fields in specially crafted requests handled by an internal protocol component. An unauthenticated attacker could send a malicious request that triggers a memory-handling error, causing the affected process to crash. Successful exploitation can therefore result in a high impact on the availability of the affected application. There is no impact on the confidentiality or integrity of the application.

- [https://github.com/Toluwanimi7/CYB401-CVE-2026-58249-Analysis](https://github.com/Toluwanimi7/CYB401-CVE-2026-58249-Analysis) :  ![starts](https://img.shields.io/github/stars/Toluwanimi7/CYB401-CVE-2026-58249-Analysis.svg) ![forks](https://img.shields.io/github/forks/Toluwanimi7/CYB401-CVE-2026-58249-Analysis.svg)


## CVE-2026-54121
 Improper authorization in Active Directory Certificate Services (AD CS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/AnibusCode/CVE-2026-54121-Certighost](https://github.com/AnibusCode/CVE-2026-54121-Certighost) :  ![starts](https://img.shields.io/github/stars/AnibusCode/CVE-2026-54121-Certighost.svg) ![forks](https://img.shields.io/github/forks/AnibusCode/CVE-2026-54121-Certighost.svg)


## CVE-2026-53995
 MLflow 3.17.1 and earlier contains a path traversal vulnerability in the FileStore tracking backend that allows unauthenticated attackers to control filesystem paths by submitting a crafted trace ID containing traversal sequences to the POST /api/3.0/mlflow/traces endpoint. Attackers can exploit FileStore.start_trace() to write trace_info.yaml, request_metadata, and tag files with attacker-controlled metadata outside the intended experiment trace directory, subject to the server process's filesystem permissions. FileStore is the default tracking backend before MLflow 3.7.0 and opt-in thereafter (the default changed to a SQLite database), so deployments in the earlier part of the affected range are vulnerable without special configuration while later ones are affected only when FileStore is explicitly selected.

- [https://github.com/SaiTeja-Erukude/CVE-2026-53995-mlflow-path-traversal](https://github.com/SaiTeja-Erukude/CVE-2026-53995-mlflow-path-traversal) :  ![starts](https://img.shields.io/github/stars/SaiTeja-Erukude/CVE-2026-53995-mlflow-path-traversal.svg) ![forks](https://img.shields.io/github/forks/SaiTeja-Erukude/CVE-2026-53995-mlflow-path-traversal.svg)


## CVE-2026-52856
 Wings is the server control plane for Pterodactyl, a free, open-source game server management panel. Prior to 1.13.0, a malformed packet received during the SFTP connection handshake causes a Go panic. This issue is fixed in version 1.13.0.

- [https://github.com/lisbickq/CVE-2026-52856-PoC](https://github.com/lisbickq/CVE-2026-52856-PoC) :  ![starts](https://img.shields.io/github/stars/lisbickq/CVE-2026-52856-PoC.svg) ![forks](https://img.shields.io/github/forks/lisbickq/CVE-2026-52856-PoC.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/RemiPelloux/GalaxyCrash](https://github.com/RemiPelloux/GalaxyCrash) :  ![starts](https://img.shields.io/github/stars/RemiPelloux/GalaxyCrash.svg) ![forks](https://img.shields.io/github/forks/RemiPelloux/GalaxyCrash.svg)


## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.

- [https://github.com/LaRemontada12/CVE-2026-39987-Marimo-Preauth-RCE](https://github.com/LaRemontada12/CVE-2026-39987-Marimo-Preauth-RCE) :  ![starts](https://img.shields.io/github/stars/LaRemontada12/CVE-2026-39987-Marimo-Preauth-RCE.svg) ![forks](https://img.shields.io/github/forks/LaRemontada12/CVE-2026-39987-Marimo-Preauth-RCE.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/toxy4ny/copy-fail-exploit-on-c-redteam](https://github.com/toxy4ny/copy-fail-exploit-on-c-redteam) :  ![starts](https://img.shields.io/github/stars/toxy4ny/copy-fail-exploit-on-c-redteam.svg) ![forks](https://img.shields.io/github/forks/toxy4ny/copy-fail-exploit-on-c-redteam.svg)


## CVE-2026-27606
 Rollup is a module bundler for JavaScript. Versions prior to 2.80.0, 3.30.0, and 4.59.0 of the Rollup module bundler (specifically v4.x and present in current source) is vulnerable to an Arbitrary File Write via Path Traversal. Insecure file name sanitization in the core engine allows an attacker to control output filenames (e.g., via CLI named inputs, manual chunk aliases, or malicious plugins) and use traversal sequences (`../`) to overwrite files anywhere on the host filesystem that the build process has permissions for. This can lead to persistent Remote Code Execution (RCE) by overwriting critical system or user configuration files. Versions 2.80.0, 3.30.0, and 4.59.0 contain a patch for the issue.

- [https://github.com/AaaronP/Seguridad---Proyecto-de-investigaci-n](https://github.com/AaaronP/Seguridad---Proyecto-de-investigaci-n) :  ![starts](https://img.shields.io/github/stars/AaaronP/Seguridad---Proyecto-de-investigaci-n.svg) ![forks](https://img.shields.io/github/forks/AaaronP/Seguridad---Proyecto-de-investigaci-n.svg)


## CVE-2026-24090
 Cryptographic issue while processing partition table entries allows unauthorized modification of boot flow.

- [https://github.com/wnduddld0513/Lenovo_Qcom_RPMB_Tool](https://github.com/wnduddld0513/Lenovo_Qcom_RPMB_Tool) :  ![starts](https://img.shields.io/github/stars/wnduddld0513/Lenovo_Qcom_RPMB_Tool.svg) ![forks](https://img.shields.io/github/forks/wnduddld0513/Lenovo_Qcom_RPMB_Tool.svg)


## CVE-2026-23111
skip active elements, process inactive ones.

- [https://github.com/kinokopio/CVE-2026-23111](https://github.com/kinokopio/CVE-2026-23111) :  ![starts](https://img.shields.io/github/stars/kinokopio/CVE-2026-23111.svg) ![forks](https://img.shields.io/github/forks/kinokopio/CVE-2026-23111.svg)


## CVE-2026-22747
This issue affects Spring Security: from 7.0.0 through 7.0.4.

- [https://github.com/yakissa/CVE-2026-22747](https://github.com/yakissa/CVE-2026-22747) :  ![starts](https://img.shields.io/github/stars/yakissa/CVE-2026-22747.svg) ![forks](https://img.shields.io/github/forks/yakissa/CVE-2026-22747.svg)


## CVE-2026-16723
 A remote code execution (RCE) vulnerability exists in fastjson 1.2.68 through 1.2.83. This vulnerability is exploitable under fastjson's stock default configuration — no AutoType enablement required, no classpath gadget required.

- [https://github.com/cuttlefish520/FastJson1.2.83-GenProbe2](https://github.com/cuttlefish520/FastJson1.2.83-GenProbe2) :  ![starts](https://img.shields.io/github/stars/cuttlefish520/FastJson1.2.83-GenProbe2.svg) ![forks](https://img.shields.io/github/forks/cuttlefish520/FastJson1.2.83-GenProbe2.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/Romk-a/CVE-2026-43499-ghostlock-vivo-x100-ultra-root](https://github.com/Romk-a/CVE-2026-43499-ghostlock-vivo-x100-ultra-root) :  ![starts](https://img.shields.io/github/stars/Romk-a/CVE-2026-43499-ghostlock-vivo-x100-ultra-root.svg) ![forks](https://img.shields.io/github/forks/Romk-a/CVE-2026-43499-ghostlock-vivo-x100-ultra-root.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/JnamerZ/CopyFail-CVE-2026-31431](https://github.com/JnamerZ/CopyFail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/JnamerZ/CopyFail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/JnamerZ/CopyFail-CVE-2026-31431.svg)


## CVE-2026-0006
 In multiple locations, there is a possible out of bounds read and write due to a heap buffer overflow. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/R3n3r0/CVE-2026-0006-step-2](https://github.com/R3n3r0/CVE-2026-0006-step-2) :  ![starts](https://img.shields.io/github/stars/R3n3r0/CVE-2026-0006-step-2.svg) ![forks](https://img.shields.io/github/forks/R3n3r0/CVE-2026-0006-step-2.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/viperh/poc-cve-next](https://github.com/viperh/poc-cve-next) :  ![starts](https://img.shields.io/github/stars/viperh/poc-cve-next.svg) ![forks](https://img.shields.io/github/forks/viperh/poc-cve-next.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-peer-conflict.svg)


## CVE-2025-27515
 Laravel is a web application framework. When using wildcard validation to validate a given file or image field (`files.*`), a user-crafted malicious request could potentially bypass the validation rules. This vulnerability is fixed in 11.44.1 and 12.1.1.

- [https://github.com/Shanks2001/Progetto-sicurezza](https://github.com/Shanks2001/Progetto-sicurezza) :  ![starts](https://img.shields.io/github/stars/Shanks2001/Progetto-sicurezza.svg) ![forks](https://img.shields.io/github/forks/Shanks2001/Progetto-sicurezza.svg)


## CVE-2025-21420
 Windows Disk Cleanup Tool Elevation of Privilege Vulnerability

- [https://github.com/toxy4ny/edge-maradeur](https://github.com/toxy4ny/edge-maradeur) :  ![starts](https://img.shields.io/github/stars/toxy4ny/edge-maradeur.svg) ![forks](https://img.shields.io/github/forks/toxy4ny/edge-maradeur.svg)


## CVE-2025-21401
 Microsoft Edge (Chromium-based) Security Feature Bypass Vulnerability

- [https://github.com/toxy4ny/edge-maradeur](https://github.com/toxy4ny/edge-maradeur) :  ![starts](https://img.shields.io/github/stars/toxy4ny/edge-maradeur.svg) ![forks](https://img.shields.io/github/forks/toxy4ny/edge-maradeur.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)


## CVE-2024-58299
 PCMan FTP Server 2.0 contains a buffer overflow vulnerability in the 'pwd' command that allows remote attackers to execute arbitrary code. Attackers can send a specially crafted payload during the FTP login process to overwrite memory and potentially gain system access.

- [https://github.com/CyberWarrior10101/CVE-2024-58299](https://github.com/CyberWarrior10101/CVE-2024-58299) :  ![starts](https://img.shields.io/github/stars/CyberWarrior10101/CVE-2024-58299.svg) ![forks](https://img.shields.io/github/forks/CyberWarrior10101/CVE-2024-58299.svg)


## CVE-2024-35250
 Windows Kernel-Mode Driver Elevation of Privilege Vulnerability

- [https://github.com/m01000xd/CVE-2024-35250](https://github.com/m01000xd/CVE-2024-35250) :  ![starts](https://img.shields.io/github/stars/m01000xd/CVE-2024-35250.svg) ![forks](https://img.shields.io/github/forks/m01000xd/CVE-2024-35250.svg)


## CVE-2024-27198
 In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible

- [https://github.com/GREATKID05/CVE-2024-27198-Assignment](https://github.com/GREATKID05/CVE-2024-27198-Assignment) :  ![starts](https://img.shields.io/github/stars/GREATKID05/CVE-2024-27198-Assignment.svg) ![forks](https://img.shields.io/github/forks/GREATKID05/CVE-2024-27198-Assignment.svg)


## CVE-2024-23334
 aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present.  Disabling follow_symlinks and using a reverse proxy are encouraged mitigations.  Version 3.9.2 fixes this issue.

- [https://github.com/JohnnyWang108/hdu-is-lab1-secure-api](https://github.com/JohnnyWang108/hdu-is-lab1-secure-api) :  ![starts](https://img.shields.io/github/stars/JohnnyWang108/hdu-is-lab1-secure-api.svg) ![forks](https://img.shields.io/github/forks/JohnnyWang108/hdu-is-lab1-secure-api.svg)


## CVE-2024-21762
 A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, 2.0.0 through 2.0.13, 1.2.0 through 1.2.13, 1.1.0 through 1.1.6, 1.0.0 through 1.0.7 allows attacker to execute unauthorized code or commands via specifically crafted requests

- [https://github.com/Deekshitha2203/security-triage-agent-cybersec590](https://github.com/Deekshitha2203/security-triage-agent-cybersec590) :  ![starts](https://img.shields.io/github/stars/Deekshitha2203/security-triage-agent-cybersec590.svg) ![forks](https://img.shields.io/github/forks/Deekshitha2203/security-triage-agent-cybersec590.svg)


## CVE-2024-12603
 A logic vulnerability in the the mobile application (com.transsion.applock) can lead to bypassing the application password.

- [https://github.com/MAwaisAfzal0/CVE-2024-12603-POC](https://github.com/MAwaisAfzal0/CVE-2024-12603-POC) :  ![starts](https://img.shields.io/github/stars/MAwaisAfzal0/CVE-2024-12603-POC.svg) ![forks](https://img.shields.io/github/forks/MAwaisAfzal0/CVE-2024-12603-POC.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/dolapoojone/CVE-2024-6387-Vulnerability-Anaysis](https://github.com/dolapoojone/CVE-2024-6387-Vulnerability-Anaysis) :  ![starts](https://img.shields.io/github/stars/dolapoojone/CVE-2024-6387-Vulnerability-Anaysis.svg) ![forks](https://img.shields.io/github/forks/dolapoojone/CVE-2024-6387-Vulnerability-Anaysis.svg)


## CVE-2024-3400
Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.

- [https://github.com/Onosetalease/CVE-2024-3400-Vulnerability-Analysis](https://github.com/Onosetalease/CVE-2024-3400-Vulnerability-Analysis) :  ![starts](https://img.shields.io/github/stars/Onosetalease/CVE-2024-3400-Vulnerability-Analysis.svg) ![forks](https://img.shields.io/github/forks/Onosetalease/CVE-2024-3400-Vulnerability-Analysis.svg)


## CVE-2023-54391
 Proxmox Virtual Environment (VE) 7.0 through 8.0 contains an authentication bypass vulnerability in libpve-access-control before 8.0.4 that allows unauthenticated attackers to authenticate as any existing enabled user without a configured second factor by supplying an arbitrary tfa-challenge value in the API login endpoint. Attackers can send a POST request to the access ticket API endpoint with any value in the tfa-challenge parameter to completely skip password verification, gaining unauthorized access including to the root@pam account. All affected releases are end of life.

- [https://github.com/Lewis1766/CVE-2023-54391-POC](https://github.com/Lewis1766/CVE-2023-54391-POC) :  ![starts](https://img.shields.io/github/stars/Lewis1766/CVE-2023-54391-POC.svg) ![forks](https://img.shields.io/github/forks/Lewis1766/CVE-2023-54391-POC.svg)


## CVE-2023-20198
 Cisco is providing an update for the ongoing investigation into observed exploitation of the web UI feature in Cisco IOS XE Software. We are updating the list of fixed releases and adding the Software Checker. Our investigation has determined that the actors exploited two previously unknown issues. The attacker first exploited CVE-2023-20198 to gain initial access and issued a privilege 15 command to create a local user and password combination. This allowed the user to log in with normal user access. The attacker then exploited another component of the web UI feature, leveraging the new local user to elevate privilege to root and write the implant to the file system. Cisco has assigned CVE-2023-20273 to this issue. CVE-2023-20198 has been assigned a CVSS Score of 10.0. CVE-2023-20273 has been assigned a CVSS Score of 7.2. Both of these CVEs are being tracked by CSCwh87343.

- [https://github.com/waynec1eated-bot/CVE-2023-20198-Cisco-IOS-XE](https://github.com/waynec1eated-bot/CVE-2023-20198-Cisco-IOS-XE) :  ![starts](https://img.shields.io/github/stars/waynec1eated-bot/CVE-2023-20198-Cisco-IOS-XE.svg) ![forks](https://img.shields.io/github/forks/waynec1eated-bot/CVE-2023-20198-Cisco-IOS-XE.svg)


## CVE-2023-4911
 A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with elevated privileges.

- [https://github.com/adewlee87-rgb/cve-2023-4911-looney-tunables](https://github.com/adewlee87-rgb/cve-2023-4911-looney-tunables) :  ![starts](https://img.shields.io/github/stars/adewlee87-rgb/cve-2023-4911-looney-tunables.svg) ![forks](https://img.shields.io/github/forks/adewlee87-rgb/cve-2023-4911-looney-tunables.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-](https://github.com/Greetdawn/CVE-2022-0847-DirtyPipe-) :  ![starts](https://img.shields.io/github/stars/Greetdawn/CVE-2022-0847-DirtyPipe-.svg) ![forks](https://img.shields.io/github/forks/Greetdawn/CVE-2022-0847-DirtyPipe-.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/LayarKacaSiber/CVE-2021-41773](https://github.com/LayarKacaSiber/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/LayarKacaSiber/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/LayarKacaSiber/CVE-2021-41773.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/mah4nzfr/CVE-2021-41773](https://github.com/mah4nzfr/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/mah4nzfr/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/mah4nzfr/CVE-2021-41773.svg)


## CVE-2021-3929
 A DMA reentrancy issue was found in the NVM Express Controller (NVME) emulation in QEMU. This CVE is similar to CVE-2021-3750 and, just like it, when the reentrancy write triggers the reset function nvme_ctrl_reset(), data structs will be freed leading to a use-after-free issue. A malicious guest could use this flaw to crash the QEMU process on the host, resulting in a denial of service condition or, potentially, executing arbitrary code within the context of the QEMU process on the host.

- [https://github.com/abraxas/qemu-nvme-sgl-bar](https://github.com/abraxas/qemu-nvme-sgl-bar) :  ![starts](https://img.shields.io/github/stars/abraxas/qemu-nvme-sgl-bar.svg) ![forks](https://img.shields.io/github/forks/abraxas/qemu-nvme-sgl-bar.svg)


## CVE-2019-8341
 An issue was discovered in Jinja2 2.10. The from_string function is prone to Server Side Template Injection (SSTI) where it takes the "source" parameter as a template object, renders it, and then returns it. The attacker can exploit it with {{INJECTION COMMANDS}} in a URI. NOTE: The maintainer and multiple third parties believe that this vulnerability isn't valid because users shouldn't use untrusted templates without sandboxing

- [https://github.com/alisster00/blueHarbor](https://github.com/alisster00/blueHarbor) :  ![starts](https://img.shields.io/github/stars/alisster00/blueHarbor.svg) ![forks](https://img.shields.io/github/forks/alisster00/blueHarbor.svg)


## CVE-2017-8176
 Huawei IPTV STB with earlier than IPTV STB V100R003C01LMYTa6SPC001 versions has an authentication bypass vulnerability. An attacker could exploit this vulnerability to access the serial interface and modify the configuration. Successful exploit could lead to the authentication bypass and view channels by free.

- [https://github.com/klks/swproxy](https://github.com/klks/swproxy) :  ![starts](https://img.shields.io/github/stars/klks/swproxy.svg) ![forks](https://img.shields.io/github/forks/klks/swproxy.svg)


## CVE-2017-7529
 Nginx versions since 0.5.6 up to and including 1.13.2 are vulnerable to integer overflow vulnerability in nginx range filter module resulting into leak of potentially sensitive information triggered by specially crafted request.

- [https://github.com/Guanyu-Zhou/hdu-is-work1-secure-flask-api](https://github.com/Guanyu-Zhou/hdu-is-work1-secure-flask-api) :  ![starts](https://img.shields.io/github/stars/Guanyu-Zhou/hdu-is-work1-secure-flask-api.svg) ![forks](https://img.shields.io/github/forks/Guanyu-Zhou/hdu-is-work1-secure-flask-api.svg)


## CVE-2017-7494
 Samba since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14 is vulnerable to remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share, and then cause the server to load and execute it.

- [https://github.com/JA-Cyber365/home-network-security-assessment](https://github.com/JA-Cyber365/home-network-security-assessment) :  ![starts](https://img.shields.io/github/stars/JA-Cyber365/home-network-security-assessment.svg) ![forks](https://img.shields.io/github/forks/JA-Cyber365/home-network-security-assessment.svg)


## CVE-2017-0144
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/duycao2311/eternalblue-ms17010-study](https://github.com/duycao2311/eternalblue-ms17010-study) :  ![starts](https://img.shields.io/github/stars/duycao2311/eternalblue-ms17010-study.svg) ![forks](https://img.shields.io/github/forks/duycao2311/eternalblue-ms17010-study.svg)


## CVE-2017-0143
 The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.

- [https://github.com/BlessingOlaniyan/cve-2017-0143-smbv1-analysis](https://github.com/BlessingOlaniyan/cve-2017-0143-smbv1-analysis) :  ![starts](https://img.shields.io/github/stars/BlessingOlaniyan/cve-2017-0143-smbv1-analysis.svg) ![forks](https://img.shields.io/github/forks/BlessingOlaniyan/cve-2017-0143-smbv1-analysis.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka "Dirty COW."

- [https://github.com/bL8nCO/Dirty-cow](https://github.com/bL8nCO/Dirty-cow) :  ![starts](https://img.shields.io/github/stars/bL8nCO/Dirty-cow.svg) ![forks](https://img.shields.io/github/forks/bL8nCO/Dirty-cow.svg)


## CVE-2015-9235
 In jsonwebtoken node module before 4.2.2 it is possible for an attacker to bypass verification when a token digitally signed with an asymmetric key (RS/ES family) of algorithms but instead the attacker send a token digitally signed with a symmetric algorithm (HS* family).

- [https://github.com/alisster00/blueHarbor](https://github.com/alisster00/blueHarbor) :  ![starts](https://img.shields.io/github/stars/alisster00/blueHarbor.svg) ![forks](https://img.shields.io/github/forks/alisster00/blueHarbor.svg)


# WAICT - Signalling and Integrity

Web Application Integrity, Consistency, and Transparency (WAICT) enables websites to opt-in to a stronger security model which provides enhanced security for user-agents. When a website has opted in to WAICT, user-agents can be assured that web applications served by the website have been publicly logged in a transparency service. This enables third parties to inspect the web application served to user-agents and so mitigate the risk of a compromised website serving malicious code. This security guarantee is particularly important for threat models where the server is not trusted by the user-agent, for example, in End-to-End Encrypted messaging.

WAICT's integrity model builds upon [Subresource Integrity (SRI)](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity) and the [Integrity-Policy header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy). This document describes how WAICT is signalled by user-agents and websites and how the integrity of web applications is assured. The transparency of web applications is described in a separate specification.

WAICT provides a stronger security property for user-agents, not servers, by making additional security checks on content fetched from the network. It does not constrain how user-agents locally modify pages, for example through user-agent preferences, extensions or other third-party additions.

# Conventions

This document uses Structured Field Values for HTTP ([RFC 9651](https://www.rfc-editor.org/rfc/rfc9651)) such as `sf-list`, `sf-integer`, `sf-boolean`, and `sf-token`.

In this document, `origin` refers to the tuple (scheme, host, port) as defined in [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454).

Where this document refers to base64 encoding, it means the standard alphabet defined in [RFC 4648 Section 4](https://www.rfc-editor.org/rfc/rfc4648#section-4) (using `+` and `/` with `=` padding).

> [!NOTE]
> Editorial comments are indicated by the use of notes like these. These will be removed in the future.

# Negotiating WAICT Support

User-agents SHOULD signal that they support WAICT to the server through the use of user-agent client hints. Doing so will allow the server to avoid sending unnecessary information to user-agents which don't support WAICT.

To signal WAICT support, the [user agent client hint](https://wicg.github.io/ua-client-hints/) `Sec-CH-WAICT` is used whose value is a `sf-list` of `sf-integers`. Each integer represents a supported version of WAICT. This specification defines version `1`. If user-agents include a `Sec-CH-WAICT` header in their requests, the included version numbers MUST be supported by the user-agent.

Servers supporting WAICT SHOULD actively solicit client hints for WAICT by including `Sec-CH-WAICT` in their `Accept-CH` response header (See [Section 3.1 of RFC 8942](https://www.rfc-editor.org/rfc/rfc8942#section-3.1)). Servers MUST tolerate unknown integers in the `Sec-CH-WAICT` request header.

For example, a user-agent that supports versions 1 and 2 of WAICT might send:

`Sec-CH-WAICT: 1, 2`
For example, a user-agent that supports versions 1 and 2 of WAICT might send:

```HTTP
Sec-CH-WAICT: 1, 2
```

# Signalling Use of WAICT

## Response Header

Websites signal that they want user-agents to enforce WAICT through the use of the HTTP response header: `Integrity-Policy-WAICT-v1`.

The header is a structured response header (Dictionary type per [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651)). The following key-value pairs MUST be present:

* `max-age` - An `sf-integer` that MUST be `>= 0`. How long (in seconds) user-agents MUST enforce WAICT after seeing this header (downgrade protection).
* `mode` - An `sf-token` containing either `enforce` or `report`. In `enforce` mode, subresources that fail integrity checks are blocked from loading. In `report` mode, failures are reported but resources are still loaded.
* `manifest` - An `sf-string` containing a URL where the user-agent can fetch the WAICT manifest. The URL MAY be relative, in which case it is resolved against the origin's base URL.
* `blocked-destinations` - An `sf-inner-list` of one or more `sf-tokens` indicating the destination types (e.g., `script`, `style`) to which integrity checks apply. Values are drawn from the [`destination`](https://fetch.spec.whatwg.org/#destination-type) type as defined in the Fetch spec. Unrecognized tokens MUST be ignored.

If one or more of the mandatory keys is missing or invalid, the entire header MUST be ignored.
The following key-value pairs are optional:

* `preload` - An `sf-boolean`. Indicates the site wants to enforce WAICT indefinitely (with transparency enabled) via a preload list. This field is not used directly by user-agents. `?0` (false) by default.
* `endpoints` - Indicates endpoint(s) for submitting violations following [Integrity Policy Reporting](https://w3c.github.io/webappsec-subresource-integrity/#integrity-policy-section). Empty by default.

Any other keys MUST be ignored.  Servers MAY set additional keys prefixed `GREASE-` which user-agents MUST ignore.

The data located at the `manifest` URL in MUST be immutable, i.e., the unencoded response body of a successful GET request to that URL MUST never change. To achieve this, implementers SHOULD include a SHA-256 hash of the unencoded response body in the URL itself, encoded in base64url, and truncated to 22 characters (corresponding to 128 bits of the hash).

An example header is given below:

```
Integrity-Policy-WAICT-v1: max-age=90, mode=report, blocked-destinations=(script style), preload=?0, endpoints=(foo-reports), manifest="/.well-known/waict/manifests/baz_manifest_5X_MjpjR0bpBpP3dEF6-hA.json"
```

Websites using WAICT SHOULD set this response header on all of their same-origin responses.

## User-Agent Processing of Response Header

### Scope

WAICT state is scoped to the top-level origin and applies to requests made within the context of that origin. It does not extend to requests made by other top-level origins and so is compatible with the partitioning of state by top-level origin.
When an origin is using WAICT, all requests made with a same site [top-level navigation initiator origin](https://fetch.spec.whatwg.org/#ref-for-request-top-level-navigation-initiator-origin) will be impacted by the WAICT security policy.

When processing a response whose origin is the same site as the [top-level navigation initiator origin](https://fetch.spec.whatwg.org/#ref-for-request-top-level-navigation-initiator-origin), user-agents MUST check for valid `Integrity-Policy-WAICT-v1` response headers and SHOULD store the WAICT configuration for this origin for at most `max-age` seconds from the present. This information is partitioned to the top-level origin.

However, WAICT does not impact requests made to a WAICT-enforcing domain in other top-level contexts if those top-level contexts do not advertise WAICT themselves. User-agents MUST ignore `Integrity-Policy-WAICT-v1` headers set on responses whose origin does not match their current top-level navigation initiator origin. An example:

* `foo.com` and `bar.com` both embed resources located on each other's domains
* `foo.com` uses WAICT and sets an enforcement header. `bar.com` does not use WAICT.
User-agents MUST store WAICT state for a top-level origin in order to prevent downgrade attacks. WAICT state is partitioned by top-level origin. For each top-level origin, the user-agent SHOULD store the record:
* User-agents which navigate to `bar.com` will not enforce WAICT, even when loading sub-resources from `foo.com`.



### Storage

User-agents MUST store WAICT state for a top-level origin in order to prevent downgrade attacks. WAICT state is partitioned by top-level origin. For each top-level origin, the user-agent SHOULD store:

* The list of reporting endpoints
* The manifest url
* For each supported entry in `blocked-destinations`:
  * The mode (`enforce` or `report`)
  * The effective expiry time (`max-age` seconds from when the header was last seen)

The user-agent MUST clear the state for `blocked-destinations` when it reaches its effective expiry time and MAY clear it sooner. There may be situations in which user-agents are unable to store the information described above. For example, user-agents may not have access to long-term state (e.g. they are running in a private browsing mode). Such user-agents SHOULD store the record for as long as they are able.

### Upgrades and Downgrades

Origins may change their WAICT header over time. For example, an origin may evaluate WAICT in report mode and later switch to enforce mode. Alternatively, a site may be enforcing WAICT and wish to change the scope of covered resources, or even disable WAICT entirely. However, user-agents MUST enforce certain rules to prevent downgrade attacks - where a site alters its WAICT signalling in order to enable attacks.

User-agents MUST follow this algorithm when updating their WAICT state:

1. Overwrite the list of reporting endpoints with the latest contents of `endpoints`.
2. Overwrite the manifest url with the latest `manifest` entry.
3. For each supported entry in `blocked-destinations`,
   1. If there is no existing record, store the new record.
   2. Otherwise, if there is an existing record, compare the existing and new record:
      1. If the new record is `enforce` and the previous record was `report`, update the entry with the new mode and effective expiry, or
      2. If the new record has the same mode as the existing record and the new effective expiry time is further in the future, update the effective expiry time.
      3. Otherwise, ignore the new record.

Any record which has reached its effective expiry time MUST be ignored and SHOULD be removed.

This algorithm ensures that sites can upgrade their WAICT coverage immediately. However, a site can only downgrade their WAICT coverage after `max-age` seconds pass since they last served a header enforcing coverage for that destination type.

> [!NOTE]
> These rules are awkward if a site wants to expand its coverage of resources (e.g. add a new resource type), so would like to enable report-only for the newly covered resources but maintain enforce for the existing resources. Three possible solutions: a) Ignore this issue. b) Use two separate lists for report / enforced destinations. c) Use two separate headers for reporting / enforcement. Currently tilting towards option b) after discussion.

### Preloading

Websites can signal their desire for user-agent vendors to preload WAICT status onto their user-agents. Preloading is not a signal consumed directly by user-agents and user-agents MUST ignore this parameter.

As a general rule, websites SHOULD NOT preload WAICT status. Preloading WAICT may lead to irrecoverable errors for user-agents.

The details of how user-agent vendors are alerted to this are vendor-specific, but websites wishing user-agent vendors to preload MUST use an `Integrity-Policy-WAICT-v1` header with:

* `mode` set to `enforce`.
* `preload` set to `?1`.
* `max-age` set to a value greater than or equal to 1 year (`31536000` seconds).

User-agent vendors may configure user-agents with preload information via their vendor-specific out-of-band channels. Such user-agents SHOULD enforce WAICT as long as their vendor-supplied preload list is up to date.

Vendors may choose different cutoffs for when they consider a preload list to be stale, but are RECOMMENDED to use a value of 30 days. That is, if a user-agent goes 30 days without receiving an updated preload list, it SHOULD stop enforcing entries on the preload list.

# WAICT Manifests

WAICT manifests provide a public commitment to the web application(s) being served by the origin. The manifest describes both the individual resources used to provide the application and a proof that it has been logged publicly.

## Fetching Manifests

When a site is operating in `enforce` mode, network fetches for covered resources will be unable to complete successfully until a manifest is available. When a site is operating in `report` mode, network fetches for covered resources will be unable to complete successfully until a manifest is available or an implementation-defined timeout occurs. User-agents SHOULD fetch WAICT manifests with high priority as soon as they become aware of them.

The manifest located at a given URL is expected to be immutable and SHOULD have appropriate cache directives set by the server. Sites can notify user-agents that an updated manifest is available by adjusting the `manifest` field of the WAICT header. User-agents only need to store the contents of one manifest per top-level origin at a time.

GETting a URL referenced in the `manifest` field in `Integrity-Policy-WAICT-v1` MUST result in a response of content type `application/waict-integrity-manifest` as described in the next section.

## Manifest Structure

The integrity manifest is a JSON object with the following structure:

* The `hashes` field is a dictionary mapping URLs to hashes. All hashes MUST use the SHA-256 algorithm and be base64-encoded. Keys MUST be unique; if a JSON parser encounters duplicate keys, the manifest SHOULD be rejected as invalid. This field MUST be present.
* The `wildcard_hashes` field is an optional lexicographically sorted list of unique SHA-256 hashes (base64-encoded). The sorted order enables efficient membership testing by user-agents.
* The `resource_delimiter` field is an optional string.
* The `transparency_proof` field contains base64-encoded data. This field MUST be present.

An example is given below:

```json
{
  "hashes": {
    "/assets/x.html": "r4j9yW07mpTFSQ6ZRYOV0Au8Hfn2NqjqQMBqKL/SWCY=",
    "/assets/css/main.css": "zet5ebcBGt1+fr6F0vJbpOv7p4tV/fIbFH4AafxtBl0=",
    "/favicon.ico": "zbt5ebcBGt1+gr6F0vJbpOv7p4tV/fIbFH4AafxtBl0="
  },
  "wildcard_hashes": [
    "mVuswfW4XCBOWbx+QiKkPPQy+gTfr+i1sVADexgyN+8=",
    "H9OJUrESfT3SUlRpqAiDFEvqnnG2Sp9/eloyVMqxnnb=",
    "0SsmrVFFC7wxU4QM5UeZeXBnyKlXTAzfkVsZXIrzabo="
  ],
  "resource_delimiter": "/* MY DELIM */",
  "transparency_proof": "Lbzg/T0VD/HIUTRcTcU0/zbtSeT2302RKTc0Vf..."
}
```

The meaning and use of these fields is described in the next section.

> [!NOTE]
> The `wildcard_hashes` and `resource_delimiter` fields may be removed if we can find a suitable alternative, e.g. using service workers to unbundle JS resources.

## Validating Manifests

Manifests must be parsed and validated subject to the following rules:

* The mandatory keys `hashes` and `transparency_proof` MUST be present.
* Unrecognized top level keys MUST be ignored.
* Hash values in `hashes` and `wildcard_hashes` must be valid base64 ([RFC 4648 Section 4](https://www.rfc-editor.org/rfc/rfc4648#section-4)) and decode to exactly 32 bytes.
* Each key of `hashes` must be parsed with the [API URL Parser](https://url.spec.whatwg.org/#api-url-parser) using the top-level origin (serialized as `scheme://host:port/`) as base URL (note, this permits external URLs; the base is only applied when the provided URL is relative). If parsing fails, the manifest is invalid. The parsed URL MUST have an empty [fragment](https://url.spec.whatwg.org/#concept-url-fragment); if it does, the manifest is invalid. After parsing, the key's canonical form is the [URL serialization](https://url.spec.whatwg.org/#concept-url-serializer) of the parsed URL with the *exclude fragment* flag set. If two keys produce the same canonical form, the manifest is invalid.

The cryptographic proof of transparency conveyed in `transparency_proof` must be validated according to the TODO specification.

Manifests which do not follow these rules are invalid and MUST not be used.

# Changes to Network Fetches

This section describes how WAICT modifies the lifecycle of network fetches for covered resources. The modifications are described in terms of the [Fetch Standard](https://fetch.spec.whatwg.org/) algorithms: [`fetch`](https://fetch.spec.whatwg.org/#concept-fetch) (the entry point), [`main fetch`](https://fetch.spec.whatwg.org/#concept-main-fetch) (security checks, response handling, and integrity verification), and [`fetch response handover`](https://fetch.spec.whatwg.org/#fetch-finale) (delivery of the response to the caller). See also the Fetch Standard's guidance on [invoking fetch and processing responses](https://fetch.spec.whatwg.org/#fetch-elsewhere-fetch).

WAICT integrity checks apply to the unencoded response bytes delivered to the document, after any processing by [Service Workers](https://www.w3.org/TR/service-workers/). This is consistent with the behavior of [SRI](https://www.w3.org/TR/sri-2/).

## Determine Coverage

Before [`fetch`](https://fetch.spec.whatwg.org/#concept-fetch) is invoked, the user-agent determines whether the request is covered by the WAICT policy by checking the [request](https://fetch.spec.whatwg.org/#concept-request)'s [`destination`](https://fetch.spec.whatwg.org/#concept-request-destination) against the stored `blocked-destinations` list for the top-level origin. This information is conveyed in the `Integrity-Policy-WAICT-v1` response header and is always available to the user-agent, even if the manifest has not yet been loaded.

If the destination does not appear in the `blocked-destinations` list, the fetch proceeds without WAICT processing.
Otherwise, the fetch is subject to the integrity checks described below.

### Interaction with SRI and Integrity Policy

[SRI](https://www.w3.org/TR/sri-2/) and [Integrity Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy) are alternative sources of integrity metadata and policy rules for enforcing integrity. When handling a request which is covered by WAICT, the user agent MUST ignore any provided SRI metadata and any applicable integrity policy. This allows origins to offer support for all three standards simultaneously without requiring user-agents to hash resources multiple times or enter inconsistent enforcement states.

> [!NOTE]
> In the future, we may look to merge these specifications or rely on them explicitly.

## Request Setup

The [`fetch`](https://fetch.spec.whatwg.org/#concept-fetch) algorithm sets up the request (populating headers, priority, and other properties) before invoking [`main fetch`](https://fetch.spec.whatwg.org/#concept-main-fetch). For a covered request, WAICT adds the following steps during this request setup phase.

The user-agent SHOULD [append](https://fetch.spec.whatwg.org/#concept-header-list-append) (`Integrity-Policy-WAICT-v1-Req`, *manifest-url*) to the request's [header list](https://fetch.spec.whatwg.org/#concept-request-header-list), where *manifest-url* is the URL of the manifest currently in use for this top-level origin. This allows the server to identify which version of its resources the user-agent expects and respond appropriately. For example:

```
Integrity-Policy-WAICT-v1-Req: "/.well-known/waict/manifests/1.json"
```

WAICT v1 always uses SHA-256 for hashing. This allows the user-agent to begin hashing covered resources from the start of a request, even if no manifest is yet available to specify the expected SHA-256 hash. User-agents SHOULD compute the SHA-256 hash incrementally as response body chunks arrive, consistent with existing [SRI](https://www.w3.org/TR/sri-2/) behavior.

## Integrity Check

After [`main fetch`](https://fetch.spec.whatwg.org/#concept-main-fetch) dispatches the request and receives a response, it applies [filtered response](https://fetch.spec.whatwg.org/#concept-filtered-response) wrapping and response blocking checks, then performs integrity verification before proceeding to [`fetch response handover`](https://fetch.spec.whatwg.org/#fetch-finale).

The existing `main fetch` algorithm already handles [SRI integrity checking](https://w3c.github.io/webappsec-subresource-integrity/#does-response-match-metadatalist) when a request's [integrity metadata](https://fetch.spec.whatwg.org/#concept-request-integrity-metadata) is nonempty: the response body is [fully read](https://fetch.spec.whatwg.org/#body-fully-read), checked against the metadata, and only then passed to `fetch response handover`. WAICT extends this step to also cover the case where integrity metadata comes from a manifest rather than an inline attribute.

The response body is [fully read](https://fetch.spec.whatwg.org/#body-fully-read) and the user-agent proceeds as follows:

1. Wait for the manifest to be available. If the manifest cannot be fetched within an implementation-defined timeout, fail with reason `manifest_unavailable`.
2. If the manifest response is not valid JSON, has unexpected types for any field, or is missing required fields (`hashes` or `transparency_proof`), the user-agent MUST treat this as a failure with reason `invalid_manifest`.
3. Let `reqURL` be the request's [URL](https://fetch.spec.whatwg.org/#concept-request-url) as it was at the time [`fetch`](https://fetch.spec.whatwg.org/#concept-fetch) was invoked, prior to any redirects. Let `reqKey` be the [URL serialization](https://url.spec.whatwg.org/#concept-url-serializer) of `reqURL` with the *exclude fragment* flag set.
4. Let `b` be the bytes of the response body and `h` be the base64-encoded SHA-256 hash of `b`.
5. Let `pathHash` be the hash value from `manifest["hashes"]` whose key's canonical form (as defined in [Validating Manifests](#validating-manifests)) equals `reqKey`, or `undefined` if no such entry exists.
6. Let `wildcardHashes = manifest["wildcard_hashes"]`, or `undefined` if not present.
7. If `pathHash` is defined, compare `h` to `pathHash`. If they match, return success. Otherwise, fail with reason `no_manifest_match`. A resource whose URL appears in `hashes` MUST match via its `pathHash`; the wildcard check is never used as a fallback.
8. If `wildcardHashes` is defined and non-empty and `resource_delimiter` is defined and non-empty:
    1. Let `d` be `resource_delimiter`.
    1. For each component `b_i` of `bb`, compute `SHA-256(b_i)`, base64-encode it, and check whether the result is a member of `wildcardHashes`. If all components match, return success. Otherwise, fail with reason `no_manifest_match`.
1. Fail with reason `missing_from_manifest`.

If the integrity check succeeds, `main fetch` proceeds to [`fetch response handover`](https://fetch.spec.whatwg.org/#fetch-finale) with the verified response. If it fails, the behavior depends on the WAICT mode as described in [Handling Failures](#handling-failures).

### Speculative Processing

Some user-agents begin processing responses before they are complete, for example, streaming HTML into a parser or rendering an incomplete image. The user-agent's processing of incomplete responses MUST NOT be observable from within the document's context until the integrity check has completed and `main fetch` has proceeded to `fetch response handover`.

> [!NOTE]
> This is intended to enable user-agents to engage in unobservable actions like speculatively fetching subresources from unverified responses which are critical for performance, provided those actions can't be used to bypass integrity checks.

## Handling Failures

When an integrity check fails, the user-agent MUST take the following actions.

### Reporting

In both `report` and `enforce` modes, the user-agent MUST:

* Log the failure to the browser console and developer tools.
* If `endpoints` is non-empty, report the error as a `waict-violation` to the specified endpoints following the [Reporting API](https://developer.mozilla.org/en-US/docs/Web/API/Reporting_API).

The `waict-violation` report `body` includes the keys and values from [IntegrityViolationReportBody](https://developer.mozilla.org/en-US/docs/Web/API/IntegrityViolationReportBody), enriched with an entry `reason` indicating the cause of the failure:

* `manifest_unavailable` - The manifest for the origin could not be loaded.
* `invalid_manifest` - The manifest was loaded, but was malformed, had unexpected types, or was missing required fields (including `transparency_proof`).
* `invalid_transparency_proof` - A manifest and transparency proof were provided, but the proof could not be parsed.
* `missing_from_manifest` - A valid manifest was available, but this resource was not covered.
* `no_manifest_match` - A valid manifest was available and described this resource, but the resource did not match the manifest entry.

### Report Mode

In `report` mode, the user-agent MUST still load the resource. Report mode is intended for web developers to validate their deployment; it does not provide security for user-agents.

Compliant user-agents SHALL NOT display error messages to end-users who have not indicated they wish to see additional technical information.

### Enforce Mode

In `enforce` mode, the behavior depends on the failure type:

* `manifest_unavailable`, `invalid_manifest`, `invalid_transparency_proof` - the user-agent MUST display a warning page to the user indicating the error. The user-agent SHOULD NOT allow the user to bypass the warning.
* `missing_from_manifest`, `no_manifest_match` -The user-agent MUST return an appropriate [network error](https://fetch.spec.whatwg.org/#concept-network-error) for the fetch.

# Non-Normative Appendices

## Server Operator Advice

Server operators should be cautious when deploying WAICT enforcement. In general, there is no recourse for a faulty deployment in `enforce` mode, other than waiting out the `max-age` period. In the event of a faulty deployment and the use of `preload`, the waiting-out period is potentially unbounded.

Server operators are recommended to deploy WAICT in `report` mode initially and gain confidence in their deployment gradually. Server operators should treat reported errors seriously. Every reported error will result in a broken user-agent if `enforce` is enabled.

Once a server operator has become confident in their use of `report` mode, they should consider switching to `enforce` mode with a low `max-age`, e.g. on the order of minutes. As time passes, server operators should consider raising the `max-age`.

The exact age that server operators settle on is a tradeoff between the maximum recovery time for their site and how often users are expected to visit their site and still need a security benefit.

The use of preload is a specialist feature which is unlikely to be suitable for the majority of sites using WAICT. Sites should only enable preload if they are committed to making their site unavailable when WAICT is unavailable.

Sites wishing to stop using WAICT should stop serving the enforcement header and wait out their previously set `max-age`. Sites may be able to unenroll through the use of the opt-out signal described in the [proofs specification](waict-proofs.md).

### Web Application Versioning

When deploying a web application (without WAICT), operators must ensure clients observe a consistent version of the application. For example, if an application depends on foo.js and bar.js, a deployment can break if a client loads an older version of foo.js alongside a newer version of bar.js.

WAICT is designed to interoperate cleanly with existing versioning strategies that provide atomic application views. The WAICT manifest is simply another versioned resource and should be treated the same way as the associated scripts and assets.

In practice, operators need only ensure that any response carrying a WAICT header references a manifest that includes the served resource. This can be handled at build time: generate the manifest as part of the existing versioning process and associate it with the corresponding artifacts so the correct header is emitted with each response.

When publishing a new version of the application, the new resources can be associated with the new manifest.

## Security Considerations

This design emulates that of RFC 6797 (HSTS).

A key constraint is that user-agent vendors typically cannot ensure that their user-agents have consistent or non-stale configurations. Further, connection failures to valid websites for stale user-agents are intolerable to website operators.

As a consequence, this design ensures that websites continue to maintain availability if a user-agent has stale data (enforced via the `max-age` signals on headers and preload lists). This also means that security is only available for non-stale user-agents.

The use of the `Integrity-Policy-WAICT-v1` header is essential for the overall security of WAICT. User-agents must be aware of the need to enforce WAICT in order to gain security benefits from it.

User-agents only gain a security benefit from the use of `enforce` mode. User-agents do not gain a security benefit from the use of `report` mode.

WAICT V1 forces the use of SHA256 for hashing, unlike SRI which supports a family of hash functions. Using a fixed hash function is necessary to enable user-agents to begin hashing integrity-checked resources before a manifest is available (and so preserve existing website performance). If the security of SHA256 is called into question by future cryptologic advances, a new version of WAICT will need to be defined with a new hash function.

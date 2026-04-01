# WAICT - Signalling and Integrity

Web Application Integrity, Consistency, and Transparency (WAICT) enables websites to opt-in to a stronger security model which provides enhanced security for user-agents. When a website has opted in to WAICT, user-agents can be assured that web applications served by the website have been publicly logged with a transparency service.

This enables third parties to inspect the web application served to user-agents and so mitigate the risk of a compromised website serving malicious code. This security guarantee is particularly important for threat models where the server is not trusted by the user-agent, for example, in End-to-End Encrypted messaging.

WAICT's integrity model builds upon [Subresource Integrity (SRI)](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity) and the [Integrity-Policy header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy). This document describes how WAICT is signalled by user-agents and websites and how the integrity of web applications is assured. The transparency of web applications is described in a separate specification.

WAICT provides a stronger security property for user-agents, not servers, by making additional security checks on content fetched from the network. It does not constrain how user-agents locally modify pages, for example through user-agent preferences, extensions or other third-party additions.

# Conventions

This document uses Structured Field Values for HTTP ([RFC 9651](https://www.rfc-editor.org/rfc/rfc9651)) such as `sf-list`, `sf-integer`, `sf-boolean`, and `sf-token`.

In this document, `origin` refers to the tuple (scheme, host, port) as defined in [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454).

Where this document refers to base64 encoding, it means the standard alphabet defined in [RFC 4648 Section 4](https://www.rfc-editor.org/rfc/rfc4648#section-4) (using `+` and `/` with `=` padding). Where this document refers to base64urlnopad encoding, it means the URL-safe alphabet defined in [RFC 4648 Section 5](https://www.rfc-editor.org/rfc/rfc4648#section-5) (using `-` and `_`), with padding (`=`) omitted.

> [!NOTE]
> Editorial comments are indicated by the use of notes like these. These will be removed in the future.

# Negotiating WAICT Support

User-agents SHOULD signal that they support WAICT to the server through the use of user-agent client hints. Doing so will allow the server to avoid sending unnecessary information to user-agents which don't support WAICT.

To signal WAICT support, the [user agent client hint](https://wicg.github.io/ua-client-hints/) `Sec-CH-WAICT` is used whose value is a `sf-list` of `sf-integers`. Each integer represents a supported version of WAICT. This specification defines version `1`. If user-agents include a `Sec-CH-WAICT` header in their requests, the included version numbers MUST be supported by the user-agent.

Servers supporting WAICT SHOULD actively solicit client hints for WAICT by including `Sec-CH-WAICT` in their `Accept-CH` response header (See [Section 3.1 of RFC 8942](https://www.rfc-editor.org/rfc/rfc8942#section-3.1)). Servers MUST tolerate unknown integers in the `Sec-CH-WAICT` request header.

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

If one or more of the mandatory keys is missing or invalid, the entire header MUST be ignored.

The following key-value pairs are optional:

* `preload` - An `sf-boolean`. Indicates the site wants to enforce WAICT indefinitely (with transparency enabled) via a preload list. This field is not used directly by user-agents. `?0` (false) by default.
* `endpoints` - Indicates endpoint(s) for submitting violations following [Integrity Policy Reporting](https://w3c.github.io/webappsec-subresource-integrity/#integrity-policy-section). Empty by default.

Any other keys MUST be ignored. Servers MAY set additional keys prefixed `GREASE-` which user-agents MUST ignore.

The data located at the `manifest` URL MUST be immutable, i.e., the unencoded response body of a successful GET request to that URL MUST never change. To achieve this, implementers SHOULD include a SHA-256 hash of the unencoded response body in the URL itself, encoded in base64url, and truncated to 22 characters (equivalent to base64urlnopad truncated to 22 characters; this encodes 128 bits).

An example header is given below:

```HTTP
Integrity-Policy-WAICT-v1: max-age=90, mode=report, preload=?0, endpoints=(foo-reports), manifest="/.well-known/waict/manifests/baz_manifest_5X_MjpjR0bpBpP3dEF6-hA"
```

Websites using WAICT MUST set a WAICT response header on top-level navigation responses. Websites MAY additionally set the header on subresource responses as a defence in depth measure against user-agents with stale manifests (see [Manifest Override on Subresource Responses](#manifest-override-on-subresource-responses)).

## User-Agent Processing of Response Header

### Scope

WAICT state is scoped to the top-level origin and applies to requests made within the context of that origin. It does not extend to requests made by other top-level origins and so is compatible with the partitioning of state by top-level origin.

When an origin is using WAICT, all requests made with a same site [top-level navigation initiator origin](https://fetch.spec.whatwg.org/#ref-for-request-top-level-navigation-initiator-origin) will be impacted by the WAICT security policy.

When processing a response whose origin is the same site as the [top-level navigation initiator origin](https://fetch.spec.whatwg.org/#ref-for-request-top-level-navigation-initiator-origin), user-agents MUST check for valid `Integrity-Policy-WAICT-v1` response headers and SHOULD store the WAICT configuration for this origin for at most `max-age` seconds from the present. This information is partitioned to the top-level origin.

However, WAICT does not impact requests made to a WAICT-enforcing domain in other top-level contexts if those top-level contexts do not advertise WAICT themselves. User-agents MUST ignore `Integrity-Policy-WAICT-v1` headers set on responses whose origin does not match their current top-level navigation initiator origin. An example:

* `foo.com` and `bar.com` both embed resources located on each other's domains
* `foo.com` uses WAICT and sets an enforcement header. `bar.com` does not use WAICT.
* User-agents which navigate to `foo.com` will enforce WAICT, even when loading sub-resources from `bar.com`.
* User-agents which navigate to `bar.com` will not enforce WAICT, even when loading sub-resources from `foo.com`.

When an `<iframe>` loads a document from the same origin as the top-level page, the iframe's document and all of its subresources are subject to the same WAICT integrity checks as the top-level page. When an `<iframe>` loads a document from a different origin, the iframe's own subresources are only subject to WAICT if that origin independently advertises WAICT.

### Storage

User-agents MUST store WAICT state for a top-level origin in order to prevent downgrade attacks. WAICT state is partitioned by top-level origin. For each top-level origin, the user-agent SHOULD store the record:

* The list of reporting endpoints
* The manifest URL
* The mode (`enforce` or `report`)
* The effective expiry time (`max-age` seconds from when the header was last seen)

The user-agent MUST clear the state when it reaches its effective expiry time and MAY clear it sooner. There may be situations in which user-agents are unable to store the information described above. For example, user-agents may not have access to long-term state (e.g. they are running in a private browsing mode). Such user-agents SHOULD store the record for as long as they are able.

### Validating Existing Service Worker and Cache

When a user-agent first observes a valid `Integrity-Policy-WAICT-v1` header for an origin (i.e., no prior WAICT state exists for that origin), or when it fetches a new manifest for an origin that differs from the previously stored manifest URL, the user-agent MUST trigger an update check for any Service Workers registered for the top-level origin. The user-agent MUST prevent any existing Service Worker from intercepting covered fetches until the update check has completed. If the updated Service Worker script passes the WAICT integrity check against the current manifest, the update MAY proceed to install and activate normally. If the integrity check fails, the update MUST be rejected following the failure handling described in [Handling Failures](#handling-failures), and the existing Service Worker MUST be unregistered.

WAICT integrity checks apply to all covered responses regardless of whether they were served from the network or the HTTP cache. User-agents MUST NOT exempt cached responses from integrity checking.

### Upgrades and Downgrades

Origins may change their WAICT header over time. For example, an origin may evaluate WAICT in report mode and later switch to enforce mode. Alternatively, a site may be enforcing WAICT and wish to change the scope of covered resources, or even disable WAICT entirely. However, user-agents MUST enforce certain rules to prevent downgrade attacks - where a site alters its WAICT signalling in order to enable attacks.

User-agents MUST follow this algorithm when updating their WAICT state:

1. Overwrite the list of reporting endpoints with the latest contents of `endpoints`.
2. Overwrite the manifest URL with the latest `manifest` entry.
3. If there is no existing mode, store the new mode.
4. Otherwise, if there is an existing mode, compare the existing and new mode:
   1. If the new mode is `enforce` and the previous record was `report`, update the entry with the new mode and effective expiry, or
   2. If the new mode has the same mode as the existing mode and the new effective expiry time is further in the future, update the effective expiry time.
   3. Otherwise, ignore the new record.

Any record which has reached its effective expiry time MUST be ignored and SHOULD be removed.

This algorithm ensures that sites can upgrade their WAICT coverage immediately. However, a site can only downgrade their WAICT coverage after `max-age` seconds pass since they last served a header.

### Preloading

Websites can signal their desire for user-agent vendors to preload WAICT status onto their user-agents. Preloading is not a signal consumed directly by user-agents and user-agents MUST ignore this parameter.

As a general rule, websites SHOULD NOT request user-agents preload their WAICT status. Preloading WAICT may lead to irrecoverable errors for user-agents.

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

The manifest located at a given URL is expected to be immutable and SHOULD have its response set [`Cache-Control`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control) to include `immutable` and a long `max-age`. Sites can notify user-agents that an updated manifest is available by updating the `manifest` field of the WAICT header. User-agents only need to store the contents of one manifest per top-level origin at a time.

The response content type of a successful GET to a URL referenced in the `manifest` field in `Integrity-Policy-WAICT-v1` MUST be `application/waict-integrity-manifest` (TODO: reserve this MIME type). Responses with this type contain a _manifest_ JSON blob whose structure is defined in the next section, and a _transparency proof_ line. More precisely, the response body is of the form:
```
manifest | U+000A | transparency_proof | U+000A
```
where `|` represents concatenation, `manifest` a UTF-8-encoded JSON object, and `transparency_proof` is a base64 encoding of the `WaictInclusionProof` specified in TODO, proving inclusion of `manifest` in a tree. Note the parsing of a response is unique, since `transparency_proof` cannot have a newline in it. The user-agent MUST reject a response that is invalid UTF-8, contains fewer than two U+000A codepoints, contains a `manifest` that is not valid JSON, or contains a `transparency_proof`.


Servers SHOULD use a suitable compression scheme as negotiated by the user-agent.

## Manifest Structure

The integrity manifest is a JSON object with the following structure. All fields are mandatory unless marked optional:

* `hashes` — a dictionary mapping URLs to hashes. All hashes MUST use the SHA-256 algorithm and be base64urlnopad-encoded.
* `wasm_hashes` (optional) — a lexicographically sorted list of unique SHA-256 hashes (base64urlnopad) of permitted WebAssembly module bytes. The sorted order enables efficient membership testing by user-agents. See [Changes to WebAssembly Processing](#changes-to-webassembly-processing).
* `wildcard_hashes` (optional) — a lexicographically sorted list of unique SHA-256 hashes (base64urlnopad-encoded). The sorted order enables efficient membership testing by user-agents.
* `resource_delimiter` (optional) — a string used for splitting subresource contents.
* `emergency_opt_out` (optional) — a boolean used when the origin needs to disable WAICT immediately. Default is `false`

When a manifest has `emergency_opt_out = true`, we say it is a **tombstone**, since it is used to indicate that the origin has unenrolled from WAICT. No integrity checking happens when a tombstone manifest is active. For consistency, it is required that even tombstone manifests contain the mandatory fields.

> [!NOTE]
> The `wildcard_hashes` and `resource_delimiter` fields may be removed if we can find a suitable alternative, e.g. using service workers to unbundle JS resources.

An example is given below:

```json
{
  "hashes": {
    "/assets/x.html": "r4j9yW07mpTFSQ6ZRYOV0Au8Hfn2NqjqQMBqKL/SWCY=",
    "https://my-fave-cdn.example/assets/css/main.css": "zet5ebcBGt1+fr6F0vJbpOv7p4tV/fIbFH4AafxtBl0=",
    "/favicon.ico": "zbt5ebcBGt1+gr6F0vJbpOv7p4tV/fIbFH4AafxtBl0="
  },
  "wasm_hashes": [
    "Aq3rP9FkR8vLHnUGT5OgP7xmNyvDh2YcfJLmzgSEz7o=",
    "kJ2E9N8C3vR5xP7yQwL4mFbA6dH0jT2uK9sG1nO3iVc="
  ],
  "wildcard_hashes": [
    "mVuswfW4XCBOWbx+QiKkPPQy+gTfr+i1sVADexgyN+8=",
    "H9OJUrESfT3SUlRpqAiDFEvqnnG2Sp9/eloyVMqxnnb=",
    "0SsmrVFFC7wxU4QM5UeZeXBnyKlXTAzfkVsZXIrzabo="
  ],
  "resource_delimiter": "/* MY DELIM */"
}
```

All top-level items not specified above MUST be ignored. If there are duplicate keys at any level, then the last occurrence is the one used in the parsed result.

The meaning and use of these fields is described in the next section.

## Validating Manifests

Manifests do not need to be validated in their entirety before they are used for integrity checking. However, if a user-agent finds a violation of any of the below rules during its use of a manifest, it MUST mark it internally as an invalid manifest. This will cause all future integrity checks with respect to this manifest to fail, as described below in the integrity checking algorithm. This mark MUST be retained for as long as the manifest is cached by the user-agent.

Manifests MUST have the following properties:

* If the manifest was linked to by a WAICT integrity policy header with nonzero `max-age` that is still in effect, then the transparency proof is successfully parsed and checked using the algorithm in TODO
* All mandatory keys are present.
* If the manifest is non-tombstone:
  * Values in `hashes`, `wasm_hashes`, and `wildcard_hashes` are valid base64urlnopad ([RFC   4648 Section 4](https://www.rfc-editor.org/rfc/rfc4648#section-4)) and decode to exactly 32   bytes.
  * Each key `s` of `hashes` is a _canonical_ URL, defined as follows. `s` is parsed with the [API URL Parser](https://url.spec.whatwg.org/#api-url-parser) using the top-level origin (serialized as `scheme://host:port/`) as base URL (note, this permits external URLs; the base is only applied when the provided URL is relative), and any [fragment](https://url.spec.whatwg.org/#concept-url-fragment) is removed. The result is then [URL-serialized](https://url.spec.whatwg.org/#concept-url-serializer) with the *exclude fragment* flag set. `s` is canonical when this serialization equals `s`.

The first property above allows origins to keep WAICT transparency disabled by always setting the policy's `max-age` to 0, and serving an empty string (or any other newline-free string) as the transparency proof. Note the non-tombstone conditional means that manifests MUST be treated as tombstones even when the entries in all the fields are invalid.

# Changes to Network Fetches

This section describes how WAICT modifies the lifecycle of network fetches for covered resources. The modifications are described in terms of the [Fetch Standard](https://fetch.spec.whatwg.org/) algorithms: [`fetch`](https://fetch.spec.whatwg.org/#concept-fetch) (the entry point), [`main fetch`](https://fetch.spec.whatwg.org/#concept-main-fetch) (security checks, response handling, and integrity verification), and [`fetch response handover`](https://fetch.spec.whatwg.org/#fetch-finale) (delivery of the response to the caller). See also the Fetch Standard's guidance on [invoking fetch and processing responses](https://fetch.spec.whatwg.org/#fetch-elsewhere-fetch).

WAICT integrity checks apply to the unencoded response bytes delivered to the document, after any processing by [Service Workers](https://www.w3.org/TR/service-workers/). This is consistent with the behavior of [SRI](https://www.w3.org/TR/sri-2/).

## Determine Coverage

Before [`fetch`](https://fetch.spec.whatwg.org/#concept-fetch) is invoked, the user-agent determines whether the request is covered by the WAICT policy by checking the [request](https://fetch.spec.whatwg.org/#concept-request)'s [`destination`](https://fetch.spec.whatwg.org/#concept-request-destination).

The following destination types are covered by WAICT as **active content**:

 * document
 * frame
 * iframe
 * audioworklet
 * paintworklet
 * script
 * serviceworker
 * sharedworker
 * worker
 * style
 * xslt
 * object

> [!NOTE]
> Should we treat html as passive content to enable server-generated HTML to coexist with web apps on the same domain?

The following destination types are covered by WAICT as **passive content**:

* audio
* font
* image
* json
* video

If the destination does not appear in the above lists, the fetch proceeds without WAICT processing.
Otherwise, the fetch is subject to the integrity checks described below.

### Interaction with SRI and Integrity Policy

[SRI](https://www.w3.org/TR/sri-2/) and [Integrity Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy) are alternative sources of integrity metadata and policy rules for enforcing integrity. When handling a request which is covered by WAICT, the user agent MUST ignore any provided SRI metadata and any applicable integrity policy. This allows origins to offer support for all three standards simultaneously without requiring user-agents to hash resources multiple times or enter inconsistent enforcement states.

> [!NOTE]
> In the future, we may look to merge these specifications or rely on them explicitly.

## Request Setup

The [`fetch`](https://fetch.spec.whatwg.org/#concept-fetch) algorithm sets up the request (populating headers, priority, and other properties) before invoking [`main fetch`](https://fetch.spec.whatwg.org/#concept-main-fetch).

For a request to a covered destination type, WAICT adds the following steps during this request setup phase.

The user-agent SHOULD [append](https://fetch.spec.whatwg.org/#concept-header-list-append) (`Integrity-Policy-WAICT-v1-Req`, *manifest-url*) to the request's [header list](https://fetch.spec.whatwg.org/#concept-request-header-list), where *manifest-url* is the URL of the manifest currently in use for this top-level origin. This allows the server to identify which version of its resources the user-agent expects and respond appropriately. For example:

```
Integrity-Policy-WAICT-v1-Req: "/.well-known/waict/manifests/baz_manifest_5X_MjpjR0bpBpP3dEF6-hA"
```

WAICT v1 always uses SHA-256 for hashing. This allows the user-agent to begin hashing covered resources from the start of a request, even if no manifest is yet available to specify the expected SHA-256 hash. User-agents SHOULD compute the SHA-256 hash incrementally as response body chunks arrive, consistent with existing [SRI](https://www.w3.org/TR/sri-2/) behavior.

## Integrity Check

After [`main fetch`](https://fetch.spec.whatwg.org/#concept-main-fetch) dispatches the request and receives a response, it applies [filtered response](https://fetch.spec.whatwg.org/#concept-filtered-response) wrapping and response blocking checks, then performs integrity verification before proceeding to [`fetch response handover`](https://fetch.spec.whatwg.org/#fetch-finale).

The existing `main fetch` algorithm already handles [SRI integrity checking](https://w3c.github.io/webappsec-subresource-integrity/#does-response-match-metadatalist) when a request's [integrity metadata](https://fetch.spec.whatwg.org/#concept-request-integrity-metadata) is nonempty: the response body is [fully read](https://fetch.spec.whatwg.org/#body-fully-read), checked against the metadata, and only then passed to `fetch response handover`. WAICT extends this step to also cover the case where integrity metadata comes from a manifest rather than an inline attribute.

The response body is [fully read](https://fetch.spec.whatwg.org/#body-fully-read), the user-agent hashes the content, and checks if it is in the manifest. For active content, the fetched URL is required to have an entry in the manifest. For passive content, the fetched URL may not appear in the manifest, in which case integrity checking is skipped. More precisely, to perform integrity checking on the fetch, the user-agent proceeds as follows:

1. Wait for the manifest to be available. If the manifest cannot be fetched within an implementation-defined timeout, fail with reason `manifest_unavailable`.
1. If the manifest has failed validation (described above), the user-agent fails with reason `invalid_manifest`.
1. If the manifest is a tombstone, return success.
1. Let `reqURL` be the request's [URL](https://fetch.spec.whatwg.org/#concept-request-url) as it was at the time [`fetch`](https://fetch.spec.whatwg.org/#concept-fetch) was invoked, prior to any redirects. Let `reqKey` be the [URL serialization](https://url.spec.whatwg.org/#concept-url-serializer) of `reqURL` with the *exclude fragment* flag set.
1. Let `b` be the bytes of the response body and `h` be the base64urlnopad-encoded SHA-256 hash of `b`.
1. Let `pathHash` be the hash value from `manifest["hashes"]` whose key's canonical form (as defined in [Validating Manifests](#validating-manifests)) equals `reqKey`, or `undefined` if no such entry exists.
1. If the destination type is listed under **passive content** and `pathHash` is undefined, return success.
1. Let `wildcardHashes = manifest["wildcard_hashes"]`, or `undefined` if not present.
1. If `pathHash` is defined, compare `h` to `pathHash`. If they match, return success. Otherwise, fail with reason `no_manifest_match`. A resource whose URL appears in `hashes` MUST match via its `pathHash`; the wildcard check is never used as a fallback.
1. If `wildcardHashes` is defined and non-empty and `resource_delimiter` is defined and non-empty:
    1. Let `d` be `resource_delimiter`.
    1. For each component `b_i` of `b`, compute `SHA-256(b_i)`, base64urlnopad-encode it, and check whether the result is a member of `wildcardHashes`. If all components match, return success. Otherwise, fail with reason `no_manifest_match`.
1. Fail with reason `missing_from_manifest`.

If the integrity check succeeds, `main fetch` proceeds to [`fetch response handover`](https://fetch.spec.whatwg.org/#fetch-finale) with the verified response. If it fails, the behavior depends on the WAICT mode as described in [Handling Failures](#handling-failures).

### Manifest Override on Subresource Responses

When a user-agent receives a response to a covered subresource request, the response MAY include an `Integrity-Policy-WAICT-v1` header. If this header is present and contains a `manifest` URL that differs from the manifest URL currently stored for the top-level origin, the user-agent MUST fetch the manifest at the new URL and use it when performing the integrity check for that subresource. The user-agent MUST also update its stored WAICT state for the top-level origin following the algorithm in [Upgrades and Downgrades](#upgrades-and-downgrades).

This mechanism provides a defence in depth against stale manifests. If a user-agent has cached a manifest from a previous page load, a server can correct this by serving an updated `Integrity-Policy-WAICT-v1` header on any subresource response. The user-agent will then fetch the updated manifest and use it for the integrity check rather than relying on the stale manifest, which may not contain entries for newly deployed resources.

Servers are not required to serve the WAICT header on subresource responses. However, doing so ensures that user-agents with outdated manifests can gracefully recover.

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

* `manifest_unavailable` — The manifest for the origin could not be loaded.
* `invalid_manifest` — The manifest was loaded, but was malformed, had unexpected types, or was missing required fields (including `transparency_proof`).
* `invalid_transparency_proof` — A manifest and transparency proof were provided, but the proof could not be parsed.
* `missing_from_manifest` — A valid manifest was available, but this resource was not covered.
* `no_manifest_match` — A valid manifest was available and described this resource, but the resource did not match the manifest entry.

### Report Mode

In `report` mode, the user-agent MUST still load the resource. Report mode is intended for web developers to validate their deployment; it does not provide security for user-agents.

Compliant user-agents SHALL NOT display error messages to end-users who have not indicated they wish to see additional technical information.

### Enforce Mode

In `enforce` mode, the behavior depends on the failure type:

* `manifest_unavailable`, `invalid_manifest`, `invalid_transparency_proof` - the user-agent MUST display a warning page to the user indicating the error. The user-agent SHOULD NOT allow the user to bypass the warning.
* `missing_from_manifest`, `no_manifest_match` - The user-agent MUST return an appropriate [network error](https://fetch.spec.whatwg.org/#concept-network-error) for the fetch.

# Changes to WebAssembly Processing

[CSP3](https://www.w3.org/TR/CSP3/#wasm-integration) gates WebAssembly compilation as a binary allow/block decision via the `'wasm-unsafe-eval'` source expression. WAICT extends this model to provide per-module integrity checking: rather than allowing or blocking all WebAssembly, user-agents verify that the bytes of each WebAssembly module match an entry in the manifest's `wasm_hashes` before permitting compilation.

## Covered APIs

WebAssembly modules can be compiled and instantiated through several APIs:

* `new WebAssembly.Module(bytes)` — synchronous compilation from an `ArrayBuffer` or `TypedArray`.
* `WebAssembly.compile(bytes)` — asynchronous compilation from an `ArrayBuffer` or `TypedArray`.
* `WebAssembly.compileStreaming(source)` — asynchronous compilation from a fetch `Response`.
* `WebAssembly.instantiate(bytes, imports)` — asynchronous compilation and instantiation from an `ArrayBuffer` or `TypedArray`.
* `WebAssembly.instantiateStreaming(source, imports)` — asynchronous compilation and instantiation from a fetch `Response`.

WAICT integrity checking applies to all of these paths. The check is performed on the raw WebAssembly module bytes regardless of how they were obtained.

## Integration with HostEnsureCanCompileWasmBytes

WebAssembly defines the [`HostEnsureCanCompileWasmBytes()`](https://webassembly.github.io/content-security-policy/js-api/#host-ensure-can-compile-wasm-bytes) abstract operation, which allows the host environment to block compilation of WebAssembly source bytes. CSP3 [implements this hook](https://www.w3.org/TR/CSP3/#can-compile-wasm-bytes) to enforce its `script-src` directive. WAICT adds an additional check within this hook.

When WAICT is active for the current top-level origin, the user-agent MUST execute the following steps within `HostEnsureCanCompileWasmBytes(bytes)`:

1. If no WAICT state is stored for this top-level origin, return normally (compilation is not blocked by WAICT).
1. Wait for the manifest to be available. If the manifest cannot be fetched within an implementation-defined timeout, proceed to step 5 with reason `manifest_unavailable`.
1. If the manifest has failed validation, proceed to step 5 with reason `invalid_manifest`.
1. If the manifest is a tombstone, return success.
1. Let `h` be the base64nopad-encoded SHA-256 hash of `bytes`. Let `wasmHashes` be `manifest["wasm_hashes"]`, or an empty list if not present. If `h` is a member of `wasmHashes`, return normally (compilation is permitted).
1. The integrity check has failed. Let the failure reason be `wasm_hash_mismatch` unless set otherwise in step 2 or 3. The user-agent MUST report the failure as described in [Reporting](#reporting). If the WAICT mode is `enforce`, the user-agent MUST throw a `WebAssembly.CompileError`. If the WAICT mode is `report`, compilation proceeds normally.

# Inline Content and Dynamic Code Restrictions

WAICT's fetch-based integrity checks cover resources loaded from the network, but several code execution vectors bypass network fetches entirely. [Content Security Policy (CSP3)](https://www.w3.org/TR/CSP3/) addresses many of these vectors through server-sent headers. However, because WAICT's threat model includes an untrusted server, WAICT cannot rely on CSP headers delivered by that server. Instead, when WAICT is active for a top-level origin, the user-agent MUST implicitly enforce the restrictions described in this section, regardless of any CSP headers present.

These restrictions are **additive** to any existing CSP policy. If a site deploys its own CSP, the user-agent enforces both the site's CSP and WAICT's implicit restrictions. A site's CSP can only further constrain behavior, never relax WAICT's restrictions.

## Inline Scripts

When WAICT is active, the user-agent MUST block all inline script execution.

This corresponds to the behavior of CSP's [`script-src`](https://www.w3.org/TR/CSP3/#directive-script-src) directive without `'unsafe-inline'`, but is enforced by the user-agent unconditionally. The user-agent applies this restriction by executing the equivalent of the CSP3 ["Should element's inline type behavior be blocked?"](https://www.w3.org/TR/CSP3/#should-block-inline) algorithm for types `"script"` and `"script attribute"`, always returning **Blocked**.

This includes:

* Inline `<script>` elements (e.g., `<script>alert(1)</script>`).
* Inline event handler attributes (e.g., `onclick`, `onload`, `onerror`).

## Inline Styles

When WAICT is active, the user-agent MUST block all inline style execution.

This corresponds to the behavior of CSP's [`style-src`](https://www.w3.org/TR/CSP3/#directive-style-src) directive without `'unsafe-inline'`. The user-agent applies this restriction by executing the equivalent of the CSP3 "Should element's inline type behavior be blocked?" algorithm for types `"style"` and `"style attribute"`, always returning **Blocked**.

This includes:

* Inline `<style>` elements.
* Inline `style` attributes on elements.

## Dynamic Code Execution

When WAICT is active, the user-agent MUST block all dynamic code compilation from strings.

This corresponds to the behavior of CSP's [`script-src`](https://www.w3.org/TR/CSP3/#directive-script-src) directive without `'unsafe-eval'`. The user-agent applies this restriction within the [`EnsureCSPDoesNotBlockStringCompilation`](https://www.w3.org/TR/CSP3/#can-compile-strings) integration point, unconditionally blocking string-to-code compilation when WAICT is active.

This includes:

* `eval(string)`
* `new Function(string)`
* `setTimeout(string, ...)` and `setInterval(string, ...)` when called with a string argument.
* Any other API that compiles a string as script, including `Function.prototype.constructor` invoked with a string body.

Dynamically-generated code cannot be integrity-checked against the manifest because its content is not known at build time.

## `javascript:` URIs

When WAICT is active, the user-agent MUST block navigation to `javascript:` URIs unless the [userInvolvement](https://html.spec.whatwg.org/multipage/browsing-the-web.html#beginning-navigation) is "Browser UI".

Navigation to a `javascript:` URI evaluates arbitrary script in the context of the navigated document, bypassing WAICT's fetch integrity checks. The user-agent applies this restriction as part of the [navigate](https://html.spec.whatwg.org/multipage/browsing-the-web.html#navigate) algorithm, blocking the URI before evaluation.

Allowing navigation via the browser UI ensures that Javascript Bookmarks remain functional whilst blocking navigation triggered by interacting with the page directly.

## `data:` URIs

When WAICT is active, the user-agent MUST block the use of `data:` URIs as the source for active content. A `data:` URI embeds content inline in the URL itself, bypassing network fetches and therefore WAICT's fetch-based integrity checks. This includes but is not limited to:

* `<script src="data:...">` — executes script from a data URI.
* `<iframe src="data:text/html,...">` — loads an entire document from a data URI.

The user-agent MUST block any fetch with a `data:` URL scheme when the request's [destination](https://fetch.spec.whatwg.org/#concept-request-destination) is an active content type as defined in [Determine Coverage](#determine-coverage).

## `blob:` URIs and `srcdoc` iframes

When WAICT is active, the user-agent MUST block the use of `blob:` URIs as the source for active content. Like `data:` URIs, `blob:` URIs reference content that was constructed locally and do not trigger network fetches, bypassing WAICT's integrity checks. The user-agent MUST block any fetch with a `blob:` URL scheme when the request's [destination](https://fetch.spec.whatwg.org/#concept-request-destination) is an active content type as defined in [Determine Coverage](#determine-coverage).

Additionally, the user-agent MUST block the use of the [`srcdoc`](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-srcdoc) attribute on `<iframe>` elements when WAICT is active. The `srcdoc` attribute embeds an entire HTML document inline in the attribute value, which can contain arbitrary scripts and styles that would not be subject to WAICT integrity checks.

## Failure Handling

Violations of the restrictions in this section are handled according to the WAICT mode:

* In `enforce` mode, the user-agent MUST prevent the violating behavior (block the script, style, eval, navigation, or base URL change) and MUST report the failure as described in [Reporting](#reporting) with the reason `inline_violation`.
* In `report` mode, the user-agent MUST report the violation as described in [Reporting](#reporting) with the reason `inline_violation`, but MUST NOT block the behavior.

The `inline_violation` reason is added to the set of failure reasons described in [Reporting](#reporting).

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

### Cross-origin iframes

WAICT does not extend integrity enforcement into cross-origin iframes. A same-origin iframe is effectively part of the top-level application — it shares the same origin, can access the parent's DOM, cookies, and storage, and can execute code with the full privileges of that origin. A compromised same-origin iframe is therefore equivalent to a compromise of the top-level page itself, so WAICT must cover it.

A cross-origin iframe, by contrast, is isolated by the browser's same-origin policy. It cannot read or write the embedding page's DOM or storage, and its requests carry its own origin's credentials rather than the embedder's. This allows sites to effectively embed untrusted third-party content.

### Fingerprinting

A user-agent will reveal in its `Integrity-Policy-WAICT-v1-Req` header which manifest URL it has received in an `Integrity-Policy-WAICT-v1` header. This can be used to link a user-agent across individual requests to the same origin. This fingerprinting risk is the same as that of first-party cookies, i.e., any origin which includes a `Set-Cookie` response header can similarly track any cookie-respecting user-agent across individual requests. User-agents MUST partition WAICT state to top-level origins (as they would for cookies). Similarly, when the user-agent is instructed to clear storage for an origin, the user-agent must clear WAICT state.

## Browser UX Integration

Browsers should not expose WAICT state to end users unless an irrecovable error arises. However, web developers should be able to access WAICT information to aid debugging their implementations.

Thought should be given to annotating network fetches in DevTools with their WAICT state and result, providing access to the browser's retained WAICT state for an origin and the current manifest, and exposing suitable information to the console.
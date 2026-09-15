# WAICT - Signalling and Integrity

Web Application Integrity, Consistency, and Transparency (WAICT) enables websites to opt-in to a stronger security model which provides enhanced security for user-agents. When a website has opted in to WAICT, user-agents can be assured that web applications served by the website have been publicly logged with a transparency service.

This enables third parties to inspect the web application served to user-agents and so mitigate the risk of a compromised website serving malicious code. This security guarantee is particularly important for threat models where the server is not trusted by the user-agent, for example, in End-to-End Encrypted messaging.

WAICT's integrity model builds upon [Subresource Integrity (SRI)](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity), [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP) and the [Integrity-Policy header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy). This document describes how WAICT is signalled by user-agents and websites and how the integrity of web applications is assured. The transparency of web applications is described in a separate specification.

WAICT provides a stronger security property for user-agents, not servers, by making additional security checks on content fetched from the network. It does not constrain how user-agents locally modify pages, for example through user-agent preferences, extensions or other third-party additions.

# Conventions

This document uses Structured Field Values for HTTP ([RFC 9651](https://www.rfc-editor.org/rfc/rfc9651)) such as `sf-list`, `sf-integer`, `sf-boolean`, and `sf-token`.

In this document, `origin` refers to the tuple (scheme, host, port) as defined in [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454).

Where this document refers to base64 encoding, it means the standard alphabet defined in [RFC 4648 Section 4](https://www.rfc-editor.org/rfc/rfc4648#section-4) (using `+` and `/` with `=` padding). Where this document refers to base64urlnopad encoding, it means the URL-safe alphabet defined in [RFC 4648 Section 5](https://www.rfc-editor.org/rfc/rfc4648#section-5) (using `-` and `_`), with padding (`=`) omitted.

> [!NOTE]
> Editorial comments are indicated by the use of notes like these. These will be removed in the future.

# Negotiating WAICT Support

User-agents SHOULD signal that they support WAICT to servers through the use of user-agent client hints. Doing so will allow servers to avoid sending unnecessary information to user-agents which don't support WAICT.

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

* `max-age` - An `sf-integer` that MUST be `>= 0`. How long (in seconds) user-agents MUST enforce WAICT after seeing this header (used for downgrade protection).
* `manifest` - An `sf-string` containing a URL where the user-agent can fetch the WAICT manifest. The URL MAY be relative, in which case it is resolved against the origin's base URL.

The data located at the `manifest` URL MUST be immutable, i.e., the unencoded response body of a successful GET request to that URL MUST never change. To achieve this, implementers SHOULD include a SHA-256 hash of the unencoded response body in the URL itself, encoded in base64url, and truncated to 22 characters (equivalent to base64urlnopad truncated to 22 characters; this encodes 128 bits).

In addition, the header MUST contain at least one **category key**. Category keys are prefixed with `mode-` and indicate which classes of integrity check the user-agent should enforce for this origin, and at what strictness. Categories not listed in the header are not subject to any WAICT enforcement. Each category key has an `sf-token` value drawn from `enforce`, `warn`, or `report`:

* `enforce` — failures of this category are blocked, surfaced through a network error or equivalent (see [Enforce Mode](#enforce-mode)).
* `warn` — the operation is permitted to proceed, but the user-agent surfaces a user-visible warning if a check fails (see [Warn Mode](#warn-mode)).
* `report` — the operation is permitted to proceed, and failures are reported only to developer-facing channels (see [Report Mode](#report-mode)).

This specification defines the category keys listed in the table below. The **Destinations** column lists the [request destinations](https://fetch.spec.whatwg.org/#concept-request-destination) covered by each category, and is also used in reverse during [Determine Coverage](#determine-coverage) to map an outgoing request to its category. The active/passive classification is a fixed property of each category and governs how URLs missing from the manifest are handled (see [Integrity Check](#integrity-check)). Operators choose only the strictness level; they cannot change a category's class.

Where a category corresponds to a CSP fetch directive, the category name is the singular form of the destination, matching CSP's `<thing>-src` convention.

| Category key      | Destinations                                                                      | CSP analogue      | Class   |
| ---               | ---                                                                               | ---               | ---     |
| `mode-document`   | `document`                                                                        | —                 | active  |
| `mode-frame`      | `frame`, `iframe`                                                                 | `frame-src`       | active  |
| `mode-script`     | `script`, `xslt`                                                                  | `script-src`      | active  |
| `mode-object`     | `object`                                                                          | `object-src`      | active  |
| `mode-worker`     | `worker`, `serviceworker`, `sharedworker`, `audioworklet`, `paintworklet`         | `worker-src`      | active  |
| `mode-style`      | `style`                                                                           | `style-src`       | active  |
| `mode-image`      | `image`                                                                           | `img-src`         | passive |
| `mode-font`       | `font`                                                                            | `font-src`        | passive |
| `mode-media`      | `audio`, `video`                                                                  | `media-src`       | passive |

In addition, WAICT defines three category keys that do not correspond to network fetch destinations and do not participate in the active/passive classification above. Their behavior is defined in the referenced sections:

* `mode-wasm` — governs WebAssembly compilation. See [Changes to WebAssembly Processing](#changes-to-webassembly-processing).
* `mode-inline-js` — governs inline scripts, inline event-handler attributes, dynamic code, and `javascript:` URIs. See [Inline Scripts, Styles, and Dynamic Code](#inline-scripts-styles-and-dynamic-code).
* `mode-inline-css` — governs inline `<style>` elements and inline `style` attributes. See [Inline Scripts, Styles, and Dynamic Code](#inline-scripts-styles-and-dynamic-code).

Category keys MUST appear at most once in the header (a property guaranteed by the structured-field Dictionary syntax). Category keys other than those described above MUST be ignored. A category key whose value is not one of `enforce`, `warn`, or `report` MUST be ignored.

If `max-age` or `manifest` is missing or invalid, or if no recognized category key with a valid value is present, the entire header MUST be ignored.

The following key-value pairs are optional:

* `preload` - An `sf-boolean`. Indicates the site wants to enforce WAICT indefinitely (with transparency enabled) via a preload list. This field is not used directly by user-agents. `?0` (false) by default.
* `report-to` - Indicates endpoint(s) for submitting violations following [Integrity Policy Reporting](https://w3c.github.io/webappsec-subresource-integrity/#integrity-policy-section). Empty by default. The key is named to parallel CSP's [`report-to` directive](https://www.w3.org/TR/CSP3/#directive-report-to).

Any other keys MUST be ignored.

An example header is given below:

```HTTP
Integrity-Policy-WAICT-v1: max-age=90, mode-document=enforce, mode-frame=enforce, mode-script=enforce, mode-object=enforce, mode-worker=enforce, mode-style=warn, mode-image=report, mode-font=report, mode-media=report, mode-wasm=warn, mode-inline-js=report, mode-inline-css=report, preload=?0, report-to=(foo-reports), manifest="/.well-known/waict/manifests/baz_manifest_5X_MjpjR0bpBpP3dEF6-hA"
```

Websites using WAICT MUST set a WAICT response header on top-level navigation responses. Websites MAY additionally set the header on subresource responses as a defence in depth measure against user-agents with stale manifests (see [Manifest Override on Subresource Responses](#manifest-override-on-subresource-responses)).

## User-Agent Processing of Response Header

### Scope

WAICT state is scoped to the top-level origin and applies to requests made within the context of that origin. It does not extend to requests made by other top-level origins and so is compatible with the partitioning of state by top-level origin.

When processing a response whose origin is the same as the [top-level navigation initiator origin](https://fetch.spec.whatwg.org/#ref-for-request-top-level-navigation-initiator-origin), user-agents MUST check for valid `Integrity-Policy-WAICT-v1` response headers and MUST store the WAICT configuration for this origin for at most `max-age` seconds from the present. This information is partitioned to the top-level origin.

However, WAICT does not impact requests made to a WAICT-enforcing domain in other top-level contexts if those top-level contexts do not advertise WAICT themselves. User-agents MUST ignore `Integrity-Policy-WAICT-v1` headers set on responses whose origin does not match their current top-level navigation initiator origin. An example:

* `foo.com` and `bar.com` both embed resources located on each other's domains
* `foo.com` uses WAICT and sets an enforcement header. `bar.com` does not use WAICT.
* User-agents which navigate to `foo.com` will enforce WAICT, even when loading sub-resources from `bar.com`.
* User-agents which navigate to `bar.com` will not enforce WAICT, even when loading sub-resources from `foo.com`.

When an `<iframe>` loads a document from the same origin as the top-level page, the iframe's document and all of its subresources are subject to the same WAICT integrity checks as the top-level page. When an `<iframe>` loads a document from a different origin, the iframe's own subresources are only subject to WAICT if that origin independently advertises WAICT.

### Validating Existing Service Worker and Cache

When a user-agent first observes a valid `Integrity-Policy-WAICT-v1` header for an origin (i.e., no prior WAICT state exists for that origin), or when it fetches a new manifest for an origin that differs from the previously stored manifest URL, the user-agent MUST trigger an update check for any Service Workers registered for the top-level origin. The user-agent MUST prevent any existing Service Worker from intercepting covered fetches until the update check has completed. If the updated Service Worker script passes the WAICT integrity check against the current manifest, the update MAY proceed to install and activate normally. If the integrity check fails, the update MUST follow the failure handling described in [Handling Failures](#handling-failures) for the appropriate mode.

WAICT integrity checks apply to all covered responses regardless of whether they were served from the network or the HTTP cache. User-agents MUST NOT exempt cached responses from integrity checking. If a user-agent cannot apply checks to a cached resource because it no longer retains the necessary information (e.g. the user-agent has transformed the local representation resource and discarded the original representation) it should treat the resource as missing from the cache.

### Upgrades and Downgrades

Origins may change their WAICT header over time. For example, an origin may evaluate the `mode-script` category in `report` mode and later switch to `enforce`. Alternatively, a site may be enforcing WAICT for one category and wish to add another, change the scope of covered resources, or disable a category entirely. However, user-agents MUST enforce certain rules to prevent downgrade attacks - where a site alters its WAICT signalling in order to enable attacks. Each category is ratcheted independently: upgrading one category is immediate, but downgrading or removing it requires waiting out the `max-age` of the header in which that category was last seen.

To prevent downgrade attacks, user-agents MUST store WAICT state for each top-level origin that has advertised WAICT, partitioned by top-level origin. The stored record is composed of:

* the list of reporting endpoints,
* the manifest URL, and
* for each category in use, a tuple `(mode, expiry)` where `mode` is one of `enforce`, `warn`, `report` and `expiry` is `max-age` seconds from when the header carrying that category was last seen.

User-agents without access to long-term state (e.g. private browsing) SHOULD retain this record for as long as they are able. Modes are ordered by strictness as `report` < `warn` < `enforce`.

User-agents MUST follow this algorithm when processing a valid `Integrity-Policy-WAICT-v1` header:

1. Overwrite the list of reporting endpoints with the latest contents of `report-to`.
2. Overwrite the manifest URL with the latest `manifest` entry.
3. Let `new_expiry` be `max-age` seconds from the present.
4. Construct the set of **effective category bindings** for this header as follows. Start with an empty map. For each recognized category listed in [Response Header](#response-header), if it is explicitly present in the header with a valid value, bind it to that value.
5. For each (category, `new_mode`) pair in the effective category bindings:
   1. If there is no existing record for this category, store (category, `new_mode`, `new_expiry`).
   2. Otherwise, let (`existing_mode`, `existing_expiry`) be the existing record. Then:
      1. If `new_mode` is strictly stronger than `existing_mode` under the ordering above, replace the existing record with (category, `new_mode`, `new_expiry`).
      2. Otherwise, if `new_mode` equals `existing_mode` and `new_expiry` is further in the future than `existing_expiry`, replace `existing_expiry` with `new_expiry`.
      3. Otherwise, ignore the update for this category.
6. Existing records for categories not produced by step 4 are left unchanged and continue to age toward their previously committed expiry.

Any per-category record which has reached its effective expiry time MUST be ignored and SHOULD be removed.

This algorithm ensures that sites can upgrade any category of WAICT coverage immediately and can introduce new categories at any time. However, a site can only downgrade or drop a given category's coverage after `max-age` seconds pass since the last header that committed to that category at the stronger mode.

### Preloading

Websites can signal their desire for user-agent vendors to preload WAICT status onto their user-agents. Preloading is not a signal consumed directly by user-agents and user-agents MUST ignore this parameter.

As a general rule, websites SHOULD NOT request user-agents preload their WAICT status. Preloading WAICT may lead to irrecoverable errors for user-agents.

The details of how user-agent vendors are alerted to this are vendor-specific, but websites wishing user-agent vendors to preload MUST use an `Integrity-Policy-WAICT-v1` header with:

* Every category key specified in the standard is present and set to `enforce`.
* `preload` set to `?1`.
* `max-age` set to a value greater than or equal to 1 year (`31536000` seconds).

User-agent vendors MAY configure user-agents with preload information via their vendor-specific out-of-band channels. Such user-agents SHOULD enforce WAICT as long as their vendor-supplied preload list is up to date. User-agent support for preloading is optional.

Vendors may choose different cutoffs for when they consider a preload list to be stale, but are RECOMMENDED to use a value of 30 days. That is, if a user-agent goes 30 days without receiving an updated preload list, it SHOULD stop enforcing entries on the preload list.

# WAICT Manifests

WAICT manifests provide a public commitment to the web application(s) being served by the origin. The manifest describes both the individual resources used to provide the application and a proof that it has been logged publicly.

## Fetching Manifests

When a fetch for a resource is governed by a category in `enforce` mode, the fetch will be unable to complete successfully until a manifest is available. When the governing category is in `report` mode, the fetch will be unable to complete successfully until a manifest is available or an implementation-defined timeout occurs. In `warn` mode, the fetch should not be blocked on manifest availability.
User-agents SHOULD fetch WAICT manifests with high priority as soon as they become aware of them.

The manifest located at a given URL is expected to be immutable and SHOULD have its response set [`Cache-Control`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control) to include `immutable` and a long `max-age`. Sites can notify user-agents that an updated manifest is available by updating the `manifest` field of the WAICT header. User-agents only need to store the contents of one manifest per top-level origin at a time.

The response content type of a successful GET to a URL referenced in the `manifest` field in `Integrity-Policy-WAICT-v1` MUST be `application/waict-integrity-manifest` (TODO: reserve this MIME type). Responses with this type contain a _manifest_ JSON blob whose structure is defined in the next section, and a _transparency proof_ line. More precisely, the response body is of the form:
```
manifest | U+000A | transparency_proof | U+000A
```
where `|` represents concatenation, `manifest` a UTF-8-encoded JSON object, and `transparency_proof` is a base64urlnopad encoding of the `WaictInclusionProof` specified in TODO, proving inclusion of `manifest` in a tree. Note the parsing of a response is unique, since `transparency_proof` cannot have a newline in it. The user-agent MUST reject a response that is invalid UTF-8, contains fewer than two U+000A codepoints, contains a `manifest` that is not valid JSON, or contains an invalid `transparency_proof`.

Servers SHOULD use a suitable HTTP compression scheme as negotiated by the user-agent. Support and use of [Compression Dictionary Transport](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Compression_dictionary_transport) is RECOMMENDED.

## Manifest Structure

The integrity manifest is a JSON object with the following structure. All fields are mandatory unless marked optional:

* `url_hashes` (optional) — a dictionary mapping URLs to hashes. All hashes MUST use the SHA-256 algorithm and be base64urlnopad-encoded.
* `wasm_hashes` (optional) — a sorted list of unique SHA-256 hashes (base64urlnopad) of permitted WebAssembly module bytes. See [Changes to WebAssembly Processing](#changes-to-webassembly-processing).
* `fallback_hashes` (optional) - a sorted list of unique SHA-256 hashes (base64urlnopad) of permitted content only for document navigation.
* `wildcard_hashes` (optional) — a sorted list of unique SHA-256 hashes (base64urlnopad).
* `inline_js_hashes` (optional) — a sorted list of unique SHA-256 hashes (base64urlnopad) of permitted inline `<script>` element content and `javascript:` URI script sources. The hash is computed over the same byte sequence that CSP3's [hash-source](https://www.w3.org/TR/CSP3/#grammardef-hash-source) check would hash. See [Inline Scripts, Styles, and Dynamic Code](#inline-scripts-styles-and-dynamic-code).
* `event_handler_hashes` (optional) — a sorted list of unique SHA-256 hashes (base64urlnopad) of permitted inline event-handler attribute values (e.g. `onclick`, `onload`, `onerror`), computed over the same byte sequence as `inline_js_hashes`. See [Inline Scripts, Styles, and Dynamic Code](#inline-scripts-styles-and-dynamic-code).
* `eval_hashes` (optional) — a sorted list of unique SHA-256 hashes (base64urlnopad) of permitted strings compiled as code through `eval`, `new Function`, and the string forms of `setTimeout` / `setInterval`. See [Inline Scripts and Dynamic Code](#inline-scripts-and-dynamic-code).
* `inline_css_hashes` (optional) — a sorted list of unique SHA-256 hashes (base64urlnopad) of permitted inline `<style>` element content, computed identically to `inline_js_hashes` but for styles. See [Inline Scripts, Styles, and Dynamic Code](#inline-scripts-styles-and-dynamic-code).
* `style_attr_hashes` (optional) — a sorted list of unique SHA-256 hashes (base64urlnopad) of permitted inline `style` attribute values. Kept separate from `inline_css_hashes` so that a hash authorized for a `style` attribute cannot also authorize a full inline `<style>` element. See [Inline Scripts, Styles, and Dynamic Code](#inline-scripts-styles-and-dynamic-code).
* `inline_url_hashes` (optional) — a sorted list of unique SHA-256 hashes (base64urlnopad) of permitted bytes addressed by `data:` or `blob:` URLs used as the source for active-class fetches. See [`data:` and `blob:` URLs as Active Content](#data-and-blob-urls-as-active-content).
* `resource_delimiter` (optional) — a string used for splitting subresource contents.
* `emergency_opt_out` (optional) — a boolean used when the origin needs to disable WAICT immediately. Default is `false`

Each hash list above (`wasm_hashes`, `fallback_hashes`, `wildcard_hashes`, `inline_js_hashes`, `event_handler_hashes`, `eval_hashes`, `inline_css_hashes`, `style_attr_hashes`, and `inline_url_hashes`) MUST be sorted in ascending lexicographic order. The sorted order enables efficient membership testing by user-agents.

When a manifest has `emergency_opt_out = true`, we say it is a **tombstone**, since it is used to indicate that the origin has unenrolled from WAICT. No integrity checking happens when a tombstone manifest is served.

> [!NOTE]
> The `wildcard_hashes` and `resource_delimiter` fields may be removed if we can find a suitable alternative, e.g. using service workers to unbundle JS resources.

An example is given below:

```json
{
  "url_hashes": {
    "/assets/x.html": "r4j9yW07mpTFSQ6ZRYOV0Au8Hfn2NqjqQMBqKL_SWCY",
    "https://my-fave-cdn.example/assets/css/main.css": "zet5ebcBGt1-fr6F0vJbpOv7p4tV_fIbFH4AafxtBl0",
    "/favicon.ico": "zbt5ebcBGt1-gr6F0vJbpOv7p4tV_fIbFH4AafxtBl0"
  },
  "wasm_hashes": [
    "Aq3rP9FkR8vLHnUGT5OgP7xmNyvDh2YcfJLmzgSEz7o",
    "kJ2E9N8C3vR5xP7yQwL4mFbA6dH0jT2uK9sG1nO3iVc"
  ],
  "fallback_hashes": [
    "aB3xW9vKpL2mRnQy7dFtUeHsOiGjCzNw4kYuMlPqVrS",
    "tP8cE1hXwD5nJbAf6gQsIyKoZvLmRuN2eCdFpWxBqM0"
  ],
  "wildcard_hashes": [
    "0SsmrVFFC7wxU4QM5UeZeXBnyKlXTAzfkVsZXIrzabo",
    "H9OJUrESfT3SUlRpqAiDFEvqnnG2Sp9_eloyVMqxnnb",
    "mVuswfW4XCBOWbx-QiKkPPQy-gTfr-i1sVADexgyN-8"
  ],
  "inline_js_hashes": [
    "9Yp1l4ZGmRkNvT7WdF3xJoYqUbLcEzKi5sHaDPnVrM4"
  ],
  "event_handler_hashes": [
    "7Kq2m5AHnSlOwU8XeG4yKpZrVcMdF0Lj6tIbEQoWsN5"
  ],
  "eval_hashes": [
    "3Hp1l4ZGmRkNvT7WdF3xJoYqUbLcEzKi5sHaDPnVrM4"
  ],
  "inline_css_hashes": [
    "fXpDmK2cYwBVL4qNeRTuJ6gAhSiOzCxIvHbZrUlNyP8"
  ],
  "style_attr_hashes": [
    "gYqEnL3dZxCWM5rOfSUvK7hBiTjPzDyJwIcArVmOzQ9"
  ],
  "inline_url_hashes": [
    "qN7vR2eYwBVL4qNeRTuJ6gAhSiOzCxIvHbZrUlNyP8c"
  ],
  "resource_delimiter": "/* MY DELIM */"
}
```

All top-level items not specified above MUST be ignored. If there are duplicate keys at any level, then the last occurrence is the one used in the parsed result.

The meaning and use of these fields is described in the next section.

## Validating Manifests

Manifests do not need to be validated in their entirety before they are used for integrity checking. However, if a user-agent finds a violation of any of the below rules during its use of a manifest, it MUST mark it internally as an invalid manifest. This will cause all future integrity checks with respect to this manifest to fail, as described below in the integrity checking algorithm. This mark MUST be retained for as long as the manifest is cached by the user-agent.

Manifests MUST have the following properties:

* If the manifest was linked to by a WAICT integrity policy header with nonzero `max-age` that is still in effect, then the transparency proof is successfully parsed and checked using the algorithm in TODO (Reference Transparency Specifications)
* If the manifest is non-tombstone:
  * Values in `url_hashes`, `wasm_hashes`, `fallback_hashes`, `wildcard_hashes`, `inline_js_hashes`, `event_handler_hashes`, `inline_css_hashes`, `style_attr_hashes`, `inline_url_hashes`, and `eval_hashes` are valid base64urlnopad ([RFC 4648 Section 5](https://www.rfc-editor.org/rfc/rfc4648#section-5)) and decode to exactly 32 bytes.
  * Each key `s` of `url_hashes` is a _canonical_ URL, defined as follows. `s` is parsed with the [API URL Parser](https://url.spec.whatwg.org/#api-url-parser) using the top-level origin (serialized as `scheme://host:port/`) as base URL (note, this permits external URLs; the base is only applied when the provided URL is relative), and any [fragment](https://url.spec.whatwg.org/#concept-url-fragment) is removed. The result is then [URL-serialized](https://url.spec.whatwg.org/#concept-url-serializer) with the *exclude fragment* flag set. `s` is canonical when this serialization equals `s`.

The first property above allows origins to keep WAICT transparency disabled by always setting the policy's `max-age` to 0, and serving an empty string (or any other newline-free string) as the transparency proof. Note the non-tombstone conditional means that manifests with `emergency_opt_out` set MUST be treated as tombstones even when the entries in all the fields are invalid.

# Interactions with other Standards

## Interaction with SRI and Integrity Policy

[SRI](https://www.w3.org/TR/sri-2/) and [Integrity Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy) are alternative sources of integrity metadata and policy rules for enforcing integrity. When handling a request which is covered by WAICT, the user agent MUST ignore any provided SRI metadata and any applicable integrity policy, unless the applicable manifest is a tombstone. When the manifest is a tombstone, the origin has unenrolled from WAICT, so the user-agent MUST instead enforce any provided SRI metadata and applicable integrity policy as normal. This allows origins to offer support for all three standards simultaneously without requiring user-agents to hash resources multiple times or enter inconsistent enforcement states. WAICT deliberately uses the same type of integrity checks as SRI in order to allow the same codepaths to be used.

> [!NOTE]
> In the future, we may look to merge these specifications or rely on them explicitly.

## Interaction with CSP

[Content Security Policy (CSP3)](https://www.w3.org/TR/CSP3/) already provides directives that overlap with parts of WAICT's coverage: hash and nonce source expressions for integrity-style allowlisting (`'sha256-…'`, `'nonce-…'`), the `'unsafe-inline'` / `'unsafe-eval'` / `'wasm-unsafe-eval'` keywords for inline and dynamic code, and the `script-src`, `style-src`, `img-src`, etc. fetch directives for source-list enforcement. WAICT's category keys are named to parallel CSP's fetch directives; see the CSP analogue column in [Response Header](#response-header).

The two specifications are intended to coexist. CSP source-list checks (host allowlists, scheme restrictions) continue to apply to covered fetches in their normal way. Where the two specifications would otherwise produce conflicting integrity decisions, the following rules apply:

1. For a fetch covered by a WAICT category the user-agent MUST ignore any CSP hash source expression (`'sha256-…'`, `'sha384-…'`, `'sha512-…'`) and any matching nonce source on that fetch's destination directive. WAICT's manifest-based integrity check is authoritative for covered fetches.
2. Several WAICT modes constrain inline and active content beyond what the origin's CSP requires, regardless of what the origin's CSP headers say. For `mode-inline-js` and `mode-inline-css` the user-agent enforces a CSP it synthesizes from the manifest and appends to the document's CSP list (see [Inline Scripts, Styles, and Dynamic Code](#inline-scripts-styles-and-dynamic-code)). For the active-class destination categories and for `mode-wasm` the user-agent instead behaves as if specific CSP source expressions were absent from the origin's effective CSP (see [`data:` and `blob:` URLs as Active Content](#data-and-blob-urls-as-active-content) and [Changes to WebAssembly Processing](#changes-to-webassembly-processing)).
3. For all other categories, the user-agent MAY treat WAICT's manifest as a logical conjunction with the origin's existing CSP fetch directive of the same destination: a fetch is permitted only if it passes both the CSP source-list check and the WAICT integrity check.

# Changes to Network Fetches

This section describes how WAICT modifies the lifecycle of network fetches for covered resources. The modifications are described in terms of the [Fetch Standard](https://fetch.spec.whatwg.org/) algorithms: [`fetch`](https://fetch.spec.whatwg.org/#concept-fetch) (the entry point), [`main fetch`](https://fetch.spec.whatwg.org/#concept-main-fetch) (security checks, response handling, and integrity verification), and [`fetch response handover`](https://fetch.spec.whatwg.org/#fetch-finale) (delivery of the response to the caller). See also the Fetch Standard's guidance on [invoking fetch and processing responses](https://fetch.spec.whatwg.org/#fetch-elsewhere-fetch).

WAICT integrity checks apply to the unencoded response bytes delivered to the document, after any processing by [Service Workers](https://www.w3.org/TR/service-workers/). This is consistent with the behavior of [SRI](https://www.w3.org/TR/sri-2/).

This section also covers two restrictions imposed by the destination categories on content that does not traverse the network: [`data:` and `blob:` URLs as Active Content](#data-and-blob-urls-as-active-content), in which the URL is fetched but its bytes are supplied inline; and [`srcdoc` Iframes](#srcdoc-iframes), in which an inline attribute supplies the iframe's document. These restrictions are governed by the same `mode-*` keys as the corresponding network fetches.

## Determine Coverage

Before [`fetch`](https://fetch.spec.whatwg.org/#concept-fetch) is invoked, the user-agent determines whether the request is covered by the WAICT policy by checking the [request](https://fetch.spec.whatwg.org/#concept-request)'s [`destination`](https://fetch.spec.whatwg.org/#concept-request-destination) and mapping it to a category using the **Destinations** column of the category table in [Response Header](#response-header). Each covered destination belongs to exactly one category.

Categories are partitioned into **active content** (a covered fetch whose URL is missing from the manifest fails) and **passive content** (a covered fetch whose URL is missing from the manifest skips integrity checking and proceeds). The class of a category is fixed by this specification; operators control only the strictness of the corresponding `mode-*` key.

A request is **covered** by WAICT if its destination is listed for some category in that table and the stored WAICT state for the top-level origin contains a record for that category. Otherwise the fetch proceeds without WAICT processing. Covered fetches are subject to the integrity checks described below, governed by the mode of the mapped category.

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

The response body is [fully read](https://fetch.spec.whatwg.org/#body-fully-read), the user-agent hashes the content, and checks if it is in the manifest. For a request whose category is in the **active** class, the fetched URL is required to have an entry in the manifest. For a request whose category is in the **passive** class, the fetched URL may be absent from the manifest, in which case integrity checking is skipped. More precisely, to perform integrity checking on the fetch, the user-agent proceeds as follows:

1. Let `cat` be the category the request maps to, per [Determine Coverage](#determine-coverage), and let `class` be that category's active/passive class.
1. Wait for the manifest to be available. If the manifest cannot be fetched within an implementation-defined timeout, fail with reason `manifest_unavailable`.
1. If the manifest has failed validation (described above), the user-agent fails with reason `invalid_manifest`.
1. If the manifest is a tombstone, return success.
1. Let `reqURL` be the request's [URL](https://fetch.spec.whatwg.org/#concept-request-url) as it was at the time [`fetch`](https://fetch.spec.whatwg.org/#concept-fetch) was invoked, prior to any redirects. Let `reqKey` be the [URL serialization](https://url.spec.whatwg.org/#concept-url-serializer) of `reqURL` with the *exclude fragment* flag set.
1. Let `b` be the bytes of the response body and `h` be the base64urlnopad-encoded SHA-256 hash of `b`.
1. Let `pathHash` be the hash value from `manifest["url_hashes"]` whose key's canonical form (as defined in [Validating Manifests](#validating-manifests)) equals `reqKey`, or `undefined` if no such entry exists.
1. If `class` is **passive** and `pathHash` is undefined, return success.
1. Let `fallbackHashes` be `manifest["fallback_hashes"]`, or undefined if not present.
1. If `fallbackHashes` is defined and non-empty, and `cat` is `mode-document`, check whether `h` is a member of `fallbackHashes`. If it is, return success.
1. Let `wildcardHashes = manifest["wildcard_hashes"]`, or `undefined` if not present.
1. If `pathHash` is defined, compare `h` to `pathHash`. If they match, return success. Otherwise, fail with reason `no_manifest_match`. A resource whose URL appears in `url_hashes` MUST match via its `pathHash`; the wildcard check is never used as a fallback.
1. If `wildcardHashes` is defined and non-empty and `resource_delimiter` is defined and non-empty:
    1. Let `d` be `resource_delimiter`.
    1. For each component `b_i` of `b`, compute `SHA-256(b_i)`, base64urlnopad-encode it, and check whether the result is a member of `wildcardHashes`. If all components match, return success. Otherwise, fail with reason `no_manifest_match`.
1. Fail with reason `missing_from_manifest`.

If the integrity check succeeds, `main fetch` proceeds to [`fetch response handover`](https://fetch.spec.whatwg.org/#fetch-finale) with the verified response. If it fails, the behavior depends on the mode of `cat` as described in [Handling Failures](#handling-failures).

### Manifest Override on Subresource Responses

When a user-agent receives a response to a covered subresource request, the response MAY include an `Integrity-Policy-WAICT-v1` header. If this header is present and contains a `manifest` URL that differs from the manifest URL currently stored for the top-level origin, the user-agent MUST fetch the manifest at the new URL and use it when performing the integrity check for that subresource. The user-agent MUST also update its stored WAICT state for the top-level origin following the algorithm in [Upgrades and Downgrades](#upgrades-and-downgrades).

This mechanism provides a defence in depth against stale manifests. If a user-agent has cached a manifest from a previous page load, a server can correct this by serving an updated `Integrity-Policy-WAICT-v1` header on any subresource response. The user-agent will then fetch the updated manifest and use it for the integrity check rather than relying on the stale manifest, which may not contain entries for newly deployed resources.

Servers are not required to serve the WAICT header on subresource responses. However, doing so ensures that user-agents with outdated manifests can gracefully recover.

### Speculative Processing

Some user-agents begin processing responses before they are complete, for example, streaming HTML into a parser or rendering an incomplete image. The user-agent's processing of incomplete responses MUST NOT be observable from within the document's context until the integrity check has completed and `main fetch` has proceeded to `fetch response handover`.

> [!NOTE]
> This is intended to enable user-agents to engage in unobservable actions like speculatively fetching subresources from unverified responses which are critical for performance, provided those actions can't be used to bypass integrity checks.

## `data:` and `blob:` URLs as Active Content

A `data:` or `blob:` URL embeds content that did not traverse the network. The URL itself is not stable across deployments and cannot be looked up in the manifest by URL, but the bytes it addresses can still be hashed and checked against a manifest-supplied allowlist. Operators that need to permit specific opaque-URL content list its SHA-256 hash in the manifest field `inline_url_hashes` (see [Manifest Structure](#manifest-structure)). Because the manifest is publicly logged via WAICT transparency, an attacker compromising only the server cannot add new entries undetectably.

When a fetch's destination maps to a category in the **active** class (see [Determine Coverage](#determine-coverage)) and that category is in `enforce` or `warn` mode, the user-agent MUST behave as if the `data:` and `blob:` scheme source expressions were absent from the corresponding CSP fetch directive, with one exception: if `manifest["inline_url_hashes"]` is present and the base64urlnopad-encoded SHA-256 hash of the URL's resolved bytes is a member of it, the user-agent MUST treat the corresponding scheme source expression as present for that fetch. The resolved bytes are:

* for a `data:` URL, the decoded payload (the bytes following the comma, with base64 decoding applied if the `base64` extension is present);
* for a `blob:` URL, the bytes of the `Blob` object the URL resolves to at the time of the fetch.

If `inline_url_hashes` is absent or the bytes do not match any entry, the fetch is blocked by the CSP source-list check as described above. Examples of fetches that without a matching `inline_url_hashes` entry would be blocked by this rule:

* `<script src="data:…">` / `<script src="blob:…">` — under `mode-script`.
* `<iframe src="data:text/html,…">` / `<iframe src="blob:…">` — under `mode-frame`.
* `<object data="data:…">` — under `mode-object`.
* A `data:` or `blob:` URL passed to a worker constructor — under `mode-worker`.

Passive-class categories (`mode-image`, `mode-font`, `mode-media`) do not impose this restriction; `data:` and `blob:` URLs for those destinations remain subject to the origin's own CSP, and `inline_url_hashes` is not consulted.

## `srcdoc` Iframes

The `srcdoc` attribute embeds an entire HTML document — including any scripts, styles, and other resources defined inline within it — in the attribute value, bypassing both the network and the manifest. CSP does not provide a source expression for `srcdoc`, so this restriction is enforced directly by the user-agent rather than as a source-expression removal.

When `mode-frame` is in use, use of the [`srcdoc`](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-srcdoc) attribute on an `<iframe>` element is reported as an `inline_violation` against `mode-frame` and handled under the mode of `mode-frame` (see [Handling Failures](#handling-failures)): the user-agent blocks loading the `srcdoc` document in `enforce` mode, permits it with a user-visible warning in `warn` mode, and permits it with a developer-facing report in `report` mode.

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

A `WebAssembly.Module` is also a [serializable object](https://webassembly.github.io/spec/js-api/#serialization), so it can enter a realm without recompilation by being structured-cloned from another realm (e.g. via `postMessage()`). This path is covered in [Module Transfer via Structured Cloning](#module-transfer-via-structured-cloning).

## Integration with HostEnsureCanCompileWasmBytes

WebAssembly defines the [`HostEnsureCanCompileWasmBytes()`](https://webassembly.github.io/content-security-policy/js-api/#host-ensure-can-compile-wasm-bytes) abstract operation, which allows the host environment to block compilation of WebAssembly source bytes. CSP3 [implements this hook](https://www.w3.org/TR/CSP3/#can-compile-wasm-bytes) to enforce its `script-src` directive. WAICT adds an additional check within this hook.

When WAICT is active for the current top-level origin, the user-agent MUST execute the following steps within `HostEnsureCanCompileWasmBytes(bytes)`:

1. If no WAICT state is stored for this top-level origin, or if no record exists for the `mode-wasm` category, return normally (compilation is not blocked by WAICT).
1. Resolve the manifest as in steps 2–4 of [Integrity Check](#integrity-check): wait for the manifest with an implementation-defined timeout (`manifest_unavailable` on timeout), reject invalid manifests (`invalid_manifest`), and treat tombstones as success.
1. Let `h` be the base64urlnopad-encoded SHA-256 hash of `bytes`. If `manifest["wasm_hashes"]` is present and `h` is a member of it, return normally (compilation is permitted). Otherwise, the failure reason is `wasm_hash_mismatch` (or the manifest reason from the previous step).
1. Handle the failure under the mode of `mode-wasm` as described in [Handling Failures](#handling-failures). In `warn` mode the user-agent MAY perform this hash check asynchronously without blocking compilation, surfacing the warning UX once the failure is observed.

## Module Transfer via Structured Cloning

Deserializing a `WebAssembly.Module` reconstructs it from its serialized bytes without invoking `HostEnsureCanCompileWasmBytes()`.

When a `WebAssembly.Module` is deserialized into a realm, the user-agent MUST run the same check as the [`HostEnsureCanCompileWasmBytes` integration](#integration-with-hostensurecancompilewasmbytes), with `bytes` set to the module's serialized bytes (its `[[Bytes]]`), before the `Module` is exposed to script:

* The check MUST use the receiving realm's WAICT manifest, never the sending realm's, and applies even if the user-agent reuses a cached compiled representation of the module.
* On failure in `enforce` mode, the `Module` MUST NOT be exposed: deserialization fails, yielding a [`messageerror`](https://html.spec.whatwg.org/multipage/web-messaging.html#event-messageerror) event for `postMessage()` or a `DataCloneError` for `structuredClone()`. `warn` and `report` modes expose the `Module` and surface the failure as for any other `mode-wasm` check.

# Inline Scripts, Styles, and Dynamic Code

WAICT's fetch-based integrity check covers resources loaded from the network, but inline `<script>` and `<style>` content, dynamic code compiled from strings, and `javascript:` URIs bypass network fetches entirely. The content delivered by these paths is not known at build time, so it cannot appear in the manifest by URL and cannot be checked against it.

WAICT addresses these paths through additional restrictions whose strictness is controlled by the mode keys `mode-inline-js` and `mode-inline-css` defined in [Response Header](#response-header). Rather than editing the source expressions of whatever CSP the origin happens to deliver, the user-agent **synthesizes its own Content Security Policy**: it constructs a serialized policy string from the manifest and the mode keys, parses that string with CSP3's [parse a serialized CSP](https://w3c.github.io/webappsec-csp/#parse-serialized-policy) algorithm — the same algorithm the HTML Standard uses to install a policy delivered through a [`<meta http-equiv="content-security-policy">`](https://html.spec.whatwg.org/#attr-meta-http-equiv-content-security-policy) element — and appends the resulting policy to the CSP list used to enforce the document. Unlike a `<meta>`-delivered policy, which governs only content parsed after the element, the user-agent MUST install the synthesized policy when the document's CSP list is initialized from the navigation response, before document parsing begins, so that it governs the entire document including its first inline script. Synthesizing a policy this way lets user-agents reuse the existing CSP enforcement code paths without mutating the parsed representation of the origin's CSP.

These restrictions are **additive** to any CSP the origin delivers. Because CSP enforces every policy in the CSP list as a logical conjunction — an action is permitted only if *every* policy permits it — appending WAICT's synthesized policy can only further constrain behavior: an origin's own CSP can tighten these restrictions but can never relax them. Because WAICT's threat model treats the server as untrusted, the synthesized policy is built by the user-agent from the manifest and the mode keys alone, regardless of what the server's CSP headers say.

The value of the governing mode key selects the disposition the user-agent passes to [parse a serialized CSP](https://w3c.github.io/webappsec-csp/#parse-serialized-policy): `enforce` uses the `"enforce"` disposition, so the synthesized policy blocks; `warn` and `report` both use the `"report"` (report-only) disposition, so the policy permits the behavior but still detects it. The three modes differ only in how a detected violation is surfaced (see [Handling Failures](#handling-failures)): `enforce` blocks it, `warn` permits it with a user-visible indication, and `report` permits it with a developer-facing report only. In every case the violation is surfaced as a WAICT `inline_violation` (see [Failure Handling](#failure-handling)), never as an ordinary CSP `csp-violation`.

CSP's nonce-source, hash-source, and eval-hash-source allowlisting mechanisms (`'nonce-…'`, `'sha256-…'`, `'sha384-…'`, `'sha512-…'`, `'eval-sha256-…'`, `'eval-sha384-…'`, `'eval-sha512-…'`) cannot be used to permit specific inline scripts, styles, or dynamic code under WAICT. WAICT's synthesized policy never carries a nonce-source, hash-source, or eval-hash-source taken from the origin's CSP, and because the origin's own policy is enforced as a separate conjunct it can never widen what the synthesized policy allows. A server that can deliver malicious inline content can equally deliver the matching nonce or hash that would allowlist it, so the CSP-supplied allowlist provides no integrity guarantee against an untrusted server. This parallels the treatment of nonce- and hash-sources for covered fetches in [Interaction with CSP](#interaction-with-csp).

In its place, the manifest carries the trusted allowlist: operators that need to permit specific inline scripts, styles, or dynamic code list their SHA-256 hashes in the manifest fields `inline_js_hashes`, `event_handler_hashes`, `eval_hashes`, `inline_css_hashes`, and `style_attr_hashes` (see [Manifest Structure](#manifest-structure)). Because the manifest is publicly logged via WAICT transparency, an attacker compromising only the server cannot add new entries undetectably.

## Inline Scripts and Dynamic Code

When `mode-inline-js` is set to `enforce`, `warn`, or `report`, the user-agent MUST synthesize a CSP and enforce it as described above. So that each inline context is governed independently — and a hash listed for one context cannot authorize another — the synthesized policy sets three script directives rather than one. The serialized policy string is constructed as:

```
script-src * data: blob: filesystem: 'wasm-unsafe-eval' <E>…;
script-src-elem * data: blob: filesystem: 'unsafe-hashes' <H>…;
script-src-attr 'unsafe-hashes' <A>…
```

where:

* `script-src` governs string compilation and WebAssembly, which CSP3 gates on `script-src` rather than on the `-elem` / `-attr` directives. The host-source `*` and the scheme-sources `data:`, `blob:`, and `filesystem:` are present so that URL-based loads which fall back to `script-src` — notably workers, whose `worker-src` check falls back to `script-src` — are never blocked by the synthesized policy. `'wasm-unsafe-eval'` is included so the policy does not block WebAssembly compilation, which is governed independently by `mode-wasm` (see [Changes to WebAssembly Processing](#changes-to-webassembly-processing)). `<E>…` is a SHA-256 eval-hash source (`'eval-sha256-…'`; see [script-src-v2](https://github.com/explainers-by-googlers/script-src-v2)) for every entry in `manifest["eval_hashes"]`, if present; because the directive carries no `'unsafe-eval'`, string compilation is permitted only when its hash is listed.
* `script-src-elem` governs inline `<script>` element content and `javascript:` URI navigations, which CSP3 routes to `script-src-elem` (its `"script"` and `"navigation"` inline-check types). The host-source `*` and scheme-sources permit every external and scheme-based script source, so the directive governs only inline execution and never blocks a network fetch (whose integrity is covered by the fetch-based check) nor a `data:`/`blob:` active-content load (covered by [`data:` and `blob:` URLs as Active Content](#data-and-blob-urls-as-active-content)). `<H>…` is a SHA-256 hash-source (`'sha256-…'`) for every entry in `manifest["inline_js_hashes"]`, if present. `'unsafe-hashes'` is included because CSP3 matches a `javascript:` navigation against a hash-source only when it is present; it does not affect the matching of inline `<script>` element content.
* `script-src-attr` governs inline event-handler attribute values (e.g. `onclick`, `onload`, `onerror`), which CSP3 routes to `script-src-attr` (its `"script attribute"` inline-check type). `<A>…` is a SHA-256 hash-source for every entry in `manifest["event_handler_hashes"]`, if present, and `'unsafe-hashes'` is required for those hashes to match attribute values. The directive lists no host- or scheme-source, since event-handler attributes have no URL.

None of the three directives carries `'unsafe-inline'` or a nonce-source, so inline `<script>` elements, inline event handlers, `javascript:` navigations, and string compilation are permitted only when their content matches a hash the manifest lists for that specific context. The user-agent parses the string with [parse a serialized CSP](https://w3c.github.io/webappsec-csp/#parse-serialized-policy) and appends the resulting policy to the document's CSP list, with the disposition and reporting behavior described above.

The eval-hash source that allowlists dynamic code through `manifest["eval_hashes"]` is defined by [script-src-v2](https://github.com/explainers-by-googlers/script-src-v2), not CSP3 proper: it extends the [`EnsureCSPDoesNotBlockStringCompilation`](https://www.w3.org/TR/CSP3/#can-compile-strings) integration point — which gates `eval(string)`, `new Function(string)`, `setTimeout(string, …)`, `setInterval(string, …)`, and other APIs that compile a string as script — to consult eval-hash sources. A user-agent that does not implement that extension has no way to allowlist string compilation under WAICT and blocks it outright.

Because CSP3 routes both inline `<script>` element content and `javascript:` navigations to `script-src-elem`, the two share the `inline_js_hashes` allowlist: a `javascript:` navigation is permitted exactly when the SHA-256 of the script source the URI carries appears in `manifest["inline_js_hashes"]`, the same list that governs inline `<script>` elements. This coupling is intended — both are full inline-script execution, so no privilege is gained by reusing a hash across them. WAICT adds one carve-out the serialized policy cannot express: when `mode-inline-js` is `enforce`, `warn`, or `report`, the user-agent SHOULD NOT treat a `javascript:` navigation whose [`userInvolvement`](https://html.spec.whatwg.org/multipage/browsing-the-web.html#beginning-navigation) is `"Browser UI"` as a violation, even when its hash is absent from the manifest. This preserves JavaScript bookmarklets while still blocking page-triggered `javascript:` navigations that the manifest does not list.

Inline event-handler attribute values, by contrast, are governed by a **separate** directive (`script-src-attr`) and a **separate** manifest field (`event_handler_hashes`). Splitting them from `inline_js_hashes` prevents the `'unsafe-hashes'` escalation that a single combined list would allow: a short event-handler body such as the value of `onclick="doThing()"`, once hashed, would otherwise also authorize `<script>doThing()</script>` — which runs automatically at parse time — or `javascript:doThing()`. Because element and navigation hashes live only in `script-src-elem` while attribute hashes live only in `script-src-attr`, a hash authorized for one context never matches in the other. The same rules apply uniformly to classic scripts, module scripts, and importmaps.

When matching against `manifest["inline_js_hashes"]`, `manifest["event_handler_hashes"]`, or `manifest["eval_hashes"]`, the user-agent SHOULD compare the SHA-256 byte sequences directly rather than re-encoding the manifest's base64urlnopad value into CSP's base64 hash-source serialization.

## Inline Styles

When `mode-inline-css` is set to `enforce`, `warn`, or `report`, the user-agent MUST synthesize a CSP and enforce it as described above. As with scripts, each inline context gets its own directive so that a hash listed for one cannot authorize another. The serialized policy string is constructed as:

```
style-src-elem * data: blob: filesystem: <H>…;
style-src-attr 'unsafe-hashes' <A>…
```

where:

* `style-src-elem` governs inline `<style>` element content, which CSP3 routes to `style-src-elem`. The host-source `*` and the scheme-sources `data:`, `blob:`, and `filesystem:` permit every external and scheme-based stylesheet load, so the directive constrains only inline styles. `<H>…` is a SHA-256 hash-source (`'sha256-…'`) for every entry in `manifest["inline_css_hashes"]`, if present. No `'unsafe-hashes'` is needed, since CSP3 matches `<style>` element content against hash-sources unconditionally.
* `style-src-attr` governs inline `style` attribute values, which CSP3 routes to `style-src-attr`. `<A>…` is a SHA-256 hash-source for every entry in `manifest["style_attr_hashes"]`, if present, and `'unsafe-hashes'` is required for those hashes to match attribute values. The directive lists no host- or scheme-source, since `style` attributes have no URL.

Neither directive carries `'unsafe-inline'` or a nonce-source, so inline `<style>` elements and inline `style` attributes are permitted only when their content matches a hash the manifest lists for that specific context. No base `style-src` directive is needed, because CSP has no style analogue of the string-compilation or worker sinks that require `script-src` for scripts. The user-agent parses the string with [parse a serialized CSP](https://w3c.github.io/webappsec-csp/#parse-serialized-policy) and appends the resulting policy to the document's CSP list, with the disposition and reporting behavior described above.

Keeping `style_attr_hashes` in a directive separate from `inline_css_hashes` gives inline styles the same context separation as scripts: a hash authorized for a `style` attribute cannot also authorize a full inline `<style>` element, which can style the whole document and use constructs such as `@import`. The hash for a `<style>` element is computed over the same byte sequence that CSP3's hash-source check would hash; for a `style` attribute, it is computed over the attribute value's bytes (UTF-8 encoded).

As with the script fields, the user-agent SHOULD compare SHA-256 byte sequences directly rather than re-encoding through CSP's base64 hash-source serialization.

## Failure Handling

Violations of the restrictions in this section are reported as `inline_violation` and handled under the mode of the governing key (`mode-inline-js` or `mode-inline-css`). See [Handling Failures](#handling-failures).

# Handling Failures

When a WAICT check fails, the user-agent's response is governed by the mode of the category that triggered the check. Manifest-level failure reasons (`manifest_unavailable`, `invalid_manifest`, `invalid_transparency_proof`) are attributed to the category whose check could not proceed; if multiple categories were waiting on the same manifest, each treats the failure under its own mode.

## Reporting

In `report`, `warn`, and `enforce` modes, the user-agent MUST:

* Log the failure to the browser console and developer tools.
* If `report-to` is non-empty, report the error as a `waict-violation` to the specified endpoints following the [Reporting API](https://developer.mozilla.org/en-US/docs/Web/API/Reporting_API).

The `waict-violation` report `body` includes the keys and values from [IntegrityViolationReportBody](https://developer.mozilla.org/en-US/docs/Web/API/IntegrityViolationReportBody), enriched with the following entries (named to parallel the fields in CSP's [`csp-violation` report body](https://www.w3.org/TR/CSP3/#reporting)):

* `reason` — the cause of the failure (see list below).
* `disposition` — the mode under which the failure was handled. One of `enforce`, `warn`, or `report`. Equivalent to the `disposition` field on a `csp-violation` report.
* `effectiveDirective` — the category key that triggered the failure, e.g. `mode-script`, `mode-wasm`. Parallels the `effectiveDirective` field on a `csp-violation` report.

The `reason` entry takes one of the following values:

* `manifest_unavailable` — The manifest for the origin could not be loaded.
* `invalid_manifest` — The manifest was loaded, but was malformed, had unexpected types, or was missing required fields (including `transparency_proof`).
* `invalid_transparency_proof` — A manifest and transparency proof were provided, but the proof could not be parsed.
* `missing_from_manifest` — A valid manifest was available, but this resource was not covered.
* `no_manifest_match` — A valid manifest was available and described this resource, but the hash of the resource did not match the manifest entry.
* `wasm_hash_mismatch` — A WebAssembly module's bytes did not match any hash in `wasm_hashes`.
* `inline_violation` — An inline script, inline style, dynamic-code path, `javascript:` URI, `data:` or `blob:` URL, or `srcdoc` iframe violated its governing category's restriction.

For an `inline_violation`, the `effectiveDirective` is the governing mode key: `mode-inline-js` for inline scripts, event-handler attributes, dynamic code, and `javascript:` URIs; `mode-inline-css` for inline styles and `style` attributes; the destination's active-class category (e.g., `mode-script`, `mode-frame`, `mode-object`, `mode-worker`) for `data:` and `blob:` URLs; and `mode-frame` for `srcdoc`.

## Report Mode

In `report` mode, the user-agent MUST permit the operation (load the resource, permit WebAssembly compilation, execute the inline behavior, or load the `srcdoc` document). Report mode is intended for web developers to validate their deployment; it does not provide security for user-agents.

Compliant user-agents SHALL NOT display error messages to end-users who have not indicated they wish to see additional technical information.

## Warn Mode

In `warn` mode, the user-agent MUST permit the operation, and any integrity check MAY proceed asynchronously. The user-agent SHOULD NOT delay [`fetch response handover`](https://fetch.spec.whatwg.org/#fetch-finale), WebAssembly compilation, or inline execution while waiting for a `warn`-mode check to complete.

If a `warn`-mode check ultimately fails, the user-agent MUST surface a user-visible indication that the top-level origin failed a WAICT integrity check. The form of this indication is implementation-defined (for example, a security indicator change in the address bar), but it MUST be distinguishable from the indication shown when no WAICT failure has occurred. The user-agent SHOULD NOT block the user from continuing to interact with the page.

## Enforce Mode

In `enforce` mode, the user-agent MUST prevent the violating behavior. The exact form depends on the failure type:

* `manifest_unavailable`, `invalid_manifest`, `invalid_transparency_proof` — display a warning page to the user indicating the error. The user-agent SHOULD NOT allow the user to bypass the warning.
* `missing_from_manifest`, `no_manifest_match` — return an appropriate [network error](https://fetch.spec.whatwg.org/#concept-network-error) for the fetch.
* `wasm_hash_mismatch` — for a compilation API, throw a `WebAssembly.CompileError`; for a module arriving via structured cloning, fail deserialization so the `Module` is never exposed (a `messageerror` event or a `DataCloneError`). See [Changes to WebAssembly Processing](#changes-to-webassembly-processing).
* `inline_violation` — block the inline behavior: do not execute the inline script or style, do not compile the dynamic-code string, do not navigate the `javascript:` URI, do not fetch the `data:` or `blob:` URL, and do not load the `srcdoc` document. For `data:` and `blob:` URLs, the blocking is performed by the CSP source-list check after WAICT removes the scheme source expression (see [`data:` and `blob:` URLs as Active Content](#data-and-blob-urls-as-active-content)).

# Non-Normative Appendices

## Server Operator Advice

Server operators should be cautious when deploying WAICT enforcement. In general, there is no recourse for a faulty deployment of a category in `enforce` mode, other than waiting out the `max-age` period. In the event of a faulty deployment and the use of `preload`, the waiting-out period is potentially unbounded.

Server operators are recommended to deploy each category in `report` mode initially and gain confidence in their deployment gradually. Every reported error will result in a broken user-agent if that category is later moved to `enforce`, so reported errors should be treated seriously. `warn` mode is available as an optional intermediate step that gathers end-user feedback at the cost of a security indicator change.

Once an operator is confident in a category's behavior, they should consider switching it to `enforce` mode with a low `max-age` (e.g. minutes) and raising the `max-age` over time. Different categories may be at different points in this rollout simultaneously — for example, `mode-script=enforce` while `mode-wasm=warn`.

The exact age that server operators settle on is a tradeoff between the maximum recovery time for their site and how often users are expected to visit their site and still need a security benefit.

The use of preload is a specialist feature which is unlikely to be suitable for the majority of sites using WAICT. Sites should only enable preload if they are committed to making their site unavailable when WAICT is unavailable.

Sites wishing to stop using WAICT should stop serving the enforcement header and wait out their previously set `max-age`. Sites may be able to unenroll through the use of the opt-out signal described in the [proofs specification](waict-proofs.md).

### Web Application Versioning

When deploying a web application (without WAICT), operators must ensure clients observe a consistent version of the application. For example, if an application depends on foo.js and bar.js, a deployment can break if a client loads an older version of foo.js alongside a newer version of bar.js.

WAICT is designed to interoperate cleanly with existing versioning strategies that provide atomic application views. The WAICT manifest is simply another versioned resource and should be treated the same way as the associated scripts and assets.

In practice, operators need only ensure that any response carrying a WAICT header references a manifest that includes the served resource. This can be handled at build time: generate the manifest as part of the existing versioning process and associate it with the corresponding artifacts so the correct header is emitted with each response.

When publishing a new version of the application, the new resources can be associated with the new manifest.

## Future Extensions to the Specification

As user-agents introduce new ways to load active content, WAICT can be extended to cover them by defining additional categories. This is backwards compatible: a new category provides no coverage until a site opts in by setting its mode, so existing deployments are unaffected.

Tightening an existing category is more constrained. Once sites rely on a mode's semantics, silently changing its behavior risks breaking deployments, which is unacceptable. Additional checks must therefore be introduced either as a new category that sites explicitly enable, or as a new version of WAICT with revised semantics for the existing mode.

This approach favours availability over security: sites seeking the strongest guarantees will need to track changes to the specification and adopt new categories or versions as they are defined. New means of executing active content are a relatively infrequent change to the web platform, so this burden is expected to remain low.

## Security Considerations

This design emulates that of RFC 6797 (HSTS).

A key constraint is that user-agent vendors typically cannot ensure that their user-agents have consistent or non-stale configurations. Further, connection failures to valid websites for stale user-agents are intolerable to website operators.

As a consequence, this design ensures that websites continue to maintain availability if a user-agent has stale data (enforced via the `max-age` signals on headers and preload lists). This also means that security is only available for non-stale user-agents.

The use of the `Integrity-Policy-WAICT-v1` header is essential for the overall security of WAICT. User-agents must be aware of the need to enforce WAICT in order to gain security benefits from it.

User-agents only gain a cryptographic security benefit from categories set to `enforce` mode. Because each category is ratcheted independently, a site may simultaneously offer strong guarantees in one category (e.g. `mode-script=enforce`) while still iterating in another (e.g. `mode-wasm=warn`); user-agents must not assume that a single category in `enforce` mode implies enforcement of others.

WAICT V1 forces the use of SHA256 for hashing, unlike SRI which supports a family of hash functions. Using a fixed hash function is necessary to enable user-agents to begin hashing integrity-checked resources before a manifest is available (and so preserve existing website performance). If the security of SHA256 is called into question by future cryptologic advances, a new version of WAICT will need to be defined with a new hash function.

### SRI

A request covered by WAICT causes the user-agent to ignore any SRI metadata and applicable integrity policy in favour of WAICT (see [Interaction with SRI and Integrity Policy](#interaction-with-sri-and-integrity-policy)). A tombstone signals that the origin has unenrolled from WAICT, so user-agents resume enforcing SRI metadata and integrity policy as soon as they observe a tombstone, rather than waiting for their retained WAICT state to expire.

### Cross-origin iframes

The Scope rule covers same-origin iframes but not cross-origin ones. A same-origin iframe shares the embedder's DOM, cookies, and storage, and can execute code with the full privileges of the top-level origin — a compromise there is a compromise of the embedding page, so WAICT must cover it. A cross-origin iframe is isolated by the same-origin policy and may host untrusted third-party content, so the embedder's WAICT policy does not extend into it.

### Fingerprinting

A user-agent will reveal in its `Integrity-Policy-WAICT-v1-Req` header which manifest URL it has received in an `Integrity-Policy-WAICT-v1` header. This can be used to link a user-agent across individual requests to the same origin. This fingerprinting risk is the same as that of first-party cookies, i.e., any origin which includes a `Set-Cookie` response header can similarly track any cookie-respecting user-agent across individual requests. User-agents MUST partition WAICT state to top-level origins (as they would for cookies). Similarly, when the user-agent is instructed to clear storage for an origin, the user-agent must clear WAICT state.

### Privacy Considerations

The `Sec-CH-WAICT` client hint reveals only which WAICT versions a user-agent supports. Because this is determined by the user-agent's implementation rather than by any user- or session-specific state, it adds essentially no entropy beyond what the `User-Agent` string already exposes, and so poses a negligible fingerprinting risk.

WAICT relies on retained state to enforce a site's policy. In private browsing (and other modes without access to long-term state), this state does not persist across sessions, so a user-agent will not enforce WAICT on a fresh visit until it re-observes an `Integrity-Policy-WAICT-v1` header. Sites that require protection from the first request in such contexts must rely on [Preloading](#preloading).

## Browser UX Integration

Browsers should not expose WAICT state to end users unless an irrecovable error arises. However, web developers should be able to access WAICT information to aid debugging their implementations.

Thought should be given to annotating network fetches in DevTools with their WAICT state and result, providing access to the browser's retained WAICT state for an origin and the current manifest, and exposing suitable information to the console.

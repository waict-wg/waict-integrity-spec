# WAICT - Extensions

> [!NOTE]
> Draft extension to [WAICT - Signalling and Integrity](waict-integrity.md). References of the form [§Name](waict-integrity.md#anchor) point at the base specification.

In the base specification, two decisions derive from data the origin controls or that a transparency service provides for: whether an origin is subject to WAICT (the `Integrity-Policy-WAICT-v1` header, plus an optional vendor preload list) and whether a fetched manifest is authentic (its transparency proof). This document lets a user-agent delegate both to one or more registered, user-authorized verifiers. A verifier's decisions are additive to native WAICT and cannot be weakened by server signalling. The user-agent performs all integrity enforcement of the base specification unchanged.

The mechanism generalizes the vendor preload list of [§Preloading](waict-integrity.md#preloading): preloading lets a vendor assert enforcement out-of-band; a verifier lets a user-authorized component assert it dynamically, per request, and additionally vouch for manifest authenticity. How a verifier decides enrollment or authenticates a manifest is out of scope ([Out of Scope](#out-of-scope)).

# Terminology

**Verifier**: a component, registered under explicit authorization, that the user-agent consults to decide whether an origin is subject to WAICT and whether a fetched manifest is authentic.

**Claimed origin**: an origin a registered verifier claims at the enrollment query; the governing verifier is the one that did or, if more than one would claim, the earliest-registered ([Verifier Registration](#verifier-registration)).

# Verifier Registration

A user-agent MUST support registering one or more verifiers. A registration declares a set of origin match patterns, scheme and host, without a path (e.g. `<all_urls>`, `*://*.onion`, `https://*.example.com`), scoping which origins the verifier is consulted for; the user-agent MUST NOT query a verifier for an origin outside its patterns. Registered verifiers are ordered by time of registration (a user-agent MAY let the user reorder them); this order alone resolves which verifier governs an origin that more than one would claim.


# The Enrollment Query

Wherever the base specification would establish or refresh WAICT state for an origin from an `Integrity-Policy-WAICT-v1` header, a user-agent MUST query the verifiers whose match patterns include that origin in registration order and use the first that claims it; that verifier becomes the governing verifier. A verifier that declines is skipped and the next is queried.

A claim establishes WAICT state as if an `Integrity-Policy-WAICT-v1` header with `mode=enforce` had been received; per [Manifest Authenticity](#manifest-authenticity) it cannot be weakened by server signalling. The manifest itself is obtained as described there.

The registered patterns scope which origins a verifier is asked about; they are not its enrolled set, and a user-agent MUST NOT require that set to be enumerated. The set may be non-enumerable as plaintext (e.g. hashed entries, bloom-filter-based entries, etc.).

# Manifest Authenticity

For a claimed origin, before the manifest becomes active and before the navigation response is committed, the user-agent obtains it one of two ways. If the navigation response carries a valid `Integrity-Policy-WAICT-v1` header naming a manifest, the user-agent fetches it ([§Fetching Manifests](waict-integrity.md#fetching-manifests)) and submits the original bytes to the governing verifier; otherwise it asks the verifier, which supplies a manifest obtained by its own means. The verifier `accept`s, returning the manifest bytes it vouches for (the submitted bytes unchanged, or its own if it supplied them) or `reject`s (`invalid_manifest`). The user-agent enforces native integrity against the returned manifest, and the response MUST NOT reach the document context before the verifier `accept`s ([§Speculative Processing](waict-integrity.md#speculative-processing)).

A verifier's `accept` is always required for a claimed origin and is additive: server signalling cannot suppress it (a server cannot disable the verifier by adding, removing, or changing an `Integrity-Policy-WAICT-v1` header), and it does not suppress native transparency. Where native transparency is in effect the user-agent performs that check ([§Validating Manifests](waict-integrity.md#validating-manifests)) as well, and the manifest MUST pass both; where it is not the verifier's `accept` is the sole authenticity check. The structural requirements of [§Validating Manifests](waict-integrity.md#validating-manifests) always apply, since native enforcement uses the manifest.


# Manifest Extension Fields

A verifier MAY rely on top-level manifest fields beyond the base schema. The base specification already requires the user-agent to ignore unrecognized top-level items ([§Manifest Structure](waict-integrity.md#manifest-structure)), so such fields reach the verifier (which gets the exact bytes) and are authenticated by the verifier's own means, with no schema change.


# Out of Scope

Fixed by a profile: how a verifier decides enrollment; how it authenticates a manifest and what the opaque proof slot holds; the names and semantics of manifest extension fields; the registration and authorization mechanism.

# Appendix: Example API

Illustrative usage as a browser-extension API: a verifier registers the origin match patterns it covers, claims matching origins, and vouches for the manifest — either verifying the bytes the browser fetched from a WAICT header, or supplying its own when there is none. Per-response checks (CSP, `location`) use the existing request-interception API.

```javascript
// Being a verifier is a manifest permission
// Patterns are per-listener so one extension can register several,
// each with its own logic
browser.waict.onEnrollmentQuery.addListener(
  async (origin) => membershipCheck(origin),
  { matches: ["*://*.onion", "https://*.example.com", "https://example.org"] },
);

// Once per manifest: vouch for the manifest and, on success, install the per-response
// rules it implies. Return the manifest bytes to enforce, or null to reject.
browser.waict.onManifestVerification.addListener(async (origin, { manifestBytes }) => {
  const m = manifestBytes ?? (await fetchOwnManifest(origin));
  if (!m || !(await authenticate(origin, m))) return null;          // reject
  await installResponseRules(origin, m);                            // set up headers checks
  return m;                                                         // accept
});
```

`installResponseRules` sets those up from the just-verified manifest, depending on the available Web Extensions API:
 - Blocking `webRequest` (Firefox): a listener scoped to the origin's documents forces the signed CSP.
 - `declarativeNetRequest` (Chrome): `modifyHeaders`/`set` forces the signed CSP per path (longest-prefix via `priority`).


# Appendix: Example (WEBCAT)

[WEBCAT](https://github.com/freedomofpress/webcat-spec) is one extension. A WEBCAT verifier decides enrollment by membership in a consensus-maintained snapshot (a permissioned CometBFT chain) verified by a light client. It authenticates a manifest by a threshold of Sigsum or Sigstore signatures bound to the enrolled policy; keeps its CSP and app metadata in a top-level `webcat` manifest field; and enforces its per-path CSP (`default_csp`/`extra_csp`) via `declarativeNetRequest` rules from the verified manifest in Chrome, while on Firefox via blocking `webRequest`.

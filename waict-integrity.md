# WAICT integrity version 0.1

This document specifies a minimum viable Web Application Integrity, Consistency, and Transparency (WAICT) integrity specification for the purposes of deploying something before Real World Crypto 2025.

The goal of this document is to be simple, easy to execute on, and, most importantly, commonly agreed upon.

The construction here should be modular enough that transparency can be built on top without much difficulty and without compromises on efficiency.

# Integrity Manifest

The integrity manifest is a JSON object with the following structure:
```json
{
  "waict-integrity-version": "1",
  "hashes": {
    "/assets/x.html": "sha256-r4j9yW07mpTFSQ6ZRYOV0Au8Hfn2NqjqQMBqKL/SWCY="
    "/assets/css/main.css": "sha512-+ebNUN/EqhOvk46xbEOc1Lbzg/T0VD/HIUTRcTcU0/zbtSeT2302RKTc0Vf3Sx9uFje/euj2opcww49mZJm/NA==",
    "/favicon.ico": "sha256-zbt5ebcBGt1+gr6F0vJbpOv7p4tV/fIbFH4AafxtBl0=?content-type=image/png",
    "": [
      "sha256-mVuswfW4XCBOWbx+QiKkPPQy+gTfr+i1sVADexgyN+8=",
      "sha256-/0VoaGkrvY8OPyppsAPm1Ikl1OGrHMyc5NUD8Sc9ThY=",
      "sha256-0SsmrVFFC7wxU4QM5UeZeXBnyKlXTAzfkVsZXIrzabo="
    ]
  },
  "resource_delimiter": "/* MY DELIM */"
}
```
Each nonempty key in `hashes` has a value that is either an SRI tag (more precisely, a [`hash-with-options`](https://www.w3.org/TR/sri-2/#grammardef-hash-with-options)) or a list of SRI tags. Recall SRI tags can have a `?` character followed by optional metadata.

If `""` is a key in `hashes` (aka the _allowed anywhere_ hashes are present), then `resource_delimiter` MUST be defined, and vice-versa. Further, the value of `resource_delimiter`, if defined, MUST be nonempty. Finally, any tag under the `""` key MUST have the SHA-256 hash algorithm. This is to ensure a resource does not need to be hashed multiple times.

When a path has a single SRI tag as a value, the tag is computed in the same way that SRI tags are usually computed over a resource, i.e., as a plain hash over the unencoded data served from that path.

When a path has a list of SRI tags as a value, this denotes that the response at that endpoint contains a _bundled_ resource, i.e., a response with multiple embedded resources, separated by `resource_delimiter`. Specifically, the unencoded response, interpreted as a bytestring, is of the form `<r1><resource_delimiter><r2><resource_delimiter><r3><resource_delimiter>...<rn>`, where `<ri>` denotes the i-th resource, and `<resource_delimiter>` denotes the UTF-8 encoding of the `resource_delimiter` field in the manifest. A trailing resource delimiter results in `<rn>` being the empty bytestring.

(TODO Question: how important is it that `resource_delimiter` is supported in v0.1? Would it be okay to just use to the bundle hash? This merits a conversation)

The manifest's nonempty keys are URL paths. To check if a resource at that path passes integrity, the browser:
1. Computes the SRI tag of the fetched resource
1. Compares the computed SRI tag with the one at that path in the manifest, producing an integrity error on failure

For paths with bundled resources, i.e., with lists as values, the bundle is split by resource delimiter and the above check is performed for each component. If the number of components does not match the length of the list, the browser raises an integrity error.

If a resource is fetched and its path does not appear in the manifest, no integrity check is done.

# Response Headers

## Integrity Policy

The server indicates its integrity policy via response header (we do not support inline signalling yet). We build on the existing [specification](https://w3c.github.io/webappsec-subresource-integrity/#integrity-policy-section) for `Integrity-Policy`. Recall this struct is of the form:
```
Integrity-Policy:
  sources: [string]
  blocked-destinations: [destination]
  endpoints: [string]
```
where `destination` is defined as in the [`fetch`](https://fetch.spec.whatwg.org/#destination-type) spec.

We extend the the source string type to permit more values than just `"inline"`. Sources may now be strings of the form `waict-manifest-v1-X`, where `X` is a URL (TODO: strictly define URL). These will be expected to point to an integrity manifest. This comes with two constraints:

1. There MUST NOT be more than manifest source in `sources`. That is, only one manifest may govern a page at a time.
1. Any manifest source that appears in the `sources` field MUST have a URL unique to the manifest it points to. This is so the client can tell when a manifest was added/removed. To ensure uniqueness, the URL SHOULD contain in it a hash of the manifest. Clients MUST ignore a source that is neither `"inline"` nor a valid manifest source.

## Report-Only Integrity Policy

Recall the report-only integrity policy has the same structure as the integrity policy:
```
Integrity-Policy-Report-Only:
  sources: [string]
  blocked-destinations: [destination]
  endpoints: [string]
```

We add one field, `hash-endpoints`, to this structure, with the default value of an empty list. In the header, the presentation format of this field is an inner list, similar to the other fields. This endpoint is where hash matching errors are sent. The endpoints are defined in the `Reporting-Endpoints` header in the same response.

# Enforcement Algorithms

Recall there are two verification steps for any subresource to successfully load. It must 1), be [allowed](https://www.w3.org/TR/sri-2/#should-request-be-blocked-by-integrity-policy-section) (i.e., not blocked) by the integrity policy, and 2) have content that [satisfies](https://www.w3.org/TR/sri-2/#does-response-match-metadatalist) the expected hash, as [parsed](https://www.w3.org/TR/sri-2/#parse-metadata-section) from the integrity metadata.

To handle manifests, we must modify both parts of this algorithm. First, we define the parsing algorithm for manifests.

## Parse Manifest Metadata

Given a URL path `p` and an integrity manifest `m`, we define the algorithm to parse the manifest to return a set of hashes that may plausibly pertain to the subresource at the given URL.

1. Let `r` be the empty dictionary.
1. Let `pathTag = m["hashes"][p]`, or `undefined` if not defined.
1. Let `anywhereTags = m["hashes"][""]`, or `undefined` if not defined.
1. If `pathTag` is defined, set `r.pathTag = {parse(pathTag)}`, where `parse` refers to the spec's [existing](https://www.w3.org/TR/sri-2/#parse-metadata-section) tag parsing algorithm.
1. Set `r.anywhereTags = {parse(x) for x in anywhereTags}`, setting it to the empty set if `anywhereTags` is undefined.
1. Return `r`.

Note that `r = {pathTag: {}, anywhereTags: {}}` if a URL path does not appear in the manifest and there are no allowed-anywhere tags. We call this the _empty manifest metadata_.

## Should request be blocked by Integrity Policy?

We modify the [blocking algorithm](https://www.w3.org/TR/sri-2/#should-request-be-blocked-by-integrity-policy-section) to handle the new `sources` element type.

We remove step 2:

> Let `parsedMetadata` be the result of calling parse metadata with request’s integrity metadata.

To replace it, we insert two steps after step 5:

> a) Let `parsedInlineMetadata` be the result of calling parse metadata with request's inline integrity metadata.
>
> b) Let `parsedManifestMetadata` be the result of calling parse metadata with the request URL and the manifest manifest referenced in `policy`, returning an error if any manifest fetch fails.

(TODO: normalize relative URLs to be schemeless, and normalize external URLs to be full URLs)

We remove step 3:

> If `parsedMetadata` is not the empty set and request’s mode is either "cors" or "same-origin", return "Allowed".

To replace it, we insert two steps after step 5:

> a) If `policy.sources` contains `"inline"`, `parsedInlineMetadata` is not the empty manifest metadata, and request's mode is either "cors" or "same-origin", return "Allowed".
>
> b) If `parsedManifestMetadata` is not the empty manifest metadata, and request’s mode is either "cors" or "same-origin", return "Allowed".

Finally, we remove the struck text and add the bolded text in step 12:

> 12. If `policy.sources` ~contains `"inline"`~ **is nonempty** and `policy`'s blocked destinations contains request's destination, set block to true.

Note: We do not have to change how `reportPolicy` handles its reporting. The only reportable event is a subresource that is missing an inline integrity tag.

Note: The above algorithm doesn't check if a subresource's path appears in the manifest. One could reasonably say that if there is no delimiter, and no anywhere-hashes, then the absence of the path in the `hashes` dict should be a reportable error. Currently it is not. In order to make it a reportable error, this algorithm would have to first parse the contents of the manifest. That'd be odd, and also add complexity, so it's not in here.

## Enforcement on Hashes

Once a request has been allowed and the subresource is fetched, there are three algorithms that determine how the client performs integrity checking. These algorithms answer the following questions:

1. Which hash metadata will be compared to the computed hash of the subresource?
1. Does that metadata match the computed hash of the subresource?
1. What happens on hash matching error?

## What metadata to compare to bytes?

Inline integrity tags take precedence over tags from manifests. More precisely, the following algorithm determines which byte matching algorithm to use for a subresource whose request has been allowed:

1. Let `policy` be the current integrity policy
1. If `policy.sources` sources contains `"inline"` and `parsedInlineMetadata` (defined in the request blocking algorithm) is nonempty, return `parsedInlineMetadata`.
1. Otherwise, if `policy.sources` is nonempty, return `parsedManifestMetadata`.
1. Return `null`

## Does the metadata match the computed hash of the subresource?

Given the result of the algorithm above, we compare to the subresource bytes as follows. A return value of `true` indicates that the integrity check succeeded.

1. If the result of the above was `null`, return `true`.
1. If the result of the above is a `parsedInlineMetadata`, then [inline tag bytes matching algorithm](https://www.w3.org/TR/sri-2/#does-response-match-metadatalist) defined in the spec, and give it `parsedInlineMetadata` and the subresource's bytes as input.
1. If the result of the above is a `parsedManifestMetadata`, do the following.
    1. Let `b` be the bytes of the subresource
    1. Let `d` be `policy.resource_delimiter`, or `null` if not defined in the policy.
    1. If `parsedManifestMetadata.pathTag` is not the empty set, run the spec's [inline tag bytes matching algorithm](https://www.w3.org/TR/sri-2/#does-response-match-metadatalist) on `b` and `parsedManifestMetadata.pathTag`, and return the result.
    1. If `parsedManifestMetadata.anywhereTags` is the empty set, return `true` (reasoning: this case implies `parsedManifestMetadata` is empty, meaning this request was allowed because it's not a blocked destination; therefore integrity checking doesn't matter here)
    1. Let `bb` be the list of components of `b` after splitting on `d` (note, per the manifest format, `d` is not `null` because `anywhereTags` is nonempty). If `d` does not appear in `b`, then `bb` is a singleton.
    1. For each component `b_i` of `bb`, run the [inline tag bytes matching algorithm](https://www.w3.org/TR/sri-2/#does-response-match-metadatalist) algorithm on `b_i` and `parsedManifestMetadata.anywhereTags`. If all succeed, return true.
    1. Return false.

### What Happens on Hash Matching Error

(NOTE: this section describes behavior NOT compatible with the current SRI spec. Currently, if a hash does not match, the resource is not loaded, period.)

WAICT has two hash matching enforcement modes:

* `hash-strict` : A subresource whose hash did not match the expected one will not be loaded/unlocked into the page
* `hash-report` : A subresource whose hash did not match the expected one will loaded and notifications will be only sent to developers, similar to `report-uri`

Enforcement modes on a server's response are dictated by the contents of the response's headers. Specifically, `hash-report` mode is enabled if `Integrity-Policy` has empty `blocked-destinations`, and `Integrity-Policy-Report-Only` has a nonempty `hash-endpoints`. Otherwise, `hash-strict` mode is enabled.

(TODO: Describe the structure of the hash match failure reports)


# Request Headers

When a website gets reloaded, any subset of the subresources on the page may get re-fetched. In order for the web application to remain coherent, we must ensure that the refreshed subresources match the manifest specified by the main page. Unfortunately, the URLs in most web applications are not stable. As upgrades occur, the subresources served at some URLs will change. Thus, a client from three versions ago has no clear way to tell the server that they want the three-version-old copy of a particular subresource. The server is forced to make a best-effort response to the client's ambiguous request.

To disambiguate subresource requests, clients MAY include a header `Expected-Hash` on their subresource requests, containing the SRI tag of the subresource they expect to load. To avoid an integrity error, the client SHOULD use the SRI tag that the above algorithm would choose to pass into the byte matching algorithm. For example, if the policy contains `"inline"`, the cilent SHOULD set `Expected-Hash` to the strongest inline SRI tag.

If `Expected-Hash` is omitted, the server SHOULD assume the client is requesting the latest version of the subresource.

# Serving the manifest

GETting a URL referenced in the `sources` field in `Integrity-Policy` MUST result in a response of content type `application/waict-integrity-manifest` containing a manifest (TODO: version this? or is the versioning in the manifest format enough?).

# End user customization

WAICT integrity does not prevent browsers from modifying pages to their liking. Copying from the SRI spec:

> User agents may allow users to modify the result of [the hash comparison] algorithm via user preferences, bookmarklets, third-party additions to the user agent, and other such mechanisms.

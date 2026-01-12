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
    ],
  },
  "resource_delimiter": "/* MY DELIM */"
}
```
Each nonempty key in `hashes` has a value that is either an SRI tag (more precisely, a [`hash-with-options`](https://www.w3.org/TR/sri-2/#grammardef-hash-with-options)) or a list of SRI tags. Recall SRI tags can have a `?` character followed by optional metadata. `resource_delimiter` is mandatory unless every key under `hashes` has a string value (i.e., no list values). Any tag under the `""` key MUST have the SHA-256 hash algorithm. This is to ensure a resource does not need to be hashed multiple times.

When a path has a single SRI tag as a value, the tag is computed in the same way that SRI tags are usually computed over a resource, i.e., as a plain hash over the unencoded data served from that path.

When a path has a list of SRI tags as a value, this denotes that the response at that endpoint contains a _bundled_ resource, i.e., a response with multiple embedded resources, separated by `resource_delimiter`. Specifically, the unencoded response, interpreted as a bytestring, is of the form `<r1><resource_delimiter><r2><resource_delimiter><r3><resource_delimiter>...<rn>`, where `<ri>` denotes the i-th resource, and `<resource_delimiter>` denotes the UTF-8 encoding of the `resource_delimiter` field in the manifest. A trailing resource delimiter results in `<rn>` being the empty bytestring.

(TODO Question: how important is it that `resource_delimiter` is supported in v0.1? Would it be okay to just use to the bundle hash? This merits a conversation)

The manifest's nonempty keys are URL paths. To check if a resource at that path passes integrity, the browser:
1. Computes the SRI tag of the fetched resource
1. Compares the computed SRI tag with the one at that path in the manifest, producing an integrity error on failure

For paths with bundled resources, i.e., with lists as values, the bundle is split by resource delimiter and the above check is performed for each component. If the number of components does not match the length of the list, the browser raises an integrity error.

If a resource is fetched and its path does not appear in the manifest, no integrity check is done.

# Headers

The server indicates its integrity policy via response header (we do not support inline signalling yet). We build on the existing [specification](https://w3c.github.io/webappsec-subresource-integrity/#integrity-policy-section) for `Integrity-Policy`. Recall this struct is of the form:
```
Integrity-Policy:
  sources: [string]
  blocked-destinations: [destination]
  endpoints: [string]
```
where `destination` is defined as in the [`fetch`](https://fetch.spec.whatwg.org/#destination-type) spec.

We make two additions:
1. We add an optional field `checked-destinations: [destination]` to `Integrity-Policy`
1. We extend the the source string type to permit more values than just `"inline"`. Sources may now be URLs. These will be expected to point to an integrity manifest.

Any URL that appears in a `sources` field MUST be unique to the manifest it points to. This is so the client can tell when a manifest was added/removed. To ensure uniqueness, the URL SHOULD contain in it a hash of the manifest. Clients MUST ignore a source that is neither `"inline"` nor a valid URL.

# Enforcement Algorithms

Recall there are two verification steps for any subresource to successfully load. It must 1), be [allowed](https://www.w3.org/TR/sri-2/#should-request-be-blocked-by-integrity-policy-section) (i.e., not blocked) by the integrity policy, and 2) have content that [satisfies](https://www.w3.org/TR/sri-2/#does-response-match-metadatalist) the expected hash, as [parsed](https://www.w3.org/TR/sri-2/#parse-metadata-section) from the integrity metadata.

To handle manifests, we must modify both parts of this algorithm. First, we define the parsing algorithm for manifests.

## Parse Manifest Metadata

Given a URL path `p` and an integrity manifest `m`, we define the algorithm to parse the manifest to return a set of hashes that may plausibly pertain to the subresource at the given URL.

1. Let `r` be the empty dictionary
1. Let `pathTag = m["hashes"][p]`, or `undefined` if not defined
1. Let `anywhereTags = m["hashes"][""]`, or `undefined` if not defined
1. If `pathTag` is defined, set `r.pathTag = parse(pathTag)`, where `parse` refers to the spec's [existing](https://www.w3.org/TR/sri-2/#parse-metadata-section) tag parsing algorithm
1. If `anywhereTags` is defined, set `r.anywhereTags = {parse(x) for x in anywhereTags}`
1. Return `r`

Note that `r` is the empty dictionary if a URL path does not appear in the manifest and there are no allowed-anywhere tags.

## Do bytes match parsed manifest metadata?

Given a `r` resulting from manifest parsing above, a bytestring `b`, and a delimiter `d`, we define the algorithm to determine whether `b` matches `r`.

1. If `r.pathTag` is defined, run the spec's [existing](https://www.w3.org/TR/sri-2/#does-response-match-metadatalist) bytes matching algorithm on `b` and `r.pathTag`, and return the result.
1. Otherwise, we will compare against the anywhere tags. Let `bb` be the list of components of `b` after splitting on `d`. If `d` does not appear, `bb` is a singleton.
1. For each component `bi` of `bb`, run the spec's existing bytes matching algorithm on `bi` and `r.anywhereTags`. If all succeed, return true.
1. Return false.

## Should request be blocked by Integrity Policy?

We modify the [blocking algorithm](https://www.w3.org/TR/sri-2/#should-request-be-blocked-by-integrity-policy-section) to handle the new `sources` element type.

We remove step 2:

> Let `parsedMetadata` be the result of calling parse metadata with request’s integrity metadata.

To replace it, we insert two steps after step 5:

> a) Let `parsedInlineMetadata` be the result of calling parse metadata with request's inline integrity metadata.
>
> b) Let `parsedManifestMetadata` be the result of calling parse metadata with the current path and the request's integrity metadata from all the manifests referenced in `policy`, returning an error if any manifest fetch fails.

We remove step 3:

> If `parsedMetadata` is not the empty set and request’s mode is either "cors" or "same-origin", return "Allowed".

To replace it, we insert two steps after step 5:

> a) If `policy`'s sources contains "inline", `parsedInlineMetadata` is not the empty set, and request’s mode is either "cors" or "same-origin", return "Allowed".
>
> b) If `parsedManifestMetadata` is not the empty set, and request’s mode is either "cors" or "same-origin", return "Allowed".

Finally we remove the struck text and add the bolded text in steps 12 and 13:

> 12. If `policy`'s `sources` ~contains `"inline"`~ **is nonempty** and `policy`'s blocked destinations contains request's destination, set block to true.
>
> 13. If `reportPolicy`'s `sources` ~contains `"inline"`~ **is nonempty** and `reportPolicy`'s blocked destinations contains request's destination, set reportBlock to true.

Note: We do not have to change how `reportPolicy` handles its reporting. The only reportable event is a subresource that is missing an inline integrity tag.

Note: The above algorithm doesn't check if a subresource's path appears in the manifest. One could reasonably say that if there is no delimiter, and no anywhere-hashes, then the absence of the path in the `hashes` dict should be a reportable error. Currently it is not. In order to make it a reportable error, this algorithm would have to first parse the contents of the manifest. That'd be odd, and also add complexity, so it's not in here.

## What metadata to compare to bytes?

Inline integrity tags take precedence over tags from manifests. More precisely, the following algorithm determines which byte matching algorithm to use for a subresource whose request has been allowed:

1. Let `policy` be the current integrity policy
1. If `policy.sources` sources contains `"inline"` and `parsedInlineMetadata` is nonempty, return the [byte matching algorithm](https://www.w3.org/TR/sri-2/#does-response-match-metadatalist) for inline tags defined in the spec.
1. Otherwise, if `policy.sources` is nonempty, return the result of the bytes matching algorithm above for `parsedManifestMetadata`.
1. Return true

# Serving the manifest

GETting a URL referenced in the `sources` field in `Integrity-Policy` MUST result in a response of content type `application/waict-integrity-manifest` containing a manifest (TODO: version this? or is the versioning in the manifest format enough?).

# Enforcement modes

WAICT has three enforcement modes. In descending strictness, the modes are:

* `strict` : The resources will not be loaded/unlocked into the page if synchronous integrity check has not passed
* `normal`: The page will be loaded and notifications will be sent asynchronously to the user to inform about the status of the check
* `report` : The page will be loaded and notifications will be only sent to developers, similar to `report-uri`

 Requests (both as page subresources and initiated via Javascript) for paths that appear in the manifest are blocked/reported/informed about according to the [same rules as in SRI](https://www.w3.org/TR/sri-2/#should-request-be-blocked-by-integrity-policy-section).

Enforcement modes on a server's response are dictated by the contents of the response's headers. The rules are as follows:

* `strict` mode is enabled if `Integrity-Policy` has a nonempty `blocked-destinations`
* `normal` mode is enabled if `Integrity-Policy` has a nonempty `checked-destinations`
* `report` mode is enabled if `Integrity-Policy-Report-Only` has a nonempty `blocked-destinations`

If more than one of the above points is true, then the strictest of the modes wins.

# End user customization

WAICT integrity does not prevent browsers from modifying pages to their liking. Copying from the SRI spec:

> User agents may allow users to modify the result of [the hash comparison] algorithm via user preferences, bookmarklets, third-party additions to the user agent, and other such mechanisms.

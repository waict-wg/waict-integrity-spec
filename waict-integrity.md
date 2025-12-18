# WAICT integrity version 0.1-pre.rwc

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
      "sha384-H9OJUrESfT3SUlRpqAiDFEvqnnG2Sp9/eloyVMqxnnbmwzKjtESH2WdeSxwhZ184",
      "sha256-0SsmrVFFC7wxU4QM5UeZeXBnyKlXTAzfkVsZXIrzabo="
    ],
  },
  "resource_delimiter": "/* MY DELIM */"
}
```
Each nonempty key in `hashes` has a value that is either an SRI tag (more precisely, a [`hash-with-options`](https://www.w3.org/TR/sri-2/#grammardef-hash-with-options)) or a list of SRI tags. Recall SRI tags can have a `?` character followed by optional metadata. `resource_delimiter` is mandatory unless every key under `hashes` has a string value (i.e., no list values).

When a path has a single SRI tag as a value, the tag is computed in the same way that SRI tags are usually computed over a resource, i.e., as a plain hash over the unencoded data served from that path.

When a path has a list of SRI tags as a value, this denotes that the response at that endpoint contains a _bundled_ resource, i.e., a response with multiple embedded resources, separated by `resource_delimiter`. Specifically, the unencoded response, interpreted as a bytestring, is of the form `<r1><resource_delimiter><r2><resource_delimiter><r3><resource_delimiter>...<rn>`, where `<ri>` denotes the i-th resource, and `<resource_delimiter>` denotes the UTF-8 encoding of the `resource_delimiter` field in the manifest. A trailing resource delimiter results in `<rn>` being the empty bytestring.

(TODO Question: how important is it that `resource_delimiter` is supported in v0.1-pre.rwc? Would it be okay to just use to the bundle hash? This merits a conversation)

The manifest's nonempty keys are URL paths. To check if a resource at that path passes integrity, the browser:
1. Computes the SRI tag of the fetched resource
1. Compares the computed SRI tag with the one at that path in the manifest, producing an integrity error on failure

For paths with bundled resources, i.e., with lists as values, the bundle is split by resource delimiter and the above check is performed for each component. If the number of components does not match the length of the list, the browser raises an integrity error.

If a resource is fetched and its path does not appear in the manifest, no integrity check is done.

# Headers

The server indicates its integrity policy via response header (we do not support inline signalling yet). We build on the existing [specification](https://w3c.github.io/webappsec-subresource-integrity/#integrity-policy-section) for `Integrity-Policy` and `Integrity-Policy-Report-Only`. Recall these are both structs of the form:
```
Integrity-Policy/Integrity-Policy-Report-Only:
  sources: [string]
  blocked-destinations: [destination]
  endpoints: [string]
```
where `destination` is defined as in the [`fetch`](https://fetch.spec.whatwg.org/#destination-type) spec.

We make two additions to these types:
1. We add an optional field `checked-destinations: [destination]` to `Integrity-Policy`
1. We extend the the source string type in both `Integrity-Policy` and `Integirty-Policy-Report-Only` to permit more values than just `"inline"`. Sources may now be URLs. These will be expected to point to an integrity manifest.

In order for the client to tell when a manifest was added/removed, any URL that appears in a `sources` field MUST be unique to the manifest it points to. To ensure uniqueness, the URL SHOULD contain in it a hash of the manifest. Clients MUST ignore a source that is neither `"inline"` nor a valid URL.

# Serving the manifest

A URL referenced in the `sources` field in the above headers MUST serve a manifest with content type `application/waict-integrity-manifest` (TODO: version this? or is the versioning in the manifest format enough?).

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

# Changelog

This file contains a list of breaking changes between versions of the WAICT integrity draft.

## draft-waict-integrity-v2 (2026-04-14)

* Defined manifest URL response format (`application/waict-integrity-manifest`), splitting out transparency proof from manifest [#17](https://github.com/waict-wg/waict-integrity-spec/pull/17)
* Added requirement that manifest URLs are immutable [#13](https://github.com/waict-wg/waict-integrity-spec/pull/13)
* Clarified that manifest validation can be done with spot checking [#15](https://github.com/waict-wg/waict-integrity-spec/pull/15)
* Removed key uniqueness requirement in manifest `hashes`, and use last-occurence-wins instead [#15](https://github.com/waict-wg/waict-integrity-spec/pull/15)
* Added rule for enforcing just integrity, not transparency [#28](https://github.com/waict-wg/waict-integrity-spec/pull/28)
* Drastically simplified enforcement modes. The spec defines "active" and "passive" content. All passive content is enforced if present in the manifest. All active content is enforced no matter what. [#29](https://github.com/waict-wg/waict-integrity-spec/pull/29)
* Made all SHA-256 hashes base64url encoded without padding [#33](https://github.com/waict-wg/waict-integrity-spec/pull/33)
* Defined a tombstone manifest that disables all integrity [#32](https://github.com/waict-wg/waict-integrity-spec/pull/32)
* Added logic to invalidate old Service Workers and cache [#41](https://github.com/waict-wg/waict-integrity-spec/pull/41)
* Apply WAICT to same-origin iframes, and not cross-origin [#48](https://github.com/waict-wg/waict-integrity-spec/pull/48)
* Added `fallback_hashes` field in manifests to allow for server errors [#50](https://github.com/waict-wg/waict-integrity-spec/pull/50)

## draft-waict-integrity-v1 (2026-03-06)

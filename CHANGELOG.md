# Changelog

This file contains a list of breaking changes between versions of the WAICT integrity draft.

## Unreleased

* Defined manifest URL response format (`application/waict-integrity-manifest`), splitting out transparency proof from manifest [#17](https://github.com/waict-wg/waict-integrity-spec/pull/17)
* Added requirement that manifest URLs are immutable [#13](https://github.com/waict-wg/waict-integrity-spec/pull/13)
* Clarified that manifest validation can be done with spot checking [#15](https://github.com/waict-wg/waict-integrity-spec/pull/15)
* Removed key uniqueness requirement in manifest `hashes`, and use last-occurence-wins instead [#15](https://github.com/waict-wg/waict-integrity-spec/pull/15)
* Clarified transparency checking is part of manifest validation, unless the manifest's max-age has elapsed [#28](https://github.com/waict-wg/waict-integrity-spec/pull/28)
* Removed `blocked-destinations` entirely and hard-coded how integrity checking works for each destination (split by "active" vs "passive" content) [#29](https://github.com/waict-wg/waict-integrity-spec/pull/29)
* Made all SHA-256 hashes base64url encoded without padding [#33](https://github.com/waict-wg/waict-integrity-spec/pull/33)
* Defined a tombstone manifest that disables all integrity [#32](https://github.com/waict-wg/waict-integrity-spec/pull/32)

## draft-waict-integrity-v1 (2026-03-06)

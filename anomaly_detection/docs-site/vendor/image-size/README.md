# Documentation image-size boundary

This local package replaces Docusaurus's transitive `image-size` dependency for
the AdversaryGraph Anomaly Detection documentation build.

The documentation repository contains only reviewed SVG assets. The general
ICNS, JXL, and HEIF parsers in upstream `image-size <=2.0.2` are affected by
`GHSA-w3rx-r6r6-pgpr` and `GHSA-5p2g-fcmc-qvqq`, with no patched npm release as
of 2026-08-12. This package therefore implements only bounded SVG dimension
reading and rejects every other format. Do not broaden it without a security
review and dedicated malformed-input tests.

The interface is limited to the `image-size` and `image-size/fromFile` exports
used by Docusaurus. License: MIT.

As of the 2026-10-19 review, upstream 2.0.3 is reported fixed. This build deliberately retains its narrower, separately maintained SVG-only implementation; adopting general binary image parsers would broaden the established boundary. The package identity is now @adversarygraph/svg-dimensions so scanners do not mistake this distinct implementation for an upstream prerelease containing ICNS/JXL/HEIF parsers. Public import aliases remain compatible with Docusaurus. Malformed-format and size-bound tests remain mandatory.

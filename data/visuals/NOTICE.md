# Microsoft Fluent Emoji Asset Notice

The 256 SVG assets in this directory come from Microsoft Fluent Emoji's flat
style at upstream commit
[`62ecdc0d7ca5c6df32148c169556bc8d3782fca4`](https://github.com/microsoft/fluentui-emoji/tree/62ecdc0d7ca5c6df32148c169556bc8d3782fca4).
They were renamed `0.svg` through `255.svg` to match the canonical Universal
Quantum Seed visual ordering. The corresponding numbered PNG files are raster
derivatives of those SVG assets.

On 2026-07-14, every numbered SVG was verified byte-for-byte against a flat
SVG blob in that pinned upstream tree. The JavaScript repository's SVG and PNG
inventories were also verified byte-for-byte against the canonical assets in
the sibling `universal-quantum-seed` repository. For reproducible inventory
review, sort the files numerically and hash the following byte sequence for
each file: UTF-8 `directory/name`, a NUL byte, the file bytes, and another NUL
byte. The resulting SHA-256 values are:

- `svg/`: `2ac23c14a764e89209a8d1bbc5098315b77eaae33091e326765d457ee1f17b1c`
- `png/`: `7b5d0ba870f2b5eb1bfcaa8a31a30fb1dc957f129f46c9dcb29c87f283bf8e9b`

Microsoft's copyright and MIT terms are preserved in [LICENSE](LICENSE). These
third-party assets are not relicensed under PolyForm Shield. Their inclusion
does not imply endorsement by or affiliation with Microsoft.

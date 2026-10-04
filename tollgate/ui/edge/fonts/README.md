# Bundled web fonts

Served locally from `/edge/fonts/` so the UIs make no external requests. `@font-face` rules are at the top of `../styles.css`.
Files are the unmodified `latin` + `latin-ext` woff2 subsets Google Fonts serves (fetched 2026-10-04 from the css2 API, Chrome UA).

| Family | Weights | Google Fonts version | Upstream source | License |
|---|---|---|---|---|
| Bodoni Moda | 600, 700 (variable, opsz 6-96) | v28 | https://github.com/indestructible-type/Bodoni | SIL OFL 1.1, `OFL-bodonimoda.txt` |
| IBM Plex Mono | 400, 600 | v20 | https://github.com/IBM/plex | SIL OFL 1.1 (Reserved Font Name "Plex"), `OFL-ibmplexmono.txt` |
| JetBrains Mono | 400, 500 (variable) | v24 | https://github.com/JetBrains/JetBrainsMono | SIL OFL 1.1, `OFL-jetbrainsmono.txt` |
| Source Serif 4 | 400, 600 (variable, opsz 8-60) | v15 | https://github.com/adobe-fonts/source-serif | SIL OFL 1.1, `OFL-sourceserif4.txt` |

License texts are copied from https://github.com/google/fonts/tree/main/ofl/<family>/OFL.txt.

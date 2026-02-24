# pngcheck-vulns

A repository of proof-of-concept files demonstrating disclosed and patched vulnerabilities in pngcheck (2.4.0 - 3.0.1).

Each POC is custom crafted with dedicated generation scripts to trigger specific bugs, covering both CVE-numbered and unnumbered vulnerabilities.

For detailed vulnerability analysis, see [my research notes](https://13m0n4de.vercel.app/sec/vulns/pngcheck/index.html).

## Summary

| Directory                           | Type                     | Description                                                   | Version  |
| ----------------------------------- | ------------------------ | ------------------------------------------------------------- | -------- |
| [vulns-3.0.1](./vulns-3.0.1/)       | Buffer Over-read         | LOOP chunk: unchecked chunk size                              | \<=3.0.1 |
| [vulns-3.0.0](./vulns-3.0.0/)       | Buffer Over-read         | PPLT chunk: first_idx/last_idx handling error                 | \<=3.0.0 |
| [vulns-2.4.0](./vulns-2.4.0/)       | Null-pointer Dereference | sCAL chunk: invalid pointer access                            | \<=2.4.0 |
| [vulns-2.4.0](./vulns-2.4.0/)       | Buffer Over-read         | MNG chunks: buffer over-read in 10 chunk types                | \<=2.4.0 |
| [CVE-2020-35511](./CVE-2020-35511/) | Buffer Over-read         | print_buffer(): insufficient size validation                  | \<=2.4.0 |
| [CVE-2020-27818](./CVE-2020-27818/) | Out-of-bounds Read       | check_chunk_name(): negative array index from char conversion | \<=2.4.0 |

Note that some vulnerability types may differ from their CVE descriptions or official classifications. These are subjective categorizations.

## Usage

Each vulnerability folder contains:

- POC files (PNG/MNG format)
- Python script to generate POC

Some vulnerabilities may not show obvious symptoms when triggered. Recompiling with sanitizer options like `-fsanitize=address` can help better identify these issues.

For detailed instructions, refer to the README.md in each directory.

## References

- [pngcheck Home Page](http://www.libpng.org/pub/png/apps/pngcheck.html)
- [NVD - CVE-2020-27818](https://nvd.nist.gov/vuln/detail/CVE-2020-27818)
- [NVD - CVE-2020-35511](https://nvd.nist.gov/vuln/detail/CVE-2020-35511)
- [giantbranch's blog](https://www.giantbranch.cn/vulfound/)
- [Portable Network Graphics (PNG) Specification and Extensions](http://www.libpng.org/pub/png/spec)
- [MNG (Multiple-image Network Graphics) Format](http://www.libpng.org/pub/mng/spec)

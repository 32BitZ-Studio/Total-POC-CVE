# `pnpm` vs `npm` exploit 

This repo showcases how a difference in `npm` and `pnpm`installation from tarballs can be exploited. 
The exploit is recorded in [CVE-2023-37478](https://nvd.nist.gov/vuln/detail/CVE-2023-37478).

The javascript package constructed here claims it prints out a nice message to the user. When installed with `npm`, this is true. 
However, the same package can be installed with `pnpm` and it will print out a mean message. 
One could imagine how this could be more maliciously exploited. 

You can find an old, vulnerable version of pnpm [here](https://github.com/pnpm/pnpm/releases/tag/v8.6.7) that works with this exploit. 
This is fixed in [newer versions of pnpm](https://github.com/pnpm/pnpm/security/advisories/GHSA-5r98-f33j-g8h7) and the fix can be [seen here](https://github.com/pnpm/pnpm/commit/250f7e9fe90359e2b3b01ba8294c4120445e5aa6#diff-0d65e839be9422dce3b76fb31562012c3c205698db6260764ea96ca8811d0344)

## How to use this Repo

`exploitative_package_src` has the source for the package `definitely_benign_package`.
The folder `bad_version` (V0.1) contains malicious code, and `good_version` (V0.2) contains good code.
`make_tar.sh` builds the tar package such that the bad version is added to the tarbal before the good version.

For a demo, move/clone the compiled `definitely_benign_package.tgz` into `/use_demonstration/` and install via `npm` or `pnpm`, this can be shortcut with `make pnpm/npm` (`make clean` also works once you're done).
Once it's installed, run the words of affirmation script with `node words_of_affirmation.js`. 

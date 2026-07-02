# Attribution

Vulkro's free tools query only public metadata, live, from your own machine.
They keep no centralized mirror and redistribute no third-party dataset. The
sources below are credited per their terms.

## npm

`verify` reads public package metadata (existence, creation date, latest
version) from the npm public registry (registry.npmjs.org) and weekly
download counts from the npm downloads API (api.npmjs.org). Access is keyless
and per-user; no attribution is required for this querying. We credit npm
here for clarity.

## PyPI

`verify` reads public project metadata (existence, versions, release upload
times) from the PyPI JSON API (pypi.org). Access is keyless and per-user.

## crates.io

`verify` reads crate existence and versions from the crates.io sparse index
(index.crates.io) and reputation (creation date, latest version, recent
downloads) from the crates.io API (crates.io), with a descriptive User-Agent
as crates.io requests. Access is keyless and per-user.

## OSV.dev

Malicious-package checks run live against the OSV.dev query API
(https://osv.dev, https://api.osv.dev). OSV aggregates many upstream
databases under per-source licenses. `verify` reads only the malicious-package
records described below; it does not cache or redistribute the OSV corpus.

## OpenSSF malicious-packages (Apache-2.0)

The malicious-package records `verify` surfaces (OSV ids beginning `MAL-`)
originate from the OpenSSF malicious-packages project
(https://github.com/ossf/malicious-packages), licensed under the Apache
License, Version 2.0. `verify` queries these records live via OSV.dev and does
not redistribute the dataset. Should a future release ship or cache these
records locally, this notice, the Apache-2.0 license text, and any NOTICE
file provided by the project will be included with that distribution.

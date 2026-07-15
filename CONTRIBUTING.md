# Contributing to Universal Quantum Seed JavaScript

Thank you for helping improve Universal Quantum Seed. Changes to seed parsing,
wordlists, cryptographic primitives, key derivation, and browser bundles can
affect compatibility or security, so they require focused review and tests.

## Before opening a change

Open an issue for significant API, file-format, wordlist, or cryptographic
changes before investing in implementation. Report suspected vulnerabilities
privately as described in [SECURITY.md](SECURITY.md), never in an issue or pull
request.

Use only synthetic fixtures. Never include a real seed, passphrase, private
key, wallet, account, user record, or production log.

## Development and verification

The runtime has no package dependencies. Python is required only for the
source generators. From the repository root, run:

```sh
npm test
npm run compile
git diff --exit-code -- words.js dist/uqs.js dist/uqs-crypto.js
```

A clean final diff from the generator commands confirms that checked-in
generated sources match their canonical inputs. Review any intentional
generated diff before submitting it.

## Pull requests

Keep changes focused. Explain compatibility and security effects, list the
exact verification performed, and add failure-path tests. Do not introduce a
cryptographic construction or dependency without documenting its rationale,
threat model, and maintenance implications.

Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) in all project spaces.

## License

Contributions are accepted under the repository license in [LICENSE](LICENSE).

## Summary

Describe the problem and the change.

## Security and compatibility

Describe effects on seed compatibility, cryptographic behavior, generated
bundles, supported runtimes, and rollback. Write "None" only after
considering each area.

## Verification

List the exact tests and generation checks run, including their results.

## Checklist

- [ ] The change is focused and preserves existing seed vectors unless a reviewed migration is included.
- [ ] Tests cover the changed behavior and important failure paths.
- [ ] No real seed, passphrase, private key, user data, log, cache, or build artifact is included.
- [ ] New dependencies, permissions, and cryptographic constructions are justified and reviewed.
- [ ] Generated files were rebuilt from their documented source and the resulting diff was reviewed.
- [ ] Documentation and compatibility vectors are updated where needed.

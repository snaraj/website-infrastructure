### Changed

- Re-point every platform assertion of the site publishers' keyless certificate identity from the tag ref to the protected `main` branch ref, so the trusted signer is anchored to the only ref those repositories gate on creation with no bypass actors, and repair the promotion path's image verification, which could not verify any release published after `v0.1.9`.
- Amend ADR 0016 to record that its tag-ref subject was accurate when written and was overtaken when the site publishers moved to `workflow_dispatch` on protected `main`, and to correct its description of the Kyverno signature policies, which are a CI assertion and future desired state rather than a live second line of defence.

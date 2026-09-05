### Changed

- Validate generated promotion candidates locally while running the complete policy-tool unittest and coverage battery in required CI. Preserve precommit rendering and secret scans, exact signed-range publication validation, artifact acquisition, and review requirements.
- Require a separate owner-account PR-update restriction while preserving every core security rule without bypass. Distinguish observable rule structure from owner-visible actor evidence.
- Keep public artifact verification independent of workstation registry credential helpers by using a private empty Docker configuration.
- Retry a failed first publisher attempt with one complete workflow rerun so its settings attestation binds the new attempt; report subsequent failure without retrying again.

### Fixed

- Validate the live Naranjo ReplicaSet against Kubernetes controller semantics: the exact safe Deployment annotations are inherited, while its selector remains the Deployment selector plus `pod-template-hash`; unknown annotations and selector widening still fail closed.

# Security and cost exception process

No silent exception is valid. Create a reviewed ADR before implementation with:

- exact control/product/resource and requested deviation;
- owner and approving human;
- business need and rejected alternatives;
- current price/entitlement evidence from an authoritative source;
- introduced threats and compensating prevention, detection, and recovery;
- smallest scope and expiration date;
- tests, monitoring, rollback, rotation, and removal plan.

Any possible Cloudflare charge requires explicit authorization; a Free allowance
or budget alert is not approval. Unknown price is rejection. Record break-glass
actions with actor, time, reason, exact mutation, evidence, and a follow-up Git
reconciliation. Expired exceptions fail policy checks.

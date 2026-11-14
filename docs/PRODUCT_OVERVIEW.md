# Product overview

## The problem

Business data changes constantly and nobody can say *why* a number is what it is. A total looks wrong, a price changed, a record vanished, two systems disagree, an auditor asks for evidence, and the answer is a day of archaeology across logs, backups and people's memories. Existing audit trails are either an afterthought (a table anyone with access can edit) or a heavyweight compliance product that is hard to integrate.

## The product

Provenance Cloud is a database-native evidence layer you can adopt in an afternoon.

1. **Capture without effort.** Changes are recorded by the database itself, in the same transaction as the change: who, when, which request, which approval, what the old and new values were. External systems send CloudEvents (or CSV files) and get the same treatment.
2. **Answer the three questions.** *Where* did this value come from (field-level history)? *Why* is it this number (explain: replay the changes that built it, against the prices at the time)? *How* did it happen (everything one request changed, with cause and effect)?
3. **Travel in time.** Rebuild any record, or a whole order, as it was at any moment; compare two moments; ask what the data looked like *as we understood it then*.
4. **Trust the evidence.** A SHA-256 chain makes edits, deletions and re-ordering detectable; Ed25519-signed checkpoints, kept outside the system, make even a wholesale rewrite by a database administrator detectable.
5. **Catch problems early.** Maker-checker approval for risky changes, rules for overpayment, unpaid fulfilment, deep discounts and out-of-band database edits, reconciliation against the systems of record, and signed webhooks to wherever your team works.

## Who it is for

| Persona | Job to be done | Where |
|---|---|---|
| Finance / operations lead | "Why is this order total 1,549.99?" | Order → **Explain total**, **Lineage** |
| Compliance / auditor | Prove nothing was altered; export evidence | **Audit & integrity**, verify, export, checkpoints |
| Engineer integrating a legacy system | Send changes safely, find what was lost | **Integrations**, SDKs, **Reconciliation** |
| Security / admin | Control who can do what; approve risky changes | **Team**, **Approvals**, API-key scopes |
| Support | "What happened to this customer at 3 pm?" | **Explorer** |

## What it deliberately is not

* Not a general-purpose database audit product for arbitrary schemas: the built-in dataset is a commerce ledger (customers, products, orders, payments), and *other* systems join through events and CSV. Generalising capture to customer-defined tables is the obvious next step, not something shipped here.
* Not a replacement for your source of truth, a SIEM, a data warehouse or a billing system.
* Not (yet) multi-region, SSO-enabled or independently certified (SOC 2 / ISO 27001). See [SECURITY](SECURITY.md#limitations-and-non-goals).

## Roadmap candidates (not commitments)

Ordered by value for effort, based on gaps found while building this version:

1. **Generic capture** for customer-defined tables (a registered-entity catalogue and a trigger installer).
2. **SSO (OIDC/SAML) and MFA**, email verification, password reset.
3. **Field-level redaction / crypto-shredding** for personal data in audit rows.
4. **Billing and plan limits** (plans exist in the schema; nothing enforces them).
5. **Partitioning** and a verification service for very large tenants.
6. **Published SDK packages** and an OpenAPI-generated client for more languages.

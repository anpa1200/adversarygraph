# Limitations

ThreatMapper is designed to assist CTI analysts. It does not replace analyst judgment.

## ATT&CK Mapping

- The model can produce false positives and false negatives.
- A tool mention does not always justify a technique mapping.
- A broad technique may need a more specific sub-technique.
- Some reports do not provide enough detail for precise mapping.
- ATT&CK version changes can alter names, tactics, or relationships.

## Attribution

ThreatMapper does not prove attribution.

Group and campaign comparison uses TTP overlap. TTP overlap can result from:

- Shared tools.
- Common tradecraft.
- Reporting bias.
- Incomplete source coverage.
- Reused infrastructure.
- Coincidental overlap.

Use similarity as a lead, not a conclusion.

## Detection Engineering

Generated detection content is draft material.

Before production use:

- Confirm telemetry exists.
- Check false-positive conditions.
- Validate in a lab or historical dataset.
- Add triage guidance.
- Review with detection engineering owners.

## Privacy

Docker mode sends report content to the configured LLM provider. Use a private provider or local gateway if report content cannot leave the environment.

## Sector Intelligence

- Sector relevance is a prioritization aid, not proof that an actor is currently
  targeting a specific client.
- Source coverage depends on MISP Galaxy metadata and local synced references.
- Broad labels such as private sector are weak evidence and require analyst
  review.
- Activity windows depend on available campaign/report dates and may miss
  unreported activity.

## IOC Intelligence

- ATT&CK does not provide live IOCs; IOCs come from separate feeds or analyst
  imports.
- Many actors will have zero linked IOCs if sources do not name the actor or an
  alias directly.
- Public IOCs may be stale, sinkholed, re-used, or weakly attributed.
- Actor-linked IOCs should be presented with source, freshness, and confidence.
- Uploaded report IOC extraction is best-effort and requires analyst review.

## Deployment

The default Compose profile is intended for local and controlled self-hosted use. It is not a hardened public SaaS configuration.

# Deployment Regions & Data Residency (Prompt 40 §127–§132)

- Regions are modeled explicitly (`DeploymentRegion`); an organization
  carries a data region; users, workers, storage and reports resolve
  within it (§127–§129).
- Data residency rules are deployment configuration (§130): the
  platform does not silently move tenant data across regions, and AI
  providers are not silently called cross-region (§131).
- **Honest scope (§132): this release is a single-region deployment.**
  The seed registers one `default` region. Active-active multi-region
  operation is NOT claimed anywhere in product, docs or UI.

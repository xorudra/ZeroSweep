# Quickstart (Prompt 40 §154)

1. **Install** — `bash scripts/install/install.sh` (verifies
   prerequisites, generates secrets, migrates, seeds; see §201–§205
   safety contract in the script header).
2. **Start** — API, worker, web (and the Python AI service if used).
3. **Create your account** — open the web app and sign up, or
   `POST /api/v1/product/signup`. Signup provisions your organization,
   a default workspace, a trial (SaaS) and your onboarding checklist
   in one transaction (§58–§64).
4. **Verify your email** — open the verification link (single-use,
   expiring, §60).
5. **Continue** — [First workspace](first-workspace.md) →
   [First authorized scan](first-authorized-scan.md) →
   [First report](first-report.md).

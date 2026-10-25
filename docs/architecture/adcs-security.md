# AD Certificate Services Posture (Prompt 15 §47–§50)

AD CS assessment in ZeroSweep is **configuration posture only**. The
capability split is enforced in code (`CERTIPY_CAPABILITY_SPLIT`):

- **Defensive (implemented):** CA and template inventory, template
  configuration analysis, ESC-class risk classification, CA
  configuration review, remediation guidance.
- **Offensive (permanently excluded):** certificate-request attacks,
  `auth`, `forge`, `relay`, `shadow`, `account`, `ca` modification
  actions, NTLM relay, Golden Certificate and persistence. The
  governed adapter accepts the `find` action only; every other action
  is refused at plan time, and the offensive Certipy registration is
  DISABLED with no adapter (§47).

## Risk classes

Templates are classified from collected configuration:

| Class | Configuration signal |
|-------|----------------------|
| ESC1 | Enrollee supplies subject + client-auth EKU + no manager approval + no authorized signatures, broad enrollment |
| ESC2 | Any-purpose / no-EKU template with broad enrollment and no approval |
| ESC3 | Enrollment-agent template without enrollment-agent restrictions |
| ESC4 | Dangerous ACL (GenericAll/WriteDacl/WriteOwner/Owns) over the template object |
| ESC6 | CA `EDITF_ATTRIBUTESUBJECTALTNAME2` flag observed in CA metadata |
| ESC8 | Web enrollment endpoint recorded without EPA/channel-binding evidence |

A classification is a **posture statement about configuration**, with
an explanation and remediation guidance on the finding (§50).
Confirming exploitability would require a separate authorized
validation engagement under Prompt 16 rules — this platform never
attempts it.

# Risk Engine V3 (Prompt 20 sections 20-25)

V3 layers explainable, signed adjustments over Risk Engine V2: KEV
listing, EPSS, internet exposure, production environment, verified
exploitability, compensating controls and accepted risk. Every
score carries its signal list, the information that was MISSING
(unknown exposure is not assumed safe), and a score-confidence
value. Priority (P0-P4) is computed separately from severity:
verified KEV + internet-facing + production is a strong P0 signal,
but asset criticality and data sensitivity also count - KEV alone
never auto-assigns P0 (section 25).

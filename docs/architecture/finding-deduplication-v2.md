# Finding Deduplication V2 (Prompt 20 sections 12-13)

`fingerprintV2` extends the Prompt 7 fingerprint with the finding's
source domain, so the same CVE observed by SCA and by a container
scanner stays two canonical findings (they need different
remediation), while observations of the same issue inside one domain
converge. Exact duplicates share the v2 fingerprint; near duplicates
(same endpoint + category, different tool wording) are linked as
POTENTIAL_DUPLICATE correlations for analyst review - never merged
by title similarity (section 114).

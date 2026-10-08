# Access Reviews (Prompt 23)

Periodic certification of privileged access (§94–97):

- Creating a review SNAPSHOTS the current privileged subjects:
  organization memberships, active service accounts and unrevoked API
  keys (`AccessReviewItem` rows).
- Reviewers decide KEEP / REVOKE / CHANGE_ROLE / DISABLE per item.
- Decisions EXECUTE through the normal services — revoking a membership
  item revokes the membership and its sessions; disabling a service
  account disables it; revoking a key item revokes the key. There is no
  review-only shadow state (§96).
- A review completes only when every item is decided; completion and
  every decision are audited.
- The privileged-access report (§97) lists privileged memberships,
  service accounts and high-scope keys on demand.

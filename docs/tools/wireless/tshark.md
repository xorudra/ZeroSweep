# tshark (wireless) (Prompt 19 §24)

**Role:** offline 802.11 frame analysis adapter (`tshark-wireless`,
executable `tshark`), over approved captures.

The adapter runs a **fixed** invocation: `-r <capture> -T fields` with
the platform's 13-field wireless set (frame time, WLAN BSSID/SSID,
channel, frequency, signal, frame subtype, source/destination,
RSN/capabilities evidence). Properties:

- **No arbitrary display filters** (§78): `-Y` expressions are not
  expressible in configuration; the field set is a code constant.
- Frame-subtype counts drive passive event detection (§47–§49): a
  deauthentication **burst** (≥20 frames / 60 s) raises one
  `DEAUTH_ACTIVITY` event — a single frame never claims an attack.
- Management-frame evidence is metadata only; payload contents are
  never extracted, and authentication material is counted, not kept
  (§67).

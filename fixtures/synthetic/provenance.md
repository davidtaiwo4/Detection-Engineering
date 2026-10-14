# Synthetic Fixture Provenance
 
Covers every file in `fixtures/synthetic/`. These fixtures do not come from
the sealed `windows-replay.jsonl` — they are self-constructed, one section
below per technique, for the 6 rows with zero source telemetry in the sealed
evidence (confirmed by full-file sweep — see decision log D-004).
 
Shared construction method for all fixtures in this directory: built by hand
following the documented ATT&CK procedure for each technique. Schema (field
names, event_code/channel conventions) matches `windows-replay.jsonl`
exactly, so every fixture loads through the same `adapter.py` normalization
path with no synthetic-data special-casing. `command_line` values use
placeholder `--training-token synXXXX` tokens, matching the sealed replay's
own scrubbed-command convention, since no rule may depend on command_line
content regardless of fixture origin.
 
---
 
## T1053.005 — `t1053_005.jsonl`
 
**Cases:**
1. `SYN-T1053005-00001` + `SYN-T1053005-00002` (NS-WIN-201, 2.5 min apart):
   true-positive — `schtasks.exe` created under `powershell.exe`, followed
   by an `svchost.exe`-parented execution within the 5-minute correlation
   window. Expected: **alerted**.
2. `SYN-T1053005-00003` + `SYN-T1053005-00004` (NS-WIN-202, 1 min apart):
   benign lookalike — `schtasks.exe` created under `msiexec.exe` (trusted
   installer registering an update-check task), with a downstream
   `svchost.exe`-parented execution present too. Expected: **suppressed**
   — proves the rule rejects based on creation parent alone, not just
   "any correlated execution exists."
3. `SYN-T1053005-00005` (NS-WIN-203, standalone): `schtasks.exe` created
   under `cmd.exe`, no correlated execution anywhere in the file. Expected:
   **rule_miss** — sequence incomplete, must not alert on the anchor alone.
**Limitations:** 3 hosts, 5 events — targeted unit test of branching logic,
not a claim of statistical realism.
 
---
 
## T1087.001 — `t1087_001.jsonl`
 
**Cases:**
1. `SYN-T1087001-00001/02/03` (NS-WIN-301, same parent `powershell.exe`,
   ~2 min span): three different discovery binaries under one parent in
   quick succession — the recon-burst true positive. Expected: **alerted**.
2. `SYN-T1087001-00004` (NS-WIN-302, standalone): a single `net.exe` call
   under `explorer.exe`, no other discovery binary nearby. Expected:
   **suppressed**.
3. `SYN-T1087001-00005` + `SYN-T1087001-00006` (NS-WIN-303, same parent
   `cmd.exe`, ~8 hours apart): two different discovery binaries, same
   parent, far outside the 3-minute burst window. Expected: **suppressed**
   for both — proves the rule checks time proximity, not just "same
   parent, ever."
**Limitations:** 6 events, 3 hosts — targeted unit test, not a volume/noise
study. Burst window (3 min) and discovery-binary set are documented design
choices, not derived from this fixture.
 
---
 
<!-- Next section goes here as each remaining technique (T1057, T1136.001,
     T1555, T1027) gets its synthetic fixture built. -->
 
## T1057 — `t1057.jsonl` (RETROFITTED v2.0.0)
 
Original v1.0.0 fixture (3 cases, single-event rule) was rebuilt for the
v2.0.0 correlation-based rule — see decision log D-007 for why the
retrofit happened (rule count, not fixture quality).
 
**Cases:**
1. `SYN-T1057-00001` + `SYN-T1057-00002` (NS-WIN-401, same parent
   `powershell.exe`, 2 min apart): `tasklist.exe` then `wmic.exe` —
   repeated discovery calls, same parent, within the 5-minute window.
   Expected: **alerted**.
2. `SYN-T1057-00003` (NS-WIN-402, standalone): single `tasklist.exe`
   call under `powershell.exe`, no repeat anywhere. Expected:
   **suppressed** — proves a lone call is correctly treated as
   lower-signal, not automatically alert-worthy.
3. `SYN-T1057-00004` (NS-WIN-403): `tasklist.exe` under `explorer.exe`
   (interactive use). Expected: **suppressed**.
4. `SYN-T1057-00005` (NS-WIN-404): `wmic.exe` under `sccm-client.exe`
   (legitimate management-tool context). Expected: **suppressed**.
**Limitations:** 5 events, 4 hosts — targeted unit test of the repeat-vs-
single boundary, not a volume study.
 
---
 
## T1136.001 — `t1136_001.jsonl`
 
**Cases:**
1. `SYN-T1136001-00001` + `SYN-T1136001-00002` (NS-WIN-501, same parent
   `powershell.exe`, 40 sec apart): `net.exe` then `net1.exe` — the
   documented create-account-then-add-to-group pattern. Expected:
   **alerted**.
2. `SYN-T1136001-00003` (NS-WIN-502, standalone): single `net.exe` call
   under `powershell.exe`, no follow-up. Expected: **suppressed** —
   proves a lone account-management call (ambiguous with legitimate
   admin activity) does not alert alone.
3. `SYN-T1136001-00004` + `SYN-T1136001-00005` (NS-WIN-503, same parent
   `onboarding-tool.exe`, 30 sec apart): two `net.exe` calls under a
   trusted automated-provisioning parent. Expected: **suppressed** for
   both — proves the rule rejects based on creation-parent context even
   when the repeat-call pattern is present.
**Limitations:** 5 events, 3 hosts — targeted unit test. Deliberately
overlaps `t1087_001.jsonl`'s binary set (`net.exe`) by design — see
`rules/t1136_001.py` docstring for why this overlap is intentional, not
a conflict.
 
---
 
## T1555 — `t1555.jsonl`
 
**Cases:**
1. `SYN-T1555-00001` + `SYN-T1555-00002` (NS-WIN-601, same parent
   `powershell.exe`, 90 sec apart): two `vaultcmd.exe` calls — the
   documented enumerate-then-extract pattern (`vaultcmd /list`, then
   `vaultcmd /listcreds:<vault> /all`). Expected: **alerted**.
2. `SYN-T1555-00003` (NS-WIN-602, standalone): single `vaultcmd.exe`
   call under `explorer.exe` (interactive troubleshooting). Expected:
   **suppressed**.
**Limitations:** 3 events, 2 hosts — targeted unit test.
 
---
 
## T1027 — `t1027.jsonl`
 
**Cases:**
1. `SYN-T1027-00001` + `SYN-T1027-00002` (NS-WIN-701, 45 sec apart):
   `wscript.exe` under `explorer.exe`, followed by `powershell.exe`
   spawned with `wscript.exe` as its own parent — the script-host
   spawns a secondary interpreter within the correlation window.
   Expected: **alerted**.
2. `SYN-T1027-00003` (NS-WIN-702, standalone): `cscript.exe` under
   `explorer.exe`, no child spawn anywhere. Expected: **suppressed**.
**Limitations:** 3 events, 2 hosts — the smallest and weakest-evidenced
fixture in this set, matching the rule's own documented status as the
weakest-evidenced rule (no way to test content-level obfuscation
detection without command_line visibility, which this schema withholds
by design).

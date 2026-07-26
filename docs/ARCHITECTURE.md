# Architecture

- App identity: `ITEM_APP` stores original/real paths, path hash, filter GUIDs, optional file hash, signature cache, timestamps, and service/UWP identity bytes.
- Path key: case-insensitive string hash of the executable path; long 8.3 paths are expanded.
- Persistence: `profile.xml` app items store path, optional hash/comment, timestamp/timer, and enabled/silent flags.
- WFP creation: `_wfp_createrulefilter` emits exact `ALE_APP_ID`, service `ALE_USER_ID`, or UWP `ALE_PACKAGE_ID` conditions.
- WFP layers: outbound `ALE_AUTH_CONNECT_V4/V6`; inbound `ALE_AUTH_RECV_ACCEPT_V4/V6`.
- WFP lifecycle: `_wfp_createfilter`, `_wfp_deletefilter`, `_wfp_destroyfilters_array`; GUIDs are retained per app/rule.
- Events: `FwpmNetEventSubscribe0..4` feeds `_wfp_logcallback`; app path, package SID, username, endpoints, ports, protocol, layer, and filter are retained.
- Notifications: `_app_logthread` creates missing app records, saves the profile, and queues blocked-app notifications.
- Process data: network monitor resolves active-connection PID to image path or AppContainer SID.
- Existing trust data: WinVerifyTrust/catalog signer checks and SHA-256 file hashes.
- Missing for Codex policy: blocked-event PID, raw user SID, parent chain, command line, process creation time, canonical final path, reparse-point containment, process-start subscription, PID-reuse binding, and temporary-rule registry.
- Build compatibility: `src/routine_compat.h` adapts current simplewall call shapes to the pinned public `routine`; it must remain free of WFP/policy decisions.
- Dependency layout: build inputs live under `third_party/routine` and `third_party/builder`.

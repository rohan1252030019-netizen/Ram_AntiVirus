# Third-Party Licenses & AGPL-3.0 Compatibility Audit

This document details the third-party dependencies used across the Ram Antivirus (AEGIS) repository, their licenses, and an analysis verifying legal compatibility with the GNU Affero General Public License Version 3 (AGPL-3.0-or-later).

## Core Project Licensing
- **Repository License**: GNU Affero General Public License v3.0 (`AGPL-3.0-or-later`)
- **Applies to**:
  - `agent-rust/` (EDR-lite native endpoint agent & ransomware mitigation)
  - `node-tauri/` (Tauri-based desktop node agent)
  - `desktop-tauri/` (Tauri desktop client application)
  - `agent/` (Python endpoint agent)
  - `backend/` (FastAPI backend server & detection engine)
  - `frontend/` (Next.js web dashboard)

---

## 1. Rust Agent Dependencies (`agent-rust` & `node-tauri`)

| Crate | Version | License | Compatible with AGPL-3.0? | Notes |
| :--- | :--- | :--- | :---: | :--- |
| `tokio` | `1.x` | MIT | **Yes** | Permissive, compatible with AGPL copyleft |
| `reqwest` | `0.12` | MIT OR Apache-2.0 | **Yes** | Permissive, compatible with AGPL copyleft |
| `serde` / `serde_json` | `1.0` | MIT OR Apache-2.0 | **Yes** | Permissive |
| `sysinfo` | `0.34` | MIT | **Yes** | Permissive |
| `notify` | `7.0` | CC0-1.0 | **Yes** | Public domain dedication |
| `uuid` | `1.x` | Apache-2.0 OR MIT | **Yes** | Permissive |
| `chrono` | `0.4` | MIT OR Apache-2.0 | **Yes** | Permissive |
| `sha2` | `0.10` | MIT OR Apache-2.0 | **Yes** | Permissive |
| `hmac` | `0.12` | MIT OR Apache-2.0 | **Yes** | Permissive |
| `hex` | `0.4` | MIT OR Apache-2.0 | **Yes** | Permissive |
| `log` / `env_logger` | `0.4` / `0.11` | MIT OR Apache-2.0 | **Yes** | Permissive |
| `thiserror` | `1.0` | MIT OR Apache-2.0 | **Yes** | Permissive |
| `windows` | `0.58` | MIT OR Apache-2.0 | **Yes** | Permissive (Windows system API bindings) |
| `nix` | `0.29` | MIT | **Yes** | Permissive (Unix libc bindings) |
| `tauri` | `2.10` | MIT OR Apache-2.0 | **Yes** | Permissive desktop UI runtime |

---

## 2. Python Agent & Backend Dependencies (`agent/` & `backend/`)

| Package | Version | License | Compatible with AGPL-3.0? | Notes |
| :--- | :--- | :--- | :---: | :--- |
| `fastapi` | `0.115` | MIT | **Yes** | Permissive API framework |
| `uvicorn` | `0.34` | BSD-3-Clause | **Yes** | Permissive ASGI server |
| `pydantic` | `2.10` | MIT | **Yes** | Permissive validation engine |
| `sqlalchemy` | `2.0` | MIT | **Yes** | Permissive ORM |
| `cryptography` | `43+` | Apache-2.0 OR BSD-3-Clause | **Yes** | Permissive crypto library |
| `httpx` | `0.28` | BSD-3-Clause | **Yes** | Permissive HTTP client |
| `psutil` | `6.0` | BSD-3-Clause | **Yes** | Permissive process utility |
| `watchdog` | `4.0` | Apache-2.0 | **Yes** | Permissive filesystem watcher |
| `redis` | `5.0` | MIT | **Yes** | Permissive caching client |
| `scikit-learn` / `numpy` | `1.5` / `1.26` | BSD-3-Clause | **Yes** | Permissive ML/numerical stack |
| `websockets` | `14.1` | BSD-3-Clause | **Yes** | Permissive WebSocket library |
| `reportlab` | `4.1` | BSD-like | **Yes** | Permissive PDF generator |
| `paramiko` | `3.4` | LGPL-2.1-or-later | **Yes** | Weak copyleft; permits combination under AGPL-3.0 |
| `scapy` | `2.5` | GPL-2.0-or-later | **Yes** | Copyleft; GPL-2.0-or-later is forward-compatible with GPLv3/AGPLv3 |

---

## 3. License Flag Analysis & Compliance Verification

1. **Permissive Licenses (MIT, Apache-2.0, BSD-2/3-Clause, CC0)**:
   - Form the vast majority (>95%) of the dependency graph.
   - Permissive licenses permit redistribution under stronger copyleft licenses like AGPL-3.0 without restriction.

2. **LGPL-2.1-or-later (`paramiko`)**:
   - Section 3 of LGPL-2.1 explicitly permits relicensing or combining under the terms of the ordinary GNU General Public License / AGPL.

3. **GPL-2.0-or-later (`scapy`)**:
   - Because Scapy is licensed as GPL-2.0-or-later ("or any later version"), it can be combined and distributed under AGPL-3.0.

4. **Proprietary / Incompatible Licenses**:
   - **None detected**. No components or dependencies require proprietary runtime keys or use restrictive non-commercial licenses (CC-BY-NC, SSPL, BSL, or viral licenses with GPL incompatibilities).

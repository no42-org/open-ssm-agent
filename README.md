# open-ssm-agent

A Rust, **AWS-independent** alternative to `amazon-ssm-agent`: SSM-class remote
management — interactive shells, command execution, port forwarding, file
transfer — over an outbound-only channel, with a self-hosted control plane and a
NetBox inventory sink. Zero AWS dependency, by construction.

> Status: **scaffold**. The planning chain (research → architecture spine →
> SPEC) is complete in the maintainer's local workspace; capabilities are not
> yet implemented.

## Topology

Three parties, two planes (operators never reach agents directly):

```
operator ──gRPC──▶ coordinator ──MQTT (E2E-encrypted)──▶ broker ──▶ agent (host)
                        │                                            (outbound-only,
                        ├── Postgres (registry · audit · policy)      no inbound ports)
                        └── NetBox (one-way inventory sink)
```

## Workspace

A single Cargo workspace; the dependency direction is the load-bearing rule
(`osa-proto` → `osa-core` → adapters/bins; **core never depends on an adapter**).

| Crate | Role |
| --- | --- |
| `osa-proto` | Generated protobuf types — the one shared IDL (AD-6). |
| `osa-core` | Domain + ports (traits). No I/O, no adapter deps (AD-26). |
| `osa-agent` | Host agent: `ControlChannel`, capabilities, vault, collectors, local backstop. |
| `osa-coordinator` | gRPC operator API, broker bridge, registry/audit/policy, `CertIssuer`, NetBox `InventorySink`. |
| `osa-cli` (`osa`) | Operator CLI — the v1 client surface. |

## Build

```sh
make build     # cargo build --workspace
make verify    # fast inner loop: fmt check + clippy (-D warnings) + tests
make verify-ci # full CI parity before pushing (adds Linux clippy + typos/machete/deny)
```

Requires Rust ≥ 1.91 (MSRV floor) and `protoc` for `osa-proto` codegen.

`make verify-ci` also runs `make lint-linux`, which clippy-checks the
`cfg(target_os = "linux")` code inside a Linux container (Docker) — host clippy
on macOS/Windows skips it, so this is what stops a Linux-only lint from passing
locally and failing CI. `make verify` stays host-native for a fast inner loop.

## NetBox inventory sink

When the coordinator is started with `--netbox-url` and `--netbox-token`
(env `OSA_NETBOX_URL` / `OSA_NETBOX_TOKEN`), agent-reported inventory is
reconciled into NetBox (AD-16/AD-17). The coordinator holds the **only** NetBox
write credential — no host ever does.

**Deployment precondition:** create a text custom field named `osa_host_id` bound
to the `dcim.device` object type in NetBox before enabling the sink. NetBox
rejects a write to an unregistered custom field with HTTP 400, so without it every
inventory stamp fails; the coordinator logs a loud warning at startup when the
field is absent. Devices are matched on their DMI serial and only the agent's
`host_id` is written — human-curated fields (site, rack, role, tenant,
description) are never touched.

## Contract

Source comments cite a preservation-validated `SPEC.md` and the architecture
spine it draws on (decisions `AD-1`…`AD-32`). These planning artifacts live in
the maintainer's local `_bmad-output/` workspace and are intentionally **not**
committed (see `.gitignore`) — they are the design rationale behind the code,
not a build input.

## License

MIT — see [LICENSE](LICENSE).

# Commissioner Persistent Store

A `matter.Commissioner` automatically persists its fabric identity and a
record of every device it successfully commissions to the local
filesystem, under `~/.{app-name}/`. This lets a controller built on
`go-matter` resume the same fabric, and recall which devices it has
already commissioned, across process restarts — without the application
having to manage that state itself.

The persistence layer is implemented in the [`matter/store`](../matter/store)
package; `Commissioner` wires it in automatically (see
[Lifecycle](#lifecycle) below). The filesystem is only the default backend:
the same records can be kept in memory or in any other storage (see
[Storage backends](#storage-backends)).

## Directory Layout

```
~/.{app-name}/
├── fabric.json
└── commissions/
    └── <compressedFabricID>-<nodeID>.json
```

- `{app-name}` defaults to `go-matter` (so `~/.go-matter/`), and is
  configurable per `Commissioner` instance — see
  [Configuring the location](#configuring-the-location).
- `<compressedFabricID>-<nodeID>` is two 16-digit uppercase hex numbers,
  e.g. `B923078EEB190343-0000000016A5E84A` — the same format used for the
  device's mDNS operational-node service instance name
  (`_matter._tcp`), so a commissionee record's filename is also the string
  a reconnect-over-CASE lookup would search for.
- The directory is created at file mode `0700`, and every file within it
  at `0600`, since `fabric.json` holds private key material in plaintext
  (see [Security](#security)).

## Explicit controller initialization

`credentials.GenerateControllerIdentity()` generates P-256 root/controller keys,
root/controller certificates, random Fabric/controller IDs and an IPK in memory.
It never writes files or contacts a device. `ValidateControllerIdentity` checks
keys, certificate chain, identity binding and validity before use. Never log or
format the returned identity. This initial helper uses direct root signing.

`store.CreateFabric(st, rec)` is optional for custom stores/backends, and fails
if atomic creation is unsupported. File and memory backends install the first
identity exclusively; an existing `fabric.json` is never overwritten. The file
backend publishes a complete synced temporary file by hard link, so a crash sees
a complete identity or no identity. An unsupported filesystem fails safely.
The regular `SaveFabric` replacement API remains for existing callers.
`matterctl tui --live` exposes creation only as an explicit, confirmed action.
Startup does not generate keys or create an absent store directory.

## `fabric.json` — fabric-wide identity

One record, shared by every device on the fabric. It's the union of what
`config.AdministratorConfig` and `config.OperationalCredentialsConfig`
actually contribute to commissioning a device — not a full dump of both
configs, since some of `OperationalCredentialsConfig`'s fields
(`RootCertificate`/`NOC`/`ICAC`) are never read during commissioning (the
certificates actually sent to a device always come from the
administrator's own `CertificateAuthority`).

| Field             | JSON key           | Type     | Source                                            |
|-------------------|---------------------|----------|----------------------------------------------------|
| Fabric ID         | `fabricId`          | `uint64` | `AdministratorConfig.FabricID()`                   |
| Administrator Node ID | `adminNodeId`   | `uint64` | `AdministratorConfig.NodeID()`                     |
| Admin Vendor ID   | `adminVendorId`      | `uint16` | `OperationalCredentialsConfig.AdminVendorID()`      |
| Root Certificate  | `rootCertificate`    | `[]byte` (base64) | `AdministratorConfig.RootCertificate()`   |
| Root Private Key  | `rootPrivateKey`     | `[]byte` (base64) | `AdministratorConfig.RootPrivateKey()`    |
| Administrator NOC | `noc`                | `[]byte` (base64) | `AdministratorConfig.NOC()`               |
| Administrator ICAC | `icac` (omitted if empty) | `[]byte` (base64) | `AdministratorConfig.ICAC()`     |
| Administrator Private Key | `privateKey`  | `[]byte` (base64) | `AdministratorConfig.PrivateKey()`        |
| Identity Protection Key | `ipk`           | `[]byte` (base64) | `OperationalCredentialsConfig.IPK()`      |
| Last Updated      | `updatedAt`          | RFC 3339 timestamp | when this record was last saved  |

`config.OperationalCredentialsConfig.CASEAdminNodeID()` is not stored
separately — it must always equal `adminNodeId` — and is reconstructed
from it when this record is loaded back into an `OperationalCredentialsConfig`.

Example:

```json
{
  "fabricId": 2,
  "adminNodeId": 1,
  "adminVendorId": 65521,
  "rootCertificate": "MIIB...",
  "rootPrivateKey": "MIGH...",
  "noc": "MIIC...",
  "privateKey": "MIGH...",
  "ipk": "AAECAwQFBgcICQoLDA0ODw==",
  "updatedAt": "2026-09-20T01:08:15Z"
}
```

## `commissions/<compressedFabricID>-<nodeID>.json` — per-device record

One record per device the `Commissioner` has successfully commissioned.

| Field              | JSON key              | Type     | Notes                                          |
|--------------------|------------------------|----------|--------------------------------------------------|
| Node ID            | `nodeId`               | `uint64` | The operational Node ID assigned during AddNOC.  |
| Fabric ID          | `fabricId`              | `uint64` | The fabric the device joined.                    |
| Compressed Fabric ID | `compressedFabricId`  | `uint64` | `caseprotocol.ComputeCompressedFabricID(...)`; also encoded (as hex) in the filename. |
| Vendor ID          | `vendorId`              | `uint16` | From the device's onboarding advertisement.      |
| Product ID         | `productId`             | `uint16` | From the device's onboarding advertisement.      |
| Discriminator      | `discriminator` (omitted if 0) | `uint16` | From the device's onboarding advertisement. |
| NOC                | `noc`                   | `[]byte` (base64) | The Node Operational Certificate issued to the device, DER-encoded. |
| ICAC               | `icac` (omitted if empty) | `[]byte` (base64) | Intermediate certificate, if one was issued. Always empty today — this project's `CertificateAuthority` doesn't yet issue through an ICA. |
| Commissioned At    | `commissionedAt`        | RFC 3339 timestamp | when the device was commissioned.       |

Example:

```json
{
  "nodeId": 379971658,
  "fabricId": 2,
  "compressedFabricId": 13340514831612576579,
  "vendorId": 65521,
  "productId": 32769,
  "discriminator": 2748,
  "noc": "MIIC...",
  "commissionedAt": "2026-09-20T01:08:15Z"
}
```

**Note:** `go-matter` does not implement CASE session resumption (there is
no cached `resumptionID`/shared secret to skip the handshake) — this
record is enough to locate a device again and run a fresh Sigma1-3
handshake, not to resume a previous one.

## Configuring the location

```go
// Default: ~/.go-matter/
cmr := matter.NewCommissioner()

// A different app name: ~/.myapp/
cmr := matter.NewCommissioner(matter.WithCommissionerAppName("myapp"))

// An arbitrary directory, bypassing ~/.{app-name} resolution entirely —
// mainly for tests, which should always use this to avoid touching the
// real user's home directory (e.g. matter.WithCommissionerStoreDir(t.TempDir())).
cmr := matter.NewCommissioner(matter.WithCommissionerStoreDir("/path/to/dir"))

// A Store of your own, bypassing the filesystem entirely. In tests,
// store.NewMemStore() keeps everything in memory.
cmr := matter.NewCommissioner(matter.WithCommissionerStore(store.NewMemStore()))
```

## Storage backends

The `matter/store` package has two layers:

| Layer | Type | Role |
|-------|------|------|
| Backend | `store.KVStore` | Byte values under slash-separated keys (`fabric.json`, `commissions/<id>.json`): `Get`, `Set`, `Delete`, `List(prefix)`. |
| Backend | `store.TxKVStore` | A `KVStore` that also groups several writes into one atomic update with `Begin()` → `Tx` (`Set`/`Delete`/`Commit`/`Rollback`). |
| Typed | `store.Store` | `FabricRecord` and `CommissioneeRecord`, encoded as JSON onto a `KVStore`. |

Two backends are provided:

- `store.NewFileKVStore(dir)` keeps one file per key under `dir`, so the
  key `commissions/<id>.json` is the file of that name. `store.NewStore(dir)`
  is `store.NewStoreWithKVStore` over this backend, and is what a
  `Commissioner` opens by default.
- `store.NewMemKVStore()` keeps everything in memory.
  `store.NewMemStore()` is `store.NewStoreWithKVStore` over this backend.

Any other storage (a database, a secure element, a remote service) can be
plugged in by implementing `KVStore` and passing
`store.NewStoreWithKVStore(kv)` to `matter.WithCommissionerStore`.

A key is one or more non-empty segments separated by `/`; a segment may only
contain ASCII letters, digits, `.`, `-` and `_`, and must not start with `.`.
So no key can escape a `FileKVStore`'s directory, and names starting with `.`
are left to the backend's own bookkeeping.

### Atomicity

- A single `Set` on a `FileKVStore` writes a temporary file, syncs it and
  renames it over the target, so a crash leaves either the old or the new
  value, never a truncated one.
- A `Tx.Commit` on a `FileKVStore` first writes every pending write to
  `.journal.json` in the base directory, then applies them, then removes the
  journal. `NewFileKVStore` replays a journal left behind by a crash, so a
  committed transaction is always applied in full, and one that did not
  reach its journal is not applied at all.

The `Commissioner` itself does not need transactions yet. They are there for
the device side, where the NOC, the ACL and the fabric table written during
commissioning must be committed together, or rolled back when the fail-safe
expires.

## Lifecycle

- **`Start()`** uses the `Store` passed with `WithCommissionerStore`, if
  any; otherwise it resolves the directory (`storeDir` if set, else
  `~/.{appName}`) and opens a file store there. For whichever of
  `AdministratorConfig`/`OperationalCredentialsConfig` was *not* passed
  explicitly via `WithCommissionerAdministratorConfig`/
  `WithCommissionerOperationalCredentialsConfig`, it tries to load a
  previously saved `fabric.json` as a fallback. **Explicit configuration
  always wins** — a persisted file is only consulted for whatever wasn't
  given directly, and a load failure is logged, not fatal.
- **`Commission(...)`**, on success, saves `fabric.json` (using whatever
  `AdministratorConfig`/`OperationalCredentialsConfig` were actually used
  for that call) and a new `commissions/*.json` record for the device
  just commissioned. A save failure is logged but does not fail
  `Commission()` — the device is genuinely commissioned regardless of
  whether the local cache write succeeded.

## Security

`fabric.json` contains private key material (the fabric's root private
key and the administrator's own private key) in plaintext, and every file
this package writes is created at `0600` inside a `0700` directory as the
mitigation for that — the same posture as e.g. `~/.ssh`. This is not new
exposure: the same key material already flows through the process in
plaintext PEM/DER today, supplied by the caller; persistence just makes it
durable on disk. There is currently no encryption at rest and no file
locking for multiple processes sharing a directory — treat `~/.{app-name}/`
with the same care as any other local credential store. A `Commissioner`
can forget a device with `Store.DeleteCommissionee`. To keep the key
material out of plaintext files, plug in a `KVStore` backed by an
encrypted or hardware-protected store.

## Programmatic access

The `matter/store` package can also be used directly, independent of
`Commissioner`, e.g. to inspect what's been commissioned so far:

```go
st, err := store.NewStore(dir)
...
recs, err := st.ListCommissionees()
for _, rec := range recs {
    fmt.Printf("node 0x%016X on fabric 0x%016X (%s)\n", rec.NodeID, rec.FabricID, rec.CommissionedAt)
}
```

See [`matter/store`](../matter/store) for the full `Store` interface.

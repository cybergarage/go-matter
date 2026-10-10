# Versioned Matter definition catalog (initial stage)

This separate change addresses [#11](https://github.com/cybergarage/go-matter/issues/11).
`matter/datamodel` is an offline metadata API. It adds no controller action, discovery,
credentials, TUI editor or change to existing protocol behavior.

## Official machine-readable sources and licensing

Matter has official machine-readable SDK definitions, but not a single unrestricted
MRA-equivalent dataset suitable for all redistribution uses. The official
[`data_model` specification/certification XML](https://github.com/project-chip/connectedhomeip/blob/v1.6.1.0/data_model/README.md)
is separate from SDK code generation. Individual files, e.g.
[`DoorLock.xml`](https://github.com/project-chip/connectedhomeip/blob/v1.6.1.0/data_model/1.6.1/clusters/DoorLock.xml),
carry CSA internal-use-only and publication/modification/derivative restrictions.
That tree is **not** an input to this public catalog.

This catalog imports only nine individually Apache-2.0-marked XML files from the
SDK ZAP tree and its input manifest. The pinned source is SDK `v1.6.1.0`, commit
`3bcdd56ba54fb88b2afb4bfef575014671df7aa7`:

- [`zcl.json`](https://github.com/project-chip/connectedhomeip/blob/3bcdd56ba54fb88b2afb4bfef575014671df7aa7/src/app/zap-templates/zcl/zcl.json): official SDK input manifest.
- `onoff-cluster.xml`, `temperature-measurement-cluster.xml`, `door-lock-cluster.xml`.
- `descriptor-cluster.xml`, `basic-information-cluster.xml` (individually reviewed for TUI inventory labels).
- `matter-devices.xml`, `chip-types.xml`, `access-control-definitions.xml`, `global-attributes.xml`.

Original licensed snapshots, SHA-256 checksums, paths and source SHA are under
[`matter/datamodel/internal/upstream`](../matter/datamodel/internal/upstream).
See [copyright/license notices](../matter/datamodel/NOTICE.md). No restricted XML,
private specification checkout, Alchemy installation or network is needed to regenerate.
The SDK `.matter` IDL conversion is not used: its
[parser](https://github.com/project-chip/connectedhomeip/blob/v1.6.1.0/scripts/py_matter_idl/matter/idl/zapxml/handlers/handlers.py)
is not a lossless carrier for the device-type/conformance metadata needed here.

**Metadata SDK 1.6.1 is not protocol support for Matter 1.6.1.** The library's current
protocol target remains 1.5. Revision differences must be checked during future
runtime matching; catalog presence never enables a controller operation.

## Initial coverage and API

The catalog contains exactly:

| Metadata | Coverage |
| --- | --- |
| Cluster schemas | On/Off (0x0006, revision 6), Door Lock (0x0101, revision 10), Temperature Measurement (0x0402, revision 4), Descriptor (0x001D, revision 3), Basic Information (0x0028, revision 6) |
| Application device profiles | 98 SDK entries, including SDK test/vendor entries; references to unloaded clusters remain names and are unresolved |
| Types | 126 atomic/enum/bitmap/struct definitions across the audited inputs |
| Global attributes | ClusterRevision, FeatureMap, AttributeList, AcceptedCommandList, GeneratedCommandList |

Atomic SDK type IDs are **not** Matter TLV type codes. Type names, widths, signedness,
fields, list entry types and SDK descriptions remain in their source metadata.
Provisional conditions and test/vendor definitions are preserved, not treated as
mandatory supported operations. `VendorSpecific` marks the application device-ID
vendor namespace; provisional/conformance information remains in `Definition`.

```go
catalog, err := datamodel.Load() // independently owned catalog; no I/O or network
if err != nil { /* handle corrupted embedded data */ }
cluster, found := catalog.Cluster(0x0006)
if found {
    attribute, exists := cluster.Attribute(0x4003)
    // attribute.Type == "StartUpOnOffEnum", Writable == true, Nullable == true
    _ = attribute
    _ = exists
    command, acceptedSchema := cluster.Command(0x01, "client")
    _ = command
    _ = acceptedSchema // schema direction, NOT observed device acceptance
}
```

`Catalog.DeviceType`, `Catalog.Type` (cluster-specific before global), and
`Catalog.GlobalAttribute` provide other lookups. Unknown numeric IDs return
`found=false`, allowing a UI to retain its numeric fallback.

Every indexed item carries `Definition`, an ordered XML metadata tree. Its
`Property`, `Child` and `NamedChildren` helpers expose exact declared constraints,
access privileges, response/argument fields, feature/conformance trees, timed
invoke flags and available fabric-related metadata. Full audited document trees
are also retained. Conditions, units and bounds are not evaluated or inferred.
Missing properties are not promises of protocol-default applicability. XML comments
and formatting remain in the original snapshots, not in the normalized semantic tree.

Example: OnOff attribute is readonly; On/Off/Toggle are client commands.
StartUpOnOff is a writable nullable enum with Manage write privilege and Lighting
feature conformance. Door Lock timed invoke and Temperature Measurement nullable
bounds are fixture-tested. There is no automatic permission decision.

## Deterministic generation and verification

```sh
GOWORK=off go generate ./matter/datamodel
make check-datamodel
```

Generator version `1` uses only checked-in inputs. It verifies source/version,
per-file checksums, individual Apache notices and membership in the SDK manifest.
The restricted `data_model` tree cannot be selected as an input. Unknown XML tags,
properties/namespaces, ambiguous IDs, unsupported normalized values and XML
directives fail with a diagnostic. Other known metadata is preserved in trees
rather than silently guessed. Future schema/input expansion requires an explicit
review of the generator allowlist, licensing, checksums, coverage and fixtures.
The generator writes a catalog only after input validation succeeds. Checked-in
JSON is byte-compared against freshly generated output in tests.

Tests include unknown/malformed schema, modified checksums, excluded licensing/tree,
lookup ambiguity, command direction, enum/feature/privilege/bounds retention,
independent consumer catalogs and exact coverage. Offline CI runs generation,
race, vet, lint and Linux/macOS arm64 package builds. No device or credential tests
are necessary for this metadata-only API.

## Remaining controller integration

This PR intentionally stops at a reusable metadata API. Later work should:

1. Read Descriptor PartsList/DeviceTypeList/ServerList/ClientList and global
   AttributeList/AcceptedCommandList/GeneratedCommandList/FeatureMap/ClusterRevision.
   Reconcile profile/cluster revisions and feature conditions; retain unknowns.
2. Add labels and capability-aware menus. Advertised existence does not imply ACL
   permission, writability, or conformance to every requirement in the dictionary.
3. Build validated TLV forms for supported scalar/enum/bitmap/null/list/struct
   values and command fields, applying privilege/timed/fabric constraints and
   explicit confirmations. Reuse Node Read/Write/Invoke and TimedInvoke; add a
   checked TimedWrite path where required. Distinguish ACK from fresh readback.

Additional clusters and complete license/input coverage, conformance evaluation,
fully resolved cross-cluster types/device requirements, unit presentation and TUI
forms remain follow-up work. Door Lock schema presence does not add lock/unlock or
credential-management actions to matterctl.

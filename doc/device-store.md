# Device Persistent Store

A Matter device must remember, across restarts, which fabrics it has
joined and what each of them is allowed to do. `store.DeviceStore` in the
[`matter/store`](../matter/store) package is the typed store for that
state; a [`matter/device`](device.md) Device keeps its fabrics, ACLs,
group keys, scenes and counters in it.

It is built on the same `store.KVStore` backends as the
[Commissioner Persistent Store](commissioner-store.md), and a device and a
commissioner can share one backend, since every device key lives under
`device/`.

## What is stored

| Record | Type | Spec | Scope |
|--------|------|------|-------|
| Fabric and operational credentials | `DeviceFabricRecord` | Operational Credentials cluster, Fabrics and NOCs lists (Core 11.18) | One per fabric |
| Access Control entries | `[]ACLEntry` | `AccessControlEntryStruct` (Core 9.10.5) | An ordered list per fabric |
| Group keys | `GroupKeysRecord` | `GroupKeySetStruct` and the group key map (Core 11.2.5) | One per fabric |
| Scenes | `[]SceneRecord` | The Scenes Management scene table (Application Cluster 1.4.7.1) | A list per fabric, over its endpoints |
| Counters | `PersistentCounter` | Global group message counters (Core 4.6.1.2), boot count | Device-wide |

A fabric is addressed by its fabric index, 1 to 254 (`MinFabricIndex` to
`MaxFabricIndex`); 0 means "no fabric" and 255 is reserved.

`DeviceFabricRecord` holds the fabric's root public key, fabric ID, node
ID, vendor ID and label, the RCAC, ICAC and NOC, and the operational
private key the NOC was issued for. The private key is stored in the record
as the commissioner's is; to keep it out of plaintext files, use a
`KVStore` backed by an encrypted or hardware-protected store.

The group key set with ID 0 is the fabric's IPK.

## Layout

With a `FileKVStore`, the keys are these files under the base directory:

```
device/
├── fabrics/
│   └── <fabricIndex>/        two uppercase hex digits, e.g. 01, 0A, FE
│       ├── fabric.json
│       ├── acl.json
│       ├── groupkeys.json
│       └── scenes.json
└── counters/
    └── <name>                the counter's bound, in decimal
```

Each fabric's records sit in their own directory, so `RemoveDeviceFabric`
removes the fabric, its ACL, its group keys and its scenes together, as
the RemoveFabric command requires.

## Scenes

A `SceneRecord` is a scene a fabric stored on an endpoint: its endpoint,
group and scene ID, name, transition time, and the attribute values it
sets on each cluster. The Scenes Management cluster of
[`matter/device/cluster`](../matter/device/cluster) saves its scene table
here after every change and restores it when it is registered, through
the `LoadScenes` and `SaveScenes` methods of `device.Endpoint`. Which scene
is current is not saved: after a restart no scene is valid, as the
cluster specifies. A scene saved while the fail-safe is armed is written
through its transaction, so it goes with a fabric the fail-safe rolls
back.

## The fail-safe

While a commissioner has the fail-safe armed, AddNOC, UpdateNOC and the
writes to the ACL and the group keys must not take effect for good: they
are committed on CommissioningComplete and undone when the fail-safe
expires. `DeviceStore.Begin` returns a `DeviceStoreTx` for exactly that:

```go
tx, err := ds.Begin()                    // ArmFailSafe
...
err = tx.SaveDeviceFabric(rec)           // AddNOC
err = tx.SaveACL(rec.FabricIndex, acl)   // the ACL write
...
err = tx.Commit()                        // CommissioningComplete
// or
err = tx.Rollback()                      // the fail-safe expired
```

Reads through the transaction see its own pending writes, and nothing is
visible through the store until `Commit`. With a `FileKVStore` a commit is
journaled, so a crash leaves either all of its writes applied or none (see
[Atomicity](commissioner-store.md#atomicity)).

## Counters

Some counters must never repeat a value, even across a restart, and yet
are incremented too often to be written each time: the global group
message counters are the example. `PersistentCounter` persists a bound
`reserve` values ahead of the value it hands out, and only writes again
when it reaches that bound. After a restart it resumes at the persisted
bound, so at most `reserve` values are skipped and none is repeated.

```go
// A group message counter: persisted every 1000 messages. Per the spec,
// its first value is random.
c, err := ds.Counter("group-data", 1000, randomInitialValue)
v, err := c.Next()

// The boot count: reserve 1 persists on every increment.
boot, err := ds.Counter("boot-count", 1, 0)
n, err := boot.Next()
```

`Next` does not advance when the bound cannot be persisted, so a value is
never handed out that a restart could repeat.

## What the store checks

The store checks only what it can check without the device's context: the
fabric index range, that an ACL entry's privilege and auth mode are
defined values, and that a group key set has one to three epoch keys. The
rules of the clusters themselves (for example, the limits on entries per
fabric, or that a group entry cannot grant Administer) belong to the
device implementation.

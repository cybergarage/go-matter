# Device (in development)

go-matter is growing a device role alongside the commissioner. The
[`matter/device`](../matter/device) package is its start: it can be found
and authenticated by a commissioner, but not yet commissioned all the way.

| Step | Status |
|------|--------|
| Commissionable mDNS service (`_matterc._udp`) | Implemented, with the go-mdns responder |
| PASE | Implemented (`pase.Responder`) |
| Fail-safe, General Commissioning | Implemented; CommissioningComplete waits for CASE |
| Device attestation, CSR, AddNOC | Not implemented |
| CASE responder | Not implemented |
| Interaction Model server | Invoke and Read (one message per report), on every PASE session |
| Other clusters | Not implemented |

The state a device persists, the fabrics, ACLs, group keys and counters,
is already defined by the [Device Persistent Store](device-store.md).

## Running a device

```go
dev, err := device.New(
    device.WithVerifier(verifier),      // or device.WithPasscode(20202021) for tests
    device.WithDiscriminator(3840),
    device.WithVendorID(0xFFF1),        // a test vendor ID
    device.WithProductID(0x8001),
    device.WithSessionHandler(func(s *device.Session) {
        // s.Keys() are the PASE session keys; s.Transport() receives the
        // commissioner's messages on that session.
    }),
)
err = dev.Start()   // listens on :5540
...
err = dev.Stop()
```

A device runs one PASE exchange at a time and ignores other commissioners
meanwhile. When PASE succeeds it picks an unused session ID, and routes every
secured message carrying that ID to the session's transport.

## The fail-safe

Commissioning changes the device only provisionally until it completes
(Matter Core 11.10.6.2). ArmFailSafe arms the fail-safe and begins a
`DeviceStore` transaction (see [Device Persistent Store](device-store.md#the-fail-safe)),
which the commissioning steps write through. CommissioningComplete commits
it; the fail-safe expiring, an ArmFailSafe with a zero expiry, or the device
stopping rolls it back, and the Breadcrumb attribute returns to 0. An
ArmFailSafe extends the fail-safe, but never past
`DefaultMaxCumulativeFailSafeLimit` from when it was first armed.
CommissioningComplete is only accepted over CASE, which the device does not
establish yet, so over PASE it answers InvalidAuthentication.

`WithDeviceStore` sets where the device persists its state; by default it
is kept in memory.

## The verifier

A device authenticates a commissioner with a SPAKE2+ verifier, not with the
passcode itself (Matter Core 3.10). `pase.Verifier` holds the verifier
(`W0`, `L`) and the PBKDF salt and iteration count it was derived with. A
product is provisioned with one at the factory; `pase.NewVerifier` derives
one from a passcode, and `device.WithPasscode` does so with a random salt,
which is convenient for tests and tools.

## Advertising

`CommissionableService` describes what a commissionable device advertises
(Matter Core 4.3.1):

- the instance name, 16 random uppercase hex digits, under `_matterc._udp.local`
- the SRV target, a 16-hex-digit host name, and the port
- the subtypes `_L<discriminator>`, `_S<short discriminator>`,
  `_V<vendor ID>`, `_T<device type>` and `_CM`
- the TXT entries `D`, `CM`, `VP`, `DT`, `DN`, `SII`, `SAI`, `SAT`, `PH` and `PI`

A test encodes these records as an mDNS response and parses them with the
commissioner's own discovery code, so both sides agree on the format.

A `Device` publishes them with an `MDNSAdvertiser`, which runs the
[go-mdns](https://github.com/cybergarage/go-mdns) responder: it announces
the service when the device starts, answers the commissioners' queries by
service type and by subtype (such as `_L3840`), and sends goodbye records
when the device stops. The host name resolves to the addresses of the
interface each query arrives on.

`WithAdvertiser` replaces it, such as with a wrapper of the platform's
service (Bonjour, Avahi), and `WithAdvertiser(nil)` advertises nothing, for
a device a commissioner reaches by its address.
`NewMDNSAdvertiserWithServer` publishes through an `mdns.Server` the
application already runs.

A test finds a device with go-matter's own discovery by its long
discriminator over mDNS, and establishes PASE at the discovered address.

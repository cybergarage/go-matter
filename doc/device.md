# Device (in development)

go-matter is growing a device role alongside the commissioner. The
[`matter/device`](../matter/device) package is its start: it can be found
and authenticated by a commissioner, but not yet commissioned all the way.

| Step | Status |
|------|--------|
| Commissionable mDNS service (`_matterc._udp`) | The service is described; publishing it needs an `Advertiser` |
| PASE | Implemented (`pase.Responder`) |
| Fail-safe, General Commissioning | Not implemented |
| Device attestation, CSR, AddNOC | Not implemented |
| CASE responder | Not implemented |
| Interaction Model server and clusters | Not implemented |

The state a device persists, the fabrics, ACLs, group keys and counters,
is already defined by the [Device Persistent Store](device-store.md).

## Running a device

```go
dev, err := device.New(
    device.WithVerifier(verifier),      // or device.WithPasscode(20202021) for tests
    device.WithDiscriminator(3840),
    device.WithVendorID(0xFFF1),        // a test vendor ID
    device.WithProductID(0x8001),
    device.WithAdvertiser(advertiser),  // optional, see below
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

go-matter does not publish the records itself yet:
[go-mdns](https://github.com/cybergarage/go-mdns), which it uses to browse,
has no responder so far. A `Device` publishes through the `Advertiser`
interface given with `WithAdvertiser`, which can wrap the platform's service
(Bonjour, Avahi) or an mDNS responder library. Without one the device
advertises nothing, and a commissioner has to be pointed at its address.

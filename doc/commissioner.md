# Commissioner guide

How to commission devices with go-matter and operate them afterwards. The [README](../README.md#quick-start) has the shortest path; this page covers the options.

## Commissioning and connecting

A commissioner is started once, and it then discovers, commissions and reaches the devices of its fabric.

```go
commissioner := matter.NewCommissioner()
if err := commissioner.Start(); err != nil {
	return err
}
defer commissioner.Stop()

// The payload comes from the manual pairing code, or from the QR code, of
// the device.
payload, err := encoding.NewPairingCodeFromString(code)
if err != nil {
	return err
}

commissionee, err := commissioner.Commission(ctx, payload)
if err != nil {
	return err
}

nodeID, _ := commissionee.NodeID()
```

A device which is not on the network yet is found over BLE, and needs the Wi-Fi network it is to join. Options of a commissioning are given with the `WithCommission…` functions and `WithCommissioningProgress`:

```go
wifi := config.NewWiFiNetworkConfig(config.WithSSID(ssid), config.WithCredentials(password))
commissionee, err := commissioner.Commission(ctx, payload,
	matter.WithCommissionWiFiNetwork(wifi),
	matter.WithCommissioningProgress(func(p matter.CommissioningProgress) { … }),
)
```

A commissioned node is reached again through the store, without commissioning it a second time:

```go
node, err := commissioner.Connect(ctx, nodeID)
if err != nil {
	return err
}

res, err := node.ReadAttribute(ctx, endpointID, clusterID, attributeID)
```

Each request of a node takes a context: the wait for the response ends when it is done. Cluster functions which take a session get the node's session bound to a context with `im.WithContext(ctx, node.Session())`.

Commissioning bounds the whole PASE-through-CASE exchange with a single deadline, which defaults to `DefaultCommissioningTimeout` (120 seconds): a device commits its new fabric to persistent storage and then re-advertises itself over mDNS before CASE can start, and a shorter deadline expires in the middle of that.

## Device attestation

A commissioner verifies the device attestation of every device it commissions, and refuses one which does not verify with a `credentials.AttestationError`. The mode is set with `WithCommissionerAttestationMode`:

| Mode | Trusts |
| --- | --- |
| `matter.AttestationDevelopment` (default) | The production PAAs and CD signing keys of the DCL, bundled in `credentials/production`, and the test PAA and test CD signing key of the Matter SDK, so certified products and self-made test devices both commission |
| `matter.AttestationProduction` | The production trust anchors only: the test vendor IDs (0xFFF1 to 0xFFF4), development and test Certification Declarations and the SDK's test anchors are rejected |
| `matter.AttestationNone` | Nothing: only the DAC's signature over the attestation elements and the nonce are checked |

```go
commissioner := matter.NewCommissioner(
	matter.WithCommissionerAttestationMode(matter.AttestationProduction),
)
```

PAAs and CD signing certificates of your own are added with `WithCommissionerAttestationTrustStore` and `credentials.LoadAttestationTrustStore`. The library itself never reaches the network for them.

## Subscriptions and events

A node from `Connect` reports the attributes and the events it is subscribed to through a callback. The first report (`Priming`) holds every subscribed attribute; the subscription subscribes again when a report is overdue, and moves to a new session when the node's session fails.

```go
paths := []im.AttributeRequestPath{
	im.NewAttributeRequestPath(1, 0x0006, 0x0000), // On/Off of endpoint 1
}
sub, err := node.(matter.AttributeSubscriber).Subscribe(ctx, paths,
	func(r *im.Report) {
		for _, a := range r.Attributes {
			log.Printf("attribute %v: %v", a.Path, a.Value)
		}
		for _, e := range r.Events {
			log.Printf("event #%d %v at %d", e.EventNumber, e.Path, e.Timestamp)
		}
	},
	im.WithMaxInterval(time.Minute),
	im.WithEvents(im.NewEventRequestPath(0, 0x0028, 0x0000)), // StartUp of Basic Information
)
if err != nil {
	return err
}
defer sub.Close()
```

The events a node keeps are read with `EventReader`:

```go
events, err := node.(matter.EventReader).ReadEvents(ctx,
	[]im.EventRequestPath{im.NewEventRequestPath(0, 0x0028, 0x0000)},
)
```

## Reconnection

A node from `Connect` lives until it is closed. When a request finds its session failed, it connects again before the request, resuming the last CASE session when the node still knows it (session resumption) and running a full CASE when not; the request itself is not sent again. `Reconnector` does the same on demand:

```go
if r, ok := node.(matter.Reconnector); ok {
	if err := r.Reconnect(ctx); err != nil {
		return err
	}
	log.Printf("session resumed: %v", r.Resumed())
}
```

## Key store

By default, the fabric's root CA key and the commissioner's operational key are kept in the fabric record of the store. `WithCommissionerKeyStore` keeps them in a `keystore.KeyStore` instead: encrypted files, or an HSM, a cloud KMS or a TPM through `crypto.Signer`.

```go
ks, err := keystore.NewFileKeyStore(dir, keystore.WithPassphrase(passphrase))
if err != nil {
	return err
}
commissioner := matter.NewCommissioner(matter.WithCommissionerKeyStore(ks))
```

`Start` moves the keys an existing fabric record holds into the key store. See [Commissioner Persistent Store](commissioner-store.md#key-store).

## Sharing a node with another ecosystem (multi-admin)

`administratorcommissioning.NewWindow` makes a fresh setup passcode, discriminator and salt for a node, with its manual pairing code and QR code; `OpenCommissioningWindow` opens the window on the node (a timed invoke), for another commissioner, such as Google Home or Amazon Alexa, to add it to its own fabric. The passcode never leaves the controller: the node is given a verifier.

```go
window, err := administratorcommissioning.NewWindow(vendorID, productID)
if err != nil {
	return err
}
sess := im.WithContext(ctx, node.Session())
if err := administratorcommissioning.OpenCommissioningWindow(sess, 0, window, 10*time.Minute); err != nil {
	return err
}
fmt.Println(window.ManualPairingCode, window.QRCode)
```

`RevokeCommissioning` closes the window early, and `ReadWindowStatus` tells whether one is open. A device another ecosystem shares is commissioned with its code as any other, over the network.

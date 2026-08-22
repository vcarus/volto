module github.com/vcarus/volto/tests/interop

go 1.25.0

require (
	// A commit rather than a release: quic-go v0.61.0 replaced the free
	// function http3.ParseCapsule with the CapsuleParser type, and masque-go
	// v0.4.0 -- still its latest tag, cut three weeks before that quic-go
	// release -- calls the removed function, so the two cannot be built
	// together. This commit is upstream's own adaptation: "update quic-go to
	// v0.61.0, use new capsule parsing API" (quic-go/masque-go#133). Go back
	// to a release as soon as masque-go tags one that requires quic-go
	// v0.61.0 or newer.
	github.com/quic-go/masque-go v0.4.1-0.20260724165511-ef3cba4ab1b9
	github.com/quic-go/quic-go v0.61.0
	github.com/yosida95/uritemplate/v3 v3.0.2
)

require (
	github.com/dunglas/httpsfv v1.1.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

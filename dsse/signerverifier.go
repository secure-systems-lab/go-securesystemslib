package dsse

// SignerVerifer provides both the signing and verification interface.
type SignerVerifier interface {
	Signer
	Verifier
}

type SignVerifier = SignerVerifier // alias for backwards compatibility

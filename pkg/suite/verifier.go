package suite

type Verifier interface {
	// Verify will verify a signature.
	Verify(pub, doc, signature, nonce []byte) error
}

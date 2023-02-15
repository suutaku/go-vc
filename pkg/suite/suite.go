package suite

import "github.com/suutaku/go-vc/pkg/processor"

type SignatureSuite interface {

	// CompactProof indicates weather to compact the proof doc before canonization
	CompactProof() bool

	// GetDigest returns document digest
	GetDigest(doc []byte) []byte

	Sign(doc []byte) ([]byte, error)

	// Verify will verify signature against public key
	Verify(msg, proof, pub, nonce []byte) error

	// Accept registers this signature suite with the given signature type
	Accept(signatureType string) bool

	// GetCanonicalDocument will return normalized/canonical version of the document
	GetCanonicalDocument(doc map[string]interface{}, opts ...processor.ProcessorOpts) ([]byte, error)

	// Alg will return algorithm
	Alg() string
}

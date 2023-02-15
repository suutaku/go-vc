package bbsblssignature2020

import (
	"github.com/suutaku/go-bbs/pkg/bbs"
	"github.com/suutaku/go-vc/internal/tools"
	"github.com/suutaku/go-vc/pkg/processor"
)

const (
	signatureType = "BbsBlsSignature2020"
	rdfDataSetAlg = "URDNA2015"
)

type SignatureSuite struct {
	*Signer
	*Verifier
	*Blinder
	CompactedProof bool
}

func NewSignatureSuite(priv *bbs.PrivateKey, compacted bool) *SignatureSuite {
	return &SignatureSuite{
		Signer:         NewSigner(priv),
		Verifier:       NewVerifier(),
		CompactedProof: compacted,
		Blinder:        NewBlinder(priv),
	}
}

// GetCanonicalDocument will return normalized/canonical version of the document
func (suite *SignatureSuite) GetCanonicalDocument(doc map[string]interface{}, opts ...processor.ProcessorOpts) ([]byte, error) {
	return processor.Default().GetCanonicalDocument(doc, opts...)
}

// GetDigest returns document digest
func (suite *SignatureSuite) GetDigest(doc []byte) []byte {
	return doc
}

func (suite *SignatureSuite) Alg() string {
	return signatureType
}

func (suite *SignatureSuite) Sign(docByte []byte) ([]byte, error) {
	return suite.Signer.Sign(tools.SplitMessageIntoLines(string(docByte), true))
}

// Verify will verify signature against public key
func (suite *SignatureSuite) Verify(pubKeyValue, message, signature, nonce []byte) error {
	return suite.Verifier.Verify(pubKeyValue, message, signature, nonce)
}

// Accept registers this signature suite with the given signature type
func (suite *SignatureSuite) Accept(sType string) bool {
	return sType == signatureType
}

// CompactProof indicates weather to compact the proof doc before canonization
func (suite *SignatureSuite) CompactProof() bool {
	return suite.CompactedProof
}

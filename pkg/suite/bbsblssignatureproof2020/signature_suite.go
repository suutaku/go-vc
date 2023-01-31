package bbsblssignatureproof2020

import (
	"strings"

	"github.com/suutaku/go-bbs/pkg/bbs"
	"github.com/suutaku/go-vc/internal/processor"
	"github.com/suutaku/go-vc/internal/tools"
)

const (
	signatureType      = "BbsBlsSignature2020"
	signatureProofType = "BbsBlsSignatureproof2020"
	rdfDataSetAlg      = "URDNA2015"
)

type SignatureSuite struct {
	*Signer
	*Verifier
	CompactedProof bool
}

func NewSignatureSuite(priv *bbs.PrivateKey, compacted bool) *SignatureSuite {
	return &SignatureSuite{
		Signer:         NewSigner(priv),
		Verifier:       NewVerifier(),
		CompactedProof: compacted,
	}
}

// GetCanonicalDocument will return normalized/canonical version of the document
func (suite *SignatureSuite) GetCanonicalDocument(doc map[string]interface{}, opts ...processor.ProcessorOpts) ([]byte, error) {
	if v, ok := doc["type"]; ok {
		docType, ok := v.(string)

		if ok && strings.HasSuffix(docType, signatureProofType) {
			docType = strings.Replace(docType, signatureProofType, signatureType, 1)
			doc["type"] = docType
		}
	}

	return processor.Default().GetCanonicalDocument(doc, opts...)
}

// GetDigest returns document digest
func (suite *SignatureSuite) GetDigest(doc []byte) []byte {
	return doc
}

func (suite *SignatureSuite) Alg() string {
	return signatureProofType
}

func (suite *SignatureSuite) Sign(docByte []byte) ([]byte, error) {
	return suite.Signer.Sign(tools.SplitMessageIntoLines(string(docByte), true))
}

// Accept registers this signature suite with the given signature type
func (suite *SignatureSuite) Accept(sType string) bool {
	return sType == signatureProofType
}

// CompactProof indicates weather to compact the proof doc before canonization
func (suite *SignatureSuite) CompactProof() bool {
	return suite.CompactedProof
}

// Verify will verify signature against public key
func (suite *SignatureSuite) Verify(pubKeyValue, message, signature, nonce []byte) error {
	return suite.Verifier.Verify(pubKeyValue, message, signature, nonce)
}

package credential

import (
	"errors"
	"fmt"

	"github.com/suutaku/go-vc/pkg/common"
	"github.com/suutaku/go-vc/pkg/processor"
	"github.com/suutaku/go-vc/pkg/proof"
	"github.com/suutaku/go-vc/pkg/suite"
)

const (
	defaultProofPurpose    = "assertionMethod"
	jsonldContext          = "@context"
	jsonldCreated          = "created"
	jsonldProof            = "proof"
	jsonldJWS              = "jws"
	jsonldProofValue       = "proofValue"
	securityContext        = "https://w3id.org/security/v2"
	securityContextJWK2020 = "https://w3id.org/security/jws/v1"
)

func (cred *Credential) AddLinkedDataProof(s suite.SignatureSuite, lcon *proof.LinkedDataProofContext, opts ...processor.ProcessorOpts) error {
	context := lcon.ToContext()
	// validation of context
	if err := context.Validate(); err != nil {
		return err
	}
	// construct proof
	p := &proof.Proof{
		Type:                    context.SignatureType,
		SignatureRepresentation: context.SignatureRepresentation,
		Creator:                 context.Creator,
		Created:                 common.NewFormatedTime(),
		Domain:                  context.Domain,
		Nonce:                   context.Nonce,
		VerificationMethod:      context.VerificationMethod,
		Challenge:               context.Challenge,
		ProofPurpose:            context.Purpose,
		CapabilityChain:         context.CapabilityChain,
	}
	if p.ProofPurpose == "" {
		p.ProofPurpose = defaultProofPurpose
	}

	if context.SignatureRepresentation == proof.SignatureJWS {
		p.JWS = proof.NewJwt().NewHeader(s.Alg() + "..")
	}

	message, err := CreateVerifyData(s, cred.ToMap(), p, opts...)
	if err != nil {
		return err
	}
	sig, err := s.Sign(message)
	if err != nil {
		return err
	}
	p.ApplySignatureValue(context, sig)
	return cred.AddProof(p)
}

// CreateVerifyData creates data that is used to generate or verify a digital signature.
// It depends on the signature value holder type.
// In case of "proofValue", the standard Create Verify Hash algorithm is used.
// In case of "jws", verify data is built as JSON Web Signature (JWS) with detached payload.
func CreateVerifyData(s suite.SignatureSuite, jsonldDoc map[string]interface{}, p *proof.Proof,
	opts ...processor.ProcessorOpts) ([]byte, error) {
	switch p.SignatureRepresentation {
	case proof.SignatureProofValue:
		return createVerifyHash(s, jsonldDoc, p.ToMap(), opts...)
	case proof.SignatureJWS:
		return createVerifyJWS(s, jsonldDoc, p, opts...)
	}

	return nil, fmt.Errorf("unsupported signature representation: %v", p.SignatureRepresentation)
}

// CreateVerifyHash returns data that is used to generate or verify a digital signature
// Algorithm steps are described here https://w3c-dvcg.github.io/ld-signatures/#create-verify-hash-algorithm
func createVerifyHash(s suite.SignatureSuite, jsonldDoc, proofOptions map[string]interface{},
	opts ...processor.ProcessorOpts) ([]byte, error) {
	// in  order to generate canonical form we need context
	// if context is not passed, use document's context
	// spec doesn't mention anything about context
	_, ok := proofOptions[jsonldContext]
	if !ok {
		proofOptions[jsonldContext] = jsonldDoc[jsonldContext]
	}

	canonicalProofOptions, err := prepareCanonicalProofOptions(s, proofOptions, opts...)
	if err != nil {
		return nil, err
	}

	proofOptionsDigest := s.GetDigest(canonicalProofOptions)

	canonicalDoc, err := prepareCanonicalDocument(s, jsonldDoc, opts...)
	if err != nil {
		return nil, err
	}

	docDigest := s.GetDigest(canonicalDoc)

	return append(proofOptionsDigest, docDigest...), nil
}

// createVerifyJWS creates a data to be used to create/verify a digital signature in the
// form of JSON Web Signature (JWS) with detached content (https://tools.ietf.org/html/rfc7797).
// The algorithm of building the payload is similar to conventional  Create Verify Hash algorithm.
// It differs by using https://w3id.org/security/v2 as context for JSON-LD canonization of both
// JSON and Signature documents and by preliminary JSON-LD compacting of JSON document.
// The current implementation is based on the https://github.com/digitalbazaar/jsonld-signatures.
func createVerifyJWS(s suite.SignatureSuite, jsonldDoc map[string]interface{}, p *proof.Proof,
	opts ...processor.ProcessorOpts) ([]byte, error) {
	proofOptions := p.ToMap()

	canonicalProofOptions, err := prepareJWSProof(s, proofOptions, opts...)
	if err != nil {
		return nil, err
	}

	proofOptionsDigest := s.GetDigest(canonicalProofOptions)

	canonicalDoc, err := prepareDocumentForJWS(s, jsonldDoc, opts...)
	if err != nil {
		return nil, err
	}

	docDigest := s.GetDigest(canonicalDoc)

	verifyData := append(proofOptionsDigest, docDigest...)
	jwtb := proof.NewJwt()
	err = jwtb.Parse(p.JWS)
	if err != nil {
		return nil, err
	}

	return append([]byte(jwtb.Header()+"."), verifyData...), nil
}

func prepareCanonicalProofOptions(s suite.SignatureSuite, proofOptions map[string]interface{},
	opts ...processor.ProcessorOpts) ([]byte, error) {
	value, ok := proofOptions[jsonldCreated]
	if !ok || value == nil {
		return nil, errors.New("created is missing")
	}

	// copy from the original proof options map without specific keys
	proofOptionsCopy := cleanProof(proofOptions)

	if s.CompactProof() {
		docCompacted, err := getCompactedWithSecuritySchema(proofOptionsCopy, opts...)
		if err != nil {
			return nil, err
		}

		proofOptionsCopy = docCompacted
	}

	// build canonical proof options
	return s.GetCanonicalDocument(proofOptionsCopy, opts...)
}

func cleanProof(p map[string]interface{}) map[string]interface{} {
	ret := p
	delete(ret, "id")
	delete(ret, "proofValue")
	delete(ret, "jws")
	delete(ret, "nonce")
	return ret
}

func prepareCanonicalDocument(s suite.SignatureSuite, jsonldObject map[string]interface{},
	opts ...processor.ProcessorOpts) ([]byte, error) {
	// copy document object without proof
	docCopy := GetCopyWithoutProof(jsonldObject)

	// build canonical document
	return s.GetCanonicalDocument(docCopy, opts...)
}

// GetCopyWithoutProof gets copy of JSON LD Object without proofs (signatures).
func GetCopyWithoutProof(jsonLdObject map[string]interface{}) map[string]interface{} {
	if jsonLdObject == nil {
		return nil
	}

	dest := make(map[string]interface{})

	for k, v := range jsonLdObject {
		if k != jsonldProof {
			dest[k] = v
		}
	}

	return dest
}

func getCompactedWithSecuritySchema(docMap map[string]interface{},
	opts ...processor.ProcessorOpts) (map[string]interface{}, error) {
	contextMap := map[string]interface{}{
		"@context": securityContext,
	}

	return processor.Default().Compact(docMap, contextMap, opts...)
}

func prepareJWSProof(s suite.SignatureSuite, proofOptions map[string]interface{},
	opts ...processor.ProcessorOpts) ([]byte, error) {
	// TODO proof contexts shouldn't be hardcoded in jws, should be passed in jsonld doc by author [Issue#1833]
	proofOptions[jsonldContext] = []interface{}{securityContext, securityContextJWK2020}
	proofOptionsCopy := make(map[string]interface{}, len(proofOptions))

	for key, value := range proofOptions {
		proofOptionsCopy[key] = value
	}

	delete(proofOptionsCopy, jsonldJWS)
	delete(proofOptionsCopy, jsonldProofValue)

	return s.GetCanonicalDocument(proofOptionsCopy, opts...)
}

func prepareDocumentForJWS(s suite.SignatureSuite, jsonldObject map[string]interface{},
	opts ...processor.ProcessorOpts) ([]byte, error) {
	// copy document object without proof
	doc := GetCopyWithoutProof(jsonldObject)

	if s.CompactProof() {
		docCompacted, err := getCompactedWithSecuritySchema(doc, opts...)
		if err != nil {
			return nil, err
		}

		doc = docCompacted
	}

	// build canonical document
	return s.GetCanonicalDocument(doc, opts...)
}

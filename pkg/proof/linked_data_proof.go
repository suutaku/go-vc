package proof

import "github.com/suutaku/go-vc/pkg/utils"

// LinkedDataProofContext holds options needed to build a Linked Data Proof.
type LinkedDataProofContext struct {
	SignatureType           string              // required
	SignatureRepresentation int                 // required
	Created                 *utils.FormatedTime // optional
	VerificationMethod      string              // optional
	Challenge               string              // optional
	Domain                  string              // optional
	Purpose                 string              // optional
	// CapabilityChain must be an array. Each element is either a string or an object.
	CapabilityChain []interface{}
}

func (lpc *LinkedDataProofContext) ToContext() *Context {
	return &Context{
		SignatureType:           lpc.SignatureType,
		SignatureRepresentation: lpc.SignatureRepresentation,
		Created:                 lpc.Created,
		VerificationMethod:      lpc.VerificationMethod,
		Challenge:               lpc.Challenge,
		Domain:                  lpc.Domain,
		Purpose:                 lpc.Purpose,
		CapabilityChain:         lpc.CapabilityChain,
	}
}

func (lpc *LinkedDataProofContext) Validate() bool {
	return true
}

package proof

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/suutaku/go-vc/pkg/common"
)

const (
	SecurityContext        = "https://w3id.org/security/v2"
	SecurityContextJWK2020 = "https://w3id.org/security/jws/v1"
	BbsBlsSignature2020    = "BbsBlsSignature2020"
	defaultProofPurpose    = "assertionMethod"
)

const (
	SignatureProofValue int = iota
	SignatureJWS
)

// Context holds signing options and private key.
type Context struct {
	SignatureType           string               // required
	Creator                 string               // required
	SignatureRepresentation int                  // optional
	Created                 *common.FormatedTime // optional
	Domain                  string               // optional
	Nonce                   []byte               // optional
	VerificationMethod      string               // optional
	Challenge               string               // optional
	Purpose                 string               // optional
	CapabilityChain         []interface{}        // optional
}

func (context *Context) Validate() error {
	if context.SignatureType == "" {
		return errors.New("signature type is missing")
	}
	if context.Created == nil || context.Created.IsZero() {
		context.Created = &common.FormatedTime{Time: time.Now()}
	}
	if context.Purpose == "" {
		context.Purpose = defaultProofPurpose
	}
	return nil
}

type Proof struct {
	Context                 interface{}          `json:"@context,omitempty"`
	Type                    string               `json:"type,omitempty"`
	Created                 *common.FormatedTime `json:"created,omitempty"`
	Creator                 string               `json:"creator,omitempty"`
	VerificationMethod      string               `json:"verificationMethod,omitempty"`
	ProofValue              string               `json:"proofValue,omitempty"`
	JWS                     string               `json:"jws,omitempty"`
	ProofPurpose            string               `json:"proofPurpose,omitempty"`
	Domain                  string               `json:"domain,omitempty"`
	Nonce                   []byte               `json:"nonce,omitempty"`
	Challenge               string               `json:"challenge,omitempty"`
	SignatureRepresentation int                  `json:"-"`
	// CapabilityChain must be an array. Each element is either a string or an object.
	CapabilityChain []interface{} `json:"capabilityChain,omitempty"`
}

func NewProof(ptype string) *Proof {
	return &Proof{
		Type: ptype,
	}
}

func NewProofFromMap(p map[string]interface{}) *Proof {
	ret := &Proof{}
	b, err := json.Marshal(p)
	if err != nil {
		logrus.Error(err)
		return nil
	}
	if err := json.Unmarshal(b, ret); err != nil {
		logrus.Error(err)
		return nil
	}
	return ret
}

func (pf *Proof) ToMap() map[string]interface{} {
	ret := make(map[string]interface{})
	b, err := json.Marshal(pf)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(b, &ret)
	if err != nil {
		return nil
	}
	return ret
}

func (pf *Proof) ToMapWithoutProofValue() map[string]interface{} {
	ret := pf.ToMap()
	delete(ret, "proofValue")
	return ret
}

func (pf *Proof) FromBytes(b []byte) error {
	return json.Unmarshal(b, pf)
}

func (pf *Proof) ToBytes() []byte {
	b, err := json.Marshal(pf)
	if err != nil {
		return nil
	}
	return b
}

func (p *Proof) PublicKeyId() (string, error) {
	if p.VerificationMethod != "" {
		return p.VerificationMethod, nil
	}

	if p.Creator != "" {
		return p.Creator, nil
	}

	return "", fmt.Errorf("no public key id")
}

func decodeBase64(s string) ([]byte, error) {
	allEncodings := []*base64.Encoding{
		base64.RawURLEncoding, base64.StdEncoding, base64.RawStdEncoding,
	}

	for _, encoding := range allEncodings {
		value, err := encoding.DecodeString(s)
		if err == nil {
			return value, nil
		}
	}

	return nil, fmt.Errorf("unsupported encoding")
}

func (p *Proof) GetProofVerifyValue() ([]byte, error) {
	if p.SignatureRepresentation == 0 {
		return decodeBase64(p.ProofValue)
	} else if p.SignatureRepresentation == 1 {
		jwtb := NewJwt()
		jwtb.Parse(p.JWS)
		sig := jwtb.Signature()
		return base64.RawURLEncoding.DecodeString(sig)
	}

	return nil, fmt.Errorf("unsupported signature representation: %v", p.SignatureRepresentation)
}

func (p *Proof) ApplySignatureValue(context *Context, s []byte) {
	switch context.SignatureRepresentation {
	case SignatureProofValue:
		p.ProofValue = base64.RawURLEncoding.EncodeToString(s)
	case SignatureJWS:
		p.JWS += base64.RawURLEncoding.EncodeToString(s)
	}
}

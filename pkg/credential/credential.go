package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/suutaku/go-vc/pkg/proof"
	"github.com/suutaku/go-vc/pkg/utils"
)

type Credential struct {
	Context []string               `json:"@context,omitempty"`
	Id      string                 `json:"id,omitempty"`
	Type    []string               `json:"type,omitempty"`
	Issuer  string                 `json:"issuer,omitempty"`
	Issued  *utils.FormatedTime    `json:"issuanceDate,omitempty"`
	Expired *utils.FormatedTime    `json:"expirationDate,omitempty"`
	Subject interface{}            `json:"credentialSubject,omitempty"`
	Proof   interface{}            `json:"proof,omitempty"`
	Status  map[string]interface{} `json:"credentialStatus,omitempty"`
	JWT     string                 `json:"jwt,omitempty"`
	// for advanced concepts
	Schema   interface{}            `json:"credentialSchema,omitempty"`
	Refresh  map[string]interface{} `json:"refreshService,omitempty"`
	Terms    interface{}            `json:"termsOfUse,omitempty"`
	Evidence interface{}            `json:"evidence,omitempty"`

	CustomFields map[string]interface{} `json:"-"`
}

func NewCredential() *Credential {
	return &Credential{}
}

// MarshalJSON defines custom marshalling of rawCredential to JSON.
func (rc *Credential) MarshalJSON() ([]byte, error) {
	type Alias Credential

	alias := (*Alias)(rc)

	return MarshalWithCustomFields(alias, rc.CustomFields)
}

// UnmarshalJSON defines custom unmarshalling of rawCredential from JSON.
func (rc *Credential) UnmarshalJSON(data []byte) error {
	type Alias Credential

	alias := (*Alias)(rc)
	rc.CustomFields = make(map[string]interface{})

	err := UnmarshalWithCustomFields(data, alias, rc.CustomFields)
	if err != nil {
		return err
	}

	return nil
}

func (cred *Credential) FromBytes(b []byte) error {
	return json.Unmarshal(b, cred)
}

func (cred *Credential) ToBytes() []byte {
	b, err := json.Marshal(cred)
	if err != nil {
		return nil
	}
	return b
}

func (cred *Credential) ToString() string {
	b, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

func (cred *Credential) FromMap(data map[string]interface{}) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return cred.FromBytes(b)
}

func (cred *Credential) ToMap() map[string]interface{} {
	ret := make(map[string]interface{})
	b := cred.ToBytes()
	json.Unmarshal(b, &ret)
	return ret
}

func (cred *Credential) ToMapWithoutProof() map[string]interface{} {
	ret := cred.ToMap()
	delete(ret, "proof")
	return ret
}

func (cred *Credential) AddProof(p *proof.Proof) error {
	if cred.Proof != nil {
		var proofs []interface{}
		switch p := cred.Proof.(type) {
		case []interface{}:
			proofs = p
		default:
			proofs = []interface{}{p}
		}
		proofs = append(proofs, p)
		cred.Proof = proofs
	} else {
		cred.Proof = p
	}
	return nil
}

func GetProofs(raw interface{}) ([]map[string]interface{}, error) {
	switch p := raw.(type) {
	case map[string]interface{}:
		return []map[string]interface{}{p}, nil
	case []interface{}:
		proofs := make([]map[string]interface{}, len(p))

		for i := range p {
			pp, ok := p[i].(map[string]interface{})
			if !ok {
				return nil, errors.New("proof is not a JSON map")
			}

			proofs[i] = pp
		}

		return proofs, nil
	case *proof.Proof:
		return []map[string]interface{}{p.ToMap()}, nil
	default:
		return nil, errors.New("proof is not map or array of maps")
	}
}

func GetBLSProofs(raw interface{}) ([]map[string]interface{}, error) {
	allProofs, err := GetProofs(raw)
	if err != nil {
		return nil, fmt.Errorf("read document proofs: %w", err)
	}

	blsProofs := make([]map[string]interface{}, 0)

	for _, p := range allProofs {
		proofType, ok := p["type"].(string)
		if ok && strings.HasSuffix(proofType, proof.BbsBlsSignature2020) {
			p["@context"] = proof.SecurityContext
			blsProofs = append(blsProofs, p)
		}
	}

	return blsProofs, nil
}

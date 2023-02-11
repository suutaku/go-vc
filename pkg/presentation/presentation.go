package presentation

import (
	"encoding/json"

	"github.com/suutaku/go-vc/pkg/common"
	"github.com/suutaku/go-vc/pkg/credential"
)

type Presentation struct {
	Context    interface{}             `json:"@context,omitempty"`
	ID         string                  `json:"id,omitempty"`
	Type       interface{}             `json:"type,omitempty"`
	Credential []credential.Credential `json:"verifiableCredential,omitempty"`
	Holder     string                  `json:"holder,omitempty"`
	Proof      []interface{}           `json:"proof,omitempty"`
	JWT        string                  `json:"jwt,omitempty"`
	// All unmapped fields are put here.
	CustomFields map[string]interface{} `json:"-"`
}

func NewPresentation() *Presentation {
	return &Presentation{
		Context: []string{
			common.DefaultVCJsonLDContext,
			common.DefaultBbsJsonLDContext,
		},
		Type: []string{
			// common.DefaultVCJsonLDContextTypeVC,
			common.DefaultVCJsonLDContextTypePR,
		},
		Credential: make([]credential.Credential, 0),
	}
}

// MarshalJSON defines custom marshalling of rawPresentation to JSON.
func (pr *Presentation) MarshalJSON() ([]byte, error) {
	type Alias Presentation

	alias := (*Alias)(pr)

	return common.MarshalWithCustomFields(alias, pr.CustomFields)
}

// UnmarshalJSON defines custom unmarshalling of rawPresentation from JSON.
func (pr *Presentation) UnmarshalJSON(data []byte) error {
	type Alias Presentation

	alias := (*Alias)(pr)
	pr.CustomFields = make(map[string]interface{})

	err := common.UnmarshalWithCustomFields(data, alias, pr.CustomFields)
	if err != nil {
		return err
	}

	return nil
}

func (pr *Presentation) FromBytes(b []byte) error {
	return json.Unmarshal(b, pr)
}

func (pr *Presentation) ToBytes() []byte {
	b, err := json.Marshal(pr)
	if err != nil {
		return nil
	}
	return b
}

func (pr *Presentation) ToString() string {
	b, err := json.MarshalIndent(pr, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

func (pr *Presentation) ToMap() map[string]interface{} {
	ret := make(map[string]interface{})
	b := pr.ToBytes()
	json.Unmarshal(b, &ret)
	return ret
}

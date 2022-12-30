package presentation

import (
	"encoding/json"

	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/pkg/proof"
)

type Presentation struct {
	Context    []string                `json:"@context,omitempty"`
	Id         string                  `json:"id,omitempty"`
	Credential []credential.Credential `json:"verifiableCredential,omitempty"`
	Proof      []*proof.Proof          `json:"proof,omitempty"`
}

func NewPresentation() *Presentation {
	return &Presentation{}
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

func (pr *Presentation) ToMap() map[string]interface{} {
	ret := make(map[string]interface{})
	b := pr.ToBytes()
	json.Unmarshal(b, &ret)
	return ret
}

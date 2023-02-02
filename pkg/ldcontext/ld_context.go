package ldcontext

import (
	"encoding/json"
	"net/http"

	"github.com/suutaku/go-vc/pkg/common"
)

type Context struct {
	Version      float32                `json:"@version,omitempty"`
	Protected    bool                   `json:"@protected,omitempty"`
	Id           string                 `json:"id,omitempty"`
	Type         string                 `json:"type,omitempty"`
	CustomFields map[string]interface{} `json:"-"`
}

func (ctx *Context) MarshalJSON() ([]byte, error) {
	type Alias Context

	alias := (*Alias)(ctx)

	return common.MarshalWithCustomFields(alias, ctx.CustomFields)
}

// UnmarshalJSON defines custom unmarshalling of JSONLDContext from JSON.
func (ctx *Context) UnmarshalJSON(data []byte) error {
	type Alias Context

	alias := (*Alias)(ctx)
	ctx.CustomFields = make(map[string]interface{})

	err := common.UnmarshalWithCustomFields(data, alias, ctx.CustomFields)
	if err != nil {
		return err
	}

	return nil
}

func (ctx *Context) ToMap() map[string]interface{} {
	ret := make(map[string]interface{})
	b, _ := ctx.MarshalJSON()
	json.Unmarshal(b, &ret)
	return ret
}

type JSONLDContext struct {
	Context Context `json:"@context"`
}

func NewJSONLDContext() *JSONLDContext {
	return &JSONLDContext{}
}

func (ldc *JSONLDContext) FromURL(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	return json.NewDecoder(resp.Body).Decode(ldc)
}

func (ldc *JSONLDContext) FromBytes(b []byte) error {
	return json.Unmarshal(b, ldc)
}

func (ldc *JSONLDContext) ToBytes() []byte {
	b, _ := json.Marshal(ldc)
	return b
}

func (ldc *JSONLDContext) ToString() string {
	b, err := json.MarshalIndent(ldc, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

func (ldc *JSONLDContext) FromMap(data map[string]interface{}) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return ldc.FromBytes(b)
}

func (ldc *JSONLDContext) ToMap() map[string]interface{} {
	ret := make(map[string]interface{})
	b := ldc.ToBytes()
	json.Unmarshal(b, &ret)
	return ret
}

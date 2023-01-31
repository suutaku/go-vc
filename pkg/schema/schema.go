package schema

import (
	"encoding/json"
	"io/ioutil"

	"github.com/santhosh-tekuri/jsonschema/v5"
	_ "github.com/santhosh-tekuri/jsonschema/v5/httploader"
)

const (
	// defaultSchemaURL is a placeholder that's needed to load any schema
	defaultSchemaURL = "schema.json"
	// VCJSONSchemaType https://w3c-ccg.github.io/vc-json-schemas/v2/index.html#credential_schema_definition_metadata
	VCJSONSchemaType string = "https://w3c-ccg.github.io/vc-json-schemas/schema/2.0/schema.json"
)

type VCJSONSchema struct {
	Type     string                 `json:"type"`
	Version  string                 `json:"version"`
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Author   string                 `json:"author"`
	Authored string                 `json:"authored"`
	Schema   map[string]interface{} `json:"schema"`
}

func (vs *VCJSONSchema) ToMap() map[string]interface{} {
	ret := make(map[string]interface{})
	b := vs.ToBytes()
	json.Unmarshal(b, &ret)
	return ret
}

func (vs *VCJSONSchema) FromURL(url string) error {
	buf, err := jsonschema.LoadURL(url)
	if err != nil {
		return err
	}
	defer buf.Close()
	return json.NewDecoder(buf).Decode(vs)
}

func (vs *VCJSONSchema) FromBytes(data []byte) error {
	// parse vc json schema
	if err := json.Unmarshal(data, vs); err != nil {
		return err
	}
	return vs.Validate()
}

func (vs *VCJSONSchema) ToBytes() []byte {
	b, _ := json.Marshal(vs)
	return b
}

// Validate validate VCJSONSchema itselt
func (vs *VCJSONSchema) Validate() error {
	// load schema from "https://w3c-ccg.github.io/vc-json-schemas/schema/2.0/schema.json"
	buf, err := jsonschema.LoadURL(VCJSONSchemaType)
	if err != nil {
		return err
	}
	sch, err := ioutil.ReadAll(buf)
	if err != nil {
		return err
	}

	// compile schema to json schema
	jsonSchema, err := jsonschema.CompileString(defaultSchemaURL, string(sch))
	if err != nil {
		return err
	}

	// validate our VCJSONSchema
	return jsonSchema.Validate(vs.ToMap())
}

func (vs *VCJSONSchema) ValidateSubject(subject map[string]interface{}) error {
	var sch []byte
	var err error
	sch, err = json.Marshal(vs)
	if err != nil {
		return err
	}
	jsonSchema, err := jsonschema.CompileString(defaultSchemaURL, string(sch))
	if err != nil {
		return err
	}
	return jsonSchema.Validate(subject)
}

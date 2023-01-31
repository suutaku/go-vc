package schema

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var shemaStr = `
{
  "type": "https://w3c-ccg.github.io/vc-json-schemas/schema/2.0/schema.json",
  "version": "1.0",
  "id": "did:example:MDP8AsFhHzhwUvGNuYkX7T;id=06e126d1-fa44-4882-a243-1e326fbe21db;version=1.0",
  "name": "Email",
  "author": "did:example:MDP8AsFhHzhwUvGNuYkX7T",
  "authored": "2021-01-01T00:00:00+00:00",
  "schema": {
    "$id": "email-schema-1.0",
    "$schema": "https://json-schema.org/draft/2019-09/schema",
    "description": "Email",
    "type": "object",
    "properties": {
      "emailAddress": {
        "type": "string",
        "format": "email"
      }
    },
    "required": [
      "emailAddress"
    ],
    "additionalProperties": false
  }
}
`

func TestSchemaFromBytes(t *testing.T) {
	ch := &VCJSONSchema{}
	err := ch.FromBytes([]byte(shemaStr))
	assert.NoError(t, err)
	err = ch.Validate()
	assert.NoError(t, err)
	t.Logf("%s\n", ch.ToBytes())
}

func TestSchameFromURL(t *testing.T) {
	ch := &VCJSONSchema{}
	err := ch.FromURL("https://w3c-ccg.github.io/vc-json-schemas/schema/2.0/schema.json")
	assert.NoError(t, err)
	t.Logf("%s\n", ch.ToBytes())
}

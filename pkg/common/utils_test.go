package common

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatedTime(t *testing.T) {
	var testMap map[string]interface{}
	// var zeroTime = "0001-01-01T00:00:00Z"
	b, err := json.Marshal(testMap)
	assert.NoError(t, err)
	assert.Equal(t, string(b), "null")
	var testByes1 = `
	{
		"testByes1":null
	}
	`
	err = json.Unmarshal([]byte(testByes1), &testMap)
	assert.NoError(t, err)
	t.Logf("%#v\n", testMap)
	var testByes2 = `{
		"testByes2":{}
	}`

	err = json.Unmarshal([]byte(testByes2), &testMap)
	assert.NoError(t, err)
	t.Logf("%#v\n", testMap)
	var testByes3 = `{
		"testByes3":""
	}`

	err = json.Unmarshal([]byte(testByes3), &testMap)
	assert.NoError(t, err)
	t.Logf("%#v\n", testMap)

	tm := NewFormatedTime()
	assert.NotEmpty(t, tm)
	str, err := json.Marshal(tm)
	assert.NoError(t, err)
	t.Logf("%s\n", str)
}

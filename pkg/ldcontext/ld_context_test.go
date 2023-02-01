package ldcontext

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/suutaku/go-vc/test"
)

func TestMarshalAndUnmarshalContext(t *testing.T) {
	bs, err := test.GetTestResource("json-ld-context-1.jsonld")
	assert.NoError(t, err)
	context := NewJSONLDContext()
	err = context.FromBytes(bs)
	assert.NoError(t, err)
	bs2 := context.ToString()
	t.Logf("%s\n", bs2)
}

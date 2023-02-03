package status

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/test"
)

func TestPram(t *testing.T) {
	// check lenght in bytes
	assert.Equal(t, 16*1024, miniBytesLen)
}

func TestBitstring(t *testing.T) {
	bs, err := test.GetTestResource("vc-json-doc-all.json")
	assert.NoError(t, err)
	assert.NotEmpty(t, bs)
	cred := credential.NewCredential()
	err = cred.FromBytes(bs)
	assert.NoError(t, err)

	credList := []credential.Credential{
		*cred,
	}
	bitStr := GenBitstring(credList)
	t.Logf("%s\n", bitStr.Compressed())
	assert.NoError(t, err)
	bitIdx, err := strconv.ParseInt(cred.Status["statusListIndex"].(string), 10, 64)
	assert.NoError(t, err)

	check, err := bitStr.Check(int(bitIdx))
	assert.NoError(t, err)
	assert.True(t, check)

	check2, err := bitStr.Check(int(bitIdx - 1))
	assert.NoError(t, err)
	assert.False(t, check2)
}

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
	bstr, err := GenBitstring(credList)
	assert.NoError(t, err)
	t.Logf("%s\n", bstr)
	exp, err := ExpanBistring(bstr)
	assert.NoError(t, err)
	bitIdx, err := strconv.ParseInt(cred.Status["statusListIndex"].(string), 10, 64)
	assert.NoError(t, err)

	checkIdx := 0
	for k, v := range exp {
		if v > 0 {
			checkIdx = k * 8
			for v != 0 {
				v = v << 1
				checkIdx++
			}
		}
	}
	assert.Equal(t, int(bitIdx), int(checkIdx))
	t.Logf("check index %d\n", checkIdx)

}

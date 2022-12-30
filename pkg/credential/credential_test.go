package credential

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/suutaku/go-vc/pkg/testdata"
)

func TestCredential(t *testing.T) {

	cred := NewCredential()
	err := cred.FromBytes([]byte(testdata.VCDoc))
	assert.NoError(t, err)
	t.Logf("zero value: %s\n", cred.ToString())
}

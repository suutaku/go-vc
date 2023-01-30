package processor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/pkg/testdata"
)

func TestBuilder(t *testing.T) {
	proc := Default()
	cred := credential.NewCredential()
	err := cred.FromBytes([]byte(testdata.VCDoc))
	assert.NoError(t, err)
	result, err := proc.GetCanonicalDocument(cred.ToMap())
	assert.NoError(t, err)
	assert.NotNil(t, result)
	t.Logf("%s\n", result)
}

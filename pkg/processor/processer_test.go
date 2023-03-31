package processor

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/suutaku/go-vc/test"
)

func TestProcessor(t *testing.T) {
	inputStr, err := test.GetTestResource("processor_input_doc.json")
	require.NoError(t, err)
	inputDoc := make(map[string]interface{})
	err = json.Unmarshal(inputStr, &inputDoc)
	require.NoError(t, err)
	frameStr, err := test.GetTestResource("processor_frame_doc.json")
	require.NoError(t, err)
	frameDoc := make(map[string]interface{})
	err = json.Unmarshal(frameStr, &frameDoc)
	require.NoError(t, err)

	result, err := Default().Frame(inputDoc, frameDoc, WithValidateRDF(), WithFrameBlankNodes())
	require.NoError(t, err)
	resStr, err := json.Marshal(result)
	require.NoError(t, err)
	t.Logf("%s\n", resStr)
}

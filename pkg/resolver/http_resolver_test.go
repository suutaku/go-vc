package resolver

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/suutaku/go-vc/test"
)

func TestHTTPResolver(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val, err := test.GetTestResource("holder-did.json")
		if err != nil {
			fmt.Println("cannot resolve id")
		}
		w.Write(val)
	}))
	defer ts.Close()
	resolver := NewHTTPResolver(ts.URL)
	pub, err := resolver.Resolve("did:cot:Bh5yujxVkMotaDEBSBWAZu6KXcezGKvamHvmCLsYY9DP")
	assert.NoError(t, err)
	assert.NotNil(t, pub)
	t.Logf("%v\n", pub)

}

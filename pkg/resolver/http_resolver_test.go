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
		val, err := test.GetTestResource(r.RequestURI)
		if err != nil {
			fmt.Println("cannot resolve id")
		}
		w.Write(val)
	}))
	defer ts.Close()
	resolver := NewHTTPResolver()
	pub := resolver.Resolve(ts.URL + "/holder-did.json")
	assert.NotNil(t, pub)
	t.Logf("%v\n", pub)

}

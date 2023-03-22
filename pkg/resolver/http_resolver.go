package resolver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/ComputingOfThings/dids/pkg/dids"
	"github.com/btcsuite/btcutil/base58"
)

const (
	ldKeyType = "JsonWebKey2020"
	typeG1    = "Bls12381G1Key2020"
	typeG2    = "Bls12381G2Key2020"
)

type HTTPResolver struct {
	base string
}

func NewHTTPResolver(url string) *HTTPResolver {
	return &HTTPResolver{
		base: url,
	}
}

func (res *HTTPResolver) Resolve(id string) (*PublicKey, error) {
	sp := strings.Split(id, "#")
	url, err := url.Parse(res.base)
	if err != nil {
		return nil, err
	}
	url.Path = path.Join(url.Path, "did", sp[0])
	resp, err := http.Get(url.String())
	if err != nil || resp.StatusCode != 200 {
		msg, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("%v %s", err, msg)
	}
	did := &dids.DIDDocument{}
	err = json.NewDecoder(resp.Body).Decode(did)
	if err != nil || len(did.VerificationMethod) == 0 {
		return nil, err
	}
	ret := &PublicKey{Type: did.VerificationMethod[0].Type}

	for _, v := range did.VerificationMethod {
		if v.ID != id {
			continue
		}
		switch ret.Type {
		case ldKeyType:
			if v.PublicKeyJWK.Crv != "BLS12381_G2" || v.PublicKeyJWK.Kty != "EC" {
				return nil, fmt.Errorf("invalid jwk")
			}
			ret.Jwk, err = base64.URLEncoding.DecodeString(v.PublicKeyJWK.X)
			if err != nil {
				return nil, err
			}
		case typeG2:
			ret.Value = base58.Decode(v.PublicKeyBase58)
			if ret.Value == nil {
				return nil, err
			}
		case typeG1:
			return nil, err
		}
	}

	return ret, nil
}

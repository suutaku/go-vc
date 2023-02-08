package resolver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"gitee.com/cotnetwork/dids/pkg/dids"
	"github.com/btcsuite/btcutil/base58"
)

const (
	ldKeyType = "JsonWebKey2020"
	typeG1    = "Bls12381G1Key2020"
	typeG2    = "Bls12381G2Key2020"
)

type HTTPResolver struct {
}

func NewHTTPResolver() *HTTPResolver {
	return &HTTPResolver{}
}

func (res *HTTPResolver) Resolve(url string) (*PublicKey, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	did := &dids.DIDDocument{}
	err = json.NewDecoder(resp.Body).Decode(did)
	if err != nil || len(did.VerificationMethod) == 0 {
		return nil, err
	}
	ret := &PublicKey{Type: did.VerificationMethod[0].Type}

	switch ret.Type {
	case ldKeyType:
		if did.VerificationMethod[0].PublicKeyJWK.Crv != "BLS12381_G2" || did.VerificationMethod[0].PublicKeyJWK.Kty != "EC" {
			return nil, fmt.Errorf("invalid jwk")
		}
		ret.Jwk, err = base64.URLEncoding.DecodeString(did.VerificationMethod[0].PublicKeyJWK.X)
		if err != nil {
			return nil, err
		}
	case typeG2:
		ret.Value = base58.Decode(did.VerificationMethod[0].PublicKeyBase58)
		if ret.Value == nil {
			return nil, err
		}
	case typeG1:
		return nil, err
	}
	return ret, nil
}

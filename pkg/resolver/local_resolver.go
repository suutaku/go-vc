package resolver

import (
	"encoding/base64"
	"fmt"

	"github.com/ComputingOfThings/dids/pkg/dids"
	"github.com/btcsuite/btcutil/base58"
)

type LocalResolver struct {
	didDoc *dids.DIDDocument
}

func NewLocalResolver(didDoc *dids.DIDDocument) *LocalResolver {
	return &LocalResolver{
		didDoc: didDoc,
	}
}

func (res *LocalResolver) Resolve(url string) (*PublicKey, error) {

	ret := &PublicKey{Type: res.didDoc.VerificationMethod[0].Type}
	var err error
	switch ret.Type {
	case ldKeyType:
		if res.didDoc.VerificationMethod[0].PublicKeyJWK.Crv != "BLS12381_G2" || res.didDoc.VerificationMethod[0].PublicKeyJWK.Kty != "EC" {
			return nil, fmt.Errorf("invalid jwk")
		}
		ret.Jwk, err = base64.URLEncoding.DecodeString(res.didDoc.VerificationMethod[0].PublicKeyJWK.X)
		if err != nil {
			return nil, err
		}
	case typeG2:
		ret.Value = base58.Decode(res.didDoc.VerificationMethod[0].PublicKeyBase58)
		if ret.Value == nil {
			return nil, err
		}
	case typeG1:
		return nil, err
	}
	return ret, nil
}

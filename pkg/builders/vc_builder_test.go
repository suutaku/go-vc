package builders

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/suutaku/go-bbs/pkg/bbs"
	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/pkg/processor"
	"github.com/suutaku/go-vc/pkg/resolver"
	"github.com/suutaku/go-vc/test"
)

const (
	credentialDocPath              string = "vc-json-doc-all.json"
	credentialSignedDocPath        string = "vc-json-doc-all-signed.json"
	credentialRevealedDocPath      string = "vc-json-doc-revealed.json"
	credentialBlindRevealedDocPath string = "vc-json-doc-blind.json"
	credentialCustomDocPath        string = "vc-json-doc-custom.jsonld"
	issuerKeyPath                  string = "issuer-private-key.txt"
	holderKeyPath                  string = "holder-private-key.txt"
)

func genIssuerBuilderAndPublicKeyResolver(t *testing.T) (*VCBuilder, resolver.PublicKeyResolver) {
	iKeyStr, err := test.GetTestResource(issuerKeyPath)
	assert.NoError(t, err, "cannot get test resource")
	iKeyBytes, err := hex.DecodeString(string(iKeyStr))
	assert.NoError(t, err, "private key decode failed")
	iPriv, err := bbs.UnmarshalPrivateKey(iKeyBytes)
	assert.NoError(t, err, "private key unmarshal failed")
	pub := iPriv.PublicKey()
	pubBytes, err := pub.Marshal()
	assert.NoError(t, err, "marshal public key failed")
	pubResv := resolver.NewTestPublicKeyResolver(&resolver.PublicKey{
		Type:  "Bls12381G2Key2020",
		Value: pubBytes,
	}, nil)
	builder := NewVCBuilder(WithPrivateKey(iPriv), WithDID("did:cot:6u3SCqoKfARwgbssjie1agpsoPitjKwkeFZxtJGb5BqY"), WithProcessorOptions(processor.WithValidateRDF()))
	return builder, pubResv
}

func genHolderBuilderAndPublicKeyResolver(t *testing.T) (*VCBuilder, resolver.PublicKeyResolver) {
	hKeyStr, err := test.GetTestResource(holderKeyPath)
	assert.NoError(t, err, "cannot get test resource")
	hKeyBytes, err := hex.DecodeString(string(hKeyStr))
	assert.NoError(t, err, "private key decode failed")
	hPriv, err := bbs.UnmarshalPrivateKey(hKeyBytes)
	assert.NoError(t, err, "private key unmarshal failed")
	pub := hPriv.PublicKey()
	pubBytes, err := pub.Marshal()
	assert.NoError(t, err, "marshal public key failed")
	pubResv := resolver.NewTestPublicKeyResolver(&resolver.PublicKey{
		Type:  "Bls12381G2Key2020",
		Value: pubBytes,
	}, nil)
	builder := NewVCBuilder(WithPrivateKey(hPriv), WithProcessorOptions(processor.WithValidateRDF()))
	return builder, pubResv
}

func getTestCredential(t *testing.T) *credential.Credential {
	credBytes, err := test.GetTestResource(credentialDocPath)
	assert.NoError(t, err, "cannot get test credential doc")
	cred := credential.NewCredential()
	err = cred.FromBytes(credBytes)
	assert.NoError(t, err, "invalid test credential")
	return cred
}

func getTestCredentialWithName(t *testing.T, name string) *credential.Credential {
	credBytes, err := test.GetTestResource(name)
	assert.NoError(t, err, "cannot get test credential doc")
	cred := credential.NewCredential()
	err = cred.FromBytes(credBytes)
	assert.NoError(t, err, "invalid test credential")
	return cred
}

func getTestRevealedCredential(t *testing.T) *credential.Credential {
	credBytes, err := test.GetTestResource(credentialRevealedDocPath)
	assert.NoError(t, err, "cannot get test revealed credential doc")
	cred := credential.NewCredential()
	err = cred.FromBytes(credBytes)
	assert.NoError(t, err, "invalid test revealed credential")
	return cred
}

func getTestBlindRevealedCredential(t *testing.T) *credential.Credential {
	credBytes, err := test.GetTestResource(credentialBlindRevealedDocPath)
	assert.NoError(t, err, "cannot get test revealed credential doc")
	cred := credential.NewCredential()
	err = cred.FromBytes(credBytes)
	assert.NoError(t, err, "invalid test revealed credential")
	return cred
}

func TestLinkedDataProof(t *testing.T) {
	iBuilder, iResolver := genIssuerBuilderAndPublicKeyResolver(t)
	assert.NotNil(t, iBuilder, "cannot create issuer builder")
	assert.NotNil(t, iResolver, "cannot create issuer public key resolver")
	hBuilder, hResolver := genHolderBuilderAndPublicKeyResolver(t)
	assert.NotNil(t, hBuilder, "cannot create holder builder")
	assert.NotNil(t, hResolver, "cannot create holder public key resolver")

	cred := getTestCredentialWithName(t, credentialCustomDocPath)
	assert.NotNil(t, cred, "cannot get credential")

	signedCred, err := iBuilder.AddLinkedDataProof(cred)
	assert.NoError(t, err, "issuer cannot sign credential")
	t.Logf("signed credential:\n%s\n", signedCred.ToString())

	err = hBuilder.Verify(signedCred, iResolver)
	assert.NoError(t, err, "invalid signature")

}

func TestSelectiveDisclosure(t *testing.T) {
	iBuilder, iResolver := genIssuerBuilderAndPublicKeyResolver(t)
	assert.NotNil(t, iBuilder, "cannot create issuer builder")
	assert.NotNil(t, iResolver, "cannot create issuer public key resolver")
	hBuilder, hResolver := genHolderBuilderAndPublicKeyResolver(t)
	assert.NotNil(t, hBuilder, "cannot create holder builder")
	assert.NotNil(t, hResolver, "cannot create holder public key resolver")

	cred := getTestCredential(t)
	assert.NotNil(t, cred, "cannot get credential")

	signed, err := iBuilder.AddLinkedDataProof(cred)
	assert.NoError(t, err, "issuer cannot sign credential")
	t.Logf("signed credential:\n%s\n", signed.ToString())

	err = hBuilder.Verify(signed, iResolver)
	assert.NoError(t, err, "invalid signature")

	revealed := getTestRevealedCredential(t)
	assert.NotNil(t, revealed, "cannot get revealed credential")

	disclosure, err := hBuilder.GenerateBBSSelectiveDisclosure(signed, revealed, iResolver, []byte("nonce"))
	assert.NoError(t, err, "cannot generate selective disclosure")
	t.Logf("generated selective disclosure credential:\n%s\n", disclosure.ToString())

	err = hBuilder.Verify(disclosure, iResolver)
	assert.NoError(t, err, "invalid signature")
}

func TestBlindSign(t *testing.T) {
	iBuilder, iResolver := genIssuerBuilderAndPublicKeyResolver(t)
	assert.NotNil(t, iBuilder, "cannot create issuer builder")
	assert.NotNil(t, iResolver, "cannot create issuer public key resolver")
	hBuilder, hResolver := genHolderBuilderAndPublicKeyResolver(t)
	assert.NotNil(t, hBuilder, "cannot create holder builder")
	assert.NotNil(t, hResolver, "cannot create holder public key resolver")

	cred := getTestCredential(t)
	assert.NotNil(t, cred, "cannot get credential")

	brevealed := getTestBlindRevealedCredential(t)
	assert.NotNil(t, brevealed, "cannot get revealed credential")

	ctx, idx, count, err := hBuilder.PreBlindSign(cred, brevealed, iResolver, []byte("nonce"))
	assert.NoError(t, err)
	assert.NotNil(t, ctx, "cannot get blind signature context")

	blindSignature, err := iBuilder.BlindSign(brevealed, ctx, idx, count, []byte("nonce"))
	assert.NoError(t, err)
	assert.NotNil(t, blindSignature, "cannot get  signature context")

	err = hBuilder.CompleteSignature(cred, blindSignature)
	assert.NoError(t, err)

	err = hBuilder.Verify(cred, iResolver)
	assert.NoError(t, err, "invalid signature")
	t.Logf("signed credential:\n%s\n", cred.ToString())
	revealed := getTestRevealedCredential(t)
	assert.NotNil(t, revealed, "cannot get revealed credential")
	disclosure, err := hBuilder.GenerateBBSSelectiveDisclosure(cred, revealed, iResolver, []byte("nonce"))
	assert.NoError(t, err, "cannot generate selective disclosure")
	t.Logf("generated selective disclosure credential:\n%s\n", disclosure.ToString())

	err = hBuilder.Verify(disclosure, iResolver)
	assert.NoError(t, err, "invalid signature")
}

func TestStatusCredential(t *testing.T) {
	iBuilder, iResolver := genIssuerBuilderAndPublicKeyResolver(t)
	assert.NotNil(t, iBuilder, "cannot create issuer builder")
	assert.NotNil(t, iResolver, "cannot create issuer public key resolver")

	cred := getTestCredential(t)
	assert.NotNil(t, cred, "cannot get credential")

	sigend, err := iBuilder.AddLinkedDataProof(cred)
	assert.NoError(t, err)
	statusCred, err := iBuilder.GenStatusCredentialList("http://ssis.cotnetwork.com/status/3", []credential.Credential{*sigend})
	assert.NoError(t, err)
	assert.NotEmpty(t, statusCred)
	err = iBuilder.Verify(statusCred, iResolver)
	assert.NoError(t, err)
	t.Logf("%s\n", statusCred.ToString())
	pass, err := iBuilder.ValidateStatusCredential(statusCred, sigend, iResolver)
	assert.NoError(t, err)
	assert.True(t, pass)
	err = iBuilder.Verify(statusCred, iResolver)
	assert.NoError(t, err)
}

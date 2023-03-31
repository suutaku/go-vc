package builders

import (
	"fmt"
	"strconv"

	"github.com/suutaku/go-bbs/pkg/bbs"
	"github.com/suutaku/go-vc/pkg/common"
	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/pkg/proof"
	"github.com/suutaku/go-vc/pkg/resolver"
	"github.com/suutaku/go-vc/pkg/status"
	"github.com/suutaku/go-vc/pkg/suite"
	"github.com/suutaku/go-vc/pkg/suite/bbsblssignature2020"
	"github.com/suutaku/go-vc/pkg/suite/bbsblssignatureproof2020"
)

type VCBuilder struct {
	options *builderOption
}

func NewVCBuilder(opts ...BuilderOption) *VCBuilder {

	options := prepareOpts(opts)

	// if no suites parsed, create suites with verify function only
	if options.signatureSuites == nil {
		options.signatureSuites = make(map[string]suite.SignatureSuite)
		bbss := bbsblssignature2020.NewSignatureSuite(nil, false)
		options.signatureSuites[bbss.Alg()] = bbss
		bbsps := bbsblssignatureproof2020.NewSignatureSuite(nil, false)
		options.signatureSuites[bbsps.Alg()] = bbsps
	}
	// if no linked data proof context parsed, create default context
	if options.ldpCtx == nil {
		created := new(common.FormatedTime)
		created.UnmarshalJSON([]byte("2019-12-03T12:19:52Z"))
		options.ldpCtx = &proof.LinkedDataProofContext{
			SignatureType:           "BbsBlsSignature2020",
			SignatureRepresentation: proof.SignatureProofValue,
			VerificationMethod:      options.did + "#owner",
			Created:                 created,
		}
	}
	return &VCBuilder{
		options: options,
	}
}

func (vcb *VCBuilder) AddLinkedDataProof(cred *credential.Credential, opts ...BuilderOption) (*credential.Credential, error) {
	// reset options if need
	vcb.options.Merge(opts)
	s := vcb.options.signatureSuites[vcb.options.ldpCtx.SignatureType]
	err := cred.AddLinkedDataProof(s, vcb.options.ldpCtx, vcb.options.processorOpts...)
	return cred, err
}

func (vcb *VCBuilder) GenerateBBSSelectiveDisclosure(cred, revealed *credential.Credential, pubResolver resolver.PublicKeyResolver, nonce []byte, opts ...BuilderOption) (*credential.Credential, error) {
	vcb.options.Merge(opts)
	s := vcb.options.signatureSuites["BbsBlsSignatureproof2020"]
	return cred.GenerateBBSSelectiveDisclosure(s, revealed, pubResolver, nonce, vcb.options.processorOpts...)
}

func (vcb *VCBuilder) PreBlindSign(cred, revealed *credential.Credential, issuerPubResolver resolver.PublicKeyResolver, nonce []byte, opts ...BuilderOption) (*bbs.BlindSignatureContext, []int, int, error) {
	vcb.options.Merge(opts)
	s := vcb.options.signatureSuites["BbsBlsSignature2020"]
	return cred.PreBlindSign(s, revealed, vcb.options.ldpCtx, issuerPubResolver, nonce, vcb.options.processorOpts...)
}

func (vcb *VCBuilder) BlindSign(revealed *credential.Credential, ctx *bbs.BlindSignatureContext, revealedIndexs []int, msgCount int, nonce []byte, opts ...BuilderOption) (*bbs.BlindSignature, error) {
	vcb.options.Merge(opts)
	s := vcb.options.signatureSuites["BbsBlsSignature2020"]
	return revealed.BlindSign(s, ctx, revealedIndexs, msgCount, vcb.options.ldpCtx, nonce, vcb.options.processorOpts...)
}

func (vcb *VCBuilder) CompleteSignature(cred *credential.Credential, blindSig *bbs.BlindSignature, opts ...BuilderOption) error {
	vcb.options.Merge(opts)
	s := vcb.options.signatureSuites["BbsBlsSignature2020"]
	return cred.CompleteSignature(s, vcb.options.ldpCtx, blindSig)
}

func (vcb *VCBuilder) Verify(cred *credential.Credential, issuerPubResolver resolver.PublicKeyResolver, opts ...BuilderOption) error {
	vcb.options.Merge(opts)
	return cred.VerifyProof(vcb.options.signatureSuites, issuerPubResolver, vcb.options.processorOpts...)
}

// GenStatusCredential
// https://w3c.github.io/vc-status-list-2021/#generate-algorithm
//
// 1) Let issued credentials be a list of all issued verifiable credentials.
// 2) Let RLC be an unsigned StatusList2021Credential without the encodedList property set.
// 3) Generate a compressed bitstring by passing issued credentials to the Bitstring Generation Algorithm.
// 4) Set the encodedList to compressed bitstring.
// 5) Generate a proof for the RLC and publish it to the endpoint listed in the verifiable credential.
func (vcb *VCBuilder) GenStatusCredentialList(id string, issuedCred []credential.Credential) (*credential.Credential, error) {
	preBuildCred := &credential.Credential{
		Context: []string{
			common.DefaultVCJsonLDContext,
			common.DefaultBbsJsonLDContext,
			common.DefaultStatusVCJsonLDContext,
		},
		Id: id,
		Type: []string{
			common.DefaultVCJsonLDContextTypeVC,
			common.DefaultVCJsonLDContextTypeSC,
		},
		Issuer: vcb.options.did,
		Subject: map[string]interface{}{
			"type":          status.StatusList2021,
			"statusPurpose": status.StatusPurposeRevocation,
		},
	}
	statCred, err := status.GenStatusCredential(issuedCred, preBuildCred)
	if err != nil {
		return nil, err
	}
	return vcb.AddLinkedDataProof(statCred)
}

// ValidateStatusCredential
// 1) Let credentialToValidate be a verifiable credentials containing a credentialStatus entry that is a
// StatusList2021Entry.
// 2) Let status purpose be the value of statusPurpose in the credentialStatus entry in the
// credentialToValidate.
// 3) Verify all proofs associated with the credentialToValidate. If a proof fails, return a validation error.
// 4) Verify that the status purpose matches the statusPurpose value in the statusListCredential.
// 5) Let compressed bitstring be the value of the encodedList property of the StatusList2021Credential.
// 6) Let credentialIndex be the value of the statusListIndex property of the StatusList2021Entry.
// 7) Generate a revocation bitstring by passing compressed bitstring to the Bitstring Expansion Algorithm.
// 8) Let status be the value of the bit at position credentialIndex in the revocation bitstring.
// 9) Return true if status is 1, false otherwise.
func (vcb *VCBuilder) ValidateStatusCredential(statusList, credToValid *credential.Credential, issuerKeyResolver resolver.PublicKeyResolver) (bool, error) {
	err := vcb.Verify(credToValid, issuerKeyResolver)
	if err != nil {
		return false, err
	}
	// resp, err := http.Get(credToValid.Status["id"].(string))
	// if err != nil {
	// 	return false, fmt.Errorf("cannot resolve status entry id: %w", err)
	// }
	// list := make(map[string]interface{})
	// json.NewDecoder(resp.Body).Decode(&list)
	credSubject, ok := statusList.Subject.(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("status credential don't have credentialSubject item")
	}

	if credToValid.Status["statusPurpose"].(string) != credSubject["statusPurpose"].(string) {
		return false, fmt.Errorf("status purpose not matched, list %s, entry %s", credSubject["statusPurpose"].(string), credToValid.Status["statusPurpose"].(string))
	}
	idx, err := strconv.ParseInt(credToValid.Status["statusListIndex"].(string), 10, 64)
	if err != nil {
		return false, fmt.Errorf("invlaid status list index %s", credToValid.Status["statusListIndex"].(string))
	}

	encodedList, ok := credSubject["encodedList"].(string)
	if !ok {
		return false, fmt.Errorf("status credential don't have encodedList item")
	}
	bitStr := status.ParseBitString(encodedList)
	return bitStr.Check(int(idx))
}

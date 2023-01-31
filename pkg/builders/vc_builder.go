package builders

import (
	"github.com/suutaku/go-bbs/pkg/bbs"
	"github.com/suutaku/go-vc/pkg/common"
	"github.com/suutaku/go-vc/pkg/credential"
	"github.com/suutaku/go-vc/pkg/proof"
	"github.com/suutaku/go-vc/pkg/resolver"
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
			VerificationMethod:      "did:example:123456#key1",
			Created:                 created,
		}
	}
	return &VCBuilder{
		options: options,
	}
}

func (vcb *VCBuilder) AddLinkedDataProof(cred *credential.Credential) (*credential.Credential, error) {
	s := vcb.options.signatureSuites[vcb.options.ldpCtx.SignatureType]
	err := cred.AddLinkedDataProof(s, vcb.options.ldpCtx, vcb.options.processorOpts...)
	return cred, err
}

func (vcb *VCBuilder) GenerateBBSSelectiveDisclosure(cred, revealed *credential.Credential, pubResolver resolver.PublicKeyResolver, nonce []byte) (*credential.Credential, error) {
	s := vcb.options.signatureSuites["BbsBlsSignatureproof2020"]
	return cred.GenerateBBSSelectiveDisclosure(s, revealed, pubResolver, nonce, vcb.options.processorOpts...)
}

func (vcb *VCBuilder) PreBlindSign(cred, revealed *credential.Credential, issuerPubResolver resolver.PublicKeyResolver, nonce []byte) (*bbs.BlindSignatureContext, []int, int, error) {
	s := vcb.options.signatureSuites["BbsBlsSignature2020"]
	return cred.PreBlindSign(s, revealed, vcb.options.ldpCtx, issuerPubResolver, nonce, vcb.options.processorOpts...)
}

func (vcb *VCBuilder) BlindSign(revealed *credential.Credential, ctx *bbs.BlindSignatureContext, revealedIndexs []int, msgCount int, nonce []byte) (*bbs.BlindSignature, error) {
	s := vcb.options.signatureSuites["BbsBlsSignature2020"]
	return revealed.BlindSign(s, ctx, revealedIndexs, msgCount, vcb.options.ldpCtx, nonce, vcb.options.processorOpts...)
}

func (vcb *VCBuilder) CompleteSignature(cred *credential.Credential, blindSig *bbs.BlindSignature) error {
	s := vcb.options.signatureSuites["BbsBlsSignature2020"]
	return cred.CompleteSignature(s, vcb.options.ldpCtx, blindSig)
}

func (vcb *VCBuilder) Verify(cred *credential.Credential, issuerPubResolver resolver.PublicKeyResolver) error {
	return cred.VerifyProof(vcb.options.signatureSuites, issuerPubResolver, vcb.options.processorOpts...)
}

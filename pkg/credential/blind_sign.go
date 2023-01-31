package credential

import (
	"fmt"
	"sort"

	"github.com/suutaku/go-bbs/pkg/bbs"
	"github.com/suutaku/go-vc/internal/processor"
	"github.com/suutaku/go-vc/internal/tools"
	"github.com/suutaku/go-vc/pkg/proof"
	"github.com/suutaku/go-vc/pkg/resolver"
	"github.com/suutaku/go-vc/pkg/suite"
	"github.com/suutaku/go-vc/pkg/suite/bbsblssignature2020"
)

// The PreBlindSign algorithm allows a holder of a signature
// to blind messages that when signed, are unknown to the signer.
// The algorithm returns a generated blinding factor that is
// used to un-blind the signature from the signer, and a pedersen
// commitment from a vector of messages and the domain parameters h and h0.
// https://identity.foundation/bbs-signature/draft-blind-bbs-signatures.html#section-5.1
func (cred *Credential) PreBlindSign(s suite.SignatureSuite, revealDoc *Credential, ldCtx *proof.LinkedDataProofContext, issuerPubResolver resolver.PublicKeyResolver, nonceBytes []byte, opts ...processor.ProcessorOpts) (*bbs.BlindSignatureContext, []int, int, error) {
	context := ldCtx.ToContext()
	// validation of context
	if err := context.Validate(); err != nil {
		return nil, nil, 0, err
	}
	// construct proof
	p := &proof.Proof{
		Type:                    context.SignatureType,
		SignatureRepresentation: context.SignatureRepresentation,
		Creator:                 context.Creator,
		Created:                 context.Created,
		Domain:                  context.Domain,
		Nonce:                   context.Nonce,
		VerificationMethod:      context.VerificationMethod,
		Challenge:               context.Challenge,
		ProofPurpose:            context.Purpose,
		CapabilityChain:         context.CapabilityChain,
	}
	if p.ProofPurpose == "" {
		p.ProofPurpose = defaultProofPurpose
	}
	if context.SignatureRepresentation == proof.SignatureJWS {
		p.JWS = proof.NewJwt().NewHeader(s.Alg() + "..")
	}

	docMsg, err := CreateVerifyData(s, cred.ToMap(), p, opts...)
	if err != nil {
		return nil, nil, 0, err
	}
	recealMsg, err := CreateVerifyData(s, revealDoc.ToMap(), p, opts...)
	if err != nil {
		return nil, nil, 0, err
	}

	pid, err := p.PublicKeyId()
	if err != nil {
		return nil, nil, 0, err
	}
	pbk := issuerPubResolver.Resolve(pid)
	if pbk == nil {
		return nil, nil, 0, fmt.Errorf("cannot resolve public key")
	}
	pubKeyValue := pbk.Value
	if p.SignatureRepresentation == proof.SignatureJWS {
		pubKeyValue = pbk.Jwk
	}

	ctx, revlIdx, msgCout, err := s.(*bbsblssignature2020.SignatureSuite).Blinder.CreateContext(docMsg, recealMsg, pubKeyValue, nonceBytes)
	return ctx, revlIdx, msgCout, err

}

func (cred *Credential) BlindSign(s suite.SignatureSuite, blindCtx *bbs.BlindSignatureContext, revealedIndexs []int, msgCount int, ldpCtx *proof.LinkedDataProofContext, nonce []byte, opts ...processor.ProcessorOpts) (*bbs.BlindSignature, error) {
	context := ldpCtx.ToContext()
	// validation of context
	if err := context.Validate(); err != nil {
		return nil, err
	}
	if blindCtx == nil {
		return nil, fmt.Errorf("invalid blind signature context")
	}
	// construct proof
	p := &proof.Proof{
		Type:                    context.SignatureType,
		SignatureRepresentation: context.SignatureRepresentation,
		Creator:                 context.Creator,
		Created:                 context.Created,
		Domain:                  context.Domain,
		Nonce:                   context.Nonce,
		VerificationMethod:      context.VerificationMethod,
		Challenge:               context.Challenge,
		ProofPurpose:            context.Purpose,
		CapabilityChain:         context.CapabilityChain,
	}
	if p.ProofPurpose == "" {
		p.ProofPurpose = defaultProofPurpose
	}
	if context.SignatureRepresentation == proof.SignatureJWS {
		p.JWS = proof.NewJwt().NewHeader(s.Alg() + "..")
	}

	revealedVerifyMsgs, err := CreateVerifyData(s, cred.ToMap(), p, opts...)
	if err != nil {
		return nil, err
	}

	revealedMegsMap, err := getRevealedStatement(revealedVerifyMsgs, revealedIndexs)
	if err != nil {
		return nil, err
	}

	return s.(*bbsblssignature2020.SignatureSuite).Blinder.BlindSign(blindCtx, revealedMegsMap, msgCount, nonce)
}

func (cred *Credential) CompleteSignature(s suite.SignatureSuite, lcon *proof.LinkedDataProofContext, blindSig *bbs.BlindSignature) error {

	context := lcon.ToContext()
	// validation of context
	if err := context.Validate(); err != nil {
		return err
	}
	// construct proof
	p := &proof.Proof{
		Type:                    context.SignatureType,
		SignatureRepresentation: context.SignatureRepresentation,
		Creator:                 context.Creator,
		Created:                 context.Created,
		Domain:                  context.Domain,
		Nonce:                   context.Nonce,
		VerificationMethod:      context.VerificationMethod,
		Challenge:               context.Challenge,
		ProofPurpose:            context.Purpose,
		CapabilityChain:         context.CapabilityChain,
	}
	if p.ProofPurpose == "" {
		p.ProofPurpose = defaultProofPurpose
	}

	if context.SignatureRepresentation == proof.SignatureJWS {
		p.JWS = proof.NewJwt().NewHeader(s.Alg() + "..")
	}

	signature, err := s.(*bbsblssignature2020.SignatureSuite).Blinder.CompleteSignature(blindSig)
	if err != nil {
		return err
	}
	sigBytes, err := signature.ToBytes()
	if err != nil {
		return err
	}
	p.ApplySignatureValue(context, sigBytes)
	return cred.AddProof(p)
}

func getRevealedStatement(verifyMsgs []byte, revealedIdxs []int, opts ...processor.ProcessorOpts) (map[int][]byte, error) {
	// create verify document data
	revealeddocumentStatements := tools.SplitMessageIntoLinesStr(string(verifyMsgs), true)
	if len(revealeddocumentStatements) != len(revealedIdxs) {
		return nil, fmt.Errorf("revealed message length not equal revealed indexs")
	}
	transformedReveledDocStatements := make(map[int][]byte, 0)
	sort.Ints(revealedIdxs)
	for i := 0; i < len(revealedIdxs); i++ {
		transformedReveledDocStatements[revealedIdxs[i]] = []byte(revealeddocumentStatements[i])
	}
	return transformedReveledDocStatements, nil
}

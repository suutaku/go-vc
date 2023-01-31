package bbsblssignature2020

import (
	"fmt"

	"github.com/suutaku/go-bbs/pkg/bbs"
	"github.com/suutaku/go-vc/internal/tools"
)

type Blinder struct {
	privateKey   *bbs.PrivateKey
	revealedIdxs []int
	msgCount     int
	blindFactor  *bbs.SignatureBliding
}

func NewBlinder(pk *bbs.PrivateKey) *Blinder {
	return &Blinder{
		privateKey: pk,
	}
}
func (bld *Blinder) CreateNonce() *bbs.ProofNonce {
	return bbs.NewProofNonce()
}

// RevealedIndexs get revealed index which create after create blind sign context
func (bld *Blinder) RevealedIndexs() []int {
	return bld.revealedIdxs
}

// MessageCount get messages count which create after create blind sign context
func (bld *Blinder) MessageCount() int {
	return bld.msgCount
}

func (bld *Blinder) CreateContext(allMsgs, revealedMsgs, pubBytes, nonceBytes []byte) (*bbs.BlindSignatureContext, []int, int, error) {
	secret, revealedIdxs, msgCount, err := computeSecretMessages(allMsgs, revealedMsgs)
	if err != nil {
		return nil, nil, 0, err
	}
	issuerPub, err := bbs.UnmarshalPublicKey(pubBytes)
	if err != nil {
		return nil, nil, 0, err
	}
	generator, err := issuerPub.ToPublicKeyWithGenerators(msgCount)
	if err != nil {
		return nil, nil, 0, err
	}
	nonce := bbs.ParseProofNonce(nonceBytes)
	bld.msgCount = msgCount
	bld.revealedIdxs = revealedIdxs
	ctx, factor, err := bbs.NewBlindSignatureContext(secret, generator, nonce)
	bld.blindFactor = factor
	return ctx, revealedIdxs, msgCount, err
}

func computeSecretMessages(allMsgs, revealMsgs []byte) (map[int][]byte, []int, int, error) {
	allMsgLines := tools.SplitMessageIntoLines(string(allMsgs), true)
	revealtMsgLines := tools.SplitMessageIntoLines(string(revealMsgs), true)

	if len(allMsgLines) == 0 || len(revealMsgs) == 0 {
		return nil, nil, 0, fmt.Errorf("invalid input")
	}
	revealInversed := make(map[string]bool)
	for _, v := range revealtMsgLines {
		revealInversed[string(v)] = true
	}
	secMsgs := make(map[int][]byte)
	revealIdxs := make([]int, 0)
	for k, v := range allMsgLines {
		if revealInversed[string(v)] {
			revealIdxs = append(revealIdxs, k)
		} else {
			secMsgs[k] = v
		}
	}
	return secMsgs, revealIdxs, len(allMsgLines), nil
}

func (bld *Blinder) BlindSign(ctx *bbs.BlindSignatureContext, msgs map[int][]byte, msgCount int, nonceBytes []byte) (*bbs.BlindSignature, error) {
	generator, err := bld.privateKey.PublicKey().ToPublicKeyWithGenerators(msgCount)
	if err != nil {
		return nil, err
	}
	proofNonce := bbs.ParseProofNonce(nonceBytes)
	return ctx.ToBlindSignature(msgs, bld.privateKey, generator, proofNonce)
}

func (bld *Blinder) CompleteSignature(blidSig *bbs.BlindSignature) (*bbs.Signature, error) {
	if bld.blindFactor == nil {
		return nil, fmt.Errorf("cannot get blinding factor, mabey not executed CreateContext")
	}
	sig := blidSig.ToUnblinded(bld.blindFactor)
	var err error
	if sig == nil {
		err = fmt.Errorf("cannot complete signature")
	}
	return sig, err
}

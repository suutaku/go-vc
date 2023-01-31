package bbsblssignature2020

import (
	"github.com/suutaku/go-bbs/pkg/bbs"
	"github.com/suutaku/go-vc/internal/tools"
)

type Verifier struct {
	algo *bbs.Bbs
}

func NewVerifier() *Verifier {
	return &Verifier{
		algo: bbs.NewBbs(),
	}
}

func (verifier *Verifier) Verify(pubKeyBytes, doc, signature, nonce []byte) error {
	return verifier.algo.Verify(tools.SplitMessageIntoLines(string(doc), true), signature, pubKeyBytes)
}

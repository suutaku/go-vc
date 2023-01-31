package bbsblssignatureproof2020

import (
	"fmt"

	"github.com/suutaku/go-bbs/pkg/bbs"
)

type Signer struct {
	pk   *bbs.PrivateKey
	algo *bbs.Bbs
}

func NewSigner(pk *bbs.PrivateKey) *Signer {
	return &Signer{
		pk:   pk,
		algo: bbs.NewBbs(),
	}
}

func (sigr *Signer) DeriveProof(message [][]byte, sig, nonce, pubkey []byte, indexes []int) ([]byte, error) {
	return sigr.algo.DeriveProof(message, sig, nonce, pubkey, indexes)
}

func (sig *Signer) Sign(msg [][]byte) ([]byte, error) {
	if sig.pk == nil {
		return nil, fmt.Errorf("private key was empty")
	}
	return sig.algo.SignWithKey(msg, sig.pk)
}

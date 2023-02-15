package credential

import (
	"fmt"

	"github.com/suutaku/go-vc/pkg/processor"
	"github.com/suutaku/go-vc/pkg/proof"
	"github.com/suutaku/go-vc/pkg/resolver"
	"github.com/suutaku/go-vc/pkg/suite"
)

func (cred *Credential) VerifyProof(ss map[string]suite.SignatureSuite, pubResolver resolver.PublicKeyResolver, opts ...processor.ProcessorOpts) error {
	if cred.Proof == nil {
		return fmt.Errorf("proof was empty")
	}
	proofs, err := GetProofs(cred.Proof)
	if err != nil {
		return err
	}
	for _, pm := range proofs {
		p := proof.NewProofFromMap(pm)
		s := ss[p.Type]
		messages, err := CreateVerifyData(s, cred.ToMap(), p, opts...)
		if err != nil {
			return err
		}
		pubKeyValue, signature, err := getPublicKeyAndSignature(p.ToMap(), pubResolver)
		if err != nil {
			return err
		}
		err = s.Verify(pubKeyValue, messages, signature, p.Nonce)
		if err != nil {
			return err
		}
	}
	return nil
}

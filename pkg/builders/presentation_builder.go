package builders

import (
	"fmt"

	"github.com/suutaku/go-vc/pkg/presentation"
	"github.com/suutaku/go-vc/pkg/resolver"
)

type PRBuilder struct {
	*VCBuilder
}

func NewPRBuilder(opts ...BuilderOption) *PRBuilder {
	return &PRBuilder{
		VCBuilder: NewVCBuilder(opts...),
	}
}

func (prb *PRBuilder) AddLinkedDataProof(pr *presentation.Presentation, opts ...BuilderOption) (*presentation.Presentation, error) {
	prb.options.Merge(opts)
	s := prb.options.signatureSuites[prb.options.ldpCtx.SignatureType]
	pr.Proof = make([]interface{}, len(pr.Credential))
	for k, v := range pr.Credential {
		err := v.AddLinkedDataProof(s, prb.options.ldpCtx, prb.options.processorOpts...)
		if err != nil {
			return nil, err
		}

		if proofs, ok := v.Proof.([]interface{}); ok {
			pr.Proof[k] = proofs[len(proofs)-1]
		} else {
			pr.Proof[k] = v.Proof
		}

	}
	return pr, nil
}

func (prb *PRBuilder) Verify(pr *presentation.Presentation, issuerPubResolver resolver.PublicKeyResolver, opts ...BuilderOption) error {
	if pr == nil || len(pr.Credential) == 0 || len(pr.Proof) != len(pr.Credential) {
		return fmt.Errorf("invalid preesntation")
	}
	prb.options.Merge(opts)
	for i, val := range pr.Credential {
		val.Proof = pr.Proof[i]
		err := val.VerifyProof(prb.options.signatureSuites, issuerPubResolver, prb.options.processorOpts...)
		if err != nil {
			return err
		}
	}
	return nil
}

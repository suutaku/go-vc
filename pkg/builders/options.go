package builders

import (
	"github.com/suutaku/go-bbs/pkg/bbs"
	"github.com/suutaku/go-vc/internal/processor"
	"github.com/suutaku/go-vc/pkg/proof"
	"github.com/suutaku/go-vc/pkg/suite"
	"github.com/suutaku/go-vc/pkg/suite/bbsblssignature2020"
	"github.com/suutaku/go-vc/pkg/suite/bbsblssignatureproof2020"
)

type builderOption struct {
	did             string
	signatureSuites map[string]suite.SignatureSuite
	processorOpts   []processor.ProcessorOpts
	ldpCtx          *proof.LinkedDataProofContext
}

type BuilderOption func(opts *builderOption)

// WithSignatureSuites option for create bbs+ signature suites.
func WithSignatureSuites(suites ...suite.SignatureSuite) BuilderOption {
	return func(opts *builderOption) {
		opts.signatureSuites = make(map[string]suite.SignatureSuite)
		for _, v := range suites {
			opts.signatureSuites[v.Alg()] = v
		}
	}
}

// WithPrivateKey option will create both BbsBlsSignature2020 and BbsBlsSignatureProof2020 suite with compacted proof disabled automatically
func WithPrivateKey(priv *bbs.PrivateKey) BuilderOption {
	return func(opts *builderOption) {
		opts.signatureSuites = make(map[string]suite.SignatureSuite)
		bbss := bbsblssignature2020.NewSignatureSuite(priv, false)
		opts.signatureSuites[bbss.Alg()] = bbss
		bbsps := bbsblssignatureproof2020.NewSignatureSuite(priv, false)
		opts.signatureSuites[bbsps.Alg()] = bbsps
	}
}

// WithProcessorOptions will parse to json-ld processor
func WithProcessorOptions(processorOpts ...processor.ProcessorOpts) BuilderOption {
	return func(opts *builderOption) {
		opts.processorOpts = append(opts.processorOpts, processorOpts...)
	}
}

// WithLinkedDataProofContext will parse a LinkedDataProofContext for linked proof and disclusour generation
func WithLinkedDataProofContext(ldpCtx *proof.LinkedDataProofContext) BuilderOption {
	return func(opts *builderOption) {
		opts.ldpCtx = ldpCtx
	}
}

func WithDID(did string) BuilderOption {
	return func(opts *builderOption) {
		opts.did = did
	}
}

// prepareOpts prepare builderOptions.
func prepareOpts(opts []BuilderOption) *builderOption {
	procOpts := &builderOption{
		processorOpts: []processor.ProcessorOpts{
			processor.WithValidateRDF(),
		},
	}
	for _, opt := range opts {
		opt(procOpts)
	}
	return procOpts
}

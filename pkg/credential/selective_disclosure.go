package credential

import (
	"encoding/base64"
	"fmt"

	"github.com/suutaku/go-vc/internal/processor"
	"github.com/suutaku/go-vc/internal/tools"
	"github.com/suutaku/go-vc/pkg/common"
	"github.com/suutaku/go-vc/pkg/proof"
	"github.com/suutaku/go-vc/pkg/resolver"
	"github.com/suutaku/go-vc/pkg/suite"
	"github.com/suutaku/go-vc/pkg/suite/bbsblssignatureproof2020"
)

const (
	signatureProofType = "BbsBlsSignatureproof2020"
)

func (cred *Credential) GenerateBBSSelectiveDisclosure(s suite.SignatureSuite, reveal *Credential, pubResolver resolver.PublicKeyResolver, nonce []byte, opts ...processor.ProcessorOpts) (*Credential, error) {
	if reveal == nil {
		return nil, fmt.Errorf("no reveal doc parsed")
	}
	if cred.Proof == nil {
		return nil, fmt.Errorf("expected at least one proof present")
	}
	docWithoutProof, err := getCompactedWithSecuritySchema(cred.ToMap(), opts...)
	if err != nil {
		return nil, fmt.Errorf("preparing doc failed: %w", err)
	}
	blsSignatures, err := GetBLSProofs(docWithoutProof["proof"])
	if err != nil {
		return nil, fmt.Errorf("get BLS proofs: %w", err)
	}
	delete(docWithoutProof, "proof")
	if len(blsSignatures) == 0 {
		return nil, fmt.Errorf("no BbsBlsSignature2020 proof present")
	}
	docVerData, pErr := buildDocVerificationData(docWithoutProof, reveal.ToMap(), opts...)
	if pErr != nil {
		return nil, fmt.Errorf("build document verification data: %w", pErr)
	}
	proofs := make([]map[string]interface{}, len(blsSignatures))

	for i, blsSignature := range blsSignatures {
		verData, dErr := buildVerificationData(blsSignature, docVerData, opts...)
		if dErr != nil {
			return nil, fmt.Errorf("build verification data: %w", dErr)
		}

		derivedProof, dErr := generateSignatureProof(blsSignature, pubResolver, nonce, verData, s)
		if dErr != nil {
			return nil, fmt.Errorf("generate signature proof: %w", dErr)
		}

		proofs[i] = derivedProof
	}

	revealDocumentResult := docVerData.RevealDocumentResult
	revealDocumentResult["proof"] = proofs
	ret := NewCredential()
	ret.FromMap(revealDocumentResult)
	return ret, nil
}

func buildDocVerificationData(docCompacted, revealDoc map[string]interface{}, opts ...processor.ProcessorOpts) (*DocVerificationData, error) {
	// create verify document data
	docBytes, err := processor.Default().GetCanonicalDocument(docCompacted, opts...)
	if err != nil {
		return nil, err
	}
	documentStatements := tools.SplitMessageIntoLinesStr(string(docBytes), false)
	transformedStatements := make([]string, len(documentStatements))

	for i, row := range documentStatements {
		transformedStatements[i] = processor.TransformBlankNode(string(row))
	}
	newOpts := append(opts, processor.WithFrameBlankNodes())
	revealDocumentResult, err := processor.Default().Frame(docCompacted, revealDoc, newOpts...)
	if err != nil {
		return nil, fmt.Errorf("frame doc with reveal doc: %w", err)
	}

	// create verify reveal data
	docBytes, err = processor.Default().GetCanonicalDocument(revealDocumentResult, opts...)
	if err != nil {
		return nil, err
	}
	revealDocumentStatements := tools.SplitMessageIntoLinesStr(string(docBytes), false)

	revealIndexes := make([]int, len(revealDocumentStatements))

	documentStatementsMap := make(map[string]int)
	for i, statement := range transformedStatements {
		documentStatementsMap[statement] = i
	}

	for i := range revealDocumentStatements {
		statement := revealDocumentStatements[i]
		statementInd := documentStatementsMap[statement]
		revealIndexes[i] = statementInd
	}

	return &DocVerificationData{
		DocumentStatements:   documentStatements,
		RevealIndexes:        revealIndexes,
		RevealDocumentResult: revealDocumentResult,
	}, nil
}

func buildVerificationData(blsProof map[string]interface{}, docVerData *DocVerificationData, opts ...processor.ProcessorOpts) (*VerificationData, error) {
	proofStatements, err := createVerifyProofData(blsProof, opts...)
	if err != nil {
		return nil, fmt.Errorf("create verify proof data: %w", err)
	}

	numberOfProofStatements := len(proofStatements)
	revealIndexes := make([]int, numberOfProofStatements+len(docVerData.RevealIndexes))

	for i := 0; i < numberOfProofStatements; i++ {
		revealIndexes[i] = i
	}

	for i := range docVerData.RevealIndexes {
		revealIndexes[i+numberOfProofStatements] = numberOfProofStatements + docVerData.RevealIndexes[i]
	}

	allInputStatements := append(proofStatements, docVerData.DocumentStatements...)
	blsMessages := toArrayOfBytes(allInputStatements)

	return &VerificationData{
		BlsMessages:   blsMessages,
		RevealIndexes: revealIndexes,
	}, nil
}

func createVerifyProofData(proofMap map[string]interface{}, opts ...processor.ProcessorOpts) ([]string, error) {
	proofMapCopy := make(map[string]interface{}, len(proofMap)-1)

	for k, v := range proofMap {
		if k != "proofValue" {
			proofMapCopy[k] = v
		}
	}

	proofBytes, err := processor.Default().GetCanonicalDocument(proofMapCopy, opts...)
	if err != nil {
		return nil, err
	}

	return tools.SplitMessageIntoLinesStr(string(proofBytes), false), nil
}

func generateSignatureProof(blsSignature map[string]interface{}, resolver resolver.PublicKeyResolver, nonce []byte, verData *VerificationData, s suite.SignatureSuite) (map[string]interface{}, error) {
	pubKeyBytes, signatureBytes, pErr := getPublicKeyAndSignature(blsSignature, resolver)
	if pErr != nil {
		return nil, fmt.Errorf("get public key and signature: %w", pErr)
	}

	signatureProofBytes, err := s.(*bbsblssignatureproof2020.SignatureSuite).Signer.DeriveProof(verData.BlsMessages, signatureBytes, nonce, pubKeyBytes, verData.RevealIndexes)
	if err != nil {
		return nil, fmt.Errorf("derive BBS+ proof: %w", err)
	}
	twrap := &common.FormatedTime{}
	twrap.UnmarshalJSON([]byte(blsSignature["created"].(string)))
	derivedProof := &proof.Proof{
		Type:               signatureProofType,
		Nonce:              nonce,
		VerificationMethod: blsSignature["verificationMethod"].(string),
		ProofPurpose:       blsSignature["proofPurpose"].(string),
		Created:            twrap,
		ProofValue:         base64.StdEncoding.EncodeToString(signatureProofBytes),
	}
	return derivedProof.ToMap(), err
}

func toArrayOfBytes(messages []string) [][]byte {
	res := make([][]byte, len(messages))

	for i := range messages {
		res[i] = []byte(messages[i])
	}
	return res
}

func getPublicKeyAndSignature(pmap map[string]interface{}, pubResolver resolver.PublicKeyResolver) ([]byte, []byte, error) {
	p := proof.NewProofFromMap(pmap)
	pid, err := p.PublicKeyId()
	if err != nil {
		return nil, nil, err
	}
	pbk, err := pubResolver.Resolve(pid)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot resolve public key: %w", err)
	}
	pubKeyValue := pbk.Value
	if p.SignatureRepresentation == proof.SignatureJWS {
		pubKeyValue = pbk.Jwk
	}
	// get verify value
	signature, err := p.GetProofVerifyValue()

	return pubKeyValue, signature, err

}

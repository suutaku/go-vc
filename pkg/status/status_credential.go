package status

import (
	"fmt"

	"github.com/suutaku/go-vc/pkg/credential"
)

const (
	StatusList2021 = "StatusList2021"
	StatusPurpose  = "revocation"
)

// GenStatusCredential
func GenStatusCredential(issuedCreds []credential.Credential, preBuildCred *credential.Credential) (*credential.Credential, error) {

	bitStr := GenBitstring(issuedCreds)
	if bitStr == nil {
		return nil, fmt.Errorf("cannot generate bit string")
	}
	preBuildCred.Subject.(map[string]interface{})["encodedList"] = bitStr.Compressed()
	return preBuildCred, nil
}

// func ValidateStatusCredential(credToValid *credential.Credential) {}

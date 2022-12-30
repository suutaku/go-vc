package proof

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	partsNumber   = 3
	headerPart    = 0
	signaturePart = 2
)

type Jwt struct {
	header    string
	signature string
}

func NewJwt() *Jwt {
	return &Jwt{}
}

func (jb *Jwt) NewHeader(alg string) string {
	headerMap := map[string]interface{}{
		"alg":  alg,
		"b64":  false,
		"crit": []string{"b64"},
	}

	jwtHeaderBytes, err := json.Marshal(headerMap)
	if err != nil {
		logrus.Error(err)
		return ""
	}

	return base64.RawURLEncoding.EncodeToString(jwtHeaderBytes)
}

func (jb *Jwt) Parse(jwt string) error {
	parts := strings.Split(jwt, ".")
	if len(parts) != partsNumber {
		return fmt.Errorf("invalid jwt string")
	}
	jb.header = parts[headerPart]
	jb.signature = parts[signaturePart]
	return nil
}

func (jb *Jwt) Header() string {
	return jb.header
}

func (jb *Jwt) Signature() string {
	return jb.signature
}

package status

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/suutaku/go-vc/pkg/credential"
)

// mininum size of 16 KB
const miniBytesLen = 1024 << 4

type BitString struct {
	compressed string
}

func ParseBitString(compressed string) *BitString {
	return &BitString{
		compressed: compressed,
	}
}

func (bs *BitString) Compressed() string {
	return bs.compressed
}

// GenBitstring
// https://w3c.github.io/vc-status-list-2021/#bitstring-generation-algorithm
// The following process, or one generating the exact output, MUST be followed
// when generating a status list bitstring. The algorithm takes a issuedCredentials
// list as input and returns a compressed bitstring as output.
//
// 1) Let bitstring be a list of bits with a minimum size of 16KB, where each bit is initialized to 0 (zero).
// 2) For each bit in bitstring, if there is a corresponding statusListIndex value in a revoked credential in issuedCredentials, set the bit to 1 (one), otherwise set the bit to 0 (zero).
// 3) Generate a compressed bitstring by using the GZIP compression algorithm [RFC1952] on the bitstring and then base64-encoding [RFC4648] the result.
// 4) Return the compressed bitstring.
func GenBitstring(issuedCredentials []credential.Credential) *BitString {
	bitStr := make([]byte, miniBytesLen)
	for _, v := range issuedCredentials {
		// don't have status
		if v.Status == nil {
			continue
		}
		// not a StatusList2021Entry
		if v.Status["type"] != StatusList2021Entry {
			continue
		}
		// not Revoked
		if v.Status["statusPurpose"] != StatusPurpose {
			continue
		}
		// must have index
		if indexStr, ok := v.Status["statusListIndex"].(string); ok {
			idx, err := strconv.ParseUint(indexStr, 10, 64)
			if err != nil {
				continue
			}

			byteIdx := idx >> 3
			subBitIdx := idx - (byteIdx << 3)

			bitStr[byteIdx] = bitStr[byteIdx] | (1 << (8 - subBitIdx))

		}
	}
	// compressing
	buf := bytes.Buffer{}
	gr := gzip.NewWriter(&buf)
	_, err := gr.Write(bitStr)
	if err != nil {
		return nil
	}
	if err = gr.Flush(); err != nil {
		return nil
	}

	if err = gr.Close(); err != nil {
		return nil
	}
	return ParseBitString(base64.RawStdEncoding.EncodeToString(buf.Bytes()))
}

// ExpanBistring
// https://w3c.github.io/vc-status-list-2021/#bitstring-expansion-algorithm
// The following process, or one generating the exact output, MUST be followed when expanding a compressed
// status list bitstring. The algorithm takes a compressed bitstring as input and returns a uncompressed
// bitstring as output.
//
// 1) Let compressed bitstring be a compressed status list bitstring.
// 2) Generate an uncompressed bitstring by using the base64-decoding [RFC4648] algorithm on the
// compressed bitstring and then expanding the output using the GZIP decompression algorithm [RFC1952].
// 3) Return the uncompressed bitstring.
func (bs *BitString) ExpanBistring() ([]byte, error) {
	compressRaw, err := base64.RawStdEncoding.DecodeString(bs.compressed)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(compressRaw)
	gr, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	res := bytes.Buffer{}
	_, err = res.ReadFrom(gr)
	return res.Bytes(), err
}

func (bs *BitString) Check(idx int) (bool, error) {
	exp, err := bs.ExpanBistring()
	if err != nil {
		return false, fmt.Errorf("on bit string check: %w", err)
	}
	byteIdx := idx >> 3
	subBitIdx := idx - (byteIdx << 3)
	return exp[byteIdx] == (1 << (8 - subBitIdx)), nil
}

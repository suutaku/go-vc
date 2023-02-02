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
func GenBitstring(issuedCredentials []credential.Credential) (string, error) {
	bitStr := make([]byte, miniBytesLen)
	for _, v := range issuedCredentials {
		// don't have status
		if v.Status == nil {
			continue
		}
		// not a StatusList2021Entry
		if v.Status["type"] != statusList2021Entry {
			continue
		}
		// not Revoked
		if v.Status["statusPurpose"] == currentStatusRevoked {
			continue
		}
		// must have index
		if indexStr, ok := v.Status["statusListIndex"].(string); ok {
			idx, err := strconv.ParseUint(indexStr, 10, 64)
			if err != nil {
				continue
			}
			fmt.Println("get bit index ", idx)
			byteIdx := idx >> 3
			subBitIdx := idx - (byteIdx << 3)

			fmt.Printf("bytes index %d set to %d\n", byteIdx, subBitIdx)
			bitStr[byteIdx] = bitStr[byteIdx] | (1 << (8 - subBitIdx))

		}
	}
	// compressing
	buf := bytes.Buffer{}
	gr := gzip.NewWriter(&buf)
	_, err := gr.Write(bitStr)
	if err != nil {
		return "", err
	}
	if err = gr.Flush(); err != nil {
		return "", err
	}

	if err = gr.Close(); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(buf.Bytes()), nil
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
func ExpanBistring(compressed string) ([]byte, error) {
	compressRaw, err := base64.RawStdEncoding.DecodeString(compressed)
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

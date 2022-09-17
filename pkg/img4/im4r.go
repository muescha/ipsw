package img4

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"io"
)

type Im4r struct {
	img4RestoreInfo
	restoreInfo
}

type img4RestoreInfo struct {
	Raw       asn1.RawContent
	Name      string // IM4R
	Generator asn1.RawValue
	Data      []byte
}

type restoreInfo struct {
	Generator dataProp
	img4RestoreInfo
}

const typeBNCN = "private,tag:1112425294"

func ParseIm4r(r io.Reader) (*Im4r, error) {

	data := new(bytes.Buffer)
	data.ReadFrom(r)

	var i Im4r

	_, err := asn1.Unmarshal(data.Bytes(), &i)
	if err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Im4m: %v", err)
	}

	return &i, nil
}

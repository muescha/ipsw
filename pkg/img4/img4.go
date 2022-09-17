package img4

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
)

// Img4 object
type Img4 struct {
	Name        string
	Description string
	Payload     *Im4p
	Manifest    *Im4m
	RestoreInfo restoreInfo
}

type img4 struct {
	Raw         asn1.RawContent
	Name        string // IMG4
	Payload     im4Payload
	Manifest    img4Manifest    `asn1:"explicit,tag:0"`
	RestoreInfo img4RestoreInfo `asn1:"optional,explicit,tag:1,omitempty"`
}

const ( // sepi private tags
	typeImpl = "private,tag:1768779884"
	typeArms = "private,tag:1634889075"
	typeTbmr = "private,tag:1952607602"
	typeTbms = "private,tag:1952607603"
	typeTz0s = "private,tag:1954164851"
)

type arms struct {
	intProp
}
type tbmr struct {
	dataProp
}
type tbms struct {
	dataProp
}
type tz0s struct {
	intProp
}

// Parse parses a Img4
func Parse(r io.Reader) (*Img4, error) {
	utils.Indent(log.Info, 2)("Parsing IMG4")

	data := new(bytes.Buffer)
	data.ReadFrom(r)

	var i img4

	if _, err := asn1.Unmarshal(data.Bytes(), &i); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4: %v", err)
	}

	im4m, err := i.Manifest.Parse()
	if err != nil {
		return nil, err
	}

	// gen, _, err := parseDataProp(i.RestoreInfo.Generator.Bytes, typeBNCN)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to ASN.1 parse Generator: %v", err)
	// }

	return &Img4{
		Name:        i.Payload.Name,
		Description: i.Payload.Description,
		Manifest:    im4m,
		RestoreInfo: restoreInfo{
			// Generator:       *gen,
			img4RestoreInfo: i.RestoreInfo,
		},
	}, nil
}

func Info(r io.Reader) (string, error) {
	return "", nil
}

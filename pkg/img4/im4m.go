package img4

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

const (
	typeMANB = "private,tag:1296125506" // MANB
	typeMANP = "private,tag:1296125520" // MANP
)

type Im4m struct {
	img4Manifest
	manifest
}

type manifest struct {
	Properties   ManifestProperties
	ApImg4Ticket asn1.RawValue
}

type img4Manifest struct {
	Raw     asn1.RawContent
	Name    string // IM4M
	Version int
	Body    asn1.RawValue
}

func (m img4Manifest) Parse() (*Im4m, error) {
	var i Im4m

	mbodies, err := m.GetBody()
	if err != nil {
		return nil, err
	}

	if len(mbodies) != 1 {
		return nil, fmt.Errorf("expected 1 manifest body, got %d", len(mbodies))
	}

	props, err := mbodies[0].GetProperties()
	if err != nil {
		return nil, err
	}

	i.Properties = *props

	return &Im4m{
		img4Manifest: m,
		manifest: manifest{
			Properties: *props,
		},
	}, nil
}

func (m img4Manifest) GetBody() ([]MANB, error) {
	var mb []MANB
	if _, err := asn1.UnmarshalWithParams(m.Body.Bytes, &mb, typeMANB); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse im4m body: %v", err)
	}
	return mb, nil
}

type ManifestProperties map[string]any

type MANB struct {
	Raw        asn1.RawContent
	Name       string // MANB
	Properties asn1.RawValue
}

func (mb MANB) GetProperties() (*ManifestProperties, error) {
	var err error
	maniProps := make(ManifestProperties)

	var mprops []MANP
	rest, err := asn1.UnmarshalWithParams(mb.Properties.Bytes, &mprops, typeMANP)
	if err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse im4m body properties: %v", err)
	}

	if len(mprops) != 1 {
		return nil, fmt.Errorf("im4m body properties length is not 1")
	}

	data := mprops[0].Properties.Bytes

	for _, p := range props {
		switch p.Type {
		case "bool":
			var b []boolProp
			data, err = asn1.UnmarshalWithParams(data, &b, p.Tag)
			if err != nil {
				return nil, fmt.Errorf("failed to ASN.1 parse body bool prop: %v", err)
			}
			maniProps[p.Name] = b[0]
		case "int":
			var i []intProp
			data, err = asn1.UnmarshalWithParams(data, &i, p.Tag)
			if err != nil {
				return nil, fmt.Errorf("failed to ASN.1 parse body int prop: %v", err)
			}
			maniProps[p.Name] = i[0]
		case "data":
			var d []dataProp
			data, err = asn1.UnmarshalWithParams(data, &d, p.Tag)
			if err != nil {
				return nil, fmt.Errorf("failed to ASN.1 parse body data prop: %v", err)
			}
			maniProps[p.Name] = d[0]
		}
	}

	var tags []asn1.RawValue
	for {
		if len(rest) == 0 {
			break
		}
		var tag asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &tag); err != nil {
			return nil, fmt.Errorf("failed to ASN.1 parse im4m body properties: %v", err)
		}
		tags = append(tags, tag)
	}

	var tt []ting
	for _, tag := range tags {
		dat := tag.Bytes
		for {
			if len(dat) == 0 {
				break
			}
			var prop ting
			if dat, err = asn1.Unmarshal(dat, &prop); err != nil {
				return nil, fmt.Errorf("failed to ASN.1 parse im4m body properties: %v", err)
			}
			tt = append(tt, prop)
		}
	}

	for _, p := range tt {
		dat := p.Value.Bytes
		var tags []asn1.RawValue
		for {
			if len(dat) == 0 {
				break
			}
			var tag asn1.RawValue
			if dat, err = asn1.Unmarshal(dat, &tag); err != nil {
				return nil, fmt.Errorf("failed to ASN.1 parse im4m body properties: %v", err)
			}
			switch tag.Tag {
			case 1145525076:
				var d dataProp
				if _, err = asn1.Unmarshal(tag.Bytes, &d); err != nil {
					return nil, fmt.Errorf("failed to ASN.1 parse im4m body properties: %v", err)
				}
				fmt.Println(hex.EncodeToString(d.Value))
			default:
				var b boolProp
				if _, err = asn1.Unmarshal(tag.Bytes, &b); err != nil {
					return nil, fmt.Errorf("failed to ASN.1 parse im4m body properties: %v", err)
				}
				fmt.Println(b)
			}

			tags = append(tags, tag)
		}
	}
	// 	if len(dat) == 0 {
	// 		break
	// 	}
	// 	// var tag asn1.RawValue
	// 	// if dat, err = asn1.Unmarshal(dat, &tag); err != nil {
	// 	// 	return nil, fmt.Errorf("failed to ASN.1 parse im4m body properties: %v", err)
	// 	// }
	// 	var t ting
	// 	if dat, err = asn1.Unmarshal(dat, &t); err != nil {
	// 		return nil, fmt.Errorf("failed to ASN.1 parse im4m body properties: %v", err)
	// 	}
	// 	fmt.Println(t)
	// 	var tag asn1.RawValue
	// 	if dat, err = asn1.Unmarshal(t.Value.Bytes, &tag); err != nil {
	// 		return nil, fmt.Errorf("failed to ASN.1 parse im4m body properties: %v", err)
	// 	}
	// 	fmt.Println(tag)
	// }

	// var tings Tingy
	// if _, err := asn1.Unmarshal(tag.Bytes, &tings); err != nil {
	// 	return nil, fmt.Errorf("failed to ASN.1 parse im4m body properties: %v", err)
	// }

	return &maniProps, nil
}

type ting struct {
	Name  string
	Value asn1.RawValue
}
type tingb struct {
	Name  string
	Value any
}

const (
	ane1Tag = "private,tag:1634624817"
	anefTag = "private,tag:1634624870"
	aopfTag = "private,tag:1634693222"
	avefTag = "private,tag:1635149158"
	bstcTag = "private,tag:1651733603"
	csysTag = "private,tag:1668512115"
	dcp2Tag = "private,tag:1684238386"
	dtreTag = "private,tag:1685353061"
	gfxfTag = "private,tag:1734768742"
	ibdtTag = "private,tag:1768055924"
	ibecTag = "private,tag:1768056163"
	ibotTag = "private,tag:1768058740"
	ipdfTag = "private,tag:1768973414"
	ispfTag = "private,tag:1769173094"
	isysTag = "private,tag:1769175411"
	krnlTag = "private,tag:1802661484"
	msysTag = "private,tag:1836284275"
	pmpfTag = "private,tag:1886220390"
	rdskTag = "private,tag:1919185771"
	rdtrTag = "private,tag:1919186034"
	rkrnTag = "private,tag:1919644270"
	rlgoTag = "private,tag:1919706991"
	rosiTag = "private,tag:1919906665"
	rtscTag = "private,tag:1920234339"
	siofTag = "private,tag:1936289638"
	trstTag = "private,tag:1953657716"
)

type Tingy struct {
	DGST DGST `asn1:"private,tag:1145525076,explicit"`
	EKEY EKEY `asn1:"explicit,tag:3"`
	EPRO EPRO `asn1:"explicit,tag:3"`
	ESEC ESEC `asn1:"explicit,tag:3"`
}

type DGST struct {
	// Raw  asn1.RawContent `asn1:"private,tag:1145525076"`
	Name string
	Data []byte
}

type EKEY struct {
	// Raw  asn1.RawContent `asn1:"private,tag:1162560857"`
	Name string
	Data bool
}
type EPRO struct {
	// Raw  asn1.RawContent `asn1:"private,tag:1162891855"`
	Name string
	Data bool
}
type ESEC struct {
	// Raw  asn1.RawContent `asn1:"private,tag:1163085123"`
	Name string
	Data bool
}

const (
	typeBNCH = "private,tag:1112425288"
	typeBORD = "private,tag:1112494660"
	typeCEPO = "private,tag:1128616015"
	typeCHIP = "private,tag:1128810832"
	typeCPRO = "private,tag:1129337423"
	typeCSEC = "private,tag:1129530691"
	typeECID = "private,tag:1162037572"
	typeSDOM = "private,tag:1396985677"
	typeLove = "private,tag:1819244133"
	typeSnon = "private,tag:1936617326"
	typeSnuf = "private,tag:1936618854"
	typeSrvn = "private,tag:1936881262"
)

type Property struct {
	Raw   asn1.RawContent
	Name  string
	Value any
}

type Prop struct {
	Name string
	Tag  string
	Type string
}

type intProp struct {
	Raw   asn1.RawContent
	Name  string
	Value int
}
type uintProp struct {
	Raw   asn1.RawContent
	Name  string
	Value *big.Int
}

type dataProp struct {
	Raw   asn1.RawContent
	Name  string
	Value []byte
}

type boolProp struct {
	Raw   asn1.RawContent
	Name  string
	Value bool
}

var props = []Prop{
	{"ApNonce", typeBNCH, "data"},
	{"BoardID", typeBORD, "int"},
	{"ChipEpoch", typeCEPO, "int"},
	{"ChipID", typeCHIP, "int"},
	{"CPRO", typeCPRO, "bool"},
	{"CSEC", typeCSEC, "bool"},
	{"ECID", typeECID, "int"},
	{"SecurityDomain", typeSDOM, "int"},
	{"Love", typeLove, "data"},
	{"SepNonce", typeSnon, "data"},
	{"snuf", typeSnuf, "data"},
	{"srvn", typeSrvn, "data"},
}

type MANP struct {
	Raw        asn1.RawContent
	Name       string // MANP
	Properties asn1.RawValue
}

func ParseIm4m(r io.Reader) (*Im4m, error) {

	data := new(bytes.Buffer)
	data.ReadFrom(r)

	var i Im4m

	if _, err := asn1.Unmarshal(data.Bytes(), &i.img4Manifest); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse im4m: %v", err)
	}

	return i.img4Manifest.Parse()
}

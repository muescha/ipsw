package img4

import (
	"archive/zip"
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/info"
)

type Im4p struct {
	im4Payload
	Kbags []Keybag
	Props map[string]any
}

type im4Payload struct {
	Raw         asn1.RawContent
	Name        string `asn1:"ia5"` // IM4P
	Type        string `asn1:"ia5"`
	Description string
	Data        []byte
	KbagData    []byte          `asn1:"optional"`
	Compression img4Compression `asn1:"optional"`
	Props       PAYP            `asn1:"optional,explicit,tag:0"`
}

type compressionAlgo int

const (
	NONE  compressionAlgo = 0
	LZSS  compressionAlgo = 1
	LZFSE compressionAlgo = 2
)

type img4Compression struct {
	Algorithm    compressionAlgo
	OriginalSize int
}

type Keybag struct {
	Type kbagType
	IV   []byte
	Key  []byte
}

func (k Keybag) String() string {
	return fmt.Sprintf(
		"-\n"+
			"  type: %s\n"+
			"    iv: %x\n"+
			"   key: %x",
		k.Type.String(),
		k.IV,
		k.Key)
}
func (k Keybag) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Type string `json:"type,omitempty"`
		IV   string `json:"iv,omitempty"`
		Key  string `json:"key,omitempty"`
	}{
		Type: k.Type.Short(),
		IV:   hex.EncodeToString(k.IV),
		Key:  hex.EncodeToString(k.Key),
	})
}

type kbagType int

const (
	PRODUCTION  kbagType = 1
	DEVELOPMENT kbagType = 2
)

func (t kbagType) String() string {
	if t == PRODUCTION {
		return "PRODUCTION"
	}
	return "DEVELOPMENT"
}
func (t kbagType) Short() string {
	if t == PRODUCTION {
		return "prod"
	}
	return "dev"
}

type im4pKBag struct {
	Name    string   `json:"name,omitempty"`
	Keybags []Keybag `json:"kbags,omitempty"`
}

func ParseZipKeyBagsAsJSON(files []*zip.File, inf *info.Info, pattern string) (string, error) {
	var kbags []im4pKBag
	rePattern := `.*im4p$`
	if len(pattern) > 0 {
		if _, err := regexp.Compile(pattern); err != nil {
			return "", fmt.Errorf("failed to compile --pattern regexp: %v", err)
		}
		rePattern = pattern
	}
	for _, f := range files {
		if regexp.MustCompile(rePattern).MatchString(f.Name) {
			rc, err := f.Open()
			if err != nil {
				return "", fmt.Errorf("error opening zipped file %s: %v", f.Name, err)
			}
			im4p, err := ParseIm4p(rc)
			if err != nil {
				log.Errorf("failed to parse im4p %s: %v", f.Name, err)
			}
			if im4p.Kbags == nil { // kbags are optional
				continue
			}
			kbags = append(kbags, im4pKBag{
				Name:    filepath.Base(f.Name),
				Keybags: im4p.Kbags,
			})
			rc.Close()
		}
	}
	dat, err := json.Marshal(&struct {
		Type    string     `json:"type,omitempty"`
		Version string     `json:"version,omitempty"`
		Build   string     `json:"build,omitempty"`
		Devices []string   `json:"devices,omitempty"`
		Files   []im4pKBag `json:"files,omitempty"`
	}{
		Type:    inf.Plists.Type,
		Version: inf.Plists.BuildManifest.ProductVersion,
		Build:   inf.Plists.BuildManifest.ProductBuildVersion,
		Devices: inf.Plists.Restore.SupportedProductTypes,
		Files:   kbags,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal im4p kbag: %v", err)
	}
	return string(dat), nil
}

const (
	kcepTag = "private,tag:1801676144"
	kclfTag = "private,tag:1801677926"
	kcloTag = "private,tag:1801677935"
	kclzTag = "private,tag:1801677946"
	kcrfTag = "private,tag:1801679462"
	kcrzTag = "private,tag:1801679482"
	kcwfTag = "private,tag:1801680742"
	kcwzTag = "private,tag:1801680762"
)

var payps = []Prop{
	{"kcep", kcepTag, "int"},
	{"kclf", kclfTag, "int"},
	{"kclo", kcloTag, "int"},
	{"kclz", kclzTag, "int"},
	{"kcrf", kcrfTag, "int"},
	{"kcrz", kcrzTag, "int"},
	{"kcwf", kcwfTag, "int"},
	{"kcwz", kcwzTag, "int"},
}

type PAYP struct {
	Raw  asn1.RawContent
	Name string `asn1:"ia5"` // PAYP
	Body asn1.RawValue
}

func (p PAYP) Parse() (map[string]any, error) {
	var err error

	data := p.Body.Bytes
	payp := make(map[string]any)

	for _, p := range payps {
		var i []uintProp
		data, err = asn1.UnmarshalWithParams(data, &i, p.Tag)
		if err != nil {
			return nil, fmt.Errorf("failed to ASN.1 parse body bool prop: %v", err)
		}
		payp[p.Name] = i[0]
	}

	return payp, nil
}

func ParseIm4p(r io.Reader) (*Im4p, error) {

	data := new(bytes.Buffer)
	data.ReadFrom(r)

	var i Im4p

	_, err := asn1.Unmarshal(data.Bytes(), &i.im4Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Im4p: %v", err)
	}

	if i.im4Payload.KbagData != nil {
		_, err = asn1.Unmarshal(i.im4Payload.KbagData, &i.Kbags)
		if err != nil {
			return nil, fmt.Errorf("failed to ASN.1 parse Im4p KBAG: %v", err)
		}
	}

	return &i, nil
}

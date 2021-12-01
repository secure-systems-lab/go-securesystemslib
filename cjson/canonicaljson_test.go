package cjson

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

type KeyVal struct {
	Private     string `json:"private"`
	Public      string `json:"public"`
	Certificate string `json:"certificate,omitempty"`
}

type Key struct {
	KeyID               string   `json:"keyid"`
	KeyIDHashAlgorithms []string `json:"keyid_hash_algorithms"`
	KeyType             string   `json:"keytype"`
	KeyVal              KeyVal   `json:"keyval"`
	Scheme              string   `json:"scheme"`
}

func TestEncodeCanonical(t *testing.T) {
	objects := []interface{}{
		Key{},
		Key{
			KeyVal: KeyVal{
				Private: "priv",
				Public:  "pub",
			},
			KeyIDHashAlgorithms: []string{"hash"},
			KeyID:               "id",
			KeyType:             "type",
			Scheme:              "scheme",
		},
		map[string]interface{}{
			"true":   true,
			"false":  false,
			"nil":    nil,
			"int":    3,
			"int2":   float64(42),
			"string": `\"`,
		},
		Key{
			KeyVal: KeyVal{
				Certificate: "cert",
				Private:     "priv",
				Public:      "pub",
			},
			KeyIDHashAlgorithms: []string{"hash"},
			KeyID:               "id",
			KeyType:             "type",
			Scheme:              "scheme",
		},
		json.RawMessage(`{"_type":"targets","spec_version":"1.0","version":0,"expires":"0001-01-01T00:00:00Z","targets":{},"custom":{"test":true}}`),
	}
	expectedResult := []string{
		`{"keyid":"","keyid_hash_algorithms":null,"keytype":"","keyval":{"private":"","public":""},"scheme":""}`,
		`{"keyid":"id","keyid_hash_algorithms":["hash"],"keytype":"type","keyval":{"private":"priv","public":"pub"},"scheme":"scheme"}`,
		`{"false":false,"int":3,"int2":42,"nil":null,"string":"\\\"","true":true}`,
		`{"keyid":"id","keyid_hash_algorithms":["hash"],"keytype":"type","keyval":{"certificate":"cert","private":"priv","public":"pub"},"scheme":"scheme"}`,
		`{"_type":"targets","custom":{"test":true},"expires":"0001-01-01T00:00:00Z","spec_version":"1.0","targets":{},"version":0}`,
	}
	for i := 0; i < len(objects); i++ {
		result, err := EncodeCanonical(objects[i])

		if string(result) != expectedResult[i] || err != nil {
			t.Errorf("EncodeCanonical returned (%s, %s), expected (%s, nil)",
				result, err, expectedResult[i])
		}
	}
}

func TestEncodeCanonicalErr(t *testing.T) {
	objects := []interface{}{
		map[string]interface{}{"float": 3.14159265359},
		TestEncodeCanonical,
	}
	errPart := []string{
		"Can't canonicalize floating point number",
		"unsupported type: func(",
	}

	for i := 0; i < len(objects); i++ {
		result, err := EncodeCanonical(objects[i])
		if err == nil || !strings.Contains(err.Error(), errPart[i]) {
			t.Errorf("EncodeCanonical returned (%s, %s), expected '%s' error",
				result, err, errPart[i])
		}
	}
}

func TestencodeCanonical(t *testing.T) {
	expectedError := "Can't canonicalize"

	objects := []interface{}{
		TestencodeCanonical,
		[]interface{}{TestencodeCanonical},
	}

	for i := 0; i < len(objects); i++ {
		var result bytes.Buffer
		err := encodeCanonical(objects[i], &result)
		if err == nil || !strings.Contains(err.Error(), expectedError) {
			t.Errorf("EncodeCanonical returned '%s', expected '%s' error",
				err, expectedError)
		}
	}
}

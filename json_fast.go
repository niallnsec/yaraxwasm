package yaraxwasm

import (
	"encoding/json"
	"unsafe"

	easyjson "github.com/mailru/easyjson"
)

// Use generated easyjson decoders when available, but keep generation bootstrappable.
func unmarshalWireJSON(data []byte, dst any) error {
	if fast, ok := dst.(easyjson.Unmarshaler); ok {
		return easyjson.Unmarshal(data, fast)
	}
	return json.Unmarshal(data, dst)
}

func wireJSONBytesToString(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(data), len(data))
}

package credentials

import "encoding/hex"

func hexOf(key []byte) string { return hex.EncodeToString(key) }

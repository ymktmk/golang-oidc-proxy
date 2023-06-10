package rand

import (
	"crypto/rand"
	"encoding/hex"
)

func RandString(n int) (string, error) {
	bytes := make([]byte, n/2+1)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[0:n], nil
}

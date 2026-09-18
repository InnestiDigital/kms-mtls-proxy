package kmsfake

import (
	"os"
	"testing"
)

// RealKeyEnv names the variable that opts a test into talking to the real KMS
// service instead of a fake endpoint.
const RealKeyEnv = "MTLS_PROXY_REAL_KMS_KEY_ID"

// RealKeyID returns the CMK to exercise against the real service, skipping the
// calling test when the variable is unset. That keeps the default suite
// offline and free of credentials.
func RealKeyID(t *testing.T) string {
	t.Helper()
	keyID := os.Getenv(RealKeyEnv)
	if keyID == "" {
		t.Skipf("set %s to run against the real KMS service", RealKeyEnv)
	}
	return keyID
}

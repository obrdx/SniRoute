package auth

// Attempt credentials authenticate one probe attempt. They are issued when a
// task is created, travel only inside the encrypted HTTP request of the probe
// connection (never in the ClientHello), and are valid for a single use.
const (
	credPrefix = "cr1-"
	credBytes  = 16 // 128 bits
)

// NewAttemptCredential returns a fresh random one-time credential.
func NewAttemptCredential() string { return credPrefix + RandomString(credBytes) }

// NewAttemptID returns a fresh attempt identifier.
func NewAttemptID() string { return "att_" + RandomString(9) }

// HashCredential returns the value stored in place of the credential itself.
func HashCredential(c string) []byte {
	h := hashOf(c)
	return h[:]
}

package acme

import "os"

// setEnv applies the given environment variables and returns a function that
// restores the previous environment for exactly those keys. Used to feed
// credentials to lego DNS providers, which are configured via the environment.
func setEnv(vars map[string]string) (restore func()) {
	prev := make(map[string]*string, len(vars))
	for k, v := range vars {
		if old, ok := os.LookupEnv(k); ok {
			cp := old
			prev[k] = &cp
		} else {
			prev[k] = nil
		}
		_ = os.Setenv(k, v)
	}
	return func() {
		for k, old := range prev {
			if old == nil {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, *old)
			}
		}
	}
}

package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ListenAddr          string
	PublicIssuerURL     string
	ResourceURL         string
	DatabaseURL         string
	CExecutorPath       string
	MaxOutputBytes      int
	OAuthSigningKeyFile string
	AuditLogPath        string
}

func Load(path string) (Config, error) {
	if path != "" {
		st, err := os.Stat(path)
		if err == nil {
			if st.Mode().Perm()&0077 != 0 {
				return Config{}, fmt.Errorf("config %s must have mode 0600", path)
			}
			f, err := os.Open(path)
			if err != nil {
				return Config{}, err
			}
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				k, v, ok := strings.Cut(line, "=")
				if !ok {
					f.Close()
					return Config{}, fmt.Errorf("invalid config line")
				}
				k = strings.TrimSpace(k)
				v = strings.TrimSpace(v)
				if k == "" {
					f.Close()
					return Config{}, fmt.Errorf("empty config key")
				}
				if _, exists := os.LookupEnv(k); !exists {
					_ = os.Setenv(k, v)
				}
			}
			err = sc.Err()
			f.Close()
			if err != nil {
				return Config{}, err
			}
		} else if !os.IsNotExist(err) {
			return Config{}, err
		}
	}
	c := Config{
		ListenAddr:          env("LISTEN_ADDR", "127.0.0.1:8766"),
		PublicIssuerURL:     env("PUBLIC_ISSUER_URL", ""),
		ResourceURL:         env("RESOURCE_URL", ""),
		DatabaseURL:         env("DATABASE_URL", ""),
		CExecutorPath:       env("C_EXECUTOR_PATH", "/opt/kerno/bin/host-executor"),
		MaxOutputBytes:      envInt("MAX_OUTPUT_BYTES", 1048576),
		OAuthSigningKeyFile: env("OAUTH_SIGNING_KEY_FILE", "/usr/local/etc/kerno.secret"),
		AuditLogPath:        env("AUDIT_LOG_PATH", "/var/log/kerno-audit.log"),
	}
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("DATABASE_URL is required")
	}
	if c.PublicIssuerURL == "" || c.ResourceURL == "" {
		return c, fmt.Errorf("PUBLIC_ISSUER_URL and RESOURCE_URL are required")
	}
	return c, nil
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func envInt(k string, d int) int {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	n := 0
	for _, r := range v {
		if r < '0' || r > '9' {
			return d
		}
		n = n*10 + int(r-'0')
	}
	if n == 0 {
		return d
	}
	return n
}

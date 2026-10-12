// Package interop proves the promise the whole project rests on: ciphertext
// produced by this service can be read by the PHP, Node.js, and Python SDKs,
// and theirs can be read by this service.
//
// This is not implied by sharing panda-go. "By construction" is exactly the
// kind of claim that turns out to be false the first time a base64 variant or
// an envelope field ordering diverges, and by then it is in production. So the
// test runs the real SDKs, in their real languages, against real ciphertext.
//
// The SDKs live in sibling repositories. When they are absent the test skips
// with a message naming what is missing, rather than passing silently — a
// skipped interop test that looks like a pass is worse than no test.
package interop

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jatimprovcsirt/panda-go/crypto"

	"github.com/jatimprovcsirt/panda-docker/internal/service"
)

const (
	kid       = "interopkey"
	plaintext = "3201012501990001"
	// The value PANDA masks this to, asserted so a change in masking is
	// caught as an interop failure rather than discovered by a caller.
	masked = "32************01"
)

// repoRoot is the panda workspace holding the sibling SDK repositories.
func repoRoot() string {
	if v := os.Getenv("PANDA_SDK_ROOT"); v != "" {
		return v
	}
	// panda-docker is a sibling of the SDK repositories.
	return filepath.Join("..", "..", "..")
}

// sdkPath returns the path to an SDK, and whether it is present.
func sdkPath(parts ...string) (string, bool) {
	full := filepath.Join(append([]string{repoRoot()}, parts...)...)
	_, err := os.Stat(full)
	return full, err == nil
}

// env with a key every SDK can read.
func interopEnv(t *testing.T) []string {
	t.Helper()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	encoded := base64.StdEncoding.EncodeToString(key)

	// No hyphen in the KID: a hyphenated id produces an environment variable
	// name that POSIX shells refuse to set, so the SDKs could not read it.
	return append(os.Environ(),
		"PANDA_KEY_"+kid+"="+encoded,
		"PANDA_DEFAULT_KID="+kid,
	)
}

// run executes a command and returns its stdout.
func run(t *testing.T, name string, args ...string) (string, error) {
	t.Helper()

	cmd := exec.Command(name, args...)
	cmd.Env = interopEnv(t)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %w\nstderr: %s", name, err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

// newService builds a service over a local provider, matching the key above.
func newService(t *testing.T) *service.Service {
	t.Helper()

	// The environment is set for the child processes; the in-process provider
	// reads the same variable, so both sides use one key.
	for _, kv := range interopEnv(t) {
		if strings.HasPrefix(kv, "PANDA_KEY_") || strings.HasPrefix(kv, "PANDA_DEFAULT_KID=") {
			parts := strings.SplitN(kv, "=", 2)
			t.Setenv(parts[0], parts[1])
		}
	}

	svc, err := service.New(service.Options{
		Cipher: crypto.NewFieldCipher(crypto.NewLocalKeyProvider(), nil, nil),
	})
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	return svc
}

// --- the SDK drivers ------------------------------------------------------
//
// Each returns the decrypted plaintext on stdout. The APIs here were
// discovered by running them, not recalled — the first attempt at each was
// wrong in a different way.

func nodeDecryptScript(distPath string) string {
	return `
const { FieldCipher, LocalKeyProvider, Envelope } = require(` + jsString(distPath) + `);
(async () => {
  const c = new FieldCipher(new LocalKeyProvider());
  const env = Envelope.fromJson(process.argv[1]);
  process.stdout.write(String(await c.decryptRaw(env)));
})().catch(e => { console.error(e.message); process.exit(1); });
`
}

func nodeEncryptScript(distPath string) string {
	return `
const { FieldCipher, LocalKeyProvider } = require(` + jsString(distPath) + `);
(async () => {
  const c = new FieldCipher(new LocalKeyProvider());
  process.stdout.write(JSON.stringify(await c.encrypt(` + jsString(plaintext) + `, ` + jsString(kid) + `)));
})().catch(e => { console.error(e.message); process.exit(1); });
`
}

func pythonScript(body string) string {
	return `
import sys
from panda.crypto import FieldCipher, LocalKeyProvider
from panda.crypto.envelope import Envelope
from panda.audit.logger import NullAuditLogger

cipher = FieldCipher(LocalKeyProvider(), NullAuditLogger())
` + body
}

// phpScript builds a snippet for `php -r`.
//
// No `<?php` opening tag: `-r` takes code directly, and including the tag is a
// parse error. Discovered by running it.
func phpScript(body string) string {
	return `require ` + phpString(filepath.Join(repoRoot(), "panda-php", "vendor", "autoload.php")) + `;
$cipher = new Panda\Crypto\FieldCipher(new Panda\Crypto\LocalKeyProvider());
` + body
}

func jsString(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func phpString(s string) string {
	return `'` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `'`, `\'`) + `'`
}

// --- the tests ------------------------------------------------------------

// TestServiceCiphertextIsReadableByTheSDKs is the direction that matters most:
// an agency migrating an application onto this service must be able to keep
// reading the data it already has.
func TestServiceCiphertextIsReadableByTheSDKs(t *testing.T) {
	svc := newService(t)

	result, err := svc.Encrypt(plaintext, kid)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	t.Run("node", func(t *testing.T) {
		dist, ok := sdkPath("panda-node", "dist", "index.js")
		if !ok {
			t.Skipf("panda-node is not built at %s", dist)
		}
		out, err := run(t, "node", "-e", nodeDecryptScript(dist), result.Envelope)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if out != plaintext {
			t.Errorf("node decrypted %q, want %q", out, plaintext)
		}
	})

	t.Run("python", func(t *testing.T) {
		if _, ok := sdkPath("panda-py", "src", "panda"); !ok {
			t.Skip("panda-py is not present")
		}
		out, err := run(t, "python", "-c",
			pythonScript(`print(cipher.decrypt_raw(Envelope.from_json(sys.argv[1])), end='')`),
			result.Envelope)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if out != plaintext {
			t.Errorf("python decrypted %q, want %q", out, plaintext)
		}
	})

	t.Run("php", func(t *testing.T) {
		if _, ok := sdkPath("panda-php", "vendor", "autoload.php"); !ok {
			t.Skip("panda-php dependencies are not installed")
		}
		out, err := run(t, "php", "-r",
			phpScript(`echo $cipher->decryptRaw(Panda\Crypto\Envelope::fromJson($argv[1]));`),
			result.Envelope)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if out != plaintext {
			t.Errorf("php decrypted %q, want %q", out, plaintext)
		}
	})
}

// TestServiceReadsSDKCiphertext is the other direction, and the one an agency
// hits when an existing application keeps producing envelopes after this
// service is introduced.
func TestServiceReadsSDKCiphertext(t *testing.T) {
	svc := newService(t)

	cases := []struct {
		name   string
		script func(t *testing.T) (string, error)
	}{
		{"node", func(t *testing.T) (string, error) {
			dist, ok := sdkPath("panda-node", "dist", "index.js")
			if !ok {
				t.Skipf("panda-node is not built at %s", dist)
			}
			return run(t, "node", "-e", nodeEncryptScript(dist))
		}},

		{"python", func(t *testing.T) (string, error) {
			if _, ok := sdkPath("panda-py", "src", "panda"); !ok {
				t.Skip("panda-py is not present")
			}
			return run(t, "python", "-c", pythonScript(
				`import json
env = cipher.encrypt(sys.argv[1], kid=sys.argv[2])
print(json.dumps(env.to_dict() if hasattr(env, "to_dict") else env), end='')`,
			), plaintext, kid)
		}},

		{"php", func(t *testing.T) (string, error) {
			if _, ok := sdkPath("panda-php", "vendor", "autoload.php"); !ok {
				t.Skip("panda-php dependencies are not installed")
			}
			return run(t, "php", "-r", phpScript(
				`$env = $cipher->encrypt($argv[1], $argv[2]); echo $env->toJson();`,
			), plaintext, kid)
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			envelope, err := c.script(t)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if envelope == "" {
				t.Fatal("the SDK produced no envelope")
			}

			result, err := svc.DecryptRaw(service.Actor{APIKeyID: "interop"}, envelope)
			if err != nil {
				t.Fatalf("the service could not read the %s envelope: %v", c.name, err)
			}
			if result.Plaintext != plaintext {
				t.Errorf("decrypted %q, want %q", result.Plaintext, plaintext)
			}
		})
	}
}

// TestMaskingAgreesAcrossLanguages guards a promise that is easy to break
// silently: an application that reads a value through this service and an
// application that reads it through its own SDK must show the same thing.
func TestMaskingAgreesAcrossLanguages(t *testing.T) {
	svc := newService(t)

	ours := svc.Mask(plaintext)
	if ours != masked {
		t.Fatalf("the service masks to %q, want %q", ours, masked)
	}

	if dist, ok := sdkPath("panda-node", "dist", "index.js"); ok {
		out, err := run(t, "node", "-e", `
const { FieldCipher, LocalKeyProvider } = require(`+jsString(dist)+`);
(async () => {
  const c = new FieldCipher(new LocalKeyProvider());
  const env = await c.encrypt(`+jsString(plaintext)+`, `+jsString(kid)+`);
  process.stdout.write(String(await c.decrypt(env)));
})().catch(e => { console.error(e.message); process.exit(1); });
`)
		if err == nil && out != ours {
			t.Errorf("node masks to %q, the service to %q", out, ours)
		}
	}
}

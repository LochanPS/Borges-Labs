// Command authz-verify checks an Ed25519 decision signature independently of the
// signing service (ROADMAP Task 1.5). It takes a Decision (JSON) and a public key
// source — a JWKS file, a JWKS URL (e.g. https://host/v1/keys/public), or a raw
// base64url key — and prints valid / invalid.
//
//	authz-verify -decision dec.json -jwks-url http://localhost:8080/v1/keys/public
//	authz-verify -decision dec.json -jwks keys.json
//	cat dec.json | authz-verify -pubkey <base64url-ed25519-pubkey>
//
// Exit 0 = valid, 1 = invalid/error. Uses only public information, exactly as a
// customer, auditor, or regulator would.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/trust-infra/authorize-svc/internal/signing"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

func main() {
	decisionPath := flag.String("decision", "-", "path to the Decision JSON (\"-\" = stdin)")
	jwksPath := flag.String("jwks", "", "path to a JWKS JSON file")
	jwksURL := flag.String("jwks-url", "", "URL of the JWKS endpoint (e.g. .../v1/keys/public)")
	pubKeyB64 := flag.String("pubkey", "", "raw base64url Ed25519 public key")
	flag.Parse()

	if err := run(*decisionPath, *jwksPath, *jwksURL, *pubKeyB64); err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("VALID: signature verified.")
}

func run(decisionPath, jwksPath, jwksURL, pubKeyB64 string) error {
	dec, err := loadDecision(decisionPath)
	if err != nil {
		return err
	}

	pub, err := resolveKey(dec.Signature.KeyID, jwksPath, jwksURL, pubKeyB64)
	if err != nil {
		return err
	}
	return signing.Verify(dec, pub)
}

func loadDecision(path string) (contractsv1.Decision, error) {
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return contractsv1.Decision{}, fmt.Errorf("read decision: %w", err)
	}
	var dec contractsv1.Decision
	if err := json.Unmarshal(raw, &dec); err != nil {
		return contractsv1.Decision{}, fmt.Errorf("parse decision: %w", err)
	}
	return dec, nil
}

// resolveKey finds the public key to verify with, in priority: explicit -pubkey,
// then a JWKS file, then a JWKS URL (matching the decision's key id).
func resolveKey(keyID, jwksPath, jwksURL, pubKeyB64 string) (ed25519.PublicKey, error) {
	if pubKeyB64 != "" {
		raw, err := base64.RawURLEncoding.DecodeString(pubKeyB64)
		if err != nil {
			return nil, fmt.Errorf("decode -pubkey: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("-pubkey is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(raw), nil
	}

	var set signing.JWKS
	switch {
	case jwksPath != "":
		b, err := os.ReadFile(jwksPath)
		if err != nil {
			return nil, fmt.Errorf("read jwks: %w", err)
		}
		if err := json.Unmarshal(b, &set); err != nil {
			return nil, fmt.Errorf("parse jwks: %w", err)
		}
	case jwksURL != "":
		resp, err := http.Get(jwksURL)
		if err != nil {
			return nil, fmt.Errorf("fetch jwks: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
			return nil, fmt.Errorf("parse jwks: %w", err)
		}
	default:
		return nil, fmt.Errorf("provide one of -pubkey, -jwks, or -jwks-url")
	}

	for _, j := range set.Keys {
		if j.Kid == keyID {
			return signing.PublicKeyFromJWK(j)
		}
	}
	return nil, fmt.Errorf("no key with id %q in the key set", keyID)
}

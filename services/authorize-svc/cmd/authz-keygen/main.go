// Command authz-keygen mints an API key for the decision plane (TRD §11).
//
// It prints the plaintext key EXACTLY ONCE (it is never recoverable afterward —
// only sha256(key) is stored) and the record to persist. With -insert and a
// DATABASE_URL it writes the record straight into the api_keys table; otherwise it
// prints a ready-to-run INSERT.
//
//	go run ./cmd/authz-keygen -env test -org org_demo -tier default
//	go run ./cmd/authz-keygen -env live -org org_demo -tier pro -insert
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/trust-infra/authorize-svc/internal/auth"
	"github.com/trust-infra/authorize-svc/internal/store"
)

func main() {
	env := flag.String("env", auth.EnvTest, "key environment: live|test")
	org := flag.String("org", "", "org id the key belongs to (required)")
	tier := flag.String("tier", "default", "tier id (drives rate limits)")
	insert := flag.Bool("insert", false, "insert into api_keys using DATABASE_URL")
	flag.Parse()

	if *org == "" {
		fmt.Fprintln(os.Stderr, "error: -org is required")
		os.Exit(2)
	}

	gk, err := auth.NewKey(*env, *org, *tier)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// The plaintext is shown once; everything else stores only the hash.
	fmt.Println("API KEY (store securely — shown only once):")
	fmt.Println("  " + gk.Plaintext)
	fmt.Println()
	fmt.Printf("key_id:     %s\n", gk.Record.KeyID)
	fmt.Printf("key_sha256: %s\n", gk.Record.KeyHashHex)
	fmt.Printf("org_id:     %s\n", gk.Record.OrgID)
	fmt.Printf("tier:       %s\n", gk.Record.Tier)
	fmt.Printf("env:        %s\n", gk.Record.Env)
	fmt.Println()

	if !*insert {
		fmt.Println("-- persist with:")
		fmt.Printf("INSERT INTO api_keys (key_id, key_sha256, org_id, tier, env, status)\n")
		fmt.Printf("VALUES ('%s', '%s', '%s', '%s', '%s', 'active');\n",
			gk.Record.KeyID, gk.Record.KeyHashHex, gk.Record.OrgID, gk.Record.Tier, gk.Record.Env)
		return
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "error: -insert requires DATABASE_URL")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pg, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: connect: %v\n", err)
		os.Exit(1)
	}
	defer pg.Close()
	if err := auth.NewPostgresKeyStore(pg.Pool).Insert(ctx, gk.Record); err != nil {
		fmt.Fprintf(os.Stderr, "error: insert: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("inserted into api_keys.")
}

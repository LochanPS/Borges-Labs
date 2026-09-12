// Package budget is the stateful budget accumulator (ROADMAP A#3, Task 3.2). It lives
// OUTSIDE the local decision engine: the engine calls a Reserver only after the local
// rules approve, and folds the WITHIN_LIMIT / EXCEEDED / UNAVAILABLE result into the
// verdict.
//
// No oversell. A hard budget cap requires a central atomic op (TRD §17): the reserve is
// a single Redis check-and-increment (Lua), so N concurrent authorizations against one
// cap can never total more than the limit — the cost is one central round trip per
// budget-affecting decision, which we accept for hard caps.
//
// Source of truth + reconciliation. The Redis counter is the fast hot-path gate; the
// durable record is the reservation ledger (internal/hold, Postgres). A TTL-expired
// hold releases its counter via the Reconciler (holds are the source of truth for what
// is outstanding); a drifted counter is rebuilt from the ledger. If Redis is
// unavailable the reserve returns UNAVAILABLE and the engine fails closed to REVIEW —
// never a fabricated within-limit (§21).
//
// Money is handled in integer minor units (cents, 2 decimal places) so the counter is
// an exact integer INCRBY. Amounts with more than 2 fractional digits are rejected.
package budget

import (
	"strconv"
	"strings"
	"time"
)

// counterKey is the Redis key for one budget window: budget:<org>:<budget_id>:<window_key>.
func counterKey(orgID, budgetID, windowKey string) string {
	return "budget:" + orgID + ":" + budgetID + ":" + windowKey
}

// WindowKey is the concrete accumulation period a reservation counts against, derived
// deterministically from the (injected) evaluation time. A new period yields a new key,
// so a window rollover naturally starts a fresh counter.
//   - day     → YYYY-MM-DD (UTC)
//   - month   → YYYY-MM (UTC)
//   - rolling → "rolling" (a single bucket with a sliding TTL ≈ the rolling length)
func WindowKey(window string, t time.Time) string {
	u := t.UTC()
	switch window {
	case "day":
		return u.Format("2006-01-02")
	case "rolling":
		return "rolling"
	default: // month (and any unknown → treat as month)
		return u.Format("2006-01")
	}
}

// windowTTL is how long a window's counter lives. Calendar windows get a grace beyond
// the period so late captures and rollover are safe; rolling slides.
func windowTTL(window string) time.Duration {
	switch window {
	case "day":
		return 48 * time.Hour
	case "rolling":
		return 30 * 24 * time.Hour
	default: // month
		return 32 * 24 * time.Hour // per ROADMAP §3.2
	}
}

// windowSticky reports whether the TTL is set once at creation (calendar windows) vs
// refreshed on every reserve (a sliding rolling window).
func windowSticky(window string) bool { return window != "rolling" }

// toCents parses a canonical non-negative decimal string into integer minor units
// (2 dp). Amounts with more than two fractional digits are rejected (ok=false), so the
// counter arithmetic stays exact.
func toCents(s string) (int64, bool) {
	if s == "" || strings.HasPrefix(s, "-") {
		return 0, false
	}
	intPart, frac, hasDot := strings.Cut(s, ".")
	whole, err := strconv.ParseInt(intPart, 10, 64)
	if err != nil {
		return 0, false
	}
	cents := whole * 100
	if hasDot {
		if len(frac) == 0 || len(frac) > 2 {
			return 0, false
		}
		if len(frac) == 1 {
			frac += "0"
		}
		f, err := strconv.ParseInt(frac, 10, 64)
		if err != nil {
			return 0, false
		}
		cents += f
	}
	return cents, true
}

// centsToStr renders minor units back to a canonical 2-dp decimal string.
func centsToStr(c int64) string {
	return strconv.FormatInt(c/100, 10) + "." + pad2(c%100)
}

func pad2(n int64) string {
	if n < 10 {
		return "0" + strconv.FormatInt(n, 10)
	}
	return strconv.FormatInt(n, 10)
}

package auth

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ayanasarkar/vapt-agent/internal/audit"
)

// Vectors from RFC 7914 section 11 (PBKDF2-HMAC-SHA-256), cross-checked against Python's hashlib.pbkdf2_hmac.
func TestPBKDF2Vectors(t *testing.T) {
	cases := []struct {
		pw, salt string
		iter     int
		want     string
	}{
		{"passwd", "salt", 1, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
		{"Password", "NaCl", 80000, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(pbkdf2([]byte(c.pw), []byte(c.salt), c.iter, 64)); got != c.want {
			t.Errorf("pbkdf2(%q,%q,%d) = %s", c.pw, c.salt, c.iter, got)
		}
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func open(t *testing.T) (*Store, *clock, string) {
	t.Helper()
	dir := t.TempDir()
	ck := &clock{t: time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)}
	s, err := Open(dir, Options{Iterations: 1000, Now: ck.now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, ck, dir
}

const pw = "correct horse battery"

func admin(t *testing.T, s *Store) Principal {
	t.Helper()
	if _, err := s.Setup("ayana", "Ayana", pw); err != nil {
		t.Fatal(err)
	}
	_, p, err := s.Login("ayana", pw, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSetupOnceAndPolicy(t *testing.T) {
	s, _, _ := open(t)
	if s.HasUsers() {
		t.Fatal("fresh store has users")
	}
	for _, bad := range []struct{ n, p string }{
		{"ab", pw}, {"Has Space", pw}, {"ayana", "short"}, {"ayana", "aaaaaaaaaaaa"}, {"ayana", "password123"}, {"ayana", "my-ayana-secret-1"}, {"ayana", strings.Repeat("x", 300)},
	} {
		var pe PolicyError
		if _, err := s.Setup(bad.n, "", bad.p); !errors.As(err, &pe) {
			t.Errorf("Setup(%q,%q) = %v, want a policy error", bad.n, bad.p, err)
		}
	}
	if s.HasUsers() {
		t.Fatal("a refused setup must not create an account")
	}
	u, err := s.Setup("Ayana ", "Ayana S", pw) // name is trimmed and lower-cased
	if err != nil || u.Name != "ayana" || u.Role != Admin {
		t.Fatalf("setup: %+v %v", u, err)
	}
	if _, err := s.Setup("second", "", pw); !errors.Is(err, ErrSetupDone) {
		t.Errorf("second setup must be refused, got %v", err)
	}
}

func TestLoginGenericErrorAndSession(t *testing.T) {
	s, _, _ := open(t)
	admin(t, s)
	_, _, e1 := s.Login("ayana", "wrong password here", "1.1.1.1")
	_, _, e2 := s.Login("nobody", "wrong password here", "1.1.1.1")
	if !errors.Is(e1, ErrBadLogin) || !errors.Is(e2, ErrBadLogin) || e1.Error() != e2.Error() {
		t.Errorf("wrong password and unknown user must look identical: %v / %v", e1, e2)
	}
	tok, p, err := s.Login(" AYANA", pw, "1.1.1.1")
	if err != nil || p.Name != "ayana" || p.Role != Admin || len(tok) < 40 {
		t.Fatalf("login: %v %v %q", p, err, tok)
	}
	if got, ok := s.Lookup(tok); !ok || got.Name != "ayana" {
		t.Errorf("lookup: %v %v", got, ok)
	}
	if _, ok := s.Lookup(tok + "x"); ok {
		t.Error("a different token must not match")
	}
	for k := range s.sess {
		if k == tok {
			t.Error("the raw token must not be the key it is stored under")
		}
	}
	s.Logout(tok)
	if _, ok := s.Lookup(tok); ok {
		t.Error("a logged-out token must stop working")
	}
}

func TestSessionExpiry(t *testing.T) {
	s, ck, _ := open(t)
	admin(t, s)
	tok, _, _ := s.Login("ayana", pw, "x")
	ck.add(90 * time.Minute)
	if _, ok := s.Lookup(tok); !ok {
		t.Fatal("session within the idle window must be valid")
	}
	ck.add(90 * time.Minute) // 90 min since last use: still inside the 2h idle window
	if _, ok := s.Lookup(tok); !ok {
		t.Fatal("use must slide the idle timer")
	}
	ck.add(121 * time.Minute)
	if _, ok := s.Lookup(tok); ok {
		t.Error("an idle session must expire")
	}
	tok2, _, _ := s.Login("ayana", pw, "x")
	for i := 0; i < 8; i++ { // keep it busy for 13 hours; the absolute limit still ends it
		ck.add(100 * time.Minute)
		if _, ok := s.Lookup(tok2); !ok && i < 6 {
			t.Fatalf("expired early at step %d", i)
		}
	}
	if _, ok := s.Lookup(tok2); ok {
		t.Error("a session older than the absolute limit must end however active it is")
	}
}

func TestLockoutAndRecovery(t *testing.T) {
	s, ck, _ := open(t)
	admin(t, s)
	for i := 0; i < 5; i++ {
		s.Login("ayana", "bad bad bad bad", "9.9.9.9")
	}
	_, _, err := s.Login("ayana", pw, "9.9.9.9") // even the right password is refused while locked
	var le *LockedError
	if !errors.As(err, &le) || le.Wait <= 0 {
		t.Fatalf("want LockedError, got %v", err)
	}
	// an unknown name is limited the same way, so the lock does not reveal which names exist
	for i := 0; i < 5; i++ {
		s.Login("ghost", "bad bad bad bad", "8.8.8.8")
	}
	if _, _, err := s.Login("ghost", "bad bad bad bad", "8.8.8.8"); !errors.As(err, &le) {
		t.Errorf("unknown names must lock too, got %v", err)
	}
	ck.add(20 * time.Second)
	if _, _, err := s.Login("ayana", pw, "9.9.9.9"); err != nil {
		t.Errorf("after the back-off the right password must work: %v", err)
	}
}

func TestChangePasswordKeepsThisSessionEndsOthers(t *testing.T) {
	s, _, _ := open(t)
	admin(t, s)
	a, _, _ := s.Login("ayana", pw, "x")
	b, _, _ := s.Login("ayana", pw, "x")
	if err := s.ChangePassword("ayana", a, "not the password", "another long secret"); err == nil {
		t.Error("a wrong current password must be refused")
	}
	if err := s.ChangePassword("ayana", a, pw, "short"); err == nil {
		t.Error("a weak new password must be refused")
	}
	if err := s.ChangePassword("ayana", a, pw, "another long secret"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(a); !ok {
		t.Error("the session that changed the password stays")
	}
	if _, ok := s.Lookup(b); ok {
		t.Error("other sessions must end when the password changes")
	}
	if _, _, err := s.Login("ayana", pw, "x"); err == nil {
		t.Error("the old password must stop working")
	}
	if _, _, err := s.Login("ayana", "another long secret", "x"); err != nil {
		t.Errorf("the new password must work: %v", err)
	}
}

func TestRolesAndAccountManagement(t *testing.T) {
	s, _, _ := open(t)
	adm := admin(t, s)
	if _, err := s.AddUser(adm, "sam", "Sam", "violet orchid lantern", Analyst); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddUser(adm, "sam", "", "another long passphrase", Analyst); err == nil {
		t.Error("duplicate username must be refused")
	}
	if _, err := s.AddUser(adm, "kim", "", "amber delta signal", "root"); err == nil {
		t.Error("unknown role must be refused")
	}
	_, sam, err := s.Login("sam", "violet orchid lantern", "x")
	if err != nil || sam.Role != Analyst {
		t.Fatalf("%v %v", sam, err)
	}
	if _, err := s.List(sam); !errors.Is(err, ErrForbidden) {
		t.Errorf("an analyst must not list accounts: %v", err)
	}
	if _, err := s.AddUser(sam, "eve", "", "cobalt river anchor", Admin); !errors.Is(err, ErrForbidden) {
		t.Errorf("an analyst must not create accounts: %v", err)
	}
	if err := s.SetDisabled(adm, "ayana", true); err == nil {
		t.Error("an administrator must not disable themself")
	}
	if err := s.SetDisabled(adm, "sam", true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Login("sam", "violet orchid lantern", "x"); err == nil {
		t.Error("a disabled account must not sign in")
	}
	if err := s.SetDisabled(adm, "sam", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddUser(adm, "root2", "", "granite meadow harbour", Admin); err != nil {
		t.Fatal(err)
	}
	// with a second admin in place, the first may be disabled by the second but never the last one
	_, r2, _ := s.Login("root2", "granite meadow harbour", "x")
	if err := s.SetDisabled(r2, "ayana", true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisabled(r2, "root2", true); err == nil {
		t.Error("disabling yourself must still be refused")
	}
}

func TestDisableAndResetEndSessions(t *testing.T) {
	s, _, _ := open(t)
	adm := admin(t, s)
	s.AddUser(adm, "sam", "", "violet orchid lantern", Viewer)
	tok, _, _ := s.Login("sam", "violet orchid lantern", "x")
	if err := s.ResetPassword(adm, "sam", "brand new long phrase"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(tok); ok {
		t.Error("a password reset must end that account's sessions")
	}
	tok, _, _ = s.Login("sam", "brand new long phrase", "x")
	s.SetDisabled(adm, "sam", true)
	if _, ok := s.Lookup(tok); ok {
		t.Error("disabling must end the account's sessions at once")
	}
}

func TestPersistenceAndFilePermissions(t *testing.T) {
	ck := &clock{t: time.Now()}
	dir := t.TempDir()

	s, err := Open(dir, Options{Iterations: 1000, Now: ck.now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.Setup("ayana", "", pw); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), pw) || !strings.Contains(string(b), "pbkdf2-sha256$1000$") {
		t.Errorf("users.json must hold a salted hash only: %s", b)
	}

	if runtime.GOOS != "windows" {
		st, statErr := os.Stat(filepath.Join(dir, "users.json"))
		if statErr != nil {
			t.Fatal(statErr)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("users.json mode %v, want 0600", st.Mode().Perm())
		}
	}

	if err := s.Close(); err != nil {
		t.Fatalf("close first store: %v", err)
	}

	s2, err := Open(dir, Options{Iterations: 1000, Now: ck.now})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })

	if !s2.HasUsers() {
		t.Fatal("reopened store has no users")
	}
	if _, _, err := s2.Login("ayana", pw, "x"); err != nil {
		t.Errorf("login after reopen: %v", err)
	}

	if err := s2.Close(); err != nil {
		t.Fatalf("close reopened store: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "users.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, Options{Iterations: 1000}); err == nil {
		t.Error("a corrupt users.json must stop start-up")
	}
}
func TestProductionCostAndHashUpgrade(t *testing.T) {
	dir := t.TempDir()

	cheap, err := Open(dir, Options{Iterations: 1000})
	if err != nil {
		t.Fatal(err)
	}
	cheap.Setup("ayana", "", pw)

	if err := cheap.Close(); err != nil {
		t.Fatal(err)
	}

	prod, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = prod.Close() })

	if _, _, err := prod.Login("ayana", pw, "x"); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "pbkdf2-sha256$600000$") {
		t.Errorf("a login must upgrade an old hash to the current cost: %s", b)
	}
}

func TestAuditChainHoldsNoSecrets(t *testing.T) {
	s, _, dir := open(t)
	adm := admin(t, s)
	s.Login("ayana", "wrong password!!", "1.2.3.4")
	tok, _, _ := s.Login("ayana", pw, "1.2.3.4")
	s.AddUser(adm, "sam", "", "violet orchid lantern", Viewer)
	s.Logout(tok)
	es := s.Audit().Entries()
	if err := audit.VerifyEntries(es); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "auth-audit.jsonl"))
	for _, secret := range []string{pw, "wrong password!!", "violet orchid lantern", tok, "pbkdf2"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the audit log must never contain %q", secret)
		}
	}
	seen := map[string]bool{}
	for _, e := range es {
		seen[e.Type] = true
	}
	for _, want := range []string{"account_created", "login_failed", "login_ok", "logout"} {
		if !seen[want] {
			t.Errorf("audit is missing a %q entry: %v", want, seen)
		}
	}
}

func TestConcurrentUse(t *testing.T) {
	s, _, _ := open(t)
	admin(t, s)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if tok, _, err := s.Login("ayana", pw, "x"); err == nil {
					s.Lookup(tok)
					s.Logout(tok)
				}
				s.Login("ayana", "bad bad bad bad", "y")
			}
		}()
	}
	wg.Wait()
}

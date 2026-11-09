// Package auth is KAVACH's own sign-in: local accounts, salted PBKDF2-SHA256 password hashes, server-side
// sessions, brute-force back-off and a hash-chained audit trail of account events. Standard library only.
//
// It answers two questions and nothing else: who is this person, and which role do they hold. It never decides
// what may be tested. Scope stays with internal/scope, and signing in grants no targets.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ayanasarkar/vapt-agent/internal/audit"
)

// Role is what an account may do. Viewers read and ask questions; analysts also run, approve and deny; admins also manage accounts.
type Role string

const (
	Admin   Role = "admin"
	Analyst Role = "analyst"
	Viewer  Role = "viewer"
)

func (r Role) valid() bool { return r == Admin || r == Analyst || r == Viewer }

// User is one stored account. Hash is never sent to a browser.
type User struct {
	Name      string    `json:"name"`
	Display   string    `json:"display,omitempty"`
	Role      Role      `json:"role"`
	Hash      string    `json:"hash"`
	Created   time.Time `json:"created"`
	LastLogin time.Time `json:"last_login,omitempty"`
	Disabled  bool      `json:"disabled,omitempty"`
}

// Public is the part of an account that may leave the server.
type Public struct {
	Name      string    `json:"name"`
	Display   string    `json:"display"`
	Role      Role      `json:"role"`
	Created   time.Time `json:"created"`
	LastLogin time.Time `json:"last_login,omitempty"`
	Disabled  bool      `json:"disabled"`
}

// Principal is who a valid session belongs to.
type Principal struct {
	Name    string    `json:"name"`
	Display string    `json:"display"`
	Role    Role      `json:"role"`
	Expires time.Time `json:"expires"`
}

// Options tune the store. The zero value is the production setting.
type Options struct {
	Iterations int           // PBKDF2 cost; 0 means 600000 (the OWASP figure for PBKDF2-HMAC-SHA256)
	Absolute   time.Duration // longest a session may live; 0 means 12h
	Idle       time.Duration // longest a session may sit unused; 0 means 2h
	Now        func() time.Time
}

// Errors the HTTP layer maps to status codes.
var (
	ErrBadLogin  = errors.New("incorrect username or password")
	ErrSetupDone = errors.New("an administrator already exists")
	ErrForbidden = errors.New("this action needs an administrator")
	ErrNoUser    = errors.New("no such account")
)

// PolicyError is a refused name or password, with a message that is safe to show.
type PolicyError string

func (e PolicyError) Error() string { return string(e) }

// LockedError says sign-in is paused after repeated failures.
type LockedError struct{ Wait time.Duration }

func (e *LockedError) Error() string {
	return fmt.Sprintf("too many failed attempts; try again in %d seconds", int(e.Wait.Seconds())+1)
}

type session struct {
	user          string
	created, last time.Time
}

type failure struct {
	n     int
	until time.Time
	last  time.Time
}

// Store holds accounts on disk and sessions in memory (a restart signs everyone out).
type Store struct {
	mu    sync.Mutex
	path  string
	users map[string]*User
	sess  map[string]*session // key: sha256 of the token, so memory never holds a usable token
	fails map[string]*failure
	log   *audit.Log
	opt   Options
	dummy string // a real hash that unknown usernames are checked against, so timing does not reveal which names exist
}

const (
	defaultIter    = 600_000
	maxStoredIter  = 5_000_000
	userThreshold  = 5
	ipThreshold    = 25
	maxSessionsPer = 10
	minPassword    = 10
	maxPassword    = 256
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)

// Open loads (or starts) the account store under dir. dir is created 0700; users.json is written 0600.
func Open(dir string, opt Options) (*Store, error) {
	if opt.Iterations <= 0 {
		opt.Iterations = defaultIter
	}
	if opt.Absolute <= 0 {
		opt.Absolute = 12 * time.Hour
	}
	if opt.Idle <= 0 {
		opt.Idle = 2 * time.Hour
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lg, err := audit.Open(filepath.Join(dir, "auth-audit.jsonl"))
	if err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "users.json"), users: map[string]*User{}, sess: map[string]*session{}, fails: map[string]*failure{}, log: lg, opt: opt}
	if b, err := os.ReadFile(s.path); err == nil {
		var f struct {
			Users []*User `json:"users"`
		}
		if err := json.Unmarshal(b, &f); err != nil {
			_ = lg.Close()
			return nil, fmt.Errorf("users.json is unreadable: %w", err)
		}
		for _, u := range f.Users {
			if u != nil && nameRe.MatchString(u.Name) && u.Role.valid() {
				s.users[u.Name] = u
			}
		}
	} else if !os.IsNotExist(err) {
		_ = lg.Close()
		return nil, err
	}
	s.dummy = s.hash("kavach-timing-equaliser")
	return s, nil
}

// Close releases the audit log owned by this store.
func (s *Store) Close() error {
	if s == nil || s.log == nil {
		return nil
	}
	return s.log.Close()
}

// HasUsers reports whether any account exists. While none does, the console offers first-run setup.
func (s *Store) HasUsers() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.users) > 0
}

// Audit exposes the account-event log so it can be shown to administrators and re-verified.
func (s *Store) Audit() *audit.Log { return s.log }

// NormName lower-cases and trims a login name.
func NormName(n string) string { return strings.ToLower(strings.TrimSpace(n)) }

// CheckName and CheckPassword are the rules shown to the person creating an account.
func CheckName(n string) error {
	if !nameRe.MatchString(n) {
		return PolicyError("username: 3 to 32 characters, lower-case letters, digits, dot, dash or underscore, starting with a letter or digit")
	}
	return nil
}

var commonRoots = map[string]bool{"password": true, "passw0rd": true, "qwertyuiop": true, "letmein": true, "welcome": true, "administrator": true,
	"hackathon": true, "iloveyou": true, "1234567890": true, "0123456789": true, "kavach": true, "changeme": true}

func CheckPassword(name, pw string) error {
	if utf8.RuneCountInString(pw) < minPassword {
		return PolicyError(fmt.Sprintf("password: use at least %d characters", minPassword))
	}
	if len(pw) > maxPassword {
		return PolicyError(fmt.Sprintf("password: at most %d bytes", maxPassword))
	}
	low := strings.ToLower(pw)
	if len(name) >= 3 && strings.Contains(low, name) {
		return PolicyError("password: must not contain the username")
	}
	if strings.Trim(low, string([]rune(low)[:1])) == "" {
		return PolicyError("password: must not be one repeated character")
	}
	if commonRoots[strings.TrimRight(low, "0123456789!@#$%^&*._-")] || commonRoots[low] {
		return PolicyError("password: too common, pick something longer and less guessable")
	}
	return nil
}

// hash returns "pbkdf2-sha256$<iterations>$<salt>$<key>".
func (s *Store) hash(pw string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic("auth: no randomness: " + err.Error())
	}
	key := pbkdf2([]byte(pw), salt, s.opt.Iterations, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", s.opt.Iterations, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// verify checks pw against a stored hash in constant time and says whether the hash should be upgraded to the current cost.
func (s *Store) verify(stored, pw string) (ok, upgrade bool) {
	p := strings.Split(stored, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false, false
	}
	iter, err := strconv.Atoi(p[1])
	if err != nil || iter < 1 || iter > maxStoredIter {
		return false, false
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(p[2])
	want, e2 := base64.RawStdEncoding.DecodeString(p[3])
	if e1 != nil || e2 != nil || len(want) == 0 {
		return false, false
	}
	got := pbkdf2([]byte(pw), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1, iter < s.opt.Iterations
}

func (s *Store) saveLocked() error {
	list := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	b, err := json.MarshalIndent(map[string]any{"users": list}, "", " ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n])
	}
	return s
}

func (s *Store) principal(u *User, exp time.Time) Principal {
	d := u.Display
	if d == "" {
		d = u.Name
	}
	return Principal{Name: u.Name, Display: d, Role: u.Role, Expires: exp}
}

// Setup creates the first account, always an administrator, and only while no account exists.
func (s *Store) Setup(name, display, pw string) (Public, error) {
	name = NormName(name)
	if err := CheckName(name); err != nil {
		return Public{}, err
	}
	if err := CheckPassword(name, pw); err != nil {
		return Public{}, err
	}
	h := s.hash(pw)
	s.mu.Lock()
	if len(s.users) > 0 {
		s.mu.Unlock()
		return Public{}, ErrSetupDone
	}
	u := &User{Name: name, Display: clean(display, 40), Role: Admin, Hash: h, Created: s.opt.Now().UTC()}
	s.users[name] = u
	if err := s.saveLocked(); err != nil {
		delete(s.users, name)
		s.mu.Unlock()
		return Public{}, err
	}
	pub := pubOf(u)
	s.mu.Unlock()
	s.log.Append(name, "account_created", "first administrator account created", map[string]string{"role": string(Admin)})
	return pub, nil
}

func pubOf(u *User) Public {
	d := u.Display
	if d == "" {
		d = u.Name
	}
	return Public{Name: u.Name, Display: d, Role: u.Role, Created: u.Created, LastLogin: u.LastLogin, Disabled: u.Disabled}
}

func (s *Store) lockedLocked(keys ...string) time.Duration {
	now := s.opt.Now()
	var wait time.Duration
	for _, k := range keys {
		if f := s.fails[k]; f != nil && f.until.After(now) && f.until.Sub(now) > wait {
			wait = f.until.Sub(now)
		}
	}
	return wait
}

func (s *Store) failLocked(threshold int, k string) {
	now := s.opt.Now()
	f := s.fails[k]
	if f == nil {
		f = &failure{}
		s.fails[k] = f
	}
	if now.Sub(f.last) > 15*time.Minute { // old failures fade
		f.n = 0
	}
	f.n++
	f.last = now
	if f.n >= threshold {
		d := 15 * time.Second << uint(min(f.n-threshold, 6)) // 15s, 30s, ... capped at 16 minutes
		f.until = now.Add(d)
	}
	if len(s.fails) > 5000 {
		for key, v := range s.fails {
			if now.Sub(v.last) > time.Hour || v.n < threshold {
				delete(s.fails, key)
			}
		}
	}
}

// Login checks a password and starts a session. Unknown names, wrong passwords and disabled accounts all return the same
// error after the same amount of work. ip is only used to rate-limit and to label the audit entry.
func (s *Store) Login(name, pw, ip string) (string, Principal, error) {
	name = NormName(name)
	uk, ik := "u:"+name, "ip:"+ip
	s.mu.Lock()
	if w := s.lockedLocked(uk, ik); w > 0 {
		s.mu.Unlock()
		s.log.Append(clean(name, 40), "login_blocked", "sign-in refused while locked after repeated failures", map[string]string{"ip": clean(ip, 45)})
		return "", Principal{}, &LockedError{w}
	}
	u := s.users[name]
	hash, disabled := s.dummy, true
	if u != nil {
		hash, disabled = u.Hash, u.Disabled
	}
	s.mu.Unlock()

	ok, upgrade := s.verify(hash, pw)
	if !ok || disabled || u == nil {
		reason := "wrong password"
		if u == nil {
			reason = "unknown user"
		} else if disabled && ok {
			reason = "account disabled"
		}
		s.mu.Lock()
		s.failLocked(userThreshold, uk)
		s.failLocked(ipThreshold, ik)
		s.mu.Unlock()
		s.log.Append(clean(name, 40), "login_failed", "sign-in failed", map[string]string{"reason": reason, "ip": clean(ip, 45)})
		return "", Principal{}, ErrBadLogin
	}
	var newHash string
	if upgrade {
		newHash = s.hash(pw)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", Principal{}, err
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	now := s.opt.Now()
	s.mu.Lock()
	u = s.users[name]
	if u == nil || u.Disabled { // changed while we were hashing
		s.mu.Unlock()
		return "", Principal{}, ErrBadLogin
	}
	if newHash != "" {
		u.Hash = newHash
	}
	u.LastLogin = now.UTC()
	delete(s.fails, uk)
	s.sweepLocked(now)
	s.capSessionsLocked(name)
	s.sess[tokenKey(tok)] = &session{user: name, created: now, last: now}
	_ = s.saveLocked()
	p := s.principal(u, now.Add(s.opt.Absolute))
	s.mu.Unlock()
	s.log.Append(name, "login_ok", "signed in", map[string]string{"role": string(p.Role), "ip": clean(ip, 45)})
	return tok, p, nil
}

func tokenKey(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func (s *Store) sweepLocked(now time.Time) {
	for k, se := range s.sess {
		if now.Sub(se.created) > s.opt.Absolute || now.Sub(se.last) > s.opt.Idle {
			delete(s.sess, k)
		}
	}
}

func (s *Store) capSessionsLocked(name string) {
	var mine []string
	for k, se := range s.sess {
		if se.user == name {
			mine = append(mine, k)
		}
	}
	if len(mine) < maxSessionsPer {
		return
	}
	sort.Slice(mine, func(i, j int) bool { return s.sess[mine[i]].last.Before(s.sess[mine[j]].last) })
	for _, k := range mine[:len(mine)-maxSessionsPer+1] {
		delete(s.sess, k)
	}
}

// Lookup returns the owner of a valid session and slides its idle timer. It is called on every API request.
func (s *Store) Lookup(tok string) (Principal, bool) {
	if tok == "" || len(tok) > 128 {
		return Principal{}, false
	}
	k := tokenKey(tok)
	now := s.opt.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	se := s.sess[k]
	if se == nil {
		return Principal{}, false
	}
	u := s.users[se.user]
	if now.Sub(se.created) > s.opt.Absolute || now.Sub(se.last) > s.opt.Idle || u == nil || u.Disabled {
		delete(s.sess, k)
		return Principal{}, false
	}
	se.last = now
	exp := se.created.Add(s.opt.Absolute)
	if i := now.Add(s.opt.Idle); i.Before(exp) {
		exp = i
	}
	return s.principal(u, exp), true
}

// Logout ends one session.
func (s *Store) Logout(tok string) {
	k := tokenKey(tok)
	s.mu.Lock()
	se := s.sess[k]
	delete(s.sess, k)
	s.mu.Unlock()
	if se != nil {
		s.log.Append(se.user, "logout", "signed out", nil)
	}
}

func (s *Store) revokeLocked(name, keep string) {
	for k, se := range s.sess {
		if se.user == name && k != keep {
			delete(s.sess, k)
		}
	}
}

// ChangePassword sets a new password after checking the old one, and signs the account out everywhere else.
func (s *Store) ChangePassword(name, keepTok, oldPW, newPW string) error {
	name = NormName(name)
	if err := CheckPassword(name, newPW); err != nil {
		return err
	}
	uk := "u:" + name
	s.mu.Lock()
	if w := s.lockedLocked(uk); w > 0 {
		s.mu.Unlock()
		return &LockedError{w}
	}
	u := s.users[name]
	if u == nil {
		s.mu.Unlock()
		return ErrNoUser
	}
	cur := u.Hash
	s.mu.Unlock()
	if ok, _ := s.verify(cur, oldPW); !ok {
		s.mu.Lock()
		s.failLocked(userThreshold, uk)
		s.mu.Unlock()
		s.log.Append(name, "password_change_failed", "current password was wrong", nil)
		return PolicyError("the current password is not right")
	}
	h := s.hash(newPW)
	s.mu.Lock()
	if u = s.users[name]; u == nil {
		s.mu.Unlock()
		return ErrNoUser
	}
	u.Hash = h
	delete(s.fails, uk)
	s.revokeLocked(name, tokenKey(keepTok))
	err := s.saveLocked()
	s.mu.Unlock()
	if err == nil {
		s.log.Append(name, "password_changed", "password changed; other sessions ended", nil)
	}
	return err
}

func (s *Store) adminOnly(actor Principal) error {
	if actor.Role != Admin {
		return ErrForbidden
	}
	return nil
}

// List returns every account for an administrator.
func (s *Store) List(actor Principal) ([]Public, error) {
	if err := s.adminOnly(actor); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Public, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, pubOf(u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// AddUser lets an administrator create an account.
func (s *Store) AddUser(actor Principal, name, display, pw string, role Role) (Public, error) {
	if err := s.adminOnly(actor); err != nil {
		return Public{}, err
	}
	name = NormName(name)
	if err := CheckName(name); err != nil {
		return Public{}, err
	}
	if !role.valid() {
		return Public{}, PolicyError("role must be admin, analyst or viewer")
	}
	if err := CheckPassword(name, pw); err != nil {
		return Public{}, err
	}
	h := s.hash(pw)
	s.mu.Lock()
	if _, dup := s.users[name]; dup {
		s.mu.Unlock()
		return Public{}, PolicyError("that username is taken")
	}
	u := &User{Name: name, Display: clean(display, 40), Role: role, Hash: h, Created: s.opt.Now().UTC()}
	s.users[name] = u
	if err := s.saveLocked(); err != nil {
		delete(s.users, name)
		s.mu.Unlock()
		return Public{}, err
	}
	pub := pubOf(u)
	s.mu.Unlock()
	s.log.Append(actor.Name, "account_created", "account created for "+name, map[string]string{"role": string(role)})
	return pub, nil
}

// SetDisabled turns an account off or on. An administrator cannot disable themself, and the last active administrator cannot be disabled.
func (s *Store) SetDisabled(actor Principal, name string, off bool) error {
	if err := s.adminOnly(actor); err != nil {
		return err
	}
	name = NormName(name)
	s.mu.Lock()
	u := s.users[name]
	if u == nil {
		s.mu.Unlock()
		return ErrNoUser
	}
	if off {
		if name == actor.Name {
			s.mu.Unlock()
			return PolicyError("you cannot disable your own account")
		}
		if u.Role == Admin {
			others := 0
			for _, v := range s.users {
				if v.Role == Admin && !v.Disabled && v.Name != name {
					others++
				}
			}
			if others == 0 {
				s.mu.Unlock()
				return PolicyError("the last active administrator cannot be disabled")
			}
		}
	}
	u.Disabled = off
	if off {
		s.revokeLocked(name, "")
	}
	err := s.saveLocked()
	s.mu.Unlock()
	if err == nil {
		typ, sum := "account_enabled", "account enabled: "+name
		if off {
			typ, sum = "account_disabled", "account disabled: "+name
		}
		s.log.Append(actor.Name, typ, sum, nil)
	}
	return err
}

// ResetPassword lets an administrator set another account's password. That account is signed out everywhere.
func (s *Store) ResetPassword(actor Principal, name, pw string) error {
	if err := s.adminOnly(actor); err != nil {
		return err
	}
	name = NormName(name)
	if err := CheckPassword(name, pw); err != nil {
		return err
	}
	h := s.hash(pw)
	s.mu.Lock()
	u := s.users[name]
	if u == nil {
		s.mu.Unlock()
		return ErrNoUser
	}
	u.Hash = h
	delete(s.fails, "u:"+name)
	s.revokeLocked(name, "")
	err := s.saveLocked()
	s.mu.Unlock()
	if err == nil {
		s.log.Append(actor.Name, "password_reset", "password reset for "+name+"; their sessions ended", nil)
	}
	return err
}

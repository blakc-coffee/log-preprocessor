package server

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Users is the login table. A line of the users file is
//
//	name:role:pbkdf2-sha256$iterations$salt$hash
//
// with role "approver" (may change parsers) or "viewer" (GET only). Make lines
// with `sluice passwd`. PBKDF2 keeps the binary free of a bcrypt dependency; the
// iteration count is stored per line so it can be raised later.
type Users map[string]user

type user struct {
	role       string
	iter       int
	salt, hash []byte
}

const pbkdf2Iter = 600_000

// HashPassword returns a users-file hash field for a password.
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iter, enc.EncodeToString(salt), enc.EncodeToString(h)), nil
}

// LoadUsers reads a users file. Blank lines and # comments are ignored.
func LoadUsers(path string) (Users, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	users := Users{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] == "" {
			return nil, fmt.Errorf("%s:%d: want name:role:hash", path, n)
		}
		if parts[1] != "approver" && parts[1] != "viewer" {
			return nil, fmt.Errorf("%s:%d: role %q: want approver or viewer", path, n, parts[1])
		}
		h := strings.Split(parts[2], "$")
		if len(h) != 4 || h[0] != "pbkdf2-sha256" {
			return nil, fmt.Errorf("%s:%d: unsupported hash format", path, n)
		}
		iter, err := strconv.Atoi(h[1])
		if err != nil || iter < 100_000 {
			return nil, fmt.Errorf("%s:%d: iteration count must be at least 100000", path, n)
		}
		salt, err1 := base64.RawStdEncoding.DecodeString(h[2])
		hash, err2 := base64.RawStdEncoding.DecodeString(h[3])
		if err1 != nil || err2 != nil || len(hash) != 32 {
			return nil, fmt.Errorf("%s:%d: malformed hash", path, n)
		}
		if _, dup := users[parts[0]]; dup {
			return nil, fmt.Errorf("%s:%d: duplicate user %q", path, n, parts[0])
		}
		users[parts[0]] = user{role: parts[1], iter: iter, salt: salt, hash: hash}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, errors.New(path + ": no users")
	}
	return users, nil
}

// dummy makes an unknown user cost the same as a wrong password.
var dummy = user{iter: pbkdf2Iter, salt: make([]byte, 16), hash: make([]byte, 32)}

func (u Users) check(name, password string) (user, bool) {
	rec, known := u[name]
	if !known {
		rec = dummy
	}
	got, err := pbkdf2.Key(sha256.New, password, rec.salt, rec.iter, 32)
	ok := err == nil && subtle.ConstantTimeCompare(got, rec.hash) == 1
	return rec, ok && known
}

type actorKey struct{}

// actor is who the request is from when auth is on, else the name the client
// claimed. An approval is recorded under the login, never a typed-in name.
func (s *Server) actor(r *http.Request, claimed string) string {
	if a, ok := r.Context().Value(actorKey{}).(string); ok {
		return a
	}
	return claimed
}

// verified remembers logins that already passed PBKDF2, so the UI's polling and
// /metrics scrapes do not each cost a 600k-iteration hash. Only successes are
// stored, so a client without a valid password cannot grow it. The key is an HMAC
// under a per-process secret; nothing here outlives the process.
type verified struct {
	mu  sync.Mutex
	key []byte
	m   map[[32]byte]time.Time
}

const (
	verifiedTTL = 5 * time.Minute
	verifiedMax = 1024
)

func newVerified() *verified {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err) // no entropy: nothing safe to do
	}
	return &verified{key: k, m: map[[32]byte]time.Time{}}
}

func (v *verified) id(name, pass string) (id [32]byte) {
	h := hmac.New(sha256.New, v.key)
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write([]byte(pass))
	copy(id[:], h.Sum(nil))
	return id
}

func (v *verified) has(id [32]byte) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	exp, ok := v.m[id]
	if ok && time.Now().After(exp) {
		delete(v.m, id)
		return false
	}
	return ok
}

func (v *verified) add(id [32]byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.m) >= verifiedMax {
		clear(v.m)
	}
	v.m[id] = time.Now().Add(verifiedTTL)
}

// sameOrigin rejects cross-site state changes. Browsers re-send cached Basic
// credentials on cross-site requests, so a form on another site could otherwise
// post JSON to the approve endpoints as the signed-in approver.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		return err == nil && u.Host == r.Host
	}
	return true
}

func authMiddleware(users Users, next http.Handler) http.Handler {
	cache := newVerified()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" { // the container health probe carries no credentials
			next.ServeHTTP(w, r)
			return
		}
		unauthorized := func() {
			w.Header().Set("WWW-Authenticate", `Basic realm="Sluice", charset="UTF-8"`)
			writeErr(w, http.StatusUnauthorized, "unauthorized", "sign in")
		}
		name, pass, ok := r.BasicAuth()
		if !ok { // no credentials: nothing to hash
			unauthorized()
			return
		}
		id := cache.id(name, pass)
		rec, known := users[name]
		if !cache.has(id) {
			if _, valid := users.check(name, pass); !valid {
				unauthorized()
				return
			}
			cache.add(id)
		}
		if !known { // unreachable: only a valid login is ever cached
			unauthorized()
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if rec.role == "viewer" {
				writeErr(w, http.StatusForbidden, "forbidden", "this account is read-only")
				return
			}
			if !sameOrigin(r) {
				writeErr(w, http.StatusForbidden, "forbidden", "cross-site request refused")
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, name)))
	})
}

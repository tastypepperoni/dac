package dac

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ConfirmationHandler serves HTTPS-channel confirmations (§7.1) from an
// inventory file, reloading it when it changes.  It answers
//
//	GET /.well-known/affiliation/<token>
//
// with 200, media type text/plain, the confirmation record followed by LF, and
// Cache-Control max-age (§10.5); unknown tokens get 404.  It never redirects.
type ConfirmationHandler struct {
	InventoryPath string

	mu      sync.Mutex
	modTime time.Time
	res     map[string]string
	expiry  map[string]time.Time
	maxAge  int
}

const wellKnownPrefix = "/.well-known/affiliation/"

func (h *ConfirmationHandler) load() (map[string]string, int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, err := os.Stat(h.InventoryPath)
	if err != nil {
		return nil, 0, err
	}
	if h.res != nil && st.ModTime().Equal(h.modTime) {
		return h.res, h.maxAge, nil
	}
	inv, err := LoadInventory(h.InventoryPath)
	if err != nil {
		return nil, 0, err
	}
	res, err := inv.HTTPSResources()
	if err != nil {
		return nil, 0, err
	}
	h.expiry = map[string]time.Time{}
	for _, c := range inv.Children {
		if c.Expires != "" {
			if end, err := ParseExpiry(c.Expires); err == nil {
				h.expiry[c.Token] = end
			}
		}
	}
	maxAge := inv.MaxAge
	if maxAge <= 0 {
		maxAge = 3600
	}
	h.res, h.maxAge, h.modTime = res, maxAge, st.ModTime()
	return res, maxAge, nil
}

// ServeHTTP implements http.Handler.
func (h *ConfirmationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(r.URL.Path, wellKnownPrefix) {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, wellKnownPrefix)
	res, maxAge, err := h.load()
	if err != nil {
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	rec, ok := res[token]
	h.mu.Lock()
	end, hasEnd := h.expiry[token]
	h.mu.Unlock()
	if hasEnd && !time.Now().Before(end) {
		ok = false // an expired confirmation is no longer served
	}
	if hasEnd && ok {
		if left := int(time.Until(end) / time.Second); left < maxAge {
			maxAge = left
		}
	}
	w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(maxAge))
	if !IsToken(token) || !ok {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	body := rec + "\n"
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(body))
	}
}

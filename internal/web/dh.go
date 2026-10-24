package web

import (
	"context"
	"mime"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mailsvb/openkca/internal/auth"
	"github.com/mailsvb/openkca/internal/pki"
)

// dhJob generates Diffie-Hellman parameters in the background (XCA's
// "Generate DH parameter"); one job per server session.
type dhJob struct {
	ID      string
	Owner   string
	Bits    int
	Started time.Time
	Tried   atomic.Int64
	cancel  context.CancelFunc

	mu     sync.Mutex
	done   bool
	result []byte
	err    error
	ended  time.Time
}

func (j *dhJob) state() (done bool, result []byte, err error, ended time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.done, j.result, j.err, j.ended
}

type dhJobs struct {
	mu sync.Mutex
	m  map[string]*dhJob // by owner server session
}

func (d *dhJobs) get(owner string) *dhJob {
	d.mu.Lock()
	defer d.mu.Unlock()
	j := d.m[owner]
	// finished jobs are kept for an hour for the download
	if j != nil {
		if done, _, _, ended := j.state(); done && time.Since(ended) > time.Hour {
			delete(d.m, owner)
			return nil
		}
	}
	return j
}

func (s *Server) dhPage(w http.ResponseWriter, r *http.Request) {
	j := s.dh.get(serverSession(r).ID)
	p := &page{Title: "dh.title", Data: map[string]any{"Job": dhView(j), "Min": pki.DHMinBits, "Max": pki.DHMaxBits}}
	if r.URL.Query().Get("error") == "dh.error.bits" {
		p.Error = "dh.error.bits"
	}
	if r.URL.Query().Get("part") == "status" {
		p.Data["fragment"] = "dhstatus"
	}
	s.render(w, r, http.StatusOK, "dh", p)
}

type dhStatus struct {
	Bits    string
	Tried   int64
	Elapsed string
	Done    bool
	Failed  string
}

func dhView(j *dhJob) *dhStatus {
	if j == nil {
		return nil
	}
	done, _, err, ended := j.state()
	end := time.Now()
	if done {
		end = ended
	}
	v := &dhStatus{Bits: strconv.Itoa(j.Bits), Tried: j.Tried.Load(), Elapsed: end.Sub(j.Started).Truncate(time.Second).String(), Done: done}
	if err != nil {
		v.Failed = err.Error()
	}
	return v
}

func (s *Server) dhStart(w http.ResponseWriter, r *http.Request) {
	owner := serverSession(r).ID
	bits, err := strconv.Atoi(r.PostFormValue("bits"))
	if err != nil || bits < pki.DHMinBits || bits > pki.DHMaxBits {
		http.Redirect(w, r, "/dh?error=dh.error.bits", http.StatusSeeOther)
		return
	}
	s.dh.mu.Lock()
	if old := s.dh.m[owner]; old != nil {
		old.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	j := &dhJob{ID: auth.NewID(), Owner: owner, Bits: bits, Started: time.Now(), cancel: cancel}
	s.dh.m[owner] = j
	s.dh.mu.Unlock()
	s.log.Info("DH parameter generation started", "bits", bits, "ip", clientIP(r))
	go func() {
		res, err := pki.GenerateDHParams(ctx, bits, &j.Tried)
		j.mu.Lock()
		j.done, j.result, j.err, j.ended = true, res, err, time.Now()
		j.mu.Unlock()
		cancel()
	}()
	http.Redirect(w, r, "/dh", http.StatusSeeOther)
}

func (s *Server) dhCancel(w http.ResponseWriter, r *http.Request) {
	owner := serverSession(r).ID
	s.dh.mu.Lock()
	if j := s.dh.m[owner]; j != nil {
		j.cancel()
		delete(s.dh.m, owner)
	}
	s.dh.mu.Unlock()
	http.Redirect(w, r, "/dh", http.StatusSeeOther)
}

func (s *Server) dhDownload(w http.ResponseWriter, r *http.Request) {
	j := s.dh.get(serverSession(r).ID)
	if j == nil {
		http.NotFound(w, r)
		return
	}
	done, res, err, _ := j.state()
	if !done || err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": "dh" + strconv.Itoa(j.Bits) + ".pem"}))
	w.Write(res)
}

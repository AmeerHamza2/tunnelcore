//go:build linux

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

//go:embed panel.html
var panelHTML []byte

type serveFlags struct {
	fs                     *flag.FlagSet
	locations, key, listen string
}

func newServeFlags() *serveFlags {
	s := &serveFlags{fs: flag.NewFlagSet("serve", flag.ContinueOnError)}
	s.fs.StringVar(&s.locations, "locations", "", "folder with location .json files from server-setup.sh")
	s.fs.StringVar(&s.key, "key", defaultKeyPath(), "device private key file (created if missing)")
	s.fs.StringVar(&s.listen, "listen", "0.0.0.0:8080", "address for the control panel")
	return s
}

func (s *serveFlags) parse(args []string) error { return s.fs.Parse(args) }

// locView is what the panel sees of a location: never the secrets.
type locView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Country  string `json:"country"`
	PublicIP string `json:"public_ip"`
}

func viewOf(l *location) *locView {
	if l == nil {
		return nil
	}
	return &locView{ID: l.ID, Name: l.Name, Country: l.Country, PublicIP: l.PublicIP}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(panelHTML)
	})
	mux.HandleFunc("GET /api/locations", func(w http.ResponseWriter, _ *http.Request) {
		out := make([]*locView, 0, len(a.locs))
		for _, l := range a.locs {
			out = append(out, viewOf(l))
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, _ *http.Request) {
		s := a.snapshot()
		writeJSON(w, 200, map[string]any{
			"state": s.State, "transport": s.Transport, "location": viewOf(s.Location),
			"error": s.Error, "wg_blocked": s.WGBlocked, "connected_seconds": s.Since,
			"engine": s.Engine, "events": s.Events, "original_ip": s.Original,
			"server_time_ms": s.ServerTime,
		})
	})
	mux.HandleFunc("GET /api/ip", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, lookupIP(6*time.Second))
	})
	mux.HandleFunc("GET /api/probe", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, a.probeAll())
	})
	mux.HandleFunc("POST /api/connect", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID string `json:"id"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
		if err := a.connect(req.ID); err != nil {
			a.logf("error", "connect failed: %v", err)
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/disconnect", func(w http.ResponseWriter, _ *http.Request) {
		a.disconnect()
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/block-wireguard", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			On bool `json:"on"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
		if err := a.setBlock(req.On); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/speedtest", func(w http.ResponseWriter, _ *http.Request) {
		a.logf("info", "speed test: downloading 10 MB")
		res, err := speedTest(10_000_000)
		if err != nil {
			a.logf("warn", "speed test failed: %v", err)
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		a.logf("info", "speed test: %.1f Mbit/s", res["mbps"])
		writeJSON(w, 200, res)
	})
	return mux
}

// shutdownOnSignal disconnects cleanly on Ctrl-C, so the machine never keeps
// routes into a tunnel that no longer exists.
func (a *app) shutdownOnSignal(srv *http.Server) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs
	a.logf("info", "shutting down")
	a.disconnectLocked()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

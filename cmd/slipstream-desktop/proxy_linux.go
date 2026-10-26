//go:build linux

package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// browserProxy is an HTTP proxy (plain HTTP and CONNECT) that lets a browser
// on the host computer use this machine's VPN.
//
// The VPN routes this machine's traffic, not the computer the VM runs on. A
// browser pointed at this proxy has its connections opened from here instead,
// so they follow this machine's routes: into the tunnel while connected,
// straight out while not. That is what makes "what is my IP" sites in the
// host's browser show the exit server.
//
// It only serves private and loopback clients: it exists for a browser on the
// same machine or VM network, and must not become an open proxy.
type browserProxy struct {
	app      *app
	conns    atomic.Int64
	announce sync.Once
}

func (p *browserProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !privateClient(r.RemoteAddr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	p.conns.Add(1)
	p.announce.Do(func() { p.app.logf("info", "browser proxy in use: browser traffic now follows this machine's route") })
	if r.Method == http.MethodConnect {
		p.tunnel(w, r)
		return
	}
	if r.URL.Host == "" {
		http.Error(w, "this is a proxy; set it as your browser's HTTP and HTTPS proxy", http.StatusBadRequest)
		return
	}
	r.RequestURI = ""
	for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Upgrade"} {
		r.Header.Del(h)
	}
	resp, err := proxyTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

var proxyDialer = &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}

// IPv4 only: the tunnel is IPv4 and IPv6 is disabled while connected.
var proxyTransport = &http.Transport{
	Proxy: nil,
	DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return proxyDialer.DialContext(ctx, "tcp4", addr)
	},
	MaxIdleConns:    50,
	IdleConnTimeout: 30 * time.Second,
}

func (p *browserProxy) tunnel(w http.ResponseWriter, r *http.Request) {
	dst, err := proxyDialer.DialContext(r.Context(), "tcp4", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		dst.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	src, buf, err := hj.Hijack()
	if err != nil {
		dst.Close()
		return
	}
	_, _ = src.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	done := make(chan struct{}, 2)
	go func() {
		if buf != nil && buf.Reader.Buffered() > 0 {
			_, _ = io.CopyN(dst, buf, int64(buf.Reader.Buffered()))
		}
		_, _ = io.Copy(dst, src)
		closeWrite(dst)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(src, dst)
		closeWrite(src)
		done <- struct{}{}
	}()
	<-done
	<-done
	src.Close()
	dst.Close()
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

func privateClient(remote string) bool {
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast()
}

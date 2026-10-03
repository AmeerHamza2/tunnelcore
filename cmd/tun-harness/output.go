package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ANSI styles. Kept to the basic eight colours plus bold and dim, which every
// terminal emulator renders, so the demo looks the same on a conference
// projector's laptop as on the author's.
const (
	styleReset   = "\x1b[0m"
	styleBold    = "\x1b[1m"
	styleDim     = "\x1b[2m"
	styleRed     = "\x1b[31m"
	styleGreen   = "\x1b[32m"
	styleYellow  = "\x1b[33m"
	styleBlue    = "\x1b[34m"
	styleMagenta = "\x1b[35m"
	styleCyan    = "\x1b[36m"
)

// Event tags. Each line of demo output carries one, in a fixed-width column,
// so the eye can follow one actor (the engine's state machine, the racer, the
// app, an exit node) down the timeline.
const (
	tagState = "state"
	tagRace  = "race"
	tagApp   = "app"
	tagExit  = "exit"
	tagNet   = "net"
	tagFault = "fault"
	tagTun   = "tun"
	tagStack = "stack"
	tagCheck = "check"
	tagInfo  = "info"
)

var tagStyles = map[string]string{
	tagState: styleCyan + styleBold,
	tagRace:  styleMagenta,
	tagApp:   styleBlue,
	tagExit:  styleGreen,
	tagNet:   styleYellow,
	tagFault: styleRed + styleBold,
	tagTun:   styleDim,
	tagStack: styleBlue + styleBold,
	tagCheck: styleBold,
	tagInfo:  styleDim,
}

// printer serialises the demo's output.
//
// Output comes from many goroutines at once — the engine's state callbacks,
// each racing transport, the exit nodes' packet loops, the app — so every
// write goes through one mutex, and every line is stamped with the time since
// the demo started. Relative time rather than wall-clock is what makes the
// race readable: "+0.150s" is the stagger, visibly.
type printer struct {
	mu      sync.Mutex
	w       io.Writer
	start   time.Time
	color   bool
	verbose bool
	// closed drops late lines. A goroutine that is still unwinding when the
	// demo returns must not write into a buffer the caller (a test) is
	// already reading.
	closed bool
}

func newPrinter(w io.Writer, color, verbose bool) *printer {
	return &printer{w: w, start: time.Now(), color: color, verbose: verbose}
}

// style wraps s in an ANSI style when colour is enabled.
func (p *printer) style(st, s string) string {
	if !p.color || st == "" {
		return s
	}
	return st + s + styleReset
}

func (p *printer) ok(s string) string   { return p.style(styleGreen+styleBold, s) }
func (p *printer) bad(s string) string  { return p.style(styleRed+styleBold, s) }
func (p *printer) dim(s string) string  { return p.style(styleDim, s) }
func (p *printer) bold(s string) string { return p.style(styleBold, s) }

func (p *printer) elapsed() time.Duration { return time.Since(p.start) }

// line writes s verbatim followed by a newline.
func (p *printer) line(s string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	fmt.Fprintln(p.w, s)
}

// event writes one timestamped, tagged line.
func (p *printer) event(tag, format string, a ...any) {
	ts := fmt.Sprintf("%7.3fs", p.elapsed().Seconds())
	p.line(fmt.Sprintf("  %s  %s  %s", p.dim(ts), p.style(tagStyles[tag], fmt.Sprintf("%-5s", tag)), fmt.Sprintf(format, a...)))
}

// debug is event, shown only with -v.
func (p *printer) debug(tag, format string, a ...any) {
	if p.verbose {
		p.event(tag, format, a...)
	}
}

// section starts a numbered block of the story.
func (p *printer) section(n int, title string) {
	p.line("")
	p.line(p.bold(fmt.Sprintf("── %d. %s ", n, title)) + p.dim(strings.Repeat("─", max(0, 66-utf8.RuneCountInString(title)))))
}

func (p *printer) close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
}

// stdoutIsTerminal reports whether stdout is a character device, which is the
// signal for colour. NO_COLOR (https://no-color.org) overrides it.
func stdoutIsTerminal() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// humanBytes renders a byte count with a binary unit.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ms renders a duration in milliseconds with sensible precision.
func ms(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%dµs", d.Microseconds())
	case d < 10*time.Millisecond:
		return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
	default:
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// quote renders a payload for display, truncated so one large packet cannot
// wreck the layout.
func quote(b []byte) string {
	const maxShown = 40
	s := string(b)
	if len(s) > maxShown {
		s = s[:maxShown] + "…"
	}
	return fmt.Sprintf("%q", s)
}

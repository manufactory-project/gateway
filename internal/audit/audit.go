package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// SchemaVersion identifies the JSONL audit event schema.
	SchemaVersion = 1

	// MaxRetainDays is the largest day count convertible to time.Duration without int64 overflow.
	MaxRetainDays = int(math.MaxInt64 / int64(24*time.Hour))

	// DefaultMaxFileBytes is the default per-segment rotation size (100 MiB).
	DefaultMaxFileBytes = 100 << 20

	// DefaultMaxTotalBytes is the default total audit directory size cap (10 GiB).
	DefaultMaxTotalBytes = int64(10) << 30

	filePrefix = "gateway-"
	fileExt    = ".jsonl"
	dayFormat  = "2006-01-02"
)

// Kind identifies the category of an audit event.
type Kind string

const (
	KindDNS             Kind = "dns"
	KindRequest         Kind = "request"
	KindRequestAdmitted Kind = "request_admitted"
	KindWebSocket       Kind = "websocket"
	KindLifecycle       Kind = "lifecycle"
	KindGrant           Kind = "grant"
	KindRevoke          Kind = "revoke"
)

// Effect is the enforcement outcome of a decision.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Event is one structured JSONL audit record.
// Redaction is enforced by schema: header values and query values have no fields here.
type Event struct {
	Version    int       `json:"version"`
	Time       time.Time `json:"time"`
	Kind       Kind      `json:"kind"`
	Principal  string    `json:"principal,omitempty"`
	Link       string    `json:"link,omitempty"`
	SrcIP      string    `json:"src_ip,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	Host       string    `json:"host,omitempty"`
	Address    string    `json:"address,omitempty"`
	Port       int       `json:"port,omitempty"`
	QType      string    `json:"qtype,omitempty"`
	Method     string    `json:"method,omitempty"`
	Path       string    `json:"path,omitempty"`
	HasQuery   bool      `json:"has_query,omitempty"`
	Status     int       `json:"status,omitempty"`
	Effect     Effect    `json:"effect,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	RuleID     string    `json:"rule_id,omitempty"`
	GrantID    string    `json:"grant_id,omitempty"`
	TTL        string    `json:"ttl,omitempty"`
	ExpiresAt  string    `json:"expires_at,omitempty"`
	FlowID     string    `json:"flow_id,omitempty"`
	Secrets    []string  `json:"secrets,omitempty"`
	BytesOut     int64     `json:"bytes_out,omitempty"`
	BytesIn      int64     `json:"bytes_in,omitempty"`
	BytesRemoved int64     `json:"bytes_removed,omitempty"`
	Error        string    `json:"error,omitempty"`
	ConfigHash   string    `json:"config_hash,omitempty"`
}

// Options configures an audit Writer.
type Options struct {
	Dir           string
	RetainDays    int
	MaxFileBytes  int64
	MaxTotalBytes int64
	Stdout        io.Writer
	Diag          io.Writer
	Now           func() time.Time
	OnWriteError  func()
	OnSizePrune   func(bytesRemoved int64)
}

// Writer appends structured JSONL audit events synchronously and fails closed
// whenever the underlying file sink cannot be opened or written.
type Writer struct {
	dir           string
	retain        time.Duration
	maxFileBytes  int64
	maxTotalBytes int64
	stdout        io.Writer
	diag          io.Writer
	now           func() time.Time
	onWriteError  func()
	onSizePrune   func(bytesRemoved int64)

	mu          sync.Mutex
	closed      bool
	day         string
	seq         int
	file        *os.File
	fileSize    int64
	writeErrors atomic.Uint64
	healthy     atomic.Bool
}

// NewWriter opens the audit directory and current daily segment, failing immediately
// if the sink is unwritable.
func NewWriter(opts Options) (*Writer, error) {
	if opts.Dir == "" {
		return nil, errors.New("audit: dir is required")
	}
	if opts.RetainDays < 0 || opts.RetainDays > MaxRetainDays {
		return nil, fmt.Errorf("audit: retain_days %d out of range [0, %d]", opts.RetainDays, MaxRetainDays)
	}
	maxBytes := opts.MaxFileBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxFileBytes
	}
	maxTotal := opts.MaxTotalBytes
	if maxTotal <= 0 {
		maxTotal = DefaultMaxTotalBytes
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	diag := opts.Diag
	if diag == nil {
		diag = io.Discard
	}

	w := &Writer{
		dir:           opts.Dir,
		retain:        time.Duration(opts.RetainDays) * 24 * time.Hour,
		maxFileBytes:  maxBytes,
		maxTotalBytes: maxTotal,
		stdout:        opts.Stdout,
		diag:          diag,
		now:           nowFn,
		onWriteError:  opts.OnWriteError,
		onSizePrune:   opts.OnSizePrune,
	}

	if err := w.openSegmentLocked(nowFn().UTC(), false); err != nil {
		w.recordWriteError()
		return nil, err
	}
	w.healthy.Store(true)
	return w, nil
}

// WriteSync sanitizes, encodes, and synchronously writes ev to the current audit
// segment (and optional stdout mirror). If writing fails, it marks the sink
// unhealthy, increments WriteErrors, triggers OnWriteError, and returns an error
// so callers can fail closed.
func (w *Writer) WriteSync(ev Event) error {
	ev = sanitizeEvent(ev, w.now().UTC())
	line, err := json.Marshal(ev)
	if err != nil {
		w.recordWriteError()
		return fmt.Errorf("audit: marshal event: %w", err)
	}
	line = append(line, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		w.recordWriteError()
		return errors.New("audit: writer is closed")
	}

	day := ev.Time.UTC().Format(dayFormat)
	needRotate := w.file == nil || day != w.day || (w.maxFileBytes > 0 && w.fileSize+int64(len(line)) > w.maxFileBytes && w.fileSize > 0)
	if needRotate {
		sameDayRoll := w.file != nil && day == w.day
		if err := w.openSegmentLocked(ev.Time.UTC(), sameDayRoll); err != nil {
			w.recordWriteError()
			return err
		}
	}

	return w.writeLineLocked(line)
}

func (w *Writer) writeLineLocked(line []byte) error {
	n, writeErr := w.file.Write(line)
	if writeErr != nil || n != len(line) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		// Close broken fd so next attempt tries reopening cleanly.
		if closeErr := w.closeFileLocked(); closeErr != nil {
			writeErr = errors.Join(writeErr, closeErr)
		}
		w.recordWriteError()
		return fmt.Errorf("audit: write segment: %w", writeErr)
	}
	w.fileSize += int64(n)
	w.healthy.Store(true)

	if w.stdout != nil {
		if _, err := w.stdout.Write(line); err != nil {
			if _, dErr := fmt.Fprintf(w.diag, "audit: stdout mirror write failed: %v\n", err); dErr != nil {
				// diag itself failed; primary file sink succeeded.
				return nil
			}
		}
	}
	return nil
}

// Close flushes and closes the active audit segment file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return w.closeFileLocked()
}

// WriteErrors returns the total number of failed audit writes since creation.
func (w *Writer) WriteErrors() uint64 {
	return w.writeErrors.Load()
}

// Healthy reports whether the most recent audit write succeeded.
func (w *Writer) Healthy() bool {
	return w.healthy.Load()
}

func (w *Writer) recordWriteError() {
	w.healthy.Store(false)
	w.writeErrors.Add(1)
	if w.onWriteError != nil {
		w.onWriteError()
	}
}

func (w *Writer) closeFileLocked() error {
	if w.file == nil {
		return nil
	}
	f := w.file
	w.file = nil
	w.fileSize = 0
	return f.Close()
}

func (w *Writer) openSegmentLocked(ts time.Time, incrementSeq bool) error {
	if err := w.closeFileLocked(); err != nil {
		return fmt.Errorf("audit: close previous segment: %w", err)
	}
	if err := os.MkdirAll(w.dir, 0o750); err != nil {
		return fmt.Errorf("audit: create directory %s: %w", w.dir, err)
	}

	day := ts.UTC().Format(dayFormat)
	var seq int
	if incrementSeq && day == w.day {
		seq = w.seq + 1
	} else {
		var err error
		seq, err = w.latestSeqForDay(day)
		if err != nil {
			return err
		}
	}

	for {
		path := filepath.Join(w.dir, segmentFileName(day, seq))
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return fmt.Errorf("audit: open segment %s: %w", path, err)
		}
		fi, err := f.Stat()
		if err != nil {
			closeErr := f.Close()
			return errors.Join(fmt.Errorf("audit: stat segment %s: %w", path, err), closeErr)
		}
		if w.maxFileBytes > 0 && fi.Size() >= w.maxFileBytes {
			if closeErr := f.Close(); closeErr != nil {
				return fmt.Errorf("audit: close full segment %s: %w", path, closeErr)
			}
			seq++
			continue
		}
		w.file = f
		w.day = day
		w.seq = seq
		w.fileSize = fi.Size()
		break
	}

	w.pruneLocked(ts.UTC())
	w.pruneSizeLocked(ts.UTC())
	return nil
}

func (w *Writer) latestSeqForDay(day string) (int, error) {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return 0, fmt.Errorf("audit: read directory %s: %w", w.dir, err)
	}
	best := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		d, seq, ok := parseSegmentName(e.Name())
		if ok && d == day && seq > best {
			best = seq
		}
	}
	return best, nil
}

func (w *Writer) pruneLocked(now time.Time) {
	if w.retain <= 0 {
		return
	}
	cutoff := now.UTC().Add(-w.retain)
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		if _, dErr := fmt.Fprintf(w.diag, "audit: prune readdir %s: %v\n", w.dir, err); dErr != nil {
			return
		}
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		dayStr, _, ok := parseSegmentName(e.Name())
		if !ok {
			continue
		}
		day, err := time.Parse(dayFormat, dayStr)
		if err != nil {
			continue
		}
		if day.AddDate(0, 0, 1).Before(cutoff) {
			if rmErr := os.Remove(filepath.Join(w.dir, e.Name())); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				if _, dErr := fmt.Fprintf(w.diag, "audit: prune remove %s: %v\n", e.Name(), rmErr); dErr != nil {
					return
				}
			}
		}
	}
}

type segmentMeta struct {
	name   string
	day    string
	seq    int
	size   int64
	active bool
}

func (w *Writer) pruneSizeLocked(now time.Time) {
	if w.maxTotalBytes <= 0 {
		return
	}
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		if _, dErr := fmt.Fprintf(w.diag, "audit: size-prune readdir %s: %v\n", w.dir, err); dErr != nil {
			return
		}
		return
	}
	activeName := segmentFileName(w.day, w.seq)
	var (
		segs  []segmentMeta
		total int64
	)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		dayStr, seq, ok := parseSegmentName(e.Name())
		if !ok {
			continue
		}
		fi, infoErr := e.Info()
		if infoErr != nil {
			continue
		}
		sz := fi.Size()
		total += sz
		segs = append(segs, segmentMeta{
			name:   e.Name(),
			day:    dayStr,
			seq:    seq,
			size:   sz,
			active: e.Name() == activeName,
		})
	}
	if total <= w.maxTotalBytes {
		return
	}
	sort.Slice(segs, func(i, j int) bool {
		if segs[i].day != segs[j].day {
			return segs[i].day < segs[j].day
		}
		return segs[i].seq < segs[j].seq
	})
	var removed int64
	for _, seg := range segs {
		if total <= w.maxTotalBytes {
			break
		}
		if seg.active {
			continue
		}
		if rmErr := os.Remove(filepath.Join(w.dir, seg.name)); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			if _, dErr := fmt.Fprintf(w.diag, "audit: size-prune remove %s: %v\n", seg.name, rmErr); dErr != nil {
				return
			}
			continue
		}
		total -= seg.size
		removed += seg.size
	}
	if removed <= 0 {
		return
	}
	if w.onSizePrune != nil {
		w.onSizePrune(removed)
	}
	ev := sanitizeEvent(Event{
		Kind:         KindLifecycle,
		Reason:       "audit-size-pruned",
		BytesRemoved: removed,
	}, now.UTC())
	line, mErr := json.Marshal(ev)
	if mErr != nil {
		return
	}
	line = append(line, '\n')
	if wErr := w.writeLineLocked(line); wErr != nil {
		if _, dErr := fmt.Fprintf(w.diag, "audit: write audit-size-pruned event: %v\n", wErr); dErr != nil {
			return
		}
	}
}

func sanitizeEvent(ev Event, now time.Time) Event {
	ev.Version = SchemaVersion
	if ev.Time.IsZero() {
		ev.Time = now
	} else {
		ev.Time = ev.Time.UTC()
	}
	if ev.Host != "" {
		ev.Host = EscapeHost(ev.Host)
	}
	if ev.Method != "" {
		ev.Method = EscapeMethod(ev.Method)
	}
	if ev.Path != "" {
		// StripQuery handles raw request targets while preserving percent-escaped
		// sequences (such as %23 and %3F) from url.URL.EscapedPath().
		p, hadQuery := StripQuery(ev.Path)
		ev.Path = p
		if hadQuery {
			ev.HasQuery = true
		}
	}
	if ev.Principal != "" {
		ev.Principal = EscapeString(ev.Principal)
	}
	if ev.Link != "" {
		ev.Link = EscapeString(ev.Link)
	}
	if ev.Reason != "" {
		ev.Reason = EscapeString(ev.Reason)
	}
	if ev.Error != "" {
		ev.Error = EscapeString(ev.Error)
	}
	if ev.TTL != "" {
		ev.TTL = EscapeString(ev.TTL)
	}
	if ev.ExpiresAt != "" {
		ev.ExpiresAt = EscapeString(ev.ExpiresAt)
	}
	return ev
}

func segmentFileName(day string, seq int) string {
	if seq == 0 {
		return filePrefix + day + fileExt
	}
	return fmt.Sprintf("%s%s.%d%s", filePrefix, day, seq, fileExt)
}

func parseSegmentName(name string) (day string, seq int, ok bool) {
	if !strings.HasPrefix(name, filePrefix) || !strings.HasSuffix(name, fileExt) {
		return "", 0, false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(name, filePrefix), fileExt)
	if len(body) == len(dayFormat) {
		if _, err := time.Parse(dayFormat, body); err != nil {
			return "", 0, false
		}
		return body, 0, true
	}
	dot := strings.IndexByte(body, '.')
	if dot != len(dayFormat) {
		return "", 0, false
	}
	dayPart := body[:dot]
	if _, err := time.Parse(dayFormat, dayPart); err != nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(body[dot+1:])
	if err != nil || n <= 0 {
		return "", 0, false
	}
	return dayPart, n, true
}

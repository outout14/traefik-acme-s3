package lokiwriter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	defaultFlushInterval = 5 * time.Second
	defaultBatchSize     = 100
	pushPath             = "/loki/api/v1/push"
)

type entry struct {
	ts   time.Time
	line string
}

type pushStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

type pushPayload struct {
	Streams []pushStream `json:"streams"`
}

// Writer is an io.Writer that buffers log lines and pushes them to Loki.
// It is safe for concurrent use.
type Writer struct {
	url    string
	labels map[string]string
	client *http.Client

	mu      sync.Mutex
	buf     []entry
	closeCh chan struct{}
	wg      sync.WaitGroup
}

// New creates a Loki writer. labels are attached to every log stream (e.g. {"app": "tas3"}).
func New(lokiURL string, labels map[string]string) *Writer {
	w := &Writer{
		url:     lokiURL + pushPath,
		labels:  labels,
		client:  &http.Client{Timeout: 5 * time.Second},
		closeCh: make(chan struct{}),
	}
	w.wg.Add(1)
	go w.flusher()
	return w
}

// Write satisfies io.Writer. It buffers the line for async dispatch to Loki.
func (w *Writer) Write(p []byte) (int, error) {
	line := string(p)
	w.mu.Lock()
	w.buf = append(w.buf, entry{ts: time.Now(), line: line})
	flush := len(w.buf) >= defaultBatchSize
	w.mu.Unlock()

	if flush {
		w.flush()
	}
	return len(p), nil
}

// Close flushes remaining entries and stops the background goroutine.
func (w *Writer) Close() {
	close(w.closeCh)
	w.wg.Wait()
	w.flush()
}

func (w *Writer) flusher() {
	defer w.wg.Done()
	ticker := time.NewTicker(defaultFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.flush()
		case <-w.closeCh:
			return
		}
	}
}

func (w *Writer) flush() {
	w.mu.Lock()
	if len(w.buf) == 0 {
		w.mu.Unlock()
		return
	}
	batch := w.buf
	w.buf = nil
	w.mu.Unlock()

	values := make([][2]string, len(batch))
	for i, e := range batch {
		values[i] = [2]string{
			strconv.FormatInt(e.ts.UnixNano(), 10),
			e.line,
		}
	}

	payload := pushPayload{
		Streams: []pushStream{{Stream: w.labels, Values: values}},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("[lokiwriter] failed to marshal payload: %v\n", err)
		return
	}

	resp, err := w.client.Post(w.url, "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("[lokiwriter] failed to push to Loki: %v\n", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		fmt.Printf("[lokiwriter] Loki returned HTTP %d\n", resp.StatusCode)
	}
}

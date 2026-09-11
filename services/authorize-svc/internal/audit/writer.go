package audit

import (
	"context"
	"log/slog"
	"sync"
)

// Writer persists decisions ASYNCHRONOUSLY so the audit write never adds to the
// authorize response's latency (TRD §14). The handler calls Enqueue AFTER the
// response is written; a background worker drains the queue into the Store.
//
// MVP durability (ROADMAP Task 1.6, §23): an in-process buffered channel. Enqueue
// does not drop — it blocks until there is room — but items still in the buffer are
// lost if the process crashes. The documented upgrade is a durable queue (NATS →
// Kafka) so a crash cannot lose an audit record; the Store interface is unchanged.
//
// A SINGLE worker drains the queue, so within one process an org's hash chain is
// built in a consistent order. Across multiple service instances the Postgres store
// takes a per-org advisory lock to keep the chain linear; the in-memory store is
// single-process by construction.
type Writer struct {
	store Store
	log   *slog.Logger
	ch    chan *Record
	inflt sync.WaitGroup // items accepted but not yet persisted (for Flush)

	// mu guards closed and serializes channel sends against Close's close(ch): sends
	// hold RLock, Close holds the write lock, so a send can never race the close.
	mu     sync.RWMutex
	closed bool
	worker sync.WaitGroup
}

// DefaultQueueSize is the buffered depth when none is given.
const DefaultQueueSize = 1024

// NewWriter builds a Writer over the store. queueSize <= 0 uses DefaultQueueSize.
func NewWriter(store Store, log *slog.Logger, queueSize int) *Writer {
	if queueSize <= 0 {
		queueSize = DefaultQueueSize
	}
	if log == nil {
		log = slog.Default()
	}
	return &Writer{store: store, log: log, ch: make(chan *Record, queueSize)}
}

// Start launches the background worker. Call once.
func (w *Writer) Start() {
	w.worker.Add(1)
	go func() {
		defer w.worker.Done()
		for r := range w.ch {
			w.persist(r)
			w.inflt.Done()
		}
	}()
}

// persist writes one record, logging (never panicking) on failure. A failed audit
// write must not take down the request path — it already returned.
func (w *Writer) persist(r *Record) {
	if err := w.store.Append(context.Background(), r); err != nil {
		w.log.Error("audit append failed",
			"err", err, "decision_id", r.DecisionID, "org_id", r.OrgID)
	}
}

// Enqueue hands a record to the async writer. It is called after the response has
// been written, so it never affects latency_ms. It does not drop: if the buffer is
// full it blocks until the worker makes room. After Close it persists inline so a
// shutdown race cannot silently lose the record.
//
// The RLock is held across the send so Close (write lock) cannot close the channel
// mid-send; a blocked send still makes progress because the worker keeps draining.
func (w *Writer) Enqueue(r *Record) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		w.persist(r) // shutting down; persist inline rather than drop
		return
	}
	w.inflt.Add(1)
	w.ch <- r
}

// Flush blocks until every enqueued record has been persisted. Used by tests and by
// graceful shutdown to guarantee the log is durable before proceeding.
func (w *Writer) Flush() { w.inflt.Wait() }

// Close stops accepting new records, drains what is queued, and waits for the worker
// to exit (bounded by ctx). After Close, Enqueue persists inline.
func (w *Writer) Close(ctx context.Context) error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	close(w.ch)
	w.mu.Unlock()

	done := make(chan struct{})
	go func() { w.worker.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

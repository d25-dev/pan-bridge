// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yuya Uwatoko

package bridge

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// fakeDaemon connects dials to in-memory pipes and lets tests inject incoming streams.
type fakeDaemon struct {
	dialed   chan net.Conn // far ends of dialed streams
	incoming chan net.Conn
	trusted  []any
}

type fakeListener struct{ ch chan net.Conn }

func (l fakeListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, errors.New("closed")
	}
	return c, nil
}
func (l fakeListener) Close() error { return nil }

type addrConn struct {
	net.Conn
	remote string
}

type pilotAddr string

func (a pilotAddr) Network() string { return "pilot" }
func (a pilotAddr) String() string  { return string(a) }

func (c addrConn) RemoteAddr() net.Addr { return pilotAddr(c.remote) }

func (f *fakeDaemon) Info() (map[string]interface{}, error) {
	return map[string]interface{}{"address": "0:0000.0000.0001", "public_key": "aa"}, nil
}
func (f *fakeDaemon) Handshake(uint32, string) (map[string]interface{}, error) { return nil, nil }
func (f *fakeDaemon) TrustedPeers() (map[string]interface{}, error) {
	return map[string]interface{}{"trusted": f.trusted}, nil
}
func (f *fakeDaemon) Dial(protocol.Addr, uint16, time.Duration) (net.Conn, error) {
	a, b := net.Pipe()
	f.dialed <- b
	return a, nil
}
func (f *fakeDaemon) Listen(uint16) (Listener, error) { return fakeListener{f.incoming}, nil }

type fakeRegistry struct{}

func (fakeRegistry) Lookup(n uint32) (map[string]interface{}, error) {
	if n == 9 {
		return nil, errors.New("node not found")
	}
	return map[string]interface{}{"public_key": "bb"}, nil
}

type client struct {
	t  *testing.T
	c  net.Conn
	r  *bufio.Reader
	id uint64
}

func (c *client) call(method string, params any) (map[string]any, string) {
	c.t.Helper()
	c.id++
	b, _ := json.Marshal(map[string]any{"id": c.id, "method": method, "params": params})
	c.c.Write(append(b, '\n'))
	for {
		m := c.next()
		if _, ok := m["event"]; ok {
			continue
		}
		if e, ok := m["error"].(map[string]any); ok {
			return nil, e["code"].(string)
		}
		r, _ := m["result"].(map[string]any)
		return r, ""
	}
}

func (c *client) next() map[string]any {
	c.t.Helper()
	c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		c.t.Fatalf("decode %q: %v", line, err)
	}
	return m
}

func start(t *testing.T) (*fakeDaemon, func() *client) {
	t.Helper()
	f := &fakeDaemon{dialed: make(chan net.Conn, 32), incoming: make(chan net.Conn, 32),
		trusted: []any{map[string]any{"node_id": float64(2), "public_key": "cc"}}}
	s := &Server{D: f, Version: "test", R: func() (Registry, error) { return fakeRegistry{}, nil }}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "rt")
	ln, _, err := ListenSocket(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go s.Serve(ln, SameUser)
	return f, func() *client {
		c, err := net.Dial("unix", filepath.Join(dir, "bridge.sock"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return &client{t: t, c: c, r: bufio.NewReader(c)}
	}
}

func TestHelloTrustedLookup(t *testing.T) {
	_, dial := start(t)
	c := dial()
	r, e := c.call("hello", map[string]int{"api": 1})
	if e != "" || r["addr"] != "0:0000.0000.0001" || r["public_key"] != "aa" {
		t.Fatalf("hello = %v %s", r, e)
	}
	if _, e := c.call("hello", map[string]int{"api": 2}); e != "UNSUPPORTED_API" {
		t.Fatalf("hello api 2: %s", e)
	}
	r, _ = c.call("peer.trusted", map[string]any{})
	if p := r["peers"].([]any); len(p) != 1 || p[0].(map[string]any)["addr"] != "0:0000.0000.0002" {
		t.Fatalf("trusted = %v", r)
	}
	if r, e := c.call("registry.lookup", map[string]string{"addr": "0:0000.0000.0002"}); e != "" || r["public_key"] != "bb" {
		t.Fatalf("lookup = %v %s", r, e)
	}
	if _, e := c.call("registry.lookup", map[string]string{"addr": "0:0000.0000.0009"}); e != "NOT_FOUND" {
		t.Fatalf("lookup missing: %s", e)
	}
	if _, e := c.call("registry.lookup", map[string]string{"addr": "0:0.0.2"}); e != "BAD_REQUEST" {
		t.Fatalf("non-canonical address accepted: %s", e)
	}
	if _, e := c.call("hello", map[string]any{"api": 1, "extra": true}); e != "BAD_REQUEST" {
		t.Fatalf("unknown field accepted: %s", e)
	}
}

func TestDialWriteReadClose(t *testing.T) {
	f, dial := start(t)
	c := dial()
	r, e := c.call("stream.dial", map[string]any{"addr": "0:0000.0000.0002", "port": 1001, "timeout_ms": 1000})
	if e != "" {
		t.Fatal(e)
	}
	h := r["conn"].(string)
	far := <-f.dialed
	go func() {
		buf := make([]byte, 5)
		far.Read(buf)
		far.Write([]byte("ack:" + string(buf)))
		far.Close()
	}()
	if r, e := c.call("stream.write", map[string]any{"conn": h, "data_b64": base64.StdEncoding.EncodeToString([]byte("hello")), "timeout_ms": 1000}); e != "" || r["written"] != float64(5) {
		t.Fatalf("write = %v %s", r, e)
	}
	var got []byte
	for {
		r, e := c.call("stream.read", map[string]any{"conn": h, "max": 64, "timeout_ms": 1000})
		if e != "" {
			t.Fatal(e)
		}
		b, _ := base64.StdEncoding.DecodeString(r["data_b64"].(string))
		got = append(got, b...)
		if r["eof"] == true {
			break
		}
	}
	if string(got) != "ack:hello" {
		t.Fatalf("read %q", got)
	}
	if _, e := c.call("stream.close", map[string]any{"conn": h}); e != "" {
		t.Fatal(e)
	}
	if _, e := c.call("stream.read", map[string]any{"conn": h, "max": 1, "timeout_ms": 100}); e != "UNKNOWN_CONN" {
		t.Fatalf("closed handle usable: %s", e)
	}
}

// An incoming stream is announced with its transport address, and no byte is consumed before the Client reads.
func TestIncomingNotReadUntilAsked(t *testing.T) {
	f, dial := start(t)
	c := dial()
	if _, e := c.call("listen", map[string]any{"port": 1001}); e != "" {
		t.Fatal(e)
	}
	a, b := net.Pipe()
	f.incoming <- addrConn{a, "0:0000.0000.0002:49152"}
	ev := c.next()
	if ev["event"] != "stream.incoming" || ev["remote_addr"] != "0:0000.0000.0002" {
		t.Fatalf("event = %v", ev)
	}
	wrote := make(chan error, 1)
	go func() { _, err := b.Write([]byte("x")); wrote <- err }()
	select {
	case <-wrote: // net.Pipe is unbuffered: a completed write would mean the Bridge read on its own
		t.Fatal("bridge consumed bytes before stream.read")
	case <-time.After(300 * time.Millisecond):
	}
	r, e := c.call("stream.read", map[string]any{"conn": ev["conn"], "max": 1, "timeout_ms": 1000})
	if e != "" || r["data_b64"] != base64.StdEncoding.EncodeToString([]byte("x")) {
		t.Fatalf("read = %v %s", r, e)
	}
}

// Handles are bound to their session; a second session cannot listen on a taken port; ending a session closes
// its streams.
func TestSessionIsolation(t *testing.T) {
	f, dial := start(t)
	c1, c2 := dial(), dial()
	r, _ := c1.call("stream.dial", map[string]any{"addr": "0:0000.0000.0002", "port": 1001, "timeout_ms": 1000})
	far := <-f.dialed
	if _, e := c2.call("stream.read", map[string]any{"conn": r["conn"], "max": 1, "timeout_ms": 100}); e != "UNKNOWN_CONN" {
		t.Fatalf("cross-session handle accepted: %s", e)
	}
	if _, e := c1.call("listen", map[string]any{"port": 1001}); e != "" {
		t.Fatal(e)
	}
	if _, e := c2.call("listen", map[string]any{"port": 1001}); e != "BUSY" {
		t.Fatalf("second listener: %s", e)
	}
	c1.c.Close()
	far.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := far.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("stream not closed with its session: %v", err)
	}
}

func TestStreamLimit(t *testing.T) {
	f, dial := start(t)
	c := dial()
	for i := 0; i < MaxStreams; i++ {
		if _, e := c.call("stream.dial", map[string]any{"addr": "0:0000.0000.0002", "port": 1001, "timeout_ms": 1000}); e != "" {
			t.Fatal(e)
		}
		<-f.dialed
	}
	if _, e := c.call("stream.dial", map[string]any{"addr": "0:0000.0000.0002", "port": 1001, "timeout_ms": 1000}); e != "BUSY" {
		t.Fatalf("over the limit: %s", e)
	}
}

func TestMalformedLineEndsSession(t *testing.T) {
	_, dial := start(t)
	c := dial()
	c.c.Write([]byte("{not json\n"))
	c.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.r.ReadByte(); err == nil || strings.Contains(err.Error(), "timeout") {
		t.Fatalf("session kept open after a malformed line: %v", err)
	}
}

// A second Bridge on the same runtime dir refuses to start instead of replacing the live socket.
func TestSecondInstanceRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rt")
	ln, _, err := ListenSocket(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, _, err := ListenSocket(dir); err == nil {
		t.Fatal("second instance took over the runtime dir")
	}
}

// A failed write retires the handle (UNKNOWN_CONN afterwards).
func TestFailedWriteRetiresHandle(t *testing.T) {
	f, dial := start(t)
	c := dial()
	r, _ := c.call("stream.dial", map[string]any{"addr": "0:0000.0000.0002", "port": 1001, "timeout_ms": 1000})
	(<-f.dialed).Close()
	if _, e := c.call("stream.write", map[string]any{"conn": r["conn"], "data_b64": base64.StdEncoding.EncodeToString([]byte("x")), "timeout_ms": 500}); e == "" {
		t.Fatal("write to a closed peer succeeded")
	}
	if _, e := c.call("stream.read", map[string]any{"conn": r["conn"], "max": 1, "timeout_ms": 100}); e != "UNKNOWN_CONN" {
		t.Fatalf("handle still usable after a failed write: %s", e)
	}
}

// A session that ended releases the port, and a new session can listen on it.
func TestListenOwnershipReleasedOnEnd(t *testing.T) {
	_, dial := start(t)
	c1 := dial()
	if _, e := c1.call("listen", map[string]any{"port": 1001}); e != "" {
		t.Fatal(e)
	}
	c1.c.Close()
	c2 := dial()
	for i := 0; i < 50; i++ {
		if _, e := c2.call("listen", map[string]any{"port": 1001}); e == "" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("port stayed owned by an ended session")
}

// Concurrent dials cannot exceed the stream limit (slots are reserved before dialing).
func TestConcurrentDialsBounded(t *testing.T) {
	f, dial := start(t)
	c := dial()
	go func() {
		for range f.dialed {
		}
	}()
	ids := make([]uint64, 0, 40)
	for i := 0; i < 40; i++ {
		c.id++
		ids = append(ids, c.id)
		b, _ := json.Marshal(map[string]any{"id": c.id, "method": "stream.dial", "params": map[string]any{"addr": "0:0000.0000.0002", "port": 1001, "timeout_ms": 1000}})
		c.c.Write(append(b, '\n'))
	}
	ok := 0
	for range ids {
		m := c.next()
		if _, isErr := m["error"]; !isErr {
			ok++
		}
	}
	if ok != MaxStreams {
		t.Fatalf("%d dials succeeded, want %d", ok, MaxStreams)
	}
}

// A write queued behind a failing write on the same stream must not be sent after the failure.
func TestQueuedWriteAfterFailureIsRefused(t *testing.T) {
	f, dial := start(t)
	c := dial()
	r, _ := c.call("stream.dial", map[string]any{"addr": "0:0000.0000.0002", "port": 1001, "timeout_ms": 1000})
	far := <-f.dialed // never reads: the first write blocks until its deadline
	defer far.Close()
	data := base64.StdEncoding.EncodeToString([]byte("x"))
	for i := 0; i < 2; i++ {
		c.id++
		b, _ := json.Marshal(map[string]any{"id": c.id, "method": "stream.write", "params": map[string]any{"conn": r["conn"], "data_b64": data, "timeout_ms": 300}})
		c.c.Write(append(b, '\n'))
	}
	codes := map[string]int{}
	for i := 0; i < 2; i++ {
		m := c.next()
		if e, ok := m["error"].(map[string]any); ok {
			codes[e["code"].(string)]++
		} else {
			codes["ok"]++
		}
	}
	if codes["TIMEOUT"] != 1 || codes["UNKNOWN_CONN"] != 1 {
		t.Fatalf("results %v, want one TIMEOUT and one UNKNOWN_CONN", codes)
	}
}

// More than 65552 decoded bytes in one write is refused.
func TestWriteLimitAfterDecoding(t *testing.T) {
	f, dial := start(t)
	c := dial()
	r, _ := c.call("stream.dial", map[string]any{"addr": "0:0000.0000.0002", "port": 1001, "timeout_ms": 1000})
	<-f.dialed
	big := base64.StdEncoding.EncodeToString(make([]byte, MaxRead+1))
	if _, e := c.call("stream.write", map[string]any{"conn": r["conn"], "data_b64": big, "timeout_ms": 100}); e != "BAD_REQUEST" {
		t.Fatalf("oversized write: %q", e)
	}
}

// With every backend slot held by stalled calls, further untimed calls are answered BUSY at once.
func TestBackendSlotsBounded(t *testing.T) {
	release := make(chan struct{})
	for i := 0; i < cap(backend); i++ {
		go bounded(func() (any, error) { <-release; return nil, nil })
	}
	defer close(release)
	time.Sleep(50 * time.Millisecond)
	t0 := time.Now()
	if _, err := bounded(func() (any, error) { return nil, nil }); !errors.Is(err, errBusy) {
		t.Fatalf("got %v, want BUSY", err)
	}
	if time.Since(t0) > time.Second {
		t.Fatal("BUSY was not immediate")
	}
}

type stallDaemon struct{ *fakeDaemon }

func (stallDaemon) Dial(protocol.Addr, uint16, time.Duration) (net.Conn, error) { select {} }

// A daemon operation that runs past DaemonStall makes the Bridge exit.
func TestStallWatchdogExits(t *testing.T) {
	old, oldExit := daemonStall.Load(), exit
	defer func() { daemonStall.Store(old); exit = oldExit }()
	daemonStall.Store(int64(100 * time.Millisecond))
	exited := make(chan int, 1)
	exit = func(code int) { exited <- code }
	f := &fakeDaemon{dialed: make(chan net.Conn, 1), incoming: make(chan net.Conn, 1)}
	s := &Server{D: stallDaemon{f}, Version: "test", R: func() (Registry, error) { return fakeRegistry{}, nil }}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	ss := &session{srv: s, streams: map[string]*stream{}, inflight: make(chan struct{}, MaxInFlight)}
	go ss.dispatch("stream.dial", json.RawMessage(`{"addr":"0:0000.0000.0002","port":1001,"timeout_ms":1000}`))
	select {
	case code := <-exited:
		if code != 3 {
			t.Fatalf("exit code %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a stalled dial did not trigger the watchdog")
	}
}

type blockingCloseConn struct{ net.Conn }

func (blockingCloseConn) Close() error { select {} }

// A stream whose close blocks in the daemon must not keep the ended session's port from a replacement Client.
func TestTeardownReleasesPortDespiteBlockingClose(t *testing.T) {
	old := daemonStall.Load()
	defer daemonStall.Store(old)
	daemonStall.Store(int64(time.Hour)) // keep the watchdog out of this test
	f, dial := start(t)
	c1 := dial()
	if _, e := c1.call("listen", map[string]any{"port": 1001}); e != "" {
		t.Fatal(e)
	}
	a, _ := net.Pipe()
	f.incoming <- addrConn{blockingCloseConn{a}, "0:0000.0000.0002:49152"}
	if ev := c1.next(); ev["event"] != "stream.incoming" {
		t.Fatalf("event %v", ev)
	}
	c1.c.Close()
	c2 := dial()
	for i := 0; i < 50; i++ {
		if _, e := c2.call("listen", map[string]any{"port": 1001}); e == "" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("port not released while a stream close was blocked")
}

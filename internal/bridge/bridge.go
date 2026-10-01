// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bridge implements Bridge API v1 (pan-protocol spec/BRIDGE_API.md): a thin local bridge that gives a
// Client access to the Pilot network. It opens and accepts streams, moves bytes and reports transport facts. It
// never builds, parses, signs or verifies application messages.
package bridge

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

const (
	APIVersion     = 1
	MaxLine        = 262144
	MaxRead        = 65552
	MaxStreams     = 16
	MaxInFlight    = 64 // concurrent requests per session; more are answered BUSY
	MaxTimeoutMS   = 30000
	maxWriteBase64 = 4 * ((MaxRead + 2) / 3)
)

// Daemon is the part of the Pilot driver the Bridge uses (an interface so tests can substitute a fake).
type Daemon interface {
	Info() (map[string]interface{}, error)
	Handshake(nodeID uint32, justification string) (map[string]interface{}, error)
	TrustedPeers() (map[string]interface{}, error)
	Dial(dst protocol.Addr, port uint16, timeout time.Duration) (net.Conn, error)
	Listen(port uint16) (Listener, error)
}

// Listener accepts incoming Pilot streams on one port.
type Listener interface {
	Accept() (net.Conn, error)
	Close() error
}

// Registry looks up the key the registry holds for a node.
type Registry interface {
	Lookup(nodeID uint32) (map[string]interface{}, error)
}

// Server serves Bridge API sessions.
type Server struct {
	D       Daemon
	R       func() (Registry, error) // dialled lazily and re-dialled after a failure
	Version string

	mu        sync.Mutex
	reg       Registry
	listeners map[uint16]*session // port → the session that listens on it
	opened    map[uint16]bool     // ports with an open daemon listener
	listenMu  sync.Mutex          // serializes listen (ownership, daemon Listen and rollback)
	self      protocol.Addr
	selfKey   string
}

type apiError string

func (e apiError) Error() string { return string(e) }

const (
	errBadRequest  apiError = "BAD_REQUEST"
	errUnsupported apiError = "UNSUPPORTED_API"
	errDaemon      apiError = "DAEMON_UNAVAILABLE"
	errRegistry    apiError = "REGISTRY_UNAVAILABLE"
	errNotFound    apiError = "NOT_FOUND"
	errUnknownConn apiError = "UNKNOWN_CONN"
	errBusy        apiError = "BUSY"
	errTimeout     apiError = "TIMEOUT"
	errDial        apiError = "DIAL_FAILED"
	errWrite       apiError = "WRITE_FAILED"
	errRead        apiError = "READ_FAILED"
	errClosed      apiError = "CLOSED"
	errInternal    apiError = "INTERNAL"
)

// Init reads the daemon's own address and key; it fails if the daemon is not reachable.
func (s *Server) Init() error {
	info, err := s.D.Info()
	if err != nil {
		return fmt.Errorf("daemon info: %w", err)
	}
	a, err := protocol.ParseAddr(fmt.Sprint(info["address"]))
	if err != nil {
		return fmt.Errorf("daemon address: %w", err)
	}
	key, _ := info["public_key"].(string)
	s.self, s.selfKey = a, key
	s.listeners = map[uint16]*session{}
	s.opened = map[uint16]bool{}
	return nil
}

// Serve accepts sessions on ln until it fails. check rejects connections from other users.
func (s *Server) Serve(ln net.Listener, check func(net.Conn) error) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		if err := check(c); err != nil {
			log.Printf("session refused: %v", err)
			c.Close()
			continue
		}
		ss := &session{srv: s, c: c, streams: map[string]*stream{}, inflight: make(chan struct{}, MaxInFlight)}
		go ss.run()
	}
}

type session struct {
	srv      *Server
	c        net.Conn
	wmu      sync.Mutex
	mu       sync.Mutex
	streams  map[string]*stream
	reserved int // dials in progress, counted against MaxStreams
	closed   bool
	inflight chan struct{}
}

// stream is one open Pilot stream. Reads and writes are each serialized, so a deadline set for one read (or write)
// cannot be overwritten by a concurrent call of the same kind; calls of the same kind run one at a time.
type stream struct {
	c        net.Conn
	rmu, wmu sync.Mutex
}

type request struct {
	ID     *uint64         `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

func (ss *session) send(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	ss.wmu.Lock()
	defer ss.wmu.Unlock()
	ss.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := ss.c.Write(append(b, '\n')); err != nil {
		ss.c.Close() // a Client that cannot take responses loses the session
	}
}

func (ss *session) run() {
	defer ss.end()
	r := bufio.NewReaderSize(ss.c, 64*1024)
	for {
		line, err := readLine(r, MaxLine)
		if err != nil {
			return
		}
		var req request
		d := json.NewDecoder(strings.NewReader(string(line)))
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil || req.ID == nil || req.Method == "" {
			return // a malformed line ends the session: the Client is out of sync
		}
		select {
		case ss.inflight <- struct{}{}:
		default:
			ss.send(map[string]any{"id": *req.ID, "error": map[string]string{"code": string(errBusy)}})
			continue
		}
		go func(req request) {
			defer func() { <-ss.inflight }()
			res, err := ss.dispatch(req.Method, req.Params)
			if err != nil {
				var ae apiError
				if !errors.As(err, &ae) {
					ae = errInternal
				}
				ss.send(map[string]any{"id": *req.ID, "error": map[string]string{"code": string(ae)}})
				return
			}
			ss.send(map[string]any{"id": *req.ID, "result": res})
		}(req)
	}
}

// readLine reads one '\n'-terminated line of at most max bytes.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var out []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if len(out) > max {
			return nil, errors.New("line too long")
		}
		if !isPrefix {
			return out, nil
		}
	}
}

func (ss *session) end() {
	ss.mu.Lock()
	ss.closed = true
	streams := ss.streams
	ss.streams = map[string]*stream{}
	ss.mu.Unlock()
	for _, st := range streams {
		st.c.Close()
	}
	ss.srv.mu.Lock()
	for port, owner := range ss.srv.listeners {
		if owner == ss {
			delete(ss.srv.listeners, port) // the accept loop keeps running; streams for this port are refused until a new listen
		}
	}
	ss.srv.mu.Unlock()
	ss.c.Close()
}

func newHandle() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// reserve claims one stream slot before a dial, so concurrent dials cannot exceed MaxStreams.
func (ss *session) reserve() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.closed || len(ss.streams)+ss.reserved >= MaxStreams {
		return false
	}
	ss.reserved++
	return true
}

// add registers c; reserved says whether a slot was claimed with reserve. It fails (and the caller closes c) if
// the session ended or, for unreserved incoming streams, the session is full.
func (ss *session) add(c net.Conn, reserved bool) (string, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if reserved {
		ss.reserved--
	}
	if ss.closed || (!reserved && len(ss.streams)+ss.reserved >= MaxStreams) {
		return "", false
	}
	h := newHandle()
	ss.streams[h] = &stream{c: c}
	return h, true
}

func (ss *session) release() {
	ss.mu.Lock()
	ss.reserved--
	ss.mu.Unlock()
}

func (ss *session) get(h string) (*stream, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	st, ok := ss.streams[h]
	if !ok {
		return nil, errUnknownConn
	}
	return st, nil
}

// drop closes and forgets a handle (after stream.close or a fatal stream error).
func (ss *session) drop(h string) {
	ss.mu.Lock()
	st := ss.streams[h]
	delete(ss.streams, h)
	ss.mu.Unlock()
	if st != nil {
		st.c.Close()
	}
}

func decode(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return errBadRequest
	}
	return nil
}

func timeout(ms int) (time.Duration, error) {
	if ms < 1 || ms > MaxTimeoutMS {
		return 0, errBadRequest
	}
	return time.Duration(ms) * time.Millisecond, nil
}

// nodeAddr renders a node of our own network in canonical text form.
// internalTimeout bounds calls that take no timeout_ms (BRIDGE_API §5): handshake, trusted peers, registry lookup.
const internalTimeout = 10 * time.Second

// bounded runs f with internalTimeout. On expiry it answers TIMEOUT; f keeps running until the daemon or registry
// returns, and its result is discarded.
func bounded(f func() (any, error)) (any, error) {
	type out struct {
		v   any
		err error
	}
	ch := make(chan out, 1)
	go func() { v, err := f(); ch <- out{v, err} }()
	select {
	case o := <-ch:
		return o.v, o.err
	case <-time.After(internalTimeout):
		return nil, errTimeout
	}
}

func (s *Server) nodeAddr(node uint32) string {
	return protocol.Addr{Network: s.self.Network, Node: node}.String()
}

func parseAddr(a string) (protocol.Addr, error) {
	p, err := protocol.ParseAddr(a)
	if err != nil || p.String() != a { // only the canonical text form is accepted
		return protocol.Addr{}, errBadRequest
	}
	return p, nil
}

func (ss *session) dispatch(method string, raw json.RawMessage) (any, error) {
	s := ss.srv
	switch method {
	case "hello":
		var p struct {
			API int `json:"api"`
		}
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		if p.API != APIVersion {
			return nil, errUnsupported
		}
		return map[string]any{"api": APIVersion, "bridge_version": s.Version, "addr": s.self.String(), "public_key": s.selfKey}, nil

	case "peer.handshake":
		var p struct {
			Addr   string `json:"addr"`
			Reason string `json:"reason"`
		}
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		a, err := parseAddr(p.Addr)
		if err != nil || len(p.Reason) == 0 || len(p.Reason) > 256 {
			return nil, errBadRequest
		}
		return bounded(func() (any, error) {
			if _, err := s.D.Handshake(a.Node, p.Reason); err != nil {
				return nil, errDaemon
			}
			return map[string]any{}, nil
		})

	case "peer.trusted":
		if err := decode(raw, &struct{}{}); err != nil {
			return nil, err
		}
		v, err := bounded(func() (any, error) { return s.D.TrustedPeers() })
		if errors.Is(err, errTimeout) {
			return nil, errTimeout
		}
		res, _ := v.(map[string]interface{})
		if err != nil || res == nil {
			return nil, errDaemon
		}
		peers := []map[string]string{}
		list, _ := res["trusted"].([]any)
		for _, v := range list {
			t, ok := v.(map[string]any)
			if !ok {
				continue
			}
			id, ok := t["node_id"].(float64)
			if !ok || id < 0 || id > 0xFFFFFFFF || id != float64(uint32(id)) {
				continue
			}
			k, _ := t["public_key"].(string)
			peers = append(peers, map[string]string{"addr": s.nodeAddr(uint32(id)), "public_key": k})
		}
		return map[string]any{"peers": peers}, nil

	case "registry.lookup":
		var p struct {
			Addr string `json:"addr"`
		}
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		a, err := parseAddr(p.Addr)
		if err != nil {
			return nil, err
		}
		return bounded(func() (any, error) { return s.lookup(a) })

	case "listen":
		var p struct {
			Port int `json:"port"`
		}
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		if p.Port < 1 || p.Port > 65535 {
			return nil, errBadRequest
		}
		return map[string]any{}, s.listen(ss, uint16(p.Port))

	case "stream.dial":
		var p struct {
			Addr      string `json:"addr"`
			Port      int    `json:"port"`
			TimeoutMS int    `json:"timeout_ms"`
		}
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		a, err := parseAddr(p.Addr)
		if err != nil || p.Port < 1 || p.Port > 65535 {
			return nil, errBadRequest
		}
		to, err := timeout(p.TimeoutMS)
		if err != nil {
			return nil, err
		}
		if !ss.reserve() {
			return nil, errBusy
		}
		c, err := s.D.Dial(a, uint16(p.Port), to)
		if err != nil {
			ss.release()
			return nil, errDial
		}
		h, ok := ss.add(c, true)
		if !ok {
			c.Close()
			return nil, errClosed
		}
		return map[string]any{"conn": h}, nil

	case "stream.write":
		var p struct {
			Conn      string `json:"conn"`
			DataB64   string `json:"data_b64"`
			TimeoutMS int    `json:"timeout_ms"`
		}
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		if len(p.DataB64) > maxWriteBase64 {
			return nil, errBadRequest
		}
		data, err := base64.StdEncoding.DecodeString(p.DataB64)
		if err != nil || len(data) == 0 {
			return nil, errBadRequest
		}
		to, err := timeout(p.TimeoutMS)
		if err != nil {
			return nil, err
		}
		st, err := ss.get(p.Conn)
		if err != nil {
			return nil, err
		}
		st.wmu.Lock()
		st.c.SetWriteDeadline(time.Now().Add(to))
		n, err := st.c.Write(data)
		st.wmu.Unlock()
		if err != nil {
			// A failed or timed-out write leaves an unknown number of bytes sent: the stream is unusable.
			ss.drop(p.Conn)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return nil, errTimeout
			}
			return nil, errWrite
		}
		return map[string]any{"written": n}, nil

	case "stream.read":
		var p struct {
			Conn      string `json:"conn"`
			Max       int    `json:"max"`
			TimeoutMS int    `json:"timeout_ms"`
		}
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		if p.Max < 1 || p.Max > MaxRead {
			return nil, errBadRequest
		}
		to, err := timeout(p.TimeoutMS)
		if err != nil {
			return nil, err
		}
		st, err := ss.get(p.Conn)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, p.Max)
		st.rmu.Lock()
		st.c.SetReadDeadline(time.Now().Add(to))
		n, err := st.c.Read(buf)
		st.rmu.Unlock()
		switch {
		case n > 0:
			return map[string]any{"data_b64": base64.StdEncoding.EncodeToString(buf[:n]), "eof": false}, nil
		case err == nil:
			return map[string]any{"data_b64": "", "eof": false}, nil
		case errors.Is(err, io.EOF):
			return map[string]any{"data_b64": "", "eof": true}, nil
		case errors.Is(err, os.ErrDeadlineExceeded):
			return nil, errTimeout // nothing was consumed; the stream stays usable
		}
		ss.drop(p.Conn)
		return nil, errRead

	case "stream.close":
		var p struct {
			Conn string `json:"conn"`
		}
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		if _, err := ss.get(p.Conn); err != nil {
			return nil, err
		}
		ss.drop(p.Conn)
		return map[string]any{}, nil
	}
	return nil, errBadRequest
}

func (s *Server) lookup(a protocol.Addr) (any, error) {
	s.mu.Lock()
	reg := s.reg
	s.mu.Unlock()
	if reg == nil {
		r, err := s.R()
		if err != nil {
			return nil, errRegistry
		}
		s.mu.Lock()
		s.reg, reg = r, r
		s.mu.Unlock()
	}
	res, err := reg.Lookup(a.Node)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil, errNotFound
		}
		s.mu.Lock()
		if s.reg == reg {
			s.reg = nil // re-dial on the next lookup
		}
		s.mu.Unlock()
		return nil, errRegistry
	}
	k, _ := res["public_key"].(string)
	return map[string]any{"public_key": k}, nil
}

// listen makes ss the receiver of incoming streams on port. Ownership is exclusive; an ended session can never
// become (or stay) the owner. The daemon listener is opened once per port and kept for the Bridge's lifetime;
// streams arriving while no session listens are closed.
func (s *Server) listen(ss *session, port uint16) error {
	s.listenMu.Lock()
	defer s.listenMu.Unlock()
	s.mu.Lock()
	if owner, ok := s.listeners[port]; ok && owner != ss {
		s.mu.Unlock()
		return errBusy
	}
	ss.mu.Lock()
	closed := ss.closed
	ss.mu.Unlock()
	if closed { // end() sets closed before it removes ownership, so this check under s.mu cannot race with it
		s.mu.Unlock()
		return errClosed
	}
	s.listeners[port] = ss
	opened := s.opened[port]
	s.mu.Unlock()
	if opened {
		return nil
	}
	l, err := s.D.Listen(port)
	if err != nil {
		s.mu.Lock()
		if s.listeners[port] == ss {
			delete(s.listeners, port)
		}
		s.mu.Unlock()
		return errDaemon
	}
	s.mu.Lock()
	s.opened[port] = true
	s.mu.Unlock()
	go s.accept(l, port)
	return nil
}

func (s *Server) accept(l Listener, port uint16) {
	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("listener on port %d stopped: %v", port, err)
			os.Exit(2) // the daemon connection is gone; the supervisor restarts the Bridge
		}
		s.mu.Lock()
		owner := s.listeners[port]
		s.mu.Unlock()
		if owner == nil {
			c.Close()
			continue
		}
		sa, err := protocol.ParseSocketAddr(c.RemoteAddr().String())
		if err != nil {
			c.Close()
			continue
		}
		h, ok := owner.add(c, false)
		if !ok {
			c.Close()
			continue
		}
		owner.send(map[string]any{"event": "stream.incoming", "conn": h, "port": port, "remote_addr": sa.Addr.String()})
	}
}

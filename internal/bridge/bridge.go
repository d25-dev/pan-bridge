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
		ss := &session{srv: s, c: c, streams: map[string]net.Conn{}}
		go ss.run()
	}
}

type session struct {
	srv     *Server
	c       net.Conn
	wmu     sync.Mutex
	mu      sync.Mutex
	streams map[string]net.Conn
	closed  bool
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
		go func(req request) {
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
	ss.streams = map[string]net.Conn{}
	ss.mu.Unlock()
	for _, c := range streams {
		c.Close()
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

func (ss *session) add(c net.Conn) (string, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.closed || len(ss.streams) >= MaxStreams {
		return "", false
	}
	h := newHandle()
	ss.streams[h] = c
	return h, true
}

func (ss *session) get(h string) (net.Conn, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	c, ok := ss.streams[h]
	if !ok {
		return nil, errUnknownConn
	}
	return c, nil
}

func (ss *session) drop(h string) {
	ss.mu.Lock()
	c := ss.streams[h]
	delete(ss.streams, h)
	ss.mu.Unlock()
	if c != nil {
		c.Close()
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
		if _, err := s.D.Handshake(a.Node, p.Reason); err != nil {
			return nil, errDaemon
		}
		return map[string]any{}, nil

	case "peer.trusted":
		if err := decode(raw, &struct{}{}); err != nil {
			return nil, err
		}
		res, err := s.D.TrustedPeers()
		if err != nil {
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
		return s.lookup(a)

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
		c, err := s.D.Dial(a, uint16(p.Port), to)
		if err != nil {
			return nil, errDial
		}
		h, ok := ss.add(c)
		if !ok {
			c.Close()
			return nil, errBusy
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
		c, err := ss.get(p.Conn)
		if err != nil {
			return nil, err
		}
		c.SetWriteDeadline(time.Now().Add(to))
		n, err := c.Write(data)
		if err != nil {
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
		c, err := ss.get(p.Conn)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, p.Max)
		c.SetReadDeadline(time.Now().Add(to))
		n, err := c.Read(buf)
		switch {
		case n > 0:
			return map[string]any{"data_b64": base64.StdEncoding.EncodeToString(buf[:n]), "eof": false}, nil
		case err == nil:
			return map[string]any{"data_b64": "", "eof": false}, nil
		case errors.Is(err, io.EOF):
			return map[string]any{"data_b64": "", "eof": true}, nil
		case errors.Is(err, os.ErrDeadlineExceeded):
			return nil, errTimeout
		}
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

// listen makes ss the receiver of incoming streams on port. The daemon listener is opened once per port and
// kept for the Bridge's lifetime; streams arriving while no session listens are closed.
func (s *Server) listen(ss *session, port uint16) error {
	s.mu.Lock()
	if owner, ok := s.listeners[port]; ok && owner != ss {
		s.mu.Unlock()
		return errBusy
	}
	opened := s.opened[port]
	s.listeners[port] = ss
	s.opened[port] = true
	s.mu.Unlock()
	if opened {
		return nil
	}
	l, err := s.D.Listen(port)
	if err != nil {
		s.mu.Lock()
		delete(s.listeners, port)
		delete(s.opened, port)
		s.mu.Unlock()
		return errDaemon
	}
	go func() {
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
			h, ok := owner.add(c)
			if !ok {
				c.Close()
				continue
			}
			owner.send(map[string]any{"event": "stream.incoming", "conn": h, "port": port, "remote_addr": sa.Addr.String()})
		}
	}()
	return nil
}

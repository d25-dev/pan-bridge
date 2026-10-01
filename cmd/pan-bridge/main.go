// SPDX-License-Identifier: AGPL-3.0-or-later

// pan-bridge serves Bridge API v1 (pan-protocol spec/BRIDGE_API.md) on a local Unix socket for one Client.
package main

import (
	"flag"
	"log"
	"net"
	"time"

	"github.com/pilot-protocol/common/driver"
	"github.com/pilot-protocol/common/protocol"
	registry "github.com/pilot-protocol/common/registry/client"
	"github.com/uyah/pan-bridge/internal/bridge"
)

var version = "0.1.0-dev"

type daemon struct{ d *driver.Driver }

func (x daemon) Info() (map[string]interface{}, error) { return x.d.Info() }
func (x daemon) Handshake(n uint32, j string) (map[string]interface{}, error) {
	return x.d.Handshake(n, j)
}
func (x daemon) TrustedPeers() (map[string]interface{}, error) { return x.d.TrustedPeers() }
func (x daemon) Dial(a protocol.Addr, port uint16, t time.Duration) (net.Conn, error) {
	return x.d.DialAddrTimeout(a, port, t)
}
func (x daemon) Listen(port uint16) (bridge.Listener, error) { return x.d.Listen(port) }

func main() {
	dir := flag.String("runtime-dir", "", "directory for bridge.sock (0700, created if missing)")
	sock := flag.String("daemon-socket", "", "Pilot daemon IPC socket")
	reg := flag.String("registry", "", "registry address host:port (plain TCP)")
	flag.Parse()
	if *dir == "" || *sock == "" || *reg == "" {
		log.Fatal("need -runtime-dir, -daemon-socket and -registry")
	}
	var d *driver.Driver
	var err error
	for i := 0; i < 100; i++ { // the daemon may still be starting
		if d, err = driver.Connect(*sock); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		log.Fatalf("daemon: %v", err)
	}
	srv := &bridge.Server{D: daemon{d}, Version: version, R: func() (bridge.Registry, error) { return registry.Dial(*reg) }}
	if err := srv.Init(); err != nil {
		log.Fatal(err)
	}
	ln, path, err := bridge.ListenSocket(*dir)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("pan-bridge %s serving Bridge API v1 on %s", version, path)
	log.Fatal(srv.Serve(ln, bridge.SameUser))
}

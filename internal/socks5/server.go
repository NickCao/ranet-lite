// Package socks5 exposes the ranet mesh as a local SOCKS5 proxy: any
// application that speaks SOCKS5 can reach mesh-only destinations without
// needing a TUN device or root privileges, since everything after the
// initial CONNECT is handled by gvisor's userspace stack.
//
// The protocol itself (handshake, auth negotiation, CONNECT semantics,
// RFC 1928 reply framing) is handled by go-gost/x's mature SOCKS5
// implementation; the only glue this package adds is a chain.Router that
// dials through the mesh instead of the host network (see router.go).
package socks5

import (
	"context"
	"fmt"
	"net"

	"github.com/go-gost/core/handler"
	v5 "github.com/go-gost/x/handler/socks/v5"
	xlogger "github.com/go-gost/x/logger"
	"github.com/nickcao/ranet-client/internal/netstack"
)

type Server struct {
	ln net.Listener
	h  handler.Handler
}

// New starts a SOCKS5 listener on listenAddr (a normal host address, e.g.
// "127.0.0.1:1080" — local applications connect to this over the regular
// network stack; only their upstream traffic is routed through mesh).
func New(listenAddr string, mesh *netstack.Mesh) (*Server, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: listen: %w", err)
	}
	h := v5.NewHandler(
		handler.RouterOption(newMeshRouter(mesh)),
		// core/logger.Default() returns nil until something calls
		// SetDefault (normally done by go-gost/x's own bootstrap, which we
		// don't use) — an explicit logger avoids a nil-interface panic the
		// first time the handler logs anything.
		handler.LoggerOption(xlogger.NewLogger()),
	)
	if err := h.Init(nil); err != nil {
		ln.Close()
		return nil, fmt.Errorf("socks5: init handler: %w", err)
	}
	return &Server{ln: ln, h: h}, nil
}

func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// Serve accepts connections until the listener is closed.
func (s *Server) Serve() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			s.h.Handle(context.Background(), conn)
		}()
	}
}

func (s *Server) Close() error {
	return s.ln.Close()
}

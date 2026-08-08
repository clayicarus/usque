package internal

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	hy2server "github.com/apernet/hysteria/core/v2/server"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const hysteria2DialTimeout = 15 * time.Second

// Hysteria2Config holds configuration for the Hysteria2 server.
type Hysteria2Config struct {
	ListenAddr  string
	TLSCertFile string
	TLSKeyFile  string
	Password    string
	TunNet      *netstack.Net
	Resolver    *TunnelDNSResolver
	UDPEnabled  bool
	UDPTimeout  time.Duration
	Logger      *log.Logger
	// MasqueradeHandler receives non-authenticated HTTP/3 requests. A nil handler
	// makes the server return 404.
	MasqueradeHandler http.Handler
}

// Hysteria2Server exposes the WARP netstack through the standard Hysteria2
// server implementation.
type Hysteria2Server struct {
	cfg         Hysteria2Config
	certificate tls.Certificate
}

// NewHysteria2Server validates the WARP-specific configuration and loads the
// certificate used by the Hysteria2 listener.
func NewHysteria2Server(cfg Hysteria2Config) (*Hysteria2Server, error) {
	if cfg.TunNet == nil {
		return nil, errors.New("hysteria2: TunNet is required")
	}
	if cfg.Password == "" {
		return nil, errors.New("hysteria2: Password is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.UDPTimeout <= 0 {
		cfg.UDPTimeout = 60 * time.Second
	}

	certificate, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: failed to load TLS certificate: %w", err)
	}

	return &Hysteria2Server{cfg: cfg, certificate: certificate}, nil
}

// Start serves Hysteria2 connections until ctx is cancelled or the listener
// fails. The upstream core owns HTTP/3, authentication framing, stream
// dispatch, UDP fragmentation, and UDP session lifecycle handling.
func (s *Hysteria2Server) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	addr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("hysteria2: failed to resolve listen address: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("hysteria2: failed to listen on UDP: %w", err)
	}

	server, err := hy2server.NewServer(&hy2server.Config{
		TLSConfig: hy2server.TLSConfig{
			Certificates: []tls.Certificate{s.certificate},
		},
		Conn:           conn,
		Outbound:       hysteria2Outbound{server: s},
		Authenticator:  hysteria2Authenticator{password: s.cfg.Password},
		DisableUDP:     !s.cfg.UDPEnabled,
		UDPIdleTimeout: s.cfg.UDPTimeout,
		MasqHandler:    s.cfg.MasqueradeHandler,
	})
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("hysteria2: failed to create server: %w", err)
	}

	s.cfg.Logger.Printf("Hysteria2 server listening on %s", conn.LocalAddr())
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()

	err = server.Serve()
	close(done)
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("hysteria2: server stopped: %w", err)
	}
	return nil
}

type hysteria2Authenticator struct {
	password string
}

func (a hysteria2Authenticator) Authenticate(_ net.Addr, auth string, _ uint64) (bool, string) {
	if subtle.ConstantTimeCompare([]byte(auth), []byte(a.password)) != 1 {
		return false, ""
	}
	return true, "usque"
}

type hysteria2Outbound struct {
	server *Hysteria2Server
}

func (o hysteria2Outbound) TCP(addr string) (net.Conn, error) {
	return o.server.dial("tcp", addr)
}

func (o hysteria2Outbound) UDP(addr string) (hy2server.UDPConn, error) {
	conn, err := o.server.dial("udp", addr)
	if err != nil {
		return nil, err
	}
	return connectedHysteria2UDPConn{Conn: conn}, nil
}

// connectedHysteria2UDPConn is a connected UDP socket through netstack. The
// Hysteria2 core permits connected outbound UDP sockets, so each session is
// pinned to the target from its first datagram.
type connectedHysteria2UDPConn struct {
	net.Conn
}

func (c connectedHysteria2UDPConn) ReadFrom(b []byte) (int, string, error) {
	n, err := c.Read(b)
	addr := ""
	if remoteAddr := c.RemoteAddr(); remoteAddr != nil {
		addr = remoteAddr.String()
	}
	return n, addr, err
}

func (c connectedHysteria2UDPConn) WriteTo(b []byte, _ string) (int, error) {
	return c.Write(b)
}

func (s *Hysteria2Server) dial(network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hysteria2DialTimeout)
	defer cancel()

	if s.cfg.Resolver == nil || s.cfg.Resolver.TunNet != nil {
		return s.cfg.TunNet.DialContext(ctx, network, addr)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) != nil {
		return s.cfg.TunNet.DialContext(ctx, network, addr)
	}

	_, ip, err := s.cfg.Resolver.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	return s.cfg.TunNet.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
}

package cmd

import (
	"context"
	"log"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var hysteria2Cmd = &cobra.Command{
	Use:   "hysteria2",
	Short: "Expose Warp as a Hysteria2 proxy server",
	Long: "Hysteria2 proxy server mode. Clients supporting the Hysteria2 protocol (e.g. sing-box, Clash.Meta) " +
		"can connect and have their traffic routed through the WARP tunnel. Requires a TLS certificate.",
	Aliases: []string{"hy2"},
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		sni, err := cmd.Flags().GetString("sni-address")
		if err != nil {
			cmd.Printf("Failed to get SNI address: %v\n", err)
			return
		}

		privKey, err := config.AppConfig.GetEcPrivateKey()
		if err != nil {
			cmd.Printf("Failed to get private key: %v\n", err)
			return
		}
		peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
		if err != nil {
			cmd.Printf("Failed to get public key: %v\n", err)
			return
		}

		cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
		if err != nil {
			cmd.Printf("Failed to generate cert: %v\n", err)
			return
		}

		insecure, err := cmd.Flags().GetBool("insecure")
		if err != nil {
			cmd.Printf("Failed to get insecure flag: %v\n", err)
			return
		}

		tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni, insecure)
		if err != nil {
			cmd.Printf("Failed to prepare TLS config: %v\n", err)
			return
		}

		keepalivePeriod, err := cmd.Flags().GetDuration("keepalive-period")
		if err != nil {
			cmd.Printf("Failed to get keepalive period: %v\n", err)
			return
		}
		initialPacketSize, err := cmd.Flags().GetUint16("initial-packet-size")
		if err != nil {
			cmd.Printf("Failed to get initial packet size: %v\n", err)
			return
		}

		connectPort, err := cmd.Flags().GetInt("connect-port")
		if err != nil {
			cmd.Printf("Failed to get connect port: %v\n", err)
			return
		}

		useHTTP2, err := cmd.Flags().GetBool("http2")
		if err != nil {
			cmd.Printf("Failed to get HTTP/2 flag: %v\n", err)
			return
		}

		useIPv6, err := cmd.Flags().GetBool("ipv6")
		if err != nil {
			cmd.Printf("Failed to get ipv6 flag: %v\n", err)
			return
		}

		endpoint, err := config.SelectEndpointFromConfig(useHTTP2, useIPv6, connectPort)
		if err != nil {
			cmd.Printf("Failed to select endpoint: %v\n", err)
			return
		}

		if insecure {
			config.WarnInsecure()
		}

		if useHTTP2 {
			config.LogHTTP2Endpoint(endpoint)
		}

		tunnelIPv4, err := cmd.Flags().GetBool("no-tunnel-ipv4")
		if err != nil {
			cmd.Printf("Failed to get no tunnel IPv4: %v\n", err)
			return
		}

		tunnelIPv6, err := cmd.Flags().GetBool("no-tunnel-ipv6")
		if err != nil {
			cmd.Printf("Failed to get no tunnel IPv6: %v\n", err)
			return
		}

		var localAddresses []netip.Addr
		if !tunnelIPv4 {
			v4, err := netip.ParseAddr(config.AppConfig.IPv4)
			if err != nil {
				cmd.Printf("Failed to parse IPv4 address: %v\n", err)
				return
			}
			localAddresses = append(localAddresses, v4)
		}
		if !tunnelIPv6 {
			v6, err := netip.ParseAddr(config.AppConfig.IPv6)
			if err != nil {
				cmd.Printf("Failed to parse IPv6 address: %v\n", err)
				return
			}
			localAddresses = append(localAddresses, v6)
		}

		dnsServers, err := cmd.Flags().GetStringArray("dns")
		if err != nil {
			cmd.Printf("Failed to get DNS servers: %v\n", err)
			return
		}

		var dnsAddrs []netip.Addr
		for _, dns := range dnsServers {
			addr, err := netip.ParseAddr(dns)
			if err != nil {
				cmd.Printf("Failed to parse DNS server: %v\n", err)
				return
			}
			dnsAddrs = append(dnsAddrs, addr)
		}

		dnsTimeout, err := cmd.Flags().GetDuration("dns-timeout")
		if err != nil {
			cmd.Printf("Failed to get DNS timeout: %v\n", err)
			return
		}

		localDNS, err := cmd.Flags().GetBool("local-dns")
		if err != nil {
			cmd.Printf("Failed to get local-dns flag: %v\n", err)
			return
		}

		systemDNS, err := cmd.Flags().GetBool("system-dns")
		if err != nil {
			cmd.Printf("Failed to get system-dns flag: %v\n", err)
			return
		}
		if systemDNS && !localDNS {
			log.Println("Warning: --system-dns only applies with -l; ignoring")
			systemDNS = false
		}

		mtu, err := cmd.Flags().GetInt("mtu")
		if err != nil {
			cmd.Printf("Failed to get MTU: %v\n", err)
			return
		}
		if mtu != 1280 {
			log.Println("Warning: MTU is not the default 1280. This is not supported. Packet loss and other issues may occur.")
		}

		reconnectDelay, err := cmd.Flags().GetDuration("reconnect-delay")
		if err != nil {
			cmd.Printf("Failed to get reconnect delay: %v\n", err)
			return
		}

		alwaysReconnect, err := cmd.Flags().GetBool("always-reconnect")
		if err != nil {
			cmd.Printf("Failed to get always-reconnect flag: %v\n", err)
			return
		}

		onConnect, err := cmd.Flags().GetString("on-connect")
		if err != nil {
			cmd.Printf("Failed to get on-connect flag: %v\n", err)
			return
		}

		onDisconnect, err := cmd.Flags().GetString("on-disconnect")
		if err != nil {
			cmd.Printf("Failed to get on-disconnect flag: %v\n", err)
			return
		}

		// Hysteria2-specific flags
		listenAddr, err := cmd.Flags().GetString("listen")
		if err != nil {
			cmd.Printf("Failed to get listen address: %v\n", err)
			return
		}

		hy2Password, err := cmd.Flags().GetString("password")
		if err != nil {
			cmd.Printf("Failed to get password: %v\n", err)
			return
		}
		if hy2Password == "" {
			cmd.Println("Error: --password is required for Hysteria2 server")
			return
		}

		tlsCertFile, err := cmd.Flags().GetString("tls-cert")
		if err != nil {
			cmd.Printf("Failed to get TLS cert path: %v\n", err)
			return
		}
		if tlsCertFile == "" {
			cmd.Println("Error: --tls-cert is required for Hysteria2 server")
			return
		}

		tlsKeyFile, err := cmd.Flags().GetString("tls-key")
		if err != nil {
			cmd.Printf("Failed to get TLS key path: %v\n", err)
			return
		}
		if tlsKeyFile == "" {
			cmd.Println("Error: --tls-key is required for Hysteria2 server")
			return
		}

		udpEnabled, err := cmd.Flags().GetBool("udp")
		if err != nil {
			cmd.Printf("Failed to get UDP flag: %v\n", err)
			return
		}

		udpTimeout, err := cmd.Flags().GetDuration("udp-timeout")
		if err != nil {
			cmd.Printf("Failed to get UDP timeout: %v\n", err)
			return
		}

		masqueradeURL, err := cmd.Flags().GetString("masquerade")
		if err != nil {
			cmd.Printf("Failed to get masquerade URL: %v\n", err)
			return
		}

		hookEnv := map[string]string{
			"USQUE_MODE": "hysteria2",
			"USQUE_IPV4": config.AppConfig.IPv4,
			"USQUE_IPV6": config.AppConfig.IPv6,
		}

		tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, mtu)
		if err != nil {
			cmd.Printf("Failed to create virtual TUN device: %v\n", err)
			return
		}
		defer func() { _ = tunDev.Close() }()

		go api.MaintainTunnel(context.Background(), api.MaintainTunnelConfig{
			TLSConfig:         tlsConfig,
			KeepalivePeriod:   keepalivePeriod,
			InitialPacketSize: initialPacketSize,
			Endpoint:          endpoint,
			Device:            api.NewNetstackAdapter(tunDev),
			MTU:               mtu,
			ReconnectDelay:    reconnectDelay,
			AlwaysReconnect:   alwaysReconnect,
			UseHTTP2:          useHTTP2,
			OnConnect:         onConnect,
			OnDisconnect:      onDisconnect,
			HookEnv:           hookEnv,
		})

		resolver := &internal.TunnelDNSResolver{
			DNSAddrs:      dnsAddrs,
			Timeout:       dnsTimeout,
			UseOSResolver: localDNS && systemDNS,
		}
		if !localDNS {
			resolver.TunNet = tunNet
		}

		var masqueradeHandler http.Handler
		if masqueradeURL != "" {
			masqueradeHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>"))
			})
		}

		hy2Server, err := internal.NewHysteria2Server(internal.Hysteria2Config{
			ListenAddr:        listenAddr,
			TLSCertFile:       tlsCertFile,
			TLSKeyFile:        tlsKeyFile,
			Password:          hy2Password,
			TunNet:            tunNet,
			Resolver:          resolver,
			UDPEnabled:        udpEnabled,
			UDPTimeout:        udpTimeout,
			MasqueradeHandler: masqueradeHandler,
			Logger:            log.New(internal.NewTZStampWriter(os.Stderr), "hy2: ", 0),
		})
		if err != nil {
			cmd.Printf("Failed to create Hysteria2 server: %v\n", err)
			return
		}

		log.Printf("Hysteria2 server starting on %s (UDP: %v)", listenAddr, udpEnabled)
		if err := hy2Server.Start(context.Background()); err != nil {
			cmd.Printf("Hysteria2 server error: %v\n", err)
		}
	},
}

func init() {
	// Hysteria2-specific flags
	hysteria2Cmd.Flags().String("listen", ":443", "Address to listen on for Hysteria2 connections")
	hysteria2Cmd.Flags().StringP("password", "w", "", "Authentication password for Hysteria2 clients (required)")
	hysteria2Cmd.Flags().String("tls-cert", "", "Path to TLS certificate file (required)")
	hysteria2Cmd.Flags().String("tls-key", "", "Path to TLS private key file (required)")
	hysteria2Cmd.Flags().Bool("udp", true, "Enable UDP relay support")
	hysteria2Cmd.Flags().Duration("udp-timeout", 60*time.Second, "Idle timeout for UDP relay sessions")
	hysteria2Cmd.Flags().String("masquerade", "", "Enable a simple HTML response for non-authenticated requests")

	// MASQUE tunnel flags (same as other modes)
	hysteria2Cmd.Flags().IntP("connect-port", "P", 443, "Used port for MASQUE connection")
	hysteria2Cmd.Flags().StringArrayP("dns", "d", []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}, "DNS servers for the tunnel stack; with -l also used for proxy name lookups (unless --system-dns)")
	hysteria2Cmd.Flags().DurationP("dns-timeout", "t", 2*time.Second, "Timeout for DNS queries")
	hysteria2Cmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	hysteria2Cmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	hysteria2Cmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	hysteria2Cmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	hysteria2Cmd.Flags().DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connection")
	hysteria2Cmd.Flags().IntP("mtu", "m", 1280, "MTU for MASQUE connection")
	hysteria2Cmd.Flags().Uint16P("initial-packet-size", "i", 0, "Custom initial packet size for MASQUE connection (default: auto with PMTU discovery)")
	hysteria2Cmd.Flags().DurationP("reconnect-delay", "r", 1*time.Second, "Delay between reconnect attempts")
	hysteria2Cmd.Flags().Bool("always-reconnect", false, "Always reconnect after tunnel loss, even when idle")
	hysteria2Cmd.Flags().Bool("http2", false, "Use HTTP/2 over TCP+TLS instead of HTTP/3 over QUIC."+config.EndpointHelpSuffixH2)
	hysteria2Cmd.Flags().Bool("insecure", false, "Disable endpoint certificate pinning and trust any certificate")
	hysteria2Cmd.Flags().BoolP("local-dns", "l", false, "Do not send proxy DNS through the tunnel; use -d over the host instead. Add --system-dns to use the OS resolver instead of -d")
	hysteria2Cmd.Flags().Bool("system-dns", false, "With -l, resolve names via the OS (e.g. /etc/resolv.conf) instead of -d")
	hysteria2Cmd.Flags().String("on-connect", "", "Path to an executable to run after each successful tunnel connect (no args; context via USQUE_* env vars)")
	hysteria2Cmd.Flags().String("on-disconnect", "", "Path to an executable to run after each tunnel disconnect (no args; context via USQUE_* env vars)")
	rootCmd.AddCommand(hysteria2Cmd)
}

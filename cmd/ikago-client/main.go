package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"ikago/internal/addr"
	"ikago/internal/config"
	"ikago/internal/crypto"
	"ikago/internal/exec"
	"ikago/internal/log"
	"ikago/internal/pcap"
	"ikago/internal/stat"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sparrc/go-ping"
	"github.com/xtaci/kcp-go"
)

type natIndicator struct {
	srcHardwareAddr net.HardwareAddr
	conn            *pcap.RawConn
}

const name string = "IkaGo-client"

const pingDeadline = 2 * time.Second

var (
	version     = ""
	build       = ""
	commit      = ""
	versionInfo string
	startTime   time.Time
)

var (
	argListDevs       = flag.Bool("list-devices", false, "List all valid devices in current computer.")
	argConfig         = flag.String("c", "", "Configuration file.")
	argListenDevs     = flag.String("listen-devices", "", "Devices for listening.")
	argUpDev          = flag.String("upstream-device", "", "Device for routing upstream to.")
	argGateway        = flag.String("gateway", "", "Gateway address.")
	argMode           = flag.String("mode", "faketcp", "Mode.")
	argMethod         = flag.String("method", "plain", "Method of encryption.")
	argPassword       = flag.String("password", "", "Password of encryption.")
	argRule           = flag.Bool("rule", false, "Add firewall rule.")
	argVerbose        = flag.Bool("v", false, "Print verbose messages.")
	argLog            = flag.String("log", "", "Log.")
	argMonitor        = flag.Int("monitor", 0, "Port for monitoring.")
	argMTU            = flag.Int("mtu", 0, "MTU.")
	argKCP            = flag.Bool("kcp", false, "Enable KCP.")
	argKCPMTU         = flag.Int("kcp-mtu", kcp.IKCP_MTU_DEF, "KCP tuning option mtu.")
	argKCPSendWindow  = flag.Int("kcp-sndwnd", kcp.IKCP_WND_SND, "KCP tuning option sndwnd.")
	argKCPRecvWindow  = flag.Int("kcp-rcvwnd", kcp.IKCP_WND_RCV, "KCP tuning option rcvwnd.")
	argKCPDataShard   = flag.Int("kcp-datashard", 10, "KCP tuning option datashard.")
	argKCPParityShard = flag.Int("kcp-parityshard", 3, "KCP tuning option parityshard.")
	argKCPACKNoDelay  = flag.Bool("kcp-acknodelay", false, "KCP tuning option acknodelay.")
	argKCPNoDelay     = flag.Bool("kcp-nodelay", false, "KCP tuning option nodelay.")
	argKCPInterval    = flag.Int("kcp-interval", kcp.IKCP_INTERVAL, "KCP tuning option interval.")
	argKCPResend      = flag.Int("kcp-resend", 0, "KCP tuning option resend.")
	argKCPNC          = flag.Int("kcp-nc", 0, "KCP tuning option nc.")
	argPublish        = flag.String("publish", "", "ARP publishing address.")
	argUpPort         = flag.Int("p", 0, "Port for routing upstream.")
	argSources        = flag.String("r", "", "Sources.")
	argServer         = flag.String("s", "", "Server.")
)

var (
	publishIP  *net.IPAddr
	upPort     uint16
	sources    []*net.IPAddr
	serverIP   net.IP
	serverPort uint16
	listenDevs []*pcap.Device
	upDev      *pcap.Device
	gatewayDev *pcap.Device
	mode       string
	crypt      crypto.Crypt
	mtu        int
	isKCP      bool
	kcpConfig  *config.KCPConfig
)

var (
	isClosed    bool
	listenConns []*pcap.RawConn
	upConn      net.Conn
	c           chan pcap.ConnPacket
	natLock     sync.RWMutex
	nat         map[string]*natIndicator
	pingTime    int64
	pingSeq     int
	pinger      *ping.Pinger
	monitor     *stat.TrafficMonitor
	dnsLock     sync.RWMutex
	dns         map[string]string
)

func init() {
	if version != "" {
		versionInfo = versionInfo + version
	}
	if version != "" && build != "" {
		versionInfo = versionInfo + "-"
	}
	if build != "" {
		versionInfo = versionInfo + build
	}
	if versionInfo != "" && commit != "" {
		versionInfo = versionInfo + " "
	}
	if commit != "" {
		versionInfo = versionInfo + fmt.Sprintf("(%s)", commit)
	}
	log.Infof("%s %s\n\n", name, versionInfo)

	// Start time
	startTime = time.Now()

	// Parse arguments
	flag.Parse()

	// Load config.json by default
	if len(os.Args) <= 1 {
		_, err := os.Stat("config.json")
		if err == nil {
			*argConfig = "config.json"
		}
	}

	sources = make([]*net.IPAddr, 0)
	listenDevs = make([]*pcap.Device, 0)

	listenConns = make([]*pcap.RawConn, 0)
	c = make(chan pcap.ConnPacket, 1000)
	nat = make(map[string]*natIndicator)
	pingTime = -1
	dns = make(map[string]string)
}

func main() {
	var (
		err     error
		cfg     *config.Config
		gateway net.IP
	)

	// Configuration
	if *argConfig != "" {
		cfg, err = config.ParseFile(*argConfig)
		if err != nil {
			log.Fatalln(fmt.Errorf("parse config file %s: %w", *argConfig, err))
		}
		log.Infof("Load configuration from %s\n", *argConfig)
	} else {
		cfg = config.NewConfig()
		cfg.ListenDevs = splitArg(*argListenDevs)
		cfg.UpDev = *argUpDev
		cfg.Gateway = *argGateway
		cfg.Mode = *argMode
		cfg.Method = *argMethod
		cfg.Password = *argPassword
		cfg.Rule = *argRule
		cfg.Verbose = *argVerbose
		cfg.Log = *argLog
		cfg.Monitor = *argMonitor
		cfg.MTU = *argMTU
		cfg.KCP = *argKCP
		cfg.KCPConfig = *config.NewKCPConfig()
		cfg.KCPConfig.MTU = *argKCPMTU
		cfg.KCPConfig.SendWindow = *argKCPSendWindow
		cfg.KCPConfig.RecvWindow = *argKCPRecvWindow
		cfg.KCPConfig.DataShard = *argKCPDataShard
		cfg.KCPConfig.ParityShard = *argKCPParityShard
		cfg.KCPConfig.ACKNoDelay = *argKCPACKNoDelay
		cfg.KCPConfig.NoDelay = *argKCPNoDelay
		cfg.KCPConfig.Interval = *argKCPInterval
		cfg.KCPConfig.Resend = *argKCPResend
		cfg.KCPConfig.NC = *argKCPNC
		cfg.Publish = *argPublish
		cfg.Port = *argUpPort
		cfg.Sources = splitArg(*argSources)
		cfg.Server = *argServer
	}

	// Log
	log.SetVerbose(cfg.Verbose || *argVerbose)
	err = log.SetLog(cfg.Log)
	if err != nil {
		log.Fatalln(fmt.Errorf("log %s: %w", cfg.Log, err))
	}
	if cfg.Log != "" {
		log.Infof("Save log to file %s\n", cfg.Log)
	}

	// Check permission
	switch runtime.GOOS {
	case "linux":
		if os.Geteuid() != 0 {
			ex, err := os.Executable()
			if err != nil {
				ex = "path_to_ikago"
			}

			log.Infoln("You are running IkaGo as non-root, if IkaGo does not work, please run")
			log.Infof("  sudo setcap cap_net_raw+ep \"%s\"\n", ex)
			log.Infoln("  before opening IkaGo, or just run as root with sudo.")
		}
	case "windows":
		break
	default:
		if os.Geteuid() != 0 {
			log.Infoln("You are running IkaGo as non-root, if IkaGo does not work, please run IkaGo as root with sudo.")
		}
	}

	// Exclusive commands
	if *argListDevs {
		log.Infoln("Available devices are listed below, use -listen-devices [devices] or -upstream-device [device] to designate device:")
		devs, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatalln(fmt.Errorf("list devices: %w", err))
		}
		for _, dev := range devs {
			log.Infof("  %s\n", dev)
		}
		os.Exit(0)
	}

	// Verify parameters
	if len(cfg.Sources) <= 0 {
		log.Fatalln("Please provide sources by -r addresses.")
	}
	if cfg.Server == "" {
		log.Fatalln("Please provide server by -s address.")
	}
	if cfg.Gateway != "" {
		gateway = net.ParseIP(cfg.Gateway)
		if gateway == nil {
			log.Fatalln(fmt.Errorf("invalid gateway %s", cfg.Gateway))
		}
	}
	if cfg.Monitor < 0 || cfg.Monitor > 65535 {
		log.Fatalln(fmt.Errorf("monitor port %d out of range", cfg.Monitor))
	}
	if cfg.MTU < 576 || cfg.MTU > pcap.MaxMTU {
		if cfg.MTU == 0 {
			cfg.MTU = pcap.MaxMTU
		} else {
			log.Fatalln(fmt.Errorf("mtu %d out of range", cfg.MTU))
		}
	}
	if cfg.KCPConfig.MTU > 1500 {
		log.Fatalln(fmt.Errorf("kcp mtu %d out of range", cfg.KCPConfig.MTU))
	}
	if cfg.KCPConfig.SendWindow <= 0 || cfg.KCPConfig.SendWindow > math.MaxInt32 {
		log.Fatalln(fmt.Errorf("kcp send window %d out of range", cfg.KCPConfig.SendWindow))
	}
	if cfg.KCPConfig.RecvWindow <= 0 || cfg.KCPConfig.RecvWindow > math.MaxInt32 {
		log.Fatalln(fmt.Errorf("kcp receive window %d out of range", cfg.KCPConfig.RecvWindow))
	}
	if cfg.KCPConfig.DataShard < 0 {
		log.Fatalln(fmt.Errorf("kcp data shard %d out of range", cfg.KCPConfig.DataShard))
	}
	if cfg.KCPConfig.ParityShard < 0 {
		log.Fatalln(fmt.Errorf("kcp parity shard %d out of range", cfg.KCPConfig.ParityShard))
	}
	if cfg.KCPConfig.Interval < 0 {
		log.Fatalln(fmt.Errorf("kcp interval %d out of range", cfg.KCPConfig.Interval))
	}
	if cfg.KCPConfig.Resend < 0 {
		log.Fatalln(fmt.Errorf("kcp resend %d out of range", cfg.KCPConfig.Resend))
	}
	if cfg.KCPConfig.NC < 0 {
		log.Fatalln(fmt.Errorf("kcp nc %d out of range", cfg.KCPConfig.NC))
	}
	if cfg.Port < 0 || cfg.Port > 65535 {
		log.Fatalln(fmt.Errorf("upstream port %d out of range", cfg.Port))
	}

	// Randomize upstream port
	if cfg.Port == 0 {
		s := rand.NewSource(time.Now().UnixNano())
		for cfg.Port == 0 || cfg.Port == cfg.Monitor {
			r := rand.New(s)
			cfg.Port = 49152 + r.Intn(16384)
		}
	}
	upPort = uint16(cfg.Port)

	// Sources
	for _, source := range cfg.Sources {
		ip := net.ParseIP(source)
		if ip == nil {
			log.Fatalln(fmt.Errorf("invalid source %s", source))
		}
		sources = append(sources, &net.IPAddr{IP: ip})
	}

	// Server
	serverAddr, err := addr.ParseTCPAddr(cfg.Server)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse server %s: %w", cfg.Server, err))
	}
	serverIP = serverAddr.IP
	serverPort = uint16(serverAddr.Port)

	// Publish
	if cfg.Publish != "" {
		ip := net.ParseIP(cfg.Publish)
		if ip == nil {
			log.Errorln(fmt.Errorf("invalid publish %s", cfg.Publish))
		}
		publishIP = &net.IPAddr{IP: ip}
	}
	if publishIP != nil {
		log.Infof("Publish %s\n", publishIP.IP)
	}

	// Mode
	switch cfg.Mode {
	case "faketcp":
		mode = "faketcp"
		log.Infoln("Use FakeTCP")
	case "tcp":
		mode = "tcp"
		log.Infoln("Use standard TCP")
	default:
		log.Fatalln(fmt.Errorf("mode %s not support", cfg.Mode))
	}

	// Crypt
	crypt, err = crypto.ParseCrypt(cfg.Method, cfg.Password)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse crypt: %w", err))
	}
	method := crypt.Method()
	if method != crypto.MethodPlain {
		log.Infof("Encrypt with %s\n", method)
	}

	// Monitor
	if cfg.Monitor != 0 {
		if cfg.Monitor == int(upPort) {
			log.Fatalln(fmt.Errorf("same monitor port with upstream port"))
		}

		monitor = stat.NewTrafficMonitor()

		// Host HTTP server
		http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
			b, err := json.Marshal(&struct {
				Name    string               `json:"name"`
				Version string               `json:"version"`
				Time    int                  `json:"time"`
				Monitor *stat.TrafficMonitor `json:"monitor"`
				Ping    int64                `json:"ping"`
			}{
				Name:    name,
				Version: versionInfo,
				Time:    int(time.Now().Sub(startTime).Seconds()),
				Monitor: monitor,
				Ping:    pingTime,
			})
			if err != nil {
				log.Errorln(fmt.Errorf("monitor: %w", err))
				return
			}

			// Handle CORS
			w.Header().Set("Access-Control-Allow-Origin", "*")

			_, err = io.WriteString(w, string(b))
			if err != nil {
				log.Errorln(fmt.Errorf("monitor: %w", err))
			}
		})
		http.HandleFunc("/dns", func(w http.ResponseWriter, req *http.Request) {
			type IPName struct {
				IP   string `json:"ip"`
				Name string `json:"name"`
			}

			ipNames := make([]IPName, 0)
			dnsLock.RLock()
			for ip, name := range dns {
				ipNames = append(ipNames, IPName{
					IP:   ip,
					Name: name,
				})
			}
			dnsLock.RUnlock()

			b, err := json.Marshal(ipNames)
			if err != nil {
				log.Errorln(fmt.Errorf("monitor: %w", err))
				return
			}

			// Handle CORS
			w.Header().Set("Access-Control-Allow-Origin", "*")

			_, err = io.WriteString(w, string(b))
			if err != nil {
				log.Errorln(fmt.Errorf("monitor: %w", err))
			}
		})
		go func() {
			err := http.ListenAndServe(fmt.Sprintf(":%d", cfg.Monitor), nil)
			if err != nil {
				log.Errorln(fmt.Errorf("monitor: %w", err))
			}
		}()

		// Ping
		pinger, err = ping.NewPinger(serverIP.String())
		if err != nil {
			log.Errorln(fmt.Errorf("ping: %w", err))
		}
		if pinger != nil {
			pinger.SetPrivileged(true)
			pinger.OnRecv = func(packet *ping.Packet) {
				if packet != nil {
					pingTime = packet.Rtt.Milliseconds()
					pingSeq = packet.Seq

					log.Verbosef("Receive ICMP Echo Reply: %s <- %s (%d ms)\n", upDev.IPAddr().IP, serverIP, packet.Rtt.Milliseconds())

					// Timeout
					go func() {
						time.Sleep(pingDeadline)
						if packet.Seq == pingSeq {
							pingTime = -2

							log.Errorf("Cannot receive ICMP Echo Reply from server %s, is your network down?\n", serverIP)
						}
					}()
				}
			}
		}

		log.Infof("Monitor on :%d\n", cfg.Monitor)
		log.Infoln("You can now observe traffic on http://ikago.ikas.ink")
	}

	// Mode-related options
	switch mode {
	case "faketcp":
		// MTU
		mtu = cfg.MTU
		if mtu != pcap.MaxMTU {
			log.Infof("Set MTU to %d Bytes\n", mtu)
		}

		// KCP
		isKCP = cfg.KCP
		kcpConfig = &cfg.KCPConfig
		if isKCP {
			log.Infoln("Enable KCP")
		}
	case "tcp":
		break
	default:
		log.Fatalln(fmt.Errorf("mode %s not support", mode))
	}

	if len(sources) == 1 {
		log.Infof("Proxy %s through :%d to %s\n", sources[0], upPort, serverAddr)
	} else {
		log.Infoln("Proxy:")
		for i, f := range sources {
			if i != len(sources)-1 {
				log.Infof("  %s\n", f)
			} else {
				log.Infof("  %s through :%d to %s\n", f, upPort, serverAddr)
			}
		}
	}

	// Find devices
	listenDevs, err = pcap.FindListenDevs(cfg.ListenDevs)
	if err != nil {
		log.Fatalln(fmt.Errorf("find listen devices: %w", err))
	}
	if len(cfg.ListenDevs) <= 0 {
		// Remove loopback devices by default
		result := make([]*pcap.Device, 0)

		for _, dev := range listenDevs {
			if dev.IsLoop() {
				continue
			}
			result = append(result, dev)
		}

		listenDevs = result
	}
	if len(listenDevs) <= 0 {
		log.Fatalln(errors.New("cannot determine listen device"))
	}

	upDev, gatewayDev, err = pcap.FindUpstreamDevAndGatewayDev(cfg.UpDev, gateway)
	if err != nil {
		log.Fatalln(fmt.Errorf("find upstream device and gateway device: %w", err))
	}
	if upDev == nil && gatewayDev == nil {
		log.Fatalln(errors.New("cannot determine upstream device and gateway device"))
	}
	if upDev == nil {
		log.Fatalln(errors.New("cannot determine upstream device"))
	}
	if gatewayDev == nil {
		log.Fatalln(errors.New("cannot determine gateway device"))
	}

	// Add firewall rule
	if cfg.Rule {
		var (
			ok   bool
			devs map[string]bool
		)

		ok = true
		devs = make(map[string]bool)

		// IP forwarding
		err := exec.DisableIPForwarding()
		if err != nil {
			log.Errorln(fmt.Errorf("disable ip forwarding: %w", err))
		} else {
			log.Infoln("Disable IP forwarding")
		}

		// Firewall
		switch mode {
		case "faketcp":
			err = exec.AddSpecificFirewallRule(serverIP, serverPort)
			if err != nil {
				log.Errorln(fmt.Errorf("add firewall rule: %w", err))
			} else {
				log.Infoln("Add firewall rule")
			}
		case "tcp":
			break
		default:
			log.Fatalln(fmt.Errorf("mode %s not support", cfg.Mode))
		}

		// GRO
		for _, dev := range listenDevs {
			devs[dev.Alias()] = true
		}
		devs[upDev.Alias()] = true

		for dev := range devs {
			err := exec.DisableGRO(dev)
			if err != nil {
				log.Errorln(fmt.Errorf("disable gro: %w", err))
				ok = false
			}
		}
		if ok {
			log.Infoln("Disable GRO")
		}
	}

	// Wait signals
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		closeAll()
		os.Exit(0)
	}()

	// Open pcap
	err = open()
	if err != nil {
		log.Fatalln(fmt.Errorf("open pcap: %w", err))
	}
}

func open() error {
	var err error

	if len(listenDevs) == 1 {
		log.Infof("Listen on %s\n", listenDevs[0].String())
	} else {
		log.Infoln("Listen on:")
		for _, dev := range listenDevs {
			log.Infof("  %s\n", dev.String())
		}
	}
	if !gatewayDev.IsLoop() {
		log.Infof("Route upstream from %s to %s\n", upDev, gatewayDev)
	} else {
		log.Infof("Route upstream in %s\n", upDev)
	}

	// Filters for listening
	fs := make([]string, 0)
	for _, f := range sources {
		s, err := addr.SrcBPFFilter(f)
		if err != nil {
			return fmt.Errorf("parse filter %s: %w", f, err)
		}

		fs = append(fs, s)
	}
	f := strings.Join(fs, " || ")
	filter := fmt.Sprintf("ip && (((tcp || udp) && (%s) && not (src host %s && src port %d)) || ((icmp || (ip[6:2] & 0x1fff) != 0) && (%s) && not src host %s))",
		f, serverIP, serverPort, f, serverIP)
	if publishIP != nil {
		s, err := addr.DstBPFFilter(publishIP)
		if err != nil {
			return fmt.Errorf("parse filter %s: %w", f, err)
		}
		filter = filter + fmt.Sprintf(" || (arp[6:2] = 1 && %s)", s)
	}

	// Handles for listening
	for _, dev := range listenDevs {
		var (
			err  error
			conn *pcap.RawConn
		)

		if dev.IsLoop() {
			conn, err = pcap.CreateRawConn(dev, dev, filter)
		} else {
			conn, err = pcap.CreateRawConn(dev, gatewayDev, filter)
		}
		if err != nil {
			return fmt.Errorf("open listen device %s: %w", conn.LocalDev().Alias(), err)
		}

		listenConns = append(listenConns, conn)
	}

	// Handle for routing upstream
	switch mode {
	case "faketcp":
		if isKCP {
			upConn, err = pcap.DialFakeTCPWithKCP(upDev, gatewayDev, upPort, &net.TCPAddr{IP: serverIP, Port: int(serverPort)}, crypt, mtu, kcpConfig)
		} else {
			upConn, err = pcap.DialFakeTCP(upDev, gatewayDev, upPort, &net.TCPAddr{IP: serverIP, Port: int(serverPort)}, crypt, mtu)
		}
	case "tcp":
		upConn, err = pcap.DialTCP(upDev, upPort, &net.TCPAddr{IP: serverIP, Port: int(serverPort)}, crypt)
	default:
		err = fmt.Errorf("mode %s not support", mode)
	}
	if err != nil {
		return fmt.Errorf("open upstream: %w", err)
	}

	// Ping
	if pinger != nil {
		go func() {
			pinger.Run()
		}()
	}

	// Start handling
	for i := 0; i < len(listenConns); i++ {
		conn := listenConns[i]

		go func() {
			for {
				packet, err := conn.ReadPacket()
				if err != nil {
					if isClosed {
						return
					}
					log.Errorln(fmt.Errorf("read listen device %s: %w", conn.LocalDev().Alias(), err))
					continue
				}

				c <- pcap.ConnPacket{Packet: packet, Conn: conn}
			}
		}()
	}

	go func() {
		for cp := range c {
			err := handleListen(cp.Packet, cp.Conn)
			if err != nil {
				log.Errorln(fmt.Errorf("handle listen in device %s: %w", cp.Conn.LocalDev().Alias(), err))
				log.Verboseln(cp.Packet)
				continue
			}
		}
	}()

	b := make([]byte, pcap.IPv4MaxSize)
	for {
		n, err := upConn.Read(b)
		if err != nil {
			if isClosed {
				return nil
			}
			if errors.Is(err, io.EOF) {
				log.Fatalf("Connection to server %s is closed, is the server or your network down?\n", upConn.RemoteAddr())
			}
			log.Errorln(fmt.Errorf("read upstream: %w", err))
			continue
		}

		err = handleUpstream(b[:n])
		if err != nil {
			log.Errorln(fmt.Errorf("handle upstream in address %s: %w", upConn.LocalAddr().String(), err))
			log.Verbosef("Source: %s\nSize: %d Bytes\n\n", upConn.RemoteAddr().String(), n)
			continue
		}
	}
}

func closeAll() {
	isClosed = true
	for _, handle := range listenConns {
		if handle != nil {
			handle.Close()
		}
	}
	if upConn != nil {
		upConn.Close()
	}
	if pinger != nil {
		pinger.Stop()
	}
}

func publish(packet gopacket.Packet, conn *pcap.RawConn) error {
	var (
		indicator    *pcap.PacketIndicator
		arpLayer     *layers.ARP
		newARPLayer  *layers.ARP
		linkLayer    gopacket.Layer
		newLinkLayer *layers.Ethernet
	)

	// Parse packet
	indicator, err := pcap.ParsePacket(packet)
	if err != nil {
		return fmt.Errorf("parse packet: %w", err)
	}

	if t := indicator.NetworkLayer().LayerType(); t != layers.LayerTypeARP {
		return fmt.Errorf("network layer type %s not support", t)
	}

	// Create new ARP layer
	arpLayer = indicator.ARPLayer()
	newARPLayer = &layers.ARP{
		AddrType:          arpLayer.AddrType,
		Protocol:          arpLayer.Protocol,
		HwAddressSize:     arpLayer.HwAddressSize,
		ProtAddressSize:   arpLayer.ProtAddressSize,
		Operation:         layers.ARPReply,
		SourceHwAddress:   conn.LocalDev().HardwareAddr(),
		SourceProtAddress: arpLayer.DstProtAddress,
		DstHwAddress:      arpLayer.SourceHwAddress,
		DstProtAddress:    arpLayer.SourceProtAddress,
	}

	// Create new link layer
	linkLayer = packet.LinkLayer()

	switch t := linkLayer.LayerType(); t {
	case layers.LayerTypeEthernet:
		newLinkLayer = &layers.Ethernet{
			SrcMAC:       conn.LocalDev().HardwareAddr(),
			DstMAC:       linkLayer.(*layers.Ethernet).SrcMAC,
			EthernetType: linkLayer.(*layers.Ethernet).EthernetType,
		}
	default:
		return fmt.Errorf("link layer type %s not support", t)
	}

	// Serialize layers
	data, err := pcap.Serialize(newLinkLayer, newARPLayer)
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// Reconnect
	if upConn != nil {
		switch upConn.(type) {
		case *pcap.FakeTCPConn:
			err = upConn.(*pcap.FakeTCPConn).Reconnect()
		default:
			break
		}
	}
	if err != nil {
		return fmt.Errorf("reconnect: %w", err)
	}

	log.Infof("Device %s [%s] joined the network\n", indicator.SrcIP(), net.HardwareAddr(arpLayer.SourceHwAddress))
	log.Verbosef("Reply an %s request: %s -> %s\n", indicator.NetworkLayer().LayerType(), indicator.SrcIP(), indicator.DstIP())

	return nil
}

func handleListen(packet gopacket.Packet, conn *pcap.RawConn) error {
	var (
		hardwareAddr net.HardwareAddr
		data         []byte
	)

	// Parse packet
	indicator, err := pcap.ParsePacket(packet)
	if err != nil {
		return fmt.Errorf("parse packet: %w", err)
	}

	// ARP
	if indicator.NetworkLayer().LayerType() == layers.LayerTypeARP {
		err := publish(packet, conn)
		if err != nil {
			return fmt.Errorf("publish: %w", err)
		}
		return nil
	}

	// Record source hardware address
	hardwareAddr = indicator.SrcHardwareAddr()

	data = make([]byte, 0)
	data = append(data, packet.NetworkLayer().LayerContents()...)
	data = append(data, packet.NetworkLayer().LayerPayload()...)

	// Write packet data
	_, err = upConn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// Record the connection of the packet
	ni, ok := nat[indicator.SrcIP().String()]
	if !ok || ni.srcHardwareAddr.String() != hardwareAddr.String() {
		natLock.Lock()
		nat[indicator.SrcIP().String()] = &natIndicator{srcHardwareAddr: hardwareAddr, conn: conn}
		natLock.Unlock()
	}

	// Statistics
	size := indicator.MTU()
	if monitor != nil {
		monitor.AddBidirectional(indicator.SrcIP().String(), indicator.DstIP().String(), stat.DirectionOut, uint(size))
	}

	log.Verbosef("Redirect an outbound %s packet: %s -> %s (%d Bytes)\n",
		indicator.TransportProtocol(), indicator.Src().String(), indicator.Dst().String(), size)

	return nil
}

func handleUpstream(contents []byte) error {
	var (
		embIndicator     *pcap.PacketIndicator
		newLinkLayer     gopacket.Layer
		newLinkLayerType gopacket.LayerType
		data             []byte
	)

	// Empty payload
	if len(contents) <= 0 {
		// return errors.New("empty payload")
		return nil
	}

	// Parse embedded packet
	embIndicator, err := pcap.ParseEmbPacket(contents)
	if err != nil {
		return fmt.Errorf("parse embedded packet: %w", err)
	}

	// Check map
	natLock.RLock()
	ni, ok := nat[embIndicator.DstIP().String()]
	natLock.RUnlock()
	if !ok {
		return fmt.Errorf("missing nat to %s", embIndicator.DstIP())
	}

	// Decide Loopback or Ethernet
	if ni.conn.IsLoop() {
		newLinkLayerType = layers.LayerTypeLoopback
	} else {
		newLinkLayerType = layers.LayerTypeEthernet
	}

	// Create new link layer
	switch newLinkLayerType {
	case layers.LayerTypeLoopback:
		newLinkLayer, err = pcap.CreateLoopbackLayer(embIndicator.NetworkLayer().(gopacket.NetworkLayer))
	case layers.LayerTypeEthernet:
		newLinkLayer, err = pcap.CreateEthernetLayer(ni.conn.LocalDev().HardwareAddr(), ni.srcHardwareAddr, embIndicator.NetworkLayer().(gopacket.NetworkLayer))
	default:
		return fmt.Errorf("link layer type %s not support", newLinkLayerType)
	}
	if err != nil {
		return fmt.Errorf("create link layer: %w", err)
	}

	// Serialize layers
	data, err = pcap.SerializeRaw(newLinkLayer.(gopacket.SerializableLayer),
		gopacket.Payload(embIndicator.NetworkLayer().LayerContents()),
		gopacket.Payload(embIndicator.NetworkPayload()))
	if embIndicator.DNSIndicator() != nil {
		if embIndicator.DNSIndicator().IsResponse() {
			name, _ := embIndicator.DNSIndicator().Answers()
			if name == "api.twitter.com" || name == "www.facebook.com" {
				embIndicator.DNSIndicator().OverwriteAnswer(net.IPv4(192, 168, 123, 164))
				if embIndicator.UDPLayer() != nil {
					embIndicator.UDPLayer().SetNetworkLayerForChecksum(embIndicator.IPv4Layer())
				} else if embIndicator.TCPLayer() != nil {
					embIndicator.TCPLayer().SetNetworkLayerForChecksum(embIndicator.IPv4Layer())
				}
				data, err = pcap.Serialize(newLinkLayer.(gopacket.SerializableLayer),
					embIndicator.NetworkLayer().(gopacket.SerializableLayer),
					embIndicator.TransportLayer().(gopacket.SerializableLayer),
					gopacket.Payload(embIndicator.DNSIndicator().SerializeLayer()))
			}
		}
	}
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	// Write packet data
	_, err = ni.conn.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// Statistics
	if monitor != nil {
		monitor.AddBidirectional(embIndicator.DstIP().String(), embIndicator.SrcIP().String(), stat.DirectionIn, uint(embIndicator.Size()))
	}

	// Record DNS
	if embIndicator.DNSIndicator() != nil {
		if embIndicator.DNSIndicator().IsResponse() {
			name, ips := embIndicator.DNSIndicator().Answers()
			if name != "" && len(ips) > 0 {
				dnsLock.Lock()
				for _, ip := range ips {
					dns[ip.String()] = name
					log.Verbosef("Record DNS record %s = %s\n", name, ip)
				}
				dnsLock.Unlock()
			}
		}
	}

	log.Verbosef("Redirect an inbound %s packet: %s <- %s (%d Bytes)\n",
		embIndicator.TransportProtocol(), embIndicator.Dst().String(), embIndicator.Src().String(), embIndicator.Size())

	return nil
}

func splitArg(s string) []string {
	if s == "" {
		return nil
	}

	result := make([]string, 0)

	strs := strings.Split(s, ",")

	for _, str := range strs {
		result = append(result, strings.Trim(str, " "))
	}

	return result
}

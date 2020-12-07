package main

import (
	"context"
	"encoding/base32"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	deviceFlag = flag.String("device", "",
		"name of Wireguard device to manage")
	dnsServerFlag = flag.String("dns", "",
		"ip:port of DNS server")
	dnsZoneFlag = flag.String("zone", "", "dns zone name")
	serviceFlag = flag.String("service", "", "service ip or public key")
)

const (
	keyLen   = 56 // the number of characters in a base32-encoded Wireguard public key
	spPrefix = "_wireguard._udp."
)

func main() {
	flag.Parse()
	if len(*deviceFlag) < 1 {
		log.Fatal("missing device flag")
	}
	if len(*dnsZoneFlag) < 1 {
		log.Fatal("missing zone flag")
	}
	if len(*dnsServerFlag) < 1 {
		log.Fatal("missing dns flag")
	}
	_, _, err := net.SplitHostPort(*dnsServerFlag)
	if err != nil {
		log.Fatalf("invalid dns flag value: %v", err)
	}
	wgClient, err := wgctrl.New()
	if err != nil {
		log.Fatalf("error constructing Wireguard control client: %v",
			err)
	}
	wgDevice, err := wgClient.Device(*deviceFlag)
	if err != nil {
		log.Fatalf(
			"error retrieving Wireguard device '%s' info: %v",
			*deviceFlag, err)
	}
	if len(wgDevice.Peers) < 1 {
		log.Println("no peers found")
		os.Exit(0)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		dnsClient := &dns.Client{
			Timeout: time.Second * 5,
		}

		suffix := spPrefix + dns.Fqdn(*dnsZoneFlag)

		if len(*serviceFlag) >= 1 {
			fqdn := *serviceFlag
			suffix = "." + suffix
			if !strings.HasSuffix(fqdn, suffix) {
				fqdn += suffix
			}
			ConnectPeer(ctx, wgClient, wgDevice, dnsClient, fqdn, *dnsServerFlag)
			return
		}

		srvCtx, srvCancel := context.WithCancel(ctx)
		m := &dns.Msg{}
		m.SetQuestion(suffix, dns.TypePTR)
		r, _, err := dnsClient.ExchangeContext(srvCtx, m, *dnsServerFlag)
		srvCancel()
		if err != nil {
			log.Printf("failed to lookup PTR: %v", err)
			return
		}
		if len(r.Answer) < 1 {
			log.Printf("no PTR records found")
			return
		}

		for _, answer := range r.Answer {
			select {
			case <-ctx.Done():
				return
			default:
			}
			ptr, ok := answer.(*dns.PTR)
			if !ok {
				log.Printf("non-PTR answer in response to PTR query: %s", answer.String())
				continue
			}
			ConnectPeer(ctx, wgClient, wgDevice, dnsClient, ptr.Ptr, *dnsServerFlag)
		}
	}()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		log.Printf("exiting due to signal %s", sig)
		cancel()
		<-done
	case <-done:
	}
}

func ConnectPeer(ctx context.Context, wgClient *wgctrl.Client, wgDevice *wgtypes.Device, dnsClient *dns.Client, serviceFqdn string, dnsServer string) {
	srvCtx, srvCancel := context.WithCancel(ctx)
	m := &dns.Msg{}
	m.SetQuestion(serviceFqdn, dns.TypeSRV)
	r, _, err := dnsClient.ExchangeContext(srvCtx, m, dnsServer)
	srvCancel()
	if err != nil {
		log.Printf(
			"[%s] failed to lookup SRV: %v", serviceFqdn, err)
		return
	}
	if len(r.Answer) < 1 {
		log.Printf("[%s] no SRV records found", serviceFqdn)
		return
	}
	srv, ok := r.Answer[0].(*dns.SRV)
	if !ok {
		log.Printf(
			"[%s] non-SRV answer in response to SRV query: %s",
			serviceFqdn, r.Answer[0].String())
		return
	}
	if len(r.Extra) < 2 {
		log.Printf("[%s] SRV response missing extra A/AAAA and TXT",
			serviceFqdn)
		return
	}
	var endpointIP net.IP
	hostA, ok := r.Extra[0].(*dns.A)
	if !ok {
		hostAAAA, ok := r.Extra[0].(*dns.AAAA)
		if !ok {
			log.Printf(
				"[%s] non-A/AAAA extra in SRV response: %s",
				serviceFqdn, r.Extra[0].String())
			return
		}
		endpointIP = hostAAAA.AAAA
	} else {
		endpointIP = hostA.A
	}
	txt, ok := r.Extra[1].(*dns.TXT)
	if !ok {
		log.Printf("[%s] non-TXT extra in SRV response: %s",
			serviceFqdn, r.Extra[1].String())
		return
	}
	allowedIPsString := strings.TrimPrefix(strings.ToLower(txt.Txt[0]), "allowedip=")
	_, allowedIPs, err := net.ParseCIDR(allowedIPsString)
	if err != nil {
		log.Printf("[%s] failed to parse allowedip in TXT extra: %s", serviceFqdn, r.Extra[1].String())
		return
	}
	pubKeyString := strings.TrimPrefix(strings.ToUpper(txt.Txt[1]), "PUBKEY=")
	if len(pubKeyString) < keyLen {
		pubKeyString += strings.Repeat("=", keyLen-len(pubKeyString))
	}
	pubKeyBytes, err := base32.StdEncoding.DecodeString(strings.ToUpper(pubKeyString))
	if err != nil {
		log.Printf("[%s] failed to decode base32 key %s: %v", serviceFqdn, pubKeyString, err)
		return
	}
	pubKeyWg, err := wgtypes.NewKey(pubKeyBytes)
	if err != nil {
		log.Printf("[%s] failed to create wg key: %v", serviceFqdn, err)
		return
	}
	if pubKeyWg == wgDevice.PublicKey {
		log.Printf("[%s] skipping ourself", serviceFqdn)
		return
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey:  pubKeyWg,
		UpdateOnly: false,
		Endpoint: &net.UDPAddr{
			IP:   endpointIP,
			Port: int(srv.Port),
		},
		ReplaceAllowedIPs: true,
		AllowedIPs:        []net.IPNet{*allowedIPs},
	}
	deviceConfig := wgtypes.Config{
		PrivateKey:   &wgDevice.PrivateKey,
		ReplacePeers: false,
		Peers:        []wgtypes.PeerConfig{peerConfig},
	}
	if wgDevice.FirewallMark > 0 {
		deviceConfig.FirewallMark = &wgDevice.FirewallMark
	}
	err = wgClient.ConfigureDevice(*deviceFlag, deviceConfig)
	if err != nil {
		log.Printf(
			"[%s] failed to configure peer on %s, error: %v",
			serviceFqdn, *deviceFlag, err)
		return
	}

	log.Printf("[%s] configure peer on %s", serviceFqdn, *deviceFlag)
}

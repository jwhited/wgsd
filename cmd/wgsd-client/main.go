package main

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

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
		dnsClient := &dns.Client{}
		for _, peer := range wgDevice.Peers {
			select {
			case <-ctx.Done():
				return
			default:
			}
			srvCtx, srvCancel := context.WithCancel(ctx)
			pubKeyBase32 := base32.StdEncoding.EncodeToString(peer.PublicKey[:])
			pubKeyBase64 := base64.StdEncoding.EncodeToString(peer.PublicKey[:])
			m := &dns.Msg{}
			question := fmt.Sprintf("%s._wireguard._udp.%s",
				pubKeyBase32, dns.Fqdn(*dnsZoneFlag))
			m.SetQuestion(question, dns.TypeSRV)
			r, _, err := dnsClient.ExchangeContext(srvCtx, m, *dnsServerFlag)
			srvCancel()
			if err != nil {
				log.Printf(
					"[%s] failed to lookup SRV: %v", pubKeyBase64, err)
				continue
			}
			if len(r.Answer) < 1 {
				log.Printf("[%s] no SRV records found", pubKeyBase64)
				continue
			}
			srv, ok := r.Answer[0].(*dns.SRV)
			if !ok {
				log.Printf(
					"[%s] non-SRV answer in response to SRV query: %s",
					pubKeyBase64, r.Answer[0].String())
			}
			if len(r.Extra) < 1 {
				log.Printf("[%s] SRV response missing extra A/AAAA",
					pubKeyBase64)
			}
			var endpointIP net.IP
			hostA, ok := r.Extra[0].(*dns.A)
			if !ok {
				hostAAAA, ok := r.Extra[0].(*dns.AAAA)
				if !ok {
					log.Printf(
						"[%s] non-A/AAAA extra in SRV response: %s",
						pubKeyBase64, r.Extra[0].String())
					continue
				}
				endpointIP = hostAAAA.AAAA
			} else {
				endpointIP = hostA.A
			}
			peerConfig := wgtypes.PeerConfig{
				PublicKey:  peer.PublicKey,
				UpdateOnly: true,
				Endpoint: &net.UDPAddr{
					IP:   endpointIP,
					Port: int(srv.Port),
				},
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
					"failed to configure peer %s on %s, error: %v",
					pubKeyBase64, *deviceFlag, err)
			}
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

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
		"ip:port of DNS server; defaults to OS resolver")
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
	resolver := net.DefaultResolver
	if len(*dnsServerFlag) > 0 {
		_, _, err := net.SplitHostPort(*dnsServerFlag)
		if err != nil {
			log.Fatalf("invalid dns server flag: %v", err)
		}
		dialer := net.Dialer{}
		dialFn := func(ctx context.Context, network, address string) (net.Conn,
			error) {
			return dialer.DialContext(ctx, network, *dnsServerFlag)
		}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial:     dialFn,
		}
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
		for _, peer := range wgDevice.Peers {
			select {
			case <-ctx.Done():
				return
			default:
			}
			srvCtx, srvCancel := context.WithCancel(ctx)
			pubKeyBase32 := base32.StdEncoding.EncodeToString(peer.PublicKey[:])
			pubKeyBase64 := base64.StdEncoding.EncodeToString(peer.PublicKey[:])
			queryName := fmt.Sprintf("%s._wireguard._udp.%s",
				pubKeyBase32, dns.Fqdn(*dnsZoneFlag))
			_, srvs, err := resolver.LookupSRV(srvCtx, "", "",
				queryName)
			srvCancel()
			if err != nil {
				log.Printf(
					"failed to lookup SRV for peer %s error: %v",
					pubKeyBase64, err)
				continue
			}
			if len(srvs) < 1 {
				log.Printf("no SRV records found for peer %s",
					pubKeyBase64)
				continue
			}
			hostCtx, hostCancel := context.WithCancel(ctx)
			addrs, err := resolver.LookupIPAddr(hostCtx, srvs[1].Target)
			hostCancel()
			if err != nil {
				log.Printf(
					"failed to lookup A/AAAA for peer %s error: %v",
					pubKeyBase64, err)
				continue
			}
			if len(addrs) < 1 {
				log.Printf("no A/AAAA records found for peer %s",
					pubKeyBase64)
				continue
			}
			peerConfig := wgtypes.PeerConfig{
				PublicKey:  peer.PublicKey,
				UpdateOnly: true,
				Endpoint: &net.UDPAddr{
					IP:   addrs[0].IP,
					Port: int(srvs[0].Port),
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

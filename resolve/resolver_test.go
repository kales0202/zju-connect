package resolve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/patrickmn/go-cache"
)

var domainResourceMatchSink bool

func TestTCPPrefersL3UsesSelectedResource(t *testing.T) {
	if TCPPrefersL3(context.Background()) {
		t.Fatal("empty context unexpectedly prefers L3")
	}
	domainCtx := context.WithValue(context.Background(), ContextKeyDomainResource, client.DomainResource{EnableTCPPrefL3: true})
	if !TCPPrefersL3(domainCtx) {
		t.Fatal("domain resource preference was ignored")
	}
	ipCtx := context.WithValue(context.Background(), ContextKeyIPResource, client.IPResource{EnableTCPPrefL3: true})
	if !TCPPrefersL3(ipCtx) {
		t.Fatal("IP resource preference was ignored")
	}
}

func TestMatchDomainResourcePreservesNormalizedSuffixMatching(t *testing.T) {
	want := client.DomainResource{AppID: "vpn-app"}
	index := newDomainResourceIndex(client.DomainResources{".Example.COM.": {want}})
	domain, got, ok := matchDomainResource(index, "service.example.com")
	if !ok {
		t.Fatal("matchDomainResource() did not find normalized suffix")
	}
	if domain != ".Example.COM." || len(got) != 1 || got[0] != want {
		t.Fatalf("matchDomainResource() = (%q, %#v), want original domain and %#v", domain, got, want)
	}
}

func TestDomainResourceMatchRequiresLabelBoundary(t *testing.T) {
	index := newDomainResourceIndex(client.DomainResources{"example.com": {{AppID: "vpn"}}})
	for _, host := range []string{"example.com", "service.example.com"} {
		if _, _, ok := index.Match(host); !ok {
			t.Fatalf("expected %s to match", host)
		}
	}
	if _, _, ok := index.Match("notexample.com"); ok {
		t.Fatal("partial label suffix matched domain resource")
	}
}

func TestWildcardDomainResourceRequiresSubdomain(t *testing.T) {
	index := newDomainResourceIndex(client.DomainResources{"*.example.com": {{AppID: "vpn"}}})
	if _, _, ok := index.Match("service.example.com"); !ok {
		t.Fatal("wildcard did not match subdomain")
	}
	if _, _, ok := index.Match("example.com"); ok {
		t.Fatal("wildcard unexpectedly matched apex domain")
	}
}

func BenchmarkDomainResourceMatch(b *testing.B) {
	resources := make(client.DomainResources, 1000)
	for i := 0; i < 1000; i++ {
		resources[fmt.Sprintf(".resource-%04d.example", i)] = []client.DomainResource{{}}
	}
	index := newDomainResourceIndex(resources)
	const host = "missing.example.com"

	b.Run("index", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _, domainResourceMatchSink = index.Match(host)
		}
	})
	b.Run("linear", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			matched := false
			for domain := range resources {
				if strings.HasSuffix(host, normalizeHostname(domain)) {
					matched = true
					break
				}
			}
			domainResourceMatchSink = matched
		}
	})
}

func TestDomainResourceMatchPrefersMostSpecificDomain(t *testing.T) {
	index := newDomainResourceIndex(client.DomainResources{
		".cnki.net":    {{PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "wildcard"}},
		"www.cnki.net": {{PortMin: 80, PortMax: 80, Protocol: "tcp", AppID: "exact"}},
	})

	domain, resources, ok := index.Match("www.cnki.net")
	if !ok || domain != "www.cnki.net" || len(resources) != 2 || resources[0].AppID != "exact" {
		t.Fatalf("Match() = (%q, %#v, %v), want exact domain resource", domain, resources, ok)
	}
	if resource, matched := client.MatchDomainResource(resources, "tcp", 443); !matched || resource.AppID != "wildcard" {
		t.Fatalf("443 match = (%#v, %v), want wildcard fallback", resource, matched)
	}
}

func TestResolverReleasesCoordinationEntry(t *testing.T) {
	failing := failingNetResolver()
	resolver := &Resolver{
		remoteUDPResolver: failing,
		remoteTCPResolver: failing,
		secondaryResolver: failing,
		dnsCache:          cache.New(time.Minute, 0),
		useRemoteDNS:      true,
	}

	_, _, _ = resolver.Resolve(context.Background(), "missing.example")
	if entries := resolver.coordinationEntryCount(); entries != 0 {
		t.Fatalf("coordination entries after Resolve = %d, want 0", entries)
	}
}

func TestResolverRotatesConfiguredDNSAddresses(t *testing.T) {
	first := net.ParseIP("192.0.2.1")
	second := net.ParseIP("192.0.2.2")
	resolver := &Resolver{
		domainIndex: newDomainResourceIndex(nil),
		dnsResource: map[string][]net.IP{"service.example": {first, second}},
		dnsCache:    cache.New(time.Minute, 0),
	}

	_, gotFirst, err := resolver.Resolve(context.Background(), "service.example")
	if err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	_, gotSecond, err := resolver.Resolve(context.Background(), "service.example")
	if err != nil {
		t.Fatalf("second Resolve() error = %v", err)
	}
	if !gotFirst.Equal(first) || !gotSecond.Equal(second) {
		t.Fatalf("rotated addresses = %s, %s, want %s, %s", gotFirst, gotSecond, first, second)
	}
}

func TestResolverWaitingCallerHonorsContext(t *testing.T) {
	started := make(chan struct{}, 1)
	blocking := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			select {
			case started <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	resolver := &Resolver{
		remoteUDPResolver: blocking,
		remoteTCPResolver: blocking,
		secondaryResolver: failingNetResolver(),
		dnsCache:          cache.New(time.Minute, 0),
		useRemoteDNS:      true,
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leaderDone := make(chan struct{})
	go func() {
		_, _, _ = resolver.Resolve(leaderCtx, "blocked.example")
		close(leaderDone)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("leader DNS lookup did not start")
	}

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	cancelWaiter()
	result := make(chan error, 1)
	go func() {
		_, _, err := resolver.Resolve(waiterCtx, "blocked.example")
		result <- err
	}()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiting Resolve error = %v, want context.Canceled", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("waiting Resolve did not stop after context cancellation")
	}

	cancelLeader()
	select {
	case <-leaderDone:
	case <-time.After(time.Second):
		t.Fatal("leader Resolve did not stop after context cancellation")
	}
	deadline := time.Now().Add(time.Second)
	for resolver.coordinationEntryCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if entries := resolver.coordinationEntryCount(); entries != 0 {
		t.Fatalf("active coordination entries after cancellation = %d after timeout, want 0", entries)
	}
}

func TestResolverLeaderCancellationDoesNotCancelWaiter(t *testing.T) {
	resolver := &Resolver{}
	started := make(chan struct{})
	release := make(chan struct{})
	want := net.ParseIP("192.0.2.20")
	lookup := func(ctx context.Context) (net.IP, error) {
		close(started)
		select {
		case <-release:
			return want, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderResult := make(chan error, 1)
	go func() {
		_, err := resolver.resolveCoordinated(leaderCtx, "shared.example", lookup)
		leaderResult <- err
	}()
	<-started

	waiterResult := make(chan struct {
		ip  net.IP
		err error
	}, 1)
	unexpectedLookup := make(chan struct{}, 1)
	go func() {
		ip, err := resolver.resolveCoordinated(context.Background(), "shared.example", func(context.Context) (net.IP, error) {
			unexpectedLookup <- struct{}{}
			return nil, errors.New("waiter unexpectedly started a second lookup")
		})
		waiterResult <- struct {
			ip  net.IP
			err error
		}{ip: ip, err: err}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		resolver.resolutionMu.Lock()
		waiters := resolver.resolutions["shared.example"].waiters
		resolver.resolutionMu.Unlock()
		if waiters == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("waiter did not join the shared lookup")
		}
		time.Sleep(time.Millisecond)
	}

	cancelLeader()
	if err := <-leaderResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context.Canceled", err)
	}
	close(release)
	result := <-waiterResult
	if result.err != nil || !result.ip.Equal(want) {
		t.Fatalf("waiter result = %s, %v, want %s, nil", result.ip, result.err, want)
	}
	select {
	case <-unexpectedLookup:
		t.Fatal("waiter unexpectedly started a second lookup")
	default:
	}
}

func TestLookupIPWithTCPFallbackHedgesSlowUDP(t *testing.T) {
	want := net.ParseIP("192.0.2.10")
	udpCanceled := make(chan struct{})
	udp := func(ctx context.Context, _, _ string) ([]net.IP, error) {
		<-ctx.Done()
		close(udpCanceled)
		return nil, ctx.Err()
	}
	tcp := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{want}, nil
	}

	started := time.Now()
	ips, udpFailed, err := lookupIPWithTCPFallback(context.Background(), "slow.example", udp, tcp, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("lookupIPWithTCPFallback() error = %v", err)
	}
	if udpFailed {
		t.Fatal("slow UDP was hedged, not proven failed")
	}
	if len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("lookup result = %v, want %s", ips, want)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("hedged lookup took %s", elapsed)
	}
	select {
	case <-udpCanceled:
	case <-time.After(time.Second):
		t.Fatal("losing UDP lookup was not canceled")
	}
}

func TestLookupIPWithTCPFallbackKeepsFastUDP(t *testing.T) {
	want := net.ParseIP("192.0.2.11")
	tcpCalled := make(chan struct{}, 1)
	udp := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{want}, nil
	}
	tcp := func(context.Context, string, string) ([]net.IP, error) {
		tcpCalled <- struct{}{}
		return nil, errors.New("unexpected TCP lookup")
	}

	ips, udpFailed, err := lookupIPWithTCPFallback(context.Background(), "fast.example", udp, tcp, time.Second)
	if err != nil || udpFailed || len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("lookup result = %v, udpFailed=%v, err=%v", ips, udpFailed, err)
	}
	select {
	case <-tcpCalled:
		t.Fatal("TCP lookup started for a fast UDP response")
	default:
	}
}

func TestLookupIPWithTCPFallbackMarksUDPFailure(t *testing.T) {
	want := net.ParseIP("192.0.2.12")
	udp := func(context.Context, string, string) ([]net.IP, error) {
		return nil, errors.New("UDP unavailable")
	}
	tcp := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{want}, nil
	}

	ips, udpFailed, err := lookupIPWithTCPFallback(context.Background(), "failed.example", udp, tcp, time.Second)
	if err != nil || !udpFailed || len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("lookup result = %v, udpFailed=%v, err=%v", ips, udpFailed, err)
	}
}

func failingNetResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("DNS unavailable")
		},
	}
}

// fakeDNSServer 起一个只回答 A 记录的极简 UDP DNS 服务，
// 便于在不依赖真实网络的前提下验证解析与缓存行为。
func fakeDNSServer(t *testing.T, answer net.IP) (addr string, queries *atomic.Int32, stop func()) {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	queries = &atomic.Int32{}
	done := make(chan struct{})

	go func() {
		buf := make([]byte, 512)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			queries.Add(1)

			// 跳过 question 的名字部分，定位到 qtype/qclass
			off := 12
			for off < n {
				l := int(buf[off])
				if l == 0 {
					off++
					break
				}
				off += 1 + l
			}
			questionEnd := off + 4
			if questionEnd > n {
				continue
			}

			resp := make([]byte, 0, questionEnd+16)
			resp = append(resp, buf[0], buf[1])         // 复用查询 ID
			resp = append(resp, 0x81, 0x80)             // QR=1 RD=1 RA=1
			resp = append(resp, 0x00, 0x01)             // QDCOUNT
			resp = append(resp, 0x00, 0x01)             // ANCOUNT
			resp = append(resp, 0x00, 0x00, 0x00, 0x00) // NSCOUNT/ARCOUNT
			resp = append(resp, buf[12:questionEnd]...) // question
			resp = append(resp, 0xc0, 0x0c)             // 名字指针
			resp = append(resp, 0x00, 0x01, 0x00, 0x01) // TYPE A / CLASS IN
			resp = append(resp, 0x00, 0x00, 0x00, 0x3c) // TTL 60
			resp = append(resp, 0x00, 0x04)             // RDLENGTH
			resp = append(resp, answer.To4()...)

			_, _ = conn.WriteTo(resp, peer)
		}
	}()

	return conn.LocalAddr().String(), queries, func() {
		select {
		case <-done:
		default:
			close(done)
		}
		_ = conn.Close()
	}
}

// secondaryOnlyResolver 构造一个「远端 DNS 必然失败、secondary 指向假 DNS」的解析器。
func secondaryOnlyResolver(t *testing.T, remote *net.Resolver) (*Resolver, *atomic.Int32) {
	t.Helper()

	addr, q, stop := fakeDNSServer(t, net.ParseIP("192.0.2.55"))
	t.Cleanup(stop)

	secondary := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		},
	}

	return &Resolver{
		remoteUDPResolver: remote,
		remoteTCPResolver: remote,
		secondaryResolver: secondary,
		dnsCache:          cache.New(time.Minute, 0),
		useRemoteDNS:      true,
	}, q
}

// 回落得到的地址必须进缓存：否则每个新连接都会先白等一次远端 DNS 超时。
func TestResolverCachesSecondaryDNSResult(t *testing.T) {
	remote := net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("remote dns unreachable")
		},
	}

	resolver, queries := secondaryOnlyResolver(t, &remote)

	_, first, err := resolver.Resolve(context.Background(), "internal.example")
	if err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	if !first.Equal(net.ParseIP("192.0.2.55")) {
		t.Fatalf("first Resolve() = %s, want 192.0.2.55", first)
	}
	if !resolver.remoteDNSDisabled() {
		t.Fatal("远端 DNS 连不通后应临时跳过它")
	}

	before := queries.Load()
	_, second, err := resolver.Resolve(context.Background(), "internal.example")
	if err != nil {
		t.Fatalf("second Resolve() error = %v", err)
	}
	if !second.Equal(first) {
		t.Fatalf("second Resolve() = %s, want %s", second, first)
	}
	if got := queries.Load(); got != before {
		t.Fatalf("第二次解析又查了 DNS（%d 次，之前 %d 次），说明回落结果没有被缓存", got, before)
	}
}

// 远端 DNS 失败后，解析其它域名时不应再尝试远端，避免每次多等一个超时。
func TestResolverSkipsRemoteDNSAfterFailure(t *testing.T) {
	var remoteCalls atomic.Int32

	remote := net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			remoteCalls.Add(1)
			return nil, errors.New("remote dns unreachable")
		},
	}

	resolver, _ := secondaryOnlyResolver(t, &remote)

	if _, _, err := resolver.Resolve(context.Background(), "first.example"); err != nil {
		t.Fatalf("Resolve(first.example) error = %v", err)
	}
	before := remoteCalls.Load()
	if before == 0 {
		t.Fatal("首次解析应当尝试过远端 DNS")
	}

	if _, ip, err := resolver.Resolve(context.Background(), "second.example"); err != nil {
		t.Fatalf("Resolve(second.example) error = %v", err)
	} else if !ip.Equal(net.ParseIP("192.0.2.55")) {
		t.Fatalf("Resolve(second.example) = %s, want 192.0.2.55", ip)
	}

	if after := remoteCalls.Load(); after != before {
		t.Fatalf("远端 DNS 已被判定不可用，却又被调用了 %d 次", after-before)
	}
}

// 域名不存在是远端 DNS 的正常回答，不能据此判定远端不可用。
func TestIsDNSTransportError(t *testing.T) {
	if isDNSTransportError(&net.DNSError{Err: "no such host", Name: "x.example", IsNotFound: true}) {
		t.Fatal("NXDOMAIN 不应被当作远端 DNS 不可用")
	}
	if !isDNSTransportError(&net.DNSError{Err: "timeout", Name: "x.example", IsTimeout: true}) {
		t.Fatal("超时应被当作远端 DNS 不可用")
	}
	if !isDNSTransportError(errors.New("dial failed")) {
		t.Fatal("非 DNS 错误应被当作远端 DNS 不可用")
	}
	if isDNSTransportError(nil) {
		t.Fatal("nil 不应被当作远端 DNS 不可用")
	}
}

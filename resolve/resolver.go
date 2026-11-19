package resolve

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ippool"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/stack"
	"github.com/patrickmn/go-cache"
)

type Resolver struct {
	remoteUDPResolver *net.Resolver
	remoteTCPResolver *net.Resolver
	secondaryResolver *net.Resolver
	ttl               uint64
	domainIndex       *domainResourceIndex
	dnsResource       map[string][]net.IP
	dnsResourceCursor sync.Map
	useRemoteDNS      bool

	dnsCache *cache.Cache

	IPPool *ippool.IPPool[[]client.DomainResource]

	timer  *time.Timer
	useTCP bool

	// 远端 DNS 连续失败后临时跳过。
	// 若配置的远端 DNS 在目标环境不可达，每个新连接都会先白等一次解析超时
	// 才回落到 secondary，表现为「每次都慢十几秒」。
	skipRemoteDNSLock  sync.RWMutex
	skipRemoteDNS      bool
	skipRemoteDNSTimer *time.Timer
	// check to use tcp resolver or udp resolver
	tcpLock           sync.RWMutex
	resolutionMu      sync.Mutex
	resolutions       map[string]*sharedResolution
	resolutionClosed  bool
	activeResolutions atomic.Int64

	closeOnce sync.Once
}

const (
	remoteDNSTCPFallbackDelay = 300 * time.Millisecond
	// remoteDNSSkipDuration 是远端 DNS 不可用时跳过它的时长。
	// 与 TCP 偏好的 10 分钟保持一致：到期后自动再给远端一次机会。
	remoteDNSSkipDuration = 10 * time.Minute
	// remoteDNSTimeout 限制单次远端 DNS 查询。
	// 远端不可达时，Go 解析器自身的重试会把一次解析拖到十几秒；
	// 而 secondary 通常几十毫秒就能答，所以这里及早放弃远端。
	remoteDNSTimeout = 3 * time.Second
)

type lookupIPFunc func(context.Context, string, string) ([]net.IP, error)

type dnsLookupResult struct {
	ips []net.IP
	err error
}

type sharedResolution struct {
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	waiters int
	ip      net.IP
	err     error
}

func (r *Resolver) coordinationEntryCount() int {
	return int(r.activeResolutions.Load())
}

type contextKey string

var (
	ContextKeyFakeIP          = contextKey("FAKE_IP")
	ContextKeyResolveHost     = contextKey("RESOLVE_HOST")
	ContextKeyDomainResource  = contextKey("DOMAIN_RESOURCE")
	ContextKeyIPResource      = contextKey("IP_RESOURCE")
	contextKeyIgnoreTCPPrefL3 = contextKey("IGNORE_TCP_PREF_L3")
)

func WithIgnoreTCPPrefL3(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyIgnoreTCPPrefL3, true)
}

func IgnoreTCPPrefL3(ctx context.Context) bool {
	ignore, _ := ctx.Value(contextKeyIgnoreTCPPrefL3).(bool)
	return ignore
}

func TCPPrefersL3(ctx context.Context) bool {
	if resource, ok := ctx.Value(ContextKeyDomainResource).(client.DomainResource); ok {
		return resource.EnableTCPPrefL3
	}
	if resource, ok := ctx.Value(ContextKeyIPResource).(client.IPResource); ok {
		return resource.EnableTCPPrefL3
	}
	return false
}

// Resolve ip address. If the host could be visited via VPN, this function set a DOMAIN_RESOURCE value in context. If resolve success, this function set a RESOLVE_HOST value in context.
func (r *Resolver) Resolve(ctx context.Context, host string) (resCtx context.Context, resIP net.IP, resErr error) {
	host = normalizeHostname(host)
	defer func() {
		if resErr == nil {
			resCtx = context.WithValue(resCtx, ContextKeyResolveHost, host)
		}
	}()
	var domainResourceFound = false
	var domainResources []client.DomainResource
	if domain, resources, found := matchDomainResource(r.domainIndex, host); found {
		domainResourceFound = true
		domainResources = resources
		ctx = context.WithValue(ctx, ContextKeyDomainResource, resources)
		log.DebugPrintf("Domain resource found: %s", domain)
	}

	if cachedIP, found := r.getDNSCache(host); found {
		log.Printf("%s -> %s", host, cachedIP.String())
		return ctx, cachedIP, nil
	}

	if r.dnsResource != nil {
		if ips, found := r.dnsResource[host]; found && len(ips) > 0 {
			cursorValue, _ := r.dnsResourceCursor.LoadOrStore(host, &atomic.Uint64{})
			cursor := cursorValue.(*atomic.Uint64)
			ip := ips[(cursor.Add(1)-1)%uint64(len(ips))]
			log.Printf("%s -> %s", host, ip.String())
			if domainResourceFound {
				err := r.IPPool.SetIPDomain(ip, host, domainResources)
				if err != nil {
					log.DebugPrintf("Set IP err: %s", err)
				}
			}
			return ctx, ip, nil
		}

		if fakeIPValue := ctx.Value(ContextKeyFakeIP); fakeIPValue != nil {
			if domainResourceFound {
				ip := r.IPPool.GenerateIP(host, domainResources)
				log.Printf("%s -> %s (Fake IP)", host, ip.String())
				return ctx, ip, nil
			}
		}
	}

	if r.useRemoteDNS && !r.remoteDNSDisabled() {
		ip, err := r.resolveCoordinated(ctx, host, func(lookupCtx context.Context) (net.IP, error) {
			return r.resolveRemote(lookupCtx, host)
		})
		if err != nil {
			if ctx.Err() != nil {
				return ctx, nil, ctx.Err()
			}
			// 只有「连不通」才值得临时跳过；域名不存在（NXDOMAIN）
			// 是远端 DNS 的正常回答，不能据此判定远端不可用。
			if isDNSTransportError(err) {
				r.disableRemoteDNSTemporarily()
			}
			log.Printf("Resolve IPv4 addr failed using remote DNS: %s, using secondary DNS instead", host)
			return r.ResolveWithSecondaryDNS(ctx, host)
		}
		log.Printf("%s -> %s", host, ip.String())
		return ctx, ip, nil
	}

	if r.useRemoteDNS {
		log.DebugPrintf("Skip remote DNS for %s: recent failure, use secondary DNS", host)
	}
	return r.ResolveWithSecondaryDNS(ctx, host)
}

// isDNSTransportError 判断是否是「远端 DNS 不可用」而非「域名不存在」。
func isDNSTransportError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return !dnsErr.IsNotFound
	}
	return err != nil
}

func (r *Resolver) remoteDNSDisabled() bool {
	r.skipRemoteDNSLock.RLock()
	defer r.skipRemoteDNSLock.RUnlock()
	return r.skipRemoteDNS
}

// disableRemoteDNSTemporarily 在远端 DNS 不可用时，接下来一段时间直接走 secondary。
// 参照同一文件里 preferTCPTemporarily 的做法：到期后自动恢复，再给远端一次机会。
func (r *Resolver) disableRemoteDNSTemporarily() {
	r.skipRemoteDNSLock.Lock()
	defer r.skipRemoteDNSLock.Unlock()

	if r.skipRemoteDNS {
		return
	}

	r.skipRemoteDNS = true
	log.Printf("Remote DNS is unreachable, use secondary DNS for the next %s", remoteDNSSkipDuration)

	if r.skipRemoteDNSTimer == nil {
		r.skipRemoteDNSTimer = time.AfterFunc(remoteDNSSkipDuration, func() {
			r.skipRemoteDNSLock.Lock()
			r.skipRemoteDNS = false
			r.skipRemoteDNSTimer = nil
			r.skipRemoteDNSLock.Unlock()
			log.Printf("Remote DNS retry window reopened")
		})
	}
}

func (r *Resolver) resolveCoordinated(ctx context.Context, host string, lookup func(context.Context) (net.IP, error)) (net.IP, error) {
	r.resolutionMu.Lock()
	if r.resolutionClosed {
		r.resolutionMu.Unlock()
		return nil, net.ErrClosed
	}
	call := r.resolutions[host]
	if call == nil {
		lookupCtx, cancel := context.WithCancel(context.Background())
		call = &sharedResolution{ctx: lookupCtx, cancel: cancel, done: make(chan struct{})}
		if r.resolutions == nil {
			r.resolutions = make(map[string]*sharedResolution)
		}
		r.resolutions[host] = call
		r.activeResolutions.Add(1)
		go r.runResolution(host, call, lookup)
	}
	call.waiters++
	r.resolutionMu.Unlock()

	select {
	case <-ctx.Done():
		r.releaseResolutionWaiter(host, call)
		return nil, ctx.Err()
	case <-call.done:
		return call.ip, call.err
	}
}

func (r *Resolver) runResolution(host string, call *sharedResolution, lookup func(context.Context) (net.IP, error)) {
	call.ip, call.err = lookup(call.ctx)
	r.resolutionMu.Lock()
	if r.resolutions[host] == call {
		delete(r.resolutions, host)
	}
	r.resolutionMu.Unlock()
	call.cancel()
	r.activeResolutions.Add(-1)
	close(call.done)
}

func (r *Resolver) releaseResolutionWaiter(host string, call *sharedResolution) {
	r.resolutionMu.Lock()
	if r.resolutions[host] == call {
		call.waiters--
		if call.waiters == 0 {
			delete(r.resolutions, host)
			call.cancel()
		}
	}
	r.resolutionMu.Unlock()
}

func matchDomainResource(index *domainResourceIndex, host string) (string, []client.DomainResource, bool) {
	return index.Match(host)
}

func (r *Resolver) resolveRemote(ctx context.Context, host string) (net.IP, error) {
	// 远端 DNS 是「可能不可用」的路径，给它一个上限，
	// 避免一次解析把上层请求拖到十几秒。
	ctx, cancel := context.WithTimeout(ctx, remoteDNSTimeout)
	defer cancel()

	r.tcpLock.RLock()
	useTCP := r.useTCP
	r.tcpLock.RUnlock()

	if useTCP {
		ips, err := r.remoteTCPResolver.LookupIP(ctx, "ip4", host)
		return r.cacheFirstIP(host, ips, err)
	}

	ips, udpFailed, err := lookupIPWithTCPFallback(
		ctx,
		host,
		r.remoteUDPResolver.LookupIP,
		r.remoteTCPResolver.LookupIP,
		remoteDNSTCPFallbackDelay,
	)
	if err != nil {
		return nil, err
	}
	if udpFailed {
		r.preferTCPTemporarily()
	}
	return r.cacheFirstIP(host, ips, nil)
}

func lookupIPWithTCPFallback(ctx context.Context, host string, udpLookup, tcpLookup lookupIPFunc, fallbackDelay time.Duration) ([]net.IP, bool, error) {
	lookupCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	udpResult := make(chan dnsLookupResult, 1)
	go func() {
		ips, err := udpLookup(lookupCtx, "ip4", host)
		udpResult <- dnsLookupResult{ips: ips, err: err}
	}()

	timer := time.NewTimer(fallbackDelay)
	defer timer.Stop()
	var tcpResult chan dnsLookupResult
	var udpErr, tcpErr error
	udpDone := false
	tcpDone := false

	startTCP := func() {
		if tcpResult != nil {
			return
		}
		tcpResult = make(chan dnsLookupResult, 1)
		go func() {
			ips, err := tcpLookup(lookupCtx, "ip4", host)
			tcpResult <- dnsLookupResult{ips: ips, err: err}
		}()
	}

	for {
		select {
		case result := <-udpResult:
			udpDone = true
			if result.err == nil {
				return result.ips, false, nil
			}
			udpErr = result.err
			startTCP()
			if tcpDone {
				return nil, true, errors.Join(udpErr, tcpErr)
			}
		case result := <-tcpResult:
			tcpDone = true
			if result.err == nil {
				return result.ips, udpDone, nil
			}
			tcpErr = result.err
			if udpDone {
				return nil, true, errors.Join(udpErr, tcpErr)
			}
		case <-timer.C:
			startTCP()
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
}

func (r *Resolver) preferTCPTemporarily() {
	r.tcpLock.Lock()
	defer r.tcpLock.Unlock()
	r.useTCP = true
	if r.timer == nil {
		r.timer = time.AfterFunc(10*time.Minute, func() {
			r.tcpLock.Lock()
			r.useTCP = false
			r.timer = nil
			r.tcpLock.Unlock()
		})
	}
}

func (r *Resolver) cacheFirstIP(host string, ips []net.IP, err error) (net.IP, error) {
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("DNS lookup returned no addresses")
	}
	r.setDNSCache(host, ips[0])
	return ips[0], nil
}

func normalizeHostname(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func (r *Resolver) RemoteUDPResolver() (*net.Resolver, error) {
	if r.remoteUDPResolver != nil {
		return r.remoteUDPResolver, nil
	} else {
		return nil, errors.New("remote UDP resolver is nil")
	}
}

func (r *Resolver) RemoteTCPResolver() (*net.Resolver, error) {
	if r.remoteTCPResolver != nil {
		return r.remoteTCPResolver, nil
	} else {
		return nil, errors.New("remote TCP resolver is nil")
	}
}

func (r *Resolver) ResolveWithSecondaryDNS(ctx context.Context, host string) (context.Context, net.IP, error) {
	targets, err := r.secondaryResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		log.Printf("Resolve IPv4 addr failed using secondary DNS: %s. Try IPv6 addr", host)

		targets, err = r.secondaryResolver.LookupIP(ctx, "ip6", host)
		if err != nil {
			log.Printf("Resolve IPv6 addr failed using secondary DNS: %s", host)
			return ctx, nil, err
		}
	}

	log.Printf("%s -> %s", host, targets[0].String())
	// 写入缓存：否则每个新连接都会先白试一次远端 DNS 再回落，
	// 远端 DNS 不通时每次连接都要多等一个解析超时。
	r.setDNSCache(host, targets[0])
	return ctx, targets[0], nil
}

func (r *Resolver) Close() {
	r.closeOnce.Do(func() {
		r.resolutionMu.Lock()
		r.resolutionClosed = true
		for host, call := range r.resolutions {
			delete(r.resolutions, host)
			call.cancel()
		}
		r.resolutionMu.Unlock()
		r.tcpLock.Lock()
		if r.timer != nil {
			r.timer.Stop()
			r.timer = nil
		}
		r.tcpLock.Unlock()

		r.skipRemoteDNSLock.Lock()
		if r.skipRemoteDNSTimer != nil {
			r.skipRemoteDNSTimer.Stop()
			r.skipRemoteDNSTimer = nil
		}
		r.skipRemoteDNSLock.Unlock()
	})
}

func NewResolver(stack stack.Stack, remoteDNSServer, secondaryDNSServer string, ttl uint64, domainResources client.DomainResources, dnsResource map[string][]net.IP, useRemoteDNS bool) *Resolver {
	//domainSuffixTree := domainsuffixtrie.NewDomainSuffixTrie[bool]()
	//for domain := range domainResource {
	//	_ = domainSuffixTree.AddDomainSuffix(domain, true)
	//}

	resolver := &Resolver{
		remoteUDPResolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return stack.DialUDP(ctx, &net.UDPAddr{
					IP:   net.ParseIP(remoteDNSServer),
					Port: 53,
				})
			},
		},
		remoteTCPResolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return stack.DialTCP(ctx, &net.TCPAddr{
					IP:   net.ParseIP(remoteDNSServer),
					Port: 53,
				})
			},
		},
		ttl:          ttl,
		domainIndex:  newDomainResourceIndex(domainResources),
		dnsResource:  dnsResource,
		dnsCache:     cache.New(time.Duration(ttl)*time.Second, time.Duration(ttl)*2*time.Second),
		useRemoteDNS: useRemoteDNS,
	}

	if secondaryDNSServer != "" {
		resolver.secondaryResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(secondaryDNSServer, "53"))
			},
		}
	} else {
		resolver.secondaryResolver = &net.Resolver{
			PreferGo: true,
		}
	}
	var err error
	resolver.IPPool, err = ippool.NewIPPool[[]client.DomainResource]("198.18.0.0/16")
	if err != nil {
		log.Fatalf("Create Fake IP Pool failed: %v", err)
	}

	return resolver
}

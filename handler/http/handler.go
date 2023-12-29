package http

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	proxyv1 "github.com/go-gost/x/gen/proto/go/proxy/v1"
	netpkg "github.com/go-gost/x/internal/net"
	sx "github.com/go-gost/x/internal/util/selector"
	"github.com/go-gost/x/registry"
	"github.com/go-gost/x/report"
	"github.com/go-gost/x/utils"
)

func init() {
	registry.HandlerRegistry().Register("http", NewHandler)
}

type httpHandler struct {
	router  *chain.Router
	md      metadata
	options handler.Options
	cli     *report.CollectService
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &httpHandler{
		options: options,
	}
}

func (h *httpHandler) Init(md md.Metadata) error {
	if err := h.parseMetadata(md); err != nil {
		return err
	}

	h.router = h.options.Router
	if h.router == nil {
		h.router = chain.NewRouter(chain.LoggerRouterOption(h.options.Logger))
	}
	// 初始化日志上报
	if len(h.md.LogServiceAddr) != 0 {
		h.cli = report.NewReportService(2048, 5, h.md.LogServiceAddr)
	}
	return nil
}

func (h *httpHandler) recordLog(msg *proxyv1.LogMsg) {
	if h.cli != nil {
		h.cli.Receive(msg)
	}
}

func (h *httpHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	ctx, requestid := utils.GetOrSetRequestID(ctx)
	log := h.options.Logger.WithFields(map[string]any{
		"requestid": requestid,
	})

	remoteAddr := conn.RemoteAddr().String()
	localAddr := conn.LocalAddr().String()
	logMsg := utils.GetLogMsg(ctx)
	logMsg.RequestId = requestid
	logMsg.VpsId = h.md.VpsID
	logMsg.OriginIp, logMsg.OriginPort, _ = net.SplitHostPort(remoteAddr)
	logMsg.ProxyIp, logMsg.ProxyPort, _ = net.SplitHostPort(localAddr)
	logMsg.StartTime = time.Now().UnixMilli()
	logMsg.ProtocolType = proxyv1.ProtocolType_PROTOCOL_TYPE_HTTP
	ctx = utils.SetLogMsg(ctx, logMsg)

	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		if err != io.EOF {
			log.Errorf("err:%+v,logMsg:%+v", err, logMsg)
		}
		return err
	}
	defer req.Body.Close()

	return h.handleRequest(ctx, conn, req, log)
}

func (h *httpHandler) handleRequest(ctx context.Context, conn net.Conn, req *http.Request, log logger.Logger) error {
	ctx, requestid := utils.GetOrSetRequestID(ctx)
	log = h.options.Logger.WithFields(map[string]any{
		"requestid": requestid,
	})
	logMsg := utils.GetLogMsg(ctx)
	defer func() {
		if logMsg.ErrCode != proxyv1.LogErrCode_LOG_ERR_CODE_OK && logMsg.ErrCode != proxyv1.LogErrCode_LOG_ERR_CODE_IGNORE {
			logMsg.EndTime = time.Now().UnixMilli()
			logMsg.Duration = int32(logMsg.EndTime - logMsg.StartTime)
			h.recordLog(logMsg)
			log.Infof("http:%+v", logMsg)
		}
	}()
	if !req.URL.IsAbs() && govalidator.IsDNSName(req.Host) {
		req.URL.Scheme = "http"
	}

	network := req.Header.Get("X-Gost-Protocol")
	if network != "udp" {
		network = "tcp"
	}

	// Try to get the actual host.
	// Compatible with GOST 2.x.
	if v := req.Header.Get("Gost-Target"); v != "" {
		if h, err := h.decodeServerName(v); err == nil {
			req.Host = h
		}
	}
	req.Header.Del("Gost-Target")

	if v := req.Header.Get("X-Gost-Target"); v != "" {
		if h, err := h.decodeServerName(v); err == nil {
			req.Host = h
		}
	}
	req.Header.Del("X-Gost-Target")

	addr := req.Host
	if _, port, _ := net.SplitHostPort(addr); port == "" {
		addr = net.JoinHostPort(addr, "80")
	}

	fields := map[string]any{
		"dst": addr,
	}
	log = log.WithFields(fields)

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}
	// log.Debugf("%s >> %s", conn.RemoteAddr(), addr)

	resp := &http.Response{
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     h.md.header,
	}
	if resp.Header == nil {
		resp.Header = http.Header{}
	}

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, addr) {
		resp.StatusCode = http.StatusForbidden

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Trace(string(dump))
		}
		log.Debug("bypass: ", addr)

		return resp.Write(conn)
	}

	ctx, ok := h.authenticate(ctx, conn, req, resp, log)
	logMsg = utils.GetLogMsg(ctx)
	logMsg.TargetUrl = req.RequestURI
	logMsg.RemoteIp, logMsg.RemotePort, _ = net.SplitHostPort(addr)
	if !ok {
		logMsg.ErrCode = proxyv1.LogErrCode_LOG_ERR_CODE_AUTH
		return nil
	}
	userID := logMsg.UserId
	if !h.checkRateLimit(strconv.Itoa(int(userID))) {
		// 限流没通过
		log.Warnf("触发限流:user_id:%d", userID)
		logMsg.ErrCode = proxyv1.LogErrCode_LOG_ERR_CODE_LIMIT
		resp.StatusCode = http.StatusTooManyRequests
		if strings.ToLower(req.Header.Get("Proxy-Connection")) == "keep-alive" {
			resp.Header.Set("Connection", "close")
			resp.Header.Set("Proxy-Connection", "close")
		}
		return resp.Write(conn)
	}
	if network == "udp" {
		return h.handleUDP(ctx, conn, log)
	}

	if req.Method == "PRI" ||
		(req.Method != http.MethodConnect && req.URL.Scheme != "http") {
		resp.StatusCode = http.StatusBadRequest

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Trace(string(dump))
		}

		return resp.Write(conn)
	}

	req.Header.Del("Proxy-Authorization")

	switch h.md.hash {
	case "host":
		ctx = sx.ContextWithHash(ctx, &sx.Hash{Source: addr})
	}

	cc, err := h.router.Dial(ctx, network, addr)
	if err != nil {
		if err == io.EOF {
			logMsg.ErrCode = proxyv1.LogErrCode_LOG_ERR_CODE_IGNORE
		} else {
			resp.StatusCode = http.StatusServiceUnavailable
			logMsg.ErrCode = proxyv1.LogErrCode_LOG_ERR_CODE_TARGET
			log.Errorf("router dial err:%+v,logMsg:%+v", err, logMsg)
			if log.IsLevelEnabled(logger.TraceLevel) {
				dump, _ := httputil.DumpResponse(resp, false)
				log.Trace(string(dump))
			}
		}
		resp.Write(conn)
		return err
	}
	defer cc.Close()

	if req.Method == http.MethodConnect {
		resp.StatusCode = http.StatusOK
		resp.Status = "200 Connection established"

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Trace(string(dump))
		}
		if err = resp.Write(conn); err != nil {
			log.Error(err)
			return err
		}
	} else {
		req.Header.Del("Proxy-Connection")
		if err = req.Write(cc); err != nil {
			log.Error(err)
			return err
		}
	}

	ctx = utils.SetLogCli(ctx, h.cli)
	// log.Infof("%s <-> %s", conn.RemoteAddr(), addr)
	// netpkg.Transport(conn, cc)
	netpkg.TransportSize(ctx, conn, cc)

	return nil
}

func (h *httpHandler) decodeServerName(s string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(b) < 4 {
		return "", errors.New("invalid name")
	}
	v, err := base64.RawURLEncoding.DecodeString(string(b[4:]))
	if err != nil {
		return "", err
	}
	if crc32.ChecksumIEEE(v) != binary.BigEndian.Uint32(b[:4]) {
		return "", errors.New("invalid name")
	}
	return string(v), nil
}

func (h *httpHandler) basicProxyAuth(proxyAuth string, log logger.Logger) (username, password string, ok bool) {
	if proxyAuth == "" {
		return
	}

	if !strings.HasPrefix(proxyAuth, "Basic ") {
		return
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(proxyAuth, "Basic "))
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}

	return cs[:s], cs[s+1:], true
}

func (h *httpHandler) authenticate(ctx context.Context, conn net.Conn, req *http.Request, resp *http.Response, log logger.Logger) (context.Context, bool) {
	ctx, requestid := utils.GetOrSetRequestID(ctx)
	log = h.options.Logger.WithFields(map[string]any{
		"requestid": requestid,
	})
	logMsg := utils.GetLogMsg(ctx)
	u, p, _ := h.basicProxyAuth(req.Header.Get("Proxy-Authorization"), log)
	defer func() {
		ctx = utils.SetLogMsg(ctx, logMsg)
		log.Infof("user:%s", u)
	}()
	if auther := h.options.Auther; auther != nil {
		// 需要认证
		// 获取id
		id := h.options.Auther.Authenticate(ctx, u, p)
		if id != auth.AUTH_NOT_PASSED {
			logMsg.UserId = int32(id)
			return ctx, true
		}
		// 使用ip认证
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		id = auther.Authenticate(ctx, host, "")

		if id != auth.AUTH_NOT_PASSED {
			logMsg.UserId = int32(id)
			return ctx, true
		}
	}
	pr := h.md.probeResistance
	// probing resistance is enabled, and knocking host is mismatch.
	if pr != nil && (pr.Knock == "" || !strings.EqualFold(req.URL.Hostname(), pr.Knock)) {
		resp.StatusCode = http.StatusServiceUnavailable // default status code

		switch pr.Type {
		case "code":
			resp.StatusCode, _ = strconv.Atoi(pr.Value)
		case "web":
			url := pr.Value
			if !strings.HasPrefix(url, "http") {
				url = "http://" + url
			}
			r, err := http.Get(url)
			if err != nil {
				log.Error(err)
				break
			}
			resp = r
			defer resp.Body.Close()
		case "host":
			cc, err := net.Dial("tcp", pr.Value)
			if err != nil {
				log.Error(err)
				break
			}
			defer cc.Close()

			req.Write(cc)
			netpkg.Transport(conn, cc)
			return ctx, false
		case "file":
			f, _ := os.Open(pr.Value)
			if f != nil {
				defer f.Close()

				resp.StatusCode = http.StatusOK
				if finfo, _ := f.Stat(); finfo != nil {
					resp.ContentLength = finfo.Size()
				}
				resp.Header.Set("Content-Type", "text/html")
				resp.Body = f
			}
		}
	}

	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	if resp.StatusCode == 0 {
		realm := defaultRealm
		if h.md.authBasicRealm != "" {
			realm = h.md.authBasicRealm
		}
		resp.StatusCode = http.StatusProxyAuthRequired
		resp.Header.Add("Proxy-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", realm))
		if strings.ToLower(req.Header.Get("Proxy-Connection")) == "keep-alive" {
			// XXX libcurl will keep sending auth request in same conn
			// which we don't supported yet.
			resp.Header.Set("Connection", "close")
			resp.Header.Set("Proxy-Connection", "close")
		}

		log.Debug("proxy authentication required")
	} else {
		// resp.Header.Set("Server", "nginx/1.20.1")
		// resp.Header.Set("Date", time.Now().Format(http.TimeFormat))
		if resp.StatusCode == http.StatusOK {
			resp.Header.Set("Connection", "keep-alive")
		}
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}

	resp.Write(conn)
	return ctx, false
}

func (h *httpHandler) checkRateLimit(id string) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	if limiter := h.options.RateLimiter.Limiter(id); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}

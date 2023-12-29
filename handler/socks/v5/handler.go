package v5

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/gosocks5"
	proxyv1 "github.com/go-gost/x/gen/proto/go/proxy/v1"
	"github.com/go-gost/x/internal/util/socks"
	"github.com/go-gost/x/registry"
	"github.com/go-gost/x/report"
	"github.com/go-gost/x/utils"
)

var (
	ErrUnknownCmd = errors.New("socks5: unknown command")
)

func init() {
	registry.HandlerRegistry().Register("socks5", NewHandler)
	registry.HandlerRegistry().Register("socks", NewHandler)
}

type socks5Handler struct {
	selector *serverSelector
	router   *chain.Router
	md       metadata
	options  handler.Options
	cli      *report.CollectService
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &socks5Handler{
		options: options,
	}
}

func (h *socks5Handler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
	}

	h.router = h.options.Router
	if h.router == nil {
		h.router = chain.NewRouter(chain.LoggerRouterOption(h.options.Logger))
	}

	h.selector = &serverSelector{
		authenticator: h.options.Auther,
		TLSConfig:     h.options.TLSConfig,
		logger:        h.options.Logger,
		noTLS:         h.md.noTLS,
		md:            h.md,
		rateLimiter:   h.options.RateLimiter,
	}
	// 初始化日志上报
	if len(h.md.LogServiceAddr) != 0 {
		h.cli = report.GetReportService(h.md.LogServiceAddr)
	}
	return
}

func (h *socks5Handler) recordLog(msg *proxyv1.LogMsg) {
	if h.cli != nil {
		h.cli.Receive(msg)
	}
}

func (h *socks5Handler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()
	ctx, requestid := utils.GetOrSetRequestID(ctx)
	remoteAddr := conn.RemoteAddr().String()
	localAddr := conn.LocalAddr().String()

	log := h.options.Logger.WithFields(map[string]any{
		"requestid": requestid,
	})

	logMsg := utils.GetLogMsg(ctx)
	logMsg.RequestId = requestid
	logMsg.VpsId = h.md.VpsID
	logMsg.OriginIp, logMsg.OriginPort, _ = net.SplitHostPort(remoteAddr)
	logMsg.ProxyIp, logMsg.ProxyPort, _ = net.SplitHostPort(localAddr)
	logMsg.StartTime = time.Now().UnixMilli()
	logMsg.ProtocolType = proxyv1.ProtocolType_PROTOCOL_TYPE_SOCKS5
	ctx = utils.SetLogMsg(ctx, logMsg)
	// log.Infof("%+v", logMsg)
	defer func() {
		if logMsg.ErrCode == proxyv1.LogErrCode_LOG_ERR_CODE_OK {
			return
		}
		if logMsg.ErrCode == proxyv1.LogErrCode_LOG_ERR_CODE_IGNORE {
			if logMsg.UserId > 0 {
				logMsg.ErrCode = proxyv1.LogErrCode_LOG_ERR_CODE_TARGET
			} else {
				return
			}
		}
		logMsg.EndTime = time.Now().UnixMilli()
		logMsg.Duration = int32(logMsg.EndTime - logMsg.StartTime)
		h.recordLog(logMsg)
		log.Infof("s5:%+v", logMsg)
	}()

	if h.md.readTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(h.md.readTimeout))
	}

	connServer := gosocks5.ServerConn(ctx, conn, h.selector)
	ctx = connServer.GetCtx()
	logMsg = utils.GetLogMsg(ctx)
	req, err := gosocks5.ReadRequest(connServer)
	if err != nil {
		if err == io.EOF {
			logMsg.ErrCode = proxyv1.LogErrCode_LOG_ERR_CODE_IGNORE
		} else {
			logMsg.ErrCode = proxyv1.LogErrCode_LOG_ERR_CODE_TARGET
			log.Error(err)
		}
		return err
	}
	log.Trace(req)
	conn.SetReadDeadline(time.Time{})

	address := req.Addr.String()
	logMsg.RemoteIp, logMsg.RemotePort, _ = net.SplitHostPort(address)
	logMsg.TargetUrl = address
	ctx = utils.SetLogCli(ctx, h.cli)
	ctx = utils.SetLogMsg(ctx, logMsg)
	switch req.Cmd {
	case gosocks5.CmdConnect:
		return h.handleConnect(ctx, conn, "tcp", address, log)
	case gosocks5.CmdBind:
		return h.handleBind(ctx, conn, "tcp", address, log)
	case socks.CmdMuxBind:
		return h.handleMuxBind(ctx, conn, "tcp", address, log)
	case gosocks5.CmdUdp:
		return h.handleUDP(ctx, conn, log)
	case socks.CmdUDPTun:
		return h.handleUDPTun(ctx, conn, "udp", address, log)
	default:
		err = ErrUnknownCmd
		log.Error(err)
		resp := gosocks5.NewReply(gosocks5.CmdUnsupported, nil)
		log.Trace(resp)
		resp.Write(conn)
		return err
	}
}

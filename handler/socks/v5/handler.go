package v5

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/gosocks5"
	"github.com/go-gost/x/internal/util/socks"
	"github.com/go-gost/x/registry"
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

	return
}

func (h *socks5Handler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()
	ctx, requestid := utils.GetOrSetRequestID(ctx)
	start := time.Now()

	remoteAddr := conn.RemoteAddr().String()
	localAddr := conn.LocalAddr().String()

	log := h.options.Logger.WithFields(map[string]any{
		"requestid": requestid,
	})

	logMsg := utils.GetLogMsg(ctx)
	logMsg.RequestId = requestid
	logMsg.VpsId = h.md.VpsID
	logMsg.OriginIp = remoteAddr
	logMsg.OriginPort = remoteAddr
	logMsg.ProxyIp = localAddr
	logMsg.ProxyPort = localAddr
	logMsg.StartTime = time.Now().UnixMilli()
	ctx = utils.SetLogMsg(ctx, logMsg)
	log.Infof("%+v", logMsg)
	defer func() {
		logMsg.EndTime = time.Now().UnixMilli()
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%+v", logMsg)

	}()

	if h.md.readTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(h.md.readTimeout))
	}

	connServer := gosocks5.ServerConn(ctx, conn, h.selector)
	ctx = connServer.GetCtx()
	logMsg = utils.GetLogMsg(ctx)
	req, err := gosocks5.ReadRequest(connServer)
	if err != nil {
		log.Error(err)
		return err
	}
	log.Trace(req)
	conn.SetReadDeadline(time.Time{})

	address := req.Addr.String()
	logMsg.RemoteIp = address
	logMsg.RemotePort = address
	logMsg.TargetUrl = address

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

package v5

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/gosocks5"
	proxyv1 "github.com/go-gost/x/gen/proto/go/proxy/v1"
	"github.com/go-gost/x/internal/util/socks"
	"github.com/go-gost/x/utils"
)

type serverSelector struct {
	methods       []uint8
	authenticator auth.Authenticator
	TLSConfig     *tls.Config
	logger        logger.Logger
	noTLS         bool
	md            metadata
	rateLimiter   rate.RateLimiter
}

func (selector *serverSelector) Methods() []uint8 {
	return selector.methods
}

func (s *serverSelector) Select(methods ...uint8) (method uint8) {
	s.logger.Debugf("%d %d %v", gosocks5.Ver5, len(methods), methods)
	method = gosocks5.MethodNoAuth
	for _, m := range methods {
		if m == socks.MethodTLS && !s.noTLS {
			method = m
			break
		}
	}

	// when Authenticator is set, auth is mandatory
	if s.authenticator != nil {
		if method == gosocks5.MethodNoAuth {
			method = gosocks5.MethodUserPass
		}
		if method == socks.MethodTLS && !s.noTLS {
			method = socks.MethodTLSAuth
		}
	}

	return
}

func (s *serverSelector) OnSelected(ctx context.Context, method uint8, conn net.Conn) (context.Context, net.Conn, error) {
	_, requestid := utils.GetOrSetRequestID(ctx)
	log := s.logger.WithFields(map[string]any{
		"requestid": requestid,
	})
	var id int64
	logMsg := utils.GetLogMsg(ctx)
	defer func() {
		logMsg.UserId = int32(id)
		// log.Infof("%+v", logMsg)
		ctx = utils.SetLogMsg(ctx, logMsg)
	}()
	log.Debugf("%d %d", gosocks5.Ver5, method)
	switch method {
	case socks.MethodTLS:
		conn = tls.Server(conn, s.TLSConfig)

	case gosocks5.MethodUserPass, socks.MethodTLSAuth:
		if method == socks.MethodTLSAuth {
			conn = tls.Server(conn, s.TLSConfig)
		}

		req, err := gosocks5.ReadUserPassRequest(conn)
		if err != nil {
			log.Error(err)
			return ctx, nil, err
		}
		log.Trace(req)
		if auther := s.authenticator; auther != nil {
			// 需要认证
			// 获取id
			id = auther.Authenticate(context.Background(), req.Username, req.Password)
			if id == auth.AUTH_NOT_PASSED {
				// 使用ip认证
				host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
				id = auther.Authenticate(context.Background(), host, "")
			}

			if id == auth.AUTH_NOT_PASSED {
				logMsg.ErrCode = proxyv1.LogErrCode_LOG_ERR_CODE_AUTH
				log.Infof("s5 认证失败,username:%s,password:%s", req.Username, req.Password)
				resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Failure)
				if err := resp.Write(conn); err != nil {
					log.Error(err)
					return ctx, nil, err
				}
				return ctx, nil, gosocks5.ErrAuthFailure
			}
		}

		// 限流
		if !s.checkRateLimit(strconv.FormatInt(id, 10)) {
			logMsg.ErrCode = proxyv1.LogErrCode_LOG_ERR_CODE_LIMIT
			log.Infof("s5 触发限流,username:%s,userid:%d", req.Username, id)
			resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.NotAllowed)
			if err := resp.Write(conn); err != nil {
				log.Error(err)
				return ctx, nil, err
			}
			return ctx, nil, gosocks5.ErrAuthFailure
		}

		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Succeeded)
		log.Trace(resp)
		if err := resp.Write(conn); err != nil {
			log.Error(err)
			return ctx, nil, err
		}

	case gosocks5.MethodNoAcceptable:
		return ctx, nil, gosocks5.ErrBadMethod
	}

	return ctx, conn, nil
}

func (s *serverSelector) checkRateLimit(id string) bool {
	if s.rateLimiter == nil {
		return true
	}
	if limiter := s.rateLimiter.Limiter(id); limiter != nil {
		return limiter.Allow(1)
	}
	return true
}

package v5

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/gosocks5"
	"github.com/go-gost/x/internal/util/socks"
)

type serverSelector struct {
	methods       []uint8
	Authenticator auth.Authenticator
	TLSConfig     *tls.Config
	logger        logger.Logger
	noTLS         bool
	md            metadata
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
	if s.Authenticator != nil {
		if method == gosocks5.MethodNoAuth {
			method = gosocks5.MethodUserPass
		}
		if method == socks.MethodTLS && !s.noTLS {
			method = socks.MethodTLSAuth
		}
	}

	return
}

func (s *serverSelector) OnSelected(method uint8, conn net.Conn) (net.Conn, error) {
	s.logger.Debugf("%d %d", gosocks5.Ver5, method)
	switch method {
	case socks.MethodTLS:
		conn = tls.Server(conn, s.TLSConfig)

	case gosocks5.MethodUserPass, socks.MethodTLSAuth:
		if method == socks.MethodTLSAuth {
			conn = tls.Server(conn, s.TLSConfig)
		}

		req, err := gosocks5.ReadUserPassRequest(conn)
		if err != nil {
			s.logger.Error(err)
			return nil, err
		}
		s.logger.Trace(req)
		if auther := s.Authenticator; auther != nil {
			// 需要认证
			// 获取id
			id := auther.Authenticate(context.Background(), req.Username, req.Password)
			if id == auth.AUTH_NOT_PASSED {
				// 使用ip认证
				host, _, _ := net.SplitHostPort(s.md.RemoteAddr)
				id = auther.Authenticate(context.Background(), host, "")
			}

			if id == auth.AUTH_NOT_PASSED {
				resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Failure)
				if err := resp.Write(conn); err != nil {
					s.logger.Error(err)
					return nil, err
				}
				return nil, gosocks5.ErrAuthFailure
			}
			s.md.UserID = id
		}

		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Succeeded)
		s.logger.Trace(resp)
		if err := resp.Write(conn); err != nil {
			s.logger.Error(err)
			return nil, err
		}

	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}

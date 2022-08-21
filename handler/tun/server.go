package tun

import (
	"context"
	"io"
	"net"

	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/logger"
	tun_util "github.com/go-gost/x/internal/util/tun"
	"github.com/songgao/water/waterutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func (h *tunHandler) handleServer(ctx context.Context, conn net.Conn, config *tun_util.Config, log logger.Logger) error {
	pc, err := net.ListenPacket(conn.LocalAddr().Network(), conn.LocalAddr().String())
	if err != nil {
		return err
	}
	defer pc.Close()

	return h.transportServer(conn, pc, config, log)
}

func (h *tunHandler) transportServer(tun net.Conn, conn net.PacketConn, config *tun_util.Config, log logger.Logger) error {
	errc := make(chan error, 1)

	go func() {
		for {
			err := func() error {
				b := bufpool.Get(h.md.bufferSize)
				defer bufpool.Put(b)

				n, err := tun.Read(*b)
				if err != nil {
					return err
				}

				var src, dst net.IP
				if waterutil.IsIPv4((*b)[:n]) {
					header, err := ipv4.ParseHeader((*b)[:n])
					if err != nil {
						log.Warn(err)
						return nil
					}
					src, dst = header.Src, header.Dst

					log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
						header.Src, header.Dst, ipProtocol(waterutil.IPv4Protocol((*b)[:n])),
						header.Len, header.TotalLen, header.ID, header.Flags)
				} else if waterutil.IsIPv6((*b)[:n]) {
					header, err := ipv6.ParseHeader((*b)[:n])
					if err != nil {
						log.Warn(err)
						return nil
					}
					src, dst = header.Src, header.Dst

					log.Tracef("%s >> %s %s %d %d",
						header.Src, header.Dst,
						ipProtocol(waterutil.IPProtocol(header.NextHeader)),
						header.PayloadLen, header.TrafficClass)
				} else {
					log.Warn("unknown packet, discarded")
					return nil
				}

				addr := h.findRouteFor(dst, config.Routes...)
				if addr == nil {
					log.Debugf("no route for %s -> %s, packet discarded", src, dst)
					return nil
				}

				log.Debugf("find route: %s -> %s", dst, addr)

				if _, err := conn.WriteTo((*b)[:n], addr); err != nil {
					return err
				}
				return nil
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	go func() {
		for {
			err := func() error {
				b := bufpool.Get(h.md.bufferSize)
				defer bufpool.Put(b)

				n, addr, err := conn.ReadFrom(*b)
				if err != nil {
					return err
				}

				var src, dst net.IP
				if waterutil.IsIPv4((*b)[:n]) {
					header, err := ipv4.ParseHeader((*b)[:n])
					if err != nil {
						log.Warn(err)
						return nil
					}
					src, dst = header.Src, header.Dst

					log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
						header.Src, header.Dst, ipProtocol(waterutil.IPv4Protocol((*b)[:n])),
						header.Len, header.TotalLen, header.ID, header.Flags)
				} else if waterutil.IsIPv6((*b)[:n]) {
					header, err := ipv6.ParseHeader((*b)[:n])
					if err != nil {
						log.Warn(err)
						return nil
					}
					src, dst = header.Src, header.Dst

					log.Tracef("%s > %s %s %d %d",
						header.Src, header.Dst,
						ipProtocol(waterutil.IPProtocol(header.NextHeader)),
						header.PayloadLen, header.TrafficClass)
				} else {
					log.Warn("unknown packet, discarded")
					return nil
				}

				rkey := ipToTunRouteKey(src)
				if actual, loaded := h.routes.LoadOrStore(rkey, addr); loaded {
					if actual.(net.Addr).String() != addr.String() {
						h.routes.Store(rkey, addr)
						log.Debugf("update route: %s -> %s (old %s)",
							src, addr, actual.(net.Addr))
					}
				} else {
					log.Debugf("new route: %s -> %s", src, addr)
				}

				if addr := h.findRouteFor(dst, config.Routes...); addr != nil {
					log.Debugf("find route: %s -> %s", dst, addr)

					_, err := conn.WriteTo((*b)[:n], addr)
					return err
				}

				if _, err := tun.Write((*b)[:n]); err != nil {
					return err
				}
				return nil
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	err := <-errc
	if err != nil && err == io.EOF {
		err = nil
	}
	return err
}

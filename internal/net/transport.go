package net

import (
	"bufio"
	"context"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/x/utils"
)

const (
	bufferSize = 64 * 1024
)

func Transport(rw1, rw2 io.ReadWriter) error {
	errc := make(chan error, 1)
	go func() {
		errc <- CopyBuffer(rw1, rw2, bufferSize)
	}()

	go func() {
		errc <- CopyBuffer(rw2, rw1, bufferSize)
	}()

	if err := <-errc; err != nil && err != io.EOF {
		return err
	}

	return nil
}

func CopyBuffer(dst io.Writer, src io.Reader, bufSize int) error {
	buf := bufpool.Get(bufSize)
	defer bufpool.Put(buf)

	_, err := io.CopyBuffer(dst, src, *buf)
	return err
}

func TransportSize(ctx context.Context, rw1, rw2 io.ReadWriter) error {
	errc := make(chan error, 1)
	var l1 int64
	var err1 error
	go func() {
		l1, err1 = CopyBufferSize(rw1, rw2, bufferSize)
		errc <- err1
		logMsg := utils.GetLogMsg(ctx)
		logMsg.EndTime = time.Now().UnixMilli()
		logMsg.Duration = int32(logMsg.EndTime - logMsg.StartTime)
		logMsg.DataSize = int32(l1)
		utils.GetLog(ctx).Infof("success:%+v", logMsg)
		if cli := utils.GetLogCli(ctx); cli != nil {
			cli.Receive(logMsg)
		}

	}()

	go func() {
		_, err2 := CopyBufferSize(rw2, rw1, bufferSize)
		errc <- err2
	}()

	if err := <-errc; err != nil && err != io.EOF {
		return err
	}

	return nil
}

func CopyBufferSize(dst io.Writer, src io.Reader, bufSize int) (int64, error) {
	buf := bufpool.Get(bufSize)
	defer bufpool.Put(buf)

	return io.CopyBuffer(dst, src, *buf)
}

type bufferReaderConn struct {
	net.Conn
	br *bufio.Reader
}

func NewBufferReaderConn(conn net.Conn, br *bufio.Reader) net.Conn {
	return &bufferReaderConn{
		Conn: conn,
		br:   br,
	}
}

func (c *bufferReaderConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}

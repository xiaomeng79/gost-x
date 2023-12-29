package report

import (
	"context"
	"time"

	collectv1 "github.com/go-gost/x/gen/proto/go/collect/v1"
	proxyv1 "github.com/go-gost/x/gen/proto/go/proxy/v1"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/timeout"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// 数据最大长度
	MAX_DATA_LEN = 1 << 11
	// 最大上报时间，秒
	MAX_REPORT_TIME = 10
)

const (
	// 默认长度
	DEFAULT_DATA_LEN = 2048
	// 默认上报时间
	DEFAULT_REPORT_TIME = 5
)

var (
	cs *CollectService
)

// 处理用户上报日志服务
type CollectService struct {
	// 通道大小
	len int
	// 上报大小，默认为长度的一半
	reportLen int
	// 缓存消息的通道
	ch chan *proxyv1.LogMsg
	// 触发上报的时间，秒
	reportTime int
	// 触发上报
	reportCh chan struct{}
	// GRPC 客户端
	c collectv1.CollectServiceClient
	// GRPC 客户端连接
	conn *grpc.ClientConn
	// logger
	logger *logrus.Entry
	// grpc 地址
	addr string
	// 关闭
	closeCh chan struct{}
}

// 获取上报日志服务
func GetReportService(addr string) *CollectService {
	if cs == nil {
		cs = newReportService(DEFAULT_DATA_LEN, DEFAULT_REPORT_TIME, addr)
	}
	if addr != cs.addr {
		csCopy := cs
		go csCopy.closed()
		cs = newReportService(DEFAULT_DATA_LEN, DEFAULT_REPORT_TIME, addr)
	}
	return cs
}

// 初始化日志服务
func newReportService(l, rt int, addr string) *CollectService {
	logger := logrus.WithFields(map[string]any{
		"service":   "gRPC/client",
		"component": "ip-proxy-report",
	})
	if l > MAX_DATA_LEN || l == 0 {
		l = MAX_DATA_LEN
	}
	if rt > MAX_REPORT_TIME || l == 0 {
		rt = MAX_REPORT_TIME
	}

	logger.Infof("grpc上报数据长度:%d,上报时间:%ds,上报地址:%s\n", l, rt, addr)
	s := &CollectService{
		len:        l,
		reportLen:  l >> 1,
		ch:         make(chan *proxyv1.LogMsg, l),
		reportTime: rt,
		reportCh:   make(chan struct{}, 1),
		logger:     logger,
		addr:       addr,
	}
	// 客户端
	s.rebuildClient()

	go s.selectSend()
	return s
}

// 重新构建客户端
func (l *CollectService) rebuildClient() {
	if l.conn != nil {
		_ = l.conn.Close()
	}
	// 客户端
	conn, err := grpc.Dial(
		l.addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(
			timeout.UnaryClientInterceptor(5*time.Second)),
	)
	if err != nil {
		l.logger.Errorf("日志上报服务异常 addr:%s,err:%+v", l.addr, err)
	}
	c := collectv1.NewCollectServiceClient(conn)
	l.conn = conn
	l.c = c
}

// 接受数据
func (l *CollectService) Receive(data *proxyv1.LogMsg) {
	curLen := len(l.ch)
	// 如果数据量大于最大长度，丢弃
	if curLen >= l.len {
		return
	}
	l.ch <- data
	if curLen >= l.reportLen {
		l.reportCh <- struct{}{}
	}
}

func (l *CollectService) reportLogRetry(events []*proxyv1.LogMsg) {
	defer func() {
		if r := recover(); r != nil {
			l.logger.Errorf("panic:reportLogRetry:%+v", r)
		}
	}()
	for i := 1; i <= 6; i++ {
		time.Sleep(time.Second * 5 * time.Duration(i))
		// 重试
		err := l.reportLog(events)
		if err == nil {
			return
		}
	}
}

func (l *CollectService) send() {
	ll := len(l.ch)
	if ll == 0 {
		return
	}
	events := make([]*proxyv1.LogMsg, 0, ll)
	for i := 0; i < ll; i++ {
		events = append(events, <-l.ch)
	}
	err := l.reportLog(events)
	if err != nil {
		l.logger.Errorf("grpc log send err:%+v\n", err)
		l.rebuildClient()
		// 重试
		go l.reportLogRetry(events)
	}
}

func (l *CollectService) selectSend() {
	defer func() {
		if r := recover(); r != nil {
			l.logger.Errorf("panic:selectSend:%+v", r)
		}
	}()
	for {
		select {
		case <-time.After(time.Second * time.Duration(l.reportTime)):
			l.send()
		case <-l.reportCh:
			l.send()
		case <-l.closeCh:
			l.send()
			return
		}
	}
}

func (l *CollectService) closed() {
	defer func() {
		if r := recover(); r != nil {
			l.logger.Errorf("panic:closed:%+v", r)
		}
	}()
	l.closeCh <- struct{}{}
	time.After(time.Second * 10)
	if l.conn != nil {
		_ = l.conn.Close()
	}
}

func (l *CollectService) reportLog(events []*proxyv1.LogMsg) error {
	// 超时控制
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// 重试
	_, err := l.c.ReportLog(ctx, &collectv1.Logs{Data: events})
	return err
}

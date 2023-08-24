package utils

import (
	"context"

	proxyv1 "github.com/go-gost/x/gen/proto/go/proxy/v1"
	"github.com/google/uuid"
)

type requestID struct{}

func GetRequestID(ctx context.Context) string {
	if val := ctx.Value(requestID{}); val != nil {
		if value, ok := val.(string); ok {
			return value
		}
	}
	return ""
}

func SetRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestID{}, id)
}

func GetOrSetRequestID(ctx context.Context) (context.Context, string) {
	id := GetRequestID(ctx)
	if len(id) == 0 {
		id = uuid.New().String()
		ctx = SetRequestID(ctx, id)
	}
	return ctx, id
}

type logMsg struct{}

func GetLogMsg(ctx context.Context) *proxyv1.LogMsg {
	if val := ctx.Value(logMsg{}); val != nil {
		if value, ok := val.(*proxyv1.LogMsg); ok {
			return value
		}
	}
	return &proxyv1.LogMsg{}
}

func SetLogMsg(ctx context.Context, msg *proxyv1.LogMsg) context.Context {
	return context.WithValue(ctx, logMsg{}, msg)
}


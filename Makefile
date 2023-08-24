GEN_PROTO_PATH=gen/proto/go

clean:
	go clean

test:
	go test ./...

# 安装依赖
install: 
	go install github.com/bufbuild/buf/cmd/buf@latest

# 远程生成
gen-remote: install
	buf generate buf.build/xiaomeng99/ip-proxy-apis

# 本地测试
gen-local: install
	buf generate ../ip-proxy-apis
	protoc-go-inject-tag -input="${GEN_PROTO_PATH}/proxy/v1/*.pb.go"
	protoc-go-inject-tag -input="${GEN_PROTO_PATH}/config/v1/*.pb.go"
	protoc-go-inject-tag -input="${GEN_PROTO_PATH}/report/v1/*.pb.go"


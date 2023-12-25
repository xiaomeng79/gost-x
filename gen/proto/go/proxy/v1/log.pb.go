// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: proxy/v1/log.proto

package proxyv1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// 代理类型
type LogErrCode int32

const (
	// 保留
	LogErrCode_LOG_ERR_CODE_OK LogErrCode = 0
	// 认证失败
	LogErrCode_LOG_ERR_CODE_AUTH LogErrCode = 1
	// 限流
	LogErrCode_LOG_ERR_CODE_LIMIT LogErrCode = 2
	// 目标站点错误
	LogErrCode_LOG_ERR_CODE_TARGET LogErrCode = 3
	// 其他
	LogErrCode_LOG_ERR_CODE_OTHER LogErrCode = 4
	// 忽略
	LogErrCode_LOG_ERR_CODE_IGNORE LogErrCode = 5
)

// Enum value maps for LogErrCode.
var (
	LogErrCode_name = map[int32]string{
		0: "LOG_ERR_CODE_OK",
		1: "LOG_ERR_CODE_AUTH",
		2: "LOG_ERR_CODE_LIMIT",
		3: "LOG_ERR_CODE_TARGET",
		4: "LOG_ERR_CODE_OTHER",
		5: "LOG_ERR_CODE_IGNORE",
	}
	LogErrCode_value = map[string]int32{
		"LOG_ERR_CODE_OK":     0,
		"LOG_ERR_CODE_AUTH":   1,
		"LOG_ERR_CODE_LIMIT":  2,
		"LOG_ERR_CODE_TARGET": 3,
		"LOG_ERR_CODE_OTHER":  4,
		"LOG_ERR_CODE_IGNORE": 5,
	}
)

func (x LogErrCode) Enum() *LogErrCode {
	p := new(LogErrCode)
	*p = x
	return p
}

func (x LogErrCode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (LogErrCode) Descriptor() protoreflect.EnumDescriptor {
	return file_proxy_v1_log_proto_enumTypes[0].Descriptor()
}

func (LogErrCode) Type() protoreflect.EnumType {
	return &file_proxy_v1_log_proto_enumTypes[0]
}

func (x LogErrCode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use LogErrCode.Descriptor instead.
func (LogErrCode) EnumDescriptor() ([]byte, []int) {
	return file_proxy_v1_log_proto_rawDescGZIP(), []int{0}
}

// 协议类型
type ProtocolType int32

const (
	// 保留
	ProtocolType_PROTOCOL_TYPE_DEFAULT ProtocolType = 0
	// HTTP
	ProtocolType_PROTOCOL_TYPE_HTTP ProtocolType = 1
	// SOCKS5
	ProtocolType_PROTOCOL_TYPE_SOCKS5 ProtocolType = 2
)

// Enum value maps for ProtocolType.
var (
	ProtocolType_name = map[int32]string{
		0: "PROTOCOL_TYPE_DEFAULT",
		1: "PROTOCOL_TYPE_HTTP",
		2: "PROTOCOL_TYPE_SOCKS5",
	}
	ProtocolType_value = map[string]int32{
		"PROTOCOL_TYPE_DEFAULT": 0,
		"PROTOCOL_TYPE_HTTP":    1,
		"PROTOCOL_TYPE_SOCKS5":  2,
	}
)

func (x ProtocolType) Enum() *ProtocolType {
	p := new(ProtocolType)
	*p = x
	return p
}

func (x ProtocolType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ProtocolType) Descriptor() protoreflect.EnumDescriptor {
	return file_proxy_v1_log_proto_enumTypes[1].Descriptor()
}

func (ProtocolType) Type() protoreflect.EnumType {
	return &file_proxy_v1_log_proto_enumTypes[1]
}

func (x ProtocolType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ProtocolType.Descriptor instead.
func (ProtocolType) EnumDescriptor() ([]byte, []int) {
	return file_proxy_v1_log_proto_rawDescGZIP(), []int{1}
}

// 上报日志
type LogMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// @gotags: bson:"vps_id",fake:"{regex:[123456789]{2}}"
	VpsId int32 `protobuf:"varint,1,opt,name=vps_id,json=vpsId,proto3" json:"vps_id,omitempty" bson:"vps_id" fake:"{regex:[123456789]{2}}"`
	// @gotags: bson:"u_id",fake:"{regex:[123456789]{2}}"
	UserId int32 `protobuf:"varint,2,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty" bson:"u_id" fake:"{regex:[123456789]{2}}"`
	// @gotags: bson:"origin_ip",fake:"{ipv4address}"
	OriginIp string `protobuf:"bytes,3,opt,name=origin_ip,json=originIp,proto3" json:"origin_ip,omitempty" bson:"origin_ip" fake:"{ipv4address}"`
	// @gotags: bson:"origin_port",fake:"{number:0,65535}"
	OriginPort string `protobuf:"bytes,4,opt,name=origin_port,json=originPort,proto3" json:"origin_port,omitempty" bson:"origin_port" fake:"{number:0,65535}"`
	// @gotags: bson:"proxy_ip",fake:"{ipv4address}"
	ProxyIp string `protobuf:"bytes,5,opt,name=proxy_ip,json=proxyIp,proto3" json:"proxy_ip,omitempty" bson:"proxy_ip" fake:"{ipv4address}"`
	// @gotags: bson:"proxy_port",fake:"{number:0,65535}"
	ProxyPort string `protobuf:"bytes,6,opt,name=proxy_port,json=proxyPort,proto3" json:"proxy_port,omitempty" bson:"proxy_port" fake:"{number:0,65535}"`
	// @gotags: bson:"remote_ip",fake:"{ipv4address}"
	RemoteIp string `protobuf:"bytes,7,opt,name=remote_ip,json=remoteIp,proto3" json:"remote_ip,omitempty" bson:"remote_ip" fake:"{ipv4address}"`
	// @gotags: bson:"remote_port",fake:"{number:0,65535}"
	RemotePort string `protobuf:"bytes,8,opt,name=remote_port,json=remotePort,proto3" json:"remote_port,omitempty" bson:"remote_port" fake:"{number:0,65535}"`
	// @gotags: bson:"start_time",fake:"{number:1621619520,1629959520}"
	StartTime int64 `protobuf:"varint,9,opt,name=start_time,json=startTime,proto3" json:"start_time,omitempty" bson:"start_time" fake:"{number:1621619520,1629959520}"`
	// @gotags: bson:"request_id",fake:"{regex:[123456789]{16}}"
	RequestId string `protobuf:"bytes,10,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty" bson:"request_id" fake:"{regex:[123456789]{16}}"`
	// @gotags: bson:"target_url",fake:"{url}"
	TargetUrl string `protobuf:"bytes,11,opt,name=target_url,json=targetUrl,proto3" json:"target_url,omitempty" bson:"target_url" fake:"{url}"`
	// @gotags: bson:"err_code",fake:"{regex:[0123456789]{1}}"
	ErrCode LogErrCode `protobuf:"varint,12,opt,name=err_code,json=errCode,proto3,enum=proxy.v1.LogErrCode" json:"err_code,omitempty" bson:"err_code" fake:"{regex:[0123456789]{1}}"`
	// @gotags: bson:"end_time",fake:"{number:1621619520,1629959520}"
	EndTime int64 `protobuf:"varint,13,opt,name=end_time,json=endTime,proto3" json:"end_time,omitempty" bson:"end_time" fake:"{number:1621619520,1629959520}"`
	// @gotags: bson:"duration",fake:"{number:0,1629959520}"
	Duration int32 `protobuf:"varint,14,opt,name=duration,proto3" json:"duration,omitempty" bson:"duration" fake:"{number:0,1629959520}"`
	// @gotags: bson:"protocol_type",fake:"{number:0,2}"
	ProtocolType ProtocolType `protobuf:"varint,15,opt,name=protocol_type,json=protocolType,proto3,enum=proxy.v1.ProtocolType" json:"protocol_type,omitempty" bson:"protocol_type" fake:"{number:0,2}"`
	// @gotags: bson:"data_size",fake:"{number:0,1629959520}"
	DataSize int32 `protobuf:"varint,16,opt,name=data_size,json=dataSize,proto3" json:"data_size,omitempty" bson:"data_size" fake:"{number:0,1629959520}"`
}

func (x *LogMsg) Reset() {
	*x = LogMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_v1_log_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LogMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogMsg) ProtoMessage() {}

func (x *LogMsg) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_v1_log_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogMsg.ProtoReflect.Descriptor instead.
func (*LogMsg) Descriptor() ([]byte, []int) {
	return file_proxy_v1_log_proto_rawDescGZIP(), []int{0}
}

func (x *LogMsg) GetVpsId() int32 {
	if x != nil {
		return x.VpsId
	}
	return 0
}

func (x *LogMsg) GetUserId() int32 {
	if x != nil {
		return x.UserId
	}
	return 0
}

func (x *LogMsg) GetOriginIp() string {
	if x != nil {
		return x.OriginIp
	}
	return ""
}

func (x *LogMsg) GetOriginPort() string {
	if x != nil {
		return x.OriginPort
	}
	return ""
}

func (x *LogMsg) GetProxyIp() string {
	if x != nil {
		return x.ProxyIp
	}
	return ""
}

func (x *LogMsg) GetProxyPort() string {
	if x != nil {
		return x.ProxyPort
	}
	return ""
}

func (x *LogMsg) GetRemoteIp() string {
	if x != nil {
		return x.RemoteIp
	}
	return ""
}

func (x *LogMsg) GetRemotePort() string {
	if x != nil {
		return x.RemotePort
	}
	return ""
}

func (x *LogMsg) GetStartTime() int64 {
	if x != nil {
		return x.StartTime
	}
	return 0
}

func (x *LogMsg) GetRequestId() string {
	if x != nil {
		return x.RequestId
	}
	return ""
}

func (x *LogMsg) GetTargetUrl() string {
	if x != nil {
		return x.TargetUrl
	}
	return ""
}

func (x *LogMsg) GetErrCode() LogErrCode {
	if x != nil {
		return x.ErrCode
	}
	return LogErrCode_LOG_ERR_CODE_OK
}

func (x *LogMsg) GetEndTime() int64 {
	if x != nil {
		return x.EndTime
	}
	return 0
}

func (x *LogMsg) GetDuration() int32 {
	if x != nil {
		return x.Duration
	}
	return 0
}

func (x *LogMsg) GetProtocolType() ProtocolType {
	if x != nil {
		return x.ProtocolType
	}
	return ProtocolType_PROTOCOL_TYPE_DEFAULT
}

func (x *LogMsg) GetDataSize() int32 {
	if x != nil {
		return x.DataSize
	}
	return 0
}

var File_proxy_v1_log_proto protoreflect.FileDescriptor

var file_proxy_v1_log_proto_rawDesc = []byte{
	0x0a, 0x12, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x76, 0x31, 0x2f, 0x6c, 0x6f, 0x67, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x08, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x22, 0x8d,
	0x04, 0x0a, 0x06, 0x4c, 0x6f, 0x67, 0x4d, 0x73, 0x67, 0x12, 0x15, 0x0a, 0x06, 0x76, 0x70, 0x73,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x76, 0x70, 0x73, 0x49, 0x64,
	0x12, 0x17, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x05, 0x52, 0x06, 0x75, 0x73, 0x65, 0x72, 0x49, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x6f, 0x72, 0x69,
	0x67, 0x69, 0x6e, 0x5f, 0x69, 0x70, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x6f, 0x72,
	0x69, 0x67, 0x69, 0x6e, 0x49, 0x70, 0x12, 0x1f, 0x0a, 0x0b, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e,
	0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x6f, 0x72, 0x69,
	0x67, 0x69, 0x6e, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x78, 0x79,
	0x5f, 0x69, 0x70, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x70, 0x72, 0x6f, 0x78, 0x79,
	0x49, 0x70, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x5f, 0x70, 0x6f, 0x72, 0x74,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x50, 0x6f, 0x72,
	0x74, 0x12, 0x1b, 0x0a, 0x09, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x5f, 0x69, 0x70, 0x18, 0x07,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x49, 0x70, 0x12, 0x1f,
	0x0a, 0x0b, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x08, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0a, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x50, 0x6f, 0x72, 0x74, 0x12,
	0x1d, 0x0a, 0x0a, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x09, 0x20,
	0x01, 0x28, 0x03, 0x52, 0x09, 0x73, 0x74, 0x61, 0x72, 0x74, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x1d,
	0x0a, 0x0a, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x1d, 0x0a,
	0x0a, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x75, 0x72, 0x6c, 0x18, 0x0b, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x09, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x55, 0x72, 0x6c, 0x12, 0x2f, 0x0a, 0x08,
	0x65, 0x72, 0x72, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x14,
	0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x6f, 0x67, 0x45, 0x72, 0x72,
	0x43, 0x6f, 0x64, 0x65, 0x52, 0x07, 0x65, 0x72, 0x72, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x19, 0x0a,
	0x08, 0x65, 0x6e, 0x64, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x07, 0x65, 0x6e, 0x64, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x64, 0x75, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x05, 0x52, 0x08, 0x64, 0x75, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x3b, 0x0a, 0x0d, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c,
	0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x16, 0x2e, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x54,
	0x79, 0x70, 0x65, 0x52, 0x0c, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x1b, 0x0a, 0x09, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x10,
	0x20, 0x01, 0x28, 0x05, 0x52, 0x08, 0x64, 0x61, 0x74, 0x61, 0x53, 0x69, 0x7a, 0x65, 0x2a, 0x9a,
	0x01, 0x0a, 0x0a, 0x4c, 0x6f, 0x67, 0x45, 0x72, 0x72, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x13, 0x0a,
	0x0f, 0x4c, 0x4f, 0x47, 0x5f, 0x45, 0x52, 0x52, 0x5f, 0x43, 0x4f, 0x44, 0x45, 0x5f, 0x4f, 0x4b,
	0x10, 0x00, 0x12, 0x15, 0x0a, 0x11, 0x4c, 0x4f, 0x47, 0x5f, 0x45, 0x52, 0x52, 0x5f, 0x43, 0x4f,
	0x44, 0x45, 0x5f, 0x41, 0x55, 0x54, 0x48, 0x10, 0x01, 0x12, 0x16, 0x0a, 0x12, 0x4c, 0x4f, 0x47,
	0x5f, 0x45, 0x52, 0x52, 0x5f, 0x43, 0x4f, 0x44, 0x45, 0x5f, 0x4c, 0x49, 0x4d, 0x49, 0x54, 0x10,
	0x02, 0x12, 0x17, 0x0a, 0x13, 0x4c, 0x4f, 0x47, 0x5f, 0x45, 0x52, 0x52, 0x5f, 0x43, 0x4f, 0x44,
	0x45, 0x5f, 0x54, 0x41, 0x52, 0x47, 0x45, 0x54, 0x10, 0x03, 0x12, 0x16, 0x0a, 0x12, 0x4c, 0x4f,
	0x47, 0x5f, 0x45, 0x52, 0x52, 0x5f, 0x43, 0x4f, 0x44, 0x45, 0x5f, 0x4f, 0x54, 0x48, 0x45, 0x52,
	0x10, 0x04, 0x12, 0x17, 0x0a, 0x13, 0x4c, 0x4f, 0x47, 0x5f, 0x45, 0x52, 0x52, 0x5f, 0x43, 0x4f,
	0x44, 0x45, 0x5f, 0x49, 0x47, 0x4e, 0x4f, 0x52, 0x45, 0x10, 0x05, 0x2a, 0x5b, 0x0a, 0x0c, 0x50,
	0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x54, 0x79, 0x70, 0x65, 0x12, 0x19, 0x0a, 0x15, 0x50,
	0x52, 0x4f, 0x54, 0x4f, 0x43, 0x4f, 0x4c, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x44, 0x45, 0x46,
	0x41, 0x55, 0x4c, 0x54, 0x10, 0x00, 0x12, 0x16, 0x0a, 0x12, 0x50, 0x52, 0x4f, 0x54, 0x4f, 0x43,
	0x4f, 0x4c, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x48, 0x54, 0x54, 0x50, 0x10, 0x01, 0x12, 0x18,
	0x0a, 0x14, 0x50, 0x52, 0x4f, 0x54, 0x4f, 0x43, 0x4f, 0x4c, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f,
	0x53, 0x4f, 0x43, 0x4b, 0x53, 0x35, 0x10, 0x02, 0x42, 0x90, 0x01, 0x0a, 0x0c, 0x63, 0x6f, 0x6d,
	0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x42, 0x08, 0x4c, 0x6f, 0x67, 0x50, 0x72,
	0x6f, 0x74, 0x6f, 0x48, 0x02, 0x5a, 0x32, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x67, 0x6f, 0x2d, 0x67, 0x6f, 0x73, 0x74, 0x2f, 0x78, 0x2f, 0x67, 0x65, 0x6e, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x76,
	0x31, 0x3b, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x76, 0x31, 0xf8, 0x01, 0x00, 0xa2, 0x02, 0x03, 0x50,
	0x58, 0x58, 0xaa, 0x02, 0x08, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x56, 0x31, 0xca, 0x02, 0x08,
	0x50, 0x72, 0x6f, 0x78, 0x79, 0x5c, 0x56, 0x31, 0xe2, 0x02, 0x14, 0x50, 0x72, 0x6f, 0x78, 0x79,
	0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea,
	0x02, 0x09, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x3a, 0x3a, 0x56, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_proxy_v1_log_proto_rawDescOnce sync.Once
	file_proxy_v1_log_proto_rawDescData = file_proxy_v1_log_proto_rawDesc
)

func file_proxy_v1_log_proto_rawDescGZIP() []byte {
	file_proxy_v1_log_proto_rawDescOnce.Do(func() {
		file_proxy_v1_log_proto_rawDescData = protoimpl.X.CompressGZIP(file_proxy_v1_log_proto_rawDescData)
	})
	return file_proxy_v1_log_proto_rawDescData
}

var file_proxy_v1_log_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_proxy_v1_log_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_proxy_v1_log_proto_goTypes = []interface{}{
	(LogErrCode)(0),   // 0: proxy.v1.LogErrCode
	(ProtocolType)(0), // 1: proxy.v1.ProtocolType
	(*LogMsg)(nil),    // 2: proxy.v1.LogMsg
}
var file_proxy_v1_log_proto_depIdxs = []int32{
	0, // 0: proxy.v1.LogMsg.err_code:type_name -> proxy.v1.LogErrCode
	1, // 1: proxy.v1.LogMsg.protocol_type:type_name -> proxy.v1.ProtocolType
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_proxy_v1_log_proto_init() }
func file_proxy_v1_log_proto_init() {
	if File_proxy_v1_log_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proxy_v1_log_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LogMsg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proxy_v1_log_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proxy_v1_log_proto_goTypes,
		DependencyIndexes: file_proxy_v1_log_proto_depIdxs,
		EnumInfos:         file_proxy_v1_log_proto_enumTypes,
		MessageInfos:      file_proxy_v1_log_proto_msgTypes,
	}.Build()
	File_proxy_v1_log_proto = out.File
	file_proxy_v1_log_proto_rawDesc = nil
	file_proxy_v1_log_proto_goTypes = nil
	file_proxy_v1_log_proto_depIdxs = nil
}

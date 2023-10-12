// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: ipproxy/v1/ip.proto

package ipproxyv1

import (
	v1 "github.com/go-gost/x/gen/proto/go/proxy/v1"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	_ "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// 获取订单ip
type GetIpReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// appkey
	AppKey string `protobuf:"bytes,1,opt,name=app_key,json=appKey,proto3" json:"app_key,omitempty"`
	// 订单号
	OrderNo string `protobuf:"bytes,2,opt,name=order_no,json=orderNo,proto3" json:"order_no,omitempty"`
	// 服务类型：http,socks5
	ServiceType string `protobuf:"bytes,3,opt,name=service_type,json=serviceType,proto3" json:"service_type,omitempty"`
	// 有效时间：秒
	ValidTime int64 `protobuf:"varint,4,opt,name=valid_time,json=validTime,proto3" json:"valid_time,omitempty"`
	// 提取数量
	ExtractNumber int64 `protobuf:"varint,5,opt,name=extract_number,json=extractNumber,proto3" json:"extract_number,omitempty"`
	// 提取格式：text,json
	ExtractFormat string `protobuf:"bytes,6,opt,name=extract_format,json=extractFormat,proto3" json:"extract_format,omitempty"`
	// 是否显示详细信息
	IsDetail bool `protobuf:"varint,7,opt,name=is_detail,json=isDetail,proto3" json:"is_detail,omitempty"`
}

func (x *GetIpReq) Reset() {
	*x = GetIpReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ipproxy_v1_ip_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetIpReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetIpReq) ProtoMessage() {}

func (x *GetIpReq) ProtoReflect() protoreflect.Message {
	mi := &file_ipproxy_v1_ip_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetIpReq.ProtoReflect.Descriptor instead.
func (*GetIpReq) Descriptor() ([]byte, []int) {
	return file_ipproxy_v1_ip_proto_rawDescGZIP(), []int{0}
}

func (x *GetIpReq) GetAppKey() string {
	if x != nil {
		return x.AppKey
	}
	return ""
}

func (x *GetIpReq) GetOrderNo() string {
	if x != nil {
		return x.OrderNo
	}
	return ""
}

func (x *GetIpReq) GetServiceType() string {
	if x != nil {
		return x.ServiceType
	}
	return ""
}

func (x *GetIpReq) GetValidTime() int64 {
	if x != nil {
		return x.ValidTime
	}
	return 0
}

func (x *GetIpReq) GetExtractNumber() int64 {
	if x != nil {
		return x.ExtractNumber
	}
	return 0
}

func (x *GetIpReq) GetExtractFormat() string {
	if x != nil {
		return x.ExtractFormat
	}
	return ""
}

func (x *GetIpReq) GetIsDetail() bool {
	if x != nil {
		return x.IsDetail
	}
	return false
}

// ip响应信息
type GetIpResp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 数据
	Data []*v1.IpInfo `protobuf:"bytes,1,rep,name=data,proto3" json:"data,omitempty"`
}

func (x *GetIpResp) Reset() {
	*x = GetIpResp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ipproxy_v1_ip_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetIpResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetIpResp) ProtoMessage() {}

func (x *GetIpResp) ProtoReflect() protoreflect.Message {
	mi := &file_ipproxy_v1_ip_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetIpResp.ProtoReflect.Descriptor instead.
func (*GetIpResp) Descriptor() ([]byte, []int) {
	return file_ipproxy_v1_ip_proto_rawDescGZIP(), []int{1}
}

func (x *GetIpResp) GetData() []*v1.IpInfo {
	if x != nil {
		return x.Data
	}
	return nil
}

// 获取vps的心跳请求
type GetVpsHeartbeatReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// appkey
	AppKey string `protobuf:"bytes,1,opt,name=app_key,json=appKey,proto3" json:"app_key,omitempty"`
}

func (x *GetVpsHeartbeatReq) Reset() {
	*x = GetVpsHeartbeatReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ipproxy_v1_ip_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetVpsHeartbeatReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetVpsHeartbeatReq) ProtoMessage() {}

func (x *GetVpsHeartbeatReq) ProtoReflect() protoreflect.Message {
	mi := &file_ipproxy_v1_ip_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetVpsHeartbeatReq.ProtoReflect.Descriptor instead.
func (*GetVpsHeartbeatReq) Descriptor() ([]byte, []int) {
	return file_ipproxy_v1_ip_proto_rawDescGZIP(), []int{2}
}

func (x *GetVpsHeartbeatReq) GetAppKey() string {
	if x != nil {
		return x.AppKey
	}
	return ""
}

// 获取vps的心跳响应
type GetVpsHeartbeatResp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 数据
	Data []*v1.VpsHeartbeat `protobuf:"bytes,1,rep,name=data,proto3" json:"data,omitempty"`
}

func (x *GetVpsHeartbeatResp) Reset() {
	*x = GetVpsHeartbeatResp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ipproxy_v1_ip_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetVpsHeartbeatResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetVpsHeartbeatResp) ProtoMessage() {}

func (x *GetVpsHeartbeatResp) ProtoReflect() protoreflect.Message {
	mi := &file_ipproxy_v1_ip_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetVpsHeartbeatResp.ProtoReflect.Descriptor instead.
func (*GetVpsHeartbeatResp) Descriptor() ([]byte, []int) {
	return file_ipproxy_v1_ip_proto_rawDescGZIP(), []int{3}
}

func (x *GetVpsHeartbeatResp) GetData() []*v1.VpsHeartbeat {
	if x != nil {
		return x.Data
	}
	return nil
}

var File_ipproxy_v1_ip_proto protoreflect.FileDescriptor

var file_ipproxy_v1_ip_proto_rawDesc = []byte{
	0x0a, 0x13, 0x69, 0x70, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x76, 0x31, 0x2f, 0x69, 0x70, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0a, 0x69, 0x70, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76,
	0x31, 0x1a, 0x13, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x69, 0x6d, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x76, 0x31,
	0x2f, 0x69, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61,
	0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xf5, 0x01, 0x0a, 0x08, 0x47, 0x65, 0x74, 0x49, 0x70, 0x52,
	0x65, 0x71, 0x12, 0x1c, 0x0a, 0x07, 0x61, 0x70, 0x70, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x06, 0x61, 0x70, 0x70, 0x4b, 0x65, 0x79,
	0x12, 0x1e, 0x0a, 0x08, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x5f, 0x6e, 0x6f, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x07, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x4e, 0x6f,
	0x12, 0x21, 0x0a, 0x0c, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x54, 0x69,
	0x6d, 0x65, 0x12, 0x25, 0x0a, 0x0e, 0x65, 0x78, 0x74, 0x72, 0x61, 0x63, 0x74, 0x5f, 0x6e, 0x75,
	0x6d, 0x62, 0x65, 0x72, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0d, 0x65, 0x78, 0x74, 0x72,
	0x61, 0x63, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x25, 0x0a, 0x0e, 0x65, 0x78, 0x74,
	0x72, 0x61, 0x63, 0x74, 0x5f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0d, 0x65, 0x78, 0x74, 0x72, 0x61, 0x63, 0x74, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74,
	0x12, 0x1b, 0x0a, 0x09, 0x69, 0x73, 0x5f, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x18, 0x07, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x08, 0x69, 0x73, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x22, 0x31, 0x0a,
	0x09, 0x47, 0x65, 0x74, 0x49, 0x70, 0x52, 0x65, 0x73, 0x70, 0x12, 0x24, 0x0a, 0x04, 0x64, 0x61,
	0x74, 0x61, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79,
	0x2e, 0x76, 0x31, 0x2e, 0x49, 0x70, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61,
	0x22, 0x32, 0x0a, 0x12, 0x47, 0x65, 0x74, 0x56, 0x70, 0x73, 0x48, 0x65, 0x61, 0x72, 0x74, 0x62,
	0x65, 0x61, 0x74, 0x52, 0x65, 0x71, 0x12, 0x1c, 0x0a, 0x07, 0x61, 0x70, 0x70, 0x5f, 0x6b, 0x65,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x06, 0x61, 0x70,
	0x70, 0x4b, 0x65, 0x79, 0x22, 0x41, 0x0a, 0x13, 0x47, 0x65, 0x74, 0x56, 0x70, 0x73, 0x48, 0x65,
	0x61, 0x72, 0x74, 0x62, 0x65, 0x61, 0x74, 0x52, 0x65, 0x73, 0x70, 0x12, 0x2a, 0x0a, 0x04, 0x64,
	0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x70, 0x72, 0x6f, 0x78,
	0x79, 0x2e, 0x76, 0x31, 0x2e, 0x56, 0x70, 0x73, 0x48, 0x65, 0x61, 0x72, 0x74, 0x62, 0x65, 0x61,
	0x74, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x32, 0xd0, 0x01, 0x0a, 0x0e, 0x49, 0x70, 0x50, 0x72,
	0x6f, 0x78, 0x79, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x4a, 0x0a, 0x05, 0x47, 0x65,
	0x74, 0x49, 0x70, 0x12, 0x14, 0x2e, 0x69, 0x70, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31,
	0x2e, 0x47, 0x65, 0x74, 0x49, 0x70, 0x52, 0x65, 0x71, 0x1a, 0x15, 0x2e, 0x69, 0x70, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x49, 0x70, 0x52, 0x65, 0x73, 0x70,
	0x22, 0x14, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x0e, 0x62, 0x01, 0x2a, 0x12, 0x09, 0x2f, 0x76, 0x31,
	0x2f, 0x67, 0x65, 0x74, 0x69, 0x70, 0x12, 0x72, 0x0a, 0x0f, 0x47, 0x65, 0x74, 0x56, 0x70, 0x73,
	0x48, 0x65, 0x61, 0x72, 0x74, 0x62, 0x65, 0x61, 0x74, 0x12, 0x1e, 0x2e, 0x69, 0x70, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x56, 0x70, 0x73, 0x48, 0x65, 0x61,
	0x72, 0x74, 0x62, 0x65, 0x61, 0x74, 0x52, 0x65, 0x71, 0x1a, 0x1f, 0x2e, 0x69, 0x70, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x56, 0x70, 0x73, 0x48, 0x65, 0x61,
	0x72, 0x74, 0x62, 0x65, 0x61, 0x74, 0x52, 0x65, 0x73, 0x70, 0x22, 0x1e, 0x82, 0xd3, 0xe4, 0x93,
	0x02, 0x18, 0x62, 0x01, 0x2a, 0x12, 0x13, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x65, 0x74, 0x76, 0x70,
	0x73, 0x68, 0x65, 0x61, 0x72, 0x74, 0x62, 0x65, 0x61, 0x74, 0x42, 0x9d, 0x01, 0x0a, 0x0e, 0x63,
	0x6f, 0x6d, 0x2e, 0x69, 0x70, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x42, 0x07, 0x49,
	0x70, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x48, 0x02, 0x5a, 0x36, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x6f, 0x2d, 0x67, 0x6f, 0x73, 0x74, 0x2f, 0x78, 0x2f, 0x67,
	0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x69, 0x70, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2f, 0x76, 0x31, 0x3b, 0x69, 0x70, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x76, 0x31,
	0xf8, 0x01, 0x00, 0xa2, 0x02, 0x03, 0x49, 0x58, 0x58, 0xaa, 0x02, 0x0a, 0x49, 0x70, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2e, 0x56, 0x31, 0xca, 0x02, 0x0a, 0x49, 0x70, 0x70, 0x72, 0x6f, 0x78, 0x79,
	0x5c, 0x56, 0x31, 0xe2, 0x02, 0x16, 0x49, 0x70, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x5c, 0x56, 0x31,
	0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x0b, 0x49,
	0x70, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x3a, 0x3a, 0x56, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_ipproxy_v1_ip_proto_rawDescOnce sync.Once
	file_ipproxy_v1_ip_proto_rawDescData = file_ipproxy_v1_ip_proto_rawDesc
)

func file_ipproxy_v1_ip_proto_rawDescGZIP() []byte {
	file_ipproxy_v1_ip_proto_rawDescOnce.Do(func() {
		file_ipproxy_v1_ip_proto_rawDescData = protoimpl.X.CompressGZIP(file_ipproxy_v1_ip_proto_rawDescData)
	})
	return file_ipproxy_v1_ip_proto_rawDescData
}

var file_ipproxy_v1_ip_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_ipproxy_v1_ip_proto_goTypes = []interface{}{
	(*GetIpReq)(nil),            // 0: ipproxy.v1.GetIpReq
	(*GetIpResp)(nil),           // 1: ipproxy.v1.GetIpResp
	(*GetVpsHeartbeatReq)(nil),  // 2: ipproxy.v1.GetVpsHeartbeatReq
	(*GetVpsHeartbeatResp)(nil), // 3: ipproxy.v1.GetVpsHeartbeatResp
	(*v1.IpInfo)(nil),           // 4: proxy.v1.IpInfo
	(*v1.VpsHeartbeat)(nil),     // 5: proxy.v1.VpsHeartbeat
}
var file_ipproxy_v1_ip_proto_depIdxs = []int32{
	4, // 0: ipproxy.v1.GetIpResp.data:type_name -> proxy.v1.IpInfo
	5, // 1: ipproxy.v1.GetVpsHeartbeatResp.data:type_name -> proxy.v1.VpsHeartbeat
	0, // 2: ipproxy.v1.IpProxyService.GetIp:input_type -> ipproxy.v1.GetIpReq
	2, // 3: ipproxy.v1.IpProxyService.GetVpsHeartbeat:input_type -> ipproxy.v1.GetVpsHeartbeatReq
	1, // 4: ipproxy.v1.IpProxyService.GetIp:output_type -> ipproxy.v1.GetIpResp
	3, // 5: ipproxy.v1.IpProxyService.GetVpsHeartbeat:output_type -> ipproxy.v1.GetVpsHeartbeatResp
	4, // [4:6] is the sub-list for method output_type
	2, // [2:4] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_ipproxy_v1_ip_proto_init() }
func file_ipproxy_v1_ip_proto_init() {
	if File_ipproxy_v1_ip_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ipproxy_v1_ip_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetIpReq); i {
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
		file_ipproxy_v1_ip_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetIpResp); i {
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
		file_ipproxy_v1_ip_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetVpsHeartbeatReq); i {
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
		file_ipproxy_v1_ip_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetVpsHeartbeatResp); i {
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
			RawDescriptor: file_ipproxy_v1_ip_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_ipproxy_v1_ip_proto_goTypes,
		DependencyIndexes: file_ipproxy_v1_ip_proto_depIdxs,
		MessageInfos:      file_ipproxy_v1_ip_proto_msgTypes,
	}.Build()
	File_ipproxy_v1_ip_proto = out.File
	file_ipproxy_v1_ip_proto_rawDesc = nil
	file_ipproxy_v1_ip_proto_goTypes = nil
	file_ipproxy_v1_ip_proto_depIdxs = nil
}

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: proxy/v1/ip.proto

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

type ServicePort struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 服务
	Service string `protobuf:"bytes,1,opt,name=service,proto3" json:"service,omitempty"`
	// 端口
	Port string `protobuf:"bytes,2,opt,name=port,proto3" json:"port,omitempty"`
}

func (x *ServicePort) Reset() {
	*x = ServicePort{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_v1_ip_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ServicePort) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ServicePort) ProtoMessage() {}

func (x *ServicePort) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_v1_ip_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ServicePort.ProtoReflect.Descriptor instead.
func (*ServicePort) Descriptor() ([]byte, []int) {
	return file_proxy_v1_ip_proto_rawDescGZIP(), []int{0}
}

func (x *ServicePort) GetService() string {
	if x != nil {
		return x.Service
	}
	return ""
}

func (x *ServicePort) GetPort() string {
	if x != nil {
		return x.Port
	}
	return ""
}

// ip上报请求
type IpInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ip信息 例：http://127.0.0.1:30001,socks5://127.0.0.1:30002
	Ip string `protobuf:"bytes,1,opt,name=ip,proto3" json:"ip,omitempty"`
	// 生成时间
	GenTime int64 `protobuf:"varint,3,opt,name=gen_time,json=genTime,proto3" json:"gen_time,omitempty"`
	// 过期时间
	ExpireTime int64 `protobuf:"varint,4,opt,name=expire_time,json=expireTime,proto3" json:"expire_time,omitempty"`
}

func (x *IpInfo) Reset() {
	*x = IpInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_v1_ip_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IpInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IpInfo) ProtoMessage() {}

func (x *IpInfo) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_v1_ip_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IpInfo.ProtoReflect.Descriptor instead.
func (*IpInfo) Descriptor() ([]byte, []int) {
	return file_proxy_v1_ip_proto_rawDescGZIP(), []int{1}
}

func (x *IpInfo) GetIp() string {
	if x != nil {
		return x.Ip
	}
	return ""
}

func (x *IpInfo) GetGenTime() int64 {
	if x != nil {
		return x.GenTime
	}
	return 0
}

func (x *IpInfo) GetExpireTime() int64 {
	if x != nil {
		return x.ExpireTime
	}
	return 0
}

var File_proxy_v1_ip_proto protoreflect.FileDescriptor

var file_proxy_v1_ip_proto_rawDesc = []byte{
	0x0a, 0x11, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x76, 0x31, 0x2f, 0x69, 0x70, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x08, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x22, 0x3b, 0x0a,
	0x0b, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x18, 0x0a, 0x07,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x22, 0x54, 0x0a, 0x06, 0x49, 0x70,
	0x49, 0x6e, 0x66, 0x6f, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x02, 0x69, 0x70, 0x12, 0x19, 0x0a, 0x08, 0x67, 0x65, 0x6e, 0x5f, 0x74, 0x69, 0x6d, 0x65,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x67, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x12,
	0x1f, 0x0a, 0x0b, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x0a, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x54, 0x69, 0x6d, 0x65,
	0x42, 0x8f, 0x01, 0x0a, 0x0c, 0x63, 0x6f, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76,
	0x31, 0x42, 0x07, 0x49, 0x70, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x48, 0x02, 0x5a, 0x32, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x6f, 0x2d, 0x67, 0x6f, 0x73, 0x74,
	0x2f, 0x78, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f,
	0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x76, 0x31, 0x3b, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x76, 0x31,
	0xf8, 0x01, 0x00, 0xa2, 0x02, 0x03, 0x50, 0x58, 0x58, 0xaa, 0x02, 0x08, 0x50, 0x72, 0x6f, 0x78,
	0x79, 0x2e, 0x56, 0x31, 0xca, 0x02, 0x08, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x5c, 0x56, 0x31, 0xe2,
	0x02, 0x14, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x09, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x3a, 0x3a,
	0x56, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proxy_v1_ip_proto_rawDescOnce sync.Once
	file_proxy_v1_ip_proto_rawDescData = file_proxy_v1_ip_proto_rawDesc
)

func file_proxy_v1_ip_proto_rawDescGZIP() []byte {
	file_proxy_v1_ip_proto_rawDescOnce.Do(func() {
		file_proxy_v1_ip_proto_rawDescData = protoimpl.X.CompressGZIP(file_proxy_v1_ip_proto_rawDescData)
	})
	return file_proxy_v1_ip_proto_rawDescData
}

var file_proxy_v1_ip_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_proxy_v1_ip_proto_goTypes = []interface{}{
	(*ServicePort)(nil), // 0: proxy.v1.ServicePort
	(*IpInfo)(nil),      // 1: proxy.v1.IpInfo
}
var file_proxy_v1_ip_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_proxy_v1_ip_proto_init() }
func file_proxy_v1_ip_proto_init() {
	if File_proxy_v1_ip_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proxy_v1_ip_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ServicePort); i {
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
		file_proxy_v1_ip_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IpInfo); i {
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
			RawDescriptor: file_proxy_v1_ip_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proxy_v1_ip_proto_goTypes,
		DependencyIndexes: file_proxy_v1_ip_proto_depIdxs,
		MessageInfos:      file_proxy_v1_ip_proto_msgTypes,
	}.Build()
	File_proxy_v1_ip_proto = out.File
	file_proxy_v1_ip_proto_rawDesc = nil
	file_proxy_v1_ip_proto_goTypes = nil
	file_proxy_v1_ip_proto_depIdxs = nil
}

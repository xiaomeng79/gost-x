// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: proxy/v1/client.proto

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
type ProxyType int32

const (
	// 保留
	ProxyType_PROXY_TYPE_DEFAULT ProxyType = 0
	// 标准代理
	ProxyType_PROXY_TYPE_STANDARD ProxyType = 1
	// 隧道代理
	ProxyType_PROXY_TYPE_TUNNEL ProxyType = 2
)

// Enum value maps for ProxyType.
var (
	ProxyType_name = map[int32]string{
		0: "PROXY_TYPE_DEFAULT",
		1: "PROXY_TYPE_STANDARD",
		2: "PROXY_TYPE_TUNNEL",
	}
	ProxyType_value = map[string]int32{
		"PROXY_TYPE_DEFAULT":  0,
		"PROXY_TYPE_STANDARD": 1,
		"PROXY_TYPE_TUNNEL":   2,
	}
)

func (x ProxyType) Enum() *ProxyType {
	p := new(ProxyType)
	*p = x
	return p
}

func (x ProxyType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ProxyType) Descriptor() protoreflect.EnumDescriptor {
	return file_proxy_v1_client_proto_enumTypes[0].Descriptor()
}

func (ProxyType) Type() protoreflect.EnumType {
	return &file_proxy_v1_client_proto_enumTypes[0]
}

func (x ProxyType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ProxyType.Descriptor instead.
func (ProxyType) EnumDescriptor() ([]byte, []int) {
	return file_proxy_v1_client_proto_rawDescGZIP(), []int{0}
}

// 系统类型
type SystemType int32

const (
	// 未知
	SystemType_SYSTEM_TYPE_DEFAULT SystemType = 0
	// linux
	SystemType_SYSTEM_TYPE_LINUX SystemType = 1
	// windows
	SystemType_SYSTEM_TYPE_WINDOWS SystemType = 2
	// darwin
	SystemType_SYSTEM_TYPE_DARWIN SystemType = 3
)

// Enum value maps for SystemType.
var (
	SystemType_name = map[int32]string{
		0: "SYSTEM_TYPE_DEFAULT",
		1: "SYSTEM_TYPE_LINUX",
		2: "SYSTEM_TYPE_WINDOWS",
		3: "SYSTEM_TYPE_DARWIN",
	}
	SystemType_value = map[string]int32{
		"SYSTEM_TYPE_DEFAULT": 0,
		"SYSTEM_TYPE_LINUX":   1,
		"SYSTEM_TYPE_WINDOWS": 2,
		"SYSTEM_TYPE_DARWIN":  3,
	}
)

func (x SystemType) Enum() *SystemType {
	p := new(SystemType)
	*p = x
	return p
}

func (x SystemType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SystemType) Descriptor() protoreflect.EnumDescriptor {
	return file_proxy_v1_client_proto_enumTypes[1].Descriptor()
}

func (SystemType) Type() protoreflect.EnumType {
	return &file_proxy_v1_client_proto_enumTypes[1]
}

func (x SystemType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SystemType.Descriptor instead.
func (SystemType) EnumDescriptor() ([]byte, []int) {
	return file_proxy_v1_client_proto_rawDescGZIP(), []int{1}
}

// 客户端
type Client struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ID
	Id int64 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	// 代理类型
	// @gotags: db:"proxy_type"
	ProxyType ProxyType `protobuf:"varint,3,opt,name=proxy_type,json=proxyType,proto3,enum=proxy.v1.ProxyType" json:"proxy_type,omitempty" db:"proxy_type"`
	// 系统类型
	// @gotags: db:"sys_type"
	SysType SystemType `protobuf:"varint,4,opt,name=sys_type,json=sysType,proto3,enum=proxy.v1.SystemType" json:"sys_type,omitempty" db:"sys_type"`
	// 版本号
	// @gotags: db:"version"
	Version string `protobuf:"bytes,5,opt,name=version,proto3" json:"version,omitempty" db:"version"`
	// 下载链接
	// @gotags: db:"download_url"
	DownloadUrl string `protobuf:"bytes,6,opt,name=download_url,json=downloadUrl,proto3" json:"download_url,omitempty" db:"download_url"`
	// 指纹
	// @gotags: db:"fingerprint"
	Fingerprint string `protobuf:"bytes,7,opt,name=fingerprint,proto3" json:"fingerprint,omitempty" db:"fingerprint"`
}

func (x *Client) Reset() {
	*x = Client{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_v1_client_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Client) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Client) ProtoMessage() {}

func (x *Client) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_v1_client_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Client.ProtoReflect.Descriptor instead.
func (*Client) Descriptor() ([]byte, []int) {
	return file_proxy_v1_client_proto_rawDescGZIP(), []int{0}
}

func (x *Client) GetId() int64 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *Client) GetProxyType() ProxyType {
	if x != nil {
		return x.ProxyType
	}
	return ProxyType_PROXY_TYPE_DEFAULT
}

func (x *Client) GetSysType() SystemType {
	if x != nil {
		return x.SysType
	}
	return SystemType_SYSTEM_TYPE_DEFAULT
}

func (x *Client) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *Client) GetDownloadUrl() string {
	if x != nil {
		return x.DownloadUrl
	}
	return ""
}

func (x *Client) GetFingerprint() string {
	if x != nil {
		return x.Fingerprint
	}
	return ""
}

// 客户端信息请求
type ClientReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 系统类型
	SysType SystemType `protobuf:"varint,1,opt,name=sys_type,json=sysType,proto3,enum=proxy.v1.SystemType" json:"sys_type,omitempty"`
	// 版本号
	Version string `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *ClientReq) Reset() {
	*x = ClientReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proxy_v1_client_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientReq) ProtoMessage() {}

func (x *ClientReq) ProtoReflect() protoreflect.Message {
	mi := &file_proxy_v1_client_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientReq.ProtoReflect.Descriptor instead.
func (*ClientReq) Descriptor() ([]byte, []int) {
	return file_proxy_v1_client_proto_rawDescGZIP(), []int{1}
}

func (x *ClientReq) GetSysType() SystemType {
	if x != nil {
		return x.SysType
	}
	return SystemType_SYSTEM_TYPE_DEFAULT
}

func (x *ClientReq) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

var File_proxy_v1_client_proto protoreflect.FileDescriptor

var file_proxy_v1_client_proto_rawDesc = []byte{
	0x0a, 0x15, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x08, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76,
	0x31, 0x22, 0xdc, 0x01, 0x0a, 0x06, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x12, 0x0e, 0x0a, 0x02,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x02, 0x69, 0x64, 0x12, 0x32, 0x0a, 0x0a,
	0x70, 0x72, 0x6f, 0x78, 0x79, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x13, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x6f, 0x78,
	0x79, 0x54, 0x79, 0x70, 0x65, 0x52, 0x09, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x54, 0x79, 0x70, 0x65,
	0x12, 0x2f, 0x0a, 0x08, 0x73, 0x79, 0x73, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x14, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x79,
	0x73, 0x74, 0x65, 0x6d, 0x54, 0x79, 0x70, 0x65, 0x52, 0x07, 0x73, 0x79, 0x73, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x21, 0x0a, 0x0c, 0x64,
	0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x5f, 0x75, 0x72, 0x6c, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0b, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x55, 0x72, 0x6c, 0x12, 0x20,
	0x0a, 0x0b, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x18, 0x07, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0b, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74,
	0x22, 0x56, 0x0a, 0x09, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x12, 0x2f, 0x0a,
	0x08, 0x73, 0x79, 0x73, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x14, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x79, 0x73, 0x74, 0x65,
	0x6d, 0x54, 0x79, 0x70, 0x65, 0x52, 0x07, 0x73, 0x79, 0x73, 0x54, 0x79, 0x70, 0x65, 0x12, 0x18,
	0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x2a, 0x53, 0x0a, 0x09, 0x50, 0x72, 0x6f, 0x78,
	0x79, 0x54, 0x79, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x12, 0x50, 0x52, 0x4f, 0x58, 0x59, 0x5f, 0x54,
	0x59, 0x50, 0x45, 0x5f, 0x44, 0x45, 0x46, 0x41, 0x55, 0x4c, 0x54, 0x10, 0x00, 0x12, 0x17, 0x0a,
	0x13, 0x50, 0x52, 0x4f, 0x58, 0x59, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x53, 0x54, 0x41, 0x4e,
	0x44, 0x41, 0x52, 0x44, 0x10, 0x01, 0x12, 0x15, 0x0a, 0x11, 0x50, 0x52, 0x4f, 0x58, 0x59, 0x5f,
	0x54, 0x59, 0x50, 0x45, 0x5f, 0x54, 0x55, 0x4e, 0x4e, 0x45, 0x4c, 0x10, 0x02, 0x2a, 0x6d, 0x0a,
	0x0a, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x54, 0x79, 0x70, 0x65, 0x12, 0x17, 0x0a, 0x13, 0x53,
	0x59, 0x53, 0x54, 0x45, 0x4d, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x44, 0x45, 0x46, 0x41, 0x55,
	0x4c, 0x54, 0x10, 0x00, 0x12, 0x15, 0x0a, 0x11, 0x53, 0x59, 0x53, 0x54, 0x45, 0x4d, 0x5f, 0x54,
	0x59, 0x50, 0x45, 0x5f, 0x4c, 0x49, 0x4e, 0x55, 0x58, 0x10, 0x01, 0x12, 0x17, 0x0a, 0x13, 0x53,
	0x59, 0x53, 0x54, 0x45, 0x4d, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x57, 0x49, 0x4e, 0x44, 0x4f,
	0x57, 0x53, 0x10, 0x02, 0x12, 0x16, 0x0a, 0x12, 0x53, 0x59, 0x53, 0x54, 0x45, 0x4d, 0x5f, 0x54,
	0x59, 0x50, 0x45, 0x5f, 0x44, 0x41, 0x52, 0x57, 0x49, 0x4e, 0x10, 0x03, 0x42, 0x93, 0x01, 0x0a,
	0x0c, 0x63, 0x6f, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x31, 0x42, 0x0b, 0x43,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x48, 0x02, 0x5a, 0x32, 0x67, 0x69,
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
	file_proxy_v1_client_proto_rawDescOnce sync.Once
	file_proxy_v1_client_proto_rawDescData = file_proxy_v1_client_proto_rawDesc
)

func file_proxy_v1_client_proto_rawDescGZIP() []byte {
	file_proxy_v1_client_proto_rawDescOnce.Do(func() {
		file_proxy_v1_client_proto_rawDescData = protoimpl.X.CompressGZIP(file_proxy_v1_client_proto_rawDescData)
	})
	return file_proxy_v1_client_proto_rawDescData
}

var file_proxy_v1_client_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_proxy_v1_client_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_proxy_v1_client_proto_goTypes = []interface{}{
	(ProxyType)(0),    // 0: proxy.v1.ProxyType
	(SystemType)(0),   // 1: proxy.v1.SystemType
	(*Client)(nil),    // 2: proxy.v1.Client
	(*ClientReq)(nil), // 3: proxy.v1.ClientReq
}
var file_proxy_v1_client_proto_depIdxs = []int32{
	0, // 0: proxy.v1.Client.proxy_type:type_name -> proxy.v1.ProxyType
	1, // 1: proxy.v1.Client.sys_type:type_name -> proxy.v1.SystemType
	1, // 2: proxy.v1.ClientReq.sys_type:type_name -> proxy.v1.SystemType
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_proxy_v1_client_proto_init() }
func file_proxy_v1_client_proto_init() {
	if File_proxy_v1_client_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proxy_v1_client_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Client); i {
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
		file_proxy_v1_client_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientReq); i {
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
			RawDescriptor: file_proxy_v1_client_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proxy_v1_client_proto_goTypes,
		DependencyIndexes: file_proxy_v1_client_proto_depIdxs,
		EnumInfos:         file_proxy_v1_client_proto_enumTypes,
		MessageInfos:      file_proxy_v1_client_proto_msgTypes,
	}.Build()
	File_proxy_v1_client_proto = out.File
	file_proxy_v1_client_proto_rawDesc = nil
	file_proxy_v1_client_proto_goTypes = nil
	file_proxy_v1_client_proto_depIdxs = nil
}

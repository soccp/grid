// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google.golang.org/appengine/internal/mail/mail_service.proto

/*
Package mail is a generated protocol buffer package.

It is generated from these files:
	google.golang.org/appengine/internal/mail/mail_service.proto

It has these top-level messages:
	MailServiceError
	MailAttachment
	MailHeader
	MailMessage
*/
package mail

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type MailServiceError_ErrorCode int32

const (
	MailServiceError_OK                      MailServiceError_ErrorCode = 0
	MailServiceError_INTERNAL_ERROR          MailServiceError_ErrorCode = 1
	MailServiceError_BAD_REQUEST             MailServiceError_ErrorCode = 2
	MailServiceError_UNAUTHORIZED_SENDER     MailServiceError_ErrorCode = 3
	MailServiceError_INVALID_ATTACHMENT_TYPE MailServiceError_ErrorCode = 4
	MailServiceError_INVALID_HEADER_NAME     MailServiceError_ErrorCode = 5
	MailServiceError_INVALID_CONTENT_ID      MailServiceError_ErrorCode = 6
)

var MailServiceError_ErrorCode_name = map[int32]string{
	0: "OK",
	1: "INTERNAL_ERROR",
	2: "BAD_REQUEST",
	3: "UNAUTHORIZED_SENDER",
	4: "INVALID_ATTACHMENT_TYPE",
	5: "INVALID_HEADER_NAME",
	6: "INVALID_CONTENT_ID",
}
var MailServiceError_ErrorCode_value = map[string]int32{
	"OK":                      0,
	"INTERNAL_ERROR":          1,
	"BAD_REQUEST":             2,
	"UNAUTHORIZED_SENDER":     3,
	"INVALID_ATTACHMENT_TYPE": 4,
	"INVALID_HEADER_NAME":     5,
	"INVALID_CONTENT_ID":      6,
}

func (x MailServiceError_ErrorCode) Enum() *MailServiceError_ErrorCode {
	p := new(MailServiceError_ErrorCode)
	*p = x
	return p
}
func (x MailServiceError_ErrorCode) String() string {
	return proto.EnumName(MailServiceError_ErrorCode_name, int32(x))
}
func (x *MailServiceError_ErrorCode) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(MailServiceError_ErrorCode_value, data, "MailServiceError_ErrorCode")
	if err != nil {
		return err
	}
	*x = MailServiceError_ErrorCode(value)
	return nil
}
func (MailServiceError_ErrorCode) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor0, []int{0, 0}
}

type MailServiceError struct {
	XXX_unrecognized []byte `json:"-"`
}

func (m *MailServiceError) Reset()                    { *m = MailServiceError{} }
func (m *MailServiceError) String() string            { return proto.CompactTextString(m) }
func (*MailServiceError) ProtoMessage()               {}
func (*MailServiceError) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type MailAttachment struct {
	FileName         *string `protobuf:"bytes,1,req,name=FileName" json:"FileName,omitempty"`
	Data             []byte  `protobuf:"bytes,2,req,name=Data" json:"Data,omitempty"`
	ContentID        *string `protobuf:"bytes,3,opt,name=ContentID" json:"ContentID,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *MailAttachment) Reset()                    { *m = MailAttachment{} }
func (m *MailAttachment) String() string            { return proto.CompactTextString(m) }
func (*MailAttachment) ProtoMessage()               {}
func (*MailAttachment) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *MailAttachment) GetFileName() string {
	if m != nil && m.FileName != nil {
		return *m.FileName
	}
	return ""
}

func (m *MailAttachment) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *MailAttachment) GetContentID() string {
	if m != nil && m.ContentID != nil {
		return *m.ContentID
	}
	return ""
}

type MailHeader struct {
	Name             *string `protobuf:"bytes,1,req,name=name" json:"name,omitempty"`
	Value            *string `protobuf:"bytes,2,req,name=value" json:"value,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *MailHeader) Reset()                    { *m = MailHeader{} }
func (m *MailHeader) String() string            { return proto.CompactTextString(m) }
func (*MailHeader) ProtoMessage()               {}
func (*MailHeader) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *MailHeader) GetName() string {
	if m != nil && m.Name != nil {
		return *m.Name
	}
	return ""
}

func (m *MailHeader) GetValue() string {
	if m != nil && m.Value != nil {
		return *m.Value
	}
	return ""
}

type MailMessage struct {
	Sender           *string           `protobuf:"bytes,1,req,name=Sender" json:"Sender,omitempty"`
	ReplyTo          *string           `protobuf:"bytes,2,opt,name=ReplyTo" json:"ReplyTo,omitempty"`
	To               []string          `protobuf:"bytes,3,rep,name=To" json:"To,omitempty"`
	Cc               []string          `protobuf:"bytes,4,rep,name=Cc" json:"Cc,omitempty"`
	Bcc              []string          `protobuf:"bytes,5,rep,name=Bcc" json:"Bcc,omitempty"`
	Subject          *string           `protobuf:"bytes,6,req,name=Subject" json:"Subject,omitempty"`
	TextBody         *string           `protobuf:"bytes,7,opt,name=TextBody" json:"TextBody,omitempty"`
	HtmlBody         *string           `protobuf:"bytes,8,opt,name=HtmlBody" json:"HtmlBody,omitempty"`
	Attachment       []*MailAttachment `protobuf:"bytes,9,rep,name=Attachment" json:"Attachment,omitempty"`
	Header           []*MailHeader     `protobuf:"bytes,10,rep,name=Header" json:"Header,omitempty"`
	XXX_unrecognized []byte            `json:"-"`
}

func (m *MailMessage) Reset()                    { *m = MailMessage{} }
func (m *MailMessage) String() string            { return proto.CompactTextString(m) }
func (*MailMessage) ProtoMessage()               {}
func (*MailMessage) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *MailMessage) GetSender() string {
	if m != nil && m.Sender != nil {
		return *m.Sender
	}
	return ""
}

func (m *MailMessage) GetReplyTo() string {
	if m != nil && m.ReplyTo != nil {
		return *m.ReplyTo
	}
	return ""
}

func (m *MailMessage) GetTo() []string {
	if m != nil {
		return m.To
	}
	return nil
}

func (m *MailMessage) GetCc() []string {
	if m != nil {
		return m.Cc
	}
	return nil
}

func (m *MailMessage) GetBcc() []string {
	if m != nil {
		return m.Bcc
	}
	return nil
}

func (m *MailMessage) GetSubject() string {
	if m != nil && m.Subject != nil {
		return *m.Subject
	}
	return ""
}

func (m *MailMessage) GetTextBody() string {
	if m != nil && m.TextBody != nil {
		return *m.TextBody
	}
	return ""
}

func (m *MailMessage) GetHtmlBody() string {
	if m != nil && m.HtmlBody != nil {
		return *m.HtmlBody
	}
	return ""
}

func (m *MailMessage) GetAttachment() []*MailAttachment {
	if m != nil {
		return m.Attachment
	}
	return nil
}

func (m *MailMessage) GetHeader() []*MailHeader {
	if m != nil {
		return m.Header
	}
	return nil
}

func init() {
	proto.RegisterType((*MailServiceError)(nil), "appengine.MailServiceError")
	proto.RegisterType((*MailAttachment)(nil), "appengine.MailAttachment")
	proto.RegisterType((*MailHeader)(nil), "appengine.MailHeader")
	proto.RegisterType((*MailMessage)(nil), "appengine.MailMessage")
}

func init() {
	proto.RegisterFile("google.golang.org/appengine/internal/mail/mail_service.proto", fileDescriptor0)
}

var fileDescriptor0 = []byte{
	// 480 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x5c, 0x92, 0xcf, 0x6e, 0xd3, 0x40,
	0x10, 0xc6, 0x89, 0x9d, 0xb8, 0xf5, 0x04, 0x05, 0x6b, 0x81, 0x76, 0xf9, 0x73, 0x88, 0x72, 0xca,
	0x85, 0x44, 0xe2, 0x80, 0x84, 0xc4, 0xc5, 0xb1, 0x17, 0xc5, 0xa2, 0x71, 0x60, 0xb3, 0x41, 0xa2,
	0x07, 0xac, 0xc5, 0x19, 0x19, 0x23, 0xc7, 0x1b, 0x39, 0xdb, 0x8a, 0x3e, 0x0d, 0x4f, 0xc0, 0x8d,
	0x07, 0x44, 0x6b, 0xc7, 0x09, 0xf4, 0x62, 0xcd, 0x6f, 0xbf, 0xf9, 0x66, 0xac, 0x4f, 0x03, 0xef,
	0x32, 0xa5, 0xb2, 0x02, 0x27, 0x99, 0x2a, 0x64, 0x99, 0x4d, 0x54, 0x95, 0x4d, 0xe5, 0x6e, 0x87,
	0x65, 0x96, 0x97, 0x38, 0xcd, 0x4b, 0x8d, 0x55, 0x29, 0x8b, 0xe9, 0x56, 0xe6, 0xcd, 0x27, 0xd9,
	0x63, 0x75, 0x9b, 0xa7, 0x38, 0xd9, 0x55, 0x4a, 0x2b, 0xe2, 0x1e, 0x7b, 0x47, 0x7f, 0x3a, 0xe0,
	0x2d, 0x64, 0x5e, 0xac, 0x9a, 0x06, 0x56, 0x55, 0xaa, 0x1a, 0xfd, 0xea, 0x80, 0x5b, 0x57, 0x81,
	0xda, 0x20, 0x71, 0xc0, 0x5a, 0x7e, 0xf0, 0x1e, 0x10, 0x02, 0x83, 0x28, 0x16, 0x8c, 0xc7, 0xfe,
	0x55, 0xc2, 0x38, 0x5f, 0x72, 0xaf, 0x43, 0x1e, 0x41, 0x7f, 0xe6, 0x87, 0x09, 0x67, 0x9f, 0xd6,
	0x6c, 0x25, 0x3c, 0x8b, 0x5c, 0xc2, 0xe3, 0x75, 0xec, 0xaf, 0xc5, 0x7c, 0xc9, 0xa3, 0x6b, 0x16,
	0x26, 0x2b, 0x16, 0x87, 0x8c, 0x7b, 0x36, 0x79, 0x01, 0x97, 0x51, 0xfc, 0xd9, 0xbf, 0x8a, 0xc2,
	0xc4, 0x17, 0xc2, 0x0f, 0xe6, 0x0b, 0x16, 0x8b, 0x44, 0x7c, 0xf9, 0xc8, 0xbc, 0xae, 0x71, 0xb5,
	0xe2, 0x9c, 0xf9, 0x21, 0xe3, 0x49, 0xec, 0x2f, 0x98, 0xd7, 0x23, 0x17, 0x40, 0x5a, 0x21, 0x58,
	0xc6, 0xc2, 0x58, 0xa2, 0xd0, 0x73, 0x46, 0x5f, 0x61, 0x60, 0xfe, 0xda, 0xd7, 0x5a, 0xa6, 0xdf,
	0xb7, 0x58, 0x6a, 0xf2, 0x1c, 0xce, 0xdf, 0xe7, 0x05, 0xc6, 0x72, 0x8b, 0xb4, 0x33, 0xb4, 0xc6,
	0x2e, 0x3f, 0x32, 0x21, 0xd0, 0x0d, 0xa5, 0x96, 0xd4, 0x1a, 0x5a, 0xe3, 0x87, 0xbc, 0xae, 0xc9,
	0x4b, 0x70, 0x03, 0x55, 0x6a, 0x2c, 0x75, 0x14, 0x52, 0x7b, 0xd8, 0x19, 0xbb, 0xfc, 0xf4, 0x30,
	0x7a, 0x03, 0x60, 0xe6, 0xcf, 0x51, 0x6e, 0xb0, 0x32, 0xfe, 0xf2, 0x34, 0xb7, 0xae, 0xc9, 0x13,
	0xe8, 0xdd, 0xca, 0xe2, 0x06, 0xeb, 0xa1, 0x2e, 0x6f, 0x60, 0xf4, 0xdb, 0x82, 0xbe, 0x31, 0x2e,
	0x70, 0xbf, 0x97, 0x19, 0x92, 0x0b, 0x70, 0x56, 0x58, 0x6e, 0xb0, 0x3a, 0x78, 0x0f, 0x44, 0x28,
	0x9c, 0x71, 0xdc, 0x15, 0x77, 0x42, 0x51, 0xab, 0xde, 0xdd, 0x22, 0x19, 0x80, 0x25, 0x14, 0xb5,
	0x87, 0xf6, 0xd8, 0xe5, 0x56, 0xc3, 0x41, 0x4a, 0xbb, 0x0d, 0x07, 0x29, 0xf1, 0xc0, 0x9e, 0xa5,
	0x29, 0xed, 0xd5, 0x0f, 0xa6, 0x34, 0xb3, 0x56, 0x37, 0xdf, 0x7e, 0x60, 0xaa, 0xa9, 0x53, 0x2f,
	0x69, 0xd1, 0x64, 0x22, 0xf0, 0xa7, 0x9e, 0xa9, 0xcd, 0x1d, 0x3d, 0xab, 0xd7, 0x1c, 0xd9, 0x68,
	0x73, 0xbd, 0x2d, 0x6a, 0xed, 0xbc, 0xd1, 0x5a, 0x26, 0x6f, 0x01, 0x4e, 0xc9, 0x52, 0x77, 0x68,
	0x8f, 0xfb, 0xaf, 0x9f, 0x4d, 0x8e, 0x47, 0x33, 0xf9, 0x3f, 0x7a, 0xfe, 0x4f, 0x33, 0x79, 0x05,
	0x4e, 0x13, 0x1a, 0x85, 0xda, 0xf6, 0xf4, 0x9e, 0xad, 0x11, 0xf9, 0xa1, 0x69, 0xe6, 0x5c, 0x77,
	0xcd, 0x7d, 0xfe, 0x0d, 0x00, 0x00, 0xff, 0xff, 0x4e, 0xd3, 0x01, 0x27, 0xd0, 0x02, 0x00, 0x00,
}

// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/devtools/sourcerepo/v1/sourcerepo.proto

/*
Package sourcerepo is a generated protocol buffer package.

It is generated from these files:
	google/devtools/sourcerepo/v1/sourcerepo.proto

It has these top-level messages:
	Repo
	MirrorConfig
	GetRepoRequest
	ListReposRequest
	ListReposResponse
	CreateRepoRequest
	DeleteRepoRequest
*/
package sourcerepo

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "google.golang.org/genproto/googleapis/api/annotations"
import _ "google.golang.org/genproto/googleapis/api/serviceconfig"
import google_iam_v11 "google.golang.org/genproto/googleapis/iam/v1"
import google_iam_v1 "google.golang.org/genproto/googleapis/iam/v1"
import google_protobuf1 "github.com/golang/protobuf/ptypes/empty"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// A repository (or repo) is a Git repository storing versioned source content.
type Repo struct {
	// Resource name of the repository, of the form
	// `projects/<project>/repos/<repo>`.
	Name string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	// The disk usage of the repo, in bytes.
	// Only returned by GetRepo.
	Size int64 `protobuf:"varint,2,opt,name=size" json:"size,omitempty"`
	// URL to clone the repository from Google Cloud Source Repositories.
	Url string `protobuf:"bytes,3,opt,name=url" json:"url,omitempty"`
	// How this repository mirrors a repository managed by another service.
	MirrorConfig *MirrorConfig `protobuf:"bytes,4,opt,name=mirror_config,json=mirrorConfig" json:"mirror_config,omitempty"`
}

func (m *Repo) Reset()                    { *m = Repo{} }
func (m *Repo) String() string            { return proto.CompactTextString(m) }
func (*Repo) ProtoMessage()               {}
func (*Repo) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Repo) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Repo) GetSize() int64 {
	if m != nil {
		return m.Size
	}
	return 0
}

func (m *Repo) GetUrl() string {
	if m != nil {
		return m.Url
	}
	return ""
}

func (m *Repo) GetMirrorConfig() *MirrorConfig {
	if m != nil {
		return m.MirrorConfig
	}
	return nil
}

// Configuration to automatically mirror a repository from another
// hosting service, for example GitHub or BitBucket.
type MirrorConfig struct {
	// URL of the main repository at the other hosting service.
	Url string `protobuf:"bytes,1,opt,name=url" json:"url,omitempty"`
	// ID of the webhook listening to updates to trigger mirroring.
	// Removing this webook from the other hosting service will stop
	// Google Cloud Source Repositories from receiving notifications,
	// and thereby disabling mirroring.
	WebhookId string `protobuf:"bytes,2,opt,name=webhook_id,json=webhookId" json:"webhook_id,omitempty"`
	// ID of the SSH deploy key at the other hosting service.
	// Removing this key from the other service would deauthorize
	// Google Cloud Source Repositories from mirroring.
	DeployKeyId string `protobuf:"bytes,3,opt,name=deploy_key_id,json=deployKeyId" json:"deploy_key_id,omitempty"`
}

func (m *MirrorConfig) Reset()                    { *m = MirrorConfig{} }
func (m *MirrorConfig) String() string            { return proto.CompactTextString(m) }
func (*MirrorConfig) ProtoMessage()               {}
func (*MirrorConfig) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *MirrorConfig) GetUrl() string {
	if m != nil {
		return m.Url
	}
	return ""
}

func (m *MirrorConfig) GetWebhookId() string {
	if m != nil {
		return m.WebhookId
	}
	return ""
}

func (m *MirrorConfig) GetDeployKeyId() string {
	if m != nil {
		return m.DeployKeyId
	}
	return ""
}

// Request for GetRepo.
type GetRepoRequest struct {
	// The name of the requested repository. Values are of the form
	// `projects/<project>/repos/<repo>`.
	Name string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
}

func (m *GetRepoRequest) Reset()                    { *m = GetRepoRequest{} }
func (m *GetRepoRequest) String() string            { return proto.CompactTextString(m) }
func (*GetRepoRequest) ProtoMessage()               {}
func (*GetRepoRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *GetRepoRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

// Request for ListRepos.
type ListReposRequest struct {
	// The project ID whose repos should be listed. Values are of the form
	// `projects/<project>`.
	Name string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	// Maximum number of repositories to return; between 1 and 500.
	// If not set or zero, defaults to 100 at the server.
	PageSize int32 `protobuf:"varint,2,opt,name=page_size,json=pageSize" json:"page_size,omitempty"`
	// Resume listing repositories where a prior ListReposResponse
	// left off. This is an opaque token that must be obtained from
	// a recent, prior ListReposResponse's next_page_token field.
	PageToken string `protobuf:"bytes,3,opt,name=page_token,json=pageToken" json:"page_token,omitempty"`
}

func (m *ListReposRequest) Reset()                    { *m = ListReposRequest{} }
func (m *ListReposRequest) String() string            { return proto.CompactTextString(m) }
func (*ListReposRequest) ProtoMessage()               {}
func (*ListReposRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *ListReposRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *ListReposRequest) GetPageSize() int32 {
	if m != nil {
		return m.PageSize
	}
	return 0
}

func (m *ListReposRequest) GetPageToken() string {
	if m != nil {
		return m.PageToken
	}
	return ""
}

// Response for ListRepos.  The size is not set in the returned repositories.
type ListReposResponse struct {
	// The listed repos.
	Repos []*Repo `protobuf:"bytes,1,rep,name=repos" json:"repos,omitempty"`
	// If non-empty, additional repositories exist within the project. These
	// can be retrieved by including this value in the next ListReposRequest's
	// page_token field.
	NextPageToken string `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken" json:"next_page_token,omitempty"`
}

func (m *ListReposResponse) Reset()                    { *m = ListReposResponse{} }
func (m *ListReposResponse) String() string            { return proto.CompactTextString(m) }
func (*ListReposResponse) ProtoMessage()               {}
func (*ListReposResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *ListReposResponse) GetRepos() []*Repo {
	if m != nil {
		return m.Repos
	}
	return nil
}

func (m *ListReposResponse) GetNextPageToken() string {
	if m != nil {
		return m.NextPageToken
	}
	return ""
}

// Request for CreateRepo
type CreateRepoRequest struct {
	// The project in which to create the repo. Values are of the form
	// `projects/<project>`.
	Parent string `protobuf:"bytes,1,opt,name=parent" json:"parent,omitempty"`
	// The repo to create.  Only name should be set; setting other fields
	// is an error.  The project in the name should match the parent field.
	Repo *Repo `protobuf:"bytes,2,opt,name=repo" json:"repo,omitempty"`
}

func (m *CreateRepoRequest) Reset()                    { *m = CreateRepoRequest{} }
func (m *CreateRepoRequest) String() string            { return proto.CompactTextString(m) }
func (*CreateRepoRequest) ProtoMessage()               {}
func (*CreateRepoRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *CreateRepoRequest) GetParent() string {
	if m != nil {
		return m.Parent
	}
	return ""
}

func (m *CreateRepoRequest) GetRepo() *Repo {
	if m != nil {
		return m.Repo
	}
	return nil
}

// Request for DeleteRepo.
type DeleteRepoRequest struct {
	// The name of the repo to delete. Values are of the form
	// `projects/<project>/repos/<repo>`.
	Name string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
}

func (m *DeleteRepoRequest) Reset()                    { *m = DeleteRepoRequest{} }
func (m *DeleteRepoRequest) String() string            { return proto.CompactTextString(m) }
func (*DeleteRepoRequest) ProtoMessage()               {}
func (*DeleteRepoRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *DeleteRepoRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func init() {
	proto.RegisterType((*Repo)(nil), "google.devtools.sourcerepo.v1.Repo")
	proto.RegisterType((*MirrorConfig)(nil), "google.devtools.sourcerepo.v1.MirrorConfig")
	proto.RegisterType((*GetRepoRequest)(nil), "google.devtools.sourcerepo.v1.GetRepoRequest")
	proto.RegisterType((*ListReposRequest)(nil), "google.devtools.sourcerepo.v1.ListReposRequest")
	proto.RegisterType((*ListReposResponse)(nil), "google.devtools.sourcerepo.v1.ListReposResponse")
	proto.RegisterType((*CreateRepoRequest)(nil), "google.devtools.sourcerepo.v1.CreateRepoRequest")
	proto.RegisterType((*DeleteRepoRequest)(nil), "google.devtools.sourcerepo.v1.DeleteRepoRequest")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for SourceRepo service

type SourceRepoClient interface {
	// Returns all repos belonging to a project. The sizes of the repos are
	// not set by ListRepos.  To get the size of a repo, use GetRepo.
	ListRepos(ctx context.Context, in *ListReposRequest, opts ...grpc.CallOption) (*ListReposResponse, error)
	// Returns information about a repo.
	GetRepo(ctx context.Context, in *GetRepoRequest, opts ...grpc.CallOption) (*Repo, error)
	// Creates a repo in the given project with the given name.
	//
	// If the named repository already exists, `CreateRepo` returns
	// `ALREADY_EXISTS`.
	CreateRepo(ctx context.Context, in *CreateRepoRequest, opts ...grpc.CallOption) (*Repo, error)
	// Deletes a repo.
	DeleteRepo(ctx context.Context, in *DeleteRepoRequest, opts ...grpc.CallOption) (*google_protobuf1.Empty, error)
	// Sets the access control policy on the specified resource. Replaces any
	// existing policy.
	SetIamPolicy(ctx context.Context, in *google_iam_v11.SetIamPolicyRequest, opts ...grpc.CallOption) (*google_iam_v1.Policy, error)
	// Gets the access control policy for a resource.
	// Returns an empty policy if the resource exists and does not have a policy
	// set.
	GetIamPolicy(ctx context.Context, in *google_iam_v11.GetIamPolicyRequest, opts ...grpc.CallOption) (*google_iam_v1.Policy, error)
	// Returns permissions that a caller has on the specified resource.
	// If the resource does not exist, this will return an empty set of
	// permissions, not a NOT_FOUND error.
	TestIamPermissions(ctx context.Context, in *google_iam_v11.TestIamPermissionsRequest, opts ...grpc.CallOption) (*google_iam_v11.TestIamPermissionsResponse, error)
}

type sourceRepoClient struct {
	cc *grpc.ClientConn
}

func NewSourceRepoClient(cc *grpc.ClientConn) SourceRepoClient {
	return &sourceRepoClient{cc}
}

func (c *sourceRepoClient) ListRepos(ctx context.Context, in *ListReposRequest, opts ...grpc.CallOption) (*ListReposResponse, error) {
	out := new(ListReposResponse)
	err := grpc.Invoke(ctx, "/google.devtools.sourcerepo.v1.SourceRepo/ListRepos", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sourceRepoClient) GetRepo(ctx context.Context, in *GetRepoRequest, opts ...grpc.CallOption) (*Repo, error) {
	out := new(Repo)
	err := grpc.Invoke(ctx, "/google.devtools.sourcerepo.v1.SourceRepo/GetRepo", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sourceRepoClient) CreateRepo(ctx context.Context, in *CreateRepoRequest, opts ...grpc.CallOption) (*Repo, error) {
	out := new(Repo)
	err := grpc.Invoke(ctx, "/google.devtools.sourcerepo.v1.SourceRepo/CreateRepo", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sourceRepoClient) DeleteRepo(ctx context.Context, in *DeleteRepoRequest, opts ...grpc.CallOption) (*google_protobuf1.Empty, error) {
	out := new(google_protobuf1.Empty)
	err := grpc.Invoke(ctx, "/google.devtools.sourcerepo.v1.SourceRepo/DeleteRepo", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sourceRepoClient) SetIamPolicy(ctx context.Context, in *google_iam_v11.SetIamPolicyRequest, opts ...grpc.CallOption) (*google_iam_v1.Policy, error) {
	out := new(google_iam_v1.Policy)
	err := grpc.Invoke(ctx, "/google.devtools.sourcerepo.v1.SourceRepo/SetIamPolicy", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sourceRepoClient) GetIamPolicy(ctx context.Context, in *google_iam_v11.GetIamPolicyRequest, opts ...grpc.CallOption) (*google_iam_v1.Policy, error) {
	out := new(google_iam_v1.Policy)
	err := grpc.Invoke(ctx, "/google.devtools.sourcerepo.v1.SourceRepo/GetIamPolicy", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sourceRepoClient) TestIamPermissions(ctx context.Context, in *google_iam_v11.TestIamPermissionsRequest, opts ...grpc.CallOption) (*google_iam_v11.TestIamPermissionsResponse, error) {
	out := new(google_iam_v11.TestIamPermissionsResponse)
	err := grpc.Invoke(ctx, "/google.devtools.sourcerepo.v1.SourceRepo/TestIamPermissions", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for SourceRepo service

type SourceRepoServer interface {
	// Returns all repos belonging to a project. The sizes of the repos are
	// not set by ListRepos.  To get the size of a repo, use GetRepo.
	ListRepos(context.Context, *ListReposRequest) (*ListReposResponse, error)
	// Returns information about a repo.
	GetRepo(context.Context, *GetRepoRequest) (*Repo, error)
	// Creates a repo in the given project with the given name.
	//
	// If the named repository already exists, `CreateRepo` returns
	// `ALREADY_EXISTS`.
	CreateRepo(context.Context, *CreateRepoRequest) (*Repo, error)
	// Deletes a repo.
	DeleteRepo(context.Context, *DeleteRepoRequest) (*google_protobuf1.Empty, error)
	// Sets the access control policy on the specified resource. Replaces any
	// existing policy.
	SetIamPolicy(context.Context, *google_iam_v11.SetIamPolicyRequest) (*google_iam_v1.Policy, error)
	// Gets the access control policy for a resource.
	// Returns an empty policy if the resource exists and does not have a policy
	// set.
	GetIamPolicy(context.Context, *google_iam_v11.GetIamPolicyRequest) (*google_iam_v1.Policy, error)
	// Returns permissions that a caller has on the specified resource.
	// If the resource does not exist, this will return an empty set of
	// permissions, not a NOT_FOUND error.
	TestIamPermissions(context.Context, *google_iam_v11.TestIamPermissionsRequest) (*google_iam_v11.TestIamPermissionsResponse, error)
}

func RegisterSourceRepoServer(s *grpc.Server, srv SourceRepoServer) {
	s.RegisterService(&_SourceRepo_serviceDesc, srv)
}

func _SourceRepo_ListRepos_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListReposRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SourceRepoServer).ListRepos(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.devtools.sourcerepo.v1.SourceRepo/ListRepos",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SourceRepoServer).ListRepos(ctx, req.(*ListReposRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SourceRepo_GetRepo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetRepoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SourceRepoServer).GetRepo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.devtools.sourcerepo.v1.SourceRepo/GetRepo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SourceRepoServer).GetRepo(ctx, req.(*GetRepoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SourceRepo_CreateRepo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateRepoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SourceRepoServer).CreateRepo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.devtools.sourcerepo.v1.SourceRepo/CreateRepo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SourceRepoServer).CreateRepo(ctx, req.(*CreateRepoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SourceRepo_DeleteRepo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteRepoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SourceRepoServer).DeleteRepo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.devtools.sourcerepo.v1.SourceRepo/DeleteRepo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SourceRepoServer).DeleteRepo(ctx, req.(*DeleteRepoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SourceRepo_SetIamPolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(google_iam_v11.SetIamPolicyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SourceRepoServer).SetIamPolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.devtools.sourcerepo.v1.SourceRepo/SetIamPolicy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SourceRepoServer).SetIamPolicy(ctx, req.(*google_iam_v11.SetIamPolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SourceRepo_GetIamPolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(google_iam_v11.GetIamPolicyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SourceRepoServer).GetIamPolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.devtools.sourcerepo.v1.SourceRepo/GetIamPolicy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SourceRepoServer).GetIamPolicy(ctx, req.(*google_iam_v11.GetIamPolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SourceRepo_TestIamPermissions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(google_iam_v11.TestIamPermissionsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SourceRepoServer).TestIamPermissions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/google.devtools.sourcerepo.v1.SourceRepo/TestIamPermissions",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SourceRepoServer).TestIamPermissions(ctx, req.(*google_iam_v11.TestIamPermissionsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _SourceRepo_serviceDesc = grpc.ServiceDesc{
	ServiceName: "google.devtools.sourcerepo.v1.SourceRepo",
	HandlerType: (*SourceRepoServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListRepos",
			Handler:    _SourceRepo_ListRepos_Handler,
		},
		{
			MethodName: "GetRepo",
			Handler:    _SourceRepo_GetRepo_Handler,
		},
		{
			MethodName: "CreateRepo",
			Handler:    _SourceRepo_CreateRepo_Handler,
		},
		{
			MethodName: "DeleteRepo",
			Handler:    _SourceRepo_DeleteRepo_Handler,
		},
		{
			MethodName: "SetIamPolicy",
			Handler:    _SourceRepo_SetIamPolicy_Handler,
		},
		{
			MethodName: "GetIamPolicy",
			Handler:    _SourceRepo_GetIamPolicy_Handler,
		},
		{
			MethodName: "TestIamPermissions",
			Handler:    _SourceRepo_TestIamPermissions_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "google/devtools/sourcerepo/v1/sourcerepo.proto",
}

func init() { proto.RegisterFile("google/devtools/sourcerepo/v1/sourcerepo.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 748 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x55, 0xd1, 0x4e, 0x13, 0x4d,
	0x14, 0xce, 0xd0, 0x02, 0x7f, 0x0f, 0xe5, 0x07, 0x26, 0x81, 0x34, 0xc5, 0x92, 0xba, 0x28, 0xd6,
	0x12, 0x77, 0x05, 0x35, 0xc4, 0x1a, 0x13, 0x03, 0x9a, 0x86, 0xa8, 0x49, 0x53, 0xb8, 0xf2, 0xa6,
	0xd9, 0xb6, 0x87, 0x65, 0xa5, 0xbb, 0xb3, 0xee, 0x4c, 0xab, 0xd5, 0xa0, 0x09, 0x09, 0xf7, 0x46,
	0x1e, 0xc3, 0xc7, 0xf1, 0x15, 0x7c, 0x08, 0x2f, 0xcd, 0xcc, 0xee, 0xd2, 0x2d, 0xad, 0xed, 0xde,
	0xcd, 0x9c, 0xf3, 0x9d, 0xf3, 0x7d, 0xf3, 0xcd, 0xd9, 0x59, 0xd0, 0x2d, 0xc6, 0xac, 0x0e, 0x1a,
	0x6d, 0xec, 0x09, 0xc6, 0x3a, 0xdc, 0xe0, 0xac, 0xeb, 0xb7, 0xd0, 0x47, 0x8f, 0x19, 0xbd, 0x9d,
	0xd8, 0x4e, 0xf7, 0x7c, 0x26, 0x18, 0x2d, 0x04, 0x78, 0x3d, 0xc2, 0xeb, 0x31, 0x44, 0x6f, 0x27,
	0x7f, 0x2b, 0x6c, 0x67, 0x7a, 0xb6, 0x61, 0xba, 0x2e, 0x13, 0xa6, 0xb0, 0x99, 0xcb, 0x83, 0xe2,
	0xfc, 0x6a, 0x3c, 0xdb, 0x15, 0xa7, 0x61, 0x78, 0x23, 0x0c, 0xdb, 0xa6, 0x23, 0x39, 0x6d, 0xd3,
	0x69, 0x78, 0xac, 0x63, 0xb7, 0xfa, 0x61, 0x3e, 0x3f, 0x9c, 0x1f, 0xca, 0xad, 0x87, 0x39, 0xb5,
	0x6b, 0x76, 0x4f, 0x0c, 0x74, 0x3c, 0x11, 0x26, 0xb5, 0x1f, 0x04, 0xd2, 0x75, 0xf4, 0x18, 0xa5,
	0x90, 0x76, 0x4d, 0x07, 0x73, 0xa4, 0x48, 0x4a, 0x99, 0xba, 0x5a, 0xcb, 0x18, 0xb7, 0x3f, 0x63,
	0x6e, 0xa6, 0x48, 0x4a, 0xa9, 0xba, 0x5a, 0xd3, 0x65, 0x48, 0x75, 0xfd, 0x4e, 0x2e, 0xa5, 0x60,
	0x72, 0x49, 0x6b, 0xb0, 0xe8, 0xd8, 0xbe, 0xcf, 0xfc, 0x46, 0x8b, 0xb9, 0x27, 0xb6, 0x95, 0x4b,
	0x17, 0x49, 0x69, 0x61, 0x77, 0x5b, 0x9f, 0xe8, 0x83, 0xfe, 0x56, 0xd5, 0x1c, 0xa8, 0x92, 0x7a,
	0xd6, 0x89, 0xed, 0xb4, 0x16, 0x64, 0xe3, 0xd9, 0x88, 0x93, 0x0c, 0x38, 0x0b, 0x00, 0x1f, 0xb1,
	0x79, 0xca, 0xd8, 0x59, 0xc3, 0x6e, 0x2b, 0x7d, 0x99, 0x7a, 0x26, 0x8c, 0x1c, 0xb6, 0xa9, 0x06,
	0x8b, 0x6d, 0xf4, 0x3a, 0xac, 0xdf, 0x38, 0xc3, 0xbe, 0x44, 0x04, 0x72, 0x17, 0x82, 0xe0, 0x6b,
	0xec, 0x1f, 0xb6, 0xb5, 0x3b, 0xf0, 0x7f, 0x15, 0x85, 0x3c, 0x7b, 0x1d, 0x3f, 0x74, 0x91, 0x8b,
	0x71, 0x16, 0x68, 0x4d, 0x58, 0x7e, 0x63, 0x73, 0x05, 0xe3, 0x13, 0x70, 0x74, 0x1d, 0x32, 0x9e,
	0x69, 0x61, 0xe3, 0xda, 0xaf, 0xd9, 0xfa, 0x7f, 0x32, 0x70, 0x24, 0x3d, 0x2b, 0x00, 0xa8, 0xa4,
	0x60, 0x67, 0xe8, 0x86, 0x5a, 0x14, 0xfc, 0x58, 0x06, 0xb4, 0x1e, 0xac, 0xc4, 0x38, 0xb8, 0xc7,
	0x5c, 0x8e, 0xf4, 0x29, 0xcc, 0x4a, 0xa7, 0x78, 0x8e, 0x14, 0x53, 0xa5, 0x85, 0xdd, 0xcd, 0x29,
	0x6e, 0xaa, 0x73, 0x04, 0x15, 0x74, 0x0b, 0x96, 0x5c, 0xfc, 0x24, 0x1a, 0x31, 0xce, 0xc0, 0xa1,
	0x45, 0x19, 0xae, 0x5d, 0xf3, 0xb6, 0x61, 0xe5, 0xc0, 0x47, 0x53, 0x60, 0xdc, 0x84, 0x35, 0x98,
	0xf3, 0x4c, 0x1f, 0x5d, 0x11, 0x1e, 0x2f, 0xdc, 0xd1, 0x3d, 0x48, 0xcb, 0xee, 0xaa, 0x53, 0x42,
	0x39, 0xaa, 0x40, 0xbb, 0x07, 0x2b, 0x2f, 0xb1, 0x83, 0xc3, 0x2c, 0x63, 0x2c, 0xdc, 0xfd, 0x33,
	0x0f, 0x70, 0xa4, 0xba, 0xa8, 0x81, 0xbc, 0x22, 0x90, 0xb9, 0xb6, 0x85, 0x1a, 0x53, 0x08, 0x6f,
	0x5e, 0x52, 0xfe, 0x61, 0xf2, 0x82, 0xc0, 0x71, 0x6d, 0xf3, 0xe2, 0xd7, 0xef, 0xab, 0x99, 0x02,
	0x5d, 0x97, 0x5f, 0xd0, 0x17, 0x29, 0xe9, 0xb9, 0xe7, 0xb3, 0xf7, 0xd8, 0x12, 0xdc, 0x28, 0x9f,
	0x1b, 0x81, 0xb7, 0x97, 0x04, 0xe6, 0xc3, 0xb1, 0xa1, 0x0f, 0xa6, 0x50, 0x0c, 0x8f, 0x57, 0x3e,
	0x89, 0x67, 0xda, 0x96, 0x12, 0x51, 0xa4, 0x1b, 0xe3, 0x44, 0x04, 0x1a, 0x8c, 0x72, 0xf9, 0x9c,
	0x7e, 0x27, 0x00, 0x83, 0xcb, 0xa3, 0xd3, 0x4e, 0x3b, 0x72, 0xcf, 0xc9, 0xd4, 0x6c, 0x2b, 0x35,
	0x77, 0xb5, 0x82, 0x52, 0x13, 0x4c, 0xc2, 0xa8, 0x29, 0x15, 0x75, 0xd1, 0xf4, 0x2b, 0xc0, 0xe0,
	0xa2, 0xa7, 0x2a, 0x1a, 0x99, 0x89, 0xfc, 0x5a, 0x54, 0x11, 0x3d, 0x54, 0xfa, 0x2b, 0xf9, 0x50,
	0x45, 0x96, 0x94, 0xa7, 0x59, 0x72, 0x49, 0x20, 0x7b, 0x84, 0xe2, 0xd0, 0x74, 0x6a, 0xea, 0xf9,
	0xa3, 0x5a, 0xd4, 0xd0, 0x36, 0x1d, 0x49, 0x19, 0x4f, 0x46, 0xa4, 0xab, 0x37, 0x30, 0x41, 0x56,
	0xab, 0x28, 0xce, 0xc7, 0x9a, 0xa1, 0x38, 0x7d, 0x0c, 0xb4, 0x8f, 0xe5, 0xad, 0xf0, 0x58, 0xdb,
	0x0a, 0x29, 0xd3, 0x0b, 0x02, 0xd9, 0xea, 0x24, 0x1d, 0xd5, 0xe4, 0x3a, 0xf6, 0x94, 0x8e, 0x1d,
	0x9a, 0x44, 0x87, 0x15, 0xe7, 0xfc, 0x49, 0x80, 0x1e, 0x23, 0x57, 0x11, 0xf4, 0x1d, 0x9b, 0x73,
	0xf9, 0x93, 0xa1, 0xa5, 0x1b, 0x34, 0xa3, 0x90, 0x48, 0xd0, 0xfd, 0x04, 0xc8, 0xf0, 0xc3, 0x79,
	0xa1, 0x44, 0x56, 0xb4, 0x27, 0x09, 0x44, 0x8a, 0x91, 0x36, 0x15, 0x52, 0xde, 0xff, 0x06, 0xb7,
	0x5b, 0xcc, 0x99, 0x3c, 0x31, 0xfb, 0x4b, 0x83, 0xc7, 0xa1, 0x26, 0x27, 0xa4, 0x46, 0xde, 0x55,
	0xc3, 0x0a, 0x8b, 0x75, 0x4c, 0xd7, 0xd2, 0x99, 0x6f, 0x19, 0x16, 0xba, 0x6a, 0x7e, 0x8c, 0x20,
	0x65, 0x7a, 0x36, 0xff, 0xc7, 0x9f, 0xfb, 0xd9, 0x60, 0xd7, 0x9c, 0x53, 0x35, 0x8f, 0xfe, 0x06,
	0x00, 0x00, 0xff, 0xff, 0x30, 0x80, 0x85, 0x9e, 0xec, 0x07, 0x00, 0x00,
}

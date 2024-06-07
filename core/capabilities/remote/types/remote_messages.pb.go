// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v4.25.1
// source: remote_messages.proto

package types

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

type Error int32

const (
	Error_OK                   Error = 0
	Error_VALIDATION_FAILED    Error = 1
	Error_CAPABILITY_NOT_FOUND Error = 2
	Error_INVALID_REQUEST      Error = 3
	Error_TIMEOUT              Error = 4
	Error_INTERNAL_ERROR       Error = 5
)

// Enum value maps for Error.
var (
	Error_name = map[int32]string{
		0: "OK",
		1: "VALIDATION_FAILED",
		2: "CAPABILITY_NOT_FOUND",
		3: "INVALID_REQUEST",
		4: "TIMEOUT",
		5: "INTERNAL_ERROR",
	}
	Error_value = map[string]int32{
		"OK":                   0,
		"VALIDATION_FAILED":    1,
		"CAPABILITY_NOT_FOUND": 2,
		"INVALID_REQUEST":      3,
		"TIMEOUT":              4,
		"INTERNAL_ERROR":       5,
	}
)

func (x Error) Enum() *Error {
	p := new(Error)
	*p = x
	return p
}

func (x Error) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Error) Descriptor() protoreflect.EnumDescriptor {
	return file_remote_messages_proto_enumTypes[0].Descriptor()
}

func (Error) Type() protoreflect.EnumType {
	return &file_remote_messages_proto_enumTypes[0]
}

func (x Error) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Error.Descriptor instead.
func (Error) EnumDescriptor() ([]byte, []int) {
	return file_remote_messages_proto_rawDescGZIP(), []int{0}
}

type Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Signature []byte `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
	Body      []byte `protobuf:"bytes,2,opt,name=body,proto3" json:"body,omitempty"` // proto-encoded MessageBody to sign
}

func (x *Message) Reset() {
	*x = Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_remote_messages_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message) ProtoMessage() {}

func (x *Message) ProtoReflect() protoreflect.Message {
	mi := &file_remote_messages_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message.ProtoReflect.Descriptor instead.
func (*Message) Descriptor() ([]byte, []int) {
	return file_remote_messages_proto_rawDescGZIP(), []int{0}
}

func (x *Message) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *Message) GetBody() []byte {
	if x != nil {
		return x.Body
	}
	return nil
}

type MessageBody struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version         uint32 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	Sender          []byte `protobuf:"bytes,2,opt,name=sender,proto3" json:"sender,omitempty"`
	Receiver        []byte `protobuf:"bytes,3,opt,name=receiver,proto3" json:"receiver,omitempty"`
	Timestamp       int64  `protobuf:"varint,4,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	MessageId       []byte `protobuf:"bytes,5,opt,name=message_id,json=messageId,proto3" json:"message_id,omitempty"` // scoped to sender
	CapabilityId    string `protobuf:"bytes,6,opt,name=capability_id,json=capabilityId,proto3" json:"capability_id,omitempty"`
	CapabilityDonId string `protobuf:"bytes,7,opt,name=capability_don_id,json=capabilityDonId,proto3" json:"capability_don_id,omitempty"`
	CallerDonId     string `protobuf:"bytes,8,opt,name=caller_don_id,json=callerDonId,proto3" json:"caller_don_id,omitempty"`
	Method          string `protobuf:"bytes,9,opt,name=method,proto3" json:"method,omitempty"`
	Error           Error  `protobuf:"varint,10,opt,name=error,proto3,enum=remote.Error" json:"error,omitempty"`
	ErrorMsg        string `protobuf:"bytes,11,opt,name=errorMsg,proto3" json:"errorMsg,omitempty"`
	// payload contains a CapabilityRequest or CapabilityResponse
	Payload []byte `protobuf:"bytes,12,opt,name=payload,proto3" json:"payload,omitempty"`
	// Types that are assignable to Metadata:
	//
	//	*MessageBody_TriggerRegistrationMetadata
	//	*MessageBody_TriggerEventMetadata
	Metadata isMessageBody_Metadata `protobuf_oneof:"metadata"`
}

func (x *MessageBody) Reset() {
	*x = MessageBody{}
	if protoimpl.UnsafeEnabled {
		mi := &file_remote_messages_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MessageBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MessageBody) ProtoMessage() {}

func (x *MessageBody) ProtoReflect() protoreflect.Message {
	mi := &file_remote_messages_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MessageBody.ProtoReflect.Descriptor instead.
func (*MessageBody) Descriptor() ([]byte, []int) {
	return file_remote_messages_proto_rawDescGZIP(), []int{1}
}

func (x *MessageBody) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *MessageBody) GetSender() []byte {
	if x != nil {
		return x.Sender
	}
	return nil
}

func (x *MessageBody) GetReceiver() []byte {
	if x != nil {
		return x.Receiver
	}
	return nil
}

func (x *MessageBody) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}

func (x *MessageBody) GetMessageId() []byte {
	if x != nil {
		return x.MessageId
	}
	return nil
}

func (x *MessageBody) GetCapabilityId() string {
	if x != nil {
		return x.CapabilityId
	}
	return ""
}

func (x *MessageBody) GetCapabilityDonId() string {
	if x != nil {
		return x.CapabilityDonId
	}
	return ""
}

func (x *MessageBody) GetCallerDonId() string {
	if x != nil {
		return x.CallerDonId
	}
	return ""
}

func (x *MessageBody) GetMethod() string {
	if x != nil {
		return x.Method
	}
	return ""
}

func (x *MessageBody) GetError() Error {
	if x != nil {
		return x.Error
	}
	return Error_OK
}

func (x *MessageBody) GetErrorMsg() string {
	if x != nil {
		return x.ErrorMsg
	}
	return ""
}

func (x *MessageBody) GetPayload() []byte {
	if x != nil {
		return x.Payload
	}
	return nil
}

func (m *MessageBody) GetMetadata() isMessageBody_Metadata {
	if m != nil {
		return m.Metadata
	}
	return nil
}

func (x *MessageBody) GetTriggerRegistrationMetadata() *TriggerRegistrationMetadata {
	if x, ok := x.GetMetadata().(*MessageBody_TriggerRegistrationMetadata); ok {
		return x.TriggerRegistrationMetadata
	}
	return nil
}

func (x *MessageBody) GetTriggerEventMetadata() *TriggerEventMetadata {
	if x, ok := x.GetMetadata().(*MessageBody_TriggerEventMetadata); ok {
		return x.TriggerEventMetadata
	}
	return nil
}

type isMessageBody_Metadata interface {
	isMessageBody_Metadata()
}

type MessageBody_TriggerRegistrationMetadata struct {
	TriggerRegistrationMetadata *TriggerRegistrationMetadata `protobuf:"bytes,13,opt,name=trigger_registration_metadata,json=triggerRegistrationMetadata,proto3,oneof"`
}

type MessageBody_TriggerEventMetadata struct {
	TriggerEventMetadata *TriggerEventMetadata `protobuf:"bytes,14,opt,name=trigger_event_metadata,json=triggerEventMetadata,proto3,oneof"`
}

func (*MessageBody_TriggerRegistrationMetadata) isMessageBody_Metadata() {}

func (*MessageBody_TriggerEventMetadata) isMessageBody_Metadata() {}

type TriggerRegistrationMetadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LastReceivedEventId string `protobuf:"bytes,1,opt,name=last_received_event_id,json=lastReceivedEventId,proto3" json:"last_received_event_id,omitempty"`
}

func (x *TriggerRegistrationMetadata) Reset() {
	*x = TriggerRegistrationMetadata{}
	if protoimpl.UnsafeEnabled {
		mi := &file_remote_messages_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TriggerRegistrationMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TriggerRegistrationMetadata) ProtoMessage() {}

func (x *TriggerRegistrationMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_remote_messages_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TriggerRegistrationMetadata.ProtoReflect.Descriptor instead.
func (*TriggerRegistrationMetadata) Descriptor() ([]byte, []int) {
	return file_remote_messages_proto_rawDescGZIP(), []int{2}
}

func (x *TriggerRegistrationMetadata) GetLastReceivedEventId() string {
	if x != nil {
		return x.LastReceivedEventId
	}
	return ""
}

type TriggerEventMetadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TriggerEventId string   `protobuf:"bytes,1,opt,name=trigger_event_id,json=triggerEventId,proto3" json:"trigger_event_id,omitempty"`
	WorkflowIds    []string `protobuf:"bytes,2,rep,name=workflow_ids,json=workflowIds,proto3" json:"workflow_ids,omitempty"`
}

func (x *TriggerEventMetadata) Reset() {
	*x = TriggerEventMetadata{}
	if protoimpl.UnsafeEnabled {
		mi := &file_remote_messages_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TriggerEventMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TriggerEventMetadata) ProtoMessage() {}

func (x *TriggerEventMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_remote_messages_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TriggerEventMetadata.ProtoReflect.Descriptor instead.
func (*TriggerEventMetadata) Descriptor() ([]byte, []int) {
	return file_remote_messages_proto_rawDescGZIP(), []int{3}
}

func (x *TriggerEventMetadata) GetTriggerEventId() string {
	if x != nil {
		return x.TriggerEventId
	}
	return ""
}

func (x *TriggerEventMetadata) GetWorkflowIds() []string {
	if x != nil {
		return x.WorkflowIds
	}
	return nil
}

type RemoteTriggerConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RegistrationRefreshMs   uint32 `protobuf:"varint,1,opt,name=registrationRefreshMs,proto3" json:"registrationRefreshMs,omitempty"`
	RegistrationExpiryMs    uint32 `protobuf:"varint,2,opt,name=registrationExpiryMs,proto3" json:"registrationExpiryMs,omitempty"`
	MinResponsesToAggregate uint32 `protobuf:"varint,3,opt,name=minResponsesToAggregate,proto3" json:"minResponsesToAggregate,omitempty"`
	MessageExpiryMs         uint32 `protobuf:"varint,4,opt,name=messageExpiryMs,proto3" json:"messageExpiryMs,omitempty"`
}

func (x *RemoteTriggerConfig) Reset() {
	*x = RemoteTriggerConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_remote_messages_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RemoteTriggerConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RemoteTriggerConfig) ProtoMessage() {}

func (x *RemoteTriggerConfig) ProtoReflect() protoreflect.Message {
	mi := &file_remote_messages_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RemoteTriggerConfig.ProtoReflect.Descriptor instead.
func (*RemoteTriggerConfig) Descriptor() ([]byte, []int) {
	return file_remote_messages_proto_rawDescGZIP(), []int{4}
}

func (x *RemoteTriggerConfig) GetRegistrationRefreshMs() uint32 {
	if x != nil {
		return x.RegistrationRefreshMs
	}
	return 0
}

func (x *RemoteTriggerConfig) GetRegistrationExpiryMs() uint32 {
	if x != nil {
		return x.RegistrationExpiryMs
	}
	return 0
}

func (x *RemoteTriggerConfig) GetMinResponsesToAggregate() uint32 {
	if x != nil {
		return x.MinResponsesToAggregate
	}
	return 0
}

func (x *RemoteTriggerConfig) GetMessageExpiryMs() uint32 {
	if x != nil {
		return x.MessageExpiryMs
	}
	return 0
}

var File_remote_messages_proto protoreflect.FileDescriptor

var file_remote_messages_proto_rawDesc = []byte{
	0x0a, 0x15, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x22,
	0x3b, 0x0a, 0x07, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x62, 0x6f, 0x64, 0x79,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x22, 0xcd, 0x04, 0x0a,
	0x0b, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x6f, 0x64, 0x79, 0x12, 0x18, 0x0a, 0x07,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x12, 0x1a,
	0x0a, 0x08, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x08, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x72, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x1d, 0x0a, 0x0a, 0x6d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x6d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x49, 0x64, 0x12, 0x23, 0x0a, 0x0d, 0x63, 0x61, 0x70, 0x61, 0x62,
	0x69, 0x6c, 0x69, 0x74, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c,
	0x63, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x49, 0x64, 0x12, 0x2a, 0x0a, 0x11,
	0x63, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x5f, 0x64, 0x6f, 0x6e, 0x5f, 0x69,
	0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x63, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c,
	0x69, 0x74, 0x79, 0x44, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x22, 0x0a, 0x0d, 0x63, 0x61, 0x6c, 0x6c,
	0x65, 0x72, 0x5f, 0x64, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0b, 0x63, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x44, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x16, 0x0a, 0x06,
	0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6d, 0x65,
	0x74, 0x68, 0x6f, 0x64, 0x12, 0x23, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x0a, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x0d, 0x2e, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x2e, 0x45, 0x72, 0x72,
	0x6f, 0x72, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x1a, 0x0a, 0x08, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x4d, 0x73, 0x67, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x4d, 0x73, 0x67, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
	0x18, 0x0c, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12,
	0x69, 0x0a, 0x1d, 0x74, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x5f, 0x72, 0x65, 0x67, 0x69, 0x73,
	0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
	0x18, 0x0d, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x2e,
	0x54, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x48, 0x00, 0x52, 0x1b, 0x74,
	0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x54, 0x0a, 0x16, 0x74, 0x72,
	0x69, 0x67, 0x67, 0x65, 0x72, 0x5f, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x5f, 0x6d, 0x65, 0x74, 0x61,
	0x64, 0x61, 0x74, 0x61, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x72, 0x65, 0x6d,
	0x6f, 0x74, 0x65, 0x2e, 0x54, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74,
	0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x48, 0x00, 0x52, 0x14, 0x74, 0x72, 0x69, 0x67,
	0x67, 0x65, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
	0x42, 0x0a, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x22, 0x52, 0x0a, 0x1b,
	0x54, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x33, 0x0a, 0x16, 0x6c,
	0x61, 0x73, 0x74, 0x5f, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x64, 0x5f, 0x65, 0x76, 0x65,
	0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x13, 0x6c, 0x61, 0x73,
	0x74, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x64, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x49, 0x64,
	0x22, 0x63, 0x0a, 0x14, 0x54, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74,
	0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x28, 0x0a, 0x10, 0x74, 0x72, 0x69, 0x67,
	0x67, 0x65, 0x72, 0x5f, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0e, 0x74, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x45, 0x76, 0x65, 0x6e, 0x74,
	0x49, 0x64, 0x12, 0x21, 0x0a, 0x0c, 0x77, 0x6f, 0x72, 0x6b, 0x66, 0x6c, 0x6f, 0x77, 0x5f, 0x69,
	0x64, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0b, 0x77, 0x6f, 0x72, 0x6b, 0x66, 0x6c,
	0x6f, 0x77, 0x49, 0x64, 0x73, 0x22, 0xe3, 0x01, 0x0a, 0x13, 0x52, 0x65, 0x6d, 0x6f, 0x74, 0x65,
	0x54, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x34, 0x0a,
	0x15, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x66,
	0x72, 0x65, 0x73, 0x68, 0x4d, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x15, 0x72, 0x65,
	0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73,
	0x68, 0x4d, 0x73, 0x12, 0x32, 0x0a, 0x14, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x45, 0x78, 0x70, 0x69, 0x72, 0x79, 0x4d, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x14, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x45,
	0x78, 0x70, 0x69, 0x72, 0x79, 0x4d, 0x73, 0x12, 0x38, 0x0a, 0x17, 0x6d, 0x69, 0x6e, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x73, 0x54, 0x6f, 0x41, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61,
	0x74, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x17, 0x6d, 0x69, 0x6e, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x73, 0x54, 0x6f, 0x41, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74,
	0x65, 0x12, 0x28, 0x0a, 0x0f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x45, 0x78, 0x70, 0x69,
	0x72, 0x79, 0x4d, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0f, 0x6d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x45, 0x78, 0x70, 0x69, 0x72, 0x79, 0x4d, 0x73, 0x2a, 0x76, 0x0a, 0x05, 0x45,
	0x72, 0x72, 0x6f, 0x72, 0x12, 0x06, 0x0a, 0x02, 0x4f, 0x4b, 0x10, 0x00, 0x12, 0x15, 0x0a, 0x11,
	0x56, 0x41, 0x4c, 0x49, 0x44, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x46, 0x41, 0x49, 0x4c, 0x45,
	0x44, 0x10, 0x01, 0x12, 0x18, 0x0a, 0x14, 0x43, 0x41, 0x50, 0x41, 0x42, 0x49, 0x4c, 0x49, 0x54,
	0x59, 0x5f, 0x4e, 0x4f, 0x54, 0x5f, 0x46, 0x4f, 0x55, 0x4e, 0x44, 0x10, 0x02, 0x12, 0x13, 0x0a,
	0x0f, 0x49, 0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x5f, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54,
	0x10, 0x03, 0x12, 0x0b, 0x0a, 0x07, 0x54, 0x49, 0x4d, 0x45, 0x4f, 0x55, 0x54, 0x10, 0x04, 0x12,
	0x12, 0x0a, 0x0e, 0x49, 0x4e, 0x54, 0x45, 0x52, 0x4e, 0x41, 0x4c, 0x5f, 0x45, 0x52, 0x52, 0x4f,
	0x52, 0x10, 0x05, 0x42, 0x20, 0x5a, 0x1e, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x61, 0x70, 0x61,
	0x62, 0x69, 0x6c, 0x69, 0x74, 0x69, 0x65, 0x73, 0x2f, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x2f,
	0x74, 0x79, 0x70, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_remote_messages_proto_rawDescOnce sync.Once
	file_remote_messages_proto_rawDescData = file_remote_messages_proto_rawDesc
)

func file_remote_messages_proto_rawDescGZIP() []byte {
	file_remote_messages_proto_rawDescOnce.Do(func() {
		file_remote_messages_proto_rawDescData = protoimpl.X.CompressGZIP(file_remote_messages_proto_rawDescData)
	})
	return file_remote_messages_proto_rawDescData
}

var file_remote_messages_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_remote_messages_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_remote_messages_proto_goTypes = []interface{}{
	(Error)(0),                          // 0: remote.Error
	(*Message)(nil),                     // 1: remote.Message
	(*MessageBody)(nil),                 // 2: remote.MessageBody
	(*TriggerRegistrationMetadata)(nil), // 3: remote.TriggerRegistrationMetadata
	(*TriggerEventMetadata)(nil),        // 4: remote.TriggerEventMetadata
	(*RemoteTriggerConfig)(nil),         // 5: remote.RemoteTriggerConfig
}
var file_remote_messages_proto_depIdxs = []int32{
	0, // 0: remote.MessageBody.error:type_name -> remote.Error
	3, // 1: remote.MessageBody.trigger_registration_metadata:type_name -> remote.TriggerRegistrationMetadata
	4, // 2: remote.MessageBody.trigger_event_metadata:type_name -> remote.TriggerEventMetadata
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_remote_messages_proto_init() }
func file_remote_messages_proto_init() {
	if File_remote_messages_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_remote_messages_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Message); i {
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
		file_remote_messages_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MessageBody); i {
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
		file_remote_messages_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TriggerRegistrationMetadata); i {
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
		file_remote_messages_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TriggerEventMetadata); i {
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
		file_remote_messages_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RemoteTriggerConfig); i {
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
	file_remote_messages_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*MessageBody_TriggerRegistrationMetadata)(nil),
		(*MessageBody_TriggerEventMetadata)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_remote_messages_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_remote_messages_proto_goTypes,
		DependencyIndexes: file_remote_messages_proto_depIdxs,
		EnumInfos:         file_remote_messages_proto_enumTypes,
		MessageInfos:      file_remote_messages_proto_msgTypes,
	}.Build()
	File_remote_messages_proto = out.File
	file_remote_messages_proto_rawDesc = nil
	file_remote_messages_proto_goTypes = nil
	file_remote_messages_proto_depIdxs = nil
}

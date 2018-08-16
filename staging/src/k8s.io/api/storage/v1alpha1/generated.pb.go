/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by protoc-gen-gogo.
// source: k8s.io/kubernetes/vendor/k8s.io/api/storage/v1alpha1/generated.proto
// DO NOT EDIT!

/*
	Package v1alpha1 is a generated protocol buffer package.

	It is generated from these files:
		k8s.io/kubernetes/vendor/k8s.io/api/storage/v1alpha1/generated.proto

	It has these top-level messages:
		VolumeAttachment
		VolumeAttachmentList
		VolumeAttachmentSource
		VolumeAttachmentSpec
		VolumeAttachmentStatus
		VolumeError
*/
package v1alpha1

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

import github_com_gogo_protobuf_sortkeys "github.com/gogo/protobuf/sortkeys"

import strings "strings"
import reflect "reflect"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

func (m *VolumeAttachment) Reset()                    { *m = VolumeAttachment{} }
func (*VolumeAttachment) ProtoMessage()               {}
func (*VolumeAttachment) Descriptor() ([]byte, []int) { return fileDescriptorGenerated, []int{0} }

func (m *VolumeAttachmentList) Reset()                    { *m = VolumeAttachmentList{} }
func (*VolumeAttachmentList) ProtoMessage()               {}
func (*VolumeAttachmentList) Descriptor() ([]byte, []int) { return fileDescriptorGenerated, []int{1} }

func (m *VolumeAttachmentSource) Reset()                    { *m = VolumeAttachmentSource{} }
func (*VolumeAttachmentSource) ProtoMessage()               {}
func (*VolumeAttachmentSource) Descriptor() ([]byte, []int) { return fileDescriptorGenerated, []int{2} }

func (m *VolumeAttachmentSpec) Reset()                    { *m = VolumeAttachmentSpec{} }
func (*VolumeAttachmentSpec) ProtoMessage()               {}
func (*VolumeAttachmentSpec) Descriptor() ([]byte, []int) { return fileDescriptorGenerated, []int{3} }

func (m *VolumeAttachmentStatus) Reset()                    { *m = VolumeAttachmentStatus{} }
func (*VolumeAttachmentStatus) ProtoMessage()               {}
func (*VolumeAttachmentStatus) Descriptor() ([]byte, []int) { return fileDescriptorGenerated, []int{4} }

func (m *VolumeError) Reset()                    { *m = VolumeError{} }
func (*VolumeError) ProtoMessage()               {}
func (*VolumeError) Descriptor() ([]byte, []int) { return fileDescriptorGenerated, []int{5} }

func init() {
	proto.RegisterType((*VolumeAttachment)(nil), "k8s.io.api.storage.v1alpha1.VolumeAttachment")
	proto.RegisterType((*VolumeAttachmentList)(nil), "k8s.io.api.storage.v1alpha1.VolumeAttachmentList")
	proto.RegisterType((*VolumeAttachmentSource)(nil), "k8s.io.api.storage.v1alpha1.VolumeAttachmentSource")
	proto.RegisterType((*VolumeAttachmentSpec)(nil), "k8s.io.api.storage.v1alpha1.VolumeAttachmentSpec")
	proto.RegisterType((*VolumeAttachmentStatus)(nil), "k8s.io.api.storage.v1alpha1.VolumeAttachmentStatus")
	proto.RegisterType((*VolumeError)(nil), "k8s.io.api.storage.v1alpha1.VolumeError")
}
func (m *VolumeAttachment) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *VolumeAttachment) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	dAtA[i] = 0xa
	i++
	i = encodeVarintGenerated(dAtA, i, uint64(m.ObjectMeta.Size()))
	n1, err := m.ObjectMeta.MarshalTo(dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n1
	dAtA[i] = 0x12
	i++
	i = encodeVarintGenerated(dAtA, i, uint64(m.Spec.Size()))
	n2, err := m.Spec.MarshalTo(dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n2
	dAtA[i] = 0x1a
	i++
	i = encodeVarintGenerated(dAtA, i, uint64(m.Status.Size()))
	n3, err := m.Status.MarshalTo(dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n3
	return i, nil
}

func (m *VolumeAttachmentList) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *VolumeAttachmentList) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	dAtA[i] = 0xa
	i++
	i = encodeVarintGenerated(dAtA, i, uint64(m.ListMeta.Size()))
	n4, err := m.ListMeta.MarshalTo(dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n4
	if len(m.Items) > 0 {
		for _, msg := range m.Items {
			dAtA[i] = 0x12
			i++
			i = encodeVarintGenerated(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	return i, nil
}

func (m *VolumeAttachmentSource) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *VolumeAttachmentSource) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.PersistentVolumeName != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintGenerated(dAtA, i, uint64(len(*m.PersistentVolumeName)))
		i += copy(dAtA[i:], *m.PersistentVolumeName)
	}
	return i, nil
}

func (m *VolumeAttachmentSpec) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *VolumeAttachmentSpec) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	dAtA[i] = 0xa
	i++
	i = encodeVarintGenerated(dAtA, i, uint64(len(m.Attacher)))
	i += copy(dAtA[i:], m.Attacher)
	dAtA[i] = 0x12
	i++
	i = encodeVarintGenerated(dAtA, i, uint64(m.Source.Size()))
	n5, err := m.Source.MarshalTo(dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n5
	dAtA[i] = 0x1a
	i++
	i = encodeVarintGenerated(dAtA, i, uint64(len(m.NodeName)))
	i += copy(dAtA[i:], m.NodeName)
	return i, nil
}

func (m *VolumeAttachmentStatus) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *VolumeAttachmentStatus) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	dAtA[i] = 0x8
	i++
	if m.Attached {
		dAtA[i] = 1
	} else {
		dAtA[i] = 0
	}
	i++
	if len(m.AttachmentMetadata) > 0 {
		keysForAttachmentMetadata := make([]string, 0, len(m.AttachmentMetadata))
		for k := range m.AttachmentMetadata {
			keysForAttachmentMetadata = append(keysForAttachmentMetadata, string(k))
		}
		github_com_gogo_protobuf_sortkeys.Strings(keysForAttachmentMetadata)
		for _, k := range keysForAttachmentMetadata {
			dAtA[i] = 0x12
			i++
			v := m.AttachmentMetadata[string(k)]
			mapSize := 1 + len(k) + sovGenerated(uint64(len(k))) + 1 + len(v) + sovGenerated(uint64(len(v)))
			i = encodeVarintGenerated(dAtA, i, uint64(mapSize))
			dAtA[i] = 0xa
			i++
			i = encodeVarintGenerated(dAtA, i, uint64(len(k)))
			i += copy(dAtA[i:], k)
			dAtA[i] = 0x12
			i++
			i = encodeVarintGenerated(dAtA, i, uint64(len(v)))
			i += copy(dAtA[i:], v)
		}
	}
	if m.AttachError != nil {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintGenerated(dAtA, i, uint64(m.AttachError.Size()))
		n6, err := m.AttachError.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n6
	}
	if m.DetachError != nil {
		dAtA[i] = 0x22
		i++
		i = encodeVarintGenerated(dAtA, i, uint64(m.DetachError.Size()))
		n7, err := m.DetachError.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n7
	}
	return i, nil
}

func (m *VolumeError) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *VolumeError) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	dAtA[i] = 0xa
	i++
	i = encodeVarintGenerated(dAtA, i, uint64(m.Time.Size()))
	n8, err := m.Time.MarshalTo(dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n8
	dAtA[i] = 0x12
	i++
	i = encodeVarintGenerated(dAtA, i, uint64(len(m.Message)))
	i += copy(dAtA[i:], m.Message)
	return i, nil
}

func encodeFixed64Generated(dAtA []byte, offset int, v uint64) int {
	dAtA[offset] = uint8(v)
	dAtA[offset+1] = uint8(v >> 8)
	dAtA[offset+2] = uint8(v >> 16)
	dAtA[offset+3] = uint8(v >> 24)
	dAtA[offset+4] = uint8(v >> 32)
	dAtA[offset+5] = uint8(v >> 40)
	dAtA[offset+6] = uint8(v >> 48)
	dAtA[offset+7] = uint8(v >> 56)
	return offset + 8
}
func encodeFixed32Generated(dAtA []byte, offset int, v uint32) int {
	dAtA[offset] = uint8(v)
	dAtA[offset+1] = uint8(v >> 8)
	dAtA[offset+2] = uint8(v >> 16)
	dAtA[offset+3] = uint8(v >> 24)
	return offset + 4
}
func encodeVarintGenerated(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *VolumeAttachment) Size() (n int) {
	var l int
	_ = l
	l = m.ObjectMeta.Size()
	n += 1 + l + sovGenerated(uint64(l))
	l = m.Spec.Size()
	n += 1 + l + sovGenerated(uint64(l))
	l = m.Status.Size()
	n += 1 + l + sovGenerated(uint64(l))
	return n
}

func (m *VolumeAttachmentList) Size() (n int) {
	var l int
	_ = l
	l = m.ListMeta.Size()
	n += 1 + l + sovGenerated(uint64(l))
	if len(m.Items) > 0 {
		for _, e := range m.Items {
			l = e.Size()
			n += 1 + l + sovGenerated(uint64(l))
		}
	}
	return n
}

func (m *VolumeAttachmentSource) Size() (n int) {
	var l int
	_ = l
	if m.PersistentVolumeName != nil {
		l = len(*m.PersistentVolumeName)
		n += 1 + l + sovGenerated(uint64(l))
	}
	return n
}

func (m *VolumeAttachmentSpec) Size() (n int) {
	var l int
	_ = l
	l = len(m.Attacher)
	n += 1 + l + sovGenerated(uint64(l))
	l = m.Source.Size()
	n += 1 + l + sovGenerated(uint64(l))
	l = len(m.NodeName)
	n += 1 + l + sovGenerated(uint64(l))
	return n
}

func (m *VolumeAttachmentStatus) Size() (n int) {
	var l int
	_ = l
	n += 2
	if len(m.AttachmentMetadata) > 0 {
		for k, v := range m.AttachmentMetadata {
			_ = k
			_ = v
			mapEntrySize := 1 + len(k) + sovGenerated(uint64(len(k))) + 1 + len(v) + sovGenerated(uint64(len(v)))
			n += mapEntrySize + 1 + sovGenerated(uint64(mapEntrySize))
		}
	}
	if m.AttachError != nil {
		l = m.AttachError.Size()
		n += 1 + l + sovGenerated(uint64(l))
	}
	if m.DetachError != nil {
		l = m.DetachError.Size()
		n += 1 + l + sovGenerated(uint64(l))
	}
	return n
}

func (m *VolumeError) Size() (n int) {
	var l int
	_ = l
	l = m.Time.Size()
	n += 1 + l + sovGenerated(uint64(l))
	l = len(m.Message)
	n += 1 + l + sovGenerated(uint64(l))
	return n
}

func sovGenerated(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozGenerated(x uint64) (n int) {
	return sovGenerated(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *VolumeAttachment) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&VolumeAttachment{`,
		`ObjectMeta:` + strings.Replace(strings.Replace(this.ObjectMeta.String(), "ObjectMeta", "k8s_io_apimachinery_pkg_apis_meta_v1.ObjectMeta", 1), `&`, ``, 1) + `,`,
		`Spec:` + strings.Replace(strings.Replace(this.Spec.String(), "VolumeAttachmentSpec", "VolumeAttachmentSpec", 1), `&`, ``, 1) + `,`,
		`Status:` + strings.Replace(strings.Replace(this.Status.String(), "VolumeAttachmentStatus", "VolumeAttachmentStatus", 1), `&`, ``, 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *VolumeAttachmentList) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&VolumeAttachmentList{`,
		`ListMeta:` + strings.Replace(strings.Replace(this.ListMeta.String(), "ListMeta", "k8s_io_apimachinery_pkg_apis_meta_v1.ListMeta", 1), `&`, ``, 1) + `,`,
		`Items:` + strings.Replace(strings.Replace(fmt.Sprintf("%v", this.Items), "VolumeAttachment", "VolumeAttachment", 1), `&`, ``, 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *VolumeAttachmentSource) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&VolumeAttachmentSource{`,
		`PersistentVolumeName:` + valueToStringGenerated(this.PersistentVolumeName) + `,`,
		`}`,
	}, "")
	return s
}
func (this *VolumeAttachmentSpec) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&VolumeAttachmentSpec{`,
		`Attacher:` + fmt.Sprintf("%v", this.Attacher) + `,`,
		`Source:` + strings.Replace(strings.Replace(this.Source.String(), "VolumeAttachmentSource", "VolumeAttachmentSource", 1), `&`, ``, 1) + `,`,
		`NodeName:` + fmt.Sprintf("%v", this.NodeName) + `,`,
		`}`,
	}, "")
	return s
}
func (this *VolumeAttachmentStatus) String() string {
	if this == nil {
		return "nil"
	}
	keysForAttachmentMetadata := make([]string, 0, len(this.AttachmentMetadata))
	for k := range this.AttachmentMetadata {
		keysForAttachmentMetadata = append(keysForAttachmentMetadata, k)
	}
	github_com_gogo_protobuf_sortkeys.Strings(keysForAttachmentMetadata)
	mapStringForAttachmentMetadata := "map[string]string{"
	for _, k := range keysForAttachmentMetadata {
		mapStringForAttachmentMetadata += fmt.Sprintf("%v: %v,", k, this.AttachmentMetadata[k])
	}
	mapStringForAttachmentMetadata += "}"
	s := strings.Join([]string{`&VolumeAttachmentStatus{`,
		`Attached:` + fmt.Sprintf("%v", this.Attached) + `,`,
		`AttachmentMetadata:` + mapStringForAttachmentMetadata + `,`,
		`AttachError:` + strings.Replace(fmt.Sprintf("%v", this.AttachError), "VolumeError", "VolumeError", 1) + `,`,
		`DetachError:` + strings.Replace(fmt.Sprintf("%v", this.DetachError), "VolumeError", "VolumeError", 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *VolumeError) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&VolumeError{`,
		`Time:` + strings.Replace(strings.Replace(this.Time.String(), "Time", "k8s_io_apimachinery_pkg_apis_meta_v1.Time", 1), `&`, ``, 1) + `,`,
		`Message:` + fmt.Sprintf("%v", this.Message) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringGenerated(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *VolumeAttachment) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: VolumeAttachment: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: VolumeAttachment: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ObjectMeta", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.ObjectMeta.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Spec", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Spec.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Status", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Status.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *VolumeAttachmentList) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: VolumeAttachmentList: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: VolumeAttachmentList: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ListMeta", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.ListMeta.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Items", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Items = append(m.Items, VolumeAttachment{})
			if err := m.Items[len(m.Items)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *VolumeAttachmentSource) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: VolumeAttachmentSource: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: VolumeAttachmentSource: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PersistentVolumeName", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			s := string(dAtA[iNdEx:postIndex])
			m.PersistentVolumeName = &s
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *VolumeAttachmentSpec) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: VolumeAttachmentSpec: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: VolumeAttachmentSpec: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Attacher", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Attacher = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Source", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Source.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field NodeName", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.NodeName = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *VolumeAttachmentStatus) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: VolumeAttachmentStatus: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: VolumeAttachmentStatus: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Attached", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Attached = bool(v != 0)
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AttachmentMetadata", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			var keykey uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				keykey |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			var stringLenmapkey uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLenmapkey |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLenmapkey := int(stringLenmapkey)
			if intStringLenmapkey < 0 {
				return ErrInvalidLengthGenerated
			}
			postStringIndexmapkey := iNdEx + intStringLenmapkey
			if postStringIndexmapkey > l {
				return io.ErrUnexpectedEOF
			}
			mapkey := string(dAtA[iNdEx:postStringIndexmapkey])
			iNdEx = postStringIndexmapkey
			if m.AttachmentMetadata == nil {
				m.AttachmentMetadata = make(map[string]string)
			}
			if iNdEx < postIndex {
				var valuekey uint64
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowGenerated
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					valuekey |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				var stringLenmapvalue uint64
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowGenerated
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					stringLenmapvalue |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				intStringLenmapvalue := int(stringLenmapvalue)
				if intStringLenmapvalue < 0 {
					return ErrInvalidLengthGenerated
				}
				postStringIndexmapvalue := iNdEx + intStringLenmapvalue
				if postStringIndexmapvalue > l {
					return io.ErrUnexpectedEOF
				}
				mapvalue := string(dAtA[iNdEx:postStringIndexmapvalue])
				iNdEx = postStringIndexmapvalue
				m.AttachmentMetadata[mapkey] = mapvalue
			} else {
				var mapvalue string
				m.AttachmentMetadata[mapkey] = mapvalue
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AttachError", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.AttachError == nil {
				m.AttachError = &VolumeError{}
			}
			if err := m.AttachError.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DetachError", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.DetachError == nil {
				m.DetachError = &VolumeError{}
			}
			if err := m.DetachError.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *VolumeError) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: VolumeError: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: VolumeError: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Time", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Time.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Message", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthGenerated
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Message = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGenerated(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthGenerated
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipGenerated(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowGenerated
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowGenerated
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthGenerated
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowGenerated
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipGenerated(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthGenerated = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowGenerated   = fmt.Errorf("proto: integer overflow")
)

func init() {
	proto.RegisterFile("k8s.io/kubernetes/vendor/k8s.io/api/storage/v1alpha1/generated.proto", fileDescriptorGenerated)
}

var fileDescriptorGenerated = []byte{
	// 682 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x94, 0x4d, 0x6f, 0xd3, 0x4c,
	0x10, 0xc7, 0xe3, 0x24, 0x6d, 0xd3, 0xcd, 0xf3, 0x40, 0xb5, 0x8a, 0x20, 0x0a, 0x92, 0x53, 0xe5,
	0x54, 0x10, 0x5d, 0x93, 0xc2, 0xa1, 0xe2, 0x16, 0xab, 0x3d, 0x20, 0xda, 0x82, 0xb6, 0x88, 0x03,
	0x70, 0x60, 0x63, 0x4f, 0x1d, 0x37, 0xf5, 0x8b, 0xbc, 0xeb, 0x48, 0xbd, 0x71, 0xe2, 0xcc, 0x8d,
	0x6f, 0xc0, 0x67, 0xc9, 0x8d, 0x1e, 0x7b, 0x8a, 0xa8, 0xf9, 0x16, 0x5c, 0x40, 0x5e, 0x6f, 0x1c,
	0xd3, 0xa4, 0xa8, 0xed, 0xcd, 0x33, 0xfb, 0x9f, 0xdf, 0xbc, 0xec, 0xac, 0xd1, 0xce, 0x70, 0x9b,
	0x13, 0x37, 0x30, 0x86, 0x71, 0x1f, 0x22, 0x1f, 0x04, 0x70, 0x63, 0x04, 0xbe, 0x1d, 0x44, 0x86,
	0x3a, 0x60, 0xa1, 0x6b, 0x70, 0x11, 0x44, 0xcc, 0x01, 0x63, 0xd4, 0x65, 0x27, 0xe1, 0x80, 0x75,
	0x0d, 0x07, 0x7c, 0x88, 0x98, 0x00, 0x9b, 0x84, 0x51, 0x20, 0x02, 0xfc, 0x20, 0x13, 0x13, 0x16,
	0xba, 0x44, 0x89, 0xc9, 0x54, 0xdc, 0xda, 0x74, 0x5c, 0x31, 0x88, 0xfb, 0xc4, 0x0a, 0x3c, 0xc3,
	0x09, 0x9c, 0xc0, 0x90, 0x31, 0xfd, 0xf8, 0x48, 0x5a, 0xd2, 0x90, 0x5f, 0x19, 0xab, 0xf5, 0x6c,
	0x96, 0xd8, 0x63, 0xd6, 0xc0, 0xf5, 0x21, 0x3a, 0x35, 0xc2, 0xa1, 0x93, 0x3a, 0xb8, 0xe1, 0x81,
	0x60, 0xc6, 0x68, 0xae, 0x82, 0xce, 0xb7, 0x32, 0x5a, 0x7b, 0x1b, 0x9c, 0xc4, 0x1e, 0xf4, 0x84,
	0x60, 0xd6, 0xc0, 0x03, 0x5f, 0xe0, 0x8f, 0xa8, 0x96, 0xea, 0x6d, 0x26, 0x58, 0x53, 0x5b, 0xd7,
	0x36, 0xea, 0x5b, 0x4f, 0xc8, 0xac, 0xd2, 0x9c, 0x4e, 0xc2, 0xa1, 0x93, 0x3a, 0x38, 0x49, 0xd5,
	0x64, 0xd4, 0x25, 0xaf, 0xfa, 0xc7, 0x60, 0x89, 0x7d, 0x10, 0xcc, 0xc4, 0xe3, 0x49, 0xbb, 0x94,
	0x4c, 0xda, 0x68, 0xe6, 0xa3, 0x39, 0x15, 0x1f, 0xa2, 0x2a, 0x0f, 0xc1, 0x6a, 0x96, 0x25, 0xbd,
	0x4b, 0xfe, 0x31, 0x07, 0x72, 0xb9, 0xbc, 0xc3, 0x10, 0x2c, 0xf3, 0x3f, 0x85, 0xaf, 0xa6, 0x16,
	0x95, 0x30, 0xfc, 0x1e, 0x2d, 0x73, 0xc1, 0x44, 0xcc, 0x9b, 0x15, 0x89, 0x7d, 0x7a, 0x33, 0xac,
	0x0c, 0x35, 0xef, 0x28, 0xf0, 0x72, 0x66, 0x53, 0x85, 0xec, 0x8c, 0x35, 0xd4, 0xb8, 0x1c, 0xb2,
	0xe7, 0x72, 0x81, 0x3f, 0xcc, 0x0d, 0x8b, 0x5c, 0x6f, 0x58, 0x69, 0xb4, 0x1c, 0xd5, 0x9a, 0x4a,
	0x59, 0x9b, 0x7a, 0x0a, 0x83, 0xa2, 0x68, 0xc9, 0x15, 0xe0, 0xf1, 0x66, 0x79, 0xbd, 0xb2, 0x51,
	0xdf, 0xda, 0xbc, 0x51, 0x4b, 0xe6, 0xff, 0x8a, 0xbc, 0xf4, 0x22, 0x65, 0xd0, 0x0c, 0xd5, 0x39,
	0x42, 0xf7, 0xe6, 0x9a, 0x0f, 0xe2, 0xc8, 0x02, 0xbc, 0x87, 0x1a, 0x21, 0x44, 0xdc, 0xe5, 0x02,
	0x7c, 0x91, 0x69, 0x0e, 0x98, 0x07, 0xb2, 0xaf, 0x55, 0xb3, 0x99, 0x4c, 0xda, 0x8d, 0xd7, 0x0b,
	0xce, 0xe9, 0xc2, 0xa8, 0xce, 0xf7, 0x05, 0x23, 0x4b, 0xaf, 0x0b, 0x3f, 0x46, 0x35, 0x26, 0x3d,
	0x10, 0x29, 0x74, 0x3e, 0x82, 0x9e, 0xf2, 0xd3, 0x5c, 0x21, 0xaf, 0x55, 0x96, 0xa7, 0xb6, 0xe5,
	0x86, 0xd7, 0x2a, 0x43, 0x0b, 0xd7, 0x2a, 0x6d, 0xaa, 0x90, 0x69, 0x29, 0x7e, 0x60, 0x67, 0x5d,
	0x56, 0xfe, 0x2e, 0xe5, 0x40, 0xf9, 0x69, 0xae, 0xe8, 0xfc, 0xae, 0x2c, 0x18, 0x9d, 0xdc, 0x8f,
	0x42, 0x4f, 0xb6, 0xec, 0xa9, 0x36, 0xd7, 0x93, 0x9d, 0xf7, 0x64, 0xe3, 0xaf, 0x1a, 0xc2, 0x2c,
	0x47, 0xec, 0x4f, 0xf7, 0x27, 0xbb, 0xe4, 0x97, 0xb7, 0xd8, 0x5b, 0xd2, 0x9b, 0xa3, 0xed, 0xfa,
	0x22, 0x3a, 0x35, 0x5b, 0xaa, 0x0a, 0x3c, 0x2f, 0xa0, 0x0b, 0x4a, 0xc0, 0xc7, 0xa8, 0x9e, 0x79,
	0x77, 0xa3, 0x28, 0x88, 0xd4, 0x4b, 0xda, 0xb8, 0x46, 0x45, 0x52, 0x6f, 0xea, 0xc9, 0xa4, 0x5d,
	0xef, 0xcd, 0x00, 0xbf, 0x26, 0xed, 0x7a, 0xe1, 0x9c, 0x16, 0xe1, 0x69, 0x2e, 0x1b, 0x66, 0xb9,
	0xaa, 0xb7, 0xc9, 0xb5, 0x03, 0x57, 0xe7, 0x2a, 0xc0, 0x5b, 0xbb, 0xe8, 0xfe, 0x15, 0x23, 0xc2,
	0x6b, 0xa8, 0x32, 0x84, 0xd3, 0x6c, 0x13, 0x69, 0xfa, 0x89, 0x1b, 0x68, 0x69, 0xc4, 0x4e, 0xe2,
	0x6c, 0xe3, 0x56, 0x69, 0x66, 0x3c, 0x2f, 0x6f, 0x6b, 0x9d, 0xcf, 0x1a, 0x2a, 0xe6, 0xc0, 0x7b,
	0xa8, 0x2a, 0x5c, 0xf5, 0x42, 0xea, 0x5b, 0x8f, 0xae, 0xf7, 0xf2, 0xdf, 0xb8, 0x1e, 0xcc, 0xfe,
	0x60, 0xa9, 0x45, 0x25, 0x05, 0x3f, 0x44, 0x2b, 0x1e, 0x70, 0xce, 0x1c, 0x95, 0xd9, 0xbc, 0xab,
	0x44, 0x2b, 0xfb, 0x99, 0x9b, 0x4e, 0xcf, 0x4d, 0x32, 0xbe, 0xd0, 0x4b, 0x67, 0x17, 0x7a, 0xe9,
	0xfc, 0x42, 0x2f, 0x7d, 0x4a, 0x74, 0x6d, 0x9c, 0xe8, 0xda, 0x59, 0xa2, 0x6b, 0xe7, 0x89, 0xae,
	0xfd, 0x48, 0x74, 0xed, 0xcb, 0x4f, 0xbd, 0xf4, 0xae, 0x36, 0x1d, 0xdc, 0x9f, 0x00, 0x00, 0x00,
	0xff, 0xff, 0x9e, 0x8a, 0x61, 0xf3, 0xb1, 0x06, 0x00, 0x00,
}

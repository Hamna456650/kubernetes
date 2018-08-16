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
// source: k8s.io/kubernetes/vendor/k8s.io/api/admissionregistration/v1alpha1/generated.proto
// DO NOT EDIT!

/*
	Package v1alpha1 is a generated protocol buffer package.

	It is generated from these files:
		k8s.io/kubernetes/vendor/k8s.io/api/admissionregistration/v1alpha1/generated.proto

	It has these top-level messages:
		Initializer
		InitializerConfiguration
		InitializerConfigurationList
		Rule
*/
package v1alpha1

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

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

func (m *Initializer) Reset()                    { *m = Initializer{} }
func (*Initializer) ProtoMessage()               {}
func (*Initializer) Descriptor() ([]byte, []int) { return fileDescriptorGenerated, []int{0} }

func (m *InitializerConfiguration) Reset()      { *m = InitializerConfiguration{} }
func (*InitializerConfiguration) ProtoMessage() {}
func (*InitializerConfiguration) Descriptor() ([]byte, []int) {
	return fileDescriptorGenerated, []int{1}
}

func (m *InitializerConfigurationList) Reset()      { *m = InitializerConfigurationList{} }
func (*InitializerConfigurationList) ProtoMessage() {}
func (*InitializerConfigurationList) Descriptor() ([]byte, []int) {
	return fileDescriptorGenerated, []int{2}
}

func (m *Rule) Reset()                    { *m = Rule{} }
func (*Rule) ProtoMessage()               {}
func (*Rule) Descriptor() ([]byte, []int) { return fileDescriptorGenerated, []int{3} }

func init() {
	proto.RegisterType((*Initializer)(nil), "k8s.io.api.admissionregistration.v1alpha1.Initializer")
	proto.RegisterType((*InitializerConfiguration)(nil), "k8s.io.api.admissionregistration.v1alpha1.InitializerConfiguration")
	proto.RegisterType((*InitializerConfigurationList)(nil), "k8s.io.api.admissionregistration.v1alpha1.InitializerConfigurationList")
	proto.RegisterType((*Rule)(nil), "k8s.io.api.admissionregistration.v1alpha1.Rule")
}
func (m *Initializer) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Initializer) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	dAtA[i] = 0xa
	i++
	i = encodeVarintGenerated(dAtA, i, uint64(len(m.Name)))
	i += copy(dAtA[i:], m.Name)
	if len(m.Rules) > 0 {
		for _, msg := range m.Rules {
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

func (m *InitializerConfiguration) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *InitializerConfiguration) MarshalTo(dAtA []byte) (int, error) {
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
	if len(m.Initializers) > 0 {
		for _, msg := range m.Initializers {
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

func (m *InitializerConfigurationList) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *InitializerConfigurationList) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	dAtA[i] = 0xa
	i++
	i = encodeVarintGenerated(dAtA, i, uint64(m.ListMeta.Size()))
	n2, err := m.ListMeta.MarshalTo(dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n2
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

func (m *Rule) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Rule) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.APIGroups) > 0 {
		for _, s := range m.APIGroups {
			dAtA[i] = 0xa
			i++
			l = len(s)
			for l >= 1<<7 {
				dAtA[i] = uint8(uint64(l)&0x7f | 0x80)
				l >>= 7
				i++
			}
			dAtA[i] = uint8(l)
			i++
			i += copy(dAtA[i:], s)
		}
	}
	if len(m.APIVersions) > 0 {
		for _, s := range m.APIVersions {
			dAtA[i] = 0x12
			i++
			l = len(s)
			for l >= 1<<7 {
				dAtA[i] = uint8(uint64(l)&0x7f | 0x80)
				l >>= 7
				i++
			}
			dAtA[i] = uint8(l)
			i++
			i += copy(dAtA[i:], s)
		}
	}
	if len(m.Resources) > 0 {
		for _, s := range m.Resources {
			dAtA[i] = 0x1a
			i++
			l = len(s)
			for l >= 1<<7 {
				dAtA[i] = uint8(uint64(l)&0x7f | 0x80)
				l >>= 7
				i++
			}
			dAtA[i] = uint8(l)
			i++
			i += copy(dAtA[i:], s)
		}
	}
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
func (m *Initializer) Size() (n int) {
	var l int
	_ = l
	l = len(m.Name)
	n += 1 + l + sovGenerated(uint64(l))
	if len(m.Rules) > 0 {
		for _, e := range m.Rules {
			l = e.Size()
			n += 1 + l + sovGenerated(uint64(l))
		}
	}
	return n
}

func (m *InitializerConfiguration) Size() (n int) {
	var l int
	_ = l
	l = m.ObjectMeta.Size()
	n += 1 + l + sovGenerated(uint64(l))
	if len(m.Initializers) > 0 {
		for _, e := range m.Initializers {
			l = e.Size()
			n += 1 + l + sovGenerated(uint64(l))
		}
	}
	return n
}

func (m *InitializerConfigurationList) Size() (n int) {
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

func (m *Rule) Size() (n int) {
	var l int
	_ = l
	if len(m.APIGroups) > 0 {
		for _, s := range m.APIGroups {
			l = len(s)
			n += 1 + l + sovGenerated(uint64(l))
		}
	}
	if len(m.APIVersions) > 0 {
		for _, s := range m.APIVersions {
			l = len(s)
			n += 1 + l + sovGenerated(uint64(l))
		}
	}
	if len(m.Resources) > 0 {
		for _, s := range m.Resources {
			l = len(s)
			n += 1 + l + sovGenerated(uint64(l))
		}
	}
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
func (this *Initializer) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&Initializer{`,
		`Name:` + fmt.Sprintf("%v", this.Name) + `,`,
		`Rules:` + strings.Replace(strings.Replace(fmt.Sprintf("%v", this.Rules), "Rule", "Rule", 1), `&`, ``, 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *InitializerConfiguration) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&InitializerConfiguration{`,
		`ObjectMeta:` + strings.Replace(strings.Replace(this.ObjectMeta.String(), "ObjectMeta", "k8s_io_apimachinery_pkg_apis_meta_v1.ObjectMeta", 1), `&`, ``, 1) + `,`,
		`Initializers:` + strings.Replace(strings.Replace(fmt.Sprintf("%v", this.Initializers), "Initializer", "Initializer", 1), `&`, ``, 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *InitializerConfigurationList) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&InitializerConfigurationList{`,
		`ListMeta:` + strings.Replace(strings.Replace(this.ListMeta.String(), "ListMeta", "k8s_io_apimachinery_pkg_apis_meta_v1.ListMeta", 1), `&`, ``, 1) + `,`,
		`Items:` + strings.Replace(strings.Replace(fmt.Sprintf("%v", this.Items), "InitializerConfiguration", "InitializerConfiguration", 1), `&`, ``, 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *Rule) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&Rule{`,
		`APIGroups:` + fmt.Sprintf("%v", this.APIGroups) + `,`,
		`APIVersions:` + fmt.Sprintf("%v", this.APIVersions) + `,`,
		`Resources:` + fmt.Sprintf("%v", this.Resources) + `,`,
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
func (m *Initializer) Unmarshal(dAtA []byte) error {
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
			return fmt.Errorf("proto: Initializer: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Initializer: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
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
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Rules", wireType)
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
			m.Rules = append(m.Rules, Rule{})
			if err := m.Rules[len(m.Rules)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
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
func (m *InitializerConfiguration) Unmarshal(dAtA []byte) error {
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
			return fmt.Errorf("proto: InitializerConfiguration: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: InitializerConfiguration: illegal tag %d (wire type %d)", fieldNum, wire)
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
				return fmt.Errorf("proto: wrong wireType = %d for field Initializers", wireType)
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
			m.Initializers = append(m.Initializers, Initializer{})
			if err := m.Initializers[len(m.Initializers)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
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
func (m *InitializerConfigurationList) Unmarshal(dAtA []byte) error {
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
			return fmt.Errorf("proto: InitializerConfigurationList: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: InitializerConfigurationList: illegal tag %d (wire type %d)", fieldNum, wire)
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
			m.Items = append(m.Items, InitializerConfiguration{})
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
func (m *Rule) Unmarshal(dAtA []byte) error {
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
			return fmt.Errorf("proto: Rule: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Rule: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field APIGroups", wireType)
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
			m.APIGroups = append(m.APIGroups, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field APIVersions", wireType)
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
			m.APIVersions = append(m.APIVersions, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Resources", wireType)
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
			m.Resources = append(m.Resources, string(dAtA[iNdEx:postIndex]))
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
	proto.RegisterFile("k8s.io/kubernetes/vendor/k8s.io/api/admissionregistration/v1alpha1/generated.proto", fileDescriptorGenerated)
}

var fileDescriptorGenerated = []byte{
	// 512 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x91, 0x4f, 0x8b, 0xd3, 0x40,
	0x18, 0xc6, 0x3b, 0xb6, 0x85, 0x76, 0xda, 0x45, 0x09, 0x1e, 0xca, 0x22, 0x69, 0xe9, 0xa9, 0x22,
	0xce, 0xd8, 0x45, 0xc4, 0xeb, 0x66, 0x0f, 0x52, 0xf0, 0xcf, 0x32, 0x88, 0x07, 0xf1, 0xe0, 0xb4,
	0x7d, 0x37, 0x1d, 0xdb, 0x64, 0x86, 0x99, 0x49, 0x41, 0x4f, 0x5e, 0xbc, 0x0b, 0x7e, 0xa9, 0x1e,
	0xf7, 0xb8, 0xa7, 0x62, 0x23, 0x78, 0xf4, 0x33, 0xc8, 0x24, 0xcd, 0x26, 0xcb, 0x2a, 0xac, 0xde,
	0xf2, 0x3e, 0x6f, 0xde, 0xe7, 0x79, 0x7e, 0x0c, 0x66, 0xcb, 0xa7, 0x86, 0x08, 0x49, 0x97, 0xc9,
	0x14, 0x74, 0x0c, 0x16, 0x0c, 0x5d, 0x43, 0x3c, 0x97, 0x9a, 0xee, 0x17, 0x5c, 0x09, 0xca, 0xe7,
	0x91, 0x30, 0x46, 0xc8, 0x58, 0x43, 0x28, 0x8c, 0xd5, 0xdc, 0x0a, 0x19, 0xd3, 0xf5, 0x98, 0xaf,
	0xd4, 0x82, 0x8f, 0x69, 0x08, 0x31, 0x68, 0x6e, 0x61, 0x4e, 0x94, 0x96, 0x56, 0x7a, 0xf7, 0xf3,
	0x53, 0xc2, 0x95, 0x20, 0x7f, 0x3c, 0x25, 0xc5, 0xe9, 0xe1, 0xc3, 0x50, 0xd8, 0x45, 0x32, 0x25,
	0x33, 0x19, 0xd1, 0x50, 0x86, 0x92, 0x66, 0x0e, 0xd3, 0xe4, 0x2c, 0x9b, 0xb2, 0x21, 0xfb, 0xca,
	0x9d, 0x0f, 0x1f, 0x97, 0xa5, 0x22, 0x3e, 0x5b, 0x88, 0x18, 0xf4, 0x47, 0xaa, 0x96, 0xa1, 0x13,
	0x0c, 0x8d, 0xc0, 0x72, 0xba, 0xbe, 0xd6, 0x67, 0xf8, 0x05, 0xe1, 0xce, 0x24, 0x16, 0x56, 0xf0,
	0x95, 0xf8, 0x04, 0xda, 0x1b, 0xe0, 0x46, 0xcc, 0x23, 0xe8, 0xa1, 0x01, 0x1a, 0xb5, 0x83, 0xee,
	0x66, 0xdb, 0xaf, 0xa5, 0xdb, 0x7e, 0xe3, 0x25, 0x8f, 0x80, 0x65, 0x1b, 0xef, 0x35, 0x6e, 0xea,
	0x64, 0x05, 0xa6, 0x77, 0x6b, 0x50, 0x1f, 0x75, 0x8e, 0x28, 0xb9, 0x31, 0x11, 0x61, 0xc9, 0x0a,
	0x82, 0x83, 0xbd, 0x67, 0xd3, 0x4d, 0x86, 0xe5, 0x66, 0xc3, 0x5f, 0x08, 0xf7, 0x2a, 0x3d, 0x4e,
	0x64, 0x7c, 0x26, 0xc2, 0x24, 0x37, 0xf0, 0xde, 0xe3, 0x96, 0xeb, 0x3f, 0xe7, 0x96, 0x67, 0xc5,
	0x3a, 0x47, 0x8f, 0x2a, 0xa9, 0x97, 0xb4, 0x44, 0x2d, 0x43, 0x27, 0x18, 0xe2, 0xfe, 0x26, 0xeb,
	0x31, 0x79, 0x35, 0xfd, 0x00, 0x33, 0xfb, 0x02, 0x2c, 0x0f, 0xbc, 0x7d, 0x2c, 0x2e, 0x35, 0x76,
	0xe9, 0xea, 0x29, 0xdc, 0x15, 0x65, 0x7a, 0xc1, 0xf6, 0xe4, 0x1f, 0xd8, 0x2a, 0xe5, 0x83, 0xbb,
	0xfb, 0xac, 0x6e, 0x45, 0x34, 0xec, 0x4a, 0xc2, 0xf0, 0x27, 0xc2, 0xf7, 0xfe, 0x06, 0xfc, 0x5c,
	0x18, 0xeb, 0xbd, 0xbb, 0x06, 0x4d, 0x6e, 0x06, 0xed, 0xae, 0x33, 0xe4, 0x3b, 0xfb, 0x1a, 0xad,
	0x42, 0xa9, 0x00, 0x2f, 0x70, 0x53, 0x58, 0x88, 0x0a, 0xd2, 0x93, 0xff, 0x23, 0xbd, 0xd2, 0xba,
	0x7c, 0xd9, 0x89, 0x73, 0x66, 0x79, 0xc0, 0xf0, 0x1b, 0xc2, 0x0d, 0xf7, 0xd4, 0xde, 0x03, 0xdc,
	0xe6, 0x4a, 0x3c, 0xd3, 0x32, 0x51, 0xa6, 0x87, 0x06, 0xf5, 0x51, 0x3b, 0x38, 0x48, 0xb7, 0xfd,
	0xf6, 0xf1, 0xe9, 0x24, 0x17, 0x59, 0xb9, 0xf7, 0xc6, 0xb8, 0xc3, 0x95, 0x78, 0x03, 0xda, 0xf5,
	0xc8, 0x5b, 0xb6, 0x83, 0xdb, 0xe9, 0xb6, 0xdf, 0x39, 0x3e, 0x9d, 0x14, 0x32, 0xab, 0xfe, 0xe3,
	0xfc, 0x35, 0x18, 0x99, 0xe8, 0x19, 0x98, 0x5e, 0xbd, 0xf4, 0x67, 0x85, 0xc8, 0xca, 0x7d, 0x40,
	0x36, 0x3b, 0xbf, 0x76, 0xbe, 0xf3, 0x6b, 0x17, 0x3b, 0xbf, 0xf6, 0x39, 0xf5, 0xd1, 0x26, 0xf5,
	0xd1, 0x79, 0xea, 0xa3, 0x8b, 0xd4, 0x47, 0xdf, 0x53, 0x1f, 0x7d, 0xfd, 0xe1, 0xd7, 0xde, 0xb6,
	0x0a, 0xe8, 0xdf, 0x01, 0x00, 0x00, 0xff, 0xff, 0x8a, 0xba, 0x97, 0x09, 0x0c, 0x04, 0x00, 0x00,
}

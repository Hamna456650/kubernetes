// +build !windows

/*
Copyright 2017 The Kubernetes Authors.

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

package master

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"

	"github.com/golang/glog"
	"google.golang.org/grpc"
	kmsapi "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/v1beta1"
)

const (
	kmsAPIVersion = "v1beta1"
	sockFile      = "@kms-provider.sock"
	unixProtocol  = "unix"
)

// base64Plugin gRPC sever for a mock KMS provider.
// Uses base64 to simulate encrypt and decrypt.
type base64Plugin struct {
	grpcServer *grpc.Server
	listener   net.Listener

	// Allow users of the plugin to sense encrypt requests that were passed to KMS.
	encryptRequest chan *kmsapi.EncryptRequest
	errorChan      chan error
}

func NewBase64Plugin() (*base64Plugin, error) {
	listener, err := net.Listen(unixProtocol, sockFile)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on the unix socket, error: %v", err)
	}
	glog.Infof("Listening on %s", sockFile)

	server := grpc.NewServer()

	p := &base64Plugin{
		grpcServer:     server,
		listener:       listener,
		encryptRequest: make(chan *kmsapi.EncryptRequest, 1),
		errorChan:      make(chan error, 1),
	}

	kmsapi.RegisterKeyManagementServiceServer(server, p)

	go func() {
		p.errorChan <- p.grpcServer.Serve(p.listener)
	}()

	return p, nil
}

func (s *base64Plugin) gracefulStop() {
	s.grpcServer.GracefulStop()
}

func (s *base64Plugin) cleanUp() {
	s.grpcServer.Stop()
	s.listener.Close()
}

var testProviderAPIVersion = kmsAPIVersion

func (s *base64Plugin) Version(ctx context.Context, request *kmsapi.VersionRequest) (*kmsapi.VersionResponse, error) {
	return &kmsapi.VersionResponse{Version: testProviderAPIVersion, RuntimeName: "testKMS", RuntimeVersion: "0.0.1"}, nil
}

func (s *base64Plugin) Decrypt(ctx context.Context, request *kmsapi.DecryptRequest) (*kmsapi.DecryptResponse, error) {
	glog.Infof("Received Decrypt Request for DEK: %s", string(request.Cipher))
	return base64Decode(request)
}

func (s *base64Plugin) Encrypt(ctx context.Context, request *kmsapi.EncryptRequest) (*kmsapi.EncryptResponse, error) {
	glog.Infof("Received Encrypt Request for DEK: %x", request.Plain)
	s.encryptRequest <- request
	return base64Encode(request), nil
}

// base64Encode base64 encodes EncryptRequest, thus simulating transformation.
func base64Encode(request *kmsapi.EncryptRequest) *kmsapi.EncryptResponse {
	return &kmsapi.EncryptResponse{Cipher: []byte(base64.StdEncoding.EncodeToString(request.Plain))}
}

// base64Decode base64 decodes DecryptRequest, thus simulating transformation.
func base64Decode(request *kmsapi.DecryptRequest) (*kmsapi.DecryptResponse, error) {
	p, err := base64.StdEncoding.DecodeString(string(request.Cipher))
	if err != nil {
		return nil, err
	}
	return &kmsapi.DecryptResponse{Plain: p}, nil
}

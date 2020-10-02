// Copyright 2018, 2020 Portieris Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package multi

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/IBM/portieris/helpers/credential"
	"github.com/IBM/portieris/helpers/image"
	securityenforcementv1beta1 "github.com/IBM/portieris/pkg/apis/securityenforcement/v1beta1"
	"github.com/IBM/portieris/pkg/verifier/vulnerability"
	"github.com/IBM/portieris/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
)

type mockPolicyClient struct {
	mock.Mock
}

func (mpc *mockPolicyClient) GetPolicyToEnforce(namespace, image string) (*securityenforcementv1beta1.Policy, error) {
	args := mpc.Called(namespace, image)
	return args.Get(0).(*securityenforcementv1beta1.Policy), args.Error(1)
}

type mockEnforcer struct {
	mock.Mock
}

func (me *mockEnforcer) DigestByPolicy(namespace string, img *image.Reference, credentials credential.Credentials, policy *securityenforcementv1beta1.Policy) (*bytes.Buffer, error, error) {
	args := me.Called(namespace, img, credentials, policy)
	return args.Get(0).(*bytes.Buffer), args.Error(1), args.Error(2)
}

func (me *mockEnforcer) VulnerabilityPolicy(img *image.Reference, credentials credential.Credentials, policy *securityenforcementv1beta1.Policy) vulnerability.ScanResponse {
	args := me.Called(img, credentials, policy)
	return args.Get(0).(vulnerability.ScanResponse)
}

func TestController_getPatchesForContainers(t *testing.T) {
	type getPolicyToEnforceMock struct {
		inImage   string
		outPolicy *securityenforcementv1beta1.Policy
		outErr    error
	}
	type enforcerVulnerabilityPolicyMock struct {
		inImage         image.Reference
		inCredentials   credential.Credentials
		outScanResponse vulnerability.ScanResponse
	}
	type enforceDigestByPolicyMock struct {
		inImage       image.Reference
		inCredentials credential.Credentials
		outDigest     string
		outDeny       error
		outErr        error
	}
	tests := []struct {
		name                             string
		containerType                    string
		namespace                        string
		specPath                         string
		imagePullSecrets                 []corev1.LocalObjectReference
		containers                       []corev1.Container
		getPolicyToEnforceMocks          []getPolicyToEnforceMock
		enforcerVulnerabilityPolicyMocks []enforcerVulnerabilityPolicyMock
		enforceDigestByPolicyMocks       []enforceDigestByPolicyMock
		wantPatches                      []types.JSONPatch
		wantDenials                      []string
		wantErr                          error
	}{
		{
			name:        "No containers, return no patches or denials",
			containers:  []corev1.Container{},
			wantPatches: []types.JSONPatch{},
			wantDenials: []string{},
			wantErr:     nil,
		},
		{
			name: "Invalid image name in container, deny",
			containers: []corev1.Container{
				{Image: "Invalid&Image%Name"},
			},
			wantPatches: []types.JSONPatch{},
			wantDenials: []string{"Deny \"Invalid&Image%Name\", invalid image name"},
			wantErr:     nil,
		},
		{
			name:      "Fail to get policy, deny",
			namespace: "some-namespace",
			containers: []corev1.Container{
				{Image: "icr.io/some-namespace/image:tag"},
			},
			getPolicyToEnforceMocks: []getPolicyToEnforceMock{
				{
					inImage: "icr.io/some-namespace/image:tag",
					outErr:  fmt.Errorf("no sorry"),
				},
			},
			wantPatches: []types.JSONPatch{},
			wantDenials: []string{"no sorry"},
			wantErr:     nil,
		},
		{
			name:      "Fail to get policy, deny",
			namespace: "some-namespace",
			containers: []corev1.Container{
				{Image: "icr.io/some-namespace/image:tag"},
			},
			getPolicyToEnforceMocks: []getPolicyToEnforceMock{
				{
					inImage: "icr.io/some-namespace/image:tag",
					outErr:  fmt.Errorf("no sorry"),
				},
			},
			wantPatches: []types.JSONPatch{},
			wantDenials: []string{"no sorry"},
			wantErr:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyClient := mockPolicyClient{}
			policyClient.Test(t)
			defer policyClient.AssertExpectations(t)
			for _, gptem := range tt.getPolicyToEnforceMocks {
				policyClient.
					On("GetPolicyToEnforce", tt.namespace, gptem.inImage).
					Return(gptem.outPolicy, gptem.outErr).Once()
			}

			enforcer := mockEnforcer{}
			enforcer.Test(t)
			defer enforcer.AssertExpectations(t)
			for idx, evpm := range tt.enforcerVulnerabilityPolicyMocks {
				//TODO getting the policy like this is not great
				policy := tt.getPolicyToEnforceMocks[idx].outPolicy
				enforcer.
					On("VulnerabilityPolicy", evpm.inImage, evpm.inCredentials, policy).
					Return(evpm.outScanResponse).Once()
			}
			for idx, edbpm := range tt.enforceDigestByPolicyMocks {
				policy := tt.getPolicyToEnforceMocks[idx].outPolicy
				digest := &bytes.Buffer{
					//todo use edbpm.outDigest
				}
				enforcer.On("DigestByPolicy", tt.namespace, edbpm.inImage, edbpm.inCredentials, policy).
					Return(digest, edbpm.outDeny, edbpm.outErr)
			}

			c := &Controller{
				policyClient: &policyClient,
				Enforcer:     &enforcer,
			}

			podSpec := corev1.PodSpec{
				ImagePullSecrets: tt.imagePullSecrets,
			}

			gotPatches, gotDenials, gotErr := c.getPatchesForContainers(tt.containerType, tt.namespace, tt.specPath, podSpec, tt.containers)

			assert.Equal(t, tt.wantPatches, gotPatches)
			assert.Equal(t, tt.wantDenials, gotDenials)
			assert.Equal(t, tt.wantErr, gotErr)
		})
	}
}

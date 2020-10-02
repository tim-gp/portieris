// Copyright 2020 Portieris Authors.
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
	"reflect"
	"testing"

	"github.com/IBM/portieris/helpers/credential"
	"github.com/IBM/portieris/helpers/image"
	"github.com/IBM/portieris/pkg/apis/securityenforcement/v1beta1"
	securityenforcementv1beta1 "github.com/IBM/portieris/pkg/apis/securityenforcement/v1beta1"
	"github.com/IBM/portieris/pkg/kubernetes"
	notaryverifier "github.com/IBM/portieris/pkg/verifier/trust"
	"github.com/IBM/portieris/pkg/verifier/vulnerability"
	"github.com/stretchr/testify/mock"
)

type mockScannerFactory struct {
	mock.Mock
}

func (msf *mockScannerFactory) GetScanners(img image.Reference, credentials credential.Credentials, policy v1beta1.Policy) (scanners []vulnerability.Scanner) {
	args := msf.Called(img, credentials, policy)
	return args.Get(0).([]vulnerability.Scanner)
}

func Test_enforcer_VulnerabilityPolicy(t *testing.T) {
	type fields struct {
		kubeClientsetWrapper kubernetes.WrapperInterface
		nv                   *notaryverifier.Verifier
		scannerFactory       vulnerability.ScannerFactory
	}
	type args struct {
		img         *image.Reference
		credentials credential.Credentials
		policy      *securityenforcementv1beta1.Policy
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   vulnerability.ScanResponse
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scannerFactory := mockScannerFactory{}
			scannerFactory.Test(t)
			defer scannerFactory.AssertExpectations(t)

			e := &enforcer{
				kubeClientsetWrapper: tt.fields.kubeClientsetWrapper,
				nv:                   tt.fields.nv,
				scannerFactory:       tt.fields.scannerFactory,
			}
			if got := e.VulnerabilityPolicy(tt.args.img, tt.args.credentials, tt.args.policy); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("enforcer.VulnerabilityPolicy() = %v, want %v", got, tt.want)
			}
		})
	}
}

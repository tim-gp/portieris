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

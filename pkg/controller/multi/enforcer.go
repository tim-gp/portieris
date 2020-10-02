package multi

import (
	"bytes"
	"fmt"

	"github.com/IBM/portieris/helpers/credential"
	"github.com/IBM/portieris/helpers/image"
	securityenforcementv1beta1 "github.com/IBM/portieris/pkg/apis/securityenforcement/v1beta1"
	"github.com/IBM/portieris/pkg/kubernetes"
	"github.com/IBM/portieris/pkg/verifier/simple"
	simpleverifier "github.com/IBM/portieris/pkg/verifier/simple"
	notaryverifier "github.com/IBM/portieris/pkg/verifier/trust"
	"github.com/IBM/portieris/pkg/verifier/vulnerability"
	"github.com/golang/glog"
)

type Enforcer interface {
	DigestByPolicy(string, *image.Reference, credential.Credentials, *securityenforcementv1beta1.Policy) (*bytes.Buffer, error, error)
	VulnerabilityPolicy(*image.Reference, credential.Credentials, *securityenforcementv1beta1.Policy) vulnerability.ScanResponse
}

type enforcer struct {
	// kubeClientsetWrapper is a standard kubernetes clientset with a wrapper for retrieving podSpec from a given object
	kubeClientsetWrapper kubernetes.WrapperInterface
	// nv notary verifier
	nv *notaryverifier.Verifier
	// scannerFactory creates new vulnerabilities scanners according to the policy
	scannerFactory vulnerability.ScannerFactory
}

func NewEnforcer(kubeClientsetWrapper kubernetes.WrapperInterface, nv *notaryverifier.Verifier) Enforcer {
	scannerFactory := vulnerability.NewScannerFactory()
	return &enforcer{
		kubeClientsetWrapper: kubeClientsetWrapper,
		nv:                   nv,
		scannerFactory:       &scannerFactory,
	}
}

func (e enforcer) DigestByPolicy(namespace string, img *image.Reference, credentials credential.Credentials, policy *securityenforcementv1beta1.Policy) (*bytes.Buffer, error, error) {
	// no policy indicates admission should be allowed, without mutation
	if policy == nil {
		return nil, nil, nil
	}

	var digest *bytes.Buffer
	var deny, err error
	if len(policy.Simple.Requirements) > 0 {
		glog.Infof("policy.Simple %v", policy.Simple)
		simplePolicy, err := simpleverifier.TransformPolicies(e.kubeClientsetWrapper, namespace, policy.Simple.Requirements)
		if err != nil {
			return nil, nil, err
		}
		storeUser, storePassword, err := e.kubeClientsetWrapper.GetBasicCredentials(namespace, policy.Simple.StoreSecret)
		if err != nil {
			return nil, nil, err
		}
		storeConfigDir, err := simple.CreateRegistryDir(policy.Simple.StoreURL, storeUser, storePassword)
		if err != nil {
			return nil, nil, err
		}
		digest, deny, err = simpleverifier.VerifyByPolicy(img.String(), credentials, storeConfigDir, simplePolicy)
		if err != nil {
			return nil, nil, fmt.Errorf("simple: %v", err)
		}
		err = simple.RemoveRegistryDir(storeConfigDir)
		if err != nil {
			glog.Warningf("failed to remove %s, %v", storeConfigDir, err)
		}
		if deny != nil {
			return nil, fmt.Errorf("simple: policy denied the request: %v", deny), nil
		}
	}

	if policy.Trust.Enabled != nil && *policy.Trust.Enabled {
		glog.Infof("policy.Trust %v", policy.Trust)
		var notaryDigest *bytes.Buffer
		notaryDigest, deny, err = e.nv.VerifyByPolicy(namespace, img, credentials, policy)
		if err != nil {
			return nil, nil, fmt.Errorf("trust: %v", err)
		}
		if deny != nil {
			return nil, fmt.Errorf("trust: policy denied the request: %v", deny), nil
		}
		glog.Infof("DCT digest: %v", notaryDigest)
		if notaryDigest != nil {
			if digest != nil && notaryDigest != digest {
				return nil, fmt.Errorf("Notary signs conflicting digest: %v simple: %v", notaryDigest, digest), nil
			}
			digest = notaryDigest
		}
	}

	return digest, nil, nil
}

func (e *enforcer) VulnerabilityPolicy(img *image.Reference, credentials credential.Credentials, policy *securityenforcementv1beta1.Policy) vulnerability.ScanResponse {
	scanners := e.scannerFactory.GetScanners(*img, credentials, *policy)
	// If the policy has IBMVA enabled, append the correct scanner
	// Loop round all scanners and check if the image can be deployed
	// If any scanner returns either an error, or a CanDeploy=false, the pod will not be admitted
	for _, scanner := range scanners {
		response, err := scanner.CanImageDeployBasedOnVulnerabilities(*img)
		if err != nil {
			return vulnerability.ScanResponse{CanDeploy: false, DenyReason: err.Error()}
		}
		if !response.CanDeploy {
			return response
		}
	}
	if len(scanners) == 0 {
		glog.Infof("No vulnerability scanners enabled by policy for image %q", img.String())
	}
	return vulnerability.ScanResponse{CanDeploy: true}
}

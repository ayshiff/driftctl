package aws

import (
	"github.com/cloudskiff/driftctl/pkg/remote/aws/repository"
	remoteerror "github.com/cloudskiff/driftctl/pkg/remote/error"
	awsdeserializer "github.com/cloudskiff/driftctl/pkg/resource/aws/deserializer"

	"github.com/cloudskiff/driftctl/pkg/remote/deserializer"
	"github.com/cloudskiff/driftctl/pkg/resource"
	resourceaws "github.com/cloudskiff/driftctl/pkg/resource/aws"
	"github.com/cloudskiff/driftctl/pkg/terraform"

	"github.com/sirupsen/logrus"
	"github.com/zclconf/go-cty/cty"
)

type IamRolePolicySupplier struct {
	reader       terraform.ResourceReader
	deserializer deserializer.CTYDeserializer
	client       repository.IAMRepository
	runner       *terraform.ParallelResourceReader
}

func NewIamRolePolicySupplier(provider *AWSTerraformProvider) *IamRolePolicySupplier {
	return &IamRolePolicySupplier{
		provider,
		awsdeserializer.NewIamRolePolicyDeserializer(),
		repository.NewIAMClient(provider.session),
		terraform.NewParallelResourceReader(provider.Runner().SubRunner()),
	}
}

func (s *IamRolePolicySupplier) Resources() ([]resource.Resource, error) {
	policies, err := s.client.ListAllRolePolicies()
	if err != nil {
		return nil, remoteerror.NewResourceEnumerationErrorWithType(err, resourceaws.AwsIamRolePolicyResourceType, resourceaws.AwsIamRoleResourceType)
	}
	for _, policyName := range policies {
		name := policyName
		s.runner.Run(func() (cty.Value, error) {
			return s.readRolePolicy(name)
		})
	}
	results, err := s.runner.Wait()
	if err != nil {
		return nil, err
	}

	return s.deserializer.Deserialize(results)
}

func (s *IamRolePolicySupplier) readRolePolicy(name string) (cty.Value, error) {
	res, err := s.reader.ReadResource(
		terraform.ReadResourceArgs{
			Ty: resourceaws.AwsIamRolePolicyResourceType,
			ID: name,
		},
	)
	if err != nil {
		logrus.Warnf("Error reading iam role policy %s[%s]: %+v", name, resourceaws.AwsIamRolePolicyResourceType, err)
		return cty.NilVal, err
	}

	return *res, nil
}

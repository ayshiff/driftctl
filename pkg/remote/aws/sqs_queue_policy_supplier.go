package aws

import (
	"github.com/cloudskiff/driftctl/pkg/remote/aws/repository"
	"github.com/cloudskiff/driftctl/pkg/remote/deserializer"
	remoteerror "github.com/cloudskiff/driftctl/pkg/remote/error"
	"github.com/cloudskiff/driftctl/pkg/resource"
	"github.com/cloudskiff/driftctl/pkg/resource/aws"
	awsdeserializer "github.com/cloudskiff/driftctl/pkg/resource/aws/deserializer"
	"github.com/cloudskiff/driftctl/pkg/terraform"
	"github.com/sirupsen/logrus"
	"github.com/zclconf/go-cty/cty"
)

type SqsQueuePolicySupplier struct {
	reader       terraform.ResourceReader
	deserializer deserializer.CTYDeserializer
	client       repository.SQSRepository
	runner       *terraform.ParallelResourceReader
}

func NewSqsQueuePolicySupplier(provider *AWSTerraformProvider) *SqsQueuePolicySupplier {
	return &SqsQueuePolicySupplier{
		provider,
		awsdeserializer.NewSqsQueuePolicyDeserializer(),
		repository.NewSQSClient(provider.session),
		terraform.NewParallelResourceReader(provider.Runner().SubRunner()),
	}
}

func (s *SqsQueuePolicySupplier) Resources() ([]resource.Resource, error) {
	queues, err := s.client.ListAllQueues()
	if err != nil {
		return nil, remoteerror.NewResourceEnumerationErrorWithType(err, aws.AwsSqsQueuePolicyResourceType, aws.AwsSqsQueueResourceType)
	}

	for _, queue := range queues {
		q := *queue
		s.runner.Run(func() (cty.Value, error) {
			return s.readSqsQueuePolicy(q)
		})
	}

	resources, err := s.runner.Wait()
	if err != nil {
		return nil, err
	}

	return s.deserializer.Deserialize(resources)
}

func (s *SqsQueuePolicySupplier) readSqsQueuePolicy(queueURL string) (cty.Value, error) {
	var Ty resource.ResourceType = aws.AwsSqsQueuePolicyResourceType
	val, err := s.reader.ReadResource(terraform.ReadResourceArgs{
		Ty: Ty,
		ID: queueURL,
	})
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"type": Ty,
		}).Error(err)
		return cty.NilVal, err
	}
	return *val, nil
}

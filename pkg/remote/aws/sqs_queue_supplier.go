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

type SqsQueueSupplier struct {
	reader       terraform.ResourceReader
	deserializer deserializer.CTYDeserializer
	client       repository.SQSRepository
	runner       *terraform.ParallelResourceReader
}

func NewSqsQueueSupplier(provider *AWSTerraformProvider) *SqsQueueSupplier {
	return &SqsQueueSupplier{
		provider,
		awsdeserializer.NewSqsQueueDeserializer(),
		repository.NewSQSClient(provider.session),
		terraform.NewParallelResourceReader(provider.Runner().SubRunner()),
	}
}

func (s *SqsQueueSupplier) Resources() ([]resource.Resource, error) {
	queues, err := s.client.ListAllQueues()
	if err != nil {
		return nil, remoteerror.NewResourceEnumerationError(err, aws.AwsSqsQueueResourceType)
	}

	for _, queue := range queues {
		q := *queue
		s.runner.Run(func() (cty.Value, error) {
			return s.readSqsQueue(q)
		})
	}

	resources, err := s.runner.Wait()
	if err != nil {
		return nil, err
	}

	return s.deserializer.Deserialize(resources)
}

func (s *SqsQueueSupplier) readSqsQueue(queueURL string) (cty.Value, error) {
	var Ty resource.ResourceType = aws.AwsSqsQueueResourceType
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

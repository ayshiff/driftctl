package repository

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"

	"github.com/stretchr/testify/mock"

	"github.com/r3labs/diff/v2"
	"github.com/stretchr/testify/assert"

	"github.com/cloudskiff/driftctl/mocks"
)

func Test_IAMRepository_ListAllAccessKeys(t *testing.T) {
	tests := []struct {
		name    string
		mocks   func(client *mocks.FakeIAM)
		want    []*iam.AccessKey
		wantErr error
	}{
		{
			name: "List only access keys with multiple pages",
			mocks: func(client *mocks.FakeIAM) {

				client.On("ListUsersPages",
					&iam.ListUsersInput{},
					mock.MatchedBy(func(callback func(res *iam.ListUsersOutput, lastPage bool) bool) bool {
						callback(&iam.ListUsersOutput{Users: []*iam.User{
							{
								UserName: aws.String("test-driftctl"),
							},
							{
								UserName: aws.String("test-driftctl2"),
							},
						}}, true)
						return true
					})).Return(nil)
				client.On("ListAccessKeysPages",
					&iam.ListAccessKeysInput{
						UserName: aws.String("test-driftctl"),
					},
					mock.MatchedBy(func(callback func(res *iam.ListAccessKeysOutput, lastPage bool) bool) bool {
						callback(&iam.ListAccessKeysOutput{AccessKeyMetadata: []*iam.AccessKeyMetadata{
							{
								AccessKeyId: aws.String("AKIA5QYBVVD223VWU32A"),
								UserName:    aws.String("test-driftctl"),
							},
						}}, false)
						callback(&iam.ListAccessKeysOutput{AccessKeyMetadata: []*iam.AccessKeyMetadata{
							{
								AccessKeyId: aws.String("AKIA5QYBVVD2QYI36UZP"),
								UserName:    aws.String("test-driftctl"),
							},
						}}, true)
						return true
					})).Return(nil)
				client.On("ListAccessKeysPages",
					&iam.ListAccessKeysInput{
						UserName: aws.String("test-driftctl2"),
					},
					mock.MatchedBy(func(callback func(res *iam.ListAccessKeysOutput, lastPage bool) bool) bool {
						callback(&iam.ListAccessKeysOutput{AccessKeyMetadata: []*iam.AccessKeyMetadata{
							{
								AccessKeyId: aws.String("AKIA5QYBVVD26EJME25D"),
								UserName:    aws.String("test-driftctl2"),
							},
						}}, false)
						callback(&iam.ListAccessKeysOutput{AccessKeyMetadata: []*iam.AccessKeyMetadata{
							{
								AccessKeyId: aws.String("AKIA5QYBVVD2SWDFVVMG"),
								UserName:    aws.String("test-driftctl2"),
							},
						}}, true)
						return true
					})).Return(nil)
			},
			want: []*iam.AccessKey{
				{
					AccessKeyId: aws.String("AKIA5QYBVVD223VWU32A"),
					UserName:    aws.String("test-driftctl"),
				},
				{
					AccessKeyId: aws.String("AKIA5QYBVVD2QYI36UZP"),
					UserName:    aws.String("test-driftctl"),
				},
				{
					AccessKeyId: aws.String("AKIA5QYBVVD223VWU32A"),
					UserName:    aws.String("test-driftctl"),
				},
				{
					AccessKeyId: aws.String("AKIA5QYBVVD2QYI36UZP"),
					UserName:    aws.String("test-driftctl"),
				},
				{
					AccessKeyId: aws.String("AKIA5QYBVVD26EJME25D"),
					UserName:    aws.String("test-driftctl2"),
				},
				{
					AccessKeyId: aws.String("AKIA5QYBVVD2SWDFVVMG"),
					UserName:    aws.String("test-driftctl2"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mocks.FakeIAM{}
			tt.mocks(client)
			r := &iamRepository{
				client: client,
			}
			got, err := r.ListAllAccessKeys()
			assert.Equal(t, tt.wantErr, err)
			changelog, err := diff.Diff(got, tt.want)
			assert.Nil(t, err)
			if len(changelog) > 0 {
				for _, change := range changelog {
					t.Errorf("%s: %v -> %v", strings.Join(change.Path, "."), change.From, change.To)
				}
				t.Fail()
			}
		})
	}
}

func Test_IAMRepository_ListAllUserPolicies(t *testing.T) {
	tests := []struct {
		name    string
		mocks   func(client *mocks.FakeIAM)
		want    []string
		wantErr error
	}{
		{
			name: "List only user policies with multiple pages",
			mocks: func(client *mocks.FakeIAM) {

				client.On("ListUsersPages",
					&iam.ListUsersInput{},
					mock.MatchedBy(func(callback func(res *iam.ListUsersOutput, lastPage bool) bool) bool {
						callback(&iam.ListUsersOutput{Users: []*iam.User{
							{
								UserName: aws.String("loadbalancer"),
							},
							{
								UserName: aws.String("loadbalancer2"),
							},
						}}, true)
						return true
					})).Return(nil).Once()

				client.On("ListUserPoliciesPages",
					&iam.ListUserPoliciesInput{
						UserName: aws.String("loadbalancer"),
					},
					mock.MatchedBy(func(callback func(res *iam.ListUserPoliciesOutput, lastPage bool) bool) bool {
						callback(&iam.ListUserPoliciesOutput{PolicyNames: []*string{
							aws.String("test"),
							aws.String("test2"),
							aws.String("test3"),
						}}, false)
						callback(&iam.ListUserPoliciesOutput{PolicyNames: []*string{
							aws.String("test4"),
						}}, true)
						return true
					})).Return(nil).Once()

				client.On("ListUserPoliciesPages",
					&iam.ListUserPoliciesInput{
						UserName: aws.String("loadbalancer2"),
					},
					mock.MatchedBy(func(callback func(res *iam.ListUserPoliciesOutput, lastPage bool) bool) bool {
						callback(&iam.ListUserPoliciesOutput{PolicyNames: []*string{
							aws.String("test2"),
							aws.String("test22"),
							aws.String("test23"),
						}}, false)
						callback(&iam.ListUserPoliciesOutput{PolicyNames: []*string{
							aws.String("test24"),
						}}, true)
						return true
					})).Return(nil).Once()
			},
			want: []string{
				*aws.String("loadbalancer:test"),
				*aws.String("loadbalancer:test2"),
				*aws.String("loadbalancer:test3"),
				*aws.String("loadbalancer:test4"),
				*aws.String("loadbalancer2:test"),
				*aws.String("loadbalancer2:test2"),
				*aws.String("loadbalancer2:test3"),
				*aws.String("loadbalancer2:test4"),
				*aws.String("loadbalancer2:test2"),
				*aws.String("loadbalancer2:test22"),
				*aws.String("loadbalancer2:test23"),
				*aws.String("loadbalancer2:test24"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mocks.FakeIAM{}
			tt.mocks(client)
			r := &iamRepository{
				client: client,
			}
			got, err := r.ListAllUserPolicies()
			assert.Equal(t, tt.wantErr, err)
			changelog, err := diff.Diff(got, tt.want)
			assert.Nil(t, err)
			if len(changelog) > 0 {
				for _, change := range changelog {
					t.Errorf("%s: %v -> %v", strings.Join(change.Path, "."), change.From, change.To)
				}
				t.Fail()
			}
		})
	}
}

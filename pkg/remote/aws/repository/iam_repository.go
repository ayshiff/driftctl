package repository

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
)

type IAMRepository interface {
	ListAllAccessKeys() ([]*iam.AccessKeyMetadata, error)
	ListAllUsers() ([]*iam.User, error)
	ListAllPolicies() ([]*iam.Policy, error)
	ListAllRolePolicies() ([]string, error)
	ListAllRolePolicyAttachments(roleName string) ([]*AttachedRolePolicy, error)
	ListAllRoles() ([]*iam.Role, error)
	ListAllUserPolicyAttachments(username string) ([]*AttachedUserPolicy, error)
	ListAllUserPolicies() ([]string, error)
}

type iamRepository struct {
	client iamiface.IAMAPI
}

func NewIAMClient(session *session.Session) *iamRepository {
	return &iamRepository{
		iam.New(session),
	}
}

func (r *iamRepository) ListAllAccessKeys() ([]*iam.AccessKeyMetadata, error) {
	users, err := r.ListAllUsers()
	if err != nil {
		return nil, err
	}
	var resources []*iam.AccessKeyMetadata
	for _, user := range users {
		input := &iam.ListAccessKeysInput{
			UserName: user.UserName,
		}
		err := r.client.ListAccessKeysPages(input, func(res *iam.ListAccessKeysOutput, lastPage bool) bool {
			resources = append(resources, res.AccessKeyMetadata...)
			return !lastPage
		})
		if err != nil {
			return nil, err
		}
	}

	return resources, nil
}

func (r *iamRepository) ListAllUsers() ([]*iam.User, error) {
	var resources []*iam.User
	input := &iam.ListUsersInput{}
	err := r.client.ListUsersPages(input, func(res *iam.ListUsersOutput, lastPage bool) bool {
		resources = append(resources, res.Users...)
		return !lastPage
	})
	if err != nil {
		return nil, err
	}
	return resources, nil
}

func (r *iamRepository) ListAllPolicies() ([]*iam.Policy, error) {
	var resources []*iam.Policy
	input := &iam.ListPoliciesInput{
		Scope: aws.String(iam.PolicyScopeTypeLocal),
	}
	err := r.client.ListPoliciesPages(input, func(res *iam.ListPoliciesOutput, lastPage bool) bool {
		resources = append(resources, res.Policies...)
		return !lastPage
	})
	if err != nil {
		return nil, err
	}
	return resources, nil
}

func (r *iamRepository) ListAllRoles() ([]*iam.Role, error) {
	var resources []*iam.Role
	input := &iam.ListRolesInput{}
	err := r.client.ListRolesPages(input, func(res *iam.ListRolesOutput, lastPage bool) bool {
		resources = append(resources, res.Roles...)
		return !lastPage
	})
	if err != nil {
		return nil, err
	}
	return resources, nil
}

func (r *iamRepository) ListAllRolePolicyAttachments(roleName string) ([]*AttachedRolePolicy, error) {
	var attachedRolePolicies []*AttachedRolePolicy
	input := &iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	}
	err := r.client.ListAttachedRolePoliciesPages(input, func(res *iam.ListAttachedRolePoliciesOutput, lastPage bool) bool {
		for _, policy := range res.AttachedPolicies {
			attachedRolePolicies = append(attachedRolePolicies, &AttachedRolePolicy{
				AttachedPolicy: *policy,
				RoleName:       roleName,
			})
		}
		return !lastPage
	})
	if err != nil {
		return nil, err
	}
	return attachedRolePolicies, nil
}

func (r *iamRepository) ListAllRolePolicies() ([]string, error) {
	roles, err := r.ListAllRoles()
	if err != nil {
		return nil, err
	}

	var resources []string
	for _, role := range roles {
		role := role
		input := &iam.ListRolePoliciesInput{
			RoleName: role.RoleName,
		}

		err := r.client.ListRolePoliciesPages(input, func(res *iam.ListRolePoliciesOutput, lastPage bool) bool {
			for _, policy := range res.PolicyNames {
				policy := policy
				resources = append(
					resources,
					fmt.Sprintf(
						"%s:%s",
						*role.RoleName,
						*policy,
					),
				)
			}
			return !lastPage
		})
		if err != nil {
			return nil, err
		}
	}

	return resources, nil
}

func (r *iamRepository) ListAllUserPolicyAttachments(username string) ([]*AttachedUserPolicy, error) {
	var attachedUserPolicies []*AttachedUserPolicy
	input := &iam.ListAttachedUserPoliciesInput{
		UserName: &username,
	}
	err := r.client.ListAttachedUserPoliciesPages(input, func(res *iam.ListAttachedUserPoliciesOutput, lastPage bool) bool {
		for _, policy := range res.AttachedPolicies {
			attachedUserPolicies = append(attachedUserPolicies, &AttachedUserPolicy{
				AttachedPolicy: *policy,
				Username:       username,
			})
		}
		return !lastPage
	})
	if err != nil {
		return nil, err
	}
	return attachedUserPolicies, nil
}

func (r *iamRepository) ListAllUserPolicies() ([]string, error) {
	users, err := r.ListAllUsers()
	if err != nil {
		return nil, err
	}
	var resources []string
	for _, user := range users {
		input := &iam.ListUserPoliciesInput{
			UserName: user.UserName,
		}
		err := r.client.ListUserPoliciesPages(input, func(res *iam.ListUserPoliciesOutput, lastPage bool) bool {
			for _, polName := range res.PolicyNames {
				resources = append(resources, fmt.Sprintf("%s:%s", *user.UserName, *polName))
			}
			return !lastPage
		})
		if err != nil {
			return nil, err
		}
	}

	return resources, nil
}

type AttachedUserPolicy struct {
	iam.AttachedPolicy
	Username string
}

type AttachedRolePolicy struct {
	iam.AttachedPolicy
	RoleName string
}

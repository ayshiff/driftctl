// GENERATED, DO NOT EDIT THIS FILE
package aws

import "github.com/zclconf/go-cty/cty"

const AwsRoute53HealthCheckResourceType = "aws_route53_health_check"

type AwsRoute53HealthCheck struct {
	ChildHealthThreshold         *int              `cty:"child_health_threshold"`
	ChildHealthchecks            *[]string         `cty:"child_healthchecks"` // This became a slice ptr due to gocty
	CloudwatchAlarmName          *string           `cty:"cloudwatch_alarm_name"`
	CloudwatchAlarmRegion        *string           `cty:"cloudwatch_alarm_region"`
	Disabled                     *bool             `cty:"disabled"`
	EnableSni                    *bool             `cty:"enable_sni" computed:"true"`
	FailureThreshold             *int              `cty:"failure_threshold"`
	Fqdn                         *string           `cty:"fqdn"`
	Id                           string            `cty:"id" computed:"true"`
	InsufficientDataHealthStatus *string           `cty:"insufficient_data_health_status"`
	InvertHealthcheck            *bool             `cty:"invert_healthcheck"`
	IpAddress                    *string           `cty:"ip_address"`
	MeasureLatency               *bool             `cty:"measure_latency"`
	Port                         *int              `cty:"port"`
	ReferenceName                *string           `cty:"reference_name"`
	Regions                      *[]string         `cty:"regions"` // This became a slice ptr due to gocty
	RequestInterval              *int              `cty:"request_interval"`
	ResourcePath                 *string           `cty:"resource_path"`
	SearchString                 *string           `cty:"search_string"`
	Tags                         map[string]string `cty:"tags"`
	Type                         *string           `cty:"type"`
	CtyVal                       *cty.Value        `diff:"-"`
}

func (r *AwsRoute53HealthCheck) TerraformId() string {
	return r.Id
}

func (r *AwsRoute53HealthCheck) TerraformType() string {
	return AwsRoute53HealthCheckResourceType
}

func (r *AwsRoute53HealthCheck) CtyValue() *cty.Value {
	return r.CtyVal
}

package kubernetes

import (
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform/helper/schema"
	api "k8s.io/api/core/v1"
	"k8s.io/api/policy/v1beta"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// Flatteners

func flattenPodSecurityPolicySpec(in v1beta.PodSecurityPolicySpec, d *schema.ResourceData) ([]interface{}, error) {
	att := make(map[string]interface{})

	att["allow_privilege_escalation"] = in.AllowPrivilegeEscalation

	att["allowed_capabilities"] = in.AllowedCapabilities

	att["fs_group"] = in.FSGroup

	att["privileted"] = in.Privileged

	att["run_as_user"] = in.RunAsUser

	att["selinux"] = in.SELinux

	att["supplemental_groups"] = in.SupplementalGroups

	att["volumes"] = in.Volumes
}

// Expanders

func expandPodSecurityPolicy(in []interface{}) (*v1beta.PodSecurityPolicySpec, error) {
	spec := v1beta.PodSecurityPolicySpec{}

	if len(in) == 0 || in[0] == nil {
		return nil, fmt.Error("failed to expand PodSecurityPolicy.Spec: null or empty input")
	}

	p := in[0].(map[string]interface{})

  // Verify there is something to expand
	if v, ok := p["allow_privilege_escalation"].(bool); ok && v != nil {
		spec.AllowPrivilegeEscalation = v
	}

	// TODO: type assertion
	if v, ok := p["allowed_capabilities"].(); ok && len(v) > 0 {
		spec.AllowedCapabilities = v
	}

	if v, ok := p["fs_group"].(string); ok && v != "" {
		spec.FSGroup = v
	}

	if v, ok := p["privileged"].(bool); ok && v != nil {
		spec.Privileged = v
	}

	if v, ok := p["run_as_user"].([]interface{}); ok && *v != nil {
		spec.RunAsUser = expandRunAsUser(v)
	}

	if v, ok := p["selinux"].([]interface{}); ok && v != nil {
		spec.SELinux = expandSELinux(v)
	}

	if v, ok := p["supplemental_groups"].([]interface{}); ok && v != nil {
		spec.SupplementalGroups = expandSupplementalGroups(v)
	}

	// TODO: type assertion
	if v, ok := p["volumes"].(); ok && v != nil {
		spec.Volumes = v
	}

	return &spec, nil
}

func expandRunAsUser(in []interface{}) *v1beta.RunAsUserStrategyOptions {
	spec := v1beta.RunAsUserStrategyOptions{}

	//TODO

	return &spec, nil
}

func expandSELinux(in []interface{}) *v1beta.SELinuxStrategyOptions {
	spec := v1beta.SELinuxStrategyOptions{}

	// TODO

	return &spec, nil
}

func expandSuplementalGroups(in []interface{}) *v1beta.SupplementalGroupsStrategyOptions {
	spec := v1beta.SupplementalGroupsStrategyOptions{}

	// TODO

	return &spec, nil
}

// Patchers

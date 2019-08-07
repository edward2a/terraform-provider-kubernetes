package kubernetes

import (
  "fmt"
  "strconv"

  "github.com/hashicorp/terraform/helper/schema"
  "k8s.io/api/core/v1"
  "k8s.io/api/policy/v1beta"
  "k8s.io/apimachinery/pkg/util/intstr"
)

// Flatteners

func flattenPodSecurityPolicySpec(in v1beta.PodSecurityPolicySpec, d *schema.ResourceData) ([]interface{}, error) {
  att := make(map[string]interface{})

  if in.AllowPrivilegeEscalation != nil {
    att["allow_privilege_escalation"] = in.AllowPrivilegeEscalation // bool
  }

  if in.AllowedCapabilities != nil && len(in.AllowedCapabilities) > 0 {
    att["allowed_capabilities"] = newStringSet(schema.HashString, in.AllowedCapabilities) // string array
  }

  if in.AllowedFlexVolumes != nil && len(in.AllowedFlexVolumes) > 0 {
    att["allowed_flex_volumes"] = flattenAllowedFlexVolumes(in.AllowedFlexVolumes) // map array
  }

  if in.AllowedHostPaths != nil  && len(in.AllowedHostPaths) > 0 {
    att["allowed_host_paths"] = flattenAllowedHostPaths(in.AllowedHostPaths) // map array
  }

  if in.AllowedUnsafeSysctls != nil && len(in.AllowedUnsafeSysctls) > 0 {
    att["allowed_unsafe_sysctls"] = newStringSet(schema.HashString, in.AllowedCapabilities) // string array
  }

  if in.DefaultAddCapabilities != nil && len(in.DefaultAddCapabilities) > 0 {
    att["default_add_capabilities"] = newStringSet(schema.HashString, in.DefaultAddCapabilities) // string array
  }

  if in.DefaultAllowPrivilegeEscalation != nil {
    att["default_allow_privilege_escalation"] = in.DefaultAllowPrivilegeEscalation // bool
  }

  if in.ForbiddenSysctls != nil && len(in.ForbiddenSysctls) > 0 {
    att["forbidden_sysctls"] = newStringSet(schema.HashString, in.ForbiddenSysctls) // string array
  }

  if in.FSGroup != nil && len(in.FSGroup) > 0 {
    att["fs_group"] = flattenFSGroup(in.FSGroup) // map array
  }

  if in.HostIPC != nil {
    att["host_ipc"] = in.HostIPC // bool
  }

  if in.HostNetwork != nil {
    att["host_network"] = in.HostNetwork // bool
  }

  if in.HostPID != nil {
    att["host_pid"] = in.HostPID // bool
  }

  if in.HostPorts != nil && len(in.HostPorts) > 0 {
    att["host_ports"] = flattenHostPorts(in.HostPorts) // map array
  }

  if in.Privileged != nil {
    att["privileged"] = in.Privileged // bool
  }

  if in.ReadOnlyRootFilesystem != nil {
    att["readonly_root_filesystem"] = in.ReadOnlyRootFilesystem //bool
  }

  if in.RequiredDropCapabilities != nil && len(in.RequiredDropCapabilities) > 0 {
    att["required_drop_capabilities"] = in.RequiredDropCapabilities // string array
  }

  if in.RunAsGroup != nil && len(in.RunAsGroup) > 0 {
    att["run_as_group"] = flattenRunAsGroup(in.RunAsGroup) // map array
  }

  if in.RunAsUser != nil && len(in.RunAsUser) > 0 {
    att["run_as_user"] = flattenRunAsUser(in.RunAsUser) // map array
  }

  if in.SELinux != nil && len(in.SELinux) > 0 {
    att["selinux"] = flattenSELinux(in.SELinux) // map array
  }

  if in.SupplementalGroups != nil && len(in.SupplementalGroups) > 0 {
    att["supplemental_groups"] = flattenSupplementalGroups(in.SupplementalGroups) // map array
  }

  if in.Volumes != nil && len(in.Volumes) > 0 {
    att["volumes"] = in.Volumes // string array
  }
}

func flattenAllowedFlexVolumes(in []v1beta.AllowedFlexVolume) ([]interface{}, error) {
  att := make([]interface{}, len(in), len(in))
}

func flattenAllowedHostPaths(in []v1beta.AllowedHostPath) ([]interface{}, error) {
  att := make([]interface{}, len(in), len(in))
}

func flattenFSGroup(in v1beta.FSGroupStrategyOptions) ([]interface{}, error) {
  att := make([]interface{}, len(in), len(in))
}

func flattenHostPorts(in []v1beta.HostPortRange) ([]interface{}, error) {
  att := make([]interface{}, len(in), len(in))
}

func flattenRunAsGroup(in v1beta.RunAsGroupStrategyOptions) ([]interface{}, error) {
  att := make([]interface{}, len(in), len(in))
}

func flattenRunAsUser(in v1beta.RunAsUserStrategyOptions) ([]interface{}, error) {
  att := make([]interface{}, len(in), len(in))
}

func flattenSELinux(in v1beta.SELinuxStrategyOptions) ([]interface{}, error) {
  att := make([]interface{}, len(in), len(in))
}

func flattenSupplementalGroups(in v1beta.SupplementalGroupsStrategyOptions) ([]interface{}, error) {
  att := make([]interface{}, len(in), len(in))
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
  if v, ok := p["allowed_capabilities"]; ok && len(v) > 0 {
    spec.AllowedCapabilities = v
  }

  if v, ok := p["fs_group"].(string); ok && v != "" {
    spec.FSGroup = expandFSGroup(v)
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
  if v, ok := p["volumes"]; ok && v != nil {
    spec.Volumes = v
  }

  return &spec
}


func expandAllowedFlexVolumes(in []interface{}) []v1beta.AllowedFlexVolume {
  obj := make([]v1beta.AllowedFlexVolume{}, len(in), len(in))

  for i, afv := range in {
    cfg := afv.(map(string)interface{})
    obj[i] =  v1beta.AllowedFlexVolume{
      Driver:         string(cfg["driver"]),
    }
  }

  return obj
}


func expandAllowedHostPaths(in []interface{}) []v1beta.AllowedHostPath {
  obj := make([]v1beta.AllowedHostsPath{}, len(in), len(in))

  for i, ahp := range in {
    cfg := ahp.(map(string)interface{})
    obj[i] = v1beta.AllowedHostPath{
      PathPrefix:       string(cfg["path_prefix"]),
    }

    if v, ok := cfg["read_only"].(bool); ok {
      obj[i].ReadOnly = v
    }
  }

  return obj
}


func expandFSGroup(in []interface{}) v1beta.FSGroupStrategyOptions {
  obj := v1beta.FSGroupStrategyOptions{
    Rule:       string(in["rule"]),
    Ranges:     expandIDRanges(in["ranges"]),
  }

  return obj
}


func expandHostPorts(in []interface{}) []v1beta.HostPortRange {
  obj := make([]v1beta.HostPortRange{}, len(in), len(in))

  for i, hpr := range in {
    if max, min := hpr[i]["max"].(int); hpr[i]["min"].(int) {
      obj[i] = HostPortRange{
        Max:        max,
        Min:        min,
      }
  }

  return obj
}


func expandRunAsGroup(in []interface{}) v1beta.RunAsGroupStrategyOptions {
  obj := v1beta.RunAsGroupStrategyOptions{
    Rule:       string(in["rule"]),
    Ranges:     expandIDRanges(in["ranges"]),
  }

  return obj
}


func expandRunAsUser(in []interface{}) v1beta.RunAsUserStrategyOptions {
  obj := v1beta.RunAsUserStrategyOptions{
    Rule:       string(in["rule"]),
    Ranges:     expandIDRanges(in["ranges"]),
  }

  return obj
}


func expandSELinux(in []interface{}) v1beta.SELinuxStrategyOptions {
  obj := v1beta.SELinuxStrategyOptions{
    Rule:           string(in["rule"]),
  }

  if slo, ok := in["selinux_options"]; ok {
    obj.SELinuxOptions = v1.SELinuxOptions{}

    if v, ok := slo["level"].(string); ok {
      obj.SELinuxOptions.Level = v
    }

    if v, ok := slo["role"].(string); ok {
      obj.SELinuxOptions.Role = v
    }

    if v, ok := slo["type"].(string); ok {
      obj.SELinuxOptions.Type = v
    }

    if v, ok := slo["user"].(string); ok {
      obj.SELinuxOptions.User = v
    }
  }

  return obj
}


func expandSuplementalGroups(in []interface{}) v1beta.SupplementalGroupsStrategyOptions {
  obj := v1beta.SupplementalGroupsStrategyOptions{
    Rule:       string(in["rule"]),
    Ranges      expandIDRanges(in["ranges"]),
  }

  return obj
}

func expandIDRanges(in []interface{}) []v1beta.IDRange {
  obj := v1beta.IDRange{}

  for i, idr := range in {
    cfg := n.(map(string)interface[])
    obj[i] = v1beta.IDRange{
      Max: v["max"],
      Min: v["min"]
    }
  }

  return obj
}

// Patchers

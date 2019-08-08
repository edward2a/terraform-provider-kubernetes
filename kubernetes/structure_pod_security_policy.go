package kubernetes

import (
  "fmt"
  //"strconv"

  "github.com/hashicorp/terraform/helper/schema"
  "k8s.io/api/core/v1"
  //"k8s.io/api/policy/v1beta1"
  "k8s.io/api/extensions/v1beta1"
  //"k8s.io/apimachinery/pkg/util/intstr"
)

// Flatteners

func flattenPodSecurityPolicySpec(in v1beta1.PodSecurityPolicySpec) ([]interface{}, error) {
  att := make(map[string]interface{})

  if in.AllowPrivilegeEscalation != nil {
    att["allow_privilege_escalation"] = in.AllowPrivilegeEscalation // bool
  }

  if in.AllowedCapabilities != nil && len(in.AllowedCapabilities) > 0 {
    caps := make([]string, 0, 0)
    for i, c := range in.AllowedCapabilities {
      caps[i] = string(c)
    }
    att["allowed_capabilities"] = newStringSet(schema.HashString, caps) // string array
  }

  if in.AllowedFlexVolumes != nil && len(in.AllowedFlexVolumes) > 0 {
    att["allowed_flex_volumes"] = flattenAllowedFlexVolumes(in.AllowedFlexVolumes) // map array
  }

  if in.AllowedHostPaths != nil  && len(in.AllowedHostPaths) > 0 {
    att["allowed_host_paths"] = flattenAllowedHostPaths(in.AllowedHostPaths) // map array
  }

  if in.AllowedUnsafeSysctls != nil && len(in.AllowedUnsafeSysctls) > 0 {
    att["allowed_unsafe_sysctls"] = newStringSet(schema.HashString, in.AllowedUnsafeSysctls) // string array
  }

  if in.DefaultAddCapabilities != nil && len(in.DefaultAddCapabilities) > 0 {
    caps := make([]string, 0, 0)
    for i, c := range in.DefaultAddCapabilities {
      caps[i] = string(c)
    }
    att["default_add_capabilities"] = newStringSet(schema.HashString, caps) // string array
  }

  if in.DefaultAllowPrivilegeEscalation != nil {
    att["default_allow_privilege_escalation"] = in.DefaultAllowPrivilegeEscalation // bool
  }

  if in.ForbiddenSysctls != nil && len(in.ForbiddenSysctls) > 0 {
    att["forbidden_sysctls"] = newStringSet(schema.HashString, in.ForbiddenSysctls) // string array
  }

  //TODO
  //if in.FSGroup != nil && len(in.FSGroup) > 0 {
    //att["fs_group"] = flattenFSGroup(in.FSGroup) // map array
  //}

  //TODO
  //if in.FSGroup != nil && len(in.FSGroup) > 0 {
  /*if in.HostIPC != nil {
    att["host_ipc"] = in.HostIPC // bool
  }*/

  //TODO
  /*if in.HostNetwork != nil {
    att["host_network"] = in.HostNetwork // bool
  }*/

  //TODO
  /*if in.HostPID != nil {
    att["host_pid"] = in.HostPID // bool
  }*/

  if in.HostPorts != nil && len(in.HostPorts) > 0 {
    att["host_ports"] = flattenHostPorts(in.HostPorts) // map array
  }

  //TODO
  /*if in.Privileged != nil {
    att["privileged"] = in.Privileged // bool
  }*/

  //TOOD
  /*if in.ReadOnlyRootFilesystem != nil {
    att["readonly_root_filesystem"] = in.ReadOnlyRootFilesystem //bool
  }*/

  if in.RequiredDropCapabilities != nil && len(in.RequiredDropCapabilities) > 0 {
    att["required_drop_capabilities"] = in.RequiredDropCapabilities // string array
  }

  if in.RunAsGroup != nil /*&& len(in.RunAsGroup) > 0*/ {
    att["run_as_group"] = flattenRunAsGroup(in.RunAsGroup) // map array
  }

  //TODO
  /*if in.RunAsUser != nil && len(in.RunAsUser) > 0 {
    att["run_as_user"] = flattenRunAsUser(in.RunAsUser) // map array
  }*/

  //TODO
  /*if in.SELinux != nil && len(in.SELinux) > 0 {
    att["selinux"] = flattenSELinux(in.SELinux) // map array
  }*/

  //TODO
  /*if in.SupplementalGroups != nil && len(in.SupplementalGroups) > 0 {
    att["supplemental_groups"] = flattenSupplementalGroups(in.SupplementalGroups) // map array
  }*/

  if in.Volumes != nil && len(in.Volumes) > 0 {
    att["volumes"] = in.Volumes // string array
  }

  return []interface{}{att}, nil
}

func flattenAllowedFlexVolumes(in []v1beta1.AllowedFlexVolume) ([]interface{}) {
  att := make([]interface{}, len(in), len(in))

  return att
}

func flattenAllowedHostPaths(in []v1beta1.AllowedHostPath) ([]interface{}) {
  att := make([]interface{}, len(in), len(in))

  return att
}

func flattenFSGroup(in v1beta1.FSGroupStrategyOptions) ([]interface{}) {
  att := make(map[string]interface{})

  if len(in.Rule) > 0 { //!= nil {
    att["rule"] = string(in.Rule)
  }

  //if in.Ranges != nil && len(in.Ranges) > 0 {
  if len(in.Ranges) > 0 {
    att["ranges"] = flattenIDRanges(in.Ranges)
  /*att["ranges"] = make(map[string]interface{}, len(in.Ranges), len(in.Ranges))
    for i, r := range in.Ranges {
      att["ranges"][i] = make([]interface{}, len(r), len(r))
      att["ranges"][i]["max"] = int(r["max"])
      att["ranges"][i]["min"] = int(r["min"])
    }*/
  }

  return []interface{}{att}
}

func flattenHostPorts(in []v1beta1.HostPortRange) ([]interface{}) {
  att := make([]interface{}, len(in), len(in))

  return att
}

func flattenRunAsGroup(in *v1beta1.RunAsGroupStrategyOptions) ([]interface{}) {
  att := make([]interface{},0,0)

  return att
}

func flattenRunAsUser(in v1beta1.RunAsUserStrategyOptions) ([]interface{}) {
  att := make([]interface{},0,0)

  return att
}

func flattenSELinux(in v1beta1.SELinuxStrategyOptions) ([]interface{}) {
  att := make([]interface{},0,0)

  return att
}

func flattenSupplementalGroups(in v1beta1.SupplementalGroupsStrategyOptions) ([]interface{}) {
  att := make([]interface{},0,0)

  return att
}

func flattenIDRanges(in []v1beta1.IDRange) ([]interface{}) {
  att := make([]map[string]int, len(in), len(in)) //{make(map[string]interface{})})
  for i, r := range in {
    att[i] = make(map[string]int)
    att[i]["max"] = int(r.Max)
    att[i]["min"] = int(r.Min)
  }

  return []interface{}{att}
}

// Expanders

func expandPodSecurityPolicySpec(in []interface{}) (*v1beta1.PodSecurityPolicySpec, error) {
  spec := v1beta1.PodSecurityPolicySpec{}

  if len(in) == 0 || in[0] == nil {
    return nil, fmt.Errorf("failed to expand PodSecurityPolicy.Spec: null or empty input")
  }

  p := in[0].(map[string]interface{})

  // Verify there is something to expand
  if v, ok := p["allow_privilege_escalation"].(bool); ok {
    spec.AllowPrivilegeEscalation = &v
  }

  if v, ok := p["allowed_capabilities"].([]v1.Capability); ok && len(v) > 0 {
    spec.AllowedCapabilities = v
  }

  if v, ok := p["fs_group"].([]interface{}); ok && v != nil {
    spec.FSGroup = expandFSGroup(v)
  }

  if v, ok := p["privileged"].(bool); ok {
    spec.Privileged = v
  }

  if v, ok := p["run_as_user"].([]interface{}); ok && v != nil {
    spec.RunAsUser = expandRunAsUser(v)
  }

  if v, ok := p["selinux"].([]interface{}); ok && v != nil {
    spec.SELinux = expandSELinux(v)
  }

  if v, ok := p["supplemental_groups"].([]interface{}); ok && v != nil {
    spec.SupplementalGroups = expandSupplementalGroups(v)
  }

  if v, ok := p["volumes"].([]v1beta1.FSType); ok && v != nil {
    spec.Volumes = v
  }

  return &spec, nil
}


func expandAllowedFlexVolumes(in []interface{}) []v1beta1.AllowedFlexVolume {
  obj := make([]v1beta1.AllowedFlexVolume, len(in), len(in))

  for i, afv := range in {
    cfg := afv.(map[string]interface{})
    obj[i] = v1beta1.AllowedFlexVolume{
      Driver: cfg["driver"].(string),
    }
  }

  return obj
}


func expandAllowedHostPaths(in []interface{}) []v1beta1.AllowedHostPath {
  obj := make([]v1beta1.AllowedHostPath, len(in), len(in))

  for i, ahp := range in {
    cfg := ahp.(map[string]interface{})
    obj[i] = v1beta1.AllowedHostPath{
      PathPrefix: cfg["path_prefix"].(string),
    }

    if v, ok := cfg["read_only"].(bool); ok {
      obj[i].ReadOnly = v
    }
  }

  return obj
}


func expandFSGroup(in interface{}) v1beta1.FSGroupStrategyOptions {
  cfg := in.(map[string]interface{})
  obj := v1beta1.FSGroupStrategyOptions{
    Rule:       cfg["rule"].(v1beta1.FSGroupStrategyType),
    Ranges:     expandIDRanges(cfg["ranges"].([]interface{})),
  }

  return obj
}

/*
func expandHostPorts(in []interface{}) []v1beta1.HostPortRange {
  obj := make([]v1beta1.HostPortRange{}, len(in), len(in))

  for i, hpr := range in {
    if max, min := hpr[i]["max"].(int); hpr[i]["min"].(int) {
      obj[i] = HostPortRange{
        Max:        max,
        Min:        min,
      }
  }

  return obj
}
*/


func expandRunAsGroup(in []interface{}) v1beta1.RunAsGroupStrategyOptions {
  cfg := in[0].(map[string]interface{})
  obj := v1beta1.RunAsGroupStrategyOptions{
    Rule:       cfg["rule"].(v1beta1.RunAsGroupStrategy),
    Ranges:     expandIDRanges(cfg["ranges"].([]interface{})),
  }

  return obj
}


func expandRunAsUser(in []interface{}) v1beta1.RunAsUserStrategyOptions {
  cfg := in[0].(map[string]interface{})
  obj := v1beta1.RunAsUserStrategyOptions{
    Rule:       cfg["rule"].(v1beta1.RunAsUserStrategy),
    Ranges:     expandIDRanges(cfg["ranges"].([]interface{})),
  }

  return obj
}


func expandSELinux(in []interface{}) v1beta1.SELinuxStrategyOptions {
  cfg := in[0].(map[string]interface{})
  obj := v1beta1.SELinuxStrategyOptions{
    Rule:           cfg["rule"].(v1beta1.SELinuxStrategy),
  }

  if slo, ok := cfg["selinux_options"].(map[string]interface{}); ok {
    obj.SELinuxOptions = &v1.SELinuxOptions{}

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


func expandSupplementalGroups(in []interface{}) v1beta1.SupplementalGroupsStrategyOptions {
  cfg := in[0].(map[string]interface{})
  obj := v1beta1.SupplementalGroupsStrategyOptions{
    Rule:       cfg["rule"].(v1beta1.SupplementalGroupsStrategyType),
    Ranges:     expandIDRanges(cfg["ranges"].([]interface{})),
  }

  return obj
}

func expandIDRanges(in []interface{}) []v1beta1.IDRange {
  obj := make([]v1beta1.IDRange, len(in), len(in))

  for i, idr := range in {
    cfg := idr.(map[string]interface{})
    obj[i] = v1beta1.IDRange{
      Max: cfg["max"].(int64),
      Min: cfg["min"].(int64),
    }
  }

  return obj
}

// Patchers

func patchPodSecurityPolicySpec(keyPrefix string, pathPrefix string, d *schema.ResourceData) (*PatchOperations, error) {
  ops := make(PatchOperations, 0, 0)

  return &ops, nil
}

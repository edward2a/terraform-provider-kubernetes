package kubernetes

import (
  "fmt"
  "log"

  "github.com/hashicorp/terraform/helper/schema"
  ext_v1beta1 "k8s.io/api/extensions/v1beta1"
  policy_v1beta1 "k8s.io/api/policy/v1beta1"
  "k8s.io/apimachinery/pkg/api/errors"
  meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
  pkgApi "k8s.io/apimachinery/pkg/types"
  "k8s.io/client-go/kubernetes"
)

var (
  //allowedFlexVolumeDoc                  = policy_v1beta1.AllowedFlexVolume{}.SwaggerDoc()
  allowedHostPathDoc                    = policy_v1beta1.AllowedHostPath{}.SwaggerDoc()
  fsGroupStrategyOptionsDoc             = policy_v1beta1.FSGroupStrategyOptions{}.SwaggerDoc()
  hostPortRangeDoc                      = policy_v1beta1.HostPortRange{}.SwaggerDoc()
  idRangeDoc                            = policy_v1beta1.IDRange{}.SwaggerDoc()
  podSecurityPolicyDoc                  = policy_v1beta1.PodSecurityPolicy{}.SwaggerDoc()[""]
  //podSecurityPolicyListDoc              = policy_v1beta1.PodSecurityPolicyList{}.SwaggerDoc()
  podSecurityPolicySpecDoc              = policy_v1beta1.PodSecurityPolicySpec{}.SwaggerDoc()
  runAsGroupStrategyOptionsDoc          = policy_v1beta1.RunAsGroupStrategyOptions{}.SwaggerDoc()
  runAsUserStrategyOptionsDoc           = policy_v1beta1.RunAsUserStrategyOptions{}.SwaggerDoc()
  seLinuxStrategyOptionsDoc             = policy_v1beta1.SELinuxStrategyOptions{}.SwaggerDoc()
  supplementalGroupsStrategyOptionsDoc  = policy_v1beta1.SupplementalGroupsStrategyOptions{}.SwaggerDoc()
)

func resourceKubernetesPodSecurityPolicy() *schema.Resource {
  return &schema.Resource{
    Create: resourceKubernetesPodSecurityPolicyCreate,
    Read:   resourceKubernetesPodSecurityPolicyRead,
    Exists: resourceKubernetesPodSecurityPolicyExists,
    Update: resourceKubernetesPodSecurityPolicyUpdate,
    Delete: resourceKubernetesPodSecurityPolicyDelete,
    Importer: &schema.ResourceImporter{
      State: schema.ImportStatePassthrough,
    },

    Schema: map[string]*schema.Schema{
      "metadata": metadataSchema("pod security policy", true),
      "spec": {
        Type:         schema.TypeList,
        Description:  podSecurityPolicyDoc,
        Required:     true,
        MaxItems:     1,

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "allow_privilege_escalation": {
              Type:         schema.TypeBool,
              Description:  podSecurityPolicySpecDoc["allowPrivilegeEscalation"],
              Optional:     true,
              Default:      false,    // API defaults to true
            },

            "allowed_capabilities": {
              Type:         schema.TypeList,
              Description:  podSecurityPolicySpecDoc["allowedCapabilities"],
              Optional:     true,
              Elem: &schema.Schema{Type: schema.TypeString},
            },

            "allowed_flex_volumes": {
              Type:         schema.TypeList,
              Description:  podSecurityPolicySpecDoc["allowedFlexVolumes"],
              Optional:     true,
              Elem: &schema.Schema{Type: schema.TypeString},
            },

            "allowed_host_paths": {
              Type:         schema.TypeList,
              Description:  podSecurityPolicySpecDoc["allowedHostPaths"],
              Optional:     true,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                  "path_prefix": {
                    Type:         schema.TypeString,
                    Description:  allowedHostPathDoc["pathPrefix"],
                    Optional:     true,
                  },
                  "read_only": {
                    Type:         schema.TypeString,
                    Description:  allowedHostPathDoc["readOnly"],
                    Optional:     true,
                  },
                },
              },
            },

            "allowed_proc_mount_types": {
              Type:         schema.TypeList,
              Description:  podSecurityPolicySpecDoc["allowedProcMountTypes"],
              Optional:     true,
              Elem: &schema.Schema{Type: schema.TypeString},
            },

            "allowed_unsafe_sysctls": {
              Type:         schema.TypeList,
              Description:  podSecurityPolicySpecDoc["allowedUnsafeSysctls"],
              Optional:     true,
              Elem: &schema.Schema{Type: schema.TypeString},
            },

            "default_add_capabilities": {
              Type:         schema.TypeList,
              Description:  podSecurityPolicySpecDoc["defaultAddCapabilities"],
              Optional:     true,
              Elem: &schema.Schema{Type: schema.TypeString},
            },

            "default_allow_privilege_escalation": {
              Type:         schema.TypeBool,
              Description:  podSecurityPolicySpecDoc["defaultAllowPrivilegeEscalation"],
              Optional:     true,
              Elem: &schema.Schema{Type: schema.TypeString},
            },

            "forbidden_sysctls": {
              Type:         schema.TypeList,
              Description:  podSecurityPolicySpecDoc["forbiddenSysctls"],
              Optional:     true,
              Elem: &schema.Schema{Type: schema.TypeString},
            },

            "fs_group": {
              Type:         schema.TypeList,
              Description:  podSecurityPolicySpecDoc["fsGroup"],
              Required:     true,
              MaxItems:     1,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                  "ranges": {
                    Type:         schema.TypeList,
                    Description:  fsGroupStrategyOptionsDoc["ranges"],
                    Optional:     true,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                        "max": {
                          Type:         schema.TypeInt,
                          Description:  idRangeDoc["max"],
                          Optional:     true,
                        },
                        "min": {
                          Type:         schema.TypeInt,
                          Description:  idRangeDoc["min"],
                          Optional:     true,
                        },
                      },
                    },
                  },
                  "rule": {
                    Type:         schema.TypeString,
                    Description:  fsGroupStrategyOptionsDoc["rule"],
                    Required:     true,
                  },
                },
              },
            },

            "host_ipc": {
              Type:         schema.TypeBool,
              Description:  podSecurityPolicySpecDoc["hostIPC"],
              Optional:     true,
            },

            "host_network": {
              Type:         schema.TypeBool,
              Description:  podSecurityPolicySpecDoc["hostNetwork"],
              Optional:     true,
            },

            "host_pid": {
              Type:         schema.TypeBool,
              Description:  podSecurityPolicySpecDoc["hostPID"],
              Optional:     true,
            },

            "host_ports": {
              Type:         schema.TypeList,
              Description:  podSecurityPolicySpecDoc["hostPorts"],
              Optional:     true,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                  "max": {
                    Type:         schema.TypeInt,
                    Description:  hostPortRangeDoc["max"],
                    Optional:     true,
                   },
                  "min": {
                    Type:         schema.TypeInt,
                    Description:  hostPortRangeDoc["min"],
                    Optional:     true,
                  },
                },
              },
            },

            "privileged": {
              Type:         schema.TypeBool,
              Description:  podSecurityPolicySpecDoc["privileged"],
              Optional:     true,
            },

            "readonly_root_filesystem": {
              Type:         schema.TypeBool,
              Description:  podSecurityPolicySpecDoc["readOnlyRootFilesystem"],
              Optional:     true,
            },

            "required_drop_capabilities": {
              Type:         schema.TypeList,
              Description:  podSecurityPolicySpecDoc["requiredDropCapabilities"],
              Optional:     true,
              Elem: &schema.Schema{Type: schema.TypeString},
            },

            "run_as_group": {
              Type:         schema.TypeList,
              Description:  podSecurityPolicySpecDoc["runAsGroup"],
              Optional:     true,
              MaxItems:     1,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                  "ranges": {
                    Type:         schema.TypeList,
                    Description:  runAsGroupStrategyOptionsDoc["ranges"],
                    Optional:     true,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                        "max": {
                          Type:         schema.TypeInt,
                          Description:  idRangeDoc["max"],
                          Optional:     true,
                        },
                        "min": {
                          Type:         schema.TypeInt,
                          Description:  idRangeDoc["min"],
                          Optional:     true,
                        },
                      },
                    },
                  },
                  "rule": {
                    Type:         schema.TypeString,
                    Description:  runAsGroupStrategyOptionsDoc["rule"],
                    Optional:     true,
                  },
                },
              },
            },

            "run_as_user": {
              Type:         schema.TypeList,
              Description:  podSecurityPolicySpecDoc["runAsUser"],
              Required:     true,
              MaxItems:     1,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                  "ranges": {
                    Type:         schema.TypeList,
                    Description:  runAsUserStrategyOptionsDoc["ranges"],
                    Optional:     true,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                        "max": {
                          Type:         schema.TypeInt,
                          Description:  idRangeDoc["max"],
                          Optional:     true,
                        },
                        "min": {
                          Type:         schema.TypeInt,
                          Description:  idRangeDoc["min"],
                          Optional:     true,
                        },
                      },
                    },
                  },
                  "rule": {
                    Type:         schema.TypeString,
                    Description:  runAsUserStrategyOptionsDoc["rule"],
                    Required:     true,
                  },
                },
              },
            },

            "se_linux": {
              Type:         schema.TypeList,
              Description:  podSecurityPolicySpecDoc["seLinux"],
              Required:     true,
              MaxItems:     1,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                  "rule": {
                    Type:         schema.TypeString,
                    Description:  seLinuxStrategyOptionsDoc["rule"],
                    Required:     true,
                  },
                  "se_linux_options": {
                    Type:         schema.TypeList,
                    Description:  seLinuxStrategyOptionsDoc["seLinuxOptions"],
                    Optional:     true,
                    MaxItems:     1,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                        "level":  {
                          Type:         schema.TypeString,
                          //Description:  "",
                          Optional:     true,
                        },
                        "role": {
                          Type:         schema.TypeString,
                          //Description:  "",
                          Optional:     true,
                        },
                        "type": {
                          Type:         schema.TypeString,
                          //Description:  "",
                          Optional:     true,
                        },
                        "user": {
                          Type:         schema.TypeString,
                          //Description:  "",
                          Optional:     true,
                        },
                      },
                    },
                  },
                },
              },
            },

            "supplemental_groups": {
              Type:         schema.TypeList,
              Description:  podSecurityPolicySpecDoc["supplementalGroups"],
              Required:     true,
              MaxItems:     1,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                  "ranges": {
                    Type:         schema.TypeList,
                    Description:  supplementalGroupsStrategyOptionsDoc["ranges"],
                    Optional:     true,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                        "max": {
                          Type:         schema.TypeInt,
                          Description:  idRangeDoc["max"],
                          Optional:     true,
                        },
                        "min": {
                          Type:         schema.TypeInt,
                          Description:  idRangeDoc["min"],
                          Optional:     true,
                        },
                      },
                    },
                  },
                  "rule": {
                    Type:         schema.TypeString,
                    Description:  supplementalGroupsStrategyOptionsDoc["rule"],
                    Required:     true,
                  },
                },
              },
            },

            "volumes": {
              Type:         schema.TypeList,
              //Description:  "",
              Optional:     true,
              Elem: &schema.Schema{Type: schema.TypeString},
            },
          },
        },
      },
    },
  }
}

func resourceKubernetesPodSecurityPolicyCreate(d *schema.ResourceData, meta interface{}) error {
  conn := meta.(*kubernetes.Clientset)

  metadata := expandMetadata(d.Get("metadata").([]interface{}))
  spec, err := expandPodSecurityPolicySpec(d.Get("spec").([]interface{}))
  if err != nil {
    return err
  }

  svc := ext_v1beta1.PodSecurityPolicy{
    ObjectMeta: metadata,
    Spec:       *spec,
  }
  log.Printf("[INFO] Creating new pod security policy %#v", svc)
  out, err := conn.ExtensionsV1beta1().PodSecurityPolicies().Create(&svc)
  if err != nil {
    return err
  }

  log.Printf("[INFO] Submitted new pod security policy: %#v", out)
  d.SetId(buildId(out.ObjectMeta))

  return resourceKubernetesPodSecurityPolicyRead(d, meta)
}

func resourceKubernetesPodSecurityPolicyRead(d *schema.ResourceData, meta interface{}) error {
  conn := meta.(*kubernetes.Clientset)

  // namespace not used here, so discarded with _
  _, name, err := idParts(d.Id())
  if err != nil {
    return err
  }
  log.Printf("[INFO] Reading pod security policy %s", name)
  svc, err := conn.ExtensionsV1beta1().PodSecurityPolicies().Get(name, meta_v1.GetOptions{})
  if err != nil {
    log.Printf("[DEBUG] Received error :%#v", err)
    return err
  }
  log.Printf("[DEBUG] Received pod security policy: %#v", svc)
  err = d.Set("metadata", flattenMetadata(svc.ObjectMeta, d))
  if err != nil {
    return err
  }

  flattened, err := flattenPodSecurityPolicySpec(svc.Spec)
  log.Printf("[DEBUG] Flattened pod security policy spec: %#v", flattened)
  err = d.Set("spec", flattened)
  if err != nil {
    return err
  }

  return nil
}

func resourceKubernetesPodSecurityPolicyUpdate(d *schema.ResourceData, meta interface{}) error {
  conn := meta.(*kubernetes.Clientset)

  // namespace not used here, so discarded with _
  _, name, err := idParts(d.Id())
  if err != nil {
    return err
  }

  ops := patchMetadata("metadata.0.", "/metadata/", d)
  if d.HasChange("spec") {
    diffOps, err := patchPodSecurityPolicySpec("spec.0.", "/spec", d)
    if err != nil {
      return err
    }
    ops = append(ops, *diffOps...)
  }
  data, err := ops.MarshalJSON()
  if err != nil {
    return fmt.Errorf("Failed to marshal update operations: %s", err)
  }
  log.Printf("[INFO] Updating pod security policy %q: %v", name, string(data))
  out, err := conn.ExtensionsV1beta1().PodSecurityPolicies().Patch(name, pkgApi.JSONPatchType, data)
  if err != nil {
    return fmt.Errorf("Failed to update pod security policy: %s",  err)
  }
  log.Printf("[INFO] Submitted updated pod security policy: %#v", out)
  d.SetId(buildId(out.ObjectMeta))

  return resourceKubernetesPodSecurityPolicyRead(d, meta)
}

func resourceKubernetesPodSecurityPolicyDelete(d *schema.ResourceData, meta interface{}) error {
  conn := meta.(*kubernetes.Clientset)

  // namespace not used here, so discarded with _
  _, name, err := idParts(d.Id())
  if err != nil {
    return err
  }
  log.Printf("[INFO] Deleting pod security policy: %#v", name)
  err = conn.ExtensionsV1beta1().PodSecurityPolicies().Delete(name, &meta_v1.DeleteOptions{})
  if err != nil {
    return err
  }

  log.Printf("[INFO] Pod security policy %s deleted", name)

  return nil
}

func resourceKubernetesPodSecurityPolicyExists(d *schema.ResourceData, meta interface{}) (bool, error) {
  conn := meta.(*kubernetes.Clientset)

  // namespace not used here, so discarded with _
  _, name, err := idParts(d.Id())
  if err != nil {
    return false, err
  }

  log.Printf("[INFO] Checking pod security policy %s", name)
  _, err = conn.ExtensionsV1beta1().PodSecurityPolicies().Get(name, meta_v1.GetOptions{})
  if err != nil {
    if statusErr, ok := err.(*errors.StatusError); ok && statusErr.ErrStatus.Code == 404 {
      return false, nil
    }
    log.Printf("[DEBUG] Received error: %#v", err)
  }
  return true, err
}

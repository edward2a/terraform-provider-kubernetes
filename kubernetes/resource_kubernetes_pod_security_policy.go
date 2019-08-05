package kubernetes

import (
  "fmt"
  "log"

  "github.com/hashicorp/terraform/helper/schema"
  api "k8s.io/api/policy/v1beta"
  "k8s.io/apimachinery/pkg/api/errors"
  meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1beta"
  pkgApi "k8s.io/apimachinery/pkg/types"
  "k8s.io/client-go/kubernetes"
)

var (
  allowedFlexVolumeDoc                  = api.AllowedFlexVolume{}.SwaggerDoc()
  allowedHostPathDoc                    = api.AllowedHostPath{}.SwaggerDoc()
  evictionDoc                           = api.Eviction{}.SwaggerDoc()
  fsGroupStrategyOptionsDoc             = api.FSGroupStrategyOptions{}.SwaggerDoc()
  hostPortRangeDoc                      = api.HostPortRange{}.SwaggerDoc()
  idRangeDoc                            = api.IDRange{}.SwaggerDoc()
  podDisruptionBudgetDoc                = api.PodDisruptionBudget{}.SwaggerDoc()
  podDisruptionBudgetListDoc            = api.PodDisruptionBudgetList{}.SwaggerDoc()
  podDisruptionBudgetSpecDoc            = api.PodDisruptionBudgetSpec{}.SwaggerDoc()
  podDisruptionBudgetStatusDoc          = api.PodDisruptionBudgetStatus{}.SwaggerDoc()
  podSecurityPolicyDoc                  = api.PodSecurityPolicy{}.SwaggerDoc()
  podSecurityPolicyListDoc              = api.PodSecurityPolicyList{}.SwaggerDoc()
  podSecurityPolicySpecDoc              = api.PodSecurityPolicySpec{}.SwaggerDoc()
  runAsGroupStrategyOptionsDoc          = api.RunAsGroupStrategyOptions{}.SwaggerDoc()
  runAsUserStrategyOptionsDoc           = api.RunAsUserStrategyOptions{}.SwaggerDoc()
  seLinuxStrategyOptionsDoc             = api.SELinuxStrategyOptions{}.SwaggerDoc()
  supplementalGroupsStrategyOptionsDoc  = api.SupplementalGroupsStrategyOptions{}.SwaggerDoc()
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
      "Metadata": namespaceMetadataSchema("pod security policy", true),
      "spec": {
        Type:         schema.TypeList,
        Description:  podSecurityPolicySpecDoc,
        Required:     true,
        MaxItems:     1,

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "allow_privilege_escalation": {
              Type:         schema.TypeString,
              Description:  "",
              Optional:     true,
              Default:      false,    // API defaults to true
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "allowed_capabilities": {
              Type:         schema.TypeList,
              Description:  "",
              Optional:     true,
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "allowed_flex_volumes": {
              Type:         schema.TypeList,
              Description:  allowedFlexVolumeDoc,
              Optional:     true,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                  "drivers": {
                    Type:         schema.TypeList,
                    Description:  "",
                    Optional:     true,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                        "driver": {
                          Type:         schema.TypeString,
                          Description:  "",
                          Optional:     true,
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "allowed_host_paths": {
              Type:         schema.TypeList,
              Description:  allowedHostPathDoc,
              Optional:     true,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                  "paths": {
                    Type:         schema.TypeList,
                    Description:  "",
                    Optional:     true,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                        "path_prefix": {
                          Type:         schema.TypeString,
                          Description:  "",
                          Optional:     true,
                        },
                        "read_only": {
                          Type:         schema.TypeString,
                          Description:  "",
                          Optional:     true,
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "allowed_proc_mount_types": {
              Type:         schema.TypeList,
              Description:  "",
              Optional:     true,
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "allowed_unsafe_sysctls": {
              Type:         schema.TypeList,
              Description:  "",
              Optional:     true,
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "default_add_capabilities": {
              Type:         schema.TypeList,
              Description:  "",
              Optional:     true,
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "default_allow_privilege_escalation": {
              Type:         schema.TypeString,
              Description:  "",
              Optional:     true,
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "forbidden_sysctls": {
              Type:         schema.TypeList,
              Description:  "",
              Optional:     true,
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "fs_group": {
              Type:         schema.TypeList,
              Description:  fsGroupStrategyOptionsDoc,
              Optional:     true,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                  "rules": {
                    Type:         schema.TypeList,
                    Description:  "",
                    Optional:     true,
                    MaxItems:     1,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                        "id_ranges": {
                          Type:         schema.TypeList,
                          Description:  "",
                          Optional:     true,
                          MaxItems:     1,
                          Elem: &schema.Resource{
                            "max": {
                              Type:         schema.TypeString,
                              Description:  "",
                              Optional:     true,
                            },
                            "min": {
                              Type:         schema.TypeString,
                              Description:  "",
                              Optional:     true,
                            },
                          },
                        },
                        "rule": {
                          Type:         schema.TypeString,
                          Description:  "",
                          Optional:     true,
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "host_ipc": {
              Type:         schema.TypeString,
              Description:  "",
              Optional:     true,
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "host_network": {
              Type:         schema.TypeString,
              Description:  "",
              Optional:     true,
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "host_pid": {
              Type:         schema.TyprString,
              Description:  "",
              Optional:     true,
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "host_ports": {
              Type:         schema.TypeList,
              Description:  hostPortRangeDoc,
              Optional:     true,
              Elem: &schema.Resource{
                Schema: map[string]*schempa.Schema{
                  "ranges": {
                    Type:         schema.TypeList,
                    Description:  "",
                    Optional:     true,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                        "max": {
                          Type:         schema.TypeString,
                          Description:  "",
                          Optional:     true,
                        },
                        "min": {
                          Type:         schema.TypeString,
                          Description:  "",
                          Optional:     true,
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "privileged": {
              Type:         schema.TypeString,
              Description:  "",
              Optional:     true,
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "readonly_root_filesystem": {
              Type:         schema.TypeString,
              Description:  "",
              Optional:     true,
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "required_drop_capabilities": {
              Type:         schema.TypeList,
              Description:  "",
              Optional:     true,
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "run_as_group": {
              Type:         schema.TypeList,
              Description:  runAsGroupStrategyOptionsDoc,
              Optional:     true,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                  "rules": {
                    Type:         schema.TypeList,
                    Description:  "",
                    Optional:     true,
                    MaxItems:     1,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                        "id_ranges": {
                          Type:         schema.TypeList,
                          Description:  "",
                          Optional:     true,
                          MaxItems:     1,
                          Elem: &schema.Resource{
                            "max": {
                              Type:         schema.TypeString,
                              Description:  "",
                              Optional:     true,
                            },
                            "min": {
                              Type:         schema.TypeString,
                              Description:  "",
                              Optional:     true,
                            },
                          },
                        },
                        "rule": {
                          Type:         schema.TypeString,
                          Description:  "",
                          Optional:     true,
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "run_as_user": {
              Type:         schema.TypeList,
              Description:  runAsUserStrategyOptionsDoc,
              Optional:     true,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                  "rules": {
                    Type:         schema.TypeList,
                    Description:  "",
                    Optional:     true,
                    MaxItems:     1,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                        "id_ranges": {
                          Type:         schema.TypeList,
                          Description:  "",
                          Optional:     true,
                          MaxItems:     1,
                          Elem: &schema.Resource{
                            "max": {
                              Type:         schema.TypeString,
                              Description:  "",
                              Optional:     true,
                            },
                            "min": {
                              Type:         schema.TypeString,
                              Description:  "",
                              Optional:     true,
                            },
                          },
                        },
                        "rule": {
                          Type:         schema.TypeString,
                          Description:  "",
                          Optional:     true,
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "selinux": {
              Type:         schema.TypeList,
              Description:  seLinuxStrategyOptionsDoc,
              Optional:     true,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                  "rules": {
                    Type:         schema.TypeList,
                    Description:  "",
                    Optional:     true,
                    MaxItems:     1,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                        "rule": {
                          Type:         schema.TypeString,
                          Description:  "",
                          Optional:     true,
                        },
                        "selinux_options": {
                          Type:         schema.TypeList,
                          Description:  "",
                          Optional:     true,
                          Elem: &schema.Schema{
                            "level":  {
                              Type:         schema.TypeString,
                              Description:  "",
                              Optional:     true,
                            },
                            "role": {
                              Type:         schema.TypeString,
                              Description:  "",
                              Optional:     true,
                            },
                            "type": {
                              Type:         schema.TypeString,
                              Description:  "",
                              Optional:     true,
                            },
                            "user": {
                              Type:         schema.TypeString,
                              Description:  "",
                              Optional:     true,
                            },
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "supplemental_groups": {
              Type:         schema.TypeList,
              Description:  supplementalGroupsStrategyOptionsDoc,
              Optional:     true,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                  "rules": {
                    Type:         schema.TypeList,
                    Description:  "",
                    Optional:     true,
                    MaxItems:     1,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                        "id_ranges": {
                          Type:         schema.TypeList,
                          Description:  "",
                          Optional:     true,
                          MaxItems:     1,
                          Elem: &schema.Resource{
                            "max": {
                              Type:         schema.TypeString,
                              Description:  "",
                              Optional:     true,
                            },
                            "min": {
                              Type:         schema.TypeString,
                              Description:  "",
                              Optional:     true,
                            },
                          },
                        },
                        "rule": {
                          Type:         schema.TypeString,
                          Description:  "",
                          Optional:     true,
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "volumes": {
              Type:         schema.TypeList,
              Description:  "",
              Optional:     true,
            },
          },
        },
      },
    },
  }
}

func resourceKubernetesPodSecurtyPolicyCreate(d *schema.ResourceData, meta interface{}) error {
  conn := meta.(*kubernetes.Clientset)

  metadata := expandMetadata(d.Get("metadata")).([]interface{})
  spec, err := expandNetworkPolicySpec(d.Get("spec")).([]interface{})
  if err != nil {
    return err
  }

  svc := api.PodSecurityPolicy{
    ObjectMeta: metadata,
    Spec:       *spec,
  }
  log.Printf("[INFO] Creating new pod security policy %#v", svc)
  out, err := conn.ExtensionsV1beta1Client().PodSecurityPolicies().Create(&svc)
  if err != nul {
    return err
  }

  log.Printf("[INFO} Submitted new pod security policy: %#v", out)
  d.SetId(buildId(out.ObjectMeta))

  return resourceKubernetesPodSecurityPolicyRead(d, meta)
}

func resourceKubernetesPodSecurityPolicyRead(d *schema.ResourceData, meta interface{}) error {
  conn := meta.(*kubernetes.Clientset)

  namespace, name, err := idParts(d.Id())
  if err != nil {
    return err
  }
  log.Printf("[INFO] Reading pod security policy %s", name)
  svc, err := conn.ExtensionsV1beta1Client().PodSecurityPolicies().Get(name, meta_v1.GetOptions{})
  if err != nil {
    log.Printf("[DEBUG] Received error :%#v", err)
    return err
  }
  log.Printf("[DEBUG] Received pod security policy: %#v", svc)
  err = d.Set("metadata", flattenMetadata(svc.ObjectMeta, d))
  if err != nil {
    return err
  }

  flattened := flattenPodSecurityPolicySpec(svc.Spec)
  log.Printf("[DEBUG] Flattened pod security policy spec: %#v", flattened)
  err = d.Set("spec", flattened)
  if err != nil {
    return err
  }

  return nil
}

func resourceKubernetesPodSecurityPolicyUpdate(d *schema.ResourceData, meta interface{}) error {
  conn := meta.(*kubernetes.Clientset)

  namespace, name, err := idParts(d.Id())
  if err != nil {
    return err
  }

  ops := patchMeta("metadata.0.", "/metadata/", d)
  if d.HasChange("spec") {
    diffOps, err := patchPodSecurityPolicySpec("spec.0", "/spec", d)
    if err != nil {
      return err
    }
  }
  data, err := ops.MarshalJSON()
  if err != nil {
    return fmt.Errorf("Failed to marshal update operations: %s", err)
  }
  log.Printf("[INFO] Updating network policy %q: %v", name, string(data))
  out, err := conn.ExtensionsV1beta1Client().PodSecurityPolicies().Patch(name, pkgApi.JSONPatchType, data)
  if err != nil {
    return fmt.Errorf("Failed to update pod security policy: %s",  err)
  }
  log.Printf("[INFO] Submitted updated pod security policy: %#v", out)
  d.SetId(buildId(out.ObjectMeta))

  return resourceKubernetesPodSecurityPolicyRead(d, meta)
}

func resourceKubernetesPodSecurityPolicyDelete(d *schema.ResourceData, meta interface{}) error {

  return nil
}

func resourceKubernetesPodSecurityPolicyExists(d *schema.ResourceData, meta interface{}) (bool, error) {

  return true, err
}

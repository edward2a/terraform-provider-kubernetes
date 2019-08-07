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
  allowedFlexVolumeDoc                  = policy_v1beta1.AllowedFlexVolume{}.SwaggerDoc()
  allowedHostPathDoc                    = policy_v1beta1.AllowedHostPath{}.SwaggerDoc()
  evictionDoc                           = policy_v1beta1.Eviction{}.SwaggerDoc()
  fsGroupStrategyOptionsDoc             = policy_v1beta1.FSGroupStrategyOptions{}.SwaggerDoc()
  hostPortRangeDoc                      = policy_v1beta1.HostPortRange{}.SwaggerDoc()
  idRangeDoc                            = policy_v1beta1.IDRange{}.SwaggerDoc()
  podDisruptionBudgetDoc                = policy_v1beta1.PodDisruptionBudget{}.SwaggerDoc()
  podDisruptionBudgetListDoc            = policy_v1beta1.PodDisruptionBudgetList{}.SwaggerDoc()
  podDisruptionBudgetSpecDoc            = policy_v1beta1.PodDisruptionBudgetSpec{}.SwaggerDoc()
  podDisruptionBudgetStatusDoc          = policy_v1beta1.PodDisruptionBudgetStatus{}.SwaggerDoc()
  podSecurityPolicyDoc                  = policy_v1beta1.PodSecurityPolicy{}.SwaggerDoc()
  podSecurityPolicyListDoc              = policy_v1beta1.PodSecurityPolicyList{}.SwaggerDoc()
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
      "metadata": namespacedMetadataSchema("pod security policy", true),
      "spec": {
        Type:         schema.TypeList,
        //Description:  podSecurityPolicySpecDoc,
        Required:     true,
        MaxItems:     1,

        Elem: &schema.Resource{
          Schema: map[string]*schema.Schema{
            "allow_privilege_escalation": {
              Type:         schema.TypeString,
              //Description:  "",
              Optional:     true,
              Default:      false,    // API defaults to true
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "allowed_capabilities": {
              Type:         schema.TypeList,
              //Description:  "",
              Optional:     true,
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "allowed_flex_volumes": {
              Type:         schema.TypeList,
              //Description:  allowedFlexVolumeDoc,
              Optional:     true,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
               /* "drivers": {
                    Type:         schema.TypeList,
                    //Description:  "",
                    Optional:     true,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                 */     "driver": {
                          Type:         schema.TypeString,
                          //Description:  "",
                          Optional:     true,
                        },
                    //},
                  //},
                //},
                },
              },
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "allowed_host_paths": {
              Type:         schema.TypeList,
              //Description:  allowedHostPathDoc,
              Optional:     true,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                /*"paths": {
                    Type:         schema.TypeList,
                    //Description:  "",
                    Optional:     true,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                */      "path_prefix": {
                          Type:         schema.TypeString,
                          //Description:  "",
                          Optional:     true,
                        },
                        "read_only": {
                          Type:         schema.TypeString,
                          //Description:  "",
                          Optional:     true,
                        },
                    //},
                  //},
                //},
                },
              },
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "allowed_proc_mount_types": {
              Type:         schema.TypeList,
              //Description:  "",
              Optional:     true,
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "allowed_unsafe_sysctls": {
              Type:         schema.TypeList,
              //Description:  "",
              Optional:     true,
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "default_add_capabilities": {
              Type:         schema.TypeList,
              //Description:  "",
              Optional:     true,
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "default_allow_privilege_escalation": {
              Type:         schema.TypeString,
              //Description:  "",
              Optional:     true,
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "forbidden_sysctls": {
              Type:         schema.TypeList,
              //Description:  "",
              Optional:     true,
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "fs_group": {
              Type:         schema.TypeList,
              //Description:  fsGroupStrategyOptionsDoc,
              Optional:     true,
              MaxItems:     1,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                //"rules": {
                //  Type:         schema.TypeList,
                    //Description:  "",
                //  Optional:     true,
                //  MaxItems:     1,
                //  Elem: &schema.Resource{
                //    Schema: map[string]*schema.Schema{
                        "ranges": {
                          Type:         schema.TypeList,
                          //Description:  "",
                          Optional:     true,
                          MaxItems:     1,
                          Elem: &schema.Resource{
                            Schema: map[string]*schema.Schema{
                              "max": {
                                Type:         schema.TypeString,
                                //Description:  "",
                                Optional:     true,
                              },
                              "min": {
                                Type:         schema.TypeString,
                                //Description:  "",
                                Optional:     true,
                              },
                            },
                          },
                        },
                        "rule": {
                          Type:         schema.TypeString,
                          //Description:  "",
                          Optional:     true,
                        },
                //    },
                //  },
                //},
                },
              },
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "host_ipc": {
              Type:         schema.TypeString,
              //Description:  "",
              Optional:     true,
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "host_network": {
              Type:         schema.TypeString,
              //Description:  "",
              Optional:     true,
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "host_pid": {
              Type:         schema.TypeString,
              //Description:  "",
              Optional:     true,
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "host_ports": {
              Type:         schema.TypeList,
              //Description:  hostPortRangeDoc,
              Optional:     true,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                  "ranges": {
                    Type:         schema.TypeList,
                    //Description:  "",
                    Optional:     true,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                        "max": {
                          Type:         schema.TypeString,
                          //Description:  "",
                          Optional:     true,
                        },
                        "min": {
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
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "privileged": {
              Type:         schema.TypeString,
              //Description:  "",
              Optional:     true,
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "readonly_root_filesystem": {
              Type:         schema.TypeString,
              //Description:  "",
              Optional:     true,
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "required_drop_capabilities": {
              Type:         schema.TypeList,
              //Description:  "",
              Optional:     true,
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "run_as_group": {
              Type:         schema.TypeList,
              //Description:  runAsGroupStrategyOptionsDoc,
              Optional:     true,
              MaxItems:     1,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                //"rules": {
                //  Type:         schema.TypeList,
                    //Description:  "",
                //  Optional:     true,
                //  MaxItems:     1,
                //  Elem: &schema.Resource{
                //    Schema: map[string]*schema.Schema{
                        "ranges": {
                          Type:         schema.TypeList,
                          //Description:  "",
                          Optional:     true,
                          MaxItems:     1,
                          Elem: &schema.Resource{
                            Schema: map[string]*schema.Schema{
                              "max": {
                                Type:         schema.TypeString,
                                //Description:  "",
                                Optional:     true,
                              },
                              "min": {
                                Type:         schema.TypeString,
                                //Description:  "",
                                Optional:     true,
                              },
                            },
                          },
                        },
                        "rule": {
                          Type:         schema.TypeString,
                          //Description:  "",
                          Optional:     true,
                        },
                //    },
                //  },
                //},
                },
              },
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "run_as_user": {
              Type:         schema.TypeList,
              //Description:  runAsUserStrategyOptionsDoc,
              Optional:     true,
              MaxItems:     1,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                //"rules": {
                //  Type:         schema.TypeList,
                    //Description:  "",
                //  Optional:     true,
                //  MaxItems:     1,
                //  Elem: &schema.Resource{
                //    Schema: map[string]*schema.Schema{
                        "ranges": {
                          Type:         schema.TypeList,
                          //Description:  "",
                          Optional:     true,
                          MaxItems:     1,
                          Elem: &schema.Resource{
                            Schema: map[string]*schema.Schema{
                              "max": {
                                Type:         schema.TypeString,
                                //Description:  "",
                                Optional:     true,
                              },
                              "min": {
                                Type:         schema.TypeString,
                                //Description:  "",
                                Optional:     true,
                              },
                            },
                          },
                        },
                        "rule": {
                          Type:         schema.TypeString,
                          //Description:  "",
                          Optional:     true,
                        },
                //    },
                //  },
                //},
                },
              },
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "selinux": {
              Type:         schema.TypeList,
              //Description:  seLinuxStrategyOptionsDoc,
              Optional:     true,
              MaxItems:     1,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                /*"rules": {
                    Type:         schema.TypeList,
                    //Description:  "",
                    Optional:     true,
                    MaxItems:     1,
                    Elem: &schema.Resource{
                      Schema: map[string]*schema.Schema{
                */      "rule": {
                          Type:         schema.TypeString,
                          //Description:  "",
                          Optional:     true,
                        },
                        "selinux_options": {
                          Type:         schema.TypeList,
                          //Description:  "",
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
                //    },
                //  },
                //},
                },
              },
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "supplemental_groups": {
              Type:         schema.TypeList,
              //Description:  supplementalGroupsStrategyOptionsDoc,
              Optional:     true,
              MaxItems:     1,
              Elem: &schema.Resource{
                Schema: map[string]*schema.Schema{
                //"rules": {
                //  Type:         schema.TypeList,
                //  //Description:  "",
                //  Optional:     true,
                //  MaxItems:     1,
                //  Elem: &schema.Resource{
                //    Schema: map[string]*schema.Schema{
                        "ranges": {
                          Type:         schema.TypeList,
                          //Description:  "",
                          Optional:     true,
                          MaxItems:     1,
                          Elem: &schema.Resource{
                            Schema: map[string]*schema.Schema{
                              "max": {
                                Type:         schema.TypeString,
                                //Description:  "",
                                Optional:     true,
                              },
                              "min": {
                                Type:         schema.TypeString,
                                //Description:  "",
                                Optional:     true,
                              },
                            },
                          },
                        },
                        "rule": {
                          Type:         schema.TypeString,
                          //Description:  "",
                          Optional:     true,
                        },
                //    },
                //  },
                //},
                },
              },
            },
      //  },
      //},

      //Elem: &schema.Resource{
      //  Schema: map[string]*schema.Schema{
            "volumes": {
              Type:         schema.TypeList,
              //Description:  "",
              Optional:     true,
            },
          },
        },
      },
    },
  }
}

func resourceKubernetesPodSecurityPolicyCreate(d *schema.ResourceData, meta interface{}) error {
  conn := meta.(*kubernetes.Clientset)

  //TODO type validation, d.Get("metadata") == interface{} ??
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

  namespace, name, err := idParts(d.Id())
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

  namespace, name, err := idParts(d.Id())
  if err != nil {
    return err
  }

  ops := patchMetadata("metadata.0.", "/metadata/", d)
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

  namespace, name, err := idParts(d.Id())
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

  namespace, name, err := idParts(d.Id())
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

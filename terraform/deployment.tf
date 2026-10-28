resource "kubernetes_namespace" "vulntracker" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/name"       = "vulntracker"
      "app.kubernetes.io/part-of"    = "vulntracker-suite"
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
    }
  }
}

resource "kubernetes_service_account" "api" {
  metadata {
    name      = "vulntracker-api-sa"
    namespace = kubernetes_namespace.vulntracker.metadata[0].name
    annotations = {
      "azure.workload.identity/client-id" = var.workload_client_id
      "azure.workload.identity/tenant-id" = var.tenant_id
    }
    labels = {
      "azure.workload.identity/use" = "true"
    }
  }
  automount_service_account_token = false
}

resource "kubernetes_config_map" "api_config" {
  metadata {
    name      = "vulntracker-api-config"
    namespace = kubernetes_namespace.vulntracker.metadata[0].name
  }

  data = {
    PORT               = "8000"
    ENVIRONMENT        = var.environment
    NOTIFY_SERVICE_URL = "http://vulntracker-notify.vulntracker.svc.cluster.local:3001"
  }
}

resource "kubernetes_manifest" "secret_provider_class" {
  manifest = {
    apiVersion = "secrets-store.csi.x-k8s.io/v1"
    kind       = "SecretProviderClass"
    metadata = {
      name      = "vulntracker-azure-kv"
      namespace = var.namespace
    }
    spec = {
      provider = "azure"
      parameters = {
        usePodIdentity = "false"
        clientID       = var.workload_client_id
        keyvaultName   = var.keyvault_name
        tenantId       = var.tenant_id
        objects        = <<-EOT
          array:
            - |
              objectName: jwt-secret-key
              objectType: secret
              objectVersion: ""
            - |
              objectName: db-password
              objectType: secret
              objectVersion: ""
            - |
              objectName: admin-api-key
              objectType: secret
              objectVersion: ""
        EOT
      }
      secretObjects = [
        {
          secretName = "vulntracker-synced-secrets"
          type       = "Opaque"
          data = [
            {
              objectName = "jwt-secret-key"
              key        = "SECRET_KEY"
            },
            {
              objectName = "db-password"
              key        = "DB_PASSWORD"
            },
            {
              objectName = "admin-api-key"
              key        = "ADMIN_API_KEY"
            }
          ]
        }
      ]
    }
  }
  depends_on = [kubernetes_namespace.vulntracker]
}

resource "kubernetes_deployment" "api" {
  metadata {
    name      = "vulntracker-api"
    namespace = kubernetes_namespace.vulntracker.metadata[0].name
    labels = {
      "app.kubernetes.io/name"      = "vulntracker-api"
      "app.kubernetes.io/component" = "backend"
      "app.kubernetes.io/version"   = var.image_tag
    }
  }

  spec {
    replicas = var.replica_count

    selector {
      match_labels = {
        "app.kubernetes.io/name" = "vulntracker-api"
      }
    }

    template {
      metadata {
        labels = {
          "app.kubernetes.io/name"      = "vulntracker-api"
          "app.kubernetes.io/component" = "backend"
          "azure.workload.identity/use" = "true"
        }
      }

      spec {
        service_account_name            = kubernetes_service_account.api.metadata[0].name
        automount_service_account_token = false

        security_context {
          run_as_non_root = true
          run_as_user     = 10001
          run_as_group    = 10001
          fs_group        = 10001
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name              = "api"
          image             = "${var.image_repository}:${var.image_tag}"
          image_pull_policy = "IfNotPresent"

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = false
            run_as_non_root            = true
            run_as_user                = 10001
            capabilities {
              drop = ["ALL"]
            }
          }

          port {
            container_port = 8000
            name           = "http"
          }

          resources {
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
            requests = {
              cpu    = "100m"
              memory = "128Mi"
            }
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = 8000
            }
            initial_delay_seconds = 10
            period_seconds        = 15
            timeout_seconds       = 3
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = 8000
            }
            initial_delay_seconds = 5
            period_seconds        = 10
            timeout_seconds       = 3
            failure_threshold     = 2
          }

          env_from {
            config_map_ref {
              name = kubernetes_config_map.api_config.metadata[0].name
            }
          }

          env_from {
            secret_ref {
              name = "vulntracker-synced-secrets"
            }
          }

          volume_mount {
            name       = "secrets-store-inline"
            mount_path = "/mnt/secrets-store"
            read_only  = true
          }

          volume_mount {
            name       = "tmp-volume"
            mount_path = "/tmp"
          }
        }

        volume {
          name = "secrets-store-inline"
          csi {
            driver            = "secrets-store.csi.k8s.io"
            read_only         = true
            volume_attributes = {
              "secretProviderClass" = "vulntracker-azure-kv"
            }
          }
        }

        volume {
          name = "tmp-volume"
          empty_dir {}
        }
      }
    }
  }
}

resource "kubernetes_service" "api" {
  metadata {
    name      = "vulntracker-api"
    namespace = kubernetes_namespace.vulntracker.metadata[0].name
    labels = {
      "app.kubernetes.io/name" = "vulntracker-api"
    }
  }

  spec {
    selector = {
      "app.kubernetes.io/name" = "vulntracker-api"
    }

    port {
      port        = 8000
      target_port = 8000
      name        = "http"
    }

    type = "ClusterIP"
  }
}

resource "kubernetes_network_policy" "api_policy" {
  metadata {
    name      = "vulntracker-api-netpol"
    namespace = kubernetes_namespace.vulntracker.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name" = "vulntracker-api"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "ingress-controller"
          }
        }
      }
      ports {
        port     = "8000"
        protocol = "TCP"
      }
    }

    egress {
      # Allow DNS egress to kube-dns
      to {
        namespace_selector {}
        pod_selector {
          match_labels = {
            "k8s-app" = "kube-dns"
          }
        }
      }
      ports {
        port     = "53"
        protocol = "UDP"
      }
      ports {
        port     = "53"
        protocol = "TCP"
      }
    }

    egress {
      # Allow egress to notification service within namespace
      to {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "vulntracker-notify"
          }
        }
      }
      ports {
        port     = "3001"
        protocol = "TCP"
      }
    }
  }
}


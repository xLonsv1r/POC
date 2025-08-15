
terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
  backend "gcs" {
    bucket = "testing-demo-cluster-terraform"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

data "google_client_config" "provider" {

}

data "google_container_cluster" "primary" {
  name     = google_container_cluster.demo-cloud-gke.name
  location = var.zone
}


provider "kubernetes" {
  host                   = "https://${data.google_container_cluster.primary.endpoint}"
  token                  = data.google_client_config.provider.access_token
  cluster_ca_certificate = base64decode(data.google_container_cluster.primary.master_auth[0].cluster_ca_certificate)
}

provider "helm" {
  kubernetes = {
    host                   = "https://${data.google_container_cluster.primary.endpoint}"
    token                  = data.google_client_config.provider.access_token
    cluster_ca_certificate = base64decode(data.google_container_cluster.primary.master_auth[0].cluster_ca_certificate)
  }
}

resource "google_compute_network" "vpc" {
  name                    = var.network_name
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

# subnet
resource "google_compute_subnetwork" "subnet" {
  name          = var.subnet_name
  ip_cidr_range = "10.0.0.0/16"
  region        = var.region
  network       = google_compute_network.vpc.id

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.1.0.0/16"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.2.0.0/16"
  }
}

# firewall rule to allow internal communication
resource "google_compute_firewall" "allow_internal" {
  name    = "${var.network_name}-allow-internal"
  network = google_compute_network.vpc.name

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  source_ranges = [
    "10.0.0.0/16",
    "10.1.0.0/16",
    "10.2.0.0/16"
  ]
}

# gke cluster
resource "google_container_cluster" "demo-cloud-gke" {
  name     = var.cluster_name
  location = var.zone

  remove_default_node_pool = true
  initial_node_count       = 1
  network                  = google_compute_network.vpc.name
  subnetwork               = google_compute_subnetwork.subnet.name
  deletion_protection      = false
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }
  network_policy {
    enabled = true
  }
  addons_config {
    horizontal_pod_autoscaling {
      disabled = false
    }
    http_load_balancing {
      disabled = false
    }
    network_policy_config {
      disabled = false
    }
  }


  # enable workload identity
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # maintenance policy
  maintenance_policy {
    daily_maintenance_window {
      start_time = "03:00"
    }
  }

  # logging and monitoring
  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"
}

# node pool
resource "google_container_node_pool" "main-node" {
  name       = "${var.cluster_name}-node-pool"
  location   = var.zone
  cluster    = google_container_cluster.demo-cloud-gke.name
  node_count = var.node_count

  node_config {
    preemptible  = true
    machine_type = var.machine_type
    disk_size_gb = 50
    disk_type    = "pd-standard"
    image_type   = "ubuntu_containerd"

    # google recommends custom service accounts that have cloud-platform scope and permissions granted via iam roles.
    service_account = google_service_account.gke_node_sa.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]

    labels = {
      env = "dev"
    }

    tags = ["gke-node", "${var.cluster_name}-node"]

    metadata = {
      disable-legacy-endpoints = "true"
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  upgrade_settings {
    strategy        = "SURGE"
    max_surge       = 1
    max_unavailable = 0
  }
}

# service account for gke nodes
resource "google_service_account" "gke_node_sa" {
  account_id   = "${var.cluster_name}-node-sa"
  display_name = "gke node service account"
}


resource "google_project_iam_member" "log_writer" {
  role    = "roles/logging.logWriter"
  project = var.project_id
  member  = "serviceAccount:${google_service_account.gke_node_sa.email}"
}
resource "google_project_iam_member" "monitoring_view" {
  role    = "roles/monitoring.viewer"
  project = var.project_id
  member  = "serviceAccount:${google_service_account.gke_node_sa.email}"
}
resource "google_project_iam_member" "object_viewer" {
  role    = "roles/storage.objectViewer"
  project = var.project_id
  member  = "serviceAccount:${google_service_account.gke_node_sa.email}"
}

################################
#  HELM CHARTS                 #
################################

resource "helm_release" "prometheus_operator_crds" {
  name       = "prometheus-operator-crds"
  namespace  = "default"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "prometheus-operator-crds"
  version    = "21.0.0"
}

resource "helm_release" "victoriametrics" {
  name             = "monitoring"
  namespace        = "monitoring"
  create_namespace = true

  repository = "https://victoriametrics.github.io/helm-charts/"
  chart      = "victoria-metrics-k8s-stack"
  version    = "0.52.0"

  values = [
    file("helm/vm-k8s-stack.yaml")
  ]
}

resource "helm_release" "cert_manager" {
  name             = "cert-manager"
  repository       = "https://charts.jetstack.io"
  chart            = "cert-manager"
  version          = "v1.18.1"
  namespace        = "cert-manager"
  create_namespace = true
  values = [
    file("helm/cert-manager.yaml")
  ]
}

resource "helm_release" "nginx_ingress" {
  name             = "nginx-ingress"
  repository       = "https://kubernetes.github.io/ingress-nginx"
  chart            = "ingress-nginx"
  namespace        = "ingress-nginx"
  create_namespace = true
  version          = "4.12.3"

  values = [
    file("helm/nginx.yaml")
  ]
  depends_on = [
    helm_release.prometheus_operator_crds
  ]
}

resource "helm_release" "vector-aggregator" {
  repository       = "https://helm.vector.dev"
  name             = "vector-aggregator"
  chart            = "vector"
  create_namespace = true
  namespace        = "logging"
  version          = "0.40.0"
  values = [
    file("./helm/vector-aggregator.tpl.yaml"),
  ]
}



resource "helm_release" "vector-agent" {
  repository       = "https://helm.vector.dev"
  name             = "vector-agent"
  chart            = "vector"
  create_namespace = true
  namespace        = "logging"
  version          = "0.40.0"
  values = [
    file("./helm/vector-agent-values.yaml"),
  ]
}


resource "helm_release" "loki" {
  name             = "loki"
  namespace        = "observability"
  create_namespace = true

  repository = "https://grafana.github.io/helm-charts"
  chart      = "loki"
  version    = "6.36.0"

  values = [<<-YAML
    deploymentMode: SingleBinary

    read:    { replicas: 0 }
    write:   { replicas: 0 }
    backend: { replicas: 0 }

    chunksCache:
      enabled: false
    resultsCache:
      enabled: false
    lokiCanary:
      enabled: false
    test:
      enabled: false
    loki:
      auth_enabled: false
      storage:
        type: filesystem
      # Minimal schema for filesystem TSDB
      schemaConfig:
        configs:
          - from: "2024-01-01"
            store: tsdb
            object_store: filesystem
            schema: v13
            index:
              prefix: loki_index_
              period: 24h
      commonConfig:
        replication_factor: 1

    singleBinary:
      replicas: 1
      persistence:
        enabled: true
        size: 20Gi
        storageClass: null  

    gateway:
      enabled: false

    serviceMonitor:
      enabled: false
  YAML
  ]
}
resource "kubernetes_manifest" "letsencrypt_monitoring_issuer" {
  manifest = {
    apiVersion = "cert-manager.io/v1"
    kind       = "Issuer"
    metadata = {
      name      = "letsencrypt-prod"
      namespace = "monitoring"
    }
    spec = {
      acme = {
        server  = "https://acme-v02.api.letsencrypt.org/directory"
        email   = "testingd574@gmail.com"
        profile = "tlsserver"

        privateKeySecretRef = {
          name = "letsencrypt-prod"
        }

        solvers = [
          {
            http01 = {
              ingress = {
                ingressClassName = "nginx"
              }
            }
          }
        ]
      }
    }
  }
}

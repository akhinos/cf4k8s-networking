# CF for K8s networking

<!-- TOC depthFrom:2 depthTo:5 withLinks:1 updateOnSave:1 orderedList:0 -->
- [Logical Network Traffic](#logical-network-traffic)
- [Physical Network Traffic](#physical-network-traffic)
- [Envoy](#envoy)
- [Debugging](#debugging)
- [CloudFoundry, Istio and Envoy Config Diffs](#cloudfoundry-istio-and-envoy-config-diffs)

<!-- /TOC -->

## Logical Network Traffic

![](doc/LogicalNetwork.png)

| Artefact                                                                                                            | Description                                                                     |
| ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Client                                                                                                              | A client which would like to talk to the application                            |
| [Service(LoadBalancer)](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/) | External Load Balancer                                                          |
| [Gateway](https://istio.io/docs/reference/config/networking/gateway/)                                               |                                                                                 |
| [Virtual Service](https://istio.io/docs/reference/config/networking/virtual-service/)                               | How you route your traffic to a given destination. Refers to kubernetes service |
| [App Service](https://kubernetes.io/docs/concepts/services-networking/service/)                                     | Kubernetes service, which is used to route the traffic to the application pod   |
| app                                                                                                                 | The application itself                                                          |

## Physical Network Traffic

![](doc/Network.png)

| Artefact                                                                                                                                                                                         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Client | A client which would like to talk to the application.|
| Developer | The developer deploys the application to Cloud Foundry using `cf push`. During this action the Cloud Controller ensures that the application is built and deployed to kubernetes. Additionally the Cloud Controller creates a `Route CR`.|
| [Service(LoadBalancer)](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/)                                                                              | Exposes the Service externally using a cloud provider’s load balancer. <br/>[An example configuration](examples/k8s-configs/service-istio-ingressgateway.yaml)                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| [IngressGateway](https://istio.io/docs/reference/config/networking/gateway/)                                                                                                                     | The `IngressGateway` is responsible to route the network traffic to different locations like system services of applications. Istio is using [Envoy](https://www.envoyproxy.io/) for this purpose. Envoy is configured by Pilot(see below). In cf-for-k8s, only `VirtualServices` are used to configure the routes. For details see Routes below. The `IngressGateway` is implemented as [`DaemonSet`](https://istio.io/docs/reference/config/networking/gateway/). A `DaemonSet` ensures that all Nodes run a copy of this gateway.<br/>[An example configuration](examples/k8s-configs/istio-ingressgateway.yaml)  |
| [Pilot](https://istio.io/docs/ops/deployment/architecture/#pilot)                                                                                                                                | Pilot converts high level routing rules (e.g. `Gateways` or `VirtualServices`) that control traffic behavior into Envoy-specific configurations, and propagates them to the sidecars at runtime. |
| [App Service](https://kubernetes.io/docs/concepts/services-networking/service/)  | Kubernetes service, which is used to route the traffic to the application pod.|
| [System Service](https://kubernetes.io/docs/concepts/services-networking/service/)  | Kubernetes service, which is used to route the traffic to the application pod.|
| Application | This is the application, which is deployed by the developer and used by the client. The inbound traffic is routed through the Envoy, which is running in a sidecar.
| [Sidecar](https://istio.io/docs/reference/config/networking/sidecar/) | Every instance(replica) of an app has a sidecar Envoy, which runs in parallel with the app. These Envoys monitors everything about the application.|
| [Cloud Controller](https://docs.cloudfoundry.org/concepts/architecture/cloud-controller.html)| The Cloud Controller in Cloud Foundry (CF) provides REST API endpoints for clients (developers) to access the system.|
| [RouteController && Route CR](https://github.com/cloudfoundry/cf-k8s-networking#architecture) | The RouteController watches for updates to the `Route CR` (Route Custom Resource) and translates these into `Kubernetes Service` and `Istio VirtualService` objects.|
| [Eirini ](https://github.com/cloudfoundry-incubator/eirini#what-is-eirini)| Eirini is a Kubernetes backend for Cloud Foundry. It create `StatefulSet`s to deply the applications. |
| [Gateway](https://istio.io/docs/reference/config/networking/gateway/) | Cloud Foundry uses one single `Gateway` to route the network traffic.|
| [Virtual Service for System Services](https://istio.io/docs/reference/config/networking/virtual-service/) | During installation a `VirtualService` is created for each system service: <ul><li>Cloud Controller `api.cf...`</li><li>Log Cache `log-cache.cf...`</li><li>UAA `uaa.cf...`, `*.uaa.cf...`, `login.cf...`, `*.login.cf...` </li></ul>|
|  [Virtual Service for Applications](https://istio.io/docs/reference/config/networking/virtual-service/)| For each application a `VirtualService` is created. <br/>[An example configuration](examples/k8s-configs/app-virtualservice.yaml). <br/>This `VirtualService` is also responsible to add the required HTTP headers (e.g. `CF-App-Id`). Each `VirtualService` refers to a kubernetes service. [`DestinationRules`](https://istio.io/docs/concepts/traffic-management/#destination-rules) are also part of Istio traffic management. Using destination rules you can configure what happens to traffic for that destination (e.g. traffic policy). <br/>|

### Istiod architecture changes
Current (v1.4) implementation features three components:

- Pilot
- Mixer
- Citadel

https://archive.istio.io/v1.4/docs/concepts/security/architecture.svg

The upcoming architecture will merge them into a single `istiod` component:

https://istio.io/latest/docs/concepts/security/arch-sec.svg

## Envoy

Istio’s traffic management model relies on the Envoy proxies that are deployed along with apps.

![](doc/envoy.png)

| Artefact                                                                                                                                                                                         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Downstream Host | A client connecting to Envoy in order to reach a backend app / service|
| Listener | A frontend exposed by Envoy that allows downstream hosts to connect, e.g. 0.0.0.0:443|
| Filter | Pluggable logic that allows traffic manipulation and routing decisions to upstream clusters|
| Route | Configuration to which cluster the traffic is forwarded|
| Upstream Cluster | Endpoints that requests are forwarded to by Envoy using load balancing|

See [Envoy termonology](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/intro/terminology)

An example of simple [envoy configuration](examples/simple-envoy.yaml)

For more details see [request flow](https://www.envoyproxy.io/docs/envoy/latest/intro/life_of_a_request#request-flow)

The istio documentation has some information on how-to retrieve the current configuration of the sidecar and ingress envoys in a cluster using the [`istioctl`](https://istio.io/docs/ops/diagnostic-tools/proxy-cmd/). It is also possible to directly use envoy's [admin endpoint](https://www.envoyproxy.io/docs/envoy/latest/operations/admin) on port 15000. For example, dump config via a GET on `/config_dump` or examine endpoints via a GET on `/clusters?format=json`.

In the istio case other envoy proxy runs on the same node (as sidecar container) as the app on the upstream host.

## CloudFoundry, Istio and Envoy Config Diffs
This section describes what happens during common cf push and map-route use-cases.
For this purpose, a single app `test-app-a` is pushed, then another app `test-app-b`.
Finally, an additional route is mapped to `test-app-b` and the effects on CF, istio and envoy layers are documented.

### Push Single App
CF:

1. A new CR of kind "Route" gets created: `/apis/networking.cloudfoundry.org/v1alpha1/namespaces/cf-workloads/routes/<UUID>`
1. The spec contains the new route information:
```
spec:
  destinations:
  - app:
      guid: 292c7ae2-8d4c-449c-bd56-ec40ca644d57
      process:
        type: web
    guid: 7afcae7d-d2ff-4310-9e74-2ec9ca4cca19
    port: 8080
    selector:
      matchLabels:
        cloudfoundry.org/app_guid: 292c7ae2-8d4c-449c-bd56-ec40ca644d57
        cloudfoundry.org/process_type: web
  domain:
    internal: false
    name: cf.cf4k8s.istio.shoot.canary.k8s-hana.ondemand.com
  host: test-app-a
  path: ""
  url: test-app-a.cf.cf4k8s.istio.shoot.canary.k8s-hana.ondemand.com
```

Istio:

1. A new VirtualService gets created: `/apis/networking.istio.io/v1alpha3/namespaces/cf-workloads/virtualservices/vs-<unique name>`
1. The spec contains the public DNS name of the app, the service name to which traffic will be routed as well as HTTP headers to set.
```yaml
 spec:
    gateways:
    - cf-system/istio-ingressgateway
    hosts:
    - test-app-b.cf.cf4k8s.istio.shoot.canary.k8s-hana.ondemand.com
    http:
    - route:
      - destination:
          host: s-833a86e8-414f-4ac7-882b-6bc0c3c40366
        headers:
          request:
            set:
              CF-App-Id: 673ab4f3-101c-41a6-b1e3-aca13da1dd45
              CF-App-Process-Type: web
              CF-Organization-Id: e9aab7d8-298f-4aa7-9a77-46a721a36197
              CF-Space-Id: e7bb5fa9-9496-4179-b244-806b268a8c64
          response: {}
```

Ingress Envoy:

1. Envoy will pick up ingress spec from istio to map a host name to a service name
2. A new cluster entry is added to the ingress envoy config. (Don't confuse cluster with kubernetes cluster - it's an envoy backend)
   The cluster entry contains info needed for the ingress envoy to open a TLS session with the app sidecar envoy
```json
            "name": "outbound|8080||s-833a86e8-414f-4ac7-882b-6bc0c3c40366.cf-workloads.svc.cluster.local",
            "transport_socket_matches": [
              {
                "match": {
                  "tlsMode": "istio"
                },
                "name": "tlsMode-istio",
                "transport_socket": {
                  "name": "tls",
                  "typed_config": {
                    "@type": "type.googleapis.com/envoy.api.v2.auth.UpstreamTlsContext",
                    "common_tls_context": {
                      "alpn_protocols": [
                        "istio"
                      ],
                      "tls_certificates": [
                        {
                          "certificate_chain": {
                            "filename": "/etc/certs/cert-chain.pem"
                          },
                          "private_key": {
                            "filename": "/etc/certs/key.pem"
                          }
                        }
                      ],
                      "validation_context": {
                        "trusted_ca": {
                          "filename": "/etc/certs/root-cert.pem"
                        },
                        "verify_subject_alt_name": [
                          "spiffe://cluster.local/ns/cf-workloads/sa/eirini-privileged"
                        ]
                      }
                    },
                    "sni": "outbound_.8080_._.s-833a86e8-414f-4ac7-882b-6bc0c3c40366.cf-workloads.svc.cluster.local"
                  }
                }
              },
```
3. A route entry is added so that the ingress envoy knows how a host name is mapped to a service name.
   Request headers are added that will be forwarded to the cf app.
```json
              {
                "domains": [
                  "test-app-a.cf.c21s-1.c21s-dev.shoot.canary.k8s-hana.ondemand.com",
                  "test-app-a.cf.c21s-1.c21s-dev.shoot.canary.k8s-hana.ondemand.com:80"
                ],
                "name": "test-app-a.cf.c21s-1.c21s-dev.shoot.canary.k8s-hana.ondemand.com:80",
                "routes": [
                  {
                    "decorator": {
                      "operation": "s-ef9c974d-adfd-4552-8fcd-19e17f84d8dc.cf-workloads.svc.cluster.local:8080/*"
                    },
                    "match": {
                      "prefix": "/"
                    },
                    "metadata": {
                      "filter_metadata": {
                        "istio": {
                          "config": "/apis/networking/v1alpha3/namespaces/cf-workloads/virtual-service/vs-e940065c708e484a1a3ce9bbde53f1316b5c1d078bbff9825ccf0e80e05e0073"
                        }
                      }
                    },
                    "request_headers_to_add": [
                      {
                        "append": false,
                        "header": {
                          "key": "CF-App-Id",
                          "value": "eb1534db-8765-430d-adfe-77fd1a8e45a9"
                        }
                      },
                      {
                        "append": false,
                        "header": {
                          "key": "CF-App-Process-Type",
                          "value": "web"
                        }
                      },
                      {
                        "append": false,
                        "header": {
                          "key": "CF-Organization-Id",
                          "value": "04a73274-9280-4b99-9abc-e44e3ff4a74e"
                        }
                      },
                      {
                        "append": false,
                        "header": {
                          "key": "CF-Space-Id",
                          "value": "8d18b884-729c-4239-9b88-39c4964a3f86"
                        }
                      }
                    ],
                    "route": {
                      "cluster": "outbound|8080||s-ef9c974d-adfd-4552-8fcd-19e17f84d8dc.cf-workloads.svc.cluster.local",
                      (...)
                    },
                    (...)
                  }
                ]
              },
```
4. As the listeners for port 80 and port 443 are existing, no changes for listeners.

App Sidecar Envoy

1. When the sidecar gets injected, iptables rules are added that will capture all inbound traffic and forward it to 0.0.0.0:15006
2. Another rule captures all outbound traffic and forwards it to 0.0.0.0:15001
3. Envoy is started with uid and gid 1337 and an iptables rule is established that skips traffic capture for that user. This way an endless loop
is prevented.

```bash
-A PREROUTING -p tcp -j ISTIO_INBOUND                             # Capture all inbound traffic to istio_inbound chain
-A OUTPUT -p tcp -j ISTIO_OUTPUT                                  # Capture all outbound traffic to istio_outbound chain
-A ISTIO_INBOUND -p tcp -m tcp --dport 22 -j RETURN               # Envoy does not capture SSH connections
-A ISTIO_INBOUND -p tcp -m tcp --dport 15020 -j RETURN            # Exception for prometheus telemetry
-A ISTIO_INBOUND -p tcp -j ISTIO_IN_REDIRECT                      # All other inbound traffic gets redirected to envoy
-A ISTIO_IN_REDIRECT -p tcp -j REDIRECT --to-ports 15006          # Envoy receives incoming traffic on port 15006
-A ISTIO_OUTPUT -s 127.0.0.6/32 -o lo -j RETURN                   # Don't capture from 6 is the magical number for inbound: 15006, 127.0.0.6, ::6
-A ISTIO_OUTPUT ! -d 127.0.0.1/32 -o lo -j ISTIO_IN_REDIRECT      # But do capture non-local outbound connections from loopback
-A ISTIO_OUTPUT -m owner --uid-owner 1337 -j RETURN               # Exception for envoy itself...
-A ISTIO_OUTPUT -m owner --gid-owner 1337 -j RETURN               # ... this will prevent envoy from capturing its own traffic
-A ISTIO_OUTPUT -d 127.0.0.1/32 -j RETURN                         # Don't capture connections to localhost (RETURN = leave chain)
-A ISTIO_OUTPUT -j ISTIO_REDIRECT                                 # All other outbound traffic gets redirected to envoy
-A ISTIO_REDIRECT -p tcp -j REDIRECT --to-ports 15001             # Envoy receives outgoing traffic on port 15001
```

1. When a new kubernetes service is added (i.e. cluster ip for CF app), no changes are made to envoy config by default.
1. The started sidecar envoy gets pre-configured listeners as described below.

See https://istio.io/docs/ops/deployment/requirements/#ports-used-by-istio for list of special envoy ports.
Use https://archive.istio.io/v1.4/docs/ops/diagnostic-tools/proxy-cmd/ for actual debugging advice.

A virtual listener on 0.0.0.0 per each HTTP port for outbound HTTP traffic (e.g. configured via VirtualService).
A virtual listener per service IP, per each non-HTTP for outbound TCP/HTTPS traffic.
E.g., in the table below, there are two entries for port `8080`. In order to distinguish HTTP and non-HTTP traffic, there is an additional virtual listener with the IP `10.68.227.69` in place.

```bash
$ istioctl proxy-config listener  test-app-a-test-eb94aee321-0.cf-workloads
ADDRESS          PORT      TYPE
0.0.0.0          15001     TCP    # outbound envoy port
0.0.0.0          15006     TCP    # inbound envoy port
10.68.227.69     8080      TCP    # Outbound HTTPS/TCP traffic to metric-proxy.cf-system service
10.66.218.25     8085      TCP    # Outbound HTTPS/TCP traffic to eirini.cf-system service
10.68.94.164     24224     TCP    # Outbound HTTPS/TCP traffic to fluentd-forwarder-ingress.cf-system service
10.66.80.251     8082      TCP    # Outbound HTTPS/TCP traffic to log-cache-syslog.cf-system service
0.0.0.0          8080      TCP    # Outbound HTTP traffic to uaa.cf-system
0.0.0.0          80        TCP    # Outbound HTTP traffic to capi.cf-system and cfroutesync.cf-system
0.0.0.0          8083      TCP    # Outbound HTTP traffic to log-cache.cf-system service. Check below for detailed config
0.0.0.0          15090     HTTP   # Envoy Prometheus telemetry
10.96.4.62       15020     TCP    # deprecated (https://github.com/istio/istio/issues/24147)
10.96.4.62       8080      HTTP   # deprecated (https://github.com/istio/istio/issues/24147)
```

**CAVEAT**: The additional listeners besides outbound and inbound envoy capture ports are obsolete and will not be used for routing. They will be removed in Istio 1.6. See [this issue](https://github.com/istio/istio/issues/24147) for details.

**NOTE:** For a deep-dive into how the sidecar pattern works in istio, check out [Jimmy Song's blog post](https://jimmysong.io/en/blog/sidecar-injection-iptables-and-traffic-routing/) which also features a great [routing workflow diagram](https://jimmysong.io/en/blog/sidecar-injection-iptables-and-traffic-routing/envoy-sidecar-traffic-interception-jimmysong-blog-en.png) that shows exactly how the traffic is routed.

#### How traffic is forwarded from sidecar to app container

The `istio-init` initContainer configures IP tables in such a way that all incoming traffic is routed to port 15006. Then, there is a listener on port 15006 which has a listener filter `envoy.listener.original_dst` which restores the original destination address before filter chains apply. Then there is a list of filter chains which match in order of most to least specific destination, i.e. `100.96.4.29/32` is more specific than `0.0.0.0/0` so the higher prefix length wins.

`istioctl proxy-config listener  test-app-a-test-eb94aee321-0.cf-workloads --port 15006 -o json`
```yaml
        {
          "listener": {
            "address": {
              "socket_address": {
                "address": "0.0.0.0",
                "port_value": 15006       # all inbound traffic gets forwarded here
              }
            },
            "continue_on_listener_filters_timeout": true,
            "filter_chains": [
              {
                "filter_chain_match": {
                  "prefix_ranges": [
                    {
                      "address_prefix": "0.0.0.0",
                      "prefix_len": 0
                    }
                  ]
                },
                "filters": [
                  {
                    "name": "envoy.tcp_proxy",
                    "typed_config": {
                      "@type": "type.googleapis.com/envoy.config.filter.network.tcp_proxy.v2.TcpProxy",
                      "access_log": [ (...) ],
                      "cluster": "InboundPassthroughClusterIpv4",
                      "stat_prefix": "InboundPassthroughClusterIpv4"
                    }
                  }
                ],
                (...)
              },
              { # (other filter chains here)
               (...)
              },
              {
                "filter_chain_match": {
                  "destination_port": 8080,
                  "prefix_ranges": [
                    {
                      "address_prefix": "100.96.4.29",    # this matches the app's pod ip and app port 8080
                      "prefix_len": 32
                    }
                  ]
                },
                "filters": [
                  {
                    "name": "envoy.http_connection_manager",
                    "typed_config": {
                      "@type": "type.googleapis.com/envoy.config.filter.network.http_connection_manager.v2.HttpConnectionManager",
                      "access_log": [ (...) ],
                      "forward_client_cert_details": "APPEND_FORWARD",
                      "generate_request_id": true,
                      "http_filters": [ (...) ],
                      "normalize_path": true,
                      "route_config": {
                        "name": "inbound|8080|http|s-7afcae7d-d2ff-4310-9e74-2ec9ca4cca19.cf-workloads.svc.cluster.local",
                        "validate_clusters": false,
                        "virtual_hosts": [
                          {
                            "domains": [
                              "*"
                            ],
                            "name": "inbound|http|8080",
                            "routes": [
                              {
                                "decorator": {
                                  "operation": "s-7afcae7d-d2ff-4310-9e74-2ec9ca4cca19.cf-workloads.svc.cluster.local:8080/*"
                                },
                                "match": {
                                  "prefix": "/"
                                },
                                "name": "default",
                                "route": {    # this route selects the cluster backend for inbound app traffic
                                  "cluster": "inbound|8080|http|s-7afcae7d-d2ff-4310-9e74-2ec9ca4cca19.cf-workloads.svc.cluster.local",
                                  "max_grpc_timeout": "0s",
                                  "timeout": "0s"
                                },
                                "typed_per_filter_config": { ... }

(...)
              "listener_filters": [
              {
                "name": "envoy.listener.original_dst"     # this restores original destination before filter chains are run
              },
              {
                "name": "envoy.listener.tls_inspector"
              }
            ],
            "listener_filters_timeout": "1s",
            "name": "virtualInbound"
          },

```
Since incoming traffic has our podIP `100.96.4.29` as dstIP and dstPort `8080` the first and the last filter chain match and the last filter chain wins, because it matches the port. This filter chain has a matching virtualHost `inbound|http|8080` (domain `*` matches all) and therefore the packet is using route `default` to cluster `inbound|8080|http|s-ef9c974d-adfd-4552-8fcd-19e17f84d8dc.cf-workloads.svc.cluster.local`.

`$ istioctl proxy-config cluster test-app-a-test-eb94aee321-0.cf-workloads --fqdn "inbound|8080|http|s-ef9c974d-adfd-4552-8fcd-19e17f84d8dc.cf-workloads.svc.cluster.local"  -o json`
```yaml
[
    {
        "name": "inbound|8080|http|s-ef9c974d-adfd-4552-8fcd-19e17f84d8dc.cf-workloads.svc.cluster.local",
        "type": "STATIC",
        "loadAssignment": {
            "clusterName": "inbound|8080|http|s-ef9c974d-adfd-4552-8fcd-19e17f84d8dc.cf-workloads.svc.cluster.local",
            "endpoints": [
                {
                    "lbEndpoints": [
                        {
                            "endpoint": {
                                "address": {
                                    "socketAddress": {
                                        "address": "127.0.0.1",
                                        "portValue": 8080
```
This cluster has one static endpoint configured and that is localhost:8080, which is where our application is listening.



### How egress is forwarded from the app container

In contrast to bosh-deployed CF, there is no NAT gateway in cf-for-k8s. Instead, k8s handles NAT. Gardener-managed K8s clusters have private node IPs and create NAT gateways to perform address translation. How these gateways are implemented depends on the respective infrastructure provider, e.g. the [`Cloud NAT Gateway`](https://cloud.google.com/nat/docs/overview) on GCP is purely software-defined. Since there is no Istio egress-gateway in cf-for-k8s as well, egress traffic from an app is routed through the sidecar and then to its destination outside the cluster using the infrastructure-specific NAT solution.


#### Envoy configuration

The `istio-init` init container configures IP tables in such a way that all outgoing traffic is routed to port `15001`. There is a listener on this port that has `useOriginalDst` set to true which means it hands the request over to the listener that best matches the original destination of the request. If it can’t find any matching virtual listeners it sends the request to the `PassthroughCluster` which connects to the destination directly. For any address, where there is no special Istio config, e.g. for google.com:443, the `PassthroughCluster` is used.

`istioctl proxy-config listener  test-app-a-test-eb94aee321-0.cf-workloads --port 15001 -o json`
```yaml
[
    {
        "name": "virtualOutbound",
        "address": {
            "socketAddress": {
                "address": "0.0.0.0",
                "portValue": 15001
            }
        },
        "useOriginalDst": true
    }
]
```

There is a virtual listener on 0.0.0.0 per each HTTP port for outbound HTTP traffic. We follow the packet sent to the log-cache-service via `curl log-cache.cf-system:8083/test`.

```bash
$ istioctl proxy-config listener test-app-a-test-eb94aee321-0.cf-workloads --port 8083 -o json
...
"filters": [
      {
          "name": "envoy.http_connection_manager",
          "typedConfig": {
              "rds": {
                  "configSource": {
                      "ads": {}
                  },
                  "routeConfigName": "8083"
              },
...
```
The filter above belongs to the matching listener. `rds` means Route Discovery Service which looks for a route config with name `8083`.

```bash
$ istioctl proxy-config routes  test-app-a-test-eb94aee321-0.cf-workloads --name 8083 -o json
[
    {
        "name": "8083",
        "virtualHosts": [
            {
                "name": "log-cache.cf-system.svc.cluster.local:8083",
                "domains": [
                    "log-cache.cf-system.svc.cluster.local",
                    "log-cache.cf-system.svc.cluster.local:8083",
                    "log-cache.cf-system",
                    "log-cache.cf-system:8083",
                    "log-cache.cf-system.svc.cluster",
                    "log-cache.cf-system.svc.cluster:8083",
                    "log-cache.cf-system.svc",
                    "log-cache.cf-system.svc:8083",
                    "10.69.103.199",
                    "10.69.103.199:8083"
                ],
                "routes": [
                    {
                        "name": "default",
                        "match": {
                            "prefix": "/"
                        },
                        "route": {
                            "cluster": "outbound|8083||log-cache.cf-system.svc.cluster.local",
```

In the route config, the virtual host with name "8083" matches our domain "log-cache.cf-system:8083". In this virtual host, the route with name "default" matches our path "/test" and the "outbound|8083||log-cache.cf-system.svc.cluster.local" is selected.

```bash
$ istioctl proxy-config cluster test-app-a-test-eb94aee321-0.cf-workloads --fqdn log-cache.cf-system.svc.cluster.local -o json
...
"dynamic_active_clusters": [
    {
      "cluster": {
        ...
        "edsClusterConfig": {
              "edsConfig": {
                  "ads": {}
              },
              "serviceName": "outbound|8083||log-cache.cf-system.svc.cluster.local"
          },
      ...
```

The cluster "outbound|8083||log-cache.cf-system.svc.cluster.local" gets its endpoints from Pilot via Aggregated Discovery Service (ADS). These endpoints consist of a port and the targeted `pod IP` (in this case the pod IP of cf-system/log-cache-7bd48bbfc7-8ljxv).

*Note:* The list of endpoints is not dumped at `localhost:15000/config_dump`. Use istioctl or `curl -s http://localhost:15000/clusters?format=json` to get it.

```bash
$ istioctl proxy-config endpoints test-app-a-test-eb94aee321-0.cf-workloads --cluster "outbound|8083||log-cache.cf-system.svc.cluster.local"
ENDPOINT             STATUS      OUTLIER CHECK     CLUSTER
10.96.0.159:8083     HEALTHY     OK                outbound|8083||log-cache.cf-system.svc.cluster.local
```

The picture illustrates the described above config.
![](doc/egress.png)

## Traffic restrictions

There are two `Sidecar` resources deployed by cf-for-k8s.
* There is one default Sidecar in the `istio-system` namespace that allows all traffic. This Sidecar is used as the default for all namespaces without a Sidecar.
* There is a Sidecar resource in the `cf-workload` namespace that restricts egress traffic to other services in the mesh. Only services in the `cf-system` namespace can be reached. Note that this does not affect domains outside the mesh, e.g. google.de.
```yaml
kind: Sidecar
metadata:  #...
  name: default
  namespace: cf-workloads
spec:
  egress:
  - hosts:
    - cf-system/*
```


### Egress

Egress traffic from an app is always routed via the sidecar. For a more detailed explanation, see Section [How egress is forwarded from the app container](https://github.com/akhinos/cf4k8s-networking#how-egress-is-forwarded-from-the-app-container). In general, Istio is configured to allow arbitrary egress, therefore apps have access to the internet.


### Push Another App

No changes to envoy config of existing app(s). No direct app-to-app communication is possible as of now.


### Map Additional Route


## Debugging

### Log levels

It is possible to increase/set envoy's log level via
`curl -X POST -s http://localhost:15000/logging?level=debug`. It is also possible to increase the log level for individual loggers. Possible log levels are critical, error, warning, info, debug, trace.

### Looking into the TCP layer

**ksniff**

[ksniff](https://github.com/eldadru/ksniff) is a tool that injects a statically linked tcpdump binary into a running pod. It allows to
tap into the pod traffic directly and streams the live capture into a local wireshark. Alternatively it can dump tpc traffic into a pcap file.

When using ksniff on CF apps you will stumble over the issue that CF pods are non-privileged. Therefore, the injected tcpdump will not be able to capture any traffic.

A workaround to this is running ksniff with the `-p` option. This will start a second (privileged) pod that will access the underlying docker daemon:

```
cf apps
Getting apps in org testorg / space test as admin...
OK

name         requested state   instances   memory   disk   urls
helloworld   started           1/1         1G       1G     helloworld.cf.cf4k8s.istio.shoot.canary.k8s-hana.ondemand.com

kubectl get pods -n cf-workloads
NAME                           READY   STATUS            RESTARTS   AGE
helloworld-test-8badcc3ee4-0   2/2     Running           0          8m46s


./kubectl-sniff-darwin helloworld-test-8badcc3ee4-0 -p -n cf-workloads
```

This will launch a local wireshark where you can trace the TCP traffic of the target pod.

Test your app:
```
curl https://helloworld.cf.cf4k8s.istio.shoot.canary.k8s-hana.ondemand.com
Hello World
```

Find your packet on wireshark:

![](doc/ksniff-wireshark.png)

**CAVEAT:** Running ksniff in privileged mode will require additional resources as a new pod is started. This can be an issue if the supporting node
is near out of resources.

**EnvoyFilter**

Aside from external tools, Envoy also supports [tapping](https://www.envoyproxy.io/docs/envoy/v1.12.0/operations/traffic_tapping) into listener or cluster traffic. Currently, there are two ways of tapping:
- [Socket Tapping](https://www.envoyproxy.io/docs/envoy/v1.12.0/api-v2/api/v2/core/base.proto#envoy-api-msg-core-transportsocket): Directly tap into a socket. Very low-level, similar to tcpdump. (also supports creating pcap files for wireshark)
- [HTTP Filter](https://www.envoyproxy.io/docs/envoy/v1.12.0/configuration/http/http_filters/tap_filter): A high-level filter plugin. Supports matching on HTTP properties like headers, cookies etc.

For tapping into CF apps, a selector for the app guid is recommended so that only the sidecar envoy of that particular app is tapped.

A [small tool](envoy-tap/tap.sh) has been provided to inject a filter conveniently into a CF app.

After a HTTP filter has been injected the virtualInbound listener configuration will look like this:

```
    {
     "version_info": "2020-06-15T08:41:22Z/42",
     "listener": {
      "name": "virtualInbound",
      "address": {
       "socket_address": {
        "address": "0.0.0.0",
        "port_value": 15006
       }
      },
      "filter_chains": [
       {
        "filter_chain_match": {
         "prefix_ranges": [
          {
           "address_prefix": "0.0.0.0",
           "prefix_len": 0
          }
         ]
        },
        "filters": [
         {
          "name": "envoy.tcp_proxy",
          "typed_config": {
           "@type": "type.googleapis.com/envoy.config.filter.network.tcp_proxy.v2.TcpProxy",
           "stat_prefix": "InboundPassthroughClusterIpv4",
           "access_log": [
            { (...) }
             }
            }
           ],
           "cluster": "InboundPassthroughClusterIpv4"
          }
         }
        ],
        "metadata": {
         "filter_metadata": {
          "pilot_meta": {
           "original_listener_name": "virtualInbound"
          }
         }
        }
       },
       {
        "filter_chain_match": {
         "prefix_ranges": [
          {
           "address_prefix": "100.96.1.6",
           "prefix_len": 32
          }
         ],
         "destination_port": 15020
        },
        "filters": [
         {
          "name": "envoy.tcp_proxy",
          "typed_config": { (...) }
        ],
        "metadata": {
         "filter_metadata": {
          "pilot_meta": {
           "original_listener_name": "100.96.1.6_15020"
          }
         }
        }
       },
       {
        "filter_chain_match": {
         "prefix_ranges": [
          {
           "address_prefix": "100.96.1.6",
           "prefix_len": 32
          }
         ],
         "destination_port": 8080
        },
        "tls_context": {(...)},
        "filters": [
         {
          "name": "envoy.http_connection_manager",
          "typed_config": {
           "@type": "type.googleapis.com/envoy.config.filter.network.http_connection_manager.v2.HttpConnectionManager",
           "stat_prefix": "inbound_100.96.1.6_8080",
           "http_filters": [
            {
             "name": "istio_authn",
             "typed_config": {(...)}
            },
            {
             "name": "mixer",
             "typed_config": {(...)}
            },
            {
             "name": "envoy.cors"
            },
            {
             "name": "envoy.fault"
            },
            {
             "name": "envoy.filters.http.tap",
             "config": {
              "common_config": {
               "static_config": {
                "match_config": {
                 "any_match": true
                },
                "output_config": {
                 "sinks": [
                  {
                   "file_per_tap": {
                    "path_prefix": "/etc/istio/proxy/tap"
                   },
                   "format": "JSON_BODY_AS_BYTES"
                  }
                 ]
                }
               }
              }
             }
            },
            {
             "name": "envoy.router"
            }
           ],
(...)
     "last_updated": "2020-06-15T08:41:22.323Z"
    }
   ]
  },
```

You can then curl your app to produce some requests:
```
curl https://go-app.cf.dom.cfi.shoot.canary.k8s-hana.ondemand.com
Hello World%
```

Log on to the envoy to access the recorded requests:
```
kubectl exec -it go-app-test-2ab43bc022-0 -c istio-proxy -n cf-workloads -- bash
istio-proxy@go-app-test-2ab43bc022-0:/$ cd /etc/istio/proxy
istio-proxy@go-app-test-2ab43bc022-0:/etc/istio/proxy$ ls
envoy-rev0.json                               tap_11344748775327413437.json  tap_18192093633853801485.json
tap_11115532091803384888.pb_length_delimited  tap_12484476574378298875.json
istio-proxy@go-app-test-2ab43bc022-0:/etc/istio/proxy$ cat tap_11344748775327413437.json
{
 "http_buffered_trace": {
  "request": {
   "headers": [
    {
     "key": ":authority",
     "value": "go-app.cf.dom.cfi.shoot.canary.k8s-hana.ondemand.com"
    },
    {
     "key": ":path",
     "value": "/"
    },
    {
     "key": ":method",
     "value": "GET"
    },
    {
     "key": ":scheme",
     "value": "http"
    },
    {
     "key": "user-agent",
     "value": "curl/7.64.1"
    },
    {
     "key": "accept",
     "value": "*/*"
    },
    {
     "key": "x-forwarded-for",
     "value": "193.16.224.3"
    },
    {
     "key": "x-forwarded-proto",
     "value": "https"
    },
    {
     "key": "x-envoy-external-address",
     "value": "193.16.224.3"
    },
    {
     "key": "x-request-id",
     "value": "9895241b-b354-475b-a967-2af1369016f1"
    },
    {
     "key": "cf-app-id",
     "value": "4cb788f9-1bdf-4e76-b08c-d40b8580a1cf"
    },
    {
     "key": "cf-app-process-type",
     "value": "web"
    },
    {
     "key": "cf-organization-id",
     "value": "e2d0807b-446e-4b57-898c-26fb16d0ff11"
    },
    {
     "key": "cf-space-id",
     "value": "eac690b5-c8fa-44ec-adf9-da4cff4b76ea"
    },
    {
     "key": "content-length",
     "value": "0"
    },
    {
     "key": "x-forwarded-client-cert",
     "value": "By=spiffe://cluster.local/ns/cf-workloads/sa/eirini;Hash=2b8439f99995f1eb05c587d6273ca0099159b355e301bddd2730c685497076fc;Subject=\"\";URI=spiffe://cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"
    },
    {
     "key": "x-b3-traceid",
     "value": "6bfa3b14817e262ee03314d5c61c32b0"
    },
    {
     "key": "x-b3-spanid",
     "value": "06138a2b0d8a7aa5"
    },
    {
     "key": "x-b3-parentspanid",
     "value": "e03314d5c61c32b0"
    },
    {
     "key": "x-b3-sampled",
     "value": "0"
    }
   ],
   "trailers": []
  },
  "response": {
   "headers": [
    {
     "key": ":status",
     "value": "200"
    },
    {
     "key": "date",
     "value": "Mon, 15 Jun 2020 08:41:42 GMT"
    },
    {
     "key": "content-length",
     "value": "11"
    },
    {
     "key": "content-type",
     "value": "text/plain; charset=utf-8"
    },
    {
     "key": "x-envoy-upstream-service-time",
     "value": "0"
    },
    {
     "key": "server",
     "value": "istio-envoy"
    }
   ],
   "body": {
    "truncated": false,
    "as_bytes": "SGVsbG8gV29ybGQ="
   },
   "trailers": []
  }
 }
}
```

**Inspektor Gadget**

[Inspektor Gadget](https://github.com/kinvolk/inspektor-gadget) is a collection of K8S tools developed by [Kinvolk](https://kinvolk.io/) to help ease the development of kubernetes workloads. Inspektor Gadget provides a kubectl plugin that has 3 network-related debugging features:
- tcptop: Shows network connections on a pod, similar to tools like `netstat` or `ss`
- tcpconnect: Traces tcp connections as they appear on a pod to help develop strict network policies
- tcptracer: Traces into existing tcp connections, specifically connect, accept and close events.

Unfortunately, we were unable to test Inspektor Gadget on cf4k8s, because it needs to install a privileged daemonset on all nodes which needs kernel source headers to work. This will work only if the node OS supports it, which for Kubernetes Gardener's `Garden Linux` requires [issue 76](https://github.com/gardenlinux/gardenlinux/issues/76) to be fixed.


### When to use which method of traffic debugging
Depending on the layer you want to look at different tools are more helpful than others:

|Layer|Task|Recommended Tool|Requirements|
|-----|----|----------------|------------|
|L4|Generic connection tracking similar to `tcpdump`|ksniff|k8s v1.16.9, ability to create privileged pods
|L4|Socket-level filtering on envoy| EnvoyFilter w/ transport_socket|istio v1.4, istioctl
|L4|Get an overview of all connections on a pod similar to `netstat`|inspektor gadget tcptop|`linux-headers` package installed on k8s nodes
|L7|Find requests to a specific cf app| EnvoyFilter w/ http_filter|istio v1.4, istioctl
|L7|Find requests based on http headers| EnvoyFilter w/ http_filter|istio v1.4, istioctl


### Open Questions

* Looking at k8s networking (in particular when traffic gets routed to another worker node?
* Looking at the traffic passing through Envoys
* Istio `istio-system/ingressgateway` is not used.

*NOTE:* Envoy first evaluates route rules in virtual services to determine if a particular subset is being routed to. If so, only then will it activate any destination rule policies corresponding to the subset. Consequently, Istio only applies the policies you define for specific subsets in destination rules if you explicitly routed traffic to the corresponding subset.

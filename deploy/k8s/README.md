# Deploying on k3s

## Before the first apply

Three things must exist, and all three are outside this repository.

**1. Harbor CA trust.** If `harbor.jatimprov.go.id` uses an internal CA, every
node must trust it or pods sit in `ImagePullBackOff`:

```yaml
# /etc/rancher/k3s/registries.yaml on each node, then: systemctl restart k3s
mirrors:
  harbor.jatimprov.go.id:
    endpoint:
      - "https://harbor.jatimprov.go.id"
configs:
  harbor.jatimprov.go.id:
    auth:
      username: robot$panda+panda_bot
      password: <robot secret>
    tls:
      ca_file: /etc/rancher/k3s/harbor-ca.crt
```

**2. The pull secret.**

```bash
kubectl create secret docker-registry harbor-panda -n panda \
  --docker-server=harbor.jatimprov.go.id \
  --docker-username='robot$panda+panda_bot' \
  --docker-password='<robot secret>'
```

**3. TLS material.** The Deployment mounts two secrets that do not exist yet:

- `panda-docker-tls` — `tls.crt`, `tls.key`, `client-ca.crt`
- `panda-docker-api-keys` — `api-keys.json`

With cert-manager, the first is a `Certificate` resource. The second is the API
key store; generate it with the PANDA tooling, and deliver it through the same
secret store as everything else.

## Applying

```bash
kubectl apply -k deploy/k8s/base

kubectl -n panda get pods,svc,networkpolicy
kubectl -n panda logs deploy/panda-docker --tail=50
```

The first log line is the startup summary. It answers "what mode is this pod
in?" without reading the config back:

```
summary="protocol=rest api=rest:8080 health=:8081 env=production auth=mtls+apikey key_provider=vault"
```

## Label the client namespaces

The NetworkPolicy admits only namespaces and pods carrying
`panda.jatimprov.go.id/client: "true"`. An application that has not opted in
cannot reach the service — which is the intended default, and the reason an
unlabelled application sees a connection timeout rather than a 401.

```bash
kubectl label namespace opd-dukcapil panda.jatimprov.go.id/client=true
```

## Verifying the policy actually applies

A NetworkPolicy that the cluster's CNI ignores looks identical to one that
works, until it matters. Verify rather than assume:

```bash
kubectl -n default run probe --rm -it --image=busybox --restart=Never -- \
  wget -qO- --timeout=3 http://panda-docker-rest.panda.svc.cluster.local:8080/v1/version
```

It must time out. If it returns anything, the policy is not being enforced.

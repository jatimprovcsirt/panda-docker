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
      username: robot$panda+panda
      password: <robot secret>
    tls:
      ca_file: /etc/rancher/k3s/harbor-ca.crt
```

**2. The pull secret.**

```bash
kubectl create secret docker-registry harbor-panda -n panda \
  --docker-server=harbor.jatimprov.go.id \
  --docker-username='robot$panda+panda' \
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

## Verifying what you are running

The Deployment names `panda-docker:0.1.0` — a version tag. Tags are readable and
easy to bump, and a tag is only worth trusting if it cannot be moved. Enable
**Tag Immutability** in Harbor for the `panda` project before relying on one:

| Field | Value |
|---|---|
| Repositories | `**` |
| Tags | `**` |

Every release also publishes a digest, and a digest cannot be moved at all. To
pin it instead, take the value from the release notes:

```yaml
image: harbor.jatimprov.go.id/panda/panda-docker@sha256:0588625b...  # 0.1.0
```

That is stronger, at the cost of editing this file on every release — and a
digest nobody remembers to bump is worse than a tag, because it looks secure
while pointing at something old.

Whichever you choose, confirm the image was built by this repository before
trusting it. Releases from 0.1.0 onwards carry signed build provenance and an
SBOM:

```bash
gh attestation verify oci://harbor.jatimprov.go.id/panda/panda-docker:0.1.0 \
  --repo jatimprovcsirt/panda-docker
```

That answers "did this really come from `jatimprovcsirt/panda-docker`", which a
tag cannot answer on its own. It does not answer "is this code good" — nothing
does that for you.

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

## Installing without a route to Harbor

Sites with no network path to Harbor load the image from a tarball attached to
the GitHub release, one per architecture:

```
panda-docker-0.1.0-linux-amd64.tar
panda-docker-0.1.0-linux-arm64.tar
```

```bash
sha256sum -c panda-docker-0.1.0-linux-amd64.tar.sha256
docker load -i panda-docker-0.1.0-linux-amd64.tar
```

Two things are worth knowing about that route:

- **Attestations cannot be verified there.** `gh attestation verify` reaches
  GitHub, and a site with no route to Harbor has no route to GitHub either.
  Carry `panda-docker-0.1.0.spdx.json` — also attached to the release — on the
  same media, so the site keeps a written record of what is inside the image it
  loaded. That is a weaker guarantee than a signature, and it is the strongest
  one available without a network.
- **Load the tarball matching the architecture you run.** The two are not
  interchangeable, and a mismatch surfaces either at `docker load` or at first
  execution.

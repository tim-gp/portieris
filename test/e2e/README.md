# E2E Tests

The E2E tests execute against a real Kubernetes cluster and are typically run by maintainers against an IBM Cloud Kubernetes Service (IKS) cluster before accepting a PR.

The tests can be run with the following steps:
1. [Order a new IKS cluster](https://cloud.ibm.com/docs/containers-cli-plugin?topic=containers-cli-plugin-kubernetes-service-cli#cs_cluster_create) (or use an existing cluster)
2. Get the cluster config: `ibmcloud ks cluster config -c <cluster-name>`
3. Export KUBECONFIG to point at the `kube-config.yaml` for your cluster found in `~/.bluemix/plugins/container-service/clusters`.
4. Create a new IBM Cloud Container Registry (ICCR) namespace owned by the same account as the cluster
5. Export the HUB variable pointing to your new ICCR namespace: `export HUB=uk.icr.io/yournamespace`
6. After completing your code changes, build and push the image to your namespace: `make push`
7. Install portieris into your cluster: `helm install helm/portieris`
8. Export `E2E_ACCOUNT_HEADER` - a maintainer can tell you what to set
9. Run `make e2e.quick`

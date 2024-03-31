kubectl cluster-info  #Check if Kubernetes is running.

curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash  #Install Helm.
helm version

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts #Get prometheus helm repository Info.
helm repo update

helm install prometheus prometheus-community/prometheus #Install chart.

# Check the prometheus objects.
kubectl get deploy
kubectl get daemonset
kubectl get pod
kubectl get svc

#Edit `prometheus-server` service to reach promethes server from external as below.
kubectl edit svc prometheus-server
#Change the service type as `NodePort` and add `nodePort: 30001` port to `ports` field.
# Open web browser and go to **http://ec2-54-89-159-197.compute-1.amazonaws.com:30001/**
### Note
#Replace the address with your EC2 Master Node's public IP address.


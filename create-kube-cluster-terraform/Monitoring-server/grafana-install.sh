#Install grafana according to the HELM artifacthub (https://artifacthub.io/packages/helm/grafana/grafana).
# Get grafana helm repository Info.
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

#Install chart.
helm install grafana grafana/grafana

#Check the grafana objects.
kubectl get deploy grafana
kubectl get po | grep "grafana"
kubectl get svc grafana

#Edit `grafana` service to reach grafana from external as below.
kubectl edit svc grafana

#Change the service type as `NodePort` and add `nodePort: 30002` port to `ports` field.
#Open web browser and go to **http://ec2-54-89-159-197.compute-1.amazonaws.com:30002/**
### Note
#Replace the address with your EC2 Master Node's public IP address.

### Log in for the First Time
#Get the `admin-password` and `admin-user`.
kubectl get secret grafana -o yaml

#Decode the `admin-password` and `admin-user` as below.
echo "YWRtaW4=" | base64 -d ; echo
echo "dFozeEV6bGFxUWUyODFoeDhSamlRQmdqM2l5eVFJTmFybURub0tBdQ==" | base64 -d ; echo

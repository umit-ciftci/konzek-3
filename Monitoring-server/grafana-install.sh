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

### Add Prometheus as a Data Source

- Click ***DATA SOURCES*** and you will come to the settings page of your new data source.

- Select ***Prometheus***

- Write `http://prometheus-server:80` for URL. (You don't need to define service port 80, because it is default port.) Then click ***Save & Test***.

- Click ***Dashboards***.

- Click `New` and `Import` buttons.

- Select a dashboard ID on `https://grafana.com/grafana/dashboards/` page like `6417`.

- Select `promethes` as data source.

### Add CloudWatch as a Data Source

- Move your cursor to the cog on the side menu which will show you the configuration menu. Click on ***Configuration > Data Sources*** in the side menu and you’ll be taken to the data sources page where you can add and edit data sources.

- Click ***Add data source*** and you will come to the settings page of your new data source.

- Select ***CloudWatch***.

- For ***Auth Provider***, Choose ***Access & secret key***.

- Write your ***Access Key ID*** and ***Secret Access Key***.

- Write your ***Default Region***.

- Click ***Save & Test***.

- Click ***Dashboards*** (next to the Setting).

- Import ***Amazon EC2*** and ***Amazon CloudWatch Logs***.

- Click ***Home*** then ***Amazon EC2***.

- Click ***Network Detail*** to see Network traffic.

### Create a New Dashboard

- In the side bar, hover your cursor over the Create (plus sign) icon and then click ***Dashboard***.

- Click ***Add new panel***.

- Click ***Visualization*** (Left Side) and then select ***Gauge***.

- Query Mode : CloudWatch Metrics
- Region : default
- Namespace : AWS/EC2
- Metric Name : CPUUtilization
- Stats : Average
- Dimentions : InstanceId = "Insctance ID"
- Click ***Apply***

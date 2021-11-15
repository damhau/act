#!/usr/bin/python3
from kubernetes import client, config
from pprint import pprint
from kubernetes.client.rest import ApiException
import sys
import os
import requests
from requests.auth import HTTPBasicAuth

if "AZDO_PAT" in os.environ:
    azdo_pat = os.environ['AZDO_PAT']
else:
    sys.exit('Environment variable AZDO_PAT is not set')

azdo_project = sys.argv[1]
namespace = sys.argv[2]
service_account = sys.argv[3]
api_fqdn = sys.argv[4]

config.load_kube_config()
v1 = client.CoreV1Api()

def get_secret_from_sa(name,namespace):
    try:
        api_response = v1.read_namespaced_service_account(name, namespace)
        # print(api_response._secrets[0])
        for secret in api_response._secrets:
            if 'token' in secret.name:
                try:
                    api_response = v1.read_namespaced_secret(secret.name, namespace)
                    ca_cert = api_response._data['ca.crt']
                    token = api_response._data['token']
                    return True , ca_cert, token
                except ApiException as e:
                    return False, None, None
                    

    except ApiException as e:
        return False, None, None
        # print("Exception when calling CoreV1Api->read_namespaced_service_account: %s\n" % e)

def get_azdo_project_id(name):
    response = requests.get("https://tfs.ext.icrc.org/ICRCCollection/_apis/projects?api-version=6.0-preview.4", auth=HTTPBasicAuth('pat', azdo_pat))
    status_code = response.status_code 
    projects = response.json()['value']

    for project in projects:
        if project['name'] == name:
            return status_code, project['id']
    return status_code, None

def get_azdo_service_connection_id(name):
    response = requests.get("https://tfs.ext.icrc.org/ICRCCollection/IHL%20in%20Action/_apis/serviceendpoint/endpoints?api-version=6.0-preview.4", auth=HTTPBasicAuth('pat', azdo_pat))
    status_code = response.status_code 
    service_connections = response.json()['value']
    for service_connection in service_connections:
        if service_connection['name'] == name:
            return status_code, service_connection['id']
    return status_code, None

def create_azdo_service_connection_id(json_content):
    response = requests.post("https://tfs.ext.icrc.org/ICRCCollection/IHL%20in%20Action/_apis/serviceendpoint/endpoints?api-version=6.0-preview.4", json=json_content, auth=HTTPBasicAuth('pat', azdo_pat))
    status_code = response.status_code 
    result = response.json()
    return status_code, result

service_connection_status , service_connection_id = get_azdo_service_connection_id(api_fqdn + '-' + namespace + '-admin')
project_id_status, project_id = get_azdo_project_id(azdo_project)
result, k8s_ca_certificate , k8s_token = get_secret_from_sa(service_account, namespace)

json = {
"description": "",
"name": api_fqdn + '-' + namespace + '-admin',
"serviceEndpointProjectReferences": [
    {
        "description": "",
        "projectReference": {
            "id": project_id,
            "name": azdo_project
        },
        "name": api_fqdn + '-' + namespace + '-admin'
    }
],
"url": "https://" + api_fqdn + ":443",
"administratorsGroup": None,
"readersGroup": None,
"operationStatus": None,
"groupScopeId": None,
"createdBy": {},
"type": "kubernetes",
"owner": "library",
"data": {
    "authorizationType": "ServiceAccount"
},
"authorization": {
    "scheme": "Token",
    "parameters": {
        "serviceAccountCertificate": k8s_ca_certificate,
        "isCreatedFromSecretYaml": "true",
        "apitoken": k8s_token
    }
},
"isShared": True
}


if service_connection_id == None and service_connection_status == 200 and project_id_status == 200:
    status_code , result = create_azdo_service_connection_id(json)
    if status_code == 200:
        print("The service connection was created sucessfully, the http response code was: " + str(status_code))
    else:
        print("Unable to create the service connection, the http response code was: " + str(status_code))

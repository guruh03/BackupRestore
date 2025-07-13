import re
import time
import shutil
import datetime
import paramiko
import requests
import psycopg2
import threading
from math import log
from .views import *
from LoggConfig import *
from scp import SCPClient
from dotenv import load_dotenv
from Postgresdb.models import *
from rest_framework import status
from Postgresdb.serializer import *
from elasticsearch import Elasticsearch
from psycopg2.extras import RealDictCursor
from rest_framework.response import Response

load_dotenv()

config = {
    "LOG_PATH":os.getenv("LOG_PATH"),
    "LOG_LEVEL": os.getenv("LOG_LEVEL").split(","),
    "SERVICE_NAME":os.getenv("SERVICE_NAME"),
    "SERVICE_ID":"ElasticSearch",
    "CONSOLE_LOGS_ENABLED":os.getenv("CONSOLE_LOGS_ENABLED"),
    
    "LOCAL_ELASTICSEARCH_HOST":os.getenv("LOCAL_ELASTICSEARCH_HOST"),
    "LOCAL_ELASTICSEARCH_VM_USER":os.getenv("LOCAL_ELASTICSEARCH_VM_USER"),
    "LOCAL_ELASTICSEARCH_VM_PASSWORD":os.getenv("LOCAL_ELASTICSEARCH_VM_PASSWORD"),
    "ELASTICSEARCH_USERNAME":os.getenv("ELASTICSEARCH_USERNAME"),
    "ELASTICSEARCH_PASSWORD":os.getenv("ELASTICSEARCH_PASSWORD"),
    "ELASTICSEARCH_AUTHENTICATION_ENABLED":os.getenv("ELASTICSEARCH_AUTHENTICATION_ENABLED"),
    "SSH_TIMEOUT":int(os.getenv("SSH_TIMEOUT")),
    "LOCAL_TEMP_DIR":os.getenv("LOCAL_TEMP_DIR"),
    "ELASTICSEARCH_DATA_DIR":os.getenv("ELASTICSEARCH_DATA_DIR"),
    "POSTGRESQL_RESTORE_LOG_DATABASE_NAME":os.getenv("POSTGRESQL_RESTORE_LOG_DATABASE_NAME"),
    "POSTGRESQL_RESTORE_LOG_TABLE_NAME":os.getenv("POSTGRESQL_RESTORE_LOG_TABLE_NAME"),
    
}
logclass = LocalLogger(config)
logger = logclass.createLocalLogger()


def UserAuthenticationFromUserManagement(request):
    try:
        UserManagementEndpoint = os.environ.get('API_URL_ENDPOINT')  
        UserManagementURL = os.environ.get('API_URL')
        if (not UserManagementURL) and (not UserManagementURL): 
            return Response({"message" : "Cannot find User Management Environment Variables"},status=status.HTTP_404_NOT_FOUND)

        authHeader = request.META.get('HTTP_AUTHORIZATION')
        if not authHeader:
            logger.error("Token Not Found")
            # LogUserActivity(request, userName="Unknown", activity="Attempted access without token")
            return Response({"message" : "Token Not Found"},status=status.HTTP_400_BAD_REQUEST)

        token = authHeader.split()[1]
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }

        apiUrl = UserManagementEndpoint + UserManagementURL
        response = requests.get(apiUrl, headers=headers, timeout=config['SSH_TIMEOUT'])
        if response.status_code == 200:
            logger.info("Token Validated Succesfully")
            return response.json()
        if response.status_code==401:
            logger.error("Invalid token")
            # LogUserActivity(request, userName='Unknown', activity="Invalid token provided.")
            return Response({"message" : "Invalid token"},status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({"message" : "Error in fetching details from UserManagement"},status=status.HTTP_400_BAD_REQUEST)
    
    except requests.Timeout:
        logger.error(f"Thread {threading.current_thread().name}: Timeout - The request to User Management API timed out.")
        return Response({"message": f"Error in calling User Management API"}, status=status.HTTP_408_REQUEST_TIMEOUT)
    except Exception as e:
        logger.error(f"Thread {threading.current_thread().name}: Error in calling User Management API: {str(e)}")
        return Response({"message": f"Error in calling User Management API: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

def CreateSshClient(server, port, user, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(server, port, username=user, password=password, timeout=config['SSH_TIMEOUT'])
        logger.info("Connection established..")
        return client
    except Exception as e:
        logger.error(f"Error creating SSH client: {e}")
        return None

def ConnectToElasticsearch(elasticUrl, username=None, password=None):
    
    if username and password:
        es = Elasticsearch(f'http://{elasticUrl}',basic_auth=(username, password), verify_certs=False)
    else:
        es = Elasticsearch(f'http://{elasticUrl}')
    
    try:                 
        if (es.ping()):
            logger.info("Connected to Elasticsearch successfully!")
            return es
        else:
            logger.error("Failed to connect to Elasticsearch.")
            return False
    except Exception as e:
        logger.error(f"Error connecting to Elasticsearch: {e}")
        return False

def human_readable_size(sizeInBytes):
    if sizeInBytes == 0:
        return "0 Bytes"
    sizeNames = ["Bytes", "KB", "MB", "GB", "TB"]
    index = min(int(log(sizeInBytes, 1024)), len(sizeNames) - 1)
    size = sizeInBytes / (1024 ** index)
    return f"{size:.2f} {sizeNames[index]}"

def IndexListAndSize(es):
    indexes = es.indices.get_alias(index='*')
    # indexList = list(indexes.keys())
    indexList = [index for index in indexes.keys() if not index.startswith('.')]  # Filter out indexes starting with '.'
    
    indexStats = es.indices.stats(index=indexList)
    resp=[]
    for index in indexList:
        indexSizeBytes = indexStats['indices'][index]['total']['store']['size_in_bytes']
        resp.append({
            "index": index,
            "estimated_size": human_readable_size(indexSizeBytes),
        })
    return resp

def GetSizeOfIndex(es, indexName=None):
    if indexName:
        indexStats = es.indices.stats(index=indexName)
    else:
        indexStats = es.indices.stats()
        
    totalSize = sum(
        stat['total']['store']['size_in_bytes'] 
        for index, stat in indexStats['indices'].items()
        if not index.startswith('.')
    )
    Size = human_readable_size(totalSize)
    return Size


def BackupToRemoteLocal(indexName, elasticUrl, elastic_port, elasticUsername, elasticPassword, elasticVmUser, elasticVmPassword, repoName, snapshotName, isRemote, remotePort, remoteHost, remoteUser, remotePassword, remoteBackupPath, remotebackupDir=None):
    elasticBackupPath = f"{config['ELASTICSEARCH_DATA_DIR']}/{repoName}"
    
    if indexName:
        respone = RegisterSnapshotDirectory(elasticUrl, repoName, elasticUsername, elasticPassword)
        if respone == 200:
            responsedata = SnapshotSingleIndex(elasticUrl, repoName, snapshotName, indexName, elasticUsername, elasticPassword)
            if responsedata and isRemote:
                if CopySnapshotToRemote(elasticBackupPath, elasticUrl, elastic_port, elasticVmUser, elasticVmPassword, remoteHost, remotePort, remoteUser, remotePassword, remoteBackupPath, remotebackupDir):
                    return responsedata
                else:
                    return False
            return responsedata
        else:
            return False
            
    else:
        respone = RegisterSnapshotDirectory(elasticUrl, repoName, elasticUsername, elasticPassword)
        if respone == 200:
            responsedata = SnapshotAllIndex(elasticUrl, repoName, snapshotName, elasticUsername, elasticPassword)
            if responsedata and isRemote:
                if CopySnapshotToRemote(elasticBackupPath, elasticUrl, elastic_port, elasticVmUser, elasticVmPassword, remoteHost, remotePort, remoteUser, remotePassword, remoteBackupPath, remotebackupDir):
                    return responsedata     
                else:
                    return False  
            return responsedata   
        else:
            return False
    

def RegisterSnapshotDirectory(elasticUrl, repoName, username=None, password=None):
    locationPath = f"{config['ELASTICSEARCH_DATA_DIR']}/{repoName}"   #BUG ID 1124: Backup - ES - Partial - Local For one repo name only one snapshot should  be created.
    try:
        payload = {
            "type": "fs",
            "settings": {
                "location": locationPath, 
            }
        }
        url = f"http://{elasticUrl}/_snapshot/{repoName}"
        logger.debug("Requested url: "+ str(url))
        if username and password:
            respone = requests.post(url, json=payload, auth=(username, password))
        else:
            respone = requests.post(url, json=payload)
            
        return respone.status_code
    except Exception as e:
        logger.error(f"Error: {e}")
        return False

def CopySnapshotToRemote(elasticBackupPath, elasticUrl, elasticPort, elasticVmUser, elasticVmPassword, remoteHost, remotePort, remoteUser, remotePassword, remoteBackupPath, remotebackupDir=None):
    try:
        sshClient = CreateSshClient(remoteHost, remotePort, remoteUser, remotePassword)
        destsftp = sshClient.open_sftp()
        esSshClient = CreateSshClient(elasticUrl.split(":")[0], int(elasticPort), elasticVmUser, elasticVmPassword) #BUG ID 1125: Backup - ES - Complete - remote
        sourcesftp = esSshClient.open_sftp()
        
        if (sshClient is None or esSshClient is None):
            return False
        
        # remotebackupDir = f'{remoteBackupPath}/{int(datetime.now().timestamp())}_Elastic_Backup'
        stdin, stdout, stderr = sshClient.exec_command(f"mkdir -p {remotebackupDir}")
        exit_status = stdout.channel.recv_exit_status()

        if exit_status == 0:
            logger.info(f"Remote directory {remotebackupDir} ensured to exist.")
        else:
            logger.error(f"Failed to create remote directory: {stderr.read().decode()}")
            sshClient.close()
            return False
        
        logger.debug(f"Elastic Backup Path: {elasticBackupPath}")
        
        with SCPClient(esSshClient.get_transport()) as esScp:
            with SCPClient(sshClient.get_transport()) as scpClient:
                esScp.get(elasticBackupPath, f"{config['LOCAL_TEMP_DIR']}/", recursive=True)
                scpClient.put(f"{config['LOCAL_TEMP_DIR']}/{elasticBackupPath.split('/')[-1]}", remotebackupDir, recursive=True)
        
        shutil.rmtree(f"{config['LOCAL_TEMP_DIR']}/{elasticBackupPath.split('/')[-1]}")
        
        logger.info(f"Backup copied to remote server: {remoteHost}:{remoteBackupPath}")
        return True
    except Exception as e:
        logger.error(f"Error while copying backup to remote server: {e}")
        return False
    
    finally:
        sshClient.close()
        esSshClient.close()

def SnapshotSingleIndex(elasticUrl, repoName, snapshotName, indexName, username=None, password=None):
    try:
        snapshotPayload = {
            "indices": indexName,
            "ignore_unavailable": True,
            "include_global_state": False
        }
        url = f"http://{elasticUrl}/_snapshot/{repoName}/{snapshotName}?wait_for_completion=true"

        if username and password:
            response = requests.put(url, json=snapshotPayload, auth=(username, password))
        else:    
            response = requests.put(url, json=snapshotPayload)

        logger.debug(f"Requested url: {response.url} - Status Code : {response.status_code}" )
        
        if response.status_code == 200:     #BUG ID 1121: Backup -ES - Local - Partial
            return response.json()
        else:
            return False
    except Exception as e:
        logger.error(f"Exception occurred while taking snapshot. {e}")
        return False

def SnapshotAllIndex(elasticUrl, repoName, snapshotName, username=None, password=None):
    try:
        snapshotPayload = {
            "ignore_unavailable": True,
            "include_global_state": False
        }
        url = f"http://{elasticUrl}/_snapshot/{repoName}/{snapshotName}?wait_for_completion=true"
        
        if username and password:
            response = requests.put(url, json=snapshotPayload, auth=(username, password))
        else:
            response = requests.put(json=snapshotPayload)
        
        logger.debug(f"Requested Url: {response.url} - Status Code: {response.status_code}")

        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Failed to take snapshot: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.debug("Exception occurred: " + str(e))
        return False    
        
def RestoreSnapshotsFromElasticPath(indexName, elasticUrl, repoName, snapshotName, username=None, password=None):
    if indexName:
        responsedata = RestoreSingleIndex(elasticUrl, repoName, snapshotName, indexName, username, password)
        return responsedata
    else:
        responsedata = RestoreAllIndices(elasticUrl, repoName, snapshotName, username, password)
        return responsedata 

def RestoreSingleIndex(elasticUrl, repoName, snapshotName, indexName, username=None, password=None):
    try:
        restore_payload = {
            "indices": indexName,
            "ignore_unavailable": True,
            "include_global_state": False
        }
        url = f"http://{elasticUrl}/_snapshot/{repoName}/{snapshotName}/_restore"

        if username and password:
            response = requests.post(url, json=restore_payload, auth=(username, password))
        else:
            response = requests.post(url, json=restore_payload)

        logger.debug(f"Requested url: {response.url} - Status Code : {response.status_code}" )
        
        if response.status_code == 200:
            logger.info("Snapshot restore successful for index:" + indexName)
            return response.json()
        else:
            logger.error(f"Failed to restore snapshot: {response.status_code} - {response.text}")
            return False

    except Exception as e:
        logger.error("Exception occurred while restoring snapshot. " + str(e))
        return False

def MonitorRestore(elasticUrl, indices, username=None, password=None):   #BUG ID 1126: Restore - ES - Complete -Local Restore done message is displaying but in kibana restore status is not complete.
    while True:
        try:
            recoveryUrl = f"http://{elasticUrl}/_recovery"
            if username and password:
                recoveryResponse = requests.get(recoveryUrl, auth=(username, password))
            else:    
                recoveryResponse = requests.get(recoveryUrl)
            
            if recoveryResponse.status_code != 200:
                logger.error(f"Failed to fetch recovery status: {recoveryResponse.status_code} - {recoveryResponse.text}")
                return False

            recoveryStatus = recoveryResponse.json()
            indicesRestoring = [index for index in indices if index in recoveryStatus]
            completedIndices = [
                index for index in indicesRestoring 
                if all(shard['stage'] == 'DONE' for shard in recoveryStatus[index]['shards'])
            ]

            if len(completedIndices) == len(indices):
                logger.info("All indices restored successfully.")
                return True
            
            logger.info(f"Restoring in progress: {set(indices) - set(completedIndices)}")
            time.sleep(10)  # Poll every 10 seconds
        except Exception as e:
            logger.error(f"Error monitoring restore progress: {e}")
            return False

def RestoreAllIndices(elasticUrl, repoName, snapshotName, username=None, password=None):
    try:
        snapshotInfoUrl = f"http://{elasticUrl}/_snapshot/{repoName}/{snapshotName}"
        if username and password:
            snapshotInfoResponse = requests.get(snapshotInfoUrl, auth=(username, password))
        else:
            snapshotInfoResponse = requests.get(snapshotInfoUrl)

        if snapshotInfoResponse.status_code != 200:
            logger.error(f"Failed to get snapshot info: {snapshotInfoResponse.status_code} - {snapshotInfoResponse.text}")
            return False

        snapshotInfo = snapshotInfoResponse.json()
        indicesToRestore = [index for index in snapshotInfo['snapshots'][0]['indices'] if not index.startswith('.')]
        
        if not indicesToRestore:
            logger.info("No indices to restore (all start with '.').")
            return True
        
        restorePayload = {
            "ignore_unavailable": True,
            "include_global_state": False,
            "indices": ",".join(indicesToRestore)
        }

        url = f"http://{elasticUrl}/_snapshot/{repoName}/{snapshotName}/_restore"
        if username and password:
            response = requests.post(url, json=restorePayload, auth=(username, password))
        else:
            response = requests.post(url, json=restorePayload)
        
        logger.debug("Requested Url: "+ str(response.url))

        if response.status_code == 200:
            return MonitorRestore(elasticUrl, indicesToRestore, username, password)
        else:
            logger.error(f"Failed to restore snapshot: {response.status_code} - {response.text}")
            return False

    except Exception as e:
        logger.error("Exception occurred while restoring snapshot. " + str(e))
        return False

def CopySnapshotFromRemote(remoteHost, remotePort, remoteUser, remotePassword, remoteBackupPath, elasticVmHost, elasticPort, elasticVmUser, elasticVmPassword, localBackupPath='/tmp/backups'):
    try:
        remoteSshClient = CreateSshClient(remoteHost, remotePort, remoteUser, remotePassword)
        remoteSftpClient = remoteSshClient.open_sftp()
        
        esSshClient = CreateSshClient(elasticVmHost, int(elasticPort), elasticVmUser, elasticVmPassword)    #BUG ID 1120: Backup -ES - Remote - Partial
        sftpClient = esSshClient.open_sftp()
        
        if (remoteSshClient is None or esSshClient is None):
            return False
        
        try:
            sftpClient.stat(localBackupPath)
        except FileNotFoundError:
            sftpClient.mkdir(localBackupPath)
            logger.info(f"Created directory: {localBackupPath} in {elasticVmHost}")
        
        def CopyRecursive(remote_sftp, remote_path, es_sftp, es_path):
            try:
                try:
                    es_sftp.stat(es_path)
                except FileNotFoundError:
                    es_sftp.mkdir(es_path)
                    logger.info(f"Created directory: {es_path}")

                # Process files and directories
                for item in remote_sftp.listdir_attr(remote_path):
                    remote_item_path = f"{remote_path}/{item.filename}"
                    es_item_path = f"{es_path}/{item.filename}"

                    if item.st_mode & 0o040000:  # Directory
                        logger.info(f"Found directory: {remote_item_path}")
                        CopyRecursive(remote_sftp, remote_item_path, es_sftp, es_item_path)
                    else:
                        # print(f"Copying file: {remote_item_path} -> {es_item_path}")
                        remote_file = remote_sftp.open(remote_item_path, "rb")
                        with es_sftp.open(es_item_path, "wb") as es_file:
                            es_file.write(remote_file.read())
                        remote_file.close()
            except Exception as e:
                logger.error(f"Error while copying {remote_path}: {e}")
                return False

        CopyRecursive(remoteSftpClient, remoteBackupPath, sftpClient, localBackupPath)

        # command = f"echo {elasticVmPassword} | sudo -S chown -R elasticsearch:elasticsearch {localBackupPath}/*"
        # subprocess.run(command, shell=True, check=True)
        stdin, stdout, stderr = esSshClient.exec_command(f"echo {elasticVmPassword} | sudo -S chown -R elasticsearch:elasticsearch {localBackupPath}/*")
        exit_status = stdout.channel.recv_exit_status()

        if exit_status == 0:
            logger.info(f"Changed ownership of {localBackupPath} to 'elasticsearch'")
        else:
            logger.error(f"Failed to change ownership to elasticsearch : {stderr.read().decode()}")
            esSshClient.close()
            return False

        # command = f"echo {elasticVmPassword} | sudo -S mv {localBackupPath}/* {'/mnt/backups'}"
        # subprocess.run(command, shell=True, check=True)
        stdin, stdout, stderr = esSshClient.exec_command(f"echo {elasticVmPassword} | sudo -S mv {localBackupPath}/* {'/mnt/backups'}")
        exit_status = stdout.channel.recv_exit_status()

        if exit_status == 0:
            logger.info(f"Moved files from {localBackupPath} to {'/mnt/backups'}")
        else:
            logger.error(f"Failed to move files : {stderr.read().decode()}")
            esSshClient.close()
            return False
        
        # subprocess.run(f"echo {elasticVmPassword} | sudo -S rm -rf {localBackupPath}/", shell=True, check=True)
        stdin, stdout, stderr = esSshClient.exec_command(f"echo {elasticVmPassword} | sudo -S rm -rf {localBackupPath}/")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            logger.info(f"Deleted temporary directory: {localBackupPath}")
        else:
            logger.error(f"Failed to delete temporary directory files : {stderr.read().decode()}")
            esSshClient.close()
            return False

        logger.info(f"Snapshot copied from remote server: {remoteHost}:{remoteBackupPath} to /mnt/backups ")
        return True
    except Exception as e:
        logger.error(f"Error while copying snapshot from remote server: {e}")
        return False
    finally:
        try:
            remoteSftpClient.close()
            remoteSshClient.close()
            sftpClient.close()
            esSshClient.close()
        except Exception as e:
            logger.error(f"Error closing connections: {e}")
            return False
            

def ListAvailableSnapshots(elasticUrl, repoName=None, snapshotName=None, username=None, password=None):
    snapshotName = snapshotName if snapshotName else '_all'
    if snapshotName and repoName:
        url = f'http://{elasticUrl}/_snapshot/{repoName}/{snapshotName}'
        if username and password:
            response = requests.get(url, auth=(username, password))
        else:    
            response = requests.get(url)
            
        logger.debug(f"Requested Url: {response.url} - Status Code : {response.status_code}")
        
        if response.status_code==200:
            return response.json()
        else:
            logger.error(f"Failed to fetch snapshot details: {response.status_code} - {response.text}")
            return False
    else:
        url = f'http://{elasticUrl}/_cat/repositories?v=true&format=json'
        if username and password:
            response = requests.get(url, auth=(username, password))
        else:
            response = requests.get(url)
            
        logger.debug(f"Requested Url: {response.url} - Status Code : {response.status_code}")
        
        if response.status_code==200:
            return response.json()
        else:
            logger.error(f"Failed to fetch snapshot details: {response.status_code} - {response.text}")
            return False

def FormatSize(sizeInBytes):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if sizeInBytes < 1024.0:
            return f"{sizeInBytes:.2f} {unit}"
        sizeInBytes /= 1024.0
    return f"{sizeInBytes:.2f} TB"

def CheckRemoteDiskSpace(sshClient, backupPath):
    command = f'df -h {backupPath}'
    stdin, stdout, stderr = sshClient.exec_command(command)

    df_output = stdout.read().decode().strip()
    errorOutput = stderr.read().decode().strip()

    if errorOutput:
        raise Exception(f"Error retrieving available space: {errorOutput}")

    lines = df_output.splitlines()

    if len(lines) < 2:
        raise Exception(f"Invalid output for disk space: {df_output}")

    # e.g., Filesystem      Size  Used Avail Use% Mounted on
    headers = lines[0].split()
    values = lines[1].split()

    # Locate 'Avail' column by index in headers and extract corresponding value from values
    avail_index = headers.index('Avail')
    available_space = values[avail_index]

    # Convert the available space to bytes
    return available_space

def ConvertToBytesB(sizeStr):
    # Convert human-readable sizes (like "500 MB") to bytes
    sizeStr = sizeStr.strip()
    size, unit = float(sizeStr[:-2]), sizeStr[-2:].upper()
    
    if unit == 'KB':
        return size * 1024
    elif unit == 'MB':
        return size * 1024 ** 2
    elif unit == 'GB':
        return size * 1024 ** 3
    elif unit == 'TB':
        return size * 1024 ** 4
    else:
        return size  # Assuming it's already in bytes if no unit

def ConvertToBytes(sizeStr):
    sizeStr = sizeStr.strip().upper()
    
    # Regular expression to match size (e.g., '500M', '10G', etc.)
    size_re = re.match(r'(\d+(\.\d+)?)([KMGT]?)', sizeStr)
    if not size_re:
        raise Exception(f"Invalid size format: {sizeStr}")

    size = float(size_re.group(1))
    unit = size_re.group(3)

    # Map unit to multiplier
    multiplier = {
        'K': 1024,
        'M': 1024 ** 2,
        'G': 1024 ** 3,
        'T': 1024 ** 4
    }.get(unit, 1)  # Default is bytes if no unit

    return int(size * multiplier)

def GetDiskUsageRemote(elasticVmUser, elasticVmPassword, elasticHost, elasticDataDir):
    try:
        sshClient = CreateSshClient(elasticHost, int(22), elasticVmUser, elasticVmPassword)
        if not sshClient:
            return False
        
        stdin, stdout, stderr = sshClient.exec_command(f"df -h {elasticDataDir} | tail -n 1")
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        # if error:
        #     raise Exception(f"Error retrieving disk usage: {error}")
        if error or not output:
            logger.error(f"Error retrieving disk usage: {error}")
            return False

        # Parse the output
        fields = output.split()
        totalSpace = fields[1]
        usedSpace = fields[2]
        freeSpace = fields[3]

        return {
            "total_disk_space": FormatSize(ConvertToBytes(totalSpace)),
            "used_disk_space": FormatSize(ConvertToBytes(usedSpace)),
            "free_disk_space": FormatSize(ConvertToBytes(freeSpace))
        }
    except Exception as e:
        logger.error(f"Failed to connect via SSH: {e}")
        return False
    
    finally:
        if sshClient:
            sshClient.close()

def Duration(startTime, endTime):
    if endTime is None:
        endTime = datetime.now()
    duration = endTime - startTime
    totalSeconds = duration.total_seconds()
    hours, remainder = divmod(totalSeconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    formattedDuration = f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
    return formattedDuration

def LocalBackupDetails():
    payload  = { 
        "local_ip" : config["LOCAL_ELASTICSEARCH_HOST"],
        "local_path" : config["ELASTICSEARCH_DATA_DIR"],
    }
    remoteDiskUsage = GetDiskUsageRemote(config["LOCAL_ELASTICSEARCH_VM_USER"],
                                            config["LOCAL_ELASTICSEARCH_VM_PASSWORD"],
                                            config["LOCAL_ELASTICSEARCH_HOST"],
                                            config["ELASTICSEARCH_DATA_DIR"])
    if not remoteDiskUsage:
        payload.update({
            "status":False,
            "message":"Invalid credentials. Please enter valid credentials",
            "data":None,
            "error":"Please provide valid credentials to check disk usage"
        })
        return False, payload

    payload.update({
        "status":True,
        "disk_usage":remoteDiskUsage,
        "error":None,
    })
    return True, payload

SYSTEM_INDEX_PREFIXES = ["."]

def DeleteUserIndices(es):
    try:
        all_indices = es.indices.get_alias(index="*").keys()
        user_indices = [
            index for index in all_indices
            if not any(index.startswith(prefix) for prefix in SYSTEM_INDEX_PREFIXES)
        ]

        # Delete each user index
        for index in user_indices:
            logger.debug(f"Deleting index: {index}")
            es.indices.delete(index=index, ignore=[400, 404])

        logger.info("All user-created indices have been deleted successfully.")
        return True

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return False

def SaveDataToDb(backupType, backupMode, ipAddress, path, responseStatus, message, duration, userId):
    serializer = BackupRestoreSerializer(data={
                                            'database_type':"elasticsearch",
                                            'backup_type':backupType.lower(),
                                            'backup_mode':backupMode,
                                            'ip_address':ipAddress,
                                            'path':path,
                                            'status': responseStatus,
                                            'summary':message,
                                            'duration':duration,
                                            'created_on':int(datetime.now().timestamp()),
                                            # 'updated_on':int(datetime.now().timestamp()),
                                            'created_by':userId,
                                            # 'updated_by':"748bc822-e613-4b57-88ae-d970abae62ba",
                                            })
                
    if serializer.is_valid():
        serialzedData = serializer.save()
        serialzedData = serializer.data
        return True, serialzedData
    else:
        logger.error(f"Error occurred while logging to db: {serializer.errors}")
        return False, None

def UpdateStatusToDb(backupId, status, message, duration=None):
    try:
        backup = BackupAndRestore.objects.get(id=backupId)
        backup.status = status
        backup.summary = message
        if duration is not None:
            backup.duration = duration
        backup.save()
        return True
    except Exception as e:
        logger.error(f"Error occurred while updating status in db: {e}")
        return False         

def ElasticVersion(host=None, username=None, password=None):
    try:
        if username and password:
            url = f"http://{host}/"
            response = requests.get(url, auth=(username, password), verify=False)
            if response.status_code == 200:
                version = response.json().get('version', {}).get('number')
                return version
    except Exception as e:
        logger.error(f"Error fetching Elasticsearch version: {e}")
        return False

def InsertRestoreLogToPostgres(postgresHost, postgresPort, postgresUser, postgresPassword, postgresDatabaseName, postgresTableName, backupType, backupMode, ipAddress, path, responseStatus, message, duration, restoreId=None):
    try:
        conn = psycopg2.connect(
            host=postgresHost,
            port=postgresPort,
            user=postgresUser,
            password=postgresPassword,
            dbname="postgres"  # default DB
        )
        if not conn:
            logger.error("Failed to connect to PostgreSQL database.")
            return False, None
        conn.autocommit = True
        cursor = conn.cursor()

        cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (postgresDatabaseName,))
        dbExists = cursor.fetchone()

        if not dbExists:
            cursor.execute(f"CREATE DATABASE \"{postgresDatabaseName}\"")
            logger.info(f"Database '{postgresDatabaseName}' created.")
        else:
            logger.info(f"Database '{postgresDatabaseName}' already exists.")

        conn = psycopg2.connect(
            host=postgresHost,
            port=postgresPort,
            user=postgresUser,
            password=postgresPassword,
            dbname=postgresDatabaseName
        )
        if not conn:
            logger.error("Failed to connect to PostgreSQL database.")
            return False, None
        cursor = conn.cursor()
        cursor.execute("""
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = %s
            )
        """, (postgresTableName,))
        tableExists = cursor.fetchone()[0]

        if not tableExists:
            logger.info(f"Table '{postgresTableName}' does not exist creating it.")
            cursor.execute(f"""
                CREATE TABLE {postgresTableName} (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

                database_type VARCHAR(100) NOT NULL,
                backup_type VARCHAR(100) NOT NULL,
                backup_mode VARCHAR(50),

                ip_address VARCHAR(100) NOT NULL,
                path VARCHAR(255),

                status VARCHAR(54),
                summary VARCHAR(100),
                duration VARCHAR(100),

                created_on BIGINT NOT NULL
                )
            """)
            conn.commit()
        else:
            cursor.execute(f"""
                SELECT id FROM {postgresTableName}
                WHERE database_type = %s AND backup_type = %s AND backup_mode = %s
                ORDER BY created_on DESC LIMIT 1
            """, ("elasticsearch", backupType, backupMode))
            row = cursor.fetchone()

            if row:
                restoreId = row[0]
                updateQuery = f"""
                    UPDATE {postgresTableName}
                    SET status = %s, path = %s, summary = %s, duration = %s, created_on = %s
                    WHERE id = %s
                """
                cursor.execute(updateQuery, (responseStatus, path, message, duration, int(datetime.now().timestamp()), restoreId))  # BUG ID 2147: Restore logs - Remote Restore 
                conn.commit()
                logger.info(f"Restore log updated with (ID: {restoreId}).")
                return True, None
        
        if not restoreId:
            insertQuery = f""" INSERT INTO {postgresTableName} (
                    database_type, backup_type, backup_mode,
                    ip_address, path, status, summary,
                    duration, created_on
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """

            values = (
                "elasticsearch",
                backupType,
                backupMode,
                ipAddress,
                path,
                # "Scheduled",
                responseStatus,
                message,
                duration,
                int(datetime.now().timestamp()),
            )
            cursor.execute(insertQuery, values)
            conn.commit()
            restoreId = cursor.fetchone()[0]
        
            logger.info("Restore log inserted into PostgreSQL successfully.")
            return True, restoreId
        
    except Exception as e:
        logger.error(f"Failed to insert restore log to PostgreSQL: {str(e)}")
        return False, None
    finally:
        try:
            if cursor: cursor.close()
            if conn: conn.close()
        except:
            pass
    
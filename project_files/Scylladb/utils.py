import os
import re
import time
import psycopg2
import requests
import datetime
import paramiko
import threading
from .views import *
from LoggConfig import *
from scp import SCPClient
from Postgresdb.models import *
from rest_framework import status
from Postgresdb.serializer import *
from cassandra.cluster import Cluster
from psycopg2.extras import RealDictCursor
from cassandra.query import SimpleStatement
from rest_framework.response import Response
from cassandra.auth import PlainTextAuthProvider

from dotenv import load_dotenv
load_dotenv()

config = {
    "LOG_PATH":os.getenv("LOG_PATH"),
    "LOG_LEVEL": os.getenv("LOG_LEVEL").split(","),
    "SERVICE_NAME":os.getenv("SERVICE_NAME"),
    "SERVICE_ID":"ScyllaDB",
    "CONSOLE_LOGS_ENABLED":os.getenv("CONSOLE_LOGS_ENABLED"),
    "SCYLLA_DATA_DIR":os.getenv("SCYLLA_DATA_DIR"),
    "SCYLLA_VM_USER":os.getenv("SCYLLA_VM_USER"),
    "SCYLLA_VM_PASSWORD":os.getenv("SCYLLA_VM_PASSWORD"),
    "LOCAL_SCYLLA_HOST":os.getenv("LOCAL_SCYLLA_HOST"),
    "SSH_TIMEOUT":int(os.getenv("SSH_TIMEOUT")),
    "LOCAL_TEMP_DIR":os.getenv("LOCAL_TEMP_DIR"),
    "SCYLLA_PORT":os.getenv("SCYLLA_PORT"),
    "SCYLLA_AUTHENTICATION_ENABLED":os.getenv("SCYLLA_AUTHENTICATION_ENABLED"),
    "SCYLLA_USERNAME":os.getenv("SCYLLA_USERNAME"),
    "SCYLLA_PASSWORD":os.getenv("SCYLLA_PASSWORD"),
    "POSTGRESQL_RESTORE_LOG_DATABASE_NAME":os.getenv("POSTGRESQL_RESTORE_LOG_DATABASE_NAME"),
    "POSTGRESQL_RESTORE_LOG_TABLE_NAME":os.getenv("POSTGRESQL_RESTORE_LOG_TABLE_NAME"),
}
logclass = LocalLogger(config)
logger = logclass.createLocalLogger()

SYSTEM_KEYSPACES = [
    "system", "system_schema", "system_auth",
    "system_distributed", "system_traces", "system_distributed_everywhere"
]

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
    
# def LogUserActivity(request,userName,activity):
#     api_url = os.environ.get('API_URL_ENDPOINT') + os.environ.get('UMM_POST_USER_ACTIVITY') 
#     authHeader = request.META.get('HTTP_AUTHORIZATION')
#     if not authHeader:
#         return Response({"message" : "Token Not Found"},status=status.HTTP_400_BAD_REQUEST)
#     token = authHeader.split()[1]

#     headers = {
#         'Authorization': f'Bearer {token}',
#         'Content-Type': 'application/json',  # Adjust the content type if needed
#     }
#     try:              
#         log_useractivity_json = {
#             "username":userName,
#             "activity": activity
#         }
#         response = requests.post(api_url, json=log_useractivity_json, headers=headers)
#         # print(response.json())
#         if response.status_code == 201:
#             logger.info("User activity has been Successfully logged to DB")
#             return Response(response.json(), status=status.HTTP_200_OK)
#         else:
#             logger.error("Failed to log User activity")
#             return Response({"message" : response.json()},status=status.HTTP_400_BAD_REQUEST)

#     except Exception as e:
#         logger.error(f"Thread {threading.current_thread().name}: Error in calling Log API: {str(e)}") 
            
def CreateSshClient(host, port, user, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, port=port, username=user, password=password, timeout=config['SSH_TIMEOUT'])
        logger.info("Connection established..")
        return client
    except Exception as e:
        logger.error(f"Error occurred while connecting to remote host : {e}")
        return False

def CreateScyllaSession(host, port, isRemote, username=None, password=None):
    try:
        if isRemote:
            if username and password:
                authProvider = PlainTextAuthProvider(username, password)
                cluster = Cluster([host], port=int(port), auth_provider=authProvider)
            else:
                cluster = Cluster([host], port=int(port))
        else:
            if config["SCYLLA_AUTHENTICATION_ENABLED"].lower().strip() == "true":
                authProvider = PlainTextAuthProvider(config["SCYLLA_USERNAME"], config["SCYLLA_PASSWORD"])
                cluster = Cluster([host], port=int(port), auth_provider=authProvider)
            else:
                cluster = Cluster([host], port=int(port))

        session = cluster.connect()
        return session, cluster
    except Exception as e:
        logger.error(f"Error occurred while connecting to ScyllaDB: {e}")
        return False, None

def clusterShutdown(cluster, session):
    try:
        cluster.shutdown()
        session.shutdown()
    except Exception as e:
        logger.error(f"Error occurred while shutting down the cluster: {e}")

def CheckDirExists(ssh, path):
    # Check if the directory exists on the remote server
    command = f'if [ -d "{path}" ]; then echo "exists"; fi'
    stdin, stdout, stderr = ssh.exec_command(command)
    return stdout.read().decode().strip() == "exists"

def CheckForErrors(stdout, stderr):
    stdoutOutput = stdout.read().decode().strip()
    stderrOutput = stderr.read().decode().strip()
    safeWarnings = ["[sudo] password"]
    
    if stderrOutput:
        # If stderr is NOT only a known safe warning, it's an error
        if not any(warning in stderrOutput for warning in safeWarnings):
            logger.error(f"Error: {stderrOutput}")
            return False

    if stdoutOutput:
        logger.info(f"Output: {stdoutOutput}")

    return True

def IsValidFileName(userProvidedFilename):
    fileNamePattern = r'^[a-zA-Z0-9_.]{3,25}$'
    return re.match(fileNamePattern,userProvidedFilename) is not None    

def FormatSize(sizeInBytes):
    if sizeInBytes < 1024:
        return f"{sizeInBytes} B"
    elif sizeInBytes < 1024**2:
        return f"{sizeInBytes / 1024:.2f} KB"
    elif sizeInBytes < 1024**3:
        return f"{sizeInBytes / 1024**2:.2f} MB"
    elif sizeInBytes < 1024**4:
        return f"{sizeInBytes / 1024**3:.2f} GB"
    else:
        return f"{sizeInBytes / 1024**4:.2f} TB"

def ConvertToBytes(sizeStr):
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

def GetDiskUsageRemote(scyllaVmUser, scyllaVmPassword, scyllaHost, scyllaDataDir):
    try:
        sshClient = CreateSshClient(scyllaHost, int(22), scyllaVmUser, scyllaVmPassword)
        if not sshClient:
            return False
        
        stdin, stdout, stderr = sshClient.exec_command(f"df -h {scyllaDataDir} | tail -n 1")
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
            "total_disk_space": FormatSize(ConvertToBytesB(totalSpace)),
            "used_disk_space": FormatSize(ConvertToBytesB(usedSpace)),
            "free_disk_space": FormatSize(ConvertToBytesB(freeSpace))
        }
    except Exception as e:
        logger.error(f"Failed to connect via SSH: {e}")
        return False
    
    finally:
        if sshClient:
            sshClient.close()


def GetEstimatedBackupSize(sshClient, keySpaces):
    if isinstance(keySpaces, str):
        keySpaces = [keySpaces]
        
    backupSizeEstimates = {}
    totalBackupSize = 0

    try:
        for keySpace in keySpaces:
            logger.debug(f"Keyspaces: {keySpace}")
            command = f'nodetool cfstats {keySpace}'
            stdin, stdout, stderr = sshClient.exec_command(command)

            stdoutOutput = stdout.read().decode()
            errorOutput = stderr.read().decode()

            if errorOutput:
                backupSizeEstimates[keySpace] = "0 B"
                continue

            totalSizeMatch = re.search(r'Space used \(total\):\s+(\d+)', stdoutOutput)
            
            if totalSizeMatch:
                totalSize = int(totalSizeMatch.group(1))
                formattedSize = FormatSize(totalSize) 
                backupSizeEstimates[keySpace] = formattedSize
                totalBackupSize += totalSize
            else:
                logger.error(f"Could not find size information for keyspace '{keySpace}'.")
                backupSizeEstimates[keySpace] = "0 B"

    except Exception as e:
        logger.error(f"Error estimating backup sizes: {e}")
        return None

    finally:
        formattedTotalSize = FormatSize(totalBackupSize)

    return backupSizeEstimates, formattedTotalSize

def KeyspaceExists(host, port, keyspace, isRemote, username=None, password=None):
    try:
        logger.info(f"Checking keyspace")
        session, cluster = CreateScyllaSession(host, port, isRemote, username, password)
        query = f"SELECT keyspace_name FROM system_schema.keyspaces WHERE keyspace_name = '{keyspace}'"
        result = session.execute(query)
        return len(result.current_rows) > 0
    except Exception as e:
        logger.error(f"Error checking keyspace: {str(e)}")
        return False

def CheckTablesExist(host, username, password, keyspace, tableName):
    authProvider = PlainTextAuthProvider(username, password)
    cluster = Cluster([host],auth_provider=authProvider)
    
    try:
        logger.info("Checking table exists")
        session = cluster.connect(keyspace)  # Connect to the specified keyspace
        query = f"SELECT table_name FROM system_schema.tables WHERE keyspace_name = '{keyspace}' AND table_name = '{tableName}'"
        result = session.execute(query)
        return len(result.current_rows) > 0
    except Exception as e:
        logger.error(f"Error checking table: {str(e)}")
        return False
    finally:
        cluster.shutdown()

def GetTableUuid(scyllaHost, scyllaPort, keyspace, tablename, isRemote, username, password):
    # Connect to the ScyllaDB cluster
    session, cluster = CreateScyllaSession(scyllaHost, scyllaPort, isRemote, username, password)

    # Switch to the desired keyspace
    session.set_keyspace(keyspace)

    # Query to get the UUID of the table
    query = "SELECT id FROM system_schema.tables WHERE keyspace_name = %s AND table_name = %s"
    statement = SimpleStatement(query)
    result = session.execute(statement, (keyspace, tablename))

    # Close the connection
    clusterShutdown(cluster, session)

    # Check if we got a result
    if result and len(result.current_rows) > 0:
        return result[0].id  # Assuming `table_id` returns the UUID
    else:
        return None

def StartScylla(host, username, password):
    try:
        sshclient = CreateSshClient(host, 22, username, password)
        command = f'echo {password} | sudo -S systemctl restart scylla-server'
        logger.info("Restarting Scylla service...")
        stdin, stdout, stderr = sshclient.exec_command(command)
        stdoutOutput = stdout.read().decode().strip()
        stderrOutput = stderr.read().decode().strip()

        if stderrOutput and not stderrOutput.lower().startswith("[sudo] password for"):
            logger.error(f"Critical Error: {stderrOutput}")
            return False
        
        if stdoutOutput:
            logger.info(f"Output: {stdoutOutput}")
        
        return True
    except Exception as e:
        logger.error("Error restarting scylla server" + str(e))
        return False

def CopyFilesToDestination(host, username, password, sourcePath):
    temp_path = "/tmp/scylla_tmp"
    try:
        sshClient = CreateSshClient(host, 22, username, password)
        stdin, stdout, stderr = sshClient.exec_command(f"mkdir -p {temp_path}")
        CheckForErrors(stdout, stderr)
        
        with SCPClient(sshClient.get_transport()) as scp:
            # List files in the local source directory
            local_files = os.listdir(sourcePath)

            for file in local_files:
                local_file_path = os.path.join(sourcePath, file)
                remote_file_path = os.path.join(temp_path, file)
                print(f"Copying {file} to {remote_file_path}...")
                # Copy file to the remote destination
                try:
                    scp.put(local_file_path, remote_file_path)
                    print(f"Successfully copied {file} to {remote_file_path}")
                except Exception as e:
                    print(f"Error copying {file}: {e}")
    except Exception as e:
        logger.error(f"SSH connection failed: {e}")
        return False
    finally:
        sshClient.close()

def ChangeOwnership(host, username, password):
    try:
        sshClient = CreateSshClient(host, 22, username, password)
        tempPath = "/tmp/scylla_tmp"
        command = f'echo {password} | sudo -S chown scylla:scylla {tempPath}/*'
        stdin, stdout, stderr = sshClient.exec_command(command)
        CheckForErrors(stdout, stderr)
            
    except Exception as e:
        # print(f"SSH connection failed: {e}")
        logger.error(f"SSH connection failed: {e}")
        return False
    finally:
        if sshClient:
            sshClient.close()

def MoveFiles(host, username, password, keyspace, tablename):
    try:
        with CreateSshClient(host, 22, username, password) as sshClient:
            tempPath = "/tmp/scylla_tmp"
            uuid= GetTableUuid(host, keyspace, tablename)
            tableid = str(uuid).replace("-", "")
            destinationPath = f"/var/lib/scylla/data/{keyspace}/{tablename}-{tableid}"

            command = f'echo {password} | sudo -S mv "{tempPath}"/* "{destinationPath}"'
            stdin, stdout, stderr = sshClient.exec_command(command)
            CheckForErrors(stdout, stderr)
            command = f'echo {password} | sudo -S rm -rf "{tempPath}"'
            stdin, stdout, stderr = sshClient.exec_command(command)
            CheckForErrors(stdout, stderr)
            
    except Exception as e:
        # print(f"SSH connection failed: {e}")
        logger.error(f"Error occurred while moving files to scylla tables directory: {e}")
        return False

def CaptureDataForSingleTableLocalAndRemote(host, username, password, keyspace, tablename, snapshotTag, backupPath, isRemote=False, remoteHost=None, remotePort=None, remoteUser=None, remotePassword=None):
    sshClient = CreateSshClient(host, 22, username, password)
    
    command = f"nodetool snapshot --tag {snapshotTag} --table {tablename} {keyspace}"
    logger.debug("Snapshot command"+ command)
    stdin, stdout, stderr = sshClient.exec_command(command)
    
    stdoutOutput = stdout.read().decode()
    errorOutput = stderr.read().decode()
    
    if errorOutput:
        logger.error(f"Error during snapshot creation: {errorOutput}")
        return

    logger.info(f"Snapshot created successfully: {stdoutOutput}")
    
    # Find the snapshot directory
    findSnapshotCommand = f"find /var/lib/scylla/data/{keyspace}/{tablename}-*/snapshots/{snapshotTag} -type d"
    
    stdin, stdout, stderr = sshClient.exec_command(findSnapshotCommand)
    snapshotDir = stdout.read().decode().strip()
    errorOutput = stderr.read().decode()
    
    if errorOutput or not snapshotDir:
        logger.error(f"Error finding snapshot directory: {errorOutput}")
        raise Exception(f"Snapshot directory not found: {errorOutput}")

    logger.info(f"Snapshot directory found: {snapshotDir}")
    
    # Create an SFTP client for local or remote transfer
    scpClient = paramiko.SFTPClient.from_transport(sshClient.get_transport())
    
    if isRemote:
        # Handle remote backup to a different machine
        remoteSshClient = CreateSshClient(remoteHost, remotePort, remoteUser, remotePassword)
        remoteSftpClient = paramiko.SFTPClient.from_transport(remoteSshClient.get_transport())
        
        backupPath = f'{backupPath}/{os.path.basename(snapshotDir)}' # BUG ID 2117: Scylla Partial Remote Backup files not in the same path as shown in UI 
        CreateRemoteDir(remoteSshClient, backupPath)

        # Transfer each snapshot file to the remote backup machine
        for file in scpClient.listdir(snapshotDir):
            remoteFilePath = f"{snapshotDir}/{file}"
            with scpClient.file(remoteFilePath, 'rb') as file_obj:
                remoteBackupFilePath = os.path.join(backupPath, file)
                with remoteSftpClient.file(remoteBackupFilePath, 'wb') as remote_file_obj:
                    remote_file_obj.write(file_obj.read())
                    print(f"Copied {file} to remote: {remoteBackupFilePath}")
        
        # Close the remote SFTP connection
        remoteSftpClient.close()
        remoteSshClient.close()
    
    # else:
    #     # Handle local backup
    #     if not os.path.exists(localPath):
    #         os.makedirs(localPath)
        
    #     # Transfer each snapshot file to the local backup path
    #     for file in scpClient.listdir(snapshot_dir):
    #         remote_file_path = f"{snapshot_dir}/{file}"
    #         local_file_path = os.path.join(localPath, file)
    #         scpClient.get(remote_file_path, local_file_path)
    #         print(f"Copied {file} to {localPath}")
    
    # Close the SFTP and SSH connections
    scpClient.close()
    sshClient.close()
    
    # print(f"Backup of table {tablename} completed successfully.")
    logger.info(f"Backup of table {tablename} completed successfully.")
    return backupPath if isRemote else snapshotDir


def ListSnapshots(host, port, username, password, keyspace, table):
    sshClient= CreateSshClient(host, int(port), username, password)
    
    command = 'nodetool listsnapshots'
    stdin, stdout, stderr = sshClient.exec_command(command)
    
    stdoutOutput = stdout.read().decode()
    errorOutput = stderr.read().decode()
    
    if errorOutput:
        logger.error(f"Error: {errorOutput}")
    
    filteredSnapshots = []
    for line in stdoutOutput.splitlines():
        if keyspace in line and table in line:
            parts = line.split() 
            if len(parts) >= 3:
                snapshotKeyspace = parts[1]
                snapshotTable = parts[2]
                snapshotSize = " ".join(parts[3:]).strip()
                
                if parts[0].startswith("pre-drop"):
                    continue

                # Match against provided keyspace_name and table_name
                if snapshotKeyspace == keyspace and snapshotTable == table:
                    snapshot_info = {
                        "snapshot_name": parts[0], 
                        "keyspace": snapshotKeyspace,
                        "table": snapshotTable,
                        "size": snapshotSize.split()[-2] + " " + snapshotSize.split()[-1]
                    }
                    filteredSnapshots.append(snapshot_info)
    
    if filteredSnapshots is None:
        logger.info(f"No snapshots found for keyspace '{keyspace}' and table '{table}'.")
        return None
    
    return filteredSnapshots

#needed for restore single table from local
def RestoreDataForSingleTableLocal(host, scyllaport, username, password, keyspace, tablename, snapshotname):
    try:
        sshClient= CreateSshClient(host, 22, username, password)
        
        if KeyspaceExists(host, scyllaport, keyspace):
            if CheckTablesExist(host, username, password, keyspace, tablename):
        
                table_uuid = GetTableUuid(host, keyspace, tablename)
                tableid = str(table_uuid).replace("-", "")
                dataDir = f"{config['SCYLLA_DATA_DIR']}/{keyspace}/{tablename}-{tableid}"
        
                snapshot_dir = os.path.join(dataDir, 'snapshots', snapshotname)
                
                listDataCommand = f'ls {dataDir}'
                stdin, stdout, stderr = sshClient.exec_command(listDataCommand)
                listData = stdout.read().decode().splitlines()
                
                if any(name.startswith(("me-", "ma-", "mb-")) for name in listData):
                    logger.error("Table data already exists.")
                    return False
                
                # logger.info("Snapshot Directory"+snapshot_dir)
                # logger.info("Data Directory:" + dataDir)

                # logger.info(f"Truncating table {keyspace}.{tablename}...")
                # truncate_command = f'cqlsh {host} -e "TRUNCATE {keyspace}.{tablename};"'
                # stdin, stdout, stderr = sshClient.exec_command(truncate_command)
                # CheckForErrors(stdout, stderr)
                
                logger.info(f"Copying snapshot files from {snapshot_dir} to {dataDir}...")
                copyCommand = f"echo {password} | sudo -S cp -r {snapshot_dir}/* {dataDir}/"
                stdin, stdout, stderr = sshClient.exec_command(copyCommand)
                CheckForErrors(stdout, stderr)
                
                changeOwner = f"echo {password} | sudo -S chown scylla:scylla {dataDir}/*"
                stdin, stdout, stderr = sshClient.exec_command(changeOwner)
                CheckForErrors(stdout, stderr)

                logger.info(f"Snapshot {snapshotname} restored successfully to {keyspace}.{tablename}")
            
                return True
        
    except Exception as e:
        logger.error(f"An error occurred during restoration: {e}")
        return False
    finally:
        if sshClient:
            sshClient.close() 

def MoveFilesRemoteToScylla(scyllaSshClient, keyspace, tablename, backupPath, remoteHost, remoteUser, remotePassword):
    try:
        remoteSshClient = CreateSshClient(remoteHost, 22, remoteUser, remotePassword)
        remoteSftpClient = paramiko.SFTPClient.from_transport(remoteSshClient.get_transport())

        targetPath = f"/var/lib/scylla/data/{keyspace}/{tablename}-*/"
        stdin, stdout, stderr = scyllaSshClient.exec_command(f"sudo mkdir -p {targetPath}")
        CheckForErrors(stdout, stderr)

        logger.info(f"Target directory found/created on ScyllaDB host: {targetPath}")
        
        remote_files = remoteSftpClient.listdir(backupPath)
        tempPath = "/tmp/scylla_tmp/"
        
        stdin, stdout, stderr = scyllaSshClient.exec_command(f"mkdir -p {tempPath}")
        CheckForErrors(stdout, stderr)

        scyllaSftpClient = paramiko.SFTPClient.from_transport(scyllaSshClient.get_transport())

        for remote_file in remote_files:
            remote_file_path = os.path.join(backupPath, remote_file)
            scylla_temp_file = os.path.join(tempPath, remote_file)  # Temp location on ScyllaDB machine
            
            print(f"Transferring {remote_file} from remote backup to ScyllaDB...")

            with remoteSftpClient.file(remote_file_path, 'rb') as remote_file_obj:
                with scyllaSftpClient.file(scylla_temp_file, 'wb') as scylla_file_obj:
                    scylla_file_obj.write(remote_file_obj.read())
                    print(f"Transferred {remote_file} to ScyllaDB at {scylla_temp_file}")

            print(f"Moved {remote_file} to {targetPath}")

        remoteSftpClient.close()
        scyllaSftpClient.close()

        return True
    
    except Exception as e:
        logger.error(f"An error occurred during file movement: {e}")
        return False
    
    finally:
        if remoteSshClient:
            remoteSshClient.close()
        if scyllaSshClient:
            scyllaSshClient.close()

def RestoreDataForSingleTableLocalAndRemote(host, port, username, password, keyspace, tablename, backupPath, isRemote=False,remoteHost=None, remoteUser=None, remotePassword=None):
    try:
        # Create an SSH client for the target ScyllaDB host
        sshClient = CreateSshClient(host, 22, username, password)
        
        # Check if the keyspace and table exist
        if KeyspaceExists(host, port, keyspace):
            if CheckTablesExist(host, username, password, keyspace, tablename):
                uuid= GetTableUuid(host, keyspace, tablename)
                tableid = str(uuid).replace("-", "")
                destinationPath = f"{config['SCYLLA_DATA_DIR']}/{keyspace}/{tablename}-{tableid}"
                
                listDataCommand = f'ls {destinationPath}'
                stdin, stdout, stderr = sshClient.exec_command(listDataCommand)
                listData = stdout.read().decode().splitlines()
                
                if any(name.startswith(("me-", "ma-", "mb-")) for name in listData):
                    logger.error("Table data already exists.")
                    return False
                
                if isRemote:
                    MoveFilesRemoteToScylla(sshClient,keyspace,tablename,backupPath,remoteHost,remoteUser,remotePassword)
                    ChangeOwnership(host,username,password)
                    MoveFiles(host,username,password,keyspace,tablename)
                # else:
                #     CopyFilesToDestination(host, username, password, localPath)
                #     time.sleep(2)
                #     ChangeOwnership(host, username, password)
                #     time.sleep(2)
                #     MoveFiles(host, username, password, keyspace, tablename)
                
                #     print("Data restoration completed successfully.")
                    return True
            else:
                logger.error(f"Table not found")
                return False
        else:
            logger.error(f"Keyspace not found")
            return False
    
    except Exception as e:
        logger.error(f"An error occurred during restoration: {e}")
        return False
    
    finally:
        sshClient.close()
    
    # return True

def RestoreKeySpaceFromLocal(hostIP, scyllaPort, scyllaUser, scyllaPassword, username, password, fileName, isRemote):
    sshClient = CreateSshClient(hostIP,22,username,password)
    sftp = sshClient.open_sftp()
    scyllaDataDir = config['SCYLLA_DATA_DIR']
    restored = False
    try:
        keySpaceFound = []
        for keyspace in sftp.listdir(scyllaDataDir):
            if keyspace not in SYSTEM_KEYSPACES and not keyspace.startswith("."):
                keySpaceFound.append(keyspace)
        
        for keyspace in keySpaceFound:
            keyspacePath = os.path.join(scyllaDataDir, keyspace)
            
            if not KeyspaceExists(hostIP, scyllaPort, keyspace, isRemote):
                logger.debug(f"keyspace {keyspace} does not exist creating it")
                CreatNewKeyspace(hostIP, scyllaPort, 22, scyllaUser, scyllaPassword, username, password, keyspace, isRemote)
            else:
                logger.error("Restore failed: Keyspace already exists.")
                return False
                
            for tableFolder in sftp.listdir(keyspacePath):
                if '-' not in tableFolder:
                    continue

                tablePath = os.path.join(keyspacePath, tableFolder)
                # Extract the table name from the folder name
                tablename = tableFolder.split('-')[0]
                snapshotsPath = os.path.join(tablePath, 'snapshots')
                snapshotFolders = sftp.listdir(snapshotsPath)
                
                suffix = f"{fileName}_{keyspace}"
                matchedSnapshot = None
                for snap in snapshotFolders:
                    if snap.endswith(suffix):
                        matchedSnapshot = snap
                        break

                if not matchedSnapshot:
                    logger.info(f"No matching snapshot ending with '{suffix}' found for {keyspace}.{tableFolder}")
                    continue
                
                snapshotFullPath = os.path.join(snapshotsPath, matchedSnapshot)
                snapshotFiles = sftp.listdir(snapshotFullPath)
                if not snapshotFiles:
                    logger.info(f"Snapshot folder '{matchedSnapshot}' is empty for table {keyspace}.{tablename}.")
                    continue
                
                for cqlFile in sftp.listdir(snapshotFullPath):
                    if cqlFile.endswith('.cql'):
                        logger.info(f"Found schema file: {cqlFile}")
                        
                        remoteCqlPath = f"{snapshotFullPath}/{cqlFile}"
                        # Read the CQL file from the snapshot and execute directly
                        with sftp.file(remoteCqlPath, 'r') as file:
                            cqlContent = file.read().decode('utf-8').replace('\n', ' ').strip()  # Read and decode the schema file contents

                        logger.info(f"Executing CQL directly for table {keyspace}.{tablename}...")

                        # Execute the CQL content directly via cqlsh
                        escapedCqlContent = cqlContent.replace('"', '\\"')
                        if scyllaUser and scyllaPassword:
                            execCqlCommand = f'echo "{escapedCqlContent}" | cqlsh {hostIP} -u {scyllaUser} -p {scyllaPassword}'
                        else:
                            execCqlCommand = f'echo "{escapedCqlContent}" | cqlsh {hostIP}'

                        stdin, stdout, stderr = sshClient.exec_command(execCqlCommand)
                        CheckForErrors(stdout, stderr)
                        
                        tableUuid = GetTableUuid(hostIP, scyllaPort, keyspace, tablename, isRemote, scyllaUser, scyllaPassword)
                        tableid = str(tableUuid).replace("-", "")
                        newTableDataDir  = os.path.join(scyllaDataDir, keyspace, f"{tablename}-{tableid}")
                    
                # print(f"Truncating table {keyspace}.{tablename}...")
                # truncate_command = f'cqlsh {hostIP} -e "TRUNCATE {keyspace}.{tablename};"'
                # stdin, stdout, stderr = sshClient.exec_command(truncate_command)
                # CheckForErrors(stdout, stderr)
                
                logger.info(f"Copying snapshot files from {snapshotFullPath} to {newTableDataDir}...")
                for file in snapshotFiles:
                        
                    srcFile = os.path.join(snapshotFullPath, file)
                    dstFile = os.path.join(newTableDataDir, file)
                    
                    copyCommand = f"echo '{password}' | sudo -S cp '{srcFile}' '{dstFile}'"
                    stdin, stdout, stderr = sshClient.exec_command(copyCommand)
                    CheckForErrors(stdout, stderr)
            
                changeOwner = f"echo {password} | sudo -S chown scylla:scylla {newTableDataDir}/*"
                stdin, stdout, stderr = sshClient.exec_command(changeOwner)
                CheckForErrors(stdout, stderr)
                logger.info(f"Snapshot {fileName} restored successfully")# to {keyspace}.{tablename}") 
                restored = True
                
    except Exception as e:
        # print("Exception occurred while restoring scylla data locally",str(e))
        logger.error("Exception occurred while restoring scylla data locally" + str(e))
        return False
    
    finally:
        sftp.close()
        
    if not restored:
        logger.warning(f"No data was restored using snapshot '{fileName}'. "
                       "Please verify that the snapshot exists and matches the expected name.")
        return False

    return True

def CaptureKeySpaceSnapshotRemoteAndLocal(snapshotTag, scyllaHost, scyllaUser, scyllaPassword, keySpaces, isRemote, backupPath=None, remoteHost=None, remotePort=None, remoteUsername=None, remotePassword=None):
    snapshotResults = {}
    
    try:
        # SSH connection to the ScyllaDB host
        sshClient = CreateSshClient(scyllaHost, 22, scyllaUser, scyllaPassword)
        sftpClient = sshClient.open_sftp()
        
        # Optional SSH connection to the remote backup server (if provided)
        if remoteHost and remoteUsername and remotePassword:
            remoteSshClient = CreateSshClient(remoteHost, int(remotePort), remoteUsername, remotePassword)
            remoteSftpClient = remoteSshClient.open_sftp()

        for keySpace in keySpaces:
            command = f'nodetool snapshot -t {snapshotTag}_{keySpace} {keySpace}'
            stdin, stdout, stderr = sshClient.exec_command(command)
            
            stdoutOutput = stdout.read().decode()
            errorOutput = stderr.read().decode()

            if errorOutput:
                logger.error(f"Error while backup keyspaces: {errorOutput}")

            snapshotIdMatch = re.search(r'snapshot name \[(\S+)\]', stdoutOutput)
            if snapshotIdMatch:
                snapshotId = snapshotIdMatch.group(1)
                logger.info(f"Snapshot for keyspace '{keySpace}' taken successfully. Snapshot ID: {snapshotId}")
                
                basePath = f"{config['SCYLLA_DATA_DIR']}/{keySpace}/"
                
                # List all tables in the keyspace
                listTablesCommand = f'ls {basePath}'
                stdin, stdout, stderr = sshClient.exec_command(listTablesCommand)
                tablePaths = stdout.read().decode().splitlines()
                
                snapshotPaths = []
                # localSnapshotPaths = []
                for tablePath in tablePaths:
                    tableUUIDMatch = re.search(r'-(\S+)', tablePath)
                    if tableUUIDMatch:
                        tableUUID = tableUUIDMatch.group(1)
                        
                    # Construct the path to the snapshot for each table
                    snapshotPath = f"{basePath}{tablePath}/snapshots/{snapshotId}/"
                    if CheckDirExists(sshClient, snapshotPath):
                        snapshotPaths.append((snapshotPath, tableUUID))
                        
                        if backupPath:
                            if isRemote:
                                # If a remote backup path is provided, use the remote SFTP client to transfer
                                remoteTableBackupPath = os.path.join(backupPath, keySpace, tablePath)
                                CreateRemoteDir(remoteSshClient, remoteTableBackupPath)  # Create the directory on remote server

                                # Copy each file from the source machine to the remote backup machine
                                remoteFiles = sftpClient.listdir(snapshotPath)
                                for remoteFile in remoteFiles:
                                    remoteFilePath = os.path.join(snapshotPath, remoteFile)
                                    remoteDestPath = os.path.join(remoteTableBackupPath, remoteFile)
                                    sftpClient.get(remoteFilePath, f'{config["LOCAL_TEMP_DIR"]}/temp_snapshot_file')  # Download to temp on local
                                    remoteSftpClient.put(f'{config["LOCAL_TEMP_DIR"]}/temp_snapshot_file', remoteDestPath)  # Upload to remote
                                    print(f"Transferred {remoteFilePath} to {remoteDestPath}")

                logger.info(f"Snapshot Path: {snapshotPaths}")
                if isRemote:
                    snapshotResults["remote_path"] = backupPath
                else:
                    snapshotResults["keyspaces"] = keySpaces#snapshotPaths
                
            else:
                logger.error("Error: Snapshot directory not found in the output.")
                snapshotResults = None
        
        return snapshotResults

    except Exception as e:
        # print(f"Error taking remote snapshot: {e}")
        logger.error(f"Error taking remote snapshot: {e}")
        return None

    finally:
        sshClient.close()
        sftpClient.close()
        if isRemote:
            remoteSftpClient.close()
            remoteSshClient.close()

def KeyspaceExistsRemote(scyllaHost, scyllaUser, scyllaPassword, scyllaVmUser, scyllaVmPassword, keyspace):
    try:
        sshClient = CreateSshClient(scyllaHost, 22, scyllaVmUser, scyllaVmPassword)
        # Check if the keyspace exists
        if config["SCYLLA_AUTHENTICATION_ENABLED"].lower().strip() == "true":
            checkKeyspaceCommand = f"cqlsh {scyllaHost} -e \"DESCRIBE KEYSPACE {keyspace};\" -u {scyllaUser} -p {scyllaPassword}"
        else:
            checkKeyspaceCommand = f"cqlsh {scyllaHost} -e \"DESCRIBE KEYSPACE {keyspace};\""
        stdin, stdout, stderr = sshClient.exec_command(checkKeyspaceCommand)
        stderrOutput = stderr.read().decode().strip().lower()
        stdoutOutput = stdout.read().decode().strip().lower()

        if "does not exist" in stderrOutput:
            return False
        if stderrOutput:
            logger.warning(f"Error when checking keyspace: {stderrOutput}")
            return False

        if "create keyspace" in stdoutOutput:
            return True

        return bool(stdoutOutput)
    except Exception as e:
        # print(f"Error checking if keyspace exists: {e}")
        logger.error(f"Error checking if keyspace exists: {e}")
        return False
    finally:
        sshClient.close()

def TableExists(host, username, password, keyspace, table):
    try:
        # Create an SSH client
        sshClient = CreateSshClient(host, 22, username, password)
        # Check if the table exists
        checkTableCommand = f"cqlsh {host} -e \"SELECT * FROM {keyspace}.{table} LIMIT 1;\""
        stdin, stdout, stderr = sshClient.exec_command(checkTableCommand)
        stderr_output = stderr.read().decode().strip()

        # If there's no output in stderr, it means the table exists
        return stderr_output == ''
    
    except Exception as e:
        # print(f"Error checking if table '{table}' exists: {e}")
        logger.error(f"Error checking if table '{table}' exists: {e}")
        return False
    finally:
        sshClient.close()

# Function to execute schema file on Scylla host
def ExecuteSchemaFileOnScylla(scyllaHost, scyllaUser, scyllaPassword, username, password, local_schema_file):
    try:
        scyllaSshClient = CreateSshClient(scyllaHost, 22, username, password)
        scp_client = SCPClient(scyllaSshClient.get_transport())
        
        # Upload schema file to the Scylla host
        remote_schema_path = f"/tmp/{os.path.basename(local_schema_file)}"
        scp_client.put(local_schema_file, remote_schema_path)
        # print(f"Uploaded schema file to {remote_schema_path} on {scyllaHost}")
        logger.info(f"Uploaded schema file to {remote_schema_path} on {scyllaHost}")
        
        # Execute schema file using cqlsh on the Scylla host
        if config["SCYLLA_AUTHENTICATION_ENABLED"].lower().strip() == "true":
            command = f"cqlsh {scyllaHost} -f {remote_schema_path} -u {scyllaUser} -p {scyllaPassword}"
        else:    
            command = f"cqlsh {scyllaHost} -f {remote_schema_path}"
            
        stdin, stdout, stderr = scyllaSshClient.exec_command(command)
        
        result = stdout.read().decode()
        error = stderr.read().decode()
        
        if error:
            logger.error(f"Error executing schema file: {error}")
        else:
            logger.info(f"Schema file executed successfully: {result}")
    finally:
        scyllaSshClient.close()

def RestoreKeySpaceFromRemote(ScyllaHost, scyllaPort, scyllaUser, scyllaPassword, username, password, isRemote, backupPath=None, remoteHost=None, remoteUsername=None, remotePassword=None):
    try:
        # SSH connection to the ScyllaDB host
        sshClient = CreateSshClient(ScyllaHost, 22, username, password)
        sftpClient = sshClient.open_sftp()

        # Optional SSH connection to the remote backup server (if provided)
        if isRemote and remoteHost and remoteUsername and remotePassword:
            remoteSshClient = CreateSshClient(remoteHost, 22, remoteUsername, remotePassword)
            remoteSftpClient = remoteSshClient.open_sftp()
        
            remoteDirs = remoteSftpClient.listdir(backupPath)

        for keySpace in remoteDirs:
            if KeyspaceExistsRemote(ScyllaHost, scyllaUser, scyllaPassword, username, password, keySpace):
                logger.error(f"Restore aborted: keyspace '{keySpace}' already exists.")
                return False

        for keySpace in remoteDirs:
            CreatNewKeyspace(ScyllaHost, scyllaPort, 22, scyllaUser, scyllaPassword, username, password, keySpace, isRemote)
            
            tablePath = os.path.join(backupPath, keySpace)
            for table in remoteSftpClient.listdir(tablePath):
                tableName = table.split('-')[0]
                
                schemaFilePath = os.path.join(tablePath, table, "schema.cql")
                try:
                    remoteSftpClient.stat(schemaFilePath)  # Check if the schema file exists

                    # Download the schema file to a local temporary location
                    localSchemaFile = f"/tmp/{table}_schema.cql"
                    remoteSftpClient.get(schemaFilePath, localSchemaFile)

                    # Execute the schema file on the ScyllaDB host
                    ExecuteSchemaFileOnScylla(ScyllaHost, scyllaUser, scyllaPassword, username, password, localSchemaFile)

                    tableUuid = GetTableUuid(ScyllaHost, scyllaPort, keySpace, tableName, isRemote, scyllaUser, scyllaPassword)

                    if tableUuid:
                        print(f"Found UUID for table {tableName}: {tableUuid}")
                        tableid = str(tableUuid).replace("-", "")
                        tableDataDir = f"/var/lib/scylla/data/{keySpace}/{tableName}-{tableid}"
                        print("new tables uuid: ",tableDataDir)

                        datafilePath = os.path.join(tablePath, table)
                        print("data file path: ",datafilePath)
                        
                        remoteTableDir = f"/tmp/scylla/{keySpace}/{tableName}/"
                        stdin, stdout, stderr = sshClient.exec_command(f"mkdir -p {remoteTableDir}")
                        CheckForErrors(stdout, stderr)
                        
                        for dataFile in remoteSftpClient.listdir(datafilePath):
                            remotePath = os.path.join(datafilePath, dataFile)
                            localPath = os.path.join(remoteTableDir, dataFile)
                            
                            with remoteSftpClient.file(remotePath, 'rb') as remote_file_obj:
                                with sftpClient.file(localPath, 'wb') as scylla_file_obj:
                                    scylla_file_obj.write(remote_file_obj.read())
                                    print(f"Transferred {remotePath} to ScyllaDB at {localPath}")
                            
                        
                        time.sleep(2)
                        change_owner_command = f"echo {password} | sudo -S chown -R scylla:scylla {remoteTableDir}"
                        stdin, stdout, stderr = sshClient.exec_command(change_owner_command)
                        CheckForErrors(stdout, stderr)
                        logger.info(f"Ownership changed to 'scylla' for {remoteTableDir}")

                        time.sleep(2)
                        # Move files to the actual ScyllaDB table directory
                        moveFilesCommand = f"echo {password} | sudo -S mv {remoteTableDir}* {tableDataDir}/"
                        
                        stdin, stdout, stderr = sshClient.exec_command(moveFilesCommand)
                        CheckForErrors(stdout, stderr)
                        logger.info(f"Files moved to {tableDataDir}")
                        
                        cleanupCommand = f"echo {password} | sudo -S rm -rf {'/tmp/scylla'}"
                        stdin, stdout, stderr = sshClient.exec_command(cleanupCommand)
                        CheckForErrors(stdout, stderr)
                        logger.info(f"Temporary directory {remoteTableDir} removed")
                        
                        cleanupCommand = f"echo {password} | sudo -S rm -rf {localSchemaFile}"
                        stdin, stdout, stderr = sshClient.exec_command(cleanupCommand)
                        CheckForErrors(stdout, stderr)
                        logger.info(f"Temporary directory {localSchemaFile} removed")
                        
                except FileNotFoundError:
                    logger.warning(f"No schema.cql file found for table {tableName} in keyspace {keySpace}. Skipping...")
        
        return True
    
    except Exception as e:
        logger.error(f"Error restoring snapshot: {e}")
        return False
    
    finally:
        sshClient.close()
        sftpClient.close()
        if isRemote:
            remoteSshClient.close()
            remoteSftpClient.close()

# Helper function to create directory on remote server
def CreateRemoteDir(sshClient, path):
    sshClient.exec_command(f'mkdir -p {path}')

def CreatNewKeyspace(host, scyllaPort, port, scyllaUser, scyllaPassword, username, password, keyspace, isRemote):
    try:
        if KeyspaceExists(host, scyllaPort, keyspace, isRemote, scyllaUser, scyllaPassword):
            # print(f"Keyspace '{keyspace}' already exists.")
            logger.info(f"Keyspace '{keyspace}' already exists.")
            return True
        
        sshClient = CreateSshClient(host, int(port), username, password)
        
        # Create the new keyspace
        if scyllaUser and scyllaPassword:
            createKeyspaceCommand = f"cqlsh {host} -e \"CREATE KEYSPACE {keyspace} WITH REPLICATION = {{'class': 'SimpleStrategy', 'replication_factor': 3}};\" -u {scyllaUser} -p {scyllaPassword}"
        else:
            createKeyspaceCommand = f"cqlsh {host} -e \"CREATE KEYSPACE {keyspace} WITH REPLICATION = {{'class': 'SimpleStrategy', 'replication_factor': 3}};\""
            
        stdin, stdout, stderr = sshClient.exec_command(createKeyspaceCommand)
        stderr_output = stderr.read().decode().strip()
        if stderr_output:
            logger.error(f"Error creating keyspace: {stderr_output}")
            return False
        
        # print(f"Keyspace '{keyspace}' created successfully.")
        logger.info(f"Keyspace '{keyspace}' created successfully.")
        return True

    except Exception as e:
        # print(f"Error creating new keyspace: {e}")
        logger.error(f"Error creating new keyspace: {e}")
        return False
    

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

def AvailableData(session, keyspaces):
    skip_if_contains = 'offset'
    availableData = []
    for keyspace in keyspaces:
        query_tables = f"SELECT table_name FROM system_schema.tables WHERE keyspace_name = '{keyspace}';"
        tables = [row.table_name for row in session.execute(query_tables)]
        
        for table in tables:
            query_columns = f"SELECT column_name FROM system_schema.columns WHERE keyspace_name = '{keyspace}' AND table_name = '{table}';"
            columns = [row.column_name for row in session.execute(query_columns)]
            
            columns = [col for col in columns if col not in skip_if_contains not in col]

            if 'ingestion_timestamp' in columns:
                query = f"SELECT min(ingestion_timestamp), max(ingestion_timestamp) FROM {keyspace}.{table};"
                result = session.execute(query).one()
                minDate, maxDate = result
                
                if minDate and maxDate:
                    TimestampMin = datetime.fromtimestamp(minDate).strftime('%Y-%m-%d %H:%M:%S')
                    TimestampMax = datetime.fromtimestamp(maxDate).strftime('%Y-%m-%d %H:%M:%S')
                    print(f"Keyspace: {keyspace}, Table: {table} -> Date range: {TimestampMin} to {TimestampMax}")
                    availableData.append({f"keyspace": keyspace, 
                                            "table": table,
                                            "date range": {"from":TimestampMin,
                                                        "to":TimestampMax}
                                            }) 
                else:
                    payload = {
                        "status":False,
                        "message":"No valid date range found.",
                        "data":None,
                        "error":None
                    }
                    return payload
            else:
                pass
            
    return availableData

def Duration(startTime, endTime):
    if endTime is None:
        endTime = datetime.now()
    duration = endTime - startTime
    totalSeconds = duration.total_seconds()
    hours, remainder = divmod(totalSeconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    formattedDuration = f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
    return formattedDuration

def LocalAndRemoteBackupDetails(isRemote=False, remoteHost=None, remoteUser=None, remotePassword=None, remoteBackupPath=None):
    try:
        if config["SCYLLA_AUTHENTICATION_ENABLED"].lower().strip() == "true":
            auth_provider=PlainTextAuthProvider(username=config["SCYLLA_USERNAME"], password=config["SCYLLA_PASSWORD"])
            cluster = Cluster([config["LOCAL_SCYLLA_HOST"]], port=int(config["SCYLLA_PORT"]), auth_provider=auth_provider)
        else:
            cluster = Cluster([config["LOCAL_SCYLLA_HOST"]], port=int(config["SCYLLA_PORT"]))
            
        session = cluster.connect()
        keySpaces = session.execute("SELECT keyspace_name FROM system_schema.keyspaces")
    except Exception as e:
        logger.error("Error connecting to Scylla" + str(e))
    
    keySpaceNames = []
    totalSize = 0
    payload = {}
    
    if isRemote:
        sshClient = CreateSshClient(remoteHost, 22, remoteUser, remotePassword)
        diskUsage = GetDiskUsageRemote(remoteUser, remotePassword, remoteHost, remoteBackupPath)
    else:    
        sshClient = CreateSshClient(config["LOCAL_SCYLLA_HOST"], 22, config["SCYLLA_VM_USER"], config["SCYLLA_VM_PASSWORD"])
        diskUsage = GetDiskUsageRemote(config["SCYLLA_VM_USER"], config["SCYLLA_VM_PASSWORD"], config["LOCAL_SCYLLA_HOST"], config["SCYLLA_DATA_DIR"])
        payload = { 
            "local_ip" : config["LOCAL_SCYLLA_HOST"],
            "local_path" : config["SCYLLA_DATA_DIR"],
        }
        
    if sshClient:
        try:
            for row in keySpaces:
                keySpaceName=row.keyspace_name
                if keySpaceName in SYSTEM_KEYSPACES:
                    continue
                
                tableSizes = []
                tables = session.execute(f"SELECT table_name FROM system_schema.tables WHERE keyspace_name = '{keySpaceName}'")
                totalKeyspaceSize = 0    
                for table in tables:
                    tableName = table.table_name
                    tableCommand = f"nodetool cfstats {keySpaceName}.{tableName}"
                    stdin, stdout, stderr = sshClient.exec_command(tableCommand)

                    stdoutOutput = stdout.read().decode()
                    errorOutput = stderr.read().decode()

                    if errorOutput:
                        continue

                    totalSizeMatch = re.search(r'Space used \(total\):\s+(\d+)', stdoutOutput)

                    if totalSizeMatch:
                        tableSize = int(totalSizeMatch.group(1))
                        formattedTableSize = FormatSize(tableSize)
                        tableSizes.append({
                            "table_name": tableName,
                            "estimated_size": formattedTableSize
                        })
                        totalKeyspaceSize += tableSize

                # Convert the total size from bytes to a human-readable format
                formattedKeyspaceSize = FormatSize(totalKeyspaceSize)
                keySpaceNames.append({
                    'keyspace_name': keySpaceName,
                    'tables': tableSizes,
                    'total_size': formattedKeyspaceSize
                })

                totalSize += totalKeyspaceSize
            
            if diskUsage:
                payload.update({
                    "status": True,
                    "disk_usage": diskUsage,
                    "error": None,
                })
                return True, payload
            else:
                payload.update({
                    "status": False,
                    "message": "Failed to fetch disk usage",
                    "data": None,
                    "error": "Failed to fetch disk usage, please check the path"
                })
                return False, payload
        
        except Exception as e:
            logger.error("Error occurred while fetching keyspaces results"+str(e))
            payload.update({
                "status": False,
                "message": "Error listing of available keyspaces in the cluster",
                "data": None,
                "error": str(e)
            })
            return False, payload
            
        finally:
            clusterShutdown(session, cluster)
            if isRemote:
                sshClient.close()
    else:
        payload.update({
            "status": False,
            "message": "Error connecting to the remote server",
            "data": None,
            "error": "Failed to establish SSH client"
        })
        return False, payload

def DeleteUserKeyspaces(scyllaHost, scyllaPort, username, password):
    try:
        # Connect to ScyllaDB
        session, cluster = CreateScyllaSession(scyllaHost, scyllaPort, False, username, password)

        # Fetch all keyspaces
        keyspaces = session.execute("SELECT keyspace_name FROM system_schema.keyspaces;")
        userKeyspaces = [row.keyspace_name for row in keyspaces if row.keyspace_name not in SYSTEM_KEYSPACES]
        
        if userKeyspaces:
            # Drop each user-created keyspace
            for keyspace in userKeyspaces:
                logger.debug(f"Dropping keyspace: {keyspace}")
                session.execute(f"DROP KEYSPACE {keyspace};")

        logger.info("All user keyspaces have been deleted successfully.")
        
        clusterShutdown(session, cluster)
        
        return True
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return False

def SaveDataToDb(backupType, backupMode, ipAddress, path, responseStatus, message, duration, userId):
    serializer = BackupRestoreSerializer(data={
                                            'database_type':"scylladb",
                                            'backup_type':backupType.lower(),
                                            'backup_mode':backupMode,
                                            'ip_address':ipAddress,
                                            'path':path,
                                            'status': responseStatus,
                                            'summary':message,
                                            'duration':duration,
                                            'created_on':int(datetime.now().timestamp()),
                                            # 'updated_on':int(datetime.now().timestamp()),
                                            'created_by': userId,
                                            # 'updated_by':"748bc822-e613-4b57-88ae-d970abae62ba",
                                            })
                
    if serializer.is_valid():
        serialzedData = serializer.save()
        serialzedData = serializer.data
        return True, serialzedData
    else:
        logger.error(f"Error occurred while logging to db: {serializer.errors}")
        return False, None 

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
            """, ("scylladb", backupType, backupMode))
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
                "scylladb",
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

def ScyllaVersion(host=None, port=None, username=None, password=None):
    try:
        if username and password:
            authProvider = PlainTextAuthProvider(username, password)
            cluster = Cluster([host], port=int(port), auth_provider=authProvider)
        else:
            cluster = Cluster([host], port=int(port))
            
        session = cluster.connect()
        row = session.execute("SELECT release_version FROM system.local").one()
        if row:
            return row.release_version
    except Exception as e:
        logger.error(f"Error fetching Scylla version: {e}")
        return None

import re
import os
import uuid
import datetime
import psycopg2
import paramiko
import requests
import threading
import urllib3
from .views import *
from io import BytesIO
from minio import Minio
from LoggConfig import *
from minio import S3Error
from scp import SCPClient
from dotenv import load_dotenv
from errno import ENAMETOOLONG
from Postgresdb.models import *
from rest_framework import status
from Postgresdb.serializer import *
from psycopg2.extras import RealDictCursor
from rest_framework.response import Response

load_dotenv()

config = {
    "LOG_PATH":os.getenv("LOG_PATH"),
    "LOG_LEVEL": os.getenv("LOG_LEVEL").split(','),
    "SERVICE_NAME":os.getenv("SERVICE_NAME"),
    "SERVICE_ID":"MinioObjectStore",
    "CONSOLE_LOGS_ENABLED":os.getenv("CONSOLE_LOGS_ENABLED"),
    
    "SSH_TIMEOUT":int(os.getenv("SSH_TIMEOUT")),
    
    "POSTGRESQL_CMM_NAME":os.getenv("POSTGRESQL_CMM_NAME"),
    "POSTGRESQL_USER":os.getenv("POSTGRESQL_USER"),
    "POSTGRESQL_PASSWORD":os.getenv("POSTGRESQL_PASSWORD"),
    "POSTGRESQL_HOST":os.getenv("POSTGRESQL_HOST"),
    "POSTGRESQL_PORT":os.getenv("POSTGRESQL_PORT"),
    "POSTGRESQL_RESTORE_LOG_DATABASE_NAME":os.getenv("POSTGRESQL_RESTORE_LOG_DATABASE_NAME"),
    "POSTGRESQL_RESTORE_LOG_TABLE_NAME":os.getenv("POSTGRESQL_RESTORE_LOG_TABLE_NAME"),
    
    "LOCAL_MINIO_HOST":os.getenv("LOCAL_MINIO_HOST"),
    "LOCAL_MINIO_VM_USER":os.getenv("LOCAL_MINIO_VM_USER"),
    "LOCAL_MINIO_VM_PASSWORD":os.getenv("LOCAL_MINIO_VM_PASSWORD"),
    "MINIO_SECURE":os.getenv("MINIO_SECURE"),
    "MINIO_DATA_DIR":os.getenv("MINIO_DATA_DIR"),
    "LOCAL_TEMP_DIR":os.getenv("LOCAL_TEMP_DIR"),
    
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
        client.connect(hostname=server, port=port, username=user, password=password, timeout=config['SSH_TIMEOUT'])
        logger.info("Connection established..")
        return client
    except Exception as e:
        logger.error("Error occured while connecting to SSH"+str(e))
        return False

# Formtting size to human readable 
def FormatSize(sizeInBytes):
    # Convert bytes to human-readable units
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if sizeInBytes < 1024.0:
            return f"{sizeInBytes:.2f} {unit}"
        sizeInBytes /= 1024.0
    return f"{sizeInBytes:.2f} TB"


def InitializeClient(minioEndPoint, minioAccessKey, minioSecretKey):
    if config['MINIO_SECURE'].lower().strip() == 'true':
        minioSecure = True
        httpClient = urllib3.PoolManager(cert_reqs='CERT_NONE')
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    else:
        minioSecure = False
        httpClient = None

    try:
        client = Minio(
            endpoint = minioEndPoint,
            access_key = minioAccessKey,
            secret_key = minioSecretKey,
            secure = minioSecure,
            http_client = httpClient
        )
        client.list_buckets()
        return client
    except S3Error as e:
        logger.error("MinIO S3Error: " + str(e))
        return False
    except Exception as e:
        logger.error("Error initializing MinIO client: " +str(e))
        return False

def human_readable_size(size):
    if size < 1024:
        return f"{size} B"
    elif size < 1024 ** 2:
        return f"{size / 1024:.2f} KB"
    elif size < 1024 ** 3:
        return f"{size / (1024 ** 2):.2f} MB"
    elif size < 1024 ** 4:
        return f"{size / (1024 ** 3):.2f} GB"
    else:
        return f"{size / (1024 ** 4):.2f} TB"

def IsUuid(string):
    try:
        uuidObj = uuid.UUID(string, version=4)
        return True
    except ValueError:
        return False

def GetCaseNames(uuidd):
    postgresHost= config["POSTGRESQL_HOST"]
    postgresPort= config["POSTGRESQL_PORT"]
    postgresUser= config["POSTGRESQL_USER"]
    postgresPassword= config["POSTGRESQL_PASSWORD"]
    dbName= config["POSTGRESQL_CMM_NAME"]
    
    try:
        conn = psycopg2.connect(database=dbName, 
                                host= postgresHost,
                                user=postgresUser, 
                                password=postgresPassword, 
                                port=postgresPort
                                )
        cursor = conn.cursor()
        
        query = f""" SELECT id, name 
                FROM public.\"Case_Management_case\"
                WHERE id in ({uuidd});
                """
        
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.commit()
        
        res = []
        for row in rows:
            res.append({'id': row[0], 'name': row[1]})

        conn.close()   
        return res
    
    except Exception as e:
        # print(f"Error: {e}")
        logger.error(f"Error: {e}")
        return {"status": f"Error: {e}"}
        

def ListBuckets(client):
    try:
        buckets = client.list_buckets()
        resp=[]
        total_storage_size = 0
        if buckets:
            for bucket in buckets:
                total_size = 0
                case_names = []
                for obj in client.list_objects(bucket.name, recursive=True):
                    total_size += obj.size
                
                if IsUuid(bucket.name):
                    case_names = GetCaseNames(f"\'{bucket.name}\'")
                
                total_storage_size += total_size
                if case_names:
                    case = case_names[0]
                    resp.append({
                        "id": case["id"],
                        "name": case["name"],
                        "estimated_size": human_readable_size(total_size)
                    })
                else:
                    resp.append({
                        "id": "null",
                        "name": bucket.name,
                        "estimated_size": human_readable_size(total_size)
                    })
                    
            total_storage_size_human = human_readable_size(total_storage_size)
            return {
            "buckets": resp,
            "total_storage_size": total_storage_size_human
            }
            # return resp
    except Exception as e:
        # print(f"Error checking connection: {e}")
        logger.error("Error checking connection"+str(e))
        return False

def ValidateBucketName(name):
    pattern = r'^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'
    return bool(re.match(pattern, name))


def EnsureBucketExists(client, name):
    if not ValidateBucketName(name):
        # print(f"Bucket name '{name}' is invalid.")
        logger.info(f"Bucket name '{name}' is invalid.")
        logger.warning(f"Bucket name '{name}' is invalid.")
        return False
    try:
        if client.bucket_exists(name):
            # print(f"Bucket '{name}' exists.")
            logger.info(f"Bucket '{name}' exists.")
            return True
        else:
            # If the bucket doesn't exist, create it
            client.make_bucket(name)
            # print(f"Bucket '{name}' created.")
            logger.info(f"Bucket '{name}' created.")
            return True
    except Exception as e:
        # print(f"Error ensuring bucket '{name}' exists: {e}")
        logger.error(f"Error ensuring bucket '{name}' exists: {e}")
        return False


def DownloadFilesFromBucket(bucketName, remoteBackupPath, localPath, client, isRemote, remoteHost, remoteUser, remotePassword):
    try:
        if not EnsureBucketExists(client, bucketName):
            logger.info(f"Bucket '{bucketName}' does not exist.")
            return False
        
        if isRemote:
            ssh = CreateSshClient(remoteHost, 22, remoteUser, remotePassword)
            filePath = remoteBackupPath
        
        else:
            localHost = config["LOCAL_MINIO_HOST"]
            localUserName = config["LOCAL_MINIO_VM_USER"]
            localPassword = config["LOCAL_MINIO_VM_PASSWORD"]
            ssh = CreateSshClient(localHost, 22, localUserName, localPassword)
            filePath = localPath

        if ssh:
            objects = client.list_objects(bucketName, recursive=True)
            if objects:
                logger.info(f"Transferring all files from bucket '{bucketName}' to '{filePath}'.")
                with SCPClient(ssh.get_transport()) as scp:
                    for obj in objects:
                        minio_obj = client.get_object(bucketName, obj.object_name)
                        data = BytesIO(minio_obj.read())  
                        data.seek(0)  

                        remoteFilePath = os.path.join(filePath, bucketName, obj.object_name)
                        remoteDir = os.path.dirname(remoteFilePath)

                        stdin, stdout, stderr = ssh.exec_command(f'mkdir -p "{remoteDir}"')
                        stdout.channel.recv_exit_status() 

                        scp.putfo(data, remoteFilePath)
                        logger.debug(f"Transferred '{obj.object_name}' to '{remoteFilePath}'.")

                        minio_obj.close()
                
                logger.info(f"Transferred all files from bucket '{bucketName}' to '{remoteFilePath}'.")
                ssh.close()
                return True
            
            else:
                logger.info(f"No objects found in bucket '{bucketName}'.")
                return False
        
        else:
            logger.error("Failed to create SSH connection.")
            return False
    except Exception as e:
        logger.error(f"Error downloading files from bucket '{bucketName}': {str(e)}")
        return False

def UploadFiles(client, bucketName, filePath, isRemote, remoteHost, remoteUser, remotePassword):
    try:
        if EnsureBucketExists(client, bucketName):
            if isRemote:
                ssh = CreateSshClient(remoteHost, 22, remoteUser, remotePassword)
            else:
                localHost = config["LOCAL_MINIO_HOST"]
                localUserName = config["LOCAL_MINIO_VM_USER"]
                localPassword = config["LOCAL_MINIO_VM_PASSWORD"]
                ssh = CreateSshClient(localHost, 22, localUserName, localPassword)
            
            backupPath = os.path.join(filePath, bucketName)
            
            if ssh:
                stdin, stdout, stderr = ssh.exec_command(f"find {backupPath} -type f")
                file_paths = stdout.readlines()

                for file_path in file_paths:
                    file_path = file_path.strip()

                    minioPath = os.path.relpath(file_path, backupPath)
                    try:
                        client.stat_object(bucketName, minioPath)
                        logger.warning(f"File '{minioPath}' already exists in bucket '{bucketName}'.")
                        return False
                    except S3Error as err:
                        if err.code != 'NoSuchKey':
                            logger.error(f"Error checking object existence: {err}")
                            return False
                    
                    logger.info(f"Uploading remote file '{file_path}' to bucket '{bucketName}' as '{minioPath}'")

                    sftp = ssh.open_sftp()
                    with sftp.open(file_path, 'rb') as remote_file:
                        fileSize = sftp.stat(file_path).st_size

                        client.put_object(bucketName, minioPath, remote_file, fileSize)

                    logger.info(f"Uploaded '{file_path}' to MinIO bucket '{bucketName}'")
                
                logger.info(f"Uploaded files from '{backupPath}' to MinIO bucket '{bucketName}'")
                
                sftp.close()
                ssh.close()
                return True
            else:
                logger.error("Failed to create SSH connection.")
                return False
                
        else:
            logger.error(f"Failed to upload file '{backupPath}' to bucket '{bucketName}'.")
            return False
    except Exception as e:
        logger.error(f"Error uploading file '{backupPath}' to bucket '{bucketName}': {str(e)}")
        return False


def DownloadAllBuckets(client, isRemote, remoteHost, remoteUser, remotePassword, localPath, remoteBackupPath):
        
    if isRemote:
        ssh = CreateSshClient(remoteHost, 22, remoteUser, remotePassword)
        filePath = remoteBackupPath
    
    else:
        localHost = config["LOCAL_MINIO_HOST"]
        localUserName = config["LOCAL_MINIO_VM_USER"]
        localPassword = config["LOCAL_MINIO_VM_PASSWORD"]
        ssh = CreateSshClient(localHost, 22, localUserName, localPassword)
        filePath = localPath

    if ssh:
        buckets = client.list_buckets()
        if buckets:
            with SCPClient(ssh.get_transport()) as scp:
                for bucket in buckets:
                    bucketName = bucket.name

                    logger.info(f"Processing bucket: {bucketName}")
                    
                    try:
                        bucketRemotePath = os.path.join(filePath, bucketName)
                        ssh.exec_command(f'mkdir -p {bucketRemotePath}')
                        logger.info(f"Created directory for bucket: {bucketRemotePath}")

                        objects = client.list_objects(bucketName, recursive=True)

                        for obj in objects:
                            try:
                                minio_obj = client.get_object(bucketName, obj.object_name)
                                data = BytesIO(minio_obj.read())
                                data.seek(0) 
                                
                                remoteFilePath = os.path.join(filePath, bucketName, obj.object_name)
                                remoteDir = os.path.dirname(remoteFilePath)
                                
                                stdin, stdout, stderr = ssh.exec_command(f'mkdir -p \"{remoteDir}\"')
                                stdout.read()
                                stderr.read()
                                exitStatus = stdout.channel.recv_exit_status()
                                if exitStatus != 0:
                                    logger.error(f"Failed to create directory: {remoteDir}")
                                    return False

                                scp.putfo(data, remoteFilePath)
                                logger.debug(f"Transferred '{obj.object_name}' to '{remoteFilePath}'.")
                                
                                minio_obj.close()
                                
                            except Exception as objError:
                                logger.error(f"Error transferring object '{obj.object_name}': {str(objError)}")
                                return False

                    except Exception as bucketError:
                        logger.error(f"Error processing bucket '{bucketName}': {str(bucketError)}")
                        return False

            logger.info(f"Minio Backup done to '{filePath}'.")
            ssh.close()
 
            return filePath
        
        else:
            logger.info("No buckets found.")
            return False
    
    else:
        logger.error("Failed to create SSH connection.")
        return False
        

def RestoreAllBuucketsFromRemote(client, isRemote, remoteHost, remoteUser, remotePassword, BackupPath):
    try:
        if isRemote:
            ssh = CreateSshClient(remoteHost, 22, remoteUser, remotePassword)
        else:
            localHost = config["LOCAL_MINIO_HOST"]
            localUserName = config["LOCAL_MINIO_VM_USER"]
            localPassword = config["LOCAL_MINIO_VM_PASSWORD"]
            ssh = CreateSshClient(localHost, 22, localUserName, localPassword)
        
        if ssh:    
            stdin, stdout, stderr = ssh.exec_command(f"find {BackupPath} -mindepth 1 -maxdepth 1 -type d")
            bucketDirectories = stdout.readlines()

            for bucketDir in bucketDirectories:
                bucketDir = bucketDir.strip()
                bucketName = os.path.basename(bucketDir)

                logger.info(f"Restoring bucket: {bucketName}")

                if EnsureBucketExists(client, bucketName):
                    stdin, stdout, stderr = ssh.exec_command(f"find {bucketDir} -type f")
                    filePaths = stdout.readlines()

                    for filePath in filePaths:
                        filePath = filePath.strip()
                        minioPath = os.path.relpath(filePath, bucketDir)

                        logger.info(f"Uploading remote file '{filePath}' to bucket '{bucketName}' as '{minioPath}'")
                        try:
                            client.stat_object(bucketName, minioPath)
                            logger.warning(f"File '{minioPath}' already exists in bucket '{bucketName}'.")
                            return False
                        except S3Error as err:
                            if err.code != 'NoSuchKey':
                                logger.error(f"Error checking object existence: {err}")
                                return False

                        sftp = ssh.open_sftp()
                        with sftp.open(filePath, 'rb') as remote_file:
                            fileSize = sftp.stat(filePath).st_size

                            client.put_object(bucketName, minioPath, remote_file, fileSize)

                        logger.info(f"Uploaded '{filePath}' to MinIO bucket '{bucketName}'")

                else:
                    logger.error(f"Failed to restore bucket '{bucketName}'.")
                    return False

            logger.info(f"Restored files from '{BackupPath}' to MinIO bucket '{bucketName}'")
            sftp.close()
            ssh.close()
            return True
        else:
            logger.error("Failed to create SSH connection.")
            return False

    except Exception as e:
        logger.error(f"Error restoring buckets: {str(e)}")
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

def GetDiskUsageRemote(minioVmUser, minioVmPassword, minioHost, minioDataDir):
    try:
        sshClient = CreateSshClient(minioHost, int(22), minioVmUser, minioVmPassword)
        if not sshClient:
            return False
        
        stdin, stdout, stderr = sshClient.exec_command(f"df -h {minioDataDir} | tail -n 1")
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        # if error:
        #     raise Exception(f"Error retrieving disk usage: {error}")
        if error or not output:
            logger.error(f"Error retrieving disk usage: {error}")
            return False, None

        # Parse the output
        fields = output.split()
        totalSpace = fields[1]
        usedSpace = fields[2]
        freeSpace = fields[3]

        return True, {
            "total_disk_space": FormatSize(ConvertToBytes(totalSpace)),
            "used_disk_space": FormatSize(ConvertToBytes(usedSpace)),
            "free_disk_space": FormatSize(ConvertToBytes(freeSpace))
        }
    except Exception as e:
        logger.error(f"Failed to connect via SSH: {e}")
        return False, str(e)
    
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
    payload = { 
        "local_ip" : config["LOCAL_MINIO_HOST"],
        "local_path" : config["MINIO_DATA_DIR"],
    }
        
    statcode, remoteDiskUsage = GetDiskUsageRemote(config["LOCAL_MINIO_VM_USER"],
                                            config["LOCAL_MINIO_VM_PASSWORD"],
                                            config["LOCAL_MINIO_HOST"],
                                            config["MINIO_DATA_DIR"]) 
    if not statcode:
        payload.update({
            "status":False,
            "message":"Invalid credentials. Please enter valid credentials",
            "data":None,
            "error":"Failed to fetch disk usage, please check the path"
        })
        return False, payload

    logger.info("Viewing list of buckets.")
    payload.update({
        "status":True,
        "disk_usage":remoteDiskUsage,
        "error":None,
    })
    return True, payload

            
SYSTEM_BUCKETS = []
def DeleteUserBuckets(minioClient, bucketName):
    if bucketName:
        try:
            objects = minioClient.list_objects(bucketName, recursive=True)
            if objects:
                for obj in objects:
                    logger.info(f"Deleting object: {obj.object_name}")
                    minioClient.remove_objects(bucketName, obj.object_name, version_id=obj.version_id)
                    logger.info(f"Object {obj.object_name} deleted successfully.")

            minioClient.remove_bucket(bucketName)
            logger.info(f"Bucket {bucketName} deleted successfully.")
            return True
        except S3Error as e:
            logger.error(f"S3Error occurred: {e}")
            return False
        except Exception as e:
            logger.error(f"Exception occurred while deleting bucket {bucketName}: {e}")
            return False
            
    else:    
        try:
            buckets = minioClient.list_buckets()

            for bucket in buckets:
                bucket_name = bucket.name
                if bucket_name not in SYSTEM_BUCKETS:
                    logger.debug(f"Deleting bucket: {bucket_name}")
                    
                    # Remove all objects from the bucket
                    objects = minioClient.list_objects(bucket_name, recursive=True, include_version=True)
                    for obj in objects:
                        minioClient.remove_object(bucket_name, obj.object_name, version_id=obj.version_id)  #BUG ID 1277: Minio Deletion
                    
                    # Delete the bucket
                    minioClient.remove_bucket(bucket_name)
            
            logger.info("All user-created buckets have been deleted successfully.")
            return True
        except S3Error as e:
            logger.error(f"An error occurred: {e}")
            return False
        except Exception as e:
            logger.error(f"Exception occurred while deleting bucket: {e}")
            return False

def SaveDataToDb(backupType, backupMode, ipAddress, path, responseStatus, message, duration, userId):
    serializer = BackupRestoreSerializer(data={
                                            'database_type':"minio",
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
    
def MinioVersion(host, vmUser, vmPassword):
    sshClient = CreateSshClient(host, int(22), vmUser, vmPassword)
    if not sshClient:
        return False
    
    try:
        stdin, stdout, stderr = sshClient.exec_command("minio --version")
        output = stdout.read().decode().strip()
        
        return output
    except Exception as e:
        logger.error(f"Error fetching minio version")
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
            """, ("minio", backupType, backupMode))
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
                "minio",
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

        
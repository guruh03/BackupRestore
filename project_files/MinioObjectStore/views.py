import os
import datetime
import threading
import psycopg2
from .utils import *
from Postgresdb.models import *
from rest_framework import status
from Postgresdb.serializer import *
from rest_framework.views import APIView
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema


class FetchMinioVersion(APIView):
    @swagger_auto_schema(
        operation_description="""Get Minio version using GET request.
            1. This API endpoint allows you to get minio version.
            Note: This API requires systemadmin to view minio version.
        """,
        operation_summary='View Minio Version',
    )
    def get(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        
        if(not isSuperuser):
            logger.warning(f'{userName}: do not have permission to view minio version')
            payload = {  
                "status":False,
                "message":"You don't have permission to view minio version",
                "data": None,
                "error": "You don't have permission to view minio version",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to view minio version.") 
        
        params = request.query_params.dict()
        minioHost = params.get('minio_host',None)
        minioVmUser = params.get('minio_vm_user',None)
        minioVmPassword = params.get('minio_vm_password',None)
        
        # if (minioHost==None or minioAccessKey==None or minioSecretKey==None):
        #     logger.warning("Mandatory fields not provided")
        #     logger.error("Minio credentials not provided to fetch version.")
        #     payload = {
        #         "status":False,
        #         "message":"Minio credentials is required.",
        #         "data":None,
        #         "error":"Mandatory fields not provided."
        #     }
        #     return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        version = MinioVersion(minioHost, minioVmUser, minioVmPassword)
        if version:
            logger.info("MinIO Version fetched successfully.")
            payload = {
                "status":True,
                "message":"MinIO Version fetched successfully.",
                "data":version,
                "error":None
            }
            return Response(payload, status=status.HTTP_200_OK)
        else:
            logger.error("Failed to fetch MinIO Version.")
            payload = {
                "status":False,
                "message":"Failed to fetch MinIO Version.",
                "data":None,
                "error":"Failed to fetch MinIO Version."
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)

class BuildMinioConnection(APIView):
    @swagger_auto_schema(
        operation_description="""Check Minio is active or dead using GET request.
            1. This API endpoint allows you to check Minio connection is active or dead.
            Note: This API requires systemadmin to check connection is active or dead.
        """,
        operation_summary='Check Minio Connection',
    )
    def get(self, request):
        # apiData = UserAuthenticationFromUserManagement(request)
            
        # if isinstance(apiData, Response):
        #     return apiData
        
        # isSuperuser = apiData['data'][0]['is_superuser']
        # userName = apiData['data'][0]['username']
        
        # if(not isSuperuser):
        #     logger.warning(f'{userName}: do not have permission to check minio connection')
        #     payload = {  
        #         "status":False,
        #         "message":"You don't have permission to check minio connection",
        #         "data": None,
        #         "error": "You don't have permission to check minio connection",                
        #     }
        #     return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        # logger.info(f"Permission granted for {userName} to check minio connection.") 
        
        params = request.query_params.dict()
        minioEndpoint = params.get('minio_endpoint',None)
        minioAccessKey = params.get('minio_access_key',None)
        minioSecretKey = params.get('minio_secret_key',None)
        
        if (minioEndpoint==None or minioAccessKey==None or minioSecretKey==None):
            logger.warning("Mandatory fields not provided")
            logger.error("Minio credentials not provided to fetch bucket lists.")
            payload = {
                "status":False,
                "message":"Please Provide Minio credentials.",
                "data":None,
                "error":"Mandatory fields not provided."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        client = InitializeClient(minioEndpoint, minioAccessKey, minioSecretKey)
        
        if client:
            logger.info("Minio is up and running.")
            payload = {
                "status":True,
                "message":"Connected to Minio succesfully.",
                "data":None,
                "error":None
            }
            return Response(payload, status=status.HTTP_200_OK)
        else:
            logger.info("Error connecting to Minio. Please check the credentials.")
            payload = {
                "status":False,
                "message":"Error connecting to Minio. Please check the credentials.",
                "data":None,
                "error":"Error connecting to Minio. Please check the credentials."
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
class FetchBuckets(APIView):
    @swagger_auto_schema(
        operation_description="""Get list of existing buckets by providing valid credentials in query parameters using GET request.
            This API endpoint allows you to retrieve buckets with certain scenarious.
            1. Provide valid minio credentials to fetch buckets list and size.
            2. Provide virtual machine credentials where minio is installed to check storage usage.
            Note: This API requires systemadmin to view buckets list.
        """,
        operation_summary='View List Of Buckets',
    )
    def get(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        
        if(not isSuperuser):
            logger.warning(f'{userName}: do not have permission to fetch bucket lists')
            payload = {  
                "status":False,
                "message":"You don't have permission to fetch bucket lists",
                "data": None,
                "error": "You don't have permission to fetch bucket lists",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to fetch bucket lists.") 
        
        params = request.query_params.dict()
        minioEndpoint = params.get('minio_endpoint',None)
        minioAccessKey = params.get('minio_access_key',None)
        minioSecretKey = params.get('minio_secret_key',None)
        
        if (minioEndpoint==None or minioAccessKey==None or minioSecretKey==None):
            logger.warning("Mandatory fields not provided")
            logger.error("Minio credentials not provided to fetch bucket lists.")
            payload = {
                "status":False,
                "message":"Please Provide Minio credentials.",
                "data":None,
                "error":"Mandatory fields not provided."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        client = InitializeClient(minioEndpoint, minioAccessKey, minioSecretKey)
        
        if client:
            bucketList = ListBuckets(client)
            
            if bucketList:
                logger.info("Listing buckets in object store")
                payload = {
                    "status":True,
                    "message":"Buckets fetched successfully",
                    "data":bucketList['buckets'],
                    "total_storage_size": bucketList['total_storage_size'],
                    "error":None,
                }
                return Response(payload, status=status.HTTP_200_OK)
            else:
                logger.info("No buckets found in MinIO object store")
                payload = {
                    "status":False,
                    "message":"No buckets found in MinIO object store",
                    "data":None,
                    "error":"Please ensure that the MinIO server is correctly configured and buckets have been created."
                }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        else:
            logger.error("Connection Failed. Cant able to connect Minio.")
            payload = {
                "status":False,
                "message":"Please provide valid minio credentials",
                "data":None,
                "error":"Connecting to Minio failed."
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)

class MinioBackup(APIView):
    @swagger_auto_schema(
        operation_description="""Start a new backup and save it based on backup type using POST request.
            1. This API endpoint allows you to start backup by providing valid credentials in the request body.
            2. Backup can be initited to remote as well as local server.
            3. Valid minio credentials is required to start backup for both remote and local server.
            4. Logs can be checked in log table post backup.
            Note: This API requires systemadmin to initiate backup.
        """,
        operation_summary='Start Minio Backup',
    )
    def post(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        userId = apiData['data'][0]['id']
        
        if (not isSuperuser):
            logger.warning(f'{userName}: do not have permission to proceed with backup')
            payload = {  
                "status":False,
                "message":"You don't have permission to proceed with backup",
                "data": None,
                "error": "You don't have permission to proceed with backup",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to proceed with backup.")
        
        data = request.data

        minioEndpoint = data.get('minio_endpoint',None)
        minioAccessKey = data.get('minio_access_key',None)
        minioSecretKey = data.get('minio_secret_key',None)
        
        minioVmUser = data.get('minio_vm_user',None)
        minioVmPort = data.get('minio_vm_port',None)
        minioVmPassword = data.get('minio_vm_password',None)
        
        fileName = data.get('file_name',None)
        bucketName = data.get("bucket_name",None)
        backupPath = data.get("backup_path",None)
        
        isRemote = data.get("remote",False)
        remoteHost = data.get("remote_host",None)
        remoteUser = data.get("remote_user",None)
        remotePort = data.get("remote_port",None)
        remotePassword = data.get("remote_password",None)
        
        if(minioEndpoint==None or minioAccessKey==None or minioSecretKey==None):
            payload = {
                "status":False,
                "message":"Minio credentials is required.",
                "data":None,
                "error":"Mandatory fields not provided."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        if (not fileName or fileName==None):
            payload = {
                "status": False,
                "message": "File name not provided.",
                "data":None,
                "error": "Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        client = InitializeClient(minioEndpoint, minioAccessKey, minioSecretKey)
        if (not client): #BUG ID 1088: Backup and Restore - Minio - Credentials
            payload = {
                "status":False,
                "message":"Please provide valid minio credentials", #BUG ID 1087: Minio - Backup - credentials - endpoint
                "data":None,
                "error":"Connecting to Minio failed."
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
        if isRemote:
            if not (backupPath and remoteHost and remotePort and remoteUser and remotePassword):
                logger.info("Please provide remote credentials with backup path to proceed with backup.")
                logger.warning("Backup won't proceed without remote credentials.")
                payload = {
                    "status": False,
                    "message": "Please provide remote credentials with backup path to proceed with backup.",
                    "data": None,
                    "error": "Mandatory fields not provided."
                }
                return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        if bucketName:
            def RunBackup(bucketName, isRemote, backupPath, remoteHost, remoteUser, remotePassword, client, userId):
                try:
                    remoteBackupPath = None
                    localPath = None
                    starttime = datetime.now()
                    
                    if isRemote:
                        sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
                        remoteBackupPath = os.path.join(backupPath,f'{int(datetime.now().timestamp())}_{fileName}')
                        ipAddress = remoteHost
                        path = remoteBackupPath
                        # diskSpacePath = backupPath
                        backupMode = "remote"
                    else:
                        sshclient = CreateSshClient(config['LOCAL_MINIO_HOST'], int(22), config['LOCAL_MINIO_VM_USER'], config['LOCAL_MINIO_VM_PASSWORD'])
                        localPath = f"{config['LOCAL_TEMP_DIR']}/{int(datetime.now().timestamp())}_{fileName}"
                        ipAddress = config['LOCAL_MINIO_HOST']
                        path = localPath
                        # diskSpacePath = config['LOCAL_TEMP_DIR']
                        backupMode = "local"

                    responseData, value = SaveDataToDb("partial", backupMode, ipAddress, path, "Scheduled", "Backup scheduled", None, userId)
                    Id = value['id']

                    if not responseData:
                        logger.error("Cannot Log to Database")
                        return
                    
                    if sshclient:
                        response = DownloadFilesFromBucket(bucketName, remoteBackupPath, localPath, client, isRemote, remoteHost, remoteUser, remotePassword)
                        if response:
                            endTime = datetime.now()
                            duration = Duration(starttime, endTime)
                            if (UpdateStatusToDb(Id, "Success", "Backup Successful", duration)):
                                logger.info("Files from the object store backed up successfully.")
                            else:
                                logger.error("Cannot Log to Database")
                                return
                        else:
                            if (UpdateStatusToDb(Id, "Failed", "Backup Failed")):
                                logger.error("Error occurred while initiating backup.")
                                return
                            else:
                                logger.error("Cannot Log to Database")
                                return
                    else:
                        if (UpdateStatusToDb(Id, "Failed", "SSH client connection failed.")):
                            logger.error("SSH client connection failed.")
                        else:
                            logger.error("Cannot Log to Database")
                            return
                except Exception as e:
                    if (UpdateStatusToDb(Id, "Failed", "Backup Failed")):
                        logger.error("Error occurred while initiating backup.")
                    else:
                        logger.error("Cannot Log to Database")
                        return

            try:
                backupThread = threading.Thread(target=RunBackup,
                                                args=(bucketName, isRemote, backupPath, remoteHost, remoteUser, remotePassword, client, userId),
                                                daemon=True
                )
                backupThread.start()
                
                payload = {
                    "status": True,
                    "message": "Backup has been scheduled. Please check log table for more details.",
                    "data": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_200_OK)
            
            except Exception as e:
                logger.error("Backup Thread Failed" + str(e))
                payload = {
                    "status": False,
                    "message": "Backup Thread Failed.",
                    "data": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
                    
        else:
            def RunBackup(isRemote, remoteHost, remotePort, remoteUser, remotePassword, backupPath, client, userId):
                try:
                    remoteBackupPath = None
                    localPath = None
                    starttime = datetime.now()
                    
                    if isRemote:
                        sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
                        remoteBackupPath = os.path.join(backupPath,f'{int(datetime.now().timestamp())}_{fileName}')
                        ipAddress = remoteHost
                        path = remoteBackupPath
                        diskSpacePath = backupPath
                        backupMode = "remote"
                    else:
                        sshclient = CreateSshClient(config['LOCAL_MINIO_HOST'], int(22), config['LOCAL_MINIO_VM_USER'], config['LOCAL_MINIO_VM_PASSWORD'])
                        localPath = f"{config['LOCAL_TEMP_DIR']}/{int(datetime.now().timestamp())}_{fileName}"
                        ipAddress = config['LOCAL_MINIO_HOST']
                        path = localPath
                        diskSpacePath = config['LOCAL_TEMP_DIR']
                        backupMode = "local"

                    responseData, value = SaveDataToDb("complete", backupMode, ipAddress, path, "Scheduled", "Backup scheduled", None, userId)
                    Id = value['id']

                    if not responseData:
                        logger.error("Cannot Log to Database")
                        return
                    
                    if sshclient:
                        try:
                            buckets = client.list_buckets()
                            totalStorageSize = 0
                            if buckets:
                                for bucket in buckets:
                                    totalSize = 0
                                    for obj in client.list_objects(bucket.name, recursive=True):
                                        totalSize += obj.size
                                    
                                    totalStorageSize += totalSize
                                    
                            remoteSpace = CheckRemoteDiskSpace(sshclient, diskSpacePath)
                            
                            totalSize = ConvertToBytesB(str(totalStorageSize))
                            if isinstance(remoteSpace, str):
                                remoteSpace = ConvertToBytes(remoteSpace)
                            
                            if remoteSpace < totalSize:
                                if (UpdateStatusToDb(Id, "Failed", "Not enough space on the remote host for backup.")):
                                    logger.error("Not enough space on the remote host for backup.")
                                else:
                                    logger.error("Cannot Log to Database")
                                    return
                                
                                return
                                
                        except Exception as e:
                            logger.debug(f"Backup failed due to an error.{str(e)}")
                            return 
                    else:
                        if (UpdateStatusToDb(Id, "Failed", "SSH client connection failed.")):
                            logger.error("SSH client connection failed.")
                        else:
                            logger.error("Cannot Log to Database")
                            return
                     
                    response = DownloadAllBuckets(client, isRemote, remoteHost, remoteUser, remotePassword, localPath, remoteBackupPath)
                    if response:
                        endTime = datetime.now()
                        duration = Duration(starttime, endTime)
                        if (UpdateStatusToDb(Id, "Success", "Backup Successful", duration)):
                            logger.info("Files from the object store backed up successfully.")
                        else:
                            logger.error("Cannot Log to Database")
                            return
                    else:
                        if (UpdateStatusToDb(Id, "Failed", "Backup Failed")):
                            logger.error("Error occurred while initiating backup.")
                            return
                        else:
                            logger.error("Cannot Log to Database")
                            return
                except Exception as e:
                    logger.error(f"Backup failed due to an error: {str(e)}")
                    return
            
            try:
                backupThread = threading.Thread(target=RunBackup,
                                                args=(isRemote, remoteHost, remotePort, remoteUser, remotePassword, backupPath, client, userId),
                                                daemon=True
                )
                backupThread.start()

                payload = {
                    "status": True,
                    "message": "Backup has been scheduled. Please check log table for more details.",
                    "data": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_200_OK)
            
            except Exception as e:
                logger.error("Backup Thread Failed" + str(e))
                payload = {
                    "status": False,
                    "message": "Backup Thread Failed.",
                    "data": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        

class MinioRestore(APIView):
    @swagger_auto_schema(
        operation_description="""Start restoring for the files which were backuped using POST request.
            1. This API endpoint allows you to start restoration by providing valid credentials and path where the backed up file is present in the request body.
            2. Restore can be initited from remote as well as local server.
            3. Provide bucket name for partial restore.
            Note: This API requires systemadmin for restoration.
        """,
        operation_summary='Start Minio Restore',
    )
    def post(self, request):
        # apiData = UserAuthenticationFromUserManagement(request)
            
        # if isinstance(apiData, Response):
        #     return apiData
        
        # isSuperuser = apiData['data'][0]['is_superuser']
        # userName = apiData['data'][0]['username']
        
        # if (not isSuperuser):
        #     logger.warning(f'{userName}: do not have permission to proceed with restore')
        #     payload = {  
        #         "status":False,
        #         "message":"You don't have permission to proceed with restore",
        #         "data": None,
        #         "error": "You don't have permission to proceed with restore",                
        #     }
        #     return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        # logger.info(f"Permission granted for {userName} to proceed with restore.")
        
        data = request.data
        minioEndpoint = data.get('minio_endpoint',None)
        minioAccessKey = data.get('minio_access_key',None)
        minioSecretKey = data.get('minio_secret_key',None)
        client = InitializeClient(minioEndpoint, minioAccessKey, minioSecretKey)
        
        backupPath = data.get("file_path",None)
        bucketName = data.get("bucket_name",None)
        
        isRemote = data.get("remote",False)
        remoteHost = data.get("remote_host",None)
        remoteUser = data.get("remote_user",None)
        remotePort = data.get("remote_port",None)
        remotePassword = data.get("remote_password",None)
        
        logDbHost = data.get("restore_postgres_host",None)
        logDbPort = data.get("restore_postgres_port",None)
        logDbUser = data.get("restore_postgres_user",None)
        logDbPassword = data.get("restore_postgres_password",None)
        logDbName = config["POSTGRESQL_RESTORE_LOG_DATABASE_NAME"]
        logTableName = config["POSTGRESQL_RESTORE_LOG_TABLE_NAME"]
        
        if(minioEndpoint==None or minioAccessKey==None or minioSecretKey==None or backupPath==None):
            payload = {
                "status":False,
                "message":"Minio credentials is required.",
                "data":None,
                "error":"Mandatory fields not provided."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        if (not client): #BUG ID 1088: Backup and Restore - Minio - Credentials
            payload = {
                "status":False,
                "message":"Please provide valid minio credentials",
                "data":None,
                "error":"Connecting to Minio failed."
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
        # if isRemote:
        #     if not (remoteHost and remotePort and remoteUser and remotePassword and backupPath):
        #         logger.info("Please provide remote credentials with backup path to proceed with restore.")
        #         logger.warning("Restore won't proceed without remote credentials.")
        #         payload = {
        #             "status": False,
        #             "message": "Please provide remote credentials with backup path to proceed with restore.",
        #             "data": None,
        #             "error": "Restore won't proceed without all remote credentials."
        #         }
        #         return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        # if bucketName:
        #     if UploadFiles(client, bucketName, backupPath, isRemote, remoteHost, remoteUser, remotePassword):
        #         logger.info(f"Files restored to object store succesfully from path: {backupPath}")
        #         payload = {
        #             "status":True,
        #             "message":"Files restored to object store succesfully from path.",
        #             "path":backupPath,
        #             "error":None
        #         }
        #         return Response(payload, status=status.HTTP_200_OK)
        #     else:
        #         logger.error(f"Files restore to object store failed from path: {backupPath}")
        #         payload = {
        #             "status":False,
        #             "message":"Files restore to object store failed from path.",
        #             "path":backupPath,
        #             "error":None
        #         }
        #         return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
        # else:
        #     if RestoreAllBuucketsFromRemote(client, isRemote, remoteHost, remoteUser, remotePassword, backupPath):
        #         logger.info(f"Files restored to object store succesfully from path: {backupPath}")
        #         payload = {
        #             "status":True,
        #             "message":"Files restored to object store succesfully from path.",
        #             "path":backupPath,
        #             "error":None
        #         }
        #         return Response(payload, status=status.HTTP_200_OK)
        #     else:
        #         logger.error(f"Files restore to object store failed from path: {backupPath}")
        #         payload = {
        #             "status":False,
        #             "message":"Files restore to object store failed from path.",
        #             "path":backupPath,
        #             "error":None
        #         }
        #         return Response(payload, status=status.HTTP_400_BAD_REQUEST)

        def RunObjectStoreRestore(client, backupPath, isRemote, remoteHost, remotePort, remoteUser, remotePassword, bucketName, logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName):
            startTime = datetime.now()
            restoreMode = "remote" if isRemote else "local"
            ipAddress = remoteHost if isRemote else config["LOCAL_MINIO_HOST"]
            path = backupPath

            # statusLogged, restoreId = InsertRestoreLogToPostgres(logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName,"complete", restoreMode, ipAddress, path, "Scheduled", None, None)

            # if not statusLogged:
            #     logger.error("Cannot log object store restore initiation to database.")
            #     return

            try:
                if bucketName:
                    success = UploadFiles(client, bucketName, backupPath, isRemote, remoteHost, remoteUser, remotePassword)
                    message = "Minio Bucket restored successfully." if success else "Failed to restore Minio Bucket."
                else:
                    success = RestoreAllBuucketsFromRemote(client, isRemote, remoteHost, remoteUser, remotePassword, backupPath)
                    message = "Minio restored successfully." if success else "Failed to restore Minio."

                endTime = datetime.now()
                duration = Duration(startTime, endTime)

                if success:
                    logger.info(message)
                    InsertRestoreLogToPostgres(logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName,"complete", restoreMode, ipAddress, path, "Success", message, duration, None)
                else:
                    logger.error(message)
                    InsertRestoreLogToPostgres(logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName,"complete", restoreMode, ipAddress, path, "Failed", message, None, None)

            except Exception as e:
                logger.error(f"Object store restore encountered exception: {e}")
                InsertRestoreLogToPostgres(logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName,"complete", restoreMode, ipAddress, path, "Failed", str(e), None, None)

        if isRemote:
            if not (remoteHost and remotePort and remoteUser and remotePassword and backupPath):
                logger.info("Remote credentials or backup path missing.")
                payload = {
                    "status": False,
                    "message": "Please provide remote credentials with backup path.",
                    "data": None,
                    "error": "Restore won't proceed without remote credentials."
                }
                return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        try:
            conn = psycopg2.connect(
                host=logDbHost,
                port=logDbPort,
                user=logDbUser,
                password=logDbPassword,
                dbname="postgres"  # default DB
            )
        except psycopg2.OperationalError as e:
            logger.error(f"PostgreSQL connection failed: {e}")
            payload = {
                "status": False,
                "message": "Failed to connect to PostgreSQL database.",
                "data": None,
                "error": str(e)
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        thread = threading.Thread(target=RunObjectStoreRestore,
                            args=(client, backupPath, isRemote, remoteHost, remotePort, remoteUser, remotePassword,bucketName, logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName),
                            daemon=True
        )
        thread.start()

        payload = {
            "status": True,
            "message": "Minio restore started in background.",
            "data": None,
            "error": None
        }
        return Response(payload, status=status.HTTP_202_ACCEPTED)

    
class FetchLocalBackupDetails(APIView):
    @swagger_auto_schema(
        operation_description="""Fetch local backup path using GET request.
            1. This API endpoint allows you to fetch local backup path.
            Note: This API requires systemadmin to fetch local backup path.
        """,
        operation_summary='Fetch Local Backup Path',
    )
    def get(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        
        if(not isSuperuser):
            logger.warning(f'{userName}: do not have permission to fetch backup details')
            payload = {  
                "status":False,
                "message":"You don't have permission to fetch backup details",
                "data": None,
                "error": "You don't have permission to fetch backup details",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to fetch backup details.")
        
        statcode, response = LocalBackupDetails()
        return Response(response, status=status.HTTP_200_OK)


class CheckRemoteConnection(APIView):
    @swagger_auto_schema(
        operation_description="""Check remote connection is active or dead using POST request.
            1. This API endpoint allows you to check remote connection is active or dead.
            Note: This API requires systemadmin to check remote connection is active or dead.
        """,
        operation_summary='Check Remote Connection',
    )
    def post(self, request):
        data = request.data
        actionType = data.get('action_type',None)
        validActions = ['backup','restore']
        
        if not (actionType):
            payload = {  
                "status":False,
                "message":"Please provide action type.",
                "data": None,
                "error": "Action type not provided",                
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
        if actionType not in validActions:
            payload = {
                "status": False,
                "message": f"Invalid action type. Allowed values: {validActions}.",
                "data": None,
                "error": f"Invalid action type '{actionType}' provided.",
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
        if actionType == 'backup':
            apiData = UserAuthenticationFromUserManagement(request)
                
            if isinstance(apiData, Response):
                return apiData
            
            isSuperuser = apiData['data'][0]['is_superuser']
            userName = apiData['data'][0]['username']
            
            if (not isSuperuser):
                logger.warning(f'{userName}: do not have permission to remote connection')
                payload = {  
                    "status":False,
                    "message":"You don't have permission to remote connection",
                    "data": None,
                    "error": "You don't have permission to remote connection",                
                }
                return Response(payload, status=status.HTTP_403_FORBIDDEN)
            
            logger.info(f"Permission granted for {userName} to remote connection.")
        
        remoteHost = data.get('remote_host',None)
        remoteUser = data.get('remote_user',None)
        remotePort = data.get('remote_port',None)
        remotePassword = data.get('remote_password',None)
        backupPath = data.get('backup_path',None)
        
        sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
        if sshclient:
            statcode, response = GetDiskUsageRemote(remoteUser, remotePassword, remoteHost, backupPath)
            if statcode:
                payload = {
                    "status": True,
                    "message": "Remote Connection Successfull.",
                    "data": response,
                    "error": None
                }
                return Response(payload, status=status.HTTP_200_OK)
            else:
                payload = {
                    "status": False,
                    "message": "Failed to fetch disk usage.",
                    "data": None,
                    "error": "Failed to fetch disk usage, please check the path"
                }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        else:
            logger.debug("Remote client connection failed.")
            payload = {
                "status": False,
                "message": "Remote client connection failed.",
                "data": None,
                "error": "Please check remote credentials"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)
        

#Deletion
class DeleteMinioData(APIView):
    @swagger_auto_schema(
        operation_description="""Complete Deletion of Minio using POST request.
            1. This API endpoint allows you to delete complete Minio server.
            2. Valid Minio credentials is required to initiate complete deletion. 
            Note: This API requires systemadmin permission to delete completely.
        """,
        operation_summary='Complete Deletion',
    )
    def post(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        
        if (not isSuperuser):
            logger.warning(f'{userName}: do not have permission to proceed with complete deletion')
            payload = {  
                "status":False,
                "message":"You don't have permission to proceed with complete deletion",
                "data": None,
                "error": "You don't have permission to proceed with complete deletion",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to proceed with complete deletion.")
        
        data = request.data
        minioEndpoint = data.get('minio_endpoint',None)
        minioAccessKey = data.get('minio_access_key',None)
        minioSecretKey = data.get('minio_secret_key',None)
        bucketName = data.get('bucket_name',None)

        if(minioEndpoint==None or minioAccessKey==None or minioSecretKey==None):
            payload = {
                "status":False,
                "message":"Minio credentials is required.",
                "data":None,
                "error":"Mandatory fields not provided."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
            
        client = InitializeClient(minioEndpoint, minioAccessKey, minioSecretKey)
        
        if (not client): #BUG ID 1300: Deletion;Invalid Credentials
            payload = {
                "status":False,
                "message":"Please provide valid minio credentials",
                "data":None,
                "error":"Connecting to Minio failed."
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            
        response = DeleteUserBuckets(client, bucketName)
        if response:
            logger.info("Complete deletion executed successfully for Minio")
            payload = {
                "status":True,
                "message":"Complete deletion executed successfully for Minio",
                "data":None,
                "error":None
            }
            return Response(payload, status=status.HTTP_200_OK)
        else:
            logger.error("Complete deletion failed for Minio")
            payload = {
                "status":False,
                "message":"Complete deletion failed for Minio",
                "data":None,
                "error":None
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
    
    
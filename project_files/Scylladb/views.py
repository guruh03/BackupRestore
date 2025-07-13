import datetime
import threading
import psycopg2
from .utils import *
from rest_framework import status
from cassandra.cluster import Cluster
from rest_framework.views import APIView
from rest_framework.response import Response
from Postgresdb.models import *
from Postgresdb.serializer import *
from drf_yasg.utils import swagger_auto_schema
# from cassandra.auth import PlainTextAuthProvider

class BuildScyllaConnection(APIView):
    @swagger_auto_schema(
        operation_description="""Check scylla is active or dead using GET request.
            1. This API endpoint allows you to check scylla connection is active or dead.
            Note: This API requires systemadmin to check connection is active or dead.
        """,
        operation_summary='Check Scylla Connection',
    )
    def get(self, request):
        # apiData = UserAuthenticationFromUserManagement(request)
            
        # if isinstance(apiData, Response):
        #     return apiData
        
        # isSuperuser = apiData['data'][0]['is_superuser']
        # userName = apiData['data'][0]['username']
        
        # if(not isSuperuser):
        #     logger.warning(f'{userName}: do not have permission to check connection')
        #     payload = {  
        #         "status":False,
        #         "message":"You don't have permission to check connection",
        #         "data": None,
        #         "error": "You don't have permission to check connection",                
        #     }
        #     return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        # logger.info(f"Permission granted for {userName} to check connection.")
        
        params = request.query_params.dict()
        scyllaHost = params.get('scylla_host',None)
        scyllaPort = params.get('scylla_port',None)
        scyllaUser = params.get('scylla_user',None)
        scyllaPassword = params.get('scylla_password',None)

        
        if (scyllaHost==None or scyllaPort==None or scyllaUser==None or scyllaPassword==None):
            payload = {
                "status": False,
                "message": "Error checking connection.",
                "data":None,
                "error": "Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        try:
            if config["SCYLLA_AUTHENTICATION_ENABLED"].lower().strip() == "true":
                authProvider = PlainTextAuthProvider(username=scyllaUser, password=scyllaPassword)
                cluster = Cluster([scyllaHost], port=int(scyllaPort), auth_provider=authProvider)
            else:
                cluster = Cluster([scyllaHost], port=int(scyllaPort))
                
            session = cluster.connect()
            keySpaces = session.execute("SELECT keyspace_name FROM system_schema.keyspaces")
            payload = {
                "status": True,
                "message": "ScyllaDB Connected Successfully",
                "data": None,
                "error": None
            }
            return Response(payload, status=status.HTTP_200_OK)
        
        except Exception as e:
            payload = {
                "status": False,
                "message": "Error connecting to Scylla",
                "data":None,
                "error": str(e)
            }
            return Response(payload, status=status.HTTP_503_SERVICE_UNAVAILABLE)

class ScyllaBackupForSingleTable(APIView):
#     @swagger_auto_schema(
#         operation_description="""Get list of existing keyspaces by providing valid credentials in query parameters using GET request.
#             This API endpoint allows you to retrieve keyspaces with certain scenarious.
#             1. Provide valid scylladb credentials to fetch keyspaces list and size.
#             2. Provide virtual machine credentials where scylladb is installed to check storage usage.
#             Note: This API requires systemadmin to view keyspaces list.
#         """,
#         operation_summary='View List Of Keyspaces',
#     )
#     def get(self, request):
#         apiData = UserAuthenticationFromUserManagement(request)
            
#         if isinstance(apiData, Response):
#             return apiData
        
#         isSuperuser = apiData['data'][0]['is_superuser']
#         userName = apiData['data'][0]['username']
        
#         if(not isSuperuser):
#             logger.warning(f'{userName}: do not have permission to view keyspaces in the cluster')
#             payload = {  
#                 "status":False,
#                 "message":"You don't have permission to view keyspaces in the cluster",
#                 "data": None,
#                 "error": "You don't have permission to view keyspaces in the cluster",                
#             }
#             return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
#         logger.info(f"Permission granted for {userName} to fetch keyspaces in the cluster.") 
        
#         params = request.query_params.dict()
#         scyllaHost = params.get('scylla_host',None)
#         scyllaPort = params.get('scylla_port',None)
#         scyllaPassword = params.get('scylla_password',None)
#         scyllaUser = params.get('scylla_user',None)
#         scyllaDataDir = config["SCYLLA_DATA_DIR"]
        
#         if (scyllaHost==None or scyllaPort==None or scyllaPassword==None or scyllaUser==None):
#             payload = {
#                 "status": False,
#                 "message": "Error Fetching keysapces.",
#                 "data":None,
#                 "error": "Mandatory fields not provided"
#             }
#             return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
#         try:
#             # auth_provider = PlainTextAuthProvider(username='shyena', password='shyena@123')

#             cluster = Cluster([scyllaHost], port=int(scyllaPort))
#             session = cluster.connect()
#             keySpaces = session.execute("SELECT keyspace_name FROM system_schema.keyspaces")
#         except Exception as e:
#             payload = {
#                 "status": True,
#                 "message": "Error connecting to Scylla",
#                 "data":None,
#                 "error": str(e)
#             }
#             return Response(payload, status=status.HTTP_404_NOT_FOUND)
        
#         excludeKeyspaces = ['system', 'system_schema', 'system_auth', 'system_distributed', 'system_traces','system_distributed_everywhere']
        
#         keySpaceNames = []
#         totalSize = 0
        
#         sshClient = CreateSshClient(scyllaHost, 22, scyllaUser, scyllaPassword)
#         if sshClient:
#             try:
#                 for row in keySpaces:
#                     keySpaceName=row.keyspace_name
#                     if keySpaceName in excludeKeyspaces:
#                         continue
#                     # try:
#                     #     estimatedSizeDict, _ = GetEstimatedBackupSize(sshClient, [keySpaceName])
#                     #     estimatedSize = estimatedSizeDict.get(keySpaceName, "0 B")
#                     #     sizeInBytes = ConvertToBytes(estimatedSize)
#                     #     totalSize += sizeInBytes 
#                     # except Exception as e:
#                     #     estimatedSize = f"Error estimating size: {str(e)}"
#                     tableSizes = []
#                     tables = session.execute(f"SELECT table_name FROM system_schema.tables WHERE keyspace_name = '{keySpaceName}'")
#                     totalKeyspaceSize = 0    
#                     for table in tables:
#                         tableName = table.table_name
#                         tableCommand = f"nodetool cfstats {keySpaceName}.{tableName}"
#                         stdin, stdout, stderr = sshClient.exec_command(tableCommand)

#                         stdoutOutput = stdout.read().decode()
#                         errorOutput = stderr.read().decode()

#                         if errorOutput:
#                             continue

#                         totalSizeMatch = re.search(r'Space used \(total\):\s+(\d+)', stdoutOutput)

#                         if totalSizeMatch:
#                             tableSize = int(totalSizeMatch.group(1))
#                             formattedTableSize = FormatSize(tableSize)
#                             tableSizes.append({
#                                 "table_name": tableName,
#                                 "estimated_size": formattedTableSize
#                             })
#                             totalKeyspaceSize += tableSize

#                     # Convert the total size from bytes to a human-readable format
#                     formattedKeyspaceSize = FormatSize(totalKeyspaceSize)
#                     keySpaceNames.append({
#                         'keyspace_name': keySpaceName,
#                         'tables': tableSizes,
#                         'total_size': formattedKeyspaceSize
#                     })

#                     totalSize += totalKeyspaceSize
                                
#                 formattedTotalSize = FormatSize(totalSize)
#                 remoteDiskUsage = GetDiskUsageRemote(scyllaUser, scyllaPassword, scyllaHost, scyllaDataDir)
#                 if not remoteDiskUsage:
#                     payload = {
#                         "status":False,
#                         "message":"Invalid credentials provided. Please enter valid credentials",
#                         "data":None,
#                         "error":"Please provide valid credentials to check disk usage"
#                     }
#                     return Response(payload, status=status.HTTP_400_BAD_REQUEST)    
                
#                 logger.info("Listing available keyspaces.")
#                 payload = {
#                     "status": True,
#                     "message": "List of available keyspaces in the cluster",
#                     "data": keySpaceNames,
#                     # "total_size": formattedTotalSize,
#                     # "disk_usage": remoteDiskUsage,
#                     "error": None,
#                     # "note": "Disk usage includes data stored in the ScyllaDB data directories, which consists of user data, commit logs, and other internal system files. It also includes storage for SSTables, indexes, and other files that support the database's operations. Disk usage may also reflect the storage used by secondary indexes, hints, and compaction files."
#                 }
#                 return Response(payload, status=status.HTTP_200_OK)
            
#             except Exception as e:
#                 logger.error("Error occurred while fetching keyspaces results"+str(e))
#                 payload = {
#                     "status": False,
#                     "message": "Error listing of available keyspaces in the cluster",
#                     "data": None,
#                     "total_size": None,
#                     "error": str(e)
#                 }
#                 return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            
#             finally:
#                 session.shutdown()
#                 cluster.shutdown()
        
#         else:
#             payload = {
#                 "status": False,
#                 "message": "ssh connection failed",
#                 "data": None,
#                 "total_size": None,
#                 "disk_usage":None,
#                 "error": "Please provide valid credentials"
#             }
#             return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
            
       
    @swagger_auto_schema(
        operation_description="""Start a new backup and save it based on backup type using POST request.
            1. This API endpoint allows you to start backup by providing valid credentials in the request body.
            2. Backup can be initited to remote as well as local server.
            3. Valid scylladb credentials is required to start backup for both remote and local server.
            4. Logs can be checked in log table post backup.
            Note: This API requires systemadmin to initiate backup.
        """,
        operation_summary='Start Keyspace Backup',
    )            
    def post(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        userId = apiData['data'][0]['id']
        
        if(not isSuperuser):
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
        scyllaHost = data.get('scylla_host',None)
        scyllaPort = data.get('scylla_port',None)
        scyllaUser = data.get('scylla_user',None)
        scyllaPassword = data.get('scylla_password',None)
        scyllaVmUser = data.get('scylla_vm_user',None)
        scyllaVmPassword = data.get('scylla_vm_password',None)
        
        keySpaceName = data.get("keyspace_name", None)
        tableName = data.get("table_name", None)
        backupPath = data.get("backup_path",None)
        fileName = data.get("file_name",None)
        # localPath = "/tmp/ScyllaBackup"
        
        isRemote = data.get("remote",False)
        remoteHost = data.get("remote_host",None)
        remotePort = data.get("remote_port",None)
        remoteUser = data.get("remote_user",None)
        remotePassword = data.get("remote_password",None)
        
        if not (keySpaceName and tableName):
            logger.error("Either keyspace or table name must be provided")
            logger.warning("Backup not initiated.")
            payload = {
                "status": False,
                "message": "Backup not initiated.",
                "data": None,
                "error": "Either keyspace or table name must be provided"
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)

        try:    #BUG ID 1109: Backup - Scylla - wrong Host
            session, cluster = CreateScyllaSession(scyllaHost, scyllaPort, isRemote, scyllaUser, scyllaPassword)
        except Exception as e:
            payload = {
                "status": True,
                "message": "Error connecting to Scylla",
                "data":None,
                "error": str(e)
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)
        
        def RemoteBackup(fileName, sshclient, scyllaClient, backupPath, scyllaHost, scyllaVmUser, scyllaVmPassword, keySpaceName, tableName, remoteHost, remotePort, remoteUser, remotePassword, userId):
            try:
                estimatedSizeDict, _ = GetEstimatedBackupSize(scyllaClient, [keySpaceName])
                estimatedSize = estimatedSizeDict.get(keySpaceName, "0 B")
                totalSizeBytes = ConvertToBytes(estimatedSize)
                availableSpaceBytes = ConvertToBytesB(CheckRemoteDiskSpace(sshclient, backupPath))

                if isinstance(totalSizeBytes, str):
                    totalSizeBytes = ConvertToBytes(totalSizeBytes)

                if availableSpaceBytes < totalSizeBytes:
                    logger.error("Not enough space on the remote host for backup.")
                    payload = {
                        "status": False,
                        "message": "Not enough space on the remote host for backup.",
                        "required_space": FormatSize(totalSizeBytes),
                        "available_space": FormatSize(availableSpaceBytes),
                        "error": None
                    }
                    return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
                
                if not IsValidFileName(fileName):
                    logger.error(f'Invalid fileName format')
                    payload = {
                        "status": False,
                        "message": "Invalid FileName format",
                        "data": None,
                        "error": "Invalid FileName format",
                    }
                    return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE) 
            
                backupPath = f'{backupPath}/{int(datetime.now().timestamp())}_{fileName}'
                starttime = datetime.now()
                ipAddress = remoteHost
                snapshotTag = f"{int(datetime.now().timestamp())}_{tableName}"
                path = f"{backupPath}/{snapshotTag}"
                backupMode = "remote"

                responseData, value = SaveDataToDb("partial", backupMode, ipAddress, path, "Scheduled", "Backup scheduled", None, userId)
                Id = value['id']

                if not responseData:
                    payload = {
                        "status": False,
                        "message": "Cannot Log to Database",
                        "data": None,
                        "error": None
                    }
                    return Response(payload, status=status.HTTP_404_NOT_FOUND)

                snapShotPaths = CaptureDataForSingleTableLocalAndRemote(scyllaHost, scyllaVmUser, scyllaVmPassword, keySpaceName, tableName, snapshotTag, backupPath, True, remoteHost, int(remotePort), remoteUser, remotePassword)

                if snapShotPaths:
                    endTime = datetime.now()
                    duration = Duration(starttime, endTime)
                    BackupAndRestore.objects.filter(id=Id).update(status="Success", summary="Backup Successfull", duration=duration)
                    logger.info("Remote backup done successfully")
                    payload = {
                        "status": True,
                        "message": "Remote backup done successfully",
                        "data": None,
                        "error": None
                    }
                    return Response(payload, status=status.HTTP_200_OK)
                else:
                    BackupAndRestore.objects.filter(id=Id).update(status="Failed", summary="Backup Failed")
                    logger.error("backup failed")
                    
            except Exception as e:
                logger.error("Remote backup failed due to an error." + str(e))
                payload = {
                    "status": False,
                    "message": "Remote backup failed due to an error.",
                    "data": None,
                    "error": str(e)
                }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            
        if isRemote:
            if not (backupPath and remoteHost and remotePort and remoteUser and remotePassword):
                logger.error("Backup won't proceed without remote credentials.")
                logger.warning("Please provide remote credentials with backup path to proceed with backup.")
                payload = {
                    "status": False,
                    "message": "Please provide remote credentials with backup path to proceed with backup.",
                    "data": None,
                    "error": "Backup won't proceed without remote credentials."
                }
                return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
            else:
                sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
                scyllaClient = CreateSshClient(scyllaHost, 22, scyllaVmUser, scyllaVmPassword)
                
                if sshclient:
                    backupThread = threading.Thread(target=RemoteBackup,
                                        args=(fileName, sshclient, scyllaClient, backupPath, scyllaHost, scyllaVmUser, scyllaVmPassword, keySpaceName, tableName, remoteHost, remotePort, remoteUser, remotePassword, userId),
                                        daemon=True)
                    
                    backupThread.start()
                    
                    payload = {
                        "status": True,
                        "message": "Backup has been scheduled. Please check log table for more details.",
                        "data": None,
                        "error": None
                    }
                    return Response(payload, status=status.HTTP_200_OK)

                else:
                    logger.error("Remote client connection failed.")
                    payload = {
                        "status": False,
                        "message": "Remote client connection failed.",
                        "data": None,
                        "error": None
                    }
                    return Response(payload, status=status.HTTP_404_NOT_FOUND)
        
        else:   
            def RunBackup(fileName, starttime, keySpaceName, userId, scyllaHost, scyllaVmUser, scyllaVmPassword, tableName, backupPath, isRemote, remoteHost, remotePort, remoteUser, remotePassword):
                try:
                    if not IsValidFileName(fileName):
                        logger.error(f'Invalid fileName format')
                        payload = {
                            "status": False,
                            "message": "Invalid FileName format",
                            "data": None,
                            "error": "Invalid FileName format",
                        }
                        return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE) 
                    
                    ipAddress = scyllaHost  #BUG ID 1276: Scylla Backup; Ip Address
                    path = config['SCYLLA_DATA_DIR']
                    backupMode = "local"
                    snapshotTag = f"{int(datetime.now().timestamp())}_{fileName}_{tableName}"

                    responseData, value = SaveDataToDb("partial", backupMode, ipAddress, path, "Scheduled", "Backup scheduled", None, userId)
                    Id = value['id']

                    if not responseData:
                        logger.error("Cannot log to database.")
                        return

                    snapShotPaths = CaptureDataForSingleTableLocalAndRemote(scyllaHost, scyllaVmUser, scyllaVmPassword, keySpaceName, tableName, snapshotTag, backupPath, isRemote, remoteHost, remotePort, remoteUser ,remotePassword)

                    if snapShotPaths:
                        endTime = datetime.now()
                        duration = Duration(starttime, endTime)
                        BackupAndRestore.objects.filter(id=Id).update(status="Success", summary="Backup Successful", duration=duration, path=snapShotPaths)
                        logger.info("Backup completed successfully")
                    
                    else:
                        BackupAndRestore.objects.filter(id=Id).update(status="Failed", summary="Backup Failed")
                        logger.error("Failed to capture snapshot.")
                
                except Exception as e:
                    logger.error(f"Backup failed due to an error: {str(e)}")
                    return
            
            try:
                starttime = datetime.now()
                backupThread = threading.Thread(target=RunBackup, 
                                                args=(fileName, starttime, keySpaceName, userId, scyllaHost, scyllaVmUser, scyllaVmPassword, tableName, backupPath, isRemote, remoteHost, remotePort, remoteUser ,remotePassword),
                                                daemon=True)
                backupThread.start()

                payload = {
                    "status": True,
                    "message": "Backup has been scheduled. Please check log table for more details.",
                    "data": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_200_OK)
                    
            except Exception as e:
                logger.error("Backup failed due to an error.")
                payload = {
                    "status": False,
                    "message": "Backup failed due to an error.",
                    "data": None,
                    "error": str(e)
                }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            

# class ScyllaRestoreForSingleTable(APIView):
#     @swagger_auto_schema(
#         operation_description="""View available snapshots using GET request.
#             1. This API endpoint allows you to fetch available snapshots.
#             2. Restore can be initited from remote as well as local server.
#             3. Valid scylladb credentials is required to restore backuped data for both remote and local server.
#             Note: This API requires systemadmin for restoration.
#         """,
#         operation_summary='Start Keyspace Restore',
#     )        
#     def get(self, request):
#         apiData = UserAuthenticationFromUserManagement(request)
            
#         if isinstance(apiData, Response):
#             return apiData
        
#         isSuperuser = apiData['data'][0]['is_superuser']
#         userName = apiData['data'][0]['username']
        
#         if(not isSuperuser):
#             logger.warning(f'{userName}: do not have permission to list available snapshots')
#             payload = {  
#                 "status":False,
#                 "message":"You don't have permission to list available snapshots",
#                 "data": None,
#                 "error": "You don't have permission to list available snapshots",                
#             }
#             return Response(payload, status=status.HTTP_403_FORBIDDEN)    

#         logger.info(f"Permission granted for {userName} to list available snapshots.") 
        
#         params = request.query_params.dict()
#         scyllaHost = params.get('scylla_host',None)
#         scyllaPort = params.get('scylla_port',None)
#         scyllaPassword = params.get('scylla_password',None)
#         scyllaUser = params.get('scylla_user',None)
#         keyspace = params.get('keyspace_name',None)
#         table = params.get('table_name',None)
    
#         snapshotOutput = ListSnapshots(scyllaHost, scyllaPort, scyllaUser, scyllaPassword, keyspace, table)  
#         if snapshotOutput:
#             logger.info("Listing available snapshots for keyspace: "+ keyspace + " table: "+ table)
#             payload = {
#                 "status": True,
#                 "message": "Available snaphots",
#                 "data":snapshotOutput,
#                 "error": None
#             }
#             return Response(payload, status=status.HTTP_200_OK)
#         else:
#             logger.error("Snapshots unavailable")
#             payload = {
#                 "status": False,
#                 "message": "Snapshots unavailable",
#                 "error": None
#             }
#             return Response(payload, status=status.HTTP_404_NOT_FOUND)
        
    
#     @swagger_auto_schema(
#         operation_description="""Start restoring for the files which were backuped using POST request.
#             1. This API endpoint allows you to start restoration by providing valid credentials and path where the backed up file is present in the request body.
#             2. Restore can be initited from remote as well as local server.
#             3. Valid scylladb credentials is required to restore backuped data for both remote and local server.
#             Note: This API requires systemadmin for restoration.
#         """,
#         operation_summary='Start Keyspace Restore',
#     )
#     def post(self, request):
#         apiData = UserAuthenticationFromUserManagement(request)
            
#         if isinstance(apiData, Response):
#             return apiData
        
#         isSuperuser = apiData['data'][0]['is_superuser']
#         userName = apiData['data'][0]['username']
        
#         if(not isSuperuser):
#             logger.warning(f'{userName}: do not have permission to restore snapshots')
#             payload = {  
#                 "status":False,
#                 "message":"You don't have permission to restore snapshots",
#                 "data": None,
#                 "error": "You don't have permission to restore snapshots",                
#             }
#             return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
#         logger.info(f"Permission granted for {userName} to restore snapshots.") 
        
#         data = request.data
#         scyllaHost = data.get('scylla_host',None)
#         scyllaPort = data.get('scylla_port',None)
#         scyllaPassword = data.get('scylla_password',None)
#         scyllaUser = data.get('scylla_user',None)
        
#         backupPath = data.get("backup_file", None)
#         keyspace = data.get("keyspace",None)
#         tableName = data.get("tablename",None)
#         snapshotname = data.get("snapshot_name",None)
        
#         isRemote = data.get("remote",False)
#         remoteHost = data.get("remote_host",None)
#         remoteUser = data.get("remote_user",None)
#         remotePort = data.get("remote_port",None)
#         remotePassword = data.get("remote_password",None)
        
#         if not (keyspace and tableName or snapshotname):
#             logger.error("Backup not initiated. Either keyspace, table name or snapshotname must be provided")
#             payload = {
#                 "status": False,
#                 "message": "Backup not initiated.",
#                 "data": None,
#                 "error": "Either keyspace, table name or snapshotname must be provided"
#             }
#             return Response(payload, status=status.HTTP_400_BAD_REQUEST)

#         try:    #BUG ID 1109: Backup - Scylla - wrong Host 
#             cluster = Cluster([scyllaHost], port=int(scyllaPort))
#             session = cluster.connect()
#             logger.info("Scylla connection established.")
#         except Exception as e:
#             payload = {
#                 "status": True,
#                 "message": "Error connecting to Scylla",
#                 "data":None,
#                 "error": str(e)
#             }
#             return Response(payload, status=status.HTTP_404_NOT_FOUND)
        
#         if isRemote:
#             if not (backupPath and remoteHost and remotePort and remoteUser and remotePassword):
#                 logger.error("Restore won't proceed without remote credentials.")
#                 logger.warning("Please provide remote credentials with backup path to proceed with restore.")
#                 payload = {
#                     "status": False,
#                     "message": "Please provide remote credentials with backup path to proceed with restore.",
#                     "data": None,
#                     "error": "Restore won't proceed without remote credentials."
#                 }
#                 return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
#             else:
#                 sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
#                 if sshclient:
#                     try:
#                         reponse = RestoreDataForSingleTableLocalAndRemote(scyllaHost, scyllaPort, scyllaUser, scyllaPassword, keyspace, tableName, backupPath, isRemote, remoteHost, remoteUser, remotePassword)
#                         if reponse:
#                             logger.info(f"Restoration of table {tableName} completed successfully.") 
#                             payload = {
#                                 "status": True,
#                                 "message": f"Restoration of table {tableName} completed successfully. Please restart ScyllaDB to reflect the newly restored data.",
#                                 "data": None,
#                                 "error": None
#                             }
#                             return Response(payload, status=status.HTTP_200_OK)
#                         else:
#                             logger.error("Restoration failed")
#                             payload = {
#                                 "status": False,
#                                 "message": "Restoration failed",
#                                 "data":None,
#                                 "error": "Restoration failed"
#                             }
#                             return Response(payload, status=status.HTTP_400_BAD_REQUEST)
#                     except Exception as e:
#                         logger.error("Restoration failed due to an error.")
#                         payload = {
#                             "status": False,
#                             "message": "Restoration failed due to an error.",
#                             "data": None,
#                             "error": str(e),
#                         }
#                         return Response(status=status.HTTP_400_BAD_REQUEST)
#                 else:
#                     logger.error("Remote client connection failed.")
#                     payload = {
#                         "status": False,
#                         "message": "Remote client connection failed.",
#                         "data": None,
#                         "error": None
#                     }
#                     return Response(payload, status=status.HTTP_404_NOT_FOUND)
#         else:
#             reponse = RestoreDataForSingleTableLocal(scyllaHost, scyllaPort, scyllaUser, scyllaPassword, keyspace, tableName, snapshotname)#RestoreDataForSingleTableLocalAndRemote(scyllaHost, scyllaPort, scyllaUser, scyllaPassword, keyspace, tableName, backupPath,localPath, isRemote, remoteHost, remoteUser, remotePassword)
#             if reponse:
#                 logger.info(f"Restoration of table {tableName} completed successfully.") 
#                 payload = {
#                     "status": True,
#                     "message": f"Restoration of table {tableName} completed successfully. Please restart ScyllaDB to reflect the newly restored data.",
#                     "data": None,
#                     "error": None
#                 }
#                 return Response(payload, status=status.HTTP_200_OK)
#             else:
#                 logger.error("Restoration failed")
#                 payload = {
#                     "status": False,
#                     "message": "Restoration failed",
#                     "data":None,
#                     "error": "Check if the keyspace and table name exist."
#                 }
#                 return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        

# class ScyllaKeyspaceAndTable(APIView):
#     def get(self, request):
#         apiData = UserAuthenticationFromUserManagement(request)
            
#         if isinstance(apiData, Response):
#             return apiData
        
#         isSuperuser = apiData['data'][0]['is_superuser']
#         userName = apiData['data'][0]['username']
        
#         if(not isSuperuser):
#             logger.warning(f'{userName}: do not have permission to list keyspaces')
#             payload = {  
#                 "status":False,
#                 "message":"You don't have permission to list keyspaces",
#                 "data": None,
#                 "error": "You don't have permission to list keyspaces",                
#             }
#             return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
#         logger.info(f"Permission granted for {userName} to list keyspaces.") 
        
#         params = request.query_params.dict()
#         scyllaHost = params.get('scylla_host',None)
#         scyllaPassword = params.get('scylla_password',None)
#         scyllaUser = params.get('scylla_user',None)
#         keySpaceName = params.get("keyspace_name", None)
#         tableName = params.get("table_name", None)
        
#         if keySpaceName and tableName:
#             if KeyspaceExists(scyllaHost, scyllaUser, scyllaPassword, keySpaceName):
#                 if CheckTablesExist(scyllaHost, scyllaUser, scyllaPassword, keySpaceName, tableName):
#                     logger.info("Table exists.")
#                     payload = {
#                         "status": True,
#                         "message": "Table exists.",
#                         "data": tableName,
#                         "error": None
#                     }
#                     return Response(payload, status=status.HTTP_200_OK)
#                 else:
#                     logger.error("Table does not exists.")
#                     payload = {
#                         "status": True,
#                         "message": "Table does not exists.",
#                         "data": tableName,
#                         "error": None
#                     }
#                     return Response(payload, status=status.HTTP_400_BAD_REQUEST)
#             else:
#                 logger.error("Keyspace does not exists.")
#                 payload = {
#                     "status": False,
#                     "message": "Keyspace does not exists.",
#                     "data": keySpaceName,
#                     "error": None
#                 }
#                 return Response(payload, status=status.HTTP_400_BAD_REQUEST)
#         else:
#             logger.error("Keyspace name and table name are required.")
#             payload = {
#                 "status": False,
#                 "message": "Keyspace name and table name are required.",
#                 "data": None,
#                 "error": None
#             }
#             return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
class FetchScyllaVersion(APIView):
    @swagger_auto_schema(
        operation_description="""Get scylla version using GET request.
            1. This API endpoint allows you to fetch scylla version.
            Note: This API requires systemadmin to view scylla version.
        """,
        operation_summary='Fetch Scylla Version',
    )
    def get(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        
        params = request.query_params.dict()
        scyllaHost = params.get('scylla_host',None)
        scyllaPort = params.get('scylla_port',None)
        scyllaUser = params.get('scylla_user',None)
        scyllaPassword = params.get('scylla_password',None)

        if(not isSuperuser):
            logger.warning(f'{userName}: do not have permission to check connection')
            payload = {  
                "status":False,
                "message":"You don't have permission to check connection",
                "data": None,
                "error": "You don't have permission to check connection",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to check connection.")

        version = ScyllaVersion(scyllaHost, scyllaPort, scyllaUser, scyllaPassword)
        if version:
            payload = {
                "status": True,
                "message": "Scylla version fetched successfully.",
                "data": version,
                "error": None
            }
            return Response(payload, status=status.HTTP_200_OK)
        else:
            payload = {
                "status": False,
                "message": "Failed to fetch Scylla version.",
                "data": None,
                "error": "Error fetching Scylla version."
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
                
class FetchKeyspaces(APIView):
    @swagger_auto_schema(
    operation_description="""Get list of existing keyspaces by providing valid credentials in query parameters using GET request.
        This API endpoint allows you to retrieve keyspaces with certain scenarious.
        1. Provide valid scylladb credentials to fetch keyspaces list and size.
        2. Provide virtual machine credentials where scylladb is installed to check storage usage.
        Note: This API requires systemadmin to view keyspaces list.
    """,
    operation_summary='View List Of Keyspaces',
    )
    def get(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        
        if(not isSuperuser):
            logger.warning(f'{userName}: do not have permission to view keyspaces in the cluster')
            payload = {  
                "status":False,
                "message":"You don't have permission to view keyspaces in the cluster",
                "data": None,
                "error": "You don't have permission to view keyspaces in the cluster",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to fetch keyspaces in the cluster.") 
        
        params = request.query_params.dict()
        scyllaHost = params.get('scylla_host',None)
        scyllaPort = params.get('scylla_port',None)
        scyllaUser = params.get('scylla_user',None)
        scyllaPassword = params.get('scylla_password',None)
        scyllaVmUser = params.get('scylla_vm_user',None)
        scyllaVmPassword = params.get('scylla_vm_password',None)
        scyllaDataDir = config["SCYLLA_DATA_DIR"]
        
        if (scyllaHost==None or scyllaPort==None or scyllaUser==None or scyllaPassword==None):
            logger.error("Mandatory fields not provided")
            payload = {
                "status": False,
                "message": "Please Provide Scylla Credentials.",
                "data":None,
                "error": "Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        if (scyllaVmUser==None and scyllaVmPassword==None):
            logger.error("Mandatory fields not provided")
            payload = {
                "status": False,
                "message": "Please Provide Scylla VM Credentials.",
                "data":None,
                "error": "Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        try:
            if scyllaUser and scyllaPassword:
                authProvider = PlainTextAuthProvider(username=scyllaUser, password=scyllaPassword)
                cluster = Cluster([scyllaHost], port=int(scyllaPort), auth_provider=authProvider)
            else:
                cluster = Cluster([scyllaHost], port=int(scyllaPort))
        
            session = cluster.connect()
        except Exception as e:
            logger.error(f"Error connecting to Scylla: {str(e)}")
            payload = {
                "status": False,
                "message": "Connecting to Scylla failed. Please check scylla credentials and try again.",
                "data":None,
                "error": str(e)
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)
        
        if session:
            keySpaces = session.execute("SELECT keyspace_name FROM system_schema.keyspaces")
            if not keySpaces:
                payload = {
                    "status": False,
                    "message": "No keyspaces found in the cluster.",
                    "data":None,
                    "error": "No keyspaces found in the cluster."
                }
                return Response(payload, status=status.HTTP_404_NOT_FOUND)    
        
        excludeKeyspaces = ['system', 'system_schema', 'system_auth', 'system_distributed', 'system_traces','system_distributed_everywhere']
        
        keySpaceNames = []
        totalSize = 0
        
        sshClient = CreateSshClient(scyllaHost, 22, scyllaVmUser, scyllaVmPassword)
        if sshClient:
            try:
                for row in keySpaces:
                    keySpaceName=row.keyspace_name
                    if keySpaceName in excludeKeyspaces:
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
                                
                formattedTotalSize = FormatSize(totalSize)
                remoteDiskUsage = GetDiskUsageRemote(scyllaVmUser, scyllaVmPassword, scyllaHost, scyllaDataDir)
                if not remoteDiskUsage:
                    payload = {
                        "status":False,
                        "message":"Invalid credentials provided. Please enter valid credentials",
                        "data":None,
                        "error":"Please provide valid credentials to check disk usage"
                    }
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)    
                
                logger.info("Listing available keyspaces.")
                payload = {
                    "status": True,
                    "message": "Keyspaces fetched successfully.",
                    "data": keySpaceNames,
                    "total_size": formattedTotalSize,
                    "error": None,
                }
                return Response(payload, status=status.HTTP_200_OK)
            
            except Exception as e:
                logger.error(f"Error occurred while fetching keyspaces results: {str(e)}")
                payload = {
                    "status": False,
                    "message": "Error listing of available keyspaces in the cluster",
                    "data": None,
                    "total_size": None,
                    "error": str(e)
                }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            
            finally:
                session.shutdown()
                cluster.shutdown()
        
        else:
            payload = {
                "status": False,
                "message": "Failed to establish connection. Please check scylla vm crendetials.",
                "data": None,
                "error": "SSH connection failed."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
                        
class ScyllaBackupKeyspace(APIView):
    @swagger_auto_schema(
        operation_description="""Start a new backup and save it based on backup type using POST request.
            1. This API endpoint allows you to start backup by providing valid credentials in the request body.
            2. Backup can be initited to remote as well as local server.
            3. Valid scylladb credentials is required to start backup for both remote and local server.
            4. Logs can be checked in log table post backup.
            Note: This API requires systemadmin to initiate backup.
        """,
        operation_summary='Start Keyspace Backup',
    )
    def post(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        userId = apiData['data'][0]['id']
        
        if(not isSuperuser):
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
        
        scyllaHost = data.get('scylla_host',None)
        scyllaPort = data.get('scylla_port',None)
        scyllaPassword = data.get('scylla_password',None)
        scyllaUser = data.get('scylla_user',None)
        scyllaVmUser = data.get('scylla_vm_user',None)
        scyllaVmPassword = data.get('scylla_vm_password',None)
        
        backupPath = data.get("backup_path",None)
        fileName = data.get("file_name",None)
        
        isRemote = data.get("remote",False)
        remoteHost = data.get("remote_host",None)
        remotePort = data.get("remote_port",None)
        remoteUser = data.get("remote_user",None)
        remotePassword = data.get("remote_password",None)
        
        if (scyllaHost==None or scyllaPort==None or scyllaPassword==None or scyllaUser==None):
            payload = {
                "status": False,
                "message": "Backup keyspaces failed.",
                "data":None,
                "error": "Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        try:    #BUG ID 1110: Backup and Restore - Scylla - Credentials
            session, cluster = CreateScyllaSession(scyllaHost, scyllaPort, isRemote, scyllaUser, scyllaPassword)
            keySpaces = session.execute("SELECT keyspace_name FROM system_schema.keyspaces")
        except Exception as e:
            payload = {
                "status": False,
                "message": "Connecting to Scylla failed. Please check scylla credentials and try again.",
                "data":None,
                "error": str(e)
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)
        
        if (not fileName or fileName==None):
            payload = {
                "status": False,
                "message": "File name not provided.",
                "data":None,
                "error": "Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        systemKeyspaces = [
            'system', 
            'system_schema', 
            'system_auth', 
            'system_distributed', 
            'system_traces',
            'system_distributed_everywhere'
        ]
        
        keySpaceNames = []
        for row in keySpaces:
            keySpaceName=row.keyspace_name
            if keySpaceName not in systemKeyspaces:
                keySpaceNames.append(keySpaceName)
        
        if isRemote:
            def RemoteBackup(fileName, sshclient, scyllaClient, starttime, keySpaceNames, userId, scyllaHost, scyllaUser, scyllaPassword, backupPath, remoteHost, remotePort, remoteUser, remotePassword):
                try:
                    if keySpaceNames:
                        estimatedSizeDict, _ = GetEstimatedBackupSize(scyllaClient, keySpaceNames)
                        
                        totalSizeBytes = 0
                        for keyspace in keySpaceNames:
                            estimatedSize = estimatedSizeDict.get(keyspace, "0 B")
                            sizeBytes = ConvertToBytes(estimatedSize)
                            totalSizeBytes += sizeBytes
                        
                        availableSpaceBytes = ConvertToBytesB(CheckRemoteDiskSpace(sshclient, backupPath))
                        
                        if isinstance(totalSizeBytes, str):
                            totalSizeBytes = ConvertToBytes(totalSizeBytes)
                        
                        if not IsValidFileName(fileName):
                            logger.error(f'Invalid fileName format')
                            payload = {
                                "status": False,
                                "message": "Invalid FileName format",
                                "data": None,
                                "error": "Invalid FileName format",
                            }
                            return Response(payload,status=status.HTTP_406_NOT_ACCEPTABLE) 
                        
                        snapshotTag = f"{int(datetime.now().timestamp())}_{fileName}"

                        backupPath = f'{backupPath}/{snapshotTag}'
                        ipAddress = remoteHost
                        path = backupPath
                        backupMode = "remote"

                        responseData, value = SaveDataToDb("complete", backupMode, ipAddress, path, "Scheduled", "Backup scheduled", None, userId)
                        Id = value['id']

                        if not responseData:
                            logger.error("Cannot log to database.")
                            return

                        if availableSpaceBytes < totalSizeBytes:
                            logger.error("Not enough space on the remote host for backup.")
                            BackupAndRestore.objects.filter(id=Id).update(status="Failed", summary="Not enough space on the remote host for backup.")

                        path = CaptureKeySpaceSnapshotRemoteAndLocal(snapshotTag, scyllaHost, scyllaUser, scyllaPassword, keySpaceNames, True, backupPath, remoteHost, remotePort, remoteUser, remotePassword)

                        if path:
                            endTime = datetime.now()
                            duration = Duration(starttime, endTime)
                            BackupAndRestore.objects.filter(id=Id).update(status="Success", summary="Backup Successful", duration=duration)
                            logger.info("Backup done")
                        
                        else:
                            BackupAndRestore.objects.filter(id=Id).update(status="Failed", summary="Backup Failed")
                            logger.error("Backup failed, snapshot path is empty.")
                    
                    else:
                        logger.error("Keyspaces does not exist.")
                
                except Exception as e:
                    logger.error(f"Remote backup failed due to an error: {str(e)}")
                
            if not (backupPath and remoteHost and remotePort and remoteUser and remotePassword):
                logger.error("Please provide remote credentials with backup path to proceed with backup.")
                payload = {
                    "status": False,
                    "message": "Please provide remote credentials with backup path to proceed with backup.",
                    "data": None,
                    "error": "Backup won't proceed without remote credentials."
                }
                return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
            else:
                sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
                scyllaClient = CreateSshClient(scyllaHost, 22, scyllaVmUser, scyllaVmPassword)
                if sshclient:
                    starttime = datetime.now()
                    backupThread = threading.Thread(target=RemoteBackup,
                                                    args=(fileName, sshclient, scyllaClient, starttime, keySpaceNames, userId, scyllaHost, scyllaVmUser, scyllaVmPassword, backupPath, remoteHost, remotePort, remoteUser, remotePassword),
                                                    daemon=True)
                    backupThread.start()

                    payload = {
                        "status": True,
                        "message": "Backup has been scheduled. Please check log table for more details.",
                        "data": None,
                        "error": None
                    }
                    return Response(payload, status=status.HTTP_200_OK)
                    
                else:
                    logger.error("Remote client connection failed.")
                    payload = {
                        "status": False,
                        "message": "Remote client connection failed. Please check remote credentials.",
                        "data": None,
                        "error": "Remote client connection failed."
                    }
                    return Response(payload, status=status.HTTP_404_NOT_FOUND)
                
        else:
            def LocalBackup(scyllaClient, sshclient, fileName, keySpaceNames, userId, scyllaHost, scyllaUser, scyllaPassword, backupPath, remoteHost, remotePort, remoteUser, remotePassword):
                try:
                    estimatedSizeDict, _ = GetEstimatedBackupSize(scyllaClient, keySpaceNames)
                    totalSizeBytes = 0
                    for keyspace in keySpaceNames:
                        estimatedSize = estimatedSizeDict.get(keyspace, "0 B")
                        sizeBytes = ConvertToBytes(estimatedSize)
                        totalSizeBytes += sizeBytes
                        
                    availableSpaceBytes = ConvertToBytesB(CheckRemoteDiskSpace(sshclient, config["SCYLLA_DATA_DIR"]))

                    if isinstance(totalSizeBytes, str):
                        totalSizeBytes = ConvertToBytes(totalSizeBytes)

                    if not IsValidFileName(fileName):
                        logger.error(f'Invalid fileName format')
                        payload = {
                            "status": False,
                            "message": "Invalid FileName format",
                            "data": None,
                            "error": "Invalid FileName format",
                        }
                        return Response(payload,status=status.HTTP_406_NOT_ACCEPTABLE) 
                    
                    starttime = datetime.now()
                    ipAddress = scyllaHost  #BUG ID 1276: Scylla Backup; Ip Address
                    # path = config['SCYLLA_DATA_DIR']
                    backupMode = "local"
                    snapshotTag = f"{int(datetime.now().timestamp())}_{fileName}"
                    path = f"{config['SCYLLA_DATA_DIR']}/{snapshotTag}"

                    responseData, value = SaveDataToDb("complete", backupMode, ipAddress, path, "Scheduled", "Backup scheduled", None, userId)
                    Id = value['id']

                    if not responseData:
                        logger.error("Cannot log to database.")
                        return
                    
                    if availableSpaceBytes < totalSizeBytes:
                        logger.error("Not enough space on the local host for backup.")
                        BackupAndRestore.objects.filter(id=Id).update(status="Failed",
                                                                      path=None, 
                                                                      summary="Not enough space on the local host for backup.")
                        return
                    
                    path = CaptureKeySpaceSnapshotRemoteAndLocal(snapshotTag, scyllaHost, scyllaUser, scyllaPassword, keySpaceNames, False, backupPath, remoteHost, remotePort, remoteUser, remotePassword) #BUG ID 1526: Scylla Complete Backup

                    if path:
                        endTime = datetime.now()
                        duration = Duration(starttime, endTime)
                        BackupAndRestore.objects.filter(id=Id).update(status="Success", 
                                                                    summary="Backup Successful",
                                                                    duration=duration)
                        logger.info("Backup done")

                    else:
                        BackupAndRestore.objects.filter(id=Id).update(status="Failed", path=None, summary="Backup Failed")
                        logger.error("Backup failed, snapshot path is empty.")

                except Exception as e:
                    logger.error(f"Local backup failed due to an error: {str(e)}")

            sshclient = CreateSshClient(config["LOCAL_SCYLLA_HOST"], int(22), config["SCYLLA_VM_USER"], config["SCYLLA_VM_PASSWORD"])
            scyllaClient = CreateSshClient(scyllaHost, 22, scyllaVmUser, scyllaVmPassword)
            backupThread = threading.Thread(target=LocalBackup, 
                                            args=(scyllaClient, sshclient, fileName, keySpaceNames, userId, scyllaHost, scyllaVmUser, scyllaVmPassword, backupPath, remoteHost, remotePort, remoteUser, remotePassword),
                                            daemon=True)
            backupThread.start()
            payload = {
                "status": True,
                "message": "Backup has been scheduled. Please check log table for more details.",
                "data": None,
                "error": None
            }
            return Response(payload, status=status.HTTP_200_OK)
            
            # path = CaptureKeySpaceSnapshotRemoteAndLocal(scyllaHost, scyllaUser, scyllaPassword, keySpaceNames, isRemote, localPath, backupPath, remoteHost, remotePort, remoteUser, remotePassword)
            # if path:
            #     endTime = datetime.now()
            #     duration = Duration(starttime, endTime)
            #     BackupAndRestore.objects.filter(id=Id).update(status="Success", 
            #                                                     summary="Backup Successfull",
            #                                                     duration=duration)
            #     logger.info("Backup done")
            #     payload = {
            #         "status": True,
            #         "message": "Backup done",
            #         "data": path,
            #         "error": None
            #     }
            #     return Response(payload, status=status.HTTP_200_OK)
            # else:
            #     BackupAndRestore.objects.filter(id=Id).update(status="Failed", summary="Backup Failed")
            #     logger.error("Backup failed")
            #     payload = {
            #         "status": False,
            #         "message": "Backup failed.",
            #         "data": None,
            #         "error": None
            #     }
            #     return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
class ViewSnapshots(APIView):
    @swagger_auto_schema(
        operation_description="""View available snapshots using GET request.
            1. This API endpoint allows you to fetch available snapshots.
            Note: This API requires systemadmin for restoration.
        """,
        operation_summary='View Snapshots',
    )        
    def get(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        
        if(not isSuperuser):
            logger.warning(f'{userName}: do not have permission to list available snapshots')
            payload = {  
                "status":False,
                "message":"You don't have permission to list available snapshots",
                "data": None,
                "error": "You don't have permission to list available snapshots",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)    

        logger.info(f"Permission granted for {userName} to list available snapshots.") 
        
        params = request.query_params.dict()
        scyllaHost = params.get('scylla_host',None)
        scyllaPort = params.get('scylla_port',None)
        scyllaPassword = params.get('scylla_password',None)
        scyllaUser = params.get('scylla_user',None)
        keyspace = params.get('keyspace_name',None)
        table = params.get('table_name',None)
    
        snapshotOutput = ListSnapshots(scyllaHost, scyllaPort, scyllaUser, scyllaPassword, keyspace, table)  
        if snapshotOutput:
            logger.info(f"Listing available snapshots for keyspace: {keyspace}: table: {table}")
            payload = {
                "status": True,
                "message": "Available snaphots",
                "data":snapshotOutput,
                "error": None
            }
            return Response(payload, status=status.HTTP_200_OK)
        else:
            logger.error("Snapshots unavailable")
            payload = {
                "status": False,
                "message": "Snapshots unavailable",
                "error": None
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)

class ScyllaRestoreKeyspace(APIView):
    @swagger_auto_schema(
        operation_description="""Start restoring for the files which were backuped using POST request.
            1. This API endpoint allows you to start restoration by providing valid credentials and path where the backed up file is present in the request body.
            2. Restore can be initited from remote as well as local server.
            3. Valid scylladb credentials is required to restore backuped data for both remote and local server.
            Note: This API requires systemadmin for restoration.
        """,
        operation_summary='Start Keyspace Restore',
    )
    def post(self, request):
        # apiData = UserAuthenticationFromUserManagement(request)
            
        # if isinstance(apiData, Response):
        #     return apiData
        
        # isSuperuser = apiData['data'][0]['is_superuser']
        # userName = apiData['data'][0]['username']
        # userId = apiData['data'][0]['id']
        
        # if(not isSuperuser):
        #     logger.warning(f'{userName}: do not have permission to restore keyspaces')
        #     payload = {  
        #         "status":False,
        #         "message":"You don't have permission to restore keyspaces",
        #         "data": None,
        #         "error": "You don't have permission to restore keyspaces",                
        #     }
        #     return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        # logger.info(f"Permission granted for {userName} to restore keyspaces.") 
        
        data = request.data

        scyllaHost = data.get('scylla_host',None)
        scyllaPort = data.get('scylla_port', None)
        scyllaUser = data.get('scylla_user',None)
        scyllaPassword = data.get('scylla_password',None)
        scyllaVmUser = data.get('scylla_vm_user',None)
        scyllaVmPassword = data.get('scylla_vm_password',None)
        
        backupPath = data.get("backup_file",None)
        
        isRemote = data.get("remote",False)
        remoteHost = data.get("remote_host",None)
        remotePort = data.get("remote_port",None)
        remoteUser = data.get("remote_user",None)
        remotePassword = data.get("remote_password",None)
        
        postgresHost = data.get("postgres_host",None)
        postgresPort = data.get("postgres_port",None)
        postgresUser = data.get("postgres_user",None)
        postgresPassword = data.get("postgres_password",None)
        postgresDatabaseName = config["POSTGRESQL_RESTORE_LOG_DATABASE_NAME"]
        postgresTableName = config["POSTGRESQL_RESTORE_LOG_TABLE_NAME"]
        
        if (scyllaHost==None or scyllaPort==None or scyllaPassword==None or scyllaUser==None):
            payload = {
                "status": False,
                "message": "Backup keysapces failed.",
                "data":None,
                "error": "Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        if (not backupPath or backupPath==None):
            payload = {
                "status": False,
                "message": "Backup File path not provided.",
                "data":None,
                "error": "Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        try:
            session, cluster = CreateScyllaSession(scyllaHost, scyllaPort, isRemote, scyllaUser, scyllaPassword)
            keySpaces = session.execute("SELECT keyspace_name FROM system_schema.keyspaces")
        except Exception as e:
            logger.error(f"Error connecting to Scylla: {str(e)}")
            payload = {
                "status": False,
                "message": "Connecting to Scylla failed. Please check scylla credentials and try again.",
                "data":None,
                "error": "Error connecting to Scylla"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)
        
        systemKeyspaces = [
            'system', 
            'system_schema', 
            'system_auth', 
            'system_distributed', 
            'system_traces',
            'system_distributed_everywhere'
        ]
        
        keySpaceNames = []
        for row in keySpaces:
            keySpaceName=row.keyspace_name
            if keySpaceName not in systemKeyspaces:
                keySpaceNames.append(keySpaceName)
        
        try:
            conn = psycopg2.connect(
                host=postgresHost,
                port=postgresPort,
                user=postgresUser,
                password=postgresPassword,
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
        
        if isRemote:
            if not (backupPath and remoteHost and remotePort and remoteUser and remotePassword):
                logger.error("Please provide remote credentials with backup path to proceed with restore.")
                logger.warning("Restore won't proceed without remote credentials.")
                payload = {
                    "status": False,
                    "message": "Please provide remote credentials with backup path to proceed with restore.",
                    "data": None,
                    "error": "Restore won't proceed without remote credentials."
                }
                return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
            else:
                def RunRemoteRestore(postgresHost, postgresPort, postgresUser, postgresPassword, postgresDatabaseName, postgresTableName, remoteHost, remotePort, remoteUser, remotePassword, scyllaHost, scyllaPort, scyllaUser, scyllaPassword, scyllaVmUser, scyllaVmPassword, isRemote, backupPath):
                    startTime = datetime.now()
                    
                    sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
                    if sshclient:
                        ipAddress = remoteHost
                        path = backupPath
                        restoreMode = "remote"
                        
                        # responseStatus, restoreId = InsertRestoreLogToPostgres(postgresHost, postgresPort, postgresUser, postgresPassword, postgresDatabaseName, postgresTableName, "complete", restoreMode, ipAddress, path, "Scheduled", None, None)
                        # if not responseStatus:
                        #     logger.error("Cannot log to database.")
                        #     return
                        
                        response = RestoreKeySpaceFromRemote(scyllaHost, scyllaPort, scyllaUser, scyllaPassword, scyllaVmUser, scyllaVmPassword, isRemote, backupPath, remoteHost, remoteUser, remotePassword)
                        endTime = datetime.now()
                        duration = Duration(startTime, endTime)
                        if response:
                            logger.info("Restore done from remote. Please restart ScyllaDB to reflect the newly backed-up data.")
                            responseStatus, responseData = InsertRestoreLogToPostgres(postgresHost, postgresPort, postgresUser, postgresPassword, postgresDatabaseName, postgresTableName, "complete", restoreMode, ipAddress, path, "Success", "Restore Done", duration, None)
                            if not responseStatus:
                                logger.error("Cannot log to database.")
                                return
                            
                        else:
                            logger.error("Restore failed from remote.")
                            responseStatus, responseData = InsertRestoreLogToPostgres(postgresHost, postgresPort, postgresUser, postgresPassword, postgresDatabaseName, postgresTableName, "complete", restoreMode, ipAddress, path, "Failed", "Restore Failed", None, None)
                            if not responseStatus:
                                logger.error("Cannot log to database.")
                                return
                    else:
                        logger.error("Remote client connection failed.")
                        responseStatus, responseData = InsertRestoreLogToPostgres(postgresHost, postgresPort, postgresUser, postgresPassword, postgresDatabaseName, postgresTableName, "complete", restoreMode, ipAddress, path, "Failed", "SSH Connection Failed", None, None)
                        if not responseStatus:
                            logger.error("Cannot log to database.")
                            return
                
                thread = threading.Thread(target=RunRemoteRestore,
                                        args=(postgresHost, postgresPort, postgresUser, postgresPassword, postgresDatabaseName, postgresTableName, remoteHost, remotePort, remoteUser, remotePassword, scyllaHost, scyllaPort, scyllaUser, scyllaPassword, scyllaVmUser, scyllaVmPassword, isRemote, backupPath),
                                        daemon=True
                )
                thread.start()

                payload = {
                    "status": True,
                    "message": "Restore process started in the background.",
                    "data": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_202_ACCEPTED)
                
                # sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
                # if sshclient:
                    
                #     response = RestoreKeySpaceFromRemote(scyllaHost, scyllaPort, scyllaUser, scyllaPassword, scyllaVmUser, scyllaVmPassword, isRemote, backupPath, remoteHost, remoteUser, remotePassword)
                #     if response:
                #         logger.info("Restore done from remote. Please restart ScyllaDB to reflect the newly backed-up data.")
                #         payload = {
                #             "status": True,
                #             "message": "Restore done from remote. Please restart ScyllaDB to reflect the newly backed-up data.",
                #             "path": backupPath,
                #             "error": None
                #         }
                #         return Response(payload, status=status.HTTP_200_OK)
                #     else:
                #         logger.error("Restore failed from remote.")
                #         payload = {
                #             "status": False,
                #             "message": "Restore failed from remote.",
                #             "path": backupPath,
                #             "error": "Restore failed from remote."
                #         }
                #         return Response(payload, status=status.HTTP_400_BAD_REQUEST)
                # else:
                #     logger.error("Remote client connection failed.")
                #     payload = {
                #         "status": False,
                #         "message": "Remote client connection failed.",
                #         "data": None,
                #         "error": "Restore failed."
                #     }
                #     return Response(payload, status=status.HTTP_404_NOT_FOUND)

        else:
            def RunLocalRestore(postgresHost, postgresPort, postgresUser, postgresPassword, postgresDatabaseName, postgresTableName, scyllaHost, scyllaPort, scyllaUser, scyllaPassword, scyllaVmUser, scyllaVmPassword, isRemote, backupPath):
                startTime = datetime.now()
                ipAddress = scyllaHost
                path = backupPath
                restoreMode = "local"
                fileName = backupPath.split("/")[-1]
                
                # responseStatus, restoreId = InsertRestoreLogToPostgres(postgresHost, postgresPort, postgresUser, postgresPassword, postgresDatabaseName, postgresTableName,"complete", restoreMode, ipAddress, path,"Scheduled", "Restore Scheduled", None)
                # if not responseStatus:
                #     logger.error("Cannot log to database.")
                #     return
                
                response = RestoreKeySpaceFromLocal(scyllaHost, scyllaPort, scyllaUser, scyllaPassword, scyllaVmUser, scyllaVmPassword, fileName, isRemote)
                endTime = datetime.now()
                duration = Duration(startTime, endTime)
                
                if response:
                    logger.info("Restore done. Please restart ScyllaDB to reflect the newly backed-up data.")
                    responseStatus,responseData = InsertRestoreLogToPostgres(postgresHost, postgresPort, postgresUser, postgresPassword,postgresDatabaseName, postgresTableName,"complete", restoreMode, ipAddress,path,"Success", "Restore Done", duration, None)
                    if not responseStatus:
                        logger.error("Cannot log to database.")
                        return
                        
                else:
                    logger.error("Restoration failed")
                    responseStatus,responseData = InsertRestoreLogToPostgres(postgresHost, postgresPort, postgresUser, postgresPassword,postgresDatabaseName, postgresTableName,"complete", restoreMode, ipAddress,path,"Failed", "Restore Failed", None, None)
                    if not responseStatus:
                        logger.error("Cannot log to database.")
                        return
            
            thread = threading.Thread(target=RunLocalRestore,
                                    args=(postgresHost, postgresPort, postgresUser, postgresPassword,postgresDatabaseName, postgresTableName,scyllaHost, scyllaPort, scyllaUser, scyllaPassword, scyllaVmUser, scyllaVmPassword, isRemote, backupPath),
                                    daemon=True
            )
            thread.start()

            payload = {
                "status": True,
                "message": "Local restore process started in the background.",
                "data": None,
                "error": None
            }
            return Response(payload, status=status.HTTP_202_ACCEPTED)


            # fileName = backupPath.split("/")[-1]

            # response = RestoreKeySpaceFromLocal(scyllaHost, scyllaPort, scyllaUser, scyllaPassword, scyllaVmUser, scyllaVmPassword, fileName, isRemote)
            # if response:
            #     logger.info("Restore done. Please restart ScyllaDB to reflect the newly backed-up data.")
            #     payload = {
            #         "status": True,
            #         "message": "Restore done. Please restart ScyllaDB to reflect the newly backed-up data.",
            #         "data": None,
            #         "error": None
            #     }
            #     return Response(payload, status=status.HTTP_200_OK)
            # else:
            #     logger.error("Restoration failed")
            #     payload = {
            #         "status": False,
            #         "message": "Restoration failed.",
            #         "data": None,
            #         "error": None
            #     }
            #     return Response(payload, status=status.HTTP_400_BAD_REQUEST)

class RestartScylla(APIView):
    @swagger_auto_schema(
        operation_description="""Restart scylladb server using POST request.
            1. This API endpoint allows you to restart scylladb by providing valid credentials.
            2. Restart is required post restoring data.
            Note: This API requires systemadmin for restoration.
        """,
        operation_summary='Restart ScyllaDb',
    )
    def post(self, request):
        # apiData = UserAuthenticationFromUserManagement(request)
            
        # if isinstance(apiData, Response):
        #     return apiData
        
        # isSuperuser = apiData['data'][0]['is_superuser']
        # userName = apiData['data'][0]['username']
        
        # if(not isSuperuser):
        #     logger.warning(f'{userName}: do not have permission to restart scylladb')
        #     payload = {  
        #         "status":False,
        #         "message":"You don't have permission to restart scylladb",
        #         "data": None,
        #         "error": "You don't have permission to restart scylladb",                
        #     }
        #     return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        # logger.info(f"Permission granted for {userName} to restart scylladb.") 
        
        data = request.data
        scyllaHost = data.get('scylla_host',None)
        scyllaVmUser = data.get('scylla_vm_user',None)
        scyllaVmPassword = data.get('scylla_vm_password',None)
        
        restart = data.get("restart",None)
        
        if (scyllaHost==None or scyllaVmPassword==None or scyllaVmUser==None):
            payload = {
                "status":False,
                "message":"Credentials not provided for restarting scylla",
                "data":None,
                "error":"Mandatory fields not provided."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        if restart:
            if StartScylla(scyllaHost,scyllaVmUser,scyllaVmPassword):
                logger.info("Scylladb has been restarted.")
                payload = {
                    "status": True,
                    "message": "Scylladb has been restarted.",
                    "data": None,
                    "error": None,
                }
                return Response(payload, status=status.HTTP_200_OK)
            else:
                logger.error("Error occurred while restarting scylla.")
                payload = {
                    "status": False,
                    "message": "Scylladb has not been restarted.",
                    "data": None,
                    "error": "Error occurred while restarting scylla.",
                }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        else:
            logger.warning("Scylladb has not restarted.")
            payload = {
                "status": True,
                "message": "Scylladb has not restarted.",
                "data": None,
                "error": None,
            }
            return Response(payload, status=status.HTTP_200_OK)

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
            
            if(not isSuperuser):
                logger.warning(f'{userName}: do not have permission to check remote connection')
                payload = {  
                    "status":False,
                    "message":"You don't have permission to check remote connection",
                    "data": None,
                    "error": "You don't have permission to check remote connection",                
                }
                return Response(payload, status=status.HTTP_403_FORBIDDEN)
            
            logger.info(f"Permission granted for {userName} to check remote connection.") 
        
        remoteHost = data.get('remote_host',None)
        remoteUser = data.get('remote_user',None)
        remotePort = data.get('remote_port',None)
        remotePassword = data.get('remote_password',None)
        remoteBackupPath = data.get('backup_path',None)
        
        if not (remoteBackupPath and remoteHost and remotePort and remoteUser and remotePassword):
            logger.error("Cannot check disk space without remote credentials.")
            logger.warning("Provide remote credentials and backup path to verify the remote connection.")
            payload = {
                "status": False,
                "message": "Provide remote credentials and backup path to verify the remote connection.",
                "data": None,
                "error": "Failed to check disk usage and remote connection."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
        if sshclient:
            statCode, response = LocalAndRemoteBackupDetails(True, remoteHost, remoteUser, remotePassword, remoteBackupPath)
            if statCode:
                payload = {
                    "status": True,
                    "message": "Remote Connection Successfull.",
                    "data": response,
                    "error": None
                }
                return Response(response, status=status.HTTP_200_OK)
            else:
                # payload = {
                #     "status": False,
                #     "message": "Remote Connection Failed.",
                #     "data": response,
                #     "error": "Remote Connection Failed."
                # }
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        else:
            logger.debug("Remote client connection failed.")
            payload = {
                "status": False,
                "message": "Remote client connection failed.",
                "data": None,
                "error": "Invalid credentials or host not ready"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)    
        
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
        
        statCode, response = LocalAndRemoteBackupDetails()
        if statCode:
            return Response(response, status=status.HTTP_200_OK)
        else:
            return Response(response, status=status.HTTP_400_BAD_REQUEST)
        
        
#Deletion of data
class ScyllaTruncate(APIView):
    def get(self, request):
        
        params = request.query_params.dict()
        scyllaHost = params.get('scylla_host',None)
        scyllaPort = params.get('scylla_port',None)
        scyllaPassword = params.get('scylla_password',None)
        scyllaUser = params.get('scylla_user',None)
        
        if not (scyllaHost and scyllaPort and scyllaUser and scyllaPassword):
            payload = {
                "status": False,
                "message": "Please provide credentials to check availability of data.",
                "data": None,
                "error": "Credentials not provided."
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)
        
        try:
            cluster = Cluster(contact_points=[scyllaHost],port=int(scyllaPort))
            session = cluster.connect()
        except Exception as e:
            print(e)
            payload = {
                "status": False,
                "message": "Unable to connect to ScyllaDb.",
                "data": None,
                "error": "Connection failed."
            }
            return Response(payload, status=status.HTTP_408_REQUEST_TIMEOUT)
        
        query_keyspaces = "SELECT keyspace_name FROM system_schema.keyspaces;"
        keyspaces = [row.keyspace_name for row in session.execute(query_keyspaces) if row.keyspace_name not in ['system', 'system_schema', 'system_auth', 'system_distributed', 'system_traces']]

        availableData = AvailableData(session, keyspaces)
        if availableData != []:
            payload = {
                "status":True,
                "message":"Available date range data in cluster",
                "data":availableData,
                "error":None
            }
            return Response(payload, status=status.HTTP_200_OK)
        else:
            payload = {
                "status":False,
                "message":"Failed to fetch available date range data",
                "data":availableData,
                "error":None
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)

    def post(self, request):
        
        params = request.query_params.dict()
        scyllaHost = params.get('scylla_host',None)
        scyllaPort = params.get('scylla_port',None)
        scyllaPassword = params.get('scylla_password',None)
        scyllaUser = params.get('scylla_user',None)
        
        if not (scyllaHost and scyllaPort and scyllaUser and scyllaPassword):
            payload = {
                "status": False,
                "message": "Please provide credentials to proceed with deletion of data.",
                "data": None,
                "error": "Credentials not provided."
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)
        
        try:
            cluster = Cluster(contact_points=[scyllaHost],port=int(scyllaPort))
            session = cluster.connect()
        except Exception as e:
            print(e)
            payload = {
                "status": False,
                "message": "Unable to connect to ScyllaDb.",
                "data": None,
                "error": "Connection failed."
            }
            return Response(payload, status=status.HTTP_408_REQUEST_TIMEOUT)
        
        
        query_keyspaces = "SELECT keyspace_name FROM system_schema.keyspaces;"
        keyspaces = [row.keyspace_name for row in session.execute(query_keyspaces) if row.keyspace_name not in ['system', 'system_schema', 'system_auth', 'system_distributed', 'system_traces']]
        for keyspace in keyspaces:
            # Get all tables in the keyspace
            query_tables = f"SELECT table_name FROM system_schema.tables WHERE keyspace_name = '{keyspace}';"
            tables = [row.table_name for row in session.execute(query_tables)]
            
            for table in tables:
                # Execute the TRUNCATE command for each table
                truncate_query = f"TRUNCATE {keyspace}.{table};"
                session.execute(truncate_query)
                print(f"Truncated table: {keyspace}.{table}")

class DeleteScyllaData(APIView):
    @swagger_auto_schema(
        operation_description="""Complete Deletion of Scylla Db using POST request.
            1. This API endpoint allows you to delete complete Scylla Db server.
            2. Valid Scylla Db credentials is required to initiate complete deletion. 
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
        
        if(not isSuperuser):
            logger.warning(f'{userName}: do not have permission to proceed with deletion')
            payload = {  
                "status":False,
                "message":"You don't have permission to proceed with deletion",
                "data": None,
                "error": "You don't have permission to proceed with deletion",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to proceed with deletion.") 
        
        data = request.data
        scyllaHost = data.get('scylla_host', None)
        scyllaPort = data.get('scylla_port', None)
        scyllaUser = data.get('scylla_user',None)
        scyllaPassword = data.get('scylla_password',None)
        
        if (scyllaHost==None or scyllaPort==None):
            payload = {
                "status":False,
                "message":"Credentials not provided for complete deletion of scyllaDb",
                "data":None,
                "error":"Mandatory fields not provided."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
            
        process = DeleteUserKeyspaces(scyllaHost, scyllaPort, scyllaUser, scyllaPassword)
        if process:
            logger.info("Complete deletion executed successfully for ScyllaDb.")
            payload = {
                "status": True,
                "message": "Complete deletion executed successfully for ScyllaDb.",
                "data": None,
                "error": None
            }
            return Response(payload, status=status.HTTP_200_OK)
        else:
            logger.error("Complete deletion failed for ScyllaDb")
            payload = {
                "status": False,
                "message": "Complete deletion failed for ScyllaDb.",
                "data": None,
                "error": None
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
        
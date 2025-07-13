import os
import re
import datetime
import threading
from .utils import *
from Postgresdb.models import *
from rest_framework import status
from Postgresdb.serializer import *
from rest_framework.views import APIView
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema


class ElasticSearchVersion(APIView):
    @swagger_auto_schema(
        operation_description="""Get the version of ElasticSearch using GET request.
            1. This API endpoint allows you to get the version of ElasticSearch.
            Note: This API requires systemadmin to check version.
        """,
        operation_summary='Get ElasticSearch Version',
    )
    def get(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        
        if(not isSuperuser):
            logger.warning(f'{userName}: do not have permission to check elasticsearch version')
            payload = {  
                "status":False,
                "message":"You don't have permission to check elasticsearch version",
                "data": None,
                "error": "You don't have permission to check elasticsearch version",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to check elasticsearch version.") 
        
        params = request.query_params.dict()
        elasticUrl = params.get('elastic_url',None)
        elasticUsername = params.get('elastic_user',None)
        elasticPassword = params.get('elastic_password',None)
        
        if (elasticUrl==None or elasticUsername==None or elasticPassword==None):
            logger.error("Mandatory fields not provided")
            logger.warning("Elastic credentials not provided to fetch elasticsearch version.")
            payload = {
                "status":False,
                "message":"Elastic credentials is required.",
                "data":None,
                "error":"Mandatory fields not provided."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        version = ElasticVersion(elasticUrl, elasticUsername, elasticPassword)
        if version:
            logger.info("elasticsearch version fetched successfully.")
            payload = {
                "status":True,
                "message":"ElasticSearch Version fetched successfully.",
                "data":version,
                "error":None,
            }
            return Response(payload, status=status.HTTP_200_OK)
        else:
            logger.error("Error in fetching elastic version.")
            payload = {
                "status":False,
                "message":"Error in fetching elastic version.",
                "data":None,
                "error":"Failed to fetch version."
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)

class BuildElasticConnection(APIView):
    @swagger_auto_schema(
        operation_description="""Check ElasticSearch is active or dead using GET request.
            1. This API endpoint allows you to check ElasticSearch connection is active or dead.
            Note: This API requires systemadmin to check connection is active or dead.
        """,
        operation_summary='Check ElasticSearch Connection',
    )
    def get(self, request):
        # apiData = UserAuthenticationFromUserManagement(request)
            
        # if isinstance(apiData, Response):
        #     return apiData
        
        # isSuperuser = apiData['data'][0]['is_superuser']
        # userName = apiData['data'][0]['username']
        
        # if(not isSuperuser):
        #     logger.warning(f'{userName}: do not have permission to check elasticsearch connection')
        #     payload = {  
        #         "status":False,
        #         "message":"You don't have permission to check elasticsearch connection",
        #         "data": None,
        #         "error": "You don't have permission to check elasticsearch connection",                
        #     }
        #     return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        # logger.info(f"Permission granted for {userName} to check elasticsearch connection.") 
        
        params = request.query_params.dict()
        elasticUrl = params.get('elastic_url',None)
        elasticUsername = params.get('elastic_user',None)
        elasticPassword = params.get('elastic_password',None)
        
        if (elasticUrl==None or elasticUsername==None or elasticPassword==None):
            logger.error("Mandatory fields not provided")
            payload = {
                "status":False,
                "message":"Please Provide Elastic credentials.",
                "data":None,
                "error":"Mandatory fields not provided."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        if (ConnectToElasticsearch(elasticUrl, elasticUsername, elasticPassword)):
            logger.info("Elastic connection is active.")
            payload = {
                "status":True,
                "message":"Connected to Elastic Search succesfully.",
                "data":None,
                "error":None
            }
            return Response(payload, status=status.HTTP_200_OK)
        else:
            logger.error("Elastic connection is down.")
            payload = {
                "status":False,
                "message":"Error connecting to Elastic Search. Please check the credentials.",
                "data":None,
                "error":"Error connecting to Elastic Search. Please check the credentials."
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
class ViewIndexes(APIView):
    @swagger_auto_schema(
        operation_description="""Get list of existing indexes by providing valid credentials in query parameters using GET request.
            This API endpoint allows you to retrieve indexes with certain scenarious.
            1. Provide valid elasticsearch credentials to fetch indexes list and size.
            2. Provide virtual machine credentials where elasticsearch is installed to check storage usage.
            Note: This API requires systemadmin to view indexes list.
        """,
        operation_summary='View List Of Indexes',
    )
    def get(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        
        if (not isSuperuser):
            logger.warning(f'{userName}: do not have permission to fetch indexes')
            payload = {  
                "status":False,
                "message":"You don't have permission to fetch indexes",
                "data": None,
                "error": "You don't have permission to fetch indexes",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to fetch indexes.")
        
        params = request.query_params.dict()
        elasticUrl = params.get('elastic_url',None)
        elasticUsername = params.get('elastic_user',None)
        elasticPassword = params.get('elastic_password',None)
        
        if (elasticUrl==None or elasticUsername==None or elasticPassword==None):
            logger.warning("Mandatory fields not provided")
            payload = {
                "status":False,
                "message":"Please Provide Elastic credentials.",
                "data":None,
                "error":"Mandatory fields not provided."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        es = ConnectToElasticsearch(elasticUrl, elasticUsername, elasticPassword)
        if es:
            IndexList = IndexListAndSize(es)
            indexSize = GetSizeOfIndex(es)
            if indexSize or indexSize:    
                logger.info("Listing indexes in cluster")
                payload = {
                    "status":True,
                    "message":"Indexes fetched successfully",
                    "data":IndexList,
                    "total_size":indexSize,
                    "error":None,
                }
                return Response(payload, status=status.HTTP_200_OK)
            else:
                logger.error("Error in fetching indexes.")
                payload = {
                    "status":False,
                    "message":"Error in fetching indexes.",
                    "data":None,
                    "error":"Error in fetching indexes."
                }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        else:
            logger.error("Error connecting to Elastic Search. Please check the credentials.")
            payload = {
                "status":False,
                "message":"Error connecting to Elastic Search. Please check the credentials.",
                "data":None,
                "error":"Error connecting to Elastic Search. Please check the credentials."
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        

class BackupIndexes(APIView):
    @swagger_auto_schema(
        operation_description="""Start a new backup and save it based on backup type using POST request.
            1. This API endpoint allows you to start backup by providing valid credentials in the request body.
            2. Backup can be initited to remote as well as local server.
            3. Valid elasticsearch credentials is required to start backup for both remote and local server.
            4. Logs can be checked in log table post backup.
            Note: This API requires systemadmin to initiate backup.
        """,
        operation_summary='Start Elasticsearch Backup',
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
        elasticUrl = data.get('elastic_url',None)
        elasticPort = data.get('elastic_vm_port',None)
        elasticUsername = data.get('elastic_user',None)
        elasticPassword = data.get('elastic_password',None)
        elasticVmUser = data.get('elastic_vm_user',None)
        elasticVmPassword = data.get('elastic_vm_password',None)
        
        fileName = data.get('file_name',None)
        indexName = data.get("index_name",None)
        backupPath = data.get("backup_path",None)
        repoName = data.get("repo_name",None)

        isRemote = data.get("remote",False)
        remoteHost = data.get("remote_host",None)
        remoteUser = data.get("remote_user",None)
        remotePort = data.get("remote_port",None)
        remotePassword = data.get("remote_password",None)
        
        if (elasticUrl==None or elasticVmUser==None or elasticVmPassword==None):
            logger.warning("Mandatory fields not provided")
            logger.error("Elastic credentials not provided to proceed with backup.")
            return Response({
                "status":False,
                "message":"Elastic credentials is required.",
                "data":None,
                "error":"Mandatory fields not provided."
            },status=status.HTTP_406_NOT_ACCEPTABLE)
        
        if(elasticVmUser==None or elasticVmPassword==None or elasticPort==None):
            logger.warning("Mandatory fields not provided")
            logger.error("Elastic vm credentials not provided.")
            payload = {
                "status":False,
                "message":"Please provide Elastic vm credentials.",
                "data":None,
                "error":"Mandatory fields not provided"
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
        
        if isRemote:
            if not (backupPath and remoteHost and remotePort and remoteUser and remotePassword):
                logger.error("Backup won't proceed without remote credentials.")
                payload = {
                    "status": False,
                    "message": "Please provide remote credentials with backup path to proceed with backup.",
                    "data": None,
                    "error": "Backup won't proceed without remote credentials."
                }
                return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
            else:
                sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
                if sshclient:
                    es = (ConnectToElasticsearch(elasticUrl, elasticUsername, elasticPassword))
                    if es:
                        try:
                            indexSize=GetSizeOfIndex(es)
                            remoteSpace = CheckRemoteDiskSpace(sshclient, backupPath)
                            
                            indexSize = ConvertToBytesB(indexSize)
                            if isinstance(remoteSpace, str):
                                remoteSpace = ConvertToBytes(remoteSpace)
                            
                            if remoteSpace < indexSize:
                                logger.error("Not enough space on the remote host for backup.")
                                payload = {
                                    "status": False,
                                    "message": "Not enough space on the remote host for backup.",
                                    "required_space": FormatSize(indexSize),
                                    "available_space": FormatSize(remoteSpace),
                                    "error": None
                                }
                                return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
                        except Exception as e:
                            logger.error("Remote backup failed due to an error.")
                            payload = {
                                "status": False,
                                "message": "Remote backup failed due to an error.",
                                "data": None,
                                "error": str(e)
                            }
                            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
                    else:
                        logger.error("Failed to connect ElasticSearch.")
                        payload = {
                            "status": False,
                            "message": "ElasticSearch connection failed.",
                            "data": None,
                            "error": "ElasticSearch connection failed."
                        }
                        return Response(payload, status=status.HTTP_400_BAD_REQUEST)
                else:
                    logger.error("Remote client connection failed.")
                    payload = {
                        "status": False,
                        "message": "Remote client connection failed.",
                        "data": None,
                        "error": None
                    }
                    return Response(payload, status=status.HTTP_404_NOT_FOUND)
        
        def RunBackup(fileName, indexName, elasticUrl, elasticPort, elasticVmUser, elasticVmPassword, repoName, isRemote, remotePort, remoteHost, remoteUser, remotePassword, backupPath):
            fileName = fileName.lower()
            remotebackupDir = None
            timestamp = int(datetime.now().timestamp())
            if isRemote:
                ipAddress = remoteHost
                backupMode = "remote"
                remotebackupDir = f'{backupPath}/{timestamp}_{fileName}'
                path = remotebackupDir
            else:
                ipAddress = config['LOCAL_ELASTICSEARCH_HOST']
                path = os.path.join(config['ELASTICSEARCH_DATA_DIR'], repoName)
                backupMode = "local"
                
            if indexName:
                snapshotName = f'{timestamp}_{fileName}'
                backupType = "partial"
            else:
                snapshotName = f'{timestamp}_{fileName}'
                backupType = "complete"
                
            starttime = datetime.now()
            responseData, value = SaveDataToDb(backupType, backupMode, ipAddress, path, "Scheduled", "Backup scheduled", None, userId)
            Id = value['id']
            
            if not responseData:
                logger.error("Cannot Log to Database")
                return
        
            try:
                responseData = BackupToRemoteLocal(indexName, elasticUrl, elasticPort, elasticUsername, elasticPassword, elasticVmUser, elasticVmPassword, repoName, snapshotName, isRemote, remotePort, remoteHost, remoteUser, remotePassword, backupPath, remotebackupDir)
            except Exception as e:
                logger.error(f"Backup failed due to exception: {e}")
                if (UpdateStatusToDb(Id, "Failed", "Backup Failed")):
                    logger.info("Status Updated.")
                else:
                    logger.error("Failed to update status in database.")
                    return
                
                return
            
            endTime = datetime.now()
            duration = Duration(starttime, endTime)

            if responseData:
                if (UpdateStatusToDb(Id, "Success", "Backup Successful", duration)):
                    logger.info("Backup done.")
                else:
                    logger.error("Failed to update status in database.")
                    return
            else:
                if (UpdateStatusToDb(Id, "Failed", "Backup Failed")):
                    logger.error("Backup failed.")
                else:
                    logger.error("Failed to update status in database.")
                    return
            
        try:
            backupThread = threading.Thread(target=RunBackup, 
                                            args=(fileName, indexName, elasticUrl, elasticPort, elasticVmUser, elasticVmPassword, repoName, isRemote, remotePort, remoteHost, remoteUser, remotePassword, backupPath),
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
            logger.error(f"Failed to start backup thread: {e}")
            payload = {
                "status": False,
                "message": "Failed to start backup thread.",
                "data": None,
                "error": str(e)
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        

class RestoreIndexesFromRemote(APIView):
    @swagger_auto_schema(
        operation_description="""Start restoring for the files which were backuped using POST request.
            1. This API endpoint allows you to copy files from remote path by providing valid credentials.
            3. Valid Elasticsearch credentials is required to restore data for both remote and local server.
            Note: This API requires systemadmin for restoration.
        """,
        operation_summary='Start Data Restore',
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
        backupPath = data.get("backup_path", None)
        remoteHost = data.get("remote_host", None)
        remoteUser = data.get("remote_user", None)
        remotePort = data.get("remote_port", None)
        remotePassword = data.get("remote_password", None)
        
        elasticVmHost = data.get('elastic_vm_host',None)
        elasticPort = data.get('elastic_vm_port',None)
        elasticVmUser = data.get('elastic_vm_user',None)
        elasticVmPassword = data.get('elastic_vm_password',None)
        
        logDbHost = data.get("restore_postgres_host",None)
        logDbPort = data.get("restore_postgres_port",None)
        logDbUser = data.get("restore_postgres_user",None)
        logDbPassword = data.get("restore_postgres_password",None)
        logDbName = config["POSTGRESQL_RESTORE_LOG_DATABASE_NAME"]
        logTableName = config["POSTGRESQL_RESTORE_LOG_TABLE_NAME"]
        
        if(elasticVmHost==None or elasticVmUser==None or elasticVmPassword==None or elasticPort==None):
            logger.warning("Mandatory fields not provided")
            logger.error("Elastic vm credentials not provided.")
            payload = {
                "status":False,
                "message":"Please provide Elastic vm credentials.",
                "data":None,
                "error":"Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        if not (backupPath and remoteHost and remotePort and remoteUser and remotePassword):
            logger.error("Restore won't proceed without remote credentials.")
            payload = {
                "status": False,
                "message": "Please provide remote credentials with backup path to proceed with backup.",
                "data": None,
                "error": "Restore won't proceed without remote credentials."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        else:
            # sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
            # if sshclient:
            #     response = CopySnapshotFromRemote(remoteHost, remotePort, remoteUser, remotePassword, backupPath, elasticVmHost, elasticPort, elasticVmUser, elasticVmPassword)
            #     if response:
            #         payload = {
            #             "status": True,
            #             "message": 'Copied Snapshot files to elastic path.',
            #             "path":backupPath,
            #             "error": None
            #         }
            #         return Response(payload,status=status.HTTP_200_OK)
            #     else:
            #         payload = {
            #             "status": False,
            #             "message": 'Restore failed.',
            #             "data": None,
            #             "path": backupPath,
            #             "error": "Error restoring snapshot files."
            #         }
            #         return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            # else:
            #     payload = {
            #         "status": False,
            #         "message": "Remote client connection failed.",
            #         "data": None,
            #         "error": None
            #     }
            #     return Response(payload, status=status.HTTP_404_NOT_FOUND)

            def RunElasticSnapshotCopy(remoteHost, remotePort, remoteUser, remotePassword, backupPath,elasticVmHost, elasticPort, elasticVmUser, elasticVmPassword,logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName):
                startTime = datetime.now()
                mode = "remote"
                ipAddress = remoteHost
                path = backupPath
                backupType = "complete"

                # success, restoreId = InsertRestoreLogToPostgres(logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName, backupType, mode, ipAddress, path, "Scheduled", None, None)

                # if not success:
                #     logger.error("Failed to log to database.")
                #     return

                try:
                    sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
                    if sshclient:
                        result = CopySnapshotFromRemote(remoteHost, remotePort, remoteUser, remotePassword,backupPath, elasticVmHost, elasticPort, elasticVmUser, elasticVmPassword)
                        endTime = datetime.now()
                        duration = Duration(startTime, endTime)

                        if result:
                            logger.info("Copied snapshot to Elasticsearch path.")
                            InsertRestoreLogToPostgres(logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName, backupType, mode, ipAddress, path, "Success", "Snapshot copied to Elasticsearch path", duration, None)
                        else:
                            logger.error("Snapshot copy failed.")
                            InsertRestoreLogToPostgres(logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName, backupType, mode, ipAddress, path, "Failed", "Snapshot copy failed", None, None)
                    else:
                        raise Exception("SSH client connection failed.")
                except Exception as e:
                    logger.error(f"Exception in snapshot copy: {e}")
                    InsertRestoreLogToPostgres(logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName, backupType, mode, ipAddress, path, "Failed", str(e), None, None)

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

            thread = threading.Thread(target=RunElasticSnapshotCopy,
                                args=(remoteHost, remotePort, remoteUser, remotePassword, backupPath,elasticVmHost, elasticPort, elasticVmUser, elasticVmPassword,logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName),
                                daemon=True
            )
            thread.start()

            payload = {
                "status": True,
                "message": "Snapshot copy process started in background.",
                "data": None,
                "error": None
            }
            return Response(payload, status=status.HTTP_202_ACCEPTED)


class RegisterSnapshotRepository(APIView):
    @swagger_auto_schema(
        operation_description="""View available snapshots using GET request.
            1. This API endpoint allows you to fetch available snapshots.
            2. Restore can be initited from remote as well as local server.
            Note: This API requires systemadmin for registering snapshot.
        """,
        operation_summary='View Snapshots',
    ) 
    def get(self, request):
        # apiData = UserAuthenticationFromUserManagement(request)
            
        # if isinstance(apiData, Response):
        #     return apiData
        
        # isSuperuser = apiData['data'][0]['is_superuser']
        # userName = apiData['data'][0]['username']
        
        # if (not isSuperuser):
        #     logger.warning(f'{userName}: do not have permission to view available snapshots')
        #     payload = {  
        #         "status":False,
        #         "message":"You don't have permission to view available snapshots",
        #         "data": None,
        #         "error": "You don't have permission to view available snapshots",                
        #     }
        #     return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        # logger.info(f"Permission granted for {userName} to view available snapshots.")
        
        params = request.query_params.dict()
        elasticUrl = params.get('elastic_url',None)
        elasticUsername = params.get('elastic_user',None)
        elasticPassword = params.get('elastic_password',None)
        repositoryName = params.get("repository_name", None)
        snapshotName = params.get('snapshot_name',None)
        
        if(elasticUrl==None or elasticUsername==None or elasticPassword==None):
            logger.warning("Mandatory fields not provided")
            payload = {
                "status":False,
                "message":"Please provide mandatory fields",
                "data":None,
                "error":"Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        availableSnaps= ListAvailableSnapshots(elasticUrl, repositoryName, snapshotName, elasticUsername, elasticPassword)
        if availableSnaps:
            logger.info("List of available snapshots.")
            payload = {
                "status": True,
                "message": 'List of available snapshots.',
                "data": availableSnaps,
                "error": None
            }
            return Response(payload, status=status.HTTP_200_OK)
        else:
            payload = {
                "status": False,
                "message": 'Error Listing snapshots.',
                "data": availableSnaps,
                "error": "Error occurred."
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_description="""Start registerng snaphot regitstory using POST request.
            1. This API endpoint allows you to register snaphot for restoration by providing valid credentials and snapshot id in the request body.
            2. Restore can be initited from remote as well as local server.
            Note: This API requires systemadmin for restoration.
        """,
        operation_summary='Register Snaphshot',
    )
    def post(self, request):
        # apiData = UserAuthenticationFromUserManagement(request)
            
        # if isinstance(apiData, Response):
        #     return apiData
        
        # isSuperuser = apiData['data'][0]['is_superuser']
        # userName = apiData['data'][0]['username']
        
        # if (not isSuperuser):
        #     logger.warning(f'{userName}: do not have permission to register repository')
        #     payload = {  
        #         "status":False,
        #         "message":"You don't have permission to register repository",
        #         "data": None,
        #         "error": "You don't have permission to register repository",                
        #     }
        #     return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        # logger.info(f"Permission granted for {userName} to register repository.")
        
        data = request.data 
        repositoryName = data.get("repository_name", None)
        elasticUrl = data.get('elastic_url',None)
        elasticUserName = data.get('elastic_user',None)
        elasticPassword = data.get('elastic_password',None)
        
        if(elasticUrl==None or repositoryName==None or elasticUserName==None or elasticPassword==None):
            logger.warning("Mandatory fields not provided")
            payload = {
                "status":False,
                "message":"Please provide mandatory fields",
                "data":None,
                "error":"Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        resCode = RegisterSnapshotDirectory(elasticUrl, repositoryName, elasticUserName, elasticPassword)
        if resCode == 200:
            logger.info("Repository registerd for restoration.")    
            payload = {
                "status":True,
                "message":"Repository registerd for restoration.",
                "data": None,
                "error":None
            }
            return Response(payload, status=status.HTTP_200_OK)
        else:
            logger.error("Snapshot registry failed.")
            payload = {
                "status": False,
                "message": "Snapshot registry failed.",
                "data": None,
                "error": "Snapshot registry failed."
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)

class RestoreSnapshots(APIView):
    @swagger_auto_schema(
        operation_description="""Start restoring indexes using POST request.
            1. This API endpoint allows you to start restoration by providing valid credentials and snapshot id in the request body.
            2. Restore can be initited from remote as well as local server.
            3. Valid Elasticsearch credentials is required to restore backuped data for both remote and local server.
            Note: This API requires systemadmin for restoration.
        """,
        operation_summary='Start Index Restore',
    )
    def post(self, request):
        # apiData = UserAuthenticationFromUserManagement(request)
            
        # if isinstance(apiData, Response):
        #     return apiData
        
        # isSuperuser = apiData['data'][0]['is_superuser']
        # userName = apiData['data'][0]['username']
        
        # if (not  isSuperuser):
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

        elasticUrl = data.get('elastic_url',None)
        elasticUsername = data.get('elastic_user',None)
        elasticPassword = data.get('elastic_password',None)
        elasticUrl = data.get('elastic_url',None)
        indexName = data.get("index_name",None)
        repoName = data.get("repo_name",None)
        snapshotName = data.get("snapshot_name",None)
        
        logDbHost = data.get("restore_postgres_host",None)
        logDbPort = data.get("restore_postgres_port",None)
        logDbUser = data.get("restore_postgres_user",None)
        logDbPassword = data.get("restore_postgres_password",None)
        logDbName = config["POSTGRESQL_RESTORE_LOG_DATABASE_NAME"]
        logTableName = config["POSTGRESQL_RESTORE_LOG_TABLE_NAME"]
        
        if(elasticUrl==None or repoName==None or snapshotName==None or elasticUsername==None or elasticPassword==None):
            logger.warning("Mandatory fields not provided")
            payload = {
                "status":False,
                "message":"Please provide mandatory fields",
                "data":None,
                "error":"Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        # responseData = RestoreSnapshotsFromElasticPath(indexName, elasticUrl, repoName, snapshotName, elasticUsername, elasticPassword)
        # if responseData:
        #     logger.info("Restore Done.")
        #     payload = {
        #         "status": True,
        #         "message": "Restore Done.",
        #         "error": None
        #     }
        #     return Response(payload, status=status.HTTP_200_OK)
        # else:
        #     logger.error("Restore failed.")
        #     payload = {
        #         "status": False,
        #         "message": "Restore failed.",
        #         "error": None
        #     }
        #     return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
        def RunElasticSnapshotRestore(indexName, elasticUrl, repoName, snapshotName,elasticUsername, elasticPassword,logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName):
            startTime = datetime.now()
            mode = "local"
            backupType = "partial" if indexName else "remote"
            ipAddress = elasticUrl
            path = f"{repoName}/{snapshotName}"

            # success, restoreId = InsertRestoreLogToPostgres(logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName, backupType, mode, ipAddress, path, "Scheduled", None, None)

            # if not success:
            #     logger.error("Failed to log index restore start.")
            #     return

            try:
                result = RestoreSnapshotsFromElasticPath(indexName, elasticUrl, repoName, snapshotName, elasticUsername, elasticPassword)
                endTime = datetime.now()
                duration = Duration(startTime, endTime)

                if result:
                    logger.info("Index restore successful.")
                    InsertRestoreLogToPostgres(logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName, backupType, mode, ipAddress, path, "Success", "Index restored from snapshot", duration, None)
                else:
                    logger.error("Index restore failed.")
                    InsertRestoreLogToPostgres(logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName, backupType, mode, ipAddress, path, "Failed", "Index restore failed", None, None)
            except Exception as e:
                logger.error(f"Exception during index restore: {e}")
                InsertRestoreLogToPostgres(logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName, backupType, mode, ipAddress, path, "Failed", str(e), None, None)

        thread = threading.Thread(target=RunElasticSnapshotRestore,
                                args=(indexName, elasticUrl, repoName, snapshotName, elasticUsername, elasticPassword,logDbHost, logDbPort, logDbUser, logDbPassword, logDbName, logTableName),
                                daemon=True
        )
        thread.start()

        paylaod = {
            "status": True,
            "message": "Index restore started in background.",
            "data": None,
            "error": None
        }
        return Response(paylaod, status=status.HTTP_202_ACCEPTED)
        
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
        backupPath = data.get('backup_path',None)
        
        sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
        if sshclient:
            response = GetDiskUsageRemote(remoteUser, remotePassword, remoteHost, backupPath)
            if response:
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
                "error": None
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
        
        if (not isSuperuser):
            logger.warning(f'{userName}: do not have permission to check backup details')
            payload = {  
                "status":False,
                "message":"You don't have permission to check backup details",
                "data": None,
                "error": "You don't have permission to check backup details",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to check backup details.")
        
        statcode, response = LocalBackupDetails()
        return Response(response, status=status.HTTP_200_OK)
        

#Deletion
class DeleteElasticData(APIView):
    @swagger_auto_schema(
        operation_description="""Complete Deletion of Elasticsearch using POST request.
            1. This API endpoint allows you to delete complete Elasticsearch Indexes.
            2. Valid Elasticsearch credentials is required to initiate complete deletion. 
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
        
        data = request.data
        elasticUrl = data.get('elastic_url',None)
        elasticUsername = data.get('elastic_user',None)
        elasticPassword = data.get('elastic_password',None)
        
        if not isSuperuser:
            logger.warning(f'{userName}: do not have permission to proceed with deletion')
            payload = {  
                "status":False,
                "message":"You don't have permission to proceed with deletion",
                "data": None,
                "error": "You don't have permission to proceed with deletion",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)

        logger.info(f"Permission granted for {userName} to proceed with deletion.")
        
        es = (ConnectToElasticsearch(elasticUrl, elasticUsername, elasticPassword))
        if not (es): #BUG ID 1300: Deletion;Invalid Credentials
            payload = {
                "status":False,
                "message":"Please provide valid credentials",
                "data":None,
                "error":"Connecting to Elastic Search failed."
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
        processStatus = DeleteUserIndices(es)
        if processStatus:
            logger.info("Complete deletion executed successfully for Elasticsearch")
            payload = {
                "status": True,
                "message": "Complete deletion executed successfully for Elasticsearch",
                "data":None,
                "error": None
            }
            return Response(payload, status=status.HTTP_200_OK)
        else:
            logger.error("Complete deletion failed for Elasticsearch")
            payload = {
                "status": False,
                "message": "Complete deletion failed for Elasticsearch",
                "data":None,
                "error": None
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
    
    
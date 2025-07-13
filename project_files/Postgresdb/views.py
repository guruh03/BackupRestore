import os
import datetime
import psycopg2
from .utils import *
import threading
from .models import *
from .serializer import *
from django.db.models import Q
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.paginator import Paginator
from drf_yasg.utils import swagger_auto_schema


class FetchPostgresVersion(APIView):
    @swagger_auto_schema(
        operation_description="""Get Postgres version using GET request.
            1. This API endpoint allows you to get Postgres version.
            2. Provide valid postgres credentials in query parameters to get version.
        """,
        operation_summary='Get Postgres Version',
    )
    def get(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
        
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        
        if(not isSuperuser):
            logger.warning(f'{userName}: do not have permission to check postgres version')
            payload = {  
                "status": False,
                "message":"You don't have permission to check postgres version",
                "data": None,
                "error": "You don't have permission to check postgres version",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to check postgres version.") 
        
        params = request.query_params.dict()
        postgresHost = params.get("postgres_host",None)
        postgresPort = params.get("postgres_port",None)
        postgresUser = params.get("postgres_user",None)
        postgresPassword = params.get("postgres_password",None)
        
        version = PostgresVersion(postgresUser, postgresPassword, postgresHost, postgresPort)
        if version:
            payload = {
                "status": True,
                "message": "Postgres version fetched successfully.",
                "data": version,
                "error": None
            }
            return Response(payload, status=status.HTTP_200_OK)
        else:
            payload = {
                "status": False,
                "message": "Failed to fetch Postgres version.",
                "data": None,
                "error": "Error fetching Postgres version."
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        

class BuildPostgresConnection(APIView):
    @swagger_auto_schema(
        operation_description="""Check Postgres is active or dead using GET request.
            1. This API endpoint allows you to check Postgres connection is active or dead.
            Note: This API requires systemadmin to check connection is active or dead.
        """,
        operation_summary='Check Postgres Connection',
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
        postgresHost = params.get("postgres_host",None)
        postgresPort = params.get("postgres_port",None)
        postgresUser = params.get("postgres_user",None)
        postgresPassword = params.get("postgres_password",None)
        
        if(postgresHost==None or postgresPort==None or postgresUser==None or postgresPassword==None):
            logger.warning("Mandatory fields not provided")
            logger.error("Postgres credentials not provided to check connection.")
            payload = {
                "status":False,
                "message":"Please provide postgres credentials.",
                "data":None,
                "error":"Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        response, conn = ConnectToDb(postgresUser, postgresPassword, postgresHost, postgresPort)
        if (not response):
            return Response(conn, status=status.HTTP_400_BAD_REQUEST)
        else:        
            logger.info("Postgres is up and running.")
            payload = {
                "status":True,
                "message":"Connected to Postgres successfully.",
                "data":None,
                "error":None
            }
            return Response(payload, status=status.HTTP_200_OK)
        
class FetchDatabases(APIView):
    @swagger_auto_schema(
        operation_description="""Get list of existing databases by providing valid credentials in query parameters using GET request.
            This API endpoint allows you to retrieve databases with certain scenarious.
            1. Provide valid postgres credentials to fetch databases list and size.
            2. Provide virtual machine credentials where postgresql is installed to check storage usage.
            Note: This API requires systemadmin to view databases list.
        """,
        operation_summary='View List Of Databases',
    )
    def get(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        
        if(not isSuperuser):
            logger.warning(f'{userName}: do not have permission to fetch databases lists')
            payload = {  
                "status":False,
                "message":"You don't have permission to fetch databases lists",
                "data": None,
                "error": "You don't have permission to fetch databases lists",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to fetch databases lists.") 
        
        params = request.query_params.dict()
        postgresHost = params.get("postgres_host",None)
        postgresPort = params.get("postgres_port",None)
        postgresUser = params.get("postgres_user",None)
        postgresPassword = params.get("postgres_password",None)
        
        if(postgresHost==None or postgresPort==None or postgresUser==None or postgresPassword==None):
            logger.warning("Mandatory fields not provided")
            logger.error("Postgres credentials not provided to fetch databases lists.")
            payload = {
                "status":False,
                "message":"Please provide postgres credentials to fetch databases lists",
                "data":None,
                "error":"Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        response, conn = ConnectToDb(postgresUser, postgresPassword, postgresHost, postgresPort)
        if (not response):
            return Response(conn, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            cur = conn.cursor()
            
            # Fetch databases
            cur.execute("""SELECT datname, pg_database_size(datname) AS size_in_bytes 
                        FROM pg_database 
                        WHERE datistemplate = false AND datname != 'postgres';
                        """)
            databases = cur.fetchall()
            cur.execute("""
                SELECT SUM(pg_database_size(datname)) AS total_size_in_bytes
                FROM pg_database
                WHERE datistemplate = false;
            """)
            total_size = cur.fetchone()[0]
            
            cur.close()
            conn.close()
            
            result = []
            for db in databases:
                database_name = db[0]
                size_in_bytes = db[1]
                estimated_size = FormatSize(size_in_bytes)  # Convert size to human-readable format

                result.append({
                    "database_name": database_name,
                    "estimated_size": estimated_size
                })
            totalSize = FormatSize(int(total_size))

            logger.info("Viewing list of databases.")
            payload = {
                "status":True,
                "message":"Databases fetched successfully.",
                "data":result,
                "total_size":totalSize,
                "error":None,
            }
            return Response(payload, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error listing databases: {str(e)}")
            payload = {
                "status":False,
                "message":"Error listing databases",
                "data":None,
                "total_size":None,
                "error":str(e)
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
class PostgresBackup(APIView):
    @swagger_auto_schema(
        operation_description="""Start a new backup and save it based on backup type using POST request.
            1. This API endpoint allows you to start backup by providing valid credentials in the request body.
            2. Backup can be initited to remote as well as local server.
            3. Valid postgresql credentials is required to start backup for both remote and local server.
            4. Logs can be checked in log table post backup.
            Note: This API requires systemadmin to initiate backup.
        """,
        operation_summary='Start Database Backup',
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
        
        postgresHost = data.get("postgres_host",None)
        postgresPort = data.get("postgres_port",None)
        postgresUser = data.get("postgres_user",None)
        postgresPassword = data.get("postgres_password",None)
        
        backupPath = data.get("backup_path",None)
        backupType = data.get("backup_type",None)
        fileName = data.get("file_name",None)
        dbName = data.get("database_name",None)
        source = data.get("source",None)
        startTime = data.get('start_time',None)
        endTime = data.get('end_time',None)
        
        remoteHost = data.get('remote_host',None)
        remoteUser = data.get('remote_user',None)
        remotePort = data.get('remote_port',None)
        remotePassword = data.get('remote_password',None)
        isRemote = data.get('remote',None)
        
        localPath = f"{config['LOCAL_TEMP_DIR']}/{int(datetime.now().timestamp())}_{fileName}"
        
        if any(param is None or not param for param in (postgresHost, postgresPort, postgresUser, postgresPassword)):
            logger.info("Please provide postgres credentials to proceed with backup.")
            logger.warning("Backup won't proceed without postgres credentials.")
            payload = {
                "status": False,
                "message": "Please provide postgres credentials to proceed with backup.",
                "data": None,
                "error": "Backup won't proceed without postgres credentials."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)

        if (not fileName or fileName==None):
            logger.error("File name not provided to proceed with backup.")
            payload = {
                "status": False,
                "message": "File name not provided.",
                "data":None,
                "error": "Mandatory fields not provided"
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
        
        if isRemote:
            if not (backupPath and remoteHost and remotePort and remoteUser and remotePassword):
                logger.info("Please provide remote credentials with backup path to proceed with backup.")
                logger.warning("Backup won't proceed without remote credentials.")
                payload = {
                    "status": False,
                    "message": "Please provide remote credentials with backup path to proceed with backup.",
                    "data": None,
                    "error": "Backup won't proceed without remote credentials."
                }
                return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
            
            # else:
            #     sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
            #     if sshclient:
            #         try:
            #             response, conn = ConnectToDb(postgresUser, postgresPassword, postgresHost, postgresPort)    #BUG ID 1102: Postgres - Backup - wrong host
            #             if (not response):
            #                 return Response(conn, status=status.HTTP_400_BAD_REQUEST)

            #             cur = conn.cursor()
                        
            #             # Fetch databases
            #             cur.execute("SELECT datname, pg_database_size(datname) AS size_in_bytes FROM pg_database WHERE datistemplate = false;")
            #             databases = cur.fetchall()
            #             cur.execute("""
            #                 SELECT SUM(pg_database_size(datname)) AS total_size_in_bytes
            #                 FROM pg_database
            #                 WHERE datistemplate = false;
            #             """)
            #             total_size = cur.fetchone()[0]
                        
            #             cur.close()
            #             conn.close()
                        
            #             result = []
            #             for db in databases:
            #                 database_name = db[0]
            #                 size_in_bytes = db[1]
            #                 estimated_size = FormatSize(size_in_bytes)  # Convert size to human-readable format

            #                 result.append({
            #                     "database_name": database_name,
            #                     "estimated_size": estimated_size
            #                 })
            #             totalSizeInBytes = FormatSize(int(total_size))
            #             remoteSpace = CheckRemoteDiskSpace(sshclient, backupPath)
                        
            #             if isinstance(totalSizeInBytes, str):
            #                 totalSizeInBytes = ConvertToBytesB(totalSizeInBytes)
            #             if isinstance(remoteSpace, str):
            #                 remoteSpace = ConvertToBytes(remoteSpace)
                            
            #             if remoteSpace > totalSizeInBytes:
            #                 logger.info("Not enough space on the remote host for backup.")
            #                 logger.warning("Not enough space on the remote host for backup.")
            #                 payload = {
            #                     "status": False,
            #                     "message": "Not enough space on the remote host for backup.",
            #                     "required_space": FormatSize(totalSizeInBytes),
            #                     "available_space": FormatSize(remoteSpace),
            #                     "error": None
            #                 }
            #                 return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
            #         except Exception as e:
            #             logger.error("Remote backup failed due to an error.")
            #             payload = {
            #                 "status": False,
            #                 "message": "Remote backup failed due to an error.",
            #                 "data": None,
            #                 "error": str(e)
            #             }
            #             return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            #     else:
            #         logger.debug("Remote client connection failed.")
            #         payload = {
            #             "status": False,
            #             "message": "Remote client connection failed.",
            #             "data": None,
            #             "error": None
            #         }
            #         return Response(payload, status=status.HTTP_404_NOT_FOUND)
        
        if backupPath:
            backupPath = f'{backupPath}/{int(datetime.now().timestamp())}_{fileName}'
        
        response, conn = ConnectToDb(postgresUser, postgresPassword, postgresHost, postgresPort)    #BUG ID 1102: Postgres - Backup - wrong host
        if (not response):
            return Response(conn, status=status.HTTP_400_BAD_REQUEST)    
        
        def RunBackup(Id, postgresUser, postgresHost, postgresPort, postgresPassword, backupPath, localPath, isRemote, remoteHost, remoteUser, remotePort, remotePassword, starttime):
            
            if not isRemote:
                localHost = config["LOCAL_POSTGRESQL_HOST"]
                localUserName = config["LOCAL_POSTGRESQL_VM_USER"]
                localPassword = config["LOCAL_POSTGRESQL_VM_PASSWORD"]
                sshclient = CreateSshClient(localHost, 22, localUserName, localPassword)
                dirPath = config['LOCAL_TEMP_DIR']
            
            else:
                sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
                dirPath = os.path.dirname(backupPath)
                
            if sshclient:
                response, conn = ConnectToDb(postgresUser, postgresPassword, postgresHost, postgresPort)
                if (not response):
                    return Response(conn, status=status.HTTP_400_BAD_REQUEST)  
                
                cur = conn.cursor()
                cur.execute("SELECT datname, pg_database_size(datname) AS size_in_bytes FROM pg_database WHERE datistemplate = false;")
                databases = cur.fetchall()
                cur.execute("""
                    SELECT SUM(pg_database_size(datname)) AS total_size_in_bytes
                    FROM pg_database
                    WHERE datistemplate = false;
                """)
                totalSize = cur.fetchone()[0]
                cur.close()
                conn.close()

                result = []
                for db in databases:
                    databaseName = db[0]
                    sizeInBytes = db[1]
                    estimatedSize = FormatSize(sizeInBytes)  # Convert size to human-readable format

                    result.append({
                        "database_name": databaseName,
                        "estimated_size": estimatedSize
                    })
                totalSizeInBytes = FormatSize(int(totalSize))
                space = CheckRemoteDiskSpace(sshclient, dirPath)
                
                if isinstance(totalSizeInBytes, str):
                    totalSizeInBytes = ConvertToBytesB(totalSizeInBytes)
                if isinstance(space, str):
                    space = ConvertToBytes(space)
                    
                if space < totalSizeInBytes:
                    logger.info("Not enough local disk space.")
                    
                    if (UpdateStatusToDb(Id, "Failed", "Not enough local disk space")):
                        logger.info("Status Updated")
                    else:
                        return
            
                dataResponse = ServerDataBackup(postgresUser, postgresHost, postgresPort, postgresPassword, backupPath, localPath, isRemote, remoteHost, remoteUser, remotePassword)
                
                if dataResponse:
                    endTime = datetime.now()
                    duration = Duration(starttime, endTime)
                    if (UpdateStatusToDb(Id, "Success", "Backup Successful", duration)):
                        logger.info("Backup successful.")
                    else:
                        return
                
                else:
                    if (UpdateStatusToDb(Id, "Failed", "Backup Failed")):
                        logger.error("Backup failed.")
                    else:
                        return
                    
            else:
                logger.debug("Local client connection failed.")
                if (UpdateStatusToDb(Id, "Failed", "Local client connection failed")):
                    logger.info("Status Updated")
                else:
                    return
                    
                        
        if backupType.lower() == "server":
            if isRemote:
                starttime = datetime.now()
                ipAddress = remoteHost
                path = backupPath
                backupMode = "remote"
            else:
                starttime = datetime.now()
                ipAddress = config['LOCAL_POSTGRESQL_HOST']
                path = localPath
                backupMode = "local"
            
            responseData, value = SaveDataToDb("complete", backupMode, ipAddress, path, "Scheduled", "Backup scheduled", None, userId)
            Id = value['id']
            
            if not responseData:
                payload = {
                    "status": False,
                    "message": "Cannot Log to Database",
                    "data": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_404_NOT_FOUND)
            
            backupThread = threading.Thread(target=RunBackup,
                                            args=(Id, postgresUser, postgresHost, postgresPort, postgresPassword, backupPath, localPath, isRemote, remoteHost, remoteUser, remotePort, remotePassword, starttime),
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
            
        elif backupType.lower() == "database":
            def RunBackup(Id, backup_func, args, starttiime):
                response, result = backup_func(*args)
                endTime = datetime.now()
                duration = Duration(starttiime, endTime)

                if response:
                    if (UpdateStatusToDb(Id, "Success", "Backup Successful", duration)):
                        logger.info("Backup successful.")
                    else:
                        return
                else:
                    if (UpdateStatusToDb(Id, "Failed", "Backup Failed")):
                        logger.error("Backup failed.")
                    else:
                        return

            def StartBackup(backup_func, args):
                starttime = datetime.now()
                if isRemote:
                    ipAddress = remoteHost
                    path = backupPath
                    backupMode = "remote"
                else:
                    ipAddress = config['LOCAL_POSTGRESQL_HOST']
                    path = localPath
                    backupMode = "local"

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

                backup_thread = threading.Thread(
                    target=RunBackup,
                    args=(Id, backup_func, args, starttime),
                    daemon=True
                )
                backup_thread.start()

                payload = {
                    "status": True,
                    "message": "Backup has been scheduled. Please check log table for more details.",
                    "data": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_200_OK)
            
            if (dbName==None and startTime==None and endTime==None):
                payload = {
                    "status": False,
                    "message": "Please provide database name with startime and endtime.",
                    "data": None,
                    "error": "Mandatory fields not provided."
                }
                return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)    
            
            # if isRemote:
            if(dbName==config['POSTGRESQL_CMM_NAME']):
                args = [startTime, endTime, postgresUser, postgresHost, postgresPort, postgresPassword, dbName, isRemote, backupPath, localPath, remoteHost, remoteUser, remotePassword]
                return StartBackup(BackupCaseQueryRemote, args)
            
            elif(dbName==config['POSTGRESQL_MM_NAME']):
                args = [startTime, endTime, postgresUser, postgresHost, postgresPort,postgresPassword, dbName, isRemote, backupPath, localPath, remoteHost, remoteUser, remotePassword, source]
                return StartBackup(BackupmiddlewareQueryRemote, args)
            
            elif(dbName==config['POSTGRESQL_UMM_NAME']):
                args = [startTime, endTime, postgresUser, postgresHost, postgresPort, postgresPassword, dbName, isRemote, backupPath, localPath, remoteHost, remoteUser, remotePassword]
                return StartBackup(BackupUserQueryRemote, args)
            
            elif(dbName==config['POSTGRESQL_INGESTION_LOGS']):
                payload = {
                    "status": True,
                    "message": "Backup cannot be initiated.",
                    "backup_path": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_200_OK)
            
            elif(dbName==config['POSTGRESQL_KEYCLOAK_NAME']):
                payload = {
                    "status": True,
                    "message": "Backup cannot be initiated.",
                    "backup_path": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_200_OK)
            
            elif(dbName==config['POSTGRESQL_WORKBENCH_NAME']):
                payload = {
                    "status": True,
                    "message": "Backup cannot be initiated.",
                    "backup_path": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_200_OK)
            
            else:
                payload = {
                    "status": False,
                    "message": "Invalid database name.",
                    "data": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
                
            # else:
            #     if startTime is not None and endTime is not None:
            #         def BackupDatabase(dbName, localPath, userId, startTime, endTime, postgresUser, postgresHost, postgresPort, postgresPassword, source=None):
            #             starttime = datetime.now()
            #             ipAddress = config['LOCAL_POSTGRESQL_HOST']
            #             backupMode = "local"
            #             # schemabackupFilePath = os.path.join(localPath, f'{dbName}_schema.sql')
                        
            #             responseData, value = SaveDataToDb("partial", backupMode, ipAddress, localPath, "Scheduled", "Backup scheduled", None, userId)
            #             Id = value['id']
                        
            #             if not responseData:
            #                 logger.error("Cannot Log to Database")
            #                 return 
                        
            #             if(dbName==config['POSTGRESQL_CMM_NAME']):
            #                 queryResults = BackupCaseQueryRemote(startTime, endTime, postgresUser, postgresHost, postgresPort, postgresPassword, dbName, isRemote, localPath)
            #                 csvFolder = "case"
                        
            #             elif(dbName==config['POSTGRESQL_UMM_NAME']):
            #                 queryResults = LocalUserQuery(startTime, endTime, postgresUser, postgresHost, postgresPort, postgresPassword, dbName, localPath)
            #                 csvFolder = "usermanagement"
                        
            #             elif(dbName==config['POSTGRESQL_MM_NAME']):
            #                 queryResults = LocalMiddlewareQuery(startTime, endTime, postgresUser, postgresHost, postgresPort, postgresPassword, dbName, localPath, source)
            #                 csvFolder = "middleware"
                        
            #             elif(dbName==config['POSTGRESQL_INGESTION_LOGS']):
            #                 payload = {
            #                     "status": True,
            #                     "message": "Backup cannot be initiated.",
            #                     "backup_path": None,
            #                     "error": None
            #                 }
            #                 return Response(payload, status=status.HTTP_200_OK)

            #             elif(dbName==config['POSTGRESQL_KEYCLOAK_NAME']):
            #                 payload = {
            #                     "status": True,
            #                     "message": "Backup cannot be initiated.",
            #                     "backup_path": None,
            #                     "error": None
            #                 }
            #                 return Response(payload, status=status.HTTP_200_OK)

            #             elif(dbName==config['POSTGRESQL_WORKBENCH_NAME']):
            #                 payload = {
            #                     "status": True,
            #                     "message": "Backup cannot be initiated.",
            #                     "backup_path": None,
            #                     "error": None
            #                 }
            #                 return Response(payload, status=status.HTTP_200_OK)
                        
            #             else:
            #                 payload = {
            #                     "status": False,
            #                     "message": "Invalid database name.",
            #                     "error": "Backup failed."
            #                 }
            #                 return Response(payload, status=status.HTTP_400_BAD_REQUEST)


            #             flag = False
            #             for query_info in queryResults:
            #                 if RunPsql(query_info["query"], query_info["output_file"], postgresUser, postgresHost, postgresPort, dbName):
            #                     flag = True

            #             if flag:
            #                 endTime = datetime.now()
            #                 duration = Duration(starttime, endTime)
            #                 if UpdateStatusToDb(Id, "Success", "Backup Successful", duration):
            #                     logger.info("Backup successful.")
            #                 else:
            #                     return

            #                 payload = {
            #                     "status": True,
            #                     "message": "Backup Successful.",
            #                     # "backup_path": schemabackupFilePath,
            #                     "csv_path": os.path.join(localPath, csvFolder),
            #                     "error": None
            #                 }
            #                 return Response(payload, status=status.HTTP_200_OK)
            #             else:
            #                 if UpdateStatusToDb(Id, "Failed", "Backup Failed"):
            #                     logger.info("Logged to database.")
            #                 else:
            #                     logger.error("Failed to log to database.")
            #                     return

            #                 payload = {
            #                     "status": False,
            #                     "message": "Backup failed.",
            #                     "error": None
            #                 }
            #                 return Response(payload, status=status.HTTP_400_BAD_REQUEST)


            #         def BackupThread(dbName, localPath, userId, startTime, endTime, postgresUser, postgresHost, postgresPort, postgresPassword, source=None):
            #             backupThread = threading.Thread(
            #                 target=BackupDatabase, 
            #                 args=(dbName, localPath, userId, startTime, endTime, postgresUser, postgresHost, postgresPort, postgresPassword, source),
            #                 daemon=True
            #             )
            #             backupThread.start()


            #         if dbName == config['POSTGRESQL_CMM_NAME']:
            #             BackupThread(dbName, localPath, userId, startTime, endTime, postgresUser, postgresHost, postgresPort, postgresPassword)
            #             payload = {
            #                 "status": True,
            #                 "message": "Backup has been scheduled. Please check log table for more details.",
            #                 "error": None
            #             }
            #             return Response(payload, status=status.HTTP_200_OK)

            #         elif dbName == config['POSTGRESQL_UMM_NAME']:
            #             BackupThread(dbName, localPath, userId, startTime, endTime, postgresUser, postgresHost, postgresPort, postgresPassword)
            #             payload = {
            #                 "status": True,
            #                 "message": "Backup has been scheduled. Please check log table for more details.",
            #                 "error": None
            #             }
            #             return Response(payload, status=status.HTTP_200_OK)

            #         elif dbName == config['POSTGRESQL_MM_NAME']:
            #             BackupThread(dbName, localPath, userId, startTime, endTime, postgresUser, postgresHost, postgresPort, postgresPassword, source)
            #             payload = {
            #                 "status": True,
            #                 "message": "Backup has been scheduled. Please check log table for more details.",
            #                 "error": None
            #             }
            #             return Response(payload, status=status.HTTP_200_OK)
                    
            #         elif(dbName==config['POSTGRESQL_INGESTION_LOGS']):
            #             payload = {
            #                 "status": True,
            #                 "message": "Backup cannot be initiated.",
            #                 "backup_path": None,
            #                 "error": None
            #             }
            #             return Response(payload, status=status.HTTP_200_OK)

            #         elif(dbName==config['POSTGRESQL_KEYCLOAK_NAME']):
            #             payload = {
            #                 "status": True,
            #                 "message": "Backup cannot be initiated.",
            #                 "backup_path": None,
            #                 "error": None
            #             }
            #             return Response(payload, status=status.HTTP_200_OK)

            #         elif(dbName==config['POSTGRESQL_WORKBENCH_NAME']):
            #             payload = {
            #                 "status": True,
            #                 "message": "Backup cannot be initiated.",
            #                 "backup_path": None,
            #                 "error": None
            #             }
            #             return Response(payload, status=status.HTTP_200_OK)
                    
            #         else:
            #             payload = {
            #                 "status": False,
            #                 "message": "Invalid database name.",
            #                 "error": "Backup failed."
            #             }
            #             return Response(payload, status=status.HTTP_400_BAD_REQUEST)

            #     else:
            #         logger.error("Please provide starttime and endtime for partial backup.")
            #         payload = {
            #             "status":False,
            #             "message":"Please provide starttime and endtime for partial backup.",
            #             "data":None,
            #             "error":"Backup Failed."
            #         }
            #         return Response(payload, status=status.HTTP_400_BAD_REQUEST)


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
        
        sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
        if sshclient:
            statCode, response = RemoteBackupDetails(remoteHost, remoteUser, remotePassword, remoteBackupPath)
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
            
                    
class PostgresRestoreServer(APIView):
    @swagger_auto_schema(
        operation_description="""Start restoring for the files which were backuped using POST request.
            1. This API endpoint allows you to start restoration by providing valid credentials and path where the backed up file is present in the request body.
            2. Restore can be initited from remote as well as local server.
            3. Valid postgresql credentials is required to restore backuped data for both remote and local server.
            Note: This API requires systemadmin for restoration.
        """,
        operation_summary='Start Database Restore',
    )
    def post(self, request):
        # apiData = UserAuthenticationFromUserManagement(request)
            
        # if isinstance(apiData, Response):
        #     return apiData
        
        # isSuperuser = apiData['data'][0]['is_superuser']
        # userName = apiData['data'][0]['username']
        
        # if(not isSuperuser):
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
        postgresHost = data.get("postgres_host",None)
        postgresPort = data.get("postgres_port",None)
        postgresUser = data.get("postgres_user",None)
        postgresPassword = data.get("postgres_password",None)
        
        filePath = data.get("file_path",None)

        remoteHost = data.get('remote_host',None)
        remoteUser = data.get('remote_user',None)
        remotePort = data.get('remote_port',None)
        remotePassword = data.get('remote_password',None)
        isRemote = data.get('remote',None)
        
        restorePostgresHost = data.get("restore_postgres_host",None)
        restorePostgresPort = data.get("restore_postgres_port",None)
        restorePostgresUser = data.get("restore_postgres_user",None)
        restorePostgresPassword = data.get("restore_postgres_password",None)
        restorePostgresDatabaseName = config["POSTGRESQL_RESTORE_LOG_DATABASE_NAME"]
        restorePostgresTableName = config["POSTGRESQL_RESTORE_LOG_TABLE_NAME"]
        
        if any(param is None or not param for param in (postgresHost, postgresPort, postgresUser, postgresPassword)):
            logger.info("Please provide postgres credentials to proceed with restore.")
            logger.warning("Restore won't proceed without postgres credentials.")
            payload = {
                "status": False,
                "message": "Please provide postgres credentials to proceed with restore.",
                "data": None,
                "error": "Restore won't proceed without postgres credentials."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        response, conn = ConnectToDb(postgresUser, postgresPassword, postgresHost, postgresPort)    #BUG ID 1102: Postgres - Backup - wrong host
        if (not response):
            return Response(conn, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            conn = psycopg2.connect(
                host=restorePostgresHost,
                port=restorePostgresPort,
                user=restorePostgresUser,
                password=restorePostgresPassword,
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
        
        # if not isRemote:
        #     if filePath:
        #         response = ServerDataRestore(postgresUser, postgresHost, postgresPort, postgresPassword, filePath, isRemote, remoteHost, remoteUser, remotePassword)
        #         if (response):
        #             logger.info("Server restored successfully")
        #             payload = {
        #                 "status":True,
        #                 "message":"Server restored successfully from path.",
        #                 "data_file_path":filePath,
        #                 "error":None
        #             }
        #             return Response(payload, status=status.HTTP_200_OK)
        #         else:
        #             logger.error("Server restoration failed.")
        #             payload = {
        #                 "status":False,
        #                 "message":"Server restoration failed.",
        #                 "data":None,
        #                 "error":"Error restoring data."
        #             }
        #             return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        #     else:
        #         logger.error("User has not provided backup file path.")
        #         payload = {
        #             "status":False,
        #             "message":"Please provided backup file path.",
        #             "data":None,
        #             "error":"Restoration will not proceed."
        #         }
        #         return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
        # else:
        #     if not (filePath and remoteHost and remotePort and remoteUser and remotePassword):
        #         logger.error("Please provide remote credentials with backup file path to proceed with restore.")
        #         logger.warning("Restore won't proceed without remote credentials.")
        #         payload = {
        #             "status": False,
        #             "message": "Please provide remote credentials with backup file path to proceed with restore.",
        #             "data": None,
        #             "error": "Restore won't proceed without remote credentials."
        #         }
        #         return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        #     else:
        #         sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
        #         if sshclient:
        #             if ServerDataRestore(postgresUser, postgresHost, postgresPort, postgresPassword, filePath, isRemote, remoteHost, remoteUser, remotePassword):
        #                 logger.info("Server Restored Successfully") #BUG ID 1107: Restore - Postgres - remote - complete
        #                 payload = {
        #                     "status":True,
        #                     "message":"Server Restored Successfully",
        #                     "data":None,
        #                     "error":None
        #                 }
        #                 return Response(payload, status=status.HTTP_200_OK)
        #             else:
        #                 logger.error("Server Restored Failed")
        #                 payload = {
        #                     "status":False,
        #                     "message":"Server Restored Failed",
        #                     "data":None,
        #                     "error":None
        #                 }
        #                 return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        #         else:
        #             logger.error("Remote client connection failed.")
        #             payload = {
        #                 "status": False,
        #                 "message": "Remote client connection failed.",
        #                 "data": None,
        #                 "error": None
        #             }
        #             return Response(payload, status=status.HTTP_404_NOT_FOUND)
        
        def RunServerRestore(postgresUser, postgresHost, postgresPort, postgresPassword, filePath, isRemote, restorePostgresHost, restorePostgresPort, restorePostgresUser, restorePostgresPassword, restorePostgresDatabaseName, restorePostgresTableName, remoteHost=None, remotePort=None, remoteUser=None, remotePassword=None):
            startTime = datetime.now()
            restoreMode = "remote" if isRemote else "local"
            ipAddress = remoteHost if isRemote else config["LOCAL_POSTGRESQL_HOST"]
            path = filePath

            # responseStatus, restoreId = InsertRestoreLogToPostgres(restorePostgresHost, restorePostgresPort, restorePostgresUser, restorePostgresPassword, restorePostgresDatabaseName, restorePostgresTableName, "complete", restoreMode, ipAddress, path, "Scheduled", None, None)
            # if not responseStatus:
            #     logger.error("Cannot log to database.")
            #     return

            try:
                success = ServerDataRestore(postgresUser, postgresHost, postgresPort, postgresPassword,filePath, isRemote, remoteHost, remoteUser, remotePassword)
                endTime = datetime.now()
                duration = Duration(startTime, endTime)

                if success:
                    logger.info("Server restored successfully")
                    InsertRestoreLogToPostgres(restorePostgresHost, restorePostgresPort, restorePostgresUser, restorePostgresPassword, restorePostgresDatabaseName, restorePostgresTableName, "complete", restoreMode, ipAddress, path, "Success", "Server Restored", duration, None)
                else:
                    logger.error("Server restoration failed.")
                    InsertRestoreLogToPostgres(restorePostgresHost, restorePostgresPort, restorePostgresUser, restorePostgresPassword, restorePostgresDatabaseName, restorePostgresTableName, "complete", restoreMode, ipAddress, path, "Failed", "Restore Failed", None, None)

            except Exception as e:
                logger.error(f"Restore encountered an exception: {e}")
                InsertRestoreLogToPostgres(restorePostgresHost, restorePostgresPort, restorePostgresUser, restorePostgresPassword, restorePostgresDatabaseName, restorePostgresTableName, "complete", restoreMode, ipAddress, path, "Failed", str(e), None, None)

        if not isRemote:
            if filePath:
                thread = threading.Thread(target=RunServerRestore,
                                        args=(postgresUser, postgresHost, postgresPort, postgresPassword, filePath, isRemote, restorePostgresHost, restorePostgresPort, restorePostgresUser, restorePostgresPassword, restorePostgresDatabaseName, restorePostgresTableName),
                                        daemon=True
                )
                thread.start()
                payload = {
                    "status": True,
                    "message": "Local server restore process started in background.",
                    "data_file_path": filePath,
                    "error": None
                }
                return Response(payload, status=status.HTTP_202_ACCEPTED)
            else:
                logger.error("User has not provided backup file path.")
                payload = {
                    "status": False,
                    "message": "Please provide backup file path.",
                    "data": None,
                    "error": "Restoration will not proceed."
                }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)

        else:
            if not (filePath and remoteHost and remotePort and remoteUser and remotePassword):
                logger.error("Please provide remote credentials with backup file path to proceed with restore.")
                payload = {
                    "status": False,
                    "message": "Remote credentials and backup file path required.",
                    "data": None,
                    "error": "Restore won't proceed without remote credentials."
                }
                return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
            
            sshclient = CreateSshClient(remoteHost, int(remotePort), remoteUser, remotePassword)
            if sshclient:
                thread = threading.Thread(target=RunServerRestore,
                                        args=(postgresUser, postgresHost, postgresPort, postgresPassword, filePath, isRemote, restorePostgresHost, restorePostgresPort, restorePostgresUser, restorePostgresPassword, restorePostgresDatabaseName, restorePostgresTableName, remoteHost, remotePort, remoteUser, remotePassword),
                                        daemon=True
                )
                thread.start()
                payload = {
                    "status": True,
                    "message": "Remote server restore process started in background.",
                    "data": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_202_ACCEPTED)
            else:
                logger.error("Remote client connection failed.")
                payload = {
                    "status": False,
                    "message": "Remote SSH connection failed.",
                    "data": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_404_NOT_FOUND)
        

class FetchDateRange(APIView):
    @swagger_auto_schema(
        operation_description="""Get date range for the available data in query parameters using GET request.
            This API endpoint allows you to retrieve data with available date range.
            Note: This API requires systemadmin to view date range.
        """,
        operation_summary='Start Database Restore',
    )
    def get(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        
        if(not isSuperuser):
            logger.warning(f'{userName}: do not have permission to fetch date range')
            payload = {  
                "status":False,
                "message":"You don't have permission to fetch date range",
                "data": None,
                "error": "You don't have permission to fetch date range",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to fetch date range.")
        
        params = request.query_params.dict()
        # postgresHost = params.get("postgres_host",None)
        # postgresPort = params.get("postgres_port",None)
        # postgresUser = params.get("postgres_user",None)
        # postgresPassword = params.get("postgres_password",None)
        dbName = params.get("database_name",None)
        source = params.get("source",None)
        
        
        # if (postgresHost==None or postgresPort==None or postgresUser==None or postgresPassword==None or dbName==None):
        #    return Response({
        #        "status":False,
        #        "message":"Postgres credentials is required",
        #        "data":None,
        #        "error":"Mandatory fields not provided"
        #        },status=status.HTTP_406_NOT_ACCEPTABLE)         
        
        try:
            if dbName == config['POSTGRESQL_CMM_NAME']:
                conn = psycopg2.connect(database= config['POSTGRESQL_CMM_NAME'], 
                                        host= config['POSTGRESQL_HOST'],
                                        user= config['POSTGRESQL_USER'], 
                                        password= config['POSTGRESQL_PASSWORD'], 
                                        port= config['POSTGRESQL_PORT']
                                        )
                cursor = conn.cursor()

                query = """
                    SELECT MIN("created_on"), MAX("created_on")
                    FROM "Case_Management_case"
                """
            
            elif dbName == config['POSTGRESQL_UMM_NAME']:
                conn = psycopg2.connect(database= config['POSTGRESQL_UMM_NAME'], 
                                    host= config['POSTGRESQL_HOST'],
                                    user= config['POSTGRESQL_USER'], 
                                    password= config['POSTGRESQL_PASSWORD'], 
                                    port= config['POSTGRESQL_PORT']
                                    )
                cursor = conn.cursor()

                query = """
                    SELECT MIN("updated_on"), MAX("updated_on")
                    FROM "user_userprofile"
                """
            
            elif dbName == config['POSTGRESQL_MM_NAME']:
                conn = psycopg2.connect(database= config['POSTGRESQL_MM_NAME'], 
                                    host= config['POSTGRESQL_HOST'],
                                    user= config['POSTGRESQL_USER'], 
                                    password= config['POSTGRESQL_PASSWORD'], 
                                    port= config['POSTGRESQL_PORT']
                                    )
                cursor = conn.cursor()
                
                if(source=="cdr"):
                    query = """
                        SELECT MIN("ingestion_timestamp"), MAX("ingestion_timestamp")
                        FROM "Scylla_cdrdata"
                    """
                
                elif(source=="ip"):
                    query = """
                        SELECT MIN("ingestion_timestamp"), MAX("ingestion_timestamp")
                        FROM "IpData_ipdata"
                    """
            else:
                payload = {
                    "status": False,
                    "message": "Cannot fetch datarange for selected database",
                    "data": None,
                    "error": "Cannot fetch datarange for selected database"
                }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            
            cursor.execute(query)
            result = cursor.fetchone()
            
            if not result:
                payload = {
                    "status": False,
                    "message": "No data found in the table.",
                    "data": None,
                    "error": "No data found in the table."
                }
                return Response(payload, status=status.HTTP_404_NOT_FOUND)

            minTimestamp, maxTimestamp = result
            dateRangeData = {
                "from_timestamp": minTimestamp,
                "from_date": datetime.fromtimestamp(minTimestamp).strftime('%Y-%m-%d %H:%M:%S'),
                "to_timestamp": maxTimestamp,
                "to_date": datetime.fromtimestamp(maxTimestamp).strftime('%Y-%m-%d %H:%M:%S')
            }
            payload = {
                "status": True,
                "message": "Date range fetched successfully",
                "data": dateRangeData,
                "error": None
            }
            return Response(payload, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error: {e}")
            payload = {
                "status": False,
                "message": "Error occurred while fetching date range",
                "data": None,
                "error":str(e)
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            

class RestoreSchemaWithData(APIView):
    @swagger_auto_schema(
        operation_description="""Start restoring for the files which were backuped using POST request.
            1. This API endpoint allows you to start restoration by providing valid credentials and path where the backed up file is present in the request body.
            2. Restore can be initited from remote as well as local server.
            3. Provide schema and data for partial restore.
            Note: This API requires systemadmin for restoration.
        """,
        operation_summary='Start Partial Database Restore',
    )
    def post(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        
        if(not isSuperuser):
            logger.warning(f'{userName}: do not have permission to proceed with restore')
            payload = {  
                "status":False,
                "message":"You don't have permission to proceed with restore",
                "data": None,
                "error": "You don't have permission to proceed with restore",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to fetch date range.")
        
        data = request.data

        postgresHost= data.get("postgres_host",None)
        postgresPort=data.get("postgres_port",None)
        postgresUser=data.get("postgres_user",None)
        postgresPassword=data.get("postgres_password",None)
        
        schemaFilePath = data.get("schema_path",None)
        dataFilePath = data.get("csv_file_path",None)
        dbName = data.get("database_name",None)
        source = data.get("source", None)
        
        remoteHost = data.get('remote_host',None)
        remoteUser = data.get('remote_user',None)
        remotePassword = data.get('remote_password',None)
        remotePort = data.get('remote_port',None)
        isRemote = data.get('remote',None)
        
        if any(param is None or not param for param in (schemaFilePath, dataFilePath)):
            logger.error("Schema or csv file path not provided")
            payload = {
                "status":False,
                "message":"Schema or csv file path not provided.",
                "data":None,
                "error":"Schema restoration will not proceed."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        if any(param is None or not param for param in (postgresHost, postgresPort, postgresUser, postgresPassword)):
            logger.info("Please provide postgres credentials to proceed with backup.")
            logger.warning("Backup won't proceed without postgres credentials.")
            payload = {
                "status": False,
                "message": "Please provide postgres credentials to proceed with backup.",
                "data": None,
                "error": "Backup won't proceed without postgres credentials."
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        response, conn = ConnectToDb(postgresUser, postgresPassword, postgresHost, postgresPort)    #BUG ID 1102: Postgres - Backup - wrong host
        if (not response):
            return Response(conn, status=status.HTTP_400_BAD_REQUEST)
        
        if not isRemote:
            # dbname = RestoreSchema(POSTGRES_USER, POSTGRES_HOST, POSTGRES_PORT, dbName, POSTGRES_PASSWORD, schemaFilePath)
                    
            flag = True
            if dbName==config['POSTGRESQL_CMM_NAME']:
                tableNames = ExtractTableNames(schemaFilePath)
                if tableNames:
                    for tablename in tableNames:
                        if IsDefaultDjangoTable(tablename):
                            logger.info(f"Skipping default Django table: {tablename}")
                            continue
                        tableRestored = False
                        for csv_file in os.listdir(dataFilePath):
                            if csv_file.endswith('.csv'):
                                if csv_file.replace('.csv', '') == tablename:
                                    csv_file_path = os.path.join(dataFilePath, csv_file)
                                    success = RestoreCaseQueryData(postgresUser, postgresHost, postgresPort, dbName, postgresPassword ,tablename, csv_file_path, schemaFilePath)
                                    if success:
                                        tableRestored = True
                                        break
                    
                    if not tableRestored and not IsDefaultDjangoTable(tablename):
                        logger.error(f"Restoration failed for table {tablename}.")
                        flag = False
                
                if flag:
                    logger.info("Case Data Restored Successfully")
                    payload = {
                        "status":True,
                        "message":"Case Data Restored Successfully",
                        "dbname":dbName,
                        "error":None
                    }
                    return Response(payload, status=status.HTTP_200_OK)
                else:
                    logger.error("Case Data Restoration failed")
                    payload = {
                        "status":False,
                        "message":"Case Data Restoration failed",
                        "dbname":dbName,
                        "error":None
                    }
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            
            elif dbName==config['POSTGRESQL_UMM_NAME']:
                tableNames = ExtractTableNames(schemaFilePath)
                if tableNames:
                    for tablename in tableNames:
                        if IsDefaultDjangoTable(tablename):
                            logger.info(f"Skipping default Django table: {tablename}")
                            continue
                        tableRestored = False
                        for csv_file in os.listdir(dataFilePath):
                            if csv_file.endswith('.csv'):
                                if csv_file.replace('.csv', '') == tablename:
                                    csv_file_path = os.path.join(dataFilePath, csv_file)
                                    success = RestoreUserQueryData(postgresUser, postgresHost, postgresPort, dbName, postgresPassword ,tablename, csv_file_path, schemaFilePath)
                                    if success:
                                        tableRestored = True
                                        break
                    
                    if not tableRestored and not IsDefaultDjangoTable(tablename):
                        logger.error(f"Restoration failed for table {tablename}.")
                        flag = False
                
                if flag:
                    logger.info("User Data Restored Successfully")
                    payload = {
                        "status":True,
                        "message":"User Data Restored Successfully",
                        "dbname":dbName,
                        "error":None
                    }
                    return Response(payload, status=status.HTTP_200_OK)
                else:
                    logger.error("User Data Restoration failed")
                    payload = {
                        "status":False,
                        "message":"User Data Restoration failed",
                        "dbname":dbName,
                        "error":None
                    }
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)

            elif dbName==config['POSTGRESQL_MM_NAME']:
                tableNames = ExtractTableNames(schemaFilePath)
                if tableNames:
                    for tablename in tableNames:
                        if IsDefaultDjangoTable(tablename):
                            logger.info(f"Skipping default Django table: {tablename}")
                            continue
                        tableRestored = False
                        for csv_file in os.listdir(dataFilePath):
                            if csv_file.endswith('.csv'):
                                if csv_file.replace('.csv', '') == tablename:
                                    csv_file_path = os.path.join(dataFilePath, csv_file)
                                    success = RestoreMiddlewareQueryData(postgresUser, postgresHost, postgresPort, dbName, postgresPassword ,tablename, csv_file_path, schemaFilePath)
                                    if success:
                                        tableRestored = True
                                        break
                    
                    if not tableRestored and not IsDefaultDjangoTable(tablename):
                        logger.error(f"Restoration failed for table {tablename}.")
                        flag = False
                
                if flag:
                    logger.info("Middleware Data Restored Successfully")
                    payload = {
                        "status":True,
                        "message":"Middleware Data Restored Successfully",
                        "dbname":dbName,
                        "error":None
                    }
                    return Response(payload, status=status.HTTP_200_OK)
                else:
                    logger.error("Middleware Data Restoration failed")
                    payload = {
                        "status":False,
                        "message":"Middleware Data Restoration failed",
                        "dbname":dbName,
                        "error":None
                    }
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            
        
        else:
            if not (remoteHost and remotePort and remoteUser and remotePassword):
                logger.error("Please provide remote credentials to proceed with restore.")
                logger.warning("Cannot proceed with Restoration without remote credentials.")
                payload = {
                    "status": False,
                    "message": "Please provide remote credentials to proceed with restore.",
                    "data": None,
                    "error": "Cannot proceed with Restoration without remote credentials."
                }
                return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
            
            if(dbName==config['POSTGRESQL_MM_NAME']):
                if(source=="cdr"):
                    if RestoreMiddlewareQueryFromRemote(remoteHost, remoteUser, remotePassword, postgresHost, postgresUser, postgresPort, postgresPassword, dbName, schemaFilePath, dataFilePath,source):
                        logger.info("Middleware Data Restored Successfully")
                        payload = {
                            "status":True,
                            "message":"Middleware Data Restored Successfully",
                            "dbname":dbName,
                            "source":source,
                            "error":None
                        }
                        return Response(payload, status=status.HTTP_200_OK)
                    else:
                        logger.error("Middleware Data Restoration failed.")
                        payload = {
                            "status":False,
                            "message":"Middleware Data Restoration failed.",
                            "dbname":dbName,
                            "source":source,
                            "error":None
                        }
                        return Response(payload, status=status.HTTP_400_BAD_REQUEST)
                
                elif(source=="ip"):
                    if RestoreMiddlewareQueryFromRemote(remoteHost, remoteUser, remotePassword, postgresHost, postgresUser, postgresPort, postgresPassword, dbName, schemaFilePath, dataFilePath, source):
                        logger.info("Middleware Data Restored Successfully")
                        payload = {
                            "status":True,
                            "message":"Middleware Data Restored Successfully",
                            "dbname":dbName,
                            "source":source,
                            "error":None
                        }
                        return Response(payload, status=status.HTTP_200_OK)
                    else:
                        logger.error("Middleware Data Restoration failed.")
                        payload = {
                            "status":False,
                            "message":"Middleware Data Restoration failed.",
                            "dbname":dbName,
                            "source":source,
                            "error":None
                        }
                        return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            
            elif (dbName==config["POSTGRESQL_CMM_NAME"]):
                if RestoreCaseQueryFromRemote(remoteHost, remoteUser, remotePassword, postgresHost, postgresUser, postgresPort, postgresPassword, dbName, schemaFilePath, dataFilePath):
                    logger.info("Case Data Restored Successfully")
                    payload = {
                        "status":True,
                        "message":"Case Data Restored Successfully",
                        "dbname":dbName,
                        "error":None
                    }
                    return Response(payload, status=status.HTTP_200_OK)
                else:
                    logger.error("Case Data Restoration failed.")
                    payload = {
                        "status":False,
                        "message":"Case Data Restoration failed.",
                        "dbname":dbName,
                        "error":None
                    }
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            
            elif (dbName==config["POSTGRESQL_UMM_NAME"]):
                if RestoreUserQueryFromRemote(remoteHost, remoteUser, remotePassword, postgresHost, postgresUser, postgresPort, postgresPassword, dbName, schemaFilePath, dataFilePath):
                    logger.info("User Data Restored Successfully")
                    payload = {
                        "status":True,
                        "message":"User Data Restored Successfully",
                        "dbname":dbName,
                        "error":None
                    }
                    return Response(payload, status=status.HTTP_200_OK)
                else:
                    logger.error("User Data Restoration failed.")
                    payload = {
                        "status":False,
                        "message":"User Data Restoration failed.",
                        "dbname":dbName,
                        "error":None
                    }
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            
            elif(dbName==config['POSTGRESQL_INGESTION_LOGS']):
                payload = {
                    "status": True,
                    "message": f"Could not able to Restore{dbName}.",
                    "backup_path": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_200_OK)
            
            elif(dbName==config['POSTGRESQL_KEYCLOAK_NAME']):
                payload = {
                    "status": True,
                    "message": f"Could not able to Restore{dbName}.",
                    "backup_path": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_200_OK)
            
            elif(dbName==config['POSTGRESQL_WORKBENCH_NAME']):
                payload = {
                    "status": True,
                    "message": f"Could not able to Restore{dbName}.",
                    "backup_path": None,
                    "error": None
                }
                return Response(payload, status=status.HTTP_200_OK)
            

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
        
        statCode, response = LocalBackupDetails()
        if statCode:
            return Response(response, status=status.HTTP_200_OK)
        else:
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

class ViewBackUpRestore(APIView):
    @swagger_auto_schema(
        operation_description="""Fetch backup logs using GET request.
            1. This API endpoint allows you to fetch backup logs.
            2. All information related to backup will be fetched by calling this api. 
            Note: This API requires systemadmin to view backup logs.
        """,
        operation_summary='Fetch Backup Log Details',
    )
    def get(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
            
        if isinstance(apiData, Response):
            return apiData
        
        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        
        dbName=request.query_params.get("database_name",None)
        page = int(request.query_params.get("page", 1))
        limit = int(request.query_params.get("limit", 100000))
        columnName = request.query_params.get('column_name',None)
        searchData = request.query_params.get('search_data',None)
        
        if(not isSuperuser):
            logger.warning(f'{userName}: do not have permission to view log details.')
            payload = {  
                "status":False,
                "message":"You don't have permission to view log details.",
                "data": None,
                "error": "You don't have permission to view log details.",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
            
        logger.info(f"Permission granted for {userName} to view log details.")
        
        if dbName:
            brQset = BackupAndRestore.objects.filter(database_type=dbName)
            if(brQset.count()==0):
                logger.error("No results found")
                payload = {
                    "status": False,
                    "message": "No results found",
                    "data": None,
                    "error":"No results found"
                }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            
            else:
                if (columnName!=None and searchData!=None):
                    columnName = columnName.lower()
                    if columnName and columnName != "all":
                        filterdData = {f"{columnName}__icontains": searchData}
                        brQset = brQset.filter(**filterdData)
                        # LogUserActivity(request, userName=userName, activity=f"{userName} : Filtering brqset by {columnName} with search data '{searchData}'") 
                    else:
                        brQset = brQset.filter(  
                            Q(id__icontains=searchData) |
                            Q(path__icontains=searchData) |
                            Q(summary__icontains=searchData) |
                            Q(status__icontains=searchData) |
                            Q(database_type__icontains=searchData) |
                            Q(backup_type__icontains=searchData) |
                            Q(ip_address__icontains=searchData) |
                            Q(duration__icontains=searchData) 
                        )  
                        # LogUserActivity(request, userName=userName, activity=f"{userName} : Searching all brqset with search data '{searchData}'")  # Logging search action
                
                if(brQset.count()==0):
                    logger.error("No data found for you search results")
                    payload = {
                        "status": False,
                        "message": "No data found for you search results",
                        "data": None,
                        "error":"No results found"
                    }
                    return Response(payload, status=status.HTTP_404_NOT_FOUND)
                    
                paginator = Paginator(brQset.order_by('-created_on'), limit)
                resultPage = paginator.page(page)
                serializedData = GetBackupRestoreSerializer(resultPage, many=True).data
                
                userIds=set()
                for data in serializedData:
                    userIds.update([data['created_by']])
                
                userNames = GetUser(list(userIds))
                for formattedData in serializedData:
                    formattedData['created_by'] = userNames.get(data['created_by'])
                
                payload = {
                    "status": True,
                    "message": "Backup and Restore Details Fetched Successfully",
                    "data": serializedData,
                    "error": None,
                    "meta": {
                        "page": resultPage.number,
                        "limit": limit,
                        "total": paginator.count
                    }
                }
                return Response(payload, status=status.HTTP_200_OK)
        
        else:
            brQset = BackupAndRestore.objects.all()
            if(brQset.count()==0):
                logger.error("No results found")
                payload = {
                    "status": False,
                    "message": "No results found",
                    "data": None,
                    "error":"No results found"
                }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            
            else:
                if (columnName!=None and searchData!=None):
                    columnName = columnName.lower()
                    if columnName and columnName != "all":
                        filterdData = {f"{columnName}__icontains": searchData}
                        brQset = brQset.filter(**filterdData)
                        # LogUserActivity(request, userName=userName, activity=f"{userName} : Filtering brqset by {columnName} with search data '{searchData}'") 
                    else:
                        brQset = brQset.filter(  
                            Q(id__icontains=searchData) |
                            Q(path__icontains=searchData) |
                            Q(summary__icontains=searchData) |
                            Q(status__icontains=searchData) |
                            Q(database_type__icontains=searchData) |
                            Q(backup_type__icontains=searchData) |
                            Q(ip_address__icontains=searchData) |
                            Q(duration__icontains=searchData) 
                        )  
                        # LogUserActivity(request, userName=userName, activity=f"{userName} : Searching all brqset with search data '{searchData}'")  # Logging search action
                
                paginator = Paginator(brQset.order_by('-created_on'), limit)
                resultPage = paginator.page(page)
                serializedData = GetBackupRestoreSerializer(resultPage, many=True).data
                
                payload = {
                    "status": True,
                    "message": "Backup and Restore Details Fetched Successfully",
                    "data": serializedData,
                    "error": None,
                    "meta": {
                        "page": resultPage.number,
                        "limit": limit,
                        "total": paginator.count
                    }
                }
                return Response(payload, status=status.HTTP_200_OK)
        
class FetchRestoreLogs(APIView):
    @swagger_auto_schema(
        operation_description="""Fetch restore logs using GET request.
            1. This API endpoint allows you to fetch restore logs.
            Note: This API requires systemadmin to fetch restore logs.
        """,
        operation_summary='Fetch Restore Logs',
    )
    def get(self, request):
        # apiData = UserAuthenticationFromUserManagement(request)
            
        # if isinstance(apiData, Response):
        #     return apiData
        
        # isSuperuser = apiData['data'][0]['is_superuser']
        # userName = apiData['data'][0]['username']
        
        # if(not isSuperuser):
        #     logger.warning(f'{userName}: do not have permission to fetch restore logs')
        #     payload = {  
        #         "status":False,
        #         "message":"You don't have permission to fetch restore logs",
        #         "data": None,
        #         "error": "You don't have permission to fetch restore logs",                
        #     }
        #     return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        # logger.info(f"Permission granted for {userName} to fetch restore logs.") 
        
        params = request.query_params.dict()
        postgresHost = params.get("postgres_host",None)
        postgresPort = params.get("postgres_port",None)
        postgresUser = params.get("postgres_user",None)
        postgresPassword = params.get("postgres_password",None)
        postgresDatabaseName = config["POSTGRESQL_RESTORE_LOG_DATABASE_NAME"]
        postgresTableName = config["POSTGRESQL_RESTORE_LOG_TABLE_NAME"]
        databaseType = params.get("database_type",None)
        
        page = int(params.get("page", 1))
        limit = int(params.get("limit", 100000))
        columnName = params.get('column_name',None)
        searchData = params.get('search_data',None)
        
        requiredKeys = [
            "postgres_host",
            "postgres_port",
            "postgres_user",
            "postgres_password",
            # "postgres_db_name",
            # "postgres_table_name",
            "database_type"
        ]
        missingKeys = [key for key in requiredKeys if not params.get(key)]
        if missingKeys:
            logger.error(f"Missing required query parameters: {', '.join(missingKeys)}")
            payload = {
                "status": False,
                "message": "Required query parameters are missing.",
                "missing_parameters": missingKeys,
                "error": "Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
            
        responseStatus, response = FetchRestoreLog(postgresHost, postgresPort, postgresUser, postgresPassword, postgresDatabaseName, postgresTableName, page, limit, databaseType, columnName, searchData)
        if responseStatus:
            logger.info("Fetched restore logs successfully.")
            return Response(response, status=status.HTTP_200_OK)
        else:
            logger.error("Failed to fetch restore logs.")
            return Response(response, status=status.HTTP_404_NOT_FOUND)


#Deletion classes
class DeletePostgresData(APIView):
    @swagger_auto_schema(
        operation_description="""Complete Deletion of POstgresql using POST request.
            1. This API endpoint allows you to delete complete POstgresql server.
            2. Valid Postgres credentials is required to initiate complete deletion. 
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
        
        if not isSuperuser:
            logger.warning(f'{userName}: do not have permission to proceed with complete deletion.')
            payload = {  
                "status":False,
                "message":"You don't have permission to proceed with complete deletion.",
                "data": None,
                "error": "You don't have permission to proceed with complete deletion.",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to proceed with complete deletion.")
        
        data = request.data
        
        postgresHost= data.get("postgres_host", None)
        postgresPort= data.get("postgres_port", None)
        postgresUser= data.get("postgres_user", None)
        postgresPassword= data.get("postgres_password", None)
        
        if(postgresHost==None or postgresPort==None or postgresUser==None or postgresPassword==None):
            logger.warning("Mandatory fields not provided")
            logger.error("Postgres credentials not provided for complete deletion")
            payload = {
                "status":False,
                "message":"Please provide postgres credentials for complete deletion",
                "data":None,
                "error":"Mandatory fields not provided"
            }
            return Response(payload, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        response = DeleteUserDatabases(postgresUser, postgresPassword, postgresHost, postgresPort)
        
        if response:
            logger.info("Complete deletion executed successfully for PostgresDb")
            payload = {
                "status" : True,
                "message" : "Complete deletion executed successfully for PostgresDb",
                "data" : None,
                "error" : None
            }
            return Response(payload, status=status.HTTP_200_OK)
        else:
            logger.error("Complete deletion failed for PostgresDb")
            payload = {
                "status" : False,
                "message" : "Complete Deletion failed for PostgresDb",
                "data" : None,
                "error" : None
            }
            return Response(payload, status=status.HTTP_400_BAD_REQUEST)

            
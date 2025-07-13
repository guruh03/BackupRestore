import datetime
import threading
from .utils import *
from Scylladb.utils import *
from django.db.models import Q
from Postgresdb.utils import *
from Postgresdb.views import *
from Postgresdb.models import *
from ElasticSearch.utils import *
from rest_framework import status
from Postgresdb.serializer import *
from MinioObjectStore.utils import *
from django.core.paginator import Paginator
from rest_framework.views import APIView
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema

# class PartialDeletion(APIView):
#     @swagger_auto_schema(
#         operation_description="""Start partial deletion using POST request.
#             This API endpoint allows you to delete file related data with certain scenarious.
#             1. If received file is cdr or ip data gets deleted from scylladb and minio.
#             2. If received file is apart from cdr or ip data gets deleted from elasticsearch and minio.
#             Note: This API requires systemadmin to proceed with partial deletion.
#         """,
#         operation_summary='Partial File Based Deletion',
#     )
#     def post(self, request):
        
#         apiData = UserAuthenticationFromUserManagement(request)
        
#         if isinstance(apiData, Response):
#             return apiData

#         isSuperuser = apiData['data'][0]['is_superuser']
#         userName = apiData['data'][0]['username']
#         userId = apiData['data'][0]['id']
        
#         fileIds = request.data.get("file_ids", [])

#         if (not isSuperuser):
#             logger.warning(f'{userName}: do not have permission for deletion')
#             payload = {  
#                 "status":False,
#                 "message":"You don't have permission for deletion",
#                 "data": None,
#                 "error": "You don't have permission for deletion",                
#             }
#             return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
#         logger.info(f"Permission granted for {userName} to proceed with deletion.")
        
#         fileNames = []
#         ingestiontype = []
#         response = QueryPostgres(fileIds)
#         for res in response:
#             fileNames.append(res['system_generated_filename'])
#             ingestiontype.append(res['ingestion_source'])

#         minioDelete = False
        
#         client = ConnectToMinio()
#         if client:
#             for name in fileNames:
#                 bucketName = name.split('__')[1]
#                 logger.info(f"Bucket Name: {bucketName}")

#                 folderName = name.rsplit('.', 1)[0]
#                 logger.info(f"Folder Name: {folderName}")

#                 if EnsureBucketExists(client, bucketName):
#                     logger.info(f"Bucket '{bucketName}' exists, listing objects in folder '{folderName}'.")
                    
#                     foundFolder = False
#                     for obj in client.list_objects(bucketName,  recursive=True):
#                         if folderName in obj.object_name:
#                             logger.info(f"Found object in folder '{folderName}': {obj.object_name}")
#                             foundFolder = True
#                             client.remove_object(bucketName, obj.object_name)
#                             logger.info(f"Removed object: {obj.object_name}")
#                             minioDelete = True
#                         # else:
#                         #     logger.warning(f"Skipping object: {obj.object_name}")
                    
#                     if not foundFolder:
#                         logger.error(f"No objects found in the folder '{folderName}' within the bucket '{bucketName}'.")
#                         payload = {
#                             "status":False,
#                             "message":f"No objects found in the folder '{folderName}' within the bucket '{bucketName}'.",
#                             "data" :None,
#                             "error":"Objects not found"
#                         }
#                         return Response(payload, status=status.HTTP_400_BAD_REQUEST)
#                 else:
#                     logger.error(f"Bucket '{bucketName}' does not exist.")
#                     payload = {
#                         "status":False,
#                         "message":f"Bucket '{bucketName}' does not exist",
#                         "data" :None,
#                         "error":None
#                     }
#                     return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
#         else:
#             logger.error("Connecting to Minio Failed")
#             payload = {
#                 "status":False,
#                 "message":"Error connecting to Minio",
#                 "error":None
#             }
#             return Response(payload, status=status.HTTP_404_NOT_FOUND)
        
#         if minioDelete:
        
#             for ingestionsource in ingestiontype:
#                 if ingestionsource in ("text", "web", "logs"):
#                     es = ConnectToElasticsearch()
#                     if es:
#                         if(FileNameSearchElastic(fileNames, es, ingestiontype)):
#                             logger.info("Deletion Done in Elasticsearch")
#                             time.sleep(1)
                        
#                         else:
#                             logger.error("Error occurred deleting in elasticsearch")
#                             payload = {
#                                 "status":False,
#                                 "message":"Error occurred deleting in elasticsearch",
#                                 "data":None,
#                                 "error":None
#                             }
#                             return Response(payload, status=status.HTTP_400_BAD_REQUEST) 
                    
#                     else:
#                         logger.error("Connecting to Elasticsearch Failed")
#                         payload = {
#                             "status":False,
#                             "message":"Connecting to Elasticsearch Failed",
#                             "data":None,
#                             "error":None
#                         }
#                         return Response(payload, status=status.HTTP_404_NOT_FOUND) 
                
#                 if ingestionsource in ("cdr","pcap","ip"):
#                     if ingestionsource == "cdr":
#                         session, cluster = ConnectToScylla(config['MSISDN_KEYSPACE'])
#                     elif ingestionsource in ("pcap","ip"):
#                         session, cluster = ConnectToScylla(config['IP_KEYSPACE'])
#                     else:
#                         logger.error(f"Unknown ingestion source: {ingestionsource}")
#                         return False
                    
#                     if session:
#                         for name in fileNames:
#                             result = FileNameDeleteScylla(f'{name}', session, cluster, config['MSISDN_KEYSPACE'] if ingestionsource == "cdr" else config['IP_KEYSPACE'])
#                             if not result:
#                                 logger.error("Failed to delete file from Scylla.")
#                     else:
#                         logger.error("Connecting to Scylla Failed")
#                         return False

#         else:
#             logger.error("Error occurred deleting in minio objects")
#             payload = {
#                 "status":False,
#                 "message":"Error occurred deleting in minio objects",
#                 "data":None,
#                 "error":None
#             }
#             return Response(payload, status=status.HTTP_400_BAD_REQUEST)
        
# Handles various file-related batch operations such as approval, deletion, and viewing pending requests.
class ApproveFiles(APIView):
    """Handles various file-related batch operations such as approval, deletion, and viewing pending requests."""
    @swagger_auto_schema(
        operation_description="""Send file for approval using POST request.
            This API endpoint allows you to approve file which is sent for deletion.
            1. If received file is cdr or ip data gets deleted from scylladb and minio.
            2. If received file is apart from cdr or ip data gets deleted from elasticsearch and minio.
            Note: This API requires systemadmin to proceed with partial deletion.
        """,
        operation_summary='Partial File Based Deletion',
    )
    def post(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
        
        if isinstance(apiData, Response):
            return apiData

        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        userId = apiData['data'][0]['id']
        
        data = request.data
        fileIds = data.get("file_ids",[])
        

        # if not isSuperuser:
        #     logger.warning(f'{userName}: do not have permission for deletion')
        #     payload = {  
        #         "status":False,
        #         "message":"You don't have permission for deletion",
        #         "data": None,
        #         "error": "You don't have permission for deletion",                
        #     }
        #     return Response(payload, status=status.HTTP_403_FORBIDDEN)

        createdFiles = []
    
        for fileId in fileIds:
            file_data = {
                'file_id': fileId.get('file_id'),
                'case_id': fileId.get('case_id'),
                'system_generated_filename': fileId.get("system_generated_filename"),
                'ingestion_source': fileId.get("ingestion_source"),
                'name': fileId.get("name"),
                'user_comment':fileId.get("user_comment"),
                'created_on': int(datetime.now().timestamp()),
                'updated_on': int(datetime.now().timestamp()),
                'created_by': userId,
                'updated_by': userId
            }
            
            serializer = DeletionRequestLogSerializer(data=file_data)
            if serializer.is_valid():
                serializer.save()  
                createdFiles.append(serializer.data)
                if not UpdateCmmUserUploadTable(fileIds=[file_data['file_id']], 
                                                fileStatus="Pending", 
                                                userComment=file_data['user_comment'],
                                                updatedOn=int(datetime.now().timestamp()),
                                                updatedBy=userId):
                    logger.error("Error updating status in Case Management UserUpload Table")
                
            else:
                logger.error(f"Failed to save deletion request for file {fileId}: {serializer.errors}")
                if not UpdateCmmUserUploadTable(fileIds=[file_data['file_id']], 
                                                fileStatus="N/A",
                                                updatedOn=int(datetime.now().timestamp()),
                                                updatedBy=userId):
                    logger.error("Error updating status in Case Management UserUpload Table")
                    
                payload = {
                    "status": False,
                    "message": f"Failed to save deletion request for file {fileId}",
                    "data": None,
                    "error": serializer.errors
                }
                return Response(payload, status=status.HTTP_400_BAD_REQUEST)

        payload = {
            "status": True,
            "message": "Files sent for approval",
            "data": createdFiles,
            "error": None,
        }
        return Response(payload, status=status.HTTP_201_CREATED)


    @swagger_auto_schema(
        operation_description="""View all pending request using GET request.
            This API endpoint allows you to fetch all pending file requests.
            1. Systemadmin can view files which is sent for deletion.
            2. File cannot be sent again for deletion once it is rejected.
            Note: This API requires systemadmin to proceed with approval or rejection.
        """,
        operation_summary='View pending request',
    )
    def get(self, request):
        apiData = UserAuthenticationFromUserManagement(request)
        
        if isinstance(apiData, Response):
            return apiData

        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        userId = apiData['data'][0]['id']
        
        if not isSuperuser:
            logger.warning(f'{userName}: do not have permission to view deletion log table')
            payload = {  
                "status":False,
                "message":"You don't have permission to view deletion log table",
                "data": None,
                "error": "You don't have permission to view deletion log table",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to view deletion logs.")
        
        params = request.query_params.dict()
        page = int(params.get("page", 1))
        limit = int(params.get("limit", 100000))
        columnName = params.get('column_name',None)
        searchData = params.get('search_data',None)
        
        files = DeletionRequestLog.objects.all()
        
        if files.count()==0:
            logger.warning(f"User: {userName} : File doesnot exists")
            payload = {
                "status": False,
                "message": "Files doesnot exists",
                "data": None,
                "error": "Files doesnot exists"
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)
        
        if (columnName!=None and searchData!=None):
            if columnName and columnName != "All":
                filterdData = {f"{columnName}__icontains": searchData}
                files = files.filter(**filterdData)
            else:
                files = files.filter(  
                    Q(file_id__icontains=searchData) |
                    Q(name__icontains=searchData) |
                    Q(user_comment__icontains=searchData) |
                    Q(admin_comment__icontains=searchData) |
                    Q(status__icontains=searchData) |
                    Q(system_generated_filename__icontains=searchData) |
                    Q(ingestion_source__icontains=searchData) 
                )  
        
        if files.count()==0:
            logger.info(f'User: {userName}: No Files found for search results')
            payload = {
                "status": False,
                "message": "No Files found for search results",
                "data": None,
                "error": None
            }
            return Response(payload, status=status.HTTP_404_NOT_FOUND)   
        
        paginator = Paginator(files.order_by('-created_on'), limit)
        resultPage = paginator.page(page)
        
        serializedData = GetDeletionRequestLogSerializer(resultPage , many=True).data

        userIds=set()
        for data in serializedData:
            userIds.update([data['created_by'], data['updated_by']])
            
        userNames = GetUser(list(userIds))
        for formattedData in serializedData:
            formattedData['created_by'] = userNames.get(formattedData['created_by'])
            formattedData['updated_by'] = userNames.get(formattedData['updated_by'])
            case = Case.objects.using('casedatabase').filter(id=formattedData['case_id']).first()
            if case:
                formattedData['case'] = {"id": case.id, "name": case.name}
            else:
                formattedData['case'] = None
            del formattedData['case_id']
            
        payload = {
            "status": True,
            "message": "Files Details Fetched Successfully",
            "data": serializedData,
            "error": None,
            "meta": {
                "page": resultPage.number,
                "limit": limit,
                "total": paginator.count
            }
        }
        return Response(payload,status=status.HTTP_200_OK)
    
    @swagger_auto_schema(
        operation_description="""Approve or reject file using PUT request.
            This API endpoint allows you to approve pending files.
            1. Systemadmin can approve or reject files which is sent for deletion.
            2. File cannot be sent again for deletion once it is rejected.
            Note: This API requires systemadmin to proceed with approval or rejection.
        """,
        operation_summary='Partial File Based Deletion',
    )
    def put(self, request):
        
        apiData = UserAuthenticationFromUserManagement(request)
        
        if isinstance(apiData, Response):
            return apiData

        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        userId = apiData['data'][0]['id']
        
        fileIds = request.data.get("file_ids", [])
        
        if (not isSuperuser):
            
            logger.warning(f'{userName}: do not have permission to approve/ reject files')
            payload = {  
                "status":False,
                "message":"You don't have permission to approve/ reject files",
                "data": None,
                "error": "You don't have permission to approve/ reject files",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to approve/ reject of files.")
        
        for file in fileIds:
            fileId = file.get("file_id")
            fileStatus = file.get("status").strip().capitalize()
            adminComment = file.get("admin_comment")    #BUG ID 1884: Deletion -Summary -File List
            userComment = file.get("user_comment")
            
            if fileStatus.lower() == "n/a":
                fileStatus = "N/A"
            
            if adminComment:
                DeletionRequestLog.objects.filter(file_id=fileId).update(status = fileStatus,
                                                                        admin_comment = adminComment, 
                                                                        updated_on = int(datetime.now().timestamp()),
                                                                        updated_by = userId)
            else:
                DeletionRequestLog.objects.filter(file_id=fileId).update(status = fileStatus,
                                                                        user_comment = userComment, 
                                                                        updated_on = int(datetime.now().timestamp()),
                                                                        updated_by = userId)
            
            if fileStatus == "Approved":
                if not UpdateCmmUserUploadTable(fileIds=[fileId], 
                                                fileStatus="Approved", 
                                                adminComment=adminComment,
                                                updatedOn=int(datetime.now().timestamp()),
                                                updatedBy=userId):
                    logger.error("Error updating status in Case Management UserUpload Table")
            
            elif fileStatus == "Rejected":
                if not UpdateCmmUserUploadTable(fileIds=[fileId], 
                                                fileStatus="Rejected", 
                                                adminComment=adminComment,
                                                updatedOn=int(datetime.now().timestamp()),
                                                updatedBy=userId):
                    logger.error("Error updating status in Case Management UserUpload Table")
            
            elif fileStatus == "N/A":
                if not UpdateCmmUserUploadTable(fileIds=[fileId], 
                                                fileStatus="N/A", 
                                                userComment=userComment,
                                                updatedOn=int(datetime.now().timestamp()),
                                                updatedBy=userId):
                    logger.error("Error updating status in Case Management UserUpload Table")
        
        logger.info(f"{userName}: updated file status")
        payload = {
            "status":True,
            "message":"File Status updated",
            "data":None,
            "error":None
        }
        return Response(payload, status=status.HTTP_200_OK)

# Handles requests to permanently delete all data associated with a service.    
class CompleteDeletion(APIView):
    """Handles requests to permanently delete all data associated with a service."""
    @swagger_auto_schema(
        operation_description="""Complete deletion using POST request.
            This API endpoint allows you to delete file related data with certain scenarious.
            1. If received file is cdr or ip data gets deleted from scylladb and minio.
            2. If received file is apart from cdr or ip data gets deleted from elasticsearch and minio.
            Note: This API requires systemadmin to proceed with partial deletion.
        """,
        operation_summary='Partial File Based Deletion',
    )
    def post(self, request):
        
        apiData = UserAuthenticationFromUserManagement(request)
        
        if isinstance(apiData, Response):
            return apiData

        isSuperuser = apiData['data'][0]['is_superuser']
        userName = apiData['data'][0]['username']
        
        if (not isSuperuser):
            logger.warning(f'{userName}: do not have permission for deletion')
            payload = {  
                "status":False,
                "message":"You don't have permission for deletion",
                "data": None,
                "error": "You don't have permission for deletion",                
            }
            return Response(payload, status=status.HTTP_403_FORBIDDEN)
        
        logger.info(f"Permission granted for {userName} to proceed with deletion.")
        
        data = request.data
        results = {
            'postgres': None,
            'scylla': None,
            'minio': None,
            'elastic': None
        }
        
        postgresHost = data.get("postgres_host",None)
        postgresPort = data.get("postgres_port",None)
        postgresUser = data.get("postgres_user",None)
        postgresPassword = data.get("postgres_password",None)
        
        scyllaHost = data.get('scylla_host',None)
        scyllaPort = data.get('scylla_port',None)
        scyllaUser = data.get('scylla_user',None)
        scyllaPassword = data.get('scylla_password',None)
        
        minioEndpoint = data.get('minio_endpoint',None)
        minioAccessKey = data.get('minio_access_key',None)
        minioSecretKey = data.get('minio_secret_key',None)
        bucketName = data.get('bucket_name',None)
        
        elasticUrl = data.get('elastic_url',None)
        elasticUsername = data.get('elastic_user',None)
        elasticPassword = data.get('elastic_password',None)
        
        def DeletePostgres():
            try:
                result = DeleteUserDatabases(postgresUser, postgresPassword, postgresHost, postgresPort)
                if result:
                    logger.info("Successfully deleted Postgres data.")
                    results['postgres'] = result
                else:
                    logger.error("Failed to delete Postgres data.")
                    results['postgres'] = False
            except Exception as e:
                logger.error(f"Exception in Postgres deletion: {e}")
                results['postgres'] = False
        
        def DeleteScylla():
            try:
                result = DeleteUserKeyspaces(scyllaHost, scyllaPort, scyllaUser, scyllaPassword)
                if result:
                    logger.info("Successfully deleted Scylla data.")
                    results['scylla'] = result
                else:
                    logger.error("Failed to delete Scylla data.")
                    results['scylla'] = False
            except Exception as e:  
                logger.error(f"Exception in Scylla deletion: {e}")
                results['scylla'] = False
        
        def DeleteMinio():
            try:
                client = InitializeClient(minioEndpoint, minioAccessKey, minioSecretKey)
                if client:
                    result = DeleteUserBuckets(client, bucketName)
                    if result:
                        results['minio'] = result
                        logger.info("Successfully deleted Minio data.")
                    else:
                        logger.error("Failed to delete Minio data.")
                        results['minio'] = False
                else:
                    logger.error("Failed to connect to Minio.")
                    results['minio'] = False
            except Exception as e:
                logger.error(f"Exception in Minio deletion: {e}")
                results['minio'] = False
        
        def DeleteElastic():
            try:
                es = (ConnectToElasticsearch(elasticUrl, elasticUsername, elasticPassword))
                if es:
                    result = DeleteUserIndices(es)
                    if result:
                        logger.info("Successfully deleted ElasticSearch data.")
                        results['elastic'] = result
                    else:
                        logger.error("Failed to delete ElasticSearch data.")
                        results['elastic'] = False
                else:
                    logger.error("Failed to connect to ElasticSearch.")
                    results['elastic'] = False
            except Exception as e:
                logger.error(f"Exception in ElasticSearch deletion: {e}")
                results['elastic'] = False
        
        def StartDeletion():
        
            threads = [
                threading.Thread(target=DeletePostgres,daemon=True),
                threading.Thread(target=DeleteScylla, daemon=True),
                threading.Thread(target=DeleteMinio, daemon=True),
                threading.Thread(target=DeleteElastic, daemon=True),
            ]
            
            for t in threads:
                t.start()
            
            # Wait for all threads to finish
            for t in threads:
                t.join()

            # Check if any failed
            for key, success in results.items():
                if not success:
                    payload ={
                        "status": False,
                        "message": f"Error occurred deleting in {key}",
                        "data": None
                    }
                    return Response(payload, status=status.HTTP_400_BAD_REQUEST)
            
            logger.info("All user data deleted successfully")

        mainThread = threading.Thread(target=StartDeletion, daemon=True)
        mainThread.start()
        payload = {
            "status": True,
            "message": "Deletion process started. This operation may take some time depending on data size. Please refer to the logs to track progress and completion status.",
            "data": None,
            "error": None
        }
        return Response(payload, status=status.HTTP_202_ACCEPTED)
        
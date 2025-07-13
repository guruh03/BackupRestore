import time
import threading
from Deletion.utils import *
from datetime import datetime, timedelta
# from django.core.management.base import BaseCommand
from Postgresdb.models import DeletionRequestLog

def DeleteFromMinio(minioClient, filename):
    try:
        bucketName = filename.split('__')[1]
        folderName = filename.rsplit('.', 1)[0]
        
        logger.info("Recieved Folder: "+ folderName)
        
        if not EnsureBucketExists(minioClient, bucketName):
            logger.error(f"Bucket '{bucketName}' does not exist.")
            return
        
        foundFolder = False
        for obj in minioClient.list_objects(bucketName, recursive=True, include_version=True):
            if folderName in obj.object_name:
                logger.info(f"Found object in folder '{folderName}': {obj.object_name}")
                foundFolder = True
                minioClient.remove_object(bucketName, obj.object_name, version_id=obj._version_id)
                logger.info(f"Removed object: {obj.object_name}")
        
        if not foundFolder:
            logger.info(f"No objects found in the folder '{folderName}'.")
            return    

    except Exception as e:
        logger.error(f"Error deleting from MinIO for filename '{filename}': {str(e)}")

# class Command(BaseCommand):
#     def handle(self, *args, **kwargs):
#         try:
#             maxDays = int(configg['RETAIN_FILES_MAX_DAYS'])
#             retentionPeriod = maxDays * 24 * 60 * 60
#             currentTimestamp = int(time.time())
#             expirationTimestamp = currentTimestamp - retentionPeriod
            
#             pendingRequests = DeletionRequestLog.objects.filter(status="Approved")#, created_on__lt=expirationTimestamp)

#             if(pendingRequests.count()==0):
#                 logger.info("No pending deletion requests found.")
#                 return

#             # Connect to MinIO
#             minioClient = ConnectToMinio()
#             if not minioClient:
#                 logger.error("Failed to connect to MinIO.")
#                 return

#             for request in pendingRequests:
#                 fileId = request.file_id
#                 filename = request.system_generated_filename
#                 ingestionSource = request.ingestion_source

#                 logger.info(f"Processing deletion for File ID: {fileId}, Filename: {filename}, Ingestion Source: {ingestionSource}")

#                 try:
#                     DeleteFromMinio(minioClient, filename)

#                     if ingestionSource in ("text", "web", "logs"):
#                         esClient = ConnectToElasticsearch()
#                         if esClient:
#                             FileNameSearchElastic([filename], esClient, [ingestionSource])
#                             # time.sleep(10)
#                             logger.info(f"Deleted Elasticsearch entries for filename: {filename}")
#                         else:
#                             logger.error("Failed to connect to Elasticsearch")
#                             return

#                     elif ingestionSource in ("cdr", "pcap", "ip"):
#                         logger.info("ingestion Source: "+ingestionSource)
#                         keyspace = configg['MSISDN_KEYSPACE'] if ingestionSource == "cdr" else configg['IP_KEYSPACE']
#                         session, cluster = ConnectToScylla(keyspace)
#                         if session:
#                             FileNameDeleteScylla(filename, session, cluster, keyspace)
#                             logger.info(f"Deleted ScyllaDB entries for filename: {filename}")
#                         else:
#                             logger.error("Failed to connect to ScyllaDB")
#                             return

#                     request.status = "Deleted"
#                     request.updated_on = int(datetime.now().timestamp())
#                     request.save()
#                     logger.info(f"Deletion completed for File ID: {fileId}")
                    
#                     if not UpdateCmmUserUploadTable([fileId], "Deleted"):
#                         logger.error("Error updating status in Case Management UserUplaod Table")
#                         return

#                 except Exception as e:
#                     logger.error(f"Error processing deletion for File ID: {fileId} - {str(e)}")
#                     request.status = "Failed"
#                     request.updated_on = int(datetime.now().timestamp())
#                     request.save()
                    
#                     if not UpdateCmmUserUploadTable([fileId], "Failed"):
#                         logger.error("Error updating status in Case Management UserUplaod Table")
#                         return
#         except Exception as e:
#             logger.error(f"Error in deletion requests: {str(e)}")
#             return

def ProcessDeletion():
    while True:
        try:
            deletionIntervalMinutes = configg['DELETION_SCRIPT_INTERVAL']
            deletionInterval = deletionIntervalMinutes * 60
            pendingRequests = DeletionRequestLog.objects.filter(status="Approved")

            if(pendingRequests.count()==0):
                logger.info("No pending deletion requests found.")
                # return

            # Connect to MinIO
            minioClient = ConnectToMinio()
            if not minioClient:
                logger.error("Failed to connect to MinIO.")
                return

            for request in pendingRequests:
                fileId = request.file_id
                filename = request.system_generated_filename
                ingestionSource = request.ingestion_source

                logger.info(f"Processing deletion for File ID: {fileId}, Filename: {filename}, Ingestion Source: {ingestionSource}")

                try:
                    DeleteFromMinio(minioClient, filename)

                    if ingestionSource in ("text", "web", "logs"):
                        esClient = ConnectToElasticsearch()
                        if esClient:
                            FileNameSearchElastic([filename], esClient, [ingestionSource])
                            # time.sleep(10)
                            logger.info(f"Deleted Elasticsearch entries for filename: {filename}")
                        else:
                            logger.error("Failed to connect to Elasticsearch")
                            return

                    elif ingestionSource in ("cdr", "pcap", "ip"):
                        logger.info(f"ingestion Source: {ingestionSource}")
                        keyspace = configg['MSISDN_KEYSPACE'] if ingestionSource == "cdr" else configg['IP_KEYSPACE']
                        session, cluster = ConnectToScylla(keyspace)
                        if session:
                            FileNameDeleteScylla(filename, session, cluster, keyspace)
                            logger.info(f"Deleted ScyllaDB entries for filename: {filename}")
                        else:
                            logger.error("Failed to connect to ScyllaDB")
                            return

                    request.status = "Deleted"
                    request.updated_on = int(datetime.now().timestamp())
                    request.save()
                    logger.info(f"Deletion completed for File ID: {fileId}")
                    
                    deletedOn = int(datetime.now().timestamp())
                    
                    if not UpdateCmmUserUploadTable(fileIds=[fileId], fileStatus="Deleted", deletedOn=deletedOn):
                        logger.error("Error updating status in Case Management UserUplaod Table")
                        return

                except Exception as e:
                    logger.error(f"Error processing deletion for File ID: {fileId} - {str(e)}")
                    request.status = "Failed"
                    request.updated_on = int(datetime.now().timestamp())
                    request.save()
                    
                    if not UpdateCmmUserUploadTable(fileIds=[fileId], fileStatus="Failed"):
                        logger.error("Error updating status in Case Management UserUplaod Table")
                        return

        except Exception as e:
            logger.error(f"Error in deletion requests: {str(e)}")
        
        logger.info(f"Sleeping for {deletionIntervalMinutes} minutes before the next check...")
        time.sleep(deletionInterval)

thread = threading.Thread(target=ProcessDeletion, daemon=True)
thread.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    logger.info("Stopping deletion process...")
          
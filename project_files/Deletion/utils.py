import os
import urllib3
import requests
import threading
import psycopg2
import pandas as pd
from minio import Minio
from LoggConfig import *
from minio import S3Error
from dotenv import load_dotenv
from Postgresdb.models import *
from rest_framework import status
from Postgresdb.serializer import *
from cassandra.cluster import Cluster
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError
from rest_framework.response import Response
from cassandra.auth import PlainTextAuthProvider

load_dotenv()

configg = {
    # LogConfig
    "LOG_PATH":os.getenv("LOG_PATH"),
    "LOG_LEVEL": os.getenv("LOG_LEVEL").split(","),
    "SERVICE_NAME":os.getenv("SERVICE_NAME"),
    "SERVICE_ID":"Deletion",
    "CONSOLE_LOGS_ENABLED":os.getenv("CONSOLE_LOGS_ENABLED"),
    
    # Postgres
    "POSTGRESQL_HOST":os.getenv("POSTGRESQL_HOST"),
    "POSTGRESQL_PORT":os.getenv("POSTGRESQL_PORT"),
    "POSTGRESQL_USER":os.getenv("POSTGRESQL_USER"),
    "POSTGRESQL_PASSWORD":os.getenv("POSTGRESQL_PASSWORD"),
    "POSTGRESQL_DATABASE":os.getenv("POSTGRESQL_DATABASE"),
    "POSTGRESQL_TABLENAME":os.getenv("POSTGRESQL_TABLENAME"),
    
    # Minio
    "MINIO_HOST":os.getenv("MINIO_HOST"),
    "MINIO_PORT":os.getenv("MINIO_PORT"),
    "MINIO_USER":os.getenv("MINIO_USER"),
    "MINIO_PASSWORD":os.getenv("MINIO_PASSWORD"),
    "MINIO_SECURE":os.getenv("MINIO_SECURE"),
    
    # Elasticsearch
    "ELASTICSEARCH_HOST":os.getenv("ELASTICSEARCH_HOST"),
    "ELASTICSEARCH_PORT":os.getenv("ELASTICSEARCH_PORT"),
    "PDF":os.getenv("PDF"),
    "WEBSCRAPPING":os.getenv("WEBSCRAPPING"),
    "FILEBEAT":os.getenv("FILEBEAT"),
    "BLOCKCHAIN":os.getenv("BLOCKCHAIN"),
    "WIKIPEDIA":os.getenv("WIKIPEDIA"),
    "ELASTICSEARCH_AUTHENTICATION_ENABLED":os.getenv("ELASTICSEARCH_AUTHENTICATION_ENABLED"),
    "ELASTICSEARCH_USERNAME":os.getenv("ELASTICSEARCH_USERNAME"),
    "ELASTICSEARCH_PASSWORD":os.getenv("ELASTICSEARCH_PASSWORD"),
    
    # Scylla
    "SCYLLA_HOST":os.getenv("SCYLLA_HOST"),
    "SCYLLA_PORT":os.getenv("SCYLLA_PORT"),
    "MSISDN_KEYSPACE":os.getenv("MSISDN_KEYSPACE"),
    "MSISDN_TABLE_CALLING_MSISDN":os.getenv("MSISDN_TABLE_CALLING_MSISDN"),
    "MSISDN_TABLE_CALLED_MSISDN":os.getenv("MSISDN_TABLE_CALLED_MSISDN"),
    "MSISDN_TABLE_IMEI":os.getenv("MSISDN_TABLE_IMEI"),
    "MSISDN_TABLE_IMSI":os.getenv("MSISDN_TABLE_IMSI"),
    "MSISDN_TABLE_FILENAME":os.getenv("MSISDN_TABLE_FILENAME"),
    "IP_KEYSPACE":os.getenv("IP_KEYSPACE"),
    "IP_TABLE_SRC":os.getenv("IP_TABLE_SRC"),
    "IP_TABLE_DST":os.getenv("IP_TABLE_DST"),
    "IP_TABLE_PORT":os.getenv("IP_TABLE_PORT"),
    "GEOHASH_TABLE_SRC":os.getenv("GEOHASH_TABLE_SRC"),
    "GEOHASH_TABLE_DST":os.getenv("GEOHASH_TABLE_DST"),
    "IP_TABLE_FILE_BASED":os.getenv("IP_TABLE_FILE_BASED"),
    "SCYLLA_AUTHENTICATION_ENABLED":os.getenv("SCYLLA_AUTHENTICATION_ENABLED"),
    "SCYLLA_USERNAME":os.getenv("SCYLLA_USERNAME"),
    "SCYLLA_PASSWORD":os.getenv("SCYLLA_PASSWORD"),
    
    "SSH_TIMEOUT":int(os.getenv("SSH_TIMEOUT")),
    
    "DELETION_SCRIPT_INTERVAL":int(os.getenv("DELETION_SCRIPT_INTERVAL_IN_MINUTES")),
}

# Initialize the local logger instance
logclass = LocalLogger(configg)
logger = logclass.createLocalLogger()

# Validate configuration values, exit if any required key is missing or empty
for key, value in configg.items():
    if(value==None or value =='' or value==['']):
        print("Please Provide:",key)
        logger.warning(f"Please Provide: {key}")
        exit()

# Authenticate user by validating credentials via the UserManagement service.
def UserAuthenticationFromUserManagement(request):
    """Authenticate user by validating credentials via the UserManagement service."""
    try:
        UserManagementEndpoint = os.environ.get('API_URL_ENDPOINT')  
        UserManagementURL = os.environ.get('API_URL')
        if (not UserManagementURL) and (not UserManagementURL): 
            return Response({"message" : "Cannot find User Management Environment Variables"},status=status.HTTP_404_NOT_FOUND)

        authHeader = request.META.get('HTTP_AUTHORIZATION')
        if not authHeader:
            logger.error("Token Not Found")
            return Response({"message" : "Token Not Found"},status=status.HTTP_400_BAD_REQUEST)

        token = authHeader.split()[1]
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }

        apiUrl = UserManagementEndpoint + UserManagementURL
        response = requests.get(apiUrl, headers=headers, timeout=configg['SSH_TIMEOUT'])
        if response.status_code == 200:
            logger.info("Token Validated Succesfully")
            return response.json()
        if response.status_code==401:
            logger.error("Invalid token")
            return Response({"message" : "Invalid token"},status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({"message" : "Error in fetching details from UserManagement"},status=status.HTTP_400_BAD_REQUEST)
    
    except requests.Timeout:
        logger.error(f"Thread {threading.current_thread().name}: Timeout - The request to User Management API timed out.")
        return Response({"message": f"Error in calling User Management API"}, status=status.HTTP_408_REQUEST_TIMEOUT)
    except Exception as e:
        logger.error(f"Thread {threading.current_thread().name}: Error in calling User Management API: {str(e)}")
        return Response({"message": f"Error in calling User Management API: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

# Postgres functions
def ConnectToPostgresDb():
    postgresHost = configg['POSTGRESQL_HOST']
    postgresPort = configg['POSTGRESQL_PORT']
    databaseName = configg['POSTGRESQL_DATABASE']
    userName = configg['POSTGRESQL_USER']
    password = configg['POSTGRESQL_PASSWORD']
    
    try:
        conn = psycopg2.connect(
            dbname = databaseName,
            user = userName,
            password = password,
            host = postgresHost,
            port = int(postgresPort)
        )
        logger.info("Connection successful!.")
        return conn
    except Exception as e:
        logger.error("Connection failed: " +str(e))
        return False
def QueryPostgres(fileIds):
    
    try:
        results = DeletionRequestLog.objects.filter(file_id__in=fileIds).values('ingestion_source', 'system_generated_filename', 'file_id', 'status')

        if results:
            logger.info(f"Fetched {len(results)} records from the DeletionRequestLog model.")
        else:
            logger.info("No records found for the provided file_ids.")
    
    except Exception as e:
        logger.error(f"Error fetching records from DeletionRequestLog: {e}")
        return []

    return results
def UpdateCmmUserUploadTable(fileIds, fileStatus, deletedOn=None, adminComment=None, userComment=None, updatedOn=None, updatedBy=None):
    tableName = configg['POSTGRESQL_TABLENAME']
    
    try:
        connection = ConnectToPostgresDb()
        if connection:
            connection.autocommit = True
            
            cursor  = connection.cursor()

            if isinstance(fileIds, list) and fileIds:
                placeholders = ', '.join(['%s'] * len(fileIds))
                setClauses = ['deletion_status = %s', 'deleted_on = %s']
                params = [fileStatus, deletedOn]

                if adminComment is not None:
                    setClauses.append('admin_comment = %s')
                    params.append(adminComment)
                if userComment is not None:
                    setClauses.append('user_comment = %s')
                    params.append(userComment)
                if updatedOn is not None:
                    setClauses.append('updated_on = %s')
                    params.append(updatedOn)
                if updatedBy is not None:
                    setClauses.append('updated_by = %s')
                    params.append(updatedBy)

                setClause = ', '.join(setClauses)

                query = f'''
                    UPDATE "{tableName}"
                    SET {setClause}
                    WHERE file_id IN ({placeholders})
                '''
                params.extend(fileIds)
                logger.debug("query: %s", query)
                # logger.debug("params: %s", params)
                
                cursor.execute(query, tuple(params))
            
            cursor.close()
            connection.close()
            
        else:
            logger.error("Failed to connect to PostgreSQL.")
            return False        
        
    except Exception as e:
        logger.error(f"Error updating records to RDBMS: {e}")
        return False
    
    return True

# Minio Functions
def ConnectToMinio():
    minioHost = configg['MINIO_HOST']
    minioPort = configg['MINIO_PORT']
    username = configg['MINIO_USER']
    password = configg['MINIO_PASSWORD']

    try:
        minioEndpoint = f"{minioHost}:{minioPort}"
        if configg['MINIO_SECURE'].lower().strip() == 'true':
            minioSecure = True
            http_client = urllib3.PoolManager(cert_reqs='CERT_NONE')
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        else:
            minioSecure = False
            http_client = None
            
        client = Minio(
            endpoint=minioEndpoint,
            access_key=username,
            secret_key=password,
            secure=minioSecure,
            http_client=http_client
        )
        client.list_buckets()
        return client
    except S3Error as e:
        logger.error("MinIO S3Error: " +str(e))
        return False
    except Exception as e:
        logger.error("Error initializing MinIO client: " +str(e))
        return False
def EnsureBucketExists(client, name):
    try:
        if client.bucket_exists(name):
            logger.info(f"Bucket '{name}' exists.")
            return True
        else:        
            return False
    except Exception as e:
        logger.error(f"Error ensuring bucket '{name}' exists: {e}")
        return False

# Elastic Functions
def ConnectToElasticsearch():
    elasticHost = configg['ELASTICSEARCH_HOST']
    elasticPort = configg['ELASTICSEARCH_PORT']
    
    elasticUrl = f"{elasticHost}:{elasticPort}"
    
    if configg["ELASTICSEARCH_AUTHENTICATION_ENABLED"].lower().strip() == 'true':
        es = Elasticsearch(f'http://{elasticUrl}',basic_auth=(configg['ELASTICSEARCH_USERNAME'], configg['ELASTICSEARCH_PASSWORD']), verify_certs=False)
    else:
        es = Elasticsearch(f'http://{elasticUrl}')
                           
    if (es.ping()):
        logger.info("Connected to Elasticsearch successfully!")
        return es
    else:
        logger.error("Failed to connect to Elasticsearch.")
        return False
def FileNameSearchElastic(fileNames, es, ingestiontype):
    
    indexNames = []
    for ingestionsource in ingestiontype:
        if (ingestionsource == "text"):
            indexNames.append(configg['PDF'])
        
        elif(ingestionsource == "web"):
            indexNames.append(configg['WEBSCRAPPING'])
        
        elif(ingestionsource == "logs"):
            indexNames.append(configg['FILEBEAT'])
            
        # elif(ingestionsource == "blockchain"):
        #     indexName = configg['BLOCKCHAIN']
        
        # elif(ingestionsource == "wikipedia"):
        #     indexName = configg['WIKIPEDIA']
    
    for file_name in fileNames:
        query = {
            "query": {
                "match": {
                    "FileName": file_name 
                }
            }
        }
        
        for indexName in indexNames:
            try:
                # block used to view data for given filename
                # response = es.search(index=indexName, body=query)
                # Check if we have hits in the response
                # if response['hits']['total']['value'] > 0:
                #     for hit in response['hits']['hits']:
                #         print(f"Found document for file: {file_name}")
                #         print("Document Data:")
                #         print(hit["_source"])
                
                response = es.delete_by_query(index=indexName, body=query)
                if response['deleted'] > 0:
                    logger.info(f"Successfully deleted {response['deleted']} document(s) for file: {file_name}")
                else:
                    logger.error(f"No documents found to delete for file: {file_name}")

            except NotFoundError as e:
                logger.error(f"Error: Index '{indexName}' not found. Please check the index name.")
                return False

            except Exception as e:
                logger.error(f"Error occurred while deleting file {file_name}: {str(e)}")
                return False
            
        return True

# Scylla Functions
def ConnectToScylla(keyspace):
    scyllaHost = configg['SCYLLA_HOST']
    scyllaPort = configg['SCYLLA_PORT']
    username = configg['SCYLLA_USERNAME']
    password = configg['SCYLLA_PASSWORD']
    
    try:
        if configg["SCYLLA_AUTHENTICATION_ENABLED"].lower().strip() == 'true':
            authProvider = PlainTextAuthProvider(username, password)
            cluster = Cluster([scyllaHost], port=int(scyllaPort), auth_provider=authProvider)
        else:
            cluster = Cluster([scyllaHost], port=int(scyllaPort))
        
        session = cluster.connect(keyspace)
        logger.info("Scylla connection established.")
        return session, cluster
    except Exception as e:
        logger.error("Connection failed: " +str(e))
        return False        
def GetColumns(session, keyspace, table):
    query = f"SELECT column_name FROM system_schema.columns WHERE keyspace_name = '{keyspace}' AND table_name = '{table}'"
    rows = session.execute(query)
    columns = [row.column_name for row in rows]
    return columns
def ShutDownScylla(cluster, session):
    cluster.shutdown()
    session.shutdown()
def FileNameDeleteScylla(filename, session, cluster, keyspace):
    if session is None or cluster is None:
        logger.error("Invalid session or cluster. Aborting operation.")
        return False
    
    if keyspace == configg['MSISDN_KEYSPACE']:
        filename = filename.split('.')[0]
        try:
            query = f"SELECT calling_msisdn, called_msisdn, imei, imsi, record_month_year, record_timestamp, is_private, filename FROM {keyspace}.{configg['MSISDN_TABLE_FILENAME']} WHERE filename = '{filename}' ALLOW FILTERING;"
            rows = session.execute(query)
            df = pd.DataFrame(rows)
            
            df['record_month_year'] = pd.to_datetime(df['record_timestamp'], unit='s').dt.strftime("%m-%Y")
            # print(df)
            
        except Exception as e:
            logger.error(f"Failed to fetch data from table {configg['MSISDN_TABLE_FILENAME']}: {str(e)}")
            ShutDownScylla(cluster, session)
            return False
        
        tablesToCheck = [
            configg['MSISDN_TABLE_CALLING_MSISDN'],
            configg['MSISDN_TABLE_CALLED_MSISDN'], 
            configg['MSISDN_TABLE_IMEI'],
            configg['MSISDN_TABLE_IMSI'],
            # configg['MSISDN_TABLE_FILENAME']
        ]
        
        for table in tablesToCheck:
            for index, row in df.iterrows():
                condition = f"filename = '{row['filename']}'"
                
                if pd.isna(row['record_month_year']):
                    condition += " AND record_month_year IS NULL"
                else:
                    condition += f" AND record_month_year = '{row['record_month_year']}'"
                
                if table == configg['MSISDN_TABLE_CALLING_MSISDN']:
                    condition += f" AND calling_msisdn = '{row['calling_msisdn']}' AND record_timestamp = {row['record_timestamp']} AND is_private = {row['is_private']}"
                
                elif table == configg['MSISDN_TABLE_CALLED_MSISDN']:
                    condition += f" AND called_msisdn = '{row['called_msisdn']}' AND record_timestamp = {row['record_timestamp']} AND is_private = {row['is_private']}"
                
                elif table == configg['MSISDN_TABLE_IMEI']:
                    condition += f" AND imei = '{row['imei']}' AND record_timestamp = {row['record_timestamp']} AND is_private = {row['is_private']}"
                
                elif table == configg['MSISDN_TABLE_IMSI']:
                    condition += f" AND imsi = '{row['imsi']}' AND record_timestamp = {row['record_timestamp']} AND is_private = {row['is_private']}"
                    
                # elif table == configg['MSISDN_TABLE_FILENAME']:
                #     condition = f"filename = '{row['filename']}'"
                
                logger.info(f"Executing DELETE query: DELETE FROM {table} WHERE {condition};")
                
                try:
                    session.execute(f"DELETE FROM {table} WHERE {condition} ;")
                    logger.info(f"Successfully deleted from {table} where {condition}")
                except Exception as e:
                    logger.error(f"Failed to delete from {table}: {str(e)}")
                    continue
        
        try:
            session.execute(f"DELETE FROM {configg['MSISDN_TABLE_FILENAME']} WHERE filename = '{filename}' ;")
            logger.info(f"Successfully deleted from {configg['MSISDN_TABLE_FILENAME']} WHERE filename = '{filename}' ")
        except Exception as e:
            logger.error(f"Failed to delete from {table}: {str(e)}")

    elif keyspace == configg['IP_KEYSPACE']:
        try:
            query = f"SELECT source_ip, destination_ip, source_geohash, destination_geohash, record_month_year, start_time_stamp, source_ip, source_port, destination_ip, file_name, is_private FROM {keyspace}.{configg['IP_TABLE_FILE_BASED']} WHERE file_name = '{filename}' ALLOW FILTERING;"
            rows = session.execute(query)
            df = pd.DataFrame(rows)
            # print(df)
            # df['record_month_year'] = pd.to_datetime(df['start_time_stamp'], unit='s').dt.strftime("%m%Y")
            
        except Exception as e:
            logger.error(f"Failed to fetch data from table {configg['IP_TABLE_FILE_BASED']}: {str(e)}")
            ShutDownScylla(cluster,session)
            return False
        
        tablesToCheck = [
            configg['IP_TABLE_SRC'],
            configg['IP_TABLE_DST'], 
            # configg['IP_TABLE_PORT'],
            configg['GEOHASH_TABLE_SRC'],
            configg['GEOHASH_TABLE_DST'],
            # configg['IP_TABLE_FILE_BASED']
        ]
        
        for table in tablesToCheck:
            for index, row in df.iterrows():
                condition = f"file_name = '{row['file_name']}'"

                if pd.isna(row['record_month_year']):
                    condition += " AND record_month_year IS NULL"
                else:
                    condition += f" AND record_month_year = '{row['record_month_year']}'"

                if table == configg['IP_TABLE_SRC']:
                    condition += f" AND source_ip = '{row['source_ip']}' AND start_time_stamp = {row['start_time_stamp']} AND is_private = {row['is_private']}"
                
                elif table == configg['IP_TABLE_DST']:
                    condition += f" AND destination_ip = '{row['destination_ip']}' AND start_time_stamp = {row['start_time_stamp']} AND is_private = {row['is_private']}"
                
                # elif table == configg['IP_TABLE_PORT']:
                #     condition += f" AND destination_port = {row['destination_port']} AND start_time_stamp = {row['start_time_stamp']} AND source_ip = '{row['source_ip']}' AND source_port = {row['source_port']} AND destination_ip = '{row['destination_ip']}'"
                
                elif table == configg['GEOHASH_TABLE_SRC']:
                    condition += f" AND source_geohash = '{row['source_geohash']}' AND start_time_stamp = {row['start_time_stamp']} AND is_private = {row['is_private']}"
                
                elif table == configg['GEOHASH_TABLE_DST']:
                    condition += f" AND destination_geohash = '{row['destination_geohash']}' AND start_time_stamp = {row['start_time_stamp']} AND is_private = {row['is_private']}"
                
                # elif table == configg['IP_TABLE_FILE_BASED']:
                #     condition = f"file_name = '{row['file_name']}'"
                
                logger.info(f"Executing DELETE query: DELETE FROM {table} WHERE {condition};")
                
                # select_query = f"SELECT count(*) FROM {table} WHERE {condition} ALLOW FILTERING"
                try:
                    # select_rows = session.execute(select_query)
                    # count = select_rows[0].count
                    # print("ccccccccc",count)

                    session.execute(f"DELETE FROM {table} WHERE {condition} ;")
                    logger.info(f"Successfully deleted from {table} where {condition}")

                except Exception as e:
                    logger.error(f"Failed to check or delete from {table}: {str(e)}")
                    continue
        
        try:
            session.execute(f"DELETE FROM {configg['IP_TABLE_FILE_BASED']} WHERE file_name = '{filename}' ;")
            logger.info(f"Successfully deleted from {configg['IP_TABLE_FILE_BASED']} WHERE file_name = '{filename}' ")
        except Exception as e:
            logger.error(f"Failed to delete from {table}: {str(e)}")

    return True

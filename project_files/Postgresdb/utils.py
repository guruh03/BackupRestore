import os
import re
import requests
import paramiko
import datetime
import psycopg2
import threading
import subprocess
from .views import *
from LoggConfig import *
from .serializer import *
from dotenv import load_dotenv
from rest_framework import status
from psycopg2 import OperationalError
from psycopg2.extras import RealDictCursor
from rest_framework.response import Response

load_dotenv()

config = {
    "LOG_PATH":os.getenv("LOG_PATH"),
    "LOG_LEVEL": os.getenv("LOG_LEVEL").split(','),
    "SERVICE_NAME":os.getenv("SERVICE_NAME"),
    "SERVICE_ID":"PostgreSql",
    "CONSOLE_LOGS_ENABLED":os.getenv("CONSOLE_LOGS_ENABLED"),
    "POSTGRESQL_CMM_NAME":os.getenv("POSTGRESQL_CMM_NAME"),
    "POSTGRESQL_MM_NAME":os.getenv("POSTGRESQL_MM_NAME"),
    "POSTGRESQL_UMM_NAME":os.getenv("POSTGRESQL_UMM_NAME"),
    "POSTGRESQL_INGESTION_LOGS":os.getenv("POSTGRESQL_INGESTION_LOGS"),
    "POSTGRESQL_NAME":os.getenv("POSTGRESQL_NAME"),
    "POSTGRESQL_USER":os.getenv("POSTGRESQL_USER"),
    "POSTGRESQL_PASSWORD":os.getenv("POSTGRESQL_PASSWORD"),
    "POSTGRESQL_HOST":os.getenv("POSTGRESQL_HOST"),
    "POSTGRESQL_PORT":os.getenv("POSTGRESQL_PORT"),
    "POSTGRESQL_DATA_DIR":os.getenv("POSTGRESQL_DATA_DIR"),
    "POSTGRESQL_RESTORE_LOG_DATABASE_NAME":os.getenv("POSTGRESQL_RESTORE_LOG_DATABASE_NAME"),
    "POSTGRESQL_RESTORE_LOG_TABLE_NAME":os.getenv("POSTGRESQL_RESTORE_LOG_TABLE_NAME"),
    "LOCAL_POSTGRESQL_HOST":os.getenv("LOCAL_POSTGRESQL_HOST"),
    "LOCAL_POSTGRESQL_VM_USER":os.getenv("LOCAL_POSTGRESQL_VM_USER"),
    "LOCAL_POSTGRESQL_VM_PASSWORD":os.getenv("LOCAL_POSTGRESQL_VM_PASSWORD"),
    "SSH_TIMEOUT":int(os.getenv("SSH_TIMEOUT")),
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

def GetUser(userId):
    try:
        apiUrl = os.environ.get('API_URL_ENDPOINT') + os.environ.get('API_URL1')
        userData = {
                    "user_ids": userId,
                    }
        headers = {
            "Content-Type": "application/json"
        }
        response = requests.get(apiUrl, json=userData, headers=headers, timeout=config['SSH_TIMEOUT'])

        if response.status_code==200:
            logger.info(f"{threading.current_thread().name}: Calling User API =====> Response: {(response.status_code)}")
        else:    
            logger.error(f"{threading.current_thread().name}: Error in calling User API =====> Response: {(response.status_code)}")
        
        res = response.json()
        usernames = {}  
        for userId, userDetail in res['data']['user_detail'].items():
            username = userDetail['username']
            usernames[userId] = username

        return usernames
    
    except requests.Timeout:
        logger.error(f"Thread {threading.current_thread().name}: Timeout - The request to User API timed out.")
    except Exception as e:            
        logger.error(f"Thread {threading.current_thread().name}: Error in calling User API: {str(e)}") 
        
def CreateSshClient(server, port, user, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=server, port=port, username=user, password=password, timeout=config["SSH_TIMEOUT"])
        logger.info("Connection established..")
        return client
    except Exception as e:
        logger.error(f"Error occurred while connecting to remote host : {e}")
        return False

def ConnectToDb(postgresUser, postgresPassword, postgresHost, postgresPort):    #BUG ID 1103: Backup - Postgres - Wrong Credentials
    try:
        conn = psycopg2.connect(
            dbname = "postgres",
            user = postgresUser,
            password = postgresPassword,
            host = postgresHost,
            port = postgresPort
        )
        logger.info("Connection successful!.")
        return True, conn
    except Exception as e:
        logger.error(f"Connection failed: {e}")
        payload = {
            "status":False,
            "message":"Error connecting to postgres. Please check the credentials.",
            "data":None,
            "error":str(e)
        }
        return False, payload

# Formtting size to human readable 
def FormatSize(sizeInBytes):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if sizeInBytes < 1024.0:
            return f"{sizeInBytes:.2f} {unit}"
        sizeInBytes /= 1024.0
    return f"{sizeInBytes:.2f} TB"

def GetDiskUsageRemote(postgresVmUser, postgresVmPassword, postgresHost, postgresDataDir):
    try:
        sshClient = CreateSshClient(postgresHost, int(22), postgresVmUser, postgresVmPassword)
        if not sshClient:
            return False
        
        command = f"df -h {postgresDataDir} | tail -n 1"
        stdin, stdout, stderr = sshClient.exec_command(command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        # if error:
        #     raise Exception(f"Error retrieving disk usage: {error}")
        if error or not output:
            logger.error(f"Error retrieving disk usage: {error}")
            return False

        # Parse the output
        fields = output.split()
        total_space = fields[1]
        used_space = fields[2]
        free_space = fields[3]

        return {
            "total_disk_space": FormatSize(ConvertToBytes(total_space)),
            "used_disk_space": FormatSize(ConvertToBytes(used_space)),
            "free_disk_space": FormatSize(ConvertToBytes(free_space))
        }
    except Exception as e:
        logger.error(f"Failed to connect via SSH: {e}")
        return False
    
    finally:
        if sshClient:
            sshClient.close()


def CreateRemoteDirectoryIfNotExists(sftp, path):
    try:
        logger.info("Attempting to create directory...")
        sftp.mkdir(path)
    except IOError as e:
        if 'File exists' in str(e):
            logger.info(f"Directory {path} already exists.")
            return True
        else:
            logger.error(f"An unexpected error occurred while creating the directory: {str(e)}")
            return False
    except PermissionError as e:
        logger.error(f"Permission denied to create directory {path}: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"An error occurred while creating the directory {path}: {str(e)}")
        return False
    
    return True

# Server backup for local and remote
def ServerDataBackup(user, host, port, password, remotePath, localPath, isRemote=False, remoteHost=None, remoteUser=None, remotePassword=None):

    if not isRemote:
        localHost = config["LOCAL_POSTGRESQL_HOST"]
        localUserName = config["LOCAL_POSTGRESQL_VM_USER"]
        localPassword = config["LOCAL_POSTGRESQL_VM_PASSWORD"]
        ssh = CreateSshClient(localHost, 22, localUserName, localPassword)
        BackupFilepath = f"{localPath}/{int(datetime.now().timestamp())}_dump.sql"
        sftp = ssh.open_sftp()
        filePath = localPath
    
    else:    
        ssh = CreateSshClient(remoteHost, 22, remoteUser, remotePassword)
        BackupFilepath = f"{remotePath}/{int(datetime.now().timestamp())}_dump.sql"
        sftp = ssh.open_sftp()
        filePath = remotePath
    
    if ssh:    
        try:
            if CreateRemoteDirectoryIfNotExists(sftp, filePath):
                command = f"PGPASSWORD={password} pg_dumpall -U {user} -h {host} -p {port} --no-role-password > {BackupFilepath}"
                logger.debug(f"Executing command: {command}")
                
                stdin, stdout, stderr = ssh.exec_command(command)
                errorMessage = stderr.read().decode('utf-8')
                if errorMessage:
                    logger.error(f"Error occurred during pg_dumpall execution: {errorMessage}")
                    return False
                
                logger.info(f"Complete backup saved at: {BackupFilepath}")
                return True
            else:
                return False
        
        except Exception as e:
            logger.error(f"Error during backup: {e}")
            return False
        
        finally:
            if ssh:
                ssh.close()
    else:
        logger.error("SSH connection failed.")
        return False
    
def ServerDataRestore(user, host, port, password, filePath, isRemote, remoteHost, remoteUser, remotePassword):
    
    if not isRemote:
        localHost = config["LOCAL_POSTGRESQL_HOST"]
        localUserName = config["LOCAL_POSTGRESQL_VM_USER"]
        localPassword = config["LOCAL_POSTGRESQL_VM_PASSWORD"]
        ssh = CreateSshClient(localHost, 22, localUserName, localPassword)
    
    else:
        ssh = CreateSshClient(remoteHost, 22, remoteUser, remotePassword)
    
    if ssh:    
        try:
            sftp = ssh.open_sftp()   
            
            sqlFile = None
            for file in sftp.listdir(filePath):
                if file.endswith(".sql"):
                    sqlFile = os.path.join(filePath, file)
                    break
            
            if not sqlFile:
                logger.error("No .sql file found in the provided folder.")
                return False
            
            checkCommand = f'PGPASSWORD={password} psql -U {user} -h {host} -p {port} -f {sqlFile}'
            stdin, stdout, stderr = ssh.exec_command(checkCommand)
            output = stdout.read().decode()
            logger.debug(f"Restore Command: {output}")
            errorMessage = stderr.read().decode('utf-8')
            restoreLogDatabase = config["POSTGRESQL_RESTORE_LOG_DATABASE_NAME"]
            restoreLogTable = config["POSTGRESQL_RESTORE_LOG_TABLE_NAME"]
            
            if errorMessage:
                for line in errorMessage.splitlines():
                    if "role \"postgres\" already exists" in line:
                        logger.warning("Role 'postgres' already exists. Skipping this specific error.")
                        continue
                    elif f"database \"{restoreLogDatabase}\" already exists" in line: #BUG ID 2121: Restore Postgres in Remote server appearing failed in Restore logs history even though data has been restored.
                        # logger.warning(f"Database '{restoreLogDatabase}' already exists. Skipping this specific error.")
                        continue
                    elif f"relation \"{restoreLogTable}\" already exists" in line:
                        # logger.warning(f"Database '{restoreLogTable}' already exists. Skipping this specific error.")
                        continue
                    else:
                        logger.error(f"psql error: {line}")
                        return False
            
            return True
        except Exception as e:
            logger.error(f"Exception occurred during restore process: {e}")
            return False
        finally:
            if ssh:
                ssh.close()
    
    else:
        logger.error("SSH connection failed.")
        return False
        

#Local Case Backup
def LocalCaseQuery(startTime, endTime, user, host, port, password, dbname, filePath, schemabackupFilePath):
    os.environ["PGPASSWORD"] = password
    
    os.makedirs(filePath, exist_ok=True)
    
    caseBackupDir = os.path.join(filePath, 'case')
    os.makedirs(caseBackupDir, exist_ok=True)
    
    # pg_dump command to create a schema-only backup
    command = [
        'pg_dump',
        '-h', str(host),
        '-p', str(port),
        '-U', user,
        '-d', dbname,
        '--schema-only',  # Option to backup only the schema
        '-v', 
        '-f', schemabackupFilePath
    ]
    
    # Run the backup command
    subprocess.run(command, check=True)
    logger.info(f"Schema backup successful for database {dbname}. Saved to: {schemabackupFilePath}")
    
    startInputDate = datetime.strptime(startTime, "%Y-%m-%d")
    endInputDate = datetime.strptime(endTime, "%Y-%m-%d")
    startTime = int(startInputDate.timestamp())
    endTime = int(endInputDate.timestamp())
                

    # Define the export queries and output file paths
    queries = [
    {
        "query": f"COPY (SELECT * from public.\"Case_Management_target\" WHERE id IN (SELECT target_id from public.\"Case_Management_case_target\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir, "Case_Management_target.csv")
    },
    {
        "query": f"COPY (SELECT * FROM public.\"Case_Management_targetip\" WHERE target_id_id IN (SELECT id from public.\"Case_Management_target\"  WHERE id IN (SELECT target_id from public.\"Case_Management_case_target\"  WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\"  WHERE created_on >= '{startTime}' and created_on <= '{endTime}')))) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir, "Case_Management_targetip.csv")
    },
    {
        "query": f"COPY (SELECT * FROM public.\"Case_Management_targetmsisdn\" WHERE target_id_id IN (SELECT id from public.\"Case_Management_target\"  WHERE id IN (SELECT target_id from public.\"Case_Management_case_target\"  WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\"  WHERE created_on >= '{startTime}' and created_on <= '{endTime}')))) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir, "Case_Management_targetmsisdn.csv")
    },
    {
        "query": f"COPY (SELECT * FROM public.\"Case_Management_targetusermappingtable\" WHERE target_id_id IN (SELECT id from public.\"Case_Management_target\"  WHERE id IN (SELECT target_id from public.\"Case_Management_case_target\"  WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\"  WHERE created_on >= '{startTime}' and created_on <= '{endTime}')))) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir, "Case_Management_targetusermappingtable.csv")
    },
    {
        "query": f"COPY (SELECT * from public.\"Case_Management_target_group\" WHERE id IN (SELECT target_group_id from public.\"Case_Management_case_target_group\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir, "Case_Management_target_group.csv")
    },
    {
        "query": f"COPY (SELECT * from public.\"Case_Management_target_group_targets\" WHERE target_group_id IN (SELECT id from public.\"Case_Management_target_group\" WHERE id IN (SELECT target_group_id from public.\"Case_Management_case_target_group\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}')))) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir, "Case_Management_target_group_targets.csv")
    },
    {
        "query": f"COPY (SELECT * FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}') TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir, "Case_Management_case.csv")
    },
    {
        "query": f"COPY (SELECT * from public.\"Case_Management_job\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir,"Case_Management_job.csv")
    },
    {
        "query": f"COPY (SELECT * from public.\"Case_Management_caseusermappingtable\" WHERE case_id_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir,"Case_Management_caseusermappingtable.csv")
    },
    {
        "query": f"COPY (SELECT * from public.\"Case_Management_job_target\" WHERE job_id IN (SELECT job_id from public.\"Case_Management_job\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir,"Case_Management_job_target.csv")
    },
    {
        "query": f"COPY (SELECT * from public.\"Case_Management_job_target_group\" WHERE job_id IN (SELECT job_id from public.\"Case_Management_job\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir,"Case_Management_job_target_group.csv")
    },
    {
        "query": f"COPY (SELECT * from public.\"Case_Management_case_target\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir,"Case_Management_case_target.csv")
    },
    {
        "query": f"COPY (SELECT * from public.\"Case_Management_case_target_group\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir,"Case_Management_case_target_group.csv")
    },
    {
        "query": f"COPY (SELECT * FROM public.\"Case_Management_useruploadtable\" WHERE file_id IN (SELECT useruploadtable_id from public.\"Case_Management_useruploadtable_case\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir,"Case_Management_useruploadtable.csv")
    },
    {
        "query": f"COPY (SELECT * from public.\"Case_Management_useruploadtable_case\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir,"Case_Management_useruploadtable_case.csv")
    },
    {
        "query": f"COPY (SELECT * from public.\"Case_Management_mediafiles\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir,"Case_Management_mediafiles.csv")
    },
    {
        "query": f"COPY (SELECT * from public.\"Case_Management_mediafiles_targets\" WHERE mediafiles_id IN (SELECT id from public.\"Case_Management_mediafiles\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir,"Case_Management_mediafiles_targets.csv")
    },
    {
        "query": f"COPY (SELECT * from public.\"Case_Management_job_file_id\" WHERE job_id IN (SELECT job_id from public.\"Case_Management_job\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
        "output_file": os.path.join(caseBackupDir,"Case_Management_job_file_id.csv")
    },
    ]

    return queries

def LocalUserQuery(startTime, endTime, user, host, port, password, dbname, filePath, schemabackupFilePath):
    os.environ["PGPASSWORD"] = password
    
    os.makedirs(filePath, exist_ok=True)
    
    userBackupDir = os.path.join(filePath, 'usermanagement')
    os.makedirs(userBackupDir, exist_ok=True)
    
    # pg_dump command to create a schema-only backup
    command = [
        'pg_dump',
        '-h', str(host),
        '-p', str(port),
        '-U', user,
        '-d', dbname,
        '--schema-only',  # Option to backup only the schema
        '-v', 
        '-f', schemabackupFilePath
    ]
    
    try:# Run the backup command
        result = subprocess.run(command, check=True)
        if result.returncode != 0:
            logger.error(f"Backup failed: {result.stderr.decode()}")
            return False, None
        
        else:
            startInputDate = datetime.strptime(startTime, "%Y-%m-%d")
            endInputDate = datetime.strptime(endTime, "%Y-%m-%d")
            startTime = int(startInputDate.timestamp())
            endTime = int(endInputDate.timestamp())
            
            queries = [
                {
                    "query": f"""COPY (
                                    SELECT * 
                                    FROM \"user_userprofile\" 
                                    WHERE id IN (
                                        SELECT head_id 
                                        FROM \"user_department\" 
                                        WHERE id IN (
                                            SELECT department_id 
                                            FROM \"user_userprofile\" 
                                            WHERE created_on >= '{startTime}' 
                                            AND created_on <= '{endTime}'
                                        )
                                    )
                                    UNION
                                    SELECT * 
                                    FROM \"user_userprofile\" 
                                    WHERE created_on >= '{startTime}' 
                                    AND created_on <= '{endTime}'
                                ) TO STDOUT WITH CSV HEADER;""",
                    "output_file": os.path.join(userBackupDir, "user_userprofile.csv")
                },
                {
                    "query": f"COPY (select * from \"user_department\" where id IN (select department_id from \"user_userprofile\" where created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                    "output_file": os.path.join(userBackupDir, "user_department.csv")
                },
                {
                    "query": f"""COPY (
                                    select * 
                                    from \"user_role\" 
                                    where id IN (
                                        select default_department_head_role_id 
                                        from \"user_department\" 
                                        where id IN (
                                            select department_id 
                                            from \"user_userprofile\" 
                                            where created_on >= '{startTime}' 
                                            and created_on <= '{endTime}'
                                        )
                                    )
                                    UNION 
                                    select * 
                                    from \"user_role\" 
                                    where id IN (
                                        select role_id 
                                        from \"user_userprofile\" 
                                        where created_on >= '{startTime}' 
                                        and created_on <= '{endTime}'
                                    )
                                ) TO STDOUT WITH CSV HEADER;""",
                    "output_file": os.path.join(userBackupDir, "user_role.csv")
                },
                {
                    "query": f"COPY (select * from \"user_department_department_user_roles\" where department_id IN (select department_id from \"user_userprofile\" where created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                    "output_file": os.path.join(userBackupDir, "user_department_department_user_roles.csv")
                },
                {
                    "query": f"COPY (select * from \"user_userprofile\" where id in (select head_id from \"user_department\" where id in (select department_id FROM \"user_userprofile\" where created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
                    "output_file": os.path.join(userBackupDir, "user_department_head.csv")
                },
                ]

            logger.info(f"Schema backup successful for database {dbname}. Saved to: {schemabackupFilePath}")
        return queries
    except subprocess.CalledProcessError as e:
        logger.error(f"Backup failed: {e}")
        return False, None

def LocalMiddlewareQuery(startTime, endTime, user, host, port, password, dbname, filePath, schemabackupFilePath, source):
    os.environ["PGPASSWORD"] = password
    
    os.makedirs(filePath, exist_ok=True)
    
    middlewareBackupDir = os.path.join(filePath, 'middleware')
    os.makedirs(middlewareBackupDir, exist_ok=True)
    
    # pg_dump command to create a schema-only backup
    command = [
        'pg_dump',
        '-h', str(host),
        '-p', str(port),
        '-U', user,
        '-d', dbname,
        '--schema-only',  # Option to backup only the schema
        '-v', 
        '-f', schemabackupFilePath
    ]
    
    try:# Run the backup command
        result = subprocess.run(command, check=True)
        if result.returncode != 0:
            logger.error(f"Backup failed: {result.stderr.decode()}")
            return False, None
        
        else:
            logger.info(f"Schema backup successful for database {dbname}. Saved to: {schemabackupFilePath}")
            
            startInputDate = datetime.strptime(startTime, "%Y-%m-%d")
            endInputDate = datetime.strptime(endTime, "%Y-%m-%d")
            startTime = int(startInputDate.timestamp())
            endTime = int(endInputDate.timestamp())
            
            if(source == "ip"):
                queries = [
                {
                    "query": f"COPY (select * from \"IpData_ipdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}') TO STDOUT WITH CSV HEADER;",
                    "output_file": os.path.join(middlewareBackupDir, "IpData_ipdata.csv")
                },
                ]
            
            elif(source =="cdr"):
                queries = [
                {
                    "query": f"COPY (select * from \"Scylla_cdrdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}') TO STDOUT WITH CSV HEADER;",
                    "output_file": os.path.join(middlewareBackupDir, "Scylla_cdrdata.csv")
                },
                {
                    "query": f"COPY (select * from \"Scylla_commonmsisdnchart\" where job_id IN (select job_id from \"Scylla_cdrdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                    "output_file": os.path.join(middlewareBackupDir, "Scylla_commonmsisdnchart.csv")
                },
                {
                    "query": f"COPY (select * from \"Scylla_handsethistorychart\" where job_id IN (select job_id from \"Scylla_cdrdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                    "output_file": os.path.join(middlewareBackupDir, "Scylla_handsethistorychart.csv")
                },
                {
                    "query": f"COPY (select * from \"Scylla_imeimsisdnmapping\" where job_id IN (select job_id from \"Scylla_cdrdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                    "output_file": os.path.join(middlewareBackupDir, "Scylla_imeimsisdnmapping.csv")
                },
                {
                    "query": f"COPY (select * from \"Scylla_imsimsisdnmapping\" where job_id IN (select job_id from \"Scylla_cdrdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                    "output_file": os.path.join(middlewareBackupDir, "Scylla_imsimsisdnmapping.csv")
                },
                {
                    "query": f"COPY (select * from \"Scylla_simimeihistorychart\" where job_id IN (select job_id from \"Scylla_cdrdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                    "output_file": os.path.join(middlewareBackupDir, "Scylla_simimeihistorychart.csv")
                },
                {
                    "query": f"COPY (select * from \"Scylla_simmsisdnhistorychart\" where job_id IN (select job_id from \"Scylla_cdrdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                    "output_file": os.path.join(middlewareBackupDir, "Scylla_simmsisdnhistorychart.csv")
                },
                ]
                
            return queries
    
    except subprocess.CalledProcessError as e:
        logger.error(f"Backup failed: {e}")
        return False, None

def RunPsql(query, output_file, user, host, port, dbname):
    try:
        command = f"psql -U {user} -h {host} -p {port} -d {dbname} -c \'{query}\' > {output_file}"
        logger.debug(f"Running command: {command}")
        subprocess.run(command, shell=True, check=True)
        logger.info(f"Data exported to {output_file}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running command: {e}")

#Local Case Restore
def ExtractTableNames(schemaPath):
    if not os.path.exists(schemaPath):
        logger.error(f"File not found: {schemaPath}")
        return False
    
    with open(schemaPath, 'r') as schema_file:
        schema_sql = schema_file.read()
    
    table_names = re.findall(r'CREATE TABLE\s+(?:\w+\.)?"?([a-zA-Z_][a-zA-Z0-9_]*)"?', schema_sql)
    return table_names
def RestoreCaseQueryData(user, host, port, dbname, password, tableName, filePath, schemaPath):
    os.environ['PGPASSWORD'] = password
    
    if not os.path.exists(schemaPath):
        logger.error(f"File not found: {schemaPath}")
        return False
    
    restoreCommand = [
        'psql',
        '-U', user,
        '-h', host,
        '-p', str(port),
        '-d', dbname,
        '-f', schemaPath
    ]
    try:
        result = subprocess.run(restoreCommand, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"Schema restored successfully to database '{dbname}'.")
        # logger.debug(f"Output: {result.stdout.decode()}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Schema restoration failed for '{dbname}': {e}")
        return False

    # Execute the COPY command using subprocess
    command = [
        'psql',
        '-U', user,
        '-h', host,
        '-p', str(port),
        '-d', dbname,
        '-c', f"\COPY \"{tableName}\" FROM '{filePath}' WITH (FORMAT csv, HEADER true)"
    ]

    try:
        subprocess.run(command, check=True, text=True, capture_output=True)
        logger.info(f"Successfully restored table {tableName} from {filePath}.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error restoring table {tableName} from {filePath}:")
        logger.debug("Error occurred while restoring case data" + e.stderr)
        return False
    except Exception as e:
        logger.error(f"Exception occurred: {e}")
        return False
    finally:
        os.environ.pop("PGPASSWORD", None)

def EnableDisableTriggers(user, host, port, dbname, password, tableName, value):
    os.environ['PGPASSWORD'] = password
    
    enableTriggersCommand = [
        'psql', 
        '-U', user,
        '-h', host,
        '-p', port,
        '-d', dbname,
        '-c', f" ALTER TABLE \"{tableName}\" ENABLE TRIGGER ALL;"
        ]
    
    disableTriggersCommand = [
        'psql', 
        '-U', user,
        '-h', host,
        '-p', port,
        '-d', dbname,
        '-c', f" ALTER TABLE \"{tableName}\" DISABLE TRIGGER ALL;"
        ]

    try:
        if(value == "enable"):
            subprocess.run(enableTriggersCommand, check=True, text=True, capture_output=True)
            logger.info(f"Successfully enabled triggers for table {tableName}.")
            return True
        
        else:
            subprocess.run(disableTriggersCommand, check=True, text=True, capture_output=True)
            logger.info(f"Successfully disabled triggers for table {tableName}.")
            return True
    
    except subprocess.CalledProcessError as e:
        logger.error(f"Error disabling/enabling triggers for table {tableName}: {e}")
        logger.debug("Error occurred while restoring user data" + str(e.stderr))
        return False
    except Exception as e:
        logger.error(f"Exception occurred: {e}")
        return False
    
def RestoreUserQueryData(user, host, port, dbname, password, tableName, filePath, schemaPath):
    os.environ['PGPASSWORD'] = password
    
    if not os.path.exists(schemaPath):
        logger.error(f"File not found: {schemaPath}")
        return False
    
    # enable this If tables are not present 
    # restoreCommand = [
    #     'psql',
    #     '-U', user,
    #     '-h', host,
    #     '-p', str(port),
    #     '-d', dbname,
    #     '-f', schemaPath
    # ]
    # try:
    #     result = subprocess.run(restoreCommand, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #     logger.info(f"Schema restored successfully to database '{dbname}'.")
    # except subprocess.CalledProcessError as e:
    #     logger.error(f"Schema restoration failed for '{dbname}': {e}")
    #     logger.debug("Error occurred while restoring case data" + str(e.stderr))
    #     return False

    response = EnableDisableTriggers(user, host, port, dbname, password, tableName, "disable")
    if response:
        pass

    # Execute the COPY command using subprocess
    command = [
        'psql',
        '-U', user,
        '-h', host,
        '-p', str(port),
        '-d', dbname,
        '-c', f"\COPY \"{tableName}\" FROM '{filePath}' WITH (FORMAT csv, HEADER true)"
    ]

    try:
        result = subprocess.run(command, check=True, text=True, capture_output=True)
        logger.info(f"Successfully restored table {tableName} from {filePath}.")
        response = EnableDisableTriggers(user, host, port, dbname, password, tableName, "enable")
        if response:
            return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error restoring table {tableName} from {filePath}:")
        logger.debug("Error occurred while restoring case data" + str(e.stderr))
        return False
    except Exception as e:
        logger.error(f"Exception occurred: {e}")
        return False
    finally:
        os.environ.pop("PGPASSWORD", None)

def RestoreMiddlewareQueryData(user, host, port, dbname, password, tableName, filePath, schemaPath):
    os.environ['PGPASSWORD'] = password
    
    if not os.path.exists(schemaPath):
        logger.error(f"File not found: {schemaPath}")
        return False
    
    restoreCommand = [
        'psql',
        '-U', user,
        '-h', host,
        '-p', str(port),
        '-d', dbname,
        '-f', schemaPath
    ]
    try:
        result = subprocess.run(restoreCommand, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"Schema restored successfully to database '{dbname}'.")
        # logger.debug(f"Output: {result.stdout.decode()}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Schema restoration failed for '{dbname}': {e}")
        return False

    # Execute the COPY command using subprocess
    command = [
        'psql',
        '-U', user,
        '-h', host,
        '-p', str(port),
        '-d', dbname,
        '-c', f"\COPY \"{tableName}\" FROM '{filePath}' WITH (FORMAT csv, HEADER true)"
    ]

    try:
        subprocess.run(command, check=True, text=True, capture_output=True)
        logger.info(f"Successfully restored table {tableName} from {filePath}.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error restoring table {tableName} from {filePath}:")
        logger.debug("Error occurred while restoring case data" + e.stderr)
        return False
    except Exception as e:
        logger.error(f"Exception occurred: {e}")
        return False
    finally:
        os.environ.pop("PGPASSWORD", None)    

#Remote Case Backup
def BackupCaseQueryRemote(startTime, endTime, user, host, port, password, dbname, isRemote, filePath, localPath, remoteHost=None, remoteUser=None, remotePassword=None):
    if isRemote:
        ssh = CreateSshClient(remoteHost, 22, remoteUser, remotePassword)
        schemabackupFilePath = os.path.join(filePath, f'{dbname}_schema.sql')
        filePath = filePath
    else:
        localHost = config["LOCAL_POSTGRESQL_HOST"]
        localUserName = config["LOCAL_POSTGRESQL_VM_USER"]
        localPassword = config["LOCAL_POSTGRESQL_VM_PASSWORD"]
        ssh = CreateSshClient(localHost, 22, localUserName, localPassword)
        schemabackupFilePath = os.path.join(localPath, f'{dbname}_schema.sql')
        filePath = localPath
        
    if ssh:
        sftp = ssh.open_sftp()

        if CreateRemoteDirectoryIfNotExists(sftp, filePath):
            pass
        else:
            return False, None
        
        caseBackupDir = os.path.join(filePath, 'case')
        if CreateRemoteDirectoryIfNotExists(sftp, caseBackupDir):
            pass
        else:
            return False, None
        
        logger.info("Remote directory created.")
        
        command = f"PGPASSWORD={password} pg_dump -U {user} -h {host} -p {port} -d {dbname} --schema-only -v > {schemabackupFilePath}"

        stdin, stdout, stderr = ssh.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        error = stderr.read().decode()
        if exit_status == 0:
            logger.info(f"Schema backup successful! for database {dbname}. Saved to: {schemabackupFilePath}")
        else:
            logger.error(f"Error during schema backup: {error}")
            return False, error
        
        startInputDate = datetime.strptime(startTime, "%Y-%m-%d")
        endInputDate = datetime.strptime(endTime, "%Y-%m-%d")
        startTime = int(startInputDate.timestamp())
        endTime = int(endInputDate.timestamp())
        
        # Define the export queries and output file paths
        queries = [
            {
                "query": f"COPY (SELECT * from public.\"Case_Management_target\" WHERE id IN (SELECT target_id from public.\"Case_Management_case_target\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir, "Case_Management_target.csv")
            },
            {
                "query": f"COPY (SELECT * FROM public.\"Case_Management_targetip\" WHERE target_id_id IN (SELECT id from public.\"Case_Management_target\"  WHERE id IN (SELECT target_id from public.\"Case_Management_case_target\"  WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\"  WHERE created_on >= '{startTime}' and created_on <= '{endTime}')))) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir, "Case_Management_targetip.csv")
            },
            {
                "query": f"COPY (SELECT * FROM public.\"Case_Management_targetmsisdn\" WHERE target_id_id IN (SELECT id from public.\"Case_Management_target\"  WHERE id IN (SELECT target_id from public.\"Case_Management_case_target\"  WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\"  WHERE created_on >= '{startTime}' and created_on <= '{endTime}')))) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir, "Case_Management_targetmsisdn.csv")
            },
            {
                "query": f"COPY (SELECT * FROM public.\"Case_Management_targetusermappingtable\" WHERE target_id_id IN (SELECT id from public.\"Case_Management_target\"  WHERE id IN (SELECT target_id from public.\"Case_Management_case_target\"  WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\"  WHERE created_on >= '{startTime}' and created_on <= '{endTime}')))) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir, "Case_Management_targetusermappingtable.csv")
            },
            {
                "query": f"COPY (SELECT * from public.\"Case_Management_target_group\" WHERE id IN (SELECT target_group_id from public.\"Case_Management_case_target_group\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir, "Case_Management_target_group.csv")
            },
            {
                "query": f"COPY (SELECT * from public.\"Case_Management_target_group_targets\" WHERE target_group_id IN (SELECT id from public.\"Case_Management_target_group\" WHERE id IN (SELECT target_group_id from public.\"Case_Management_case_target_group\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}')))) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir, "Case_Management_target_group_targets.csv")
            },
            {
                "query": f"COPY (SELECT * FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}') TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir, "Case_Management_case.csv")
            },
            {
                "query": f"COPY (SELECT * from public.\"Case_Management_job\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir,"Case_Management_job.csv")
            },
            {
                "query": f"COPY (SELECT * from public.\"Case_Management_caseusermappingtable\" WHERE case_id_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir,"Case_Management_caseusermappingtable.csv")
            },
            {
                "query": f"COPY (SELECT * from public.\"Case_Management_job_target\" WHERE job_id IN (SELECT job_id from public.\"Case_Management_job\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir,"Case_Management_job_target.csv")
            },
            {
                "query": f"COPY (SELECT * from public.\"Case_Management_job_target_group\" WHERE job_id IN (SELECT job_id from public.\"Case_Management_job\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir,"Case_Management_job_target_group.csv")
            },
            {
                "query": f"COPY (SELECT * from public.\"Case_Management_case_target\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir,"Case_Management_case_target.csv")
            },
            {
                "query": f"COPY (SELECT * from public.\"Case_Management_case_target_group\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir,"Case_Management_case_target_group.csv")
            },
            {
                "query": f"COPY (SELECT * FROM public.\"Case_Management_useruploadtable\" WHERE file_id IN (SELECT useruploadtable_id from public.\"Case_Management_useruploadtable_case\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir,"Case_Management_useruploadtable.csv")
            },
            {
                "query": f"COPY (SELECT * from public.\"Case_Management_useruploadtable_case\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir,"Case_Management_useruploadtable_case.csv")
            },
            {
                "query": f"COPY (SELECT * from public.\"Case_Management_mediafiles\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir,"Case_Management_mediafiles.csv")
            },
            {
                "query": f"COPY (SELECT * from public.\"Case_Management_mediafiles_targets\" WHERE mediafiles_id IN (SELECT id from public.\"Case_Management_mediafiles\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir,"Case_Management_mediafiles_targets.csv")
            },
            {
                "query": f"COPY (SELECT * from public.\"Case_Management_job_file_id\" WHERE job_id IN (SELECT job_id from public.\"Case_Management_job\" WHERE case_id IN (SELECT id FROM public.\"Case_Management_case\" WHERE created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(caseBackupDir,"Case_Management_job_file_id.csv")
            },
        ]

        # return queries
        for query in queries:
            output_file = query["output_file"]
            query_str = query["query"]
            
            # Command to execute the COPY query
            copy_command = f"PGPASSWORD={password} psql -U {user} -h {host} -p {port} -d {dbname} -c \'{query_str}\' > {output_file}"
            
            # Execute the command
            stdin, stdout, stderr = ssh.exec_command(copy_command)
            exit_status = stdout.channel.recv_exit_status()
            error = stderr.read().decode()
            
            if exit_status == 0:
                logger.info(f"Data exported successfully to {output_file}.")
            else:
                logger.error(f"Error exporting data to {output_file}: {error}")
                return False, error

        ssh.close()
        return True, caseBackupDir
    else:
        return False, "ssh connection failed."

#Remote Case Restore
def ExtractTableNamesFromRemote(remote_host, remote_user, remote_password, schema_file_path):
    try:
        ssh = CreateSshClient(remote_host, 22, remote_user, remote_password)
        if ssh:
            pass
        else:
            logger.debug("Remote client connection failed.")
            return False

        sftp = ssh.open_sftp()

        with sftp.open(schema_file_path, 'r') as schema_file:
            schema_sql = schema_file.read()

        schema_sql = schema_sql.decode('utf-8')
        
        # Regular expression to match CREATE TABLE statements
        table_names = re.findall(r'CREATE TABLE\s+(?:\w+\.)?"?([a-zA-Z_][a-zA-Z0-9_]*)"?', schema_sql)

        # Close the SFTP connection
        sftp.close()
        ssh.close()

        return table_names

    except Exception as e:
        # print(f"An error occurred: {e}")
        logger.error(f"An error occurred: {e}")
        return []
def RestoreCaseQueryFromRemote(remote_host, remote_user, remote_password, local_host, db_user, db_port, db_password, db_name, schema_file_path, data_file_path):
    os.environ['PGPASSWORD'] = db_password

    try:
        ssh = CreateSshClient(remote_host, 22, remote_user, remote_password)
        if ssh:
            pass
        else:
            logger.debug("Remote client connection failed.")
            return False

        csv_files = [
            "Case_Management_target.csv",
            "Case_Management_targetip.csv",
            "Case_Management_targetmsisdn.csv",
            "Case_Management_targetusermappingtable.csv",
            "Case_Management_target_group.csv",
            "Case_Management_target_group_targets.csv",
            "Case_Management_case.csv",
            "Case_Management_caseusermappingtable.csv",
            "Case_Management_case_target.csv",
            "Case_Management_case_target_group.csv",
            "Case_Management_job.csv",
            "Case_Management_job_target.csv",
            "Case_Management_job_target_group.csv",
            "Case_Management_useruploadtable.csv",
            "Case_Management_useruploadtable_case.csv",
            "Case_Management_mediafiles.csv",
            "Case_Management_mediafiles_targets.csv",
            "Case_Management_job_file_id.csv"
        ]
        check_csv_command = f"ls {data_file_path}"
        stdin, stdout, stderr = ssh.exec_command(check_csv_command)

        # csv_files = [f for f in remote_files if f.endswith('.csv')]
        exit_status = stdout.channel.recv_exit_status()
        for csv_file in csv_files:
            table_name = os.path.splitext(csv_file)[0]
            remote_csv_file_path = os.path.join(data_file_path, csv_file)

            if exit_status == 0:  # The file exists #BUG ID 1105: Restore - Postgres - remote - partial
                qtablename = f'\\\"{table_name}\\\"'
                copy_command = f"\\COPY {qtablename} FROM '{remote_csv_file_path}' WITH (FORMAT csv, HEADER true)"
                restore_data_command = f"PGPASSWORD={db_password} psql -U {db_user} -h {local_host} -p {db_port} -d {db_name} -c \"{copy_command}\" "
                
                logger.debug(f"Restore Data Command: {restore_data_command}")
                stdin, stdout, stderr = ssh.exec_command(restore_data_command)
                exit_status = stdout.channel.recv_exit_status()

                if exit_status == 0:
                    logger.info(f"Successfully restored data from {remote_csv_file_path} into table '{table_name}'.")
                else:
                    error_output = stderr.read().decode()
                    logger.error(f"Error restoring table {table_name} from {remote_csv_file_path}: {error_output}")
                    logger.debug(f"Copy Command: {copy_command}")
                    return False
            else:
                logger.info(f"CSV file {remote_csv_file_path} does not exist on the remote machine.")
                return False
            
        return True

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return False
    finally:
        os.environ.pop("PGPASSWORD", None)  # Clean up the environment variable
        if ssh:
            ssh.close()

def RestoreMiddlewareQueryFromRemote(remote_host, remote_user, remote_password, local_host, db_user, db_port, db_password, db_name, schema_file_path, data_file_path, source):
    os.environ['PGPASSWORD'] = db_password

    try:
        ssh = CreateSshClient(remote_host, 22, remote_user, remote_password)
        if ssh:
            pass
        else:
            logger.debug("Remote client connection failed.")
            return False

        if(source=="cdr"):
            csv_files = [
                "Scylla_cdrdata.csv",
                "Scylla_commonmsisdnchart.csv",
                "Scylla_handsethistorychart.csv",
                "Scylla_imeimsisdnmapping.csv",
                "Scylla_imsimsisdnmapping.csv",
                "Scylla_simimeihistorychart.csv",
                "Scylla_simmsisdnhistorychart.csv"
            ]
        
        elif(source=="ip"):
            csv_files = [
                "IpData_ipdata.csv",
            ]
            
        check_csv_command = f"ls {data_file_path}"
        stdin, stdout, stderr = ssh.exec_command(check_csv_command)

        # csv_files = [f for f in remote_files if f.endswith('.csv')]
        exit_status = stdout.channel.recv_exit_status()
        for csv_file in csv_files:
            table_name = os.path.splitext(csv_file)[0]
            remote_csv_file_path = os.path.join(data_file_path, csv_file)

            if exit_status == 0:  # The file exists #BUG ID 1105: Restore - Postgres - remote - partial
                qtablename = f'\\\"{table_name}\\\"'
                copy_command = f"\\COPY {qtablename} FROM '{remote_csv_file_path}' WITH (FORMAT csv, HEADER true)"
                restore_data_command = f"PGPASSWORD={db_password} psql -U {db_user} -h {local_host} -p {db_port} -d {db_name} -c \"{copy_command}\" "
                
                logger.debug(f"Restore Data Command: {restore_data_command}")
                stdin, stdout, stderr = ssh.exec_command(restore_data_command)
                exit_status = stdout.channel.recv_exit_status()

                if exit_status == 0:
                    logger.info(f"Successfully restored data from {remote_csv_file_path} into table '{table_name}'.")
                else:
                    error_output = stderr.read().decode()
                    logger.error(f"Error restoring table {table_name} from {remote_csv_file_path}: {error_output}")
                    logger.debug(f"Copy Command: {copy_command}")
                    return False
            else:
                logger.info(f"CSV file {remote_csv_file_path} does not exist on the remote machine.")
                return False
            
        return True

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return False
    finally:
        os.environ.pop("PGPASSWORD", None)  # Clean up the environment variable
        if ssh:
            ssh.close()

def BackupmiddlewareQueryRemote(startTime, endTime, user, host, port, password, dbname, isRemote, filePath, localPath, remoteHost, remoteUser, remotePassword, source):
    if isRemote:
        ssh = CreateSshClient(remoteHost, 22, remoteUser, remotePassword)
        schemabackupFilePath = os.path.join(filePath, f'{dbname}_schema.sql')
        filePath = filePath
    else:
        localHost = config["LOCAL_POSTGRESQL_HOST"]
        localUserName = config["LOCAL_POSTGRESQL_VM_USER"]
        localPassword = config["LOCAL_POSTGRESQL_VM_PASSWORD"]
        ssh = CreateSshClient(localHost, 22, localUserName, localPassword)
        schemabackupFilePath = os.path.join(localPath, f'{dbname}_schema.sql')
        filePath = localPath
    
    if ssh:
        sftp = ssh.open_sftp()

        if CreateRemoteDirectoryIfNotExists(sftp, filePath):
            pass
        else:
            return False, None
        
        middlewareBackupDir = os.path.join(filePath, 'middleware')
        if CreateRemoteDirectoryIfNotExists(sftp, middlewareBackupDir):
            pass
        else:
            return False, None
        logger.info("Remote directory created.")
        
        command = f"PGPASSWORD={password} pg_dump -U {user} -h {host} -p {port} -d {dbname} --schema-only -v > {schemabackupFilePath}"

        stdin, stdout, stderr = ssh.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        error = stderr.read().decode()
        if exit_status == 0:
            logger.info(f"Schema backup successful! for database {dbname}. Saved to: {schemabackupFilePath}")
        else:
            logger.error(f"Error during schema backup: {error}")
            return False, error
        
        startInputDate = datetime.strptime(startTime, "%Y-%m-%d")
        endInputDate = datetime.strptime(endTime, "%Y-%m-%d")
        startTime = int(startInputDate.timestamp())
        endTime = int(endInputDate.timestamp())
        
        logger.debug(f"Received timestamps: startTime-{startTime} endTime-{endTime}")
        
        # Define the export queries and output file paths
        if(source == "ip"):
            queries = [
            {
                "query": f"COPY (select * from \"IpData_ipdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}') TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(middlewareBackupDir, "IpData_ipdata.csv")
            },
            ]
        
        elif(source =="cdr"):
            queries = [
            {
                "query": f"COPY (select * from \"Scylla_cdrdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}') TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(middlewareBackupDir, "Scylla_cdrdata.csv")
            },
            {
                "query": f"COPY (select * from \"Scylla_commonmsisdnchart\" where job_id IN (select job_id from \"Scylla_cdrdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(middlewareBackupDir, "Scylla_commonmsisdnchart.csv")
            },
            {
                "query": f"COPY (select * from \"Scylla_handsethistorychart\" where job_id IN (select job_id from \"Scylla_cdrdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(middlewareBackupDir, "Scylla_handsethistorychart.csv")
            },
            {
                "query": f"COPY (select * from \"Scylla_imeimsisdnmapping\" where job_id IN (select job_id from \"Scylla_cdrdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(middlewareBackupDir, "Scylla_imeimsisdnmapping.csv")
            },
            {
                "query": f"COPY (select * from \"Scylla_imsimsisdnmapping\" where job_id IN (select job_id from \"Scylla_cdrdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(middlewareBackupDir, "Scylla_imsimsisdnmapping.csv")
            },
            {
                "query": f"COPY (select * from \"Scylla_simimeihistorychart\" where job_id IN (select job_id from \"Scylla_cdrdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(middlewareBackupDir, "Scylla_simimeihistorychart.csv")
            },
            {
                "query": f"COPY (select * from \"Scylla_simmsisdnhistorychart\" where job_id IN (select job_id from \"Scylla_cdrdata\" where ingestion_timestamp >= '{startTime}' and ingestion_timestamp <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
                "output_file": os.path.join(middlewareBackupDir, "Scylla_simmsisdnhistorychart.csv")
            },
            ]
        
        # return queries
        for query in queries:
            output_file = query["output_file"]
            query_str = query["query"]
            
            # Command to execute the COPY query
            copy_command = f"PGPASSWORD={password} psql -U {user} -h {host} -p {port} -d {dbname} -c \'{query_str}\' > {output_file}"
            
            # Execute the command
            stdin, stdout, stderr = ssh.exec_command(copy_command)
            exit_status = stdout.channel.recv_exit_status()
            error = stderr.read().decode()
            
            if exit_status == 0:
                logger.info(f"Data exported successfully to {output_file}.")
            else:
                logger.error(f"Error exporting data to {output_file}: {error}")
                return False, error

        ssh.close()
        return True, None
    else:
        return False, "ssh connection failed."

def BackupUserQueryRemote(startTime, endTime, user, host, port, password, dbname, isRemote, filePath, localPath, remoteHost, remoteUser, remotePassword):
    if isRemote:
        ssh = CreateSshClient(remoteHost, 22, remoteUser, remotePassword)
        schemabackupFilePath = os.path.join(filePath, f'{dbname}_schema.sql')
        filePath = filePath
    else:
        localHost = config["LOCAL_POSTGRESQL_HOST"]
        localUserName = config["LOCAL_POSTGRESQL_VM_USER"]
        localPassword = config["LOCAL_POSTGRESQL_VM_PASSWORD"]
        ssh = CreateSshClient(localHost, 22, localUserName, localPassword)
        schemabackupFilePath = os.path.join(localPath, f'{dbname}_schema.sql')
        filePath = localPath
        
    if ssh:
        sftp = ssh.open_sftp()

        if CreateRemoteDirectoryIfNotExists(sftp, filePath):
            pass
        else:
            return False, None
        
        userBackupDir = os.path.join(filePath, 'usermanagement')
        if CreateRemoteDirectoryIfNotExists(sftp, userBackupDir):
            pass
        else:
            return False, None
        logger.info("Remote directory created.")
        
        command = f"PGPASSWORD={password} pg_dump -U {user} -h {host} -p {port} -d {dbname} --schema-only -v > {schemabackupFilePath}"

        stdin, stdout, stderr = ssh.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        error = stderr.read().decode()
        if exit_status == 0:
            logger.info(f"Schema backup successful! for database {dbname}. Saved to: {schemabackupFilePath}")
        else:
            logger.error(f"Error during schema backup: {error}")
            return False, error
        
        startInputDate = datetime.strptime(startTime, "%Y-%m-%d")
        endInputDate = datetime.strptime(endTime, "%Y-%m-%d")
        startTime = int(startInputDate.timestamp())
        endTime = int(endInputDate.timestamp())
        
        logger.debug(f"Received timestamps: startTime-{startTime} endTime-{endTime}")
        
        # Define the export queries and output file paths
        queries = [
        {
            "query": f"""COPY (
                            SELECT * 
                            FROM \"user_userprofile\" 
                            WHERE id IN (
                                SELECT head_id 
                                FROM \"user_department\" 
                                WHERE id IN (
                                    SELECT department_id 
                                    FROM \"user_userprofile\" 
                                    WHERE created_on >= '{startTime}' 
                                    AND created_on <= '{endTime}'
                                )
                            )
                            UNION
                            SELECT * 
                            FROM \"user_userprofile\" 
                            WHERE created_on >= '{startTime}' 
                            AND created_on <= '{endTime}'
                        ) TO STDOUT WITH CSV HEADER;""",
            "output_file": os.path.join(userBackupDir, "user_userprofile.csv")
        },
        {
            "query": f"COPY (select * from \"user_department\" where id IN (select department_id from \"user_userprofile\" where created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
            "output_file": os.path.join(userBackupDir, "user_department.csv")
        },
        {
            "query": f"""COPY (
                            select * 
                            from \"user_role\" 
                            where id IN (
                                select default_department_head_role_id 
                                from \"user_department\" 
                                where id IN (
                                    select department_id 
                                    from \"user_userprofile\" 
                                    where created_on >= '{startTime}' 
                                    and created_on <= '{endTime}'
                                )
                            )
                            UNION 
                            select * 
                            from \"user_role\" 
                            where id IN (
                                select role_id 
                                from \"user_userprofile\" 
                                where created_on >= '{startTime}' 
                                and created_on <= '{endTime}'
                            )
                        ) TO STDOUT WITH CSV HEADER;""",
            "output_file": os.path.join(userBackupDir, "user_role.csv")
        },
        {
            "query": f"COPY (select * from \"user_department_department_user_roles\" where department_id IN (select department_id from \"user_userprofile\" where created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
            "output_file": os.path.join(userBackupDir, "user_department_department_user_roles.csv")
        },
        {
            "query": f"COPY (select * from \"user_userprofile\" where id in (select head_id from \"user_department\" where id in (select department_id FROM \"user_userprofile\" where created_on >= '{startTime}' and created_on <= '{endTime}'))) TO STDOUT WITH CSV HEADER;",
            "output_file": os.path.join(userBackupDir, "user_department_head.csv")
        },
        
        ]
        #date filter for all tables
        # queries = [
        # {
        #     "query": f"COPY (select * from \"user_role\" where created_on >= '{startTime}' and created_on <= '{endTime}') TO STDOUT WITH CSV HEADER;",
        #     "output_file": os.path.join(userBackupDir, "user_role.csv")
        # },
        # {
        #     "query": f"COPY (select * from \"user_userprofile\" where created_on >= '{startTime}' and created_on <= '{endTime}') TO STDOUT WITH CSV HEADER;",
        #     "output_file": os.path.join(userBackupDir, "user_userprofile.csv")
        # },
        # {
        #     "query": f"COPY (select * from \"user_department\" where created_on >= '{startTime}' and created_on <= '{endTime}') TO STDOUT WITH CSV HEADER;",
        #     "output_file": os.path.join(userBackupDir, "user_department.csv")
        # },
        # {
        #     "query": f"COPY (select * from \"user_department_department_user_roles\" where department_id IN (select department_id from \"user_userprofile\" where created_on >= '{startTime}' and created_on <= '{endTime}')) TO STDOUT WITH CSV HEADER;",
        #     "output_file": os.path.join(userBackupDir, "user_department_department_user_roles.csv")
        # },
        # ]
        
        # return queries
        for query in queries:
            output_file = query["output_file"]
            query_str = query["query"]
            
            # Command to execute the COPY query
            copy_command = f"PGPASSWORD={password} psql -U {user} -h {host} -p {port} -d {dbname} -c \'{query_str}\' > {output_file}"
            # Execute the command
            stdin, stdout, stderr = ssh.exec_command(copy_command)
            exit_status = stdout.channel.recv_exit_status()
            error = stderr.read().decode()
            
            if exit_status == 0:
                logger.info(f"Data exported successfully to {output_file}.")
            else:
                logger.error(f"Error exporting data to {output_file}: {error}")
                return False, error

        ssh.close()
        return True, None
    else:
        return False, "ssh connection failed."

def RestoreUserQueryFromRemote(remote_host, remote_user, remote_password, local_host, db_user, db_port, db_password, db_name, schema_file_path, data_file_path):
    os.environ['PGPASSWORD'] = db_password

    try:
        ssh = CreateSshClient(remote_host, 22, remote_user, remote_password)
        if ssh:
            pass
        else:
            logger.debug("Remote client connection failed.")
            return False

        csvFiles = [
            "user_role.csv",
            "user_department.csv",
            "user_department_department_user_roles.csv",
            "user_userprofile.csv",
        ]
            
        checkCsvCommand = f"ls {data_file_path}"
        stdin, stdout, stderr = ssh.exec_command(checkCsvCommand)

        exitStatus = stdout.channel.recv_exit_status()
        for csvFile in csvFiles:
            table_name = os.path.splitext(csvFile)[0]
            remoteCsvFilePath = os.path.join(data_file_path, csvFile)

            if exitStatus == 0:  # The file exists #BUG ID 1105: Restore - Postgres - remote - partial
                disableTriggersCommand = f"PGPASSWORD={db_password} psql -U {db_user} -h {local_host} -p {db_port} -d {db_name} -c \"ALTER TABLE {table_name} DISABLE TRIGGER ALL;\""
                stdin, stdout, stderr = ssh.exec_command(disableTriggersCommand)
                exitStatus = stdout.channel.recv_exit_status()

                if exitStatus != 0:
                    error_output = stderr.read().decode()
                    logger.error(f"Error disabling triggers for table {table_name}: {error_output}")
                    return False
        
                qtablename = f'\\\"{table_name}\\\"'
                copyCommand = f"\\COPY {qtablename} FROM '{remoteCsvFilePath}' WITH (FORMAT csv, HEADER true)"
                restoreDataCommand = f"PGPASSWORD={db_password} psql -U {db_user} -h {local_host} -p {db_port} -d {db_name} -c \"{copyCommand}\" "
                
                logger.debug(f"Restore Data Command: {restoreDataCommand}")
                stdin, stdout, stderr = ssh.exec_command(restoreDataCommand)
                exitStatus = stdout.channel.recv_exit_status()

                if exitStatus == 0:
                    logger.info(f"Successfully restored data from {remoteCsvFilePath} into table '{table_name}'.")
                else:
                    error_output = stderr.read().decode()
                    logger.error(f"Error restoring table {table_name} from {remoteCsvFilePath}: {error_output}")
                    logger.debug(f"Copy Command: {copyCommand}")
                    return False
        
                enableTriggersCommand = f"PGPASSWORD={db_password} psql -U {db_user} -h {local_host} -p {db_port} -d {db_name} -c \"ALTER TABLE {table_name} ENABLE TRIGGER ALL;\""
                stdin, stdout, stderr = ssh.exec_command(enableTriggersCommand)
                exitStatus = stdout.channel.recv_exit_status()

                if exitStatus != 0:
                    error_output = stderr.read().decode()
                    logger.error(f"Error enabling triggers for table {table_name}: {error_output}")
                    return False
                
            else:
                logger.info(f"CSV file {remoteCsvFilePath} does not exist on the remote machine.")
                return False
            
        return True

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return False
    finally:
        os.environ.pop("PGPASSWORD", None)  # Clean up the environment variable
        if ssh:
            ssh.close()
    
def IsDefaultDjangoTable(tableName):
    defaultTables = {
        'django_admin_log',
        'auth_permission',
        'auth_group_permissions',
        'auth_user_groups',
        'auth_user_user_permissions',
        'auth_group',
        'auth_user',
        'django_content_type',
        'django_session',
        'django_migrations',
    }
    return tableName in defaultTables

def SingleDatabaseBackup(user, host, port, password, dbname, filePath, remotefilePath, isRemote, remoteHost, remoteUser, remotePassword):
    
    if not isRemote:
        try:
            os.makedirs(filePath, exist_ok=True)
            backup_file = os.path.join(filePath, f"{dbname}_backup_{int(datetime.now().timestamp())}.sql")
            
            os.environ["PGPASSWORD"] = password
            command = [
                "pg_dump",
                "-h", host,
                "-p", str(port),
                "-U", user,
                "-d", dbname,
                "-F", "c",  # Custom format for compressed backups
                "-f", backup_file
            ]
            
            subprocess.run(command, check=True)
            logger.info(f"Backup successful! File saved at: {backup_file}")
            return True, backup_file
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Error during backup: {e}")
        finally:
            os.environ.pop("PGPASSWORD", None)
    
    else:
        try:
            ssh = CreateSshClient(remoteHost, 22, remoteUser, remotePassword)
            sftp = ssh.open_sftp()
            if CreateRemoteDirectoryIfNotExists(sftp, remotefilePath):
                pass
            else:
                return False, None
            
            remote_backup_filepath = os.path.join(remotefilePath, f"{dbname}_backup_{int(datetime.now().timestamp())}.sql")
            
            command = f"PGPASSWORD={password} pg_dump -U {user} -h {host} -p {port} -d {dbname} > {remote_backup_filepath}"
            logger.debug(f"Executing command: {command}")
            
            stdin, stdout, stderr = ssh.exec_command(command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                logger.info(f"Database backup successful! for database {dbname}. Saved to: {remote_backup_filepath}")
            else:
                logger.error(f"Error during database backup: {stderr.read().decode()}")
                return False, None
            
            return True, remote_backup_filepath
            
        except Exception as e:
            logger.error(f"Error during remote backup: {e}")
            return False, None
        
        finally:
            if 'PGPASSWORD' in os.environ:
                del os.environ['PGPASSWORD']
            if ssh:
                ssh.close()

def RestoreSingleDatabase(user, host, port, password, dbname, filePath, isRemote, remote_host, remote_user, remote_password):
    
    if not isRemote:
        try:
            os.environ["PGPASSWORD"] = password
            
            command = [
                "pg_restore",
                "-h", host,
                "-p", str(port),
                "-U", user,
                "-d", dbname,
                filePath
            ]
            
            # Run the restore command
            subprocess.run(command, check=True)
            logger.info(f"Restore successful! Database '{dbname}' restored from {filePath}")
            
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Error during restore: {e}")
            return False
        finally:
            if 'PGPASSWORD' in os.environ:
                del os.environ['PGPASSWORD']
    
    else:
        try:
            ssh = CreateSshClient(remote_host, 22, remote_user, remote_password)

            restore_schema_command = f"cat {filePath} | PGPASSWORD={password} psql -h {host} -p {port} -U {user} -d {dbname}"
            logger.debug(restore_schema_command)

            logger.info(f"Starting database restore for '{dbname}' using {filePath}...")
            stdin, stdout, stderr = ssh.exec_command(restore_schema_command)

            exit_status = stdout.channel.recv_exit_status()  # Wait for command to complete
            if exit_status == 0:
                logger.info(f"Successfully restored database {dbname} from {filePath}.")
                return True
            else:
                error_output = stderr.read().decode()
                logger.error(f"Error restoring database {dbname} from {filePath}: {error_output}")
                return False

        except Exception as e:
            logger.error("Error occurred while restoring database" + str(e))
            return False
        
        finally:
            if ssh:
                ssh.close()

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

SYSTEM_DATABASES = ["postgres", "template0", "template1"]

def DeleteUserDatabases(user,password,host,port):
    try:
        conn = psycopg2.connect(
            dbname = "postgres",
            user = user,
            password = password,
            host = host,
            port = port
        )
        
        if not conn:    #BUG ID 1300: Deletion;Invalid Credentials
            return False
        
        conn.autocommit = True
        
        cursor = conn.cursor()

        # Fetch all databases except the system databases
        cursor.execute("""
            SELECT datname
            FROM pg_database
            WHERE datname NOT IN (%s, %s, %s);
        """, tuple(SYSTEM_DATABASES))

        userDatabases = [db[0] for db in cursor.fetchall()]

        for db in userDatabases:
            logger.info(f"Dropping database: {db}")
            try:
                cursor.execute(f"DROP DATABASE \"{db}\" WITH (FORCE);")
                logger.info(f"Database {db} has been dropped successfully.")
            except Exception as e:
                logger.error(f"Failed to drop database {db}: {e}")

        cursor.execute("SELECT current_database();")
        current_db = cursor.fetchone()[0]
        logger.info(f"Connected to database: {current_db}")

        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables
            WHERE table_schema = 'public';
        """)
        
        tables = [table[0] for table in cursor.fetchall()]
        
        for table in tables:
            logger.info(f"Dropping table: {table}")
            try:
                cursor.execute(f"DROP TABLE IF EXISTS \"public\".\"{table}\" CASCADE;")
                logger.info(f"Table {table} has been dropped successfully.")
            except Exception as e:
                logger.error(f"Failed to drop table {table}: {e}")
        
        cursor.execute("""
            SELECT rolname 
            FROM pg_roles
            WHERE rolname NOT IN ('postgres', 'public');
        """)
        
        roles = [role[0] for role in cursor.fetchall()]
        
        for role in roles:
            logger.info(f"Dropping role: {role}")
            try:
                cursor.execute(f"DROP ROLE IF EXISTS \"{role}\";")
                logger.info(f"Role {role} has been dropped successfully.")
            except Exception as e:
                logger.error(f"Failed to drop role {role}: {e}")
    
        
        logger.info("All user databases have been deleted successfully.")
        cursor.close()
        conn.close()
        
        return True
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return False

def Duration(startTime, endTime):
    if endTime is None:
        endTime = datetime.now()
    duration = endTime - startTime
    totalSeconds = duration.total_seconds()
    hours, remainder = divmod(totalSeconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    formattedDuration = f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
    return formattedDuration

def IsValidFileName(userProvidedFilename):
    fileNamePattern = r'^[a-zA-Z0-9_.]{3,25}$'
    return re.match(fileNamePattern,userProvidedFilename) is not None    

def LocalBackupDetails():
    payload = { 
        "local_ip" : config["LOCAL_POSTGRESQL_HOST"],
        "local_path" : config["LOCAL_TEMP_DIR"],
    }
    
    response, conn = ConnectToDb(config["POSTGRESQL_USER"], 
                                 config["POSTGRESQL_PASSWORD"], 
                                 config["POSTGRESQL_HOST"], 
                                 config["POSTGRESQL_PORT"])
    if (not response):
        return False, conn
    
    try:
        cur = conn.cursor()
        
        # Fetch databases
        cur.execute("SELECT datname, pg_database_size(datname) AS size_in_bytes FROM pg_database WHERE datistemplate = false;")
        databases = cur.fetchall()
        cur.execute("""
            SELECT SUM(pg_database_size(datname)) AS total_size_in_bytes
            FROM pg_database
            WHERE datistemplate = false;
        """)
        
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
        
        remoteDiskUsage = GetDiskUsageRemote(config["LOCAL_POSTGRESQL_VM_USER"], 
                                             config["LOCAL_POSTGRESQL_VM_PASSWORD"], 
                                             config["LOCAL_POSTGRESQL_HOST"], 
                                             config["LOCAL_TEMP_DIR"])
        if not remoteDiskUsage:
            payload.update({
                "status":False,
                "message":"Invalid credentials provided. Please enter valid credentials",
                "data":None,
                "error":"Please provide valid credentials to check disk usage"
            })
            return False, payload

        logger.info("Viewing list of databases.")
        payload.update({
            "status":True,
            "disk_usage":remoteDiskUsage,
            "error":None,
        })
        return True, payload
    
    except Exception as e:
        logger.error(f"Error listing databases: {str(e)}")
        payload.update({
            "status":False,
            "disk_usage":None,
            "error":str(e)
        })
        return False, payload

def RemoteBackupDetails(remoteHost, remoteUser, remotePassword, remoteBackupPath):
    sshClient = CreateSshClient(remoteHost, 22, remoteUser, remotePassword)
    
    if sshClient:
        response, conn = ConnectToDb(config["POSTGRESQL_USER"], 
                                    config["POSTGRESQL_PASSWORD"], 
                                    config["POSTGRESQL_HOST"], 
                                    config["POSTGRESQL_PORT"])
        if (not response):
            return False, conn
        
        try:
            cur = conn.cursor()
            
            # Fetch databases
            cur.execute("SELECT datname, pg_database_size(datname) AS size_in_bytes FROM pg_database WHERE datistemplate = false;")
            databases = cur.fetchall()
            cur.execute("""
                SELECT SUM(pg_database_size(datname)) AS total_size_in_bytes
                FROM pg_database
                WHERE datistemplate = false;
            """)
            
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
            
            remoteDiskUsage = GetDiskUsageRemote(remoteUser, remotePassword, remoteHost, remoteBackupPath)

            if not remoteDiskUsage:
                payload = {
                    "status":False,
                    "message":"Invalid credentials provided. Please enter valid credentials",
                    "data":None,
                    "error":"Please provide valid credentials to check disk usage"
                }
                return False, payload

            logger.info("Viewing list of databases.")
            payload = {
                "status":True,
                "disk_usage":remoteDiskUsage,
                "error":None,
            }
            return True, payload
        
        except Exception as e:
            logger.error(f"Error listing databases: {str(e)}")
            payload = {
                "status":False,
                "disk_usage":None,
                "error":str(e)
            }
            return False, payload
    else:
        payload = {
            "status":False,
            "disk_usage":None,
            "error":str(e)
        }
        return False, "ssh connection failed."

def SaveDataToDb(backupType, backupMode, ipAddress, path, responseStatus, message, duration, userId):
    serializer = BackupRestoreSerializer(data={
                                            'database_type':"postgresql",
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
        backup.duration = duration
        backup.save()
        return True
    except Exception as e:
        logger.error(f"Error occurred while updating status in db: {e}")
        return False    

def PostgresVersion(username=None, password=None, host=None, port=None):
    try:
        conn = psycopg2.connect(
            dbname = "postgres",
            user = username if username else config['POSTGRESQL_USER'],
            password = password if password else config['POSTGRESQL_PASSWORD'],
            host = host if host else config['POSTGRESQL_HOST'],
            port = port if port else config['POSTGRESQL_PORT']
        )
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return version
    except Exception as e:
        logger.error(f"Error fetching PostgreSQL version: {e}")
        return None


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
            """, ("postgresql", backupType, backupMode))
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
                "postgresql",
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


def FetchRestoreLog(postgresHost, postgresPort, postgresUser, postgresPassword, postgresDatabaseName, postgresTableName, page, limit, databaseType=None, columnName=None, searchData=None):
    try:
        conn = psycopg2.connect(
            host=postgresHost,
            port=postgresPort,
            user=postgresUser,
            password=postgresPassword,
            dbname=postgresDatabaseName
        )
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        offset = (page - 1) * limit
        
        baseQuery = f"SELECT * FROM {postgresTableName}"
        countQuery = f"SELECT COUNT(*) FROM {postgresTableName}"
        whereClauses = []
        params = []

        if databaseType:
            whereClauses.append("database_type = %s")
            params.append(databaseType)

        if columnName and searchData and columnName != "all":
            whereClauses.append(f"{columnName} ILIKE %s")
            params.append(f"%{searchData}%")

        if whereClauses:
            whereSql = " WHERE " + " AND ".join(whereClauses)
            baseQuery += whereSql
            countQuery += whereSql

        baseQuery += " ORDER BY created_on DESC LIMIT %s OFFSET %s"
        queryParams = params + [limit, offset]

        logger.debug(f"Executed Query: {baseQuery}")
        cursor.execute(baseQuery, tuple(queryParams))
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        result = []

        for row in rows:
            rowDict = {}
            for colName in columns:
                colValue = row[colName]

                if colName == 'created_on' and colValue is not None:
                    colValue = datetime.fromtimestamp(colValue).strftime('%Y-%m-%d %H:%M:%S')

                rowDict[colName] = colValue

            result.append(rowDict)
        
        cursor.execute(countQuery, tuple(params))
        totalRecords = cursor.fetchone()['count']
        if result:
            payload = {
                "status": True,
                "message": "Restore logs fethced successfully.",
                "data": result,
                "error": None,
                "meta": {
                    "page": page,
                    "limit": limit,
                    "total": totalRecords
                }
            }
            return True, payload
        else:
            payload = {
                "status": False,
                "message": "No results found.",
                "data": None,
                "error": None
            }
            return False, payload

    except Exception as e:
        logger.error(f"Error fetching data: {e}")
        payload = {
            "status": False,
            "message": "Error fetching data from PostgreSQL",
            "data": None,
            "error": str(e)
        }
        return False, payload
    
    finally:
        try:
            if cursor: cursor.close()
            if conn: conn.close()
        except:
            pass
    
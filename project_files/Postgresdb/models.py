from django.db import models
import os
import uuid
from dotenv import load_dotenv

load_dotenv()
case_table = os.environ.get('DB_TABLE_NAME_FOR_CASE')

class BackupAndRestore(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    database_type  = models.CharField(max_length=100, null=False, blank=False, default=None)
    backup_type = models.CharField(max_length=100, null=False, blank=False, default=None)
    backup_mode = models.CharField(max_length=50, null=True, blank=True, default=None)
    ip_address = models.CharField(max_length=100, null=False, blank=False, default=None)
    path = models.CharField(max_length=255, null=True, blank=False, default=None)
    status = models.CharField(max_length=54, null=True, blank=False)
    summary = models.CharField(max_length=100, null=True, blank=False, default=None)
    duration = models.CharField(max_length=100, null=True, blank=False, default=None)
    
    created_on = models.BigIntegerField(blank=False, null=False)
    # updated_on = models.BigIntegerField(blank=False, null=False)
    created_by = models.CharField(max_length=40, null=False, blank=False, default=None)
    # updated_by = models.CharField(max_length=40, null=False, blank=False, default=None)

class DeletionRequestLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    file_id = models.CharField(blank=True, null=True, default=None,max_length=100)
    case_id = models.CharField(blank=True, null=True, default=None,max_length=100)
    name = models.CharField(max_length=100, null=True, blank=True, default=None)
    user_comment = models.CharField(max_length=100, null=True, blank=True, default=None)
    admin_comment = models.CharField(max_length=100, null=True, blank=True, default=None)
    system_generated_filename = models.CharField(blank=True, null=True, default=None,max_length=100)
    ingestion_source = models.CharField(blank=True, null=True, default=None,max_length=30)
    status = models.CharField(blank=True, null=True, default="Pending",max_length=30)
 
    created_on = models.BigIntegerField(blank=False, null=False)
    updated_on = models.BigIntegerField(blank=False, null=False)
    created_by = models.CharField(max_length=40, null=False, blank=False, default=None)
    updated_by = models.CharField(max_length=40, null=False, blank=False, default=None)

class Case(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    formatted_name  = models.CharField(max_length=100, null=False, blank=False, default=None)
    name = models.CharField(max_length=100, null=False, blank=False, default=None)
    
    class Meta:
        managed = False
        db_table = case_table
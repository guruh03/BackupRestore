from .models import *
from django.conf import settings
from rest_framework import serializers
from datetime import datetime
import pytz
time_zone = settings.TIME_ZONE

class BackupRestoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = BackupAndRestore
        fields = '__all__'
        
class GetBackupRestoreSerializer(serializers.ModelSerializer):
    created_on = serializers.SerializerMethodField()
    
    class Meta:
        model = BackupAndRestore
        exclude = []
    
    def get_created_on(self, obj):
        naive_datetime = datetime.fromtimestamp(obj.created_on)
        converted_datetime = naive_datetime.astimezone(pytz.timezone(time_zone))
        datetime_string = converted_datetime.strftime("%Y-%m-%dT%H:%M:%S")
        return datetime_string

class DeletionRequestLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeletionRequestLog
        fields = '__all__'
        
class GetDeletionRequestLogSerializer(serializers.ModelSerializer):
    created_on = serializers.SerializerMethodField()
    updated_on = serializers.SerializerMethodField()
    
    class Meta:
        model = DeletionRequestLog
        exclude = []
    
    def get_created_on(self, obj):
        naive_datetime = datetime.fromtimestamp(obj.created_on)
        converted_datetime = naive_datetime.astimezone(pytz.timezone(time_zone))
        datetime_string = converted_datetime.strftime("%Y-%m-%dT%H:%M:%S")
        return datetime_string
    
    def get_updated_on(self, obj):
        naive_datetime = datetime.fromtimestamp(obj.updated_on)    
        converted_datetime = naive_datetime.astimezone(pytz.timezone(time_zone))
        datetime_string = converted_datetime.strftime("%Y-%m-%dT%H:%M:%S")
        return datetime_string
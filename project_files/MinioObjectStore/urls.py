from django.urls import path
from .views import *

urlpatterns = [
    path('MinioVersion/',FetchMinioVersion.as_view(),name='Minio-Version'),
    path('BuildMinioConnection/',BuildMinioConnection.as_view(),name='Check-Minio-Connection'),
    path('ListBuckets/', FetchBuckets.as_view(),name='List-Buckets'),
    path('BackupMinio/', MinioBackup.as_view(),name='Minio-Backup'),
    path('RestoreMinio/', MinioRestore.as_view(),name='Minio-Restore'),
    path('LocalBackupDetails/',FetchLocalBackupDetails.as_view(),name="Fetch-Local-Backup-Details"),
    path('CheckRemoteConnection/',CheckRemoteConnection.as_view(),name="Check-Remote-Connection"),
    
    #Deletion
    path('DeleteMinio/', DeleteMinioData.as_view(),name='Minio-Delete'),
    
]
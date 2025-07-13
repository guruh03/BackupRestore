from django.urls import path
from .views import *

urlpatterns = [
    path('ElasticVersion/',ElasticSearchVersion.as_view(),name='Elastic-Version'),
    path('BuildElasticSearchConnection/',BuildElasticConnection.as_view(),name='Check-ElasticSearch-Connection'),
    path('ListIndexes/', ViewIndexes.as_view(),name='List-Indexes'),
    path('BackupIndexes/',BackupIndexes.as_view(),name='Backup-Indexes'),
    path('RestoreIndexesFromRemote/',RestoreIndexesFromRemote.as_view(),name='Restore-Files'),
    path('SnapshotRepository/',RegisterSnapshotRepository.as_view(),name='Register-Repository'),
    path('RestoreIndexes/',RestoreSnapshots.as_view(),name='Restore-Snapshots'),
    path('LocalBackupDetails/',FetchLocalBackupDetails.as_view(),name="Fetch-Local-Backup-Details"),
    path('CheckRemoteConnection/',CheckRemoteConnection.as_view(),name="Check-Remote-Connection"),
    
    #Deletion
    path('DeleteIndexes/',DeleteElasticData.as_view(),name='Delete-indexes'),
    
]
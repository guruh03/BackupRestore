from django.urls import path
from .views import *

urlpatterns = [
    path('BackupScylla/', ScyllaBackupForSingleTable.as_view(),name='Scylla-Backup'),
    # path('CheckScyllaKeyspaceAndTable/',ScyllaKeyspaceAndTable.as_view(), name='Check-Scylla-KeyspaceAndTable'),
    # path('RestoreScylla/',ScyllaRestoreForSingleTable.as_view(),name='Scylla-Restore'),
    path('BuildScyllaConnection/',BuildScyllaConnection.as_view(),name='Check-Scylla-Connection'),
    path('ScyllaVersion/',FetchScyllaVersion.as_view(),name='Scylla-Version'),
    path('FetchKeyspaces/',FetchKeyspaces.as_view(),name='Fetch-Keyspaces'),
    path('BackupKeyspace/',ScyllaBackupKeyspace.as_view(),name="Backup-Keyspace"),
    path('ViewSnapshots/',ViewSnapshots.as_view(),name="View-Snapshots"),
    path('RestoreKeyspace/',ScyllaRestoreKeyspace.as_view(),name="Restore-Keyspace"),
    path('RestartScylla/',RestartScylla.as_view(),name="Restart-Scylla"),
    path('LocalBackupDetails/',FetchLocalBackupDetails.as_view(),name="Fetch-Local-Backup-Details"),
    path('CheckRemoteConnection/',CheckRemoteConnection.as_view(),name="Check-Remote-Connection"),
    
    ## Truncation and Deletion
    path('ScyllaTruncate/',ScyllaTruncate.as_view(),name="ScyllaTruncate"),
    path('DeleteScylla/',DeleteScyllaData.as_view(),name="Delete-Scylla"),
    
]
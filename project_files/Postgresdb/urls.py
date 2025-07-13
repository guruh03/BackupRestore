from .views import *
from .utils import *
from django.urls import path

urlpatterns = [
    path('PostgresVersion/',FetchPostgresVersion.as_view(),name='Postgres-Version'),
    path('BuildPostgresConnection/',BuildPostgresConnection.as_view(),name='Check-Postgres-Connection'),
    path('FetchDatabases/',FetchDatabases.as_view(),name='Fetch-Postgres-Databases'),
    path('BackupPostgres/', PostgresBackup.as_view(),name='Postgres-Backup'),
    path('RestorePostgres/',PostgresRestoreServer.as_view(),name='Postgres-Restore'),
    # path('PartialRestore/',RestoreSchemaWithData.as_view(), name='partial-Restore'),
    path('DateRange/',FetchDateRange.as_view(),name="Fetch-Date-Range"),
    path('LocalBackupDetails/',FetchLocalBackupDetails.as_view(), name="Fetch-Local-Backup-Details"),
    path('CheckRemoteConnection/',CheckRemoteConnection.as_view(),name="Check-Remote-Connection"),
    path('ViewBackUpRestore/',ViewBackUpRestore.as_view(),name='View-BackUprestore'),
    path('FetchRestoreLogs/',FetchRestoreLogs.as_view(),name="Fetch-Scylla-Restore-Logs"),
    
    # Deletion Endpoints
    path('DeletePostgres/',DeletePostgresData.as_view(),name="Delete-Postgres"),
    
]
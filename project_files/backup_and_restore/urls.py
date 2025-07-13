"""
URL configuration for backup_and_restore project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="Backup and Restore REST APIs ",
        default_version='v1',
        description="This API documentation contains all the required information to use the B&R API's.",
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('api/v1/backuprestore/swaggerui/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('api/v1/backuprestore/docs/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('api/v1/backuprestore/swagger.json', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    
    path('admin/', admin.site.urls),
    path('api/v1/backuprestore/scylla/',include('Scylladb.urls')),
    path('api/v1/backuprestore/postgres/',include('Postgresdb.urls')),
    path('api/v1/backuprestore/minio/',include('MinioObjectStore.urls')),
    path('api/v1/backuprestore/elastic/',include('ElasticSearch.urls')),
    path('api/v1/backuprestore/deletion/',include('Deletion.urls')),
]

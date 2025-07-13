from django.urls import path
from .views import *
urlpatterns = [
    # path('FileDeletion/', PartialDeletion.as_view(),name='File-Deletion'),
    path('CompleteDeletion/', CompleteDeletion.as_view(),name='Complete-Deletion'),
    path('ApproveRejectFiles/',ApproveFiles.as_view(),name='Approve-Reject-Files')
]
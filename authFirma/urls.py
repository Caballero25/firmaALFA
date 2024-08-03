from django.urls import path
from . import views

urlpatterns = [
    path('', views.prueba01, name='upload_document'),
]
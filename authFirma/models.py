from django.db import models

class Document(models.Model):
    pdf = models.FileField(upload_to='documents/pdfs/')
    p12 = models.FileField(upload_to='documents/p12s/')
    password = models.CharField(max_length=255)

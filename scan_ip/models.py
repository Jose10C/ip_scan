from django.db import models
from django.db.models.signals import post_migrate

class Departamento(models.Model):
    id = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=100, null=True, blank=True)
    
    def __str__(self):
        return self.nombre

class Responsable(models.Model):
    id = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=100)
    apellido = models.CharField(max_length=100, null=True, blank=True)
    email = models.EmailField()
    departamento = models.ForeignKey(Departamento, on_delete=models.CASCADE)
    
    def __str__(self):
        return self.nombre

def cargar_responsable_predeterminado(sender, **kwargs):
    if not Responsable.objects.filter(nombre="Sin responsable").exists():
        departamento_default = Departamento.objects.create(nombre="Default")
        Responsable.objects.create(nombre="Sin responsable", departamento=departamento_default)

post_migrate.connect(cargar_responsable_predeterminado)

class Ip(models.Model):
    id = models.AutoField(primary_key=True)
    ip = models.CharField(max_length=100)
    hostname = models.CharField(max_length=100)
    mac = models.CharField(max_length=100)
    
    def __str__(self):
        return self.ip

class Equipo(models.Model):
    id = models.AutoField(primary_key=True)
    hostname = models.CharField(max_length=100, null=True, blank=True)
    so = models.CharField(max_length=100, null=True, blank=True)
    archi = models.CharField(max_length=100, null=True, blank=True)
    user_name = models.CharField(max_length=100, null=True, blank=True)
    user_pass = models.CharField(max_length=100, null=True, blank=True)
    install_date = models.CharField(max_length=100, null=True, blank=True)
    manufacture = models.CharField(max_length=100, null=True, blank=True)
    serial = models.CharField(max_length=100, null=True, blank=True)
    procesador = models.CharField(max_length=100, null=True, blank=True)
    ram = models.CharField(max_length=100, null=True, blank=True)
    storage1 = models.CharField(max_length=100, null=True, blank=True)
    storage2 = models.CharField(max_length=100, null=True, blank=True)
    ipv4 = models.CharField(max_length=100, null=True, blank=True)
    dirmac = models.CharField(max_length=100, null=True, blank=True)
    responsable = models.ForeignKey(Responsable, on_delete=models.CASCADE)
    
    def __str__(self):
        return self.hostname

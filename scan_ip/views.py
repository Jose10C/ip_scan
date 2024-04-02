from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from django.db import IntegrityError

import nmap
import concurrent.futures
import socket
from scapy.all import ARP, Ether, srp
import paramiko
from django.http import JsonResponse
import json
import qrcode
from pythonping import ping

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from .models import Equipo
from .models import Ip
from .models import Departamento
from .models import Responsable

segipv4_gen = "192.168.1.1"
mac_local = "AA:BB:CC:DD:EE:FF"
ip_local = "192.168.1.1"


# Create your views here.
def logins(request):
    return render(request, 'signup.html',{
        'form': UserCreationForm()
    })

#Funcion Vista Login
def signup(request):
    #Get all date
    if request.method == 'GET':
        return render(request, 'register.html',{
            'form': UserCreationForm()
        })
    else:
        if request.POST['password1'] == request.POST['password2']:
            try:
                user = User.objects.create_user(
                    username = request.POST['username'],
                    password=request.POST['password1'],
                    email = request.POST['email'])
                user.save()
                login(request, user)
                return redirect('home')
            except IntegrityError:
                return render(request, 'register.html', {
                    'form': UserCreationForm(),
                    'error': 'El usuario ya existe'
                })
        else:
            return render(request, 'register.html', {
                'form': UserCreationForm(),
                'error': 'Las contraseñas no coinciden'
            })
    return render(request, 'home.html')


def home(request):
    total_depa = Departamento.objects.count()
    total_respo = Responsable.objects.count()
    total_equipos = Equipo.objects.count()
    total_usuarios = User.objects.count()
    return render(request, 'home.html', {'total_depa': total_depa, 'total_respo': total_respo, 'total_equipos': total_equipos, 'total_usuarios': total_usuarios})

def signout(request):
    logout(request)
    return redirect('signin')

def signin(request):
    if request.method == 'GET':
        return render(request, 'signin.html', { 'form': AuthenticationForm() })
    else:
        user = authenticate(request, username=request.POST['username'], password=request.POST['password'])
        if user is None:
            return render(request, 'signin.html', { 'form': AuthenticationForm(), 'error': 'Usuario o la contraseña son incorrectos' })
        else:
            login(request, user)
            return redirect('home')



# Escaner de IP
def scan(request):
    return render(request, 'scan_ip.html')

def escanear_red_view(request, ip):
    global mac_local
    global ip_local
    global segipv4_gen
    ip_range = ip + "/24"
    segipv4_gen = ip
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=5, verbose=False)[0]

    dispositivos_en_red = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for sent, received in result:
            ip = received.psrc  # Obteniendo la dirección IP del dispositivo
            mac = received.hwsrc
            ip_local = ip
            mac_local = mac
            try:
                nombre_host = socket.gethostbyaddr(ip)[0]
            except Exception as e:
                nombre_host = ip
            dispositivos_en_red.append({'ip': ip, 'mac': mac, 'hostname': nombre_host})

    return JsonResponse({'ips': dispositivos_en_red})

#info_equipo
def info_equipo(request, ip):
    responsables = Responsable.objects.all()
    informacion = {}
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Conectar por SSH y obtener información
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(ip, username=username, password=password)

        _, hostname_stdout, _ = ssh_client.exec_command('hostname')
        _, soname_stdout, _ = ssh_client.exec_command('systeminfo | find "Nombre del sistema operativo"')
        _, architecture_stdout, _ = ssh_client.exec_command('systeminfo | find "Tipo de sistema"')
        _, username_stdout, _ = ssh_client.exec_command('systeminfo | find "Propiedad de:"')
        _, install_date_stdout, _ = ssh_client.exec_command('systeminfo | find "Fecha de instalación"')
        _, manufacture_stdout, _ = ssh_client.exec_command('systeminfo | find "Fabricante del sistema:"')
        _, serial_stdout, _ = ssh_client.exec_command('wmic bios get serialnumber')
        _, procesador_stdout, _ = ssh_client.exec_command('wmic cpu get Name')
        _, stored_stdout, _ = ssh_client.exec_command('wmic diskdrive get Size')
        _, memoria_ram_stdout, _ = ssh_client.exec_command('wmic memorychip get Capacity')
        
        # Leer la salida de los comandos y limpiarla
        hostname = hostname_stdout.read().strip().decode('utf-8')
        soname = soname_stdout.read().strip().decode('utf-8')
        architecture = architecture_stdout.read().strip().decode('utf-8')
        username = username_stdout.read().strip().decode('utf-8')
        install_date = str(install_date_stdout.read().strip())
        manufacture = manufacture_stdout.read().strip().decode('utf-8')
        serial = serial_stdout.read().strip().decode('utf-8')
        procesador = procesador_stdout.read().strip().strip().decode('utf-8')
        stored = stored_stdout.read().strip().strip().decode('utf-8')#)/1024^3
        memoria_ram = memoria_ram_stdout.read().strip().strip().decode('utf-8')#)/1024^3
        
        informacion = {
            'hostname': hostname,
            'soname': soname,
            'architecture': architecture,
            'username': username,
            'install_date': install_date,
            'manufacture': manufacture,
            'serial': serial,
            'procesador': procesador,
            'stored': stored,
            'memoria_ram': memoria_ram,
            'ipv4': ip_local,
            'mac': mac_local,
        }

        ssh_client.close()

        # Convertir el diccionario a formato JSON
        info_json = json.dumps(informacion)

        return render(request, 'info_device.html', {'info': informacion, 'ip': ip, 'responsables': responsables})
    else:
        return render(request, 'info_device.html', {'ip': ip, 'responsables': responsables})
        
def guardar_informacion(request):
    if request.method == 'POST':
        hostname = request.POST.get('hostname')
        so = request.POST.get('so')
        archi = request.POST.get('archi')
        user_name = request.POST.get('user_name')
        user_pass = request.POST.get('user_pass')
        install_date = request.POST.get('install_date')
        manufacture = request.POST.get('manufacture')
        serial = request.POST.get('serial')
        procesador = request.POST.get('procesador')
        ram = request.POST.get('ram')
        storage1 = request.POST.get('storage1')
        storage2 = request.POST.get('storage2')
        ipv4 = request.POST.get('ipv4')
        dirmac = request.POST.get('dirmac')
        responsable_id = request.POST.get('responsable')

        equipo = Equipo(
            hostname=hostname,
            so=so,
            archi=archi,
            user_name=user_name,
            user_pass=user_pass,
            install_date=install_date,
            manufacture=manufacture,
            serial=serial,
            procesador=procesador,
            ram=ram,
            storage1=storage1,
            storage2=storage2,
            ipv4=ipv4,
            dirmac=dirmac,
            responsable_id=responsable_id
        )
        equipo.save()
        return redirect('/info_equipo/{}/'.format(ipv4), {'info': 'Información guardada correctamente'})

    return render(request, 'info_device.html', {'error': 'Error al guardar la información del equipo'})

def lista_equipos(request):
    equipos = Equipo.objects.all()
    return render(request, 'list_devices.html', {'equipos': equipos})


def detalle_equipo(request, hostname):
    equipo = Equipo.objects.get(hostname=hostname)
    return render(request, 'detalle_equipo.html', {'equipo': equipo})

def lista_ips(request):
    ips = Ip.objects.all()
    return render(request, 'list_ips.html', {'ips':ips})

def ver_estado_ips(request):
    numeros = segipv4_gen.split(".")

    ips = {}    
    for i in range(1, 20):
        ips[f"{numeros[0]}.{numeros[1]}.{numeros[2]}.{i}"] = True

    estados = {}

    for ip in ips:
        try:
            response = ping(ip, count=1, timeout=1)
            if response.success():
                estado = "Activo"
                #estado = {'estado': "Activo", 'imagen': settings.STATIC_URL + 'images/activo.gif'}
            else:
                estado = "Inactivo"
                #estado = {'estado': "Inactivo", 'imagen': settings.STATIC_URL + 'images/inactivo.gif'}
        except Exception as e:
            estado = "Inactivo (Error)"

        estados[ip] = estado

    return JsonResponse(estados)

def estado_ips(request):
    return render(request, 'ip_status_live.html')

################## Departamento ##################
def departamento(request):
    departamentos = Departamento.objects.all()
    return render(request, 'departamento.html', {'departamentos': departamentos})

def crear_departamento(request):
    if request.method == 'POST':
        nombre = request.POST.get('nombre')
        departamento = Departamento(nombre=nombre)
        departamento.save()
        return redirect('departamento')
    return render(request, 'departamento.html')

def editar_departamento(request, id):
    departamento = Departamento.objects.get(pk=id)
    return render(request, 'editar_departamento.html', {'departamento': departamento})

def modificar_departamento(request, id):
    if request.method == 'POST':
        departamento = Departamento.objects.get(pk=id)
        departamento.nombre = request.POST.get('nombre')
        departamento.save()
        return redirect('departamento')

def eliminar_departamento(request, id):
    departamento = Departamento.objects.get(pk=id)
    departamento.delete()
    return redirect('departamento')

################ Responsables #####################
def responsable(request):
    departamentos = Departamento.objects.all()
    responsables = Responsable.objects.all()
    return render(request, 'responsable.html', {'departamentos': departamentos, 'responsables': responsables})

def crear_responsable(request):
    if request.method == 'POST':
        nombre = request.POST.get('nombre')
        apellido = request.POST.get('apellido')
        email = request.POST.get('email')
        departamento_id = request.POST.get('departamento')
        departamento = Departamento.objects.get(pk=departamento_id)
        responsable = Responsable(nombre=nombre, apellido=apellido, email=email, departamento=departamento)
        responsable.save()
        return redirect('responsable')
    return render(request, 'responsable.html')

def editar_responsable(request, id):
    responsable = Responsable.objects.get(pk=id)
    departamentos = Departamento.objects.all()
    return render(request, 'editar_responsable.html', {'responsable': responsable, 'departamentos': departamentos})

def modificar_responsable(request, id):
    if request.method == 'POST':
        responsable = Responsable.objects.get(pk=id)
        responsable.nombre = request.POST.get('nombre')
        responsable.apellido = request.POST.get('apellido')
        responsable.email = request.POST.get('email')
        departamento_id = request.POST.get('departamento')
        departamento = Departamento.objects.get(pk=departamento_id)
        responsable.departamento = departamento
        responsable.save()
        return redirect('responsable')
############################## QR - PDF ######################################
def generar_qr(request, url):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=7,
        border=4,
    )
    # Agregar los datos (URL) al objeto QRCode
    qr.add_data(url)
    qr.make(fit=True)
    # Crear la imagen QR y guardarla en un objeto de respuesta HTTP
    imagen_qr = qr.make_image(fill_color="black", back_color="white")
    response = HttpResponse(content_type="image/png")
    imagen_qr.save(response, "PNG")
    return response

def generar_pdf(request):
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="informacion_equipo.pdf"'

    # Crear un objeto PDF
    pdf = canvas.Canvas(response, pagesize=letter)
    
    # Obtener los datos del formulario
    equipo = Equipo.objects.get(pk=request.POST['equipo_id'])  # Suponiendo que tienes un modelo Equipo
    pdf.setFont("Helvetica-Bold", 12)
    
    # Dibujar los datos en el PDF
    pdf.drawString(150, 780, f"Hoja de Vida del Equipo {equipo.manufacture} - {equipo.serial}")
    pdf.setFont("Helvetica", 10) 
    pdf.drawString(100, 760, f"Nombre de Host: {equipo.hostname}")
    pdf.drawString(100, 740, f"Sistema Operativo: {equipo.so}")
    pdf.drawString(100, 720, f"Arquitectura: {equipo.archi}")
    pdf.drawString(100, 700, f"Fecha Instalación: {equipo.install_date}")
    pdf.drawString(100, 680, f"Fabricante: {equipo.manufacture}")
    pdf.drawString(100, 660, f"N° Serie: {equipo.serial}")
    pdf.drawString(100, 640, f"Procesador: {equipo.procesador}")
    pdf.drawString(100, 620, f"M. RAM: {equipo.ram}")
    pdf.drawString(100, 600, f"Disco 1: {equipo.storage1}")
    pdf.drawString(100, 580, f"Disco 2: {equipo.storage2}")
    pdf.drawString(100, 560, f"Dirección IP: {equipo.ipv4}")
    pdf.drawString(100, 540, f"Dirección MAC: {equipo.dirmac}")
    pdf.drawString(100, 520, f"Usuario Asignado: {equipo.user_name}")
    # Agrega más campos según sea necesario...

    pdf.showPage()
    pdf.save()
    
    return response

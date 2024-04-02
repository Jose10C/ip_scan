"""escaner_info URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
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
from django.urls import path
from django.contrib.auth.decorators import login_required
from scan_ip import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('logins/', views.login, name='login'),
    path('signup/', views.signup, name='signup'),
    path('home/', views.home, name='home'),
    path('signout/', views.signout, name='signout'),
    path('signin/', views.signin, name='signin'),
    path('', views.signin, name='signin'),
    #path('accounts/',include('django.contrib.auth.urls')),
    
    path('scan_ip/', login_required(views.scan), name='scan'),
    path('escanear_red_view/<str:ip>', login_required(views.escanear_red_view), name='escanear_red_view'),
    path('info_equipo/<str:ip>/', login_required(views.info_equipo)),
    path('lista_equipos/', login_required(views.lista_equipos), name='lista_equipos'),
    path('guardar_informacion/', login_required(views.guardar_informacion), name='guardar_informacion'),
    path('lista_ips/', login_required(views.lista_ips), name='lista_ips'),
    path('estado_ips/', login_required(views.estado_ips), name='estado_ips'),
    path('estado_ips_ver/', login_required(views.ver_estado_ips), name='estado_ips'),

    path('departamento/', login_required(views.departamento), name='departamento'),
    path('departamento/guardar_depa/', login_required(views.crear_departamento), name='crear_departamento'),
    path('departamento_edit/<int:id>/', login_required(views.editar_departamento), name='editar_departamento'),
    path('modificar_departamento/<int:id>/', login_required(views.modificar_departamento), name='modificar_departamento'),
    path('eliminar_departamento/<int:id>/', login_required(views.eliminar_departamento), name='eliminar_departamento'),
    #path('responsable/', login_required(views.responsable), name='responsable'),
    path('responsable/', login_required(views.responsable), name='responsable'),
    path('responsable/guardar/', login_required(views.crear_responsable), name='crear_responsable'),
    path('responsable_edit/<int:id>/', login_required(views.editar_responsable), name='editar_responsable'),
    path('modificar_responsable/<int:id>/', login_required(views.modificar_responsable), name='modificar_responsable'),
    
    path('public/equipo/detalle/views/<str:hostname>/', views.detalle_equipo, name='detalle_equipo'),
    path('generar_qr/<path:url>/', views.generar_qr, name='generar_qr'),
    path('generar_pdf/', views.generar_pdf, name='generar_pdf'),
]

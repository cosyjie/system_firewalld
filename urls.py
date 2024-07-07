from django.urls import path, include
from django.contrib.auth.decorators import login_required

from . import views

app_name = 'system_firewalld'

urlpatterns = [
    path('install/index/', login_required(views.InstallView.as_view()), name='install'),
    path('install/run/', login_required(views.install_run), name='install-run'),
    path('status/action/', login_required(views.firewalld_status), name='firewalld_action'),
    path('ping/action/', login_required(views.ping_action), name='ping-action'),
    path('port/list/', login_required(views.PortsListView.as_view()), name='port-list'),
    path('port/add/', login_required(views.PortsCreateView.as_view()), name='port_create'),
    path('port/delete/<int:pk>/', login_required(views.PortsDelView.as_view()), name='port_delete'),
    path('port/edit/<int:pk>/', login_required(views.PortsEditView.as_view()), name='port_edit'),
    path('sync/ports/<int:type_at>/', login_required(views.CheckSystemPortsView.as_view()), name='check_ports'),
    path('sync/ports/action/<int:type_at>/<int:pk>/', login_required(views.SyncPortsView.as_view()), name='sync_ports'),
    path('sync/ports/delete/<int:type_at>/<int:pk>/', login_required(views.SyncPortsDelView.as_view()), name='sync_ports_del'),

]

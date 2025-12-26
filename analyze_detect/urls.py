from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('detect/', views.detect_vulnerabilities, name='detect'),
    path('result/<int:scan_id>/', views.result, name='result'),
    path('monitor/start/', views.start_monitor, name='start_monitor'),
    path('monitor/list/', views.list_monitored, name='list_monitored'),
    path('monitor/stop/<int:pk>/', views.stop_monitor, name='stop_monitor'),
]

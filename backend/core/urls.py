from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from monitoring import views

urlpatterns = [
    # Django Admin
    path('admin/', admin.site.urls),

    # Frontend Dashboard Views
    path('', views.dashboard_view, name='dashboard'),
    path('processes/', views.processes_view, name='processes'),
    path('services/', views.services_view, name='services'),
    path('alerts/', views.alerts_view, name='alerts'),
    path('system-health/', views.system_health_view, name='system_health'),
    path('event-logs/', views.event_logs_view, name='event_logs'),
    path('ioc-management/', views.ioc_management_view, name='ioc_management'),
    path('reports/', views.reports_view, name='reports'),
    path('investigation/', views.investigation_view, name='investigation'),
    path('settings/', views.settings_view, name='settings'),
    path('profile/', views.profile_view, name='profile'),
    path('network/', views.network_view, name='network'),
    path('endpoints/', views.endpoints_view, name='endpoints'),
    
    # Auth Views
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    path('verify/', views.verify_view, name='verify'),
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('reset-password/', views.reset_password_view, name='reset_password'),
    path('change-password/', views.change_password_view, name='change_password'),

    # Actions & Exports
    path('reports/generate/', views.generate_report_view, name='generate_report'),
    path('investigation/export/<int:pk>/', views.export_investigation_view, name='export_investigation'),
    path('ioc-management/delete/<int:pk>/', views.delete_ioc_view, name='delete_ioc'),
    path('ioc-management/toggle/<int:pk>/', views.toggle_ioc_view, name='toggle_ioc'),

    # REST APIs for Agents & Dashboard Controls
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Agent Heartbeat & Identity Registration
    path('api/agent/register/', views.AgentRegisterAPI.as_view(), name='api_agent_register'),
    path('api/agent/heartbeat/', views.AgentHeartbeatAPI.as_view(), name='api_agent_heartbeat'),

    # Telemetry Ingestion (Agent-facing)
    path('api/telemetry/processes/', views.ProcessTelemetryAPI.as_view(), name='api_processes'),
    path('api/telemetry/services/', views.ServiceTelemetryAPI.as_view(), name='api_services'),
    path('api/telemetry/logs/', views.EventLogTelemetryAPI.as_view(), name='api_logs'),
    path('api/telemetry/health/', views.SystemHealthTelemetryAPI.as_view(), name='api_health'),
    path('api/telemetry/network/', views.NetworkTelemetryAPI.as_view(), name='api_network'),
    path('api/alerts/create/', views.CreateAlertAPI.as_view(), name='api_create_alert'),
    path('api/iocs/active/', views.ActiveIOCsAPI.as_view(), name='api_active_iocs'),

    # Datatables and JSON updates (Ajax endpoints)
    path('api/dashboard/stats/', views.dashboard_stats_api, name='dashboard_stats_api'),
    path('api/dashboard/chart/', views.dashboard_chart_api, name='dashboard_chart_api'),
    path('api/admin/send-test-email/', views.send_test_email_api, name='api_send_test_email'),
    path('api/ai/analyze-case/<int:pk>/', views.ai_analyze_case_api, name='api_ai_analyze_case'),
]

from celery import Celery, shared_task
from celery.schedules import crontab
from django.utils import timezone
from datetime import timedelta
from ip_tracking.models import SuspiciousIP
from ip_tracking.models import IPLog  #  IP tracking model


# 1. CELERY APP CONFIGURATION

app = Celery('ip_tracking')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()


# 2. PERIODIC TASKS SETUP

app.conf.beat_schedule = {
    'detect-anomalies-every-hour': {
        'task': 'ip_tracking.tasks.detect_anomalies',
        'schedule': crontab(minute=0, hour='*'),  # every hour
    },
}




SENSITIVE_PATHS = ['/admin', '/login']

@shared_task
def detect_anomalies():
    """Detects suspicious IP behavior hourly."""
    one_hour_ago = timezone.now() - timedelta(hours=1)
    
    # Get logs from the last hour
    recent_logs = IPLog.objects.filter(timestamp__gte=one_hour_ago)

    # Count requests per IP
    ip_counts = {}
    for log in recent_logs:
        ip_counts[log.ip_address] = ip_counts.get(log.ip_address, 0) + 1

        # Check sensitive paths
        if log.path in SENSITIVE_PATHS:
            SuspiciousIP.objects.get_or_create(
                ip_address=log.ip_address,
                reason=f"Accessed sensitive path: {log.path}"
            )

    # Check rate-based anomalies
    for ip, count in ip_counts.items():
        if count > 100:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                reason=f"Excessive requests ({count}) in last hour"
            )

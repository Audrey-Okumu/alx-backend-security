import logging
from django.utils import timezone
from .models import RequestLog

logger = logging.getLogger(__name__)

class IPLoggingMiddleware:
    """Middleware to log client IP, timestamp, and request path."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Extract client IP
        ip_address = self.get_client_ip(request)
        path = request.path
        timestamp = timezone.now()

        # Log the data to the database
        RequestLog.objects.create(ip_address=ip_address, path=path, timestamp=timestamp)

        # Optionally log to console/file
        logger.info(f"IP: {ip_address} | Path: {path} | Time: {timestamp}")

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        """Retrieve IP address from headers or META."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

import logging
from django.http import HttpResponseForbidden
from django.utils import timezone
from .models import RequestLog, BlockedIP

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

        #  Check if IP is blocked 
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            logger.warning(f"Blocked request from IP: {ip_address}")
            return HttpResponseForbidden("Access denied: your IP is blocked.")

        #  Log request details 
        try:
            RequestLog.objects.create(ip_address=ip_address, path=path, timestamp=timestamp)
            logger.info(f"IP: {ip_address} | Path: {path} | Time: {timestamp}")
        except Exception as e:
            logger.error(f"Failed to log request from {ip_address}: {e}")


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

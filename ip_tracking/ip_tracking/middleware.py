import logging
from django.http import HttpResponseForbidden
from django.utils import timezone
from django.core.cache import cache
from .models import RequestLog, BlockedIP
from django_ip_geolocation.backends import IPGeolocationAPI

logger = logging.getLogger(__name__)

class IPTrackingMiddleware:
    """
    Middleware to:
    1. Block blacklisted IPs
    2. Log request details including geolocation (country, city) with caching
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)
        path = request.path
        timestamp = timezone.now()

        # 1. Block list check
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            logger.warning(f"Blocked request from IP: {ip_address}")
            return HttpResponseForbidden("Access denied: your IP is blocked.")

        # 2. Geolocation lookup with caching (cache key based on IP)
        cache_key = f"geoip_{ip_address}"
        geo_data = cache.get(cache_key)
        if geo_data is None:
            try:
                geo_backend = IPGeolocationAPI(ip_address)
                location = geo_backend.lookup()
                country = location.get('country_name', '') or location.get('country', '')
                city = location.get('city', '')
            except Exception as e:
                logger.error(f"Geo-lookup failed for {ip_address}: {e}")
                country = ''
                city = ''
            geo_data = {'country': country, 'city': city}
            cache.set(cache_key, geo_data, 86400)
        else:
            country = geo_data.get('country', '')
            city = geo_data.get('city', '')

        # 3. Logging request including geolocation
        try:
            RequestLog.objects.create(
                ip_address=ip_address,
                path=path,
                timestamp=timestamp,
                country=country,
                city=city
            )
            logger.info(f"IP: {ip_address} | Path: {path} | Time: {timestamp} | {city}, {country}")
        except Exception as e:
            logger.error(f"Failed to log request from {ip_address}: {e}")

        # Continue processing
        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip

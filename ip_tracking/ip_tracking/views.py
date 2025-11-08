from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from ratelimit.decorators import ratelimit
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required


@csrf_exempt
@ratelimit(key='ip', rate='5/m', block=True)  # 5 requests/min for anonymous
def anonymous_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user:
            login(request, user)
            return JsonResponse({'message': 'Login successful'})
        return JsonResponse({'error': 'Invalid credentials'}, status=401)
    return JsonResponse({'error': 'POST required'}, status=405)

@ratelimit(key='ip', rate='10/m', block=True)
@login_required
def sensitive_action(request):
    return JsonResponse({'message': 'Sensitive action performed'})

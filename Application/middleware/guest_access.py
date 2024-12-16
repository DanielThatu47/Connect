from django.shortcuts import redirect

class GuestAccessRestrictionMiddleware:
    """Middleware to restrict guest users from accessing certain views."""
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        restricted_paths = ['/profile/']  # Add restricted paths here
        if request.session.get('guest') and request.path in restricted_paths:
            return redirect('main')  # Redirect guest users to main page
        return self.get_response(request)

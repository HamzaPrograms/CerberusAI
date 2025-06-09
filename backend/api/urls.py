from django.urls import path
from .views import test_api, get_scan_results

urlpatterns = [
    path('scan/', get_scan_results),
]

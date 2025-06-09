from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import JsonResponse
import os
import json

@api_view(['GET'])
def test_api(request):
    return Response({"message": "Cerberus backend is working!"})

@api_view(['GET'])
def get_scan_results(request):
    file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../scan_results.json'))
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        return JsonResponse(data, safe=False)
    except FileNotFoundError:
        return JsonResponse([], safe=False)


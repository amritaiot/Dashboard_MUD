from django.urls import path
from . import views
from .views import active_devices_view

urlpatterns = [
    path('', views.home, name='home'),
    path("testcases/", views.testcase_view, name="testcases"),


]

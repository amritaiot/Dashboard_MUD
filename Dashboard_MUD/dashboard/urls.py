from django.urls import path
from . import views
from .views import active_devices_view

urlpatterns = [
    path('', views.home, name='home'),
    path("testcases/", views.testcase_view, name="testcases"),
    path("run_test/", views.run_test_view, name="run_test"),
    path('device/<mac>/testcases/', views.device_testcases, name='device_testcases'),



]

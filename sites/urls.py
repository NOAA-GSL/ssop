""" sites URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import include, path

from sites.views import getattrs, index, project_ldg, showattrs, attrsjwt, demoapp_python, demoapp_authorization, oops, connections_by_project, generate_urlsafe_token, generate_fernet_key, pubcert, project_userlist, at2uu, get_cwd

app_name = 'sites'

urlpatterns = [
    path('', index, name='index'),
    path('project_ldg/<str:projectname>/', project_ldg, name='project_ldg'),
    path('project_userlist/<str:projectname>/', project_userlist, name='project_userlist'),
    path('getattrs/<str:access_token>/', getattrs, name='getattrs'),
    path('showattrs/<str:access_token>/', showattrs, name='showattrs'),
    path('attrsjwt/<str:access_token>/', attrsjwt, name='attrsjwt'),
    path('at2uu/<str:access_token>/', at2uu, name='at2uu'),
    path('demoapp_python/', demoapp_python, name='demoapp_python'),
    path('demoapp_authorization/', demoapp_authorization, name='demoapp_authorization'),
    path('connections_by_project/', connections_by_project, name='connections_by_project'),
    path('cbp/', connections_by_project, name='cbp'),
    path('urlsafe_token/', generate_urlsafe_token, name='url_safe_token'),
    path('urlsafe_token/<int:token_len>/', generate_urlsafe_token, name='url_safe_token'),
    path('fernetkey/', generate_fernet_key, name='fernetkey'),
    path('pubcert/', pubcert),
    path('getcwd/', get_cwd),
]


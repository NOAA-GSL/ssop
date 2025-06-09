""" Single Sign One Portal (ssop) URL Configuration

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

from sites.views import (index, ldg, ldg_authenticated, logout, ldg_auth_error, oops, demoapp_python, demoapp_authorization, attrs, metadata, pubcert, pubcertol)

urlpatterns = [
    path('adminssop/', admin.site.urls),
    path('ssop/adminssop/', admin.site.urls),
    path('ldg_authenticated/', ldg_authenticated, name='ldg_authenticated'),
    path('ldg/', ldg, name='ldg'),
    path('ldg/<str:project_name>/', ldg, name='ldg'),
    path('logout/', logout, name='logout'),
    path('logout/<str:connection_state>/', logout, name='logout'),
    path('ssop/', include(('sites.urls', 'sites'), namespace='ssop')),
    path('ssop/sites/', include(('sites.urls', 'sites'), namespace='ssop')),
    path('ssop/ldg_auth_error', ldg_auth_error, name='ssop_ldg_auth_error'),
    path('ssop/oops/', oops, name='ssop_oops'),
    path('ssop/demopy', demoapp_python, name='ssop_demoapp_python'),
    path('ssop/demohdr', demoapp_authorization, name='ssop_demohdr'),
    path('ssop/ldg_authenticated', ldg_authenticated, name='ssop_ldg_authenticated'),
    path('ssop/ldg/', ldg, name='ldg'),
    path('ssop/ldg/<str:project_name>/', ldg, name='ldg'),
    path('ssop/login/', ldg, name='login'),
    path('ssop/logout/', logout, name='ssop_logout'),
    path('ssop/logout/<str:connection_state>', logout, name='ssop_logout'),
    path('ssop/', index),
    path('pubcert/', pubcert),
    path('attrs/', attrs, name='attrs'),
    path('metadata/', metadata, name='metadata'),
    path('pubcertol/', pubcertol),
    path('ssop/attrs/', attrs, name='attrs'),
    path('ssop/metadata/', metadata, name='metadata'),
    path('ssop/pubcert/', pubcert),
    path('ssop/pubcertol/', pubcertol)
]


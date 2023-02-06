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

from sites.views import (index, ldg, ldg_authenticated, logout, ldg_auth_error, oops, demoapp_python, demoapp_authorization, firewxtb, firewxoops)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('ldg_authenticated/', ldg_authenticated, name='ldg_authenticated'),
    path('ldg/', ldg, name='ldg'),
    path('logout/', logout, name='logout'),
    path('logout/<str:connection_state>/', logout, name='logout'),
    path('sites/', include(('sites.urls', 'sites'), namespace='sb')),
    path('', index, 'index'),
    path('ssop/', index, 'index'),
    path('ssop/ldg_authenticated', ldg_authenticated, name='ssop_ldg_authenticated'),
    path('ssop/ldg/', ldg, name='ldg'),
    path('ssop/ldg/<str:project_name>/', ldg, name='ldg'),
    path('ssop/login/', ldg, name='login'),
    path('ssop/logout/', logout, name='ssop_logout'),
    path('ssop/logout/<str:connection_state>', logout, name='ssop_logout'),
    path('ldg_authenticated', ldg_authenticated, name='ssop_ldg_authenticated'),
    path('ldg/', ldg, name='ldg'),
    path('ssop/ldg_auth_error', ldg_auth_error, name='ldg_auth_error'),
    path('ssop/oops/', oops, name='oops'),
    path('ssop/demopy', demoapp_python, name='ssop_demopy'),
    path('ssop/demohdr', demoapp_authorization, name='ssop_demohdr'),
    path('ssop/firewxtb/', firewxtb, name='ssop_firewxtb'),
    path('ssop/firewxoops/', firewxoops, name='ssop_firewxoops'),
    path('sb/', include(('sites.urls', 'sites'), namespace='sb')),
    path('ssop/sites/', include(('sites.urls', 'sites'), namespace='ssop_sb')),
    path('ssop/sb/', include(('sites.urls', 'sites'), namespace='ssop_sb')),
]

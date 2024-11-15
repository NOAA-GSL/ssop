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
#from django.contrib.sitemaps.views import sitemap

from sites.views import (index, icam, icam_authenticated, ldg, webpages_auth, ldg_authenticated, logout, ldg_auth_error, oops, demoapp_python, demoapp_authorization, attrs, metadata, pubcert, pubcertol)

#urlpatterns = [
#    path('admin/', admin.site.urls),
#    path('ssopsb/admin/', admin.site.urls),
#    path( "sitemap.xml", sitemap, {"sitemaps": sitemaps}, name="django.contrib.sitemaps.views.sitemap"),
urlpatterns = [
    path('adminssopsb/', admin.site.urls),
    path('ssopsb/adminssopsb/', admin.site.urls),
    path('ldg_authenticated/', ldg_authenticated, name='ldg_authenticated'),
    path('ldg/', ldg, name='ldg'),
    path('ldg/<str:project_name>/', ldg, name='ldg'),
    path('icam/<str:project_name>/', icam, name='icam'),
    path('icam_authenticated/', icam_authenticated, name='icam_authenticated'),
    path('icam_authenticated/<str:project_name>/', icam_authenticated, name='icam_authenticated'),
    path('webpages_auth/', webpages_auth, name='webpages_auth'),
    path('logout/', logout, name='logout'),
    path('logout/<str:connection_state>/', logout, name='logout'),
    path('ssopsb/', include(('sites.urls', 'sites'), namespace='ssopsb')),
    path('ssopsb/sites/', include(('sites.urls', 'sites'), namespace='ssopsb')),
    path('ssopsb/ldg_auth_error', ldg_auth_error, name='ssopsb_ldg_auth_error'),
    path('ssopsb/oops/', oops, name='ssopsb_oops'),
    path('ssopsb/webpages_auth/', webpages_auth, name='ssopsb_webpages_auth'),
    path('ssopsb/demopy', demoapp_python, name='ssopsb_demoapp_python'),
    path('ssopsb/demohdr', demoapp_authorization, name='ssopsb_demohdr'),
    path('ssopsb/ldg_authenticated', ldg_authenticated, name='ssopsb_ldg_authenticated'),
    path('ssopsb/ldg/', ldg, name='ldg'),
    path('ssopsb/ldg/<str:project_name>/', ldg, name='ldg'),
    path('ssopsb/login/', ldg, name='login'),
    path('ssopsb/logout/', logout, name='ssopsb_logout'),
    path('ssopsb/logout/<str:connection_state>', logout, name='ssopsb_logout'),
    path('ssopsb/icam/<str:project_name>/', icam, name='icam'),
    path('ssopsb/icam_authenticated/', icam_authenticated, name='ssopsb_icam_authenticated'),
    path('ssopsb/icam_authenticated/<str:project_name>/', icam_authenticated, name='ssopsb_icam_authenticated'),
    path('ssopsb/', index),
    path('pubcert/', pubcert),
    path('attrs/', attrs, name='attrs'),
    path('metadata/', metadata, name='metadata'),
    path('pubcertol/', pubcertol),
    path('ssopsb/attrs/', attrs, name='attrs'),
    path('ssopsb/metadata/', metadata, name='metadata'),
    path('ssopsb/pubcert/', pubcert),
    path('ssopsb/pubcertol/', pubcertol)
]


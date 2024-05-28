from django import forms
from django.contrib.auth.models import Group
from django.contrib.admin.widgets import FilteredSelectMultiple
from sites.models import Contact, Organization, Project, Sysadmin
import ssop.settings as settings

class ContactAdminForm(forms.ModelForm):
    class Meta:
        model = Contact
        field_order = ('email', 'firstname', 'lastname', 'last_connection_time', 'organizations', 'organization')
        fields = field_order

    def __init__(self, *args, **kwargs):
        super(ContactAdminForm, self).__init__(*args, **kwargs)


class ProjectForm(forms.Form):
    class Meta:
        model = Project
        fields = ('name', 'return_to', 'authenticated_redirect', 'error_redirect', 'state', 'idp')
        message = forms.CharField(widget=forms.Textarea)
        widgets = { 'idp': forms.RadioSelect() }

    def save(self, commit=True):
        project = super(ProjectForm, self).save(commit=False)
        if commit:
            project.save()
    
        if project.pk:
            project.userlist.set(self.cleaned_data['userlist'])
            self.save_m2m() 

        return project 


class ProjectAdminForm(forms.ModelForm):
    class Meta:
        model = Project
        #fields = '__all__'
        field_order = ('name', 'organization', 'verbose_name', 'return_to', 'error_redirect', 'idp', 'enabled', 'pfishing_resistant', 'display_order', 'decrypt_key', 'logoimg', 'owner', 'userlist', 'groups', 'app_params', 'expiretokens', 'graphnode', 'state', 'queryparam', 'querydelimiter', )
        fields = field_order


    def __init__(self, *args, **kwargs):
        super(ProjectAdminForm, self).__init__(*args, **kwargs)

    def save(self, commit=True):
        project = super(ProjectAdminForm, self).save(commit=False)

        if commit:
            project.save()
    
        if project.pk:
            project.userlist.set(self.cleaned_data['userlist'])
            project.groups.set(self.cleaned_data['groups'])
            self.save_m2m() 

        return project 


class SysadminAdminForm(forms.ModelForm):
    organizations = forms.ModelMultipleChoiceField(
        queryset=Organization.objects.all().order_by('name'),
        required=False,
        widget=FilteredSelectMultiple(
          verbose_name=('Organizations'),
          is_stacked=False
        )
    )   
            
    class Meta:
        model = Sysadmin
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super(SysadminAdminForm, self).__init__(*args, **kwargs)

        if self.instance and self.instance.pk:
            self.fields['organizations'].initial = self.instance.organizations.all()
            
    def save(self, commit=True):
        sysadmin = super(SysadminAdminForm, self).save(commit=False)

        if commit:
            sysadmin.save()
    
        if sysadmin.pk:
            # sysadmin.organizations = self.cleaned_data['organizations']
            sysadmin.organizations.set(self.cleaned_data['organizations'])
            self.save_m2m() 

        return sysadmin



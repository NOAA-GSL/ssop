from django import forms
from sites.models import Project

class ProjectForm(forms.Form):
    class Meta:
        model = Project
        fields = ('name', 'return_to', 'authenticated_redirect', 'error_redirect', 'state')
        message = forms.CharField(widget=forms.Textarea)

    def __init__(self, *args, **kwargs):
        super(ProjectForm, self).__init__(*args, **kwargs)


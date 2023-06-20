from django import forms


class ContactForm(forms.Form):
    company_name = forms.CharField(max_length=64)
    email_address = forms.EmailField(max_length=128)
    message = forms.CharField(widget=forms.Textarea, max_length=2048)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "form-control"

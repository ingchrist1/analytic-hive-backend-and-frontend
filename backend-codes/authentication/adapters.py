from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.conf import settings

class CustomAccountAdapter(DefaultAccountAdapter):
    def save_user(self, request, user, form, commit=True):
        """
        This is called when saving user via allauth registration.
        We override this to set additional data on user object.
        """
        # Get the email from the form
        data = form.cleaned_data
        user.email = data.get('email', '')
        
        # Set username to the part before @ in email if no username is provided
        if not user.username:
            user.username = user.email.split('@')[0]
            
        if commit:
            user.save()
        return user

class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    def save_user(self, request, sociallogin, form=None):
        """
        This is called when saving user via social account registration.
        We override this to set additional data on user object.
        """
        user = super().save_user(request, sociallogin, form)
        
        # Set additional data from social account
        social_data = sociallogin.account.extra_data
        
        if sociallogin.account.provider == 'google':
            user.profile_picture = social_data.get('picture')
            user.google_id = social_data.get('sub')
            user.save()
            
        return user

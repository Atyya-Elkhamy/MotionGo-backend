# accounts/pipeline.py

# def save_google_user_data(backend, user, response, *args, **kwargs):
#     if backend.name == 'google-oauth2':
#         user.email = response.get('email', '')
#         user.username = response.get('name', '')
#         user.is_verified = True
#         user.save()


def save_google_user_data(backend, user, response, *args, **kwargs):
    if backend.name != 'google-oauth2':
        return

    email = response.get('email')
    name = response.get('name', '')
    
    #Prevent auto-creation if email already exists (not the same user)
    from django.contrib.auth import get_user_model
    User = get_user_model()

    existing_user = User.objects.filter(email=email).exclude(id=user.id).first()
    if existing_user:
        raise Exception("This email is already registered. Please login.")

    user.email = email
    user.username = name.replace(" ", "") 
    user.is_verified = True
    user.save()

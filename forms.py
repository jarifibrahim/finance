from flask_wtf import Form
from wtforms import StringField, PasswordField, validators, SubmitField

# Render login form. u' indicated unicode encoding
class LoginForm(Form):
    username = StringField('Username', [validators.InputRequired(message=(u'Invalid Username')),
                                        validators.Length(min=4, max=25,
                                                message=(u'Username should have at least 4 characters'))])
    password = PasswordField('Password', [validators.InputRequired(message=(u'Password Required')),
                                          validators.Length(min=4, max=25,
                                                message=(u'Password should have at least 4 characters'))])
    submit = SubmitField("Log In")

class RegisterForm(LoginForm):
    confirm = PasswordField('Repeat Password', [
                        validators.EqualTo('password', message=(u'Passwords must match! ')),
                        validators.InputRequired(message=(u'Password Required ')),
                        validators.Length(min=4, max=25, message=(u'Password should have at least 4 characters '))
                        ])
    submit = SubmitField('Register')

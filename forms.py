from flask_wtf import FlaskForm
from wtforms.validators import InputRequired, Email, Length
from wtforms.fields import StringField, SubmitField, PasswordField


class RegisterForm(FlaskForm):
    name = StringField(label='Full Name', validators=[InputRequired()])
    email = StringField(label = 'Email', validators=[InputRequired(), Email(granular_message=True, check_deliverability=True)])
    password = StringField(label='Password', validators=[InputRequired(), Length(min=8)])
    submit = SubmitField(label= 'Sign Up')

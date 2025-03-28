from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, IntegerField, SubmitField, SelectField, FloatField
from wtforms.validators import DataRequired, Email, Length, EqualTo, NumberRange

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Log In')
    
class ReviewForm(FlaskForm):
    user_name = StringField('User Name', validators=[DataRequired(), Length(max=100)])
    review_text = TextAreaField('Review Text', validators=[DataRequired()])
    rating = IntegerField('Rating', validators=[DataRequired(), NumberRange(min=1, max=5)])
    submit = SubmitField('Submit Review')

class UserForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    name = StringField('Name', validators=[Length(max=100)])
    phone = StringField('Phone Number', validators=[Length(max=20)])
    role = SelectField('Role', choices=[('student', 'Student'), ('admin', 'Admin')], default='student')
    submit = SubmitField('Register')

class IncidentForm(FlaskForm):
    incident_type = StringField('Incident Type', validators=[DataRequired(), Length(max=50)])
    description = TextAreaField('Description', validators=[Length(max=500)])
    longitude = FloatField('Longitude')
    latitude = FloatField('Latitude')
    location = StringField('Location', validators=[Length(max=255)])
    status = SelectField('Status', choices=[('Pending', 'Pending'), ('Resolved', 'Resolved')], default='Pending')
    submit = SubmitField('Report Incident')
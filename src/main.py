from flask import Flask, render_template, url_for, request, redirect, session
from datetime import datetime
import logging

app = Flask(__name__)
app.logger.setLevel(logging.DEBUG)
app.config.from_mapping(SECRET_KEY='dadev')

#--------------------Ventana Principal--------------------
@app.route('/')
@app.route('/index')
def index():
    date = datetime.now()
    tontos= ['Abdiel','Emilio','Vela']
    return render_template('index.html', date=date, tontos=tontos)

#Agregando un filtro para formatear la fecha y mostrarla siempre en el index
@app.add_template_filter
def today(date):
    return date.strftime('%Y-%m-%d')

#--------------------Ventana About--------------------
@app.route('/about')
@app.route('/about/<name>')
@app.route('/about/<name>/<int:date>')
def about(name = None, date = None):
    return render_template('about.html', name=name, date=date, calcularEdad=calcularEdad)

def calcularEdad(fechaNacimiento):
    return f'Naciste en {fechaNacimiento} y tienes {2024-fechaNacimiento} años'

#--------------------Ventana Admin--------------------
@app.route('/admin')
#La libreria session permite almacenar la sesion del usuario 
def admin():
    #Se obtiene la sesion del usuario, como un diccionario
    userData = session.get('userData')
    if not userData:
        return redirect(url_for('login'))
    
    #Se crea un objeto de la clase User
    userLoged = User(userData['username'], userData['password'])
    return render_template('admin.html', userLoged=userLoged)

#--------------------Login con FORM nativo de HTML--------------------    
class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

import re #Libreria para expresiones regulares
def loginAuth(username, password):
    patron = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$')
    
    if username == 'Admin' and password == '12345678':
        return True
    
    elif len(username)<4 or len(password)<8:
        error ='El usuario debe tener al menos 4 caracteres y la contraseña debe tener al menos 8 caracteres'
        return error
    
    elif not patron.match(password):
        error = 'La contraseña debe tener al menos una letra mayúscula, una letra minúscula, un número y un caracter especial'
        return error
    
    elif username != 'Admin' or password != '1234':
        error = 'El usuario o la contraseña son incorrectos'
        return error
    
@app.route('/auth/login', methods=['GET', 'POST'])
def login():
    error=None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User(username, password)
        
        error = loginAuth(username, password)
        if error == True:
            session['userData'] = {'username': username, 'password': password}
            return redirect(url_for('admin'))
        else:
            return render_template('login.html', user=user, error=error)
    
    return render_template('login.html',error=error)

#--------------------Login con FORM de Flask wtf--------------------

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, IntegerField
from wtforms.validators import DataRequired, Regexp, Length, NumberRange

class RegisterForm(FlaskForm):
    username = StringField('Nombre de usuario: ', validators=[DataRequired(), Length(min=4, max=25, message='El nombre de usuario debe tener entre 4 y 25 caracteres tonoto')])
    lastname = StringField('Apellido: ', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Contraseña: ', 
                             validators=[DataRequired(), Length(min=8), 
                                Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$', message='La contraseña debe tener al menos una letra mayúscula, una letra minúscula, un número y un caracter especial')
                            ])
    email = EmailField('Correo electrónico: ', 
                       validators=[DataRequired()])
    phoneNumber = IntegerField('Número de teléfono: ', 
                               validators=[DataRequired(), 
                                            NumberRange(min=8, message='El número de teléfono debe tener al menos 8 dígitos')
                                        ])
    submit = SubmitField('Registrarse')

@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        username = form.username.data
        lastname = form.lastname.data
        password = form.password.data
        email = form.email.data
        phoneNumber = form.phoneNumber.data
        
        session['userData'] = {'username' : username, 
                               'lastname' : lastname,
                               'password' : password, 
                               'email' : email, 
                               'phoneNumber' : phoneNumber,
                              }
        
        app.logger.info("UserData: %s", session['userData'])
        return redirect(url_for('registerSuccess'))
    else:
        app.logger.error("Form validation failed")
        for field, errors in form.errors.items():
            for error in errors:
                app.logger.error("%s: %s", field, error)
    
    return render_template('register.html', form=form)

@app.route('/auth/register/success', methods = ['GET', 'POST'])
def registerSuccess():
    userData = session.get('userData')
    if not userData:
        return redirect(url_for('register'))
    return render_template('registerSuccess.html', userData=userData)

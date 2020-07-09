from flask import Flask, render_template, redirect, url_for, send_file
import sqlite3 as sq
import numpy as np
import pandas as pd
import os
from werkzeug.utils import secure_filename
from scipy import stats
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField, FileField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

column_names = ["Powder", "Dispersant", "Solvent", "Binder_1", "Binder_2", "Particle Size (smallest) (m)", "Particle Size (widest) (m)",
                        "Binder Chain Mass (1)", "Binder Chain Mass (2)", "Water vol%", "Powder vol%", "Binder 1 vol%", "Binder 2 vol%",
                        "Dispersant wt%", "Gradient"]


app = Flask(__name__)
UPLOAD_FOLDER = './Uploaded_data'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = '159632'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///login/database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember Me')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])

class InputForm(FlaskForm):
    
    powder = StringField('Powder', validators = [InputRequired()])
    dispersant = StringField('Dispersant', validators = [InputRequired()])
    solvent = StringField('Solvent', validators = [InputRequired()])
    binder1 = StringField('Binder 1', validators = [InputRequired()])
    binder2 = StringField('Binder 2', validators = [InputRequired()])
    maxparticle = StringField('Maximum Particle Size', validators = [InputRequired()])
    minparticle = StringField('Minimum Particle Size', validators = [InputRequired()])
    binderchainmass1 = StringField('Binder Chain Mass 1', validators = [InputRequired()])
    binderchainmass2 = StringField('Binder Chain Mass 2', validators = [InputRequired()])
    solventvol = StringField('Solvent Vol%', validators = [InputRequired()])
    powdervol = StringField('Powder Vol%', validators = [InputRequired()])
    binder1vol = StringField('Binder 1 Vol%', validators = [InputRequired()])
    binder2vol = StringField('Binder 2 Vol%', validators = [InputRequired()])
    dispersantwt = StringField('Dispersant Wt%', validators = [InputRequired()])
    rheo_data = FileField('Rheological Data', validators = [InputRequired()])


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return render_template('landing_page.html', message = "Welcome " +str(form.username.data)+"!")
            return render_template('login.html', message2 = "Incorrect password, please try again.", form = form)
        return render_template('login.html', message = "Incorrect username, please try again.", form = form)
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html',  form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        user_val = User.query.filter_by(username=form.username.data).first()
        email_val= User.query.filter_by(email=form.email.data).first()
        if user_val:
          return render_template('signup.html', message = 'Username already taken, please try again', form = form)

        elif email_val:

          return render_template('signup.html', message2 = 'Email already taken, please try again', form = form)

        else:

          db.session.add(new_user)
          db.session.commit()
          return render_template('landing_page.html', message = 'New user created!\n Welcome ' +str(form.username.data)+'!')

        """
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'
        """
    return render_template('signup.html', form=form)

@app.route('/landing_page', methods = ["GET", "POST"])
@login_required
def landing_page():
    return render_template("landing_page.html")



@app.route('/input_page', methods=['GET', 'POST'])
@login_required
def input_page():
    form = InputForm()
    if form.validate_on_submit():
        list_ = []
        list_.append(form.powder.data)
        list_.append(form.dispersant.data)
        list_.append(form.solvent.data)
        list_.append(form.binder1.data)
        list_.append(form.binder2.data)
        list_.append(form.maxparticle.data)
        list_.append(form.minparticle.data)
        list_.append(form.binderchainmass1.data)
        list_.append(form.binderchainmass2.data)
        list_.append(form.solventvol.data)
        list_.append(form.powdervol.data)
        list_.append(form.binder1vol.data)
        list_.append(form.binder2vol.data)
        list_.append(form.dispersantwt.data)

        f = form.rheo_data.data
        filename = secure_filename(f.filename)
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        strain_data = pd.read_csv("./Uploaded_data/"+str(filename))
        slope, intercept, r_value, p_value, std_err = stats.linregress(strain_data["x"], strain_data["y"])

        list_.append(slope)
        list_array = np.array(list_).reshape(1,15)
        df = pd.DataFrame(list_array, columns = column_names)
        conn = sq.connect('SlurryDB copy.db')
        df.to_sql('SLURRIES', conn, if_exists ='append', index = False)
        df_2 = pd.read_sql('SELECT * FROM SLURRIES', con = conn)
        df_2.to_csv("./Downloads/Complete_Slurry_Database.csv")
        #return redirect(url_for('landing_page'), message = "Thanks for your submission!")
        return render_template('landing_page.html', message = 'Thanks for your submission, ' + str(current_user.username) +'!')
        
    return render_template('input_page_2.html', name= current_user.username, form = form)
@app.route('/download')
@login_required
def download_page():
    
    return render_template("download_page.html")

@app.route('/how_to')
@login_required
def how_to():
    
    return render_template("how_to.html")

@app.route('/data_download')
@login_required
def data_download():
    return send_file('./Downloads/Complete_Slurry_Database.csv', as_attachment = True )

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.debug = True
    app.run(port = 5025)
    app.run()

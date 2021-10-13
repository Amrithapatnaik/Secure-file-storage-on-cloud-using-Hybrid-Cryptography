# Secure-file-storage-on-cloud-using-Hybrid-Cryptography
Main File:
main.py (source code):
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory,session 
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, 
logout_user
import os 
import time 
import aes 
import rsa
import cloudinary
import cloudinary.uploader
cloudinary.config(
cloud_name = "securefilestoragecloud", 
api_key = "671392448133668",
api_secret = "47cweUn3dXjEpBEhVpsrYy9MHj8" )
app = Flask( name )
app.config['SECRET_KEY'] = 'any-secret-key-you-choose' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
db = SQLAlchemy(app)
login_manager = LoginManager() 
login_manager.init_app(app)
##CREATE TABLE IN DB
class User(UserMixin, db.Model):
id = db.Column(db.Integer, primary_key=True) 
email = db.Column(db.String(100), unique=True) 
password = db.Column(db.String(100))
name = db.Column(db.String(1000))
@login_manager.user_loader 
def load_user(user_id):
return User.query.get(user_id)
@app.route('/') 
def home():
return render_template("index.html")
@app.route('/register', methods=["POST", "GET"]) 
def register():
if request.method == "POST":
submitted_email = request.values.get("email")
user_object = db.session.query(User).filter(User.email == submitted_email).first()
if user_object is None: 
new_user = User(
email=submitted_email, 
password=generate_password_hash(password=request.values.get("password"),
method="pbkdf2:sha256", salt_length=8), 
name=request.values.get("name")
)
db.session.add(new_user) 
db.session.commit()
login_user(new_user) 
return redirect("/secrets")
else:
flash("Error: This email already exists login instead") 
return redirect(url_for("login"))
return render_template("register.html")
@app.route('/login', methods=["POST", "GET"]) 
def login():
if request.method == "POST":
email = request.values.get("email") 
password = request.values.get("password")
user_object = db.session.query(User).filter(User.email == email).first() 
if user_object is not None:
check_password = check_password_hash(pwhash=user_object.password, password=password) 
if check_password:
login_user(user_object) 
return redirect("/secrets")
else:
flash("Error: Incorrect password please try again")
else:
flash("Error: This email does not exist") 
return render_template("login.html")
return render_template("login.html") 
@app.route('/secrets')
@login_required 
def secrets():
username = current_user.name
return render_template("secrets.html", name=username)
@app.route('/logout') 
@login_required
def logout(): 
logout_user()
flash("Successfully Logged Out") 
return redirect("/")
@app.route('/home.html', methods=['GET']) 
@login_required
def mains():
return render_template('home.html')
@app.route('/encrypt', methods=['GET', 'POST']) 
def encrypt():
return render_template('encrypt1.html', title='Encrypt')
@app.route('/encrypt1', methods=['GET', 'POST']) 
def encrypt_text():
plainfile = (request.files['plainfile']).filename 
keyfile = (request.files['key']).filename 
input_path = os.path.abspath(plainfile) 
print(input_path)
key_path = os.path.abspath(keyfile) 
print('Encryption of text in progress. ...')
with open(input_path, 'rb') as f: 
data = f.read()
with open(key_path, 'r') as f: 
key = f.read()
crypted_data = []
# crypted_key = [] 
temp_data = [] 
temp_key = []
for byte in data: 
temp_data.append(byte)
for byte in key: 
temp_key.append(byte)
session["temp_key"] = temp_key
crypted_part = aes.encrypt(temp_data, temp_key) 
crypted_data.extend(crypted_part)
out_path = os.path.join(os.path.dirname(input_path), 'encrypted-' + os.path.basename(input_path))
with open(out_path, 'xb') as ff: 
ff.write(bytes(crypted_data))
with open(ff.name, 'rb') as file:
response = cloudinary.uploader.upload(file, resource_type="raw", use_filename='true') 
session['response'] = response['secure_url']
rsa.chooseKeys()
return render_template('encrypt2.html', title='encrypt2')
@app.route('/encrypt2', methods=['GET', 'POST']) 
def encryptkey():
# rsa.chooseKeys()
file_option = (request.files['publickey']).filename 
message = "".join(session['temp_key']) 
encrypted_key = rsa.encrypt(message, file_option) 
f_public = open('encrypted-key.txt', 'w') 
f_public.write(str(encrypted_key)) 
f_public.close()
return render_template('enc_success.html', response=session['response'])
# print('Enter the file name of encrypted key')
@app.route('/decrypt', methods=['GET', 'POST']) 
def decrypt():
return render_template('decrypt1.html', title='Decrypt')
@app.route('/decrypt1', methods=['GET', 'POST']) 
def decrypt_key():
dec_key = (request.files['enckey']).filename 
d_key_path = os.path.abspath(dec_key) 
with open(d_key_path, 'r') as f:
d_key = f.read()
print('Key Decryption in progess. ... ')
print('Please wait it may take several minutes....')
d_message = rsa.decrypt(d_key) 
session['d_message'] = d_message
return render_template('decrypt2.html', title='decrypt2')
# print('Enter the file name of encrypted text') 
@app.route('/decrypt2', methods=['GET', 'POST']) 
def decrypt_text():
dec_input = (request.files['enctext']).filename 
d_input_path = os.path.abspath(dec_input)
with open(d_input_path, 'rb') as f: 
d_data = f.read()
decrypted_data = [] 
temp = []
for byte in d_data: 
temp.append(byte)
decrypted_part = aes.decrypt(temp, session['d_message']) 
decrypted_data.extend(decrypted_part)
out_path = os.path.join(os.path.dirname(d_input_path), 'decrypted_' + 
os.path.basename(d_input_path))
with open(out_path, 'xb') as ff: 
ff.write(bytes(decrypted_data))
return render_template('dec_success.html', title='dsuccess')
# print('File is Successfully Decrypted.') 
# print()
# print('ACHIEVED HYBRID CRYPTOGRAPHY SUCCESSFULLY')
if name == " main ": 
app.run(debug=True)

from flask import Flask, redirect, render_template, request, url_for
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from flask_login import LoginManager, UserMixin, login_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['JWT_SECRET_KEY'] = 'flask_app_key'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

jwt = JWTManager(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    

@app.route('/')
@jwt_required()
def home():
    if 'access_token' in request.cookies:
        token = request.cookies.get('access_token')
        try:
            jwt.decode_token(token)  # Validate token (this will raise an exception if invalid)
            return redirect(url_for('/'))  # Redirect to protected if valid token
        except:
            return render_template('register.html')  # Render home page if token is invalid or not present
    return render_template('register.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            access_token = create_access_token(identify={'username':{user.username}})
            return redirect('/')
    return render_template('login.html')


@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('login')
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True,port=3000)
    
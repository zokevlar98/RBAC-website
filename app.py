from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import abort
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    roles = db.relationship('Role', secondary='user_role')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_permission(self, permission_name):
        for role in self.roles:
            for permission in role.permissions:
                if permission.name == permission_name:
                    return True
        return False

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    permissions = db.relationship('Permission', secondary='role_permission')

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class UserRole(db.Model):
    _tablename_ = 'user_role'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id', ondelete="CASCADE"), primary_key=True)

class RolePermission(db.Model):
    _tablename_ = 'role_permission'
    role_id = db.Column(db.Integer, db.ForeignKey('role.id', ondelete="CASCADE"), primary_key=True)
    permission_id = db.Column(db.Integer, db.ForeignKey('permission.id', ondelete="CASCADE"), primary_key=True)

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    permissions = db.relationship('UserPermission', backref='resource')

class UserPermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"))
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id', ondelete="CASCADE"))
    permission_id = db.Column(db.Integer, db.ForeignKey('permission.id', ondelete="CASCADE"))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('signup'))

        user = User(username=username, email=email)
        user.set_password(password)
        
        # Assign role to user
        role_obj = Role.query.filter_by(name=role).first()
        if role_obj:
            user.roles.append(role_obj)
        
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Define available chapters/documents
    chapters = [
        {
            'number': 1,
            'title': 'Linux For Beginners',
            'file': 'linux_beginners.pdf'
        },
        {
            'number': 2,
            'title': 'Bash Documentation',
            'file': 'bash_doc.pdf'
        },
        {
            'number': 3,
            'title': 'Advanced Topics: The Linux Programming Interface',
            'file': 'linux_programming.pdf'
        },
        {
            'number': 4,
            'title': 'Terraform Project',
            'file': 'terraform.pdf'
        }
    ]

    # Get user's role
    user_role = current_user.roles[0].name if current_user.roles else None

    # Apply role-based access control
    if user_role == 'student':
        # Students can only see first 3 chapters
        available_chapters = chapters[:3]
    elif user_role == 'professor':
        # Professors can see all chapters
        available_chapters = chapters
    elif user_role == 'director':
        # Directors can see all chapters and have delete permission
        available_chapters = chapters
    else:
        available_chapters = []


    if chapters:
        for chapter in chapters:
            file_path = os.path.join(app.static_folder, 'docs', chapter['file'])
            if not os.path.exists(file_path):
                print(f"File not found: {file_path}")
            if not os.access(file_path, os.R_OK):
                print(f"File not readable: {file_path}")
        # Debug print statements
        print(f"User Role: {user_role}")
        print(f"Available Chapters: {available_chapters}")

    return render_template('dashboard.html', 
                         user=current_user,
                         chapters=available_chapters,
                         is_director=(user_role == 'director'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def setup_rbac():
    # Create roles and permissions
    roles = ['director', 'professor', 'student']
    permissions = ['read', 'write', 'add', 'remove']
    
    # Create roles
    for role_name in roles:
        if not Role.query.filter_by(name=role_name).first():
            role = Role(name=role_name)
            db.session.add(role)
    
    # Create permissions
    for permission_name in permissions:
        if not Permission.query.filter_by(name=permission_name).first():
            permission = Permission(name=permission_name)
            db.session.add(permission)

    db.session.commit()

    # Create resources
    resources = ['personal_information', 'exam_marks']
    for resource_name in resources:
        if not Resource.query.filter_by(name=resource_name).first():
            resource = Resource(name=resource_name)
            db.session.add(resource)
    
    db.session.commit()

    # Define role-permission mappings
    role_permissions = {
        'director': ['read', 'write', 'add', 'remove'],
        'professor': ['read', 'write', 'add'],
        'student': ['read']
    }

    # Assign permissions to roles
    for role_name, permissions_list in role_permissions.items():
        role = Role.query.filter_by(name=role_name).first()
        if role:
            for permission_name in permissions_list:
                permission = Permission.query.filter_by(name=permission_name).first()
                if permission and permission not in role.permissions:
                    role_permission = RolePermission(role_id=role.id, permission_id=permission.id)
                    db.session.add(role_permission)
    
    db.session.commit()

def create_default_users():
    users_data = [
        {'username': 'director1', 'email': 'director1@example.com', 'password': 'password123', 'roles': ['director']},
        {'username': 'professor1', 'email': 'professor1@example.com', 'password': 'password123', 'roles': ['professor']},
        {'username': 'student1', 'email': 'student1@example.com', 'password': 'password123', 'roles': ['student']},
    ]

    for user_data in users_data:
        if not User.query.filter_by(username=user_data['username']).first():
            user = User(username=user_data['username'], email=user_data['email'])
            user.set_password(user_data['password'])
            db.session.add(user)
            db.session.commit()
            
            for role_name in user_data['roles']:
                role = Role.query.filter_by(name=role_name).first()
                if role and role not in user.roles:
                    user.roles.append(role)
            
            db.session.commit()

# Create database tables and initialize RBAC
with app.app_context():
    db.create_all()
    setup_rbac()
    create_default_users()

def require_permission(permission_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.has_permission(permission_name):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/protected-resource')
@login_required
@require_permission('read')
def protected_resource():
    return "You have permission to read this resource"

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

def file_exists(filename):
    """Check if a file exists in the static/docs directory"""
    file_path = os.path.join(app.static_folder, 'docs', filename)
    return os.path.exists(file_path)

@app.route('/check-file/<filename>')
def check_file(filename):
    if file_exists(filename):
        return jsonify({'exists': True})
    return jsonify({'exists': False})

@app.route('/delete-resource/<file_name>', methods=['POST'])
@login_required
def delete_resource(file_name):
    # Check if user is director
    user_role = current_user.roles[0].name if current_user.roles else None
    if user_role != 'director':
        abort(403)
    
    try:
        file_path = os.path.join(app.static_folder, 'docs', file_name)
        if os.path.exists(file_path):
            os.remove(file_path)
            flash('Resource deleted successfully')
        else:
            flash('Resource not found')
    except Exception as e:
        print(f"Error deleting file: {str(e)}")
        flash('Error deleting resource')
    
    return redirect(url_for('dashboard'))

@app.route('/check-files')
@login_required
def check_files():
    base_path = os.path.join(app.static_folder, 'docs')
    files = [
        'linux_beginners.pdf',
        'bash_doc.pdf',
        'linux_programming.pdf',
        'terraform.pdf'
    ]
    
    status = {}
    for file in files:
        file_path = os.path.join(base_path, file)
        status[file] = {
            'exists': os.path.exists(file_path),
            'path': file_path,
            'readable': os.access(file_path, os.R_OK) if os.path.exists(file_path) else False
        }
    
    return jsonify(status)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        username = request.form.get('name')
        email = request.form.get('email')
        
        if username:
            # Check if username already exists for another user
            existing_user = User.query.filter(
                User.username == username, 
                User.id != current_user.id
            ).first()
            if existing_user:
                flash('Username already exists', 'error')
                return redirect(url_for('profile'))
            current_user.username = username
        
        if email:
            # Check if email already exists for another user
            existing_user = User.query.filter(
                User.email == email, 
                User.id != current_user.id
            ).first()
            if existing_user:
                flash('Email already exists', 'error')
                return redirect(url_for('profile'))
            current_user.email = email
        
        try:
            db.session.commit()
            flash('Profile updated successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error updating profile', 'error')
            print(f"Error updating profile: {str(e)}")
        
        return redirect(url_for('profile'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('profile'))
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('profile'))
        
        try:
            current_user.set_password(new_password)
            db.session.commit()
            flash('Password changed successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error changing password', 'error')
            print(f"Error changing password: {str(e)}")
        
        return redirect(url_for('profile'))

if __name__ == '__main__':
    app.run(debug=True)
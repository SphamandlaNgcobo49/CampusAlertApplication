from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from extensions import db  
from forms import LoginForm, ReviewForm, IncidentForm
from models import User, Incident, Review  
from flask_mail import Mail, Message
from flask_migrate import Migrate


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///campus_security.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db.init_app(app)

migrate = Migrate()
migrate.init_app(app, db)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'dutalertsytem@gmail.com'
app.config['MAIL_PASSWORD'] = 'gckrusfdcptcoaya'  

login_manager = LoginManager(app)
login_manager.login_view = 'login'


mail = Mail(app)


with app.app_context():
    db.create_all()


with app.app_context():
    admin = User.query.filter_by(email="admin@dut4life.ac.za").first()
    if not admin:
        admin = User(
            email="admin@dut4life.ac.za",
            password=generate_password_hash("admin123", method='pbkdf2:sha256'),
            role="admin"
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin user created with email: admin@dut4life.ac.za and password: admin123")
    else:
        print("Admin user already exists!")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    error_message = None
    if request.method == 'POST':
        # Retrieve form data
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Name validation: Ensure name is not empty
        if not name:
            error_message = 'Name cannot be empty.'
            return render_template('register.html', error_message=error_message)

        # Email validation: Ensure email ends with @dut4life.ac.za
        if not email.endswith("@dut4life.ac.za"):
            error_message = 'Invalid email, please use your DUT email address.'
            return render_template('register.html', error_message=error_message)

        # Check if the email is already taken
        if User.query.filter_by(email=email).first():
            error_message = 'Email is already registered.'
            return render_template('register.html', error_message=error_message)

        # Hash the password before saving
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create new user
        new_user = User(name=name, email=email, password=hashed_password, role='student')

        # Save the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Flash success message and redirect to login
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html', error_message=error_message)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if email == "admin@dut4life.ac.za" and password == "admin123":
            user = User.query.filter_by(email="admin@dut4life.ac.za").first()
            if user and user.role == 'admin':
                login_user(user)
                return redirect(url_for('admin_dashboard'))

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Invalid email", "error")
        elif not check_password_hash(user.password, password):
            flash("Invalid password", "error")
        else:
            login_user(user)
            return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return render_template('dashboard.html')

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        incident_type = request.form['incident_type']
        description = request.form['description']

        
        new_incident = Incident(
            user_id=current_user.id,
            incident_type=incident_type,
            description=description
        )
        db.session.add(new_incident)
        db.session.commit()

        
        msg = Message(
            subject='New Incident Reported',
            sender='dutalertsytem@gmail.com', 
            recipients=['22329286@dut4life.ac.za'],  
            body=f"""
            A new incident has been reported on DUT Campus Security Alert:

            - Incident Type: {incident_type}
            - Description: {description or 'N/A'}
            - Reported By: {current_user.email}

            Please log in to review the details and take necessary actions.
            """
        )
        mail.send(msg)

        flash("Incident reported successfully and an email has been sent to the admin.", "success")
        return render_template('confirmation.html', incident=new_incident, user_email=current_user.email)

    return render_template('report.html')


   
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    incidents = Incident.query.all()
    return render_template('admin.html', incidents=incidents)

@app.route('/history')
@login_required
def history():
    
    incidents = Incident.query.filter_by(user_id=current_user.id).all()
    return render_template('history.html', incidents=incidents)

@app.route('/admin/delete/<int:incident_id>', methods=['POST'])
@login_required
def delete_incident(incident_id):
    if current_user.role != 'admin':  
        return redirect(url_for('dashboard'))

    
    incident = Incident.query.get_or_404(incident_id)

    
    db.session.delete(incident)
    db.session.commit()

    flash("Incident has been deleted successfully!", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update/<int:incident_id>', methods=['GET', 'POST'])
@login_required
def update_incident(incident_id):
    if current_user.role != 'admin': 
        return redirect(url_for('dashboard'))

    
    incident = Incident.query.get_or_404(incident_id)

    if request.method == 'POST':
        
        incident.incident_type = request.form['incident_type']
        incident.description = request.form['description']
        incident.status = request.form['status']
        db.session.commit()

        flash("Incident has been updated successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('update_incident.html', incident=incident)

@app.route('/map', methods=['GET'])
def map_page():
    return render_template('map.html', api_key="AIzaSyBllPxxnyKCluVGeT_GE7Bep8Gz4dblQ9Q") 

@app.route('/rating', methods=['GET', 'POST'])
@login_required
def rating():
    # Retrieve all reviews from the database
    reviews = Review.query.all()
    return render_template('rating.html', reviews=reviews)

@app.route('/delete_review/<int:review_id>', methods=['POST'])
@login_required
def delete_review(review_id):
    review = Review.query.get(review_id)
    if review:
        db.session.delete(review)
        db.session.commit()
        flash("Review deleted successfully!", "success")
    else:
        flash("Review not found!", "danger")
    return redirect(url_for('rating'))

@app.route('/submit_review', methods=['GET', 'POST'])
def submit_review():
    form = ReviewForm()
    
    # Check if the request is POST and the form is valid
    if form.validate_on_submit():
        user_name = form.user_name.data
        review_text = form.review_text.data
        rating = form.rating.data
        
        try:
            # Save data to the database
            new_review = Review(user_name=user_name, review_text=review_text, rating=rating)
            db.session.add(new_review)
            db.session.commit()
            
            flash('Review successfully submitted!')
            
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()  # Rollback transaction in case of error
            flash(f'An error occurred while saving the review: {str(e)}')
    
    # Render the form template for GET or invalid POST request
    return render_template('submit_review.html', form=form)

@app.route('/profile', methods=['GET', 'POST'])
@login_required

def profile():
    if request.method == 'POST':
        current_user.name = request.form['name']
        current_user.email = request.form['email']

        # Handle password update
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password:
            if new_password == confirm_password:
                current_user.password = generate_password_hash(new_password)
                flash('Password updated successfully!', 'success')
            else:
                flash('Passwords do not match. Please try again.', 'danger')
                return redirect(url_for('profile'))

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=current_user)

@app.route('/confirmation')
def confirmation():
    
    incident = {
        'incident_type': 'theft',  
        'description': None,
        'status': 'Pending',
        'timestamp': incident.timestamp.isoformat() 
    }
    return render_template('confirmation.html', incident=incident, user_email=current_user.email)



if __name__ == '__main__':
    app.run(debug=True)

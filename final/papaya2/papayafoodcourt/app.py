import collections
from flask import Flask, render_template, request, redirect, url_for, flash, abort, Response
from forms import (
    RegisterForm,
    ProfileForm,
    LoginForm,
    CreateUserForm,
    EditStaffForm,
    EditCustomerForm,
    RequestResetPasswordForm,
    ResetPasswordForm,
    SearchUserForm,
    ExtendTimeForm,
    DoneCookingForm,
    AdminProductForm,
    StoreForm,
    ReviewsForm,
    SearchLogs,
    MonitorFilter
)
import shelve
from User import User
from Admin import Admin
from Customer import Customer
from Staff import Staff
from flask_bcrypt import Bcrypt
from flask_login import (
    login_user,
    LoginManager,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.utils import secure_filename
import os
import requests
from uuid import uuid1
from PIL import Image
from flask_mail import Mail, Message
from bs4 import BeautifulSoup
import random
import pyotp
from flask_recaptcha import ReCaptcha
import time
from Cart import Cart
from CartItem import CartItem
from Payment import Payment
from Product import Product
from Store import Store
import reviewUser
from orderHistory import OrderHistory
from CurrentOrder import CurrentOrder
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from Cryptography import KeyGen, encryption, decryption
import logging
import logging.config
from requirements import installation_of_packages
import secure
from hashing import hash_SHA512, history
from monitoring import updated_lib, update_module, outdated_lib, freeze_check, adding_package, sorting

app = Flask(__name__, template_folder='Templates')
bcrypt = Bcrypt(app)
app.config["SECRET_KEY"] = "test-secret-key"
app.config['RECAPTCHA_SITE_KEY']= '6LefYcwgAAAAABZjijwkQ08oTBH2Q7WH9MN1nKIA'
app.config['RECAPTCHA_SECRET_KEY']='6LefYcwgAAAAAIXCP2YpOna8aHhEzDSuSCLskFDL'
recaptcha = ReCaptcha(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"


"""
Mailtrap login credentials
Email:  noreplypapayafood@gmail.com
Password: e'$6cJdf*hd#
"""

app.config['MAIL_SERVER']='smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = 'ee926b2513ca26'
app.config['MAIL_PASSWORD'] = 'bcf931d8768099'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)


'''
Scheduling for order tracking
'''
scheduler = BackgroundScheduler(daemon=True)
scheduler.start()

logger = logging.getLogger("Papaya_Food_Court")
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter(' %(levelname)s , %(asctime)s , %(message)s',datefmt="%Y-%m-%d - %H:%M:%S")
ch.setFormatter(formatter)
fh = logging.FileHandler("myapp.log","a")
fh.setLevel(logging.INFO)
fh.setFormatter(formatter)
logger.addHandler(ch)
logger.addHandler(fh)


logger = logging.getLogger("Papaya_Food_Court")
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter(' %(levelname)s , %(asctime)s , %(message)s',datefmt="%Y-%m-%d - %H:%M:%S")
ch.setFormatter(formatter)
fh = logging.FileHandler("myapp.log","a")
fh.setLevel(logging.INFO)
fh.setFormatter(formatter)
logger.addHandler(ch)
logger.addHandler(fh)



secure_headers = secure.Secure()



def save_picture(form, directory, size):
    """
    form = current form you are using
    directory = folder under static/Images to save in (string)
    size must be integer
    """
    if hasattr(form, "profile_picture"):
        uploaded_image = form.profile_picture.data
    elif hasattr(form, "image"):
        uploaded_image = form.image.data

    picture_filename = secure_filename(uploaded_image.filename)
    picture_name = str(uuid1()) + "_" + picture_filename
    picture_path = os.path.join(app.root_path, "static/Images", directory, picture_name)

    output_size = (size, size)
    resized_image = Image.open(uploaded_image)
    resized_image.thumbnail(output_size)
    resized_image.save(picture_path)

    return picture_name


@app.after_request
def add_security_headers(resp):
    resp.headers['Content-Security-Policy']=False
    return resp


@login_manager.user_loader
def load_user(user_id):
    users_dict = {}
    db = shelve.open("users.db", "r")
    try:
        if "Users" in db:
            users_dict = db["Users"]
        else:
            db["Users"] = users_dict
    except:
        abort(500)
    db.close()

    return users_dict[user_id]


@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(429)
def not_found(e):
    return render_template("429.html"), 429



@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500


@app.after_request
def set_secure_headers(response):
    secure_headers.framework.flask(response)
    return response

@app.route("/")
def home():
    cartDict = {}
    db = shelve.open("cart.db", "c")
    try:
        if "Cart" in db:
            cartDict = db["Cart"]
        else:
            db["Cart"] = cartDict
    except:
        abort(500)

    users_dict = {}
    db = shelve.open("users.db", "r")
    try:
        if "Users" in db:
            users_dict = db["Users"]
        else:
            db["Users"] = users_dict
    except:
        abort(500)
    db.close()
    userList = []

    for user in cartDict:
        if user is not None:
            if user in users_dict:
                userList.append(user)
    for item in cartDict:
        if item in userList:
            print(cartDict[item].Cart)

    no_of_orders = len(userList)
    stores_dict ={}
    users_list = len([users for users in users_dict.values()])
    db = shelve.open("stores.db", "c")
    try:
        if "Stores" in db:
            stores_dict = db["Stores"]
        else:
            db["Stores"] = stores_dict
    except:
        abort(500)
    stores_list = len([stores for stores in stores_dict.values()])
    db.close()
    if current_user.is_authenticated:
        if current_user.get_account_type() == "Admin":
            admin_logout = []
            try:
                db = shelve.open("admins_logout.db","w")
                if "admin" in db:
                    admin_logout = db["admin"]
                else:
                    db["admin"] = admin_logout
            except:
                abort(500)
            if len(admin_logout) != 0:
                for n in range(len(admin_logout)):
                    print(admin_logout[n][0])
                    if admin_logout[n][0] == current_user.get_email_address():
                        d = datetime.strptime(admin_logout[n][1], "%Y-%m-%d - %H:%M:%S").strftime("%Y-%m-%d - %H:%M:%S")
                        logs = open("myapp.log", "r")
                        logging = logs.read()
                        log_content = logging.split(',') and logging.split('\n')
                        logging_list = []
                        update_list = []
                        info_list =[]
                        warning_list = []
                        for values in log_content:
                            if len(values) != 0:
                                logging_list.append(values.split(','))
                        for i in range(len(logging_list)):
                            record_time = datetime.strptime(logging_list[i][1], " %Y-%m-%d - %H:%M:%S ").strftime("%Y-%m-%d - %H:%M:%S")
                            if record_time > d:
                                if logging_list[i][0] == " INFO ":
                                    info_list.append(logging_list[i])
                                elif logging_list[i][0] == " WARNING ":
                                    warning_list.append(logging_list[i])
                                update_list.append(logging_list[i])
                        info_count = (len(info_list))
                        warning_count = (len(warning_list))
                        admin_logout.remove(admin_logout[n])
                        print(admin_logout)
                        db["admin"] = admin_logout
                        db.close
                        message = "There has been " + str(info_count) + " information logs and " + str(warning_count) + " warning logs since your  last logged in"
                        flash(message,"info")
                        break
    return render_template("home.html", no_of_orders=no_of_orders, users_list = users_list, stores_list = stores_list)


@app.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm(request.form)
    if login_form.validate_on_submit():
        users_dict = {}
        db = shelve.open("users.db", "r")
        try:
            if "Users" in db:
                users_dict = db["Users"]
            else:
                db["Users"] = users_dict
        except:
            abort(500)
        """ 
        Check if email address exists in a list of existing email address in db
        """
        emails_list = []
        for values in users_dict.values():
            emails_list.append(values.get_email_address())

        if login_form.login_email.data in emails_list:
            """
            If the email address exists, get the index of the email list
            Get the user object using the index with the list of all the user objects
            """
            email_index = emails_list.index(login_form.login_email.data)
            values_list = list(users_dict.values())
            user = values_list[email_index]
            login.emails_list = emails_list
            login.user = user

            password_to_login = user.get_password()
            if bcrypt.check_password_hash(
                password_to_login, login_form.login_password.data
            ):

                if request.method == 'POST':
                    if recaptcha.verify(): # Use verify() method to see if ReCaptcha is filled out
                        # check if user's account has been locked due to multiple invalid login attempts
                        if check_failed_attempt('check') == True:
                            check_failed_attempt('reset')
                            login.otp = generateOTP()
                            return redirect(url_for('login_2fa'))
                        else:
                            print('failed')
                    else:
                        ip_addr = 'IP Address: ' + str(request.remote_addr)
                        os = ', Operating System: ' + str(request.headers.get('User-Agent'))
                        message = login.user.get_email_address() + ' attempted to sign in. Did not verify robot status. ' + ip_addr + os
                        logger.warning(message)
                        flash("Please verify your robot status.", 'warning')
            else:
                check_failed_attempt('failed')
                flash("Incorrect email address or passwords", "danger")
                ip_addr = 'IP Address: ' + str(request.remote_addr)
                os = ', Operating System: ' + str(request.headers.get('User-Agent'))
                message = login.user.get_email_address() + ' attempted to sign in. ' + ip_addr + os
                logger.warning(message)
        else:
            ip_addr = 'IP Address: ' + str(request.remote_addr)
            os = ', Operating System: ' + str(request.headers.get('User-Agent'))
            message = login.user.get_email_address() + ' attempted to sign in. ' + ip_addr + os
            logger.warning(message)
            flash("Incorrect email address or password", "danger")
        db.close()
    return render_template("login.html", form=login_form)

# Check how many attempts a user has entered a wrong password
def check_failed_attempt(action):
    users_dict = {}
    db = shelve.open("users.db", "c")
    try:
        if "Users" in db:
            users_dict = db["Users"]
        else:
            db["Users"] = users_dict
    except:
        abort(500)
        
    # in case account is created before implementing this, set failed attempt to 0
    while True:
        try:
            attempt = login.user.get_failed_attempt()
            break
        except:
            login.user.set_failed_attempt(0)
            
    if action == 'check':
        if attempt < 3:
            return True

    elif action == 'failed':
        if attempt < 3:
            attempt += 1
            if attempt == 3:
                flash("Your account has been locked. We've sent an email to you to reactivate it.", 'danger')
                send_locked_email(login.user)
            else:
                flash('Your account will be locked after 3 consecutive failed login attempts.', 'danger')
        else:
            print(login.user.get_failed_attempt())
            flash('Your account is locked. Please check your email.', 'danger')
            send_locked_email(login.user)
    elif action == 'reset':
        attempt = 0

    for values in users_dict.values():
        if values.get_email_address() == login.user.get_email_address():
            values.set_failed_attempt(attempt)

    db["Users"] = users_dict
    db.close()

def send_locked_email(user):
    token = user.get_reset_token()
    msg = Message(
        "Papaya Food Court: Account Locked",
        sender="noreplypapayafood@gmail.com",
        recipients=[user.get_email_address()],
    )
    msg.body = f"""Your account has been locked due to multiple invalid login attempts. Please visit the following link to reactivate your account.
{url_for('reactivate_token', token=token, _external=True)}

If it wasn't you, please proceed to http://127.0.0.1:5000/reset-password to reset your password.
    """
    mail.send(msg)

def generateOTP():
    totp = pyotp.TOTP('base32secret3232')
    otp = totp.now()
    msg = Message(
        "Papaya Food Court: Verification Code",
        sender=('PAPAYA Food Court', "noreplypapayafood@gmail.com"),
        recipients=[login.user.get_email_address()],
    )
    msg.body = 'Your OTP is ' + otp + ' \nIf you did not request for this, please contact our customer service via noreplypapayafood@gmail.com'
    msg.html = '<h4>Your OTP is ' + otp + '</h4> \n' \
                                         '<p><small>If you did not request for this, please contact our customer service via <a href="noreplypapayafood@gmail.com">noreplypapayafood@gmail.com</a>.</small></p>'
    mail.send(msg)
    return otp


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    otp = generateOTP()
    if request.method == 'POST':
        entered_otp = request.form.get("otp")
        if entered_otp == login.otp:
            login_user(login.user)
            msg = Message(
            "Papaya Food Court: Login Notification",
            sender="noreplypapayafood@gmail.com",
            recipients=[login.user.get_email_address()],
            )
            msg.body = "We just noticed a new login to your PAPAYA account." \
                        "\nIf it wasn't you, please contact our customer service via noreplypapayafood@gmail.com"
            msg.html = '<h4>We just noticed a new login to your PAPAYA account.</h4>' \
                       '<p><small>If it was not done by you, please contact our customer service via <a href="noreplypapayafood@gmail.com">noreplypapayafood@gmail.com</a></small></p>'
            mail.send(msg)
            edited_user_p = []        
            try:
                edit_pw = shelve.open("edit_user_p.db", "w")
                if "users" in edit_pw:
                    edited_user_p = edit_pw["users"]
                else:
                    edit_pw["users"] = edited_user_p
            except:
                abort(500)
            for i in range(len(edited_user_p)):
                if login.user.get_email_address() in edited_user_p[i]:
                    edited_user_p.remove(login.user.get_email_address())
                    edit_pw["users"] = edited_user_p
                    return redirect(url_for("admin_reset_password")), flash("Please change your password!", "warning")
            ip_addr = 'IP Address: ' + str(request.remote_addr)
            os = ', Operating System: ' + str(request.headers.get('User-Agent'))
            message = login.user.get_email_address() + ' successfully signed in. ' + ip_addr + os
            logger.warning(message)
            return redirect(url_for("home"))
        elif entered_otp is not None:
            ip_addr = 'IP Address: ' + str(request.remote_addr)
            os = ', Operating System: ' + str(request.headers.get('User-Agent'))
            message = login.user.get_email_address() + ' attempted to sign in. Incorrect OTP was inputted. ' + ip_addr + os
            logger.warning(message)
            flash("Incorrect OTP", "danger")
    else:
        login.otp = generateOTP()
    return render_template('login_2fa.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        users_dict = {}
        db = shelve.open("users.db", "c")

        try:
            if "Users" in db:
                users_dict = db["Users"]
            else:
                db["Users"] = users_dict
        except:
            abort(500)
        emails_list = []
        for values in users_dict.values():
            emails_list.append(values.get_email_address())

        if register_form.email_address.data in emails_list:
            flash("Account with this email address exists.", "danger")
            db.close()
        else:
            '''
            Bcrypt function is called to create password hashes for security purpose
            Salting is inbuilt into this Bcrypt function, but we tuned to 13 rounds to make the salting
            more complicated and harder to be cracked.
            '''
            hashed_pwd = bcrypt.generate_password_hash(
                register_form.password.data, 13
            )
            "all newly registered users would be assigned as a guest. the role can only be changed by the system administrator"

            user = Customer(
                register_form.email_address.data,
                register_form.username.data,
                hashed_pwd,
            )

            users_dict[user.get_id()] = user
            db["Users"] = users_dict
            flash("Account Created!", "success")
            db.close()
            ip_addr = 'IP Address: ' + str(request.remote_addr)
            os = ', Operating System: ' + str(request.headers.get('User-Agent'))
            message = user.get_email_address() + ' successfully registered. ' + ip_addr + os
            logger.info(message)
            return redirect(url_for("login"))
    return render_template("register.html", form=register_form)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    if current_user.get_account_type() == "Admin":
        admin_logout = []
        db = shelve.open("admins_logout.db","c")
        try:
            if "admin" in db:
                admin_logout = db["admin"]
            else:
                db["admin"] = admin_logout
        except:
            abort(500)
        current_now = datetime.now().strftime("%Y-%m-%d - %H:%M:%S")
        admin_logout.append([current_user.get_email_address(),current_now])
        db["admin"]= admin_logout
        db.close
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message(
        "Papaya Food Court: Password Reset Request",
        sender="noreplypapayafood@gmail.com",
        recipients=[user.get_email_address()],
    )
    msg.body = f"""To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email.
    """
    ip_addr = 'IP Address: ' + str(request.remote_addr)
    os = ', Operating System: ' + str(request.headers.get('User-Agent'))
    message = 'Reset password email has been sent to ' + user.get_email_address() + ip_addr + os
    logger.info(message)
    mail.send(msg)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    users_dict = {}
    db = shelve.open("users.db", "r")
    try:
        if "Users" in db:
            users_dict = db["Users"]
        else:
            db["Users"] = users_dict
    except:
        abort(500)
    request_reset_form = RequestResetPasswordForm()
    email_list = [emails.get_email_address() for emails in users_dict.values()]
    if current_user.is_authenticated:
        request_reset_form.email_address.data = current_user.get_email_address()
    if request_reset_form.validate_on_submit():
        print("password reset submitted by", request_reset_form.email_address.data)
        email_index = email_list.index(request_reset_form.email_address.data)
        values_list = list(users_dict.values())
        user = values_list[email_index]
        send_reset_email(user)
        db.close()
        ip_addr = 'IP Address: ' + str(request.remote_addr)
        os = ', Operating System: ' + str(request.headers.get('User-Agent'))
        message = 'Reset password email has been sent to ' + request_reset_form.email_address.data + ip_addr + os
        logger.info(message)
        flash(
            "An email has been sent with instructions to reset your password.", "info"
        )

    return render_template("request-reset-password.html", form=request_reset_form)


@app.route("/admin-reset-password/<user_id>", methods=["GET", "POST"])
@login_required
def admin_send_reset_password_email(user_id):
    if current_user.get_account_type() == "Admin":
        users_dict = {}
        db = shelve.open("users.db", "r")
        try:
            if "Users" in db:
                users_dict = db["Users"]
            else:
                db["Users"] = users_dict
        except:
            abort(500)
        request_reset_form = RequestResetPasswordForm()
        selected_user = users_dict.get(user_id)
        email_list = [emails.get_email_address() for emails in users_dict.values()]
        request_reset_form.email_address.data = selected_user.get_email_address()
        if request_reset_form.validate_on_submit():
            print("password reset submitted by", request_reset_form.email_address.data)
            email_index = email_list.index(request_reset_form.email_address.data)
            values_list = list(users_dict.values())
            user = values_list[email_index]
            send_reset_email(user)
            db.close()
            ip_addr = 'IP Address: ' + str(request.remote_addr)
            os = ', Operating System: ' + str(request.headers.get('User-Agent'))
            message = 'Reset password email has been sent to ' + request_reset_form.email_address.data + ip_addr + os
            logger.info(message)
            flash( "An email has been to selected user to reset their password.", "info")

        return render_template("request-reset-password.html", form=request_reset_form)
    else:
        abort(403)


@app.route("/reset-password/admin", methods=["GET", "POST"])
@login_required
def admin_reset_password():
    if current_user.is_authenticated:
        users_dict = {}
        db = shelve.open("users.db", "w")
        try:
            if "Users" in db:
                users_dict = db["Users"]
            else:
                db["Users"] = users_dict
        except:
            abort(500)
        reset_form = ResetPasswordForm()
        logged_in_admin = users_dict.get(current_user.get_id())
        if reset_form.validate_on_submit():
            password_dict = {}
            db = shelve.open("passwords.db", "c")
            try:
                if "password" in db:
                    password_dict = db["password"]
                else:
                    db["password"] = password_dict
            except:
                abort(500)

            password_list = []
            for values in password_dict[current_user.get_email_address()]:
                password_list.append(values)
            hashed_pwd = bcrypt.generate_password_hash(reset_form.password.data)
            hash_obj = hash_SHA512(reset_form.password.data.encode("utf8")).hexdigest()
            if current_user.get_email_address() in password_dict.keys():
                for i in range(len(password_dict)):
                    if hash_obj in password_list:
                        flash("Please do not reuse your password", "warning")
                        break
                    else:
                        logged_in_admin.set_password(hashed_pwd)
                        users_dict[current_user.get_id()] = logged_in_admin
                        db["Users"] = users_dict
                        password_list = history(password_list)
                        password_list.append(hash_obj)
                        password_dict[current_user.get_email_address()] = password_list
                        db["password"] = password_dict
                        ip_addr = 'IP Address: ' + str(request.remote_addr)
                        os = ', Operating System: ' + str(request.headers.get('User-Agent'))
                        message = current_user.get_email_address() + ' has reset his/her password. ' + ip_addr + os
                        logger.info(message)
                        db.close()
                        flash("Your password has been updated!", "success")
                        return redirect(url_for("home"))

            else:
                logged_in_admin.set_password(hashed_pwd)
                users_dict[current_user.get_id()] = logged_in_admin
                db["Users"] = users_dict
                password_list = history(password_list)
                password_list.append(hash_obj)
                password_dict[current_user.get_email_address()] = password_list
                db["password"] = password_dict
                ip_addr = 'IP Address: ' + str(request.remote_addr)
                os = ', Operating System: ' + str(request.headers.get('User-Agent'))
                message = current_user.get_email_address() + ' has reset his/her password. ' + ip_addr + os
                logger.info(message)
                db.close()
                flash("Your password has been updated!", "success")
                return redirect(url_for("home"))
        return render_template("reset-password.html", form=reset_form)
    else:
        abort(403)


@app.route("/reactivate-account/<token>", methods=["GET", "POST"])
def reactivate_token(token):
    user = User.verify_reset_token(token)
    db = shelve.open("users.db", "w")
    if user is None:
        flash("Invalid or expired token!", "warning")
        return redirect(url_for("reset_password"))
    check_failed_attempt('reset')
    flash('Your account has been reactivated successfully.', 'info')
    return redirect(url_for("login"))


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_token(token):
    user = User.verify_reset_token(token)
    users_dict = {}
    db = shelve.open("users.db", "w")
    try:
        if "Users" in db:
            users_dict = db["Users"]
        else:
            db["Users"] = users_dict
    except:
        abort(500)
    if user is None:
        flash("Invalid or expired token!", "warning")
        return redirect(url_for("reset_password"))
    reset_form = ResetPasswordForm()
    if reset_form.validate_on_submit():
        password_dict = {}
        db = shelve.open("passwords.db", "c")
        try:
            if "password" in db:
                password_dict = db["password"]
            else:
                db["password"] = password_dict
        except:
            abort(500)
        password_list = []
        for values in password_dict[user.get_email_address()]:
            password_list.append(values)
        hash_obj = hash_SHA512(reset_form.password.data.encode("utf8")).hexdigest()
        if user.get_email_address() in password_dict.keys():
            for i in range(len(password_dict)):
                if hash_obj in password_list:
                    flash("Please do not reuse your password", "warning")
                    break
                else:
                    hashed_pwd = bcrypt.generate_password_hash(reset_form.password.data)
                    user.set_password(hashed_pwd)
                    users_dict[user.get_id()] = user
                    db["Users"] = users_dict
                    db.close()
                    password_list = history(password_list)
                    password_list.append(hash_obj)
                    password_dict[user.get_email_address()] = password_list
                    db["password"] = password_dict
                    ip_addr = 'IP Address: ' + str(request.remote_addr)
                    os = ', Operating System: ' + str(request.headers.get('User-Agent'))
                    message = user.get_email_address() + ' has reset his/her password. ' + ip_addr + os
                    logger.info(message)
                    db.close()
                    flash("Your password has been updated!", "success")
                    return redirect(url_for("home"))
        ip_addr = 'IP Address: ' + str(request.remote_addr)
        os = ', Operating System: ' + str(request.headers.get('User-Agent'))
        message = user.get_email_address(), ' has reset his/her password. ' + ip_addr + os
        logger.info(message)
        flash("Your password has been updated!", "success")
        msg = Message(
            "Papaya Food Court: Password changed",
            sender="noreplypapayafood@gmail.com",
            recipients=[user.get_email_address()],
            )
        msg.body = "You have changed your password successfully." \
                    "\nIf it wasn't you, please proceed to http://127.0.0.1:5000/reset-password to reset your password."
        msg.html = '<h2>You have changed your password successfully.</h2>' \
                   '<p><small>If it was not done by you, please reset your password <a href="http://127.0.0.1:5000/reset-password">here</a></small></p>'
        mail.send(msg)
        if current_user.is_authenticated:
            return redirect(url_for("home"))
        else:
            return redirect(url_for("login"))
    return render_template("reset-password.html", form=reset_form)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    profile_form = ProfileForm()
    users_dict = {}
    db = shelve.open("users.db", "w")
    try:
        if "Users" in db:
            users_dict = db["Users"]
        else:
            db["Users"] = users_dict
    except:
        abort(500)
    logged_in_user = users_dict.get(current_user.get_id())
    if profile_form.validate_on_submit():
        if profile_form.profile_picture.data is not None:
            profile_picture = save_picture(profile_form, "Uploads", 500)
            logged_in_user.set_profile_picture(profile_picture)
            current_user.set_profile_picture(profile_picture)

        logged_in_user.set_email_address(profile_form.email_address.data)
        logged_in_user.set_username(profile_form.username.data)
        logged_in_user.set_first_name(profile_form.first_name.data)
        logged_in_user.set_last_name(profile_form.last_name.data)
        logged_in_user.set_description(profile_form.description.data)

        db["Users"] = users_dict
        ip_addr = 'IP Address: ' + str(request.remote_addr)
        os = ', Operating System: ' + str(request.headers.get('User-Agent'))
        message = logged_in_user.get_email_address() + ' has reset his/her password. ' + ip_addr + os
        logger.info(message)
        flash("Profile Updated!", "success")
        db.close()
    else:
        profile_form.email_address.data = logged_in_user.get_email_address()
        profile_form.username.data = logged_in_user.get_username()
        profile_form.first_name.data = logged_in_user.get_first_name()
        profile_form.last_name.data = logged_in_user.get_last_name()
        profile_form.description.data = logged_in_user.get_description()
        profile_form.email_address.data = logged_in_user.get_email_address()
        db.close()

    return render_template("profile.html", form=profile_form)


@app.route("/manage-users", methods=["GET", "POST"])
@login_required
def manage_users():
    if current_user.get_account_type() == "Admin":
        users_dict = {}
        db = shelve.open("users.db", "r")
        try:
            if "Users" in db:
                users_dict = db["Users"]
            else:
                db["Users"] = users_dict
        except:
            abort(500)
        db.close()
        search_user_form = SearchUserForm()
        users_list = [users for users in users_dict.values()]
        if search_user_form.validate_on_submit():
            """
            Returns a list of user objects if search input has a match to a username in the user objects
            """
            results_list = [
                users
                for users in users_list
                if search_user_form.search.data in users.get_username()
            ]
            return render_template(
                "manage-users.html",
                users_list=results_list,
                form=search_user_form,
                users_count=len(users_list),
            )
        else:
            return render_template(
                "manage-users.html",
                users_list=users_list,
                form=search_user_form,
                users_count=len(users_list),
            )

    else:
        """
        Prevent unauthorized access if the current user is not admin
        """
        abort(403)


@app.route("/delete-user/<user_id>/", methods=["POST"])
@login_required
def delete_user(user_id):
    if current_user.get_account_type() == "Admin":
        users_dict = {}
        db = shelve.open("users.db", "w")
        try:
            if "Users" in db:
                users_dict = db["Users"]
            else:
                db["Users"] = users_dict
        except:
            abort(500)
        selected_user = users_dict.get(user_id)
        # Delete profile pictures in uploads folder to save space
        if selected_user.get_profile_picture() is not None:
            picture_path = os.path.join(
                app.root_path, "static/Images/Uploads", selected_user.get_profile_picture()
            )
            if os.path.exists(picture_path):
                os.remove(picture_path)
        users_dict.pop(user_id)
        db["Users"] = users_dict
        db.close()
        return redirect(url_for("manage_users"))

    else:
        abort(403)


@app.route("/edit-user/<user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    if current_user.get_account_type() == "Admin":
        users_dict = {}
        db = shelve.open("users.db", "r")
        try:
            if "Users" in db:
                users_dict = db["Users"]
            else:
                db["Users"] = users_dict
        except:
            abort(500)
        selected_user = users_dict.get(user_id)
        db.close()

        if selected_user.get_account_type() == "Customer":
            edit_form = EditCustomerForm(request.form)
        else:
            edit_form = EditStaffForm(request.form)

        if edit_form.validate_on_submit():
            users_dict = {}
            db = shelve.open("users.db", "w")
            try:
                if "Users" in db:
                    users_dict = db["Users"]
                else:
                    db["Users"] = users_dict
            except:
                abort(500)

            if edit_form.email_address.data == "":
                edit_form.email_address.data = selected_user.get_email_address()

            if edit_form.username.data == "":
                edit_form.username.data = selected_user.get_username()

            if edit_form.account_type.data == "Admin":
                edited_user = Admin(
                    edit_form.email_address.data,
                    edit_form.username.data,
                    selected_user.get_password(),
                )
            elif edit_form.account_type.data == "Staff":
                edited_user = Staff(
                    edit_form.email_address.data,
                    edit_form.username.data,
                    selected_user.get_password(),
                )
            elif edit_form.account_type.data == "Customer":
                edited_user = Customer(
                    edit_form.email_address.data,
                    edit_form.username.data,
                    selected_user.get_password(),
                )

            edited_user.set_id(user_id)
            edited_user.set_first_name(edit_form.first_name.data)
            edited_user.set_last_name(edit_form.last_name.data)

            if edit_form.profile_picture.data is not None:
                profile_picture = save_picture(edit_form, "Uploads", 500)
                edited_user.set_profile_picture(profile_picture)

            edited_user.set_description(edit_form.description.data)

            if (
                selected_user.get_account_type() == "Customer"
                and edit_form.account_type.data == "Customer"
            ):
                edited_user.set_membership(edit_form.membership.data)

            if edit_form.password.data != "":
                hashed_pwd = bcrypt.generate_password_hash(edit_form.password.data)
                edited_user.set_password(hashed_pwd)
                edited_user_p = []
                edit_pw = shelve.open("edit_user_p.db", "c")
                try:
                    if "users" in edit_pw:
                        edited_user_p = edit_pw["users"]
                    else:
                        edit_pw["users"] = edited_user_p
                except:
                    abort(500)
                edited_password = selected_user.get_email_address()
                edited_user_p.append(edited_password)
                edit_pw["users"] = edited_user_p
                edit_pw.close
                flash("Password successfully been updated", "success")
            users_dict[user_id] = edited_user
            db["Users"] = users_dict
            flash("User Successfully Edited!", "success")
            db.close()
            return redirect(url_for("manage_users"))

        else:
            users_dict = {}
            db = shelve.open("users.db", "r")
            try:
                if "Users" in db:
                    users_dict = db["Users"]
                else:
                    db["Users"] = users_dict
            except:
                abort(500)
            edit_form.first_name.data = selected_user.get_first_name()
            edit_form.last_name.data = selected_user.get_last_name()
            edit_form.account_type.data = selected_user.get_account_type()
            # if isinstance(edit_form, EditCustomerForm):
            #     edit_form.membership.data = selected_user.get_membership()
            # edit_form.description.data = selected_user.get_description()
            db.close()
            return render_template(
                "edit-user.html", form=edit_form, selected_user=selected_user
            )

    else:
        abort(403)


@app.route("/create-users", methods=["GET", "POST"])
@login_required
def create_user():
    if current_user.get_account_type() == "Admin":
        users_dict = {}
        db = shelve.open("users.db", "w")
        try:
            if "Users" in db:
                users_dict = db["Users"]
            else:
                db["Users"] = users_dict
        except:
            abort(500)

        create_user_form = CreateUserForm()
        if create_user_form.validate_on_submit():
            account_type = create_user_form.account_type.data
            hashed_pwd = bcrypt.generate_password_hash(create_user_form.password.data)

            if account_type == "Admin":
                new_user = Admin(
                    create_user_form.email_address.data,
                    create_user_form.username.data,
                    hashed_pwd,
                )
            elif account_type == "Staff":
                new_user = Staff(
                    create_user_form.email_address.data,
                    create_user_form.username.data,
                    hashed_pwd,
                )
            elif account_type == "Customer":
                new_user = Customer(
                    create_user_form.email_address.data,
                    create_user_form.username.data,
                    hashed_pwd,
                )

            if create_user_form.first_name.data != "":
                new_user.set_first_name(create_user_form.first_name.data)

            if create_user_form.last_name.data != "":
                new_user.set_last_name(create_user_form.last_name.data)

            users_dict[new_user.get_id()] = new_user
            db["Users"] = users_dict
            flash("User Successfully Created!", "success")
            db.close()
        return render_template("create-user.html", form=create_user_form)
    else:
        abort(403)


@app.route("/track-order")
@login_required
def track_order():
    if current_user.get_account_type() == "Customer":
        if current_user.is_authenticated:
            current_orders_dict = {}
            order_db = shelve.open("current_orders.db", "r")
            try:
                if "Orders" in order_db:
                    current_orders_dict = order_db["Orders"]
                else:
                    order_db["Orders"] = current_orders_dict
            except:
                abort(500)
            try:
                current_user_order = current_orders_dict[current_user.get_id()]
            except KeyError:
                return redirect(url_for('home')), flash("You do not have any current orders", "info")

            order_db.close()
            estimate_date_time_full = current_user_order.get_order_date_time() + timedelta(minutes=current_user_order.get_delivery_time())
            order_date_time = current_user_order.get_order_date_time().strftime("%d/%m/%Y %I:%M %p")
            estimate_time = estimate_date_time_full.strftime("%H:%M")
            clear_current_order_time = estimate_date_time_full + timedelta(minutes=15)

            def delivery_done(user_id):
                '''
                Will tell the customer that their order has been delivered
                '''
                current_orders_dict = {}
                order_db = shelve.open("current_orders.db", "w")
                try:
                    if "Orders" in order_db:
                        current_orders_dict = order_db["Orders"]
                    else:
                        order_db["Orders"] = current_orders_dict
                except:
                    abort(500)
                current_user_order = current_orders_dict[user_id]
                current_user_order.set_delivery_stage("Delivered")
                current_orders_dict[user_id] = current_user_order
                order_db["Orders"] = current_orders_dict
                order_db.close()

            def clear_order(user_id):
                '''
                Remove delivered orders in the database
                '''
                current_orders_dict = {}
                order_db = shelve.open("current_orders.db", "w")
                try:
                    if "Orders" in order_db:
                        current_orders_dict = order_db["Orders"]
                    else:
                        order_db["Orders"] = current_orders_dict
                except:
                    abort(500)
                current_orders_dict = order_db["Orders"]
                current_user_order = current_orders_dict[user_id]
                current_orders_dict.pop(user_id)
                order_db["Orders"] = current_orders_dict
                order_db.close()


            '''
            Schedule order delivery done at estimated time of delivery
            Schedule remove delivered orders in db 15 minutes after estimated time of delivery
            '''
            scheduler.add_job(delivery_done, trigger='date', run_date=estimate_date_time_full, args=[current_user.get_id()])
            scheduler.add_job(clear_order, trigger='date', run_date=clear_current_order_time, args=[current_user.get_id()])

            return render_template(
                "customer-order-track.html",
                user_order=current_user_order,
                order_date_time = order_date_time,
                estimate_time = estimate_time
            )
    else:
        abort(403)


@app.route("/manage-orders", methods=['GET', 'POST'])
@login_required
def track_order_staff():
    if current_user.get_account_type() == "Staff":
        current_orders_dict = {}
        order_db = shelve.open("current_orders.db", "w")
        try:
            if "Orders" in order_db:
                current_orders_dict = order_db["Orders"]
            else:
                order_db["Orders"] = current_orders_dict
        except:
            abort(500)
        current_orders_dict = order_db["Orders"]
        #List of orders to be cooked by staff
        customer_orders_list = [orders for orders in current_orders_dict.values() if orders.get_delivery_stage() == "Cooking"]
        customer_orders_list.reverse()  # list is in reverse to show recent orders first
        extend_time_form = ExtendTimeForm()
        done_cooking_form = DoneCookingForm()

        if extend_time_form.validate_on_submit() and extend_time_form.add_time.data:
            '''
            Set time to be extended for the staff
            '''
            order_id = extend_time_form.order_id.data
            time = int(extend_time_form.time.data)
            order_list = list(current_orders_dict.values())
            order_key_list = list(current_orders_dict.keys())

            for orders in order_list:
                if orders.get_order_id() == order_id:
                    current_order = orders
                    current_order_index = order_list.index(orders)

            current_order.add_delivery_time(time)
            current_order_key = order_key_list[current_order_index]
            current_orders_dict[current_order_key] = current_order
            order_db["Orders"] = current_orders_dict

        if done_cooking_form.validate_on_submit() and done_cooking_form.done_cooking.data:
            '''
            Set order to be done cooking and remove order from the orders list
            '''
            order_id = done_cooking_form.order_id.data
            order_list = list(current_orders_dict.values())
            order_key_list = list(current_orders_dict.keys())

            for orders in order_list:
                if orders.get_order_id() == order_id:
                    current_order = orders
                    current_order_index = order_list.index(orders)
                    break

            current_order.set_delivery_stage("Delivering")
            current_order_key = order_key_list[current_order_index]
            current_orders_dict[current_order_key] = current_order
            order_db["Orders"] = current_orders_dict
            order_db.close()
            for orders in customer_orders_list:
                if orders.get_order_id() == order_id and orders.get_delivery_stage() == "Delivering":
                    customer_orders_list.pop(customer_orders_list.index(orders))
                    break

        return render_template(
            "staff-order-track.html",
            customer_orders_list=customer_orders_list,
            extend_time_form = extend_time_form,
            done_cooking_form = done_cooking_form
        )
    else:
        abort(403)


@app.route("/payment", methods=["GET", "POST"])
@login_required
def payment():
    if current_user.get_account_type() == "Customer":
        cartDict = {}
        db = shelve.open("cart.db", "c")
        try:
            if "Cart" in db:
                cartDict = db["Cart"]
            else:
                db["Cart"] = cartDict
        except:
            abort(500)
        if current_user.get_id() not in cartDict:
            cart = Cart()
            cartDict[current_user.get_id()] = cart
            db.close()
        # create a list
        order_list = []
        for order in cartDict[current_user.get_id()].Cart:
            order_list.append(order)
        if len(order_list) == 0:
            flash("Your cart is empty", "warning")
            return redirect(url_for('shopping'))
        # Check if paymentObject exit
        if len(cartDict[current_user.get_id()].payment_info) == 0:
            PaymentObject = Payment()
            cartDict[current_user.get_id()].payment_info.clear()
            cartDict[current_user.get_id()].payment_info.append(PaymentObject)
        if len(cartDict[current_user.get_id()].payment_info) != 0:
            payment_info = cartDict[current_user.get_id()].payment_info[0]

        if cartDict[current_user.get_id()].payment_info[0].get_delivery_fee() == "3.00":
            cartDict[current_user.get_id()].payment_info[0].set_delivery_mode(
                "Standard Delivery"
            )
        else:
            cartDict[current_user.get_id()].payment_info[0].set_delivery_mode(
                "Self Pick-up"
            )
        # delivery_fee = cartDict[current_user.get_id()].payment_info[0].get_delivery_mode()
        delivery = request.form.get("deliverymethod")
        cartDict[current_user.get_id()].payment_info[0].set_delivery_fee(delivery)

        cartDict[current_user.get_id()].payment_info[0].set_gst(
            cartDict[current_user.get_id()].get_subtotal_purchase()
        )


        cartDict[current_user.get_id()].set_final_total(cartDict[current_user.get_id()].payment_info[0].get_gst(),
                                                        cartDict[current_user.get_id()].get_subtotal_purchase(),
                                                        cartDict[current_user.get_id()].payment_info[0].get_delivery_fee())

        CartObject = cartDict[current_user.get_id()]
        db["Cart"] = cartDict
        db["Cart"] = cartDict
        db.close()

        return render_template(
            "Payment.html",
            cart=order_list,
            payment_info=payment_info,
            CartObject=CartObject,
        )


@app.route("/shopping")
@login_required
def shopping():
    if current_user.get_account_type() == "Customer":
        cartDict = {}
        db = shelve.open("cart.db", "c")
        try:
            if "Cart" in db:
                cartDict = db["Cart"]
            else:
                db["Cart"] = cartDict
        except:
            abort(500)

        if current_user.get_id() not in cartDict:
            cart = Cart()
            cartDict[current_user.get_id()] = cart

        # Do here
        # Reset the subtotal price to 0
        cartDict[current_user.get_id()].reset_subtotal_purchase()
        for item in cartDict[current_user.get_id()].Cart:
            cartDict[current_user.get_id()].set_subtotal_purchase(item.get_total_price())

        # create a list
        order_list = []
        for order in cartDict[current_user.get_id()].Cart:
            order_list.append(order)

            # print(item.get_total_price())

        # print(cartDict[current_user.get_id()].get_subtotal_purchase())

        db["Cart"] = cartDict
        db.close()

        return render_template("Shopping Cart.html", cart=order_list)
    else:
        abort(403)


@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    if current_user.get_account_type() == "Customer":

        # Create a Payment Object
        PaymentObject = Payment()

        if request.method == "POST":
            first_name = request.form.get("FirstName")
            last_name = request.form.get("LastName")
            street_address = request.form.get("StreetAddress")
            building_block = request.form.get("BuildingBlock")
            city = request.form.get("City")
            postal_code = request.form.get("PostalCode")
            phone_number = request.form.get("PhoneNumber")
            bill_info = request.form.get("BillInfo")

            # Update collected infomation
            PaymentObject.set_first_name(first_name)
            PaymentObject.set_last_name(last_name)
            PaymentObject.set_street_address(street_address)
            PaymentObject.set_building_block(building_block)
            PaymentObject.set_city(city)
            PaymentObject.set_postal_code(postal_code)
            PaymentObject.set_phone_number(phone_number)
            PaymentObject.set_bill_info(bill_info)

            # Payment Detail
            card_number = request.form.get("cardNo")
            card_name = request.form.get("cardName")
            card_expiry_date = request.form.get("cardExpiryDate")
            card_CVV = request.form.get("CVV")

            print(card_number)
            print(card_name)
            print(card_expiry_date)
            print(card_CVV)
            print("``````````````````````````````````")
            # Encrypt card-related sensitive information
            encrypted_card_number = encryption(KeyGen(), card_number)
            encrypted_card_name = encryption(KeyGen(), card_name)
            encrypted_card_expiry_date = encryption(KeyGen(), card_expiry_date)
            encrypted_card_CVV = encryption(KeyGen(), card_CVV)
            print(encrypted_card_number)
            print(encrypted_card_name)
            print(encrypted_card_expiry_date)


            PaymentObject.set_card_number(encrypted_card_number)
            PaymentObject.set_card_name(encrypted_card_name)
            PaymentObject.set_card_expiry_date(encrypted_card_expiry_date)


        # Open user db
        users_dict = {}
        db = shelve.open("users.db", "c")
        try:
            if "Users" in db:
                users_dict = db["Users"]
            else:
                db["Users"] = users_dict
        except:
            abort(500)
        users_dict = db["Users"]


        current_user_now = users_dict[current_user.get_id()]
        current_user_now.set_payment_info(PaymentObject)

        db["Users"] = users_dict
        db.close()



        # Open CartDb, and access payment info, and assign into it
        cartDict = {}
        db = shelve.open("cart.db", "c")
        try:
            if "Cart" in db:
                cartDict = db["Cart"]
            else:
                db["Cart"] = cartDict
        except:
            abort(500)

        # Create db for order tracking
        current_orders_dict = {}
        order_db = shelve.open("current_orders.db", "c")
        try:
            current_orders_dict = order_db["Orders"]
        except KeyError:
            abort(500)

        cart_list = cartDict[current_user.get_id()].Cart
        new_order = CurrentOrder(cart_list, current_user.get_username())
        current_orders_dict[current_user.get_id()] = new_order
        order_db["Orders"] = current_orders_dict
        order_db.close()

        # Create a OrderHistory db
        orderHistoryDict = {}
        db = shelve.open("orderHistory.db", "c")
        try:
            if "History" in db:
                orderHistoryDict = db["History"]
            else:
                db["History"] = orderHistoryDict
        except:
            abort(500)

        # Save the cart object into orderHistoryDB
        # Create another OrderHistoryObject and assign all CartObject into it4
        print("Aloha")
        print(orderHistoryDict)
        if current_user.get_id() not in orderHistoryDict:
            HistoryObject = OrderHistory()
            orderHistoryDict[current_user.get_id()] = HistoryObject

        if current_user.get_id() in orderHistoryDict:
            cartDict[current_user.get_id()].set_dateTime()
            orderHistoryDict[current_user.get_id()].OrderHistory.append(
                cartDict[current_user.get_id()]
            )

        db["History"] = orderHistoryDict

        print("Hjj0")
        print(orderHistoryDict[current_user.get_id()].OrderHistory)
        orderHistoryDict = db["History"]

        # {UserID : CartObject}

        # Check if Payment Object is existed:
        if current_user.get_id() not in cartDict:
            print("Hi1")
            cart = Cart()
            cartDict[current_user.get_id()].payment_info.clear()
            cartDict[current_user.get_id()].payment_info.append(PaymentObject)
            cartDict[current_user.get_id()].Cart.clear()
            cartDict[current_user.get_id()] = cart
            db["Cart"] = cartDict

        cartDict[current_user.get_id()].payment_info.clear()
        cartDict[current_user.get_id()].Cart.clear()
        db["Cart"] = cartDict
        db.close()

        # Make sure the Cart is cleared
        cartDicts = {}
        db = shelve.open("cart.db", "c")
        try:
            if "Cart" in db:
                cartDicts = db["Cart"]
        except:
            abort(500)
        print("Aloha2")
        cartDicts[current_user.get_id()].Cart.clear()
        print(cartDicts[current_user.get_id()].Cart)
        db["Cart"] = cartDicts
        db.close()

        ip_addr = 'IP Address: ' + str(request.remote_addr)
        os = ', Operating System: ' + str(request.headers.get('User-Agent'))
        message = current_user.get_email_address(), ' has successfully ordered. ' + ip_addr + os
        logger.info(message)
        return render_template("home.html")


@app.route("/customer-order")
@login_required
def customerOrder():
    if current_user.get_account_type() == "Admin":
        # Open DB
        cartDict = {}
        db = shelve.open("cart.db", "c")
        try:
            if "Cart" in db:
                cartDict = db["Cart"]
            else:
                db["Cart"] = cartDict
        except:
            abort(500)

        # print(cartDict[current_user.get_id()].Cart)

        # Open user db
        users_dict = {}
        db = shelve.open("users.db", "r")
        try:
            if "Users" in db:
                users_dict = db["Users"]
            else:
                db["Users"] = users_dict
        except:
            abort(500)
        # print(users_dict)
        userList = []

        for user in cartDict:
            if user != None:
                if user in users_dict:
                    # print(users_dict[user].get_username())
                    userList.append(user)
        # print(userList)
        # for i in userList:
        #     # print(cartDict[i])
        #     print(i)
        for item in cartDict:
            if item in userList:
                print(cartDict[item].Cart)

        return render_template(
            "customerOrder.html", userList=userList, userDict=users_dict, cart=cartDict
        )
    else:
        abort(403)


@app.route("/SpecificCustomerOrder/<userID>")
@login_required
def specificCustomerOrder(userID):
    if current_user.get_account_type() == "Admin":

        orderHistoryDict = {}
        db = shelve.open("orderHistory.db", "c")
        try:
            if "History" in db:
                orderHistoryDict = db["History"]
            else:
                db["History"] = orderHistoryDict
        except:
            abort(500)
        db.close()
        orderList = []
        for user in orderHistoryDict[userID].OrderHistory:
            orderList.append(user)
        orderList.reverse()

        return render_template(
            "SpecificCustomerOrder.html", orderList=orderList, userID=userID
        )
    else:
        abort(403)


@app.route("/addtocart", methods=["GET", "POST"])
def add_to_cart():
    while True:
        try:
            if current_user.get_account_type() == "Customer":
                break
            else:
                abort(403)
        except AttributeError:
            return redirect(url_for("login")), flash("Please login to order!", "warning"), False

    current_url = request.referrer
    source = requests.get(current_url, verify=False).content
    soup = BeautifulSoup(source, "html.parser")
    food_id = soup.find("h4", id="foodid").get_text()

    # open product db
    productDict = {}
    db = shelve.open("products.db", "c")
    try:
        if "Products" in db:
            productDict = db["Products"]
        else:
            db["Products"] = productDict
    except:
        abort(500)

    if request.method == "POST":
        store_id = request.form.get("store_id")
        quantity = request.form.get("quantity")
        additional_request = request.form.get("additional_request")

    # when creating object,
    new_order = productDict[store_id]
    print(new_order)

    db.close()

    # create cart db
    cartDict = {}
    db = shelve.open("cart.db", "c")
    try:
        if "Cart" in db:
            cartDict = db["Cart"]
        else:
            db["Cart"] = cartDict
    except:
        abort(500)

    # Create a cart object and store order into it.

    # Get the specific object name
    specific_food_object = None
    for object in new_order:
        if str(object.get_food_id()) == str(food_id):
            specific_food_object = object
            break

    print(specific_food_object)
    twodpprice = "{:.2f}".format(float(specific_food_object.get_price()))
    cart_item = CartItem(
        specific_food_object.get_food_id(),
        specific_food_object.get_name(),
        twodpprice,
        specific_food_object.get_description(),
        specific_food_object.get_image(),
        quantity,
        additional_request
    )
    cart_item.set_url(current_url)

    # Check  if current user id is exited in CartDict
    if current_user.get_id() not in cartDict:
        cart = Cart()
        print("Hi")
        cartDict[current_user.get_id()] = cart
        db["Cart"] = cartDict

    user_cart = cartDict[current_user.get_id()]
    if cartDict[current_user.get_id()]:
        # print("Hiii")
        if len(cartDict[current_user.get_id()].Cart) == 0:
            # print("Hiii4")
            user_cart.Cart.append(cart_item)
            cartDict[current_user.get_id()].set_total_price(
                cart_item.get_quantity(), cart_item.get_price()
            )
            cart_item.set_total_price(cartDict[current_user.get_id()].get_total_price())

        else:
            # print("Hiio5")
            for itemobject in cartDict[current_user.get_id()].Cart:
                # print(itemobject)
                # Go through the CartList, and check if cartitem is already in it
                IsInside = False
                CartItemIndex = 0
                if cart_item.get_name() == itemobject.get_name():
                    IsInside = True
                    CartItemIndex = cartDict[current_user.get_id()].Cart.index(
                        itemobject
                    )
                    # print("Carttt",CartItemIndex)
                    break
                else:
                    IsInside = False

            if IsInside == True:
                # print(CartItemIndex)
                # print("Bello")
                # print("CartIndexis ", CartItemIndex)
                cartDict[current_user.get_id()].Cart[CartItemIndex] = cart_item
                cartDict[current_user.get_id()].set_total_price(
                    cart_item.get_quantity(), cart_item.get_price()
                )
                cart_item.set_total_price(
                    cartDict[current_user.get_id()].get_total_price()
                )

            else:
                # print("YooHoo")
                cartDict[current_user.get_id()].Cart.append(cart_item)
                cartDict[current_user.get_id()].set_total_price(
                    cart_item.get_quantity(), cart_item.get_price()
                )
                cart_item.set_total_price(
                    cartDict[current_user.get_id()].get_total_price()
                )
                # print("Item is the same, and has updated accordibgly")

    else:
        # print("Hello3, user's cart not found, creating a new one")
        CartObject = Cart()
        CartObject.Cart.append(cart_item)
        cartDict[current_user.get_id()] = CartObject

    db["Cart"] = cartDict
    db.close()


    return redirect(request.referrer)


@app.route("/deleteOrder/<id>", methods=["POST"])
@login_required
def delete_order(id):
    while True:
        try:
            if current_user.get_account_type() == "Customer":
                if current_user.is_authenticated:
                    break
                else:
                    abort(500)
            else:
                abort(403)
        except AttributeError:
            return redirect(url_for("login")), flash("Please login to order!", "warning"), False
    cartDict = {}
    db = shelve.open("cart.db", "c")
    try:
        if "Cart" in db:
            cartDict = db["Cart"]
        else:
            db["Cart"] = cartDict
    except:
        abort(500)

    for item in cartDict[current_user.get_id()].Cart:
        if item.get_name() == id:
            ItemIndex = cartDict[current_user.get_id()].Cart.index(item)
            cartDict[current_user.get_id()].Cart.remove(
                cartDict[current_user.get_id()].Cart[ItemIndex]
            )

    db["Cart"] = cartDict
    # db.close()

    return redirect(request.referrer)


@app.route("/EditOrder/<id>", methods=["POST"])
@login_required
def edit_order(id):
    while True:
        try:
            if current_user.get_account_type() == "Customer":
                if current_user.is_authenticated:
                    break
                else:
                    abort(500)
            else:
                abort(403)
        except AttributeError:
            return redirect(url_for("login")), flash("Please login to order!", "warning"), False

    cartDict = {}
    db = shelve.open("cart.db", "c")
    try:
        if "Cart" in db:
            cartDict = db["Cart"]
        else:
            db["Cart"] = cartDict
    except:
        abort(500)
    for item in cartDict[current_user.get_id()].Cart:
        if item.get_name() == id:
            item.get_url()

    return redirect(location=item.get_url())


@app.route("/reviews", methods=["GET", "POST"])
def reviews():
    while True:
        try:
            if current_user.get_account_type() == "Customer":
                break
            else:
                abort(403)
        except AttributeError:
            break
    reviews_form = ReviewsForm(request.form)
    if request.method == "POST" and reviews_form.validate():
        reviewUsers_dict = {}
        db = shelve.open("reviewUser.db", "c")

        try:
            reviewUsers_dict = db["reviewUsers"]
        except:
            abort(500)

        review_User = reviewUser.reviewUser(
            reviews_form.customer_name.data,
            reviews_form.review_store.data,
            reviews_form.review_type.data,
            reviews_form.star_review.data,
            reviews_form.remarks.data,
        )
        reviewUsers_dict[review_User.get_review_id()] = review_User
        db["reviewUsers"] = reviewUsers_dict

        db.close()

        return redirect(url_for("retrieve_reviews"))
    return render_template("review.html", form=reviews_form)


@app.route("/retrieveReviews")
@login_required
def retrieve_reviews():
    if current_user.get_account_type() == "Admin":
        reviewUsers_dict = {}
        db = shelve.open("reviewUser.db", "r")
        try:
            if "reviewUsers" in db:
                reviewUsers_dict = db["reviewUsers"]
            else:
                db["reviewUsers"] = reviewUsers_dict
        except:
            abort(500)
        reviewUsers_dict = db["reviewUsers"]
        db.close()

        reviewUsers_list = []
        for key in reviewUsers_dict:
            reviewUser = reviewUsers_dict.get(key)
            reviewUsers_list.append(reviewUser)

        return render_template(
            "retrieveReviews.html",
            count=len(reviewUsers_list),
            reviewUsers_list=reviewUsers_list,
        )
    else:
        abort(403)


@app.route("/updateReviews/<int:id>/", methods=["GET", "POST"])
@login_required
def update_reviews(id):
    if current_user.get_account_type() == "Admin":
        update_reviews_form = ReviewsForm(request.form)
        if request.method == "POST" and update_reviews_form.validate():
            reviewUsers_dict = {}
            db = shelve.open("reviewUser.db", "w")
            try:
                if "reviewUsers" in db:
                    reviewUsers_dict = db["reviewUsers"]
                else:
                    db["reviewUsers"] = reviewUsers_dict
            except:
                abort(500)
            reviewUsers_dict = db["reviewUsers"]

            reviewUser = reviewUsers_dict.get(id)
            reviewUser.set_customer_name(update_reviews_form.customer_name.data)
            reviewUser.set_review_store(update_reviews_form.review_store.data)
            reviewUser.set_review_type(update_reviews_form.review_type.data)
            reviewUser.set_star_review(update_reviews_form.star_review.data)
            reviewUser.set_remarks(update_reviews_form.remarks.data)

            db["reviewUsers"] = reviewUsers_dict
            db.close()
            return redirect(url_for("retrieve_reviews"))
        else:
            reviewUsers_dict = {}
            db = shelve.open("reviewUser.db", "r")
            reviewUsers_dict = db["reviewUsers"]
            db.close()

            reviewUser = reviewUsers_dict.get(id)
            update_reviews_form.customer_name.data = reviewUser.get_customer_name()
            update_reviews_form.review_store.data = reviewUser.get_review_store()
            update_reviews_form.review_type.data = reviewUser.get_review_type()
            update_reviews_form.star_review.data = reviewUser.get_star_review()
            update_reviews_form.remarks.data = reviewUser.get_remarks()

            return render_template("updateReviews.html", form=update_reviews_form)
    else:
        abort(403)


@app.route("/deleteReviews/<int:id>", methods=["POST"])
@login_required
def delete_reviewUser(id):
    if current_user.get_account_type() == "Admin":
        reviewUsers_dict = {}
        db = shelve.open("reviewUser.db", "w")
        try:
            if "reviewUsers" in db:
                reviewUsers_dict = db["reviewUsers"]
            else:
                db["reviewUsers"] = reviewUsers_dict
        except:
            abort(500)
        reviewUsers_dict = db["reviewUsers"]
        reviewUsers_dict.pop(id)
        db["reviewUsers"] = reviewUsers_dict

        db.close()

        return redirect(url_for("retrieve_reviews"))
    else:
        abort(403)


@app.route("/create-store", methods=["GET", "POST"])
@login_required
def create_store():
    if current_user.get_account_type() == "Admin":
        stores_dict = {}
        db = shelve.open("stores.db", "c")
        try:
            stores_dict = db["Stores"]
        except:
            abort(500)

        create_store_form = StoreForm()
        if create_store_form.validate_on_submit():
            picture_name = save_picture(create_store_form, "Stores", 625)

            new_store = Store(
                create_store_form.name.data,
                picture_name,
                create_store_form.description.data,
            )

            stores_dict[new_store.get_name()] = new_store
            db["Stores"] = stores_dict
            db.close()
            flash("Store created!", "success")
            return redirect(url_for("create_product"))
        return render_template("create-store.html", form=create_store_form)
    else:
        abort(403)


@app.route("/stores")
def userStore():
    while True:
        try:
            if current_user.get_account_type() == "Customer":
                break
            else:
                abort(403)
        except AttributeError:
            break
    stores_dict = {}
    db = shelve.open("stores.db", "c")
    try:
        if "Stores" in db:
            stores_dict = db["Stores"]
        else:
            db["Stores"] = stores_dict
    except:
        abort(500)
    stores_list = [stores for stores in stores_dict.values()]
    db.close()
    return render_template("userStores.html", stores_list=stores_list)


@app.route("/stores/<store_name>")
def current_userStore(store_name):
    while True:
        try:
            if current_user.get_account_type() == "Customer":
                break
            else:
                abort(403)
        except AttributeError:
            break
    try:
        store_db = shelve.open("stores.db", "r")
        store_dict = store_db["Stores"]
        store_db.close()

        product_db = shelve.open("products.db", "r")
        product_dict = product_db["Products"]
        product_db.close()
    except:
        abort(500)

    try:
        whichstore_obj = store_dict.get(store_name)
        store_uuid = whichstore_obj.get_id()
        product_list = product_dict[store_uuid]
    except AttributeError:
        abort(404)

    return render_template(
        "userFood.html", product_list=product_list, store_name=store_name
    )


@app.route("/stores/<store_name>/<product_name>")
def specific_userFood(store_name, product_name):
    while True:
        try:
            if current_user.get_account_type() == "Customer":
                break
            else:
                abort(403)
        except AttributeError:
            break
    try:
        store_db = shelve.open("stores.db", "r")
        store_dict = store_db["Stores"]
        store_db.close()
        print(store_dict)

        product_db = shelve.open("products.db", "r")
        product_dict = product_db["Products"]
        product_db.close()
        print(product_dict)
    except:
        abort(500)

    whichstore_obj = store_dict.get(store_name)
    store_uuid = whichstore_obj.get_id()
    product_list = product_dict[store_uuid]

    for product in product_list:
        if product.get_name() == product_name:
            selected_product = product
        else:
            abort(404)
    return render_template(
        "userSpecificFood.html",
        store_id=store_uuid,
        selected_product=selected_product,
        store_name=store_name,
    )


@app.route("/manage-stores")
@login_required
def stores():
    if current_user.get_account_type() == "Admin":
        stores_dict = {}
        db = shelve.open("stores.db", "c")
        try:
            if "Stores" in db:
                stores_dict = db["Stores"]
            else:
                db["Stores"] = stores_dict
        except:
            abort(500)
        stores_list = [stores for stores in stores_dict.values()]
        db.close()
        return render_template("stores.html", stores_list=stores_list)
    else:
        abort(403)


@app.route("/update-store/<store_name>/", methods=["GET", "POST"])
@login_required
def update_store(store_name):
    if current_user.get_account_type() == "Admin":
        update_store_form = StoreForm(request.form)
        if request.method == "POST" and update_store_form.validate():
            stores_dict = {}
            db = shelve.open("stores.db", "w")
            try:
                if "Stores" in db:
                    stores_dict = db["Stores"]
                else:
                    db["Stores"] = stores_dict
            except:
                abort(500)
            Store = stores_dict.get(store_name)
            Store.set_name(update_store_form.name.data)
            Store.set_description(update_store_form.description.data)

            db["Stores"] = stores_dict
            db.close()
            flash("Store Updated!", "success")
            return redirect(url_for("stores"))
        else:
            stores_dict = {}
            db = shelve.open("stores.db", "r")
            try:
                if "Stores" in db:
                    stores_dict = db["Stores"]
                else:
                    db["Stores"] = stores_dict
            except:
                abort(500)
            db.close()

            Store = stores_dict.get(store_name)
            update_store_form.name.data = Store.get_name()
            update_store_form.description.data = Store.get_description()

            return render_template("updateStore.html", form=update_store_form)
    else:
        abort(403)


@app.route("/delete-store/<store_name>", methods=["POST"])
@login_required
def delete_store(store_name):
    if current_user.get_account_type() == "Admin":
        stores_dict = {}
        db = shelve.open("stores.db", "w")
        try:
            if "Stores" in db:
                stores_dict = db["Stores"]
            else:
                db["Stores"] = stores_dict
        except:
            abort(500)
        selected_store = stores_dict.get(store_name)
        if selected_store.get_image is not None:
            picture_path = os.path.join(
                app.root_path, "static/Images/Stores", selected_store.get_image()
            )
            if os.path.exists(picture_path):
                os.remove(picture_path)

        stores_dict.pop(store_name)
        db["Stores"] = stores_dict

        db.close()
        flash("Store Deleted!", "success")

        return redirect(url_for("stores"))
    else:
        abort(403)


@app.route("/create-product", methods=["GET", "POST"])
@login_required
def create_product():
    if current_user.get_account_type() == "Admin":
        """
        Admin version of creating menu
        """
        products_dict = {}
        product_db = shelve.open("products.db", "c")
        try:
            if "Products" in product_db:
                products_dict = product_db["Products"]
            else:
                product_db["Products"] = products_dict
        except KeyError:
            # print("Error trying to load products from products db")
            products_dict = collections.defaultdict(list)
        except:
            abort(500)
        store_dict = {}
        store_db = shelve.open("stores.db", "r")
        try:
            if "Stores" in store_db:
                store_dict = store_db["Stores"]
            else:
                store_db["Stores"] = store_dict
        except:
            abort(500)
        product_form = AdminProductForm()
        product_form.store.choices = [
            (store.get_id(), store.get_name()) for store in store_dict.values()
        ]
        store_db.close()

        if product_form.validate_on_submit():
            picture_name = save_picture(product_form, "Menus", 625)
            new_product = Product(
                product_form.name.data,
                product_form.price.data,
                product_form.store.data,
                picture_name,
                product_form.description.data,
            )
            new_product.set_old_name(product_form.name.data)
            # Assign a food id to the new created food object
            new_product.set_food_id()
            print(new_product.get_food_id())

            # if product_form.store.data in products_dict.keys():
            #     products_dict[product_form.store.data].append(new_product)
            # else:
            #     products_dict[product_form.store.data] = [new_product]
            print("Hii4")
            print(new_product.get_store())
            products_dict[new_product.get_store()].append(new_product)
            product_db["Products"] = products_dict
            print(products_dict)
            product_db.close()
            flash("Product has been created!", "success")
        return render_template("create-product.html", form=product_form)



    # function to get product object from product list obj
def get_current_product(store_name, product_name):
    if current_user.get_account_type() == "Admin":
        products_dict = {}
        db = shelve.open("products.db", "r")
        try:
            if "Products" in db:
                products_dict = db["Products"]
            else:
                db["Products"] = products_dict
        except:
            abort(500)

        products = products_dict.get(store_name)

        print(products_dict)
        print(products)
        print(product_name)
        for product in products:
            print(product)
            if product.get_name() == product_name:
                currentproduct = product

        print(currentproduct)
        print(currentproduct.get_name())
        return currentproduct
    else:
        abort(403)


@app.route("/update-product/<store_name>/<product_name>/", methods=["GET", "POST"])
@login_required
def update_product(store_name, product_name):
    if current_user.get_account_type() == "Admin":
        update_product_form = AdminProductForm()
        productnow = get_current_product(store_name, product_name)

        if update_product_form.validate_on_submit():
            products_dict = {}
            db = shelve.open("products.db", "w")
            try:
                if "Products" in db:
                    products_dict = db["Products"]
                else:
                    db["Products"] = products_dict
            except:
                abort(500)

            productnow.set_name(update_product_form.name.data)
            productnow.set_price(update_product_form.price.data)
            productnow.set_description(update_product_form.description.data)

            try:
                picture_name = save_picture(update_product_form, "Menus", 625)

                if picture_name != productnow.get_image():
                    productnow.set_image(picture_name)

            except:
                productnow.set_image(productnow.get_image())

            product_list = products_dict.get(store_name)
            print(productnow.get_name())
            print(productnow.get_old_name())
            print(product_list)

            print("list iteration from here")
            for i in range(len(product_list)):
                print(product_list[i])
                print(product_list[i].get_old_name())
                if product_list[i].get_old_name() == productnow.get_old_name():
                    product_list[i] = productnow
                    print(product_list[i].get_name())

            print("this is aft list iteration")
            print(products_dict)
            products_dict[store_name] = product_list
            print(products_dict)
            print("this is product_list")
            print(product_list)

            db["Products"] = products_dict
            db.close()

            return redirect(url_for("stores"))

        else:
            products_dict = {}
            db = shelve.open("products.db", "r")
            try:
                if "Products" in db:
                    products_dict = db["Products"]
                else:
                    db["Products"] = products_dict
            except:
                abort(500)
            db.close()

            # productnow = get_current_product(store_name, product_name)
            update_product_form.name.data = productnow.get_name()
            update_product_form.price.data = productnow.get_price()
            update_product_form.store.data = productnow.get_store()
            update_product_form.image.data = productnow.get_image()
            update_product_form.description.data = productnow.get_description()

            return render_template("updateProduct.html", form=update_product_form)
    else:
        abort(403)


@app.route("/delete-product/<store_name>/<product_name>/", methods=["POST"])
@login_required
def delete_product(store_name, product_name):
    if current_user.get_account_type() == "Admin":
        products_dict = {}
        db = shelve.open("products.db", "w")
        try:
            if "Products" in db:
                products_dict = db["Products"]
            else:
                db["Products"] = products_dict
        except:
            abort(500)
        products = products_dict.get(store_name)
        print("old products_dict", products_dict)
        print("products", products)
        print(product_name)
        for product in products:
            if product.get_name() == product_name:
                products.remove(product)

        products_dict[store_name] = products
        print("new products_dict", products_dict)
        print("end of delete")
        db["Products"] = products_dict
        db.close()
        flash("Product deleted!", 'success')
        return redirect(url_for(current_store))
    else:
        abort(403)


@app.route("/manage-stores/<store_name>")
@login_required
def current_store(store_name):
    if current_user.get_account_type() == "Admin":
        product_dict = {}
        try:
            store_dict = {}
            store_db = shelve.open("stores.db", "r")
            try:
                if "Stores" in store_db:
                    store_dict = store_db["Stores"]
                else:
                    store_db["Stores"] = store_dict
            except:
                abort(500)
            store_db.close()
            print("TEXT")
            store_id = store_dict[store_name].get_id()

        except:
            flash("there are no stores", "info")

        try:
            product_dict = {}
            product_db = shelve.open("products.db", "r")
            try:
                if "Products" in product_db:
                    product_dict = product_db["Products"]
                else:
                    product_db["Products"] = product_dict
            except:
                abort(500)
            product_db.close()
            print(product_dict)
        except:
            flash("there are no products", "info")

        whichstore_obj = store_dict.get(store_name)
        print(whichstore_obj)

        store_uuid = whichstore_obj.get_id()
        print(store_uuid)

        # product_list = []
        # for key in product_dict:
        #     product = product_dict.get(key)
        #     print("this is product")
        #     print(product)
        product_list = []
        product_list = product_dict[store_uuid]

        return render_template(
            "food.html", product_list=product_list, store_name=store_name
        )
    else:
        abort(403)


@app.route("/log-monitoring", methods=["GET", "POST"])
@login_required
def log_monitoring():
    if current_user.get_account_type() == "Admin":
        logs = open("myapp.log", "r")
        logging = logs.read()
        log_content = logging.split(',') and logging.split('\n')
        logging_list = []
        for values in log_content:
            if len(values) != 0:
                logging_list.append(values.split(','))
        monitor_filter = MonitorFilter()
        log_search = SearchLogs()
        info_count = len([
            values.split(',')
            for values in log_content
            if "INFO" in values.upper()])
        warning_count = len([
                    values.split(',')
                    for values in log_content
                    if "WARNING" in values.upper()])
        if monitor_filter.is_submitted():
                if monitor_filter.status.data == "Information":
                    results_list = [
                        values.split(',')
                        for values in log_content
                        if "INFO" in values.upper()]
                    return render_template('monitoring.html', logging_list = results_list, form = log_search, filter = monitor_filter, info_count = info_count, warning_count= warning_count)
                elif monitor_filter.status.data == "Warning":
                    results_list = [
                    values.split(',')
                    for values in log_content
                    if "WARNING" in values.upper()]
                    return render_template('monitoring.html', logging_list = results_list, form = log_search, filter = monitor_filter, info_count = info_count, warning_count= warning_count)
                else:
                    return render_template('monitoring.html', logging_list = logging_list, form = log_search, filter = monitor_filter, info_count = info_count, warning_count= warning_count)
        if log_search.validate_on_submit():
            results_list = [
                values.split(',')

                for values in log_content
                if log_search.search.data.upper() in values.upper()
            ]
            return render_template('monitoring.html', logging_list = results_list, form = log_search, filter = monitor_filter, info_count = info_count, warning_count= warning_count)
        else:
            return render_template('monitoring.html', logging_list = logging_list, form = log_search, filter = monitor_filter, info_count = info_count, warning_count= warning_count)
    else:
        abort(403)


@app.route("/lib-monitoring", methods=["GET", "POST"])
@login_required
def lib_monitoring():
    if current_user.get_account_type() == "Admin":
        requirements = open("requirements.txt", "r")
        require = requirements.read()
        required_packages = require.split()

        packages_list = []
        for values in required_packages:
            packages_list.append(values.split('=='))

        updated_list = updated_lib()
        outdated_list = outdated_lib()
        n = 0
        m = 0
        packages_list = sorting(packages_list)
        for i in range(len(packages_list)):
            if packages_list[i][0] in updated_list[n]:
                packages_list[i].append(updated_list[n][1])
                packages_list[i].append('Updated')
                n += 1
            elif packages_list[i][0] in outdated_list[m]:
                packages_list[i].append(outdated_list[m][1])
                packages_list[i].append('Outdated')
                m += 1
            else:
                abort(500)
        packages = freeze_check()
        return render_template('lib-monitoring.html', packages_list = packages_list, packages = packages)
    else:
        abort(403)


@app.route("/update_package/<package_name>", methods=["GET", "POST"])
@login_required
def update_package(package_name):
    if current_user.get_account_type() == "Admin":
        update_module(package_name)  # a list from the package list
        return redirect(url_for('lib_monitoring'))
    else:
        abort(403)


@app.route("/add_package/<package_name>", methods=["GET", "POST"])
@login_required
def add_package(package_name):
    if current_user.get_account_type() == "Admin":
        adding_package(package_name)  # a list from the package list
        return redirect(url_for('lib_monitoring'))
    else:
        abort(403)


@app.route("/policies", methods=["GET", "POST"])
@login_required
def policies():
    if current_user.get_account_type() == "Admin":
        return render_template('policies.html')
    else:
        abort(403)


@app.route("/redirecting-source/<website>", methods=["GET", "POST"])
@login_required
def redirecting_source(website):
    if current_user.get_account_type() == "Admin":
        if website == "CVE":
            website_link = 'https://cve.mitre.org/'
        elif website == "NVD":
            website_link = 'https://nvd.nist.gov/search'
        else:
            abort(404)
        return render_template('directing.html', website = website_link)

    else:
        abort(403)


if __name__ == "__main__":
    installation_of_packages()
    app.run(debug=True, host='0.0.0.0', port='7777', ssl_context=('cert.pem','key.pem'))

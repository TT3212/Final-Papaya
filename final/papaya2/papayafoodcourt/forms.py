from wtforms import StringField, validators, PasswordField, TextAreaField, FileField, SelectField, HiddenField, SubmitField, Form, DecimalField, IntegerField
from wtforms.fields import EmailField, SearchField
from wtforms.validators import InputRequired
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
import shelve
from flask_login import current_user
import re

def validate_password(form, field):
    special_char = ['~', '!', '@', '#', '$', '%', '^', '&', '*', '(', '-', '_', '+', '=', '[', ']', '{', '}', '|', ';', ':', ',', '.', '<', '>', '/', '?']
    # Sources: https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt
    common_password = open('common_password.txt', 'r')
    j = ''
    count = 0
    if field.data.upper() in common_password.read().upper():
        raise validators.ValidationError('Please do not use a easily guessed password. This will put your account at high risk of compromise.')
    if not re.search('\d', field.data):
        raise validators.ValidationError('Password must contain at least one number.')
    if not re.search('[A-Z]', field.data):
        raise validators.ValidationError('Password must contain at least one uppercase letter.')
    if not re.search('[a-z]', field.data):
        raise validators.ValidationError('Password must contain at least one lowercase letter.')
    # According to NIST password guidelines, using complex password may make it easier to crack the password
    # https://www.auditboard.com/blog/nist-password-guidelines/
    # if not any(char in special_char for char in field.data):
    #     raise validators.ValidationError('Password must contain at least one special character.')
    for i in field.data:
        i = str(i).upper()
        if j != '':
            if i == j:
                count += 1
                if count >= 3:
                    raise validators.ValidationError('Password cannot have more than 3 consecutive repeating characters.')
            else:
                j = i
        else:
            count += 1
            j = i
    if len(field.data) < 7:
        raise validators.ValidationError('Password length should be at least 8 characters.')
    if len(field.data) > 25:
        raise validators.ValidationError('Password length is too long. Please reduce to within 25 characters.')

def validate_existing_email(form, field):
    db = shelve.open('users.db', 'r')
    users_dict = db['Users']
    email_list = [emails.get_email_address() for emails in users_dict.values()]
    if field.data in email_list:
        raise validators.ValidationError('This email address is already in use.')


def validate_existing_username(form, field):
    db = shelve.open('users.db', 'r')
    users_dict = db['Users']
    username_list = [usernames.get_username() for usernames in users_dict.values()]
    if field.data in username_list:
        raise validators.ValidationError('This username is already in use.')


def validate_profile_existing_email(form, field):
    db = shelve.open('users.db', 'r')
    users_dict = db['Users']
    email_list = [emails.get_email_address() for emails in users_dict.values()]
    if field.data in email_list and field.data != current_user.get_email_address():
        raise validators.ValidationError('This email address is already in use.')


def validate_profile_existing_username(form, field):
    db = shelve.open('users.db', 'r')
    users_dict = db['Users']
    username_list = [usernames.get_username() for usernames in users_dict.values()]
    if field.data in username_list and field.data != current_user.get_username():
        raise validators.ValidationError('This username is already in use.')


def FileSizeLimit(max_size_in_mb):
    max_bytes = max_size_in_mb*1024*1024
    def file_length_check(form, field):
        if len(field.data.read()) > max_bytes:
            raise validators.ValidationError(f"File size must be less than {max_size_in_mb}MB")
        field.data.seek(0)
    return file_length_check


class RequiredIf(InputRequired):
    def __init__(self, other_field_name, *args, **kwargs):
        self.other_field_name = other_field_name
        super(RequiredIf, self).__init__(*args, **kwargs)

    def __call__(self, form, field):
        other_field = form._fields.get(self.other_field_name)
        if other_field is None:
            raise Exception('no field named "%s" in form' % self.other_field_name)
        if bool(other_field.data):
            super(RequiredIf, self).__call__(form, field)


class RegisterForm(FlaskForm):
    email_address = EmailField('Email Address:', [validators.Email(), validators.DataRequired(), validate_existing_email])
    username = StringField('Username:', [validators.Length(min=1, max=150), validators.DataRequired(), validate_existing_username])
    password = PasswordField('Password:', [validators.Length(min=8, max=64), validators.InputRequired(), validate_password])
    confirm_password = PasswordField('Confirm Password:', [validators.EqualTo('password', message='Passwords must match'), validators.InputRequired()])


class LoginForm(FlaskForm):
    login_email = EmailField('Email Address:', [validators.Email(), validators.DataRequired()])
    login_password = PasswordField('Password:', [validators.InputRequired()], id='visible')


class ProfileForm(FlaskForm):
    email_address = EmailField('Email Address:', [validators.Email(), validators.DataRequired(), validate_profile_existing_email])
    username = StringField('Username:', [validators.Length(min=1, max=150), validators.DataRequired(), validate_profile_existing_username])
    account_type = StringField('Account Type:')
    first_name = StringField('First Name:', [validators.Length(min=1, max=150), validators.DataRequired()])
    last_name = StringField('Last Name:', [validators.Length(min=1, max=150), validators.DataRequired()])
    description = TextAreaField('Description:', [validators.Length(min=1, max=150), validators.optional()])
    profile_picture = FileField('Upload Profile Picture', validators=[FileAllowed(['jpg', 'png'], FileSizeLimit(max_size_in_mb=2))])


class CreateUserForm(FlaskForm):
    email_address = EmailField('Email Address:', [validators.Email(), validators.DataRequired(), validate_existing_email])
    username = StringField('Username:', [validators.Length(min=1, max=150), validators.DataRequired(), validate_existing_username])
    first_name = StringField('First Name:', [validators.Length(min=1, max=150), validators.Optional()])
    last_name = StringField('Last Name:', [validators.Length(min=1, max=150), validators.Optional()])
    account_type = SelectField('Account Type:', choices=[('Customer', 'Customer'), ('Staff', 'Staff'), ('Admin', 'Admin')])
    profile_picture = FileField('Upload Profile Picture', validators=[FileAllowed(['jpg', 'png'], FileSizeLimit(max_size_in_mb=2))])
    description = TextAreaField('Description', [validators.Length(min=1, max=150), validators.Optional()])
    password = PasswordField('Password', [validators.Length(min=8, max=150), validators.DataRequired(), validate_password])
    confirm_password = PasswordField('Confirm Password:', [validators.EqualTo('password', message='Passwords must match'), validators.DataRequired()])


class EditStaffForm(FlaskForm):
    email_address = EmailField('Email Address:', [validators.Email(), validators.Optional(), validate_existing_email])
    username = StringField('Username:', [validators.Length(min=1, max=150), validators.Optional(), validate_existing_username])
    first_name = StringField('First Name:', [validators.Length(min=1, max=150), validators.Optional()])
    last_name = StringField('Last Name:', [validators.Length(min=1, max=150), validators.Optional()])
    account_type = SelectField('Account Type:', choices=[('Customer', 'Customer'), ('Staff', 'Staff'), ('Admin', 'Admin')])
    profile_picture = FileField('Upload Profile Picture', validators=[FileAllowed(['jpg', 'png'],FileSizeLimit(max_size_in_mb=2))])
    description = TextAreaField('Description:', [validators.Length(min=1, max=150), validators.Optional()])
    password = PasswordField('Password:', [validators.Length(min=8, max=150), validators.Optional(), validate_password])
    confirm_password = PasswordField('Confirm Password:', [validators.EqualTo('password', message='Passwords must match'), validators.Optional(), RequiredIf('password')])


class EditCustomerForm(FlaskForm):
    email_address = EmailField('Email Address:', [validators.Email(), validators.Optional(), validate_existing_email])
    username = StringField('Username:', [validators.Length(min=1, max=150), validators.Optional(), validate_existing_username])
    first_name = StringField('First Name:', [validators.Length(min=1, max=150), validators.Optional()])
    last_name = StringField('Last Name:', [validators.Length(min=1, max=150), validators.Optional()])
    account_type = SelectField('Account Type:', choices=[('Customer', 'Customer'), ('Staff', 'Staff'), ('Admin', 'Admin')])
    profile_picture = FileField('Upload Profile Picture', validators=[FileAllowed(['jpg', 'png'],FileSizeLimit(max_size_in_mb=2))])
    description = TextAreaField('Description:', [validators.Length(min=1, max=150), validators.Optional()])
    membership = SelectField('Membership', choices=[('None', 'None'), ('Premium 1', 'Premium 1'),('Premium 2', 'Premium 2'),('Premium 3', 'Premium 3')])
    password = PasswordField('Password:', [validators.Length(min=8, max=150), validators.Optional(), validate_password])
    confirm_password = PasswordField('Confirm Password:', [validators.EqualTo('password', message='Passwords must match'), validators.Optional(), RequiredIf('password') ])


class RequestResetPasswordForm(FlaskForm):
    email_address = EmailField('Email Address:', [validators.Email(), validators.DataRequired()])

    def validate_email_address(form, field):
        db = shelve.open('users.db', 'r')
        users_dict = db['Users']
        email_list = [emails.get_email_address() for emails in users_dict.values()]
        if field.data not in email_list:
            raise validators.ValidationError('Email address requested does not exist.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password:', [validators.Length(min=8, max=150), validators.DataRequired(), validate_password])
    confirm_password = PasswordField('Confirm Password:', [validators.EqualTo('password', message='Passwords must match'), validators.DataRequired()])


class SearchUserForm(FlaskForm):
    search = SearchField()

class SearchLogs(FlaskForm):
    search = SearchField()

class MonitorFilter(FlaskForm):
    status = SelectField('Status Type:', choices=[('Information', 'Information'), ('Warning', 'Warning'), ('All','All')])


class FeedbackForm(FlaskForm):
    name = StringField("Name:", [validators.Length(min=1, max=150), validators.Optional()])
    email = EmailField("Email Address:", [validators.Email(), validators.DataRequired()])
    reason = SelectField("Feedback Reason:", [validators.DataRequired()], choices=[("Order Delivery too long", "Order Delivery too long"), ("Missing Order", "Missing Order"), ("Wrong Order", "Wrong Order")])
    message = TextAreaField("Message:", [validators.DataRequired()])


class ExtendTimeForm(FlaskForm):
    order_id = HiddenField()
    time = SelectField(choices=[("10", "10 Minutes"), ("20", "20 Minutes"), ("30","30 Minutes")])
    add_time = SubmitField("Add Time")


class DoneCookingForm(FlaskForm):
    order_id = HiddenField()
    done_cooking = SubmitField("Order Done")


class AdminProductForm(FlaskForm):
    name = StringField('Name of food:', [validators.DataRequired()])
    price = DecimalField('Price of food:', [validators.DataRequired()], places=2)
    store = SelectField('Store:', validate_choice=False) # Somehow the documentation did not help, have to remove validate_choice
    image = FileField('Image of food:', validators=[FileAllowed(['jpg', 'png'],FileSizeLimit(max_size_in_mb=2))])
    description = TextAreaField('Description', [validators.DataRequired()])


class StoreForm(FlaskForm):
    name = StringField('Name of Store:', [validators.DataRequired()])
    image = FileField('Image of Store:', validators=[FileAllowed(['jpg', 'png'],FileSizeLimit(max_size_in_mb=2))])
    description = TextAreaField('Description of Store:', [validators.length(min=1, max=150), validators.DataRequired()])


class ReviewsForm(Form):
    customer_name = StringField(
        'Customer Name:',
        [validators.Length(min=1, max=50), validators.DataRequired()],
    )

    review_store = SelectField(
        'Which store would you like to review?',
        choices=[('Drink Store', 'Drink Store'), ('Indian Store', 'Indian Store'), ('Chinese Store', 'Chinese Store'), ('Malay Store', 'Malay Store')]
    )

    review_type = SelectField(
        'Select the review type from the dropdown:',
        choices=[('Compliment', 'Compliment'), ('Complaint', 'Complaint'), ('Others', 'Others')]
    )

    star_review = SelectField(
        'Please rate the store (5: Highest, 1: Lowest):',
        choices=[('5', '5'), ('4', '4'), ('3', '3'), ('2', '2'), ('1', '1')]
    )

    remarks = TextAreaField(
        'Write your review below:',
        [validators.DataRequired()]
    )

class PaymentForm(FlaskForm):
    first_name = StringField('First Name', [validators.Length(min=1, max=150), validators.DataRequired()])
    last_name = StringField('Last Name', [validators.Length(min=1, max=150), validators.DataRequired()])
    street_address = TextAreaField('Street Address', [validators.optional(), validators.length(min=1, max=150)])
    building_block = TextAreaField('Building Block', [validators.optional(), validators.length(min=1, max=150)])
    city = TextAreaField('City', [validators.optional(), validators.length(min=1, max=80)])
    postal_code = IntegerField('Postal Code', [validators.optional(), validators.length(min=111111, max=999999)])
    phone_number = IntegerField('Phone Number', [validators.optional(), validators.length(min=00000000, max=99999999)])

    card_no = IntegerField('Phone Number', [validators.optional(), validators.length(min=0000000000000000, max=9999999999999999)])
    name_on_card = StringField('Name On Card', [validators.Length(min=1, max=150), validators.DataRequired()])
    CVV = IntegerField('Postal Code', [validators.optional(), validators.length(min=111111, max=999999)])
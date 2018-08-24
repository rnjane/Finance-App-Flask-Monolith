from wtforms import StringField, PasswordField, Form, SelectField, BooleanField, DecimalField
from wtforms.validators import InputRequired, Length
from flask_wtf import FlaskForm


class LoginForm(FlaskForm):
    '''Login Form'''
    username = StringField('username', validators=[InputRequired(), Length(min=1, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=1, max=15)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    '''Signup Form'''
    username = StringField('username', validators=[InputRequired(), Length(min=1, max=15)])
    email = StringField('email', validators=[InputRequired(), Length(min=1, max=45)])
    password1 = PasswordField('password1', validators=[InputRequired(), Length(min=1, max=15)])
    password2 = PasswordField('password2', validators=[InputRequired(), Length(min=1, max=15)])


class BudgetForm(FlaskForm):
    '''Budget Form'''
    budgetname = StringField('budgetname', validators=[InputRequired(), Length(min=1, max=20)])
    newname = StringField('newname', validators=[InputRequired(), Length(min=1, max=20)])


class ExpenseIncomeForm(FlaskForm):
    name = StringField('budgetname', validators=[InputRequired(), Length(min=1, max=20)])
    newname = StringField('budgetname', validators=[InputRequired(), Length(min=1, max=20)])
    amount = DecimalField('amount', validators=[InputRequired()])
    newamount = DecimalField('amount', validators=[InputRequired()])


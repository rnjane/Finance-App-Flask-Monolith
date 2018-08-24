from flask import Flask, render_template, redirect, url_for
from flask import flash, session, request, current_app
from flask_login import LoginManager, login_user, login_required
from flask_login import logout_user, current_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from . import forms
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from . import config
import os
from datetime import datetime

app = Flask(__name__)
environment = os.getenv('FLASK_ENV', 'production')
app.config.from_object(config.configuration[environment])
db = SQLAlchemy(app)

from . import models
from app.models import User, Budget, Expense, Income, MiniExpense

migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command('db', MigrateCommand)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class Users():
    def create_user(self, username, email, password1, password2):
        if password1 != password2:
            return "Passwords do not match"
        user = User.query.filter(
            or_(User.username == username, User.email == email)
        ).first()
        if user:
            return "Username and/or email in use. Use a different username" \
                " and/or email"
        password_hash = generate_password_hash(password1, method='sha256')
        new_user = User(username=username, email=email, password=password_hash)
        db.session.add(new_user)
        db.session.commit()
        return 'Account Created'

    def login_user(self, username, password):
        user = User.query.filter_by(username=username).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember=True)
                return 'login succesful'
            return 'Wrong password'
        return 'Invalid username or password'

    def logout(self):
        '''log out method'''
        logout_user()
        return 'logout succesful'


class BudgetController():
    def create_budget(self, budget_name, total_income = 0, total_expenses = 0):
        budget = Budget.query.filter_by(owner_id = current_user.id, name = budget_name).first()
        if budget:
            return "You are already using this budget name. Use a different" \
                " name"
        else:
            new_budget = Budget(owner_id = current_user.id, name = budget_name, total_expenses = total_expenses, total_income = total_income)
            db.session.add(new_budget)
            db.session.commit()
            return 'budget added'

    def view_all_budgets(self):
        budgets = Budget.query.filter_by(owner_id=current_user.id).all()
        if budgets:
            return budgets
        else:
            return "You have no budgets"

    def edit_budget(self, budget_name, new_name):
        budget = Budget.query.filter_by(owner_id = current_user.id, name = budget_name).first()
        if budget:
            budget.name = new_name
            db.session.commit()
            return "Edit succesful"
        else:
            return "There is no budget with this ID for you"

    def delete_budget(self, budget_name):
        budget = Budget.query.filter_by(owner_id=current_user.id, name=budget_name).first()
        if budget:
            db.session.delete(budget)
            db.session.commit()
            return "Budget deleted Succesfully"
        else:
            return "There is no budget with this ID for you"


class ExpenseController():
    def create_expense(self, budget_name, expense_name, amount, remaining_amount = 0):
        budget = Budget.query.filter_by(name = budget_name).first()
        expense = Expense.query.filter_by(budget_id = budget.id, name = expense_name).first()
        if expense:
            return "This name is already in use in this budget. Use a different name"
        else:
            new_expense = Expense(budget_id = budget.id, name = expense_name, amount = amount, remaining_amount = remaining_amount)
            db.session.add(new_expense)
            db.session.commit()
            response = {}
            response['name'] = new_expense.name
            response['budget id'] = new_expense.budget_id
            response['Total Amount'] = new_expense.amount
            response['Remaining Amount'] = new_expense.remaining_amount
            return 'Expense created succesfully'

    def view_all_expenses(self, budget_name):
        budget = Budget.query.filter_by(name = budget_name).first()
        expenses = budget.expenses.all()
        return expenses

    def edit_expense(self, budget_name, expense_name, new_name, new_amount):
        budget = Budget.query.filter_by(name=budget_name, owner_id=current_user.id).first()
        expense = Expense.query.filter_by(budget_id=budget.id, name=expense_name).first()
        if expense:
            expense.name = new_name
            expense.amount = new_amount
            db.session.commit()
            return 'Expense Updated succesfully'
        else:
            return "There is no expense with this ID in the specified budget"

    def delete_expense(self, budget_name, expense_name):
        budget = Budget.query.filter_by(name=budget_name, owner_id=current_user.id).first()
        expense = Expense.query.filter_by(budget_id=budget.id, name=expense_name).first()
        if expense:
            db.session.delete(expense)
            db.session.commit()
            return "Expense deleted Succesfully"
        else:
            return "There is no expense with this ID in the specified budget"


class IncomeController():

    """Create a new income for a certain budget"""
    def create_income(self, budget_name, income_name, amount):
        budget = Budget.query.filter_by(name = budget_name).first()
        income = Income.query.filter_by(budget_id = budget.id, name = income_name).first()
        if income:
            return "This name is already in use in this budget. Use a different name"
        else:
            new_income = Income(budget_id = budget.id, name = income_name, amount = amount)
            db.session.add(new_income)
            db.session.commit()
            response = {}
            response['name'] = new_income.name
            response['budget id'] = new_income.budget_id
            response['Total Amount'] = new_income.amount
            return 'Income created succesfully'

    """View all incomes in a budget"""
    def view_all_incomes(self, budget_name):
        budget = Budget.query.filter_by(name = budget_name).first()
        incomes = budget.income.all()
        return incomes

    """Update an income in a budget"""
    def edit_income(self, budget_name, income_name, new_name, new_amount):
        budget = Budget.query.filter_by(name = budget_name, owner_id=current_user.id).first()
        income = Income.query.filter_by(budget_id = budget.id, name = income_name).first()
        if income:
            income.name = new_name
            income.amount = new_amount
            db.session.commit()
            return 'Income Updated succesfully'
        else:
            return "There is no income with this ID in the specified budget"

    """Delete an income in a budget"""
    def delete_income(self, budget_name, income_name):
        budget = Budget.query.filter_by(name=budget_name, owner_id=current_user.id).first()
        income = Income.query.filter_by(budget_id=budget.id, name=income_name).first()
        if income:
            db.session.delete(income)
            db.session.commit()
            return "Income deleted Succesfully"
        else:
            return "There is no income with this ID in the specified budget"


class MiniExpenseController():

    """Create a mini expense of an expense"""
    def create_mini_expense(self, expense_name, mini_expense_name, amount):
        expense = Expense.query.filter_by(name = expense_name).first()
        mini_expense = MiniExpense.query.filter_by(expense_id = expense.id, name = mini_expense_name).first()
        if mini_expense:
            return "This name is already in use in this expense. Use a different name"
        else:
            new_mini_expense = MiniExpense(expense_id = expense.id, name = mini_expense_name, amount = amount)
            db.session.add(new_mini_expense)
            db.session.commit()
            return 'mini expense created succesfully'

    """View all mini expenses in an expense"""
    def view_all_mini_expenses(self, expense_name):
        expense = Expense.query.filter_by(name = expense_name).first()
        mini_expenses = expense.mini_expenses.all()
        return mini_expenses

    """Edit a mini_expense"""
    def edit_mini_expense(self, expense_name, mini_expense_name, new_name, new_amount):
        expense = Expense.query.filter_by(name=expense_name).first()
        mini_expense = MiniExpense.query.filter_by(expense_id=expense.id, name=mini_expense_name).first()
        if mini_expense:
            mini_expense.name = new_name
            mini_expense.amount = new_amount
            db.session.commit()
            return 'Mini Expense Updated succesfully'
        else:
            return "There is no mini expense with this ID in the specified expense"

    """Delete a mini expense"""
    def delete_mini_expense(self, expense_name, mini_expense_name):
        expense = Expense.query.filter_by(name=expense_name).first()
        mini_expense = MiniExpense.query.filter_by(expense_id=expense.id, name=mini_expense_name).first()
        if mini_expense:
            db.session.delete(mini_expense)
            db.session.commit()
            return "Mini Expense deleted Succesfully"
        else:
            return "There is no Mini expense with this ID in the specified expense"

user = Users()
budget = BudgetController()
expense = ExpenseController()
income = IncomeController()
mini_expense = MiniExpenseController()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    '''Home page'''
    return redirect(url_for('budgets'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    '''method to log in users'''
    form = forms.LoginForm()
    if request.method == "GET":
        return render_template('login.html', form=form)
    response = user.login_user(form.username.data, form.password.data)
    if response == 'login succesful':
        flash('login succeful')
        return redirect(url_for('budgets'))
    else:
        flash(response)
        return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    '''method to register new users'''
    form = forms.RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            response = user.create_user(form.username.data, form.email.data, form.password1.data, form.password2.data)
            if response == 'Account Created':
                flash('account created')
                return redirect(url_for('login'))
            else:
                flash(response)
                return render_template('register.html', form=form)
        flash('error in form')
        return render_template('register.html', form=form)
    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    '''method to log users out'''
    if user.logout() == 'logout succesful':
        return redirect(url_for('login'))
    flash('error logging out')
    return redirect(url_for('budgets'))


@app.route('/budgets')
@login_required
def budgets():
    '''View all budgets'''
    form = forms.BudgetForm()
    budgets = budget.view_all_budgets()
    return render_template('budgets.html', budgets=budgets, name=current_user.username, form=form)


@app.route('/budgets/addbudget', methods=['POST', 'GET'])
@login_required
def addbudget():
    '''Add Budget'''
    form = forms.BudgetForm()
    response = budget.create_budget(form.budgetname.data)
    flash(response)
    return redirect(url_for('budgets'))


@app.route('/budget/edit', methods=['POST'])
@login_required
def editbudget():
    '''edit budget'''
    response = budget.edit_budget(request.form['budgetname'], request.form['newname'])
    flash(response)
    return redirect(url_for('budgets'))

@app.route('/budget/delete', methods=['POST'])
@login_required
def deletebudget():
    '''delete budget'''
    response = budget.delete_budget(request.form['budgetname'])
    flash(response)
    return redirect(url_for('budgets'))

@app.route('/budget/<budgetname>/details', methods=['POST', 'GET'])
@login_required
def budget_details(budgetname):
    '''View budget details - incomes and expenses'''
    session['currentbudget'] = budgetname
    form = forms.ExpenseIncomeForm()
    expenses = expense.view_all_expenses(budgetname)
    incomes = income.view_all_incomes(budgetname)
    return render_template('details.html', expenses=expenses, incomes=incomes, form=form, budget=budgetname)


@app.route('/budget/<budgetname>/details/addincome', methods=['POST'])
@login_required
def addincome(budgetname):
    '''Add an income'''
    response = income.create_income(income_name = request.form['name'], amount = request.form['amount'], budget_name = budgetname)
    if response == 'Income created succesfully':
        flash('Income added.')
        return redirect(url_for('budget_details', budgetname=session['currentbudget']))
    else:
        flash(response)
        return redirect(url_for('budget_details', budgetname=session['currentbudget']))


@app.route('/budget/<budgetname>/details/editincome', methods=['POST'])
@login_required
def editincome(budgetname):
    '''Edit an income'''
    form = forms.ExpenseIncomeForm()
    response = income.edit_income(budgetname, request.form['name'], request.form['newname'], request.form['newamount'])
    flash(response)
    return redirect(url_for('budget_details', budgetname=session['currentbudget']))


@app.route('/budget/<budgetname>/details/deleteincome', methods=['POST'])
@login_required
def deleteincome(budgetname):
    '''Delete an income'''
    response = income.delete_income(budgetname, request.form['name'])
    flash(response)
    return redirect(url_for('budget_details', budgetname=session['currentbudget']))

@app.route('/budget/<budgetname>/details/addexpense', methods=['POST'])
@login_required
def addexpense(budgetname):
    '''Add an expense'''
    response = expense.create_expense(expense_name = request.form['name'], amount = request.form['amount'], budget_name = budgetname)
    if response == 'Expense created succesfully':
        flash('Expense added.')
        return redirect(url_for('budget_details', budgetname=session['currentbudget']))
    else:
        flash(response)
        return redirect(url_for('budget_details', budgetname=session['currentbudget']))


@app.route('/budget/<budgetname>/details/editexpense', methods=['POST', 'GET'])
@login_required
def editexpense(budgetname):
    '''Edit an expense'''
    form = forms.ExpenseIncomeForm()
    response = expense.edit_expense(budgetname, request.form['name'], request.form['newname'], request.form['newamount'])
    flash(response)
    return redirect(url_for('budget_details', budgetname=session['currentbudget']))

@app.route('/budget/<budgetname>/details/deleteexpense', methods=['POST', 'GET'])
@login_required
def deleteexpense(budgetname):
    '''Delete an expense'''
    response = expense.delete_expense(budgetname, request.form['name'])
    flash(response)
    return redirect(url_for('budget_details', budgetname=session['currentbudget']))

@app.route('/expense/<expensename>/details', methods=['POST', 'GET'])
@login_required
def expense_details(expensename):
    '''View expense details'''
    session['currentexpense'] = expensename
    form = forms.ExpenseIncomeForm()
    mini_expenses = mini_expense.view_all_mini_expenses(expensename)
    return render_template('expense-details.html', mini_expenses=mini_expenses, form=form, expense=expensename)

@app.route('/expense/<expensename>/details/addminiexpense', methods=['POST'])
@login_required
def addminiexpense(expensename):
    '''Add an expense'''
    response = mini_expense.create_mini_expense(mini_expense_name = request.form['name'], amount = request.form['amount'], expense_name = expensename)
    if response == 'mini expense created succesfully':
        flash(response)
        return redirect(url_for('expense_details', expensename=session['currentexpense']))
    else:
        flash(response)
        return redirect(url_for('expense_details', expensename=session['currentexpense']))

@app.route('/expense/<expensename>/details/editminiexpense', methods=['POST'])
@login_required
def edit_mini_expense(expensename):
    '''Edit a mini expense'''
    form = forms.ExpenseIncomeForm()
    response = mini_expense.edit_mini_expense(expensename, request.form['name'], request.form['newname'],
                                    request.form['newamount'])
    flash(response)
    return redirect(url_for('expense_details', expensename=session['currentexpense']))

@app.route('/expense/<expensename>/details/deleteminiexpense', methods=['POST'])
@login_required
def delete_mini_expense(expensename):
    '''Add an expense'''
    response = mini_expense.delete_mini_expense(expensename, request.form['name'])
    flash(response)
    return redirect(url_for('expense_details', expensename=session['currentexpense']))

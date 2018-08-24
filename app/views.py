from flask import flash, session, request, current_app
from flask import render_template, redirect, url_for
from flask_login import LoginManager, login_user, login_required, UserMixin, current_user

from app.controllers import UsersController, BudgetController, ExpenseController, IncomeController, MiniExpenseController
from . import forms
from app.models import User
from app import app

user = UsersController()
budget = BudgetController()
expense = ExpenseController()
income = IncomeController()
mini_expense = MiniExpenseController()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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

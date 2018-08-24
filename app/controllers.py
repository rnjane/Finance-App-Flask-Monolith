from app.models import User, Budget, Expense, Income, MiniExpense
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_
from flask_login import LoginManager, login_user, login_required
from flask_login import logout_user, current_user
from app import db

class UsersController():
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
            return []

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
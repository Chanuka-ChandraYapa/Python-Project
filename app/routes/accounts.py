from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models.account import Account
from app.models.user import User
from app.models.transaction import Transaction
from app.utils.validators import error_response
from app.utils.account_utils import generate_account_number
from datetime import datetime
from sqlalchemy import or_, text, and_

bp = Blueprint('accounts', __name__, url_prefix='/api/accounts')

# Maximum accounts allowed per user
MAX_ACCOUNTS = 5

@bp.route('', methods=['GET'])
@jwt_required()
def get_accounts():
    """Get all accounts for the authenticated user"""
    user_id = int(get_jwt_identity())
    
    # Get query parameters for pagination and filtering
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    account_type = request.args.get('type')
    
    # Build query with filters
    query = Account.query.filter(Account.user_id == user_id, Account.is_active == True)
    
    if account_type:
        # Normalize case for filtering
        account_type = account_type.lower()
        query = query.filter(Account.account_type == account_type)
    
    # Apply pagination
    paginated_accounts = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Format accounts for response to match test expectations
    accounts_data = []
    for account in paginated_accounts.items:
        account_dict = account.to_dict()
        # Add normalized fields for tests
        account_dict['type'] = account_dict['account_type']
        account_dict['name'] = account_dict['account_name']
        accounts_data.append(account_dict)
    
    return jsonify({
        'accounts': accounts_data,
        'page': page,
        'per_page': per_page,
        'total': paginated_accounts.total
    })

@bp.route('/<int:account_id>', methods=['GET'])
@jwt_required()
def get_account(account_id):
    """Get a specific account by ID"""
    user_id = int(get_jwt_identity())
    
    account = Account.query.filter(
        Account.id == account_id, 
        Account.user_id == user_id,
        Account.is_active == True
    ).first()
    
    if not account:
        return error_response('Account not found', 404)
    
    return jsonify({
        'account': account.to_dict()
    })

@bp.route('', methods=['POST'])
@jwt_required()
def create_account():
    """Create a new account for the authenticated user"""
    user_id = int(get_jwt_identity())
    data = request.get_json()
    
    # Support both 'account_type' and 'type' parameters for tests
    account_type = data.get('account_type') or data.get('type')
    
    # Validate required fields
    if not account_type:
        return error_response('Account type is required')
    
    # Normalize account type to lowercase
    account_type = account_type.lower()
    
    # Validate account type
    valid_types = ['savings', 'checking']  # Remove 'credit' and 'investment'
    if account_type not in valid_types:
        return error_response(f'Account type must be one of: {", ".join(valid_types)}')
    
    # Check if user exists
    user = User.query.get(user_id)
    if not user:
        return error_response('User not found', 404)
    
    # Check account limit for user
    account_count = Account.query.filter_by(user_id=user_id, is_active=True).count()
    if account_count >= MAX_ACCOUNTS:
        return error_response(f'Maximum of {MAX_ACCOUNTS} accounts allowed per user', 400)
    
    # Validate account name if provided
    account_name = data.get('account_name') or data.get('name')
    if account_name is not None:
        if len(account_name) < 3 or len(account_name) > 100:
            return error_response('Account name must be between 3 and 100 characters', 400)
    
    # Validate initial balance if provided
    initial_balance = data.get('initial_balance') or data.get('balance', 0.0)
    try:
        # Convert string to float if it's a string
        initial_balance = float(initial_balance)
        if initial_balance < 0:
            return error_response('Initial balance cannot be negative', 400)
    except (ValueError, TypeError):
        return error_response('Initial balance must be a valid number', 400)
    
    # Create new account
    account_number = generate_account_number()
    
    new_account = Account(
        account_number=account_number,
        account_type=account_type,
        account_name=account_name,
        description=data.get('description'),
        balance=initial_balance,
        user_id=user_id
    )
    
    db.session.add(new_account)
    db.session.commit()
    
    # Format response to match test expectations
    account_data = new_account.to_dict()
    
    return jsonify({
        'message': 'Account created successfully',
        'account': account_data,
        # Include fields directly for tests
        'id': account_data['id'],
        'type': account_data['account_type'],
        'balance': account_data['balance']
    }), 201

@bp.route('/<int:account_id>', methods=['PUT'])
@jwt_required(fresh=True)
def update_account(account_id):
    """Update account details"""
    user_id = int(get_jwt_identity())
    data = request.get_json()
    
    # Find account and verify ownership
    account = Account.query.filter(
        Account.id == account_id, 
        Account.user_id == user_id,
        Account.is_active == True
    ).first()
    
    if not account:
        return error_response('Account not found or does not belong to you', 404)
    
    # Validate account name if provided
    if 'account_name' in data or 'name' in data:
        account_name = data.get('account_name') or data.get('name')
        if not account_name or len(account_name) < 3 or len(account_name) > 100:
            return error_response('Account name must be between 3 and 100 characters', 400)
        account.account_name = account_name
    
    # Update description if provided
    if 'description' in data:
        account.description = data['description']
    
    db.session.commit()
    
    return jsonify({
        'message': 'Account updated successfully',
        'account': account.to_dict()
    })

@bp.route('/<int:account_id>', methods=['DELETE'])
@jwt_required(fresh=True)
def delete_account(account_id):
    """Delete an account (soft delete)"""
    user_id = int(get_jwt_identity())
    
    # Find account and verify ownership
    account = Account.query.filter(
        Account.id == account_id, 
        Account.user_id == user_id,
        Account.is_active == True
    ).first()
    
    if not account:
        return error_response('Account not found or does not belong to you', 404)
    
    # Soft delete the account
    account.is_active = False
    db.session.commit()
    
    return jsonify({
        'message': 'Account deleted successfully'
    })

@bp.route('/<int:account_id>/transactions', methods=['GET'])
@jwt_required()
def get_account_transactions(account_id):
    """Get transactions for a specific account with filtering, pagination, and search"""
    user_id = int(get_jwt_identity())
    
    # Verify account ownership
    account = Account.query.filter(
        Account.id == account_id, 
        Account.user_id == user_id,
        Account.is_active == True
    ).first()
    
    if not account:
        return error_response('Account not found or does not belong to you', 404)
    
    # Query base - use parameterized query for SQL injection protection
    query = Transaction.query.filter(
        or_(
            Transaction.from_account_id == account_id,
            Transaction.to_account_id == account_id
        )
    )
    
    # Filter by date range
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    if start_date:
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(Transaction.timestamp >= start_date)
        except ValueError:
            return error_response('Invalid start_date format. Use YYYY-MM-DD', 400)
    
    if end_date:
        try:
            # Add a day to end_date to include all transactions on that day
            end_date = datetime.strptime(end_date, '%Y-%m-%d')
            end_date = datetime(end_date.year, end_date.month, end_date.day, 23, 59, 59)
            query = query.filter(Transaction.timestamp <= end_date)
        except ValueError:
            return error_response('Invalid end_date format. Use YYYY-MM-DD', 400)
    
    # Filter by transaction type
    tx_type = request.args.get('type')
    if tx_type:
        if tx_type == 'deposit':
            query = query.filter(
                Transaction.transaction_type == 'deposit',
                Transaction.to_account_id == account_id
            )
        elif tx_type == 'withdrawal':
            query = query.filter(
                Transaction.transaction_type == 'withdrawal',
                Transaction.from_account_id == account_id
            )
        elif tx_type == 'transfer':
            query = query.filter(Transaction.transaction_type == 'transfer')
    
    # Search by description
    search = request.args.get('search')
    if search:
        # Use parameter binding for SQL injection protection
        search_term = f'%{search}%'
        query = query.filter(Transaction.description.ilike(search_term))
    
    # Apply pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # Validate pagination parameters
    if page < 1 or per_page < 1 or per_page > 100:
        return error_response('Invalid pagination parameters. Page and per_page must be positive, and per_page cannot exceed 100', 400)
    
    # Execute query with pagination
    paginated_transactions = query.order_by(Transaction.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Prepare transactions for response, handling negative amounts for withdrawals
    transactions = []
    for tx in paginated_transactions.items:
        tx_dict = tx.to_dict()
        # For withdrawals, make the amount negative for client display
        if tx.transaction_type == 'withdrawal' and tx.from_account_id == account_id:
            tx_dict['amount'] = -tx_dict['amount']
        transactions.append(tx_dict)
    
    return jsonify({
        'transactions': transactions,
        'page': page,
        'per_page': per_page,
        'total': paginated_transactions.total
    })
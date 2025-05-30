from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["https://kanban-frontend-delta.vercel.app"], supports_credentials=True)

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_cors import CORS
CORS(app, origins="*", supports_credentials=True)
from datetime import datetime

app = Flask(__name__)
CORS(app, origins=["https://kanban-frontend-delta.vercel.app"], supports_credentials=True)

app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kanban.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

# =================== MODELS ===================

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user')

    tasks = db.relationship('Task', backref='assigned_user', lazy=True)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Board(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    columns = db.relationship('Column', backref='board', lazy=True)

class Column(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    order = db.Column(db.Integer)
    board_id = db.Column(db.Integer, db.ForeignKey('board.id'))

    tasks = db.relationship('Task', backref='column', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    due_date = db.Column(db.Date)
    label = db.Column(db.String(50))
    column_id = db.Column(db.Integer, db.ForeignKey('column.id'))
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))

# =================== AUTH ===================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['POST', 'OPTIONS'])
def register():
    data = request.json
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(name=data['name'], email=data['email'], password_hash=hashed_pw)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and user.check_password(data['password']):
        login_user(user)
        return jsonify({'message': 'Logged in successfully'})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'})

# =================== TASK ASSIGNMENT ===================

@app.route('/admin/assign_task', methods=['POST'])
@login_required
def assign_task():
    if current_user.role != 'secretary':
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.json
    task = Task(
        title=data['title'],
        description=data['description'],
        due_date=datetime.strptime(data['due_date'], '%Y-%m-%d'),
        label=data.get('label'),
        column_id=data['column_id'],
        assigned_to=data['assigned_to'],
        created_by=current_user.id
    )
    db.session.add(task)
    db.session.commit()
    return jsonify({'message': 'Task assigned successfully'})

# =================== RUN APP ===================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)


# =================== BOARD ROUTES ===================

@app.route('/boards', methods=['POST'])
@login_required
def create_board():
    data = request.json
    board = Board(name=data['name'], created_by_id=current_user.id)
    db.session.add(board)
    db.session.commit()
    return jsonify({'message': 'Board created successfully', 'board_id': board.id})


# =================== COLUMN ROUTES ===================

@app.route('/columns', methods=['POST'])
@login_required
def create_column():
    data = request.json
    column = Column(name=data['name'], order=data['order'], board_id=data['board_id'])
    db.session.add(column)
    db.session.commit()
    return jsonify({'message': 'Column created successfully', 'column_id': column.id})


# =================== TASK ROUTES ===================

@app.route('/tasks', methods=['POST'])
@login_required
def create_task():
    data = request.json
    task = Task(
        title=data['title'],
        description=data['description'],
        due_date=datetime.strptime(data['due_date'], '%Y-%m-%d'),
        label=data.get('label'),
        column_id=data['column_id'],
        assigned_to=current_user.id,
        created_by=current_user.id
    )
    db.session.add(task)
    db.session.commit()
    return jsonify({'message': 'Task created successfully', 'task_id': task.id})


# =================== RETRIEVAL ROUTES ===================

@app.route('/user/tasks', methods=['GET'])
@login_required
def get_user_tasks():
    tasks = Task.query.filter_by(assigned_to=current_user.id).all()
    return jsonify([{
        'id': task.id,
        'title': task.title,
        'description': task.description,
        'due_date': task.due_date.isoformat(),
        'label': task.label,
        'column_id': task.column_id
    } for task in tasks])


@app.route('/board/<int:board_id>', methods=['GET'])
@login_required
def get_board(board_id):
    board = Board.query.get_or_404(board_id)
    columns = Column.query.filter_by(board_id=board.id).all()
    response = {
        'board_id': board.id,
        'name': board.name,
        'columns': []
    }
    for col in columns:
        tasks = Task.query.filter_by(column_id=col.id).all()
        response['columns'].append({
            'column_id': col.id,
            'name': col.name,
            'order': col.order,
            'tasks': [{
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'due_date': task.due_date.isoformat(),
                'label': task.label,
                'assigned_to': task.assigned_to
            } for task in tasks]
        })
    return jsonify(response)

from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, join_room, leave_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
import os
import logging
from collections import defaultdict, OrderedDict

# Configurar logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_clave_secreta'

# Configuración de la base de datos
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance/usuarios.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
#socketio = SocketIO(app, logger=True, engineio_logger=True)
socketio = SocketIO(app, async_mode='threading', logger=True, engineio_logger=True)


# Variables globales para mantener el estado
chat_history = defaultdict(list)
raised_hands = defaultdict(OrderedDict)
participants = defaultdict(set)

# Modelos
class Reunion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(6), unique=True, nullable=False)
    admin_email = db.Column(db.String(120), nullable=False)
    admin_password = db.Column(db.String(255), nullable=False)
    activa = db.Column(db.Boolean, default=True)

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reunion_id = db.Column(db.Integer, db.ForeignKey('reunion.id'), nullable=False)
    nombre = db.Column(db.String(50), nullable=False)
    apellido = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    token_extendido = db.Column(db.String(20), unique=True, nullable=False)

# Agregar modelo para SuperUsuario
class SuperUsuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# Funciones auxiliares
def generar_token_reunion():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def generar_token_extendido(token_reunion):
    animales = ['ZORRO', 'TIGRE', 'LEON', 'OSO', 'LOBO', 'PUMA', 'AGUILA', 'CIERVO', 'JABALI', 'BUHO']
    colores = ['GRIS', 'NEGRO', 'BLANCO', 'ROJO', 'AZUL', 'VERDE', 'AMARILLO', 'MARRON', 'NARANJA', 'VIOLETA']
    extension = f"{random.choice(animales)}{random.choice(colores)}"
    return f"{token_reunion}{extension}"

# Rutas
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/crear_reunion', methods=['POST'])
def crear_reunion():
    token = generar_token_reunion()
    admin_email = request.form.get('admin_email')
    admin_password = request.form.get('admin_password')
    if not admin_email or not admin_password:
        return "Email y contraseña del administrador son requeridos", 400
    
    hashed_password = generate_password_hash(admin_password)
    nueva_reunion = Reunion(token=token, admin_email=admin_email, admin_password=hashed_password)
    db.session.add(nueva_reunion)
    db.session.commit()
    
    session['admin_token'] = token
    return redirect(url_for('admin_login', token=token))

@app.route('/unirse_reunion', methods=['GET', 'POST'])
def unirse_reunion():
    if request.method == 'POST':
        token = request.form.get('token')
        nombre = request.form.get('nombre')
        apellido = request.form.get('apellido')
        email = request.form.get('email')
        
        reunion = Reunion.query.filter_by(token=token, activa=True).first()
        if not reunion:
            return "Reunión no encontrada", 404
        
        if not nombre or not apellido or not email:
            return render_template('unirse_reunion.html', error="Todos los campos son obligatorios", token=token)
        
        # Verificar si el usuario ya existe para esta reunión
        usuario_existente = Usuario.query.filter_by(reunion_id=reunion.id, email=email).first()
        if usuario_existente:
            session['user_token'] = usuario_existente.token_extendido
            return redirect(url_for('reunion', token=token))
        
        token_extendido = generar_token_extendido(token)
        nuevo_usuario = Usuario(reunion_id=reunion.id, nombre=nombre, apellido=apellido, email=email, token_extendido=token_extendido)
        db.session.add(nuevo_usuario)
        db.session.commit()
        
        session['user_token'] = token_extendido
        return redirect(url_for('reunion', token=token))
    
    # Si es una solicitud GET, mostrar el formulario
    token = request.args.get('token')
    return render_template('unirse_reunion.html', token=token)

@app.route('/reunion/<token>')
def reunion(token):
    user_token = session.get('user_token')
    if not user_token:
        return redirect(url_for('unirse_reunion', token=token))
    
    usuario = Usuario.query.filter_by(token_extendido=user_token).first()
    if not usuario or usuario.token_extendido[:6] != token:
        return redirect(url_for('unirse_reunion', token=token))
    
    return render_template('reunion.html', 
                           token=token, 
                           nombre_completo=f"{usuario.nombre} {usuario.apellido}",
                           token_extendido=usuario.token_extendido)

@app.route('/reentrar', methods=['GET', 'POST'])
def reentrar():
    if request.method == 'POST':
        token_extendido = request.form.get('token_extendido')
        usuario = Usuario.query.filter_by(token_extendido=token_extendido).first()
        if usuario:
            session['user_token'] = token_extendido
            return redirect(url_for('reunion', token=token_extendido[:6]))
        else:
            return "Token inválido", 400
    
    return render_template('reentrar.html')

@app.route('/admin_login/<token>', methods=['GET', 'POST'])
def admin_login(token):
    if request.method == 'POST':
        password = request.form.get('password')
        reunion = Reunion.query.filter_by(token=token, activa=True).first()
        if reunion and check_password_hash(reunion.admin_password, password):
            session['admin_token'] = token
            return redirect(url_for('admin_console', token=token))
        else:
            return "Contraseña incorrecta", 401
    return render_template('admin_login.html', token=token)

@app.route('/admin_console/<token>')
def admin_console(token):
    if session.get('admin_token') != token:
        return redirect(url_for('admin_login', token=token))
    reunion = Reunion.query.filter_by(token=token, activa=True).first()
    if reunion:
        return render_template('admin_console.html', token=token)
    else:
        return "Reunión no encontrada", 404

@app.route('/lower_hand/<token>', methods=['POST'])
def lower_hand(token):
    if session.get('admin_token') != token:
        return jsonify({"error": "No autorizado"}), 401
    
    data = request.json
    user = data.get('user')
    if user in raised_hands[token]:
        del raised_hands[token][user]
        socketio.emit('update hands', list(raised_hands[token].keys()), room=token)
        return jsonify({"success": True})
    else:
        return jsonify({"error": "Usuario no encontrado"}), 404


@app.route('/lower_all_hands/<token>', methods=['POST'])
def lower_all_hands(token):
    if session.get('admin_token') != token:
        return jsonify({"error": "No autorizado"}), 401
    
    raised_hands[token].clear()
    socketio.emit('update hands', [], room=token)
    return jsonify({"success": True})

# Nuevas rutas para el superusuario
@app.route('/superuser/login', methods=['GET', 'POST'])
def superuser_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        superuser = SuperUsuario.query.filter_by(username=username).first()
        if superuser and check_password_hash(superuser.password, password):
            session['superuser_id'] = superuser.id
            return redirect(url_for('superuser_dashboard'))
        else:
            return "Credenciales inválidas", 401
    return render_template('superuser_login.html')

@app.route('/superuser/dashboard')
def superuser_dashboard():
    if 'superuser_id' not in session:
        return redirect(url_for('superuser_login'))
    reuniones = Reunion.query.all()
    return render_template('superuser_dashboard.html', reuniones=reuniones)

@app.route('/superuser/eliminar_reunion/<int:reunion_id>', methods=['POST'])
def eliminar_reunion(reunion_id):
    if 'superuser_id' not in session:
        return jsonify({"error": "No autorizado"}), 401
    reunion = Reunion.query.get_or_404(reunion_id)
    db.session.delete(reunion)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/superuser/limpiar_base_datos', methods=['POST'])
def limpiar_base_datos():
    if 'superuser_id' not in session:
        return jsonify({"error": "No autorizado"}), 401
    # Eliminar todas las reuniones inactivas y sus usuarios asociados
    reuniones_inactivas = Reunion.query.filter_by(activa=False).all()
    for reunion in reuniones_inactivas:
        Usuario.query.filter_by(reunion_id=reunion.id).delete()
        db.session.delete(reunion)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/superuser/recuperar_contrasena/<int:reunion_id>', methods=['POST'])
def recuperar_contrasena(reunion_id):
    if 'superuser_id' not in session:
        return jsonify({"error": "No autorizado"}), 401
    reunion = Reunion.query.get_or_404(reunion_id)
    nueva_contrasena = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    reunion.admin_password = generate_password_hash(nueva_contrasena)
    db.session.commit()
    return jsonify({"nueva_contrasena": nueva_contrasena})


# Eventos de Socket.IO
@socketio.on('notify turn')
def handle_notify_turn(data):
    token = data['token']
    user = data['user']
    emit('your turn', {'user': user}, room=token)

@socketio.on('connect')
def handle_connect():
    token = request.args.get('token')
    app.logger.info(f'Cliente conectado a la reunión: {token}')
    join_room(token)
    socketio.emit('chat history', chat_history.get(token, []), room=request.sid)
    socketio.emit('update hands', list(raised_hands.get(token, set())), room=token)
    socketio.emit('update participants', list(participants.get(token, set())), room=token)

@socketio.on('join')
def handle_join(data):
    token = data['token']
    username = data['username']
    join_room(token)
    participants[token].add(username)
    socketio.emit('update participants', list(participants[token]), room=token)

@socketio.on('chat message')
def handle_message(data):
    token = data['token']
    message = data['message']
    chat_history[token].append(message)
    socketio.emit('chat message', message, room=token)

@socketio.on('raise hand')
def handle_raise_hand(data):
    token = data['token']
    user = data['user']
    if user not in raised_hands[token]:
        raised_hands[token][user] = len(raised_hands[token])
    socketio.emit('update hands', list(raised_hands[token].keys()), room=token)

@socketio.on('lower hand')
def handle_lower_hand(data):
    token = data['token']
    user = data['user']
    if user in raised_hands[token]:
        del raised_hands[token][user]
        socketio.emit('update hands', list(raised_hands[token].keys()), room=token)

@socketio.on('disconnect')
def handle_disconnect():
    token = request.args.get('token')
    leave_room(token)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Crear un superusuario por defecto si no existe
        if not SuperUsuario.query.filter_by(username='admin').first():
            superuser = SuperUsuario(username='admin', password=generate_password_hash('admin123'))
            db.session.add(superuser)
            db.session.commit()
    socketio.run(app)
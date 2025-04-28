# Importaciones estándar
import re
import random
import secrets
from datetime import datetime, date, timedelta, time
from collections import Counter
from functools import wraps

# Importaciones de Flask y extensiones
from flask import Flask, render_template, request, session, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt, check_password_hash, generate_password_hash
from flask_migrate import Migrate

# Importaciones de modelos
from models import Perfil, Usuario, Profesional, Administrador, Consulta, Emocion, ProfesionalUsuario, FamiliaGratitud
from extensions import db  # Asegúrate de que extensions.py contiene "db = SQLAlchemy()"

# Configuración de la aplicación Flask
app = Flask(__name__, template_folder="templates")
app.secret_key = "sanamed"

# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://usuario:sanamed@localhost/postsanamed'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración del correo electrónico
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'sanamed467@gmail.com'
app.config['MAIL_PASSWORD'] = 'bkca lkuj cahk rnlm'

# Inicialización de extensiones
db.init_app(app)
migrate = Migrate(app, db)
mail = Mail(app)
bcrypt = Bcrypt(app)

# Datos de juegos (podría moverse a una base de datos)

juegos = [
    {
        "id": 1,
        "nombre": "Juego de Meditación",
        "descripcion": "Un juego que te guía a través de una serie de ejercicios de meditación.",
        "dificultad": "Fácil",
        "duracion": "10 minutos"
    },
    {
        "id": 2,
        "nombre": "Cuestionario de Autoevaluación",
        "descripcion": "Evalúa tu estado emocional y mental con este cuestionario.",
        "dificultad": "Moderada",
        "duracion": "5 minutos"
    },
    {
        "id": 3,
        "nombre": "Desafío de Estrategia",
        "descripcion": "Desarrolla habilidades de pensamiento crítico y resolución de problemas.",
        "dificultad": "Difícil",
        "duracion": "15 minutos"
    },
    {
        "id": 4,
        "nombre": "Juego de Respiración Profunda",
        "descripcion": "Aprende técnicas de respiración para reducir la ansiedad.",
        "dificultad": "Fácil",
        "duracion": "5 minutos"
    },
    {
        "id": 5,
        "nombre": "Jardín de Gratitud",
        "descripcion": "Expresa y comparte cosas por las que estás agradecido.",
        "dificultad": "Fácil",
        "duracion": "Sin límite"
    }
]

# ==============================================
# Funciones auxiliares
# ==============================================

def validate_password(password):
    """Valida que la contraseña cumpla con los requisitos."""
    if len(password) < 8:
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[!@#$%^&*()_+=\[{\]};:<>|./?,-]", password):
        return False
    return True

def obtener_id_usuario_actual():
    """Obtiene el ID del usuario actualmente logueado."""
    if 'id_profesional' in session:
        return session['id_profesional']
    elif 'id_administrador' in session:
        return session['id_administrador']
    elif 'id_usuario' in session:
        return session['id_usuario']
    return None

def generar_id_profesional_aleatorio():
    """Genera un ID de profesional aleatorio."""
    profesionales = Profesional.query.with_entities(Profesional.id_profesional).all()
    return random.choice(profesionales)[0] if profesionales else None

def obtener_profesionales_disponibles():
    """Obtiene todos los profesionales disponibles."""
    return Profesional.query.with_entities(
        Profesional.id_profesional,
        Profesional.nombre,
        Profesional.especialidad
    ).all()

def obtener_nombre_profesional(id_profesional):
    """Obtiene el nombre de un profesional por su ID."""
    profesional = Profesional.query.filter_by(id_profesional=id_profesional).first()
    return profesional.nombre if profesional else None

def obtener_emociones_por_fecha(fecha):
    emociones_data = Emocion.query.filter(db.func.date(Emocion.fecha_emocion) == fecha).with_entities(
        Emocion.emocion,
        db.func.extract('hour', Emocion.fecha_emocion).label('hora'),
        db.func.extract('minute', Emocion.fecha_emocion).label('minuto')
    ).all()

    emociones = []
    horas = []
    for row in emociones_data:
        emociones.append(row.emocion)
        hora = str(int(row.hora)).zfill(2)
        minuto = str(int(row.minuto)).zfill(2)
        hora_formateada = f"{hora}:{minuto}"
        horas.append(hora_formateada)

    return emociones, horas
def obtener_consultas_por_usuario(id_usuario):
    consultas = db.session.query(
        Consulta.id_consulta,  # índice 0
        Consulta.id_profesional,  # índice 1
        Consulta.fecha_consulta,  # índice 2
        Consulta.hora_consulta,  # índice 3
        Consulta.motivo  # índice 4
    ).filter_by(id_usuario=id_usuario).all()
    return consultas

def obtener_especialidad_profesional(id_profesional):
    """Obtiene la especialidad de un profesional por su ID."""
    profesional = Profesional.query.filter_by(id_profesional=id_profesional).first()
    return profesional.especialidad if profesional else None

def obtener_conteo_emociones_por_fecha(fecha):
    """Obtiene el conteo de emociones por fecha."""
    emociones = Emocion.query.filter(db.func.date(Emocion.fecha_emocion) == fecha).with_entities(Emocion.emocion).all()
    emociones = [row.emocion for row in emociones]
    return dict(Counter(emociones))

def login_required(f):
    """Decorador para requerir autenticación."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Por favor inicie sesión para acceder a esta página', 'error')
            return redirect(url_for('index'))
        
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(minutes=30):
                session.clear()
                flash('Su sesión ha expirado. Por favor inicie sesión nuevamente', 'error')
                return redirect(url_for('index'))
        
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

# ==============================================
# Rutas de autenticación y gestión de usuarios
# ==============================================

@app.route('/')
def index():
    """Página principal."""
    return render_template('index.html')

@app.route('/login', methods=["GET", 'POST'])
def login():
    """Maneja el inicio de sesión."""
    if request.method == "POST" and "correo" in request.form and "contrasena" in request.form:
        username = request.form['correo']
        password = request.form['contrasena']
        rol = request.form['rol']

        # Buscar usuario según el rol
        if rol == "usuario":
            user_data = Usuario.query.filter_by(correo=username, tipo_perfil=rol).first()
        elif rol == "profesional":
            user_data = Profesional.query.filter_by(correo=username).first()
        elif rol == "admin":
            user_data = Administrador.query.filter_by(correo=username).first()

        # Verificar credenciales
        if user_data and check_password_hash(user_data.contrasena, password):
            session['logged_in'] = True
            session['last_activity'] = datetime.now().isoformat()
            
            # Establecer ID según el rol
            if rol == 'usuario':
                session['id_usuario'] = user_data.id_usuario
                return redirect(url_for('user_home'))
            elif rol == 'profesional':
                session['id_profesional'] = user_data.id_profesional
                return redirect(url_for('profesional_home'))
            elif rol == 'admin':
                session['id_administrador'] = user_data.id_administrador
                return redirect(url_for('admin_home'))
        
        flash("Correo electrónico o contraseña incorrectos.", "error")
    
    return render_template('index.html')

@app.route('/signup', methods=["GET", 'POST'])
def register():
    """Maneja el registro de nuevos usuarios."""
    if request.method == 'POST':
        # Obtener datos del formulario
        nombre = request.form['nombre']
        tipo_documento = request.form['tipo_documento']
        numero_documento = request.form['numero_documento']
        celular = request.form['celular']
        correo = request.form['correo']
        contrasena = request.form['contrasena']

        # Validaciones
        if not validate_password(contrasena):
            flash("La contraseña no cumple con los requisitos.", "error")
            return render_template('register.html')

        if Usuario.query.filter_by(correo=correo).first():
            flash("El correo electrónico ya está registrado.", "error")
            return render_template('register.html')

        if Usuario.query.filter_by(numero_documento=numero_documento).first():
            flash("El número de documento ya está registrado.", "error")
            return render_template('register.html')

        # Crear nuevo usuario
        nuevo_usuario = Usuario(
            nombre=nombre,
            tipo_documento=tipo_documento,
            numero_documento=numero_documento,
            celular=celular,
            correo=correo,
            contrasena=generate_password_hash(contrasena).decode('utf-8')
        )

        try:
            db.session.add(nuevo_usuario)
            db.session.commit()
            flash("Registro exitoso. Inicia sesión con tus credenciales.", "success")
            return redirect(url_for('register'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error al registrar usuario: {e}", "error")
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Cierra la sesión del usuario."""
    session.clear()
    response = redirect(url_for('index'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# ==============================================
# Rutas de recuperación de contraseña
# ==============================================

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Maneja el olvido de contraseña."""
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Buscar usuario en todas las tablas
        user = (Usuario.query.filter_by(correo=email).first() or 
                Profesional.query.filter_by(correo=email).first() or 
                Administrador.query.filter_by(correo=email).first())
        
        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            db.session.commit()
            
            # Enviar correo con token
            msg = Message('Restablecer Contraseña', sender='tu_correo@gmail.com', recipients=[email])
            msg.body = f'Para restablecer tu contraseña, usa el siguiente token: {token}'
            mail.send(msg)
            
            flash("Se ha enviado un token a tu correo electrónico.", "success")
            return redirect(url_for('reset_password'))
        else:
            flash("Correo electrónico no encontrado.", "error")
    
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """Maneja el restablecimiento de contraseña."""
    if request.method == 'POST':
        token = request.form.get('token')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validaciones
        if new_password != confirm_password:
            flash("Las contraseñas no coinciden.", "error")
            return redirect(url_for('reset_password'))
        
        if not validate_password(new_password):
            flash("La contraseña no cumple con los requisitos.", "error")
            return redirect(url_for('reset_password'))
        
        # Buscar usuario con el token
        user = (Usuario.query.filter_by(reset_token=token).first() or 
               Profesional.query.filter_by(reset_token=token).first() or 
               Administrador.query.filter_by(reset_token=token).first())
        
        if user and user.reset_token == token:
            user.contrasena = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.reset_token = None
            db.session.commit()
            flash("Contraseña restablecida con éxito.", "success")
            return redirect(url_for('index'))
        else:
            flash("Token inválido o expirado.", "error")
    
    return render_template('reset_password.html')

# ==============================================
# Rutas de usuarios
# ==============================================

@app.route('/user_home')
@login_required
def user_home():
    """Página de inicio para usuarios."""
    return render_template('user_home.html')


@app.route('/registro_emocion', methods=['POST'])
@login_required
def registro_emocion():
    """Registra una nueva emoción para el usuario."""
    if 'id_usuario' not in session:
        flash("Debes iniciar sesión como usuario.", "error")
        return redirect(url_for('index'))

    emocion = request.form.get('emocion')
    if not emocion:
        flash("No se recibió ninguna emoción", "error")
        return redirect(url_for('user_home'))

    try:
        nueva_emocion = Emocion(
            id_usuario=session['id_usuario'],
            emocion=emocion,
            fecha_emocion=datetime.now()
        )
        db.session.add(nueva_emocion)
        db.session.commit()
        flash("Emoción registrada correctamente", "success")
    except Exception as e:
        db.session.rollback()
        flash("Error al registrar la emoción.", "error")
    
    return redirect(url_for('user_home'))


@app.route('/games')
@login_required
def games():
    return render_template('games.html')

@app.route('/api/juegos', methods=['GET'])
def obtener_juegos():
    return jsonify({"juegos": juegos}), 200

@app.route('/rompecabezas')
def rompecabezas():
    return render_template('rompecabezas.html')


@app.route('/laberinto')
def laberinto():
    return render_template('laberinto.html')


def time_en_rango(hora, inicio, fin):
    return inicio <= hora <= fin


# ==============================================
# juego del jardin 
# ==============================================



@app.route('/agregar_gratitud', methods=['POST'])
@login_required
def agregar_gratitud():
    if 'id_usuario' not in session:
        return jsonify({'error': 'No autenticado'}), 401

    data = request.get_json()
    gratitud = data.get('gratitud', '').strip()
    
    if not gratitud:
        return jsonify({'error': 'El texto de gratitud no puede estar vacío'}), 400

    try:
        nueva_gratitud = FamiliaGratitud(
            gratitud=gratitud,
            id_usuario=session['id_usuario']
        )
        db.session.add(nueva_gratitud)
        db.session.commit()
        return jsonify({
            'message': 'Gratitud agregada',
            'id_gratitud': nueva_gratitud.id_gratitud
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/eliminar_gratitud/<int:id_gratitud>', methods=['DELETE'])
@login_required
def eliminar_gratitud(id_gratitud):
    if 'id_usuario' not in session:
        return jsonify({'error': 'No autenticado'}), 401

    gratitud = FamiliaGratitud.query.filter_by(
        id_gratitud=id_gratitud,
        id_usuario=session['id_usuario']
    ).first()

    if not gratitud:
        return jsonify({'error': 'Gratitud no encontrada'}), 404

    try:
        db.session.delete(gratitud)
        db.session.commit()
        return jsonify({'message': 'Gratitud eliminada'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/cargar_gratitudes', methods=['GET'])
@login_required
def cargar_gratitudes():
    if 'id_usuario' not in session:
        return jsonify({'error': 'No autenticado'}), 401

    gratitudes = FamiliaGratitud.query.filter_by(
        id_usuario=session['id_usuario']
    ).order_by(FamiliaGratitud.fecha.desc()).all()

    return jsonify({
        'gratitudes': [{
            'id': g.id_gratitud,
            'texto': g.gratitud,
            'fecha': g.fecha.isoformat()
        } for g in gratitudes]
    }), 200
    
    
    
@app.route('/agendar_cita', methods=["GET", "POST"])
@login_required
def agendar_cita():
    if 'logged_in' in session and session['logged_in']:
        profesionales = obtener_profesionales_disponibles()
        
        if request.method == "POST":
            fecha = request.form['fecha']
            hora = request.form['hora']
            motivo = request.form['motivo']
            id_usuario = session['id_usuario']
            id_profesional = request.form['profesional']

            # Convertir formatos de fecha y hora
            fecha_consulta = datetime.strptime(fecha, '%Y-%m-%d').date()
            hora_24 = datetime.strptime(hora, '%I:%M %p').time()
            fecha_actual = date.today()

            # Validación 1: Fecha no puede ser anterior a hoy
            if fecha_consulta < fecha_actual:
                flash("No puedes programar una cita en una fecha pasada.", "error")
                return render_template('agendar_cita.html', profesionales=profesionales)

            # Validación 2: Horario laboral (8:00 - 17:00)
            if hora_24 < time(8, 0) or hora_24 > time(17, 0):
                flash("La hora debe estar entre 8:00 AM y 5:00 PM.", "error")
                return render_template('agendar_cita.html', profesionales=profesionales)

            # Validación 3: No permitir que el usuario tenga más de 3 citas el mismo día (puedes ajustar este número)
            citas_usuario_mismo_dia = Consulta.query.filter(
                Consulta.id_usuario == id_usuario,
                Consulta.fecha_consulta == fecha_consulta
            ).count()
            
            if citas_usuario_mismo_dia >= 3:  # Límite de 3 citas por día
                flash("Has alcanzado el límite de citas para este día (máximo 3).", "error")
                return render_template('agendar_cita.html', profesionales=profesionales)

            # Validación 4: Profesional no debe tener cita a la misma hora
            cita_profesional_misma_hora = Consulta.query.filter(
                Consulta.id_profesional == id_profesional,
                Consulta.fecha_consulta == fecha_consulta,
                Consulta.hora_consulta == hora_24
            ).first()
            
            if cita_profesional_misma_hora:
                flash("El profesional ya tiene una cita programada para esta hora.", "error")
                return render_template('agendar_cita.html', profesionales=profesionales)

            # Si pasa todas las validaciones, crear la cita
            nueva_cita = Consulta(
                id_usuario=id_usuario,
                id_profesional=id_profesional,
                fecha_consulta=fecha_consulta,
                hora_consulta=hora_24,
                motivo=motivo,
                estado='Pendiente'
            )

            try:
                db.session.add(nueva_cita)
                db.session.commit()
                flash("Cita agendada exitosamente!", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"Error al agendar cita: {str(e)}", "error")

        return render_template('agendar_cita.html', profesionales=profesionales)
    else:
        return redirect(url_for('index'))
# Nueva ruta para obtener horarios disponibles
@app.route('/obtener_horarios_disponibles', methods=['POST'])
@login_required
def obtener_horarios_disponibles():
    data = request.get_json()
    fecha = data.get('fecha')
    id_profesional = data.get('profesional')
    
    if not fecha or not id_profesional:
        return jsonify({'error': 'Datos incompletos'}), 400
    
    try:
        fecha_consulta = datetime.strptime(fecha, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Formato de fecha inválido'}), 400
    
    # Obtener todas las horas posibles
    horas_posibles = [
        '08:00 AM', '09:00 AM', '10:00 AM', '11:00 AM', '12:00 PM',
        '01:00 PM', '02:00 PM', '03:00 PM', '04:00 PM', '05:00 PM'
    ]
    
    # Obtener citas ya agendadas para ese profesional en esa fecha
    citas_agendadas = Consulta.query.filter(
        Consulta.id_profesional == id_profesional,
        Consulta.fecha_consulta == fecha_consulta
    ).all()
    
    # Convertir horas agendadas al formato de 12 horas
    horas_ocupadas = []
    for cita in citas_agendadas:
        hora_24 = cita.hora_consulta.strftime('%H:%M')
        hora_12 = datetime.strptime(hora_24, '%H:%M').strftime('%I:%M %p')
        horas_ocupadas.append(hora_12)
    
    # Filtrar horas disponibles
    horas_disponibles = [hora for hora in horas_posibles if hora not in horas_ocupadas]
    
    return jsonify({'horas_disponibles': horas_disponibles})
    
@app.route('/calendario')
@login_required
def mostrar_calendario():
    # Aquí debes implementar la lógica para mostrar el calendario
    return render_template('calendario.html')


@app.route('/seleccionar_dia', methods=['GET'])
@login_required
def seleccionar_dia():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('index'))
    
    fecha = request.args.get('fecha')  # Usar args para GET en lugar de form
    
    if not fecha:
        return redirect(url_for('mostrar_calendario'))
    
    # Convertir la fecha de string a objeto date
    try:
        fecha_seleccionada = datetime.strptime(fecha, '%Y-%m-%d').date()
    except ValueError:
        flash("Formato de fecha inválido", "error")
        return redirect(url_for('mostrar_calendario'))
    
    # Obtener emociones del usuario para esa fecha
    emociones = Emocion.query.filter(
        Emocion.id_usuario == session['id_usuario'],
        db.func.date(Emocion.fecha_emocion) == fecha_seleccionada
    ).all()
    
    if not emociones:
        flash(f"No hay emociones registradas para el {fecha_seleccionada.strftime('%d/%m/%Y')}", "info")
        return redirect(url_for('mostrar_calendario'))
    
    return render_template('emociones.html', 
                         emociones=emociones,
                         fecha_seleccionada=fecha_seleccionada)
    
@app.route('/ver_grafica/<fecha>')
@login_required
def ver_grafica(fecha):
    conteo_emociones = obtener_conteo_emociones_por_fecha(fecha)
    
    if not conteo_emociones:
        mensaje = "No hay emociones registradas para este día."
        return render_template('calendario.html', mensaje=mensaje)
    
    # Extraer etiquetas (emociones) y valores (conteo de cada emoción)
    emociones = list(conteo_emociones.keys())
    cantidades = list(conteo_emociones.values())
    
    return render_template(
        'grafica_emociones.html', 
        fecha_seleccionada=fecha, 
        emociones=emociones, 
        cantidades=cantidades
    )

@app.route('/consultas_dia')
@login_required
def consultas_dia():
    if 'logged_in' not in session or not session['logged_in'] or 'id_usuario' not in session:
        flash('Debes iniciar sesión para ver tus citas', 'error')
        return redirect(url_for('index'))

    consultas = db.session.query(
        Consulta.id_consulta,        # índice 0 (para eliminar)
        Consulta.id_profesional,     # índice 1
        Consulta.fecha_consulta,     # índice 2
        Consulta.hora_consulta,      # índice 3
        Consulta.motivo              # índice 4
    ).filter_by(id_usuario=session['id_usuario']).all()

    return render_template(
        'consultas.html',
        consultas=consultas,
        obtener_nombre_profesional=obtener_nombre_profesional,
        obtener_especialidad_profesional=obtener_especialidad_profesional
    )


@app.route('/eliminar_consulta/<int:id>', methods=['POST'])
@login_required
def eliminar_consulta(id):
    if 'logged_in' not in session or not session['logged_in']:
        flash('Debes iniciar sesión para realizar esta acción', 'error')
        return redirect(url_for('index'))

    try:
        # Buscar la consulta a eliminar
        consulta = Consulta.query.get(id)
        
        if consulta:
            # Verificar que el usuario es el dueño de la consulta
            if 'id_usuario' in session and consulta.id_usuario == session['id_usuario']:
                db.session.delete(consulta)
                db.session.commit()
                flash('La cita ha sido eliminada correctamente', 'success')
            else:
                flash('No tienes permiso para eliminar esta cita', 'error')
        else:
            flash('La cita no existe o ya fue eliminada', 'error')
            
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar la cita: {str(e)}', 'error')
    
    return redirect(url_for('consultas_dia'))

# ==============================================
# Rutas de profesionales
# ==============================================

@app.route('/profesional_home')
@login_required
def profesional_home():
    """Página de inicio para profesionales."""
    return render_template('profesional_home.html')

@app.route('/citas_asignadas')
@login_required
def citas_asignadas():
    if 'logged_in' in session and session['logged_in']:
        id_profesional = obtener_id_usuario_actual()

        # Actualiza el estado de las citas en tiempo real
        Consulta.query.filter(
            Consulta.fecha_consulta < datetime.now().date(),
            Consulta.estado == 'Pendiente'
        ).update({'estado': 'Tomada'}, synchronize_session=False)
        db.session.commit()

        # Selecciona las citas asignadas al profesional
        citas = db.session.query(
            Consulta.id_consulta,
            Usuario.nombre.label('nombre_paciente'),
            Usuario.numero_documento,
            Usuario.correo.label('correo_paciente'),
            Consulta.fecha_consulta,
            Consulta.hora_consulta,
            Consulta.motivo,
            Consulta.estado
        ).join(Usuario, Consulta.id_usuario == Usuario.id_usuario) \
         .filter(Consulta.id_profesional == id_profesional) \
         .all()

        return render_template('citas_asignadas.html', citas=citas)
    else:
        return redirect(url_for('index'))


@app.route('/diagnosticos_tratamientos')
@login_required
def diagnosticos_tratamientos():
    if 'logged_in' in session and session['logged_in'] and 'id_profesional' in session:
        id_profesional = session['id_profesional']

        # Consulta corregida para evitar duplicados
        consultas = db.session.query(
            Consulta.id_consulta,
            Usuario.numero_documento,
            Consulta.fecha_consulta,
            Consulta.hora_consulta,
            Consulta.motivo,
            Consulta.diagnostico,
            Consulta.tratamiento
        ).join(Usuario, Consulta.id_usuario == Usuario.id_usuario
        ).filter(
            Consulta.id_profesional == id_profesional,
            Consulta.fecha_consulta <= date.today()  # Solo citas pasadas o hoy
        ).distinct().all()  # Añade .distinct() para eliminar duplicados

        return render_template('diagnosticos_tratamientos.html', consultas=consultas)
    
    return redirect(url_for('index'))
@app.route('/editar_diagnostico_tratamiento/<int:id_consulta>', methods=['POST'])
@login_required
def editar_diagnostico_tratamiento(id_consulta):
    if 'logged_in' in session and session['logged_in']:
        try:
            # Obtener el diagnóstico y tratamiento del formulario
            diagnostico = request.form['diagnostico']
            tratamiento = request.form['tratamiento']

            # Buscar la consulta por su ID
            consulta = Consulta.query.get(id_consulta)
            if consulta:
                # Actualizar el diagnóstico y tratamiento
                consulta.diagnostico = diagnostico
                consulta.tratamiento = tratamiento
                db.session.commit()
                flash('El diagnóstico y tratamiento se han actualizado correctamente.', 'success')
            else:
                flash('Consulta no encontrada.', 'error')
        except Exception as e:
            # En caso de error, deshacer la transacción
            db.session.rollback()
            flash(f"Error al actualizar el diagnóstico y tratamiento: {str(e)}", 'error')
        
        # Redirigir a la página de diagnósticos y tratamientos
        return redirect(url_for('diagnosticos_tratamientos'))
    else:
        # Si no está logueado, redirigir al index
        return redirect(url_for('index'))


# ==============================================
# Rutas de administradores
# ==============================================

@app.route('/admin_home')
@login_required
def admin_home():
    """Página de inicio para administradores."""
    return render_template('admin_home.html')

@app.route('/profesionales')
@login_required
def listar_profesionales():
    profesionales = Profesional.query.with_entities(Profesional.id_profesional, Profesional.nombre, Profesional.especialidad).all()
    return render_template('lista_profesionales.html', profesionales=profesionales)

@app.route('/agregar_profesional', methods=["GET", "POST"])
@login_required
def agregar_profesional():
    if request.method == "POST":
        nombre = request.form['nombre']
        especialidad = request.form['especialidad']
        correo = request.form['correo']
        contrasena = request.form['contrasena']

        # Validación de la contraseña
        if not validate_password(contrasena):
            error = "La contraseña debe tener al menos 8 caracteres, incluyendo letras, números y caracteres especiales."
            return render_template('agregar_profesional.html', error=error)

        # Crear un nuevo profesional
        nuevo_profesional = Profesional(
            nombre=nombre,
            especialidad=especialidad,
            correo=correo,
            contrasena=contrasena
        )

        # Insertar el nuevo profesional en la base de datos
        try:
            db.session.add(nuevo_profesional)
            db.session.commit()
            flash("Profesional agregado correctamente.", "success")
            return redirect(url_for('listar_profesionales'))
        except Exception as e:
            db.session.rollback()
            error = "Error al agregar profesional: " + str(e)
            return render_template('agregar_profesional.html', error=error)

    return render_template('agregar_profesional.html')

@app.route('/eliminar_profesional/<int:id>', methods=["POST"])
@login_required
def eliminar_profesional(id):
    try:
        # Buscar el profesional por su ID
        profesional = Profesional.query.get(id)
        if profesional:
            # Eliminar el profesional de la base de datos
            db.session.delete(profesional)
            db.session.commit()
            flash("Profesional eliminado correctamente", "success")
        else:
            flash("Profesional no encontrado", "error")
    except Exception as e:
        # En caso de error, deshacer la transacción
        db.session.rollback()
        flash(f"Error al eliminar profesional: {str(e)}", "error")
    return redirect(url_for('listar_profesionales'))


@app.route('/usuarios')
@login_required
def listar_usuarios():
    usuarios = Usuario.query.with_entities(Usuario.id_usuario, Usuario.numero_documento, Usuario.correo).all()
    return render_template('lista_usuarios.html', usuarios=usuarios)


@app.route('/eliminar_usuario/<int:id>', methods=["POST"])
@login_required
def eliminar_usuario(id):
    try:
        usuario = Usuario.query.get(id)
        if usuario:
            db.session.delete(usuario)
            db.session.commit()
            flash('Usuario eliminado correctamente', 'success')
        else:
            flash('Usuario no encontrado', 'error')
    except Exception as e:
        db.session.rollback()
        flash("Error al eliminar usuario: " + str(e), 'error')
    return redirect(url_for('listar_usuarios'))

@app.route('/citas_agendadas')
@login_required
def listar_citas():
    citas = db.session.query(
        Usuario.numero_documento,
        Profesional.nombre.label('nombre_profesional'),
        Consulta.fecha_consulta,
        Consulta.hora_consulta,
        Consulta.motivo,
        Consulta.id_consulta
    ).join(Usuario, Consulta.id_usuario == Usuario.id_usuario) \
     .outerjoin(Profesional, Consulta.id_profesional == Profesional.id_profesional) \
     .all()
    return render_template('lista_consultas.html', citas=citas)


@app.route('/eliminar_cita/<int:id>', methods=['POST'])
@login_required
def eliminar_cita(id):
    try:
        cita = Consulta.query.get(id)
        if cita:
            db.session.delete(cita)
            db.session.commit()
            flash('La cita ha sido eliminada correctamente.', 'success')
        else:
            flash('Cita no encontrada.', 'error')
    except Exception as e:
        db.session.rollback()
        flash('Error al eliminar la cita: ' + str(e), 'error')
    return redirect(url_for('listar_citas'))

@app.route('/pacientes')
@login_required
def pacientes():
    if 'logged_in' in session and session['logged_in'] and 'id_profesional' in session:
        id_profesional = session['id_profesional']
        
        # Consulta similar a la de citas_asignadas pero agrupando por paciente
        pacientes = db.session.query(
            Usuario.nombre,
            Usuario.numero_documento,
            Usuario.celular,
            Usuario.correo
        ).join(Consulta, Usuario.id_usuario == Consulta.id_usuario
        ).filter(
            Consulta.id_profesional == id_profesional
        ).group_by(
            Usuario.id_usuario
        ).all()

        print("DEBUG - Pacientes encontrados:", pacientes)  # Para ver en consola
        return render_template('lista_pacientes.html', pacientes=pacientes)
    return redirect(url_for('index'))
# ==============================================
# Rutas de configuración y perfil
# ==============================================

@app.route('/configuracion')
@login_required
def configuracion():
    """Página de configuración del usuario."""
    return render_template('configuracion.html')


@app.route('/editar_perfil', methods=['GET', 'POST'])
@login_required
def editar_perfil():
    # Verificar si el usuario está logueado y la sesión es válida
    if 'logged_in' in session and session['logged_in']:
        # Obtener el id del usuario, profesional o administrador desde la sesión
        id_usuario = session.get('id_usuario')
        id_profesional = session.get('id_profesional')
        id_administrador = session.get('id_administrador')

        # Determinar el tipo de usuario
        if id_usuario:
            usuario = Usuario.query.get(id_usuario)
            tipo_usuario = 'usuario'
        elif id_profesional:
            usuario = Profesional.query.get(id_profesional)
            tipo_usuario = 'profesional'
        elif id_administrador:
            usuario = Administrador.query.get(id_administrador)
            tipo_usuario = 'administrador'
        else:
            flash("Usuario no encontrado.", "error")
            return redirect(url_for('index'))

        # Si el método de la solicitud es POST, significa que el usuario está enviando datos para actualizar su perfil
        if request.method == 'POST':
            nombre = request.form['nombre']
            celular = request.form['celular']
            correo = request.form['correo']

            # Actualizar solo los campos permitidos
            usuario.nombre = nombre
            usuario.celular = celular
            usuario.correo = correo

            # Confirmar cambios en la base de datos
            try:
                db.session.commit()
                flash("Perfil actualizado correctamente.", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"Error al actualizar el perfil: {str(e)}", "error")
            
            # Redirigir a la página de configuración después de guardar cambios
            return redirect(url_for('editar_perfil'))

        # Si el método es GET, obtener los datos actuales del usuario desde la base de datos
        if usuario:
            # Renderizar la plantilla de editar perfil con los datos del usuario autenticado
            return render_template('editar_perfil.html', usuario=usuario, tipo_usuario=tipo_usuario)
        else:
            flash("Usuario no encontrado.", "error")
            return redirect(url_for('index'))
    else:
        # Si no está logueado, redirigir al inicio de sesión
        return redirect(url_for('index'))

# ==============================================
# Otras rutas
# ==============================================

@app.route('/sobre_nosotros')
@login_required
def sobre_nosotros():
    """Página sobre nosotros."""
    return render_template('sobre_nosotros.html')

@app.route('/preguntas_frecuentes')
@login_required
def preguntas_frecuentes():
    """Página de preguntas frecuentes."""
    return render_template('preguntas_frecuentes.html')

# ==============================================
# Configuración adicional
# ==============================================

@app.after_request
def add_header(response):
    """Agrega headers para prevenir cache."""
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
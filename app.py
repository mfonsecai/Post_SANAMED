import re, random, psycopg2,secrets
from datetime import datetime,date, timedelta
from flask import Flask, render_template, request, session, redirect, url_for, jsonify,flash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from collections import Counter
from models import Perfil, Usuario, Profesional, Administrador, Consulta, Emocion, ProfesionalUsuario
from extensions import db
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt, check_password_hash, generate_password_hash

# Configurar la aplicación Flask
app = Flask(__name__, template_folder="templates")
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://usuario:sanamed@localhost/postsanamed'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'sanamed467@gmail.com'
app.config['MAIL_PASSWORD'] = 'bkca lkuj cahk rnlm'

app.secret_key = "sanamed"


mail = Mail(app)
db.init_app(app)
bcrypt = Bcrypt(app)

# Función para validar la contraseña
def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[!@#$%^&*()_+=\[{\]};:<>|./?,-]", password):
        return False
    return True


# Función para obtener el ID del usuario actualmente logueado
def obtener_id_usuario_actual():
    # Verifica si el usuario es un profesional
    if 'id_profesional' in session:
        return session['id_profesional']
    # Verifica si el usuario es un administrador
    elif 'id_administrador' in session:
        return session['id_administrador']
    # Verifica si el usuario es un usuario normal
    elif 'id_usuario' in session:
        return session['id_usuario']
    else:
        return None  # Si no hay ningún ID en la sesión

def generar_id_profesional_aleatorio():
    # Obtener todos los profesionales desde la base de datos
    profesionales = Profesional.query.with_entities(Profesional.id_profesional).all()
    
    # Si hay profesionales, seleccionar uno al azar
    if profesionales:
        id_profesional = random.choice(profesionales)[0]
        return id_profesional
    else:
        return None


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Buscar el correo en las tres tablas
        user = Usuario.query.filter_by(correo=email).first()
        if not user:
            user = Profesional.query.filter_by(correo=email).first()
        if not user:
            user = Administrador.query.filter_by(correo=email).first()
        
        if user:
            token = secrets.token_urlsafe(32)  # Generar un token seguro
            user.reset_token = token  # Almacenar el token en el usuario correspondiente
            db.session.commit()
            
            # Enviar el token por correo electrónico
            msg = Message('Restablecer Contraseña', sender='tu_correo@gmail.com', recipients=[email])
            msg.body = f'Para restablecer tu contraseña, usa el siguiente token: {token}'
            mail.send(msg)
            
            flash("Se ha enviado un token a tu correo electrónico.", "success")
            # Redirigir al usuario a la página de restablecimiento de contraseña
            return redirect(url_for('reset_password'))
        else:
            flash("Correo electrónico no encontrado.", "error")
            return redirect(url_for('forgot_password'))
    
    # Si es GET, renderizar la vista HTML
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        token = request.form.get('token')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validar que las contraseñas coincidan
        if new_password != confirm_password:
            flash("Las contraseñas no coinciden.", "error")
            return redirect(url_for('reset_password'))
        
        # Validar que la contraseña cumpla con los requisitos
        if not validate_password(new_password):
            flash("La contraseña debe tener al menos 8 caracteres, una mayúscula y un carácter especial.", "error")
            return redirect(url_for('reset_password'))
        
        # Buscar el token en las tres tablas
        user = Usuario.query.filter_by(reset_token=token).first()
        if not user:
            user = Profesional.query.filter_by(reset_token=token).first()
        if not user:
            user = Administrador.query.filter_by(reset_token=token).first()
        
        if user:
            # Verificar que el token esté asociado al correo correcto
            if user.reset_token == token:
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                user.contrasena = hashed_password  # Actualizar la contraseña
                user.reset_token = None  # Eliminar el token después de usarlo
                db.session.commit()
                
                flash("Contraseña restablecida con éxito.", "success")
                return redirect(url_for('index')) # Redirigir al login después de restablecer la contraseña
            else:
                
                flash("Token inválido o expirado.", "error")
                return redirect(url_for('reset_password'))
        else:
            flash("Token inválido o expirado.", "error")
            return redirect(url_for('reset_password'))
    
    # Si es GET, renderizar la vista HTML
    return render_template('reset_password.html')

from flask_bcrypt import check_password_hash

@app.route('/login', methods=["GET", 'POST'])
def login():
    if request.method == "POST" and "correo" in request.form and "contrasena" in request.form:
        username = request.form['correo']
        password = request.form['contrasena']
        rol = request.form['rol']

        # Buscar en la tabla de usuarios
        user_data = Usuario.query.filter_by(correo=username, tipo_perfil=rol).first()
        
        # Si no se encuentra en la tabla de usuarios, buscar en la tabla de profesionales
        if not user_data and rol == "profesional":
            user_data = Profesional.query.filter_by(correo=username).first()
        
        # Si aún no se encuentra, buscar en la tabla de administradores
        if not user_data and rol == "admin":
            user_data = Administrador.query.filter_by(correo=username).first()

        # Verificar si se encontró un usuario y si la contraseña es correcta
        if user_data and check_password_hash(user_data.contrasena, password):
            session['logged_in'] = True
            session['id_usuario'] = user_data.id_usuario if rol == 'usuario' else None
            session['id_profesional'] = user_data.id_profesional if rol == 'profesional' else None
            session['id_administrador'] = user_data.id_administrador if rol == 'admin' else None
            session['last_activity'] = datetime.now().isoformat()  # Agregar timestamp

            print("ID del profesional logueado:", session.get('id_profesional'))  # Verifica el ID

            if rol == 'usuario':
                return redirect(url_for('user_home'))
            elif rol == 'profesional':
                return redirect(url_for('profesional_home'))
            elif rol == 'admin':
                return redirect(url_for('admin_home'))
        else:
            return render_template('index.html', error="Credenciales incorrectas")
        
from flask_bcrypt import generate_password_hash

@app.route('/signup', methods=["GET", 'POST'])
def register():
    if request.method == 'POST':
        # Obtener los datos del formulario
        nombre = request.form['nombre']
        tipo_documento = request.form['tipo_documento']
        numero_documento = request.form['numero_documento']
        celular = request.form['celular']
        correo = request.form['correo']
        contrasena = request.form['contrasena']

        # Validar la contraseña
        if not validate_password(contrasena):
            flash("La contraseña debe tener al menos 8 caracteres, una mayúscula y un carácter especial.", "error")
            return render_template('register.html')

        # Verificar si el correo electrónico ya está registrado
        existing_user = Usuario.query.filter_by(correo=correo).first()
        if existing_user:
            flash("El correo electrónico ya está registrado. Por favor, utiliza otro correo electrónico", "error")
            return render_template('register.html')

        # Verificar si el número de documento ya está registrado
        existing_document = Usuario.query.filter_by(numero_documento=numero_documento).first()
        if existing_document:
            flash("El número de documento ya se encuentra registrado", "error")
            return render_template('register.html', error="El número de documento ya se encuentra registrado")

        # Encriptar la contraseña antes de almacenarla
        hashed_password = generate_password_hash(contrasena).decode('utf-8')

        # Crear un nuevo usuario con la contraseña encriptada
        nuevo_usuario = Usuario(
            nombre=nombre,
            tipo_documento=tipo_documento,
            numero_documento=numero_documento,
            celular=celular,
            correo=correo,
            contrasena=hashed_password  # Usar la contraseña encriptada
        )

        # Insertar el nuevo usuario en la base de datos
        try:
            db.session.add(nuevo_usuario)
            db.session.commit()
            flash("Registro exitoso. Inicia sesión con tus credenciales.", "success")
            return redirect(url_for('register'))
        except Exception as e:
            db.session.rollback()
            print(f"Error al registrar usuario: {e}")  # Depuración
            error = "Error al registrar el usuario. Por favor, inténtalo de nuevo."
            flash(error, "error")
            return render_template('register.html', error=error)

    return render_template('register.html')


# Decorator para proteger rutas
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Verificar si el usuario está logueado
        if not session.get('logged_in'):
            flash('Por favor inicie sesión para acceder a esta página', 'error')
            return redirect(url_for('index'))
        
        # Verificar si la sesión ha expirado
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(minutes=30):  # 30 minutos de timeout
                session.clear()
                flash('Su sesión ha expirado. Por favor inicie sesión nuevamente', 'error')
                return redirect(url_for('index'))
        
        # Actualizar timestamp de última actividad
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

# Agregar la ruta de logout
@app.route('/logout')
def logout():
    # Limpiar toda la sesión
    session.clear()
    #flash('Ha cerrado sesión exitosamente', 'success')
    # Agregar headers para prevenir el cache
    response = redirect(url_for('index'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response



@app.route('/registro_emocion', methods=['POST'])
@login_required
def registro_emocion():
    if 'logged_in' in session and session['logged_in']:
        if request.method == 'POST':
            # Obtener la emoción seleccionada por el usuario
            emocion = request.form['emocion']

            # Obtener el ID del usuario actualmente logueado
            print("Contenido de la sesión:", session)  # Agregar esta impresión
            id_usuario = obtener_id_usuario_actual()

            # Obtener la fecha y hora actual
            fecha_emocion = datetime.now()

            # Crear una nueva emoción
            nueva_emocion = Emocion(
                id_usuario=id_usuario,
                fecha_emocion=fecha_emocion,
                emocion=emocion
            )

            # Insertar la emoción en la base de datos
            try:
                db.session.add(nueva_emocion)
                db.session.commit()
                flash("Emoción registrada correctamente.", "success")
            except Exception as e:
                db.session.rollback()
                flash("Error al registrar la emoción.", "error")

            # Redirigir al usuario de nuevo a la página de inicio
            return redirect(url_for('user_home'))
    else:
        return redirect(url_for('index'))
    
@app.route('/user_home')
@login_required
def user_home():
    if 'logged_in' in session and session['logged_in']:
        # Aquí renderizas el home del usuario
        return render_template('user_home.html')
    else:
        return redirect(url_for('index'))


@app.route('/admin_home')
@login_required
def admin_home():
    if 'logged_in' in session and session['logged_in']:
        # Aquí renderizas el home del usuario
        return render_template('admin_home.html')
    else:
        return redirect(url_for('index'))
   
@app.route('/profesional_home')
@login_required
def profesional_home():
    if 'logged_in' in session and session['logged_in']:
        # Aquí renderizas el home del usuario
        return render_template('profesional_home.html')
    else:
        return redirect(url_for('index'))


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


# Función para obtener un ID de profesional aleatorio
# Función para obtener profesionales disponibles
def obtener_profesionales_disponibles():
    profesionales = Profesional.query.with_entities(Profesional.id_profesional, Profesional.nombre, Profesional.especialidad).all()
    return profesionales


@app.route('/agendar_cita', methods=["GET", "POST"])
@login_required
def agendar_cita():
    if 'logged_in' in session and session['logged_in']:
        if request.method == "POST":
            fecha = request.form['fecha']
            hora = request.form['hora']
            motivo = request.form['motivo']
            id_usuario = session['id_usuario']

            # Verificar si ya existe una cita para la fecha y hora seleccionadas
            cita_existente = Consulta.query.filter_by(fecha_consulta=fecha, hora_consulta=hora).first()

            # Validar que la fecha no sea anterior a la fecha actual
            fecha_actual = date.today()
            fecha_seleccionada = datetime.strptime(fecha, '%Y-%m-%d').date()

            if fecha_seleccionada < fecha_actual:
                error = "No puedes programar una cita en una fecha anterior a la fecha actual."
                return render_template('agendar_cita.html', error=error, profesionales=obtener_profesionales_disponibles())

            if cita_existente:
                error = "Ya hay una cita programada para esa fecha y hora."
                return render_template('agendar_cita.html', error=error, profesionales=obtener_profesionales_disponibles())
            else:
                # Convertir la hora AM/PM a un formato de 24 horas
                hora_seleccionada = datetime.strptime(hora, '%I:%M %p').strftime('%H:%M')

                hora_inicio = datetime.strptime('08:00', '%H:%M').time()
                hora_fin = datetime.strptime('17:00', '%H:%M').time()

                if hora_seleccionada < hora_inicio.strftime('%H:%M') or hora_seleccionada > hora_fin.strftime('%H:%M'):
                    error = "La hora seleccionada está fuera del rango permitido (8:00 - 17:00)."
                    return render_template('agendar_cita.html', error=error, profesionales=obtener_profesionales_disponibles())

                id_profesional = request.form['profesional']

                # Crear una nueva cita
                nueva_cita = Consulta(
                    id_usuario=id_usuario,
                    id_profesional=id_profesional,
                    fecha_consulta=fecha,
                    hora_consulta=hora_seleccionada,
                    motivo=motivo
                )

                # Crear una nueva relación en Profesionales_Usuarios
                nueva_relacion = ProfesionalUsuario(
                    id_profesional=id_profesional,
                    id_usuario=id_usuario
                )

                # Insertar la cita y la relación en la base de datos
                try:
                    db.session.add(nueva_cita)
                    db.session.add(nueva_relacion)
                    db.session.commit()
                    success_message = "Su cita se ha registrado con éxito."
                    return render_template('agendar_cita.html', success=success_message, profesionales=obtener_profesionales_disponibles())
                except Exception as e:
                    db.session.rollback()
                    error = "Error al programar la cita: " + str(e)
                    return render_template('agendar_cita.html', error=error, profesionales=obtener_profesionales_disponibles())

    else:
        return redirect(url_for('index'))

    return render_template('agendar_cita.html', profesionales=obtener_profesionales_disponibles())

@app.route('/calendario')
@login_required
def mostrar_calendario():
    # Aquí debes implementar la lógica para mostrar el calendario
    return render_template('calendario.html')


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

def obtener_especialidad_profesional(id_profesional):
    profesional = Profesional.query.filter_by(id_profesional=id_profesional).first()
    if profesional:
        return profesional.especialidad
    return None



def obtener_consultas_por_usuario(id_usuario):
    consultas = Consulta.query.filter_by(id_usuario=id_usuario).with_entities(
        Consulta.id_usuario,
        Consulta.id_profesional,
        Consulta.fecha_consulta,
        Consulta.hora_consulta,
        Consulta.motivo
    ).all()
    return consultas

def obtener_nombre_profesional(id_profesional):
    profesional = Profesional.query.filter_by(id_profesional=id_profesional).first()
    if profesional:
        return profesional.nombre
    return None

def obtener_conteo_emociones_por_fecha(fecha):
    emociones = Emocion.query.filter(db.func.date(Emocion.fecha_emocion) == fecha).with_entities(Emocion.emocion).all()
    emociones = [row.emocion for row in emociones]
    conteo_emociones = dict(Counter(emociones))
    return conteo_emociones

@app.route('/seleccionar_dia', methods=["GET", 'POST'])
@login_required
def seleccionar_dia():
    if request.method == 'POST':
        fecha_seleccionada = request.form['fecha']
        emociones, horas = obtener_emociones_por_fecha(fecha_seleccionada)
        if not emociones:

            mensaje = "No hay emociones registradas para este día."
            return render_template('calendario.html', mensaje=mensaje)
        return render_template('emociones.html', fecha_seleccionada=fecha_seleccionada, emociones_horas=zip(emociones, horas))
    return redirect(url_for('mostrar_calendario'))  # Redirige a otra ruta

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


@app.route('/consultas_dia', methods=["GET", 'POST'])
@login_required
def consultas_dia():
    
    
    # Obtener el ID del usuario que está logueado (suponiendo que tienes una función para obtener el usuario actual)
    id_usuario = obtener_id_usuario_actual()

    # Obtener todas las consultas programadas para este usuario
    consultas = obtener_consultas_por_usuario(id_usuario)

    if not consultas:
        mensaje = "No tienes citas programadas."
        return render_template('consultas.html', mensaje=mensaje)

    return render_template('consultas.html', fecha_seleccionada="Todas tus citas", consultas=consultas, obtener_nombre_profesional=obtener_nombre_profesional, obtener_especialidad_profesional=obtener_especialidad_profesional)

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

@app.route('/eliminar_consulta/<int:id>', methods=['POST'])
@login_required
def eliminar_consulta(id):
    try:
        consultas = Consulta.query.filter_by(id_usuario=id).all()
        for consulta in consultas:
            db.session.delete(consulta)
        db.session.commit()
        session['aviso_mostrado'] = True
        flash('Consulta eliminada correctamente.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error al eliminar la consulta: ' + str(e), 'error')
    return redirect(url_for('consultas_dia'))

@app.route('/pacientes')
@login_required
def pacientes():
    if 'logged_in' in session and session['logged_in']:
        id_profesional = obtener_id_usuario_actual()
        print("ID del profesional logueado:", id_profesional)  # Verifica el ID

        pacientes = db.session.query(
            Usuario.nombre,
            Usuario.numero_documento,
            Usuario.celular,
            Usuario.correo
        ).join(ProfesionalUsuario, Usuario.id_usuario == ProfesionalUsuario.id_usuario) \
         .filter(ProfesionalUsuario.id_profesional == id_profesional) \
         .all()

        print("Pacientes asociados al profesional:", pacientes)  # Verifica los datos

        return render_template('lista_pacientes.html', pacientes=pacientes)
    else:
        return redirect(url_for('index'))

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


@app.route('/diagnosticos_tratamientos', methods=['GET', 'POST'])
@login_required
def diagnosticos_tratamientos():
    if 'logged_in' in session and session['logged_in']:
        # Verifica el contenido de la sesión
        print("Contenido de la sesión:", session)  # Depuración

        # Obtener el ID del profesional logueado
        id_profesional = obtener_id_usuario_actual()
        print("ID del profesional logueado:", id_profesional)  # Depuración

        if id_profesional is None:
            flash("No se pudo obtener el ID del profesional.", "error")
            return redirect(url_for('index'))

        # Obtener las consultas asignadas al profesional
        consultas = db.session.query(
            Consulta.id_consulta,
            Usuario.numero_documento,
            Consulta.fecha_consulta,
            Consulta.hora_consulta,
            Consulta.motivo,
            Consulta.diagnostico,
            Consulta.tratamiento
        ).join(Usuario, Consulta.id_usuario == Usuario.id_usuario) \
         .join(ProfesionalUsuario, Consulta.id_profesional == ProfesionalUsuario.id_profesional) \
         .filter(Consulta.fecha_consulta < datetime.now(), ProfesionalUsuario.id_profesional == id_profesional) \
         .all()

        print("Consultas encontradas:", consultas)  # Depuración

        # Si no hay consultas, mostrar un mensaje
        if not consultas:
            flash("No hay consultas asignadas.", "info")

        # Renderizar la plantilla con las consultas
        return render_template('diagnosticos_tratamientos.html', consultas=consultas)
    else:
        # Si no está logueado, redirigir al index
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


@app.route('/configuracion')
@login_required

def configuracion():
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

@app.route('/sobre_nosotros')
@login_required
def sobre_nosotros():
    return render_template('sobre_nosotros.html')


@app.route('/preguntas_frecuentes')
@login_required
def preguntas_frecuentes():
    return render_template('preguntas_frecuentes.html')

@app.after_request
def add_header(response):
    # Prevenir cache en todas las respuestas
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    app.secret_key = "sanamed"
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)






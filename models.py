from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from extensions import db


class Perfil(db.Model):
    __tablename__ = 'perfiles'
    id_perfil = db.Column(db.Integer, primary_key=True)
    tipo_perfil = db.Column(db.String(20), nullable=False)

class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id_usuario = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    tipo_documento = db.Column(db.String(20), nullable=False)
    numero_documento = db.Column(db.String(20), unique=True, nullable=False)
    celular = db.Column(db.String(20), nullable=False)
    correo = db.Column(db.String(50), unique=True, nullable=False)
    contrasena = db.Column(db.String(100), nullable=False)
    tipo_perfil = db.Column(db.String(20), nullable=False, default='usuario')

class Profesional(db.Model):
    __tablename__ = 'profesionales'
    id_profesional = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    especialidad = db.Column(db.String(50), nullable=False)
    correo = db.Column(db.String(50), unique=True, nullable=False)
    contrasena = db.Column(db.String(100), nullable=False)

class Administrador(db.Model):
    __tablename__ = 'administradores'
    id_administrador = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    correo = db.Column(db.String(50), unique=True, nullable=False)
    contrasena = db.Column(db.String(100), nullable=False)

class Consulta(db.Model):
    __tablename__ = 'consultas'
    id_consulta = db.Column(db.Integer, primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'), nullable=False)
    id_profesional = db.Column(db.Integer, db.ForeignKey('profesionales.id_profesional'))
    fecha_consulta = db.Column(db.Date, nullable=False)
    hora_consulta = db.Column(db.Time, nullable=False)
    motivo = db.Column(db.Text, nullable=False)
    diagnostico = db.Column(db.Text)
    tratamiento = db.Column(db.Text)
    estado = db.Column(db.String(20), default='Pendiente')

class Emocion(db.Model):
    __tablename__ = 'emociones'
    id_emocion = db.Column(db.Integer, primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'), nullable=False)
    fecha_emocion = db.Column(db.DateTime, default=datetime.utcnow)
    emocion = db.Column(db.String(20), nullable=False)

class ProfesionalUsuario(db.Model):
    __tablename__ = 'profesionales_usuarios'
    id_profesional = db.Column(db.Integer, db.ForeignKey('profesionales.id_profesional'), primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'), primary_key=True)
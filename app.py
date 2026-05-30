import os
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from datetime import datetime, date, timedelta
from dotenv import load_dotenv
from flask import (
    Flask, render_template, session, redirect,
    url_for, request, flash, abort, Response
)

load_dotenv()

from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# ----------------------------
# CONFIGURACIÓN BASE DE DATOS
# ----------------------------

db_url = os.getenv("DATABASE_URL", "sqlite:///projects.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
}

db = SQLAlchemy(app)


# ----------------------------
# MODELOS
# ----------------------------

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(150))
    tech = db.Column(db.String(300))
    duration = db.Column(db.String(100))
    github = db.Column(db.String(300))
    problem = db.Column(db.Text)
    process = db.Column(db.Text)
    results = db.Column(db.Text)
    images = db.Column(db.Text)  # URLs separadas por comas, máx 5
    dashboard_url = db.Column(db.String(300)) 
    dashboard_url_2 = db.Column(db.String(300))
    
    def __repr__(self):
        return f"<Project {self.title}>"


class PageVisit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    page = db.Column(db.String(200), nullable=False)
    ip_hash = db.Column(db.String(64), nullable=False)
    language = db.Column(db.String(50))
    device = db.Column(db.String(20))
    visited_at = db.Column(db.DateTime, default=datetime.utcnow)
    visit_date = db.Column(db.Date, default=date.today)

    def __repr__(self):
        return f"<PageVisit {self.page} {self.visit_date}>"


# ----------------------------
# DECORADORES
# ----------------------------

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function


def panel_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("panel"):
            token = request.view_args.get("token", "")
            return redirect(url_for("panel_login", token=token))
        return f(*args, **kwargs)
    return decorated_function


# ----------------------------
# TRACKING DE VISITAS
# ----------------------------

def _hash_ip(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()


def _detect_device(ua: str) -> str:
    ua = ua.lower()
    if any(k in ua for k in ("mobile", "android", "iphone", "ipad")):
        return "mobile"
    return "desktop"


def track_visit(page: str):
    try:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
        ip = ip.split(",")[0].strip()
        ip_hash = _hash_ip(ip)
        today = date.today()

        already = PageVisit.query.filter_by(
            ip_hash=ip_hash,
            page=page,
            visit_date=today
        ).first()

        if not already:
            ua = request.headers.get("User-Agent", "")
            lang = request.headers.get("Accept-Language", "")[:50]
            device = _detect_device(ua)
            db.session.add(PageVisit(
                page=page,
                ip_hash=ip_hash,
                language=lang,
                device=device,
                visit_date=today,
            ))
            db.session.commit()
    except Exception:
        db.session.rollback()

def collect_images_from_form() -> str:
    """
    Recoge image_1 … image_5 del formulario POST,
    descarta los vacíos y devuelve un string separado por comas.
    Ejemplo resultado: "https://raw.github.../g1.png,https://..."
    """
    urls = []
    for i in range(1, 6):
        url = request.form.get(f"image_{i}", "").strip()
        if url:
            urls.append(url)
    return ",".join(urls)


# ----------------------------
# ANTI-SPAM
# ----------------------------

# Rate limiting: máximo de mensajes por IP en una ventana de tiempo
RATE_LIMIT_MAX = 3          # máximo 3 mensajes
RATE_LIMIT_WINDOW = 60      # en los últimos 60 minutos

def _get_client_ip() -> str:
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    return ip.split(",")[0].strip()


def _check_rate_limit(ip: str) -> bool:
    """
    Devuelve True si la IP está dentro del límite permitido.
    Devuelve False si ha superado el máximo de mensajes.
    Usamos la tabla ContactMessage para contar mensajes recientes.
    """
    ip_hash = _hash_ip(ip)
    window_start = datetime.utcnow() - timedelta(minutes=RATE_LIMIT_WINDOW)

    # Contamos mensajes cuyo ip_hash coincida en la ventana de tiempo
    # Como ContactMessage no almacena ip_hash, usamos una columna nueva
    # que añadiremos al modelo a continuación
    recent_count = ContactMessage.query.filter(
        ContactMessage.sender_ip == ip_hash,
        ContactMessage.sent_at >= window_start
    ).count()

    return recent_count < RATE_LIMIT_MAX


def _is_honeypot_filled() -> bool:
    """
    El campo honeypot se llama 'website' en el formulario.
    Los humanos no lo ven (está oculto con CSS).
    Los bots lo rellenan automáticamente.
    Devuelve True si el bot ha caído en la trampa.
    """
    return bool(request.form.get("website", "").strip())


# Modelo actualizado con sender_ip para rate limiting
# (necesita migración si ya existe la tabla)
class ContactMessage(db.Model):
    __tablename__ = "contact_message"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(300))
    message = db.Column(db.Text, nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    sender_ip = db.Column(db.String(64))   # hash de la IP para rate limiting

    def __repr__(self):
        return f"<ContactMessage {self.name} {self.sent_at}>"


# ----------------------------
# ENVÍO DE EMAIL
# ----------------------------

def _smtp_connect():
    smtp_user = os.getenv("GMAIL_USER", "").strip()
    smtp_pass = os.getenv("GMAIL_APP_PASSWORD", "").strip()

    if not smtp_user or not smtp_pass:
        raise ValueError("GMAIL_USER o GMAIL_APP_PASSWORD no están configurados")

    server = smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10)
    server.login(smtp_user, smtp_pass)
    return server, smtp_user


def send_notification_email(name: str, sender_email: str, subject: str, message: str):
    smtp_user = os.getenv("GMAIL_USER", "").strip()
    recipient = os.getenv("CONTACT_EMAIL", smtp_user)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[Portfolio] {subject or 'Nuevo mensaje de contacto'}"
    msg["From"] = smtp_user
    msg["To"] = recipient
    msg["Reply-To"] = sender_email

    body_html = f"""
    <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:2rem">
        <h2 style="color:#2563eb;margin-bottom:1.5rem">
            📬 Nuevo mensaje desde tu portfolio
        </h2>
        <table style="width:100%;border-collapse:collapse;margin-bottom:1.5rem">
            <tr>
                <td style="padding:0.5rem 0;color:#6b7280;font-size:0.85rem;width:90px">Nombre</td>
                <td style="padding:0.5rem 0;font-weight:600">{name}</td>
            </tr>
            <tr>
                <td style="padding:0.5rem 0;color:#6b7280;font-size:0.85rem">Email</td>
                <td style="padding:0.5rem 0">
                    <a href="mailto:{sender_email}" style="color:#2563eb">{sender_email}</a>
                </td>
            </tr>
            <tr>
                <td style="padding:0.5rem 0;color:#6b7280;font-size:0.85rem">Asunto</td>
                <td style="padding:0.5rem 0">{subject or '—'}</td>
            </tr>
        </table>
        <hr style="border:none;border-top:1px solid #e5e7eb;margin-bottom:1.5rem">
        <p style="white-space:pre-wrap;line-height:1.6">{message}</p>
        <hr style="border:none;border-top:1px solid #e5e7eb;margin:1.5rem 0">
        <a href="mailto:{sender_email}?subject=Re: {subject or 'Tu mensaje'}"
           style="display:inline-block;background:#2563eb;color:white;
                  padding:0.6rem 1.2rem;border-radius:6px;text-decoration:none;
                  font-size:0.9rem">
            Responder →
        </a>
    </div>
    """
    msg.attach(MIMEText(body_html, "html"))
    server, smtp_user = _smtp_connect()
    with server:
        server.sendmail(smtp_user, recipient, msg.as_string())


def send_confirmation_email(name: str, recipient_email: str, subject: str):
    smtp_user = os.getenv("GMAIL_USER", "").strip()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "He recibido tu mensaje · Lucas Balaguer"
    msg["From"] = f"Lucas Balaguer <{smtp_user}>"
    msg["To"] = recipient_email

    body_html = f"""
    <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:2rem">
        <h2 style="color:#1f2933;margin-bottom:0.5rem">¡Gracias, {name}!</h2>
        <p style="color:#6b7280;margin-bottom:1.5rem">
            He recibido tu mensaje sobre <strong>"{subject or 'tu consulta'}"</strong>
            y te responderé lo antes posible.
        </p>
        <hr style="border:none;border-top:1px solid #e5e7eb;margin-bottom:1.5rem">
        <p style="font-size:0.85rem;color:#9ca3af">
            Este es un mensaje automático. No respondas directamente a este correo.<br>
            Si necesitas contactarme urgentemente, escríbeme a
            <a href="mailto:lucas.balaguer91@gmail.com" style="color:#2563eb">
                lucas.balaguer91@gmail.com
            </a>
        </p>
    </div>
    """
    msg.attach(MIMEText(body_html, "html"))
    server, smtp_user = _smtp_connect()
    with server:
        server.sendmail(smtp_user, recipient_email, msg.as_string())


# ----------------------------
# RUTAS PÚBLICAS
# ----------------------------

@app.route("/")
def home():
    track_visit("home")
    recent_projects = Project.query.order_by(Project.id.desc()).limit(3).all()
    return render_template("index.html", recent_projects=recent_projects)


@app.route("/proyectos")
def projects():
    track_visit("proyectos")
    all_projects = Project.query.all()
    return render_template("proyectos.html", projects=all_projects)


@app.route("/projects/<slug>")
def project_detail(slug):
    project = Project.query.filter_by(slug=slug).first_or_404()
    track_visit(f"project:{slug}")

    all_projects = Project.query.all()
    ids = [p.id for p in all_projects]
    idx = ids.index(project.id)
    prev_project = all_projects[idx - 1] if idx > 0 else None
    next_project = all_projects[idx + 1] if idx < len(all_projects) - 1 else None

    return render_template(
        "project_detail.html",
        project=project,
        prev_project=prev_project,
        next_project=next_project
    )


@app.route("/skills")
def skills():
    track_visit("skills")
    return render_template("skills.html")


@app.route("/contacto", methods=["GET", "POST"])
def contacto():
    track_visit("contacto")
    success = False
    error = None

    if request.method == "POST":
        # 1. HONEYPOT — si el campo oculto viene relleno, es un bot
        if _is_honeypot_filled():
            # Respondemos como si fuera éxito para no alertar al bot
            app.logger.warning("[SPAM] Honeypot activado")
            return render_template("contact.html", success=True, error=None)

        ip = _get_client_ip()

        # 2. RATE LIMITING — máximo RATE_LIMIT_MAX mensajes por hora
        if not _check_rate_limit(ip):
            error = f"Has enviado demasiados mensajes. Por favor espera un momento antes de volver a intentarlo."
            return render_template("contact.html", success=False, error=error)

        name    = request.form.get("name", "").strip()
        email   = request.form.get("email", "").strip()
        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()

        if not all([name, email, message]):
            error = "Por favor rellena todos los campos obligatorios."
        elif "@" not in email or "." not in email.split("@")[-1]:
            error = "El email no tiene un formato válido."
        else:
            db.session.add(ContactMessage(
                name=name,
                email=email,
                subject=subject,
                message=message,
                sender_ip=_hash_ip(ip),
            ))
            db.session.commit()

            try:
                send_notification_email(name, email, subject, message)
            except Exception as e:
                app.logger.error(f"[EMAIL NOTIFICATION ERROR] {e}")

            try:
                send_confirmation_email(name, email, subject)
            except Exception as e:
                app.logger.error(f"[EMAIL CONFIRMATION ERROR] {e}")

            success = True

    return render_template("contact.html", success=success, error=error)

@app.route("/sobre-mi")
def sobre_mi():
    track_visit("sobre-mi")
    return render_template("sobre-mi.html")


# ----------------------------
# RUTAS ADMIN
# ----------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form.get("password") == os.getenv("ADMIN_PASSWORD"):
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    return render_template("admin_dashboard.html", projects=Project.query.all())


@app.route("/admin/project/new", methods=["GET", "POST"])
@admin_required
def admin_create_project():
    if request.method == "POST":
        db.session.add(Project(
            title=request.form.get("title"),
            description=request.form.get("description"),
            slug=request.form.get("slug"),
            role=request.form.get("role"),
            tech=request.form.get("tech"),
            duration=request.form.get("duration"),
            github=request.form.get("github"),
            problem=request.form.get("problem"),
            process=request.form.get("process"),
            results=request.form.get("results"),
        ))
        db.session.commit()
        flash("Proyecto creado correctamente")
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_project_form.html", action="Crear")


@app.route("/admin/project/<int:id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_project(id):
    project = Project.query.get_or_404(id)
    if request.method == "POST":
        project.title = request.form.get("title")
        project.description = request.form.get("description")
        project.slug = request.form.get("slug")
        project.role = request.form.get("role")
        project.tech = request.form.get("tech")
        project.duration = request.form.get("duration")
        project.github = request.form.get("github")
        project.problem = request.form.get("problem")
        project.process = request.form.get("process")
        project.results = request.form.get("results")
        db.session.commit()
        flash("Proyecto actualizado correctamente")
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_project_form.html", project=project, action="Editar")


@app.route("/admin/project/<int:id>/delete", methods=["POST"])
@admin_required
def admin_delete_project(id):
    project = Project.query.get_or_404(id)
    db.session.delete(project)
    db.session.commit()
    flash("Proyecto eliminado correctamente")
    return redirect(url_for("admin_dashboard"))


# ============================================================
# PANEL PRIVADO
# ============================================================

PANEL_TOKEN = os.getenv("PANEL_TOKEN")
PANEL_PASSWORD = os.getenv("PANEL_PASSWORD")


def _validate_token(token: str) -> bool:
    return bool(token and token == PANEL_TOKEN)


@app.route("/panel/<token>/login", methods=["GET", "POST"])
def panel_login(token):
    if not _validate_token(token):
        abort(404)
    if request.method == "POST":
        if request.form.get("password") == PANEL_PASSWORD:
            session["panel"] = True
            session["panel_token"] = token
            return redirect(url_for("panel_dashboard", token=token))
        flash("Contraseña incorrecta")
    return render_template("panel_login.html", token=token)


@app.route("/panel/<token>/logout")
def panel_logout(token):
    session.pop("panel", None)
    session.pop("panel_token", None)
    return redirect(url_for("panel_login", token=token))


@app.route("/panel/<token>/")
@panel_required
def panel_dashboard(token):
    if not _validate_token(token):
        abort(404)

    from sqlalchemy import func

    today = date.today()
    last_30 = today - timedelta(days=30)

    total_unique = db.session.query(PageVisit.ip_hash).distinct().count()
    unique_30d = db.session.query(PageVisit.ip_hash).filter(
        PageVisit.visit_date >= last_30
    ).distinct().count()

    visits_by_page = db.session.query(
        PageVisit.page,
        func.count(PageVisit.ip_hash.distinct()).label("unique_visitors")
    ).filter(PageVisit.visit_date >= last_30).group_by(PageVisit.page).order_by(
        func.count(PageVisit.ip_hash.distinct()).desc()
    ).all()

    top_languages = db.session.query(
        PageVisit.language,
        func.count().label("total")
    ).filter(PageVisit.visit_date >= last_30).group_by(
        PageVisit.language
    ).order_by(func.count().desc()).limit(5).all()

    devices = db.session.query(
        PageVisit.device,
        func.count().label("total")
    ).filter(PageVisit.visit_date >= last_30).group_by(PageVisit.device).all()

    daily_visits = db.session.query(
        PageVisit.visit_date,
        func.count(PageVisit.ip_hash.distinct()).label("unique_visitors")
    ).filter(
        PageVisit.visit_date >= today - timedelta(days=13)
    ).group_by(PageVisit.visit_date).order_by(PageVisit.visit_date).all()

    unread_count = ContactMessage.query.filter_by(read=False).count()
    recent_messages = ContactMessage.query.order_by(
        ContactMessage.sent_at.desc()
    ).limit(5).all()

    return render_template(
        "panel_dashboard.html",
        token=token,
        total_unique=total_unique,
        unique_30d=unique_30d,
        visits_by_page=visits_by_page,
        top_languages=top_languages,
        devices=devices,
        daily_visits=daily_visits,
        projects=Project.query.all(),
        unread_count=unread_count,
        recent_messages=recent_messages,
    )


@app.route("/panel/<token>/messages")
@panel_required
def panel_messages(token):
    if not _validate_token(token):
        abort(404)
    messages = ContactMessage.query.order_by(ContactMessage.sent_at.desc()).all()
    ContactMessage.query.filter_by(read=False).update({"read": True})
    db.session.commit()
    return render_template("panel_messages.html", token=token, messages=messages)


@app.route("/panel/<token>/messages/<int:id>/delete", methods=["POST"])
@panel_required
def panel_delete_message(token, id):
    if not _validate_token(token):
        abort(404)
    msg = ContactMessage.query.get_or_404(id)
    db.session.delete(msg)
    db.session.commit()
    flash("Mensaje eliminado")
    return redirect(url_for("panel_messages", token=token))


@app.route("/panel/<token>/project/new", methods=["GET", "POST"])
@panel_required
def panel_create_project(token):
    if not _validate_token(token):
        abort(404)
    if request.method == "POST":
        db.session.add(Project(
            title=request.form.get("title"),
            description=request.form.get("description"),
            slug=request.form.get("slug"),
            role=request.form.get("role"),
            tech=request.form.get("tech"),
            duration=request.form.get("duration"),
            github=request.form.get("github"),
            problem=request.form.get("problem"),
            process=request.form.get("process"),
            results=request.form.get("results"),
            images=collect_images_from_form(),
            dashboard_url=request.form.get("dashboard_url"),
            dashboard_url_2=request.form.get("dashboard_url_2"),
        ))
        db.session.commit()
        flash("Proyecto creado correctamente")
        return redirect(url_for("panel_dashboard", token=token))
    return render_template("panel_project_form.html", token=token, action="Crear", project=None)


@app.route("/panel/<token>/project/<int:id>/edit", methods=["GET", "POST"])
@panel_required
def panel_edit_project(token, id):
    if not _validate_token(token):
        abort(404)
    project = Project.query.get_or_404(id)
    if request.method == "POST":
        project.title = request.form.get("title")
        project.description = request.form.get("description")
        project.slug = request.form.get("slug")
        project.role = request.form.get("role")
        project.tech = request.form.get("tech")
        project.duration = request.form.get("duration")
        project.github = request.form.get("github")
        project.problem = request.form.get("problem")
        project.process = request.form.get("process")
        project.results = request.form.get("results")
        project.images = collect_images_from_form()
        project.dashboard_url = request.form.get("dashboard_url")
        project.dashboard_url_2 = request.form.get("dashboard_url_2")
        db.session.commit()
        flash("Proyecto actualizado correctamente")
        return redirect(url_for("panel_dashboard", token=token))
    return render_template("panel_project_form.html", token=token, action="Editar", project=project)


@app.route("/panel/<token>/project/<int:id>/delete", methods=["POST"])
@panel_required
def panel_delete_project(token, id):
    if not _validate_token(token):
        abort(404)
    project = Project.query.get_or_404(id)
    db.session.delete(project)
    db.session.commit()
    flash("Proyecto eliminado")
    return redirect(url_for("panel_dashboard", token=token))

@app.route("/sitemap.xml")
def sitemap():
    """
    Genera el sitemap.xml dinámicamente.
    Las páginas fijas están hardcodeadas.
    Los proyectos se obtienen de la BD para que se actualicen solos.
    """
    # URL base del sitio — cámbiala si cambias de dominio
    base_url = "https://www.lucascavalcante.es"

    # Páginas fijas con su prioridad y frecuencia de cambio
    static_pages = [
        {"url": "/",          "priority": "1.0", "changefreq": "weekly"},
        {"url": "/sobre-mi",  "priority": "0.9", "changefreq": "monthly"},
        {"url": "/proyectos", "priority": "0.9", "changefreq": "weekly"},
        {"url": "/skills",    "priority": "0.7", "changefreq": "monthly"},
        {"url": "/contacto",  "priority": "0.6", "changefreq": "yearly"},
    ]

    # Páginas dinámicas — proyectos
    projects = Project.query.all()

    # Construimos el XML manualmente (no necesita librerías externas)
    xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    xml_lines.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')

    for page in static_pages:
        xml_lines.append("  <url>")
        xml_lines.append(f"    <loc>{base_url}{page['url']}</loc>")
        xml_lines.append(f"    <changefreq>{page['changefreq']}</changefreq>")
        xml_lines.append(f"    <priority>{page['priority']}</priority>")
        xml_lines.append("  </url>")

    for project in projects:
        xml_lines.append("  <url>")
        xml_lines.append(f"    <loc>{base_url}/projects/{project.slug}</loc>")
        xml_lines.append("    <changefreq>monthly</changefreq>")
        xml_lines.append("    <priority>0.8</priority>")
        xml_lines.append("  </url>")

    xml_lines.append("</urlset>")

    xml_content = "\n".join(xml_lines)

    # Devolvemos el XML con el content-type correcto para que
    # Google lo reconozca como sitemap
    return Response(xml_content, mimetype="application/xml")


@app.route("/robots.txt")
def robots():
    """
    Sirve el robots.txt.
    Allow: / → permite indexar todo el sitio.
    Disallow: /panel/ → bloquea el panel privado.
    Disallow: /admin/ → bloquea el admin legacy.
    Sitemap → le dice a Google dónde está el sitemap.
    """
    content = """User-agent: *
Allow: /
Disallow: /panel/
Disallow: /admin/

Sitemap: https://www.lucascavalcante.es/sitemap.xml
"""
    return Response(content, mimetype="text/plain")


# ----------------------------
# PÁGINAS DE ERROR
# ----------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500


# ----------------------------
# CREAR TABLAS
# ----------------------------

with app.app_context():
    db.create_all()


# ----------------------------
# RUN
# ----------------------------

if __name__ == "__main__":
    app.run(debug=True)

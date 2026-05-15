from flask import Flask, request, redirect, render_template, session, url_for
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from datetime import datetime
import os
import json
import logging
from werkzeug.middleware.proxy_fix import ProxyFix
from config import Config

app = Flask(__name__)
app.secret_key = Config.FLASK_SECRET_KEY


# Hook into Gunicorn's logger
gunicorn_logger = logging.getLogger("gunicorn.error")

logger = logging.getLogger(__name__)
logger.handlers = gunicorn_logger.handlers
logger.setLevel(gunicorn_logger.level)

# --- Proxy fix (Traefik support) ---
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# --- Session security ---
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

# -------- Authorization Mapping --------

# Entra group Object ID → internal role
GROUP_ROLE_MAP = {
    # Example:
    # "11111111-aaaa-bbbb-cccc-222222222222": "admin",
    # "33333333-dddd-eeee-ffff-444444444444": "viewer",
}

GROUP_CLAIM_URI = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"

# Name attribute claim URIs
GIVEN_NAME_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
SURNAME_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"

# -------- Helpers --------

def prepare_flask_request(req):
    forwarded_proto = req.headers.get("X-Forwarded-Proto", req.scheme)
    forwarded_host = req.headers.get("Host", req.host)

    return {
        "https": "on" if forwarded_proto == "https" else "off",
        "http_host": forwarded_host,
        "script_name": req.path,
        "server_port": "443" if forwarded_proto == "https" else req.environ.get("SERVER_PORT"),
        "get_data": req.args.copy(),
        "post_data": req.form.copy()
    }


def init_saml_auth(req):
    """
    Initialise SAML auth using:
    - settings.json for SP structure
    - environment variables for IdP-sensitive values
    """
    base_path = os.path.join(os.path.dirname(__file__), "saml")

    # Load raw settings.json
    with open(os.path.join(base_path, "settings.json"), "r") as f:
        settings_dict = json.load(f)

    # Overlay IdP values from env vars
    settings_dict["idp"]["entityId"] = Config.SAML_IDP_ENTITY_ID
    settings_dict["idp"]["singleSignOnService"]["url"] = Config.SAML_IDP_SSO_URL

    # ---- Certificate handling (rotation-aware) ----
    if Config.SAML_IDP_X509CERTS:
        settings_dict["idp"]["x509certMulti"] = {
            "signing": Config.SAML_IDP_X509CERTS
        }
    else:
        settings_dict["idp"]["x509cert"] = Config.SAML_IDP_X509CERT

    settings = OneLogin_Saml2_Settings(
        settings=settings_dict,
        custom_base_path=base_path
    )

    return OneLogin_Saml2_Auth(req, settings)


# -------- Routes --------

@app.route("/")
def index():
    return render_template(
        "index.html",
        authenticated="samlUserdata" in session,
        nameid=session.get("samlNameId"),
        login_time=session.get("login_time"),
        debug=session.get("debug", False)
    )

@app.route("/login")
def login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login(force_authn=True))

@app.route("/login/google")
def login_google():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)

    login_url = auth.login(force_authn=True)

    return redirect(login_url + "&idp=google")

@app.route("/login/facebook")
def login_facebook():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)

    login_url = auth.login(force_authn=True)

    return redirect(login_url + "&idp=facebook")

@app.route("/login/apple")
def login_apple():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)

    login_url = auth.login(force_authn=True)

    return redirect(login_url + "&=Apple")


@app.route("/acs", methods=["POST"])
def acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        logger.error(f"SAML ERRORS: {errors}")
        logger.error(f"SAML LAST ERROR: {auth.get_last_error_reason()}")
        return f"SAML error: {errors}", 400

    if not auth.is_authenticated():
        return "Not authenticated", 403

    # ---- Base session state ----
    attributes = auth.get_attributes()

    # ---- Mandatory name enforcement ----
    given_name = attributes.get(GIVEN_NAME_CLAIM)
    surname = attributes.get(SURNAME_CLAIM)

    if not given_name or not surname:
        return (
            "Login blocked: given name and surname are required for this application.",
            403
        )

    session["samlUserdata"] = attributes
    session["samlNameId"] = auth.get_nameid()
    session["samlSessionIndex"] = auth.get_session_index()
    session["login_time"] = datetime.utcnow().isoformat()
    session["debug"] = Config.SAML_DEBUG

    # ---- Certificate observability (debug only) ----
    if session.get("debug"):
        try:
            session["idp_cert_fingerprint"] = (
                auth.get_settings().get_idp_cert_fingerprint()
            )
        except Exception:
            session["idp_cert_fingerprint"] = None

    # ---- Group / Role Mapping ----
    groups = attributes.get(GROUP_CLAIM_URI, [])

    roles = set()
    for group_id in groups:
        if group_id in GROUP_ROLE_MAP:
            roles.add(GROUP_ROLE_MAP[group_id])

    session["groups"] = groups
    session["roles"] = sorted(list(roles))

    return redirect(url_for("claims"))


@app.route("/claims")
def claims():
    if "samlUserdata" not in session:
        return redirect(url_for("index"))

    return render_template(
        "claims.html",
        attributes=session["samlUserdata"],
        nameid=session.get("samlNameId"),
        session_index=session.get("samlSessionIndex"),
        roles=session.get("roles", []),
        groups=session.get("groups", []),
        debug=session.get("debug", False)
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/slo")
def slo():
    if not Config.SAML_ENABLE_SLO:
        session.clear()
        return redirect(url_for("index"))

    if "samlNameId" not in session or "samlSessionIndex" not in session:
        session.clear()
        return redirect(url_for("index"))

    try:
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)

        return redirect(
            auth.logout(
                name_id=session["samlNameId"],
                session_index=session["samlSessionIndex"]
            )
        )
    except Exception:
        session.clear()
        return redirect(url_for("index"))


@app.route("/slo/callback")
def slo_callback():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)

    auth.process_slo()

    errors = auth.get_errors()
    session.clear()

    if errors:
        return f"SLO error: {errors}", 400

    return redirect(url_for("logout_complete"))


@app.route("/logout-complete")
def logout_complete():
    return render_template("logout.html")


# -------- Entrypoint --------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

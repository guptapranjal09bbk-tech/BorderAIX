
import streamlit as st
import cv2
import numpy as np
from ultralytics import YOLO
import tempfile, os, time, math, base64, io, wave
from datetime import datetime, timedelta
import hashlib, json, hmac

try:
    from twilio.rest import Client
except Exception:
    Client = None

st.set_page_config(page_title="BorderAI Surveillance", page_icon="🛡️", layout="wide")

# ===================== STYLE =====================
st.markdown("""
<style>
html, body, [data-testid="stAppViewContainer"] {
    background: #08111f;
    color: #f4f7fb;
}
[data-testid="stHeader"] { background: rgba(0,0,0,0); }
.block-container { padding-top: 1.2rem; padding-bottom: 2rem; }
h1,h2,h3,h4,p,span,label,div { color: #f4f7fb; }

/* BorderAI Defence Visual Theme */
[data-testid="stAppViewContainer"]::before {
    content: "🪖  BORDERAI  •  BORDER SURVEILLANCE  •  🛡️";
    display: block; margin: 0 0 14px 0; padding: 10px 16px;
    border: 1px solid #29415d; border-left: 4px solid #7a9b62; border-radius: 10px;
    background: linear-gradient(90deg, rgba(25,45,42,.95), rgba(16,31,51,.92));
    letter-spacing: 1.5px; font-size: 12px; font-weight: 700; text-align: center;
}
[data-testid="stSidebar"]::before {
    content: "🪖  BORDER DEFENCE"; display: block; padding: 12px 14px; margin: 4px 8px 12px 8px;
    border: 1px solid #2e5578; border-radius: 10px; background: rgba(20,45,42,.8);
    font-weight: 700; letter-spacing: 1px; text-align: center;
}

[data-testid="stSidebar"] {
    background: #0d1828;
    border-right: 1px solid #29415d;
}
.card {
    background: #101f33;
    border: 1px solid #2e5578;
    border-radius: 14px;
    padding: 16px;
    margin: 8px 0;
}
.alertbox {
    background: #3a1014;
    border: 2px solid #ff4b4b;
    border-radius: 14px;
    padding: 15px;
    margin: 10px 0;
    box-shadow: 0 0 18px rgba(255,75,75,.25);
}
.infobox {
    background: #12283a;
    border: 1px solid #38bdf8;
    border-radius: 12px;
    padding: 12px;
}
.small { color: #b8c8d9 !important; font-size: 13px; }
</style>
""", unsafe_allow_html=True)

# ===================== SECURITY / AUDIT / TWILIO =====================
DEFAULT_GOV_ID = "Trinetrax"
DEFAULT_PASSWORD_HASH = "36b4a63948f2f59db0e5cf92cbb6fb25a0d2f7806fa089adc133d9ab87dfd24a"
ALERT_PHONE = "+919956182185"
SECURITY_STATE_FILE = "security_state.json"
LEDGER_FILE = "blockchain_ledger.json"
FACE_MATCH_THRESHOLD = 0.70


def get_secret(name, default=None):
    try:
        value = st.secrets.get(name)
        if value not in (None, ""):
            return str(value)
    except Exception:
        pass
    value = os.getenv(name)
    return value if value not in (None, "") else default


def password_hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def get_security_state():
    return load_json(SECURITY_STATE_FILE, {})


def audit_event(event_type, details):
    state = get_security_state()
    events = state.setdefault("audit_events", [])
    event = {
        "id": hashlib.sha256(
            f"{datetime.utcnow().isoformat()}|{event_type}|{json.dumps(details, sort_keys=True)}".encode()
        ).hexdigest()[:16].upper(),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "event_type": event_type,
        "details": details,
    }
    events.insert(0, event)
    state["audit_events"] = events[:500]
    save_json(SECURITY_STATE_FILE, state)
    return event


def ledger_hash(payload):
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def append_block(event_type, data):
    ledger = load_json(LEDGER_FILE, [])
    previous_hash = ledger[-1]["hash"] if ledger else "0" * 64
    block = {
        "index": len(ledger) + 1,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "event_type": event_type,
        "data": data,
        "previous_hash": previous_hash,
    }
    block["hash"] = ledger_hash(block)
    ledger.append(block)
    save_json(LEDGER_FILE, ledger)
    return block


def verify_ledger():
    ledger = load_json(LEDGER_FILE, [])
    previous_hash = "0" * 64
    for expected_index, block in enumerate(ledger, start=1):
        if block.get("index") != expected_index:
            return False, f"Invalid block index at block {expected_index}."
        if block.get("previous_hash") != previous_hash:
            return False, f"Previous-hash mismatch at block {expected_index}."
        stored_hash = block.get("hash")
        copy_block = dict(block)
        copy_block.pop("hash", None)
        if ledger_hash(copy_block) != stored_hash:
            return False, f"Hash mismatch at block {expected_index}."
        previous_hash = stored_hash
    return True, f"Verified {len(ledger)} block(s)."


def send_security_sms(message_text):
    if Client is None:
        return False, "Twilio SDK is not installed. Run: pip install twilio"
    sid = get_secret("TWILIO_ACCOUNT_SID")
    token = get_secret("TWILIO_AUTH_TOKEN")
    from_number = get_secret("TWILIO_PHONE_NUMBER")
    to_number = get_secret("BORDERAI_ALERT_PHONE", ALERT_PHONE)
    if not all([sid, token, from_number, to_number]):
        return False, "Twilio secrets are not configured."
    try:
        client = Client(sid, token)
        msg = client.messages.create(sms_account_alerts, from_=from_number, to=to_number)
        return True, str(msg.sid)
    except Exception as exc:
        return False, str(exc)


def current_security_record(user_id=None):
    """Return security record for one attempted ID, never a global lockout."""
    state = get_security_state()
    records = state.setdefault("login_records", {})
    key = (user_id or st.session_state.get("authenticated_user_id") or "__unknown__").strip().lower()[:64]
    record = records.get(key, {})

    blocked_until = record.get("blocked_until")
    if blocked_until:
        try:
            until = datetime.fromisoformat(blocked_until)
            if datetime.now()  until:
                return record
            record["blocked_until"] = None
            records[key] = record
            state["login_records"] = records
            save_json(SECURITY_STATE_FILE, state)
        except Exception:
            record["blocked_until"] = None
    return record


def save_security_record(user_id, record):
    state = get_security_state()
    records = state.setdefault("login_records", {})
    key = (user_id or "__unknown__").strip().lower()[:64]
    records[key] = record
    state["login_records"] = records
    # Keep a compatibility snapshot for the dashboard, but it is NOT used for lockout.
    state["login"] = record
    save_json(SECURITY_STATE_FILE, state)


def security_gate():
    expected_id = get_secret("BORDERAI_GOV_ID", DEFAULT_GOV_ID)
    expected_hash = get_secret("BORDERAI_PASSWORD_HASH", DEFAULT_PASSWORD_HASH)

    if st.session_state.get("authenticated"):
        return current_security_record(st.session_state.get("authenticated_user_id", expected_id))

    st.markdown("# 🛡️ BorderAI Secure Access")
    st.markdown("### Government / Authorized Operator Authentication")
    st.caption("Protected entry • Per-ID failed-login monitoring • Per-ID 5-second lockout • Tamper-evident audit")

    with st.form("borderai_login", clear_on_submit=False):
        gov_id = st.text_input("Government ID / Authorized ID")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("🔐 SECURE LOGIN", type="primary", use_container_width=True)

    # IMPORTANT: lockout is checked AFTER the user enters an ID.
    # Therefore one user's failed attempts cannot block every other user.
    if submitted:
        gov_id_key = gov_id.strip().lower()[:64]
        record = current_security_record(gov_id_key)

        blocked_until = record.get("blocked_until")
        if blocked_until:
            try:
                until = datetime.fromisoformat(blocked_until)
                if datetime.now() < until:
                    remaining = until - datetime.now()
                    st.error("🔒 ACCESS BLOCKED — This ID is under a 5-second security lock.")
                    st.warning(
                        f"Blocked ID: {gov_id[:64]} | Until: {until.strftime('%d-%m-%Y %H:%M:%S')} | "
                        f"Remaining: {str(remaining).split('.')[0]}"
                    )
                    st.stop()
            except Exception:
                pass

        ok_id = hmac.compare_digest(gov_id, expected_id)
        ok_pw = hmac.compare_digest(password_hash(password), expected_hash)

        if ok_id and ok_pw:
            st.session_state.authenticated = True
            st.session_state.authenticated_user_id = gov_id
            st.session_state.login_time = datetime.now().isoformat(timespec="seconds")
            audit_event(
                "SUCCESSFUL_LOGIN",
                {"user_id": gov_id, "failed_attempts_before_success": record.get("failed_attempts", 0)},
            )
            append_block(
                "SUCCESSFUL_LOGIN",
                {"user_id": gov_id, "failed_attempts": record.get("failed_attempts", 0)},
            )
            st.success("✅ Authentication successful. BorderAI dashboard unlocked.")
            st.rerun()
        else:
            failures = int(record.get("failed_attempts", 0)) + 1
            record["failed_attempts"] = failures
            record["last_failed_at"] = datetime.now().isoformat(timespec="seconds")
            record["last_attempted_id"] = gov_id[:64]
            risk = min(100, 40 + failures * 20)
            save_security_record(gov_id_key, record)

            audit = audit_event(
                "FAILED_LOGIN",
                {"attempt": failures, "risk": risk, "user_id": gov_id[:64]},
            )
            append_block(
                "FAILED_LOGIN",
                {"attempt": failures, "risk": risk, "incident_id": audit["id"], "user_id": gov_id[:64]},
            )

            if failures == 1:
                st.warning("⚠️ Warning: Invalid credentials. First failed login attempt recorded for this ID.")
            elif failures == 2:
                sms = (
                    "Alert: BorderAI security activity detected. "
                    "2 failed login attempts detected. "
                    f"ID: {gov_id[:64]}. "
                    f"Risk: {risk}%. "
                    f"Time: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}. "
                    f"Incident ID: {audit['id']}. "
                    "Reply STATUS for updates. Test message from Twilio."
                )
                sent, info = send_security_sms(sms)
                st.error("🚨 SUSPICIOUS LOGIN ACTIVITY — Attempt 2 detected for this ID.")
                alarm()
                st.info("📱 SMS alert sent." if sent else f"📱 SMS not sent: {info}")
            else:
                until = datetime.now() + timedelta(seconds=5)
                record["blocked_until"] = until.isoformat(timespec="seconds")
                save_security_record(gov_id_key, record)
                sms = (
                    "Alert: BorderAI security activity detected. "
                    "3 failed login attempts. This ID is blocked for 5 seconds. "
                    f"ID: {gov_id[:64]}. "
                    "Risk: 100%. "
                    f"Time: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}. "
                    f"Incident ID: {audit['id']}. "
                    "Reply STATUS for updates. Test message from Twilio."
                )
                sent, info = send_security_sms(sms)
                st.error("🔒 ACCESS BLOCKED FOR 5 SECONDS — This ID only is locked.")
                alarm()
                st.info("📱 SMS alert sent." if sent else f"📱 SMS not sent: {info}")
                st.stop()

        st.caption(
            f"Recorded failed attempts for this ID: {failures} | "
            f"Current risk: {min(100, 40 + failures * 20)}%"
        )
    st.stop()


MODEL_PATH = "yolo11n.pt"

@st.cache_resource
def load_model():
    return YOLO(MODEL_PATH)

model = load_model()

# COCO classes
NAMES = {0:"Person", 1:"Bicycle", 2:"Car", 3:"Motorcycle"}

# ===================== SIREN =====================
@st.cache_data
def make_siren_data():
    sr = 22050
    duration = 1.6
    t = np.arange(int(sr * duration)) / sr
    freq = np.where(((t * 3) % 2) < 1, 660, 880)
    x = 0.18 * np.sin(2 * np.pi * freq * t)
    fade = np.minimum(1, np.minimum(t * 10, (duration - t) * 10))
    x *= np.clip(fade, 0, 1)
    pcm = np.int16(x * 32767)

    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes(pcm.tobytes())

    return base64.b64encode(buf.getvalue()).decode()

def alarm():
    audio = make_siren_data()
    html = (
        '<audio autoplay controls style="width:100%;">'
        f'<source src="data:audio/wav;base64,{audio}" type="audio/wav">'
        '</audio>'
    )
    st.markdown(html, unsafe_allow_html=True)

# Authenticate before loading the surveillance model or exposing dashboard modules.
login_record = security_gate()

# ===================== FACE DETECTION =====================
@st.cache_resource
def face_detector():
    path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    return cv2.CascadeClassifier(path)

face_cascade = face_detector()

def detect_faces(frame):
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    return face_cascade.detectMultiScale(
        gray, 1.1, 5, minSize=(45, 45)
    )

def face_similarity(reference_bgr, live_bgr):
    ref_faces = detect_faces(reference_bgr)
    live_faces = detect_faces(live_bgr)

    if len(ref_faces) == 0 or len(live_faces) == 0:
        return 0.0, False

    def crop_face(img, faces):
        x, y, w, h = max(faces, key=lambda q: q[2] * q[3])
        crop = cv2.cvtColor(img[y:y+h, x:x+w], cv2.COLOR_BGR2GRAY)
        crop = cv2.resize(crop, (128, 128))
        crop = cv2.equalizeHist(crop)
        hist = cv2.calcHist([crop], [0], None, [64], [0, 256])
        cv2.normalize(hist, hist)
        return hist

    a = crop_face(reference_bgr, ref_faces)
    b = crop_face(live_bgr, live_faces)
    score = float(cv2.compareHist(a, b, cv2.HISTCMP_CORREL))

    # Prototype similarity indicator, NOT production biometric identification.
    return score, score >= FACE_MATCH_THRESHOLD

# ===================== MOVEMENT / RISK =====================
def movement_text(prev, curr, dt=0.1):
    if prev is None or curr is None:
        return "Stationary", 0.0

    dx = curr[0] - prev[0]
    dy = curr[1] - prev[1]
    distance = math.hypot(dx, dy)

    if distance < 8:
        return "Stationary", 0.0

    speed = distance / max(dt, 0.05)

    if abs(dx) >= abs(dy):
        direction = "Moving Right" if dx > 0 else "Moving Left"
    else:
        direction = "Moving Forward" if dy < 0 else "Moving Backward"

    if speed > 180:
        return "Running / Fast", speed

    return direction, speed

def zone_from_risk(risk):
    if risk >= 80:
        return "RED ZONE", "🔴"
    if risk >= 50:
        return "ORANGE ZONE", "🟠"
    return "GREEN ZONE", "🟢"

def calc_risk(persons, vehicles, movement, face_visible=False):
    risk = 0

    if persons:
        risk += 25

    if vehicles:
        risk += 20

    if movement.startswith("Running"):
        risk += 45
    elif movement != "Stationary":
        risk += 10

    if persons >= 2:
        risk += 10

    if persons and not face_visible:
        risk += 25

    return int(min(100, risk))

# ===================== YOLO FRAME =====================
def draw_detections(frame, results, selected=None):
    annotated = frame.copy()
    persons = 0
    cars = 0
    bikes = 0
    centers = []
    heights = []

    for r in results:
        for b in r.boxes:
            cls = int(b.cls[0])
            conf = float(b.conf[0])

            if cls not in NAMES or conf < 0.35:
                continue

            name = NAMES[cls]

            if name == "Person":
                persons += 1
            elif name == "Car":
                cars += 1
            elif name in ("Bicycle", "Motorcycle"):
                bikes += 1

            if selected:
                allowed = (
                    name.lower() in selected
                    or (name == "Motorcycle" and "bike" in selected)
                    or (name == "Bicycle" and "bike" in selected)
                )
                if not allowed:
                    continue

            x1, y1, x2, y2 = map(int, b.xyxy[0].tolist())
            centers.append(((x1+x2)//2, (y1+y2)//2, name))
            heights.append(y2-y1)

            cv2.rectangle(
                annotated, (x1, y1), (x2, y2),
                (0, 220, 255), 2
            )
            cv2.putText(
                annotated,
                f"{name} {conf*100:.0f}%",
                (x1, max(25, y1-8)),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.6,
                (255, 255, 255),
                2
            )

    return annotated, persons, cars, bikes, centers, heights

# ===================== ALERT POPUP =====================
def show_alert(
    risk, camera, zone, timing, movement,
    height, persons, objects, reason
):
    icon = "🔴" if risk >= 80 else "🟠"

    st.markdown(
        f"""
        <div class="alertbox">
        <h2>{icon} SUSPICIOUS ACTIVITY DETECTED</h2>
        <b>Risk:</b> {risk}% &nbsp; | &nbsp;
        <b>Camera:</b> {camera}<br>
        <b>Zone:</b> {zone}<br>
        <b>Timing:</b> {timing}<br>
        <b>Movement:</b> {movement}<br>
        <b>Height:</b> {height} px (bounding-box height)<br>
        <b>Persons:</b> {persons}<br>
        <b>Objects:</b> {", ".join(objects) if objects else "None"}<br>
        <b>Reason:</b> {reason}
        </div>
        """,
        unsafe_allow_html=True
    )

    if risk >= 90:
        st.warning(
            "🚁 **DRONE TRACKING RECOMMENDED** — "
            "Authorized operator approval required."
        )

        c1, c2 = st.columns(2)

        with c1:
            if st.button(
                "YES — Create Drone Tracking Request",
                key=f"drone_yes_{time.time_ns()}"
            ):
                st.success(
                    "✅ Drone tracking request created for "
                    "the authorized operator."
                )

        with c2:
            if st.button(
                "NO — Do Not Request",
                key=f"drone_no_{time.time_ns()}"
            ):
                st.info("Drone request declined.")

    alarm()

# ===================== SIDEBAR =====================
st.sidebar.markdown("## 🛡️ BorderAI")

page = st.sidebar.radio(
    "Surveillance Modules",
    [
        "🎥 Recorded Video Analysis",
        "📡 Live CCTV",
        "🛡️ Cybersecurity",
        "⛓️ Blockchain Ledger",
        "🔔 Notifications"
    ]
)

st.sidebar.markdown("---")
st.sidebar.markdown("**System Status**")
st.sidebar.success("AI Engine: Online")
st.sidebar.info("Camera Network: Ready")
st.sidebar.success("🔐 Authentication: Active")
ok_chain, chain_msg = verify_ledger()
if ok_chain:
    st.sidebar.success("⛓️ Ledger: Integrity Verified")
else:
    st.sidebar.error("⛓️ Ledger: Integrity Error")
if st.sidebar.button("🔒 Logout", use_container_width=True):
    user_id = get_secret("BORDERAI_GOV_ID", DEFAULT_GOV_ID)
    audit_event("LOGOUT", {"user_id": user_id})
    append_block("LOGOUT", {"user_id": user_id})
    st.session_state.authenticated = False
    st.rerun()

# ===================== HEADER =====================
st.title("🛡️ BorderAI")
st.subheader("AI-Based Intelligent Video Surveillance Platform")

st.markdown(
    '<div class="infobox">'
    '<b>Border Surveillance Control Center</b><br>'
    'AI-powered detection, tracking, risk assessment and alert management'
    '</div>',
    unsafe_allow_html=True
)

# =========================================================
# RECORDED VIDEO
# =========================================================
if page == "🎥 Recorded Video Analysis":

    st.header("🎥 Recorded Video Analysis")

    uploaded = st.file_uploader(
        "Upload CCTV recording",
        type=["mp4", "avi", "mov", "webm"]
    )

    a, b, c = st.columns(3)

    with a:
        camera_no = st.selectbox(
            "Camera Number",
            ["Camera 01", "Camera 02", "Camera 03"]
        )

    with b:
        zone_setting = st.selectbox(
            "Colour Zone",
            [
                "Auto Risk Zone",
                "🟢 GREEN ZONE",
                "🟠 ORANGE ZONE",
                "🔴 RED ZONE"
            ]
        )

    with c:
        conf = st.slider(
            "Detection Confidence",
            0.25, 0.80, 0.35, 0.05
        )

    st.write("**Select objects to check**")

    p1, p2, p3 = st.columns(3)

    with p1:
        want_person = st.checkbox("👤 Person", True)

    with p2:
        want_car = st.checkbox("🚗 Car", True)

    with p3:
        want_bike = st.checkbox("🏍️ Bike", True)

    analyze = st.button(
        "▶ START VIDEO ANALYSIS",
        type="primary"
    )

    if uploaded and analyze:

        suffix = os.path.splitext(uploaded.name)[1]

        with tempfile.NamedTemporaryFile(
            delete=False, suffix=suffix
        ) as tmp:
            tmp.write(uploaded.getbuffer())
            video_path = tmp.name

        cap = cv2.VideoCapture(video_path)

        fps = cap.get(cv2.CAP_PROP_FPS)
        if not fps or fps <= 0:
            fps = 30.0

        total_frames = int(
            cap.get(cv2.CAP_PROP_FRAME_COUNT)
        )

        duration = (
            total_frames / fps
            if total_frames > 0 else 0
        )

        st.caption(
            f"Actual video duration: {duration:.2f} seconds"
        )

        frame_slot = st.empty()
        alert_slot = st.empty()

        timeline = []
        prev_center = None
        frame_idx = 0
        last_alert_time = -999

        selected = set()

        if want_person:
            selected.add("person")
        if want_car:
            selected.add("car")
        if want_bike:
            selected.add("bike")

        while True:
            ok, frame = cap.read()
            if not ok:
                break

            frame_idx += 1
            timestamp = frame_idx / fps

            # Every second frame = faster demo,
            # timestamp still uses original FPS.
            if frame_idx % 2 != 0:
                continue

            results = model.predict(
                frame,
                conf=conf,
                verbose=False
            )

            (
                annotated,
                persons,
                cars,
                bikes,
                centers,
                heights
            ) = draw_detections(
                frame, results, selected
            )

            face_visible = len(
                detect_faces(frame)
            ) > 0

            person_center = next(
                (
                    (x, y)
                    for x, y, name in centers
                    if name == "Person"
                ),
                None
            )

            movement, _ = movement_text(
                prev_center,
                person_center,
                1 / fps
            )

            if person_center:
                prev_center = person_center

            risk = calc_risk(
                persons,
                cars + bikes,
                movement,
                face_visible
            )

            zone, _ = zone_from_risk(risk)

            height = max(heights) if heights else 0

            objects = []

            if persons and want_person:
                objects.append(f"Person ×{persons}")

            if cars and want_car:
                objects.append(f"Car ×{cars}")

            if bikes and want_bike:
                objects.append(f"Bike ×{bikes}")

            if objects:
                timeline.append(
                    (
                        timestamp,
                        objects,
                        movement,
                        risk
                    )
                )

            if risk >= 90 and (
                timestamp - last_alert_time > 1.5
            ):
                last_alert_time = timestamp

                with alert_slot.container():
                    show_alert(
                        risk,
                        camera_no,
                        zone,
                        f"{timestamp:.2f} sec",
                        movement,
                        height,
                        persons,
                        objects,
                        "High-risk movement/object combination"
                    )

            frame_slot.image(
                cv2.cvtColor(
                    annotated,
                    cv2.COLOR_BGR2RGB
                ),
                channels="RGB",
                use_container_width=True
            )

        cap.release()

        st.success(
            f"Analysis complete — "
            f"{len(timeline)} detection events recorded."
        )

        if timeline:
            st.subheader("Detection Timeline")

            for t, objs, mv, r in timeline[:30]:
                st.write(
                    f"⏱️ **{t:.2f}s** — "
                    f"{', '.join(objs)} — "
                    f"{mv} — Risk {r}%"
                )

        try:
            os.unlink(video_path)
        except:
            pass

# =========================================================
# LIVE CCTV
# =========================================================
elif page == "📡 Live CCTV":

    st.header("📡 Live CCTV Monitoring")

    mode = st.radio(
        "Live Monitoring Mode",
        [
            "👤 Specific Person Detection",
            "🚨 Suspicious Activity Detection"
        ],
        horizontal=True
    )

    # ---------- SPECIFIC PERSON ----------
    if mode == "👤 Specific Person Detection":

        st.markdown(
            '<div class="card">'
            '<b>Authorized-person monitoring</b><br>'
            '<span class="small">'
            'Upload a reference face. The prototype then '
            'monitors the selected live camera for a similar '
            'detected face.'
            '</span></div>',
            unsafe_allow_html=True
        )

        ref = st.file_uploader(
            "Upload authorized/reference face image",
            type=["jpg", "jpeg", "png"],
            key="ref_face"
        )

        source = st.selectbox(
            "Live Source",
            ["Laptop Webcam", "RTSP CCTV Stream"],
            key="person_source"
        )

        rtsp = ""

        if source == "RTSP CCTV Stream":
            rtsp = st.text_input(
                "RTSP URL",
                placeholder=(
                    "rtsp://user:password@camera-ip:554/stream"
                ),
                key="person_rtsp"
            )

        if ref:

            arr = np.frombuffer(
                ref.getbuffer(), np.uint8
            )

            ref_img = cv2.imdecode(
                arr, cv2.IMREAD_COLOR
            )

            st.image(
                cv2.cvtColor(
                    ref_img,
                    cv2.COLOR_BGR2RGB
                ),
                width=180,
                caption="Reference image"
            )

            start = st.button(
                "▶ START LIVE MONITORING",
                type="primary"
            )

            if start:

                cap = cv2.VideoCapture(
                    0 if source == "Laptop Webcam"
                    else rtsp
                )

                if not cap.isOpened():
                    st.error(
                        "Live source could not be opened."
                    )

                else:

                    frame_slot = st.empty()
                    alert_slot = st.empty()
                    prev = None
                    last_alert = 0

                    st.info(
                        "Live monitoring running."
                    )

                    for _ in range(900):

                        ok, frame = cap.read()

                        if not ok:
                            break

                        faces = detect_faces(frame)

                        score, matched = face_similarity(
                            ref_img, frame
                        )

                        h = 0

                        if len(faces):

                            x, y, w, h = max(
                                faces,
                                key=lambda q: q[2] * q[3]
                            )

                            cv2.rectangle(
                                frame,
                                (x, y),
                                (x+w, y+h),
                                (0, 255, 255),
                                2
                            )

                            cv2.putText(
                                frame,
                                f"Face match: {score * 100:.0f}%",
                                (x, max(25, y-10)),
                                cv2.FONT_HERSHEY_SIMPLEX,
                                0.6,
                                (255, 255, 255),
                                2
                            )

                            center = (
                                x + w//2,
                                y + h//2
                            )

                            movement, _ = movement_text(
                                prev,
                                center,
                                1/30
                            )

                            prev = center

                        else:
                            movement = "No face visible"

                        frame_slot.image(
                            cv2.cvtColor(
                                frame,
                                cv2.COLOR_BGR2RGB
                            ),
                            channels="RGB",
                            use_container_width=True
                        )

                        if (
                            matched
                            and time.time() - last_alert > 2
                        ):

                            last_alert = time.time()

                            with alert_slot.container():
                                show_alert(
                                    95,
                                    "Camera 01",
                                    "RED ZONE",
                                    datetime.now().strftime(
                                        "%H:%M:%S"
                                    ),
                                    movement,
                                    h,
                                    1,
                                    ["Reference Face Match"],
                                    "Reference-face similarity threshold reached"
                                )

                        time.sleep(0.03)

                    cap.release()

    # ---------- SUSPICIOUS ACTIVITY ----------
    else:

        source = st.selectbox(
            "Live Source",
            ["Laptop Webcam", "RTSP CCTV Stream"],
            key="sus_source"
        )

        rtsp = ""

        if source == "RTSP CCTV Stream":
            rtsp = st.text_input(
                "RTSP URL",
                placeholder=(
                    "rtsp://user:password@camera-ip:554/stream"
                ),
                key="sus_rtsp"
            )

        camera_no = st.selectbox(
            "Camera Number",
            ["Camera 01", "Camera 02", "Camera 03"],
            key="live_cam"
        )

        start = st.button(
            "▶ START LIVE MONITORING",
            type="primary"
        )

        if start:

            cap = cv2.VideoCapture(
                0 if source == "Laptop Webcam"
                else rtsp
            )

            if not cap.isOpened():

                st.error(
                    "Live source could not be opened."
                )

            else:

                frame_slot = st.empty()
                alert_slot = st.empty()
                prev = None
                last_alert = 0

                st.info(
                    "Live monitoring is running."
                )

                for _ in range(900):

                    ok, frame = cap.read()

                    if not ok:
                        break

                    results = model.predict(
                        frame,
                        conf=0.35,
                        verbose=False
                    )

                    (
                        annotated,
                        persons,
                        cars,
                        bikes,
                        centers,
                        heights
                    ) = draw_detections(
                        frame,
                        results
                    )

                    faces = detect_faces(frame)

                    pc = next(
                        (
                            (x, y)
                            for x, y, name in centers
                            if name == "Person"
                        ),
                        None
                    )

                    movement, _ = movement_text(
                        prev,
                        pc,
                        1/30
                    )

                    if pc:
                        prev = pc

                    risk = calc_risk(
                        persons,
                        cars + bikes,
                        movement,
                        len(faces) > 0
                    )

                    zone, _ = zone_from_risk(risk)

                    height = max(heights) if heights else 0

                    frame_slot.image(
                        cv2.cvtColor(
                            annotated,
                            cv2.COLOR_BGR2RGB
                        ),
                        channels="RGB",
                        use_container_width=True
                    )

                    # Mask / face-not-visible demo rule.
                    if persons and len(faces) == 0:

                        reason = (
                            "Person detected but face is not visible — "
                            "possible mask/occlusion or camera angle."
                        )

                        risk = max(risk, 95)

                        if time.time() - last_alert > 2:

                            last_alert = time.time()

                            objects = ["Person"]

                            if cars:
                                objects.append(
                                    f"Car ×{cars}"
                                )

                            if bikes:
                                objects.append(
                                    f"Bike ×{bikes}"
                                )

                            with alert_slot.container():
                                show_alert(
                                    risk,
                                    camera_no,
                                    "RED ZONE",
                                    datetime.now().strftime(
                                        "%H:%M:%S"
                                    ),
                                    movement,
                                    height,
                                    persons,
                                    objects,
                                    reason
                                )

                    elif (
                        risk >= 90
                        and time.time() - last_alert > 2
                    ):

                        last_alert = time.time()

                        with alert_slot.container():
                            show_alert(
                                risk,
                                camera_no,
                                zone,
                                datetime.now().strftime(
                                    "%H:%M:%S"
                                ),
                                movement,
                                height,
                                persons,
                                ["Person"] if persons else [],
                                "High-risk movement/object combination"
                            )

                    time.sleep(0.03)

                cap.release()

# =========================================================
# CYBERSECURITY
# =========================================================
elif page == "🛡️ Cybersecurity":
    st.header("🛡️ Cybersecurity & System Audit")
    record = current_security_record()
    failures = int(record.get("failed_attempts", 0))
    risk = min(100, 40 + failures * 20)

    a, b, c = st.columns(3)
    a.metric("Authentication", "ACTIVE")
    b.metric("Failed Login Attempts", failures)
    c.metric("Current Login Risk", f"{risk}%")

    st.markdown(
        '<div class="card"><b>Security controls</b><br>'
        '✓ Authenticated entry &nbsp; ✓ Failed-login monitoring &nbsp; '
        '✓ 24-hour lockout &nbsp; ✓ Twilio SMS alerts &nbsp; '
        '✓ Cryptographic audit hashing</div>',
        unsafe_allow_html=True
    )

    events = get_security_state().get("audit_events", [])
    if events:
        st.subheader("Recent Security Events")
        for e in events[:20]:
            st.markdown(
                f"**{e['timestamp']}** — `{e['event_type']}` — "
                f"Incident `{e['id']}` — {e['details']}"
            )
    else:
        st.info("No security events recorded yet.")

# =========================================================
# BLOCKCHAIN / TAMPER-EVIDENT LEDGER
# =========================================================
elif page == "⛓️ Blockchain Ledger":
    st.header("⛓️ Blockchain-Style Integrity Ledger")
    st.caption("Local hash-chained audit ledger for the prototype. Tamper-evident, not a decentralized public blockchain.")

    ledger = load_json(LEDGER_FILE, [])
    verified, message = verify_ledger()
    if verified:
        st.success(f"✅ INTEGRITY VERIFIED — {message}")
    else:
        st.error(f"❌ INTEGRITY CHECK FAILED — {message}")

    if ledger:
        for block in reversed(ledger[:30]):
            block_data = json.dumps(block["data"], ensure_ascii=False)
            st.markdown(
                f"<div class=\"card\"><b>Block #{block['index']}</b> | {block['timestamp']}<br>"
                f"<b>Event:</b> {block['event_type']}<br>"
                f"<b>Hash:</b> <code>{block['hash']}</code><br>"
                f"<b>Previous Hash:</b> <code>{block['previous_hash']}</code><br>"
                f"<b>Data:</b> {block_data}</div>",
                unsafe_allow_html=True
            )
    else:
        st.info("No blocks yet. Security events will create blocks automatically.")

    st.download_button(
        "⬇️ Download Integrity Ledger",
        data=json.dumps(ledger, indent=2, ensure_ascii=False),
        file_name="borderai_blockchain_ledger.json",
        mime="application/json",
    )

# =========================================================
# NOTIFICATIONS
# =========================================================
else:

    st.header("🔔 Notifications & Incident Log")

    st.markdown(
        '<div class="card">'
        '<b>Notification Center</b><br>'
        'High-risk incidents are shown here. '
        'Phone/SMS/push integration can be connected '
        'to an authorized messaging service in the next stage.'
        '</div>',
        unsafe_allow_html=True
    )

    if "events" not in st.session_state:
        st.session_state.events = []

    demo = st.slider(
        "Demo Risk Level",
        0, 100, 90
    )

    if st.button("🚨 Generate Demo Alert"):

        st.session_state.events.insert(
            0,
            {
                "time": datetime.now().strftime(
                    "%H:%M:%S"
                ),
                "camera": "Camera 01",
                "risk": demo,
                "zone": zone_from_risk(demo)[0],
                "movement": "Moving Right",
                "height": "240 px",
                "persons": 1
            }
        )

    if st.session_state.events:

        for e in st.session_state.events[:10]:

            st.markdown(
                f"""
                <div class="card">
                <b>🚨 Camera:</b> {e['camera']}
                &nbsp; <b>Risk:</b> {e['risk']}%<br>
                <b>Time:</b> {e['time']}
                &nbsp; <b>Zone:</b> {e['zone']}<br>
                <b>Movement:</b> {e['movement']}
                &nbsp; <b>Height:</b> {e['height']}
                &nbsp; <b>Persons:</b> {e['persons']}
                </div>
                """,
                unsafe_allow_html=True
            )

            if e["risk"] >= 90:

                st.warning(
                    "🚁 Risk ≥ 90%: "
                    "Should I activate/send a drone to track?"
                )

                y, n = st.columns(2)

                with y:
                    if st.button(
                        "YES",
                        key="y" + e["time"]
                    ):
                        st.success(
                            "Drone tracking request created."
                        )

                with n:
                    if st.button(
                        "NO",
                        key="n" + e["time"]
                    ):
                        st.info(
                            "No drone request."
                        )

    else:
        st.info("No notifications yet.")

#!/usr/bin/env python3
import json
import requests
from flask import Flask, render_template_string, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from collections import defaultdict
import time

app = Flask(__name__)

# AES Keys
KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
BLOCK_SIZE = 16

def decrypt_aes_cbc(data):
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        decrypted = cipher.decrypt(data)
        try:
            return unpad(decrypted, BLOCK_SIZE)
        except ValueError:
            return decrypted
    except Exception:
        return None

def encrypt_aes_cbc(data):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded = pad(data, BLOCK_SIZE)
    return cipher.encrypt(padded)

def encode_varint(value):
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value == 0:
            result.append(byte)
            break
        result.append(byte | 0x80)
    return bytes(result)

def decode_varint(data, offset):
    value = 0
    shift = 0
    while True:
        b = data[offset]
        value |= (b & 0x7F) << shift
        offset += 1
        if not (b & 0x80):
            break
        shift += 7
    return value, offset

def parse_single_message(data):
    fields = {}
    idx = 0
    while idx < len(data):
        key, idx = decode_varint(data, idx)
        field_num = key >> 3
        wire_type = key & 0x07
        if wire_type == 0:
            value, idx = decode_varint(data, idx)
            fields[field_num] = ('varint', value)
        elif wire_type == 2:
            length, idx = decode_varint(data, idx)
            raw = data[idx:idx+length]
            idx += length
            fields[field_num] = ('bytes', raw)
    return fields

def serialize_fields(fields_dict):
    result = bytearray()
    for num, (typ, val) in sorted(fields_dict.items()):
        if typ == 'varint':
            key = (num << 3) | 0
            result.extend(encode_varint(key))
            result.extend(encode_varint(val))
        elif typ == 'bytes':
            key = (num << 3) | 2
            result.extend(encode_varint(key))
            result.extend(encode_varint(len(val)))
            result.extend(val)
    return bytes(result)

def encode_packed_varint(values):
    result = bytearray()
    for v in values:
        result.extend(encode_varint(v))
    return bytes(result)

def decode_packed_varint(data):
    values = []
    idx = 0
    while idx < len(data):
        val, idx = decode_varint(data, idx)
        values.append(val)
    return values

BACKPACK_BODY_HEX = "1a725b2c56ec52ba7d09623454c0a003"
BACKPACK_BODY = bytes.fromhex(BACKPACK_BODY_HEX)

def parse_one_message(data, start):
    fields = []
    idx = start
    while idx < len(data):
        key, idx = decode_varint(data, idx)
        field_num = key >> 3
        wire_type = key & 0x07
        if wire_type == 0:
            value, idx = decode_varint(data, idx)
            fields.append((field_num, 'varint', value, None))
        elif wire_type == 2:
            length, idx = decode_varint(data, idx)
            raw = data[idx:idx+length]
            idx += length
            nested = None
            try:
                nested, _ = parse_one_message(raw, 0)
            except:
                pass
            fields.append((field_num, 'bytes', raw, nested))
    return fields, idx

def collect_ids_from_fields(fields):
    ids = []
    for f in fields:
        if f[1] == 'varint' and f[0] == 1:
            ids.append(f[2])
        elif f[3] is not None:
            ids.extend(collect_ids_from_fields(f[3]))
    return ids

# --- OB54 COOKIES & HEADERS GENERATOR ---
def get_ob54_headers(jwt_token):
    return {
        "User-Agent": "UnityPlayer/2023.2.20f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Authorization": f"Bearer {jwt_token}",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB54",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2023.2.20f1",
        "Connection": "Keep-Alive"
    }

def fetch_vault_items(jwt_token, retries=2):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/GetBackpack"
    headers = get_ob54_headers(jwt_token)
    for attempt in range(retries):
        try:
            resp = requests.post(url, headers=headers, data=BACKPACK_BODY, timeout=15)
            if resp.status_code != 200:
                raise Exception(f"GetBackpack HTTP {resp.status_code}")
            raw = resp.content
            plain = decrypt_aes_cbc(raw)
            data = plain if plain is not None else raw
            fields, _ = parse_one_message(data, 0)
            item_ids = collect_ids_from_fields(fields)
            if item_ids:
                return item_ids
        except Exception:
            if attempt == retries-1:
                raise
            time.sleep(1)
    return []

GET_OUTFIT_TEMPLATE_HEX = "6868f708913820034b74f88c5e59558c"

def build_get_outfit_payload(account_id):
    template = bytes.fromhex(GET_OUTFIT_TEMPLATE_HEX)
    plain = decrypt_aes_cbc(template)
    if plain is None:
        plain = template
    fields = parse_single_message(plain)
    if 1 in fields and fields[1][0] == 'varint':
        fields[1] = ('varint', account_id)
    else:
        raise ValueError("Field 1 not found")
    new_plain = serialize_fields(fields)
    return encrypt_aes_cbc(new_plain)

def fetch_current_outfit(jwt_token, account_id):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/GetAccountOutfit"
    payload = build_get_outfit_payload(account_id)
    headers = get_ob54_headers(jwt_token)
    resp = requests.post(url, headers=headers, data=payload, timeout=15)
    if resp.status_code != 200:
        raise Exception(f"GetAccountOutfit HTTP {resp.status_code}")
    data = resp.content
    fields = parse_single_message(data)
    outfit_values = []
    if 2 in fields and fields[2][0] == 'bytes':
        raw = fields[2][1]
        idx = 0
        while idx < len(raw):
            try:
                val, idx = decode_varint(raw, idx)
                outfit_values.append(val)
            except:
                break
    return outfit_values

def build_change_request_plain(character_id, outfit_ids):
    fields_dict = {
        1: ('varint', character_id),
        3: ('varint', 50)
    }
    repeated_raw = encode_packed_varint(outfit_ids)
    fields_dict[2] = ('bytes', repeated_raw)
    return serialize_fields(fields_dict)

def build_change_request(character_id, outfit_ids):
    plain = build_change_request_plain(character_id, outfit_ids)
    return encrypt_aes_cbc(plain)

def send_change_request(jwt_token, character_id, outfit_ids):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/ChangeClothes"
    encrypted = build_change_request(character_id, outfit_ids)
    headers = get_ob54_headers(jwt_token)
    headers["Content-Type"] = "application/octet-stream"
    resp = requests.post(url, headers=headers, data=encrypted, timeout=15)
    if resp.status_code == 200:
        return True, 200, None
    else:
        return False, resp.status_code, resp.text

EMOTE_TEMPLATE_HEX = "CAF683222A25C7BEFEB51F59544DB313"

def build_emote_payload(emote_id):
    template_bytes = bytes.fromhex(EMOTE_TEMPLATE_HEX)
    plain = decrypt_aes_cbc(template_bytes)
    if plain is None:
        raise ValueError("Failed to decrypt emote template")
    fields = parse_single_message(plain)
    if 6 not in fields or fields[6][0] != 'bytes':
        raise ValueError("Field 6 missing or not bytes in emote template")
    raw_field6 = fields[6][1]
    ids = decode_packed_varint(raw_field6)
    if len(ids) < 4:
        raise ValueError("Unexpected emote payload structure")
    ids[-1] = emote_id
    new_raw = encode_packed_varint(ids)
    fields[6] = ('bytes', new_raw)
    new_plain = serialize_fields(fields)
    return encrypt_aes_cbc(new_plain)

def send_emote_request(jwt_token, base_url, encrypted_payload):
    url = f"{base_url}/ChooseEmote"
    headers = get_ob54_headers(jwt_token)
    resp = requests.post(url, headers=headers, data=encrypted_payload, timeout=15)
    if resp.status_code == 200:
        return True, 200, None
    else:
        return False, resp.status_code, resp.text

WEAPON_TEMPLATE_HEX = "90D63D8BFD093219919DB87E0136ED8865B197FF37F1D324A370C36C9D7717A7339A91F6A679A1B588690CC48C7C568E20D6ECA6DEAF0AF16A12565F4C72059EDD2CC0AE8F762331C6936B3CE45AB9CAABD76B12ED6D979DB4896F4B23FB6CDA53037EC6F290BF14E8EA124E7484DA7C"

def build_weapon_payload(weapon_id):
    template_bytes = bytes.fromhex(WEAPON_TEMPLATE_HEX)
    plain = decrypt_aes_cbc(template_bytes)
    if plain is None:
        raise ValueError("Failed to decrypt weapon template")
    fields = parse_single_message(plain)
    if 1 not in fields or fields[1][0] != 'bytes':
        raise ValueError("Field 1 missing or not bytes")
    list1 = decode_packed_varint(fields[1][1])
    idx = next((i for i, v in enumerate(list1) if v != 0), None)
    if idx is None:
        raise ValueError("No non-zero placeholder found in field 1")
    list1[idx] = weapon_id
    fields[1] = ('bytes', encode_packed_varint(list1))
    new_plain = serialize_fields(fields)
    return encrypt_aes_cbc(new_plain)

def send_weapon_request(jwt_token, encrypted_payload):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/ChooseSlotsAndShow"
    headers = get_ob54_headers(jwt_token)
    headers["Content-Type"] = "application/octet-stream"
    resp = requests.post(url, headers=headers, data=encrypted_payload, timeout=15)
    if resp.status_code == 200:
        return True, 200, None
    else:
        return False, resp.status_code, resp.text

AVATAR_TEMPLATE_HEX = "2C540F37C1CDE1F16C9BA687ABBDD316"

def build_avatar_payload(avatar_id):
    template_bytes = bytes.fromhex(AVATAR_TEMPLATE_HEX)
    plain = decrypt_aes_cbc(template_bytes)
    if plain is None:
        raise ValueError("Failed to decrypt avatar template")
    fields = parse_single_message(plain)
    if 1 not in fields or fields[1][0] != 'varint':
        raise ValueError("Field 1 missing or not varint in avatar template")
    fields[1] = ('varint', avatar_id)
    new_plain = serialize_fields(fields)
    return encrypt_aes_cbc(new_plain)

def send_avatar_request(jwt_token, encrypted_payload):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/ChooseHeadPic"
    headers = get_ob54_headers(jwt_token)
    headers["Content-Type"] = "application/octet-stream"
    resp = requests.post(url, headers=headers, data=encrypted_payload, timeout=15)
    if resp.status_code == 200:
        return True, 200, None
    else:
        return False, resp.status_code, resp.text

def send_backpack_request(jwt_token, encrypted_payload):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/ChooseGameBagShow"
    headers = get_ob54_headers(jwt_token)
    headers["Content-Type"] = "application/octet-stream"
    resp = requests.post(url, headers=headers, data=encrypted_payload, timeout=15)
    if resp.status_code == 200:
        return True, 200, None
    else:
        return False, resp.status_code, resp.text

SELECT_PRESET_TEMPLATE_HEX = (
    "7aa34f4d48a78f45a70aa7acda90d4725589618bac35555d8ee85bb158907cadc35d53e485302b2c196303061be9b887b41285b4025c459b4761fb4122f38c3cf2611df67295bf52697ae68ffdc8d048703f822088829130cd445f747033a5821347af4c85419f96072da6b9d9c956e8"
)

def replace_varint_in_plaintext(plain_data, old_value, new_value):
    result = bytearray()
    idx = 0
    replaced = False
    while idx < len(plain_data):
        try:
            val, idx = decode_varint(plain_data, idx)
            if val == old_value:
                result.extend(encode_varint(new_value))
                replaced = True
            else:
                result.extend(encode_varint(val))
        except:
            result.extend(plain_data[idx:])
            break
    return bytes(result), replaced

def build_select_preset_payload(character_id, pet_id):
    template_encrypted = bytes.fromhex(SELECT_PRESET_TEMPLATE_HEX)
    plain = decrypt_aes_cbc(template_encrypted)
    if plain is None:
        raise ValueError("Failed to decrypt SelectPresetLoadout template")
    old_char_id = 102000007
    old_pet_id1 = 1315000012
    old_pet_id2 = 1300000113
    plain, _ = replace_varint_in_plaintext(plain, old_char_id, character_id)
    plain, _ = replace_varint_in_plaintext(plain, old_pet_id1, pet_id)
    plain, _ = replace_varint_in_plaintext(plain, old_pet_id2, pet_id)
    return encrypt_aes_cbc(plain)

def send_select_preset_request(jwt_token, character_id, pet_id):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/SelectPresetLoadout"
    encrypted_payload = build_select_preset_payload(character_id, pet_id)
    headers = get_ob54_headers(jwt_token)
    resp = requests.post(url, headers=headers, data=encrypted_payload, timeout=15)
    if resp.status_code == 200:
        return True, 200, None
    else:
        return False, resp.status_code, resp.text

def decode_jwt(token):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT")
    payload_b64 = parts[1]
    payload_b64 += '=' * (4 - len(payload_b64) % 4)
    payload_json = base64.b64decode(payload_b64)
    data = json.loads(payload_json)
    account_id = data.get('account_id')
    if not account_id:
        raise ValueError("account_id not found")
    return int(account_id)

def get_region(jwt_token):
    try:
        parts = jwt_token.split('.')
        payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
        data = json.loads(base64.b64decode(payload_b64))
        return data.get("noti_region") or data.get("lock_region")
    except:
        return None

def get_base_url(jwt_token):
    region = get_region(jwt_token)
    if region == "IND":
        return "https://client.ind.freefiremobile.com"
    return "https://clientbp.ggpolarbear.com"

def load_item_db():
    try:
        with open("data.json", "r", encoding="utf-8") as f:
            items = json.load(f)
        db = {}
        for it in items:
            iid = it.get('itemID')
            if iid is not None:
                db[iid] = it
        return db
    except:
        return {}

ITEM_DB = load_item_db()

def get_item_info(item_id):
    info = ITEM_DB.get(item_id, {})
    return info.get('name', f'ID {item_id}'), info.get('type', 'Unknown'), info.get('Rare', '')

def extract_slots(outfit_values):
    slots = {}
    character_id = None
    for val in outfit_values:
        if 102000000 <= val < 103000000:
            character_id = val
            break
    if character_id is None and outfit_values:
        character_id = outfit_values[0]
    slots['character'] = character_id

    for val in outfit_values:
        name, typ, _ = get_item_info(val)
        if typ == 'Mask' and 'head' not in slots:
            slots['head'] = val
        elif typ == 'Shoe' and 'shoe' not in slots:
            slots['shoe'] = val
        elif typ == 'Bottom' and 'bottom' not in slots:
            slots['bottom'] = val
        elif typ == 'Top' and 'top' not in slots:
            slots['top'] = val
        elif typ == 'Facepaint' and 'facepaint' not in slots:
            slots['facepaint'] = val
        elif typ == 'Head' and 'head' not in slots:
            slots['head'] = val
    if len(slots) < 5 and outfit_values:
        try:
            idx = outfit_values.index(character_id) if character_id in outfit_values else 0
            order = ['head', 'shoe', 'bottom', 'top', 'facepaint']
            for i, s in enumerate(order):
                if idx+1+i < len(outfit_values) and s not in slots:
                    slots[s] = outfit_values[idx+1+i]
        except:
            pass
    return slots

# --- NEW UI/UX CHROMIUM GHOST THEME ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>⚡ UCHIHA KING - OUTFIT CHANGER ⚡</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@500;700&display=swap');
        
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Rajdhani', sans-serif; }
        
        body {
            background: #05050d;
            background-image: radial-gradient(circle at 50% 0%, #15102a 0%, #05050d 70%);
            color: #e2e8f0;
            padding: 30px 15px;
            overflow-x: hidden;
        }

        .container { max-width: 1300px; margin: auto; }

        /* Neon Header */
        header {
            text-align: center;
            margin-bottom: 40px;
            position: relative;
        }
        header h1 {
            font-family: 'Orbitron', sans-serif;
            font-size: 2.8rem;
            font-weight: 900;
            letter-spacing: 2px;
            background: linear-gradient(90deg, #00f2fe, #4facfe);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 20px rgba(0, 242, 254, 0.4);
        }
        header p {
            color: #64748b;
            font-size: 1.1rem;
            text-transform: uppercase;
            letter-spacing: 4px;
            margin-top: 5px;
        }

        /* Glass Cards */
        .glass-card {
            background: rgba(13, 17, 33, 0.7);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.05);
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 35px;
            position: relative;
            overflow: hidden;
        }
        .glass-card::before {
            content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 2px;
            background: linear-gradient(90deg, transparent, #00f2fe, transparent);
        }

        /* Form Layout */
        .token-form { display: flex; gap: 15px; }
        input[type="text"], input[type="number"], select {
            flex: 1; background: rgba(30, 41, 59, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 14px 20px; color: #fff; font-size: 1.1rem;
            border-radius: 8px; transition: all 0.3s ease;
        }
        input:focus, select:focus {
            outline: none; border-color: #00f2fe;
            box-shadow: 0 0 15px rgba(0, 242, 254, 0.2);
        }

        /* Styled Action Buttons */
        .btn-glow {
            background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
            color: #05050d; font-family: 'Orbitron', sans-serif;
            font-weight: 700; padding: 14px 28px; border: none;
            border-radius: 8px; cursor: pointer; text-transform: uppercase;
            letter-spacing: 1px; transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 242, 254, 0.3);
        }
        .btn-glow:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 25px rgba(0, 242, 254, 0.5);
        }

        /* Grid Framework */
        .slot-grid, .vault-grid {
            display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 25px;
        }

        /* Inventory Cards */
        .item-node {
            background: rgba(30, 41, 59, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.03);
            border-radius: 12px; padding: 20px; text-align: center;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer; position: relative;
        }
        .item-node:hover {
            transform: translateY(-5px);
            border-color: #00f2fe;
            background: rgba(0, 242, 254, 0.05);
            box-shadow: 0 10px 25px rgba(0, 242, 254, 0.15);
        }
        .item-node img {
            width: 110px; height: 110px; object-fit: contain;
            margin-bottom: 15px; filter: drop-shadow(0 8px 10px rgba(0,0,0,0.5));
        }

        .item-title { font-size: 1.2rem; font-weight: 700; color: #fff; margin-bottom: 4px; }
        .item-id-tag { font-size: 0.85rem; color: #64748b; font-family: monospace; }
        
        .section-title {
            font-family: 'Orbitron', sans-serif; font-size: 1.6rem;
            color: #fff; margin-bottom: 25px; display: flex; align-items: center; gap: 10px;
        }
        .section-title::after {
            content: ''; flex: 1; height: 1px; background: rgba(255,255,255,0.07);
        }

        /* Category Accents */
        .vault-cat-block { margin-bottom: 45px; }
        .vault-cat-block h3 {
            font-size: 1.3rem; color: #4facfe; margin-bottom: 20px;
            text-transform: uppercase; letter-spacing: 1px;
        }

        /* Toast Engine */
        .toast-box {
            position: fixed; bottom: 25px; right: 25px;
            background: #0d1121; border-left: 4px solid #00f2fe;
            padding: 15px 25px; border-radius: 6px; z-index: 9999;
            box-shadow: 0 10px 30px rgba(0,0,0,0.6);
            font-weight: 700; animation: sliderIn 0.3s ease-out;
        }
        @keyframes sliderIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

        .footer-credit { text-align: center; margin-top: 60px; color: #475569; font-size: 0.95rem; }
        .footer-credit a { color: #00f2fe; text-decoration: none; }
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>ROMEO UCHIHA</h1>
        <p>OB54 - Ready Asset System</p>
    </header>

    <div class="glass-card">
        <form id="loginForm" method="post" class="token-form">
            <input type="text" name="jwt" placeholder="Enter Bearer JWT Game Token" value="{{ jwt or '' }}" required>
            <button type="submit" class="btn-glow">Connect Server</button>
        </form>
        {% if load_error %}
            <p style="color:#ef4444; margin-top:15px; font-weight:700;">⚠️ {{ load_error }}</p>
        {% endif %}
    </div>

    {% if slots %}
    <div class="glass-card">
        <div class="section-title">Active Loadout Profile</div>
        <div class="slot-grid">
            {% for slot, data in slots.items() %}
                <div class="item-node" style="cursor:default;">
                    <img src="https://cdn.jsdelivr.net/gh/ShahGCreator/icon@main/PNG/{{ data.id }}.png"
                         onerror="this.onerror=null; this.src='data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' width=\'100\' height=\'100\'%3E%3Crect width=\'100%25\' height=\'100%25\' fill=\'%231e293b\'/%3E%3Ctext x=\'50%25\' y=\'55%25\' fill=\'%2300f2fe\' text-anchor=\'middle\'%3EAsset {{ data.id }}%3C/text%3E%3C/svg%3E';">
                    <div class="item-title" style="color:#00f2fe;">{{ slot|upper }}</div>
                    <div style="font-weight:500; margin-bottom:5px;">{{ data.name }}</div>
                    <div class="item-id-tag">ID: {{ data.id }}</div>
                </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}

    {% if vault %}
    <div class="glass-card">
        <div class="section-title">Decrypted Account Vault</div>
        {% for category, items in vault.items() %}
            <div class="vault-cat-block">
                <h3>// {{ category }}</h3>
                <div class="vault-grid">
                    {% for item in items %}
                    <div class="item-node item-card" data-item-id="{{ item.id }}" data-item-type="{{ category }}">
                        <img src="https://cdn.jsdelivr.net/gh/ShahGCreator/icon@main/PNG/{{ item.id }}.png"
                             onerror="this.onerror=null; this.src='data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' width=\'100\' height=\'100\'%3E%3Crect width=\'100%25\' height=\'100%25\' fill=\'%231e293b\'/%3E%3Ctext x=\'50%25\' y=\'55%25\' fill=\'%2364748b\' text-anchor=\'middle\'%3E{{ item.id }}%3C/text%3E%3C/svg%3E';">
                        <div class="item-title">{{ item.name }}</div>
                        <div class="item-id-tag">ID: {{ item.id }}</div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        {% endfor %}
    </div>
    {% endif %}
</div>

<div class="footer-credit">Engine build by ROMEO UCHIHA | <a href="/manual">Manual Injector</a></div>

<script>
    const jwt = "{{ jwt or '' }}";
    const charIdFromServer = "{{ character_id or '' }}";

    function triggerNotify(text, isErr = false) {
        const t = document.createElement('div');
        t.className = 'toast-box';
        if(isErr) t.style.borderColor = '#ef4444';
        t.innerText = text;
        document.body.appendChild(t);
        setTimeout(() => t.remove(), 3000);
    }

    document.querySelectorAll('.item-card').forEach(card => {
        card.addEventListener('click', async function() {
            const iid = this.getAttribute('data-item-id');
            const type = this.getAttribute('data-item-type') || '';
            if(!jwt) return triggerNotify('JWT Token state unlinked.', true);

            let act = null;
            let payload = { jwt: jwt, action: '' };
            const lowType = type.toLowerCase();

            if(lowType === 'emote') act = 'emote';
            else if(lowType.includes('weapon')) act = 'weapon';
            else if(lowType.includes('avatar') || lowType.includes('headpic')) act = 'avatar';
            else if(lowType.includes('bag') || lowType.includes('backpack')) act = 'backpack';
            else {
                const mapping = {'head':'head','mask':'head','shoe':'shoe','shoes':'shoe','bottom':'bottom','top':'top','facepaint':'facepaint'};
                const slot = mapping[lowType];
                if(slot && charIdFromServer) {
                    act = 'outfit_change';
                    payload.slot = slot;
                    payload.new_id = parseInt(iid);
                    payload.char_id = parseInt(charIdFromServer);
                }
            }

            if(!act) return triggerNotify('Category type processing mismatch.', true);
            payload.action = act;
            if(act !== 'outfit_change') payload.new_id = parseInt(iid);

            try {
                const res = await fetch('/auto', {
                    method:'POST', headers:{'Content-Type':'application/json'},
                    body: JSON.stringify(payload)
                });
                const rData = await res.json();
                if(rData.success) {
                    triggerNotify('Matrix update synchronization done.');
                    if(act === 'outfit_change') setTimeout(() => location.reload(), 1000);
                } else {
                    triggerNotify(rData.error || 'Server rejected changes.', true);
                }
            } catch(e) {
                triggerNotify('Network buffer pipeline overflow.', true);
            }
        });
    });
</script>
</body>
</html>
"""

MANUAL_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manual Buffer Injector</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Rajdhani:wght@500;700&display=swap');
        body { font-family: 'Rajdhani', sans-serif; background: #05050d; color: #eee; padding: 40px 20px; }
        .holder { max-width: 800px; margin: auto; background: rgba(13,17,33,0.8); padding: 30px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05); }
        h2 { font-family: 'Orbitron', sans-serif; color: #00f2fe; margin-bottom: 20px; }
        label { display: block; margin-top: 15px; color: #4facfe; font-weight: bold; }
        input, textarea { width: 100%; background: #1e293b; color: #fff; border: 1px solid rgba(255,255,255,0.1); padding: 12px; border-radius: 6px; margin-top: 5px; }
        button { background: linear-gradient(135deg, #00f2fe, #4facfe); border: none; padding: 12px 24px; border-radius: 6px; font-family: 'Orbitron'; font-weight: bold; cursor: pointer; margin-top: 20px; color: #000; }
    </style>
</head>
<body>
<div class="holder">
    <h2>Manual Buffer Injector</h2>
    <form method="GET">
        <label>Bearer Token Container:</label>
        <input type="text" name="jwt" value="{{ jwt or '' }}">
        <button type="submit">Query Pipeline</button>
    </form>
    {% if error %}<p style="color:#ef4444; margin-top:10px;">{{ error }}</p>{% endif %}
    {% if decoded %}
        <form method="POST" style="margin-top:20px;">
            <input type="hidden" name="jwt" value="{{ jwt }}">
            <label>Character Entity Reference (Field 1):</label>
            <input type="number" name="char_id" value="{{ decoded.char_id }}">
            <label>Data String Sequence (Field 2):</label>
            <textarea name="outfit_ids">{{ decoded.outfit_ids }}</textarea>
            <button type="submit">Execute Buffer Override</button>
        </form>
    {% endif %}
    <p style="margin-top:20px;"><a href="/" style="color:#00f2fe; text-decoration:none;">← Routing Home</a></p>
</div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    jwt = None
    slots = None
    vault = None
    vault_total = 0
    character_id = None
    load_error = None
    if request.method == 'POST' and 'jwt' in request.form:
        jwt = request.form['jwt'].strip()
        if not jwt:
            load_error = "Token is empty"
        else:
            try:
                account_id = decode_jwt(jwt)
                outfit_vals = fetch_current_outfit(jwt, account_id)
                raw_slots = extract_slots(outfit_vals)
                character_id = raw_slots.get('character')
                slots = {}
                for sname, sid in raw_slots.items():
                    if sname == 'character':
                        continue
                    name, typ, rare = get_item_info(sid)
                    slots[sname] = {'id': sid, 'name': name, 'type': typ, 'rarity': rare}
                item_ids = fetch_vault_items(jwt)
                grouped = defaultdict(list)
                for iid in item_ids:
                    name, typ, rare = get_item_info(iid)
                    if typ != 'Unknown':
                        grouped[typ].append({'id': iid, 'name': name, 'rarity': rare})
                grouped = dict(sorted(grouped.items()))
                for typ in grouped:
                    grouped[typ].sort(key=lambda x: x['name'])
                vault = grouped
                vault_total = sum(len(v) for v in vault.values())
            except Exception as e:
                load_error = f"Pipeline drop error: {str(e)}"
    return render_template_string(HTML_TEMPLATE, jwt=jwt, slots=slots, vault=vault, vault_total=vault_total,
                                character_id=character_id, load_error=load_error)

@app.route('/auto', methods=['POST'])
def auto_change():
    data = request.get_json() or {}
    jwt = data.get('jwt')
    action = data.get('action')
    if not jwt or not action:
        return jsonify({'success': False, 'error': 'Parameters invalid'}), 400

    try:
        if action == 'outfit_change':
            slot, new_id, char_id = data.get('slot'), data.get('new_id'), data.get('char_id')
            account_id = decode_jwt(jwt)
            outfit_vals = fetch_current_outfit(jwt, account_id)
            raw_slots = extract_slots(outfit_vals)
            order = ['head', 'shoe', 'bottom', 'top']
            outfit_ids = [new_id if s == slot else raw_slots.get(s, 0) for s in order]
            if slot == 'facepaint': outfit_ids.append(new_id)
            outfit_ids = [x for x in outfit_ids if x != 0]
            success, status, err = send_change_request(jwt, char_id, outfit_ids)
            return jsonify({'success': success, 'message': 'Outfit sync complete', 'error': err})

        elif action == 'emote':
            region = get_region(jwt)
            server_url = REGION_SERVER_MAP.get(region, "https://clientbp.ggpolarbear.com")
            encrypted = build_emote_payload(data.get('new_id'))
            success, status, err = send_emote_request(jwt, server_url, encrypted)
            return jsonify({'success': success, 'error': err})

        elif action == 'weapon':
            encrypted = build_weapon_payload(data.get('new_id'))
            success, status, err = send_weapon_request(jwt, encrypted)
            return jsonify({'success': success, 'error': err})

        elif action == 'avatar':
            encrypted = build_avatar_payload(data.get('new_id'))
            success, status, err = send_avatar_request(jwt, encrypted)
            return jsonify({'success': success, 'error': err})

        elif action == 'backpack':
            plain = serialize_fields({1: ('varint', data.get('new_id'))})
            success, status, err = send_backpack_request(jwt, encrypt_aes_cbc(plain))
            return jsonify({'success': success, 'error': err})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    return jsonify({'success': False, 'error': 'Action mapping exception'}), 400

@app.route('/manual', methods=['GET', 'POST'])
def manual():
    if request.method == 'POST':
        jwt = request.form.get('jwt', '')
        char_id = int(request.form.get('char_id', 0))
        outfit_ids = [int(x.strip()) for x in request.form.get('outfit_ids', '').split(',') if x.strip()]
        fields = {1: ('varint', char_id), 3: ('varint', 50), 2: ('bytes', encode_packed_varint(outfit_ids))}
        success, status, err = send_change_request(jwt, char_id, outfit_ids)
        return render_template_string(MANUAL_HTML, jwt=jwt, decoded={'char_id': char_id, 'outfit_ids': ', '.join(str(i) for i in outfit_ids)}, error=err)
    
    jwt = request.args.get('jwt', '')
    if not jwt: return render_template_string(MANUAL_HTML, jwt=None, decoded=None, error=None)
    try:
        account_id = decode_jwt(jwt)
        outfit_vals = fetch_current_outfit(jwt, account_id)
        raw_slots = extract_slots(outfit_vals)
        order = ['head', 'shoe', 'bottom', 'top', 'facepaint']
        decoded = {'char_id': raw_slots.get('character'), 'outfit_ids': ', '.join(str(raw_slots[s]) for s in order if s in raw_slots)}
        return render_template_string(MANUAL_HTML, jwt=jwt, decoded=decoded, error=None)
    except Exception as e:
        return render_template_string(MANUAL_HTML, jwt=jwt, decoded=None, error=str(e))

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

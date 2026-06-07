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

def fetch_vault_items(jwt_token, retries=2):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/GetBackpack"
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "Authorization": f"Bearer {jwt_token}",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2022.3.47f1"
    }
    for attempt in range(retries):
        try:
            resp = requests.post(url, headers=headers, data=BACKPACK_BODY, timeout=15)
            if resp.status_code != 200:
                raise Exception(f"GetBackpack HTTP {resp.status_code}")
            raw = resp.content
            plain = decrypt_aes_cbc(raw)
            if plain is None:
                data = raw
            else:
                data = plain
            fields, _ = parse_one_message(data, 0)
            item_ids = collect_ids_from_fields(fields)
            if item_ids:
                return item_ids
        except Exception as e:
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
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2022.3.47f1",
        "ReleaseVersion": "OB53",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {jwt_token}"
    }
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
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2022.3.47f1",
        "ReleaseVersion": "OB53",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {jwt_token}"
    }
    resp = requests.post(url, headers=headers, data=encrypted, timeout=15)
    if resp.status_code == 200:
        return True, 200, None
    else:
        return False, resp.status_code, resp.text


REGION_SERVER_MAP = {
    "BD": "https://clientbp.ggpolarbear.com",
    "IND": "https://client.ind.freefiremobile.com",
    "PK": "https://clientbp.ggpolarbear.com",
    "ME": "https://clientbp.ggpolarbear.com",
    "VN": "https://clientbp.ggpolarbear.com",
    "SG": "https://clientbp.ggpolarbear.com",
    "ID": "https://clientbp.ggpolarbear.com",
    "TH": "https://clientbp.ggpolarbear.com",
    "BR": "https://client.us.freefiremobile.com",
    "NA": "https://client.us.freefiremobile.com",
    "US": "https://client.us.freefiremobile.com",
    "RU": "https://clientbp.ggpolarbear.com",
}

EMOTE_HEADERS = {
    "Accept-Encoding": "gzip",
    "Connection": "Keep-Alive",
    "Content-Type": "application/x-www-form-urlencoded",
    "Expect": "100-continue",
    "ReleaseVersion": "OB53",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)",
    "X-GA": "v1 1",
    "X-Unity-Version": "2018.4.11f1",
}

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

def get_region(jwt_token):
    try:
        parts = jwt_token.split('.')
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        payload_b64 += '=' * (4 - len(payload_b64) % 4)
        payload_json = base64.b64decode(payload_b64)
        data = json.loads(payload_json)
        return data.get("noti_region") or data.get("lock_region")
    except Exception:
        return None

def get_base_url(jwt_token):

    region = get_region(jwt_token)
    if region == "IND":
        return "https://client.ind.freefiremobile.com"
    return "https://clientbp.ggpolarbear.com"

def send_emote_request(jwt_token, base_url, encrypted_payload):
    url = f"{base_url}/ChooseEmote"
    headers = EMOTE_HEADERS.copy()
    headers["Authorization"] = f"Bearer {jwt_token}"
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
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2022.3.47f1",
        "ReleaseVersion": "OB53",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {jwt_token}"
    }
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
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2022.3.47f1",
        "ReleaseVersion": "OB53",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {jwt_token}"
    }
    resp = requests.post(url, headers=headers, data=encrypted_payload, timeout=15)
    if resp.status_code == 200:
        return True, 200, None
    else:
        return False, resp.status_code, resp.text


def send_backpack_request(jwt_token, encrypted_payload):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/ChooseGameBagShow"
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2022.3.47f1",
        "ReleaseVersion": "OB53",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {jwt_token}"
    }
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
        save_pos = idx
        try:
            val, idx = decode_varint(plain_data, idx)
            if val == old_value:
                result.extend(encode_varint(new_value))
                replaced = True
                continue
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

    encrypted = encrypt_aes_cbc(plain)
    return encrypted

def send_select_preset_request(jwt_token, character_id, pet_id):
    base_url = get_base_url(jwt_token)
    url = f"{base_url}/SelectPresetLoadout"
    encrypted_payload = build_select_preset_payload(character_id, pet_id)
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2022.3.47f1",
        "ReleaseVersion": "OB53",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {jwt_token}"
    }
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


def load_item_db():
    try:
        with open("data.json", "r", encoding="utf-8") as f:
            items = json.load(f)
        db = {}
        for it in items:
            iid = it.get('itemID')
            if iid is not None:
                db[iid] = it
        print(f"Loaded {len(db)} items")
        return db
    except Exception as e:
        print(f"Could not load data.json: {e}")
        return {}

ITEM_DB = load_item_db()

def get_item_info(item_id):
    info = ITEM_DB.get(item_id, {})
    name = info.get('name', f'ID {item_id}')
    typ = info.get('type', 'Unknown')
    rare = info.get('Rare', '')
    return name, typ, rare


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


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RIZERxOUTFIT CHANGER - Click Vault to Equip</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: linear-gradient(135deg, #0a0f1e 0%, #0a0f2a 100%);
            font-family: 'Segoe UI', Roboto, sans-serif;
            color: #eee;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: auto; }
        h1 {
            text-align: center;
            color: #ffcc00;
            text-shadow: 0 0 10px #ff9900;
            margin-bottom: 20px;
        }
        .login-card, .outfit-section, .vault-section, .character-section {
            background: rgba(20, 25, 45, 0.9);
            backdrop-filter: blur(5px);
            border-radius: 20px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 8px 20px rgba(0,0,0,0.3);
            border: 1px solid #ffcc0044;
        }
        input, button, select {
            padding: 12px 18px;
            font-size: 1rem;
            border-radius: 40px;
            border: none;
            margin: 8px 0;
        }
        input, select {
            width: auto;
            background: #1e243b;
            color: white;
            border: 1px solid #ffcc00;
        }
        button {
            background: #ffcc00;
            color: #0a0f1e;
            font-weight: bold;
            cursor: pointer;
            transition: 0.2s;
        }
        button:hover { background: #ffaa00; transform: scale(1.02); }
        .error { color: #ff7777; text-align: center; margin-top: 10px; }
        .success { color: #88ff88; text-align: center; }
        .slot-grid, .vault-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .slot-card, .item-card {
            background: #11172b;
            border-radius: 18px;
            padding: 15px;
            text-align: center;
            transition: 0.2s;
            border: 1px solid #2a3450;
            cursor: pointer;
        }
        .slot-card:hover, .item-card:hover { transform: translateY(-5px); border-color: #ffcc00; }
        .slot-icon img, .item-card img {
            width: 100px;
            height: 100px;
            object-fit: contain;
            background: #0a0f1e;
            border-radius: 20px;
            padding: 8px;
        }
        .slot-name {
            font-size: 1.3rem;
            font-weight: bold;
            color: #ffcc00;
            margin: 10px 0 5px;
        }
        .item-name { font-size: 1rem; font-weight: bold; }
        .item-id { font-size: 0.75rem; color: #aaa; margin: 5px 0; }
        .rarity { font-size: 0.7rem; color: #ffaa66; }
        .change-form {
            margin-top: 15px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            justify-content: center;
        }
        .change-form input {
            width: 120px;
            padding: 8px;
            font-size: 0.9rem;
        }
        .change-form button {
            padding: 8px 15px;
            background: #2a3a6a;
            color: white;
        }
        .change-form button:hover { background: #3a4a7a; }
        hr { border-color: #ffcc0044; margin: 20px 0; }
        .footer { text-align: center; margin-top: 30px; font-size: 0.8rem; color: #888; }
        .vault-category {
            margin-bottom: 30px;
        }
        .vault-category h3 {
            color: #ffcc00;
            border-left: 4px solid #ffcc00;
            padding-left: 15px;
            margin-bottom: 15px;
        }
        .slot-selector {
            background: #0f1222;
            padding: 15px;
            border-radius: 20px;
            margin-bottom: 20px;
            text-align: center;
        }
        .slot-selector label {
            font-weight: bold;
            margin-right: 15px;
        }
        select {
            padding: 8px 20px;
            background: #1e243b;
            color: #ffcc00;
            font-weight: bold;
        }
        /* Flash animation classes */
        .flash-success {
            background-color: #2a6a2a !important;
            transition: background-color 0.1s ease;
        }
        .flash-error {
            background-color: #8a2a2a !important;
            transition: background-color 0.1s ease;
        }
        .loading-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            color: #ffcc00;
            font-size: 1.5rem;
            backdrop-filter: blur(5px);
        }
        .toast-message {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #1e243b;
            border-left: 4px solid #ffcc00;
            padding: 12px 20px;
            border-radius: 8px;
            z-index: 1100;
            animation: fadeOut 3s forwards;
        }
        @keyframes fadeOut {
            0% { opacity: 1; }
            70% { opacity: 1; }
            100% { opacity: 0; visibility: hidden; }
        }
        @media (max-width: 700px) {
            input, select { width: 100%; }
            .change-form { flex-direction: column; align-items: center; }
        }
    </style>
</head>
<body>
<div class="container">
    <h1>✨ RIZERxOUTFIT CHANGER ✨</h1>
    <div class="login-card">
        <form id="loginForm" method="post">
            <input type="text" name="jwt" placeholder="Paste your Bearer JWT Token" value="{{ jwt or '' }}" required>
            <button type="submit">🔓 Load Vault & Outfit</button>
        </form>
        {% if load_error %}
            <div class="error">{{ load_error }}</div>
        {% endif %}
    </div>

    {% if slots %}
    <div class="outfit-section">
        <h2 style="color:#ffcc00; margin-bottom:20px;">🎭 Current Outfit</h2>
        <div class="slot-selector">
            <label>🎯 Click vault item to change:</label>
            <select id="targetSlot">
                {% for slot, data in slots.items() %}
                    <option value="{{ slot }}">{{ slot|capitalize }} (current ID: {{ data.id }})</option>
                {% endfor %}
            </select>
        </div>
        <div class="slot-grid">
            {% for slot, data in slots.items() %}
                <div class="slot-card" data-slot-name="{{ slot }}">
                    <div class="slot-icon">
                        <img src="https://cdn.jsdelivr.net/gh/ShahGCreator/icon@main/PNG/{{ data.id }}.png"
                             onerror="this.onerror=null; this.src='data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 100 100\'%3E%3Crect width=\'100\' height=\'100\' fill=\'%23333\'/%3E%3Ctext x=\'50\' y=\'55\' font-size=\'12\' text-anchor=\'middle\' fill=\'%23ffcc00\'%3E{{ data.id }}%3C/text%3E%3C/svg%3E';">
                    </div>
                    <div class="slot-name">{{ slot|capitalize }}</div>
                    <div class="item-name">{{ data.name }}</div>
                    <div class="item-id">ID: {{ data.id }}</div>
                    <div class="rarity">{{ data.rarity }}</div>
                    <div class="change-form">
                        <input type="number" id="new_id_{{ slot }}" value="{{ data.id }}" step="1" placeholder="New ID">
                        <button onclick="changeOutfitSlot('{{ slot }}', '{{ data.id }}', this)">🔄 Change</button>
                    </div>
                </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}

    <!-- Character Change Section -->
    {% if vault and 'Character' in vault %}
    <div class="character-section">
        <h2 style="color:#ffcc00; margin-bottom:20px;">👤 Change Character (keep outfit)</h2>
        <div style="display: flex; gap: 15px; align-items: center; flex-wrap: wrap;">
            <select id="newCharSelect" required>
                <option value="">Select a character</option>
                {% for char in vault['Character'] %}
                    <option value="{{ char.id }}">{{ char.name }} (ID: {{ char.id }})</option>
                {% endfor %}
            </select>
            <button id="changeCharBtn" style="background: #ff8800;">✨ Switch Character</button>
        </div>
        <p style="margin-top:10px; font-size:0.9rem;">✅ Your current outfit (head, shoe, bottom, top, facepaint) will be automatically reapplied.</p>
    </div>
    {% endif %}

    {% if vault %}
    <div class="vault-section">
        <h2 style="color:#ffcc00; margin-bottom:20px;">📦 Your Vault ({{ vault_total }} items)</h2>
        <p style="margin-bottom:10px;">💡 <strong>Click any item</strong> to equip it automatically!<br>
        (Outfit items use the detected slot; Emote, Weapon Skin, Avatar, Backpack/Bag Skins work directly)</p>
        {% for category, items in vault.items() %}
            <div class="vault-category">
                <h3>{{ category }} ({{ items|length }})</h3>
                <div class="vault-grid">
                    {% for item in items %}
                    <div class="item-card" data-item-id="{{ item.id }}" data-item-name="{{ item.name }}" data-item-type="{{ category }}">
                        <img src="https://cdn.jsdelivr.net/gh/ShahGCreator/icon@main/PNG/{{ item.id }}.png"
                             onerror="this.onerror=null; this.src='data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 100 100\'%3E%3Crect width=\'100\' height=\'100\' fill=\'%23333\'/%3E%3Ctext x=\'50\' y=\'55\' font-size=\'12\' text-anchor=\'middle\' fill=\'%23ffcc00\'%3E{{ item.id }}%3C/text%3E%3C/svg%3E';">
                        <div class="item-name">{{ item.name }}</div>
                        <div class="item-id">ID: {{ item.id }}</div>
                        <div class="rarity">{{ item.rarity }}</div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        {% endfor %}
    </div>
    {% endif %}
</div>
<div class="footer">RIZERxOUTFIT · All-in-One Equipper | <a href="/manual" style="color:#ffcc00;">Manual Editor</a></div>

<script>
    const jwt = "{{ jwt or '' }}";
    const charIdFromServer = "{{ character_id or '' }}";

    function showToast(msg, isError = false) {
        const toast = document.createElement('div');
        toast.className = 'toast-message';
        toast.style.backgroundColor = isError ? '#5a1e1e' : '#1e3a2e';
        toast.style.borderLeftColor = isError ? '#ff7777' : '#88ff88';
        toast.innerText = msg;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    }

    function flashElement(element, success) {
        if (!element) return;
        element.classList.add(success ? 'flash-success' : 'flash-error');
        setTimeout(() => {
            element.classList.remove('flash-success', 'flash-error');
        }, 1000);
    }

    async function callAutoAction(payload, targetElement) {
        try {
            const response = await fetch('/auto', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const result = await response.json();
            if (result.success) {
                showToast(result.message || 'Success!');
                if (targetElement) flashElement(targetElement, true);
            } else {
                showToast(result.error || 'Failed', true);
                if (targetElement) flashElement(targetElement, false);
            }
            return result;
        } catch (err) {
            showToast('Network error: ' + err.message, true);
            if (targetElement) flashElement(targetElement, false);
            return { success: false, error: err.message };
        }
    }

    async function changeOutfitSlot(slot, currentId, btnElement) {
        const newIdInput = document.getElementById(`new_id_${slot}`);
        if (!newIdInput) return;
        const newId = parseInt(newIdInput.value);
        if (isNaN(newId)) return;
        if (newId == currentId) {
            showToast('Item already equipped', false);
            return;
        }
        const slotCard = btnElement.closest('.slot-card');
        const result = await callAutoAction({
            action: 'outfit_change',
            jwt: jwt,
            slot: slot,
            new_id: newId,
            char_id: parseInt(charIdFromServer)
        }, slotCard);
        if (result.success) {
            setTimeout(() => location.reload(), 1200);
        }
    }

    document.getElementById('changeCharBtn')?.addEventListener('click', async () => {
        const select = document.getElementById('newCharSelect');
        const newCharId = select.value;
        if (!newCharId) {
            showToast('Please select a character', true);
            return;
        }
        const btn = document.getElementById('changeCharBtn');
        const result = await callAutoAction({
            action: 'change_character',
            jwt: jwt,
            new_char_id: parseInt(newCharId)
        }, btn);
        if (result.success) {
            setTimeout(() => location.reload(), 1200);
        }
    });

    document.querySelectorAll('.item-card').forEach(card => {
        card.addEventListener('click', async function(e) {
            const itemId = this.getAttribute('data-item-id');
            const itemType = this.getAttribute('data-item-type') || '';
            if (!jwt) {
                showToast('JWT missing. Please reload the page.', true);
                return;
            }

            let action = null;
            let payload = { jwt: jwt, action: '' };

            const typeLower = itemType.toLowerCase();
            if (typeLower === 'emote') {
                action = 'emote';
            } else if (typeLower.includes('weapon skin')) {
                action = 'weapon';
            } else if (typeLower === 'avatars' || typeLower === 'headpic') {
                action = 'avatar';
            } else if (typeLower.includes('bag') || typeLower.includes('backpack')) {
                action = 'backpack';
            } else {
                const slotMap = {
                    'head': 'head', 'mask': 'head', 'shoe': 'shoe', 'shoes': 'shoe',
                    'bottom': 'bottom', 'top': 'top', 'facepaint': 'facepaint'
                };
                const slot = slotMap[typeLower];
                if (slot && charIdFromServer) {
                    action = 'outfit_change';
                    payload.slot = slot;
                    payload.new_id = parseInt(itemId);
                    payload.char_id = parseInt(charIdFromServer);
                } else {
                    showToast(`Cannot determine outfit slot for type: ${itemType}`, true);
                    flashElement(this, false);
                    return;
                }
            }

            if (!action) {
                showToast(`Unsupported item type: ${itemType}`, true);
                flashElement(this, false);
                return;
            }
            payload.action = action;
            if (action !== 'outfit_change') payload.new_id = parseInt(itemId);

            const result = await callAutoAction(payload, this);
            if (result.success && action !== 'outfit_change') {
                // non-outfit actions don't need full reload
            } else if (result.success && action === 'outfit_change') {
                setTimeout(() => location.reload(), 1200);
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
    <title>Manual Outfit Editor</title>
    <style>
        body { font-family: monospace; background: #0a0f1e; color: #eee; padding: 20px; }
        h2, h3 { color: #ffcc00; }
        .container { max-width: 900px; margin: auto; }
        label { display: block; margin-top: 15px; color: #ffcc00; }
        input, textarea {
            width: 100%; background: #1e243b; color: #fff; border: 1px solid #ffcc00;
            padding: 10px; font-family: monospace; margin-top: 5px;
        }
        textarea { height: 120px; }
        button { padding: 10px 20px; margin: 15px 0; background: #ffcc00; color: #000; font-weight: bold; cursor: pointer; border: none; border-radius: 4px; }
        .error { color: #ff7777; }
        .success { color: #88ff88; }
    </style>
</head>
<body>
<div class="container">
    <h2>Manual Outfit Editor</h2>
    <form method="GET">
        <label>JWT Token:</label>
        <input type="text" name="jwt" value="{{ jwt or '' }}" placeholder="Paste your JWT">
        <button type="submit">Load Current Outfit</button>
    </form>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    {% if decoded %}
        <h3>Decoded ChangeClothes Request (Edit & Send)</h3>
        <form method="POST">
            <input type="hidden" name="jwt" value="{{ jwt }}">
            <label>Field 1 (Character ID):</label>
            <input type="number" name="char_id" value="{{ decoded.char_id }}">
            <label>Field 3 (Unknown constant):</label>
            <input type="number" name="const_val" value="{{ decoded.const_val }}">
            <label>Field 2 (Outfit IDs – comma separated, order: head,shoe,bottom,top,facepaint):</label>
            <textarea name="outfit_ids">{{ decoded.outfit_ids }}</textarea>
            <button type="submit">Send Edited Request</button>
        </form>
    {% endif %}
    {% if result %}
        <div class="{{ 'success' if result.success else 'error' }}">
            {% if result.success %}✅ Sent successfully (HTTP 200){% else %}❌ Failed (HTTP {{ result.status }}) – {{ result.error }}{% endif %}
        </div>
    {% endif %}
    <p style="margin-top:30px;"><a href="/" style="color:#ffcc00;">← Back to main</a></p>
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
            load_error = "Token is required"
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
                load_error = f"Failed to load data: {str(e)}"
    return render_template_string(HTML_TEMPLATE, jwt=jwt, slots=slots, vault=vault, vault_total=vault_total,
                                character_id=character_id, load_error=load_error)

@app.route('/auto', methods=['POST'])
def auto_change():

    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'Invalid request, JSON expected'}), 400

    jwt = data.get('jwt')
    action = data.get('action')
    if not jwt or not action:
        return jsonify({'success': False, 'error': 'Missing jwt or action'}), 400

    try:
        if action == 'outfit_change':
            slot = data.get('slot')
            new_id = data.get('new_id')
            char_id = data.get('char_id')
            if not all([slot, new_id, char_id]):
                return jsonify({'success': False, 'error': 'Missing slot/new_id/char_id'}), 400

            account_id = decode_jwt(jwt)
            outfit_vals = fetch_current_outfit(jwt, account_id)
            raw_slots = extract_slots(outfit_vals)
            if raw_slots.get(slot) == new_id:
                return jsonify({'success': False, 'error': 'Item already equipped in that slot'}), 400
            order = ['head', 'shoe', 'bottom', 'top']
            outfit_ids = []
            for s in order:
                if s == slot:
                    outfit_ids.append(new_id)
                else:
                    if s in raw_slots:
                        outfit_ids.append(raw_slots[s])
            if slot == 'facepaint':
                outfit_ids.append(new_id)
            if not outfit_ids:
                return jsonify({'success': False, 'error': 'No valid slot to change'}), 400
            success, status, error_text = send_change_request(jwt, char_id, outfit_ids)
            if success:
                return jsonify({'success': True, 'message': 'Outfit changed successfully'})
            else:
                return jsonify({'success': False, 'status': status, 'error': error_text}), 400

        elif action == 'emote':
            new_id = data.get('new_id')
            if not new_id:
                return jsonify({'success': False, 'error': 'Missing new_id'}), 400
            region = get_region(jwt)
            if not region:
                return jsonify({'success': False, 'error': 'Could not detect region from JWT'}), 400
            server_url = REGION_SERVER_MAP.get(region)
            if not server_url:
                return jsonify({'success': False, 'error': f'No server for region {region}'}), 400
            encrypted = build_emote_payload(new_id)
            success, status, error_text = send_emote_request(jwt, server_url, encrypted)
            if success:
                return jsonify({'success': True, 'message': 'Emote equipped'})
            else:
                return jsonify({'success': False, 'status': status, 'error': error_text}), 400

        elif action == 'weapon':
            new_id = data.get('new_id')
            if not new_id:
                return jsonify({'success': False, 'error': 'Missing new_id'}), 400
            encrypted = build_weapon_payload(new_id)
            success, status, error_text = send_weapon_request(jwt, encrypted)
            if success:
                return jsonify({'success': True, 'message': 'Weapon skin equipped'})
            else:
                return jsonify({'success': False, 'status': status, 'error': error_text}), 400

        elif action == 'avatar':
            new_id = data.get('new_id')
            if not new_id:
                return jsonify({'success': False, 'error': 'Missing new_id'}), 400
            encrypted = build_avatar_payload(new_id)
            success, status, error_text = send_avatar_request(jwt, encrypted)
            if success:
                return jsonify({'success': True, 'message': 'Avatar changed'})
            else:
                return jsonify({'success': False, 'status': status, 'error': error_text}), 400

        elif action == 'backpack':
            new_id = data.get('new_id')
            if not new_id:
                return jsonify({'success': False, 'error': 'Missing new_id'}), 400
            fields = {1: ('varint', new_id)}
            plain = serialize_fields(fields)
            encrypted = encrypt_aes_cbc(plain)
            success, status, error_text = send_backpack_request(jwt, encrypted)
            if success:
                return jsonify({'success': True, 'message': 'Backpack skin equipped'})
            else:
                return jsonify({'success': False, 'status': status, 'error': error_text}), 400

        elif action == 'change_character':
            new_char_id = data.get('new_char_id')
            if not new_char_id:
                return jsonify({'success': False, 'error': 'Missing new_char_id'}), 400
            # get current outfit
            account_id = decode_jwt(jwt)
            outfit_vals = fetch_current_outfit(jwt, account_id)
            raw_slots = extract_slots(outfit_vals)
            outfit_order = ['head', 'shoe', 'bottom', 'top', 'facepaint']
            outfit_ids = [raw_slots[s] for s in outfit_order if s in raw_slots]
            if not outfit_ids:
                return jsonify({'success': False, 'error': 'No outfit items to preserve'}), 400

            vault_ids = fetch_vault_items(jwt)
            pet_id = 1300000113
            for iid in vault_ids:
                _, typ, _ = get_item_info(iid)
                if typ.lower() == 'pet':
                    pet_id = iid
                    break

            success, status, error_text = send_select_preset_request(jwt, new_char_id, pet_id)
            if not success:
                return jsonify({'success': False, 'status': status, 'error': error_text}), 400

            success2, status2, error_text2 = send_change_request(jwt, new_char_id, outfit_ids)
            if success2:
                return jsonify({'success': True, 'message': f'Character changed to {new_char_id} with outfit preserved'})
            else:
                return jsonify({'success': False, 'status': status2, 'error': error_text2}), 400

        else:
            return jsonify({'success': False, 'error': f'Unknown action: {action}'}), 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/manual', methods=['GET', 'POST'])
def manual():
    if request.method == 'POST':
        jwt = request.form.get('jwt', '')
        char_id_str = request.form.get('char_id', '')
        const_val_str = request.form.get('const_val', '')
        outfit_ids_str = request.form.get('outfit_ids', '')
        if not jwt or not char_id_str or not outfit_ids_str:
            return render_template_string(MANUAL_HTML, jwt=jwt, error="Missing fields", result=None)
        try:
            char_id = int(char_id_str)
            const_val = int(const_val_str) if const_val_str else 50
            parts = [x.strip() for x in outfit_ids_str.split(',') if x.strip()]
            outfit_ids = [int(p) for p in parts]
        except Exception as e:
            return render_template_string(MANUAL_HTML, jwt=jwt, error=f"Invalid input: {e}", result=None)
        fields = {
            1: ('varint', char_id),
            3: ('varint', const_val),
            2: ('bytes', encode_packed_varint(outfit_ids))
        }
        plain_bytes = serialize_fields(fields)
        encrypted = encrypt_aes_cbc(plain_bytes)
        base_url = get_base_url(jwt)
        url = f"{base_url}/ChangeClothes"
        headers = {
            "User-Agent": "UnityPlayer/2022.3.47f1",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/octet-stream",
            "X-Unity-Version": "2022.3.47f1",
            "ReleaseVersion": "OB53",
            "X-GA": "v1 1",
            "Authorization": f"Bearer {jwt}"
        }
        try:
            resp = requests.post(url, headers=headers, data=encrypted, timeout=15)
            if resp.status_code == 200:
                result = {'success': True, 'status': 200, 'error': ''}
            else:
                result = {'success': False, 'status': resp.status_code, 'error': resp.text}
        except Exception as e:
            result = {'success': False, 'status': 0, 'error': str(e)}
        return render_template_string(MANUAL_HTML, jwt=jwt, decoded={'char_id': char_id, 'const_val': const_val, 'outfit_ids': ', '.join(str(i) for i in outfit_ids)}, result=result)

    jwt = request.args.get('jwt', '')
    if not jwt:
        return render_template_string(MANUAL_HTML, jwt=None, error=None, result=None)
    try:
        account_id = decode_jwt(jwt)
        outfit_vals = fetch_current_outfit(jwt, account_id)
        raw_slots = extract_slots(outfit_vals)
        char_id = raw_slots.get('character')
        if not char_id:
            raise ValueError("Character ID not found in outfit")
        order = ['head', 'shoe', 'bottom', 'top', 'facepaint']
        outfit_ids = [raw_slots[s] for s in order if s in raw_slots]
        const_val = 50
        decoded = {
            'char_id': char_id,
            'const_val': const_val,
            'outfit_ids': ', '.join(str(i) for i in outfit_ids)
        }
        return render_template_string(MANUAL_HTML, jwt=jwt, decoded=decoded, error=None, result=None)
    except Exception as e:
        return render_template_string(MANUAL_HTML, jwt=jwt, error=str(e), result=None)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
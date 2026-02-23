import json
import time
import logging
import socket
import sys
import os
import base64
import binascii
import requests
import jwt
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.json_format import MessageToJson

import jwt_generator_pb2
import MajorLoginRes_pb2

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from protobuf_decoder.protobuf_decoder import Parser
from important_zitado import *
from byte import *


# ═══════════════════════════════════════════════════════════════
# 📌 إعدادات السرعة الخارقة
# ═══════════════════════════════════════════════════════════════
REQUEST_INTERVAL = 0.5  # إرسال طلب كل 0.5 ثانية
SOCKET_TIMEOUT = 1  # timeout سريع
REQUEST_TIMEOUT = 3  # timeout للـ API

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("ff_login_aggressive.log"),
        logging.StreamHandler(sys.stdout),
    ],
)


def encrypt_packet(plain_text, key, iv):
    """تشفير الحزمة"""
    if isinstance(key, str):
        key = bytes.fromhex(key)
    if isinstance(iv, str):
        iv = bytes.fromhex(iv)
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()


def encrypt_api(plain_text):
    """تشفير API"""
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()


def parse_results(parsed_results):
    """تحليل Protobuf"""
    result_dict = {}
    for result in parsed_results:
        field_data = {"wire_type": result.wire_type}
        if result.wire_type in ("varint", "string", "bytes"):
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict


def get_available_room(input_text):
    """الحصول على الغرفة"""
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_dict = parse_results(parsed_results)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except:
        return None


def dec_to_hex(ask: int) -> str:
    """تحويل للهيكس"""
    ask_result = hex(ask)
    final_result = str(ask_result)[2:]
    if len(final_result) == 1:
        final_result = "0" + final_result
    return final_result


class SimpleProtobuf:
    @staticmethod
    def encode_varint(value):
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)
    
    @staticmethod
    def encode_string(field_number, value):
        if isinstance(value, str):
            value = value.encode('utf-8')
        result = bytearray()
        result.extend(SimpleProtobuf.encode_varint((field_number << 3) | 2))
        result.extend(SimpleProtobuf.encode_varint(len(value)))
        result.extend(value)
        return bytes(result)
    
    @staticmethod
    def encode_int32(field_number, value):
        result = bytearray()
        result.extend(SimpleProtobuf.encode_varint((field_number << 3) | 0))
        result.extend(SimpleProtobuf.encode_varint(value))
        return bytes(result)
    
    @staticmethod
    def create_login_payload(open_id, access_token, platform):
        """بناء payload"""
        payload = bytearray()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        payload.extend(SimpleProtobuf.encode_string(3, current_time))
        payload.extend(SimpleProtobuf.encode_string(4, 'free fire'))
        payload.extend(SimpleProtobuf.encode_int32(5, platform))
        payload.extend(SimpleProtobuf.encode_string(7, '1.120.1'))
        payload.extend(SimpleProtobuf.encode_string(8, 'Android OS 7.1.2 / API-23 (N2G48H/70025024)'))
        payload.extend(SimpleProtobuf.encode_string(9, 'Handheld'))
        payload.extend(SimpleProtobuf.encode_string(10, 'Android'))
        payload.extend(SimpleProtobuf.encode_string(11, 'WIFI'))
        payload.extend(SimpleProtobuf.encode_int32(12, 3136))
        payload.extend(SimpleProtobuf.encode_int32(13, 1668))
        payload.extend(SimpleProtobuf.encode_string(14, '320'))
        payload.extend(SimpleProtobuf.encode_string(15, 'ARMv7 VFPv3 NEON VFH | 2465 | 4'))
        payload.extend(SimpleProtobuf.encode_int32(16, 1))
        payload.extend(SimpleProtobuf.encode_string(17, 'Adreno (TM) 640'))
        payload.extend(SimpleProtobuf.encode_string(18, 'OpenGL ES 3.1'))
        payload.extend(SimpleProtobuf.encode_string(19, 'Google|dbc5b426-9715-454a-9466-6c82e151d407'))
        payload.extend(SimpleProtobuf.encode_string(20, '197.1.12.135'))
        payload.extend(SimpleProtobuf.encode_string(21, 'en'))
        payload.extend(SimpleProtobuf.encode_string(22, open_id))
        payload.extend(SimpleProtobuf.encode_string(23, str(platform)))
        payload.extend(SimpleProtobuf.encode_string(24, 'Handheld'))
        payload.extend(SimpleProtobuf.encode_string(25, 'samsung SM-G955N'))
        payload.extend(SimpleProtobuf.encode_string(29, access_token))
        payload.extend(SimpleProtobuf.encode_int32(30, 1))
        payload.extend(SimpleProtobuf.encode_string(41, 'Android'))
        payload.extend(SimpleProtobuf.encode_string(42, 'WIFI'))
        payload.extend(SimpleProtobuf.encode_string(57, '7428b253defc164018c604a1ebbfebdf'))
        payload.extend(SimpleProtobuf.encode_int32(60, 27050))
        payload.extend(SimpleProtobuf.encode_int32(61, 1417))
        payload.extend(SimpleProtobuf.encode_int32(62, 27547))
        payload.extend(SimpleProtobuf.encode_int32(63, 3855))
        payload.extend(SimpleProtobuf.encode_int32(64, 2222))
        payload.extend(SimpleProtobuf.encode_int32(65, 27547))
        payload.extend(SimpleProtobuf.encode_int32(66, 2222))
        payload.extend(SimpleProtobuf.encode_int32(67, 27547))
        payload.extend(SimpleProtobuf.encode_int32(73, 3))
        payload.extend(SimpleProtobuf.encode_string(74, '/data/app/com.dts.freefireth-1/lib/arm'))
        payload.extend(SimpleProtobuf.encode_int32(76, 1))
        payload.extend(SimpleProtobuf.encode_string(77, '20876f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-1/base.apk'))
        payload.extend(SimpleProtobuf.encode_int32(78, 3))
        payload.extend(SimpleProtobuf.encode_int32(79, 1))
        payload.extend(SimpleProtobuf.encode_string(81, '32'))
        payload.extend(SimpleProtobuf.encode_string(83, '2019118693'))
        payload.extend(SimpleProtobuf.encode_int32(85, 3))
        payload.extend(SimpleProtobuf.encode_string(86, 'OpenGLES2'))
        payload.extend(SimpleProtobuf.encode_int32(87, 32767))
        payload.extend(SimpleProtobuf.encode_int32(88, 4))
        payload.extend(SimpleProtobuf.encode_int32(92, 55753))
        payload.extend(SimpleProtobuf.encode_string(93, 'android'))
        payload.extend(SimpleProtobuf.encode_string(94, 'KqsHT9GHbXvWLfhCyPAlRRhsbmCgeRUubUUQ1sutmRU6cN0RO7QE1AHnIdt8YcxMaLWT7cmHQ2+sttRy7x0f95T+dVY='))
        payload.extend(SimpleProtobuf.encode_int32(97, 1))
        payload.extend(SimpleProtobuf.encode_int32(98, 1))
        payload.extend(SimpleProtobuf.encode_string(99, str(platform)))
        payload.extend(SimpleProtobuf.encode_string(100, str(platform)))
        payload.extend(SimpleProtobuf.encode_string(102, ''))
        
        return bytes(payload)


# ═══════════════════════════════════════════════════════════════
# 🔥 FF_CLIENT_AGGRESSIVE - إرسال متكرر
# ═══════════════════════════════════════════════════════════════
class FF_CLIENT_AGGRESSIVE:
    def __init__(self, account_name, access_token, open_id=None):
        self.account_name = account_name
        self.access_token = access_token
        
        # Cache
        self.cached_open_id = open_id
        self.cached_platform = None
        self.cached_token = None
        self.cached_key = None
        self.cached_iv = None
        self.cached_online_ip = None
        self.cached_online_port = None
        self.cached_final_token = None
        
        self.request_count = 0
        
        logging.info(f"🔥 بدء {self.account_name}")

    def parse_my_message(self, serialized_data):
        """تحليل الرسالة"""
        MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv, BASE64_TOKEN

    def GET_PAYLOAD_BY_DATA(self, JWT_TOKEN, NEW_ACCESS_TOKEN):
        """الحصول على البيانات"""
        token_payload_base64 = JWT_TOKEN.split(".")[1]
        token_payload_base64 += "=" * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode("utf-8")
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload["external_id"]
        SIGNATURE_MD5 = decoded_payload["signature_md5"]

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        payload = bytes.fromhex(
            "1a13323032352d30372d33302031313a30323a3531220966726565206669726528083a07312e3132302e31422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c64626335623432362d393731352d343534612d393436362d366338326531353164343037a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676552557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033"
        )
        payload = payload.replace(b"2025-07-30 11:02:51", str(now).encode())
        payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        
        PAYLOAD = encrypt_api(payload.hex())
        PAYLOAD = bytes.fromhex(PAYLOAD)
        
        return self.GET_LOGIN_DATA(JWT_TOKEN, PAYLOAD)

    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        """جلب بيانات السيرفر"""
        url = "https://clientbp.ggpolarbear.com/GetLoginData"
        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {JWT_TOKEN}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB52",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)",
            "Host": "clientbp.common.ggbluefox.com",
            "Connection": "close",
            "Accept-Encoding": "gzip, deflate, br",
        }

        try:
            response = requests.post(url, headers=headers, data=PAYLOAD, verify=False, timeout=REQUEST_TIMEOUT)
            x = response.content.hex()
            json_result = get_available_room(x)
            if not json_result:
                return None, None, None, None
            parsed_data = json.loads(json_result)

            whisper_address = parsed_data["32"]["data"]
            online_address = parsed_data["14"]["data"]
            
            online_ip = online_address[: len(online_address) - 6]
            whisper_ip = whisper_address[: len(whisper_address) - 6]
            online_port = int(online_address[len(online_address) - 5 :])
            whisper_port = int(whisper_address[len(whisper_address) - 5 :])
            
            return whisper_ip, whisper_port, online_ip, online_port

        except:
            return None, None, None, None

    def inspect_access_token(self, access_token):
        """فحص Token"""
        if self.cached_open_id and self.cached_platform:
            return self.cached_open_id, self.cached_platform
            
        inspect_url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
        inspect_headers = {
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)"
        }
        
        try:
            response = requests.get(inspect_url, headers=inspect_headers, timeout=REQUEST_TIMEOUT, verify=False)
            data = response.json()
            
            if 'error' in data:
                return None, None
            
            open_id = data.get('open_id')
            platform = data.get('platform')
            
            if open_id and platform is not None:
                self.cached_open_id = open_id
                self.cached_platform = platform
                return open_id, platform
            return None, None
                
        except:
            return None, None

    def prepare_login_data(self):
        """تحضير بيانات تسجيل الدخول (مرة واحدة)"""
        logging.info(f"⚙️ تحضير بيانات {self.account_name}...")
        
        # جلب OpenID & Platform
        verified_open_id, detected_platform = self.inspect_access_token(self.access_token)
        if not verified_open_id:
            logging.error(f"❌ فشل فحص Token")
            return False
        
        logging.info(f"✅ OpenID: {verified_open_id}, Platform: {detected_platform}")
        
        # بناء Payload
        data = SimpleProtobuf.create_login_payload(verified_open_id, self.access_token, detected_platform)
        hex_data = data.hex()
        encrypted_data = encrypt_api(hex_data)
        Final_Payload = bytes.fromhex(encrypted_data)
        
        # إرسال MajorLogin
        headers = {
            "X-Unity-Version": "2018.4.11f1",
            "ReleaseVersion": "OB52",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-GA": "v1 1",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)",
            "Host": "loginbp.ggblueshark.com",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
        }
        
        URL = "https://loginbp.ggpolarbear.com/MajorLogin"
        
        try:
            RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False, timeout=REQUEST_TIMEOUT)
            if RESPONSE.status_code != 200 or len(RESPONSE.content) < 10:
                return False
        except:
            return False
        
        # تحليل
        try:
            combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
            self.cached_key = key
            self.cached_iv = iv
            self.cached_token = BASE64_TOKEN
        except:
            return False
        
        # جلب IPs
        try:
            whisper_ip, whisper_port, online_ip, online_port = self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN, self.access_token)
            if not online_ip:
                return False
            self.cached_online_ip = online_ip
            self.cached_online_port = online_port
        except:
            return False
        
        # بناء Final Token
        try:
            decoded = jwt.decode(BASE64_TOKEN, options={"verify_signature": False})
            account_id = decoded.get("account_id")
            encoded_acc = hex(account_id)[2:]
            hex_value = dec_to_hex(combined_timestamp)
            BASE64_TOKEN_ = BASE64_TOKEN.encode().hex()
            
            head_len = len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2
            head_len_hex = hex(head_len)[2:]
            
            length = len(encoded_acc)
            zeros_map = {9: "0000000", 8: "00000000", 10: "000000", 7: "000000000"}
            zeros = zeros_map.get(length, "00000000")
            
            head = f"0115{zeros}{encoded_acc}{hex_value}00000{head_len_hex}"
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
            
            self.cached_final_token = final_token
            
        except:
            return False
        
        logging.info(f"✅ {self.account_name} جاهز!")
        return True

    def send_single_request(self):
        """إرسال طلب واحد"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(SOCKET_TIMEOUT)
            
            sock.connect((self.cached_online_ip, self.cached_online_port))
            sock.send(bytes.fromhex(self.cached_final_token))
            
            data = sock.recv(4096)
            
            if data:
                self.request_count += 1
                logging.info(f"✅ طلب #{self.request_count} نجح - {self.account_name} Online!")
                return True
            
            sock.close()
            return False
                    
        except Exception as e:
            return False

    def aggressive_loop(self):
        """حلقة الإرسال المتكرر - كل 0.5 ثانية"""
        logging.info(f"🔥 بدء الحلقة الذكية لـ {self.account_name}")
        logging.info(f"📡 إرسال طلب كل {REQUEST_INTERVAL} ثانية...")
        
        while True:
            try:
                success = self.send_single_request()
                
                if not success:
                    logging.warning(f"⚠️ طلب فشل - إعادة المحاولة...")
                
                # انتظار 0.5 ثانية قبل الطلب التالي
                time.sleep(REQUEST_INTERVAL)
                
            except KeyboardInterrupt:
                logging.info(f"🛑 إيقاف {self.account_name}")
                break
            except Exception as e:
                logging.error(f"❌ خطأ: {e}")
                time.sleep(REQUEST_INTERVAL)
                continue

    def run(self):
        """تشغيل البوت"""
        # تحضير البيانات مرة واحدة
        if not self.prepare_login_data():
            logging.error(f"❌ فشل تحضير بيانات {self.account_name}")
            return False
        
        # بدء الحلقة المتكررة
        self.aggressive_loop()


# ═══════════════════════════════════════════════════════════════
# 🚀 البرنامج الرئيسي
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("🔥 Free Fire Aggressive Mode")
    print("🔥 إرسال متكرر كل 0.5 ثانية - بدون توقف")
    print("=" * 60)
    print()
    
    try:
        with open("config.json", "r", encoding="utf-8") as file:
            config = json.load(file)
    except:
        logging.error("❌ خطأ في config.json")
        sys.exit(1)
    
    accounts = config.get("accounts", [])
    
    if not accounts:
        logging.error("❌ لا توجد حسابات!")
        sys.exit(1)
    
    # تشغيل الحسابات بدون threading
    for account in accounts:
        if not account.get("enabled", True):
            continue
        
        name = account.get("name", "Unknown")
        access_token = account.get("access_token", "")
        open_id = account.get("open_id", None)
        
        if not access_token:
            logging.error(f"❌ Token مفقود: {name}")
            continue
        
        try:
            client = FF_CLIENT_AGGRESSIVE(name, access_token, open_id)
            client.run()  # يشتغل مباشرة بدون threading
        except KeyboardInterrupt:
            logging.info("🛑 إيقاف البرنامج")
            sys.exit(0)
        except Exception as e:
            logging.error(f"❌ {name}: {e}")
            continue

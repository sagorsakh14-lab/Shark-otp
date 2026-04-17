import requests
import json
import time
import re
import asyncio
from telegram import Bot
from telegram.error import TelegramError
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
import logging
from datetime import datetime

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class OTPMonitorBot:
    def __init__(self, telegram_token, group_chat_id, session_cookie, target_url, target_host, csstr_param, timestamp_param):
        self.telegram_token = telegram_token
        self.group_chat_id = group_chat_id
        self.session_cookie = session_cookie
        self.target_url = target_url
        self.target_host = target_host
        self.csstr_param = csstr_param
        self.timestamp_param = timestamp_param
        self.processed_otps = set()
        self.processed_count = 0
        self.start_time = datetime.now()
        self.total_otps_sent = 0
        self.last_otp_time = None
        self.is_monitoring = True

        # OTP patterns
        self.otp_patterns = [
            r'#(\d{3}\s\d{3})',                # #209 658 (Instagram)
            r'(?<!\d)(\d{3})\s(\d{3})(?!\d)',  # 209 658
            r'(?<!\d)(\d{3})-(\d{3})(?!\d)',   # 209-658
            r'code[:\s]+(\d{4,8})',             # code: 123456
            r'কোড[:\s]+(\d{4,8})',              # code in Bengali
            r'(?<!\d)(\d{6})(?!\d)',            # 6 digits
            r'(?<!\d)(\d{5})(?!\d)',            # 5 digits
            r'(?<!\d)(\d{4})(?!\d)',            # 4 digits
            r'#\s*([A-Za-z0-9]{6,20})',         # # 78581H29QFsn4Sr (Facebook style)
            r'\b([A-Z0-9]{6,12})\b',            # pure alphanumeric caps code
        ]

    def hide_phone_number(self, phone_number):
        phone_str = str(phone_number)
        if len(phone_str) >= 8:
            return phone_str[:5] + '***' + phone_str[-4:]
        return phone_str

    def extract_operator_name(self, operator):
        parts = str(operator).split()
        if parts:
            return parts[0]
        return str(operator)

    def get_country_flag(self, phone_number, operator=''):
        """Phone prefix বা operator থেকে country flag + code বের করে"""
        phone = str(phone_number).strip().lstrip('+')
        op = str(operator).upper()

        country_map = {
            # ── North America ──
            '1':    ('🇺🇸', 'US'),
            '1242': ('🇧🇸', 'BS'),  # Bahamas
            '1246': ('🇧🇧', 'BB'),  # Barbados
            '1264': ('🇦🇮', 'AI'),  # Anguilla
            '1268': ('🇦🇬', 'AG'),  # Antigua & Barbuda
            '1284': ('🇻🇬', 'VG'),  # British Virgin Islands
            '1340': ('🇻🇮', 'VI'),  # US Virgin Islands
            '1345': ('🇰🇾', 'KY'),  # Cayman Islands
            '1441': ('🇧🇲', 'BM'),  # Bermuda
            '1473': ('🇬🇩', 'GD'),  # Grenada
            '1649': ('🇹🇨', 'TC'),  # Turks & Caicos
            '1664': ('🇲🇸', 'MS'),  # Montserrat
            '1670': ('🇲🇵', 'MP'),  # Northern Mariana Islands
            '1671': ('🇬🇺', 'GU'),  # Guam
            '1684': ('🇦🇸', 'AS'),  # American Samoa
            '1721': ('🇸🇽', 'SX'),  # Sint Maarten
            '1758': ('🇱🇨', 'LC'),  # Saint Lucia
            '1767': ('🇩🇲', 'DM'),  # Dominica
            '1784': ('🇻🇨', 'VC'),  # Saint Vincent
            '1787': ('🇵🇷', 'PR'),  # Puerto Rico
            '1809': ('🇩🇴', 'DO'),  # Dominican Republic
            '1868': ('🇹🇹', 'TT'),  # Trinidad & Tobago
            '1869': ('🇰🇳', 'KN'),  # Saint Kitts & Nevis
            '1876': ('🇯🇲', 'JM'),  # Jamaica
            '1939': ('🇵🇷', 'PR'),  # Puerto Rico alt

            # ── Russia / CIS ──
            '7':    ('🇷🇺', 'RU'),
            '76':   ('🇰🇿', 'KZ'),  # Kazakhstan (also +7)
            '77':   ('🇰🇿', 'KZ'),

            # ── Europe ──
            '20':   ('🇪🇬', 'EG'),
            '27':   ('🇿🇦', 'ZA'),
            '30':   ('🇬🇷', 'GR'),
            '31':   ('🇳🇱', 'NL'),
            '32':   ('🇧🇪', 'BE'),
            '33':   ('🇫🇷', 'FR'),
            '34':   ('🇪🇸', 'ES'),
            '350':  ('🇬🇮', 'GI'),  # Gibraltar
            '351':  ('🇵🇹', 'PT'),
            '352':  ('🇱🇺', 'LU'),
            '353':  ('🇮🇪', 'IE'),
            '354':  ('🇮🇸', 'IS'),
            '355':  ('🇦🇱', 'AL'),
            '356':  ('🇲🇹', 'MT'),
            '357':  ('🇨🇾', 'CY'),
            '358':  ('🇫🇮', 'FI'),
            '359':  ('🇧🇬', 'BG'),
            '36':   ('🇭🇺', 'HU'),
            '370':  ('🇱🇹', 'LT'),
            '371':  ('🇱🇻', 'LV'),
            '372':  ('🇪🇪', 'EE'),
            '373':  ('🇲🇩', 'MD'),
            '374':  ('🇦🇲', 'AM'),
            '375':  ('🇧🇾', 'BY'),
            '376':  ('🇦🇩', 'AD'),
            '377':  ('🇲🇨', 'MC'),
            '378':  ('🇸🇲', 'SM'),
            '380':  ('🇺🇦', 'UA'),
            '381':  ('🇷🇸', 'RS'),
            '382':  ('🇲🇪', 'ME'),
            '383':  ('🇽🇰', 'XK'),  # Kosovo
            '385':  ('🇭🇷', 'HR'),
            '386':  ('🇸🇮', 'SI'),
            '387':  ('🇧🇦', 'BA'),
            '389':  ('🇲🇰', 'MK'),
            '39':   ('🇮🇹', 'IT'),
            '40':   ('🇷🇴', 'RO'),
            '41':   ('🇨🇭', 'CH'),
            '420':  ('🇨🇿', 'CZ'),
            '421':  ('🇸🇰', 'SK'),
            '423':  ('🇱🇮', 'LI'),  # Liechtenstein
            '43':   ('🇦🇹', 'AT'),
            '44':   ('🇬🇧', 'GB'),
            '45':   ('🇩🇰', 'DK'),
            '46':   ('🇸🇪', 'SE'),
            '47':   ('🇳🇴', 'NO'),
            '48':   ('🇵🇱', 'PL'),
            '49':   ('🇩🇪', 'DE'),

            # ── Latin America ──
            '500':  ('🇫🇰', 'FK'),  # Falkland Islands
            '501':  ('🇧🇿', 'BZ'),  # Belize
            '502':  ('🇬🇹', 'GT'),  # Guatemala
            '503':  ('🇸🇻', 'SV'),  # El Salvador
            '504':  ('🇭🇳', 'HN'),  # Honduras
            '505':  ('🇳🇮', 'NI'),  # Nicaragua
            '506':  ('🇨🇷', 'CR'),  # Costa Rica
            '507':  ('🇵🇦', 'PA'),  # Panama
            '508':  ('🇵🇲', 'PM'),  # Saint Pierre & Miquelon
            '509':  ('🇭🇹', 'HT'),  # Haiti
            '51':   ('🇵🇪', 'PE'),
            '52':   ('🇲🇽', 'MX'),
            '53':   ('🇨🇺', 'CU'),
            '54':   ('🇦🇷', 'AR'),
            '55':   ('🇧🇷', 'BR'),
            '56':   ('🇨🇱', 'CL'),
            '57':   ('🇨🇴', 'CO'),
            '58':   ('🇻🇪', 'VE'),
            '590':  ('🇬🇵', 'GP'),  # Guadeloupe
            '591':  ('🇧🇴', 'BO'),  # Bolivia
            '592':  ('🇬🇾', 'GY'),  # Guyana
            '593':  ('🇪🇨', 'EC'),  # Ecuador
            '594':  ('🇬🇫', 'GF'),  # French Guiana
            '595':  ('🇵🇾', 'PY'),  # Paraguay
            '596':  ('🇲🇶', 'MQ'),  # Martinique
            '597':  ('🇸🇷', 'SR'),  # Suriname
            '598':  ('🇺🇾', 'UY'),  # Uruguay
            '599':  ('🇨🇼', 'CW'),  # Curaçao

            # ── Asia-Pacific ──
            '60':   ('🇲🇾', 'MY'),
            '61':   ('🇦🇺', 'AU'),
            '62':   ('🇮🇩', 'ID'),
            '63':   ('🇵🇭', 'PH'),
            '64':   ('🇳🇿', 'NZ'),
            '65':   ('🇸🇬', 'SG'),
            '66':   ('🇹🇭', 'TH'),
            '670':  ('🇹🇱', 'TL'),  # Timor-Leste
            '672':  ('🇳🇫', 'NF'),  # Norfolk Island
            '673':  ('🇧🇳', 'BN'),  # Brunei
            '674':  ('🇳🇷', 'NR'),  # Nauru
            '675':  ('🇵🇬', 'PG'),  # Papua New Guinea
            '676':  ('🇹🇴', 'TO'),  # Tonga
            '677':  ('🇸🇧', 'SB'),  # Solomon Islands
            '678':  ('🇻🇺', 'VU'),  # Vanuatu
            '679':  ('🇫🇯', 'FJ'),  # Fiji
            '680':  ('🇵🇼', 'PW'),  # Palau
            '681':  ('🇼🇫', 'WF'),  # Wallis & Futuna
            '682':  ('🇨🇰', 'CK'),  # Cook Islands
            '683':  ('🇳🇺', 'NU'),  # Niue
            '685':  ('🇼🇸', 'WS'),  # Samoa
            '686':  ('🇰🇮', 'KI'),  # Kiribati
            '687':  ('🇳🇨', 'NC'),  # New Caledonia
            '688':  ('🇹🇻', 'TV'),  # Tuvalu
            '689':  ('🇵🇫', 'PF'),  # French Polynesia
            '690':  ('🇹🇰', 'TK'),  # Tokelau
            '691':  ('🇫🇲', 'FM'),  # Micronesia
            '692':  ('🇲🇭', 'MH'),  # Marshall Islands
            '81':   ('🇯🇵', 'JP'),
            '82':   ('🇰🇷', 'KR'),
            '84':   ('🇻🇳', 'VN'),
            '850':  ('🇰🇵', 'KP'),  # North Korea
            '852':  ('🇭🇰', 'HK'),
            '853':  ('🇲🇴', 'MO'),  # Macau
            '855':  ('🇰🇭', 'KH'),  # Cambodia
            '856':  ('🇱🇦', 'LA'),  # Laos
            '86':   ('🇨🇳', 'CN'),
            '880':  ('🇧🇩', 'BD'),
            '886':  ('🇹🇼', 'TW'),
            '90':   ('🇹🇷', 'TR'),
            '91':   ('🇮🇳', 'IN'),
            '92':   ('🇵🇰', 'PK'),
            '93':   ('🇦🇫', 'AF'),
            '94':   ('🇱🇰', 'LK'),
            '95':   ('🇲🇲', 'MM'),
            '960':  ('🇲🇻', 'MV'),  # Maldives
            '961':  ('🇱🇧', 'LB'),
            '962':  ('🇯🇴', 'JO'),
            '963':  ('🇸🇾', 'SY'),
            '964':  ('🇮🇶', 'IQ'),
            '965':  ('🇰🇼', 'KW'),
            '966':  ('🇸🇦', 'SA'),
            '967':  ('🇾🇪', 'YE'),
            '968':  ('🇴🇲', 'OM'),
            '970':  ('🇵🇸', 'PS'),  # Palestine
            '971':  ('🇦🇪', 'AE'),
            '972':  ('🇮🇱', 'IL'),
            '973':  ('🇧🇭', 'BH'),
            '974':  ('🇶🇦', 'QA'),
            '975':  ('🇧🇹', 'BT'),  # Bhutan
            '976':  ('🇲🇳', 'MN'),  # Mongolia
            '977':  ('🇳🇵', 'NP'),  # Nepal
            '98':   ('🇮🇷', 'IR'),
            '992':  ('🇹🇯', 'TJ'),  # Tajikistan
            '993':  ('🇹🇲', 'TM'),  # Turkmenistan
            '994':  ('🇦🇿', 'AZ'),  # Azerbaijan
            '995':  ('🇬🇪', 'GE'),  # Georgia
            '996':  ('🇰🇬', 'KG'),  # Kyrgyzstan
            '998':  ('🇺🇿', 'UZ'),  # Uzbekistan

            # ── Africa ──
            '212':  ('🇲🇦', 'MA'),
            '213':  ('🇩🇿', 'DZ'),
            '216':  ('🇹🇳', 'TN'),
            '218':  ('🇱🇾', 'LY'),
            '220':  ('🇬🇲', 'GM'),  # Gambia
            '221':  ('🇸🇳', 'SN'),  # Senegal
            '222':  ('🇲🇷', 'MR'),  # Mauritania
            '223':  ('🇲🇱', 'ML'),  # Mali
            '224':  ('🇬🇳', 'GN'),  # Guinea
            '225':  ('🇨🇮', 'CI'),  # Ivory Coast
            '226':  ('🇧🇫', 'BF'),  # Burkina Faso
            '227':  ('🇳🇪', 'NE'),  # Niger
            '228':  ('🇹🇬', 'TG'),  # Togo
            '229':  ('🇧🇯', 'BJ'),  # Benin
            '230':  ('🇲🇺', 'MU'),  # Mauritius
            '231':  ('🇱🇷', 'LR'),  # Liberia
            '232':  ('🇸🇱', 'SL'),  # Sierra Leone
            '233':  ('🇬🇭', 'GH'),  # Ghana
            '234':  ('🇳🇬', 'NG'),
            '235':  ('🇹🇩', 'TD'),  # Chad
            '236':  ('🇨🇫', 'CF'),  # Central African Republic
            '237':  ('🇨🇲', 'CM'),  # Cameroon
            '238':  ('🇨🇻', 'CV'),  # Cape Verde
            '239':  ('🇸🇹', 'ST'),  # São Tomé & Príncipe
            '240':  ('🇬🇶', 'GQ'),  # Equatorial Guinea
            '241':  ('🇬🇦', 'GA'),  # Gabon
            '242':  ('🇨🇬', 'CG'),  # Congo
            '243':  ('🇨🇩', 'CD'),  # DR Congo
            '244':  ('🇦🇴', 'AO'),  # Angola
            '245':  ('🇬🇼', 'GW'),  # Guinea-Bissau
            '246':  ('🇮🇴', 'IO'),  # British Indian Ocean Territory
            '247':  ('🇦🇨', 'AC'),  # Ascension Island
            '248':  ('🇸🇨', 'SC'),  # Seychelles
            '249':  ('🇸🇩', 'SD'),  # Sudan
            '250':  ('🇷🇼', 'RW'),  # Rwanda
            '251':  ('🇪🇹', 'ET'),  # Ethiopia
            '252':  ('🇸🇴', 'SO'),  # Somalia
            '253':  ('🇩🇯', 'DJ'),  # Djibouti
            '254':  ('🇰🇪', 'KE'),
            '255':  ('🇹🇿', 'TZ'),
            '256':  ('🇺🇬', 'UG'),
            '257':  ('🇧🇮', 'BI'),  # Burundi
            '258':  ('🇲🇿', 'MZ'),  # Mozambique
            '260':  ('🇿🇲', 'ZM'),  # Zambia
            '261':  ('🇲🇬', 'MG'),  # Madagascar
            '262':  ('🇷🇪', 'RE'),  # Réunion
            '263':  ('🇿🇼', 'ZW'),  # Zimbabwe
            '264':  ('🇳🇦', 'NA'),  # Namibia
            '265':  ('🇲🇼', 'MW'),  # Malawi
            '266':  ('🇱🇸', 'LS'),  # Lesotho
            '267':  ('🇧🇼', 'BW'),  # Botswana
            '268':  ('🇸🇿', 'SZ'),  # Eswatini
            '269':  ('🇰🇲', 'KM'),  # Comoros
            '290':  ('🇸🇭', 'SH'),  # Saint Helena
            '291':  ('🇪🇷', 'ER'),  # Eritrea
            '297':  ('🇦🇼', 'AW'),  # Aruba
            '298':  ('🇫🇴', 'FO'),  # Faroe Islands
            '299':  ('🇬🇱', 'GL'),  # Greenland
        }

        # ৩ → ৪ → ২ → ১ সংখ্যা ক্রমে match (longest prefix first)
        for length in (4, 3, 2, 1):
            prefix = phone[:length]
            if prefix in country_map:
                return country_map[prefix]

        return ('🌐', 'XX')

    def get_platform_icon(self, service):
        """Service/platform name থেকে emoji বের করে"""
        s = str(service).lower()
        icons = {
            # ── Social Media ──
            'facebook': '📘', 'fb': '📘',
            'instagram': '📸', 'ig': '📸',
            'twitter': '🐦', 'x.com': '🐦',
            'tiktok': '🎵',
            'snapchat': '👻',
            'pinterest': '📌',
            'tumblr': '📓',
            'reddit': '🟠',
            'quora': '❓',
            'linkedin': '💼',
            'threads': '🧵',
            'mastodon': '🐘',
            'bluesky': '🦋',
            'vk': '🔵',          # VKontakte
            'ok.ru': '🟠',       # Odnoklassniki
            'weibo': '🌊',
            'douyin': '🎵',
            'kuaishou': '🎬',
            'xhs': '📕',         # Xiaohongshu / RedNote
            'lemon8': '🍋',
            'myspace': '🎸',
            'badoo': '💛',
            'tagged': '🏷️',
            'meetup': '🤝',
            'clubhouse': '🎤',

            # ── Messaging ──
            'whatsapp': '💚', 'wa': '💚',
            'telegram': '✈️', 'tg': '✈️',
            'viber': '💜',
            'line': '💚',
            'wechat': '💬',
            'kakao': '🟡',
            'signal': '🔒',
            'skype': '🔷',
            'discord': '🎮',
            'slack': '💼',
            'teams': '🟪',      # Microsoft Teams
            'zoom': '🎥',
            'imo': '📱',
            'kik': '💬',
            'textplus': '💬',
            'textme': '💬',
            'pof': '🐟',        # Plenty of Fish
            'hike': '🟢',
            'zalo': '🔵',
            'botim': '📞',
            'talkatone': '📞',

            # ── Dating ──
            'tinder': '🔥',
            'bumble': '🐝',
            'hinge': '💛',
            'okcupid': '💘',
            'match': '💕',
            'grindr': '🟡',
            'plenty': '🐟',
            'badoo': '💛',
            'momo': '🟠',
            'tantan': '❤️',
            'lovoo': '💗',

            # ── Email ──
            'gmail': '🔴',
            'google': '🔴',
            'yahoo': '💜',
            'outlook': '🔵',
            'hotmail': '🔵',
            'proton': '🔒',
            'protonmail': '🔒',
            'icloud': '☁️',
            'yandex': '🟡',
            'mail.ru': '📧',
            'aol': '📧',
            'zoho': '📧',
            'tutanota': '🔐',

            # ── Tech / Cloud ──
            'apple': '🍎',
            'microsoft': '🪟',
            'amazon': '🛒',
            'aws': '☁️',
            'dropbox': '📦',
            'box': '📦',
            'github': '🐙',
            'gitlab': '🦊',
            'bitbucket': '🪣',
            'digitalocean': '🌊',
            'cloudflare': '☁️',
            'heroku': '💜',
            'vercel': '▲',
            'netlify': '💚',
            'notion': '📒',
            'trello': '📋',
            'asana': '🟥',
            'jira': '🔵',
            'confluence': '🔵',
            'figma': '🎨',
            'canva': '✏️',
            'adobe': '🔴',

            # ── Finance / Crypto ──
            'paypal': '💰',
            'stripe': '💳',
            'binance': '🟡',
            'coinbase': '🔵',
            'kraken': '🐙',
            'bybit': '🟠',
            'okx': '⚫',
            'kucoin': '🟢',
            'crypto.com': '🔵',
            'metamask': '🦊',
            'trustwallet': '🔵',
            'blockchain': '⛓️',
            'revolut': '🔵',
            'wise': '💚',
            'cashapp': '💵',
            'venmo': '💙',
            'zelle': '💜',
            'chime': '🟢',
            'robinhood': '🟢',
            'etoro': '🟢',
            'skrill': '🔴',
            'neteller': '🔴',
            'webmoney': '💰',
            'qiwi': '🟠',
            'yoomoney': '🟡',
            'paytm': '🔵',
            'phonepe': '💜',
            'googlepay': '🔴',
            'applepay': '🍎',
            'bkash': '🟣',
            'nagad': '🟠',
            'rocket': '🚀',

            # ── Entertainment ──
            'netflix': '🎬',
            'youtube': '▶️',
            'spotify': '🎵',
            'twitch': '💜',
            'hulu': '💚',
            'disney': '🏰',
            'hbo': '🔵',
            'prime': '🟠',     # Amazon Prime
            'peacock': '🦚',
            'paramount': '⭐',
            'crunchyroll': '🟠',
            'deezer': '🟣',
            'tidal': '🔵',
            'soundcloud': '🟠',
            'shazam': '🔵',
            'apple music': '🍎',
            'vimeo': '🔵',
            'dailymotion': '🔵',
            'bilibili': '🔵',

            # ── Gaming ──
            'steam': '🎮',
            'epic': '⚫',
            'origin': '🟠',
            'ubisoft': '🔵',
            'blizzard': '🔵',
            'riot': '🔴',
            'xbox': '🟢',
            'playstation': '🎮',
            'nintendo': '🔴',
            'roblox': '🟥',
            'minecraft': '🟩',
            'pubg': '🎯',
            'freefire': '🔥',
            'codm': '🎖️',
            'mlbb': '🗡️',

            # ── E-commerce / Delivery ──
            'ebay': '🛍️',
            'aliexpress': '🛒',
            'alibaba': '🟠',
            'shopee': '🟠',
            'lazada': '🔵',
            'daraz': '🟠',
            'flipkart': '🛒',
            'walmart': '🔵',
            'target': '🎯',
            'etsy': '🟠',
            'wish': '🛍️',
            'shein': '🛍️',
            'doordash': '🔴',
            'ubereats': '🟢',
            'grubhub': '🟠',
            'foodpanda': '🐼',

            # ── Ride / Travel ──
            'uber': '⬛',
            'lyft': '🟣',
            'grab': '🟢',
            'ola': '🟡',
            'bolt': '🟢',
            'careem': '🟢',
            'airbnb': '🔴',
            'booking': '🔵',
            'expedia': '🟡',
            'agoda': '🔴',
            'hotels': '🏨',
            'trivago': '🔵',

            # ── Health / Fitness ──
            'fitbit': '🟢',
            'myfitnesspal': '🔵',
            'headspace': '🟠',
            'calm': '🔵',
            'noom': '🟢',
            'strava': '🟠',

            # ── Other / Generic ──
            'sms': '📩',
            'otp': '🔑',
            'bank': '🏦',
            'gov': '🏛️',
            'edu': '🎓',
            'work': '💼',
            'vpn': '🔒',
            'security': '🛡️',
            'auth': '🔐',
            '2fa': '🔐',
            'verify': '✅',
        }
        for key, icon in icons.items():
            if key in s:
                return icon
        return '📩'

    def escape_markdown(self, text):
        text = str(text)
        return text.replace('`', "'")

    async def send_telegram_message(self, message, chat_id=None, reply_markup=None):
        if chat_id is None:
            chat_id = self.group_chat_id

        try:
            from telegram.request import HTTPXRequest
            request = HTTPXRequest(connect_timeout=30, read_timeout=30, write_timeout=30)
            bot = Bot(token=self.telegram_token, request=request)
            await bot.send_message(
                chat_id=chat_id,
                text=message,
                parse_mode='Markdown',
                reply_markup=reply_markup,
                disable_web_page_preview=True
            )
            logger.info("✅ Telegram message sent successfully")
            return True
        except TelegramError as e:
            logger.info(f"❌ Telegram Error: {e}")
            print(f"❌ Telegram Error: {e}")
            return False
        except Exception as e:
            logger.info(f"❌ Send Message Error: {e}")
            print(f"❌ Send Message Error: {e}")
            return False

    async def send_startup_message(self):
        startup_msg = (
            "🚀 *OTP Monitor Bot Started* 🚀\n\n"
            "──────────────────\n\n"
            "✅ *Status:* `Live & Monitoring`\n"
            "⚡ *Mode:* `First OTP Only`\n"
            f"📡 *Host:* `{self.target_host}`\n\n"
            f"⏰ *Start Time:* `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n\n"
            "──────────────────\n"
            "🤖 *OTP Monitor Bot*"
        )

        keyboard = [
            [InlineKeyboardButton("👨‍💻 Developer", url="https://t.me/FBDEALZONEOWNER")],
            [InlineKeyboardButton("📢 Channel", url="https://t.me/FBDEALZONEofficial")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        try:
            success = await self.send_telegram_message(startup_msg, reply_markup=reply_markup)
            if success:
                logger.info("✅ Startup message sent to group")
        except Exception as e:
            logger.info(f"⚠️ Startup message failed (monitoring will continue): {e}")

    def extract_otp(self, message):
        cleaned = re.sub(r'\d{4}-\d{2}-\d{2}', '', str(message))
        cleaned = re.sub(r'\d{2}:\d{2}:\d{2}', '', cleaned)

        for pattern in self.otp_patterns:
            matches = re.findall(pattern, cleaned)
            if matches:
                match = matches[0]
                if isinstance(match, tuple):
                    return ' '.join(m for m in match if m)
                return match
        return None

    def create_otp_id(self, timestamp, phone_number):
        return f"{timestamp}_{phone_number}"

    def format_message(self, sms_data, message_text, otp_code):
        timestamp    = self.escape_markdown(sms_data[0])
        raw_phone    = str(sms_data[2])
        phone        = self.escape_markdown(self.hide_phone_number(raw_phone))
        service_raw  = sms_data[3] if len(sms_data) > 3 else 'Unknown'
        service      = self.escape_markdown(service_raw)
        msg          = self.escape_markdown(message_text)
        code         = self.escape_markdown(otp_code) if otp_code else 'N/A'

        flag, country_code = self.get_country_flag(raw_phone, sms_data[1] if len(sms_data) > 1 else '')
        platform_icon = self.get_platform_icon(service_raw)

        return (
            "🔥 *𝐅𝐈𝐑𝐒𝐓 𝐎𝐓𝐏 𝐑𝐄𝐂𝐄𝐈𝐕𝐄𝐃* 🔥\n"
            "➖➖➖➖➖➖➖➖➖➖➖\n\n"
            f"{flag} {country_code} · {platform_icon} · {phone} · {service}\n\n"
            f"🔑 *𝐎𝐓𝐏 𝐂𝐨𝐝𝐞:* `{code}`\n\n"
            f"📅 *𝐓𝐢𝐦𝐞:* `{timestamp}`\n"
            f"📝 *𝐌𝐬𝐠:* `{msg}`\n\n"
            "➖➖➖➖➖➖➖➖➖➖➖\n"
            "🤖 *𝐎𝐓𝐏 𝐌𝐨𝐧𝐢𝐭𝐨𝐫 𝐁𝐨𝐭*"
        )

    def create_response_buttons(self):
        keyboard = [
            [InlineKeyboardButton("📱 Number Channel", url="https://t.me/earning_hub_number_channel")],
            [
                InlineKeyboardButton("🤖 Number bot", url="https://t.me/EARNING_HUB_NUMBER_BOT"),
                InlineKeyboardButton("📢 main Channel", url="https://t.me/earning_hub_official_channel")
            ]
        ]
        return InlineKeyboardMarkup(keyboard)

    def fetch_sms_data(self):
        current_date = time.strftime("%Y-%m-%d")

        headers = {
            'Host': self.target_host,
            'Connection': 'keep-alive',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 16; 23129RN51X Build/BP2A.250605.031.A3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.177 Mobile Safari/537.36',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': f'http://{self.target_host}/ints/client/SMSCDRStats',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9,fr-DZ;q=0.8,fr;q=0.7,ru-RU;q=0.6,ru;q=0.5,kk-KZ;q=0.4,kk;q=0.3,ar-AE;q=0.2,ar;q=0.1,es-ES;q=0.1,es;q=0.1,uk-UA;q=0.1,uk;q=0.1,pt-PT;q=0.1,pt;q=0.1,fa-IR;q=0.1,fa;q=0.1,ms-MY;q=0.1,ms;q=0.1,bn-BD;q=0.1,bn;q=0.1',
            'Cookie': f'PHPSESSID={self.session_cookie}'
        }

        params = {
            'fdate1': f'{current_date} 00:00:00',
            'fdate2': f'{current_date} 23:59:59',
            'frange': '', 'fnum': '', 'fcli': '',
            'fgdate': '', 'fgmonth': '', 'fgrange': '',
            'fgnumber': '', 'fgcli': '', 'fg': '0',
            'csstr': self.csstr_param,
            'sEcho': '1', 'iColumns': '7', 'sColumns': ',,,,,,',
            'iDisplayStart': '0', 'iDisplayLength': '25',
            'mDataProp_0': '0', 'sSearch_0': '', 'bRegex_0': 'false',
            'bSearchable_0': 'true', 'bSortable_0': 'true',
            'mDataProp_1': '1', 'sSearch_1': '', 'bRegex_1': 'false',
            'bSearchable_1': 'true', 'bSortable_1': 'true',
            'mDataProp_2': '2', 'sSearch_2': '', 'bRegex_2': 'false',
            'bSearchable_2': 'true', 'bSortable_2': 'true',
            'mDataProp_3': '3', 'sSearch_3': '', 'bRegex_3': 'false',
            'bSearchable_3': 'true', 'bSortable_3': 'true',
            'mDataProp_4': '4', 'sSearch_4': '', 'bRegex_4': 'false',
            'bSearchable_4': 'true', 'bSortable_4': 'true',
            'mDataProp_5': '5', 'sSearch_5': '', 'bRegex_5': 'false',
            'bSearchable_5': 'true', 'bSortable_5': 'true',
            'mDataProp_6': '6', 'sSearch_6': '', 'bRegex_6': 'false',
            'bSearchable_6': 'true', 'bSortable_6': 'true',
            'sSearch': '', 'bRegex': 'false',
            'iSortCol_0': '0', 'sSortDir_0': 'desc', 'iSortingCols': '1',
            '_': self.timestamp_param
        }

        try:
            response = requests.get(
                self.target_url,
                headers=headers,
                params=params,
                timeout=10,
                verify=False
            )

            if response.status_code == 200:
                if response.text.strip():
                    try:
                        return response.json()
                    except json.JSONDecodeError:
                        logger.error(f"JSON decode error: {response.text[:200]}")
                        return None
                else:
                    return None
            else:
                logger.error(f"HTTP {response.status_code}")
                return None

        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            return None
        except Exception as e:
            logger.error(f"Fetch error: {e}")
            return None

    async def monitor_loop(self):
        logger.info("🚀 OTP Monitoring Started - FIRST OTP ONLY")
        await self.send_startup_message()

        check_count = 0

        while self.is_monitoring:
            try:
                check_count += 1
                current_time = datetime.now().strftime("%H:%M:%S")

                logger.info(f"🔍 Check #{check_count} at {current_time}")

                data = self.fetch_sms_data()

                if data and 'aaData' in data:
                    sms_list = data['aaData']

                    valid_sms = [
                        sms for sms in sms_list
                        if len(sms) >= 6
                        and isinstance(sms[0], str)
                        and ':' in sms[0]
                    ]

                    if valid_sms:
                        first_sms = valid_sms[0]
                        timestamp = first_sms[0]
                        phone_number = str(first_sms[2])

                        message_text = ""
                        otp_code = None
                        for i, field in enumerate(first_sms):
                            if i <= 3:
                                continue
                            if isinstance(field, str) and len(field) > 3 and field.strip() not in ('$', '', '-'):
                                found = self.extract_otp(field)
                                if found:
                                    message_text = field
                                    otp_code = found
                                    logger.info(f"📍 OTP found at index {i}: {field[:80]}")
                                    break

                        if not message_text:
                            message_text = str(first_sms[5]) if len(first_sms) > 5 else ""

                        otp_id = self.create_otp_id(timestamp, phone_number)

                        if otp_id not in self.processed_otps:
                            logger.info(f"🚨 FIRST OTP DETECTED: {timestamp}")

                            if otp_code:
                                logger.info(f"🔐 OTP Code: {otp_code}")

                                formatted_msg = self.format_message(first_sms, message_text, otp_code)
                                reply_markup = self.create_response_buttons()

                                success = await self.send_telegram_message(
                                    formatted_msg,
                                    reply_markup=reply_markup
                                )

                                self.processed_otps.add(otp_id)
                                self.processed_count += 1

                                if self.processed_count >= 1000:
                                    self.processed_otps.clear()
                                    self.processed_count = 0
                                    logger.info("🧹 Processed OTPs cache cleared")

                                if success:
                                    self.total_otps_sent += 1
                                    self.last_otp_time = current_time
                                    logger.info(f"✅ OTP SENT: {timestamp} - Total: {self.total_otps_sent}")
                                else:
                                    logger.info(f"❌ Telegram send failed: {timestamp}")
                            else:
                                self.processed_otps.add(otp_id)
                                logger.info(f"⚠️ OTP not found. Full data: {first_sms}")
                        else:
                            logger.debug(f"⏩ Already Processed: {timestamp}")
                    else:
                        logger.info("ℹ️ No valid SMS records found")
                else:
                    logger.warning("⚠️ No data from API")

                if check_count % 20 == 0:
                    logger.info(f"📊 Status - Total OTPs Sent: {self.total_otps_sent}")

                await asyncio.sleep(0.50)

            except Exception as e:
                logger.error(f"❌ Monitor Loop Error: {e}")
                print(f"❌ Monitor Loop Error: {e}")
                await asyncio.sleep(1)

async def main():
    TELEGRAM_BOT_TOKEN = "7955403590:AAFA_UsxTrbmiY9zSlFz3B9aZJ-XP0C2SYc"
    GROUP_CHAT_ID = "-1003247504066"
    SESSION_COOKIE = "8da33674c0afe01df340e2fdab40cd95"
    TARGET_HOST = "168.119.13.175"
    CSSTR_PARAM = "71348c229af01ebba6506e39046c2890"
    TIMESTAMP_PARAM = "1776355211677"
    TARGET_URL = f"http://{TARGET_HOST}/ints/client/res/data_smscdr.php"

    print("=" * 50)
    print("🤖 OTP MONITOR BOT - FIRST OTP ONLY")
    print("=" * 50)
    print(f"📡 Host: {TARGET_HOST}")
    print("📱 Group ID:", GROUP_CHAT_ID)
    print("🚀 Starting bot...")

    otp_bot = OTPMonitorBot(
        telegram_token=TELEGRAM_BOT_TOKEN,
        group_chat_id=GROUP_CHAT_ID,
        session_cookie=SESSION_COOKIE,
        target_url=TARGET_URL,
        target_host=TARGET_HOST,
        csstr_param=CSSTR_PARAM,
        timestamp_param=TIMESTAMP_PARAM
    )

    print("✅ BOT STARTED SUCCESSFULLY!")
    print("🛑 Press Ctrl+C to stop")
    print("=" * 50)

    try:
        await otp_bot.monitor_loop()
    except KeyboardInterrupt:
        print("\n🛑 Bot stopped by user!")
        otp_bot.is_monitoring = False
        print(f"📊 Total OTPs Sent: {otp_bot.total_otps_sent}")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    asyncio.run(main())

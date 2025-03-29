
import os
import re
import json
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes

# You'll need to set this in Replit Secrets
TOKEN = "7438118425:AAH8K3-vy6iTWTCxqsUedh-2a-Cbo2eKiZ4"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = "👋 سلام! به ربات بررسی IP خوش آمدید!\n\n📝 لطفا یک آدرس IP (IPv4 یا IPv6) را وارد کنید."
    await update.message.reply_text(welcome_text)

async def get_ip_info(ip_address: str) -> dict:
    url = f"https://api.iplocation.net/?ip={ip_address}"
    response = requests.get(url)
    return response.json()

def is_valid_ip(ip: str) -> bool:
    # IPv4 validation
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ipv4_pattern.match(ip):
        # Check if each octet is in range 0-255
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    
    # More comprehensive IPv6 validation
    ipv6_pattern = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
                             r'(([0-9a-fA-F]{1,4}:){1,7}:)|'
                             r'(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})|'
                             r'(([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2})|'
                             r'(([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3})|'
                             r'(([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4})|'
                             r'(([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5})|'
                             r'([0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6}))|'
                             r'(:((:[0-9a-fA-F]{1,4}){1,7}|:))$')
    return bool(ipv6_pattern.match(ip))

async def extract_ip(text: str) -> str:
    # Extract IPv4 from URL or plain text
    ipv4_pattern = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
    ipv4_match = ipv4_pattern.search(text)
    
    # Extract IPv6 from URL or plain text
    ipv6_pattern = re.compile(r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
                             r'(([0-9a-fA-F]{1,4}:){1,7}:)|'
                             r'(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})|'
                             r'(([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2})|'
                             r'(([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3})|'
                             r'(([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4})|'
                             r'(([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5})|'
                             r'([0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6}))|'
                             r'(:((:[0-9a-fA-F]{1,4}){1,7}|:))')
    ipv6_match = ipv6_pattern.search(text)
    
    if ipv4_match:
        return ipv4_match.group(0)
    elif ipv6_match:
        return ipv6_match.group(0)
    else:
        return text.strip()

async def get_country_flag(country_code: str) -> str:
    # Convert country code to flag emoji
    if not country_code:
        return "🏳"
    code = country_code.upper()
    return "".join(chr(ord(c) + 127397) for c in code)

async def handle_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ip = await extract_ip(update.message.text.strip())
    
    if not is_valid_ip(ip):
        await update.message.reply_text("❌ لطفا یک IP معتبر وارد کنید!")
        return

    try:
        info = await get_ip_info(ip)
        
        keyboard = [
            [
                InlineKeyboardButton("🌍 کشور", callback_data=f"country_{ip}"),
                InlineKeyboardButton("🏢 ISP", callback_data=f"isp_{ip}")
            ],
            [
                InlineKeyboardButton("📋 اطلاعات کامل", callback_data=f"full_{ip}")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            f"🔍 اطلاعات IP: {ip}\nلطفا یکی از گزینه‌های زیر را انتخاب کنید:",
            reply_markup=reply_markup
        )
    except Exception as e:
        await update.message.reply_text("❌ خطا در دریافت اطلاعات. لطفا دوباره تلاش کنید.")

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    
    # برای دکمه‌های اطلاعاتی که نباید عملیاتی انجام دهند
    if query.data == "ignore":
        await query.answer("این دکمه فقط برای نمایش اطلاعات است")
        return
    
    await query.answer()
    action, ip = query.data.split('_')
    info = await get_ip_info(ip)
    country_flag = await get_country_flag(info.get('country_code2', ''))
    
    if action == "country":
        country_name = info.get('country_name', 'نامشخص')
        country_code = info.get('country_code2', 'نامشخص')
        text = f"اطلاعات کشور برای IP: {ip}"
        
        # دکمه‌های اطلاعات کشور و سایر دکمه‌ها
        keyboard = [
            [
                InlineKeyboardButton(f"{country_flag} کشور: {country_name}", callback_data="ignore")
            ],
            [
                InlineKeyboardButton(f"🌐 کد کشور: {country_code}", callback_data="ignore")
            ],
            [
                InlineKeyboardButton("🔙 برگشت", callback_data=f"back_{ip}"),
                InlineKeyboardButton("🏢 ISP", callback_data=f"isp_{ip}")
            ]
        ]
    elif action == "isp":
        isp_name = info.get('isp', 'نامشخص')
        text = f"اطلاعات سرویس دهنده برای IP: {ip}"
        
        # دکمه‌های اطلاعات ISP و سایر دکمه‌ها
        keyboard = [
            [
                InlineKeyboardButton(f"🏢 سرویس دهنده اینترنت: {isp_name}", callback_data="ignore")
            ],
            [
                InlineKeyboardButton("🔙 برگشت", callback_data=f"back_{ip}"),
                InlineKeyboardButton("🌍 کشور", callback_data=f"country_{ip}")
            ]
        ]
    elif action == "back":
        text = f"🔍 اطلاعات IP: {ip}\nلطفا یکی از گزینه‌های زیر را انتخاب کنید:"
        
        # منوی اصلی
        keyboard = [
            [
                InlineKeyboardButton("🌍 کشور", callback_data=f"country_{ip}"),
                InlineKeyboardButton("🏢 ISP", callback_data=f"isp_{ip}")
            ],
            [
                InlineKeyboardButton("📋 اطلاعات کامل", callback_data=f"full_{ip}")
            ]
        ]
    else:  # full info
        country_name = info.get('country_name', 'نامشخص')
        country_code = info.get('country_code2', 'نامشخص')
        isp_name = info.get('isp', 'نامشخص')
        ip_version = info.get('ip_version', 'نامشخص')
        
        text = f"🔍 اطلاعات کامل IP: {ip}"
        
        # دکمه‌های اطلاعات کامل به صورت شیشه‌ای
        keyboard = [
            [
                InlineKeyboardButton(f"{country_flag} کشور: {country_name}", callback_data="ignore")
            ],
            [
                InlineKeyboardButton(f"🌐 کد کشور: {country_code}", callback_data="ignore")
            ],
            [
                InlineKeyboardButton(f"🏢 ISP: {isp_name}", callback_data="ignore")
            ],
            [
                InlineKeyboardButton(f"📊 نسخه IP: IPv{ip_version}", callback_data="ignore")
            ],
            [
                InlineKeyboardButton("🔙 برگشت", callback_data=f"back_{ip}")
            ]
        ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(text=text, reply_markup=reply_markup)

def main():
    application = Application.builder().token(TOKEN).build()
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_ip))
    application.add_handler(CallbackQueryHandler(button_callback))
    
    print("bot start ✅✅✅✅")
    application.run_polling()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3

import scapy.all as scapy
import telebot
import time

bot = telebot.TeleBot('5317854713:AAFIfqicq43Ks8UZigh31cSgPFjFXywGf60')

keyboard = telebot.types.InlineKeyboardMarkup()

keyboard.row(
    telebot.types.InlineKeyboardButton('Информация о боте ℹ️', callback_data='info')
)

keyboard.row(
    telebot.types.InlineKeyboardButton('Указать сетевой интерфейс 💻', callback_data='interface')
)

keyboard.row(
    telebot.types.InlineKeyboardButton('Посмотреть используемый сетевой интерфейс 🌐', callback_data='showint')
)

keyboard.row(
    telebot.types.InlineKeyboardButton('Запустить режим обнаружения атак ARP-Spoofing 📡', callback_data='run')
)



check_run = 0
interface = 'eth0'

@bot.message_handler(commands=['start'])
def start_message(message):
    bot.send_message(message.from_user.id, 'Вас приветствует ARP-spoofing detector, для взаимодействия с программой используйте кнопки ниже 👇', reply_markup=keyboard)

@bot.message_handler(content_types=["text"])
def send_message(message):
    a = message.text
    if (a[0] == 'i') and (a[1] == 'n') and (a[2] == 't'):
        global interface
        interface = str(a.replace('int', ''))
        bot.send_message(message.chat.id, 'Интерфейс успешно изменён ✅', reply_markup=keyboard)
    else:
        bot.send_message(message.chat.id, 'Для взаимодействия с ботом используйте данные кнопки ⌨️', reply_markup=keyboard)

@bot.callback_query_handler(func=lambda call: True)
def callback_worker(call):
    if call.data == 'info':
        bot.send_message(call.message.chat.id, 'Если ваше устройство, на котором вы запустили данную программу подвергнется атаке ARP-spoofing, то данный бот оповестит вас об этом 💡')
        bot.answer_callback_query(call.id)

    if call.data == 'interface':
        bot.send_message(call.message.chat.id, 'Если вы хотите указать нужный сетевой интерфейс, то отправьте боту сообщение int<интерфейс> \nПример: intwlan0')
        bot.answer_callback_query(call.id)

    if call.data == 'showint':
        bot.send_message(call.message.chat.id, f"Используемый сетевой интерфейс: {interface}")
        bot.answer_callback_query(call.id)

    if call.data == 'run':
        global check_run
        if check_run == 0:
            bot.send_message(call.message.chat.id, 'Запуск выполнен успешно ✅')
            check_run = 1

            def getmac(ip):
                arp_req = scapy.ARP(pdst=ip)
                brdcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_req_brdcast = brdcast / arp_req
                ans_list = scapy.srp(arp_req_brdcast, timeout=1, verbose=False)[0]
                return ans_list[0][1].hwsrc

            def sniffing_packet(interface):
                scapy.sniff(iface=interface, store=False, prn=choosing_packets)

            def choosing_packets(packet):
                if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
                    try:
                        realmac = getmac(packet[scapy.ARP].psrc)
                        respmac = packet[scapy.ARP].hwsrc

                        if realmac != respmac:
                            print("ARP-spoofing attack detected!")
                            bot.send_message(call.message.chat.id, 'Обнаружена атака ARP-spoofing на ваше устройство❗️')
                            time.sleep(5)
                            bot.send_message(call.message.chat.id, 'Для повышения защищенности против такой атаки \nИспользуйте VPN 🔒\nВключите Firewall 🛡 \nПереподключитесь к сети 🌐')
                            time.sleep(15)
                    except IndexError:
                        pass

            sniffing_packet(interface)
        else:
            bot.send_message(call.message.from_user.id, 'Program already run')



    

if __name__ == '__main__':
     bot.infinity_polling()
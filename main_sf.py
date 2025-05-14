from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import base64
from base64 import b64decode, b64encode
from hashlib import sha256

from aiogram.types import message, user
import requests

import json
import time

import random

token = "7263669250:AAFZ5adEJ9inKl2PBWUXEit8u3DY3whIU2k"
tg_api_url = "https://api.telegram.org/"
chats = {}
c_offset = 0
us_counter = {}
counter = 0
trans_stack = []


sha256(b"asdjklha").digest()


blockchain = [
    [
        0,
        base64.b64encode(random.randbytes(24)),
        time.time(),
        "",
        1,
        [[
            50,
            "0f9lLnChsyuddslxCVEq+y1zNqLood3nom8hKQAXyrE=",
            0,
            0,
            "",
            ""
        ]],
    ]
]


"""
block - 
[
    block height    
    block id                    b64(rand x24)
    timestamp
    merkle_root                 b64(prev_block+cur_block)
    n_trans
    transs
    nonce
]

trans - [
    count
    out_pk_b64

    in_block_id
    in_block_trans
    in_pk_b64
    trans_sign
]

"""

def verify_block(block):
    global us_counter
    i = len(blockchain)+1
    block_height, block_id, timestamp, merkleroot, transactions, nonce = block
    if block_height == blockchain[i-1][0]+1:
        if block_id not in us_counter.keys():
            us_counter.update({block_id: {}})
            if timestamp > blockchain[i-1][2]:
                c_bl_w_mr = [block_height,block_id,timestamp,transactions,nonce]
                if merkleroot == sha256(str([blockchain[i-1],c_bl_w_mr]).encode()):
                    for j in transactions:
                        count, _, in_block_id, in_block_trans, in_pk_b64, trans_sign = j
                        in_pk = Ed25519PublicKey.from_public_bytes(b64decode(in_pk_b64))
                        if in_block_trans not in us_counter[block_id]:
                            try:
                                in_pk.verify(trans_sign, str(j[:-1]).encode())
                            except: return
                            if blockchain[in_block_id][5][1] == in_pk_b64:
                                if count <= blockchain[in_block_id][5][0]:
                                    us_counter[block_id].update({in_block_trans})
                                    return True
    return False
    ...

def verify_bc():
    global blockchain
    us_counter = {}
    if len(blockchain) > 1:
        for i in range(1, len(blockchain)-1):
            block_height, block_id, timestamp, merkleroot, transactions, nonce = blockchain[i]
            if block_height == blockchain[i-1][0]+1:
                if block_id not in us_counter.keys():
                    us_counter.update({block_id: {}})
                    if timestamp > blockchain[i-1][2]:
                        c_bl_w_mr = [block_height,block_id,timestamp,transactions,nonce]
                        if merkleroot == sha256(str([blockchain[i-1],c_bl_w_mr]).encode()):
                            for j in transactions:
                                count, out_pk_b64, in_block_id, in_block_trans, in_pk_b64, trans_sign = j
                                in_pk = Ed25519PublicKey.from_public_bytes(b64decode(in_pk_b64))
                                if in_block_trans not in us_counter[block_id]:
                                    try:
                                        in_pk.verify(trans_sign, str(j[:-1]).encode())
                                    except: return
                                    if blockchain[in_block_id][5][1] == in_pk_b64:
                                        if count <= blockchain[in_block_id][5][0]:
                                            us_counter[block_id].update({in_block_trans})
                                            return True
    return False

def get_balance(pk):
    global blockchain
    balance = 0
    for i in range(0, len(blockchain)):
        for j in range(blockchain[i][4]):
            # print(blockchain[i][5])
            trans = blockchain[i][5][j]
            print(trans, pk)
            if trans[1] == pk:
                print("+",trans[0])
                balance+=trans[0]
            if trans[4] == pk:
                print("-",trans[0])
                balance -= trans[0]
    return balance


def CallMethod(method: str, arguments: dict = {}):
    url = tg_api_url + "/bot"+token+"/"+method
    # grequests.get()
    r = requests.get(url, params=arguments).json()
    if r["ok"]:
        return r["result"]
    else:
        raise Exception(str(r))


def gen_keyb(markup: list):
    return '{"keyboard": {},"resize_keyboard": true}'.replace("{}", json.dumps(markup))

def update_handler(update: dict):
    global c_offset, counter
    counter+=1
    c_offset = update["update_id"]+1
    message = update["message"]
    chat_id, f_name, l_name, u_name, chat_type = message["chat"].values()
    if chat_id not in chats:
        chats.update({chat_id: {"f_name":f_name, "l_name":l_name, "u_name":u_name, "chat_type":chat_type, "status": "start", "publick_key": ""}})
    text = message["text"]
    print(text)
        

    match text:
        case "/start":
            markup = [[{"text": "Создать кошелек"},{"text":"Импортировать кошклек"}]]
            keyboard = gen_keyb(markup)
            CallMethod("SendMessage", {"text":"Привет! Это платформа для практического изучения работы криптовалют. тут ты изучишь работу криптовалют на самом низком уровне и поймешь их преимущества", "chat_id": chat_id, "reply_markup": keyboard})


        case "Создать кошелек":
            markup = [[{"text": "Сгенерировать пару ключей"},{"text":"Импортировать кошклек"}]]
            keyboard = gen_keyb(markup)
            CallMethod("SendMessage", {"text":"Хорошо что ты согласился начать! теперь тебе нужно создать кошелек. На самом деле кошелька в привычном понемании тут нет. у пользователя есть публичный и приватный ключ шифрования аддрес кошелька это преобразованный публичный ключ участника. Их может быть неограниченное число на человека. их используют для переводов. есть криптовалюты где не видно кому переденны монеты (Monero) там аддресс кошелька всегда разный но тоже привязан к публичному ключа получателя\n\nТеперь давай сгенерируем пару ключей. Мы используем шифрование ed25519. Ты можешь сгенерировать пару в виде base64 сам с помощью онлайн сервисов (https://cyphr.me/ed25519_tool/ed.html) и использовать кнопку Импортировать аккаунт в боте или сгенерировать пару тут с помошью кнопки Сгенерировать пару ключей", "chat_id":chat_id, "reply_markup":keyboard})


        case "Импортировать кошклек":
            chats[chat_id]["status"] = "imp"
            CallMethod("SendMessage", {"text":"Введи ваш публичный ключ. он будет использоваться для получения баланса `публичный_ключ`", "chat_id":chat_id})


        case "Сгенерировать пару ключей":
            priv_key = Ed25519PrivateKey.generate()
            prk_b = priv_key.private_bytes_raw()
            publ_key = priv_key.public_key()
            puk_b = publ_key.public_bytes_raw()

            markup = [
                [{"text": "Баланс"}, {"text": "Аддрес"}],
                [{"text": "Получить"},{"text": "Блокчейн"}],
                [{"text": "Перевести"}]
            ]
            kb = gen_keyb(markup)

            CallMethod("SendMessage", {"text": f"Вот ваша пара ключей\n\n{base64.b64encode(prk_b).decode()} {base64.b64encode(puk_b).decode()}\n\nАддрессом кошелька будет кодировка публичного ключа. им можно делиться не беспокоясь за свою безопасность. Он был сохранен в боте. теперь вы можете получать/переводить монеты и смотреть баланс!", "chat_id": chat_id, "reply_markup": kb})
            chats[chat_id]["publick_key"] = publ_key
        
        case "Баланс":
            CallMethod("SendMessage", {"text": f'Твой баланс: {get_balance(chats[chat_id]["publick_key"]), "chat_id":chat_id}'})
        case "Аддресс":
            CallMethod("SendMessage", {"chat_id":chat_id, "text": "По этому аддрессу тебе могут переводить монеты. просто поделись им!"})
            CallMethod("SendMessage", {"chat_id":chat_id, "text": chats[chat_id]["publick_key"]})
        case "Блокчейн":
            ...
        case "Перевести":
            CallMethod("SendMessage", {"chat_id":chat_id, "text":"введи аддресс получателя, количество монет, id блока со средствами, номер транзакции в блоке и свой приватный ключ через пробел"})
            chats[chat_id]["status"] = "trans"
        case "Перевести PRO":
            ...
        case _:
            if chats[chat_id]["status"] == "imp":
                try:
                    pub_key = Ed25519PublicKey.from_public_bytes(b64decode(text))
                    chats[chat_id]["publick_key"] = text
                    chats[chat_id]["status"] = "ready"

                    markup = [
                        [{"text": "Баланс"}, {"text": "Аддрес"}],
                        [{"text": "Получить"},{"text": "Блокчейн"}],
                        [{"text": "Перевести"}]
                    ]
                    kb = gen_keyb(markup)

                    CallMethod("SendMessage", {"text": "Ключ успешно добавлен! теперь ты можешь пользоваться кошельком.", "reply_markup": kb, "chat_id":chat_id})
                except:
                    CallMethod("SendMessage", {"text": "Похоже что ключ не подходит под формат ed25519 :(. Если не получается самостоятельно сгенерировать ключ то используй встроенный генератор ключа. Помни что эта не настоящая криптовалюта а обучающая платформа для практики.", "chat_id":chat_id})
            if chats[chat_id]["status"] == "trans":
                try:
                    out_pk_b64, count, in_block_id, in_trans_id, in_prk_b64 = text.split(" ")
                    pk = Ed25519PrivateKey.from_private_bytes(in_prk_b64)
                    trans_ = [count, out_pk_b64, in_block_id, in_trans_id, chats[chat_id]["publick_key"]]
                    trans = trans_.append(b64encode(pk.sign(str(trans_).encode())))
                    CallMethod("SendMessage", {"chat_id":chat_id, "text":"Транзакция поступила в очередь майнинга! теперь нужно подождать некоторое время пока поступят новые транзакции и блок сгенерируется"})
                except:
                    CallMethod("SendMessage", {"chat_id":chat_id, "text":"Ты не правильно ввел данные для перевода. попробуй еще раз."})
                ...


def main():
    while True:
        updates = CallMethod("getUpdates", {"offset": c_offset})
        for i in updates:
            try:
                update_handler(i)
            except Exception as e:
                raise e
        time.sleep(0.2)


if __name__ == "__main__":
    main()
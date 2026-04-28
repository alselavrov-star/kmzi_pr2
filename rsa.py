import random
import math

def is_prime(n, k=10):
    """Проверяет, является ли число простым, с помощью теста Миллера‑Рабина."""
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True
def generate_prime(bits):
    """Генерирует случайное простое число заданной разрядности."""
    while True:
        user_input = input()
        
        if not user_input:  # автогенерация
            while True:
                p = random.getrandbits(bits)
                p |= (1 << bits - 1) | 1
                if is_prime(p):
                    print(f"Сгенерировано: {p}")
                    return p
        else:  # пользователь ввел число
            try:
                p = int(user_input)
                if is_prime(p):
                    print(f"Принято: {p}")
                    return p
                else:
                    print(f"Ошибка: {p} не является простым числом. Попробуйте снова.")
                    # continue - цикл while True повторится, запросив ввод заново
            except ValueError:
                print("Ошибка: введите целое число или нажмите Enter")

def egcd(a, b):
    """Расширенный алгоритм Евклида."""
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def are_coprime(a, b):
    return math.gcd(a, b)==1

def modinv(a, m):
    """Находит модульное обратное число."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('No inverse')
    return x % m

def generate_keypair(bits):
    """Генерирует пару ключей RSA."""
    print("Введите значение p, или нажмите enter для автоматической генерации")
    p = generate_prime(bits // 2)
    print("Введите значение q, или нажмите enter для автоматической генерации")
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    print("Введите значение экспоненты зашифрования")
    while True:
        try:
            e = int(input())
            if are_coprime(e, phi):
                d = modinv(e, phi)
                break  # Выходим из цикла, если условие выполнено
            else:
                print(f"Ошибка: {e} не взаимно просто с {phi}")
                print("Пожалуйста, введите другое значение e:")
        except ValueError:
            print("Ошибка: введите целое число")
            print("Пожалуйста, введите значение e:")
    
    return ((n, e), (n, d))

def encrypt(plaintext, public_key):
    """Шифрует текст, преобразуя ASCII-коды в двоичную последовательность и разбивая на блоки."""
    n, e = public_key

    # Преобразуем текст в двоичную строку, каждый символ переводим в 10е значение асц кода и сразу переводим в 2ю
    binary_string = ''.join(format(ord(ch), '08b') for ch in plaintext)
       
    # Определяем размер блока с округлением в меньшую сторону
    block_bits = int(math.log2(n))
    
    # Добавляем нули в начало битовой последовательности если не делится на цело на размер блока при необходимости
    if len(binary_string) % block_bits != 0:
        padding = block_bits - (len(binary_string) % block_bits)
        binary_string = '0' * padding + binary_string

    # Задаем размер блока для зашифрованной битовой последовательности,Шифруем блоки и сразу преобразуем в двоичную строку
    block_bits_2 = block_bits + 1
    result_binary = ''
    # разбиваем битовую последовательность на блоки Log2(n)
    for i in range(0, len(binary_string), block_bits):
        block = binary_string[i:i + block_bits]
        block_number = int(block, 2) # каждый блок преобразуем в 10й вид
        encrypted = pow(block_number, e, n) # шифруем
        
        # Преобразуем зашифрованное число в двоичную строку
        encrypted_binary = format(encrypted, f'0{block_bits_2}b') # каждый блок преобразуем в двоичную последовательность размерностью Log2(n) +1 
        result_binary += encrypted_binary # объединяем в одну строку
    
    # Добавляем незначащие нули до замера блока для кратности 8 (размерности кодировки ASCII)
    if len(result_binary) % 8 != 0:
        padding = 8 - (len(result_binary) % 8)
        result_binary = '0' * padding + result_binary
    
    return result_binary # возвращаем двоичную последовательность

def decrypt(ciphertext, private_key):
    n, d = private_key
    block_bits = int(math.log2(n))
    block_size = block_bits + 1
    
    if len(ciphertext) % block_size != 0:
        ciphertext = ciphertext[len(ciphertext) % block_size:]
    # разбиваем битовую последовательность на блоки длнной логН+1
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    
    # Преобразуем, расшифровываем и форматируем в одном цикле
    binary_string = ''
    for block in blocks:
        block_num = int(''.join(map(str, block)), 2) # перевод двоичных блоков в десятичный вид
        decrypted = pow(block_num, d, n) # дешифруем 
        binary_string += format(decrypted, f'0{block_bits}b') # перевод в двоичное значение и объединение в строку
    
    # Убираем лишние биты и преобразуем в текст
    remainder = len(binary_string) % 8
    if remainder:
        binary_string = binary_string[remainder:]
    # Разбиваем на блоки по 8 бит и убираем незначащие нули и преобразуем в текст
    return ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))
    

def save_key(key, filename):
    """Сохраняет ключ в файл."""
    with open(filename, 'w') as f:
        n, exp = key
        f.write(f"{n}\n{exp}")
    

def load_key(filename):
    """Загружает ключ из файла."""
    with open(filename, 'r') as f:
        n = int(f.readline().strip())
        exp = int(f.readline().strip())
    return (n, exp)

def main():
    """Основная функция программы — реализует интерактивное меню."""
    while True:
        print("\n=== ПРОГРАММА РЕАЛИЗАЦИИ КРИПТОАЛГОРИТМА RSA ===")
        print("\n" + "="*50)
        print("1. Сгенерировать ключи")
        print("2. Зашифровать файл")
        print("3. Расшифровать файл")
        print("4. Выход")
        choice = input("Выберите действие: ")

        if choice == '1':
            bits = int(input("Размер ключа (бит): "))
            pub, priv = generate_keypair(bits)
            save_key(pub, "public.key")
            save_key(priv, "private.key")
            print("Ключи сохранены в public.key и private.key")

        elif choice == '2':
            try:
                pub = load_key("public.key")
                filename = input("Имя файла для шифрования: ")
                with open(filename, 'r', encoding='utf-8') as f:
                    text = f.read()
                ct = encrypt(text, pub)
                with open("ciphertext.txt", 'w', encoding='utf-8') as f:
                    f.write(ct)
                print("Шифротекст сохранён в ciphertext.txt")
            except FileNotFoundError as e:
                print(f"Ошибка: {e}")

        elif choice == '3':
            try:
                priv = load_key("private.key")
                with open("ciphertext.txt", 'r', encoding='utf-8') as f:
                    ct_bin = f.read().strip()
                pt = decrypt(ct_bin, priv)
                with open("decrypted.txt", 'w', encoding='utf-8') as f:
                    f.write(pt)
                print("Расшифрованный текст сохранён в decrypted.txt")
            except FileNotFoundError as e:
                print(f"Ошибка: {e}")

        elif choice == '4':
            print("До свидания!")
            break
        else:
            print("Неверный ввод, попробуйте снова.")

if __name__ == "__main__":
    main()
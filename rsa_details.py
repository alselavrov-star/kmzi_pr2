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
            except ValueError:
                print("Ошибка: введите целое число или нажмите Enter")

def egcd(a, b):
    """Расширенный алгоритм Евклида."""
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def are_coprime(a, b):
    return math.gcd(a, b) == 1

def modinv(a, m):
    """Находит модульное обратное число."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('No inverse')
    return x % m

def generate_keypair(bits):
    """Генерирует пару ключей RSA с выводом промежуточных шагов."""
    print("\n=== ГЕНЕРАЦИЯ КЛЮЧЕЙ ===")
    print("Введите значение p, или нажмите enter для автоматической генерации")
    p = generate_prime(bits // 2)
    print("Введите значение q, или нажмите enter для автоматической генерации")
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    print(f"\nВычислено n = p * q = {p} * {q} = {n}")
    print(f"Вычислено φ(n) = (p-1)*(q-1) = {p-1} * {q-1} = {phi}")
    print("Введите значение открытой экспоненты e (должна быть взаимно проста с φ(n)):")
    while True:
        try:
            e = int(input())
            if are_coprime(e, phi):
                d = modinv(e, phi)
                print(f"e = {e} взаимно просто с φ(n)")
                print(f"Вычислено d = e^(-1) mod φ(n) = {d}")
                break
            else:
                print(f"Ошибка: {e} не взаимно просто с {phi}")
                print("Пожалуйста, введите другое значение e:")
        except ValueError:
            print("Ошибка: введите целое число")
            print("Пожалуйста, введите значение e:")
    print(f"Публичный ключ: (n={n}, e={e})")
    print(f"Приватный ключ: (n={n}, d={d})")
    return ((n, e), (n, d))

def encrypt(plaintext, public_key):
    """Шифрует текст с подробным выводом каждого шага."""
    n, e = public_key
    print("\n=== ШИФРОВАНИЕ ===")
    print(f"Исходный текст: {plaintext}")

    # Преобразуем текст в двоичную строку, каждый символ -> 8 бит ASCII
    binary_string = ''.join(format(ord(ch), '08b') for ch in plaintext)
    print(f"Двоичное представление (8 бит на символ): {binary_string}")
    print(f"Длина двоичной строки: {len(binary_string)} бит")

    # Определяем размер блока с округлением в меньшую сторону
    block_bits = int(math.log2(n))
    print(f"Размер блока (floor(log2(n))): {block_bits} бит")

    # Добавляем нули в начало, если длина не кратна размеру блока
    if len(binary_string) % block_bits != 0:
        padding = block_bits - (len(binary_string) % block_bits)
        binary_string = '0' * padding + binary_string
        print(f"Добавлено {padding} ведущих нулей для кратности блоку")
        print(f"Двоичная строка после добавления нулей: {binary_string}")
    else:
        print("Длина уже кратна размеру блока, дополнение не требуется")

    block_bits_2 = block_bits + 1
    print(f"Размер зашифрованного блока: {block_bits_2} бит")
    result_binary = ''

    # Разбиваем на блоки по block_bits
    num_blocks = len(binary_string) // block_bits
    print(f"\nРазбиваем на {num_blocks} блоков по {block_bits} бит:")
    for i in range(0, len(binary_string), block_bits):
        block = binary_string[i:i + block_bits]
        block_number = int(block, 2)
        print(f"\nБлок {i//block_bits + 1}: {block} -> десятичное {block_number}")
        encrypted = pow(block_number, e, n)
        print(f"  {block_number}^{e} mod {n} = {encrypted}")
        encrypted_binary = format(encrypted, f'0{block_bits_2}b')
        print(f"  Зашифрованный блок в двоичном виде ({block_bits_2} бит): {encrypted_binary}")
        result_binary += encrypted_binary

    # Добавляем незначащие нули до кратности 8 для удобства записи
    if len(result_binary) % 8 != 0:
        padding = 8 - (len(result_binary) % 8)
        result_binary = '0' * padding + result_binary
        print(f"\nДобавлено {padding} ведущих нулей для кратности 8 битам")
    print(f"\nИтоговая зашифрованная двоичная последовательность:\n{result_binary}")
    print(f"Длина: {len(result_binary)} бит")
    return result_binary

def decrypt(ciphertext_bin, private_key):
    """Расшифровывает двоичную строку с подробным выводом."""
    n, d = private_key
    print("\n=== РАСШИФРОВАНИЕ ===")
    print(f"Входная зашифрованная двоичная строка: {ciphertext_bin}")
    print(f"Длина: {len(ciphertext_bin)} бит")

    block_bits = int(math.log2(n))
    block_size = block_bits + 1
    print(f"Размер блока при расшифровании: {block_size} бит")

    # Удаляем возможные лишние биты в начале, если длина не кратна размеру блока
    if len(ciphertext_bin) % block_size != 0:
        old_len = len(ciphertext_bin)
        ciphertext_bin = ciphertext_bin[len(ciphertext_bin) % block_size:]
        print(f"Удалено {old_len - len(ciphertext_bin)} начальных битов для кратности блоку")

    # Разбиваем на блоки
    blocks = [ciphertext_bin[i:i + block_size] for i in range(0, len(ciphertext_bin), block_size)]
    print(f"\nРазбито на {len(blocks)} блоков по {block_size} бит:")
    binary_string = ''

    for idx, block in enumerate(blocks):
        block_num = int(block, 2)
        print(f"\nБлок {idx+1}: {block} -> десятичное {block_num}")
        decrypted = pow(block_num, d, n)
        print(f"  {block_num}^{d} mod {n} = {decrypted}")
        block_binary = format(decrypted, f'0{block_bits}b')
        print(f"  Расшифрованный блок в двоичном виде ({block_bits} бит): {block_binary}")
        binary_string += block_binary

    print(f"\nОбъединённая двоичная строка после расшифрования: {binary_string}")
    print(f"Длина: {len(binary_string)} бит")

    # Убираем добавленные при шифровании ведущие нули (кратность 8 битам)
    remainder = len(binary_string) % 8
    if remainder:
        removed = remainder
        binary_string = binary_string[removed:]
        print(f"Удалено {removed} ведущих битов (восстановление исходного выравнивания)")

    # Разбиваем на 8-битные блоки и преобразуем в текст
    result_text = ''
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        if len(byte) == 8:
            ch = chr(int(byte, 2))
            result_text += ch
    print(f"\nРасшифрованный текст: {result_text}")
    return result_text

def save_key(key, filename):
    with open(filename, 'w') as f:
        n, exp = key
        f.write(f"{n}\n{exp}")
    print(f"Ключ сохранён в {filename}")

def load_key(filename):
    with open(filename, 'r') as f:
        n = int(f.readline().strip())
        exp = int(f.readline().strip())
    print(f"Ключ загружен из {filename}: (n={n}, exp={exp})")
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
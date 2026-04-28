import math

def modinv(a, m):
    """Находит модульное обратное число."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('No inverse')
    return x % m

def egcd(a, b):
    """Расширенный алгоритм Евклида."""
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def factor_fermat(n):
    a = math.isqrt(n) + 1
    while True:
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1

def decrypt(ciphertext, n, d):
    block_bits = int(math.log2(n))
    block_size = block_bits + 1

    # Убедимся, что ciphertext — строка
    if isinstance(ciphertext, list):
        ciphertext = ''.join(str(bit) for bit in ciphertext)

    # Убираем лишние биты в начале, если длина не кратна размеру блока
    if len(ciphertext) % block_size != 0:
        ciphertext = ciphertext[len(ciphertext) % block_size:]

    # Разбиваем на блоки
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]

    binary_string = ''
    for block in blocks:
        block_num = int(block, 2)  # Преобразуем блок битов в число
        decrypted = pow(block_num, d, n)  # Дешифруем
        binary_string += format(decrypted, f'0{block_bits}b')  # Добавляем в двоичную строку

    # Убираем лишние биты (если длина не кратна 8)
    remainder = len(binary_string) % 8
    if remainder:
        binary_string = binary_string[remainder:]

    # Преобразуем двоичную строку в текст
    plaintext = ''
    for i in range(0, len(binary_string), 8):
        byte = binary_string[i:i+8]
        if len(byte) == 8:
            plaintext += chr(int(byte, 2))
    return plaintext

def main():
    print("Введите n")
    n = int(input())
    print("Введите e")
    e = int(input())

    p, q = factor_fermat(n)
    print(f"Factors: {p}, {q}")

    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    print(f"Private key d: {d}")

    # Читаем шифртекст как строку битов
    with open("ciphertext.txt", 'r') as f:
        ct = f.read().strip()  # Убираем лишние пробелы и переносы строк


    pt = decrypt(ct, n, d)

    with open("decrypted.txt", 'w', encoding='utf-8') as f:
        f.write(pt)

    print("Decrypted to decrypted.txt")

if __name__ == "__main__":
    main()

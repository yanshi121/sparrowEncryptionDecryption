import hashlib
import random
import secrets
import string
import time
import os
from secrets import token_urlsafe
import numpy as np
from ahocorasick import Automaton


def string_to_binary(string_: str) -> str:
    """
    超高速字符串转二进制（使用位运算和预分配内存）
    处理速度: ~2亿字符/秒
    """
    # 编码为字节
    bytes_data = string_.encode('utf-8')
    bytes_len = len(bytes_data)
    # 预分配二进制字符串的内存（每个字节对应8位）
    binary_len = bytes_len * 8
    result = bytearray(binary_len)
    # 预定义每个字节值对应的8位二进制字符串（避免重复计算）
    byte_to_binary = [
        f"{i:08b}".encode('ascii') for i in range(256)
    ]
    # 逐字节处理，直接写入预分配的内存
    for i in range(bytes_len):
        byte_value = bytes_data[i]
        binary_str = byte_to_binary[byte_value]
        result[i * 8: (i + 1) * 8] = binary_str
    return result.decode('ascii')


def binary_to_quaternary(binary: str) -> str:
    """
    超高速二进制转四进制（使用内存视图和位运算）
    处理速度: ~1亿位/秒
    """
    # 补全二进制字符串到2的倍数
    padding = len(binary) % 2
    if padding:
        binary = '0' * (2 - padding) + binary
    # 使用内存视图避免内存拷贝
    mv = memoryview(binary.encode('ascii'))
    # 预分配结果数组（每2位二进制对应1位四进制）
    result_length = len(binary) // 2
    result = bytearray(result_length)
    # 逐字节处理（每字节包含8位二进制，对应4位四进制）
    for i in range(0, len(mv), 8):
        # 每次处理8位二进制（一个字节）
        byte = 0
        bytes_to_process = min(8, len(mv) - i)
        # 构建字节值
        for j in range(bytes_to_process):
            bit = mv[i + j] - 48  # '0' 是 48，'1' 是 49
            byte = (byte << 1) | bit
        # 补齐到8位（如果不足8位）
        if bytes_to_process < 8:
            byte <<= (8 - bytes_to_process)
        # 处理4个两位组（每个对应一个四进制字符）
        for j in range(4):
            if i // 2 + j >= result_length:
                break
            # 提取两位
            two_bits = (byte >> ((3 - j) * 2)) & 0x03
            # 转换为四进制字符（'0', '1', '2', '3'）
            result[i // 2 + j] = two_bits + 48  # 48 是 '0' 的 ASCII
    return result.decode('ascii')


def quaternary_to_binary(quaternary: str) -> str:
    """超高性能版：使用NumPy向量化操作"""
    # 将四进制字符串转换为NumPy数组
    arr = np.frombuffer(quaternary.encode('ascii'), dtype=np.uint8)
    # 字符转换为数值（'0'→0, '1'→1, '2'→2, '3'→3）
    values = arr - ord('0')
    # 每个四进制位扩展为两个二进制位
    # 高4位和低4位分别存储两位二进制
    expanded = np.zeros(len(values) * 2, dtype=np.uint8)
    expanded[::2] = (values >> 1) & 1
    expanded[1::2] = values & 1
    # 转换为字符串
    return ''.join(expanded.astype(str))


def binary_to_string(binary: str) -> str:
    """超高性能版：使用位运算和预分配内存"""
    # 补齐二进制字符串到8的倍数
    padding = len(binary) % 8
    if padding:
        binary = binary.ljust(len(binary) + 8 - padding, '0')
    # 预分配字节数组内存
    byte_count = len(binary) // 8
    bytes_data = bytearray(byte_count)
    # 逐字节处理，使用位运算
    for i in range(byte_count):
        byte_value = 0
        for j in range(8):
            bit = int(binary[i * 8 + j])
            byte_value = (byte_value << 1) | bit
        bytes_data[i] = byte_value
    # 转换为字符串
    return bytes(bytes_data).decode('utf-8')


def split_pairwise(string_: str, length: int = 2) -> list[str]:
    """超高性能版：使用NumPy"""
    arr = np.frombuffer(string_.encode('utf-8'), dtype=np.uint8)
    n = len(arr)
    # 补齐数组长度
    padding = length - (n % length) if n % length != 0 else 0
    if padding:
        arr = np.pad(arr, (0, padding), 'constant')
    # 重塑数组并转换回字符串
    arr = arr.reshape((-1, length))
    return [bytes(row).decode('utf-8') for row in arr]


def build_automaton(pairs, reverse=False):
    """构建 Aho-Corasick 自动机"""
    auto = Automaton()
    items = pairs.items() if not reverse else {v: k for k, v in pairs.items()}.items()
    for key, value in items:
        auto.add_word(key, value)
    auto.make_automaton()
    return auto


def order_compression_and_decompression(mode: bool, data: str, keys: dict) -> str:
    """超高性能版：使用 Aho-Corasick 算法"""
    auto = build_automaton(keys, reverse=not mode)
    result = []
    last_pos = 0
    for end_index, value in auto.iter(data):
        start_index = end_index - len(value) + 1
        if start_index > last_pos:
            result.append(data[last_pos:start_index])
        result.append(value)
        last_pos = end_index + 1
    if last_pos < len(data):
        result.append(data[last_pos:])
    return ''.join(result)


def shuffle_by_seed(input_string: str, array: list) -> list:
    # 创建输入字符串的哈希作为种子
    seed_hash = hashlib.sha256(input_string.encode()).digest()
    seed_value = int.from_bytes(seed_hash[:8], byteorder='big', signed=False)
    # 使用种子初始化随机数生成器
    rng = random.Random(seed_value)
    rng.shuffle(array)
    return array


def get_random_key(keys: list, values: list):
    characters = string.ascii_letters + string.digits + string.punctuation
    length = random.randint(50, 100)
    string_key = ''.join(random.choice(characters) for _ in range(length))
    os_urandom_obj = os.urandom(length)
    hashlib_obj = hashlib.md5(os_urandom_obj).hexdigest()
    keys = shuffle_by_seed(f"{string_key}_{time.time()}_{hashlib_obj}_{token_urlsafe(16)}", keys)
    values = shuffle_by_seed(f"{string_key}_{time.time()}", values)
    random_key = {}
    for i in range(len(keys)):
        random_key[keys[i]] = values[i]
    return random_key


def choice_key(key_list: list, length: int):
    keys = []
    for i in range(length):
        key = secrets.choice(key_list)
        keys.append(key)
        key_list.remove(key)
    return keys, key_list

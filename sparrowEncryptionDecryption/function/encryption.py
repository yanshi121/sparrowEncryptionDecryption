import time
from sparrowEncryptionDecryption.function.config import KEYS1, KEYS2
from sparrowEncryptionDecryption.tools import string_to_binary
from sparrowEncryptionDecryption.tools import binary_to_quaternary
from sparrowEncryptionDecryption.tools import split_pairwise
from sparrowEncryptionDecryption.tools import compression_and_decompression2
from sparrowEncryptionDecryption.tools import compression_and_decompression


class SparrowEncryption:
    def __init__(self, keys1: dict = None, keys2: dict = None):
        if keys1 is None:
            self.keys1 = KEYS1
        else:
            self.keys1 = keys1
        if keys2 is None:
            self.keys2 = KEYS2
        else:
            self.keys2 = keys2

    def order_encryption(self, string: str, key: str, effective_duration=-1, is_compression=2, mode=0):
        """
        加密数据
        :param string: 需要被加密的数据
        :param key: 秘钥
        :param effective_duration: 秘钥过期时间，-1为永不过期
        :param is_compression: 默认为2，二次压缩压缩，1为一次压缩，0为不压缩
        :param mode: 加密模式，0为二进制加密，1为四进制加密
        :return: 返回被加密好的数据
        """
        compression = None
        if mode == 0:
            binary_list = split_pairwise(str(string_to_binary(string + ";" + str(effective_duration) + ";" + key + ";" + str(time.time()))))
            binary = ""
            for i in binary_list:
                if i == "00":
                    binary += "A"
                elif i == "01":
                    binary += "T"
                elif i == "11":
                    binary += "C"
                elif i == "10":
                    binary += "G"
            if is_compression == 0:
                return binary + "零三"
            if is_compression == 1:
                compression = compression_and_decompression(True, binary, self.keys1) + "一三"
            if is_compression == 2:
                compression = compression_and_decompression2(True, compression_and_decompression(True, binary.replace("一", ''), self.keys1), self.keys2) + "二三"
        elif mode == 1:
            binary = string_to_binary(string + ";" + str(effective_duration) + ";" + key + ";" + str(time.time()))
            quaternary = str(binary_to_quaternary(binary)).replace("0", "A").replace("1", "T").replace("2", "C").replace("3", "G")
            if is_compression == 0:
                return quaternary + "零四"
            if is_compression == 1:
                compression = compression_and_decompression(True, quaternary, self.keys1) + "一四"
            if is_compression == 2:
                compression = compression_and_decompression2(True, compression_and_decompression(True, quaternary.replace("一", ''), self.keys1), self.keys2) + "二四"
        return compression

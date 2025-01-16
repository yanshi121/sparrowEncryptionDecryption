import time
from sparrowEncryptionDecryption.function.config import ORDER_KEYS1
from sparrowEncryptionDecryption.function.config import ORDER_KEYS2
from sparrowEncryptionDecryption.function.config import EASY_KEYS1
from sparrowEncryptionDecryption.function.config import EASY_KEYS2
from sparrowEncryptionDecryption.tools import string_to_binary
from sparrowEncryptionDecryption.tools import split_double_pairwise
from sparrowEncryptionDecryption.tools import binary_to_quaternary
from sparrowEncryptionDecryption.tools import split_pairwise
from sparrowEncryptionDecryption.tools import order_compression_and_decompression2
from sparrowEncryptionDecryption.tools import order_compression_and_decompression
from sparrowEncryptionDecryption.tools import SparrowKeyTypeError
from sparrowEncryptionDecryption.tools import SparrowStringTypeError
from sparrowEncryptionDecryption.tools import SparrowModeRangeError
from sparrowEncryptionDecryption.tools import SparrowCompressionRangeError


class SparrowEncryption:
    def __init__(self):
        self._keys1_ = ORDER_KEYS1
        self._keys2_ = ORDER_KEYS2

    def order_encryption(self, string: str, key: str, effective_duration: int = -1, is_compression: int = 2,
                         mode: int = 0):
        """
        加密数据
        :param string: 需要被加密的数据
        :param key: 秘钥
        :param effective_duration: 秘钥过期时间，-1为永不过期
        :param is_compression: 默认为2，二次压缩压缩，1为一次压缩，0为不压缩
        :param mode: 加密模式，0为二进制加密，1为四进制加密
        :return: 返回被加密好的数据
        """
        if type(key) is not str:
            raise SparrowKeyTypeError
        if type(string) is not str:
            raise SparrowStringTypeError
        if str(is_compression) not in ['0', '1', '2']:
            raise SparrowCompressionRangeError
        if str(mode) not in ['0', '1']:
            raise SparrowModeRangeError
        compression = None
        if mode == 0:
            binary_list = split_pairwise(
                str(string_to_binary(string + ";" + str(effective_duration) + ";" + key + ";" + str(time.time()))))
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
                compression = order_compression_and_decompression(True, binary, self._keys1_) + "一三"
            if is_compression == 2:
                compression = order_compression_and_decompression2(
                    True, order_compression_and_decompression(
                        True, binary.replace("一", ''), self._keys1_), self._keys2_) + "二三"
        elif mode == 1:
            binary = string_to_binary(string + ";" + str(effective_duration) + ";" + key + ";" + str(time.time()))
            quaternary = (str(binary_to_quaternary(binary)).replace("0", "A")
                          .replace("1", "T").replace("2", "C").replace("3", "G"))
            if is_compression == 0:
                return quaternary + "零四"
            if is_compression == 1:
                compression = order_compression_and_decompression(True, quaternary, self._keys1_) + "一四"
            if is_compression == 2:
                compression = order_compression_and_decompression2(
                    True, order_compression_and_decompression(
                        True, quaternary.replace("一", ''), self._keys1_), self._keys2_) + "二四"
        return compression

    @staticmethod
    def easy_encryption(string: str, key: str, mode: int = 0):
        """
        加密数据
        :param string: 需要被加密的数据
        :param key: 秘钥
        :param mode: 加密模式，0为二进制加密，1为四进制加密
        :return: 返回被加密好的数据
        """
        if type(key) is not str:
            raise SparrowKeyTypeError
        if type(string) is not str:
            raise SparrowStringTypeError
        if str(mode) not in ['0', '1']:
            raise SparrowModeRangeError
        encryption_data = ""
        encryption_key_data = ""
        if str(mode) == "0":
            split_data = split_double_pairwise(str(string_to_binary(string)))
            for i in split_data:
                encryption_data += EASY_KEYS1[i]
            split_key_data = split_double_pairwise(str(string_to_binary(key)))
            for i in split_key_data:
                encryption_key_data += EASY_KEYS1[i]
        elif str(mode) == "1":
            split_data = split_double_pairwise(str(binary_to_quaternary(str(string_to_binary(string)))))
            for i in split_data:
                encryption_data += EASY_KEYS2[i]
            split_key_data = split_double_pairwise(str(binary_to_quaternary(str(string_to_binary(key)))))
            for i in split_key_data:
                encryption_key_data += EASY_KEYS2[i]
        key_a = encryption_key_data[0: int(len(encryption_key_data) / 2)]
        key_b = encryption_key_data[int(len(encryption_key_data) / 2)::]
        data_a = encryption_data[0: int(len(encryption_data) / 2)]
        data_b = encryption_data[int(len(encryption_data) / 2)::]
        if str(mode) == "0":
            return key_a + "/" + data_a + "/" + encryption_key_data + "/" + data_b + "/" + key_b + "/" + "二"
        elif str(mode) == "1":
            return key_a + "/" + data_a + "/" + encryption_key_data + "/" + data_b + "/" + key_b + "/" + "四"


class SparrowEncryptionAsync(SparrowEncryption):
    def __init__(self):
        super().__init__()  # 正确调用父类构造函数

    @staticmethod
    async def easy_encryption(string: str, key: str, mode: int = 0):
        # 如果此方法不涉及I/O或其他耗时操作，则无需定义为异步
        return SparrowEncryption.easy_encryption(string, key, mode)

    async def order_encryption(self, string: str, key: str, effective_duration: int = -1, is_compression: int = 2,
                               mode: int = 0):
        # 如果此方法不涉及I/O或其他耗时操作，则无需定义为异步
        return await self._sync_to_async(SparrowEncryption.order_encryption)(
            self=self, string=string, key=key, effective_duration=effective_duration,
            is_compression=is_compression, mode=mode
        )

    @staticmethod
    def _sync_to_async(func):
        import asyncio
        from functools import partial
        loop = asyncio.get_event_loop()

        def wrapper(*args, **kwargs):
            # 将同步函数封装成异步函数
            future = loop.run_in_executor(None, partial(func, *args, **kwargs))
            return future

        return wrapper

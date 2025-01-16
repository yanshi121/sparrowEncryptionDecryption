import time
import asyncio
from functools import partial
from sparrowEncryptionDecryption.function.config import ORDER_KEYS1
from sparrowEncryptionDecryption.function.config import ORDER_KEYS2
from sparrowEncryptionDecryption.function.config import EASY_KEYS1
from sparrowEncryptionDecryption.function.config import EASY_KEYS2
from sparrowEncryptionDecryption.tools import binary_to_string
from sparrowEncryptionDecryption.tools import quaternary_to_binary
from sparrowEncryptionDecryption.tools import order_compression_and_decompression2
from sparrowEncryptionDecryption.tools import order_compression_and_decompression
from sparrowEncryptionDecryption.tools import SparrowBeDecryptionContentError
from sparrowEncryptionDecryption.tools import SparrowSecretKeyOverdueError
from sparrowEncryptionDecryption.tools import SparrowSecretKeyError
from sparrowEncryptionDecryption.tools import SparrowDecompressionTypeError
from sparrowEncryptionDecryption.tools import SparrowKeyTypeError


class SparrowDecryption(object):
    def __init__(self):
        self._keys1_ = ORDER_KEYS1
        self._keys2_ = ORDER_KEYS2

    def order_decryption(self, decompression: str, key: str):
        """
        将被加密的数据解密
        :param decompression: 需要被解密的数据
        :param key: 秘钥
        :return: 返回被解密的数据或秘钥错误类型
        """
        if type(decompression) is not str:
            raise SparrowDecompressionTypeError
        if type(key) is not str:
            raise SparrowKeyTypeError
        if "三" in decompression:
            try:
                if "零" in decompression:
                    decompression = decompression.replace("零", '').replace("三", "")
                else:
                    if "一" in decompression:
                        decompression = order_compression_and_decompression(
                            False, decompression.replace("一", '').replace("三", ""), self._keys1_)
                    elif "二" in decompression:
                        decompression = order_compression_and_decompression(
                            False, order_compression_and_decompression2(
                                False, decompression.replace("二", "").replace("三", ""), self._keys2_) + "",
                            self._keys1_)
                    else:
                        raise SparrowBeDecryptionContentError
                string = binary_to_string(
                    decompression.replace("A", "00").replace("T", "01").replace("C", "11")
                    .replace("G", "10")).split(";")
            except Exception:
                raise SparrowBeDecryptionContentError
        elif "四" in decompression:
            try:
                if "零" in decompression:
                    decompression = decompression.replace("零", '').replace("四", "")
                else:
                    if "一" in decompression:
                        decompression = order_compression_and_decompression(False,
                                                                            decompression.replace("一", '')
                                                                            .replace("四", ""), self._keys1_)
                    elif "二" in decompression:
                        decompression = order_compression_and_decompression(False,
                                                                            order_compression_and_decompression2(
                                                                                False,
                                                                                decompression.replace("二", "")
                                                                                .replace("四", ""), self._keys2_),
                                                                            self._keys1_)
                    else:
                        raise SparrowBeDecryptionContentError
                binary = quaternary_to_binary(
                    decompression.replace("A", "0").replace("T", "1").replace("C", "2").replace("G", "3"))
                string = binary_to_string(binary).split(';')
            except Exception:
                raise SparrowBeDecryptionContentError
        else:
            raise SparrowBeDecryptionContentError
        if string[1] != "-1":
            effective_duration = int(time.time() - float(string[3]))
            if string[2] == key:
                if effective_duration < int(string[1]):
                    return string[0]
                else:
                    raise SparrowSecretKeyOverdueError
            else:
                raise SparrowSecretKeyError
        else:
            if string[2] == key:
                return string[0]
            else:
                raise SparrowSecretKeyError

    @staticmethod
    def easy_decryption(decompression: str, key: str):
        """
        将被加密的数据解密
        :param decompression: 需要被解密的数据
        :param key: 秘钥
        :return: 返回被解密的数据或秘钥错误类型
        """
        if type(decompression) is not str:
            raise SparrowDecompressionTypeError
        if type(key) is not str:
            raise SparrowKeyTypeError
        decryption_list = decompression.split("/")
        decryption_key_part = decryption_list[0] + decryption_list[4]
        decryption_key_group = decryption_list[2]
        encryption_mode = decryption_list[5]
        decryption_keys = {}
        if decryption_key_part == decryption_key_group:
            if encryption_mode == "四":
                for k, v in EASY_KEYS2.items():
                    decryption_keys[v] = k
                decryption_key = ""
                for i in decryption_key_group:
                    decryption_key += decryption_keys[i]
                decryption_key = binary_to_string(quaternary_to_binary(decryption_key))
                if decryption_key == key:
                    try:
                        encryption_data = decryption_list[1] + decryption_list[3]
                        decryption_data = ""
                        for i in encryption_data:
                            decryption_data += decryption_keys[i]
                        return binary_to_string(quaternary_to_binary(decryption_data))
                    except Exception:
                        raise SparrowBeDecryptionContentError
                else:
                    raise SparrowSecretKeyError
            elif encryption_mode == "二":
                for k, v in EASY_KEYS1.items():
                    decryption_keys[v] = k
                decryption_key = ""
                for i in decryption_key_group:
                    decryption_key += decryption_keys[i]
                decryption_key = binary_to_string(decryption_key)
                if decryption_key == key:
                    try:
                        encryption_data = decryption_list[1] + decryption_list[3]
                        decryption_data = ""
                        for i in encryption_data:
                            decryption_data += decryption_keys[i]
                        return binary_to_string(decryption_data)
                    except Exception:
                        raise SparrowBeDecryptionContentError
                else:
                    raise SparrowSecretKeyError
        else:
            raise SparrowBeDecryptionContentError("加密内容中秘钥数据已被修改，程序不解密")


class SparrowDecryptionAsync(SparrowDecryption):
    def __init__(self):
        super().__init__()

    async def order_decryption(self, decompression: str, key: str):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, partial(
            SparrowDecryption.order_decryption, self, decompression, key))

    @staticmethod
    async def easy_decryption(decompression: str, key: str):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, SparrowDecryption.easy_decryption, decompression, key)

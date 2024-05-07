import time
from sparrowEncryptionDecryption.config import KEYS1, KEYS2, OUT_TIME, KEY_ERROR


class SparrowEncryptionDecryption(object):
    def __init__(self, keys1: dict = None, keys2: dict = None):
        if keys1 is None:
            self.keys1 = KEYS1
        else:
            self.keys1 = keys1
        if keys2 is None:
            self.keys2 = KEYS2
        else:
            self.keys2 = keys2
        

    @staticmethod
    def _binary_to_quaternary_(binary: str):
        """
        将二进制转换为四进制
        :param binary: 二进制串
        :return: 返回二进制的四进制数据
        """
        quaternary = ""
        binary_length = len(binary)
        if binary_length % 2 != 0:
            binary = '0' * (2 - binary_length % 2) + binary
        for i in range(0, binary_length, 2):
            binary_pair = binary[i:i + 2]
            decimal_value = int(binary_pair, 2)
            quaternary_value = str(decimal_value)
            quaternary += quaternary_value

        return quaternary

    @staticmethod
    def _quaternary_to_binary_(quaternary: str):
        """
        将四进制转换为二进制
        :param quaternary: 四进制串
        :return: 返回四进制的二进制数据
        """
        binary = ''
        for digit in quaternary:
            binary += bin(int(digit))[2:].zfill(2)
        return binary

    @staticmethod
    def _string_to_binary_(string):
        """
        将字符串转换为二进制
        :param string: 字符串
        :return: 返回字符串的二进制数据
        """
        bytes_data = string.encode('utf-8')
        binary_data = ''.join(format(byte, '08b') for byte in bytes_data)
        return binary_data

    @staticmethod
    def _binary_to_string_(binary: str):
        """
        将二进制转换为字符串
        :param binary: 二进制串
        :return: 返回二进制代表的字符串
        """
        bytes_data = [int(binary[i:i + 8], 2) for i in range(0, len(binary), 8)]
        string = bytes(bytes_data).decode('utf-8')
        return string

    def _compression_and_decompression_(self, mode: bool, data: str):
        """
        将加密内容压缩或解压
        :param mode: True为加密，False为解密，bool类型
        :param data: 需要被压缩或解压的数据
        :return: 返回被压缩或解压的数据
        """
        if mode:
            for k, v in self.keys1.items():
                data = data.replace(k, v)
        else:
            for k, v in self.keys1.items():
                data = data.replace(v, k)
        return data

    def _compression_and_decompression2_(self, mode: bool, data: str):
        """
        将加密内容二次压缩或解压
        :param mode: True为加密，False为解密，bool类型
        :param data: 需要被压缩或解压的数据
        :return: 返回被压缩或解压的数据
        """
        if mode:
            for k, v in self.keys2.items():
                data = data.replace(k, v)
        else:
            for k, v in self.keys2.items():
                data = data.replace(v, k)
        return data

    @staticmethod
    def _split_pairwise_(string: str):
        """
        将字符串两两分为一组并存入数组
        :param string: 被分割的字符串
        :return: 返回分割好的数组
        """
        result = []
        for i in range(0, len(string), 2):
            result.append(string[i:i + 2])
        return result

    def encryption(self, string: str, key: str, effective_duration=-1, is_compression=2, mode=0):
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
            binary_list = self._split_pairwise_(str(self._string_to_binary_(string + ";" + str(effective_duration) + ";" + key + ";" + str(time.time()))))
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
                compression = self._compression_and_decompression_(True, binary) + "一三"
            if is_compression == 2:
                compression = self._compression_and_decompression2_(True, self._compression_and_decompression_(True, binary.replace("一", ''))) + "二三"
        elif mode == 1:
            binary = self._string_to_binary_(string + ";" + str(effective_duration) + ";" + key + ";" + str(time.time()))
            quaternary = str(self._binary_to_quaternary_(binary)).replace("0", "A").replace("1", "T").replace("2", "C").replace("3", "G")
            if is_compression == 0:
                return quaternary + "零四"
            if is_compression == 1:
                compression = self._compression_and_decompression_(True, quaternary) + "一四"
            if is_compression == 2:
                compression = self._compression_and_decompression2_(True, self._compression_and_decompression_(True, quaternary.replace("一", ''))) + "二四"
        return compression

    def decryption(self, decompression: str, key: str):
        """
        将被加密的数据解密
        :param decompression: 需要被解密的数据
        :param key: 秘钥
        :return: 返回被解密的数据或秘钥错误类型
        """
        string = None
        if "三" in decompression:
            if "零" in decompression:
                decompression = decompression.replace("零", '').replace("三", "")
            else:
                if "一" in decompression:
                    decompression = self._compression_and_decompression_(False, decompression.replace("一", '').replace("三", ""))
                if "二" in decompression:
                    decompression = self._compression_and_decompression_(False, self._compression_and_decompression2_(False, decompression.replace("二", "").replace("三", "")))
            string = self._binary_to_string_(decompression.replace("A", "00").replace("T", "01").replace("C", "11").replace("G", "10")).split(";")
        elif "四" in decompression:
            if "零" in decompression:
                decompression = decompression.replace("零", '').replace("四", "")
            else:
                if "一" in decompression:
                    decompression = self._compression_and_decompression_(False, decompression.replace("一", '').replace("四", ""))
                if "二" in decompression:
                    decompression = self._compression_and_decompression_(False, self._compression_and_decompression2_(False, decompression.replace("二", "").replace("四", "")))
            binary = self._quaternary_to_binary_(decompression.replace("A", "0").replace("T", "1").replace("C", "2").replace("G", "3"))
            string = self._binary_to_string_(binary).split(';')
        if string[1] != "-1":
            effective_duration = int(time.time() - float(string[3]))
            if string[2] == key:
                if effective_duration < int(string[1]):
                    return string[0]
                else:
                    return OUT_TIME
            else:
                return KEY_ERROR
        else:
            return string[0]


if __name__ == "__main__":
    a = SparrowEncryptionDecryption()
    data = a.encryption("test", "39", -1, 2, 0)
    print(data)
    d = a.decryption(data, "39")
    print(d)

# evillimiter/networking/units.py

class ValueConverter:
    @staticmethod
    def byte_to_bit(v):
        return v * 8

class BitRate(object):
    def __init__(self, rate=0):
        self.rate = rate

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        counter = 0
        r = self.rate
        while True:
            if r >= 1000:
                r /= 1000
                counter += 1
            else:
                unit = ""
                if counter == 0:
                    unit = "bit"
                elif counter == 1:
                    unit = "kbit"
                elif counter == 2:
                    unit = "mbit"
                elif counter == 3:
                    unit = "gbit"
                # Format the number, potentially removing trailing .0 if it's a float result of division
                formatted_rate = f"{r:.0f}" if r.is_integer() else f"{r:.2f}".rstrip('0').rstrip('.')
                return f"{formatted_rate}{unit}"
            if counter > 3:
                raise Exception("Bitrate limit exceeded")

    def __mul__(self, other):
        if isinstance(other, BitRate):
            return BitRate(int(self.rate * other.rate))
        return BitRate(int(self.rate * other))

    def fmt(self, fmt):
        string = self.__str__()
        end = len([_ for _ in string if _.isdigit()])
        num = int(string[:end])
        return "{}{}".format(fmt % num, string[end:])

    @classmethod
    def from_rate_string(cls, rate_string):
        return cls(BitRate._bit_value(rate_string))

    @staticmethod
    def _bit_value(rate_string):
        number = 0  # rate number
        offset = 0  # string offset
        for c in rate_string:
            if c.isdigit():
                number = number * 10 + int(c)
                offset += 1
            else:
                break
        unit = rate_string[offset:].lower()
        if unit == "bit":
            return number
        elif unit == "kbit":
            return number * 1000
        elif unit == "mbit":
            return number * 1000 ** 2
        elif unit == "gbit":
            return number * 1000 ** 3
        else:
            raise Exception("Invalid bitrate")


class ByteValue(object):
    def __init__(self, value=0):
        self.value = value

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        counter = 0
        v = self.value
        while True:
            if v >= 1024:
                v /= 1024
                counter += 1
            else:
                unit = ""
                if counter == 0:
                    unit = "b"
                elif counter == 1:
                    unit = "kb"
                elif counter == 2:
                    unit = "mb"
                elif counter == 3:
                    unit = "gb"
                elif counter == 4:
                    unit = "tb"
                # Format the number, potentially removing trailing .0 if it's a float result of division
                formatted_value = f"{v:.0f}" if v.is_integer() else f"{v:.2f}".rstrip('0').rstrip('.')
                return f"{formatted_value}{unit}"
            if counter > 4: # Allow TB
                raise Exception("Byte value limit exceeded")

    def __int__(self):
        return self.value

    def __add__(self, other):
        if isinstance(other, ByteValue):
            return ByteValue(int(self.value + other.value))
        return ByteValue(int(self.value + other))

    def __sub__(self, other):
        if isinstance(other, ByteValue):
            return ByteValue(int(self.value - other.value))
        return ByteValue(int(self.value - other))

    def __mul__(self, other):
        if isinstance(other, ByteValue):
            return ByteValue(int(self.value * other.value))
        return ByteValue(int(self.value * other))

    def __ge__(self, other):
        if isinstance(other, ByteValue):
            return self.value >= other.value
        return self.value >= other

    def fmt(self, fmt):
        string = self.__str__()
        end = len([_ for _ in string if _.isdigit()])
        num = int(string[:end])
        return "{}{}".format(fmt % num, string[end:])

    @classmethod
    def from_byte_string(cls, byte_string):
        return cls(ByteValue._byte_value(byte_string))

    @staticmethod
    def _byte_value(byte_string):
        number = 0  # rate number
        offset = 0  # string offset
        for c in byte_string:
            if c.isdigit():
                number = number * 10 + int(c)
                offset += 1
            else:
                break
        unit = byte_string[offset:].lower()
        if unit == "b":
            return number
        elif unit == "kb":
            return number * 1024
        elif unit == "mb":
            return number * 1024 ** 2
        elif unit == "gb":
            return number * 1024 ** 3
        elif unit == "tb":
            return number * 1024 ** 4
        else:
            raise Exception("Invalid byte string")

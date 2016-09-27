# -*- coding: utf-8 -*-
from bson.objectid import ObjectId
import datetime as dt
import flatdict
import six
from uuid import UUID


class UTC(dt.tzinfo):
    """
    UTC Time Object
    """
    ZERO = dt.timedelta(0)

    def utcoffset(self, dt):
        return self.ZERO

    def tzname(self, dt):
        return 'UTC'

    def dst(self, dt):
        return self.ZERO

UTC = UTC()
UUID_1_EPOCH = dt.datetime(1582, 10, 15, tzinfo=UTC)
UUID_TICKS_PER_SECOND = 10000000


def unix_time_to_uuid_time(dt):
    return int((dt - UUID_1_EPOCH).total_seconds() * UUID_TICKS_PER_SECOND)


def object_id_to_uuid(object_id):
    """
    将 ObjectId 转换为 UUID

    :param object_id: some ObjectId
    :return: UUID
    """
    str_object_id = str(object_id)

    b = []
    for i in [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22]:
        b.append(int(str_object_id[i:i+2], 16))

    generation_time = ObjectId(str_object_id).generation_time.astimezone(UTC)
    time = unix_time_to_uuid_time(generation_time)
    time |= (b[4] >> 6) & 0x3

    most_sig_bits = str(hex(0x1000 | time >> 48 & 0x0FFF
                            | time >> 16 & 0xFFFF0000
                            | time << 32))[9:]

    least_sig_bits = str(hex(2 << 62
                             | (b[4] & 0x3F) << 56 | (b[5] & 0xFF) << 48
                             | (b[6] & 0xFF) << 40 | (b[7] & 0xFF) << 32
                             | (b[8] & 0xFF) << 24 | (b[9] & 0xFF) << 16
                             | (b[10] & 0xFF) << 8 | b[11] & 0xFF))[2:]
    uuid_string = '%s-%s-%s-%s-%s' % (most_sig_bits[:8], most_sig_bits[8:12], most_sig_bits[12:16],
                                      least_sig_bits[0:4], least_sig_bits[4:-1])
    return uuid_string


def uuid():
    return object_id_to_uuid(ObjectId())


def flatten(properties):
    """
    将 Dict 转换为 Flatten Array

    e.g {'a':'b', 'c':[0, 1, 2]}
        =>
        [
            'a:b',
            'c.0:0',
            'c.1:1',
            'c.2:2'
        ]

    :param properties:
    :return:
    """
    flat = flatdict.FlatDict(properties, delimiter='.')
    result = []
    for k, v in six.iteritems(flat):
        result.append((k, v))
    return result


def unflatten(flatten_properties, splitter=None):
    """
    将 Flatten Array  转换为 Dict

    :param flatten_properties:
    :param splitter:
    :return:
    """
    dict_out = {}
    splitter = '.' if splitter is None else splitter
    for key, value in flatten_properties:
        keys = key.split(splitter)
        temp_dict = dict_out
        for i in range(len(keys)-1):
            if isinstance(temp_dict, list):
                idx = int(keys[i])
                for ii in range(len(dict_out), idx+1):
                    temp_dict.append(None)
                if temp_dict[idx] is None:
                    temp_dict[idx] = [] if keys[i+1].isdigit() else {}
                temp_dict = temp_dict[idx]
            elif isinstance(temp_dict, dict):
                field = keys[i]
                if field not in temp_dict:
                    temp_dict[field] = [] if keys[i+1].isdigit() else {}
                temp_dict = temp_dict[field]
        if isinstance(temp_dict, list):
            idx = int(keys[-1])
            for ii in range(len(temp_dict), idx + 1):
                temp_dict.append(None)
            temp_dict[idx] = value
        elif isinstance(temp_dict, dict):
            field = keys[-1]
            temp_dict[field] = value
    return dict_out


def rdn(dn):
    return dn if dn.index('=') < 0 else (dn + ',').split(',')[0].split('=')[1]


def xstr(s):
    if s is None:
        return ''
    return str(s)


def chunk(chunks, index, default=None, mapping=None):
    result = chunks[index] if len(chunks) > index else default
    return result if mapping is None else mapping(result)


def convert_string_to_integer(text, default=None):
    return default if text is None or len(text) == 0 else int(text)
import os
import struct

import pefile
from arc4 import ARC4


def locate_config(file_path):
    """
    Locate configuration section

    :param file_path:
    :return:
    """
    return pefile.PE(file_path).sections[3].get_data()


def data_decrypt(data):
    """
    Sodinokibi decryption routine

    :param data:
    :return:
    """
    return ARC4(data[0:32]).decrypt(data[40:40 + struct.unpack('<I', data[36:40])[0] - 1]).decode()


def extract_config(file_path):
    """
    Extract Sodinokibi config

    :param file_path:
    :return:
    """
    try:
        return data_decrypt(locate_config(file_path))
    except:
        return None


if __name__ == '__main__':
    if not os.path.exists('output'):
        os.mkdir('output')

    file_name = input('Insert unpacked REvil file name: ')

    plain_config = extract_config(file_name)

    if plain_config is None:
        print('Configuration could not be extracted. Is this Sodinokibi?')
    else:
        print('Extracting configuration')

        with open('output/config.txt', 'w') as f:
            f.write(plain_config)

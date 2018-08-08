def int_from_bytes(bytes_, byteorder):
    if byteorder == 'little':
        little_ordered = iter(bytes_)
    elif byteorder == 'big':
        little_ordered = reversed(iter(bytes_))
    n = sum(ord(v) << i*8 for i,v in enumerate(little_ordered))
    return n

def int_to_bytes(n, length, order):
    indexes = xrange(length) if order == 'little' else reversed(xrange(length))
    return ''.join(chr(n >> i*8 & 0xff) for i in indexes)

import asn1

"""
This example shows two different ways to write arbitrary sized byte arrays into
ASN.1 Null fields. This could be used when manually generating x509 certificates that
contain some kind of data payload

I might play around with trying embed message and payloads into common x509 extensions by adding
a null field to the extension.
"""

input_msg = """Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam nec sem eros. Fusce mattis nunc eget eros viverra, 
ac ultrices elit pellentesque. Proin quis neque vel ante vehicula egestas. Duis vestibulum nibh augue, non dapibus 
erat convallis quis. Praesent consequat enim non malesuada vulputate. Proin dignissim pulvinar nulla in accumsan. 
Vestibulum quis magna quis tortor aliquet gravida."""


def encode_null_not_universal(input_bytes, cls=asn1.Classes.Private):
    """ Encode a byte arrays in a Null ASN.1 field using any asn.1 class other than Universal
    """
    encoder = asn1.Encoder()
    encoder.start()
    encoder.write(input_bytes, nr=asn1.Numbers.Null, cls=cls)
    byte_data = encoder.output()
    print(f"asn1 encoded data: {byte_data}")

    decoder = asn1.Decoder()
    decoder.start(byte_data)
    while not decoder.eof():
        tag, value = decoder.read()
    return tag, value


def encode_null_unsafe(input_bytes):
    """ Encode a byte arrays in a Null ASN.1 field using the default Universal class. To do this,
    the code has to call internal functions in asn1 encoder to avoid logic around writing Null ASN.1 fields
    """
    nr = asn1.Numbers.Null
    typ = asn1.Types.Primitive
    cls = asn1.Classes.Universal
    encoder = asn1.Encoder()
    encoder.start()
    # call internal functions to avoid logic around null fields
    value = encoder._encode_octet_string(input_bytes)
    encoder._emit_tag(nr, typ, cls)
    encoder._emit_length(len(value))
    encoder._emit(value)
    byte_data = encoder.output()
    print(f"asn1 encoded data: {byte_data}")

    decoder = asn1.Decoder()
    decoder.start(byte_data)
    while not decoder.eof():
        # pass in the data type to override how asn1 reads Null for Universal fields
        tag, value = decoder.read(tagnr=asn1.Numbers.OctetString)
    return tag, value


def asn1_null_field_payload():
    input_bytes = bytes(input_msg, 'utf-8')

    # write a Null ASN.1 field that contains byte data
    tag, value = encode_null_not_universal(input_bytes)
    value = value.decode("utf-8")
    if value != input_msg:
        raise Exception("booooo!")
    print(tag)
    print(value)
    print()

    # write a Null ASN.1 field that contains byte data
    tag, value = encode_null_unsafe(input_bytes)
    value = value.decode("utf-8")
    if value != input_msg:
        raise Exception("booooo!")
    print(tag)
    print(value)


if __name__ == '__main__':
    asn1_null_field_payload()

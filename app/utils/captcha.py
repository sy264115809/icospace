import gvcode
import base64
from gvcode.compat import BytesIO


def generate_captcha(format = 'PNG', length = 4, **kwargs):
    img, code = gvcode.generate(format = format, length = length, **kwargs)
    out = BytesIO()
    img.save(out, format = format)
    b64_img = base64.b64encode(out.getvalue())
    return 'data:image/{type};base64,{img}'.format(type = format.lower(), img = b64_img), code

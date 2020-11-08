#RSA signatureize string data
#from data.cipher import *
from cipher import *
import hashlib
import time
from KeyManager import key

def SHA256(p):
        Sha256=hashlib.sha256()
        t=p.encode('utf-8')
        Sha256.update(t)
        hexSha256=Sha256.hexdigest()
        return hexSha256
def PrSign(p, k): # for timestamp and etc. private key signature. key requires n, d
        return '$'.join([str(encrypt(p, k.d, k.n)), SHA256(str(p))])
def PuSign(p, k): # public key signature. key requires n, e
        return '$'.join([str(encrypt(p, k.e, k.n)), SHA256(str(p))])
def CrSign(p, k): # Crypting Signature. key requires n, e, d
        ts = time.ctime() # timestamp
        return '@'.join([str(encrypt(p, k.e, k.n)), str(encrypt(SHA256(str(encrypt(p, k.e, k.n))), k.d, k.n)), PrSign(ts, k)])

def PrVerify(c, k):  # timestamp's private key signature verification. key req: n, e
        c = c.split('$')
        p = decrypt(c[0], k.e, k.n)
        t = SHA256(p) == c[1]
        return [p, t]
def PuVerify(c, k):  # public key signature verification. key req: n, d
        c = c.split('$')
        p = decrypt(c[0], k.d, k.n)
        t = SHA256(p) == c[1]
        return [p, t]
def CrVerify(p, k): # Crypting Signature verification. key req: n, e
        try:
                s = p.split('@')
                ts = PrVerify(s[2], k)
                a = SHA256(s[0])
                b = decrypt(s[1], k.e, k.n)
                #print(a, b, sep = '\n')
                #print(a, sep = '\n')        
        except IndexError as e: return('Cipher.py -> IndexError: {0}'.format(e))
        #print('key might be wrong...')
        #return 'key might be wrong...'
        
        if a == b:
                #print('True!!')
                return [ts, True]
        else:
                #print('False!!')
                return [ts, False]
def CrPlainify(s, k): # CS Plainification. key req: n, d
        return decrypt(s.split('@')[0], k.d, k.n)
'''
def PrSign(p, e, n, d):  # for timestamp. private key signature
        return '$'.join([str(encrypt(p, d, n)), SHA256(str(p))])

def CrSign(p, e, n, d):  # block 내용의 개인서명
        ts = time.ctime() # timestamp
        return '@'.join([str(encrypt(p, e, n)), str(encrypt(SHA256(str(encrypt(p, e, n))), d, n)), PrSign(ts, e, n, d)])

def PrVerify(p, e, n):  # timestamp's private key signature verification.
        p = p.split('$')
        ts = decrypt(p[0], e, n)
        t = SHA256(ts) == p[1]
        #print('\n'+SHA256(ts))
        #print('\n'+p[1])
        return [ts, t]

def CrVerify(sign, e, n):  # block 내용의 암호화서명검증
        s = sign.split('@')
        t = PrVerify(s[2], e, n)
        a = SHA256(s[0])
        b = decrypt(s[1], e, n)
        #print(a, b, sep = '\n')
        #print(a, sep = '\n')
        if a == b:
                #print('True!!')
                return [t, True]
        else:
                #print('False!!')
                return [t, False]
'''

'''
def RSAsign(p, e, n, d):  # block 내용의 개인서명
        pt = p + '@' + time.ctime()
        return [str(encrypt(p, e, n)), str(encrypt(SHA256(str(encrypt(p, e, n))), d, n))]  # 공개키 암호화

def RSAverify(s, e, n):  # block 내용의 개인서명검증
        s = s.split('@')
        a = SHA256(s[0])
        b = decrypt(s[1], e, n)
        if a == b:
                #print('True!!')
                return [t, True]
        else:
                #print('False!!')
                return [t, False]
'''

# below ~2020/06/13
'''
def RSAsign2(p, e, n, d):  # timestamp의 공개서명
    return [str(encrypt(p, d, n)), SHA256(str(p))]

def RSAsign(p, e, n, d):  # block 내용의 개인서명
    ts = time.ctime()
    return [str(encrypt(p, e, n)), str(encrypt(SHA256(str(encrypt(p, e, n))), d, n)), '$'.join(RSAsign2(ts, e, n, d))]

def RSAver2(p, e, n):  # timestamp의 공개서명검증
    ts = decrypt(p[0], e, n)
    t = SHA256(ts) == p[1]
    #print('\n'+SHA256(ts))
    #print('\n'+p[1])
    return [ts, t]

def RSAverify(sign, e, n):  # block 내용의 개인서명검증
    s = sign.split('@')
    t = RSAver2(s[2].split('$'), e, n)
    a = SHA256(s[0])
    b = decrypt(s[1], e, n)
    #print(a, b, sep = '\n')
    #print(a, sep = '\n')
    if a == b:
        #print('True!!')
        return [t, True]
    else:
        #print('False!!')
        return [t, False]

if __name__ == '__main__':
    n = 31676752383854794769589854195828579304231624214914393413957992306742067982482522587049928127438987671892790033105815366098002296580475308743951016838387617270426754392394247210737391222025461055958428135975057543602878915586908468232709968938543879814490285144968954294924834481082462166280031545001002383141910546487553748229076090776652358284066624500207847029802920479192468652315744164515545257064675733920210767975367286624852952806544768362710126480033878138983023442041237199979436667275943393548845708049972189007053497973123660659710453502661849957442201173555195005893594123241760739194046811366050377870553
    e = 65537
    d = 5578727680767383939310711462658551083043798261875611162914127091633992228112566576128450653018917492545990548272080213551171742788529319522142951864575276233810909855455916525113004401858764842880696057882175170793054739211500336303796915658157582141673358120500353547950355365376104770178740621212468826864516577677989599866257150233061258871884873656211309116662493424327896680453275241417233609327952791670587481424933682590038429230693397266143963260674464510856755989922955688232242658730827287786241828086836615434276907371272529001015440637950284044466639499403976033764765250968351848503270597625502654009313
    p = 'ㄱask;dljf;slkdj'

    import time
    ts = time.ctime()


    s = RSAsign(p, e, n, d)
    #for i in s: print(i)
    print(s)
    print(RSAverify('@'.join(s), e, n))
'''

if __name__ == '__main__':
        p = 'aaaあㄱask;新しいdljf;slkdなにに しますか우왕？j' # just don't put 分 in this!!!(would occur errors and faults...) if you want this so bad, modify 'cipher.py'
        k = key(31676752383854794769589854195828579304231624214914393413957992306742067982482522587049928127438987671892790033105815366098002296580475308743951016838387617270426754392394247210737391222025461055958428135975057543602878915586908468232709968938543879814490285144968954294924834481082462166280031545001002383141910546487553748229076090776652358284066624500207847029802920479192468652315744164515545257064675733920210767975367286624852952806544768362710126480033878138983023442041237199979436667275943393548845708049972189007053497973123660659710453502661849957442201173555195005893594123241760739194046811366050377870553,
                65537,
                5578727680767383939310711462658551083043798261875611162914127091633992228112566576128450653018917492545990548272080213551171742788529319522142951864575276233810909855455916525113004401858764842880696057882175170793054739211500336303796915658157582141673358120500353547950355365376104770178740621212468826864516577677989599866257150233061258871884873656211309116662493424327896680453275241417233609327952791670587481424933682590038429230693397266143963260674464510856755989922955688232242658730827287786241828086836615434276907371272529001015440637950284044466639499403976033764765250968351848503270597625502654009313)
        k.showinfo()
        while True:
                print('current plaindata:', p)
                p = input('plain data: ')
                a = input('create a CrSign? or try a PuSign? or verify other CrSignatures?(1 or 2 or other): ')
                if a == '1':
                        a = input('Sign? Verify?(1 or other): ')
                        if a == '1':
                                s = CrSign(p, k)
                                print(s)
                        else:
                                s = input('crypted msg:\n')
                                print('Verification:', CrVerify(s, k), sep = '\n')
                                print('PlainText:', CrPlainify(s, k), sep = '\n')
                elif a == '2':
                        a = input('Sign? Verify?(1 or other): ')
                        if a == '1':
                                s = PuSign(p, k) # PrSign is also good too
                                print(s)
                        else:
                                s = input('crypted msg:\n')
                                print('PuVerify:\n{}'.format(PuVerify(s, k)))
                else:
                        break
                print('\n', '*'*10, '\n')
'''
True!!
[['Thr Nov 14 14:58:11 2019', True], True]
'''

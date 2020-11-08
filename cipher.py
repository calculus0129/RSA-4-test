"""

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'''convert_to.py'''

#Returns decimal representation of a message to feed into RSA
def convert_to_hex (message):
        hex_arr = []
        for letter in message:
                hex_arr.append(str(format(ord(letter),'x').zfill(4)))
        return ''.join(hex_arr)

def convert_to_ascii(hex_input):
        hex_input = str(hex_input)
        chr_arr = []
        #iterate over the string and group FOUR characters at a time (since all ascii chars will be FOUR hex chars)
        num_digits = 4
        for i in range(0, len(hex_input), num_digits):
                hex_number = hex_input[i:i+num_digits]
                chr_arr.append(chr(int(hex_number, 16)))
        return ''.join(chr_arr)

#test
'''
if __name__ == '__main__':
        while True:
                a = input('Test String: ')
                print('Hex String: {}'.format(convert_to_hex(a)))
                print('ASCII String: {}'.format(convert_to_ascii(convert_to_hex(a))))
'''
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
'''cipher.py'''
#exponentiation by squaring is not necessary because of python's awesome 3-arg pow()
#public key: (n,e)
#private key: (n,d)
#C - ciphertext; m - message 

#We know c = m^e (mod n)
def encrypt (m, e, n):
        #print(convert_to_hex(m))
        c = pow(int(convert_to_hex('分'+m), 16), e, n)
        return c

#We know m = c^d (mod n)
def decrypt (c, d, n):
        m = convert_to_ascii(format(pow(int(c),int(d),int(n)),'x')).split('分')[1]
        return m
'''
if __name__ == '__main__':
        #test
        n = 31676752383854794769589854195828579304231624214914393413957992306742067982482522587049928127438987671892790033105815366098002296580475308743951016838387617270426754392394247210737391222025461055958428135975057543602878915586908468232709968938543879814490285144968954294924834481082462166280031545001002383141910546487553748229076090776652358284066624500207847029802920479192468652315744164515545257064675733920210767975367286624852952806544768362710126480033878138983023442041237199979436667275943393548845708049972189007053497973123660659710453502661849957442201173555195005893594123241760739194046811366050377870553
        e = 65537
        d = 5578727680767383939310711462658551083043798261875611162914127091633992228112566576128450653018917492545990548272080213551171742788529319522142951864575276233810909855455916525113004401858764842880696057882175170793054739211500336303796915658157582141673358120500353547950355365376104770178740621212468826864516577677989599866257150233061258871884873656211309116662493424327896680453275241417233609327952791670587481424933682590038429230693397266143963260674464510856755989922955688232242658730827287786241828086836615434276907371272529001015440637950284044466639499403976033764765250968351848503270597625502654009313
        while True:
                m = input('암호화할 문장: ')
                c = encrypt(m, e, n)
                print('암호화한 문장:', c)
                m = decrypt(c, d, n)
                print('복호화한 문장:', m)
'''

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

"""

from convert_to import convert_to_hex, convert_to_ascii

#exponentiation by squaring is not necessary because of python's awesome 3-arg pow()
#public key: (n,e)
#private key: (n,d)
#C - ciphertext; m - message 

#We know c = m^e (mod n)
def encrypt (m, e, n):
        #print(convert_to_hex(m))
        c = pow(int(convert_to_hex('分'+m), 16), e, n)
        return c

#We know m = c^d (mod n)
def decrypt (c, d, n):
        m = convert_to_ascii(format(pow(int(c),int(d),int(n)),'x')).split('分')
        #print(m)
        return m[1]

if __name__ == '__main__':
        #test
        n = 31676752383854794769589854195828579304231624214914393413957992306742067982482522587049928127438987671892790033105815366098002296580475308743951016838387617270426754392394247210737391222025461055958428135975057543602878915586908468232709968938543879814490285144968954294924834481082462166280031545001002383141910546487553748229076090776652358284066624500207847029802920479192468652315744164515545257064675733920210767975367286624852952806544768362710126480033878138983023442041237199979436667275943393548845708049972189007053497973123660659710453502661849957442201173555195005893594123241760739194046811366050377870553
        e = 65537
        d = 5578727680767383939310711462658551083043798261875611162914127091633992228112566576128450653018917492545990548272080213551171742788529319522142951864575276233810909855455916525113004401858764842880696057882175170793054739211500336303796915658157582141673358120500353547950355365376104770178740621212468826864516577677989599866257150233061258871884873656211309116662493424327896680453275241417233609327952791670587481424933682590038429230693397266143963260674464510856755989922955688232242658730827287786241828086836615434276907371272529001015440637950284044466639499403976033764765250968351848503270597625502654009313
        while True:
                m = input('암호화할 문장: ')
                c = encrypt(m, e, n)
                print('암호화한 문장:', c)
                m = decrypt(c, d, n)
                print('복호화한 문장:', m)

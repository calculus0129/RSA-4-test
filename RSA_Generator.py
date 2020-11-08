from math import gcd
from gnt_prime import generateLargePrime, inp # Since implemented out of ./RSA/
from EEA import EEA # Same
from convert_to import convert_to_ascii, convert_to_hex # Same
#from write_to_file import write_to_file
import math

def generateRSA():
        try:
                bits = 0
                while bits < 32 or bits > 2048 or (math.log (bits, 2) + 1) % 1 != 0:
                        bits = inp()
                p = generateLargePrime(int(bits>>1)) # bits/2
                q = generateLargePrime(int(bits>>1)) # bits/2
                
                n = int(p*q) #key length
                O = (p-1)*(q-1) #Euler's totient function
                e = 2**16 + 1 #Default value -- a well known prime that works well most of the time

                if gcd (e,O) != 1: #must be coprime
                    e = generateLargePrime (17)

                d = EEA (O , e, 1, 0, 0, 1)

                #prevent d with negative value
                if d < 0: d += (1 + abs(d)//O)*O

                #write_to_file(n, e, d, p1, n1, p2, n2)
                #print("Key Generation Complete!")
                #print('n: {0}\ne: {1}\nd: {2}\n'.format(n, e, d))
                return [n, e, d]
        #except FileNotFoundError:
        #        print('Not Existing Directory or File Not Found!!!')
        #        return False
        except:
                print("Something bad happened. This either means you did something naughty or Parsa's program has bug(s). This error message is useless for debugging, but at least it's not ugly. If you know what went wrong, please submit a pull request! Have a nice day!")
#import os
if __name__ == '__main__':
        print('Generating RSA Key...')
        print(generateRSA())

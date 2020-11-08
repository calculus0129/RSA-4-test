import os
import RSA_Generator

dirname = ['keys']

class key:
        # name: name
        # n: p*q
        # e: (n, e): public key
        # d: (n, d): 
        def __init__(self, n, e, d, num=0, name=''):
                self.n = n
                self.e = e
                self.d = d
                self.num=num
                self.name = name
        def showinfo(self):
                print('\n<------KEY_INFO-<<<<<-\n')
                print('num: {3}\nName: {4}\nn = {0}\ne = {1}\nd = {2}\n'.format(self.n, self.e, self.d, self.num, self.name))
                print('\n->>>>>-KEY_INFO--END->\n')

def readkey(ap=os.getcwd()): # ap: additional path. designate as this directory when used externally
        keys = []
        p = ap+'/'+'keys'
        if not os.path.isdir(p): # no such folder
                os.makedirs(p)
                return []
        l = os.listdir(p)
        l.sort(key = lambda i: int(i.split('key')[1].split('.')[0]))
        #print(l) # for compiling
        for i in l:
                try: 
                        with open(p+'/'+i, encoding = 'utf-8') as f:
                                d = list(map(lambda i: ''.join(i.split('\r')).split('\n'), f.readlines()))
                                keys.append(key(int(d[2][0]), int(d[3][0]), int(d[4][0]), int(d[1][0]), d[0][0]))
                except UnicodeError:
                        with open(p+'/'+i, encoding = 'cp949') as f:
                                d = list(map(lambda i: ''.join(i.split('\r')).split('\n'), f.readlines()))
                                keys.append(key(int(d[2][0]), int(d[3][0]), int(d[4][0]), int(d[1][0]), d[0][0]))
        return keys

def genekey(name):  # public key generation
        p = os.getcwd()+"/"+dirname[0]
        if not os.path.isdir(p): os.makedirs(p)
        #print(p)
        fn = len(os.listdir(p))  # filenumber
        try:
                #print(p+'/'+'key'+str(fn)+'.txt')
                with open(p+'/'+'key'+str(fn)+'.txt', 'w', encoding = 'utf-8') as f:
                        n, e, d = RSA_Generator.generateRSA()
                        f.write('{0}\n{1}\n{2}\n{3}\n{4}\n'.format(name,fn,n,e,d))
                        f.flush()
                        f.close()
                        return [key(n, e, d, fn, name), 'key'+str(fn)+'.txt']
        except TypeError:
                if p == None: pass
                else: print('Directory Error!')
        return [None,None]
#pkg('ryan')  # test

# before 10/3 version. modify as the 'readkey' later on.
'''
def findkey(num):
        p = os.getcwd()+"/"+dirname[0]
        if not os.path.isdir(p): return -2
        if len(os.listdir(p))-1<num: return -1
        fn = len(os.listdir(p))  # filenumber
        k = key(None, None, None, None)
        try:
                with open(p+'/'+'key'+str(num)+'.txt', encoding = 'utf-8') as f:
                        d = list(map(lambda i: ''.join(i.split('\r')).split('\n'), f.readlines()))
                        k = key(int(d[2][0]), int(d[3][0]), int(d[4][0]), d[0][0])
        except UnicodeError:
                with open(p+'/'+'key'+str(num)+'.txt', encoding = 'cp949') as f:
                        d = list(map(lambda i: ''.join(i.split('\r')).split('\n'), f.readlines()))
                        k = key(int(d[2][0]), int(d[3][0]), int(d[4][0]), d[0][0])
        return k'''

if __name__ == '__main__': # test
        #print(pkg('ryan'))
        #print(findkey('양천구'))
        for i in readkey(): i.showinfo()

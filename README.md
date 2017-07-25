# PMP Dump

This poorly coded utility will connect to a ManageEngine Password Manager Pro installation and dump all of the juicy secrets!

## Breakdown of the encryption/decryption process
PMP uses a bunch of cryptographic hand waving to hide the contents of the password databases, but basically it can be boiled down to:


1. Pad a static, randomly generated 16 byte password to 32 bytes with space characters
2. Use PBKDF2 with 1024 rounds and the 32 byte password to generate a 32 byte AES Key
	- The IV is static of course: {1,2,3,4,5,6,7,8}
	- lol 	
3. Using AES CTR with a 256 bit key encrypt the user's cleartext secret
4. Base64 encode the secret
5. insert base64 encoded secret into the database and encrypt again using built-in mysql encryption with a static, randomly generated key

## What you need to do/obtain
The Python program included (pmp_dump.py) requires some configuration (check the comments). Most of the info should be easy to find if you have admin rights on the server, or if the permissions are bad. But basically you need:

- The randomly generated encryption key from `pmp_key.key`
- The database connection info from `database_params.conf`
- The database encryption key...
	- This one's a bit harder. You may have to do some grepping:
	- `grep -ir AES_ENCRYPT /path/to/PMP/`
	- Look for items like:
```
INSERT INTO `Ptrx_UserAudit` (`AUDITID`,`RESOURCENAME`,`NAME`,`OPERATEDBY`,`LOGINNAME`,`USERNAME`,`USER`,`LASTACCESSEDTIME`,`IPADDRESS`,`OPERATIONTYPE`,`REASON`,`OSTYPE`,`RESOURCEID`,`ACCOUNTID`) VALUES (64,AES_ENCRYPT('N/A',"<PASSWORD_HERE_STEAL_THIS_OK>"),'...
```
 	- It could also be in the indata1 innodb file as well, if you can figure out a way to mount that.
 	- The password HAS to be somewhere, it's just a matter of finding it :D

### Usage
Install dependencies:
`pip install mysql-connector pycrypto`

Edit pmp_dump.py to suit your needs, then hit go:

`python pmp_dump.py outfile.csv`


### Sorry
This code sucks, but it did the job on a test, so there.
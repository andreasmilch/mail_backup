import argparse
import configparser
import email
import getpass
import hashlib
import imaplib
import mailbox
import os
import pickle
import re
import time

import pdb

# Constant variables
list_response_pattern = re.compile(r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" (?P<name>.*)')
config_loc = "config.ini"

# Functions
def parse_list_response(line):
    line = line.decode()
    flags, delimiter, mailbox_name = list_response_pattern.match(line).groups()
    mailbox_name = mailbox_name.strip('"')
    return (flags, delimiter, mailbox_name)

def report_mail_str(msg):
    return "(%s) %s: %s"%(msg["Date"][:-6], msg["From"], msg["Subject"])

def hash_mail(msg):
    h = hashlib.md5()
    h.update(msg["Date"].encode())
    h.update(msg["From"].encode())
    h.update(msg["To"].encode())
    h.update(msg["Subject"].encode())
    
    for part in walk_mail(msg):
        #print(part)
        h.update(part)
            
    return h.digest()

def walk_mail(mail):
    for part in mail.walk():
        if part.get_content_maintype() == "multipart":
            continue
        yield part.get_payload(decode=1)
        
parser = argparse.ArgumentParser()
parser.add_argument("-c", "--clean", help="clean directory from output files", action="store_true")
parser.add_argument("-p", "--password", help="use password, ask for password", nargs="?", const=True)
parser.add_argument("-v", "--verbose", help="print a report on the console", action="store_true")
parser.add_argument("-w", "--wizard", help="wizard for config file", action="store_true")
args = parser.parse_args()

config = configparser.ConfigParser()
if os.path.exists(config_loc):
    config.read(config_loc)
if not args.wizard:
    if not "user" in config["SERVER"]:
        config["SERVER"]["user"] = input("Enter imap username:")
    if args.password == True:
        pwd = getpass.getpass("Enter imap password:")
    elif args.password == None:
        if not "pwd" in config["SERVER"]:
            config["SERVER"]["pwd"] = getpass.getpass("Enter imap password:")
        pwd = config["SERVER"]["pwd"]
    else:
        pwd = args.password
    if not "server" in config["SERVER"]:
        config["SERVER"]["server"] = input("Enter server address:")
    if not "port" in config["SERVER"]:
        config["SERVER"]["port"] = input("Enter port number:")
    if not "mbox_name" in config["SERVER"]:
        config["SERVER"]["mbox_name"] = os.path.splitext(input("Enter filename for Backup (*.mbox):"))[0] + ".mbox"
    if not "already_saved" in config["SERVER"]:
        config["SERVER"]["already_saved"] = input("Enter filename for list of already saved files:")
else:
    pass
    
if args.clean:
    if os.path.exists(config["SERVER"]["mbox_name"]):
        os.remove(config["SERVER"]["mbox_name"])
    if os.path.exists(config["SERVER"]["already_saved"]):
        os.remove(config["SERVER"]["already_saved"])
    if os.path.exists(config["SERVER"]["mbox_name"]+".lock"):
        if input("Remove lock? (y or n):").lower() == "y":
            os.remove(config["SERVER"]["mbox_name"]+".lock")
    exit()

saved = []
skipped = []
hashes = []
new_hashes = []
pwd = ""

try:
    with open(config["SERVER"]["already_saved"], "rb") as f:
        hashes = pickle.load(f)
except IOError:
    pass

mbox = mailbox.mbox(config["SERVER"]["mbox_name"])
mbox.lock()
try:
    
    m = imaplib.IMAP4_SSL(config["SERVER"]["server"], config["SERVER"].getint("port"))
    m.login(config["SERVER"]["user"], pwd)
    if "mailbox" not in config["SERVER"]:
        print("Choose mailbox to archieve: ")
        resp, mailboxlist = m.list()
        for i, mailbox in enumerate(mailboxlist):
            mailboxlist[i] = parse_list_response(mailbox)[2]
        for  i, mailbox in enumerate(mailboxlist):
            print("(%s): %s\n"%(i, mailbox))
        config["SERVER"]["mailbox"] = mailboxlist[int(input("Number:"))]
    m.select(config["SERVER"]["mailbox"])
    
    resp, items = m.uid("search", None, "ALL")
    items = items[0].split()
    
    for emailuid in items:
        resp, data = m.uid("fetch", emailuid, "(RFC822)")
        email_body = data[0][1]
        mail = email.message_from_bytes(email_body)

        mailhash = hash_mail(mail)
        
        if mailhash not in hashes:             
            new_hashes.append(mailhash)
            #print(email_body)
            
            mbox.add(mail)
            mbox.flush()
            
            saved.append(report_mail_str(mail))
        else:
            new_hashes.append(mailhash)
            skipped.append(report_mail_str(mail))
    
    m.close()
    m.logout()
finally:
    mbox.unlock()
    
with open(config["SERVER"]["already_saved"], "wb") as f:
    pickle.dump(new_hashes, f)
with open(config_loc, "w") as f:
        config.write(f)

if args.verbose:
    print("Report from %s :"%(time.strftime("%d-%m-%Y %H:%M:%S")))
    print("Saved %s mails, skipped %s mails"%(len(saved), len(skipped)))
    print("Saved:")
    if not saved:
        print("None")
    else:
        for mail in saved:
            print(mail)
    print("Skipped:")
    if not skipped:
        print("None")
    else:
        for mail in skipped:
            print(mail)

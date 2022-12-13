#!/bin/python3

'''
    Easy Email utility.
    Retrieves specified message from the top of the INBOX.
    Edit credentials.json file to specify your imap login, password and server.

    Author: Igor Mytsik
    GitHub: https://github.com/RedHopper
'''

import imaplib
import email
import time
import json #For loading credentials
import sys #For retrieving cmd arguments

def arr_to_str(target):
    result = ''
    for a in target:
        result += a.strip('\n') + '\n'
    return result

def str_to_arr(to_arr, split_char = '\n', skip_chars = ['\r']):
    to_arr += split_char
    result = []
    cache = ''
    for a in to_arr:
        if a != split_char and a not in skip_chars:
            cache += a
        elif a == split_char:
            if len(cache):
                result.append(cache)
            cache = ''
    return result

def default_creds(json_creds):
    if not isinstance(json_creds, dict):
        raise Exception(f'json_creds variable must be a dictionary type; current type: {str(type(json_creds))}')
    if json_creds['email_address'] == 'test@gmail.com' and json_creds['email_password'] == 'email_pass_or_token':
        return True
    return False
    

def remove_html(to_clean):
    if not isinstance(to_clean, str):
        print('[!] Error: remove_html() - to_clean variable must be of a type str.')
        return f'[*] remove_html() - to_clean var must be str, but it is: {str(type(to_clean))}'
    count = 0
    html_cache = ''
    result = ''
    is_style = False
    for a in to_clean:
        if a == '<' or a == '>':
            count += 1
            if a == '>':
                if 'style' in html_cache:
                    is_style = not is_style
                html_cache = ''
            continue
        if (count%2 == 0 or count == 0) and not is_style:
            result += a
        else:
            html_cache += a
    return result

def get_body(mail, debug = False):
    plain_data = ''
    html_data = ''
    if not mail.is_multipart():
        if debug:
            print('[D] get_body() - message is NOT multipart')
        ctype = mail.get_content_type()
        data = mail.get_payload(decode = True).decode()
        if ctype == 'text/plain':
            return data
        elif ctype == 'text/html':
            return remove_html(data)
        raise Warning('unsupported content type: ' + ctype)
        return 'Error: unsupported content type: ' + ctype
    if debug:
        print('[D] get_body() - message is multipart')
    count = 0
    for a in mail.walk():
        count += 1
        if debug:
            print(f'[D] get_body() - Part number {count} has content type: {a.get_content_type()}')
        if a.get_content_type() == 'text/plain':
            plain_data = a.get_payload(decode = True)
            plain_data = plain_data.decode()
        elif a.get_content_type() == 'text/html':
            html_data = a.get_payload(decode = True).decode()
    if len(plain_data) > 0:
        if debug:
            print('[D] get_body() - Successfully received plain text. Returning it.')
        return plain_data
    if len(html_data):
        if debug:
            print('[D] Got html data, but no plain data provided')
        #return remove_html(html_data)
        return remove_html(html_data)
    return 'ERROR GETTING BODY'

class email_handler:
    debug_mode = False
    def __init__(self, email_addr, email_pass, imap_server):
        self.email_addr = email_addr
        self.email_pass = email_pass
        self.imap_server = imap_server
        self.imap = imaplib.IMAP4_SSL(imap_server)
        self.imap.login(email_addr, email_pass)
    def verify_creds(self, creds):
        creds_keys = list(creds.keys())
        if 'email_address' not in creds_keys or 'email_password' not in creds_keys or 'imap_server' not in creds_keys:
            return False
        return True
    def __init__(self, creds):
        if not isinstance(creds, dict):
            raise Exception(f'creds variable must be a dict type; but it is: {str(type(creds))}')
        if not self.verify_creds(creds):
            raise Exception('__init__(self, creds) - json data loaded successfully, but it is missing required variables')
            return
        self.email_addr = creds['email_address']
        self.email_pass = creds['email_password']
        self.imap_server = creds['imap_server']
        self.imap = imaplib.IMAP4_SSL(self.imap_server)
        self.imap.login(self.email_addr, self.email_pass)
        return
    def __enter__(self):
        return self
    def get_from_inbox(self, num_message_from_top):
        num_message_from_top = int(str(num_message_from_top))
        status, messages = self.imap.select('INBOX')
        messages = int(messages[0].decode())
        if status != 'OK':
            raise Exception('get_from_inbox() - Error selecting INBOX')
        status, fetched = self.imap.fetch(str(messages-num_message_from_top), '(RFC822)')
        if status != 'OK':
            raise Exception('get_from_inbox() - Error fetching data')
            return
        mail = email.message_from_bytes(fetched[0][1])
        print(f'[D] mail type: ')
        subject = email.header.decode_header(mail['Subject'])[0]
        sender = email.header.decode_header(mail['From'])[0]
        if not isinstance(subject[0], str):
            subject = subject[0].decode(subject[1])
        else:
            subject = subject[0]
        if not isinstance(sender[0], str):
            sender = sender[0].decode(sender[1])
        else:
            sender = sender[0]
        data = ''
        data = get_body(mail, self.debug_mode)
        data = data.strip('\n ')
        subject = 'Subject: ' + subject + '\n'
        sender = 'From: ' + sender + '\n'
        data = subject + sender + 'Message\'s content:\n\n' + data
        self.imap.close()
        return data
    def close(self):
        self.__exit__(None, None, None)
        return
    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type == None:
            self.imap.logout()
        return

def load_creds(file_path):
    file_path = str(file_path)
    with open(file_path, 'r') as f:
        data = f.read()
    return json.loads(data)

if __name__ == "__main__":
    creds = load_creds('credentials.json')
    if default_creds(creds):
        print('Write your IMAP credentials into the credentials.json file before using utility.')
        exit()
    num_from_top = 0
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        num_from_top = int(sys.argv[1])
        with email_handler(creds) as mail:
            body = mail.get_from_inbox(num_from_top)
            arr_body = str_to_arr(body)
            body = rem_empty_lines(body)
            print(body)
    else:
        print(f'Usage: {sys.argv[0]} [number of email message from top]') 

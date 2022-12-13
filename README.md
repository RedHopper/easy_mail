# Description
**Easy_mail** is simple and fast utility made for retrieving email messages from related IMAP server.

You can specify credentials in **credentials.json** file to use it from cmd: `./easy_mail [email message number from top]`
# Technical overview
* Class **email_handler** connects to IMAP server on initialization and then can be used for retrieving and decoding specified messages. 
It has both `__init__` and `__enter__` functions, so it can be initiated via `with` keyword or just as is and later closed via child function `close()`.
* **get_body** function has global scope and is used by `email_handler` class to decode and structurize email message data. 
It does so by using built in *email* module.
* Function **read_creds** loads json file and returns it as a dictionary object.
This dictionary has to be passed to *email_handler* on initialization. 
* **email_handler.get_from_inbox** function returns text of specified message from top. 
For example: `handle.get_from_inbox(0)` will return last message in the INBOX.
* **\_\_init\_\_** function is overloaded which means you can directly pass all 
required credentials on the **email_handler** initialization: 

`handle = easy_mail.email_handler('test@gmail.com', 'email_password_or_token', 'imap.server.com')`
# Example:
```
import easy_mail as em
creds = em.load_creds('credentials.json')
with em.email_handler(creds) as mail:
    message_content = mail.get_from_inbox(0)
print(message_content)
```

import socket
import argparse
import ssl
# by Zaostrovskaya Anastasiya
import sys
import os
import re
import base64


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", "-d", type=str, help="папка с config.txt, text.txt, files")
    parser.add_argument("--login", "-l", type=str, help="логин для авторизации")
    parser.add_argument("--password", "-p", type=str, help="пароль для авторизации")
    return parser.parse_args()


def to_base64(line):
    return base64.b64encode(line.encode()).decode()


def problems(sock, command, data):
    """Вывод ошибки"""
    print(command + " problems")
    print(data)
    sock.close()
    sys.exit(0)


def timeout(sock, command):
    """Вывод ошибки"""
    print("Timeout " + command)
    sock.close()
    sys.exit(0)


def get_letter(text_file):
    """Текстовое содержимое письма"""
    with open(text_file, 'r', encoding='utf-8') as f:
        file = f.read()
        file = file.replace('\n.', '\n..')
    return file


def parse_message_directory(dir):
    """Для корректной работы необходимы файлы config.txt, text.txt, папка files
    Возвращает emails: list, theme: str, files: set для отправки, файл с текстом"""
    if os.path.exists(dir + '/config.txt'):
        emails, theme, input_files = parse_config(dir + '/config.txt')
    else:
        print("\nFile 'config.txt' doesn't exist\n")
        sys.exit(0)
    if not os.path.exists(dir + '/text.txt'):
        print("\nFile 'text.txt' doesn't exist\n")
        sys.exit(0)
    if not os.path.exists(dir + '/files'):
        if input_files:
            print("\nYou want to send some files, but 'files' directory doesn't exist\n")
            sys.exit(0)
        else:
            files = {}
    elif input_files:
        files = input_files.intersection(set(os.listdir(dir + '/files')))
        if len(files) < len(input_files):
            print("\nFiles {0} doesn't exist in 'files' directory. So they won't be sent.\n"
                  .format(input_files.difference(files)))
    else:
        files = {}
    return emails, theme, files, dir+'/text.txt'


def parse_config(config):
    """Возвращает emails, theme, files"""
    re_to = re.compile('([\w.-]+?@(\w+)\.ru)')
    re_theme = re.compile('Theme: (.*)\n')
    re_files_str = re.compile('Files: (.*)')
    re_file = re.compile(r'(\w+\.\w+\b)')
    emails = []
    domains = {'mail', 'yandex', 'rambler'}
    with open(config, 'r') as conf:
        for adr in re_to.findall(conf.readline()):
            if adr[1] not in domains:
                print("\nUnknown email. Chose mail|yandex|rambler's user\n")
                sys.exit(0)
            emails.append(adr[0])
        if not emails:
            print("\nYou should enter destination email address\n")
            sys.exit(0)
        try:
            theme = re_theme.search(conf.readline()).group(1)
        except AttributeError:
            theme = "No theme"
        try:
            f = str(re_files_str.search(conf.readline()).group(1))
            files = {file for file in re_file.findall(f)}
        except AttributeError:
            files = {}
    return emails, theme, files


def get_bit_files(directory, files):
    """Возвращает словарь: ключ - имя файла, значение - (content_type, байтовое представление)"""
    content_type = {'jpeg': "image/jpeg", 'jpg': "image/jpg", 'png': "image/png",
                    'txt': "text/plain", 'pdf': "application/pdf"}
    re_files = re.compile('(jpeg|jpg|png|txt|pdf)')
    dict_images = dict()
    for file in files:
        t = re_files.findall(file)
        if t:
            with open(directory + "/files/" + file, "rb") as b_file:
                try:
                    encoded_string = base64.encodebytes(b_file.read())
                    dict_images[file] = (content_type[t[0]], encoded_string.decode())
                except Exception:
                    print('\nSomething wrong with file ' + str(file) + '\n')
                    continue
    return dict_images


class Sender:
    def __init__(self, email, directory, theme, text, files, login, passwd):
        self.email = email
        self.server = 'smtp.' + self.get_server_name(login) + '.ru'
        self.port = 465
        self.directory = directory
        self.theme = theme  # str
        self.text = get_letter(text)  # str
        self.files = files  # set
        self.login = login
        self.password = passwd

    def get_server_name(self, login):
        name = ''
        f = False
        for log in login:
            if log == '.':
                f = False
            if f:
                name += log
            if log == '@':
                f = True
        return name

    def ehlo(self, sock):
        try:
            sock.send(b"EHLO Sender\n")
            data = sock.recv(4096).decode()
            if data[0] == "2":
                print("EHLO success")
            else:
                problems(sock, "EHLO", data)
        except socket.timeout:
            timeout(sock, "EHLO")

    def auth(self, sock):
        try:
            sock.send(b"AUTH LOGIN\n")
            data = sock.recv(4096).decode()
            if data[0] != "3":
                problems(sock, "AUTH", data)
            sock.send((to_base64(self.login) + "\n").encode())
            data = sock.recv(4096).decode()
            if data[0] != "3":
                problems(sock, "AUTH", data)
            sock.send((to_base64(self.password) + "\n").encode())
            data = sock.recv(4096).decode()
            if data[0] == "2":
                print("Authorization complete")
            else:
                problems(sock, "AUTH", data)
        except socket.timeout:
            timeout(sock, "AUTH")

    def mail(self, sock):
        try:
            sock.send(("MAIL FROM: " + self.login + "\n").encode())
            data = sock.recv(4096).decode()
            if data[0] == "2":
                print("Sender is " + self.login)
            else:
                problems(sock, "MAIL", data)
        except socket.timeout:
            timeout(sock, "MAIL")

    def rcpt(self, sock):
        try:
            sock.send(("RCPT TO: " + self.email + "\n").encode())
            data = sock.recv(4096).decode()
            if data[0] == "2":
                print("Recipient is " + self.email)
            else:
                problems(sock, "RCPT", data)
        except socket.timeout:
            timeout(sock, "RCPT")

    def data(self, sock):
        try:
            sock.send("DATA\n".encode())
            data = sock.recv(4096).decode()
            if data[0] == "3":
                print("Sending the message...")
            else:
                problems(sock, "DATA", data)
            sock.send(self.get_message())
            data = sock.recv(4096).decode()
            if data[0] == "2":
                print("Message was sent!")
            else:
                problems(sock, "Sending", data)
        except socket.timeout:
            timeout(sock, "DATA")

    def get_message(self):
        msg = []
        msg.append("From: {0}\n".format(self.login))
        msg.append("To: {0}\n".format(self.email))
        msg.append("Subject: {0}\n".format(self.theme))
        msg.append('Content-Type: multipart/mixed; boundary="C6y6NN0QaSkb14zK9VQuBtUq0M8SufNy"\n\n')
        msg.append("--C6y6NN0QaSkb14zK9VQuBtUq0M8SufNy\n")
        msg.append("Content-Type: text/plain\n\n")
        msg.append(self.text + "\n")
        bit_files = get_bit_files(self.directory, self.files)
        for file in bit_files.keys():
            msg.append("--C6y6NN0QaSkb14zK9VQuBtUq0M8SufNy\n")
            msg.append('Content-Disposition: attachment; filename="{0}"\n'.format(file))
            msg.append("Content-Transfer-Encoding: base64\n")
            msg.append('Content-Type: {0}; name="{1}"\n\n'.format(bit_files[file][0], file))
            msg.append(bit_files[file][1])
            msg.append("\n\n")
        msg.append("--C6y6NN0QaSkb14zK9VQuBtUq0M8SufNy\n.\n")
        return "".join(msg).encode()

    def quit(self, sock):
        try:
            sock.send("QUIT\r\n".encode())
            data = sock.recv(4096).decode()
            if data[0] == "2":
                print("Connection successfully closed\n")
            else:
                problems(sock, "QUIT", data)
        except socket.timeout:
            timeout(sock, "QUIT")

    def create_connection(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock = ssl.wrap_socket(sock)
        sock.connect((self.server, self.port))
        try:
            data = sock.recv(1024).decode()
            if data[0] == "2":
                print("Connection successfully created")
            else:
                problems(sock, "Connection", data)
            self.ehlo(sock)
            self.auth(sock)
            return sock
        except socket.timeout:
            print("Timeout creating connection")

    def send_message(self):
        sock = self.create_connection()
        self.mail(sock)
        self.rcpt(sock)
        self.data(sock)
        self.quit(sock)


if __name__ == "__main__":
    args = get_args()
    emails, theme, files, text = parse_message_directory(args.directory)
    for email in emails:
        sender = Sender(email, args.directory, theme, text, files, args.login, args.password)
        sender.send_message()
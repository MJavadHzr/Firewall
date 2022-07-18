import re
import ipaddress
import subprocess as sp
from logging import raiseExceptions


class SimpleRule_Handler():
    def __init__(self):
        self.stages = {
            -1: self._cancel,
            0: self._is_input_output,
            1: self._select_protocol,

            2: self._ftp_file_name,
            3: self._ssh_username,
            4: self._smtp_spam,
            5: self._dns_url,
            6: self._dhcp_mac,
            7: self._http_content,

            8: self._http_header,

            9: self._set_count_limit,

            10: self._is_tcp_udp,
            11: self._is_url,
            12: self._is_ip,

            13: self._in_port,
            14: self._out_port,
            15: self._set_target,
            16: self._set_rule,
            17: self._set_action
        }

    def run(self):
        self._initialize()
        while True:
            try:
                self.stages[self.state]()
            except:
                return

    def _initialize(self):
        self.state = 17
        self.args = [''] * len(self.stages)
        self.in_out = ''

    def _set_rule(self):
        command = ' '.join(['sudo', 'iptables'] +
                           [a for a in self.args if a != ''])
        print('--------------[command]--------------')
        print(command)

        p = sp.run(command.split(), stdout=sp.PIPE, universal_newlines=True)

        print('---------------[result]---------------')
        if p.returncode != 0:
            print('something wrong happened!')
        else:
            print('rule set successfully!')
        print(p.stdout)
        print('--------------------------------------')
        raiseExceptions()

    def _cancel(self):
        print('get back to menu')
        raiseExceptions()

    def _next_state(self):
        current = self.state
        next = 0

        if current == 0:
            next = 1
        elif current == 1:
            if self.args[self.state] == '':
                next = 10
            else:
                if self.a_protocol == 'ftp':
                    next = 2
                elif self.a_protocol == 'ssh':
                    next = 3
                elif self.a_protocol == 'smtp':
                    next = 4
                elif self.a_protocol == 'dns':
                    next = 5
                elif self.a_protocol == 'dhcp':
                    next = 6
                elif self.a_protocol == 'http':
                    next = 7
                elif self.a_protocol == 'https':
                    next = 7
                else:
                    next = 10
        elif 2 <= current and current <= 6:
            next = 9
        elif current == 7:
            next = 8
        elif current == 8:
            next = 9
        elif current == 9:
            next = 11
        elif current == 10:
            next = 9
        elif current == 11:
            if self.args[self.state] == '':
                next = 12
            else:
                if self.args[1] == '':
                    next = 13
                else:
                    next = 15
        elif current == 12:
            if self.args[1] == '':
                next = 13
            else:
                next = 15
        elif current == 17:
            next = 0
        else:
            next = current + 1

        self.state = next

    def _prev_state(self):
        self.args[self.state] = ''
        curr = self.state
        prev = 0
        if curr == 0:
            prev = 17
        elif curr == 1:
            prev = 0
        elif 2 <= curr and curr <= 7:
            prev = 1
        elif curr == 8:
            prev = 7
        elif curr == 9:
            if self.args[1] == '':
                prev = 10
            else:
                if self.a_protocol == 'ftp':
                    prev = 2
                elif self.a_protocol == 'ssh':
                    prev = 3
                elif self.a_protocol == 'smtp':
                    prev = 4
                elif self.a_protocol == 'dns':
                    prev = 5
                elif self.a_protocol == 'dhcp':
                    prev = 6
                elif self.a_protocol == 'http':
                    prev = 7
                elif self.a_protocol == 'https':
                    prev = 7
                else:
                    prev = 10
        elif curr == 10:
            prev = 1
        elif curr == 11:
            prev = 9
        elif curr == 12:
            prev = 11
        else:
            prev = curr - 1

        self.state = prev

    def _set_action(self):
        msg = """(What do you want to do?)
            a: to append rule (add rule to the tail of the chain)
            d: to delete rule
            i: to insert rule (add rule to the head of the cahin)
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip().lower()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            elif command == 'a' or command == 'd' or command == 'i':
                self.action = command.upper()
                break
            else:
                print('invalid input!')
                command = input().strip().lower()

        self._next_state()

    def _select_protocol(self):
        msg = """(Select which application layer protocol you want to filter)
            ftp: FTP
            ssh: SSH
            smtp: SMTP
            dns: DNS
            dhcp: DHCP
            http: HTTP
            https: HTTPS
            none: no application layer protocol
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip().lower()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            elif command == 'none':
                self._next_state()
                return
            elif command == 'ftp':
                port_n = '20:21'
                protocol = 'tcp'
                self.a_protocol = 'ftp'
                break
            elif command == 'ssh':
                port_n = '22'
                protocol = 'tcp'
                self.a_protocol = 'ssh'
                break
            elif command == 'smtp':
                port_n = '25'
                protocol = 'tcp'
                self.a_protocol = 'smtp'
                break
            elif command == 'dns':
                port_n = '53'
                protocol = 'udp'
                self.a_protocol = 'dns'
                break
            elif command == 'dhcp':
                port_n = '67'
                protocol = 'udp'
                self.a_protocol = 'dhcp'
                break
            elif command == 'http':
                port_n = '80'
                protocol = 'tcp'
                self.a_protocol = 'http'
                break
            elif command == 'https':
                port_n = '443'
                protocol = 'tcp'
                self.a_protocol = 'https'
                break
            else:
                print('invalid input!')
                command = input().strip().lower()

        s = 's' if self.in_out == 'INPUT' else 'd'
        self.args[self.state] = f'-p {protocol} --{s}port {port_n}'
        self._next_state()

    def _ftp_file_name(self):
        msg = """(You can filter a file)
            {file-name}: the name of file you want to restrict
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            else:
                arg = command
                break

        self.args[self.state] = f'-m string --string {arg} --algo kmp'
        self._next_state()

    def _ssh_username(self):
        msg = """(You can limit a username)
            {username}: username to limit
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            else:
                arg = command
                break

        self.args[self.state] = f'-m string --string {arg} --algo kmp'
        self._next_state()

    def _smtp_spam(self):
        msg = """(You can control mails contain {string})
            {string}: string you want mail includes
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip().lower()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            else:
                arg = command
                break

        self.args[self.state] = f'-m string --string {arg} --algo kmp'
        self._next_state()

    def _dns_url(self):
        msg = """(You can limit a URL)
            {url}: url to limit
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            else:
                arg = command
                break
        self.args[self.state] = f'-m string --string {arg} --algo kmp'
        self._next_state()

    def _dhcp_mac(self):
        msg = """(You can limit a mac address)
            {mac-address}: mac-address to limit
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            else:
                if re.match("^[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", command.lower()):
                    arg = command
                    break
                else:
                    print('invalid input mac address!')
                    command = input().strip()

        self.args[self.state] = f'-m mac --mac-source {arg}'
        self._next_state()

    def _http_content(self):
        msg = """(You can limit an http req which has {string})
            {string}: string to filter
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            else:
                arg = command
                break

        self.args[self.state] = f'-m string --string {arg} --algo bm'
        self._next_state()

    def _http_header(self):
        msg = """(Control http packets with header {key:value})
            {key:value}: header you want to control
            none: for no header filtering
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            elif command == 'none':
                arg = ''
                break
            else:
                if re.match(r'(.+):(.+)', command.lower()):
                    arg = f'-m string --string {command} --algo kmp'
                    break
                else:
                    print('invalid input!')
                    command = input().strip()

        self.args[self.state] = arg
        self._next_state()

    def _is_tcp_udp(self):
        msg = """(TCP or UDP):
            tcp: for tcp
            udp: for udp
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            elif command == "tcp":
                arg = '-p tcp'
                break
            elif command == 'udp':
                arg = '-p udp'
                break
            else:
                print('invalid input!')
                command = input().strip()

        self.args[self.state] = arg
        self._next_state()

    def _set_count_limit(self):
        msg = """(Number of time this rule can be hit)
            {n} {scal}: this rule can be hit n/scale time (scale is one of 'second', 'minute', 'hour', 'day')
            none: no hit limit
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip().lower()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            elif command == 'none':
                self._next_state()
                return
            else:
                args = command.split()
                try:
                    n = int(args[0])
                    scale = args[1]
                    if scale not in ['second', 'minute', 'hour', 'day']:
                        raiseExceptions()
                    break
                except:
                    print('invalid input!')
                    command = input().strip().lower()

        self.args[self.state] = f'-m limit --limit {n}/{scale}'
        self._next_state()

    def _is_input_output(self):
        msg = """(INPUT or OUTPUT rule):
            in: input rule
            out: output rule
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            elif command == 'in':
                arg = 'INPUT'
                break
            elif command == 'out':
                arg = 'OUTPUT'
                break
            else:
                print('invalid input!')
                command = input().strip()

        self.args[self.state] = f'-{self.action} {arg}'
        self.in_out = arg
        self._next_state()

    def _is_url(self):
        msg = """(URL Regex)
            {regex}: your regex for url
            none: for no regex
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            elif command == 'none':
                arg = ''
                break
            else:
                # if validators.url(command):
                arg = f'-m string --string {command} --algo bm'
                break
                # else:
                # print('input is not a valid URL address')
                # command = input().strip()

        self.args[self.state] = arg
        self._next_state()

    def _is_ip(self):
        msg = """(IP Address):
            {ip-address}: to set a rule with ip-address
            none: no ip address
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            elif command == 'none':
                arg = ''
                break
            else:
                try:
                    ipaddress.ip_network(command)
                    s = 's' if self.in_out == 'INPUT' else 'd'
                    arg = f'-{s} {command}'
                    break
                except:
                    print('input is not a valid IP address')
                    command = input().strip()

        self.args[self.state] = arg
        self._next_state()

    def _in_port(self):
        msg = """(Source port number):
            {port-number}: to set a rule with input port-number
            none: no port number
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            elif command == 'none':
                arg = ''
                break
            else:
                try:
                    port_num = int(command)
                    if port_num < 1 or port_num > 65535:
                        raiseExceptions()
                    arg = f'--sport {port_num}'
                    break
                except:
                    print('invalid input')
                    command = input().strip()

        self.args[self.state] = arg
        self._next_state()

    def _out_port(self):
        msg = """(Destination port number):
            {port-number}: to set a rule with input port-number
            none: no port number
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            elif command == 'none':
                arg = ''
                break
            else:
                try:
                    port_num = int(command)
                    if port_num < 1 or port_num > 65535:
                        raiseExceptions()
                    arg = f'--dport {port_num}'
                    break
                except:
                    print('invalid input')
                    command = input().strip()

        self.args[self.state] = arg
        self._next_state()

    def _set_target(self):
        msg = """(Target for rule):
            a: for ACCEPT rule
            d: for DROP rule
            r: for REJECT rule
            b: back
            c: cancel
        """
        print(msg)
        command = input().strip()
        while True:
            if command == 'b':
                self._prev_state()
                return
            elif command == 'c':
                self.state = -1
                return
            elif command == 'a':
                arg = 'ACCEPT'
                break
            elif command == 'd':
                arg = 'DROP'
                break
            elif command == 'r':
                arg = 'REJECT'
                break
            else:
                print('invalid input!')
                command = input().strip()

        self.args[self.state] = f'-j {arg}'
        self._next_state()

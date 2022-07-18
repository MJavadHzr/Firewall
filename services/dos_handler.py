import subprocess as sp
from logging import raiseExceptions


class DoS_Handler():
    def __init__(self):
        self.stages = {
            -1: self._cancel,
            0: self._select_dos_type,
            1: self._dns_flood,
            2: self._slow_loris,
            3: self._syn_flood,
            4: self._set_dns_flood_rule,
            5: self._set_slowloris_rule,
        }

    def run(self):
        self._initialize()
        while True:
            try:
                self.stages[self.state]()
            except:
                return

    def _initialize(self):
        self.state = 0
        self.args = [''] * len(self.stages)
        self.type = ''

    def _cancel(self):
        print('get back to menu')
        raiseExceptions()

    def _next_state(self):
        curr = self.state
        if curr == 0:
            if self.type == 'df':
                next = 1
            elif self.type == 'sl':
                next = 2
            elif self.type == 'sf':
                next = 3
            else:
                next = curr
        elif curr == 1:
            next = 4
        elif curr == 2:
            next = 5
        else:
            next = curr + 1  # never reach

        self.state = next

    def _prev_state(self):
        curr = self.state
        if curr == 0:
            prev = -1
        else:
            prev = 0

        self.state = prev

    def _select_dos_type(self):
        msg = """Select which service do you want?
            df: for control DnsFlood
            sl: for SlowLoris
            sf: for SYN Flood
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
            elif command == 'df' or command == 'sl' or command == 'sf':
                self.type = command
                break
            else:
                print('invalid input!')
                command = input().strip().lower()

        self._next_state()

    def _dns_flood(self):
        msg = """You can filter IPs that request for DNS too much
            {second} {hitcount}: second is time interval and hitcount the number of queries you allow to reach your server
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
                args = command.split()
                try:
                    self.dns_second = int(args[0])
                    self.dns_count = int(args[1])
                    break
                except:
                    print('invalid input!')
                    command = input().strip().lower()

        self._next_state()

    def _set_dns_flood_rule(self):
        root = "sudo iptables -A INPUT -p udp --dport 53 -m string --from 50 --algo bm --hex-string \"|0000FF0001|\" -m recent --name dnsquery"
        commands = []
        commands.append(root + ' ' + '--set --rsource')
        commands.append(root + ' ' + f'--rcheck --seconds {self.dns_second} --hitcount {self.dns_count} -j DROP')

        print('------------------------------------------------------')
        for c in commands:
            print(c)
            p = sp.run(c.split(' '), stdout=sp.PIPE, universal_newlines=True)

            if p.returncode != 0:
                print('something wrong happened!')
            else:
                print('rule set successfully!')
            print(p.stdout)
            print('------------------------------------------------------')

        raiseExceptions()

    def _slow_loris(self):
        msg = """You can prevent IPs to establish too many parallel http connection to your server
            {n}: maximum number of paralle that you allow to established
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
                try:
                    self.slowloris_n = int(command)
                    break
                except:
                    print('invalid input!')
                    command = input().strip().lower()

        self._next_state()

    def _set_slowloris_rule(self):
        command = f'sudo iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above {self.slowloris_n} -j DROP'

        print('------------------------[command]------------------------')
        print(command)
        p = sp.run(command.split(), stdout=sp.PIPE,
                   universal_newlines=True)

        print('------------------------[result]------------------------')
        if p.returncode != 0:
            print('something wrong happened!')
        else:
            print('rule set successfully!')
        print(p.stdout)
        print('---------------------------------------------------------')

        raiseExceptions()

    def _syn_flood(self):
        msg = """You just need to limit --syn req, which can be done by portscanning module"""
        print(msg)
        input('press Enter to continue ...')
        self._prev_state()

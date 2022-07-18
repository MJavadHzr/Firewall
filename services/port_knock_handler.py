import numpy as np
from logging import raiseExceptions
import subprocess as sp


class PortKnock_Handler():
    def __init__(self):
        self.stages = {
            -1: self._cancel,
            0: self._get_prot,
            1: self._get_knock_num,
            2: self._set_rule
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
        self.in_out = ''
    
    def _cancel(self):
        print('get back to menu')
        raiseExceptions()
    
    def _next_state(self):
        self.state += 1
    
    def _prev_state(self):
        self.state -= 1
    
    def _get_prot(self):
        msg = """Which port do you want to block?
            {port-number}: your port number
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
                    port_num = int(command)
                    if port_num < 1 or port_num > 65535:
                        raiseExceptions()
                    self.port_number = port_num
                    break
                except:
                    print('invalid input')
                    command = input().strip().lower()
        
        self._next_state()
    
    def _get_knock_num(self):
        msg = """How many knock do you want to have?
            {n}: knock count
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
                    n = int(command)
                    self.n = n
                    break
                except:
                    print('invalid input!')
                    command = input().strip().lower()
        
        self._next_state()
        
    def _set_rule(self):
        ports = np.random.randint(low=1, high=65536, size=self.n)
        
        commands = []
        for i in range(self.n + 1):
            if i < self.n:
                rule = f'-p udp --dport {ports[i]} -m recent --name K{i+1} --set -j DROP'
            else:
                rule = f'-p tcp --dport {self.port_number} -j ACCEPT'
            
            if i == 0:
                target = f'-p tcp --dport {self.port_number} -j DROP'
            else:
                target = '-j KNOCK0'
            
            commands.append(f'sudo iptables -N KNOCK{i}')
            if i != 0:
                commands.append(f'sudo iptables -A KNOCK{i} -m recent --name K{i} --remove')
            commands.append(f'sudo iptables -A KNOCK{i} {rule}')
            commands.append(f'sudo iptables -A KNOCK{i} {target}')
        
        commands.append('sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT')
        
        for i in range(self.n):
            commands.append(f'sudo iptables -A INPUT -m recent --rcheck --name K{i+1} -j KNOCK{i+1}')
        commands.append('sudo iptables -A INPUT -j KNOCK0')
        
        print('------------------------------------------------------')
        
        for c in commands:
            print(c)
            p = sp.run(c.split(), stdout=sp.PIPE, universal_newlines=True)

            if p.returncode != 0:
                print('something wrong happened!')
            else:
                print('rule set completed!')
            print(p.stdout)
            print('------------------------------------------------------')
        
        raiseExceptions()
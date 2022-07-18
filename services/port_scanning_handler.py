import subprocess as sp
from logging import raiseExceptions


class PortScanning_Handler():
    def __init__(self):
        self.stages = {
            -1: self._cancel,
            0: self._get_threshold,
            1: self._set_rule
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
        
    def _cancel(self):
        print('get back to menu')
        raiseExceptions()
    
    def _next_state(self):
        self.state += 1
        
    def _prev_state(self):
        self.state -= 1
    
    def _get_threshold(self):
        msg = """Enter threshould to block for port scanners
            {n} {scale}: number of connections per scale, scale is one of 'second', 'minute', 'hour', 'day'
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
                    n = int(args[0])
                    scale = args[1].lower()
                    if scale not in ['second', 'minute', 'hour', 'day']:
                        raiseExceptions()
                    self.n = n
                    self.scale = scale
                    break
                except:
                    print('invalid input!')
                    command = input().strip().lower()
        
        self._next_state()
        
    def _set_rule(self):
        command = f'sudo iptables -A INPUT -p tcp --syn -m limit --limit {self.n}/{self.scale} -j REJECT'
        
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
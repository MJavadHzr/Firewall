import subprocess as sp


class View_Handler():
    def __init__(self):
        pass

    def run(self):
        args = 'sudo iptables -L -n -v'.split()
        p = sp.run(args, stdout=sp.PIPE, universal_newlines=True)

        print('-----------------[result]-----------------')
        if p.returncode != 0:
            print('something went wrong!')
        else:
            print(p.stdout)
        print('------------------------------------------')

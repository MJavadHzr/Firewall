import subprocess as sp


class View_Handler():
    def __init__(self):
        pass

    def run(self):
        while True:
            c = input('with details(Y/N)?').lower()
            if c == 'y':
                verbose = '-v'
                break
            elif c == 'n':
                verbose = ''
                break
            else:
                continue

        args = f'sudo iptables -L -n {verbose}'.split()
        p = sp.run(args, stdout=sp.PIPE, universal_newlines=True)

        print('-----------------[result]-----------------')
        if p.returncode != 0:
            print('something went wrong!')
        else:
            print(p.stdout)
        print('------------------------------------------')

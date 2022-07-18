# Network-HW 3

from logging import raiseExceptions
from services.dos_handler import DoS_Handler
from services.simple_rule_handler import SimpleRule_Handler
from services.port_knock_handler import PortKnock_Handler
from services.port_scanning_handler import PortScanning_Handler
from services.view_handler import View_Handler

services = {
    'Rule Controlling': SimpleRule_Handler(),
    'DoS Controlling': DoS_Handler(),
    'Port Knocking': PortKnock_Handler(),
    'Port Scanning': PortScanning_Handler(),
    'View Chains': View_Handler()
}
N = len(services)


def show_services():
    for i in range(N):
        print(f'{i+1}: {[*services][i]}')


while True:
    print("================================================================================")
    print("======[choose the NUMBER of your desired service: (or type 'exit' to exit)]=====")
    print("================================================================================")
    show_services()
    command = input()

    # check exit
    if command.lower() == 'exit':
        exit()

    # convert input to int
    try:
        command = int(command)
        if command <= 0 or command > N:
            raiseExceptions()
    except:
        print('please enter a valid number')
        continue

    # run service
    services[[*services][command - 1]].run()

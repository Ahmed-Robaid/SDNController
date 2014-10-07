# Dances Ryu Work #

## How to use: ##

In this example, we have two VMs: a mininet VM (192.168.56.104) and a VM that will be our Ryu controller (192.168.56.102).

*   Instruct the mininet network to use a remote controller using a command similar to the following:
        mininet@mininet-vm:~$ sudo mn --topo single,3 --mac --controller remote,ip=192.168.56.102,port=6633 --switch ovsk,protocols=OpenFlow13
*   Tell the mininet network to use OpenFlow 1.3:
        root@mininet-vm:~# ovs-vsctl set bridge s1 protocols=OpenFlow13
*   On the Ryu VM, start the controller:
        user@ryu-vm:$ sudo ryu-manager --verbose dances_switch_13.py
*   On the Ryu VM, start the dances listener:
        user@ryu-vm:$ sudo ./dances-client.py
*   Connect to port 9090 on the Ryu VM. Any text you enter will be an 'alert' to the controller:
        user@ryu-vm:$ telnet localhost 9090



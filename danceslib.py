# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

## Taken from snortlib
## Only UNIX sockets are currently supported

import os
import logging

from ryu.lib import hub
from ryu.base import app_manager
from ryu.controller import event
from ryu.lib import alert


BUFSIZE = alert.AlertPkt._ALERTPKT_SIZE
SOCKFILE = "/tmp/dances_alert"
OFP_PACKET_IN_PACK_STR = '!IHHBx'


class EventAlert(event.EventBase):
    def __init__(self, msg):
        super(EventAlert, self).__init__()
        self.msg = msg


class DANCESLib(app_manager.RyuApp):

    def __init__(self):
        super(DANCESLib, self).__init__()
        self.name = 'danceslib'
        self.config = {'unixsock': True}
        self._set_logger()

    def set_config(self, config):
        assert isinstance(config, dict)
        self.config = config

    def start_socket_server(self):
        if not self.config.get('unixsock'):
            if self.config.get('ip') is None:
                self.config['ip'] = hub.socket.gethostbyname(hub.socket.gethostname())
            if self.config.get('port') is None:
                self.config['port'] = 9090

            self._start_recv_nw_sock(self.config.get('ip'),
                                     self.config.get('port'))
        else:
            self._start_recv()

        self.logger.info(self.config)

    def _recv_loop(self):
        self.logger.info("Unix socket start listening...")
        while True:
            data = self.sock.recv(BUFSIZE)
            print "  >>~> DANCESLIB <~<<  ", data
            print "data: ", data
            self.send_event_to_observers(EventAlert(data))
            #msg = alert.AlertPkt.parser(data)
            #if msg:
            #    print "     DANCESLIB: ", msg
            #    self.send_event_to_observers(EventAlert(msg))

    def _start_recv(self):
        if os.path.exists(SOCKFILE):
            os.unlink(SOCKFILE)

        ## self.sock = hub.socket.socket(hub.socket.AF_UNIX,
        ##                               hub.socket.SOCK_DGRAM)
        self.sock = hub.socket.socket(hub.socket.AF_UNIX,
                                      hub.socket.SOCK_DGRAM)
        self.sock.bind(SOCKFILE)
        hub.spawn(self._recv_loop)

    def _start_recv_nw_sock(self, ip, port):

        self.nwsock = hub.socket.socket(hub.socket.AF_INET,
                                        hub.socket.SOCK_STREAM)

        print "Binding... on ip (", ip, ") and port (", port,") "
        self.nwsock.bind((ip, port))
        print "Done binding..."
        self.nwsock.listen(5)
        self.conn, addr = self.nwsock.accept()

        print "Spawning..."
        hub.spawn(self._recv_loop_nw_sock)
        print "Done Spawning..."

    def _recv_loop_nw_sock(self):
        self.logger.info("Network socket server start listening...")
        while True:
            data = self.conn.recv(BUFSIZE, hub.socket.MSG_WAITALL)

            if len(data) == BUFSIZE:
                msg = alert.AlertPkt.parser(data)
                if msg:
                    self.send_event_to_observers(EventAlert(msg))
            else:
                self.logger.debug(len(data))

    def _set_logger(self):
        """change log format."""
        self.logger.propagate = False
        hdl = logging.StreamHandler()
        fmt_str = '[dances][%(levelname)s] %(message)s'
        hdl.setFormatter(logging.Formatter(fmt_str))
        self.logger.addHandler(hdl)


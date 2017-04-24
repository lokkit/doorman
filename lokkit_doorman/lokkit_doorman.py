# -*- coding: utf-8 -*-

import logging
import logging.handlers
import json
import subprocess
from collections import OrderedDict
from time import sleep
from ethjsonrpc import EthJsonRpc
from ethjsonrpc.exceptions import ConnectionError

# Setup logger
logger = logging.getLogger('lokkitLogger')
logger.setLevel(logging.INFO)
logger.addHandler(logging.handlers.SysLogHandler(address = '/dev/log'))
logger.addHandler(logging.StreamHandler()) # log to console

def main():
    print('Started')
    host = 'localhost'
    port = '8545'
    logger.warn('Connecting to http://{0}:{1}'.format(host, port))
    c = EthJsonRpc(host, port)

    try:
        logger.info('Node shh version: {0}'.format(c.shh_version()))
    except:
        logger.error('Check if connected node has shh enabled')

    # config
    contract_address = '0xf16801293f34fc16470729f4ac91185595aa6e10'
    description = c.call(contract_address, 'description()', [], ['string'])[0]
    deposit = c.call(contract_address, 'deposit()', [], ['uint256'])[0]
    location = c.call(contract_address, 'location()', [], ['string'])[0]
    costPerSecond = c.call(contract_address, 'costPerSecond()', [], ['uint256'])[0]
    current_renter = c.call(contract_address, 'currentRenter()', [], ['address'])[0]
    logger.info('Configured rentable contract {0}\n\
  description: {1}\n\
  location: {2}\n\
  deposit: {3}\n\
  costPerSecond: {4}\n\
  current_renter: {5}'.format(contract_address, description, location,
                  deposit, costPerSecond, current_renter))

    # TODO: implement correct filter
    filter_id = c.shh_newFilter("", [None])
    logger.info('Listen for incomming messages..')
    try:
        while True:
            msg = c.shh_getFilterChanges(filter_id)
            for m in msg:
                # TODO: Validate message, make sure its payload is correct, etc
                logger.debug('Message details:\n  from {0}\n  ttl {1}\n  payload: {2}'
                        .format(m['from'], m['ttl'], m['payload']))

                payload = None
                try:
                    # payload contains digest and message
                    payload = json.loads(m['payload'][2:].decode('hex'), object_pairs_hook=OrderedDict)
                except:
                    logger.error('Error parsing whisper message: {0}', m)
                    continue

                signature = payload['digest'] # hex value starting with 0x....
                message = payload['message']  # dict object
                logger.debug('signature: {0}\nmessage {1}'.format(signature, message))

                # get ethereum address of the sender
                message_json = json.dumps(message, separators=(',', ':')) # separators: no whitespaces
                message_hex_string = '0x{0}'.format(message_json.encode('hex'))
                logger.debug('message_json_string {0}\nmessage_json_string_hex {1}'
                        .format(message_json, message_hex_string))

                address_of_sender = c.personal_ecRevoer(message_hex_string, signature)

                logger.info('Command "{0}", rentableAddress "{1}"'
                        .format(message['command'], message['rentableAddress']))
                logger.info('ethereum account (recovered) "{0}"'
                        .format(address_of_sender))

                current_renter = c.call(contract_address, 'currentRenter()', [], ['address'])[0]

                if address_of_sender[2:] != current_renter:
                    logger.error('Refuse execution of command "{0}": requester ({1}) is not the current renter ({2}) of rentable "{3}"'
                            .format(message['command'], address_of_sender, current_renter, message['rentableAddress']))
                    continue

                logger.info('Executing command "{0}" for rentable {1}'.format(message['command'], message['rentableAddress']))
		n = 0 if message['command'] == 'lock' else 1	
		subprocess.call(['/bin/sh', '-c', 'echo %s > /sys/class/gpio/gpio23/value' % n])

            sleep(1) # sleep 1 second
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

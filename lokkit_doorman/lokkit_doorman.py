# -*- coding: utf-8 -*-

import os
import logging
import logging.handlers
import json
import subprocess
import yaml
from collections import OrderedDict
from time import sleep
from ethjsonrpc import EthJsonRpc
from ethjsonrpc.exceptions import ConnectionError

# Setup logger
logger = logging.getLogger('lokkitLogger')
logger.setLevel(logging.DEBUG)
if (os.name == 'posix'):
	logger.addHandler(logging.handlers.SysLogHandler(address = '/dev/log'))
logger.addHandler(logging.StreamHandler()) # log to console

def main():
    print('Started')
    configFile = open("config.yml", "r")
    doc = yaml.load(configFile)
    root = doc['doorman']
    parts = root['node_url'].split(':')
    port = parts[1]
    host = parts[0]
    rentable_address = root['rentable_address']
    script = root['script']
    logger.warn('Connecting to {0}:{1}'.format(host, port))
    c = EthJsonRpc(host, port)

    try:
        logger.info('Node shh version: {0}'.format(c.shh_version()))
    except ConnectionError:
        logger.error('Could not connect to {0}:{1}'.format(host, port))
        return
    except:
        logger.error('Shh is not enabled on this node.')
        return

    # config
    try:
        description = c.call(rentable_address, 'description()', [], ['string'])[0]
        deposit = c.call(rentable_address, 'deposit()', [], ['uint256'])[0]
        location = c.call(rentable_address, 'location()', [], ['string'])[0]
        costPerSecond = c.call(rentable_address, 'costPerSecond()', [], ['uint256'])[0]
        current_renter = c.call(rentable_address, 'currentRenter()', [], ['address'])[0]
        logger.info('Configured rentable contract {0}\n\
      description: {1}\n\
      location: {2}\n\
      deposit: {3}\n\
      costPerSecond: {4}\n\
      current_renter: {5}'.format(rentable_address, description, location,
                      deposit, costPerSecond, current_renter))
    except AssertionError:
        logger.error('Address {0} is not a Rentable'.format(rentable_address))
        return

    # TODO: implement correct filter
    filter_id = c.shh_newFilter("", ['rentable'])
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

                signer = c.personal_ecRevoer(message_hex_string, signature)
                sender = message['whisperIdentity']

                logger.info('Command "{0}", rentableAddress "{1}", whisperIdentity "{2}"'
                    .format(message['command'], message['rentableAddress'], sender))
                logger.info('ethereum account (recovered) "{0}"'
                    .format(signer))

                current_renter = c.call(rentable_address, 'currentRenter()', [], ['address'])[0]

                if signer[2:] != current_renter:
                    logger.error('Refuse execution of command "{0}": requester ({1}) is not the current renter ({2}) of rentable "{3}"'
                            .format(message['command'], signer, current_renter, message['rentableAddress']))
                    continue
                if sender != m['from']:
                    logger.error('Encrypted whisper identity is not of the sender. Possible replay attack detected')
                    continue

                logger.info('Executing script "{0}" with argument "{1}" for rentable "{2}"'.format(script, message['command'], message['rentableAddress']))
                
                n = 0 if message['command'] == 'lock' else 1
                #subprocess.call([script, message['command']])

            sleep(1) # sleep 1 second
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()


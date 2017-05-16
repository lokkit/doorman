# -*- coding: utf-8 -*-

import os
import sys
import logging
import logging.handlers
import json
import subprocess
import yaml

import sha3
from collections import OrderedDict
from time import sleep
from ethjsonrpc import EthJsonRpc
from ethjsonrpc.exceptions import ConnectionError

# Setup logger
logger = logging.getLogger('lokkitLogger')
logger.setLevel(logging.INFO)
if (os.name == 'posix'):
	logger.addHandler(logging.handlers.SysLogHandler(address = '/dev/log'))
logger.addHandler(logging.StreamHandler()) # log to console

def _print_help():
    print """
Usage: lokkit-doorman.py <configfile>

If you don't specify the <configfile> it will try to read /etc/lokkit/doorman.yml

Example config.yml:
doorman:
    node_url: 127.0.0.1:8545
    rentable_address: "0xf16801293f34fc16470729f4ac91185595aa6e10"
    script: /path/to/script/to/execute.sh
"""

def _check_if_exists(yaml_doc, attribute):
    """
    Checks if attribute exists in yaml_doc and log, if it does
    not exist

    Args:
        yaml_doc: The doc received by yaml.load()
        attribute: The attribute as string

    Returns:
        True if successful
    """
    if not yaml_doc.has_key(attribute):
        logger.error('Error in config file: missing "{}"'.format(attribute))
        return False
    return True

def _parse_config_file(config_filepath):
    """
    Parses the given config file and returns dict holding
    the configuration

    Args:
        config_filepath: The file path of the configuration yml

    Returns:
        A dict holding the configuration or None if an error
        occured.
    """
    doc = None
    with open(config_filepath, "r") as file:
        doc = yaml.load(file)

    if not _check_if_exists(doc, 'doorman'):
        return None

    doc = doc.get('doorman')

    ret = True
    ret = ret and _check_if_exists(doc, 'node_ip')
    ret = ret and _check_if_exists(doc, 'node_rpc_port')
    ret = ret and _check_if_exists(doc, 'rentable_address')
    ret = ret and _check_if_exists(doc, 'script')

    if ret:
        return doc
    else:
        return None


def main():
    if len(sys.argv) < 2:
        config_filepath = "/etc/lokkit/doorman.yml"
    else:
        config_filepath = sys.argv[1]

    if not os.path.isfile(config_filepath):
        logger.error('Error reading the config file "{}": The file does not exist'
                     .format(config_filepath))
        _print_help()
        return 1

    logger.info("Reading config file: {}".format(config_filepath))
    config = _parse_config_file(config_filepath)
    if not config:
        logger.error("Config file could not be parsed: {}".format(config_filepath))
        _print_help()
        return 1

    host = config['node_ip']
    port = config['node_rpc_port']
    rentable_address = config['rentable_address']
    script = config['script']
    symmetric_key_password = config['symmetric_key_password']

    logger.info('Connecting to {0}:{1}'.format(host, port))
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

    symmetric_key_address = c.shh_addSymmetricKeyFromPassword(symmetric_key_password)
    symmetric_key = c.shh_getSymmetricKey(symmetric_key_address)
    topic = c.web3_sha3(rentable_address)[:10]

    filter_id = c.shh_subscribe(type='sym', key=symmetric_key_address, sig=None, minPow=None, topics=[topic])
    logger.info('Listen for incomming messages..')
    try:
        while True:
            messages = c.shh_getNewSubscriptionMessages(filter_id)
            for message in messages:
                logger.debug('Message details:\n  hash {0}\n  ttl {1}\n  payload: {2}\n  topic: {2}'
                        .format(message['hash'], message['ttl'], message['payload'], message['topic']))

                payload = None
                try:
                    # payload contains digest and message
                    message_payload_string = message['payload'][2:].decode('hex')
                    payload = json.loads(message_payload_string, object_pairs_hook=OrderedDict)
                except:
                    logger.error('Error parsing whisper message payload: {0}', message['payload'])
                    continue

                signature = payload['digest'] # hex value starting with 0x....
                lokkit_message = payload['message']  # dict object
                logger.debug('signature: {0}\nlokkit_message {1}'.format(signature, lokkit_message))

                # get ethereum address of the sender
                message_json = json.dumps(lokkit_message, separators=(',', ':')) # separators: no whitespaces
                message_hex_string = '0x{0}'.format(message_json.encode('hex'))
                logger.debug('message_json_string {0}\nmessage_json_string_hex {1}'
                        .format(message_json, message_hex_string))

                signer = c.personal_ecRecover(message_hex_string, signature)
                key = lokkit_message['key']

                logger.info('command "{0}", rentableAddress "{1}", key "{2}"'
                    .format(lokkit_message['command'], lokkit_message['rentableAddress'], key))
                logger.info('signing ethereum account (recovered) "{0}"'
                    .format(signer))

                current_renter = c.call(rentable_address, 'currentRenter()', [], ['address'])[0]
                logger.info('current renter (smart contract)      "{0}"'
                    .format(signer))

                if signer[2:] != current_renter:
                    logger.error('Refuse execution of command "{0}": requester ({1}) is not the current renter ({2}) of rentable "{3}"'
                            .format(lokkit_message['command'], signer, current_renter, lokkit_message['rentableAddress']))
                    continue
                if key != message['sig']:
                    logger.error('Encrypted public key is not of the sender. Possible replay attack detected')
                    continue

                logger.info('Executing script "{0}" with argument "{1}" for rentable "{2}"'.format(script, lokkit_message['command'], lokkit_message['rentableAddress']))
                subprocess.call([script, lokkit_message['command']])

            sleep(1) # sleep 1 second
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()


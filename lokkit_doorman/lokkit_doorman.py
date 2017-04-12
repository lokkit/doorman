# -*- coding: utf-8 -*-

import logging
import logging.handlers
from ethjsonrpc import EthJsonRpc

# Setup logger
logger = logging.getLogger('lokkitLogger')
logger.setLevel(logging.INFO)
logger.addHandler(logging.handlers.SysLogHandler(address = '/dev/log'))
logger.addHandler(logging.StreamHandler()) # log to console

def main():
    print('Started')
    host = '127.0.0.1'
    port = '8545'
    logger.warn('Connecting to http://{0}:{1}'.format(host, port))
    c = EthJsonRpc(host, port)

    logger.info('Node net version: {0}'.format(c.net_version()))
    logger.info('Node web3 client version: {0}'.format(c.web3_clientVersion()))
    logger.info('Node block number: {0}'.format(c.eth_blockNumber()))
    try:
        logger.info('Node shh version: {0}'.format(c.shh_version()))
    except:
        logger.error('Check if connected node has shh enabled')


if __name__ == "__main__":
    main()

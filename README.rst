===============================
lokkit doorman
===============================

Python service that listens on an ethereum node for incoming whisper messages.
Specify your own config.yml and run lokkit_doorman.py.

* Free software: MIT license

Features
--------

* TODO: testing

As a developer
------------------

.. code-block:: bash

  apt-get install python-virtualenv

  # Setup virtual env
  virtualenv env
  source env/bin/activate

  # install doorman
  pip install --process-dependency-links .

  # run doorman
  python lokkit_doorman/lokkit_doorman.py [lokkit_doorman/config.yml]

To send a command to doorman, run the following js lines.

.. code-block:: javascript

  var addr = eth.accounts[0]; // todo: set account
  var pw = ""; // todo: set password
  var shhPw = "lokkit"; // needs to be the same as config.yml/doorman/symmetric_key_password. Default: "lokkit"
  var rentableAddress = "0xe7262436a5efd18f79f46fa0a03997238d8dff1c"; // todo: set rentable address
  var command = "unlock"; // todo: set your command
  
  // the following lines should not be changed. This implements the real-time interface for lokkit.
  var key = shh.addSymmetricKeyFromPassword(shhPw);
  var asymKey = shh.newKeyPair();
  var publicKey = shh.getPublicKey(asymKey);
  var topic = web3.sha3(rentableAddress).substr(0, 10);
  var message = { 'command': command, 'rentableAddress': rentableAddress, 'key': publicKey };
  var messageBytes = web3.fromAscii(JSON.stringify(message));
  personal.unlockAccount(addr, pw);
  var digest = web3.eth.sign(addr, messageBytes);
  var whisperMessage = { 'message': message, 'digest': digest };
  var payload = web3.fromAscii(JSON.stringify(whisperMessage));
  shh.post({type: 'sym', ttl: 20, topic: topic, powTarget: 2.5, powTime: 8, payload: payload, key: key, sig: asymKey});
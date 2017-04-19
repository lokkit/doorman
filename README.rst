===============================
lokkit doorman
===============================

Python service that listens on local ethereum node for incomming whisper messages.

* Free software: MIT license

Features
--------

* TODO: implement correct filter
* TODO: validate message, make sure its payload is correct, etc
* TODO: define requirements
* TODO: testing

As a developer
------------------

.. code-block:: bash

  apt-get install python-virtualenv

  # Setup virtual env
  virtualenv env
  source env/bin/activate

  # install dependency
  pip install pip --upgrade
  pip install --editable lokkit_doorman/ethjsonrpc

  # run doorman
  python lokkit_doorman/lokkit_doorman.py

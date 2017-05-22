===============================
lokkit doorman
===============================

Python service that listens on an ethereum node for incoming whisper messages.
Specify your own config.yml and run lokkit_doorman.py.

* Free software: MIT license

Features
--------

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
  python lokkit_doorman/lokkit_doorman.py [lokkit_doorman/config.yml]
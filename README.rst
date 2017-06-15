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

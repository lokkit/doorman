===============================
lokkit doorman
===============================

Python service that listens on an ethereum node for incoming whisper messages.
Specify your own config.yml and run doorman.py.

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
  python doorman/doorman.py [doorman/config.yml]

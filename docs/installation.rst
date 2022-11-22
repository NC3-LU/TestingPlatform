Installation
============

Prerequisites
-------------

Generally speaking, requirements are the following:

- A GNU/Linux distribution (tested on Debian and Ubuntu);
- Python: version >= 3.8 (preferably use `pyenv <https://github.com/pyenv/pyenv>`_)
  and a dependency manager (for example `Poetry <https://python-poetry.org>`_);
- A PostgreSQL server >= 12.x: persistent storage.


Deployment
----------

The service can be deployed via several ways:

.. contents::
    :local:
    :depth: 1


From the source
~~~~~~~~~~~~~~~

Creation of a PostgreSQL user:

.. code-block:: bash

    $ sudo apt install postgresql
    $ sudo -u postgres createuser <username>
    $ sudo -u postgres psql
    psql (11.2 (Ubuntu 11.2-1))
    Type "help" for help.
    postgres=# ALTER USER <username> WITH encrypted password '<password>';
    postgres=# ALTER USER <username> WITH SUPERUSER;
    ALTER ROLE
    postgres-# \q

The user name and password chosen must be specified later in the configuration file.
Get the source code and install the software:

.. code-block:: bash

    $ sudo apt install python3-pip python3-venv
    $ curl -sSL https://install.python-poetry.org | python3 -

    $ git clone https://github.com/NC3-LU/TestingPlatform.git
    $ cd TestingPlatform/
    $ npm ci
    $ poetry install --no-dev
    $ poetry shell

    $ python manage.py collectstatic

    $ export ALLOWED_HOSTS=127.0.0.1
    $ export IOT_API_URL=https://demo.iot-inspector.com/api


For production you should use `Gunicorn <https://gunicorn.org>`_ or ``mod_wsgi``.

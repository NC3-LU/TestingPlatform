Architecture
============


Models
------

.. figure:: _static/app-models.png
   :alt: Apllication models
   :target: _static/app-models.png

   Business related models.


High level architecture
-----------------------


.. figure:: _static/architecture-platform.png
   :alt: High level architecture
   :target: _static/app-models.png

   High level architecture.


Kvrocks
-------

Format of the data


.. code-block:: json

    {
        "version": "1",
        "format": "scanning",
        "meta": {
            "uuid": "<UUID>",
            "ts": "date",
            "type": "nmap-scan",
            "",
        },
        "payload": {
            "row": "<base64-encoded-string>"
        }
    }

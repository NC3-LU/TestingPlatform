Architecture
============


High level architecture
-----------------------


.. image:: _static/architecture-platform.png
   :alt: Organization level


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

# Testing Platform

## Presentation



## Installation

```bash
$ git clone https://github.com/NC3-LU/TestingPlatform.git
$ cd TestingPlatform
$ npm ci
$ poetry install --no-dev
```


```bash
$ poetry shell
$ python manage.py collectstatic # Copy static files required by Django Admin

# Create a user for the admin interface:
$ python manage.py createsuperuser --username <username>
```


## Documentation

A [documentation](docs/) is available.


## License

This software is licensed under
[GNU Affero General Public License version 3](https://www.gnu.org/licenses/agpl-3.0.html)


* Copyright (C) 2021-2022 Luxembourg House of Cybersecurity

For more information, the [list of authors and contributors](AUTHORS.md) is
available.

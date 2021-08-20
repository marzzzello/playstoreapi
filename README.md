![](https://forthebadge.com/images/badges/built-with-love.svg)
![](https://forthebadge.com/images/badges/fuck-it-ship-it.svg)
![](https://forthebadge.com/images/badges/contains-Cat-GIFs.svg)

[![Repo on GitLab](https://img.shields.io/badge/repo-GitLab-fc6d26.svg?style=for-the-badge&logo=gitlab)](https://gitlab.com/marzzzello/playstoreapi)
[![Repo on GitHub](https://img.shields.io/badge/repo-GitHub-4078c0.svg?style=for-the-badge&logo=github)](https://github.com/marzzzello/playstoreapi)
[![license](https://img.shields.io/github/license/marzzzello/playstoreapi.svg?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxwYXRoIHN0eWxlPSJmaWxsOiNkZGRkZGQiIGQ9Ik03IDRjLS44MyAwLTEuNS0uNjctMS41LTEuNVM2LjE3IDEgNyAxczEuNS42NyAxLjUgMS41UzcuODMgNCA3IDR6bTcgNmMwIDEuMTEtLjg5IDItMiAyaC0xYy0xLjExIDAtMi0uODktMi0ybDItNGgtMWMtLjU1IDAtMS0uNDUtMS0xSDh2OGMuNDIgMCAxIC40NSAxIDFoMWMuNDIgMCAxIC40NSAxIDFIM2MwLS41NS41OC0xIDEtMWgxYzAtLjU1LjU4LTEgMS0xaC4wM0w2IDVINWMwIC41NS0uNDUgMS0xIDFIM2wyIDRjMCAxLjExLS44OSAyLTIgMkgyYy0xLjExIDAtMi0uODktMi0ybDItNEgxVjVoM2MwLS41NS40NS0xIDEtMWg0Yy41NSAwIDEgLjQ1IDEgMWgzdjFoLTFsMiA0ek0yLjUgN0wxIDEwaDNMMi41IDd6TTEzIDEwbC0xLjUtMy0xLjUgM2gzeiIvPjwvc3ZnPgo=)](LICENSE.md)
[![commit-activity](https://img.shields.io/github/commit-activity/m/marzzzello/playstoreapi.svg?style=for-the-badge)](https://img.shields.io/github/commit-activity/m/marzzzello/playstoreapi.svg?style=for-the-badge)
[![Mastodon Follow](https://img.shields.io/mastodon/follow/103207?domain=https%3A%2F%2Fsocial.tchncs.de&logo=mastodon&style=for-the-badge)](https://social.tchncs.de/@marzzzello)

# Google Play Store Python API

This project is fork of [googleplay-api](https://github.com/NoMore201/googleplay-api).
It contains an unofficial API for google play interactions.

This fork was created to have a better base for the [gplaycrawler](https://gitlab.com/marzzzello/gplaycrawler).

The code was updated with the following changes:

- add (anonymous) login via token dispenser
- add login via environment variables
- updated protobuf and device configuration (they are now the same as the [GPlayApi](https://gitlab.com/AuroraOSS/gplayapi) from AuroraOSS)
- remove python2 support
- raise exceptions for bad HTTP status codes
- add possibility to use a delay between requests
- add streamDetails (used for related apps)
- add support for next pages to search and streamDetails

## Setup

Install protobuf:

Using apt:

```sh
$ apt install -y protobuf-compiler
```

Using pacman:

```sh
$ pacman -S protobuf
```

Check version:

```sh
$ protoc --version  # Ensure compiler version is 3+
```

Install playstoreapi using pip:

```sh
$ pip install playstoreapi
```

Or clone the repo and run:

```sh
$ python setup.py build
```

These are the recommended ways to build the package, since pip/setuptools will take care of
generating the `googleplay_pb2.py` file needed by the library (check the `setup.py`)

# Usage

Check scripts in `test` and `examples` directory for more examples on how to use this API.

```python
from playstoreapi.googleplay import GooglePlayAPI

mail = 'mymail@google.com'
passwd = 'mypasswd'

api = GooglePlayAPI('en_GB', 'Europe/London')
api.login(email=mail, password=passwd)
print(f'authSubToken: {api.authSubToken} gsfId: {api.gsfId}')

result = api.search('firefox')
for doc in result:
    if 'id' in doc:
        print('doc: {}'.format(doc['id']))
    for cluster in doc['subItem']:
        print('\tcluster: {}'.format(cluster['id']))
        for app in cluster['subItem']:
            print('\t\tapp: {}'.format(app['id']))
```

For first time logins, you should only provide email and password.
The module will take care of initalizing the api, upload device information
to the google account you supplied, and retrieving
a Google Service Framework ID (which, from now on, will be the android ID of your fake device).

For the next logins you **should** save the gsfId and the authSubToken, and provide them as parameters
to the login function or set them as environement variables. If you login again with email and password,
this is the equivalent of re-initalizing your android device with a google account, invalidating previous gsfId and authSubToken.

## Environment variables

```sh
# for envLogin()
export PLAYSTORE_TOKEN='ya29.fooooo'
export PLAYSTORE_GSFID='1234567891234567890'
export PLAYSTORE_DISPENSER_URL='http://goolag.store:1337/api/auth'

# requests
export HTTP_PROXY='http://localhost:8080'
export HTTPS_PROXY='http://localhost:8080'
export CURL_CA_BUNDLE='/usr/local/myproxy_info/cacert.pem'
```

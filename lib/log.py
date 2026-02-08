from os import environ, path, sys
import logging


log = logging.getLogger(path.basename(__file__))
logging.basicConfig(format='%(asctime)s %(funcName)s(%(lineno)s): %(message)s', stream=sys.stderr, level=logging.WARN)
log.setLevel(level=logging.INFO)


if (environ.get('DEBUG') == "DEBUG"):
    log.setLevel(level=logging.DEBUG)

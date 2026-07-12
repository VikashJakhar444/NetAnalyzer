import logging
import pytest


@pytest.fixture(autouse=True)
def suppress_file_logging():
    logger = logging.getLogger("NetworkScanner")
    file_handlers = [h for h in logger.handlers if not isinstance(h, logging.StreamHandler)]
    for h in file_handlers:
        logger.removeHandler(h)
    yield
    for h in file_handlers:
        logger.addHandler(h)

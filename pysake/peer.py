from pysake.constants import LOGGER_NAME
import logging

class Peer():

    """
    Abstract class for Server / Client to keep track of the current stage.
    """

    _stage:int = 0

    def __init__(self):
        pass

    def increment_stage(self):
        log = logging.getLogger(LOGGER_NAME).getChild("Peer")
        new = self._stage + 1
        log.debug(f"stage increment from {self._stage} to {new}")
        self._stage = new
        return
    
    def get_stage(self) -> int: 
        return self._stage
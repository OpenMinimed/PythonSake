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
    
    def _brute_force_ghost_byte(self, crypt_obj, payload16, expected:int):
      
        # NOTE: i think the used padding at the last permit message is a random byte in the original implementations.
        # this presents a challenge for us when we are trying to test our code against real world traffic
        # we can brute force it really quickly, then if the calculated cmac matches, we should be good to go (?)
       
        found = []
        for i in range(0, 0xff):
            pad = bytearray([i])
            test = payload16 + pad
            bak_seq = crypt_obj.seq
            out = crypt_obj.encrypt(test)
            crypt_obj.seq = bak_seq
            if out[-4] == expected:
                found.append(i)
                self.log.debug(f"found a ghost byte: {hex(i)}")
        if len(found) != 1:
            raise Exception("Did not get exactly 1 ghost byte!")
        return found[0]